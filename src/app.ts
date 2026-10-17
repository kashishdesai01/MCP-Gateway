import express, { type Request, type Response, type NextFunction } from 'express';
import { McpServer, createMcpHandler } from '@modelcontextprotocol/server';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { z } from 'zod';
import { Counter, Histogram, Registry } from 'prom-client';
import pino from 'pino';
import { fileURLToPath } from 'node:url';
import { authenticator, type Identity } from './auth.js';
import { GatewayError, invariant } from './errors.js';
import type { Gateway } from './gateway.js';
import { toolFor } from './tools.js';
import { validatePolicy } from './policy.js';
import { appendAudit, verifyAudit } from './audit.js';
import { definitionHash } from './upstream.js';
import type { DemoIdentity } from './demo-identity.js';
import { sdkSchema } from './schema-adapter.js';
import { newTrace, traceContext } from './trace.js';

export function createApp(gw: Gateway, demo?: DemoIdentity) {
  const app = express();
  const logger = pino({ level: process.env.LOG_LEVEL ?? 'info' });
  const authenticate = authenticator(gw.c, (reason) =>
    logger.warn({ reason }, 'Token validation failed'),
  );
  const metrics = new Registry();
  const requests = new Counter({
    name: 'gateway_tool_calls_total',
    help: 'Enforced tool invocations by bounded outcome',
    labelNames: ['outcome'],
    registers: [metrics],
  });
  const latency = new Histogram({
    name: 'gateway_tool_duration_seconds',
    help: 'Full gateway tools/call duration',
    buckets: [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 15, 30],
    registers: [metrics],
  });
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    const trace = newTrace(
      typeof req.headers.traceparent === 'string' ? req.headers.traceparent : undefined,
    );
    res.set('X-Trace-Id', trace.traceId);
    traceContext.run(trace, () => next());
  });
  app.use((_req, res, next) => {
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
      'Content-Security-Policy':
        "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' " +
        new URL(gw.c.AUTH_ISSUER).origin +
        "; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    });
    next();
  });
  app.use((req, res, next) => {
    // No cookies or ambient credentials. Browser writes require an exact configured origin.
    const expected = new URL(gw.c.RESOURCE_URI);
    if (gw.c.MODE === 'demo' && !['localhost', '127.0.0.1', '[::1]'].includes(req.hostname)) {
      res.status(403).json({ error: 'invalid_host' });
      return;
    }
    if (req.headers.origin && req.headers.origin !== expected.origin) {
      res.status(403).json({ error: 'invalid_origin' });
      return;
    }
    next();
  });
  app.use(express.json({ limit: '64kb', strict: true }));
  app.get('/health/live', (_req, res) => res.json({ status: 'alive' }));
  app.get('/health/ready', async (_req, res) => {
    try {
      await gw.db.pool.query('SELECT 1 FROM delegations LIMIT 1');
      res.json({ status: 'ready' });
    } catch {
      res.status(503).json({ status: 'unavailable' });
    }
  });
  app.get(
    ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'],
    (_req, res) =>
      res.json({
        resource: gw.c.RESOURCE_URI,
        authorization_servers: [gw.c.AUTH_ISSUER],
        scopes_supported: ['mcp:tools'],
        bearer_methods_supported: ['header'],
      }),
  );
  app.get('/auth/config', (_req, res) =>
    res.json({
      issuer: gw.c.AUTH_ISSUER,
      clientId: gw.c.CONSOLE_CLIENT_ID,
      resource: gw.c.RESOURCE_URI,
      demo: Boolean(demo),
    }),
  );
  if (demo && gw.c.MODE === 'demo') {
    app.get('/demo/jwks', (_req, res) => res.json(demo.jwks));
    app.post('/demo/login', async (_req, res) => res.json({ token: await demo.token() }));
  }
  const requireIdentity = async (req: Request): Promise<Identity> =>
    authenticate(req.headers.authorization);
  app.get('/metrics', async (req, res) => {
    invariant((await requireIdentity(req)).admin, 'admin_required');
    res.type(metrics.contentType).send(await metrics.metrics());
  });
  app.post('/mcp', async (req, res, next) => {
    if (req.body?.method === 'tools/call') {
      const end = latency.startTimer();
      let recorded = false;
      const record = () => {
        if (recorded) return;
        recorded = true;
        end();
      };
      res.once('finish', record);
      res.once('close', record);
    }
    let server: McpServer | undefined;
    try {
      const identity = await requireIdentity(req);
      const d = await gw.delegation(identity);
      server = new McpServer(
        { name: 'scoped-mcp-gateway', version: '0.1.0' },
        { supportedProtocolVersions: ['2026-07-28'] },
      );
      const connectors = await gw.connectors(d);
      for (const connector of connectors) {
        const pins = (
          await gw.db.pool.query<{ tool_name: string; approved_hash: string }>(
            'SELECT tool_name,approved_hash FROM tool_pins WHERE connector_id=$1',
            [connector.id],
          )
        ).rows;
        for (const pin of pins) {
          const spec = toolFor(pin.tool_name);
          if (req.body?.method === 'tools/list') {
            if (d.read_private && spec.effect === 'write') continue;
            try {
              if (
                definitionHash(await gw.upstream.definition(connector, pin.tool_name)) !==
                pin.approved_hash
              )
                continue;
            } catch {
              continue;
            } // An unavailable catalog never exposes an unverified definition.
          }
          server.registerTool(
            `${connector.name}__${pin.tool_name}`,
            { description: spec.description, inputSchema: sdkSchema(spec.schema) },
            async (args: unknown) => {
              try {
                const result = await gw.call(identity, connector.name, pin.tool_name, args);
                requests.inc({ outcome: 'completed' });
                return result;
              } catch (error) {
                const code = error instanceof GatewayError ? error.code : 'gateway_unavailable';
                requests.inc({
                  outcome: [
                    'upstream_outcome_unknown',
                    'operation_unknown',
                    'operation_fenced',
                  ].includes(code)
                    ? 'unknown'
                    : error instanceof GatewayError && error.status < 500
                      ? 'denied'
                      : 'unavailable',
                });
                logger.warn(
                  { code, traceId: traceContext.getStore()?.traceId },
                  'Tool call did not complete',
                );
                return { isError: true, content: [{ type: 'text' as const, text: code }] };
              }
            },
          );
        }
      }
      const instance = server;
      const handler = createMcpHandler(() => instance, {
        legacy: 'reject',
        maxRequestBodySize: 65_536,
      });
      try {
        await toNodeHandler(handler)(req, res, req.body);
      } finally {
        await handler.close();
      }
    } catch (error) {
      await server?.close().catch(() => undefined);
      next(error);
    }
  });
  async function admin(req: Request) {
    const identity = await requireIdentity(req);
    invariant(identity.admin, 'admin_required');
    const user = (
      await gw.db.pool.query<{ id: string }>(
        'SELECT id FROM users WHERE issuer=$1 AND subject=$2',
        [identity.issuer, identity.subject],
      )
    ).rows[0];
    invariant(user, 'admin_not_provisioned');
    return user.id;
  }
  app.get('/admin/v1/state', async (req, res) => {
    const owner = await admin(req);
    const delegations = (
      await gw.db.pool.query('SELECT * FROM delegations WHERE owner_id=$1 ORDER BY agent_name', [
        owner,
      ])
    ).rows;
    const connectors = (
      await gw.db.pool.query(
        'SELECT id,name,kind,enabled FROM connectors WHERE owner_id=$1 ORDER BY name',
        [owner],
      )
    ).rows;
    const pins = (
      await gw.db.pool.query(
        `SELECT p.* FROM tool_pins p JOIN connectors c ON c.id=p.connector_id WHERE c.owner_id=$1`,
        [owner],
      )
    ).rows;
    const events = (
      await gw.db.pool.query(
        `SELECT a.* FROM audit_events a JOIN delegations d ON d.id=a.delegation_id
      WHERE d.owner_id=$1 ORDER BY a.seq DESC LIMIT 100`,
        [owner],
      )
    ).rows;
    const operations = (
      await gw.db.pool.query(
        `SELECT o.id,o.delegation_id,o.tool_name,o.state,o.reason,o.created_at FROM operations o
      JOIN delegations d ON d.id=o.delegation_id WHERE d.owner_id=$1 ORDER BY o.created_at DESC LIMIT 100`,
        [owner],
      )
    ).rows;
    res.json({ delegations, connectors, pins, events, operations });
  });
  app.patch('/admin/v1/delegations/:id', async (req, res) => {
    const owner = await admin(req);
    const id = z.uuid().parse(req.params.id);
    const input = z
      .object({ enabled: z.literal(false) })
      .strict()
      .parse(req.body);
    await gw.db.tx(async (tx) => {
      const row = await tx.query(
        'UPDATE delegations SET enabled=$3 WHERE id=$1 AND owner_id=$2 RETURNING id',
        [id, owner, input.enabled],
      );
      invariant(row.rowCount === 1, 'not_found', 404);
      await appendAudit(tx, id, { kind: 'delegation_revoked', actor: owner });
    });
    res.status(204).end();
  });
  app.put('/admin/v1/delegations/:id/policy', async (req, res) => {
    const owner = await admin(req);
    const id = z.uuid().parse(req.params.id);
    const input = z
      .object({
        version: z.number().int().positive(),
        agentPolicy: z.string(),
        ownerPolicy: z.string(),
      })
      .strict()
      .parse(req.body);
    validatePolicy(input.agentPolicy);
    validatePolicy(input.ownerPolicy);
    await gw.db.tx(async (tx) => {
      const updated = await tx.query(
        `UPDATE delegations SET agent_policy=$4,owner_policy=$5,policy_version=policy_version+1
        WHERE id=$1 AND owner_id=$2 AND policy_version=$3 RETURNING policy_version`,
        [id, owner, input.version, input.agentPolicy, input.ownerPolicy],
      );
      invariant(updated.rowCount === 1, 'policy_version_conflict', 409);
      await tx.query(
        `INSERT INTO policy_versions(delegation_id,version,agent_policy,owner_policy,changed_by)
        VALUES($1,$2,$3,$4,$5)`,
        [id, input.version + 1, input.agentPolicy, input.ownerPolicy, owner],
      );
      await appendAudit(tx, id, {
        kind: 'policy_updated',
        actor: owner,
        version: input.version + 1,
      });
    });
    res.status(204).end();
  });
  app.post('/admin/v1/simulate', async (req, res) => {
    const owner = await admin(req);
    const input = z
      .object({
        delegationId: z.uuid(),
        tool: z.enum(['list_issues', 'get_file_contents', 'create_issue']),
        repo: z.string().max(200),
      })
      .strict()
      .parse(req.body);
    const d = (
      await gw.db.pool.query('SELECT * FROM delegations WHERE id=$1 AND owner_id=$2', [
        input.delegationId,
        owner,
      ])
    ).rows[0];
    invariant(d, 'not_found', 404);
    res.json(gw.decision(d, input.tool, input.repo.toLowerCase()));
  });
  app.get('/admin/v1/connectors/:id/tools/:tool', async (req, res) => {
    const owner = await admin(req);
    const id = z.uuid().parse(req.params.id);
    const name = String(req.params.tool);
    toolFor(name);
    const c = (
      await gw.db.pool.query('SELECT * FROM connectors WHERE id=$1 AND owner_id=$2', [id, owner])
    ).rows[0];
    invariant(c, 'not_found', 404);
    const definition = await gw.upstream.definition(c, name);
    res.json({ hash: definitionHash(definition), definition });
  });
  app.put('/admin/v1/connectors/:id/tools/:tool', async (req, res) => {
    const owner = await admin(req);
    const id = z.uuid().parse(req.params.id);
    const name = String(req.params.tool);
    toolFor(name);
    const { expectedHash } = z
      .object({ expectedHash: z.string().regex(/^[a-f0-9]{64}$/) })
      .strict()
      .parse(req.body);
    const c = (
      await gw.db.pool.query('SELECT * FROM connectors WHERE id=$1 AND owner_id=$2', [id, owner])
    ).rows[0];
    invariant(c, 'not_found', 404);
    const definition = await gw.upstream.definition(c, name);
    const hash = definitionHash(definition);
    invariant(hash === expectedHash, 'definition_changed_during_approval', 409);
    await gw.db.tx(async (tx) => {
      await tx.query(
        `INSERT INTO tool_pins(connector_id,tool_name,approved_hash,definition,approved_by) VALUES($1,$2,$3,$4,$5)
        ON CONFLICT(connector_id,tool_name) DO UPDATE SET approved_hash=$3,definition=$4,approved_by=$5,approved_at=now()`,
        [id, name, hash, definition, owner],
      );
      const ds = (
        await tx.query<{ id: string }>('SELECT id FROM delegations WHERE owner_id=$1 ORDER BY id', [
          owner,
        ])
      ).rows;
      for (const d of ds)
        await appendAudit(tx, d.id, {
          kind: 'tool_approved',
          tool: name,
          connectorId: id,
          hash,
          actor: owner,
        });
    });
    res.status(204).end();
  });
  app.get('/admin/v1/delegations/:id/verify', async (req, res) => {
    const owner = await admin(req);
    const id = z.uuid().parse(req.params.id);
    invariant(
      (
        await gw.db.pool.query('SELECT id FROM delegations WHERE id=$1 AND owner_id=$2', [
          id,
          owner,
        ])
      ).rowCount,
      'not_found',
      404,
    );
    res.json(await verifyAudit(gw.db, id));
  });
  app.use(
    express.static(fileURLToPath(new URL('../console/dist', import.meta.url)), {
      index: 'index.html',
    }),
  );
  app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const parserStatus = (error as { status?: number })?.status;
    const status =
      error instanceof GatewayError
        ? error.status
        : error instanceof z.ZodError
          ? 400
          : parserStatus === 400 || parserStatus === 413 || parserStatus === 415
            ? parserStatus
            : 503;
    const code =
      error instanceof GatewayError
        ? error.code
        : status === 400
          ? 'invalid_request'
          : status === 413
            ? 'request_too_large'
            : status === 415
              ? 'unsupported_media_type'
              : 'gateway_unavailable';
    if (status === 401 || code === 'insufficient_scope')
      res.set(
        'WWW-Authenticate',
        `Bearer resource_metadata="${new URL('/.well-known/oauth-protected-resource', gw.c.RESOURCE_URI)}"${status === 403 ? ', error="insufficient_scope", scope="mcp:tools"' : ''}`,
      );
    logger.warn({ code, status }, 'Request rejected');
    res.status(status).json({ error: code });
  });
  return app;
}
