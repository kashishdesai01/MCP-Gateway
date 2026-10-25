import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import type { Server } from 'node:http';
import { spawn } from 'node:child_process';
import { Client, StreamableHTTPClientTransport, type Tool } from '@modelcontextprotocol/client';
import { Database } from '../src/db.js';
import { config, type Config } from '../src/config.js';
import { Gateway } from '../src/gateway.js';
import { McpUpstream, definitionHash, type Upstream } from '../src/upstream.js';
import { createApp } from '../src/app.js';
import { demoIdentity, type DemoIdentity } from '../src/demo-identity.js';
import { fixtureApp } from '../src/fixture.js';
import { seed, demoIds } from '../scripts/seed.js';
import { migrate } from '../scripts/migrate.js';
import { verifyAudit } from '../src/audit.js';
import { defaultPolicy } from '../src/policy.js';
import { registry } from '../src/tools.js';
import { provisionRuntime } from '../scripts/runtime-role.js';
import { assertRuntimePermissions } from '../src/runtime-permissions.js';

const url = process.env.TEST_DATABASE_URL;
if (!url)
  throw new Error('TEST_DATABASE_URL is required; tests never silently skip database verification');
if (!new URL(url).pathname.slice(1).startsWith('gateway_test'))
  throw new Error('Integration tests require a dedicated gateway_test* database');
const db = new Database(url);
let c: Config;
let auth: DemoIdentity;
let gateway: Gateway;
let http: Server;
let fixture: Server;
let token: string;
const identity = {
  issuer: 'http://127.0.0.1:4300/demo',
  subject: 'demo-owner',
  clientId: 'demo-client',
  admin: true,
};
const args = (extra: Record<string, unknown> = {}) => ({
  operationId: randomUUID(),
  owner: 'demo',
  repo: 'public',
  ...extra,
});
let dispatches = 0;
const tools: Record<string, Tool> = Object.fromEntries(
  Object.keys(registry).map((name) => [
    name,
    { name, description: 'stable', inputSchema: { type: 'object' as const } },
  ]),
);
let behavior: () => Promise<unknown> = async () => ({ content: [{ type: 'text', text: 'ok' }] });
const fake: Upstream = {
  definition: async (_c, name) => tools[name]!,
  call: async () => {
    dispatches++;
    return behavior();
  },
};

beforeAll(async () => {
  c = config({
    MODE: 'demo',
    PORT: '4300',
    DATABASE_URL: url,
    AUTH_ISSUER: identity.issuer,
    AUTH_JWKS_URL: 'http://127.0.0.1:4300/demo/jwks',
    RESOURCE_URI: 'http://127.0.0.1:4300/mcp',
    CREDENTIAL_MASTER_KEY: randomBytes(32).toString('hex'),
    AUDIT_HMAC_KEY: randomBytes(32).toString('hex'),
  });
  await migrate(db);
  const f = fixtureApp();
  fixture = f.app.listen(4101, '127.0.0.1');
  process.env.FIXTURE_URL = 'http://127.0.0.1:4101/mcp';
  await seed(db, c);
  await provisionRuntime(db);
  auth = await demoIdentity(c.AUTH_ISSUER, c.RESOURCE_URI);
  gateway = new Gateway(db, c, fake);
  http = createApp(gateway, auth).listen(4300, '127.0.0.1');
  token = await auth.token();
});
beforeEach(async () => {
  dispatches = 0;
  behavior = async () => ({ content: [{ type: 'text', text: 'ok' }] });
  // Fixture maintenance only: production exposes no taint-reset API.
  await db.pool.query('DELETE FROM audit_events');
  await db.pool.query('DELETE FROM audit_heads');
  await db.pool.query('DELETE FROM operations');
  await db.pool.query(
    'UPDATE delegations SET enabled=true,read_private=false,read_untrusted=false,active_operation=NULL,agent_policy=$1,owner_policy=$1',
    [defaultPolicy],
  );
  for (const [name, definition] of Object.entries(tools))
    await db.pool.query('UPDATE tool_pins SET approved_hash=$1,definition=$2 WHERE tool_name=$3', [
      definitionHash(definition),
      definition,
      name,
    ]);
});
afterAll(async () => {
  if (http) {
    http.closeAllConnections();
    await new Promise<void>((r) => http.close(() => r()));
  }
  if (fixture) {
    fixture.closeAllConnections();
    await new Promise<void>((r) => fixture.close(() => r()));
  }
  await db.close();
});

describe('durable enforcement on real CockroachDB', () => {
  it('uses a restricted runtime that cannot mutate history but can dispatch audited calls', async () => {
    await expect(assertRuntimePermissions(db)).rejects.toThrow('refusing startup');
    const url = new URL(c.DATABASE_URL);
    url.username = 'gateway_runtime';
    const runtime = new Database(url.toString());
    try {
      await assertRuntimePermissions(runtime);
      await new Gateway(runtime, c, fake).call(identity, 'github', 'list_issues', args());
      expect(dispatches).toBe(1);
    } finally {
      await runtime.close();
    }
  });
  it('records intent before dispatch and replays a stable identity without a second effect', async () => {
    behavior = async () => {
      expect(
        (await db.pool.query("SELECT * FROM audit_events WHERE event->>'kind'='dispatch_intent'"))
          .rows,
      ).toHaveLength(1);
      return { ok: true };
    };
    const input = args();
    const first = await gateway.call(identity, 'github', 'create_issue', {
      ...input,
      title: 'hello',
      body: 'world',
    });
    expect(
      await gateway.call(identity, 'github', 'create_issue', {
        ...input,
        title: 'hello',
        body: 'world',
      }),
    ).toEqual(first);
    expect(dispatches).toBe(1);
    expect((await verifyAudit(db, demoIds.delegation)).valid).toBe(true);
    expect(
      (await db.pool.query('SELECT result_envelope FROM operations')).rows[0].result_envelope,
    ).not.toContain('world');
  });
  it('binds operation identity to arguments and never replays a different request', async () => {
    const input = args();
    await gateway.call(identity, 'github', 'list_issues', input);
    await expect(
      gateway.call(identity, 'github', 'list_issues', { ...input, repo: 'private' }),
    ).rejects.toThrow('operation_conflict');
    expect(dispatches).toBe(1);
  });
  it('retains taint across fresh JWTs and gateway instances; no client run ID can clear it', async () => {
    await gateway.call(
      identity,
      'github',
      'get_file_contents',
      args({ repo: 'private', path: 'salary.csv' }),
    );
    const other = new Gateway(db, c, fake);
    await expect(
      other.call(identity, 'github', 'create_issue', args({ title: 'leak', body: 'canary' })),
    ).rejects.toThrow('private_to_external_sink');
    expect(dispatches).toBe(1);
    const freshToken = await auth.token({ jti: randomUUID() });
    expect(
      (
        await fetch('http://127.0.0.1:4300/admin/v1/state', {
          headers: { Authorization: `Bearer ${freshToken}` },
        })
      ).status,
    ).toBe(200);
  });
  it('treats issue reads from any repository outside the controlled public fixture as private', async () => {
    await gateway.call(identity, 'github', 'list_issues', args({ repo: 'private' }));
    await expect(
      gateway.call(identity, 'github', 'create_issue', args({ title: 'leak', body: 'issue text' })),
    ).rejects.toThrow('private_to_external_sink');
    expect(dispatches).toBe(1);
  });
  it('reserves source taint before parallel sink admission and serializes active calls', async () => {
    let release!: () => void;
    const pending = new Promise<void>((r) => {
      release = r;
    });
    let entered!: () => void;
    const ready = new Promise<void>((r) => {
      entered = r;
    });
    behavior = async () => {
      entered();
      await pending;
      return { private: 'canary' };
    };
    const read = gateway.call(
      identity,
      'github',
      'get_file_contents',
      args({ repo: 'private', path: 'salary.csv' }),
    );
    await ready;
    await expect(
      new Gateway(db, c, fake).call(
        identity,
        'github',
        'create_issue',
        args({ title: 'leak', body: 'x' }),
      ),
    ).rejects.toThrow('private_to_external_sink');
    await expect(gateway.call(identity, 'github', 'list_issues', args())).rejects.toThrow(
      'delegation_busy',
    );
    release();
    await read;
    expect(dispatches).toBe(1);
  });
  it('never redispatches writes after an upstream timeout', async () => {
    behavior = async () => {
      throw new Error('response lost after upstream effect');
    };
    const input = args({ title: 'write', body: 'data' });
    await expect(gateway.call(identity, 'github', 'create_issue', input)).rejects.toThrow(
      'upstream_outcome_unknown',
    );
    await expect(gateway.call(identity, 'github', 'create_issue', input)).rejects.toThrow(
      'operation_unknown',
    );
    expect(dispatches).toBe(1);
  });
  it('does not record an upstream tool error as a successful operation', async () => {
    behavior = async () => ({
      isError: true,
      content: [{ type: 'text', text: 'remote failure; effect may have occurred' }],
    });
    await expect(
      gateway.call(identity, 'github', 'create_issue', args({ title: 'x', body: 'x' })),
    ).rejects.toThrow('upstream_outcome_unknown');
    expect((await db.pool.query('SELECT state FROM operations')).rows[0].state).toBe('unknown');
    expect(dispatches).toBe(1);
  });
  it('recovers an expired dispatch as unknown and fences stale completion', async () => {
    let release!: () => void;
    let entered!: () => void;
    const ready = new Promise<void>((r) => {
      entered = r;
    });
    behavior = async () => {
      entered();
      await new Promise<void>((r) => {
        release = r;
      });
      return { effect: 'already happened' };
    };
    const input = args({ title: 'write', body: 'data' });
    const call = gateway.call(identity, 'github', 'create_issue', input);
    await ready;
    await db.pool.query("UPDATE operations SET deadline=now()-INTERVAL '1 second'");
    await new Gateway(db, c, fake).recover();
    release();
    await expect(call).rejects.toThrow('operation_fenced');
    expect((await db.pool.query('SELECT state FROM operations')).rows[0].state).toBe('unknown');
    await expect(gateway.call(identity, 'github', 'create_issue', input)).rejects.toThrow(
      'operation_unknown',
    );
    expect(dispatches).toBe(1);
  });
  it('denies changed tool definitions before any dispatch', async () => {
    await db.pool.query("UPDATE tool_pins SET approved_hash='old'");
    await expect(gateway.call(identity, 'github', 'list_issues', args())).rejects.toThrow(
      'tool_definition_changed',
    );
    expect(dispatches).toBe(0);
  });
  it('checks owner entitlement independently from agent policy', async () => {
    await db.pool.query("UPDATE delegations SET owner_policy='forbid(principal,action,resource);'");
    await expect(gateway.call(identity, 'github', 'list_issues', args())).rejects.toThrow(
      'owner:policy',
    );
    expect(dispatches).toBe(0);
  });
  it('revocation prevents the next admission even with a valid unexpired token', async () => {
    await db.pool.query('UPDATE delegations SET enabled=false');
    await expect(gateway.call(identity, 'github', 'list_issues', args())).rejects.toThrow(
      'delegation_disabled',
    );
    expect(dispatches).toBe(0);
  });
  it('separates subjects sharing an OAuth client and rejects cross-owner connector links', async () => {
    await expect(
      gateway.call({ ...identity, subject: 'another-user' }, 'github', 'list_issues', args()),
    ).rejects.toThrow('delegation_disabled');
    const foreign = randomUUID();
    await db.pool.query('INSERT INTO users VALUES($1,$2,$3,$3)', [
      foreign,
      identity.issuer,
      foreign,
    ]);
    await db.pool.query('UPDATE connectors SET owner_id=$1', [foreign]);
    try {
      await expect(gateway.call(identity, 'github', 'list_issues', args())).rejects.toThrow(
        'connector_unavailable',
      );
    } finally {
      await db.pool.query('UPDATE connectors SET owner_id=$1', [demoIds.owner]);
    }
  });
  it('detects edited audit history and a deleted suffix against its retained head', async () => {
    await gateway.call(identity, 'github', 'list_issues', args());
    await db.pool.query("UPDATE audit_events SET event='{}' WHERE seq=1");
    expect((await verifyAudit(db, demoIds.delegation)).valid).toBe(false);
    await db.pool.query('DELETE FROM audit_events');
    expect((await verifyAudit(db, demoIds.delegation)).valid).toBe(false);
  });
  it('retries database serialization failures without retrying network dispatch', async () => {
    let attempts = 0;
    await db.tx(async (tx) => {
      attempts++;
      if (attempts === 1) throw Object.assign(new Error('serialization'), { code: '40001' });
      await tx.query('SELECT 1');
    });
    expect(attempts).toBe(2);
    await gateway.call(identity, 'github', 'list_issues', args());
    expect(dispatches).toBe(1);
  });
  it('fails before dispatch when the durable audit write fails', async () => {
    await db.pool.query('ALTER TABLE audit_events RENAME TO audit_events_unavailable');
    try {
      await expect(
        gateway.call(identity, 'github', 'create_issue', args({ title: 'x', body: 'x' })),
      ).rejects.toThrow();
      expect(dispatches).toBe(0);
    } finally {
      await db.pool.query('ALTER TABLE audit_events_unavailable RENAME TO audit_events');
    }
    expect((await db.pool.query('SELECT * FROM operations')).rows).toHaveLength(0);
  });
  it('withholds results after a completion audit outage and recovers without repeating an effect', async () => {
    const input = args({ title: 'effect', body: 'data' });
    behavior = async () => {
      await db.pool.query('ALTER TABLE audit_events RENAME TO audit_events_unavailable');
      return { private: 'must not be delivered' };
    };
    try {
      await expect(gateway.call(identity, 'github', 'create_issue', input)).rejects.toThrow(
        'upstream_outcome_unknown',
      );
    } finally {
      await db.pool.query('ALTER TABLE audit_events_unavailable RENAME TO audit_events');
    }
    await db.pool.query("UPDATE operations SET deadline=now()-INTERVAL '1 second'");
    await gateway.recover();
    await expect(gateway.call(identity, 'github', 'create_issue', input)).rejects.toThrow(
      'operation_unknown',
    );
    expect(dispatches).toBe(1);
    expect(
      (await db.pool.query('SELECT result_envelope FROM operations')).rows[0].result_envelope,
    ).toBeNull();
  });
  it('survives SIGKILL after an actual MCP upstream effect without redispatch on recovery', async () => {
    let entered!: () => void;
    const ready = new Promise<void>((r) => {
      entered = r;
    });
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    const slow = fixtureApp('local-fixture-only', {
      beforeReturn: async (name) => {
        if (name === 'create_issue') {
          entered();
          await gate;
        }
      },
    });
    const upstreamServer = slow.app.listen(4103, '127.0.0.1');
    const connector = (
      await db.pool.query('SELECT * FROM connectors WHERE id=$1', [demoIds.connector])
    ).rows[0];
    await db.pool.query("UPDATE connectors SET endpoint='http://127.0.0.1:4103/mcp' WHERE id=$1", [
      connector.id,
    ]);
    const actual = new McpUpstream(c);
    const definition = await actual.definition(
      { ...connector, endpoint: 'http://127.0.0.1:4103/mcp' },
      'create_issue',
    );
    await db.pool.query('UPDATE tool_pins SET approved_hash=$1 WHERE tool_name=$2', [
      definitionHash(definition),
      'create_issue',
    ]);
    const operationId = randomUUID();
    const worker = spawn(
      process.execPath,
      ['--import', 'tsx', 'tests/helpers/dispatch-worker.ts'],
      {
        env: {
          ...process.env,
          MODE: 'demo',
          DATABASE_URL: c.DATABASE_URL,
          AUTH_ISSUER: c.AUTH_ISSUER,
          AUTH_JWKS_URL: c.AUTH_JWKS_URL,
          RESOURCE_URI: c.RESOURCE_URI,
          CREDENTIAL_MASTER_KEY: c.masterKey.toString('hex'),
          AUDIT_HMAC_KEY: c.auditKey.toString('hex'),
          OPERATION_ID: operationId,
        },
        stdio: 'ignore',
      },
    );
    try {
      await Promise.race([
        ready,
        new Promise((_, reject) =>
          setTimeout(
            () => reject(new Error('Worker never reached upstream effect')),
            10_000,
          ).unref(),
        ),
      ]);
      expect(slow.artifacts).toHaveLength(1);
      const exited = new Promise<void>((resolve) => worker.once('exit', () => resolve()));
      worker.kill('SIGKILL');
      await exited;
      release();
      await db.pool.query("UPDATE operations SET deadline=now()-INTERVAL '1 second' WHERE id=$1", [
        operationId,
      ]);
      const restarted = new Gateway(db, c, actual);
      await restarted.recover();
      await expect(
        restarted.call(identity, 'github', 'create_issue', {
          operationId,
          owner: 'demo',
          repo: 'public',
          title: 'Crash-test effect',
          body: 'Synthetic subprocess crash test',
        }),
      ).rejects.toThrow('operation_unknown');
      expect(slow.artifacts).toHaveLength(1);
      expect((await verifyAudit(db, demoIds.delegation)).valid).toBe(true);
    } finally {
      worker.kill('SIGKILL');
      release();
      upstreamServer.closeAllConnections();
      await new Promise<void>((r) => upstreamServer.close(() => r()));
      await db.pool.query('UPDATE connectors SET endpoint=$1 WHERE id=$2', [
        connector.endpoint,
        connector.id,
      ]);
    }
  });
});
describe('HTTP authentication and real MCP protocol', () => {
  it('exposes uncertain outcomes separately from denials and records request latency once', async () => {
    const client = new Client(
      { name: 'metrics-client', version: '1' },
      { versionNegotiation: { mode: 'auto' } },
    );
    await client.connect(
      new StreamableHTTPClientTransport(new URL(c.RESOURCE_URI), {
        requestInit: { headers: { Authorization: `Bearer ${token}` } },
      }),
    );
    const readMetrics = async () =>
      (
        await fetch('http://127.0.0.1:4300/metrics', {
          headers: { Authorization: `Bearer ${token}` },
        })
      ).text();
    const count = (text: string) =>
      Number(/^gateway_tool_duration_seconds_count (\d+)$/m.exec(text)?.[1] ?? 0);
    try {
      const before = await readMetrics();
      behavior = async () => {
        throw new Error('response lost after effect');
      };
      const result = await client.callTool({
        name: 'github__create_issue',
        arguments: args({ title: 'uncertain', body: 'synthetic' }),
      });
      expect(result.isError).toBe(true);
      const after = await readMetrics();
      expect(after).toContain('gateway_tool_calls_total{outcome="unknown"} 1');
      expect(after).not.toContain('denied_or_unknown');
      expect(count(after) - count(before)).toBe(1);
    } finally {
      await client.close();
    }
  });
  it('serves protected resource metadata and correct invalid-token challenge', async () => {
    const r = await fetch('http://127.0.0.1:4300/admin/v1/state');
    expect(r.status).toBe(401);
    expect(r.headers.get('www-authenticate')).toContain('resource_metadata');
    expect(
      (await (await fetch('http://127.0.0.1:4300/.well-known/oauth-protected-resource/mcp')).json())
        .resource,
    ).toBe(c.RESOURCE_URI);
  });
  it('rejects signed wrong-audience tokens and insufficient scopes', async () => {
    const wrong = await auth.token({ aud: 'https://other.example/mcp' });
    expect(
      (
        await fetch('http://127.0.0.1:4300/admin/v1/state', {
          headers: { Authorization: `Bearer ${wrong}` },
        })
      ).status,
    ).toBe(401);
    const expired = await auth.token({ exp: Math.floor(Date.now() / 1000) - 60 });
    expect(
      (
        await fetch('http://127.0.0.1:4300/admin/v1/state', {
          headers: { Authorization: `Bearer ${expired}` },
        })
      ).status,
    ).toBe(401);
    const narrow = await auth.token({ scope: 'other' });
    expect(
      (
        await fetch('http://127.0.0.1:4300/admin/v1/state', {
          headers: { Authorization: `Bearer ${narrow}` },
        })
      ).status,
    ).toBe(403);
  });
  it('blocks cross-origin browser writes and invalid admin roles', async () => {
    expect(
      (
        await fetch('http://127.0.0.1:4300/demo/login', {
          method: 'POST',
          headers: { Origin: 'https://attacker.example' },
        })
      ).status,
    ).toBe(403);
    const user = await auth.token({ realm_access: { roles: [] } });
    expect(
      (
        await fetch('http://127.0.0.1:4300/admin/v1/state', {
          headers: { Authorization: `Bearer ${user}` },
        })
      ).status,
    ).toBe(403);
  });
  it('restricts an administrator to their own records even when they share the same client', async () => {
    const subject = randomUUID();
    await db.pool.query('INSERT INTO users VALUES($1,$2,$3,$3)', [
      randomUUID(),
      identity.issuer,
      subject,
    ]);
    const foreign = await auth.token({ sub: subject });
    const headers = { Authorization: `Bearer ${foreign}` };
    const state = await (await fetch('http://127.0.0.1:4300/admin/v1/state', { headers })).json();
    expect(state.delegations).toEqual([]);
    expect(state.connectors).toEqual([]);
    expect(state.events).toEqual([]);
    const denied = await fetch(`http://127.0.0.1:4300/admin/v1/delegations/${demoIds.delegation}`, {
      method: 'PATCH',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: false }),
    });
    expect(denied.status).toBe(404);
  });
  it('connects with the official SDK, lists private-cache tools, and calls through the gateway', async () => {
    const client = new Client(
      { name: 'integration-client', version: '1.0' },
      { versionNegotiation: { mode: 'auto' } },
    );
    await client.connect(
      new StreamableHTTPClientTransport(new URL(c.RESOURCE_URI), {
        requestInit: { headers: { Authorization: `Bearer ${token}` } },
      }),
    );
    try {
      const list = await client.listTools();
      expect(list.tools).toHaveLength(3);
      expect(list.cacheScope).toBe('private');
      const result = await client.callTool({ name: 'github__list_issues', arguments: args() });
      expect(result.isError).not.toBe(true);
      expect(dispatches).toBe(1);
    } finally {
      await client.close();
    }
  });
  it('checks header/body consistency before tool execution', async () => {
    const response = await fetch(c.RESOURCE_URI, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        'MCP-Protocol-Version': '2026-07-28',
        'Mcp-Method': 'tools/call',
        'Mcp-Name': 'github__create_issue',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'github__list_issues',
          arguments: args(),
          _meta: {
            'io.modelcontextprotocol/protocolVersion': '2026-07-28',
            'io.modelcontextprotocol/clientCapabilities': {},
          },
        },
      }),
    });
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect((await response.json()).error.code).toBe(-32020);
    expect(dispatches).toBe(0);
  });
  it('rejects oversized request bodies with 413', async () => {
    const response = await fetch(c.RESOURCE_URI, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ oversized: 'x'.repeat(70_000) }),
    });
    expect(response.status).toBe(413);
    expect(dispatches).toBe(0);
  });
  it('uses the official MCP client to reach the actual synthetic upstream', async () => {
    const connector = (
      await db.pool.query('SELECT * FROM connectors WHERE id=$1', [demoIds.connector])
    ).rows[0];
    const real = new McpUpstream(c);
    expect((await real.definition(connector, 'get_file_contents')).name).toBe('get_file_contents');
    expect(
      JSON.stringify(
        await real.call(connector, 'get_file_contents', {
          owner: 'demo',
          repo: 'private',
          path: 'salary.csv',
        }),
      ),
    ).toContain('SYNTHETIC_PRIVATE_CANARY');
  });
  it('preserves bounded SSE responses from an MCP upstream', async () => {
    const upstreamServer = fixtureApp('local-fixture-only', { responseMode: 'sse' }).app.listen(
      4104,
      '127.0.0.1',
    );
    const connector = (
      await db.pool.query('SELECT * FROM connectors WHERE id=$1', [demoIds.connector])
    ).rows[0];
    try {
      const real = new McpUpstream(c);
      const remote = { ...connector, endpoint: 'http://127.0.0.1:4104/mcp' };
      expect((await real.definition(remote, 'list_issues')).name).toBe('list_issues');
      expect(
        JSON.stringify(await real.call(remote, 'list_issues', { owner: 'demo', repo: 'public' })),
      ).toContain('Bug report');
    } finally {
      upstreamServer.closeAllConnections();
      await new Promise<void>((r) => upstreamServer.close(() => r()));
    }
  });
});
