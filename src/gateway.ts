import type { Config } from './config.js';
import type { Database, Tx } from './db.js';
import type { Identity } from './auth.js';
import { appendAudit } from './audit.js';
import { keyedDigest, seal, unseal } from './crypto.js';
import { GatewayError, invariant } from './errors.js';
import { evaluate, type PolicyFacts } from './policy.js';
import { filterResult, parseArguments, toolFor } from './tools.js';
import { definitionHash, type Connector, type Upstream } from './upstream.js';

export interface Delegation {
  id: string;
  owner_id: string;
  agent_name: string;
  enabled: boolean;
  read_private: boolean;
  read_untrusted: boolean;
  active_operation: string | null;
  agent_policy: string;
  owner_policy: string;
  policy_version: number;
}
interface Operation {
  id: string;
  delegation_id: string;
  connector_id: string;
  tool_name: string;
  args_digest: string;
  state: string;
  result_envelope: string | null;
}
type ToolResult = ReturnType<typeof filterResult>;

export class Gateway {
  constructor(
    readonly db: Database,
    readonly c: Config,
    readonly upstream: Upstream,
  ) {}
  async delegation(identity: Identity, tx: Tx = this.db.pool, lock = false): Promise<Delegation> {
    const { rows } = await tx.query<Delegation>(
      `SELECT * FROM delegations WHERE issuer=$1 AND subject=$2 AND client_id=$3 ${lock ? 'FOR UPDATE' : ''}`,
      [identity.issuer, identity.subject, identity.clientId],
    );
    invariant(rows[0]?.enabled, 'delegation_disabled');
    return rows[0];
  }
  async connectors(d: Delegation, tx: Tx = this.db.pool) {
    return (
      await tx.query<Connector>(
        `SELECT c.* FROM connectors c JOIN delegation_connectors dc ON dc.connector_id=c.id
      WHERE dc.delegation_id=$1 AND c.owner_id=$2 AND c.enabled=true ORDER BY c.name`,
        [d.id, d.owner_id],
      )
    ).rows;
  }
  decision(d: Delegation, name: string, repo: string) {
    const { effect } = toolFor(name);
    const context: PolicyFacts = {
      repo,
      readPrivate: d.read_private,
      readUntrusted: d.read_untrusted,
    };
    const agent = evaluate(d.agent_policy, 'Agent', d.id, name, effect, context);
    const owner = evaluate(d.owner_policy, 'User', d.owner_id, name, effect, context);
    // Mandatory boundary cannot be weakened by editing Cedar policy.
    if (effect === 'write' && d.read_private)
      return { allowed: false, reasons: ['private_to_external_sink'] };
    return {
      allowed: agent.allowed && owner.allowed,
      reasons: [
        ...agent.reasons.map((r) => `agent:${r}`),
        ...owner.reasons.map((r) => `owner:${r}`),
      ],
    };
  }
  async call(
    identity: Identity,
    connectorName: string,
    name: string,
    args: unknown,
  ): Promise<ToolResult> {
    const spec = toolFor(name);
    const parsed = parseArguments(name, args);
    const d = await this.delegation(identity);
    const connector = (await this.connectors(d)).find((c) => c.name === connectorName);
    invariant(connector, 'connector_unavailable');
    const argsDigest = keyedDigest(this.c.auditKey, parsed.upstream);
    // Refresh immediately before admission. Pinning detects metadata drift, not changed server behavior.
    const definition = await this.upstream.definition(connector, name);
    const hash = definitionHash(definition);
    const reservation = await this.db.tx(async (tx) => {
      const current = await this.delegation(identity, tx, true);
      invariant(
        (await this.connectors(current, tx)).some((c) => c.id === connector.id),
        'connector_unavailable',
      );
      const pin = (
        await tx.query<{ approved_hash: string }>(
          'SELECT approved_hash FROM tool_pins WHERE connector_id=$1 AND tool_name=$2',
          [connector.id, name],
        )
      ).rows[0];
      const decision = this.decision(current, name, parsed.repo);
      const denial = !pin
        ? 'tool_not_approved'
        : pin.approved_hash !== hash
          ? 'tool_definition_changed'
          : !decision.allowed
            ? decision.reasons.join(',')
            : null;
      if (denial) {
        await appendAudit(tx, current.id, {
          kind: 'denied',
          tool: `${connectorName}__${name}`,
          operationId: parsed.id,
          reason: denial,
          policyVersion: current.policy_version,
          argsDigest,
        });
        return { denied: denial };
      }
      const existing = (
        await tx.query<Operation>('SELECT * FROM operations WHERE id=$1', [parsed.id])
      ).rows[0];
      if (existing) {
        invariant(
          existing.delegation_id === current.id &&
            existing.connector_id === connector.id &&
            existing.tool_name === name &&
            existing.args_digest === argsDigest,
          'operation_conflict',
          409,
        );
        if (existing.state === 'succeeded' && existing.result_envelope)
          return { replay: existing.result_envelope };
        return { denied: `operation_${existing.state}` };
      }
      if (current.active_operation) {
        await appendAudit(tx, current.id, {
          kind: 'denied',
          operationId: parsed.id,
          tool: `${connectorName}__${name}`,
          reason: 'delegation_busy',
          argsDigest,
        });
        return { denied: 'delegation_busy' };
      }
      // Conservative taint reservation BEFORE any dispatch. Failed reads can overtaint, never undertaint.
      const privateSource =
        spec.source === 'private' ||
        (name === 'list_issues' && (connector.kind === 'github' || parsed.repo !== 'demo/public'));
      await tx.query(
        `UPDATE delegations SET active_operation=$2, read_private=read_private OR $3,
        read_untrusted=read_untrusted OR $4 WHERE id=$1`,
        [current.id, parsed.id, privateSource, spec.source === 'untrusted'],
      );
      await tx.query(
        `INSERT INTO operations(id,delegation_id,connector_id,tool_name,args_digest,pin_hash,policy_version,state)
        VALUES($1,$2,$3,$4,$5,$6,$7,'dispatching')`,
        [parsed.id, current.id, connector.id, name, argsDigest, hash, current.policy_version],
      );
      await appendAudit(tx, current.id, {
        kind: 'dispatch_intent',
        operationId: parsed.id,
        tool: `${connectorName}__${name}`,
        argsDigest,
        pinHash: hash,
        policyVersion: current.policy_version,
        reasons: decision.reasons,
      });
      return { admitted: true };
    });
    if ('denied' in reservation) throw new GatewayError(reservation.denied!, 403);
    if ('replay' in reservation)
      return unseal<ToolResult>(this.c.masterKey, reservation.replay!, `operation:${parsed.id}`);
    // NEVER put this call in the serializable retry closure. Unknown outcomes are never redispatched.
    try {
      const raw = await this.upstream.call(connector, name, parsed.upstream);
      if (raw && typeof raw === 'object' && 'isError' in raw && raw.isError === true)
        throw new GatewayError('upstream_tool_error', 502);
      const result = filterResult(raw);
      await this.finish(
        d.id,
        parsed.id,
        'succeeded',
        seal(this.c.masterKey, result, `operation:${parsed.id}`),
        null,
      );
      return result;
    } catch (error) {
      // Includes output-filter and completion-write failure: a remote effect may already exist.
      await this.finish(d.id, parsed.id, 'unknown', null, 'upstream_outcome_unknown').catch(
        () => undefined,
      );
      if (error instanceof GatewayError && error.code === 'operation_fenced') throw error;
      throw new GatewayError('upstream_outcome_unknown', 502);
    }
  }
  private async finish(
    delegation: string,
    id: string,
    state: 'succeeded' | 'unknown',
    result: string | null,
    reason: string | null,
  ) {
    await this.db.tx(async (tx) => {
      const d = (
        await tx.query<Delegation>('SELECT * FROM delegations WHERE id=$1 FOR UPDATE', [delegation])
      ).rows[0];
      invariant(d?.active_operation === id, 'operation_fenced', 409);
      const updated = await tx.query(
        `UPDATE operations SET state=$2, result_envelope=$3, reason=$4, updated_at=now()
        WHERE id=$1 AND state='dispatching' AND deadline>now() RETURNING id`,
        [id, state, result, reason],
      );
      invariant(updated.rowCount === 1, 'operation_fenced', 409);
      await appendAudit(tx, delegation, { kind: 'completion', operationId: id, state, reason });
      await tx.query('UPDATE delegations SET active_operation=NULL WHERE id=$1', [delegation]);
    });
  }
  async recover() {
    // Recovery marks uncertainty; it never authorizes a replacement remote invocation.
    const ids = (
      await this.db.pool.query<{
        delegation_id: string;
        id: string;
      }>(`SELECT id,delegation_id FROM operations
      WHERE state='dispatching' AND deadline<now() LIMIT 100`)
    ).rows;
    for (const op of ids)
      await this.db.tx(async (tx) => {
        await tx.query('SELECT id FROM delegations WHERE id=$1 FOR UPDATE', [op.delegation_id]);
        const update = await tx.query(
          `UPDATE operations SET state='unknown',reason='dispatch_deadline_expired',updated_at=now()
        WHERE id=$1 AND state='dispatching' AND deadline<now() RETURNING id`,
          [op.id],
        );
        if (update.rowCount) {
          await appendAudit(tx, op.delegation_id, {
            kind: 'recovery',
            operationId: op.id,
            state: 'unknown',
          });
          await tx.query(
            'UPDATE delegations SET active_operation=NULL WHERE id=$1 AND active_operation=$2',
            [op.delegation_id, op.id],
          );
        }
      });
    return ids.length;
  }
}
