import { randomUUID } from 'node:crypto';
import { digest } from './crypto.js';
import type { Database, Tx } from './db.js';
import { traceContext } from './trace.js';

export async function appendAudit(tx: Tx, delegation: string, event: Record<string, unknown>) {
  await tx.query('INSERT INTO audit_heads(delegation_id) VALUES ($1) ON CONFLICT DO NOTHING', [
    delegation,
  ]);
  const { rows } = await tx.query<{ seq: string; hash: string }>(
    'SELECT seq, hash FROM audit_heads WHERE delegation_id=$1 FOR UPDATE',
    [delegation],
  );
  const head = rows[0]!;
  const seq = (BigInt(head.seq) + 1n).toString();
  const ts = (await tx.query<{ ts: string }>('SELECT now()::text AS ts')).rows[0]!.ts;
  const record = {
    v: 1,
    id: randomUUID(),
    ts,
    traceId: traceContext.getStore()?.traceId ?? null,
    ...event,
  };
  const hash = digest({ delegation, seq, prev: head.hash, event: record });
  await tx.query('INSERT INTO audit_events VALUES ($1,$2,$3,$4,$5)', [
    delegation,
    seq,
    record,
    head.hash,
    hash,
  ]);
  await tx.query('UPDATE audit_heads SET seq=$2, hash=$3 WHERE delegation_id=$1', [
    delegation,
    seq,
    hash,
  ]);
  return { seq, hash };
}
export async function verifyAudit(db: Database, delegation: string) {
  return db.tx(async (tx) => {
    const { rows } = await tx.query<{
      seq: string;
      event: unknown;
      prev_hash: string;
      hash: string;
    }>('SELECT * FROM audit_events WHERE delegation_id=$1 ORDER BY seq', [delegation]);
    let prev = 'genesis';
    let seq = 0n;
    for (const row of rows) {
      seq++;
      if (
        row.seq !== seq.toString() ||
        row.prev_hash !== prev ||
        row.hash !== digest({ delegation, seq: row.seq, prev, event: row.event })
      ) {
        return { valid: false, firstBrokenSequence: row.seq, count: rows.length };
      }
      prev = row.hash;
    }
    const head = (
      await tx.query<{ seq: string; hash: string }>(
        'SELECT * FROM audit_heads WHERE delegation_id=$1',
        [delegation],
      )
    ).rows[0];
    return {
      valid: head ? head.hash === prev && head.seq === seq.toString() : seq === 0n,
      count: rows.length,
      seq: seq.toString(),
      hash: prev,
    };
  });
}
