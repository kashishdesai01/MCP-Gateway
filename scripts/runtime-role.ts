import type { Database } from '../src/db.js';
export async function provisionRuntime(db: Database) {
  // Run with a migration owner; identifiers are fixed, never interpolated from input.
  await db.pool.query('CREATE USER IF NOT EXISTS gateway_runtime');
  const name = (await db.pool.query<{ name: string }>('SELECT current_database() AS name')).rows[0]!
    .name;
  if (!/^gateway_[a-z0-9_]+$/.test(name))
    throw new Error('Local runtime provisioning requires a gateway_* database');
  await db.pool.query(`GRANT CONNECT ON DATABASE "${name}" TO gateway_runtime`);
  await db.pool.query('GRANT USAGE ON SCHEMA public TO gateway_runtime');
  await db.pool.query('GRANT SELECT ON users,connectors,delegation_connectors TO gateway_runtime');
  await db.pool.query(
    'GRANT SELECT,INSERT,UPDATE ON delegations,tool_pins,operations,audit_heads TO gateway_runtime',
  );
  await db.pool.query('GRANT SELECT,INSERT ON audit_events,policy_versions TO gateway_runtime');
}
