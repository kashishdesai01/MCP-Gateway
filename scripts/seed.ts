import { randomUUID } from 'node:crypto';
import { Database } from '../src/db.js';
import { config, type Config } from '../src/config.js';
import { seal } from '../src/crypto.js';
import { defaultPolicy, validatePolicy } from '../src/policy.js';
import { McpUpstream, definitionHash, type Connector } from '../src/upstream.js';
import { registry } from '../src/tools.js';

export const demoIds = {
  owner: '10000000-0000-4000-8000-000000000001',
  delegation: '20000000-0000-4000-8000-000000000001',
  connector: '30000000-0000-4000-8000-000000000001',
};
export async function seed(db: Database, c: Config) {
  if (c.MODE !== 'demo') throw new Error('Demo seed requires MODE=demo');
  validatePolicy(defaultPolicy);
  const endpoint = process.env.FIXTURE_URL ?? 'http://127.0.0.1:4100/mcp';
  const credential = seal(
    c.masterKey,
    { token: process.env.FIXTURE_TOKEN ?? 'local-fixture-only' },
    `connector:${demoIds.connector}`,
  );
  await db.tx(async (tx) => {
    await tx.query(
      `INSERT INTO users VALUES($1,$2,'demo-owner','Demo operator') ON CONFLICT DO NOTHING`,
      [demoIds.owner, c.AUTH_ISSUER],
    );
    await tx.query(
      `INSERT INTO connectors(id,owner_id,name,kind,endpoint,credential) VALUES($1,$2,'github','fixture',$3,$4)
      ON CONFLICT(id) DO UPDATE SET credential=$4`,
      [demoIds.connector, demoIds.owner, endpoint, credential],
    );
    await tx.query(
      `INSERT INTO delegations(id,owner_id,agent_name,issuer,subject,client_id,agent_policy,owner_policy)
      VALUES($1,$2,'Support triage',$3,'demo-owner','demo-client',$4,$4) ON CONFLICT DO NOTHING`,
      [demoIds.delegation, demoIds.owner, c.AUTH_ISSUER, defaultPolicy],
    );
    await tx.query('INSERT INTO delegation_connectors VALUES($1,$2) ON CONFLICT DO NOTHING', [
      demoIds.delegation,
      demoIds.connector,
    ]);
    await tx.query(
      'INSERT INTO policy_versions VALUES($1,1,$2,$2,$3,now()) ON CONFLICT DO NOTHING',
      [demoIds.delegation, defaultPolicy, demoIds.owner],
    );
  });
  // Bootstrap approval is explicit in this fixture-only seed. Real connectors require console approval.
  const upstream = new McpUpstream(c);
  const connector = (
    await db.pool.query<Connector>('SELECT * FROM connectors WHERE id=$1', [demoIds.connector])
  ).rows[0]!;
  for (const name of Object.keys(registry)) {
    const definition = await upstream.definition(connector, name);
    await db.pool.query(
      `INSERT INTO tool_pins(connector_id,tool_name,approved_hash,definition,approved_by)
      VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`,
      [connector.id, name, definitionHash(definition), definition, demoIds.owner],
    );
  }
  return { ...demoIds, seedReceipt: randomUUID() };
}
if (process.argv[1]?.endsWith('seed.ts')) {
  const c = config();
  const db = new Database(c.DATABASE_URL);
  try {
    console.log(await seed(db, c));
  } finally {
    await db.close();
  }
}
