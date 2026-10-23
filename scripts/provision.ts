import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { config } from '../src/config.js';
import { Database } from '../src/db.js';
import { seal } from '../src/crypto.js';
import { validatePolicy } from '../src/policy.js';

// Trusted operator CLI. Tokens are read from environment, not command-line arguments or JSON.
const input = z
  .object({
    ownerSubject: z.string().min(1),
    agentSubject: z.string().min(1),
    clientId: z.string().min(1),
    agentName: z.string().min(1),
    connectorName: z.string().regex(/^[a-z][a-z0-9-]{0,30}$/),
    agentPolicy: z.string(),
    ownerPolicy: z.string(),
  })
  .strict()
  .parse(JSON.parse(await readFile(process.argv[2] ?? 'provision.json', 'utf8')));
const c = config();
validatePolicy(input.agentPolicy);
validatePolicy(input.ownerPolicy);
if (!process.env.GITHUB_TOKEN || !process.env.MIGRATION_DATABASE_URL)
  throw new Error('GITHUB_TOKEN and MIGRATION_DATABASE_URL required');
const db = new Database(process.env.MIGRATION_DATABASE_URL);
try {
  const owner = randomUUID(),
    delegation = randomUUID(),
    connector = randomUUID();
  await db.tx(async (tx) => {
    const user = (
      await tx.query<{ id: string }>(
        `INSERT INTO users(id,issuer,subject,name) VALUES($1,$2,$3,$3)
      ON CONFLICT(issuer,subject) DO UPDATE SET name=excluded.name RETURNING id`,
        [owner, c.AUTH_ISSUER, input.ownerSubject],
      )
    ).rows[0]!;
    await tx.query(
      `INSERT INTO connectors(id,owner_id,name,kind,endpoint,credential) VALUES($1,$2,$3,'github','https://api.githubcopilot.com/mcp/',$4)`,
      [
        connector,
        user.id,
        input.connectorName,
        seal(c.masterKey, { token: process.env.GITHUB_TOKEN }, `connector:${connector}`),
      ],
    );
    await tx.query(
      `INSERT INTO delegations(id,owner_id,agent_name,issuer,subject,client_id,agent_policy,owner_policy) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        delegation,
        user.id,
        input.agentName,
        c.AUTH_ISSUER,
        input.agentSubject,
        input.clientId,
        input.agentPolicy,
        input.ownerPolicy,
      ],
    );
    await tx.query('INSERT INTO delegation_connectors VALUES($1,$2)', [delegation, connector]);
    await tx.query('INSERT INTO policy_versions VALUES($1,1,$2,$3,$4,now())', [
      delegation,
      input.agentPolicy,
      input.ownerPolicy,
      user.id,
    ]);
  });
  console.log(
    JSON.stringify({
      delegation,
      connector,
      next: 'Review and approve tool definitions in the console. No tools are auto-approved.',
    }),
  );
} finally {
  await db.close();
}
