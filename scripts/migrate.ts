import { readFile } from 'node:fs/promises';
import { Database } from '../src/db.js';
export async function migrate(db: Database) {
  const sql = await readFile(new URL('../migrations/001_init.sql', import.meta.url), 'utf8');
  await db.tx(async (tx) => {
    await tx.query(sql);
  });
}
if (process.argv[1]?.endsWith('migrate.ts')) {
  const db = new Database(
    process.env.DATABASE_URL ?? 'postgresql://root@127.0.0.1:26267/gateway_demo?sslmode=disable',
  );
  try {
    await migrate(db);
    console.log('Schema migrated');
  } finally {
    await db.close();
  }
}
