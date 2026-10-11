import { Database } from '../src/db.js';
import { verifyAudit } from '../src/audit.js';
const id = process.argv[2];
if (!id) throw new Error('Usage: npm run audit:verify -- <delegation-uuid>');
const db = new Database(process.env.DATABASE_URL!);
try {
  const result = await verifyAudit(db, id);
  console.log(JSON.stringify(result, null, 2));
  if (!result.valid) process.exitCode = 1;
} finally {
  await db.close();
}
