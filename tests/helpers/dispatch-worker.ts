import { config } from '../../src/config.js';
import { Database } from '../../src/db.js';
import { Gateway } from '../../src/gateway.js';
import { McpUpstream } from '../../src/upstream.js';
const c = config();
const db = new Database(c.DATABASE_URL);
try {
  await new Gateway(db, c, new McpUpstream(c)).call(
    { issuer: c.AUTH_ISSUER, subject: 'demo-owner', clientId: 'demo-client', admin: false },
    'github',
    'create_issue',
    {
      operationId: process.env.OPERATION_ID,
      owner: 'demo',
      repo: 'public',
      title: 'Crash-test effect',
      body: 'Synthetic subprocess crash test',
    },
  );
} finally {
  await db.close();
}
