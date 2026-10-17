import { config } from './config.js';
import { Database } from './db.js';
import { Gateway } from './gateway.js';
import { McpUpstream } from './upstream.js';
import { createApp } from './app.js';
import { demoIdentity } from './demo-identity.js';
import { assertRuntimePermissions } from './runtime-permissions.js';

const c = config();
const db = new Database(c.DATABASE_URL);
const gateway = new Gateway(db, c, new McpUpstream(c));
await assertRuntimePermissions(db);
const demo = c.AUTH_MODE === 'demo' ? await demoIdentity(c.AUTH_ISSUER, c.RESOURCE_URI) : undefined;
await gateway.recover();
const server = createApp(gateway, demo).listen(
  c.PORT,
  c.MODE === 'demo' ? '127.0.0.1' : '0.0.0.0',
  () => console.log(`Gateway listening on port ${c.PORT} (${c.MODE})`),
);
server.requestTimeout = 30_000;
server.headersTimeout = 10_000;
server.maxRequestsPerSocket = 100;
const timer = setInterval(() => {
  void gateway.recover().catch(() => console.error('Recovery unavailable'));
}, 10_000).unref();
async function shutdown() {
  clearInterval(timer);
  const deadline = setTimeout(() => process.exit(1), 25_000).unref();
  server.close(() => {
    void db.close().then(() => {
      clearTimeout(deadline);
      process.exit(0);
    });
  });
}
process.on('SIGTERM', () => {
  void shutdown();
});
process.on('SIGINT', () => {
  void shutdown();
});
