import { access, mkdir } from 'node:fs/promises';
import { spawn, type ChildProcess } from 'node:child_process';
import { Database } from '../src/db.js';
import { config } from '../src/config.js';
import { migrate } from './migrate.js';
import { seed } from './seed.js';
import { provisionRuntime } from './runtime-role.js';
import { fixtureApp } from '../src/fixture.js';
import { localKeys } from './local-keys.js';

await mkdir('.local', { recursive: true });
const keysFile = '.local/demo-keys.json';
const keys = await localKeys(keysFile);
let database: ChildProcess | undefined;
const adminUrl =
  process.env.DEMO_DATABASE_URL ?? 'postgresql://root@127.0.0.1:26267/defaultdb?sslmode=disable';
let probe = new Database(adminUrl);
try {
  await probe.pool.query('SELECT 1');
} catch {
  await probe.close();
  try {
    await access('.local/bin/cockroach');
  } catch {
    throw new Error(
      'Run bash scripts/local-db.sh to install the pinned local database, or docker compose up -d db.',
    );
  }
  database = spawn(
    '.local/bin/cockroach',
    [
      'start-single-node',
      '--insecure',
      '--listen-addr=127.0.0.1:26267',
      '--http-addr=127.0.0.1:18081',
      '--store=.local/cockroach-data',
      '--cache=64MiB',
      '--max-sql-memory=128MiB',
      '--log-dir=.local/cockroach-logs',
    ],
    { stdio: 'ignore' },
  );
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 500));
    probe = new Database(adminUrl);
    try {
      await probe.pool.query('SELECT 1');
      break;
    } catch {
      await probe.close();
      if (i === 39) throw new Error('Local database did not start');
    }
  }
}
await probe.pool.query('CREATE DATABASE IF NOT EXISTS gateway_demo');
await probe.close();
const owner = new URL(adminUrl);
owner.pathname = '/gateway_demo';
const env = {
  ...process.env,
  MODE: 'demo',
  AUTH_MODE: 'demo',
  PORT: '3000',
  DATABASE_URL: owner.toString(),
  AUTH_ISSUER: 'http://localhost:3000/demo',
  AUTH_JWKS_URL: 'http://127.0.0.1:3000/demo/jwks',
  RESOURCE_URI: 'http://localhost:3000/mcp',
  CREDENTIAL_MASTER_KEY: keys.master,
  AUDIT_HMAC_KEY: keys.audit,
};
const db = new Database(env.DATABASE_URL);
const fixture = fixtureApp().app.listen(4100, '127.0.0.1');
await migrate(db);
await seed(db, config(env));
await provisionRuntime(db);
await db.close();
const runtime = new URL(env.DATABASE_URL);
runtime.username = 'gateway_runtime';
env.DATABASE_URL = runtime.toString();
const child = spawn(process.execPath, ['--import', 'tsx', 'src/main.ts'], {
  env,
  stdio: 'inherit',
});
console.log(
  '\nScoped MCP Gateway: http://localhost:3000\nSynthetic demo data. Keys and state persist under .local/. Ctrl-C stops the demo.\n',
);
const stop = () => {
  child.kill('SIGTERM');
  fixture.close();
  database?.kill('SIGTERM');
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
child.on('exit', (code) => {
  fixture.close();
  database?.kill('SIGTERM');
  process.exitCode = code ?? 0;
});
