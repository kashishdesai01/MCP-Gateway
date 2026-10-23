import { randomBytes } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { Database } from '../src/db.js';
import { config } from '../src/config.js';
import { migrate } from './migrate.js';
import { seed } from './seed.js';
import { provisionRuntime } from './runtime-role.js';
import { fixtureApp } from '../src/fixture.js';
import { localKeys } from './local-keys.js';

await mkdir('.local/reports', { recursive: true });
await mkdir('.local/keycloak/data/import', { recursive: true });
let password: string;
try {
  password = (await readFile('.local/oidc-test.env', 'utf8'))
    .split('\n')
    .find((l) => l.startsWith('KEYCLOAK_TEST_PASSWORD='))!
    .split('=')[1]!;
} catch {
  password = randomBytes(24).toString('hex');
}
const keys = await localKeys('.local/oidc-demo-keys.json');
const realm = JSON.parse(await readFile('deploy/keycloak-realm.json', 'utf8'));
realm.clients[0].redirectUris = ['http://localhost:3100/'];
realm.clients[0].webOrigins = ['http://localhost:3100'];
realm.clientScopes[0].protocolMappers[0].config['included.custom.audience'] =
  'http://localhost:3100/mcp';
realm.users = [
  {
    id: 'demo-owner',
    username: 'operator',
    enabled: true,
    email: 'operator@example.invalid',
    emailVerified: true,
    firstName: 'Demo',
    lastName: 'Operator',
    realmRoles: ['gateway-admin'],
    credentials: [{ type: 'password', value: password, temporary: false }],
  },
];
await writeFile('.local/keycloak/data/import/gateway.json', JSON.stringify(realm), { mode: 0o600 });
await writeFile(
  '.local/oidc-test.env',
  `KEYCLOAK_TEST_PASSWORD=${password}\nCONSOLE_BASE_URL=http://localhost:3100\n`,
  { mode: 0o600 },
);
const javaHome = process.env.KEYCLOAK_JAVA_HOME ?? '/opt/homebrew/opt/openjdk@21';
const keycloak = spawn(
  '.local/keycloak/bin/kc.sh',
  [
    'start-dev',
    '--http-host=127.0.0.1',
    '--http-port=18090',
    '--hostname=http://localhost:18090',
    '--import-realm',
  ],
  {
    env: {
      ...process.env,
      JAVA_HOME: javaHome,
      JAVA: `${javaHome}/bin/java`,
      JAVA_OPTS_APPEND: '-Xms64m -Xmx384m',
    },
    stdio: ['ignore', 'ignore', 'inherit'],
  },
);
const childProcess: { current?: ReturnType<typeof spawn> } = {};
let stopped = false;
const stop = () => {
  if (stopped) return;
  stopped = true;
  childProcess.current?.kill('SIGTERM');
  keycloak.kill('SIGTERM');
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
keycloak.on('error', (error) => {
  console.error(error.message);
  process.exitCode = 1;
});
for (let i = 0; i < 120; i++) {
  await new Promise((r) => setTimeout(r, 500));
  try {
    const r = await fetch('http://127.0.0.1:18090/realms/gateway/.well-known/openid-configuration');
    if (r.ok) break;
  } catch {
    /* startup */
  }
  if (i === 119) {
    stop();
    throw new Error('Keycloak startup failed; inspect its local logs');
  }
}
const rootUrl =
  process.env.DEMO_DATABASE_URL ?? 'postgresql://root@127.0.0.1:26267/defaultdb?sslmode=disable';
const root = new Database(rootUrl);
await root.pool.query('CREATE DATABASE IF NOT EXISTS gateway_oidc_demo');
await root.close();
const url = new URL(rootUrl);
url.pathname = '/gateway_oidc_demo';
const env = {
  ...process.env,
  MODE: 'demo',
  AUTH_MODE: 'oidc',
  PORT: '3100',
  DATABASE_URL: url.toString(),
  AUTH_ISSUER: 'http://localhost:18090/realms/gateway',
  AUTH_JWKS_URL: 'http://127.0.0.1:18090/realms/gateway/protocol/openid-connect/certs',
  RESOURCE_URI: 'http://localhost:3100/mcp',
  CREDENTIAL_MASTER_KEY: keys.master,
  AUDIT_HMAC_KEY: keys.audit,
};
const fixture = fixtureApp().app.listen(4102, '127.0.0.1');
process.env.FIXTURE_URL = 'http://127.0.0.1:4102/mcp';
const db = new Database(env.DATABASE_URL);
await migrate(db);
await seed(db, config(env));
await db.pool.query(
  "UPDATE delegations SET client_id='gateway-console' WHERE subject='demo-owner'",
);
await provisionRuntime(db);
await db.close();
url.username = 'gateway_runtime';
env.DATABASE_URL = url.toString();
const child = spawn(process.execPath, ['--import', 'tsx', 'src/main.ts'], {
  env,
  stdio: 'inherit',
});
childProcess.current = child;
child.on('exit', (code) => {
  fixture.close();
  stop();
  process.exitCode = code ?? 0;
});
console.log(
  'OIDC demo: http://localhost:3100. Test credentials are in .local/oidc-test.env (not printed).',
);
