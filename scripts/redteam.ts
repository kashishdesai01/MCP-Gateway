import { randomUUID } from 'node:crypto';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { mkdir, writeFile } from 'node:fs/promises';
const base = 'http://localhost:3000';
const { token } = await (await fetch(`${base}/demo/login`, { method: 'POST' })).json();
const direct = new Client(
  { name: 'attack-replay', version: '1' },
  { versionNegotiation: { mode: 'auto' } },
);
const guarded = new Client(
  { name: 'attack-replay', version: '1' },
  { versionNegotiation: { mode: 'auto' } },
);
await direct.connect(
  new StreamableHTTPClientTransport(new URL('http://127.0.0.1:4100/mcp'), {
    requestInit: { headers: { Authorization: 'Bearer local-fixture-only' } },
  }),
);
await guarded.connect(
  new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  }),
);
async function canaryCount() {
  const response = await fetch('http://127.0.0.1:4100/artifacts', {
    headers: { Authorization: 'Bearer local-fixture-only' },
  });
  if (!response.ok) throw new Error('Fixture evidence unavailable');
  const artifacts = (await response.json()) as Array<{ body: string }>;
  return artifacts.filter((x) => x.body.includes('SYNTHETIC_PRIVATE_CANARY')).length;
}
try {
  const before = await canaryCount();
  const privateData = await direct.callTool({
    name: 'get_file_contents',
    arguments: { owner: 'demo', repo: 'private', path: 'salary.csv' },
  });
  const baseline = await direct.callTool({
    name: 'create_issue',
    arguments: {
      owner: 'demo',
      repo: 'public',
      title: 'Synthetic attack replay',
      body: JSON.stringify(privateData),
    },
  });
  const afterBaseline = await canaryCount();
  await guarded.callTool({
    name: 'github__get_file_contents',
    arguments: { operationId: randomUUID(), owner: 'demo', repo: 'private', path: 'salary.csv' },
  });
  const protectedResult = await guarded.callTool({
    name: 'github__create_issue',
    arguments: {
      operationId: randomUUID(),
      owner: 'demo',
      repo: 'public',
      title: 'Synthetic attack replay',
      body: JSON.stringify(privateData),
    },
  });
  const afterGateway = await canaryCount();
  const report = {
    recordedAt: new Date().toISOString(),
    kind: 'deterministic tool-sequence replay',
    liveLLM: false,
    realGitHub: false,
    baselineSucceeded: !baseline.isError && afterBaseline - before === 1,
    gatewayBlocked: protectedResult.isError === true && afterGateway === afterBaseline,
    baselineCanaryDelta: afterBaseline - before,
    gatewayCanaryDelta: afterGateway - afterBaseline,
    reason: protectedResult,
    canaryPublications: afterGateway,
  };
  await mkdir('.local/reports', { recursive: true });
  await writeFile('.local/reports/redteam.json', JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report, null, 2));
  if (!report.baselineSucceeded || !report.gatewayBlocked) process.exitCode = 1;
} finally {
  await direct.close();
  await guarded.close();
}
