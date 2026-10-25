import { performance } from 'node:perf_hooks';
import { randomUUID } from 'node:crypto';
import { writeFile, mkdir } from 'node:fs/promises';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

const gateway = process.env.GATEWAY_URL ?? 'http://localhost:3000/mcp';
const token =
  process.env.BENCH_TOKEN ??
  (await (await fetch(new URL('/demo/login', gateway), { method: 'POST' })).json()).token;
const n = Number(process.env.BENCH_N ?? 100);
if (!Number.isInteger(n) || n < 10 || n > 10000) throw new Error('BENCH_N must be 10..10000');
async function measure(url: string, bearer: string, name: string) {
  const client = new Client(
    { name: 'gateway-benchmark', version: '1' },
    { versionNegotiation: { mode: 'auto' } },
  );
  await client.connect(
    new StreamableHTTPClientTransport(new URL(url), {
      requestInit: { headers: { Authorization: `Bearer ${bearer}` } },
    }),
  );
  const times: number[] = [];
  let errors = 0;
  try {
    for (let i = 0; i < n + 10; i++) {
      const t = performance.now();
      const result = await client.callTool({
        name,
        arguments: {
          owner: 'demo',
          repo: 'public',
          ...(name.startsWith('github__') ? { operationId: randomUUID() } : {}),
        },
      });
      if (result.isError && i >= 10) errors++;
      if (i >= 10) times.push(performance.now() - t);
    }
  } finally {
    await client.close();
  }
  times.sort((a, b) => a - b);
  return {
    samples: n,
    warmups: 10,
    concurrency: 1,
    errors,
    p50_ms: times[Math.floor(n * 0.5)],
    p95_ms: times[Math.floor(n * 0.95)],
    mean_ms: times.reduce((a, b) => a + b, 0) / n,
  };
}
const direct = await measure('http://127.0.0.1:4100/mcp', 'local-fixture-only', 'list_issues');
const throughGateway = await measure(gateway, token, 'github__list_issues');
const report = {
  recordedAt: new Date().toISOString(),
  node: process.version,
  platform: `${process.platform}/${process.arch}`,
  scope:
    'Sequential local fixture calls; full gateway with JWT verification, Cedar, live pin refresh, durable intent/completion, and encrypted result. Not production capacity.',
  direct,
  throughGateway,
};
await mkdir('.local/reports', { recursive: true });
await writeFile('.local/reports/benchmark.json', JSON.stringify(report, null, 2));
console.log(JSON.stringify(report, null, 2));
if (direct.errors || throughGateway.errors) process.exitCode = 1;
