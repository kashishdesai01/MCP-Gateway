import { Client, StreamableHTTPClientTransport, type Tool } from '@modelcontextprotocol/client';
import { digest, unseal } from './crypto.js';
import type { Config } from './config.js';
import { invariant } from './errors.js';
import { traceContext } from './trace.js';

export interface Connector {
  id: string;
  owner_id: string;
  name: string;
  kind: 'fixture' | 'github';
  endpoint: string;
  credential: string;
  enabled: boolean;
}
export interface Upstream {
  definition(connector: Connector, tool: string): Promise<Tool>;
  call(connector: Connector, tool: string, args: Record<string, unknown>): Promise<unknown>;
}
export const definitionHash = (tool: Tool) => digest(tool);
export function checkEndpoint(connector: Connector, mode: Config['MODE']) {
  const u = new URL(connector.endpoint);
  invariant(!u.username && !u.password && !u.search && !u.hash, 'invalid_upstream');
  if (connector.kind === 'github') {
    invariant(
      u.origin === 'https://api.githubcopilot.com' && u.pathname === '/mcp/',
      'invalid_upstream',
    );
  } else {
    invariant(
      mode === 'demo' && u.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(u.hostname),
      'invalid_upstream',
    );
  }
}
const boundedFetch: typeof fetch = async (input, init) => {
  const response = await fetch(input, {
    ...init,
    redirect: 'error',
    signal: AbortSignal.any([AbortSignal.timeout(12_000), ...(init?.signal ? [init.signal] : [])]),
  });
  if (!response.body || response.status === 202 || response.status === 204) return response;
  const media = response.headers.get('content-type') ?? '';
  if (!media.includes('application/json') && !media.includes('text/event-stream')) {
    await response.body.cancel();
    throw new Error('Unsupported upstream response type');
  }
  const reader = response.body.getReader();
  let size = 0;
  // Preserve MCP SSE framing while bounding the stream before the SDK parses it.
  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          controller.close();
          return;
        }
        size += value.byteLength;
        if (size > 262_144) {
          await reader.cancel();
          controller.error(new Error('Upstream response exceeds limit'));
          return;
        }
        controller.enqueue(value);
      } catch (error) {
        controller.error(error);
      }
    },
    async cancel(reason) {
      await reader.cancel(reason);
    },
  });
  const headers = new Headers(response.headers);
  headers.delete('content-encoding');
  headers.delete('content-length');
  return new Response(body, { status: response.status, headers });
};
export class McpUpstream implements Upstream {
  constructor(private c: Config) {}
  private async withClient<T>(connector: Connector, fn: (client: Client) => Promise<T>) {
    checkEndpoint(connector, this.c.MODE);
    const credential = unseal<{ token: string }>(
      this.c.masterKey,
      connector.credential,
      `connector:${connector.id}`,
    );
    const transport = new StreamableHTTPClientTransport(new URL(connector.endpoint), {
      fetch: boundedFetch,
      requestInit: {
        headers: {
          Authorization: `Bearer ${credential.token}`,
          'X-MCP-Toolsets': 'repos,issues',
          Accept: 'application/json',
          ...(traceContext.getStore() ? { traceparent: traceContext.getStore()!.traceparent } : {}),
        },
      },
    });
    const client = new Client(
      { name: 'scoped-gateway', version: '0.1.0' },
      { versionNegotiation: { mode: 'auto' } },
    );
    try {
      await client.connect(transport);
      return await fn(client);
    } finally {
      await client.close().catch(() => undefined);
    }
  }
  async definition(connector: Connector, tool: string) {
    return this.withClient(connector, async (client) => {
      const all: Tool[] = [];
      let cursor: string | undefined;
      for (let page = 0; page < 20; page++) {
        const result = await client.listTools(cursor ? { cursor } : {});
        all.push(...result.tools);
        cursor = result.nextCursor;
        if (!cursor) break;
      }
      invariant(!cursor, 'catalog_limit', 502);
      const selected = all.filter((t) => t.name === tool);
      invariant(selected.length === 1, 'upstream_tool_missing', 502);
      return selected[0]!;
    });
  }
  async call(connector: Connector, name: string, args: Record<string, unknown>) {
    return this.withClient(connector, (client) =>
      client.callTool({ name, arguments: args }, { timeout: 15_000 }),
    );
  }
}
