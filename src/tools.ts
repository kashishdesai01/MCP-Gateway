import { z } from 'zod';
import { GatewayError } from './errors.js';

const repo = {
  owner: z.string().regex(/^[A-Za-z0-9-]{1,100}$/),
  repo: z.string().regex(/^[A-Za-z0-9_.-]{1,100}$/),
};
const operationId = z
  .uuid()
  .describe(
    'Stable UUID for this logical call. Reuse on retries; never change after an unknown write outcome.',
  );
export const registry = {
  list_issues: {
    effect: 'read',
    source: 'untrusted',
    description: 'Read issues in an approved repository.',
    schema: z.object({ operationId, ...repo }).strict(),
  },
  get_file_contents: {
    effect: 'read',
    source: 'private',
    description:
      'Read a repository file. Conservatively marks this delegation as having read private data.',
    schema: z
      .object({
        operationId,
        ...repo,
        path: z
          .string()
          .min(1)
          .max(300)
          .refine((s) => !s.startsWith('/') && !s.split('/').includes('..')),
      })
      .strict(),
  },
  create_issue: {
    effect: 'write',
    source: 'none',
    description:
      'Publish an issue in an approved repository. Blocked after this delegation reads private data.',
    schema: z
      .object({
        operationId,
        ...repo,
        title: z.string().min(1).max(200),
        body: z.string().max(10_000),
      })
      .strict(),
  },
} as const;
export type ToolName = keyof typeof registry;
export function toolFor(name: string) {
  if (!Object.hasOwn(registry, name)) throw new GatewayError('unsupported_tool');
  return registry[name as ToolName];
}
export function parseArguments(tool: string, args: unknown) {
  const parsed = toolFor(tool).schema.safeParse(args);
  if (!parsed.success) throw new GatewayError('invalid_arguments', 400);
  const { operationId: id, ...upstream } = parsed.data;
  return { id, upstream, repo: `${upstream.owner}/${upstream.repo}`.toLowerCase() };
}
export function filterResult(value: unknown) {
  let json = JSON.stringify(value);
  if (!json || Buffer.byteLength(json) > 65_536) throw new GatewayError('result_limit', 502);
  json = json
    .replace(/(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}/g, '[REDACTED_TOKEN]')
    .replace(/AKIA[A-Z0-9]{16}/g, '[REDACTED_KEY]')
    .replace(
      /-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g,
      '[REDACTED_PRIVATE_KEY]',
    );
  // Data is returned as inert text: upstream links, metadata and sampling requests are not forwarded.
  return { content: [{ type: 'text' as const, text: json }] };
}
