import { AsyncLocalStorage } from 'node:async_hooks';
import { randomBytes } from 'node:crypto';
export const traceContext = new AsyncLocalStorage<{ traceId: string; traceparent: string }>();
export function newTrace(parent: string | undefined) {
  const match = /^00-([a-f0-9]{32})-([a-f0-9]{16})-0[01]$/.exec(parent ?? '');
  const traceId =
    match && !/^0+$/.test(match[1]!) && !/^0+$/.test(match[2]!)
      ? match[1]!
      : randomBytes(16).toString('hex');
  return { traceId, traceparent: `00-${traceId}-${randomBytes(8).toString('hex')}-01` };
}
