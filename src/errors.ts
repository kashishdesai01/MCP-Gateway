export class GatewayError extends Error {
  constructor(
    public readonly code: string,
    public readonly status = 403,
  ) {
    super(code);
  }
}
export function invariant(condition: unknown, code: string, status = 403): asserts condition {
  if (!condition) throw new GatewayError(code, status);
}
