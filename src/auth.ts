import { createRemoteJWKSet, jwtVerify, errors, type JWTPayload } from 'jose';
import type { Config } from './config.js';
import { GatewayError, invariant } from './errors.js';

export interface Identity {
  issuer: string;
  subject: string;
  clientId: string;
  admin: boolean;
}
export function identityFromClaims(payload: JWTPayload): Identity {
  invariant(
    typeof payload.iss === 'string' && typeof payload.sub === 'string',
    'invalid_token',
    401,
  );
  const clientId = payload.azp ?? payload.client_id;
  invariant(typeof clientId === 'string' && clientId.length > 0, 'invalid_token', 401);
  if (payload.azp && payload.client_id)
    invariant(payload.azp === payload.client_id, 'invalid_token', 401);
  const roles = (payload.realm_access as { roles?: unknown } | undefined)?.roles;
  return {
    issuer: payload.iss,
    subject: payload.sub,
    clientId,
    admin: Array.isArray(roles) && roles.includes('gateway-admin'),
  };
}
export function authenticator(c: Config, rejected: (code: string) => void = () => undefined) {
  const jwks = createRemoteJWKSet(new URL(c.AUTH_JWKS_URL), {
    timeoutDuration: 5000,
    cooldownDuration: 10000,
  });
  return async (header: string | undefined): Promise<Identity> => {
    if (!header?.startsWith('Bearer ') || header.length > 16_384)
      throw new GatewayError('invalid_token', 401);
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(header.slice(7), jwks, {
        issuer: c.AUTH_ISSUER,
        audience: c.RESOURCE_URI,
        algorithms: ['RS256', 'ES256'],
        requiredClaims: ['exp', 'iat', 'sub', 'iss'],
        maxTokenAge: '6m',
        clockTolerance: 5,
      }));
    } catch (error) {
      rejected(
        error instanceof errors.JWTClaimValidationFailed
          ? `${error.code}:${error.claim}`
          : error instanceof errors.JOSEError
            ? error.code
            : 'JWKS_UNAVAILABLE',
      );
      throw new GatewayError('invalid_token', 401);
    }
    invariant(
      typeof payload.scope === 'string' && payload.scope.split(' ').includes('mcp:tools'),
      'insufficient_scope',
      403,
    );
    return identityFromClaims(payload);
  };
}
