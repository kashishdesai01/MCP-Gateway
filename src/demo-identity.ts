import { exportJWK, generateKeyPair, SignJWT } from 'jose';
export async function demoIdentity(issuer: string, audience: string) {
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'local-demo', alg: 'RS256', use: 'sig' };
  return {
    jwks: { keys: [jwk] },
    async token(overrides: Record<string, unknown> = {}) {
      return new SignJWT({
        azp: 'demo-client',
        scope: 'mcp:tools',
        realm_access: { roles: ['gateway-admin'] },
        ...overrides,
      })
        .setProtectedHeader({ alg: 'RS256', kid: jwk.kid })
        .setIssuer(issuer)
        .setSubject(typeof overrides.sub === 'string' ? overrides.sub : 'demo-owner')
        .setAudience(typeof overrides.aud === 'string' ? overrides.aud : audience)
        .setIssuedAt()
        .setExpirationTime(typeof overrides.exp === 'number' ? overrides.exp : '5m')
        .sign(privateKey);
    },
  };
}
export type DemoIdentity = Awaited<ReturnType<typeof demoIdentity>>;
