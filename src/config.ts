import { z } from 'zod';
import { keyFromHex } from './crypto.js';

const schema = z.object({
  MODE: z.enum(['demo', 'production']).default('production'),
  AUTH_MODE: z.enum(['oidc', 'demo']).default('oidc'),
  PORT: z.coerce.number().int().min(1024).max(65535).default(3000),
  DATABASE_URL: z.string().url(),
  AUTH_ISSUER: z.string().url(),
  AUTH_JWKS_URL: z.string().url(),
  RESOURCE_URI: z.string().url(),
  CREDENTIAL_MASTER_KEY: z.string(),
  AUDIT_HMAC_KEY: z.string(),
  CONSOLE_CLIENT_ID: z.string().default('gateway-console'),
});
export function config(env: NodeJS.ProcessEnv = process.env) {
  const c = schema.parse(env);
  const masterKey = keyFromHex(c.CREDENTIAL_MASTER_KEY);
  const auditKey = keyFromHex(c.AUDIT_HMAC_KEY);
  if (masterKey.equals(auditKey)) throw new Error('Encryption and audit keys must be independent');
  if (c.MODE === 'production' && c.AUTH_MODE === 'demo')
    throw new Error('Demo identity is forbidden in production');
  if (c.MODE === 'production') {
    for (const uri of [c.AUTH_ISSUER, c.AUTH_JWKS_URL, c.RESOURCE_URI]) {
      if (new URL(uri).protocol !== 'https:')
        throw new Error('Production identity and resource URLs require HTTPS');
    }
    const db = new URL(c.DATABASE_URL);
    if (
      ['root', 'postgres'].includes(db.username) ||
      db.searchParams.get('sslmode') !== 'verify-full'
    ) {
      throw new Error('Production requires a restricted database user and sslmode=verify-full');
    }
  }
  return { ...c, masterKey, auditKey };
}
export type Config = ReturnType<typeof config>;
