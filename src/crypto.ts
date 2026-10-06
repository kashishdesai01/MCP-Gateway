import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
const canonicalize = createRequire(import.meta.url)('canonicalize') as (
  input: unknown,
) => string | undefined;

export function canonical(value: unknown): string {
  const result = canonicalize(value);
  if (result === undefined) throw new Error('Value cannot be canonicalized');
  return result;
}
export const digest = (value: unknown) =>
  createHash('sha256').update(canonical(value)).digest('hex');
export const keyedDigest = (key: Buffer, value: unknown) =>
  createHmac('sha256', key).update(canonical(value)).digest('hex');
export function keyFromHex(value: string): Buffer {
  if (!/^[a-f0-9]{64}$/i.test(value)) throw new Error('Expected a 32-byte hexadecimal key');
  return Buffer.from(value, 'hex');
}
// Each envelope has a fresh DEK and independent nonces. AAD binds ciphertext to its record.
export function seal(master: Buffer, value: unknown, aad: string): string {
  const dek = randomBytes(32);
  const encrypt = (key: Buffer, data: Buffer, purpose: string) => {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(Buffer.from(`${aad}:${purpose}`));
    const bytes = Buffer.concat([cipher.update(data), cipher.final()]);
    return {
      nonce: nonce.toString('base64'),
      bytes: bytes.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
    };
  };
  return JSON.stringify({
    v: 1,
    data: encrypt(dek, Buffer.from(canonical(value)), 'data'),
    key: encrypt(master, dek, 'key'),
  });
}
export function unseal<T>(master: Buffer, envelope: string, aad: string): T {
  const parsed = JSON.parse(envelope) as { v: number; data: Part; key: Part };
  if (parsed.v !== 1) throw new Error('Unknown envelope version');
  function decrypt(key: Buffer, part: Part, purpose: string) {
    const cipher = createDecipheriv('aes-256-gcm', key, Buffer.from(part.nonce, 'base64'));
    cipher.setAAD(Buffer.from(`${aad}:${purpose}`));
    cipher.setAuthTag(Buffer.from(part.tag, 'base64'));
    return Buffer.concat([cipher.update(Buffer.from(part.bytes, 'base64')), cipher.final()]);
  }
  return JSON.parse(
    decrypt(decrypt(master, parsed.key, 'key'), parsed.data, 'data').toString(),
  ) as T;
}
interface Part {
  nonce: string;
  bytes: string;
  tag: string;
}
