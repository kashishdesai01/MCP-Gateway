import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { randomBytes } from 'node:crypto';
import { canonical, digest, seal, unseal } from '../src/crypto.js';
import { defaultPolicy, evaluate, validatePolicy } from '../src/policy.js';
import { identityFromClaims } from '../src/auth.js';
import { parseArguments, filterResult } from '../src/tools.js';
import { checkEndpoint } from '../src/upstream.js';
import { config } from '../src/config.js';
import { localKeys } from '../scripts/local-keys.js';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('policy boundary', () => {
  it('validates the shipped policy and denies arbitrary repositories', () => {
    validatePolicy(defaultPolicy);
    expect(
      evaluate(defaultPolicy, 'Agent', 'a', 'list_issues', 'read', {
        repo: 'demo/public',
        readPrivate: false,
        readUntrusted: false,
      }).allowed,
    ).toBe(true);
    expect(
      evaluate(defaultPolicy, 'Agent', 'a', 'list_issues', 'read', {
        repo: 'other/private',
        readPrivate: false,
        readUntrusted: false,
      }).allowed,
    ).toBe(false);
  });
  it('blocks an errored forbid even when Cedar permits another policy', () => {
    const policy =
      'permit(principal, action, resource); forbid(principal, action, resource) when { context.missing };';
    expect(
      evaluate(policy, 'Agent', 'a', 'create_issue', 'write', {
        repo: 'demo/public',
        readPrivate: false,
        readUntrusted: false,
      }),
    ).toEqual({ allowed: false, reasons: ['policy_error'] });
  });
  it('private reads deny writes without requiring untrusted-source detection', () => {
    expect(
      evaluate(defaultPolicy, 'Agent', 'a', 'create_issue', 'write', {
        repo: 'demo/public',
        readPrivate: true,
        readUntrusted: false,
      }).allowed,
    ).toBe(false);
  });
  it('rejects invalid policies before activation', () => {
    expect(() => validatePolicy('permit broken')).toThrow();
  });
});
describe('credentials and commitments', () => {
  it('preserves local encryption keys across restarts and refuses corrupt key files', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'scoped-keys-'));
    const path = join(directory, 'keys.json');
    try {
      const first = await localKeys(path);
      expect(await localKeys(path)).toEqual(first);
      await writeFile(path, 'corrupt');
      await expect(localKeys(path)).rejects.toThrow();
      expect(await readFile(path, 'utf8')).toBe('corrupt');
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
  it('authenticates record identity and detects ciphertext changes', () => {
    const key = randomBytes(32);
    const envelope = seal(key, { token: 'secret' }, 'connector:a');
    expect(unseal(key, envelope, 'connector:a')).toEqual({ token: 'secret' });
    expect(() => unseal(key, envelope, 'connector:b')).toThrow();
    expect(() => unseal(randomBytes(32), envelope, 'connector:a')).toThrow();
    expect(envelope).not.toContain('secret');
    expect(seal(key, { token: 'secret' }, 'connector:a')).not.toEqual(envelope);
  });
  it('canonicalizes object ordering without changing array order', () => {
    expect(digest({ b: 2, a: 1 })).toEqual(digest({ a: 1, b: 2 }));
    expect(digest([1, 2])).not.toEqual(digest([2, 1]));
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(JSON.parse(canonical(value))).toEqual(JSON.parse(JSON.stringify(value)));
      }),
      { numRuns: 200 },
    );
  });
});
describe('identity, arguments and upstream boundaries', () => {
  it('keeps users separate when they share an OAuth client', () => {
    const base = { iss: 'issuer', azp: 'shared-client' };
    expect(identityFromClaims({ ...base, sub: 'alice' })).not.toEqual(
      identityFromClaims({ ...base, sub: 'bob' }),
    );
    expect(() => identityFromClaims({ ...base, sub: 'alice', client_id: 'other' })).toThrow();
  });
  it('never forwards gateway operation identities or unknown parameters', () => {
    const args = {
      operationId: '90000000-0000-4000-8000-000000000001',
      owner: 'demo',
      repo: 'public',
    };
    expect(parseArguments('list_issues', args).upstream).toEqual({ owner: 'demo', repo: 'public' });
    expect(() =>
      parseArguments('list_issues', { ...args, url: 'https://attacker.example' }),
    ).toThrow();
    expect(() => parseArguments('get_file_contents', { ...args, path: '../secret' })).toThrow();
    expect(() => parseArguments('run_query', args)).toThrow();
    fc.assert(
      fc.property(fc.string(), (s) => {
        if (s.includes('/') || s.length > 100 || s.length === 0)
          expect(() => parseArguments('list_issues', { ...args, repo: s })).toThrow();
      }),
    );
  });
  it('redacts recognized tokens and rejects unbounded results', () => {
    expect(filterResult({ token: 'github_pat_' + 'a'.repeat(40) }).content[0]?.text).toContain(
      'REDACTED',
    );
    expect(filterResult({ token: 'ghp_' + 'a'.repeat(30) }).content[0]?.text).toContain('REDACTED');
    expect(() => filterResult('a'.repeat(70_000))).toThrow('result_limit');
  });
  it('rejects arbitrary upstream URLs and fixture endpoints in production', () => {
    const connector = {
      id: 'id',
      owner_id: 'owner',
      name: 'x',
      kind: 'github' as const,
      credential: '',
      enabled: true,
      endpoint: 'http://169.254.169.254/',
    };
    expect(() => checkEndpoint(connector, 'production')).toThrow();
    expect(() =>
      checkEndpoint({ ...connector, endpoint: 'https://api.githubcopilot.com/mcp/' }, 'production'),
    ).not.toThrow();
    expect(() =>
      checkEndpoint(
        { ...connector, kind: 'fixture', endpoint: 'http://127.0.0.1:4100/mcp' },
        'production',
      ),
    ).toThrow();
  });
  it('rejects production mode with insecure identity or owner DB credentials', () => {
    expect(() =>
      config({
        MODE: 'production',
        DATABASE_URL: 'postgresql://root@localhost/gw',
        AUTH_ISSUER: 'http://localhost',
        AUTH_JWKS_URL: 'http://localhost/jwks',
        RESOURCE_URI: 'http://localhost/mcp',
        CREDENTIAL_MASTER_KEY: '01'.repeat(32),
        AUDIT_HMAC_KEY: '02'.repeat(32),
      }),
    ).toThrow();
  });
});
