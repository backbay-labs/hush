import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import { describe, expect, it } from 'vitest';
import { contentHash } from '../src/canonical.js';
import { createBuiltinLoader, resolve } from '../src/resolve.js';
import { parseOrThrow } from '../src/parse.js';
import type { HushSpec } from '../src/schema.js';
import {
  DEFAULT_MAX_CLOCK_SKEW_SECONDS,
  type Envelope,
  Keyring,
  type ReasonCode,
  SigningError,
  envelopeSigningInput,
  generateKeypair,
  keyIdFromPublicKey,
  keyringFromPublicKey,
  loadKeyring,
  parseEnvelope,
  publicKeyPemFromPrivateKey,
  signPolicy,
  verifyPolicy,
} from '../src/signing.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const signingDir = path.join(repoRoot, 'fixtures', 'signing');

/**
 * The 0.2 signature schema, from `schemas/` once it is promoted and from
 * `schemas/staged/0.2.0/` until then. Picking by content rather than by
 * existence means the test does not care which side of the promotion it runs
 * on -- only that the schema it checks against really is the 0.2 one.
 */
function schemaPath(name: string): string {
  const promoted = path.join(repoRoot, 'schemas', name);
  const staged = path.join(repoRoot, 'schemas', 'staged', '0.2.0', name);
  if (existsSync(promoted)) {
    const doc = JSON.parse(readFileSync(promoted, 'utf8')) as Record<string, unknown>;
    if (JSON.stringify(doc).includes('"0.2"')) return promoted;
  }
  return staged;
}

const signatureSchema = JSON.parse(
  readFileSync(schemaPath('hushspec-signature.v0.schema.json'), 'utf8'),
) as JsonSchema;

// --------------------------------------------------------------------------
// A JSON Schema checker for the subset the signature schema uses
// --------------------------------------------------------------------------
//
// The package has no JSON Schema dependency and this is not the place to add
// one: the signature schema uses `type`, `const`, `pattern`, `required`,
// `additionalProperties: false`, `minimum` and `minLength`, and nothing else.

interface JsonSchema {
  type?: string;
  const?: unknown;
  pattern?: string;
  minimum?: number;
  minLength?: number;
  required?: string[];
  additionalProperties?: boolean;
  properties?: Record<string, JsonSchema>;
}

function schemaViolations(value: unknown, schema: JsonSchema, where = '$'): string[] {
  const problems: string[] = [];
  if (schema.type === 'object') {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return [`${where}: expected an object`];
    }
    const record = value as Record<string, unknown>;
    for (const key of schema.required ?? []) {
      if (!Object.prototype.hasOwnProperty.call(record, key)) {
        problems.push(`${where}: missing required property '${key}'`);
      }
    }
    for (const [key, entry] of Object.entries(record)) {
      const property = schema.properties?.[key];
      if (property === undefined) {
        if (schema.additionalProperties === false) {
          problems.push(`${where}: additional property '${key}'`);
        }
        continue;
      }
      problems.push(...schemaViolations(entry, property, `${where}.${key}`));
    }
    return problems;
  }
  if (schema.type === 'string') {
    if (typeof value !== 'string') return [`${where}: expected a string`];
    if (schema.pattern !== undefined && !new RegExp(schema.pattern).test(value)) {
      problems.push(`${where}: ${JSON.stringify(value)} does not match ${schema.pattern}`);
    }
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      problems.push(`${where}: shorter than ${schema.minLength}`);
    }
  } else if (schema.type === 'integer') {
    if (!Number.isInteger(value)) return [`${where}: expected an integer`];
    if (schema.minimum !== undefined && (value as number) < schema.minimum) {
      problems.push(`${where}: below the minimum ${schema.minimum}`);
    }
  }
  if (schema.const !== undefined && value !== schema.const) {
    problems.push(`${where}: expected ${JSON.stringify(schema.const)}`);
  }
  return problems;
}

// --------------------------------------------------------------------------
// The vector manifest
// --------------------------------------------------------------------------

interface VectorCase {
  name: string;
  policy: string;
  signature: string;
  keyring?: string;
  now?: string;
  last_seen_version?: number;
  max_clock_skew_seconds?: number;
  expect: 'valid' | { invalid: ReasonCode };
  note?: string;
}

interface VectorManifest {
  hushspec_signing_vectors: string;
  defaults: { keyring: string; now: string; max_clock_skew_seconds: number };
  cases: VectorCase[];
}

const vectors = YAML.parse(readFileSync(path.join(signingDir, 'vectors.yaml'), 'utf8'), {
  version: '1.2',
}) as VectorManifest;

function fixture(relative: string): string {
  return readFileSync(path.join(signingDir, relative), 'utf8');
}

/**
 * The resolved policy whose content hash a signature covers (spec section 3).
 *
 * Always through `resolve()`, never the file as parsed: `extends-child.yaml`
 * hashes `builtin:default` merged in, and running every case through the same
 * path is what makes that case meaningful rather than special.
 */
function resolvedPolicy(relative: string): HushSpec {
  const spec = parseOrThrow(fixture(relative));
  const result = resolve(spec, { load: createBuiltinLoader() });
  if (!result.ok) throw new Error(`could not resolve ${relative}: ${result.error}`);
  return result.value;
}

const trustedPublicKeyPem = fixture('keys/test-signing.pub.pem');
const trustedPrivateKeyPem = fixture('keys/test-signing.key.pem');

describe('signing vectors (spec/hushspec-signing.md section 9)', () => {
  it('finds the full vector set', () => {
    expect(vectors.cases.length).toBe(16);
  });

  for (const testCase of vectors.cases) {
    it(`${testCase.name}: ${
      testCase.expect === 'valid' ? 'valid' : testCase.expect.invalid
    }`, () => {
      const outcome = verifyPolicy(
        resolvedPolicy(testCase.policy),
        JSON.parse(fixture(testCase.signature)) as unknown,
        {
          keyring: loadKeyring(fixture(testCase.keyring ?? vectors.defaults.keyring)),
          now: testCase.now ?? vectors.defaults.now,
          maxClockSkewSeconds:
            testCase.max_clock_skew_seconds ?? vectors.defaults.max_clock_skew_seconds,
          ...(testCase.last_seen_version === undefined
            ? {}
            : { lastSeenVersion: testCase.last_seen_version }),
        },
      );

      if (testCase.expect === 'valid') {
        expect(outcome.ok ? 'valid' : `${outcome.reason}: ${outcome.detail}`).toBe('valid');
      } else {
        expect(outcome.ok ? 'valid' : outcome.reason).toBe(testCase.expect.invalid);
      }
    });
  }

  it('covers every reason code the vectors claim to cover', () => {
    const covered = new Set(
      vectors.cases
        .map((testCase) => (testCase.expect === 'valid' ? undefined : testCase.expect.invalid))
        .filter((reason): reason is ReasonCode => reason !== undefined),
    );
    // `malformed_envelope` has no vector; the unit tests below cover it.
    expect([...covered].sort()).toEqual([
      'content_hash_mismatch',
      'expired',
      'key_retired',
      'key_revoked',
      'policy_version_rollback',
      'signature_mismatch',
      'signed_at_in_future',
      'unknown_key_id',
      'unsupported_algorithm',
      'unsupported_format_version',
    ]);
  });
});

describe('signing and verifying (spec sections 4 and 6)', () => {
  it('round-trips a freshly generated key', () => {
    const { privateKeyPem, publicKeyPem, keyId } = generateKeypair();
    const policy = resolvedPolicy('policies/basic.yaml');

    const envelope = signPolicy(policy, privateKeyPem, {
      signedAt: '2026-09-15T09:00:00.000Z',
      expiresAt: '2027-09-15T09:00:00.000Z',
      signer: 'security@example.com',
    });

    expect(envelope.format_version).toBe('0.2');
    expect(envelope.algorithm).toBe('ed25519');
    expect(envelope.key_id).toBe(keyId);
    // Defaulted from the policy itself (spec section 4.2, step 2).
    expect(envelope.policy_name).toBe('signed-basic');
    expect(envelope.policy_version).toBe(4);
    expect(envelope.content_hash).toBe(contentHash(policy));

    const outcome = verifyPolicy(policy, envelope, {
      keyring: keyringFromPublicKey(publicKeyPem),
      now: '2026-09-15T12:00:00.000Z',
    });
    expect(outcome).toMatchObject({
      ok: true,
      keyId,
      signedAt: '2026-09-15T09:00:00.000Z',
      expiresAt: '2027-09-15T09:00:00.000Z',
      policyName: 'signed-basic',
      policyVersion: 4,
      signer: 'security@example.com',
    });
  });

  it('is byte-for-byte deterministic', () => {
    const policy = resolvedPolicy('policies/basic.yaml');
    const options = { signedAt: '2026-09-15T09:00:00.000Z', signer: 'security@example.com' };
    const first = signPolicy(policy, trustedPrivateKeyPem, options);
    const second = signPolicy(policy, trustedPrivateKeyPem, options);
    expect(JSON.stringify(second)).toBe(JSON.stringify(first));
  });

  it('reproduces the published basic.sig from the test key', () => {
    // The vectors were signed by `openssl pkeyutl -sign -rawin` over the
    // canonical envelope; signing the same claims here has to land on the same
    // 64 bytes, or this SDK and the vector generator disagree about either the
    // canonical form or the signing input.
    const published = JSON.parse(fixture('policies/basic.sig')) as Envelope;
    const envelope = signPolicy(resolvedPolicy('policies/basic.yaml'), trustedPrivateKeyPem, {
      signedAt: published.signed_at,
      signer: published.signer as string,
    });
    expect(envelope.signature).toBe(published.signature);
    expect(envelope.content_hash).toBe(published.content_hash);
    expect(envelope.key_id).toBe(published.key_id);
  });

  it('signs a policy that has to be resolved first', () => {
    const child = resolvedPolicy('policies/extends-child.yaml');
    const published = JSON.parse(fixture('policies/extends-child.sig')) as Envelope;
    const envelope = signPolicy(child, trustedPrivateKeyPem, {
      signedAt: published.signed_at,
    });
    expect(envelope.content_hash).toBe(published.content_hash);
    expect(envelope.signature).toBe(published.signature);
  });

  it('refuses to sign an unresolved policy', () => {
    const child = parseOrThrow(fixture('policies/extends-child.yaml'));
    expect(() => signPolicy(child, trustedPrivateKeyPem)).toThrow(SigningError);
  });

  it('refuses to sign a policy that does not validate', () => {
    const broken = { ...resolvedPolicy('policies/basic.yaml'), hushspec: '9.9.9' };
    expect(() => signPolicy(broken, trustedPrivateKeyPem)).toThrow(SigningError);
  });

  it('produces envelopes that validate against the signature schema', () => {
    const policy = resolvedPolicy('policies/basic.yaml');
    const bare = { hushspec: policy.hushspec, rules: policy.rules };
    const minimal = signPolicy(bare, trustedPrivateKeyPem);
    const full = signPolicy(policy, trustedPrivateKeyPem, {
      signedAt: '2026-09-15T09:00:00.000Z',
      expiresAt: '2026-12-15T09:00:00.000Z',
      signer: 'security@example.com',
    });

    for (const envelope of [minimal, full]) {
      expect(schemaViolations(envelope, signatureSchema)).toEqual([]);
    }
    // The published vector is the same shape, which pins the checker itself.
    expect(schemaViolations(JSON.parse(fixture('policies/basic.sig')), signatureSchema)).toEqual([]);
  });

  it('signs the canonical envelope without the signature member', () => {
    const published = JSON.parse(fixture('policies/basic.sig')) as Envelope;
    expect(envelopeSigningInput(published)).toBe(
      '{"algorithm":"ed25519",' +
        '"content_hash":"sha256:386fb3d6955b04d671dd2777c6417bf322489c9e820572993923d5f9e1fa563a",' +
        '"format_version":"0.2",' +
        '"key_id":"sha256:1187bb3ca0fd60b25cb90390812fb3a90823466b499e9c29effcc9f3c4ce6142",' +
        '"policy_name":"signed-basic","policy_version":4,' +
        '"signed_at":"2026-09-15T09:00:00.000Z","signer":"security@example.com"}',
    );
  });
});

describe('keys and keyrings (spec section 5)', () => {
  it('derives key_id from the SPKI DER', () => {
    expect(keyIdFromPublicKey(trustedPublicKeyPem)).toBe(
      'sha256:1187bb3ca0fd60b25cb90390812fb3a90823466b499e9c29effcc9f3c4ce6142',
    );
    expect(keyIdFromPublicKey(fixture('keys/test-untrusted.pub.pem'))).toBe(
      'sha256:2b570037138bf0b0f6694d04ae3cd3b53e47c4af3b05e449fed87e023b172d23',
    );
  });

  it('derives the public key from the private key', () => {
    const pem = publicKeyPemFromPrivateKey(trustedPrivateKeyPem);
    expect(keyIdFromPublicKey(pem)).toBe(keyIdFromPublicKey(trustedPublicKeyPem));
  });

  it('recomputes every key_id and rejects one that lies', () => {
    const document = JSON.parse(fixture('keys/keyring.json')) as Record<string, unknown>;
    const keys = document['keys'] as Record<string, unknown>[];
    expect(loadKeyring(document).keys[0]?.keyId).toBe(keys[0]?.['key_id']);

    keys[0]!['key_id'] = `sha256:${'0'.repeat(64)}`;
    expect(() => loadKeyring(document)).toThrow(/does not match the public key/);
  });

  it('carries not_after and revoked through to the verifier', () => {
    expect(loadKeyring(fixture('keys/keyring-retired.json')).keys[0]?.notAfter).toBe(
      '2026-09-15T00:00:00.000Z',
    );
    expect(loadKeyring(fixture('keys/keyring-revoked.json')).keys[0]?.revoked).toBe(true);
    expect(loadKeyring(fixture('keys/keyring.json')).keys[0]?.revoked).toBe(false);
  });

  it('rejects a keyring that is not 0.2, is empty, or carries unknown fields', () => {
    const base = JSON.parse(fixture('keys/keyring.json')) as Record<string, unknown>;
    expect(() => loadKeyring({ ...base, keyring_version: '0.1' })).toThrow(SigningError);
    expect(() => loadKeyring({ ...base, keys: [] })).toThrow(SigningError);
    expect(() => loadKeyring({ ...base, trusted: true })).toThrow(/unknown field/);
    expect(() => loadKeyring('not json')).toThrow(SigningError);
  });

  it('selects by exact key_id with no fallback to another key on the ring', () => {
    const document = JSON.parse(fixture('keys/keyring.json')) as Record<string, unknown>;
    const untrusted = keyringFromPublicKey(fixture('keys/test-untrusted.pub.pem'));
    const ring = new Keyring([...loadKeyring(document).keys, ...untrusted.keys]);
    const envelope = JSON.parse(fixture('policies/untrusted-key.sig')) as Envelope;

    // The untrusted key *is* on this ring, so the same envelope now verifies --
    // proof that the `unknown_key_id` in the vector came from key selection and
    // not from the signature itself.
    expect(
      verifyPolicy(resolvedPolicy('policies/basic.yaml'), envelope, {
        keyring: ring,
        now: vectors.defaults.now,
      }).ok,
    ).toBe(true);
  });
});

describe('envelope parsing and the verifier contract', () => {
  it('rejects unknown format versions and algorithms fail-closed', () => {
    expect(() => parseEnvelope(fixture('policies/bad-format-version.sig'))).toThrow(
      /unsupported signature format_version/,
    );
    expect(() => parseEnvelope(fixture('policies/bad-algorithm.sig'))).toThrow(
      /unsupported signature algorithm/,
    );
    expect(parseEnvelope(fixture('policies/basic.sig')).key_id).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('rejects malformed envelopes', () => {
    const good = JSON.parse(fixture('policies/basic.sig')) as Record<string, unknown>;
    const malformed: unknown[] = [
      null,
      'a string',
      [good],
      { ...good, extra: 1 },
      { ...good, key_id: undefined },
      { ...good, key_id: 'sha256:nothex' },
      { ...good, content_hash: '386fb3d6' },
      { ...good, signed_at: '2026-09-15T09:00:00Z' },
      { ...good, signed_at: '2026-99-99T09:00:00.000Z' },
      { ...good, expires_at: 12 },
      { ...good, policy_version: 1.5 },
      { ...good, policy_version: -1 },
      { ...good, policy_name: '' },
      { ...good, signature: `${good['signature'] as string}==` },
    ];
    for (const envelope of malformed) {
      expect(() => parseEnvelope(envelope)).toThrow(SigningError);
      const outcome = verifyPolicy(resolvedPolicy('policies/basic.yaml'), envelope, {
        keyring: loadKeyring(fixture('keys/keyring.json')),
        now: vectors.defaults.now,
      });
      expect(outcome.ok ? 'valid' : outcome.reason).toBe('malformed_envelope');
    }
  });

  it('treats an unreadable policy as content_hash_mismatch', () => {
    const outcome = verifyPolicy(
      parseOrThrow(fixture('policies/extends-child.yaml')),
      JSON.parse(fixture('policies/extends-child.sig')) as unknown,
      { keyring: loadKeyring(fixture('keys/keyring.json')), now: vectors.defaults.now },
    );
    expect(outcome.ok ? 'valid' : outcome.reason).toBe('content_hash_mismatch');
  });

  it('accepts a bare public key as a one-key keyring', () => {
    const outcome = verifyPolicy(
      resolvedPolicy('policies/basic.yaml'),
      JSON.parse(fixture('policies/basic.sig')) as unknown,
      { publicKeyPem: trustedPublicKeyPem, now: vectors.defaults.now },
    );
    expect(outcome.ok).toBe(true);
  });

  it('demands exactly one key source', () => {
    const policy = resolvedPolicy('policies/basic.yaml');
    const envelope = JSON.parse(fixture('policies/basic.sig')) as unknown;
    expect(() => verifyPolicy(policy, envelope, {})).toThrow(SigningError);
    expect(() =>
      verifyPolicy(policy, envelope, {
        publicKeyPem: trustedPublicKeyPem,
        keyring: loadKeyring(fixture('keys/keyring.json')),
      }),
    ).toThrow(SigningError);
  });

  it('applies clock skew to signed_at only', () => {
    const policy = resolvedPolicy('policies/basic.yaml');
    const future = JSON.parse(fixture('policies/signed-in-future.sig')) as unknown;
    const options = { publicKeyPem: trustedPublicKeyPem };

    // signed_at is 13:00; the default 300s skew is not enough at 12:00.
    expect(
      verifyPolicy(policy, future, { ...options, now: '2026-09-15T12:00:00.000Z' }).ok,
    ).toBe(false);
    expect(
      verifyPolicy(policy, future, {
        ...options,
        now: '2026-09-15T12:00:00.000Z',
        maxClockSkewSeconds: 3600,
      }).ok,
    ).toBe(true);
    expect(DEFAULT_MAX_CLOCK_SKEW_SECONDS).toBe(300);

    // A two-year-old signature is not stale (spec section 6.3).
    expect(
      verifyPolicy(policy, JSON.parse(fixture('policies/basic.sig')) as unknown, {
        ...options,
        now: '2028-09-15T12:00:00.000Z',
      }).ok,
    ).toBe(true);
  });

  it('reports rollback only when it holds a last-seen version', () => {
    const policy = resolvedPolicy('policies/basic.yaml');
    const rollback = JSON.parse(fixture('policies/rollback.sig')) as unknown;
    const options = { publicKeyPem: trustedPublicKeyPem, now: vectors.defaults.now };
    expect(verifyPolicy(policy, rollback, options).ok).toBe(true);
    expect(verifyPolicy(policy, rollback, { ...options, lastSeenVersion: 3 }).ok).toBe(true);
    const outcome = verifyPolicy(policy, rollback, { ...options, lastSeenVersion: 4 });
    expect(outcome.ok ? 'valid' : outcome.reason).toBe('policy_version_rollback');
  });

  it('stops at the first failing check, in the order the spec fixes', () => {
    const policy = resolvedPolicy('policies/tampered.yaml');
    // A revoked key AND a tampered policy: revocation is check 5, the content
    // hash check 9, so the reason must be the revocation.
    const outcome = verifyPolicy(
      policy,
      JSON.parse(fixture('policies/tampered.sig')) as unknown,
      {
        keyring: loadKeyring(fixture('keys/keyring-revoked.json')),
        now: vectors.defaults.now,
      },
    );
    expect(outcome.ok ? 'valid' : outcome.reason).toBe('key_revoked');
  });
});
