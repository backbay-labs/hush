import { createHash } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  BUNDLE_PAYLOAD_TYPE,
  BUNDLE_PREDICATE_TYPE,
  BUNDLE_RESOLVER_TOOL,
  BUNDLE_STATEMENT_TYPE,
  BUNDLE_VERSION,
  BundleError,
  buildBundleStatement,
  bundleStatementBytes,
  bundleToJson,
  createBundle,
  parseBundle,
  verifyBundle,
  type DsseEnvelope,
} from '../src/bundle.js';
import { canonicalizeValue } from '../src/canonical.js';
import { parse } from '../src/parse.js';
import { createCompositeLoader, resolveWithOptions, type Resolution } from '../src/resolve.js';
import { loadKeyring } from '../src/signing.js';
import { SDK_NAME, SDK_VERSION } from '../src/version.js';

/**
 * Bundle creation (bundle spec 4).
 *
 * The contract a bundler has to meet is reproducibility: "two bundlers given
 * the same resolution, the same `created_at`, and the same resolver therefore
 * produce byte-identical payloads and -- Ed25519 being deterministic --
 * byte-identical bundles" (bundle spec 4). The normative vector
 * `fixtures/bundle/bundles/valid.bundle.json` was produced by the reference
 * CLI, so rebuilding it here from the same policy, key, and `created_at` is
 * that claim under test across two independent implementations.
 */

const repoRoot = realpathSync(
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..'),
);
const keysRoot = path.join(repoRoot, 'fixtures', 'signing', 'keys');
const bundlesRoot = path.join(repoRoot, 'fixtures', 'bundle', 'bundles');

/** The policy every bundle vector attests (`fixtures/bundle/README.md`). */
const vectorPolicy = path.join(repoRoot, 'library', 'healthcare', 'hipaa-base.yaml');

/** The `created_at` the vectors pin so the bundles are byte-reproducible. */
const vectorCreatedAt = '2026-09-15T12:00:00.000Z';

/**
 * The reference CLI's version at the time the vectors were generated, read
 * back from the vector rather than hardcoded twice.
 */
function vectorResolver(): { tool: string; version: string } {
  const statement = statementOf(readVector('valid.bundle.json'));
  return statement.predicate.resolver;
}

/**
 * The published test keys carry a DO-NOT-USE header above the PEM block.
 * Strip it, exactly as `scripts/generate_bundle_vectors.py` does.
 */
function readKey(name: string): string {
  const text = readFileSync(path.join(keysRoot, name), 'utf8');
  return text.slice(text.indexOf('-----BEGIN'));
}

function readVector(name: string): DsseEnvelope {
  return parseBundle(readFileSync(path.join(bundlesRoot, name), 'utf8'));
}

function statementOf(envelope: DsseEnvelope) {
  return JSON.parse(Buffer.from(envelope.payload, 'base64').toString('utf8'));
}

function resolveVectorPolicy(): Resolution {
  const parsed = parse(readFileSync(vectorPolicy, 'utf8'));
  if (!parsed.ok) throw new Error(`${vectorPolicy} does not parse: ${parsed.error}`);
  return resolveWithOptions(parsed.value, {
    source: vectorPolicy,
    loader: createCompositeLoader(),
  });
}

/** The keyring the vectors verify against. */
function vectorKeyring() {
  return loadKeyring(readFileSync(path.join(keysRoot, 'keyring.json'), 'utf8'));
}

describe('createBundle', () => {
  it('reproduces the normative signed bundle byte for byte', () => {
    const expected = readVector('valid.bundle.json');
    const built = createBundle(resolveVectorPolicy(), {
      privateKeyPem: readKey('test-signing.key.pem'),
      createdAt: vectorCreatedAt,
      baseDir: repoRoot,
      ...vectorResolver(),
    });

    // The payload is the canonical statement, so equal payloads mean the two
    // bundlers agree on every member of the statement, not merely on its
    // meaning.
    expect(built.payload).toBe(expected.payload);
    expect(built.payloadType).toBe(expected.payloadType);
    expect(built.signatures).toEqual(expected.signatures);
    expect(bundleToJson(built)).toBe(
      readFileSync(path.join(bundlesRoot, 'valid.bundle.json'), 'utf8'),
    );
  });

  it('reproduces the normative unsigned bundle', () => {
    const expected = readVector('unsigned.bundle.json');
    const built = createBundle(resolveVectorPolicy(), {
      createdAt: vectorCreatedAt,
      baseDir: repoRoot,
      ...vectorResolver(),
    });

    expect(built.signatures).toEqual([]);
    expect(built.payload).toBe(expected.payload);
  });

  it('reproduces a bundle signed by a key the keyring does not hold', () => {
    const expected = readVector('wrong-key.bundle.json');
    const built = createBundle(resolveVectorPolicy(), {
      privateKeyPem: readKey('test-untrusted.key.pem'),
      createdAt: vectorCreatedAt,
      baseDir: repoRoot,
      ...vectorResolver(),
    });

    expect(built).toEqual(expected);
  });

  it('is deterministic: the same inputs twice give the same bytes', () => {
    const options = {
      privateKeyPem: readKey('test-signing.key.pem'),
      createdAt: vectorCreatedAt,
      baseDir: repoRoot,
    };
    expect(createBundle(resolveVectorPolicy(), options)).toEqual(
      createBundle(resolveVectorPolicy(), options),
    );
  });

  it('round trips: a bundle it creates verifies', () => {
    const bundle = createBundle(resolveVectorPolicy(), {
      privateKeyPem: readKey('test-signing.key.pem'),
      createdAt: vectorCreatedAt,
      baseDir: repoRoot,
    });

    const outcome = verifyBundle(bundle, {
      keyring: vectorKeyring(),
      now: vectorCreatedAt,
      policy: resolveVectorPolicy(),
    });
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.contentHash).toBe(resolveVectorPolicy().content_hash);
      expect(outcome.policyChecked).toBe(true);
    }
  });

  it('refuses an unsigned bundle at verification, as bundle spec 3 requires', () => {
    const bundle = createBundle(resolveVectorPolicy(), { createdAt: vectorCreatedAt });
    const outcome = verifyBundle(bundle, { keyring: vectorKeyring(), now: vectorCreatedAt });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.reason).toBe('dsse_signature_mismatch');
  });

  it('defaults the resolver to this SDK', () => {
    const statement = buildBundleStatement(resolveVectorPolicy(), {
      createdAt: vectorCreatedAt,
    });
    expect(statement.predicate.resolver).toEqual({ tool: SDK_NAME, version: SDK_VERSION });
    expect(BUNDLE_RESOLVER_TOOL).toBe('h2h');
  });
});

describe('buildBundleStatement', () => {
  it('names the constants of bundle spec 3 and 4', () => {
    const statement = buildBundleStatement(resolveVectorPolicy(), {
      createdAt: vectorCreatedAt,
      baseDir: repoRoot,
    });
    expect(statement._type).toBe(BUNDLE_STATEMENT_TYPE);
    expect(statement.predicateType).toBe(BUNDLE_PREDICATE_TYPE);
    expect(statement.predicate.bundle_version).toBe(BUNDLE_VERSION);
    expect(statement.subject).toHaveLength(1);
  });

  it('is internally consistent: the subject digest is the digest of predicate.resolved', () => {
    const statement = buildBundleStatement(resolveVectorPolicy(), {
      createdAt: vectorCreatedAt,
    });
    const recomputed = createHashOf(canonicalizeValue(statement.predicate.resolved));
    expect(statement.predicate.policy.content_hash).toBe(`sha256:${recomputed}`);
    expect(statement.subject[0]?.digest.sha256).toBe(recomputed);
  });

  it('records the chain root first with each hop hashed on its own', () => {
    const resolution = resolveVectorPolicy();
    const statement = buildBundleStatement(resolution, {
      createdAt: vectorCreatedAt,
      baseDir: repoRoot,
    });
    expect(statement.predicate.chain.map(link => link.source)).toEqual([
      'builtin:strict',
      'library/healthcare/hipaa-base.yaml',
    ]);
    expect(statement.predicate.chain.map(link => link.content_hash)).toEqual(
      resolution.chain.map(link => link.content_hash),
    );
  });

  it('leaves a source outside baseDir, a builtin, and a URL alone', () => {
    const resolution = resolveVectorPolicy();
    const statement = buildBundleStatement(resolution, {
      createdAt: vectorCreatedAt,
      baseDir: path.join(repoRoot, 'crates'),
    });
    // `builtin:strict` is portable already; the leaf is not beneath `crates/`.
    expect(statement.predicate.chain[0]?.source).toBe('builtin:strict');
    expect(statement.predicate.chain[1]?.source).toBe(resolution.chain[1]?.source);
  });

  it('omits signature_verification when no verification was attempted', () => {
    const statement = buildBundleStatement(resolveVectorPolicy(), {
      createdAt: vectorCreatedAt,
    });
    // Recording `verified: false` would assert a check that never ran
    // (bundle spec 4.5).
    expect('signature_verification' in statement.predicate).toBe(false);
  });

  it('falls back to the leaf file name when the policy has no name', () => {
    const resolution = resolveVectorPolicy();
    const unnamed: Resolution = {
      ...resolution,
      spec: { ...resolution.spec, name: undefined },
    };
    const statement = buildBundleStatement(unnamed, {
      createdAt: vectorCreatedAt,
      baseDir: repoRoot,
    });
    expect(statement.subject[0]?.name).toBe('hipaa-base.yaml');
    expect(statement.predicate.policy.name).toBeUndefined();
  });

  it('honours an explicit subject name', () => {
    const statement = buildBundleStatement(resolveVectorPolicy(), {
      createdAt: vectorCreatedAt,
      subjectName: 'release-2026-09',
    });
    expect(statement.subject[0]?.name).toBe('release-2026-09');
  });

  it('writes created_at with millisecond precision and a Z suffix', () => {
    const statement = buildBundleStatement(resolveVectorPolicy(), {
      createdAt: new Date(Date.UTC(2026, 8, 15, 12, 0, 0, 500)),
    });
    expect(statement.predicate.created_at).toBe('2026-09-15T12:00:00.500Z');
  });

  it('rejects a document that still declares extends', () => {
    const parsed = parse(readFileSync(vectorPolicy, 'utf8'));
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const unresolved: Resolution = {
      spec: parsed.value,
      content_hash: 'sha256:'.padEnd(71, '0'),
      chain: [],
    };
    expect(() => buildBundleStatement(unresolved)).toThrow(BundleError);
  });
});

describe('bundleStatementBytes', () => {
  it('is the canonical serialization the payload carries', () => {
    const statement = buildBundleStatement(resolveVectorPolicy(), {
      createdAt: vectorCreatedAt,
      baseDir: repoRoot,
    });
    const bundle = createBundle(resolveVectorPolicy(), {
      createdAt: vectorCreatedAt,
      baseDir: repoRoot,
    });
    expect(bundleStatementBytes(statement).toString('base64')).toBe(bundle.payload);
    expect(bundle.payloadType).toBe(BUNDLE_PAYLOAD_TYPE);
  });
});

describe('createBundle key handling', () => {
  it('refuses a key that is not Ed25519', () => {
    expect(() =>
      createBundle(resolveVectorPolicy(), { privateKeyPem: 'not a pem' }),
    ).toThrow(BundleError);
  });
});

function createHashOf(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}
