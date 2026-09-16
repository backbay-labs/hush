import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
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
import { schemaErrors, type SchemaDocument } from './helpers/json-schema.js';

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

/** A 0.x policy that declares `name: ""`, which the frozen 0.x format admits. */
const emptyNamePolicy = path.join(repoRoot, 'fixtures', 'core', 'valid', 'empty-name-0-2.yaml');

/** The `created_at` the vectors pin so the bundles are byte-reproducible. */
const vectorCreatedAt = '2026-09-15T12:00:00.000Z';

/**
 * The resolver the named vector records, read back from the vector rather
 * than hardcoded twice. Per vector, not once for the set: the vectors were
 * regenerated at different releases of the reference CLI, so reproducing a
 * vector's bytes means naming the resolver *that* vector carries.
 */
function vectorResolver(vector: string): { tool: string; version: string } {
  const statement = statementOf(readVector(vector));
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

function resolvePolicy(file: string): Resolution {
  const parsed = parse(readFileSync(file, 'utf8'));
  if (!parsed.ok) throw new Error(`${file} does not parse: ${parsed.error}`);
  return resolveWithOptions(parsed.value, { source: file, loader: createCompositeLoader() });
}

function resolveVectorPolicy(): Resolution {
  return resolvePolicy(vectorPolicy);
}

const bundleSchema = JSON.parse(
  readFileSync(path.join(repoRoot, 'schemas', 'hushspec-bundle.v1.schema.json'), 'utf8'),
) as SchemaDocument;

/**
 * `$defs/Statement` as a schema in its own right: the definitions come along
 * so its internal `#/$defs/...` refs still resolve. The payload is base64, so
 * the statement it decodes to is validated separately from the envelope
 * (bundle spec 5.2).
 */
const statementSchema = {
  ...(bundleSchema['$defs'] as Record<string, SchemaDocument>)['Statement'],
  $defs: bundleSchema['$defs'],
} as SchemaDocument;

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
      ...vectorResolver('valid.bundle.json'),
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
      ...vectorResolver('unsigned.bundle.json'),
    });

    // Assert the vector is the unsigned one before comparing against it, so
    // this cannot pass by reading a signed vector whose payload happens to
    // match.
    expect(expected.signatures).toEqual([]);
    expect(built.signatures).toEqual([]);
    expect(built.payload).toBe(expected.payload);
  });

  it('reproduces a bundle signed by a key the keyring does not hold', () => {
    const expected = readVector('wrong-key.bundle.json');
    const built = createBundle(resolveVectorPolicy(), {
      privateKeyPem: readKey('test-untrusted.key.pem'),
      createdAt: vectorCreatedAt,
      baseDir: repoRoot,
      ...vectorResolver('wrong-key.bundle.json'),
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

  it('honours retirement against created_at, and revocation always', () => {
    const bundle = createBundle(resolveVectorPolicy(), {
      privateKeyPem: readKey('test-signing.key.pem'),
      createdAt: vectorCreatedAt,
    });
    const document = JSON.parse(
      readFileSync(path.join(keysRoot, 'keyring.json'), 'utf8'),
    ) as { keys: Record<string, unknown>[] };
    const withEntry = (fields: Record<string, unknown>): string =>
      JSON.stringify({ ...document, keys: [{ ...document.keys[0], ...fields }] });

    // A bundle produced while the key was current keeps verifying after it is
    // retired; one produced at or after `not_after` does not.
    expect(verifyBundle(bundle, {
      keyring: withEntry({ not_after: '2026-09-16T00:00:00.000Z' }),
      now: vectorCreatedAt,
    }).ok).toBe(true);

    const retired = verifyBundle(bundle, {
      keyring: withEntry({ not_after: vectorCreatedAt }),
      now: vectorCreatedAt,
    });
    expect(retired.ok).toBe(false);
    if (!retired.ok) expect(retired.reason).toBe('key_retired');

    const revoked = verifyBundle(bundle, {
      keyring: withEntry({ revoked: true }),
      now: vectorCreatedAt,
    });
    expect(revoked.ok).toBe(false);
    if (!revoked.ok) expect(revoked.reason).toBe('key_revoked');
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
    // Not `BUNDLE_RESOLVER_TOOL`: that names the reference CLI, and the
    // default is deliberately this SDK rather than a tool that did not
    // produce the bundle.
    expect(statement.predicate.resolver.tool).not.toBe(BUNDLE_RESOLVER_TOOL);
  });
});

describe('buildBundleStatement', () => {
  it('names the constants of bundle spec 3 and 4', () => {
    expect(BUNDLE_RESOLVER_TOOL).toBe('h2h');
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

  it('records a directory whose name merely starts with two dots as relative', () => {
    // `..cache` is a name, not a parent segment: only `..` on its own or
    // followed by a separator leaves `baseDir` (bundle spec 4.4).
    const base = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'hushspec-bundle-')));
    try {
      const directory = path.join(base, '..cache');
      mkdirSync(directory);
      const file = path.join(directory, 'policy.yaml');
      writeFileSync(file, 'hushspec: "1.0.0"\nname: dotted\nrules:\n  egress:\n    default: block\n');

      const parsed = parse(readFileSync(file, 'utf8'));
      if (!parsed.ok) throw new Error(parsed.error);
      const resolution = resolveWithOptions(parsed.value, {
        source: file,
        loader: createCompositeLoader(),
      });

      const statement = buildBundleStatement(resolution, {
        createdAt: vectorCreatedAt,
        baseDir: base,
      });
      expect(statement.predicate.chain[0]?.source).toBe('..cache/policy.yaml');
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
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

  it('refuses a date whose year created_at cannot express', () => {
    // `toISOString` widens the year field past 9999, which a fixed-width
    // slice turns into a malformed timestamp rather than an error.
    expect(() =>
      buildBundleStatement(resolveVectorPolicy(), { createdAt: new Date(8.64e15) }),
    ).toThrow(BundleError);
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
  it('refuses a key it cannot read at all', () => {
    expect(() =>
      createBundle(resolveVectorPolicy(), { privateKeyPem: 'not a pem' }),
    ).toThrow(BundleError);
  });

  it('refuses a well-formed key of the wrong algorithm', () => {
    // The case above never reaches the algorithm check -- it fails while
    // parsing the PEM -- so the branch that makes DSSE Ed25519-only was
    // untested. A real P-256 key is well-formed and still has to be refused.
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

    expect(() => createBundle(resolveVectorPolicy(), { privateKeyPem: pem })).toThrow(
      /not Ed25519/,
    );
  });
});

/**
 * Every other SDK validates the bundles it produces against the published
 * schema (`crates/hushspec/tests/bundle_vectors.rs`,
 * `packages/go/hushspec/bundle_vectors_test.go`,
 * `packages/python/tests/test_bundle_vectors.py`). Reproducing the vector
 * bytes proves agreement with the reference CLI, but not that either of them
 * agrees with the schema a consumer validates against -- so check it here too.
 */
describe('createBundle output against the published schema', () => {
  it.each([
    ['signed', 'test-signing.key.pem'],
    ['unsigned', undefined],
  ])('a %s bundle satisfies the envelope and statement schemas', (_kind, key) => {
    const bundle = createBundle(resolveVectorPolicy(), {
      ...(key === undefined ? {} : { privateKeyPem: readKey(key) }),
      createdAt: vectorCreatedAt,
      baseDir: repoRoot,
    });

    expect(schemaErrors(bundleSchema, JSON.parse(bundleToJson(bundle)))).toEqual([]);
    expect(schemaErrors(statementSchema, statementOf(bundle))).toEqual([]);
  });
});

/**
 * An empty name is a name the bundle schema will not accept: both
 * `subject[0].name` and `predicate.policy.name` need at least one character.
 * The 0.x document format places no such constraint on `name`, so a policy
 * that declares one has to be bundled without it.
 */
describe('a policy whose name is empty', () => {
  it('takes its subject name from the leaf file and makes no name claim', () => {
    const statement = buildBundleStatement(resolvePolicy(emptyNamePolicy), {
      createdAt: vectorCreatedAt,
      baseDir: repoRoot,
    });
    expect(statement.subject[0]?.name).toBe('empty-name-0-2.yaml');
    // Absent, not present and empty.
    expect('name' in statement.predicate.policy).toBe(false);
  });

  it('produces a schema-valid statement that verifies', () => {
    const resolution = resolvePolicy(emptyNamePolicy);
    const bundle = createBundle(resolution, {
      privateKeyPem: readKey('test-signing.key.pem'),
      createdAt: vectorCreatedAt,
      baseDir: repoRoot,
    });

    expect(schemaErrors(statementSchema, statementOf(bundle))).toEqual([]);

    const outcome = verifyBundle(bundle, {
      keyring: vectorKeyring(),
      now: vectorCreatedAt,
      policy: resolution,
    });
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.subjectName).toBe('empty-name-0-2.yaml');
      expect(outcome.policyName).toBeUndefined();
      expect(outcome.policyChecked).toBe(true);
    }
  });
});

function createHashOf(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}
