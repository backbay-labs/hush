import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import { describe, expect, it } from 'vitest';
import {
  BUNDLE_REASONS,
  bundleStatement,
  pae,
  parseBundle,
  verifyBundle,
  type BundleReason,
} from '../src/bundle.js';
import { loadKeyring } from '../src/signing.js';
import { createCompositeLoader, resolveWithOptions } from '../src/resolve.js';
import type { Resolution } from '../src/resolve.js';
import { parse } from '../src/parse.js';

/**
 * The normative policy-bundle vectors (bundle spec 7, `fixtures/bundle/`).
 *
 * An implementation conforms as a bundle verifier if, for every case in
 * `vectors.yaml`, it returns the expected outcome: `valid`, or invalid with
 * the expected reason code of bundle spec 5.4.
 */

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const fixturesRoot = path.join(repoRoot, 'fixtures', 'bundle');

interface Manifest {
  hushspec_bundle_vectors: string;
  description?: string;
  defaults: { keyring: string; now: string };
  cases: Case[];
}

interface Case {
  name: string;
  bundle: string;
  keyring?: string;
  policy?: string;
  now?: string;
  expect: 'valid' | { invalid: string };
  note?: string;
}

const manifest = YAML.parse(
  readFileSync(path.join(fixturesRoot, 'vectors.yaml'), 'utf8'),
) as Manifest;

/** Resolve a policy the way `h2h bundle verify --policy` does. */
function resolvePolicy(filePath: string): Resolution | undefined {
  if (!existsSync(filePath)) return undefined;
  const parsed = parse(readFileSync(filePath, 'utf8'));
  if (!parsed.ok) return undefined;
  try {
    return resolveWithOptions(parsed.value, {
      source: filePath,
      loader: createCompositeLoader(),
    });
  } catch {
    // A policy that will not resolve has nothing to compare, which is check
    // 4's own failure -- never a thrown error out of the runner.
    return undefined;
  }
}

describe('policy bundle vectors', () => {
  it('declares the manifest version the runner understands', () => {
    expect(manifest.hushspec_bundle_vectors).toBe('0.1.0');
    expect(manifest.cases.length).toBeGreaterThan(0);
  });

  for (const testCase of manifest.cases) {
    it(`${testCase.name}`, () => {
      const keyring = loadKeyring(
        readFileSync(
          path.join(fixturesRoot, testCase.keyring ?? manifest.defaults.keyring),
          'utf8',
        ),
      );
      const bundleJson = readFileSync(path.join(fixturesRoot, testCase.bundle), 'utf8');
      const policy = testCase.policy == null
        ? undefined
        : resolvePolicy(path.join(fixturesRoot, testCase.policy));

      const outcome = verifyBundle(bundleJson, {
        keyring,
        now: testCase.now ?? manifest.defaults.now,
        // A policy the manifest names but that does not resolve is still
        // check 4's input: `verifyBundle` reports `policy_mismatch` for it.
        ...(testCase.policy == null ? {} : { policy: policy ?? { hushspec: '0.0.0' } }),
      });

      if (testCase.expect === 'valid') {
        expect(outcome.ok ? 'valid' : `${outcome.reason}: ${outcome.detail}`).toBe('valid');
        if (!outcome.ok) return;
        expect(outcome.keyIds.length).toBeGreaterThan(0);
        expect(outcome.contentHash).toMatch(/^sha256:[0-9a-f]{64}$/);
        expect(outcome.policyChecked).toBe(testCase.policy != null);
        expect(outcome.verifiedAt).toBe(testCase.now ?? manifest.defaults.now);
      } else {
        expect(outcome.ok).toBe(false);
        if (outcome.ok) return;
        expect(outcome.reason).toBe(testCase.expect.invalid as BundleReason);
        expect(outcome.detail.length).toBeGreaterThan(0);
      }
    });
  }

  it('covers every reason code the specification defines', () => {
    const expected = new Set(
      manifest.cases
        .map(testCase => (testCase.expect === 'valid' ? undefined : testCase.expect.invalid))
        .filter((code): code is string => code != null),
    );
    for (const code of BUNDLE_REASONS) {
      expect(expected.has(code), `no vector expects ${code}`).toBe(true);
    }
  });
});

describe('bundle parsing', () => {
  const validBundle = (): string =>
    readFileSync(path.join(fixturesRoot, 'bundles/valid.bundle.json'), 'utf8');

  it('parses an envelope and reads its statement', () => {
    const envelope = parseBundle(validBundle());
    expect(envelope.payloadType).toBe('application/vnd.in-toto+json');
    expect(envelope.signatures).toHaveLength(1);

    const statement = bundleStatement(envelope);
    expect(statement._type).toBe('https://in-toto.io/Statement/v1');
    expect(statement.predicateType).toBe(
      'https://hushspec.dev/attestation/policy-bundle/v0.1',
    );
    expect(statement.predicate.bundle_version).toBe('0.1');
    expect(statement.subject).toHaveLength(1);
  });

  it('refuses a document that is not a DSSE envelope', () => {
    expect(() => parseBundle('{}')).toThrow(/payloadType is required/);
    expect(() => parseBundle('not json')).toThrow(/not JSON/);
    expect(() => parseBundle(JSON.parse(validBundle()) as unknown)).not.toThrow();
  });

  it('builds the PAE the specification quotes', () => {
    // The DSSE specification's own example.
    expect(pae('http://example.com/HelloWorld', Buffer.from('hello world')).toString('utf8'))
      .toBe('DSSEv1 29 http://example.com/HelloWorld 11 hello world');
    // Lengths are byte counts, not character counts.
    expect(pae('t', Buffer.from('é', 'utf8')).toString('utf8')).toBe('DSSEv1 1 t 2 é');
    // Every HushSpec bundle carries the same 28-byte type.
    expect(pae('application/vnd.in-toto+json', Buffer.from('{}')).toString('utf8'))
      .toBe('DSSEv1 28 application/vnd.in-toto+json 2 {}');
  });

  it('needs exactly one key source', () => {
    expect(() => verifyBundle(validBundle(), {})).toThrow(/keyring or a publicKeyPem/);
    expect(() =>
      verifyBundle(validBundle(), { keyring: '{}', publicKeyPem: 'x' })).toThrow(/not both/);
  });

  it('verifies under a single public key as well as a keyring', () => {
    const publicKeyPem = readFileSync(
      path.join(repoRoot, 'fixtures/signing/keys/test-signing.pub.pem'),
      'utf8',
    );
    const outcome = verifyBundle(validBundle(), { publicKeyPem, now: manifest.defaults.now });
    expect(outcome.ok).toBe(true);
  });
});
