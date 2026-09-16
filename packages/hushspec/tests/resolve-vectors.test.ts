import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import { describe, expect, it } from 'vitest';
import { parseOrThrow } from '../src/parse.js';
import {
  MEMORY_SOURCE,
  createCompositeLoader,
  resolveErrorReason,
  resolveWithOptions,
} from '../src/resolve.js';

/**
 * The shared resolution vectors (`fixtures/core/resolve/`): digest pins and
 * chain provenance, core spec 2.3 and receipt spec 4.2.
 *
 * Each vector is an inline leaf whose `extends` references only builtins, so
 * every SDK resolves it from its own embedded rulesets with no filesystem.
 * The expectation is either the resolved content hash plus the chain links
 * (root first, the leaf recorded as `memory`) or a rejection reason code.
 * The vectors are shared by every SDK, which must agree on them exactly.
 */

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const vectorsDir = path.join(repoRoot, 'fixtures/core/resolve');

interface Link {
  source: string;
  content_hash: string;
}

interface Vector {
  hushspec_resolve: string;
  description: string;
  policy: unknown;
  expect: {
    resolves?: boolean;
    content_hash?: string;
    chain?: Link[];
    rejects?: string;
  };
}

function vectorFiles(): string[] {
  return readdirSync(vectorsDir)
    .filter((name) => name.endsWith('.yaml'))
    .sort();
}

describe('resolve vectors', () => {
  const files = vectorFiles();

  it('finds the committed vectors', () => {
    expect(files.length).toBeGreaterThanOrEqual(7);
  });

  for (const file of files) {
    const vector = YAML.parse(readFileSync(path.join(vectorsDir, file), 'utf8')) as Vector;

    it(`${file}: ${vector.description}`, () => {
      expect(vector.hushspec_resolve).toBe('0.1.0');
      const spec = parseOrThrow(YAML.stringify(vector.policy));
      const loader = createCompositeLoader();

      if (vector.expect.rejects !== undefined) {
        let thrown: unknown;
        try {
          resolveWithOptions(spec, { loader });
        } catch (error) {
          thrown = error;
        }
        expect(thrown, `${file} must be rejected`).toBeDefined();
        expect(resolveErrorReason(thrown)).toBe(vector.expect.rejects);
        return;
      }

      const resolution = resolveWithOptions(spec, { loader });
      expect(resolution.content_hash).toBe(vector.expect.content_hash);
      expect(
        resolution.chain.map((link) => ({
          source: link.source,
          content_hash: link.content_hash,
        })),
      ).toEqual(vector.expect.chain);
      // The leaf is always last and, for an in-memory document, is `memory`.
      expect(resolution.chain[resolution.chain.length - 1]!.source).toBe(MEMORY_SOURCE);
      expect(resolution.spec.extends).toBeUndefined();
    });
  }
});

describe('digest pins under requireSignature', () => {
  it('lets a matching pin vouch for a builtin hop but still refuses the leaf', () => {
    // Mirrors the Rust `pins_satisfy_a_signature_requirement_for_that_hop`
    // test: a pinned hop needs no envelope, but the memory leaf cannot prove
    // itself, so the load fails closed on it.
    const pinned = YAML.parse(
      readFileSync(path.join(vectorsDir, 'pin-valid.yaml'), 'utf8'),
    ) as Vector;
    const spec = parseOrThrow(YAML.stringify(pinned.policy));
    expect(() =>
      resolveWithOptions(spec, {
        loader: createCompositeLoader(),
        options: { requireSignature: true, keyring: undefined },
      }),
    ).toThrow(/requireSignature needs a keyring/);
  });
});
