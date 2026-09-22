import { existsSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import { describe, expect, it } from 'vitest';
import { parseOrThrow } from '../src/parse.js';
import { canonicalizeValue, type JsonValue } from '../src/canonical.js';
import { resolutionFromResolved } from '../src/resolve.js';
import type { EvaluationAction } from '../src/evaluate.js';
import type { RuntimeContext } from '../src/conditions.js';
import {
  canonicalJson,
  deterministicUuidV7,
  evaluateAudited,
  parseReceipt,
  receiptHash,
} from '../src/receipt.js';
import type { AuditConfig, AuditContext, DecisionReceipt } from '../src/receipt.js';
import { schemaErrors, schemaValid, type SchemaDocument } from './helpers/json-schema.js';

/**
 * The normative receipt vectors.
 *
 * `fixtures/receipts/expected/<module>/<fixture stem>/<case index>.json` is
 * the format 0.2 receipt every SDK MUST produce for that shared evaluation
 * case under the fixed inputs of `fixtures/receipts/expected/README.md`.
 * Comparison is byte for byte **after canonicalization** (RFC 8785), so
 * pretty-printing and key order in the files do not matter and every field
 * value does.
 *
 * `fixtures/receipts/valid/` and `invalid/` pin the 0.2 schema itself.
 */

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const fixturesRoot = path.join(repoRoot, 'fixtures');
const expectedRoot = path.join(fixturesRoot, 'receipts/expected');

/** Fixed evaluation time for every expected receipt: 2026-09-15T12:00:00Z. */
const CLOCK_MILLIS = 1_789_473_600_000;

const CONFIG: AuditConfig = {
  enabled: true,
  includeRuleTrace: true,
  // Off: the vectors' bytes must not depend on the machine that produced them.
  recordDuration: false,
};

function fixedContext(caseIndex: number): AuditContext {
  return {
    actor: {
      agent_id: 'fixture-agent',
      session_id: 'fixture-session',
      principal: 'fixture@hushspec.dev',
      runtime: 'hushspec-conformance/0.2',
    },
    enforcementMode: 'enforce',
    timeSource: 'trusted',
    clock: new Date(CLOCK_MILLIS),
    receiptId: deterministicUuidV7(CLOCK_MILLIS, caseIndex),
  };
}

interface EvaluationCase {
  description?: string;
  action: EvaluationAction;
  context?: RuntimeContext;
}

interface EvaluationFixture {
  policy: unknown;
  cases: EvaluationCase[];
}

/** Every shared evaluation fixture, in the order the Rust generator walks. */
function evaluationFixtures(): string[] {
  const paths: string[] = [];
  for (const module of ['core', 'posture', 'origins', 'detection']) {
    const dir = path.join(fixturesRoot, module, 'evaluation');
    if (!existsSync(dir)) continue;
    for (const name of readdirSync(dir)) {
      if (name.endsWith('.test.yaml')) paths.push(path.join(dir, name));
    }
  }
  return paths.sort();
}

/** `fixtures/receipts/expected/<module>/<fixture stem>/` */
function expectedDir(fixturePath: string): string {
  const module = path.basename(path.dirname(path.dirname(fixturePath)));
  const stem = path.basename(fixturePath).replace(/\.test\.yaml$/, '');
  return path.join(expectedRoot, module, stem);
}

function canonical(value: unknown): string {
  return canonicalizeValue(value as JsonValue);
}

describe('expected receipts', () => {
  const fixtures = evaluationFixtures();

  it('finds the shared evaluation fixtures', () => {
    expect(fixtures.length).toBeGreaterThan(0);
  });

  for (const fixturePath of fixtures) {
    const relative = path.relative(fixturesRoot, fixturePath);
    const fixture = YAML.parse(readFileSync(fixturePath, 'utf8')) as EvaluationFixture;
    const dir = expectedDir(fixturePath);

    it(`matches every expected receipt for ${relative}`, () => {
      const spec = parseOrThrow(YAML.stringify(fixture.policy));
      const resolution = resolutionFromResolved(spec);

      fixture.cases.forEach((testCase, index) => {
        const action: EvaluationAction = { ...testCase.action };
        if (action.context === undefined && testCase.context !== undefined) {
          action.context = testCase.context;
        }
        const receipt = evaluateAudited(resolution, action, CONFIG, fixedContext(index));

        const file = path.join(dir, `${index}.json`);
        expect(existsSync(file), `${file} is missing`).toBe(true);
        const expected = JSON.parse(readFileSync(file, 'utf8')) as unknown;

        expect(canonicalJson(receipt), `${relative} case ${index}`).toBe(canonical(expected));
        // The receipt hash is what a log links and a signature covers, so
        // agreeing on it is the property the chain actually depends on.
        expect(receiptHash(receipt)).toBe(
          receiptHash(expected as DecisionReceipt),
        );
      });
    });
  }
});

// ---------------------------------------------------------------------------
// Schema conformance (receipt spec 8)
// ---------------------------------------------------------------------------

const receiptSchema = JSON.parse(
  readFileSync(path.join(repoRoot, 'schemas/hushspec-receipt.v1.schema.json'), 'utf8'),
) as SchemaDocument;

function jsonFiles(dir: string): string[] {
  return readdirSync(dir)
    .filter((name) => name.endsWith('.json'))
    .sort()
    .map((name) => path.join(dir, name));
}

describe('receipt schema vectors', () => {
  const validDir = path.join(fixturesRoot, 'receipts/valid');
  const invalidDir = path.join(fixturesRoot, 'receipts/invalid');

  for (const file of jsonFiles(validDir)) {
    it(`accepts ${path.basename(file)}`, () => {
      const receipt = JSON.parse(readFileSync(file, 'utf8')) as unknown;
      expect(schemaErrors(receiptSchema, receipt)).toEqual([]);
      // A conformant parser accepts it too (receipt spec 2, item 4).
      expect(() => parseReceipt(JSON.stringify(receipt))).not.toThrow();
      // Round-trip: re-serializing in canonical form yields the same bytes
      // (receipt spec 2, item 5).
      const reparsed = parseReceipt(JSON.stringify(receipt));
      expect(canonicalJson(reparsed)).toBe(canonical(receipt));
      expect(receiptHash(reparsed)).toMatch(/^sha256:[0-9a-f]{64}$/);
    });
  }

  for (const file of jsonFiles(invalidDir)) {
    it(`rejects ${path.basename(file)}`, () => {
      const receipt = JSON.parse(readFileSync(file, 'utf8')) as unknown;
      expect(schemaValid(receiptSchema, receipt), `${file} must be rejected`).toBe(false);
      // The parser is the schema's stand-in wherever there is no validator to
      // run, so it has to reject the same documents (receipt spec 2, item 4).
      expect(() => parseReceipt(JSON.stringify(receipt)), `${file} must be rejected`).toThrow();
    });
  }

  it('does not read an explicit null as an absent member', () => {
    // The two spellings parse to the same receipt but are different documents,
    // and a log entry's hash covers the difference.
    const file = jsonFiles(validDir)[0]!;
    const receipt = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
    expect(() => parseReceipt(JSON.stringify({ ...receipt, reason: null }))).toThrow(
      /reason must be a string/,
    );
  });

  it('walks both directories', () => {
    expect(jsonFiles(validDir).length).toBeGreaterThanOrEqual(12);
    expect(jsonFiles(invalidDir).length).toBeGreaterThanOrEqual(15);
  });

  it('validates the receipts this SDK emits against the published schema', () => {
    for (const fixturePath of evaluationFixtures()) {
      const fixture = YAML.parse(readFileSync(fixturePath, 'utf8')) as EvaluationFixture;
      const resolution = resolutionFromResolved(parseOrThrow(YAML.stringify(fixture.policy)));
      fixture.cases.forEach((testCase, index) => {
        const action: EvaluationAction = { ...testCase.action };
        if (action.context === undefined && testCase.context !== undefined) {
          action.context = testCase.context;
        }
        const receipt = evaluateAudited(resolution, action, CONFIG, fixedContext(index));
        // Through JSON so `undefined` members are dropped exactly as a sink
        // would write them.
        const wire = JSON.parse(JSON.stringify(receipt)) as unknown;
        expect(
          schemaErrors(receiptSchema, wire),
          `${path.relative(fixturesRoot, fixturePath)} case ${index}`,
        ).toEqual([]);
      });
    }
  });
});
