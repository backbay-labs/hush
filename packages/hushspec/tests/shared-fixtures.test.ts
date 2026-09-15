import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import { describe, expect, it } from 'vitest';
import { merge } from '../src/merge.js';
import { parse } from '../src/parse.js';
import { validate } from '../src/validate.js';
import { evaluateWithDetection } from '../src/detection.js';
import type { EvaluationAction } from '../src/evaluate.js';
import type { RuntimeContext } from '../src/conditions.js';
import { resolveWithOptions, resolutionFromResolved, type Loader } from '../src/resolve.js';
import type { HushSpec } from '../src/schema.js';
import {
  deterministicUuidV7,
  evaluateAudited,
  type AuditConfig,
  type AuditContext,
  type DecisionReceipt,
  type RuleTraceEntry,
} from '../src/receipt.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const fixturesRoot = path.join(repoRoot, 'fixtures');

/** One expected `rule_trace` entry (evaluator-test schema 0.2). */
interface RuleTraceExpectation {
  rule_block: string;
  outcome: string;
  rule_path?: string;
}

interface EvaluationCase {
  description: string;
  action: Record<string, unknown>;
  /** Runtime context for `when` conditions (evaluator-test schema v0, D15). */
  context?: RuntimeContext;
  /** The controls this case is evidence for (evaluator-test schema 0.2). */
  controls?: { framework: string; control_id: string }[];
  /** Free-form labels (evaluator-test schema 0.2). */
  tags?: string[];
  expect: {
    decision: string;
    matched_rule?: string;
    reason?: string;
    origin_profile?: string;
    posture?: {
      current: string;
      next: string;
    };
    rule_trace?: RuleTraceExpectation[];
    receipt?: Record<string, unknown>;
  };
}

/**
 * The fixed inputs an `expect.receipt` assertion is evaluated under, pinned by
 * `fixtures/receipts/expected/README.md` -- the same ones the expected-receipt
 * vectors use, so a fixture's `expect.receipt` and those files describe one
 * object.
 */
const RECEIPT_CLOCK_MILLIS = 1_789_473_600_000;

const RECEIPT_CONFIG: AuditConfig = {
  enabled: true,
  includeRuleTrace: true,
  // Off: an assertion must not depend on the machine running it.
  recordDuration: false,
};

/** Receipt members that are inputs rather than outcomes, never compared. */
const RECEIPT_IGNORED_MEMBERS = new Set(['actor', 'timestamp', 'receipt_id']);

function receiptContext(caseIndex: number, context?: RuntimeContext): AuditContext {
  return {
    actor: {
      agent_id: 'fixture-agent',
      session_id: 'fixture-session',
      principal: 'fixture@hushspec.dev',
      runtime: 'hushspec-conformance/0.2',
    },
    enforcementMode: 'enforce',
    timeSource: 'trusted',
    clock: new Date(RECEIPT_CLOCK_MILLIS),
    receiptId: deterministicUuidV7(RECEIPT_CLOCK_MILLIS, caseIndex),
    ...(context != null ? { context } : {}),
  };
}

/** `rule_block:outcome[@rule_path]`, the spelling a trace mismatch reports. */
function renderTraceEntry(entry: { rule_block: string; outcome: string; rule_path?: string }): string {
  return entry.rule_path != null
    ? `${entry.rule_block}:${entry.outcome}@${entry.rule_path}`
    : `${entry.rule_block}:${entry.outcome}`;
}

/**
 * Assert `expect.rule_trace` against the recorded trace: in order, in full,
 * and member by member -- `rule_path` only where the fixture spells it.
 */
function assertRuleTrace(
  expected: RuleTraceExpectation[],
  actual: RuleTraceEntry[],
  label: string,
): void {
  expect(actual.map(renderTraceEntry).length, `${label}: rule_trace length`).toBe(expected.length);
  expected.forEach((want, index) => {
    const got = actual[index];
    expect(got.rule_block, `${label}: rule_trace[${index}].rule_block`).toBe(want.rule_block);
    expect(got.outcome, `${label}: rule_trace[${index}].outcome`).toBe(want.outcome);
    if (want.rule_path != null) {
      expect(got.rule_path, `${label}: rule_trace[${index}].rule_path`).toBe(want.rule_path);
    }
  });
}

/**
 * Assert a partial `expect.receipt` against the receipt produced under the
 * fixed inputs: nested objects are compared member-wise, everything else
 * exactly.
 */
function assertReceiptMembers(
  expected: Record<string, unknown>,
  actual: Record<string, unknown>,
  label: string,
  path = '',
): void {
  for (const [key, want] of Object.entries(expected)) {
    if (path === '' && RECEIPT_IGNORED_MEMBERS.has(key)) continue;
    const at = path === '' ? key : `${path}.${key}`;
    const got = actual?.[key];
    if (want != null && typeof want === 'object' && !Array.isArray(want)) {
      expect(got, `${label}: receipt.${at}`).toBeTypeOf('object');
      assertReceiptMembers(
        want as Record<string, unknown>,
        got as Record<string, unknown>,
        label,
        at,
      );
      continue;
    }
    expect(got, `${label}: receipt.${at}`).toEqual(want);
  }
}

interface EvaluationFixture {
  hushspec_test: string;
  description: string;
  policy: unknown;
  cases: EvaluationCase[];
}

/** Fixture format versions this runner accepts (evaluator-test schema). */
const SUPPORTED_TEST_VERSIONS = ['0.1.0', '0.2.0'];

const validDirs = [
  'core/valid',
  'posture/valid',
  'origins/valid',
  'detection/valid',
];

const invalidDirs = [
  'core/invalid',
  'posture/invalid',
  'origins/invalid',
  'detection/invalid',
];

const evaluationDirs = [
  'core/evaluation',
  'posture/evaluation',
  'origins/evaluation',
  'detection/evaluation',
];

const mergeDirs = [
  'core/merge',
  'posture/merge',
  'origins/merge',
  'detection/merge',
];

describe('shared fixture corpus', () => {
  for (const dir of validDirs) {
    for (const fixturePath of listYamlFiles(dir)) {
      it(`accepts ${path.relative(fixturesRoot, fixturePath)}`, () => {
        const result = parse(readFileSync(fixturePath, 'utf8'));
        expect(result.ok).toBe(true);
        if (!result.ok) return;
        expect(validate(result.value).valid).toBe(true);
      });
    }
  }

  for (const dir of invalidDirs) {
    for (const fixturePath of listYamlFiles(dir)) {
      it(`rejects ${path.relative(fixturesRoot, fixturePath)}`, () => {
        const result = parse(readFileSync(fixturePath, 'utf8'));
        if (!result.ok) {
          expect(result.ok).toBe(false);
          return;
        }
        expect(validate(result.value).valid).toBe(false);
      });
    }
  }

  for (const dir of mergeDirs) {
    for (const fixtureDir of mergeFixtureDirs(path.join(fixturesRoot, dir))) {
      runMergeFixtures(fixtureDir);
    }
  }

  for (const dir of evaluationDirs) {
    for (const fixturePath of listYamlFiles(dir)) {
      const raw = YAML.parse(readFileSync(fixturePath, 'utf8')) as EvaluationFixture;
      const policyYaml = YAML.stringify(raw.policy);
      const parsed = parse(policyYaml);

      it(`validates evaluator fixture ${path.relative(fixturesRoot, fixturePath)}`, () => {
        expect(SUPPORTED_TEST_VERSIONS).toContain(raw.hushspec_test);
        expect(raw.description.trim().length).toBeGreaterThan(0);
        expect(Array.isArray(raw.cases)).toBe(true);
        expect(raw.cases.length).toBeGreaterThan(0);
        expect(parsed.ok).toBe(true);
        if (!parsed.ok) return;
        expect(validate(parsed.value).valid).toBe(true);
      });

      if (!parsed.ok) continue;
      const spec = parsed.value;

      raw.cases.forEach((testCase, caseIndex) => {
        const label = `[${path.relative(fixturesRoot, fixturePath)}] ${testCase.description}`;
        it(`evaluates ${label}`, () => {
          // Per-case `context` is delivered on the action, which is where the
          // evaluator reads the runtime context for `when` conditions (D15).
          const action: EvaluationAction = {
            ...(testCase.action as unknown as EvaluationAction),
            ...(testCase.context != null ? { context: testCase.context } : {}),
          };
          const result = evaluateWithDetection(spec, action).evaluation;

          expect(result.decision).toBe(testCase.expect.decision);

          if (testCase.expect.matched_rule != null) {
            expect(result.matched_rule).toBe(testCase.expect.matched_rule);
          }

          if (testCase.expect.reason != null) {
            expect(result.reason).toBe(testCase.expect.reason);
          }

          if (testCase.expect.origin_profile != null) {
            expect(result.origin_profile).toBe(testCase.expect.origin_profile);
          }

          if (testCase.expect.posture != null) {
            expect(result.posture).toBeDefined();
            expect(result.posture!.current).toBe(testCase.expect.posture.current);
            expect(result.posture!.next).toBe(testCase.expect.posture.next);
          }

          // `rule_trace` and `receipt` are asserted through the audited path,
          // because a receipt is where both are published (receipt spec 4.3).
          if (testCase.expect.rule_trace != null || testCase.expect.receipt != null) {
            const receipt: DecisionReceipt = evaluateAudited(
              resolutionFromResolved(spec),
              action,
              RECEIPT_CONFIG,
              receiptContext(caseIndex, testCase.context),
            );
            if (testCase.expect.rule_trace != null) {
              assertRuleTrace(testCase.expect.rule_trace, receipt.rule_trace, label);
            }
            if (testCase.expect.receipt != null) {
              assertReceiptMembers(
                testCase.expect.receipt,
                JSON.parse(JSON.stringify(receipt)) as Record<string, unknown>,
                label,
              );
            }
          }
        });
      });
    }
  }
});

function listYamlFiles(subdir: string): string[] {
  return listYamlFilesIn(path.join(fixturesRoot, subdir));
}

function listYamlFilesIn(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter(file => file.endsWith('.yaml') || file.endsWith('.yml'))
    .sort()
    .map(file => path.join(dir, file));
}

/**
 * Every directory under `root` that is a merge fixture: one holding a
 * `base.yaml`. Vectors started life flat in `<area>/merge/`, and a case that
 * needs its own base -- a digest pin has to pin *some* specific document --
 * gets a subdirectory instead of colliding with the shared one.
 */
function mergeFixtureDirs(root: string): string[] {
  if (!existsSync(root)) return [];
  const found: string[] = [];
  const walk = (dir: string): void => {
    if (existsSync(path.join(dir, 'base.yaml'))) found.push(dir);
    for (const entry of readdirSync(dir).sort()) {
      const child = path.join(dir, entry);
      if (statSync(child).isDirectory()) walk(child);
    }
  };
  walk(root);
  return found;
}

/**
 * Whether a merge fixture is expected to be *refused* rather than merged.
 *
 * Two spellings, because the four runners have to agree on one and the corpus
 * may arrive with either: a marker file named `expect-reject` in the fixture
 * directory, or `reject: true` in a `fixture.yaml` beside the vectors.
 * `reject:` may also list the child basenames (with or without the `child-`
 * prefix and extension) when only some cases in a directory are refusals.
 */
function rejectedChildren(dir: string): (childPath: string) => boolean {
  const markers = ['expect-reject', 'expect-reject.txt', '.expect-reject'];
  if (markers.some(marker => existsSync(path.join(dir, marker)))) {
    return () => true;
  }

  const metaPath = path.join(dir, 'fixture.yaml');
  if (!existsSync(metaPath)) return () => false;
  const meta = YAML.parse(readFileSync(metaPath, 'utf8')) as { reject?: unknown } | null;
  const reject = meta?.reject;
  if (reject === true) return () => true;
  if (!Array.isArray(reject)) return () => false;

  const names = new Set(reject.filter((name): name is string => typeof name === 'string'));
  return (childPath: string) => {
    const base = path.basename(childPath);
    const stem = base.replace(/\.(ya?ml)$/, '');
    return names.has(base) || names.has(stem) || names.has(stem.replace(/^child-/, ''));
  };
}

/**
 * A loader scoped to one fixture directory that accepts the reference styles
 * the corpus uses: `base`, `base.yaml`, `./base.yaml`. Fixtures are meant to
 * be portable across four runners, so a reference is resolved inside the
 * fixture directory and nowhere else.
 */
function fixtureLoader(dir: string): Loader {
  return (reference: string) => {
    for (const candidate of [reference, `${reference}.yaml`, `${reference}.yml`]) {
      const file = path.resolve(dir, candidate);
      if (!file.startsWith(dir) || !existsSync(file) || statSync(file).isDirectory()) continue;
      const parsed = parse(readFileSync(file, 'utf8'));
      if (!parsed.ok) throw new Error(`failed to parse ${file}: ${parsed.error}`);
      return { source: file, spec: parsed.value };
    }
    throw new Error(`cannot resolve 'extends: ${reference}' inside ${dir}`);
  };
}

/** `extends: "<ref>#sha256:<digest>"` -- the case that needs the resolver. */
function isDigestPinned(spec: HushSpec): boolean {
  return typeof spec.extends === 'string' && spec.extends.includes('#sha256:');
}

function runMergeFixtures(dir: string): void {
  const children = listYamlFilesIn(dir).filter(file => path.basename(file).startsWith('child-'));
  if (children.length === 0) return;

  const basePath = path.join(dir, 'base.yaml');
  const rejects = rejectedChildren(dir);

  for (const fixturePath of children) {
    const relative = path.relative(fixturesRoot, fixturePath);
    const expectedPath = path.join(
      dir,
      path.basename(fixturePath).replace('child-', 'expected-'),
    );
    const rejected = rejects(fixturePath);

    it(`${rejected ? 'refuses' : 'merges'} ${relative}`, () => {
      const outcome = applyMergeFixture(dir, basePath, fixturePath);
      if (rejected) {
        expect(outcome.ok, `expected ${relative} to be refused`).toBe(false);
        return;
      }
      expect(outcome.ok ? '' : outcome.error).toBe('');
      if (!outcome.ok) return;
      const expected = expectParsedFixture(expectedPath);
      expect(normalizeSpec(outcome.value)).toEqual(normalizeSpec(expected));
    });
  }
}

/**
 * Produce the merged document for one `child-*.yaml`.
 *
 * A child that pins its base by digest goes through the resolver, which is
 * what enforces the pin; every other child keeps the direct `merge(base,
 * child)` the corpus has always been checked with, so the pinning vectors add
 * a path rather than changing one.
 */
function applyMergeFixture(
  dir: string,
  basePath: string,
  childPath: string,
): { ok: true; value: HushSpec } | { ok: false; error: string } {
  const child = parse(readFileSync(childPath, 'utf8'));
  if (!child.ok) return { ok: false, error: child.error };

  try {
    if (isDigestPinned(child.value)) {
      return {
        ok: true,
        value: resolveWithOptions(child.value, {
          source: childPath,
          loader: fixtureLoader(dir),
        }).spec,
      };
    }
    const base = parse(readFileSync(basePath, 'utf8'));
    if (!base.ok) return { ok: false, error: base.error };
    return { ok: true, value: merge(base.value, child.value) };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}


function expectParsedFixture(fixturePath: string) {
  const result = parse(readFileSync(fixturePath, 'utf8'));
  expect(result.ok, fixturePath).toBe(true);
  if (!result.ok) {
    throw new Error(result.error);
  }
  return result.value;
}

function normalizeSpec(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value));
}
