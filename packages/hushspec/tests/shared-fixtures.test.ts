import { readFileSync, readdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import { describe, expect, it } from 'vitest';
import { merge } from '../src/merge.js';
import { parse } from '../src/parse.js';
import { validate } from '../src/validate.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const fixturesRoot = path.join(repoRoot, 'fixtures');

interface EvaluationCase {
  description: string;
  action: Record<string, unknown>;
  expect: {
    decision: string;
    matched_rule?: string;
    origin_profile?: string;
    posture?: {
      current: string;
      next: string;
    };
  };
}

interface EvaluationFixture {
  hushspec_test: string;
  description: string;
  policy: unknown;
  cases: EvaluationCase[];
}

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
    const mergeFiles = listYamlFiles(dir);
    if (mergeFiles.length === 0) continue;

    const basePath = path.join(fixturesRoot, dir, 'base.yaml');
    const base = expectParsedFixture(basePath);

    for (const fixturePath of mergeFiles.filter(file => path.basename(file).startsWith('child-'))) {
      const expectedPath = path.join(
        path.dirname(fixturePath),
        path.basename(fixturePath).replace('child-', 'expected-'),
      );

      it(`merges ${path.relative(fixturesRoot, fixturePath)}`, () => {
        const child = expectParsedFixture(fixturePath);
        const expected = expectParsedFixture(expectedPath);
        expect(normalizeSpec(merge(base, child))).toEqual(normalizeSpec(expected));
      });
    }
  }

  for (const dir of evaluationDirs) {
    for (const fixturePath of listYamlFiles(dir)) {
      it(`validates evaluator fixture ${path.relative(fixturesRoot, fixturePath)}`, () => {
        const raw = YAML.parse(readFileSync(fixturePath, 'utf8')) as EvaluationFixture;
        expect(raw.hushspec_test).toBe('0.1.0');
        expect(raw.description.trim().length).toBeGreaterThan(0);
        expect(Array.isArray(raw.cases)).toBe(true);
        expect(raw.cases.length).toBeGreaterThan(0);

        for (const testCase of raw.cases) {
          expect(testCase.description.trim().length).toBeGreaterThan(0);
          expect(['allow', 'warn', 'deny']).toContain(testCase.expect.decision);
          expect(typeof testCase.action).toBe('object');
          expect(testCase.action).not.toBeNull();
          expect(typeof testCase.action.type).toBe('string');
        }

        const policyYaml = YAML.stringify(raw.policy);
        const parsed = parse(policyYaml);
        expect(parsed.ok).toBe(true);
        if (!parsed.ok) return;
        expect(validate(parsed.value).valid).toBe(true);
      });
    }
  }
});

function listYamlFiles(subdir: string): string[] {
  const dir = path.join(fixturesRoot, subdir);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter(file => file.endsWith('.yaml') || file.endsWith('.yml'))
    .sort()
    .map(file => path.join(dir, file));
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
