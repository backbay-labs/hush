#!/usr/bin/env node
/**
 * Evaluation benchmark: compile-per-call vs. compiled policy.
 *
 * Measures the four ways a policy gets evaluated in this SDK against a mixed
 * action set:
 *
 *   compile-per-call   compilePolicy() + evaluate() on every action -- what an
 *                      evaluator that rebuilds its matchers per call pays.
 *   free function      evaluate(spec, action) -- compiles the document on
 *                      first use and reuses that compilation (WeakMap keyed by
 *                      the document object).
 *   compiled policy    compilePolicy() once, then compiled.evaluate(action).
 *   guard              HushGuard.check(action) -- compiled once at
 *                      construction, plus enforcement bookkeeping.
 *
 * No dependencies beyond the package itself; timings come from
 * `performance.now()` over a warmed loop.
 *
 *   node bench/evaluate.mjs
 *   node bench/evaluate.mjs --iterations 50000
 *   node bench/evaluate.mjs --entry ../other-build/dist/index.js   # compare builds
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(here, '..');
const repoRoot = path.resolve(packageRoot, '..', '..');

function option(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && index + 1 < process.argv.length ? process.argv[index + 1] : fallback;
}

const iterations = Number(option('iterations', '20000'));
const policyPath = path.resolve(repoRoot, option('policy', 'rulesets/default.yaml'));
const entry = path.resolve(process.cwd(), option('entry', path.join(packageRoot, 'dist', 'index.js')));

const sdk = await import(entry);
const { parseOrThrow, evaluate, HushGuard } = sdk;
// Absent from a build predating compiled policies (`--entry` can point at an
// older one): the comparison then reports only the rows that build can run.
const compilePolicy = sdk.compilePolicy;

const spec = parseOrThrow(readFileSync(policyPath, 'utf8'));

/** A mixed action set: allows and denies across every block the policy uses. */
const actions = [
  { type: 'egress', target: 'https://api.openai.com/v1/chat' },
  { type: 'egress', target: 'evil.example.com:443' },
  { type: 'file_read', target: '/home/agent/project/src/index.ts' },
  { type: 'file_read', target: '/home/agent/.ssh/id_rsa' },
  { type: 'file_write', target: '/home/agent/project/notes.md', content: 'nothing secret here\n' },
  {
    type: 'file_write',
    target: '/home/agent/project/config.ts',
    content: 'const key = "AKIAIOSFODNN7EXAMPLE";\n',
  },
  { type: 'tool_call', target: 'read_file', args_size: 2048 },
  { type: 'tool_call', target: 'shell_exec', args_size: 2048 },
  { type: 'shell_command', target: 'git status --short' },
  { type: 'shell_command', target: 'rm -rf /' },
  {
    type: 'patch_apply',
    target: '/home/agent/project/src/index.ts',
    content: '--- a/src/index.ts\n+++ b/src/index.ts\n-const a = 1;\n+const a = 2;\n',
  },
];

function bench(label, run) {
  // Warm up the JIT and any first-use caches, then time a fixed loop.
  for (let i = 0; i < Math.min(2000, iterations); i++) run(actions[i % actions.length]);
  const start = performance.now();
  for (let i = 0; i < iterations; i++) run(actions[i % actions.length]);
  const elapsedMs = performance.now() - start;
  return { label, elapsedMs, perOpUs: (elapsedMs * 1000) / iterations, opsPerSec: (iterations / elapsedMs) * 1000 };
}

const rows = [];

if (compilePolicy !== undefined) {
  rows.push(bench('compile-per-call', (action) => compilePolicy(spec, { strict: false }).evaluate(action)));
}

rows.push(bench('free function (evaluate)', (action) => evaluate(spec, action)));

if (compilePolicy !== undefined) {
  const compiled = compilePolicy(spec);
  rows.push(bench('compiled policy', (action) => compiled.evaluate(action)));
}

const guard = HushGuard.fromYaml(readFileSync(policyPath, 'utf8'));
rows.push(bench('guard.check', (action) => guard.check(action)));

const width = Math.max(...rows.map((row) => row.label.length));
console.log(`policy:     ${path.relative(repoRoot, policyPath)}`);
console.log(`entry:      ${path.relative(repoRoot, entry)}`);
console.log(`iterations: ${iterations} (${actions.length} distinct actions, round-robin)\n`);
for (const row of rows) {
  console.log(
    `${row.label.padEnd(width)}  ${row.perOpUs.toFixed(3).padStart(9)} us/op  ` +
      `${Math.round(row.opsPerSec).toLocaleString('en-US').padStart(12)} ops/s`,
  );
}

const baseline = rows.find((row) => row.label === 'compile-per-call');
const compiled = rows.find((row) => row.label === 'compiled policy');
if (baseline !== undefined && compiled !== undefined) {
  console.log(`\ncompiled policy is ${(baseline.perOpUs / compiled.perOpUs).toFixed(1)}x faster than compiling per call`);
}
