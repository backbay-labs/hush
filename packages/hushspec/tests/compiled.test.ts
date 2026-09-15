import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compilePolicy, compileResolution, CompileError, CompiledPolicy } from '../src/compiled.js';
import { evaluate, evaluateTraced, activatePanic, deactivatePanic, PANIC_RULE } from '../src/evaluate.js';
import type { EvaluationAction } from '../src/evaluate.js';
import { evaluateWithDetection } from '../src/detection.js';
import { parseOrThrow } from '../src/parse.js';
import { computePolicyHash, evaluateAuditedSpec, DEFAULT_AUDIT_CONFIG } from '../src/receipt.js';
import { resolutionFromResolved } from '../src/resolve.js';
import { HushGuard } from '../src/middleware.js';
import type { HushSpec } from '../src/schema.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const defaultPolicy = readFileSync(path.join(repoRoot, 'rulesets', 'default.yaml'), 'utf8');

const ACTIONS: EvaluationAction[] = [
  { type: 'egress', target: 'https://api.openai.com/v1/chat' },
  { type: 'egress', target: 'evil.example.com:443' },
  { type: 'file_read', target: '/home/agent/project/src/index.ts' },
  { type: 'file_read', target: '/home/agent/.ssh/id_rsa' },
  { type: 'file_write', target: '/home/agent/x.ts', content: 'const k = "AKIAIOSFODNN7EXAMPLE";' },
  { type: 'tool_call', target: 'shell_exec', args_size: 16 },
  { type: 'tool_call', target: 'file_write', args_size: 16 },
  { type: 'shell_command', target: 'rm -rf /' },
  { type: 'patch_apply', target: '/home/agent/x.ts', content: '--- a\n+++ b\n-a\n+b\n' },
  { type: 'nonsense', target: 'x' },
];

// A compiled policy is a representation change, never a behavior change: the
// decision, the matched rule, the reason and the recorded trace must be what
// the document-in form produces.
describe('compilePolicy', () => {
  const spec = parseOrThrow(defaultPolicy);

  it('decides exactly what the free functions decide', () => {
    const compiled = compilePolicy(spec);
    for (const action of ACTIONS) {
      expect(compiled.evaluate(action)).toEqual(evaluate(spec, action));
      expect(compiled.evaluateTraced(action)).toEqual(evaluateTraced(spec, action));
      expect(compiled.evaluateWithDetection(action)).toEqual(evaluateWithDetection(spec, action));
    }
  });

  it('keeps the source document for receipts and caches its content hash', () => {
    const compiled = compilePolicy(spec);
    expect(compiled.spec).toBe(spec);
    expect(compiled.contentHash).toBe(computePolicyHash(spec));
    // Cached: the same string, computed once.
    expect(compiled.contentHash).toBe(compiled.resolution.content_hash);
  });

  it('reports the resolution it was compiled with', () => {
    const resolution = resolutionFromResolved(spec, 'file:///policies/default.yaml');
    const compiled = compileResolution(resolution);
    expect(compiled.resolution).toBe(resolution);

    const receipt = compiled.evaluateAudited({ type: 'egress', target: 'api.openai.com' });
    expect(receipt.policy.content_hash).toBe(resolution.content_hash);
    expect(receipt.decision).toBe('allow');
  });

  it('records the receipt evaluateAuditedSpec records', () => {
    const action: EvaluationAction = { type: 'shell_command', target: 'rm -rf /' };
    const ctx = { receiptId: 'fixed', clock: new Date('2026-03-15T00:00:00.000Z') };
    const compiled = compilePolicy(spec);
    const fromCompiled = compiled.evaluateAudited(action, { ...DEFAULT_AUDIT_CONFIG, recordDuration: false }, ctx);
    const fromSpec = evaluateAuditedSpec(spec, action, { ...DEFAULT_AUDIT_CONFIG, recordDuration: false }, ctx);
    expect(fromCompiled).toEqual(fromSpec);
  });

  it('honors the panic protocol', () => {
    const compiled = compilePolicy(spec);
    activatePanic();
    try {
      const result = compiled.evaluate({ type: 'file_read', target: '/tmp/x' });
      expect(result.decision).toBe('deny');
      expect(result.matched_rule).toBe(PANIC_RULE);
    } finally {
      deactivatePanic();
    }
  });
});

// Fail-closed: a pattern outside the RE2 subset is a compile error for a
// caller that compiles ahead of time, and stays an evaluation-time deny for
// the document-in path (core spec 3.14.3).
describe('CompileError', () => {
  const badSpec: HushSpec = {
    hushspec: '0.1.0',
    rules: {
      shell_commands: { enabled: true, forbidden_patterns: ['(?<=sudo)rm\\s+-rf'] },
    },
  };

  it('is raised for a pattern outside the regex profile', () => {
    expect(() => compilePolicy(badSpec)).toThrow(CompileError);
    try {
      compilePolicy(badSpec);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(CompileError);
      expect((error as CompileError).path).toBe('rules.shell_commands.forbidden_patterns[0]');
      expect((error as CompileError).message).toContain('RE2 subset');
    }
  });

  it('names the offending secret pattern', () => {
    const spec: HushSpec = {
      hushspec: '0.1.0',
      rules: {
        secret_patterns: {
          enabled: true,
          patterns: [{ name: 'backref', pattern: '(a)\\1', severity: 'critical' }],
        },
      },
    };
    expect(() => compilePolicy(spec)).toThrow(/rules\.secret_patterns\.patterns\.backref\.pattern/);
  });

  it('defers to a fail-closed deny when strict is off', () => {
    const compiled = compilePolicy(badSpec, { strict: false });
    const result = compiled.evaluate({ type: 'shell_command', target: 'sudo rm -rf /tmp/demo' });
    expect(result.decision).toBe('deny');
    expect(result.matched_rule).toBe('rules.shell_commands.forbidden_patterns[0]');
    expect(result.reason).toContain('RE2 subset');
  });

  it('is never raised through the free functions', () => {
    expect(evaluate(badSpec, { type: 'shell_command', target: 'sudo rm -rf /' }).decision).toBe('deny');
  });
});

describe('HushGuard compiled policy', () => {
  it('compiles once and evaluates through the compiled policy', () => {
    const guard = HushGuard.fromYaml(defaultPolicy);
    const compiled = guard.compiled;
    expect(compiled).toBeInstanceOf(CompiledPolicy);
    guard.check({ type: 'egress', target: 'api.openai.com' });
    guard.check({ type: 'egress', target: 'evil.example.com' });
    expect(guard.compiled).toBe(compiled);
    expect(guard.compiled.spec).toBe(guard.resolution.spec);
  });

  it('recompiles on a policy swap', () => {
    const guard = HushGuard.fromYaml(defaultPolicy);
    const before = guard.compiled;
    guard.swapPolicy(parseOrThrow('hushspec: "0.1.0"\nname: empty\n'));
    expect(guard.compiled).not.toBe(before);
    expect(guard.compiled.spec).toBe(guard.resolution.spec);
    expect(guard.compiled.evaluate({ type: 'egress', target: 'evil.example.com' }).decision).toBe('allow');
  });
});
