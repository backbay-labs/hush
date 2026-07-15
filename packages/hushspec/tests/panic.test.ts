import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  evaluate,
  activatePanic,
  deactivatePanic,
  isPanicActive,
  panicPolicy,
} from '../src/evaluate.js';
import { parseOrThrow } from '../src/parse.js';
import type { HushSpec } from '../src/schema.js';

describe('panic mode', () => {
  let originalCwd: string;

  beforeEach(() => {
    originalCwd = process.cwd();
    deactivatePanic();
  });

  afterEach(() => {
    process.chdir(originalCwd);
    deactivatePanic();
  });

  it('isPanicActive returns false by default', () => {
    expect(isPanicActive()).toBe(false);
  });

  it('activatePanic sets panic active', () => {
    activatePanic();
    expect(isPanicActive()).toBe(true);
  });

  it('deactivatePanic clears panic active', () => {
    activatePanic();
    expect(isPanicActive()).toBe(true);
    deactivatePanic();
    expect(isPanicActive()).toBe(false);
  });

  it('evaluate returns deny for all action types during panic', () => {
    activatePanic();

    const spec: HushSpec = { hushspec: '0.1.0' };
    const actionTypes = [
      'tool_call',
      'egress',
      'file_read',
      'file_write',
      'patch_apply',
      'shell_command',
      'computer_use',
      'unknown_action',
    ];

    for (const actionType of actionTypes) {
      const result = evaluate(spec, { type: actionType, target: 'anything' });
      expect(result.decision).toBe('deny');
      expect(result.matched_rule).toBe('__hushspec_panic__');
      expect(result.reason).toBe('emergency panic mode is active');
    }
  });

  it('deactivate restores normal evaluation', () => {
    const spec: HushSpec = { hushspec: '0.1.0' };
    const action = { type: 'tool_call', target: 'some_tool' };

    let result = evaluate(spec, action);
    expect(result.decision).toBe('allow');

    activatePanic();
    result = evaluate(spec, action);
    expect(result.decision).toBe('deny');

    deactivatePanic();
    result = evaluate(spec, action);
    expect(result.decision).toBe('allow');
  });

  it('panicPolicy returns a valid HushSpec', () => {
    const spec = panicPolicy();
    expect(spec.hushspec).toBe('0.1.0');
    expect(spec.name).toBe('__hushspec_panic__');
    expect(spec.rules).toBeDefined();
    expect(spec.rules!.forbidden_paths).toBeDefined();
    expect(spec.rules!.egress).toBeDefined();
    expect(spec.rules!.tool_access).toBeDefined();
    expect(spec.rules!.shell_commands).toBeDefined();
    expect(spec.rules!.computer_use).toBeDefined();
  });

  it('panicPolicy does not depend on the current working directory', () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-panic-'));
    process.chdir(tmpDir);

    const spec = panicPolicy();
    expect(spec.name).toBe('__hushspec_panic__');

    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('panic policy denies file reads', () => {
    const spec = panicPolicy();
    const result = evaluate(spec, { type: 'file_read', target: '/etc/passwd' });
    expect(result.decision).toBe('deny');
  });

  it('panic policy denies egress', () => {
    const spec = panicPolicy();
    const result = evaluate(spec, { type: 'egress', target: 'example.com' });
    expect(result.decision).toBe('deny');
  });

  it('panic policy denies tool calls', () => {
    const spec = panicPolicy();
    const result = evaluate(spec, { type: 'tool_call', target: 'any_tool' });
    expect(result.decision).toBe('deny');
  });

  // DRIFT-GUARD: panicPolicy() is a YAML document (rulesets/panic.yaml,
  // mirrored as PANIC_POLICY_YAML in src/evaluate.ts), not a hardcoded
  // decision -- unlike the global activatePanic()/isPanicActive() switch
  // tested above, it is only as deny-all as the rule blocks it declares. It
  // was previously missing an `input_injection` block entirely, so
  // evaluateInputInjection() fell through to its "no rule configured" allow
  // default and an `input_inject` action was ALLOWED under the emergency
  // deny-all policy. Assert deny for input_inject plus one action of every
  // other governed rule type, so a future accidental drop of any block from
  // PANIC_POLICY_YAML (or rulesets/panic.yaml drifting out of sync with it)
  // is caught here instead of silently reopening a hole in panic mode.
  it('panic policy denies input injection and every other governed action type', () => {
    const spec = panicPolicy();
    const actions = [
      { type: 'input_inject', target: 'chat_message' },
      { type: 'file_read', target: '/etc/passwd' },
      { type: 'egress', target: 'example.com' },
      { type: 'tool_call', target: 'any_tool' },
      { type: 'shell_command', target: 'ls -la' },
      { type: 'computer_use', target: 'click' },
    ];

    for (const action of actions) {
      const result = evaluate(spec, action);
      expect(result.decision, `expected deny for action type '${action.type}'`).toBe('deny');
    }
  });
});
