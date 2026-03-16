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
});
