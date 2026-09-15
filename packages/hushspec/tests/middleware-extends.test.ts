import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { HushGuard } from '../src/middleware.js';
import { parseOrThrow } from '../src/parse.js';
import { computePolicyHash } from '../src/receipt.js';
import { resolveFromFile } from '../src/resolve.js';
import type { PolicyProvider } from '../src/policy-provider.js';
import type { HushSpec } from '../src/schema.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

/** The guard's spec is private; these tests read it to assert it was resolved. */
const specOf = (guard: HushGuard): HushSpec => (guard as unknown as { policy: HushSpec }).policy;

const ALLOW_ALL_POLICY = `
hushspec: "0.1.0"
name: allow-all
rules:
  tool_access:
    default: allow
`;

const BUILTIN_CHILD = `
hushspec: "0.1.0"
extends: "builtin:strict"
name: leaf
rules:
  egress:
    allow: ["api.example.com"]
    default: block
`;

describe('HushGuard extends resolution', () => {
  it('fromFile() resolves a library policy against its builtin base', () => {
    // recommended.yaml declares secret_patterns/patch_integrity/shell_commands/
    // tool_access and inherits forbidden_paths + egress from builtin:default.
    const file = path.join(repoRoot, 'library/general/recommended.yaml');
    const onDisk = parseOrThrow(readFileSync(file, 'utf8'));
    expect(onDisk.extends).toBe('builtin:default');
    expect(onDisk.rules?.forbidden_paths).toBeUndefined();

    const guard = HushGuard.fromFile(file);
    const spec = specOf(guard);

    expect(spec.extends).toBeUndefined();
    // A rule block the leaf policy does not define at all.
    expect(spec.rules?.forbidden_paths?.patterns).toContain('**/.ssh/**');
    expect(spec.rules?.egress).toBeDefined();
    // ...and it is enforced: loaded unresolved, this read was allowed.
    expect(guard.evaluate({ type: 'file_read', target: '/home/dev/.ssh/id_rsa' }).decision).toBe(
      'deny',
    );
  });

  it('fromFile() resolves hipaa-base and hashes the resolved document', () => {
    const file = path.join(repoRoot, 'library/healthcare/hipaa-base.yaml');
    const guard = HushGuard.fromFile(file);
    const spec = specOf(guard);

    expect(spec.extends).toBeUndefined();
    const resolved = resolveFromFile(file);
    expect(resolved.ok).toBe(true);
    if (resolved.ok) {
      expect(computePolicyHash(spec)).toBe(computePolicyHash(resolved.value));
    }
  });

  it('fromFile() resolves a relative extends against the policy directory', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-guard-'));
    writeFileSync(
      path.join(dir, 'base.yaml'),
      'hushspec: "0.1.0"\nname: base\nrules:\n  tool_access:\n    allow: [read_file]\n    default: block\n',
    );
    writeFileSync(
      path.join(dir, 'child.yaml'),
      'hushspec: "0.1.0"\nextends: base.yaml\nname: child\nrules:\n  egress:\n    allow: ["api.example.com"]\n    default: block\n',
    );

    const guard = HushGuard.fromFile(path.join(dir, 'child.yaml'));
    expect(specOf(guard).extends).toBeUndefined();
    expect(guard.evaluate({ type: 'tool_call', target: 'read_file' }).decision).toBe('allow');
    expect(guard.evaluate({ type: 'tool_call', target: 'shell_exec' }).decision).toBe('deny');

    rmSync(dir, { recursive: true, force: true });
  });

  it('fromYaml() resolves builtin references by default', () => {
    const guard = HushGuard.fromYaml(BUILTIN_CHILD);
    const spec = specOf(guard);
    expect(spec.extends).toBeUndefined();
    expect(spec.rules?.forbidden_paths?.patterns).toContain('/etc/shadow');
    expect(guard.evaluate({ type: 'file_read', target: '/etc/shadow' }).decision).toBe('deny');
  });

  it('fromYaml() throws on an unknown builtin base', () => {
    expect(() =>
      HushGuard.fromYaml('hushspec: "0.1.0"\nextends: "builtin:nope"\nname: leaf\n'),
    ).toThrow(/unknown builtin ruleset/);
  });

  it('fromYaml() throws on a file base with no baseDir (never evaluates unresolved)', () => {
    expect(() =>
      HushGuard.fromYaml('hushspec: "0.1.0"\nextends: "./base.yaml"\nname: leaf\n'),
    ).toThrow(/only serves builtin rulesets/);
  });

  it('fromYaml() resolves a file base when baseDir is given', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-guard-'));
    writeFileSync(
      path.join(dir, 'base.yaml'),
      'hushspec: "0.1.0"\nname: base\nrules:\n  tool_access:\n    allow: [read_file]\n    default: block\n',
    );

    const guard = HushGuard.fromYaml('hushspec: "0.1.0"\nextends: "./base.yaml"\nname: leaf\n', {
      baseDir: dir,
    });
    expect(specOf(guard).extends).toBeUndefined();
    expect(guard.evaluate({ type: 'tool_call', target: 'read_file' }).decision).toBe('allow');

    rmSync(dir, { recursive: true, force: true });
  });

  it('fromYaml() throws when the file base is missing under baseDir', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-guard-'));
    expect(() =>
      HushGuard.fromYaml('hushspec: "0.1.0"\nextends: "./missing.yaml"\nname: leaf\n', {
        baseDir: dir,
      }),
    ).toThrow(/Failed to resolve policy/);
    rmSync(dir, { recursive: true, force: true });
  });

  it('fromProvider() resolves the loaded policy', async () => {
    const provider: PolicyProvider = {
      async load() {
        return parseOrThrow(BUILTIN_CHILD);
      },
      watch() {},
      stop() {},
      current() {
        return null;
      },
    };

    const guard = await HushGuard.fromProvider(provider);
    expect(specOf(guard).extends).toBeUndefined();
    expect(specOf(guard).rules?.forbidden_paths?.patterns).toContain('/etc/shadow');
  });

  it('denies when a provider hands back an unresolved policy', async () => {
    const leaf = parseOrThrow(BUILTIN_CHILD);
    const provider: PolicyProvider = {
      async load() {
        return leaf;
      },
      watch() {},
      stop() {},
      current() {
        // A third-party provider that skipped resolution.
        return leaf;
      },
    };

    const guard = await HushGuard.fromProvider(provider);
    const result = guard.evaluate({ type: 'file_read', target: '/tmp/ok.txt' });
    expect(result.decision).toBe('deny');
    expect(result.matched_rule).toBe('__hushspec_policy_provider__');
    expect(result.reason).toContain('unresolved policy');
  });

  it('swapPolicy() rejects an unresolved hot-reloaded policy', () => {
    const guard = HushGuard.fromYaml(ALLOW_ALL_POLICY);
    expect(() =>
      guard.swapPolicy(parseOrThrow('hushspec: "0.1.0"\nextends: "./nope.yaml"\nname: leaf\n')),
    ).toThrow(/Failed to resolve policy/);
    // The previously resolved policy stays in force.
    expect(guard.evaluate({ type: 'tool_call', target: 'anything' }).decision).toBe('allow');
  });

  it('computePolicyHash() refuses to hash an unresolvable policy', () => {
    const leaf = parseOrThrow('hushspec: "0.1.0"\nextends: "./base.yaml"\nname: leaf\n');
    expect(() => computePolicyHash(leaf)).toThrow(/cannot hash an unresolved policy/);
  });

  it('FileProvider resolves on load and on reload', async () => {
    const { FileProvider } = await import('../src/policy-provider.js');
    const dir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-provider-'));
    const file = path.join(dir, 'policy.yaml');
    writeFileSync(file, BUILTIN_CHILD);

    const provider = new FileProvider(file);
    const spec = await provider.load();
    expect(spec.extends).toBeUndefined();
    expect(spec.rules?.forbidden_paths?.patterns).toContain('/etc/shadow');
    provider.stop();

    rmSync(dir, { recursive: true, force: true });
  });
});
