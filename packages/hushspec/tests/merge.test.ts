import { describe, it, expect } from 'vitest';
import { parseOrThrow } from '../src/parse.js';
import { merge } from '../src/merge.js';

describe('merge', () => {
  it('replace strategy uses child entirely', () => {
    const base = parseOrThrow(`
hushspec: "0.1.0"
name: base
rules:
  egress:
    allow: ["a.com"]
    default: block
`);
    const child = parseOrThrow(`
hushspec: "0.1.0"
name: child
extends: base
merge_strategy: replace
rules:
  tool_access:
    block: ["shell_exec"]
    default: allow
`);
    const merged = merge(base, child);
    expect(merged.name).toBe('child');
    expect(merged.extends).toBeUndefined();
    expect(merged.rules?.egress).toBeUndefined();
    expect(merged.rules?.tool_access?.block).toEqual(['shell_exec']);
  });

  it('merge strategy: child rule overrides base rule', () => {
    const base = parseOrThrow(`
hushspec: "0.1.0"
rules:
  egress:
    allow: ["a.com"]
    default: block
  forbidden_paths:
    patterns: ["**/.ssh/**"]
`);
    const child = parseOrThrow(`
hushspec: "0.1.0"
extends: base
merge_strategy: merge
rules:
  egress:
    allow: ["b.com"]
    default: allow
`);
    const merged = merge(base, child);
    expect(merged.extends).toBeUndefined();
    expect(merged.rules?.egress?.allow).toEqual(['b.com']);
    expect(merged.rules?.forbidden_paths?.patterns).toEqual(['**/.ssh/**']);
  });

  it('deep_merge (default): child rule overrides, base preserved', () => {
    const base = parseOrThrow(`
hushspec: "0.1.0"
rules:
  egress:
    allow: ["a.com"]
    default: block
  forbidden_paths:
    patterns: ["**/.ssh/**"]
`);
    const child = parseOrThrow(`
hushspec: "0.1.0"
extends: base
rules:
  egress:
    allow: ["b.com"]
    default: allow
`);
    const merged = merge(base, child);
    expect(merged.extends).toBeUndefined();
    expect(merged.rules?.egress?.allow).toEqual(['b.com']);
    expect(merged.rules?.forbidden_paths?.patterns).toEqual(['**/.ssh/**']);
  });

  it('child name overrides base name', () => {
    const base = parseOrThrow('hushspec: "0.1.0"\nname: base\n');
    const child = parseOrThrow('hushspec: "0.1.0"\nname: child\n');
    const merged = merge(base, child);
    expect(merged.name).toBe('child');
  });

  it('base name preserved when child has none', () => {
    const base = parseOrThrow('hushspec: "0.1.0"\nname: base\n');
    const child = parseOrThrow('hushspec: "0.1.0"\n');
    const merged = merge(base, child);
    expect(merged.name).toBe('base');
  });

  // Parity fix (v3, item S1): the merged result used to DROP top-level
  // `metadata` entirely; it is now merged child-over-parent like every other
  // field, matching Rust `merge_with_strategy`.
  it('merges metadata child-over-parent', () => {
    const base = parseOrThrow('hushspec: "0.1.0"\nname: base\nmetadata:\n  author: a\n');
    const child = parseOrThrow('hushspec: "0.1.0"\nname: child\nextends: base\nmetadata:\n  author: b\n');
    const merged = merge(base, child);
    expect(merged.metadata?.author).toBe('b');
  });

  it('preserves parent metadata when the child has none', () => {
    const base = parseOrThrow('hushspec: "0.1.0"\nname: base\nmetadata:\n  author: a\n');
    const child = parseOrThrow('hushspec: "0.1.0"\nname: child\nextends: base\n');
    const merged = merge(base, child);
    expect(merged.metadata?.author).toBe('a');
  });
});
