import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseOrThrow } from '../src/parse.js';
import { resolve, resolveFromFile } from '../src/resolve.js';

describe('resolve', () => {
  it('resolves extends chains from the filesystem', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-resolve-'));
    writeFileSync(
      path.join(dir, 'base.yaml'),
      `
hushspec: "0.1.0"
name: base
rules:
  tool_access:
    allow: [read_file]
    default: block
`,
    );
    writeFileSync(
      path.join(dir, 'child.yaml'),
      `
hushspec: "0.1.0"
extends: base.yaml
name: child
rules:
  egress:
    allow: [api.example.com]
    default: allow
`,
    );

    const result = resolveFromFile(path.join(dir, 'child.yaml'));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.extends).toBeUndefined();
      expect(result.value.name).toBe('child');
      expect(result.value.rules?.tool_access?.allow).toEqual(['read_file']);
      expect(result.value.rules?.tool_access?.default).toBe('block');
      expect(result.value.rules?.egress?.allow).toEqual(['api.example.com']);
      expect(result.value.rules?.egress?.default).toBe('allow');
    }

    rmSync(dir, { recursive: true, force: true });
  });

  it('detects circular extends chains', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-cycle-'));
    writeFileSync(
      path.join(dir, 'a.yaml'),
      `
hushspec: "0.1.0"
extends: b.yaml
`,
    );
    writeFileSync(
      path.join(dir, 'b.yaml'),
      `
hushspec: "0.1.0"
extends: a.yaml
`,
    );

    const result = resolveFromFile(path.join(dir, 'a.yaml'));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('circular extends detected');
    }

    rmSync(dir, { recursive: true, force: true });
  });

  it('supports custom loaders with canonical source ids', () => {
    const child = parseOrThrow(`
hushspec: "0.1.0"
extends: parent
rules:
  egress:
    allow: [api.example.com]
    default: block
`);

    const result = resolve(child, {
      source: 'memory://child',
      load(reference) {
        expect(reference).toBe('parent');
        return {
          source: 'memory://parent',
          spec: parseOrThrow(`
hushspec: "0.1.0"
name: parent
`),
        };
      },
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.extends).toBeUndefined();
      expect(result.value.name).toBe('parent');
    }
  });
});
