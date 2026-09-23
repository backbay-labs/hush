import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';
import { parseOrThrow } from '../src/parse.js';
import { resolve, resolveFromFile, createCompositeLoader } from '../src/resolve.js';
import { loadBuiltin, BUILTIN_NAMES } from '../src/builtin.js';
import { validate } from '../src/validate.js';

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

  // Cycle detection only catches exact repeats, so a long *acyclic* chain
  // would recurse unbounded. The resolver caps it at depth 32 and fails
  // closed with a clean error.
  it('errors cleanly on an extends chain deeper than the cap (40 levels)', () => {
    const depth = 40;
    const load = (reference: string) => {
      const n = Number(reference.slice('level-'.length));
      const spec = n < depth
        ? parseOrThrow(`hushspec: "0.1.0"\nextends: level-${n + 1}\n`)
        : parseOrThrow('hushspec: "0.1.0"\nname: leaf\n');
      return { source: `memory://level-${n}`, spec };
    };
    const root = parseOrThrow('hushspec: "0.1.0"\nextends: level-1\n');
    const result = resolve(root, { source: 'memory://root', load });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('exceeds maximum depth of 32');
    }
  });

  it('resolves a short extends chain within the cap (3 specs deep)', () => {
    const load = (reference: string) => {
      switch (reference) {
        case 'a':
          return { source: 'memory://a', spec: parseOrThrow('hushspec: "0.1.0"\nextends: b\n') };
        case 'b':
          return { source: 'memory://b', spec: parseOrThrow('hushspec: "0.1.0"\nname: leaf\n') };
        default:
          throw new Error(`unexpected reference ${reference}`);
      }
    };
    const root = parseOrThrow('hushspec: "0.1.0"\nextends: a\n');
    const result = resolve(root, { source: 'memory://root', load });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.extends).toBeUndefined();
      expect(result.value.name).toBe('leaf');
    }
  });
});

/**
 * A `rulesets/` preset is named for its file (`strict`); a library policy is
 * embedded under `library/<vertical>/<name>` and names itself with the last
 * segment (`hipaa-base`), because the prefix is a location, not a rename.
 */
function builtinDocumentName(builtin: string): string {
  return builtin.slice(builtin.lastIndexOf('/') + 1);
}

/** The canonical file a builtin name was generated from. */
function builtinSourcePath(builtin: string): string {
  return builtin.startsWith('library/')
    ? `../../../${builtin}.yaml`
    : `../../../rulesets/${builtin}.yaml`;
}

describe('builtin loader', () => {
  it('resolves every embedded policy', () => {
    expect(BUILTIN_NAMES.length).toBeGreaterThan(6);
    for (const name of BUILTIN_NAMES) {
      const spec = loadBuiltin(name);
      expect(spec).not.toBeNull();
      expect(spec!.name).toBe(builtinDocumentName(name));
      expect(spec!.hushspec).toBe('0.1.0');
    }
  });

  it('resolves with builtin: prefix', () => {
    for (const name of BUILTIN_NAMES) {
      const spec = loadBuiltin(`builtin:${name}`);
      expect(spec).not.toBeNull();
      expect(spec!.name).toBe(builtinDocumentName(name));
    }
  });

  it('embeds the vertical library under its library/ prefix', () => {
    const spec = loadBuiltin('builtin:library/healthcare/hipaa-base');
    expect(spec).not.toBeNull();
    expect(spec!.name).toBe('hipaa-base');
    // The embedded leaf still declares its own base; resolving is what
    // materializes the full document.
    expect(spec!.extends).toBe('builtin:strict');
  });

  it('returns null for unknown builtins', () => {
    expect(loadBuiltin('nonexistent')).toBeNull();
    expect(loadBuiltin('builtin:nonexistent')).toBeNull();
  });

  it('loads builtins outside the repository working tree', () => {
    const originalCwd = process.cwd();
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-builtin-'));
    process.chdir(tmpDir);

    try {
      const spec = loadBuiltin('default');
      expect(spec).not.toBeNull();
      expect(spec!.name).toBe('default');
    } finally {
      process.chdir(originalCwd);
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('matches the canonical built-in ruleset YAML', () => {
    for (const name of BUILTIN_NAMES) {
      const expected = YAML.parse(
        readFileSync(new URL(builtinSourcePath(name), import.meta.url), 'utf8'),
      );
      expect(loadBuiltin(name)).toEqual(expected);
    }
  });
});

describe('extends: builtin', () => {
  it('extends builtin:default end-to-end', () => {
    const child = parseOrThrow(`
hushspec: "0.1.0"
extends: builtin:default
name: my-custom-policy
rules:
  egress:
    allow: [custom.example.com]
    default: allow
`);

    const result = resolve(child, { source: 'memory://child' });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.extends).toBeUndefined();
      expect(result.value.name).toBe('my-custom-policy');
      expect(result.value.rules?.forbidden_paths).toBeDefined();
      expect(result.value.rules?.secret_patterns).toBeDefined();
      expect(result.value.rules?.tool_access).toBeDefined();
      expect(result.value.rules?.egress?.allow).toContain('custom.example.com');
      expect(result.value.rules?.egress?.default).toBe('allow');
    }
  });

  it('extends builtin:strict end-to-end', () => {
    const child = parseOrThrow(`
hushspec: "0.1.0"
extends: builtin:strict
name: custom-strict
`);

    const result = resolve(child, { source: 'memory://child' });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.name).toBe('custom-strict');
      expect(result.value.rules?.tool_access?.default).toBe('block');
    }
  });

  it('composite loader rejects HTTP URLs', () => {
    const loader = createCompositeLoader();
    expect(() => loader('https://example.com/policy.yaml')).toThrow('HTTP-based policy loading');
    expect(() => loader('http://example.com/policy.yaml')).toThrow('HTTP-based policy loading');
  });
});

describe('resolved documents validate', () => {
  // `merge()` clears the fields it consumes by setting them to `undefined`
  // rather than deleting them, so a resolved document reaches `validate()` as
  // `{ ..., extends: undefined }`. `key in obj` counts that as present, which
  // would make `validate(resolve(spec))` fail with "extends must be a
  // string" for a document every other SDK accepts.
  it('accepts a document whose extends chain has just been flattened', () => {
    const spec = parseOrThrow('hushspec: "0.2.0"\nextends: "builtin:default"\n');
    const resolved = resolve(spec);
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;

    expect('extends' in resolved.value).toBe(true);
    expect(resolved.value.extends).toBeUndefined();

    const validation = validate(resolved.value);
    expect(validation.errors).toEqual([]);
    expect(validation.valid).toBe(true);
  });

  it('still rejects an extends that is present with a non-string value', () => {
    const validation = validate({ hushspec: '0.2.0', extends: 42 } as never);
    expect(validation.valid).toBe(false);
    expect(validation.errors.some(error => error.message.includes('extends'))).toBe(true);
  });

  // Core section 2.3: a document that declares `merge_strategy` without
  // `extends` never reaches `merge`, and resolution still hands back a
  // document carrying neither resolution instruction.
  it('drops merge_strategy from a one-hop chain', () => {
    const spec = parseOrThrow('hushspec: "0.1.0"\nname: leaf\nmerge_strategy: replace\n');
    const resolved = resolve(spec);
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;

    expect(resolved.value.extends).toBeUndefined();
    expect(resolved.value.merge_strategy).toBeUndefined();
  });
});
