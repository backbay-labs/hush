import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import YAML from 'yaml';
import { parseOrThrow } from '../src/parse.js';
import { resolve, resolveFromFile, createCompositeLoader } from '../src/resolve.js';
import { loadBuiltin, BUILTIN_NAMES } from '../src/builtin.js';
import { createHttpLoader, isPrivateIp } from '../src/http-loader.js';

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

  // Parity fix (v3, item S2): a long *acyclic* extends chain used to recurse
  // unbounded (cycle detection only catches exact repeats). The resolver now
  // caps the chain at depth 32 and fails closed with a clean error.
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

describe('builtin loader', () => {
  it('resolves all 6 built-in rulesets', () => {
    for (const name of BUILTIN_NAMES) {
      const spec = loadBuiltin(name);
      expect(spec).not.toBeNull();
      expect(spec!.name).toBe(name);
      expect(spec!.hushspec).toBe('0.1.0');
    }
  });

  it('resolves with builtin: prefix', () => {
    for (const name of BUILTIN_NAMES) {
      const spec = loadBuiltin(`builtin:${name}`);
      expect(spec).not.toBeNull();
      expect(spec!.name).toBe(name);
    }
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
        readFileSync(new URL(`../../../rulesets/${name}.yaml`, import.meta.url), 'utf8'),
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

describe('http loader', () => {
  it('rejects private IPv6 targets before fetching', async () => {
    const mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
    const loader = createHttpLoader();

    await expect(loader('https://[fc00::1]/policy.yaml')).rejects.toThrow('SSRF protection');
    await expect(loader('https://[fe80::1]/policy.yaml')).rejects.toThrow('SSRF protection');
    expect(mockFetch).not.toHaveBeenCalled();
  });
});

// Parity fix (v3, item S3): the SSRF filter recognized the IPv4-*mapped* form
// (`::ffff:a.b.c.d`) but not the deprecated IPv4-*compatible* form (`::a.b.c.d`
// / `::hextet:hextet`, all high bits zero), so `::a9fe:a9fe` (169.254.169.254
// cloud metadata) and `::7f00:1` (127.0.0.1 loopback) were not flagged. The
// low 32 bits are now extracted as IPv4 and run through the IPv4 private check.
describe('isPrivateIp: IPv4-compatible IPv6 (SSRF)', () => {
  it('flags the deprecated IPv4-compatible form (::a.b.c.d / ::hextet:hextet)', () => {
    expect(isPrivateIp('::a9fe:a9fe')).toBe(true); // 169.254.169.254 cloud metadata
    expect(isPrivateIp('::7f00:1')).toBe(true); // 127.0.0.1 loopback
    expect(isPrivateIp('::0.0.0.0')).toBe(true); // all-zero unspecified
    expect(isPrivateIp('::a0a:a0a')).toBe(true); // 10.10.10.10 private
  });

  it('still flags the IPv4-mapped form and native private ranges', () => {
    expect(isPrivateIp('::ffff:169.254.169.254')).toBe(true);
    expect(isPrivateIp('::ffff:a9fe:a9fe')).toBe(true);
    expect(isPrivateIp('::1')).toBe(true);
    expect(isPrivateIp('::')).toBe(true);
    expect(isPrivateIp('fc00::1')).toBe(true);
    expect(isPrivateIp('fe80::1')).toBe(true);
    expect(isPrivateIp('127.0.0.1')).toBe(true);
  });

  it('leaves genuine public IPs public', () => {
    expect(isPrivateIp('8.8.8.8')).toBe(false);
    expect(isPrivateIp('1.1.1.1')).toBe(false);
    expect(isPrivateIp('2606:4700:4700::1111')).toBe(false);
    // ::2606:4700 -> 38.6.71.0 is a PUBLIC IPv4, so the compatible form stays public.
    expect(isPrivateIp('::2606:4700')).toBe(false);
  });
});
