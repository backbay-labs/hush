import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { HUSHSPEC_SUPPORTED_MINORS, HUSHSPEC_VERSION, SDK_NAME, SDK_VERSION, isSupported, majorVersion, supportedMinor } from '../src/version.js';
import { evaluate } from '../src/evaluate.js';
import { parse } from '../src/parse.js';
import { validate } from '../src/validate.js';

// Core spec 2.2: an engine that supports minor version X.Y accepts every
// X.Y.Z document.

describe('version acceptance', () => {
  it('writes 1.0.0 and supports the 0.1, 0.2 and 1.0 minors', () => {
    expect(HUSHSPEC_VERSION).toBe('1.0.0');
    expect([...HUSHSPEC_SUPPORTED_MINORS]).toEqual(['0.1', '0.2', '1.0']);
  });

  it('accepts every patch level of a supported minor', () => {
    for (const version of ['0.1.0', '0.1.1', '0.1.99', '0.2.0', '0.2.7', '1.0.0', '1.0.3']) {
      expect(isSupported(version), version).toBe(true);
    }
    expect(supportedMinor('0.1.99')).toBe('0.1');
    expect(supportedMinor('0.2.7')).toBe('0.2');
    expect(supportedMinor('1.0.3')).toBe('1.0');
  });

  it('rejects unsupported or malformed versions', () => {
    for (const version of ['0.3.0', '1.7.0', '2.0.0', '0.1', '0.1.0.0', '0.1.x', '+0.1.0', '', ' 0.1.0']) {
      expect(isSupported(version), version).toBe(false);
      expect(supportedMinor(version), version).toBeUndefined();
    }
  });

  it('validates a 0.1.1 document', () => {
    const result = parse('hushspec: "0.1.1"\nname: patch-version\nrules:\n  egress:\n    default: block\n');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(validate(result.value).valid).toBe(true);
  });

  // Core spec 10.2: 1.0 froze the 0.2 semantics without changing them, so a
  // 1.0.Z document is the same document a 0.2.Z declaration would describe.
  it('evaluates a 1.0 document exactly as the 0.2 one it mirrors', () => {
    const body = 'name: one-point-zero\nrules:\n  egress:\n    allow: ["api.example.com"]\n    default: block\n';
    const one = parse(`hushspec: "1.0.0"\n${body}`);
    const zero = parse(`hushspec: "0.2.0"\n${body}`);
    expect(one.ok && zero.ok).toBe(true);
    if (!one.ok || !zero.ok) return;
    expect(validate(one.value).valid).toBe(true);

    const action = { type: 'egress', target: 'evil.example.net' } as const;
    expect(evaluate(one.value, action)).toEqual(evaluate(zero.value, action));
  });

  it('reports the supported minors when rejecting a version', () => {
    const result = validate({ hushspec: '0.9.0' });
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E002');
    expect(result.errors[0].message).toBe(
      'unsupported hushspec version: 0.9.0 (this engine accepts minor versions 0.1, 0.2, 1.0)',
    );
  });
});

// The SDK identity a receipt log's `sdk` member records (log spec 6) has to be
// this package's real name and version, or a log would attribute entries to a
// release that never wrote them.

describe('SDK identity', () => {
  it('matches package.json', () => {
    const packageJson = JSON.parse(
      readFileSync(
        path.join(path.dirname(fileURLToPath(import.meta.url)), '../package.json'),
        'utf8',
      ),
    ) as { name: string; version: string };
    expect(SDK_NAME).toBe(packageJson.name);
    expect(SDK_VERSION).toBe(packageJson.version);
  });

  // Core spec 10.3: the two are versioned independently, so a log records
  // both. They coincide in this release and nothing may come to depend on
  // either that -- or on their ever differing again.
  it('is a separate constant from the specification version', () => {
    expect(HUSHSPEC_VERSION).toBe('1.0.0');
    expect(isSupported(HUSHSPEC_VERSION)).toBe(true);
    // The SDK version is whatever `package.json` says; it is not required to
    // be a HushSpec version at all.
    expect(SDK_VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });
});

describe('majorVersion', () => {
  it('is bounded to an unsigned 32-bit integer in every SDK', () => {
    expect(majorVersion('4294967295.0.0')).toBe(4294967295);
    expect(majorVersion('4294967296.0.0')).toBeUndefined();
    expect(majorVersion(`${'9'.repeat(5000)}.0.0`)).toBeUndefined();
  });
});
