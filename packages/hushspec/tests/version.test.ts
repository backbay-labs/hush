import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import {
  HUSHSPEC_SUPPORTED_MINORS,
  HUSHSPEC_VERSION,
  SDK_NAME,
  SDK_VERSION,
  isSupported,
  supportedMinor,
} from '../src/version.js';
import { parse } from '../src/parse.js';
import { validate } from '../src/validate.js';

// Core spec 2.2: an engine that supports minor version X.Y accepts every
// X.Y.Z document.

describe('version acceptance', () => {
  it('writes 0.2.0 and supports the 0.1 and 0.2 minors', () => {
    expect(HUSHSPEC_VERSION).toBe('0.2.0');
    expect([...HUSHSPEC_SUPPORTED_MINORS]).toEqual(['0.1', '0.2']);
  });

  it('accepts every patch level of a supported minor', () => {
    for (const version of ['0.1.0', '0.1.1', '0.1.99', '0.2.0', '0.2.7']) {
      expect(isSupported(version), version).toBe(true);
    }
    expect(supportedMinor('0.1.99')).toBe('0.1');
    expect(supportedMinor('0.2.7')).toBe('0.2');
  });

  it('rejects unsupported or malformed versions', () => {
    for (const version of ['0.3.0', '1.0.0', '0.1', '0.1.0.0', '0.1.x', '+0.1.0', '', ' 0.1.0']) {
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

  it('reports the supported minors when rejecting a version', () => {
    const result = validate({ hushspec: '0.9.0' });
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E002');
    expect(result.errors[0].message).toBe(
      'unsupported hushspec version: 0.9.0 (this engine accepts minor versions 0.1, 0.2)',
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

  it('is distinct from the specification version', () => {
    expect(SDK_VERSION).not.toBe(HUSHSPEC_VERSION);
  });
});
