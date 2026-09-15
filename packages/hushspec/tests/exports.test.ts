import { describe, expect, it } from 'vitest';
import * as hushspec from '../src/index.js';
import { ConsoleReceiptSink } from '../src/sinks.js';
import { HUSHSPEC_SUPPORTED_VERSIONS, SUPPORTED_VERSIONS } from '../src/version.js';

/**
 * The public surface every SDK is expected to carry under the same names
 * (RFC 09 isomorphism). A rename here is a breaking change for anyone porting
 * code between the four SDKs, so the names are pinned rather than assumed.
 */
describe('package entry point', () => {
  const REQUIRED = [
    // Documents
    'parse',
    'parseOrThrow',
    'validate',
    'merge',
    'resolve',
    'canonicalJson',
    'contentHash',
    // Evaluation
    'evaluate',
    'evaluateTraced',
    'evaluateWithContext',
    'evaluateWithDetection',
    'compilePolicy',
    'compileResolution',
    'CompiledPolicy',
    'HushGuard',
    // Evidence
    'evaluateAudited',
    'evaluateAuditedSpec',
    'signReceipt',
    'verifyReceipt',
    'verifyLog',
    'verifyBundle',
    'parseBundle',
    // Signing
    'signPolicy',
    'verifyPolicy',
    'loadKeyring',
    'generateKeypair',
    // Sinks
    'FileReceiptSink',
    'ConsoleReceiptSink',
    'StderrReceiptSink',
    'OtlpReceiptSink',
    'MultiSink',
    'FilteredSink',
    // Version identity
    'HUSHSPEC_VERSION',
    'HUSHSPEC_SUPPORTED_MINORS',
    'HUSHSPEC_SUPPORTED_VERSIONS',
    'isSupported',
  ] as const;

  for (const name of REQUIRED) {
    it(`exports ${name}`, () => {
      expect(hushspec).toHaveProperty(name);
      expect((hushspec as Record<string, unknown>)[name]).toBeDefined();
    });
  }
});

describe('isomorphism aliases', () => {
  it('StderrReceiptSink is the console sink under the other SDKs\' name', () => {
    expect(hushspec.StderrReceiptSink).toBe(ConsoleReceiptSink);
    expect(new hushspec.StderrReceiptSink()).toBeInstanceOf(ConsoleReceiptSink);
  });

  it('HUSHSPEC_SUPPORTED_VERSIONS is the spelling Rust and Python use', () => {
    expect(HUSHSPEC_SUPPORTED_VERSIONS).toEqual(['0.1.0', '0.2.0']);
    expect(SUPPORTED_VERSIONS).toBe(HUSHSPEC_SUPPORTED_VERSIONS);
  });

  it('names the specification version it writes and the minors it accepts', () => {
    expect(hushspec.HUSHSPEC_VERSION).toBe('0.2.0');
    expect(hushspec.HUSHSPEC_SUPPORTED_MINORS).toEqual(['0.1', '0.2']);
  });
});
