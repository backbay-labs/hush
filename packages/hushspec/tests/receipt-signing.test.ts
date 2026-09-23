import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadKeyring, signReceipt, verifyReceipt } from '../src/signing.js';
import type { SignedReceipt } from '../src/signing.js';
import { parseReceipt, receiptHash } from '../src/receipt.js';
import type { DecisionReceipt } from '../src/receipt.js';

/**
 * Receipt signing: a 0.2 signature envelope over the receipt hash (receipt
 * spec 6), so the signature covers every field of the receipt without the
 * envelope having to restate any of them.
 *
 * Vectors: `fixtures/receipts/signed/`.
 */

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const signedDir = path.join(repoRoot, 'fixtures/receipts/signed');
const keysDir = path.join(repoRoot, 'fixtures/signing/keys');

const SIGNED_AT = new Date('2026-09-15T12:00:00.000Z');

function testKey(): string {
  return readFileSync(path.join(keysDir, 'test-signing.key.pem'), 'utf8');
}

function untrustedKey(): string {
  return readFileSync(path.join(keysDir, 'test-untrusted.key.pem'), 'utf8');
}

function keyring() {
  return loadKeyring(readFileSync(path.join(keysDir, 'keyring.json'), 'utf8'));
}

function verifyOptions() {
  return { keyring: keyring(), now: SIGNED_AT, maxClockSkewSeconds: 300 };
}

function signOptions() {
  return { signedAt: SIGNED_AT, signer: 'fixtures' };
}

/** The receipt every signed vector is built from. */
function sourceReceipt(): DecisionReceipt {
  return parseReceipt(
    readFileSync(path.join(repoRoot, 'fixtures/receipts/valid/allow-egress.json'), 'utf8'),
  );
}

function readSigned(name: string): SignedReceipt {
  return JSON.parse(readFileSync(path.join(signedDir, name), 'utf8')) as SignedReceipt;
}

describe('signReceipt / verifyReceipt', () => {
  it('round-trips and covers every field', () => {
    const receipt = sourceReceipt();
    const signed = signReceipt(receipt, testKey(), signOptions());
    expect(signed.signature.content_hash).toBe(receiptHash(receipt));
    expect(signed.signature.format_version).toBe('0.2');
    expect(signed.signature.algorithm).toBe('ed25519');

    const verified = verifyReceipt(signed, verifyOptions());
    expect(verified.ok).toBe(true);
    if (verified.ok) {
      expect(verified.contentHash).toBe(signed.signature.content_hash);
    }

    // A field edited after signing breaks the content check, not the
    // signature check: the envelope is intact, the receipt is not.
    const tampered: SignedReceipt = {
      signature: signed.signature,
      receipt: { ...signed.receipt, reason: 'edited after signing' },
    };
    const failure = verifyReceipt(tampered, verifyOptions());
    expect(failure.ok).toBe(false);
    if (!failure.ok) expect(failure.reason).toBe('content_hash_mismatch');

    // The wire form re-parses and still verifies.
    const reparsed = JSON.parse(JSON.stringify(signed)) as SignedReceipt;
    expect(verifyReceipt(reparsed, verifyOptions()).ok).toBe(true);
  });

  it('is deterministic', () => {
    const receipt = sourceReceipt();
    const first = signReceipt(receipt, testKey(), signOptions());
    const second = signReceipt(receipt, testKey(), signOptions());
    expect(first.signature).toEqual(second.signature);
  });

  it('leaves policy_name and policy_version unset unless asked', () => {
    // A receipt already names its policy; repeating it in the envelope would
    // let the two disagree.
    const signed = signReceipt(sourceReceipt(), testKey(), signOptions());
    expect(signed.signature.policy_name).toBeUndefined();
    expect(signed.signature.policy_version).toBeUndefined();
  });

  it('refuses a key that is not on the keyring', () => {
    const signed = signReceipt(sourceReceipt(), untrustedKey(), signOptions());
    const outcome = verifyReceipt(signed, verifyOptions());
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.reason).toBe('unknown_key_id');
  });
});

describe('signed receipt vectors', () => {
  it('reproduces valid/allow-egress.signed.json byte for byte', () => {
    // Ed25519 is deterministic and the signing input is canonical, so the
    // same key over the same receipt hash yields the same envelope.
    const expected = readSigned('valid/allow-egress.signed.json');
    const signed = signReceipt(sourceReceipt(), testKey(), signOptions());
    expect(signed.signature).toEqual(expected.signature);
    expect(receiptHash(signed.receipt)).toBe(receiptHash(expected.receipt));
  });

  it('accepts valid/allow-egress.signed.json', () => {
    const outcome = verifyReceipt(readSigned('valid/allow-egress.signed.json'), verifyOptions());
    expect(outcome.ok).toBe(true);
  });

  it('rejects invalid/tampered-after-signing.signed.json', () => {
    const outcome = verifyReceipt(
      readSigned('invalid/tampered-after-signing.signed.json'),
      verifyOptions(),
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.reason).toBe('content_hash_mismatch');
  });

  it('rejects invalid/untrusted-key.signed.json', () => {
    const outcome = verifyReceipt(
      readSigned('invalid/untrusted-key.signed.json'),
      verifyOptions(),
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.reason).toBe('unknown_key_id');
  });
});
