import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { contentHash } from '../src/canonical.js';
import { HushGuard, POLICY_SIGNATURE_RULE } from '../src/middleware.js';
import { parseOrThrow } from '../src/parse.js';
import {
  INLINE_POLICY_SOURCE,
  PolicyVerificationError,
  createBuiltinLoader,
  defaultSignatureLocator,
  isLoadReasonCode,
  loadReasonOf,
  resolve,
  resolveFromFileWithOptions,
  resolveWithOptions,
  resolveWithOptionsAsync,
  splitDigestPin,
  type Resolution,
} from '../src/resolve.js';
import { loadKeyring, signPolicy, type Keyring } from '../src/signing.js';
import type { HushSpec } from '../src/schema.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const keysDir = path.join(repoRoot, 'fixtures/signing/keys');

const SIGNING_KEY = readFileSync(path.join(keysDir, 'test-signing.key.pem'), 'utf8');
const UNTRUSTED_KEY = readFileSync(path.join(keysDir, 'test-untrusted.key.pem'), 'utf8');
const TRUSTED_KEYRING: Keyring = loadKeyring(
  readFileSync(path.join(keysDir, 'keyring.json'), 'utf8'),
);

const ROOT_POLICY = `
hushspec: "0.1.0"
name: root
rules:
  tool_access:
    allow: [read_file]
    default: block
`;

const MID_POLICY = `
hushspec: "0.1.0"
extends: root.yaml
name: mid
rules:
  egress:
    allow: [api.example.com]
    default: block
`;

const LEAF_POLICY = `
hushspec: "0.1.0"
extends: mid.yaml
name: leaf
rules:
  forbidden_paths:
    patterns: ["~/.ssh/**"]
`;

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-verify-load-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function write(name: string, content: string): string {
  const file = path.join(dir, name);
  writeFileSync(file, content);
  return file;
}

/** Sign `resolved` with the trusted test key and drop the envelope at `sigPath`. */
function signTo(sigPath: string, resolved: HushSpec, key = SIGNING_KEY): void {
  writeFileSync(sigPath, JSON.stringify(signPolicy(resolved, key)));
}

describe('chain construction', () => {
  it('records a 3-hop builtin + file chain root first, leaf last', () => {
    write('base.yaml', `
hushspec: "0.1.0"
extends: "builtin:strict"
name: base
rules:
  egress:
    allow: [api.example.com]
    default: block
`);
    const leafPath = write('leaf.yaml', `
hushspec: "0.1.0"
extends: base.yaml
name: leaf
`);

    const resolution = resolveFromFileWithOptions(leafPath);

    expect(resolution.chain.map((link) => path.basename(link.source))).toEqual([
      'builtin:strict',
      'base.yaml',
      'leaf.yaml',
    ]);
    expect(resolution.spec.name).toBe('leaf');
    expect(resolution.spec.extends).toBeUndefined();
    expect(resolution.content_hash).toBe(contentHash(resolution.spec));
    for (const link of resolution.chain) {
      expect(link.content_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(link.signature).toBeUndefined();
    }
    expect(resolution.signature).toBeUndefined();
  });

  it('hashes each link on its own, with extends and merge_strategy stripped', () => {
    write('root.yaml', ROOT_POLICY);
    const midPath = write('mid.yaml', `${MID_POLICY}merge_strategy: deep_merge\n`);

    const resolution = resolveFromFileWithOptions(midPath);
    const [root, mid] = resolution.chain;

    // The link hash is the document alone -- not the merge of it with its base.
    expect(root!.content_hash).toBe(contentHash(parseOrThrow(ROOT_POLICY)));
    expect(mid!.content_hash).toBe(
      contentHash({ ...parseOrThrow(MID_POLICY), extends: undefined }),
    );
    expect(mid!.content_hash).not.toBe(resolution.content_hash);
  });

  it('reports a leaf with no source as <inline>', () => {
    const resolution = resolveWithOptions(parseOrThrow(ROOT_POLICY), {
      loader: createBuiltinLoader(),
    });
    expect(resolution.chain).toHaveLength(1);
    expect(resolution.chain[0]!.source).toBe(INLINE_POLICY_SOURCE);
  });

  it('resolves the same document the result-shaped resolve() does', () => {
    write('root.yaml', ROOT_POLICY);
    write('mid.yaml', MID_POLICY);
    const leafPath = write('leaf.yaml', LEAF_POLICY);

    const wrapped = resolve(parseOrThrow(LEAF_POLICY), { source: leafPath });
    expect(wrapped.ok).toBe(true);
    if (!wrapped.ok) return;
    expect(wrapped.value).toEqual(resolveFromFileWithOptions(leafPath).spec);
  });
});

describe('digest pinning', () => {
  it('splits a pin off the reference', () => {
    const digest = `sha256:${'a'.repeat(64)}`;
    expect(splitDigestPin(`base.yaml#${digest}`)).toEqual({ reference: 'base.yaml', pin: digest });
    expect(splitDigestPin('base.yaml')).toEqual({ reference: 'base.yaml' });
  });

  it('rejects a fragment that looks like a pin but is not one', () => {
    expect(() => splitDigestPin('base.yaml#sha256:abcd')).toThrow(/malformed digest pin/);
    expect(() => splitDigestPin(`base.yaml#sha256:${'A'.repeat(64)}`)).toThrow(
      /malformed digest pin/,
    );
    expect(() => splitDigestPin(`#sha256:${'a'.repeat(64)}`)).toThrow(/names no policy/);
  });

  it('accepts a pin that matches the hop hash', () => {
    write('root.yaml', ROOT_POLICY);
    const pin = contentHash(parseOrThrow(ROOT_POLICY));
    const leafPath = write('leaf.yaml', `
hushspec: "0.1.0"
extends: "root.yaml#${pin}"
name: pinned
`);

    const resolution = resolveFromFileWithOptions(leafPath);
    expect(resolution.chain[0]!.content_hash).toBe(pin);
    expect(resolution.spec.name).toBe('pinned');
  });

  it('refuses a pin that does not match, with no keyring and no requireSignature', () => {
    write('root.yaml', ROOT_POLICY);
    const wrong = `sha256:${'0'.repeat(64)}`;
    const leafPath = write('leaf.yaml', `
hushspec: "0.1.0"
extends: "root.yaml#${wrong}"
name: pinned
`);

    let thrown: unknown;
    try {
      resolveFromFileWithOptions(leafPath);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(PolicyVerificationError);
    const error = thrown as PolicyVerificationError;
    expect(error.reason).toBe('digest_mismatch');
    expect(error.status).toEqual({ verified: false, reason: 'digest_mismatch' });
    expect(path.basename(error.source)).toBe('root.yaml');
    // The merge still succeeded, so the caller can report what it was handed.
    expect(error.resolution?.spec.name).toBe('pinned');
  });

  it('enforces the pin on the plain resolve() path too', () => {
    write('root.yaml', ROOT_POLICY);
    const leafPath = write('leaf.yaml', `
hushspec: "0.1.0"
extends: "root.yaml#sha256:${'0'.repeat(64)}"
name: pinned
`);
    const result = resolve(parseOrThrow(readFileSync(leafPath, 'utf8')), { source: leafPath });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toMatch(/pinned digest/);
  });

  it('hashes nothing on the plain resolve() path when no hop is pinned', () => {
    write('root.yaml', ROOT_POLICY);
    const leafPath = write('leaf.yaml', MID_POLICY);
    const result = resolve(parseOrThrow(readFileSync(leafPath, 'utf8')), { source: leafPath });
    expect(result.ok).toBe(true);
  });

  it('satisfies requireSignature for the pinned hop without an envelope', () => {
    write('root.yaml', ROOT_POLICY);
    const pin = contentHash(parseOrThrow(ROOT_POLICY));
    const leafPath = write('leaf.yaml', `
hushspec: "0.1.0"
extends: "root.yaml#${pin}"
name: pinned
`);
    // Only the leaf is signed; the base proves itself with the pin.
    signTo(`${leafPath}.sig`, resolveFromFileWithOptions(leafPath).spec);

    const resolution = resolveFromFileWithOptions(leafPath, {
      requireSignature: true,
      keyring: TRUSTED_KEYRING,
    });
    expect(resolution.signature?.verified).toBe(true);
    // The base was checked and had no envelope, which the link records: a pin
    // satisfies the requirement without turning into a signature.
    expect(resolution.chain[0]!.signature).toEqual({
      verified: false,
      reason: 'missing_signature',
    });
  });
});

describe('requireSignature', () => {
  function signedLeaf(): string {
    const leafPath = write('leaf.yaml', `
hushspec: "0.1.0"
extends: "builtin:strict"
name: leaf
rules:
  egress:
    allow: [api.example.com]
    default: block
`);
    signTo(`${leafPath}.sig`, resolveFromFileWithOptions(leafPath).spec);
    return leafPath;
  }

  it('accepts a leaf signed by a trusted key over a builtin base', () => {
    const resolution = resolveFromFileWithOptions(signedLeaf(), {
      requireSignature: true,
      keyring: TRUSTED_KEYRING,
    });
    expect(resolution.signature).toMatchObject({ verified: true });
    expect(resolution.signature?.key_id).toMatch(/^sha256:[0-9a-f]{64}$/);
    // `verified_at` is the verifier's clock, not the envelope's `signed_at`.
    expect(resolution.signature?.verified_at).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
    );
    // The builtin hop is part of the engine and needs no envelope.
    expect(resolution.chain[0]!.source).toBe('builtin:strict');
    expect(resolution.chain[0]!.signature).toBeUndefined();
  });

  it('refuses a leaf with no envelope at all', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    let thrown: unknown;
    try {
      resolveFromFileWithOptions(leafPath, {
        requireSignature: true,
        keyring: TRUSTED_KEYRING,
      });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(PolicyVerificationError);
    expect((thrown as PolicyVerificationError).reason).toBe('missing_signature');
    expect((thrown as PolicyVerificationError).status.verified).toBe(false);
  });

  it('refuses a leaf signed by a key that is not on the keyring', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    signTo(`${leafPath}.sig`, parseOrThrow(ROOT_POLICY), UNTRUSTED_KEY);

    let thrown: unknown;
    try {
      resolveFromFileWithOptions(leafPath, {
        requireSignature: true,
        keyring: TRUSTED_KEYRING,
      });
    } catch (error) {
      thrown = error;
    }
    expect((thrown as PolicyVerificationError).reason).toBe('unknown_key_id');
    expect((thrown as PolicyVerificationError).status.key_id).toMatch(/^sha256:/);
  });

  it('refuses a base hop that is neither pinned nor signed', () => {
    write('root.yaml', ROOT_POLICY);
    const leafPath = write('leaf.yaml', MID_POLICY.replace('name: mid', 'name: leaf'));
    signTo(`${leafPath}.sig`, resolveFromFileWithOptions(leafPath).spec);

    let thrown: unknown;
    try {
      resolveFromFileWithOptions(leafPath, {
        requireSignature: true,
        keyring: TRUSTED_KEYRING,
      });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(PolicyVerificationError);
    expect(path.basename((thrown as PolicyVerificationError).source)).toBe('root.yaml');
    expect((thrown as PolicyVerificationError).reason).toBe('missing_signature');
  });

  it('accepts a base hop with its own envelope over the base resolved alone', () => {
    const rootPath = write('root.yaml', ROOT_POLICY);
    const leafPath = write('leaf.yaml', MID_POLICY.replace('extends: root.yaml', 'extends: root.yaml').replace('name: mid', 'name: leaf'));
    signTo(`${rootPath}.sig`, parseOrThrow(ROOT_POLICY));
    signTo(`${leafPath}.sig`, resolveFromFileWithOptions(leafPath).spec);

    const resolution = resolveFromFileWithOptions(leafPath, {
      requireSignature: true,
      keyring: TRUSTED_KEYRING,
    });
    expect(resolution.chain.map((link) => link.signature?.verified)).toEqual([true, true]);
  });

  it('refuses every unpinned hop without a keyring, recording why', () => {
    // Signing spec 6.5: a hop whose envelope cannot be checked against
    // anything records `no_keyring`, and one with no envelope at all records
    // `missing_signature`. Both refuse; neither is silently admitted.
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    let unsigned: unknown;
    try {
      resolveFromFileWithOptions(leafPath, { requireSignature: true });
    } catch (error) {
      unsigned = error;
    }
    expect(unsigned).toBeInstanceOf(PolicyVerificationError);
    expect((unsigned as PolicyVerificationError).reason).toBe('missing_signature');

    signTo(`${leafPath}.sig`, parseOrThrow(ROOT_POLICY));
    let unkeyed: unknown;
    try {
      resolveFromFileWithOptions(leafPath, { requireSignature: true });
    } catch (error) {
      unkeyed = error;
    }
    expect(unkeyed).toBeInstanceOf(PolicyVerificationError);
    expect((unkeyed as PolicyVerificationError).reason).toBe('no_keyring');
    expect((unkeyed as PolicyVerificationError).status.verified).toBe(false);
  });

  it('refuses a policy whose content changed after signing', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    signTo(`${leafPath}.sig`, parseOrThrow(ROOT_POLICY));
    writeFileSync(leafPath, ROOT_POLICY.replace('allow: [read_file]', 'allow: [read_file, bash]'));

    let thrown: unknown;
    try {
      resolveFromFileWithOptions(leafPath, {
        requireSignature: true,
        keyring: TRUSTED_KEYRING,
      });
    } catch (error) {
      thrown = error;
    }
    expect((thrown as PolicyVerificationError).reason).toBe('content_hash_mismatch');
  });
});

describe('opportunistic verification', () => {
  it('records a valid signature without requiring one', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    signTo(`${leafPath}.sig`, parseOrThrow(ROOT_POLICY));

    const resolution = resolveFromFileWithOptions(leafPath, { keyring: TRUSTED_KEYRING });
    expect(resolution.signature?.verified).toBe(true);
    expect(resolution.chain[0]!.signature?.verified).toBe(true);
  });

  it('records a failure without failing the load', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    signTo(`${leafPath}.sig`, parseOrThrow(ROOT_POLICY), UNTRUSTED_KEY);

    const resolution = resolveFromFileWithOptions(leafPath, { keyring: TRUSTED_KEYRING });
    expect(resolution.spec.name).toBe('root');
    expect(resolution.signature).toMatchObject({ verified: false, reason: 'unknown_key_id' });
  });

  it('records a malformed envelope as malformed_envelope', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    writeFileSync(`${leafPath}.sig`, 'not json at all');

    const resolution = resolveFromFileWithOptions(leafPath, { keyring: TRUSTED_KEYRING });
    expect(resolution.signature).toEqual({ verified: false, reason: 'malformed_envelope' });
  });

  it('surfaces a claimed key_id only when it is well formed', () => {
    // The receipt schema admits `sha256:` plus 64 lowercase hex and nothing
    // else, so an envelope that failed its own shape check contributes the
    // reason code but never its `key_id`.
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    writeFileSync(`${leafPath}.sig`, JSON.stringify({ format_version: '0.2', key_id: 'nonsense' }));
    expect(resolveFromFileWithOptions(leafPath, { keyring: TRUSTED_KEYRING }).signature)
      .toEqual({ verified: false, reason: 'malformed_envelope' });

    const claimed = `sha256:${'0'.repeat(64)}`;
    writeFileSync(`${leafPath}.sig`, JSON.stringify({ format_version: '0.2', key_id: claimed }));
    expect(resolveFromFileWithOptions(leafPath, { keyring: TRUSTED_KEYRING }).signature)
      .toMatchObject({ verified: false, key_id: claimed });
  });

  it('attempts nothing at all without a keyring', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    signTo(`${leafPath}.sig`, parseOrThrow(ROOT_POLICY));

    expect(resolveFromFileWithOptions(leafPath).signature).toBeUndefined();
  });

  it('honors the verifier clock through `verify`', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    writeFileSync(
      `${leafPath}.sig`,
      JSON.stringify(
        signPolicy(parseOrThrow(ROOT_POLICY), SIGNING_KEY, {
          signedAt: new Date('2030-01-01T00:00:00.000Z'),
        }),
      ),
    );

    const resolution = resolveFromFileWithOptions(leafPath, {
      keyring: TRUSTED_KEYRING,
      verify: { now: '2020-01-01T00:00:00.000Z' },
    });
    expect(resolution.signature?.reason).toBe('signed_at_in_future');
  });
});

describe('signature locator', () => {
  it('prefers <path>.sig over <stem>.sig', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    signTo(`${leafPath}.sig`, parseOrThrow(ROOT_POLICY));
    writeFileSync(path.join(dir, 'leaf.sig'), 'not json at all');

    expect(defaultSignatureLocator(leafPath)).toBe(readFileSync(`${leafPath}.sig`, 'utf8'));
    expect(
      resolveFromFileWithOptions(leafPath, { keyring: TRUSTED_KEYRING }).signature?.verified,
    ).toBe(true);
  });

  it('falls back to the 0.1 <stem>.sig layout', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    signTo(path.join(dir, 'leaf.sig'), parseOrThrow(ROOT_POLICY));

    expect(defaultSignatureLocator(leafPath)).not.toBeNull();
    expect(
      resolveFromFileWithOptions(leafPath, { keyring: TRUSTED_KEYRING }).signature?.verified,
    ).toBe(true);
  });

  it('never looks for an envelope next to a builtin or an inline policy', () => {
    expect(defaultSignatureLocator('builtin:strict')).toBeNull();
    expect(defaultSignatureLocator(INLINE_POLICY_SOURCE)).toBeNull();
  });

  it('accepts a caller-supplied locator, including raw bytes', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    const envelope = JSON.stringify(signPolicy(parseOrThrow(ROOT_POLICY), SIGNING_KEY));
    const seen: string[] = [];

    const resolution = resolveFromFileWithOptions(leafPath, {
      requireSignature: true,
      keyring: TRUSTED_KEYRING,
      signatureLocator: (source) => {
        seen.push(source);
        return new TextEncoder().encode(envelope);
      },
    });
    expect(seen).toEqual([leafPath]);
    expect(resolution.signature?.verified).toBe(true);
  });

  it('refuses an async locator on the synchronous path', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    expect(() =>
      resolveFromFileWithOptions(leafPath, {
        keyring: TRUSTED_KEYRING,
        signatureLocator: async () => null,
      }),
    ).toThrow(/resolveWithOptionsAsync/);
  });

  it('awaits an async locator on the async path', async () => {
    const envelope = JSON.stringify(signPolicy(parseOrThrow(ROOT_POLICY), SIGNING_KEY));
    const resolution = await resolveWithOptionsAsync(parseOrThrow(ROOT_POLICY), {
      source: 'https://policies.example.com/root.yaml',
      options: {
        requireSignature: true,
        keyring: TRUSTED_KEYRING,
        signatureLocator: async (source) =>
          source === 'https://policies.example.com/root.yaml' ? envelope : null,
      },
    });
    expect(resolution.signature?.verified).toBe(true);
  });
});

describe('HushGuard verify-on-load', () => {
  const ACTION = { type: 'tool_call', target: 'read_file' } as const;

  it('exposes the resolution of an unsigned load', () => {
    write('root.yaml', ROOT_POLICY);
    const leafPath = write('leaf.yaml', MID_POLICY.replace('name: mid', 'name: leaf'));

    const guard = HushGuard.fromFile(leafPath);
    const resolution = guard.resolution as Resolution;
    expect(resolution.chain.map((link) => path.basename(link.source))).toEqual([
      'root.yaml',
      'leaf.yaml',
    ]);
    expect(resolution.content_hash).toBe(contentHash(resolution.spec));
    expect(guard.check(ACTION)).toBe(true);
  });

  it('evaluates normally when every hop verifies', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    signTo(`${leafPath}.sig`, parseOrThrow(ROOT_POLICY));

    const guard = HushGuard.fromFile(leafPath, {
      requireSignature: true,
      keyring: TRUSTED_KEYRING,
    });
    expect(guard.resolution?.signature?.verified).toBe(true);
    expect(guard.check(ACTION)).toBe(true);
  });

  it('accepts trustedKeys PEMs in place of a keyring', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    signTo(`${leafPath}.sig`, parseOrThrow(ROOT_POLICY));

    const guard = HushGuard.fromFile(leafPath, {
      requireSignature: true,
      trustedKeys: [readFileSync(path.join(keysDir, 'test-signing.pub.pem'), 'utf8')],
    });
    expect(guard.resolution?.signature?.verified).toBe(true);
  });

  it('refuses every action when verification fails', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);

    const guard = HushGuard.fromFile(leafPath, {
      requireSignature: true,
      keyring: TRUSTED_KEYRING,
    });

    const result = guard.evaluate(ACTION);
    expect(result.decision).toBe('deny');
    expect(result.matched_rule).toBe(POLICY_SIGNATURE_RULE);
    expect(result.reason).toMatch(/missing_signature/);
    expect(guard.check(ACTION)).toBe(false);
    expect(guard.check({ type: 'egress', target: 'api.example.com' })).toBe(false);
    // The policy that was loaded is still identified, exactly as 6.5 asks.
    expect(guard.resolution?.content_hash).toBe(contentHash(parseOrThrow(ROOT_POLICY)));
  });

  it('refuses in monitor mode too: there is no policy to monitor against', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    const receipts: unknown[] = [];

    const guard = HushGuard.fromFile(leafPath, {
      requireSignature: true,
      keyring: TRUSTED_KEYRING,
      enforcement: { mode: 'monitor' },
      sink: { send: (receipt) => void receipts.push(receipt) },
    });

    const outcome = guard.gate(ACTION);
    expect(outcome.proceed).toBe(false);
    expect(outcome.enforcement).toEqual({ mode: 'enforce', outcome: 'blocked' });
    expect(receipts).toHaveLength(1);
  });

  it('refuses on a mismatched digest pin as well', () => {
    write('root.yaml', ROOT_POLICY);
    const leafPath = write('leaf.yaml', `
hushspec: "0.1.0"
extends: "root.yaml#sha256:${'0'.repeat(64)}"
name: pinned
`);

    const guard = HushGuard.fromFile(leafPath, {
      requireSignature: true,
      keyring: TRUSTED_KEYRING,
    });
    expect(guard.evaluate(ACTION).reason).toMatch(/digest_mismatch/);
  });

  it('throws rather than refusing when signatures were not required', () => {
    write('root.yaml', ROOT_POLICY);
    const leafPath = write('leaf.yaml', `
hushspec: "0.1.0"
extends: "root.yaml#sha256:${'0'.repeat(64)}"
name: pinned
`);
    expect(() => HushGuard.fromFile(leafPath)).toThrow(PolicyVerificationError);
  });

  it('keeps the last good policy when a swap fails verification', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    signTo(`${leafPath}.sig`, parseOrThrow(ROOT_POLICY));

    const guard = HushGuard.fromFile(leafPath, {
      requireSignature: true,
      keyring: TRUSTED_KEYRING,
    });
    const before = guard.resolution?.content_hash;

    const unsigned = parseOrThrow(ROOT_POLICY.replace('name: root', 'name: swapped'));
    expect(() => guard.swapPolicy(unsigned)).toThrow(PolicyVerificationError);
    expect(guard.resolution?.content_hash).toBe(before);
    expect(guard.check(ACTION)).toBe(true);
  });

  it('adopts a provider resolution instead of re-verifying a sourceless spec', async () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    signTo(`${leafPath}.sig`, parseOrThrow(ROOT_POLICY));
    const resolution = resolveFromFileWithOptions(leafPath, {
      requireSignature: true,
      keyring: TRUSTED_KEYRING,
    });

    const guard = await HushGuard.fromProvider(
      {
        load: async () => resolution.spec,
        watch: () => {},
        stop: () => {},
        current: () => resolution.spec,
        resolution: () => resolution,
      },
      { requireSignature: true, keyring: TRUSTED_KEYRING },
    );

    expect(guard.resolution?.signature?.verified).toBe(true);
    expect(guard.check(ACTION)).toBe(true);
  });

  it('rejects a provider reload that cannot prove itself and keeps the last good policy', async () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    signTo(`${leafPath}.sig`, parseOrThrow(ROOT_POLICY));
    const verified = resolveFromFileWithOptions(leafPath, {
      requireSignature: true,
      keyring: TRUSTED_KEYRING,
    });
    // A reload with no signature evidence of its own: it must never become the
    // policy in force, however it reaches the guard (signing spec 6.5).
    const unproven = resolveFromFileWithOptions(
      write('other.yaml', ROOT_POLICY.replace('name: root', 'name: reloaded')),
      {},
    );

    const events: string[] = [];
    let current = verified;
    const guard = await HushGuard.fromProvider(
      {
        load: async () => current.spec,
        watch: () => {},
        stop: () => {},
        current: () => current.spec,
        resolution: () => current,
      },
      {
        requireSignature: true,
        keyring: TRUSTED_KEYRING,
        observer: { onEvent: (event) => events.push(event.type) },
      },
    );
    expect(guard.check(ACTION)).toBe(true);

    current = unproven;
    // The policy that did verify stays in force, so the action still decides
    // against it rather than against the document the guard would not take.
    expect(guard.evaluate(ACTION).decision).toBe('allow');
    expect(guard.resolution?.content_hash).toBe(verified.content_hash);
    expect(events.filter((type) => type === 'policy.load_failed')).toHaveLength(1);

    // The same rejected document is offered on every action; it is reported
    // once, not once per evaluation.
    expect(guard.evaluate(ACTION).decision).toBe('allow');
    expect(guard.evaluate(ACTION).decision).toBe('allow');
    expect(events.filter((type) => type === 'policy.load_failed')).toHaveLength(1);
  });

  it('accepts a signed leaf over a digest-pinned unsigned base, and refuses it unpinned', async () => {
    const basePath = write('base.yaml', ROOT_POLICY);
    const baseHash = contentHash(parseOrThrow(ROOT_POLICY)).slice('sha256:'.length);
    const pinnedLeaf = `
hushspec: "0.1.0"
extends: base.yaml#sha256:${baseHash}
name: leaf
rules:
  egress:
    allow: [api.example.com]
    default: block
`;
    const leafPath = write('leaf.yaml', pinnedLeaf);
    signTo(`${leafPath}.sig`, resolveFromFileWithOptions(leafPath, {}).spec);
    const pinned = resolveFromFileWithOptions(leafPath, {
      requireSignature: true,
      keyring: TRUSTED_KEYRING,
    });
    expect(pinned.chain[0]?.pinned).toBe(true);

    const provider = (resolution: Resolution) => ({
      load: async () => resolution.spec,
      watch: () => {},
      stop: () => {},
      current: () => resolution.spec,
      resolution: () => resolution,
    });

    // A matching pin proves the base on its own (signing spec 6.5), so the
    // chain is complete and every action decides against the policy.
    const guard = await HushGuard.fromProvider(provider(pinned), {
      requireSignature: true,
      keyring: TRUSTED_KEYRING,
    });
    expect(guard.check(ACTION)).toBe(true);

    // The same chain without the pin: the base proves nothing, so the guard
    // refuses it.
    const unpinnedPath = write('unpinned.yaml', pinnedLeaf.replace(`#sha256:${baseHash}`, ''));
    signTo(`${unpinnedPath}.sig`, resolveFromFileWithOptions(unpinnedPath, {}).spec);
    const unpinned = resolveFromFileWithOptions(unpinnedPath, { keyring: TRUSTED_KEYRING });
    const refusing = await HushGuard.fromProvider(provider(unpinned), {
      requireSignature: true,
      keyring: TRUSTED_KEYRING,
    });
    const refused = refusing.evaluate(ACTION);
    expect(refused.decision).toBe('deny');
    expect(refused.matched_rule).toBe(POLICY_SIGNATURE_RULE);
    expect(refused.reason).toMatch(new RegExp(path.basename(basePath)));
  });

  it('leaves the refused state when a verified policy is swapped in', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    const guard = HushGuard.fromFile(leafPath, {
      requireSignature: true,
      keyring: TRUSTED_KEYRING,
    });
    const refused = guard.evaluate(ACTION);
    expect(refused.decision).toBe('deny');
    expect(refused.matched_rule).toBe(POLICY_SIGNATURE_RULE);

    signTo(`${leafPath}.sig`, parseOrThrow(ROOT_POLICY));
    const verified = resolveFromFileWithOptions(leafPath, {
      requireSignature: true,
      keyring: TRUSTED_KEYRING,
    });
    guard.swapPolicy(verified.spec, verified);

    expect(guard.evaluate(ACTION).decision).toBe('allow');
    expect(guard.resolution?.content_hash).toBe(verified.content_hash);
  });


  it('still resolves relative extends against an explicit baseDir', () => {
    const elsewhere = mkdtempSync(path.join(os.tmpdir(), 'hushspec-basedir-'));
    try {
      writeFileSync(path.join(elsewhere, 'root.yaml'), ROOT_POLICY);
      const leafPath = write('leaf.yaml', MID_POLICY.replace('name: mid', 'name: leaf'));

      const guard = HushGuard.fromFile(leafPath, { baseDir: elsewhere });
      expect(guard.resolution?.chain.map((link) => path.dirname(link.source))).toEqual([
        elsewhere,
        dir,
      ]);
    } finally {
      rmSync(elsewhere, { recursive: true, force: true });
    }
  });

  it('rejects keyring and trustedKeys together', () => {
    const leafPath = write('leaf.yaml', ROOT_POLICY);
    expect(() =>
      HushGuard.fromFile(leafPath, {
        keyring: TRUSTED_KEYRING,
        trustedKeys: [readFileSync(path.join(keysDir, 'test-signing.pub.pem'), 'utf8')],
      }),
    ).toThrow(/not both/);
  });
});

describe('loadReasonOf', () => {
  it('keeps a reason from the closed set', () => {
    expect(loadReasonOf({ verified: false, reason: 'key_revoked' })).toBe('key_revoked');
    expect(loadReasonOf({ verified: false, reason: 'digest_mismatch' })).toBe('digest_mismatch');
  });

  it('reads a status with no reason, or one outside the set, as missing_signature', () => {
    expect(loadReasonOf(undefined)).toBe('missing_signature');
    expect(loadReasonOf({ verified: false })).toBe('missing_signature');
    expect(loadReasonOf({ verified: false, reason: 'locator_timeout' })).toBe('missing_signature');
    expect(isLoadReasonCode('locator_timeout')).toBe(false);
    expect(isLoadReasonCode('policy_version_rollback')).toBe(true);
  });
});
