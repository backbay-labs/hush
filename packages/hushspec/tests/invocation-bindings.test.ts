import { describe, expect, it } from 'vitest';
import * as api from '../src/index.js';

const { snapshotJson, hashJson, qualifiedToolTarget, InvocationRegistry,
  AuthenticatedPolicy, typescriptInvocationEngine } = api;
const keys = api.generateKeypair();
const now = new Date('2026-09-23T12:00:00.000Z');
const policy = { hushspec: '0.2.0', name: 'coding', metadata: { policy_version: 5 },
  rules: { tool_access: { allow: ['mcp:repo/read_file'], default: 'block' as const } } };
const envelope = () => api.signPolicy(policy, keys.privateKeyPem, { signedAt: now });
const authenticate = (doc = policy, sig = envelope(), version?: number) =>
  new AuthenticatedPolicy(JSON.stringify(doc), sig, keys.publicKeyPem,
    typescriptInvocationEngine, version, now);

describe('invocation JSON snapshots', () => {
  it('exports the experimental snapshot boundary', () => {
    expect(snapshotJson).toBeTypeOf('function');
  });
  it('copies nested JSON and freezes every object including prototype-like keys', () => {
    const value = snapshotJson('{"x":{"y":[1,true,null]},"__proto__":{"ok":true}}') as any;
    expect(value.x.y).toEqual([1, true, null]);
    expect(Object.isFrozen(value.x.y)).toBe(true);
    expect(() => { value.x.y[0] = 2; }).toThrow();
    expect(Object.hasOwn(value, '__proto__')).toBe(true);
    expect({}.ok).toBeUndefined();
  });
  it.each(['{"x":1,"\\u0078":2}', '{"x":1e999}', '{"x":"\\ud800"}',
    '{"x":01}', '[1,]', '{"x":true} false', '{"x":undefined}', '{"x":NaN}',
    '{"x":"\u0000"}', '{"x":1,}', ''])('refuses ambiguous/non-JSON input %s', raw => {
    expect(() => snapshotJson(raw)).toThrow();
  });
  it('bounds UTF-8 bytes, depth and node count before publishing a snapshot', () => {
    expect(() => snapshotJson('"é"', { maxBytes: 3 })).toThrow();
    expect(() => snapshotJson('[[[0]]]', { maxDepth: 2 })).toThrow();
    expect(() => snapshotJson('[1,2,3]', { maxNodes: 3 })).toThrow();
    expect(snapshotJson('"é"', { maxBytes: 4 })).toBe('é');
  });
  it('hashes canonical JSON with independently known SHA-256', () => {
    expect(hashJson({})).toBe('sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a');
    expect(hashJson(snapshotJson('{ "b": 2, "a": 1 }'))).toBe(hashJson({ a: 1, b: 2 }));
  });
});

describe('host tool identities', () => {
  it('escapes names unambiguously and distinguishes connections', () => {
    expect(qualifiedToolTarget('repo', 'read/file')).toBe('mcp:repo/read%2Ffile');
    expect(qualifiedToolTarget('repo', 'read%2Ffile')).toBe('mcp:repo/read%252Ffile');
    expect(qualifiedToolTarget('other', 'read_file')).toBe('mcp:other/read_file');
  });
  it.each([['UPPER', 'x'], ['repo/x', 'x'], ['repo', ''], ['repo', 'e\u0301'],
    ['repo', '\ud800'], ['repo', '\n'], ['repo', 'é'.repeat(65)]])('refuses invalid identity %s/%s', (id, tool) => {
    expect(() => qualifiedToolTarget(id, tool)).toThrow();
  });
  it('captures dispatch handles instead of retaining a mutable registration', () => {
    const original = () => 'original';
    const binding = { connectionId: 'repo', toolName: 'read_file',
      extract: () => [{ type: 'file_read', target: '/workspace/note.txt' }], dispatch: original };
    const registry = new InvocationRegistry([binding]);
    binding.dispatch = () => 'replacement';
    expect(registry.get('repo', 'read_file').dispatch({}, { callId: 'host-call' })).toBe('original');
    expect(() => registry.get('other', 'read_file')).toThrow();
    expect(() => new InvocationRegistry([binding, binding])).toThrow();
  });
});

describe('authenticated policy and engine snapshot', () => {
  it('uses real compilation and receipt traces with authenticated identity', async () => {
    const captured = authenticate();
    const result = await captured.prepared.evaluate({ type: 'tool_call', target: 'mcp:repo/read_file' }, {});
    expect(result.decision).toBe('allow');
    expect(result.rule_trace.some(row => row.rule_block === 'tool_access' && row.evaluated)).toBe(true);
    expect(result.policy.signature?.verified).toBe(true);
    expect(result.policy.content_hash).toBe(captured.resolution.content_hash);
    expect(Object.isFrozen(captured.resolution.spec.rules?.tool_access?.allow)).toBe(true);
  });
  it('rejects unsigned, wrong-key, unresolved and unvalidated policies', () => {
    expect(() => authenticate(policy, {} as any)).toThrow();
    const wrong = api.signPolicy(policy, api.generateKeypair().privateKeyPem, { signedAt: now });
    expect(() => authenticate(policy, wrong)).toThrow();
    expect(() => authenticate({ ...policy, extends: 'default' } as any)).toThrow();
    expect(() => authenticate({ ...policy, merge_strategy: 'merge' } as any)).toThrow();
    expect(() => authenticate({ ...policy, surprise: true } as any)).toThrow();
  });
  it('refuses signed envelope/document disagreement and absent identity claims', () => {
    for (const options of [{ policyVersion: 99 }, { policyName: 'other' }]) {
      const sig = api.signPolicy(policy, keys.privateKeyPem, { signedAt: now, ...options });
      expect(() => authenticate(policy, sig)).toThrow(/identity/);
    }
    const withoutClaims = api.signContentHash(api.contentHash(policy), keys.privateKeyPem, { signedAt: now });
    expect(() => authenticate(policy, withoutClaims)).toThrow(/identity/);
    expect(() => authenticate(policy, envelope(), 6)).toThrow(/rollback/);
  });
  it('rechecks expiry at admission, not only installation', () => {
    const sig = api.signPolicy(policy, keys.privateKeyPem,
      { signedAt: now, expiresAt: '2026-09-23T12:00:01.000Z' });
    const captured = authenticate(policy, sig);
    expect(() => captured.verifyAt(new Date('2026-09-23T12:00:00.999Z'))).not.toThrow();
    expect(() => captured.verifyAt(new Date('2026-09-23T12:00:01.000Z'))).toThrow(/expired/);
  });
  it('refuses an engine prepared for a different policy hash', () => {
    const engine = { prepare: () => ({ policyHash: `sha256:${'0'.repeat(64)}`,
      identity: { name: 'wrong', version: '1' }, evaluate: () => { throw Error('unused'); } }) };
    expect(() => new AuthenticatedPolicy(JSON.stringify(policy), envelope(), keys.publicKeyPem,
      engine, undefined, now)).toThrow(/engine/);
  });
});
