import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as api from '../src/index.js';

const cleanup: (() => void)[] = [];
afterEach(() => { api.deactivatePanic(); for (const fn of cleanup.splice(0).reverse()) fn(); });
const deferred = <T>() => { let resolve!: (value: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; };

function harness(options: any = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hush-coordinator-'));
  cleanup.push(() => fs.rmSync(root, { recursive: true }));
  const policyKey = api.generateKeypair(); const runtime = api.generateKeypair();
  const file = new api.FileInvocationJournal(path.join(root, 'journal'), runtime.privateKeyPem);
  cleanup.push(() => file.dispose());
  const events: any[] = [];
  const effects: any[] = [];
  let prompts = 0;
  const policy: api.HushSpec = options.policy ?? { hushspec: '0.2.0', name: 'coding', metadata: { policy_version: 1 },
    rules: { tool_access: { allow: ['mcp:repo/read_file'], default: 'block' } } };
  const journal = { append(event: any) {
    if (options.sink) return options.sink(event, file, events);
    events.push(event); return file.append(event);
  }, close: () => file.close() };
  const binding = { connectionId: 'repo', toolName: 'read_file',
    extract: options.extract ?? (() => [{ type: 'file_read', target: '/workspace/note.txt' }]),
    dispatch: options.dispatch ?? ((args: any, context: any) => { effects.push({ args, context }); return { content: 'hello' }; }) };
  const registry = new api.InvocationRegistry([binding,
    { ...binding, connectionId: 'other' }]);
  const coordinator = new api.InvocationCoordinator({ registry, journal, policyPublicKeyPem: policyKey.publicKeyPem,
    timeoutMs: options.timeoutMs ?? 1000, engine: options.engine,
    confirm: (prompt: any) => { prompts++; return options.confirm ? options.confirm(prompt, coordinator) : true; } });
  const install = (doc = policy) => coordinator.installPolicy(JSON.stringify(doc), api.signPolicy(doc, policyKey.privateKeyPem));
  if (options.autoInstall !== false) install();
  return { coordinator, install, policy, file, events, effects, prompts: () => prompts,
    verify: () => { const cp = coordinator.close(); return api.verifyInvocationJournal(
      fs.readFileSync(path.join(root, 'journal', 'entries.jsonl'), 'utf8'), JSON.stringify(cp),
      { runtimePublicKeyPem: runtime.publicKeyPem, policyPublicKeyPem: policyKey.publicKeyPem, expectedStreamId: file.streamId }); } };
}
const invoke = (h: ReturnType<typeof harness>, raw = '{"path":"note.txt"}') => h.coordinator.invoke('repo', 'read_file', raw);
const warningPolicy: api.HushSpec = { hushspec: '0.2.0', name: 'coding', metadata: { policy_version: 1 }, rules: {
  tool_access: { require_confirmation: ['mcp:repo/read_file'], default: 'block' },
  secret_patterns: { patterns: [{ name: 'review', pattern: 'review-me', severity: 'warn' }] },
} };

describe('trusted invocation admission', () => {
  it('exports an enforce-only coordinator', () => {
    expect(api.InvocationCoordinator).toBeTypeOf('function');
    expect(() => new api.InvocationCoordinator({ mode: 'monitor' } as any)).toThrow(/enforce/);
  });
  it('writes a durable permit before invoking the captured handle and reconciles completion', async () => {
    let h: ReturnType<typeof harness>;
    h = harness({ dispatch: (args: any, context: any) => {
      expect(h.events.at(-1).type).toBe('permit');
      expect(Object.isFrozen(args)).toBe(true);
      expect(context.callId).toBe(h.events.at(-1).call_id);
      return { content: 'hello' };
    } });
    const result = await invoke(h);
    expect(result).toMatchObject({ status: 'completed', value: { content: 'hello' } });
    expect(h.verify().calls).toEqual([{ callId: result.callId, outcome: 'completed' }]);
  });
  it('denies a same-name tool on another connection and an unqualified allow', async () => {
    const h = harness();
    expect(await h.coordinator.invoke('other', 'read_file', '{}')).toMatchObject({ status: 'blocked' });
    h.install({ ...h.policy, rules: { tool_access: { allow: ['read_file'], default: 'block' } } });
    expect(await invoke(h)).toMatchObject({ status: 'blocked' });
    expect(h.effects).toHaveLength(0); expect(h.prompts()).toBe(0); h.verify();
  });
  it('a denied tool dominates allowed effects without prompting', async () => {
    const h = harness({ policy: { ...warningPolicy, rules: { ...warningPolicy.rules,
      tool_access: { block: ['mcp:repo/read_file'], default: 'allow' } } } });
    expect(await invoke(h)).toMatchObject({ status: 'blocked' });
    expect(h.effects).toHaveLength(0); expect(h.prompts()).toBe(0); h.verify();
  });
  it('a denied effect dominates a warning tool without prompting', async () => {
    const h = harness({ policy: { ...warningPolicy, rules: { ...warningPolicy.rules,
      forbidden_paths: { patterns: ['/workspace/**'] } } } });
    expect(await invoke(h)).toMatchObject({ status: 'blocked' });
    expect(h.effects).toHaveLength(0); expect(h.prompts()).toBe(0); h.verify();
  });
  it('collects three warnings into one immutable bound prompt', async () => {
    const h = harness({ policy: warningPolicy,
      extract: () => [{ type: 'file_write', target: '/workspace/note.txt', content: 'review-me' },
        { type: 'patch_apply', target: '/workspace/note.txt', content: '+review-me\n' }],
      confirm: (prompt: any) => {
        expect(Object.isFrozen(prompt)).toBe(true);
        expect(prompt.target).toBe('mcp:repo/read_file');
        expect(prompt.argumentsHash).toMatch(/^sha256:/);
        expect(prompt.effectsHash).toMatch(/^sha256:/);
        expect(prompt.generation).toBe(1); return true;
      } });
    expect(await invoke(h)).toMatchObject({ status: 'completed' });
    expect(h.prompts()).toBe(1); expect(h.effects).toHaveLength(1);
    expect(h.events.find(e => e.type === 'decision').receipts.map((r: any) => r.decision)).toEqual(['warn', 'warn', 'warn']);
    h.verify();
  });
  it.each(['refusal', 'exception', 'timeout', 'truthy'])('blocks confirmation %s', async failure => {
    const h = harness({ policy: warningPolicy, timeoutMs: 15,
      confirm: () => { if (failure === 'exception') throw Error('prompt unavailable');
        return failure === 'timeout' ? new Promise(() => {}) : failure === 'truthy' ? 'yes' : false; } });
    expect(await invoke(h)).toMatchObject({ status: 'blocked' });
    expect(h.effects).toHaveLength(0); expect(h.prompts()).toBe(1); h.verify();
  });
  it.each(['reload', 'failed-reload', 'panic', 'global-panic'])('invalidates approval after %s during confirmation', async change => {
    const h = harness({ policy: warningPolicy, confirm: (_: any, c: any) => {
      if (change === 'reload') h.install({ ...warningPolicy, metadata: { policy_version: 2 } });
      if (change === 'failed-reload') expect(() => c.installPolicy('{}', {})).toThrow();
      if (change === 'panic') { c.setPanic(true); c.setPanic(false); }
      if (change === 'global-panic') { api.activatePanic(); api.deactivatePanic(); }
      return true;
    } });
    expect(await invoke(h)).toMatchObject({ status: 'blocked' });
    expect(h.effects).toHaveLength(0); h.verify();
  });
  it('rechecks after permit acknowledgment against reentrant global panic changes', async () => {
    const h = harness({ sink: (event: any, file: any, events: any[]) => {
      events.push(event); const ack = file.append(event);
      if (event.type === 'permit') { api.activatePanic(); api.deactivatePanic(); }
      return ack;
    } });
    expect(await invoke(h)).toMatchObject({ status: 'blocked' });
    expect(h.effects).toHaveLength(0);
    expect(h.events.at(-1)).toMatchObject({ type: 'terminal', outcome: 'aborted_before_dispatch' }); h.verify();
  });
  it.each(['duplicate-json', 'oversize', 'unknown-tool', 'opaque', 'unknown-effect', 'effect-context'])('refuses malformed input/plan %s', async kind => {
    const h = harness({ extract: () => kind === 'opaque' ? [] : [{ type: kind === 'unknown-effect' ? 'shell_command' : 'file_read',
      target: '/workspace/note.txt', ...(kind === 'effect-context' ? { context: { user: { role: 'admin' } } } : {}) }] });
    const raw = kind === 'duplicate-json' ? '{"x":1,"x":2}' : kind === 'oversize' ? JSON.stringify({ x: 'x'.repeat(65_536) }) : '{}';
    const result = kind === 'unknown-tool' ? await h.coordinator.invoke('repo', 'missing', raw) : await invoke(h, raw);
    expect(result).toMatchObject({ status: 'blocked' }); expect(h.effects).toHaveLength(0); h.verify();
  });
  it('pins nested arguments across asynchronous confirmation and compacts receipt context consistently', async () => {
    const h = harness({ policy: warningPolicy, confirm: (prompt: any) => {
      expect(() => { prompt.arguments.nested.x = 'tampered'; }).toThrow(); return true;
    } });
    const result = await h.coordinator.invoke('repo', 'read_file', '{"nested":{"x":"original"}}',
      { user: {}, custom: { project: 'pilot' } });
    expect(result.status).toBe('completed'); expect(h.effects[0].args.nested.x).toBe('original'); h.verify();
  });
  it.each(['evaluation-rejection', 'evaluation-timeout', 'foreign-policy', 'foreign-action', 'monitor', 'duplicate-receipt'])
  ('blocks invalid engine behavior %s', async kind => {
    let prior: any;
    const engine = { prepare(resolution: any) {
      const prepared = api.typescriptInvocationEngine.prepare(resolution);
      return { ...prepared, evaluate: async (action: any, context: any) => {
        if (kind === 'evaluation-rejection') throw Error('engine failed');
        if (kind === 'evaluation-timeout') return new Promise(() => {});
        const receipt = await prepared.evaluate(action, context);
        if (kind === 'foreign-policy') receipt.policy.content_hash = `sha256:${'0'.repeat(64)}`;
        if (kind === 'foreign-action') receipt.action.target = '/other';
        if (kind === 'monitor') receipt.enforcement.mode = 'monitor';
        if (kind === 'duplicate-receipt') { if (prior) receipt.receipt_id = prior; prior = receipt.receipt_id; }
        return receipt;
      } };
    } };
    const h = harness({ engine, timeoutMs: 15 });
    expect(await invoke(h)).toMatchObject({ status: 'blocked' }); expect(h.effects).toHaveLength(0); h.verify();
  });
  it.each(['throw', 'promise', 'bad-ack'])('latches an authoritative pre-permit sink failure: %s', async kind => {
    const h = harness({ sink: (event: any, file: any) => {
      if (event.type === 'decision') {
        if (kind === 'throw') throw Error('disk unavailable');
        if (kind === 'promise') return Promise.resolve({ sequence: 3, entryHash: `sha256:${'0'.repeat(64)}` });
        return { sequence: 99, entryHash: 'garbage' };
      } return file.append(event);
    } });
    await expect(invoke(h)).rejects.toMatchObject({ name: 'InvocationEvidenceError', admitted: false });
    await expect(invoke(h)).rejects.toThrow(/unavailable/); expect(h.effects).toHaveLength(0);
    expect(() => h.coordinator.close()).toThrow();
  });
  it('terminal evidence failure reports possible execution and stops future dispatch', async () => {
    const h = harness({ sink: (event: any, file: any) => {
      if (event.type === 'terminal') throw Error('terminal disk unavailable'); return file.append(event);
    } });
    await expect(invoke(h)).rejects.toMatchObject({ name: 'InvocationEvidenceError', admitted: true });
    expect(h.effects).toHaveLength(1); await expect(invoke(h)).rejects.toThrow(/unavailable/);
    expect(() => h.coordinator.close()).toThrow();
  });
  it('does not retract already admitted effects after reload', async () => {
    const done = deferred<any>(); const reached = deferred<boolean>();
    const h = harness({ dispatch: () => { reached.resolve(true); return done.promise; } });
    const call = invoke(h); await reached.promise;
    h.install({ ...h.policy, metadata: { policy_version: 2 } });
    done.resolve({ content: 'finished' }); expect(await call).toMatchObject({ status: 'completed' }); h.verify();
  });
  it('bounds pending confirmation and refuses close until calls finish', async () => {
    const done = deferred<boolean>(); let seen = 0; const reached = deferred<boolean>();
    const h = harness({ policy: warningPolicy, confirm: () => { if (++seen === 16) reached.resolve(true); return done.promise; } });
    const calls = Array.from({ length: 16 }, () => invoke(h)); await reached.promise;
    expect(await invoke(h)).toMatchObject({ status: 'blocked' });
    expect(() => h.coordinator.close()).toThrow(/pending/);
    done.resolve(false); await Promise.all(calls); expect(h.effects).toHaveLength(0); h.verify();
  });
  it('records dispatch errors without claiming rollback or retrying', async () => {
    let effects = 0; const h = harness({ dispatch: () => { effects++; throw Error('partial write'); } });
    expect(await invoke(h)).toMatchObject({ status: 'error' }); expect(effects).toBe(1); h.verify();
  });
  it('marks a dispatch deadline unknown and refuses to close or dispatch again', async () => {
    let effects = 0;
    const h = harness({ timeoutMs: 15, dispatch: () => { effects++; return new Promise(() => {}); } });
    expect(await invoke(h)).toMatchObject({ status: 'unknown' });
    expect(effects).toBe(1);
    expect(h.events.some(e => e.type === 'terminal')).toBe(false);
    await expect(invoke(h)).rejects.toThrow(/unavailable/);
    expect(() => h.coordinator.close()).toThrow(/unavailable/);
  });
  it('refuses policy rollback and a name swap without silently keeping the old policy', async () => {
    const h = harness();
    h.install({ ...h.policy, metadata: { policy_version: 2 } });
    expect(() => h.install(h.policy)).toThrow(/rollback/);
    expect(await invoke(h)).toMatchObject({ status: 'blocked' });
    expect(() => h.install({ ...h.policy, name: 'different', metadata: { policy_version: 3 } })).toThrow(/name/);
    expect(await invoke(h)).toMatchObject({ status: 'blocked' });
    expect(h.effects).toHaveLength(0); h.verify();
  });
  it('handles a reentrant policy reload after permit without dispatch', async () => {
    let h: ReturnType<typeof harness>;
    h = harness({ sink: (event: any, file: any, events: any[]) => {
      events.push(event); const ack = file.append(event);
      if (event.type === 'permit') h.install({ ...h.policy, metadata: { policy_version: 2 } });
      return ack;
    } });
    expect(await invoke(h)).toMatchObject({ status: 'blocked' });
    expect(h.effects).toHaveLength(0);
    expect(h.events.at(-1).outcome).toBe('aborted_before_dispatch'); h.verify();
  });
  it('rejects rollback reentry while acknowledging an accepted policy', async () => {
    let h: ReturnType<typeof harness>;
    let nestedError: unknown; let outerError: unknown;
    h = harness({ sink: (event: any, file: any, events: any[]) => {
      events.push(event); const ack = file.append(event);
      if (event.type === 'policy' && event.status === 'accepted' && event.policy.metadata.policy_version === 3) {
        try { h.install({ ...h.policy, metadata: { policy_version: 2 } }); }
        catch (error) { nestedError = error; }
      }
      return ack;
    } });
    try { h.install({ ...h.policy, metadata: { policy_version: 3 } }); }
    catch (error) { outerError = error; }
    expect(await invoke(h)).toMatchObject({ status: 'completed' });
    expect(h.events.filter(e => e.type === 'policy' && e.status === 'accepted')
      .map(e => e.policy.metadata.policy_version)).toEqual([1, 3]);
    expect(nestedError).toBeInstanceOf(Error); expect(String(nestedError)).toMatch(/installation in progress/);
    expect(outerError).toBeUndefined(); expect(h.effects).toHaveLength(1); h.verify();
  });
  it('rejects a first-name replacement during accepted-policy acknowledgment', async () => {
    let h: ReturnType<typeof harness>;
    let nestedError: unknown; let outerError: unknown;
    h = harness({ autoInstall: false, sink: (event: any, file: any, events: any[]) => {
      events.push(event); const ack = file.append(event);
      if (event.type === 'policy' && event.status === 'accepted' && event.policy.name === 'coding') {
        try { h.install({ ...h.policy, name: 'different' }); }
        catch (error) { nestedError = error; }
      }
      return ack;
    } });
    try { h.install(); } catch (error) { outerError = error; }
    expect(await invoke(h)).toMatchObject({ status: 'completed' });
    expect(h.events.filter(e => e.type === 'policy' && e.status === 'accepted').map(e => e.policy.name)).toEqual(['coding']);
    expect(nestedError).toBeInstanceOf(Error); expect(String(nestedError)).toMatch(/installation in progress/);
    expect(outerError).toBeUndefined(); expect(h.effects).toHaveLength(1); h.verify();
  });
  it('rejects engine preparation reentry without skipping a journal generation', async () => {
    let h: ReturnType<typeof harness>;
    let nestedError: unknown; let outerError: unknown; let first = true;
    h = harness({ autoInstall: false, engine: { prepare(resolution: any) {
      if (first) {
        first = false;
        try { h.install({ ...h.policy, metadata: { policy_version: 2 } }); }
        catch (error) { nestedError = error; }
      }
      return api.typescriptInvocationEngine.prepare(resolution);
    } } });
    try { h.install(); } catch (error) { outerError = error; }
    expect(await invoke(h)).toMatchObject({ status: 'completed' });
    expect(h.events.filter(e => e.type === 'policy').map(e => e.generation)).toEqual([1]);
    expect(nestedError).toBeInstanceOf(Error); expect(String(nestedError)).toMatch(/installation in progress/);
    expect(outerError).toBeUndefined(); expect(h.effects).toHaveLength(1); h.verify();
  });
});
