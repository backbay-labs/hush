import { afterEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as api from '../src/index.js';
import { schemaErrors } from './helpers/json-schema.js';

const roots: string[] = [];
afterEach(() => { vi.restoreAllMocks(); for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true }); });
const directory = () => { const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hush-invocation-')); roots.push(root); return path.join(root, 'journal'); };

async function fixture() {
  const runtime = api.generateKeypair();
  const policyKey = api.generateKeypair();
  const now = new Date();
  const policy = { hushspec: '0.2.0', name: 'coding', metadata: { policy_version: 1 },
    rules: { tool_access: { allow: ['mcp:repo/read_file'], default: 'block' as const } } };
  const envelope = api.signPolicy(policy, policyKey.privateKeyPem, { signedAt: now });
  const captured = new api.AuthenticatedPolicy(JSON.stringify(policy), envelope, policyKey.publicKeyPem);
  const callId = api.uuidV7();
  const context = { current_time: now.toISOString() };
  const args = { path: 'note.txt' };
  const actions = [{ type: 'tool_call', target: 'mcp:repo/read_file', args_size: 19, context },
    { type: 'file_read', target: '/workspace/note.txt', context }];
  const receipts = await Promise.all(actions.map(action => captured.prepared.evaluate(action, context)));
  const binding = { call_id: callId, generation: 1, policy_hash: captured.resolution.content_hash,
    target: 'mcp:repo/read_file', arguments_hash: api.hashJson(args), effects_hash: api.hashJson(actions),
    panic_epoch: 0, global_panic_epoch: 0 };
  const events: any[] = [
    { type: 'policy', generation: 1, status: 'accepted', policy, envelope, engine: captured.prepared.identity },
    { type: 'attempt', ...binding, arguments: args, actions, context },
    { type: 'decision', call_id: callId, aggregate: 'allow', confirmation: 'not_required', receipts,
      receipt_hashes: receipts.map(api.receiptHash) },
    { type: 'permit', ...binding, receipt_ids: receipts.map(r => r.receipt_id), receipt_hashes: receipts.map(api.receiptHash) },
    { type: 'terminal', call_id: callId, outcome: 'completed' },
  ];
  const streamId = api.uuidV7();
  const trust = { runtimePublicKeyPem: runtime.publicKeyPem, policyPublicKeyPem: policyKey.publicKeyPem,
    expectedStreamId: streamId };
  // Deliberately sign arbitrary semantics: negative tests must not stop at signature failure.
  const seal = (input = events) => {
    let previous: string | null = null;
    const entries = input.map((event, index) => {
      const body = { kind: 'hush.invocation.entry', format_version: '0.1.0', stream_id: streamId,
        sequence: index + 1, previous_hash: previous, timestamp: new Date().toISOString(), event };
      previous = api.hashJson(body);
      return { ...body, entry_hash: previous, signature: api.signContentHash(previous, runtime.privateKeyPem,
        { signedAt: body.timestamp }) };
    });
    const body = { kind: 'hush.invocation.checkpoint', format_version: '0.1.0', stream_id: streamId,
      entry_count: entries.length, head_hash: previous, closed: true, timestamp: new Date().toISOString() };
    const checkpoint = { ...body, signature: api.signContentHash(api.hashJson(body), runtime.privateKeyPem,
      { signedAt: body.timestamp }) };
    return { entries, jsonl: entries.map(e => JSON.stringify(e)).join('\n') + '\n', checkpoint: JSON.stringify(checkpoint) };
  };
  return { runtime, policyKey, callId, streamId, trust, events, seal };
}

describe('authoritative invocation journal', () => {
  it('exports the durable writer and offline verifier', () => {
    expect(api.FileInvocationJournal).toBeTypeOf('function');
    expect(api.verifyInvocationJournal).toBeTypeOf('function');
  });
  it('persists private signed entries and a complete checkpoint', async () => {
    const f = await fixture();
    const dir = directory();
    const journal = new api.FileInvocationJournal(dir, f.runtime.privateKeyPem, { streamId: f.streamId });
    for (const event of f.events) expect(journal.append(event).entryHash).toMatch(/^sha256:/);
    const checkpoint = journal.close();
    const checked = api.verifyInvocationJournal(fs.readFileSync(path.join(dir, 'entries.jsonl'), 'utf8'),
      JSON.stringify(checkpoint), f.trust);
    expect(checked.complete).toBe(true);
    expect(checked.calls).toEqual([{ callId: f.callId, outcome: 'completed' }]);
    expect(fs.statSync(dir).mode & 0o777).toBe(0o700);
    expect(fs.statSync(path.join(dir, 'entries.jsonl')).mode & 0o777).toBe(0o600);
    expect(() => journal.append(f.events[0])).toThrow(/closed/);
    expect(() => new api.FileInvocationJournal(dir, f.runtime.privateKeyPem)).toThrow();
  });
  it('fsyncs file, directory and parent before any append acknowledgment', async () => {
    const f = await fixture();
    const kinds: string[] = [];
    const actual = fs.fsyncSync;
    vi.spyOn(fs, 'fsyncSync').mockImplementation(fd => {
      kinds.push(fs.fstatSync(fd).isDirectory() ? 'directory' : 'file'); actual(fd);
    });
    const journal = new api.FileInvocationJournal(directory(), f.runtime.privateKeyPem);
    journal.append({ type: 'rejected', call_id: f.callId, reason: 'invalid arguments' });
    expect(kinds.slice(0, 4)).toEqual(['file', 'directory', 'directory', 'file']);
    journal.close();
  });
  it('latches write/fsync failures and refuses a checkpoint over pending work', async () => {
    const f = await fixture();
    const journal = new api.FileInvocationJournal(directory(), f.runtime.privateKeyPem);
    journal.append(f.events[0]);
    journal.append(f.events[1]);
    expect(() => journal.close()).toThrow(/pending/);
    vi.spyOn(fs, 'fsyncSync').mockImplementationOnce(() => { throw Error('disk failure'); });
    expect(() => journal.append(f.events[2])).toThrow(/disk failure/);
    expect(() => journal.append(f.events[3])).toThrow(/failed/);
    expect(() => journal.close()).toThrow(/failed/);
    journal.dispose();
  });
  it('retains incomplete data after a short write or checkpoint failure', async () => {
    const f = await fixture();
    const journal = new api.FileInvocationJournal(directory(), f.runtime.privateKeyPem);
    vi.spyOn(fs, 'writeSync').mockReturnValueOnce(0);
    expect(() => journal.append(f.events[0])).toThrow(/no progress/);
    expect(() => journal.close()).toThrow(/failed/);
    journal.dispose(); vi.restoreAllMocks();
    const closing = new api.FileInvocationJournal(directory(), f.runtime.privateKeyPem);
    vi.spyOn(fs, 'fsyncSync').mockImplementationOnce(() => { throw Error('checkpoint fsync'); });
    expect(() => closing.close()).toThrow(/checkpoint fsync/);
    expect(() => closing.close()).toThrow(/failed/);
    closing.dispose();
  });
  it('bounds journal payloads before writing them', async () => {
    const f = await fixture(); const dir = directory();
    const journal = new api.FileInvocationJournal(dir, f.runtime.privateKeyPem);
    expect(() => journal.append({ type: 'rejected', call_id: f.callId,
      reason: 'x'.repeat(2_097_153) })).toThrow(/limit/);
    expect(fs.statSync(path.join(dir, 'entries.jsonl')).size).toBe(0);
    journal.dispose();
  });
});

describe('invocation evidence replay', () => {
  it('matches the published companion shape and rejects extra event fields', async () => {
    const schema = JSON.parse(fs.readFileSync(new URL('../../../schemas/hushspec-invocation-journal-experimental.v1.schema.json', import.meta.url), 'utf8'));
    const f = await fixture(); const sealed = f.seal();
    for (const entry of sealed.entries) expect(schemaErrors(schema, entry)).toEqual([]);
    expect(schemaErrors(schema, JSON.parse(sealed.checkpoint))).toEqual([]);
    const changed = structuredClone(sealed.entries[4]); changed.event.surprise = true;
    expect(schemaErrors(schema, changed).length).toBeGreaterThan(0);
  });
  it('accepts complete evidence and reports an unclosed prefix as incomplete/unknown', async () => {
    const f = await fixture();
    const full = f.seal();
    expect(api.verifyInvocationJournal(full.jsonl, full.checkpoint, f.trust).complete).toBe(true);
    const prefix = f.seal(f.events.slice(0, 4));
    expect(() => api.verifyInvocationJournal(prefix.jsonl, prefix.checkpoint, f.trust)).toThrow(/incomplete/);
    expect(api.inspectInvocationJournal(prefix.jsonl, f.trust)).toMatchObject({ complete: false,
      calls: [{ callId: f.callId, outcome: 'unknown' }] });
    expect(() => api.inspectInvocationJournal(prefix.jsonl, { ...f.trust,
      expectedHeadHash: `sha256:${'0'.repeat(64)}` })).toThrow(/head/);
  });
  it('rejects truncation, reordering, wrong stream/key and unknown signed fields', async () => {
    const f = await fixture(); const full = f.seal();
    const truncated = full.entries.slice(0, -1).map(e => JSON.stringify(e)).join('\n') + '\n';
    expect(() => api.verifyInvocationJournal(truncated, full.checkpoint, f.trust)).toThrow();
    const reordered = [...full.entries].reverse().map(e => JSON.stringify(e)).join('\n') + '\n';
    expect(() => api.verifyInvocationJournal(reordered, full.checkpoint, f.trust)).toThrow();
    expect(() => api.verifyInvocationJournal(full.jsonl, full.checkpoint, { ...f.trust,
      expectedStreamId: api.uuidV7() })).toThrow();
    expect(() => api.verifyInvocationJournal(full.jsonl, full.checkpoint, { ...f.trust,
      runtimePublicKeyPem: f.policyKey.publicKeyPem })).toThrow();
    const mutated = structuredClone(f.events); mutated[4].surprise = true;
    const signed = f.seal(mutated);
    expect(() => api.verifyInvocationJournal(signed.jsonl, signed.checkpoint, f.trust)).toThrow();
  });
  it('rejects replay below a caller-provided version floor and invalid expected heads', async () => {
    const f = await fixture(); const full = f.seal();
    expect(() => api.verifyInvocationJournal(full.jsonl, full.checkpoint, { ...f.trust,
      lastSeenVersion: 2 })).toThrow(/rollback/);
    expect(() => api.verifyInvocationJournal(full.jsonl, full.checkpoint, { ...f.trust,
      expectedHeadHash: `sha256:${'0'.repeat(64)}` })).toThrow(/head/);
    const duplicate = full.jsonl.replace('"sequence":1,', '"sequence":1,"sequence":1,');
    expect(() => api.verifyInvocationJournal(duplicate, full.checkpoint, f.trust)).toThrow(/duplicate/);
  });
  it.each(['foreign-call', 'foreign-receipt', 'receipt-content', 'receipt-context', 'warn-without-confirmation',
    'stale-generation', 'duplicate-permit', 'duplicate-receipt', 'policy-identity', 'action-substitution'])
  ('rejects correctly signed invalid semantics: %s', async mutation => {
    const f = await fixture(); const events = structuredClone(f.events);
    if (mutation === 'foreign-call') events[3].call_id = api.uuidV7();
    if (mutation === 'foreign-receipt') events[3].receipt_ids[0] = api.uuidV7();
    if (mutation === 'receipt-content') events[2].receipts[1].action.content_hash = `sha256:${'0'.repeat(64)}`;
    if (mutation === 'receipt-context') events[2].receipts[1].action.context = { user: { role: 'admin' } };
    if (mutation === 'warn-without-confirmation') {
      events[2].receipts[0].decision = 'warn'; events[2].aggregate = 'warn';
    }
    if (mutation === 'stale-generation') events.splice(3, 0,
      { type: 'policy', generation: 2, status: 'refused', reason: 'reload failed' });
    if (mutation === 'duplicate-permit') events.splice(4, 0, structuredClone(events[3]));
    if (mutation === 'duplicate-receipt') events[2].receipts[1].receipt_id = events[2].receipts[0].receipt_id;
    if (mutation === 'policy-identity') events[0].envelope = api.signPolicy(events[0].policy,
      f.policyKey.privateKeyPem, { policyVersion: 99 });
    if (mutation === 'action-substitution') events[1].actions[1].target = '/secret';
    // Rebind hashes so these must fail semantic validation, not just transport integrity.
    events[2].receipt_hashes = events[2].receipts.map(api.receiptHash);
    const permit = events.find(e => e.type === 'permit');
    permit.receipt_hashes = [...events[2].receipt_hashes];
    const signed = f.seal(events);
    expect(() => api.verifyInvocationJournal(signed.jsonl, signed.checkpoint, f.trust)).toThrow();
  });
});
