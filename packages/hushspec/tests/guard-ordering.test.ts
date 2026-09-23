import { expect, it } from 'vitest';
import { HushGuard } from '../src/middleware.js';
import { parseOrThrow } from '../src/parse.js';
import type { ReceiptSink } from '../src/sinks.js';

const old = parseOrThrow(`hushspec: '1.0.0'
name: old
rules:
  tool_access:
    require_confirmation: [edit]
`);
const next = parseOrThrow("hushspec: '1.0.0'\nname: next\n");
const action = { type: 'tool_call', target: 'edit' } as const;

function log() {
  const entries: {kind: string; hash: string}[] = [];
  const sink: ReceiptSink = {
    send: r => { entries.push({kind: 'receipt', hash: r.policy.content_hash}); },
    recordPolicyEvent: e => { entries.push({kind: e.event, hash: e.policy.content_hash}); },
  };
  return {sink, entries};
}

function ordered(entries: ReturnType<typeof log>['entries']) {
  let current: string | undefined;
  for (const entry of entries) {
    if (entry.kind === 'receipt') expect(entry.hash).toBe(current);
    else current = entry.hash;
  }
}

it('records the swap before a reload observer evaluates', () => {
  const {sink, entries} = log();
  const guard = new HushGuard(old, {sink, observer: {onEvent(e) {
    if (e.type === 'policy.reloaded') guard.evaluate(action);
  }}});
  guard.swapPolicy(next);
  expect(entries.map(e => e.kind)).toEqual(['loaded', 'swapped', 'receipt']);
  ordered(entries);
});

it('records a custom provider pull adoption before the new receipt', async () => {
  const {sink, entries} = log();
  let current = old;
  const guard = await HushGuard.fromProvider({
    async load() { return current; }, current() { return current; }, watch() {}, stop() {},
  }, {sink});
  current = next;
  guard.evaluate(action);
  expect(entries.map(e => e.kind)).toEqual(['loaded', 'swapped', 'receipt']);
  ordered(entries);
});

it('rejects a confirmation callback reload before mutation and releases the gate', () => {
  const {sink, entries} = log();
  const guard = new HushGuard(old, {sink, onWarn() { guard.swapPolicy(next); return true; }});
  expect(() => guard.gate(action)).toThrow(/reentrant/i);
  expect(entries.map(e => e.kind)).toEqual(['loaded', 'receipt']);
  ordered(entries);
  guard.swapPolicy(next);
  expect(guard.check(action)).toBe(true);
  ordered(entries);
});

it('rejects sink reentry but permits evaluation observer reentry', () => {
  const {sink, entries} = log();
  let nestedError: unknown;
  let observed = false;
  const guard = new HushGuard(old, {
    sink: {...sink, send(receipt) {
      try { guard.swapPolicy(next); } catch (error) { nestedError = error; }
      sink.send(receipt);
    }},
    observer: {onEvent(e) {
      if (e.type === 'evaluation.completed' && !observed) {
        observed = true;
        guard.swapPolicy(next);
      }
    }},
  });
  guard.evaluate(action);
  expect(nestedError).toBeInstanceOf(Error);
  expect(String(nestedError)).toMatch(/reentrant/i);
  expect(observed).toBe(true);
  ordered(entries);
});
