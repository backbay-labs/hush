import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { HushGuard } from '../src/middleware.js';
import { ChainedFileSink, verifyLog } from '../src/log.js';
import type { LogEntry, PolicyEvent } from '../src/log.js';
import type { DecisionReceipt } from '../src/receipt.js';
import { parseOrThrow } from '../src/parse.js';
import { contentHash } from '../src/canonical.js';
import { loadKeyring, signPolicy } from '../src/signing.js';
import { resolveWithOptions } from '../src/resolve.js';
import { SDK_NAME, SDK_VERSION } from '../src/version.js';
import { schemaErrors, type SchemaDocument } from './helpers/json-schema.js';

/**
 * The guard's end of the evidence chain: every receipt it emits is format
 * 0.2 and names the policy it actually resolved, every policy change is
 * recorded through the sink before any receipt evaluated under it (log spec
 * 6), and an action refused because the policy did not verify still produces
 * the receipt signing spec 6.5 requires.
 */

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const keysDir = path.join(repoRoot, 'fixtures/signing/keys');

const POLICY = `
hushspec: "0.1.0"
name: guard-evidence
metadata:
  policy_version: 3
rules:
  tool_access:
    allow: [read_file]
    block: [dangerous_tool]
    default: block
`;

const SWAPPED_POLICY = `
hushspec: "0.1.0"
name: guard-evidence
metadata:
  policy_version: 4
rules:
  tool_access:
    allow: [read_file, write_file]
    default: block
`;

interface Recorder {
  receipts: DecisionReceipt[];
  events: PolicyEvent[];
  send(receipt: DecisionReceipt): void;
  recordPolicyEvent(event: PolicyEvent): void;
}

function recorder(): Recorder {
  const receipts: DecisionReceipt[] = [];
  const events: PolicyEvent[] = [];
  return {
    receipts,
    events,
    send: (receipt) => void receipts.push(receipt),
    recordPolicyEvent: (event) => void events.push(event),
  };
}

const receiptSchema = JSON.parse(
  readFileSync(path.join(repoRoot, 'schemas/hushspec-receipt.v0.schema.json'), 'utf8'),
) as SchemaDocument;

function wire(receipt: DecisionReceipt): unknown {
  return JSON.parse(JSON.stringify(receipt)) as unknown;
}

describe('HushGuard receipts', () => {
  it('emits 0.2 receipts that validate against the published schema', () => {
    const sink = recorder();
    const guard = HushGuard.fromYaml(POLICY, { sink });
    guard.gate({ type: 'tool_call', target: 'dangerous_tool' });

    expect(sink.receipts).toHaveLength(1);
    const receipt = sink.receipts[0]!;
    expect(receipt.receipt_version).toBe('0.2');
    expect(schemaErrors(receiptSchema, wire(receipt))).toEqual([]);
    expect(receipt.policy.content_hash).toBe(guard.resolution.content_hash);
    expect(receipt.policy.spec_version).toBe('0.1.0');
    expect(receipt.policy.version).toBe(3);
    expect(receipt.enforcement).toEqual({ mode: 'enforce', outcome: 'blocked' });
  });

  it('carries the actor and time source it was configured with', () => {
    const sink = recorder();
    const guard = HushGuard.fromYaml(POLICY, {
      sink,
      actor: {
        agent_id: 'deploy-bot-3',
        session_id: 'run-0042',
        principal: 'alice@example.com',
        runtime: 'hushspec-ts/0.2',
      },
      timeSource: 'monotonic_adjusted',
    });
    guard.gate({ type: 'tool_call', target: 'read_file' });

    const receipt = sink.receipts[0]!;
    expect(receipt.actor).toEqual({
      agent_id: 'deploy-bot-3',
      session_id: 'run-0042',
      principal: 'alice@example.com',
      runtime: 'hushspec-ts/0.2',
    });
    expect(receipt.time_source).toBe('monotonic_adjusted');
    expect(schemaErrors(receiptSchema, wire(receipt))).toEqual([]);
  });

  it('records the merged chain when the policy extends a builtin', () => {
    const sink = recorder();
    const guard = HushGuard.fromYaml(
      'hushspec: "0.1.0"\nname: child\nextends: "builtin:default"\n',
      { sink },
    );
    guard.gate({ type: 'egress', target: 'api.github.com' });

    const receipt = sink.receipts[0]!;
    expect(receipt.policy.extends_chain).toHaveLength(2);
    expect(receipt.policy.extends_chain![0]!.source).toBe('builtin:default');
    expect(receipt.policy.content_hash).toBe(guard.resolution.content_hash);
    expect(schemaErrors(receiptSchema, wire(receipt))).toEqual([]);
  });
});

describe('HushGuard policy events', () => {
  it('records policy_loaded through the sink on construction', () => {
    const sink = recorder();
    const guard = HushGuard.fromYaml(POLICY, { sink });

    expect(sink.events).toHaveLength(1);
    const event = sink.events[0]!;
    expect(event.event).toBe('loaded');
    expect(event.policy.content_hash).toBe(guard.resolution.content_hash);
    expect(event.policy.version).toBe(3);
    expect(event.enforcement_mode).toBe('enforce');
    expect(event.sdk).toEqual({ name: SDK_NAME, version: SDK_VERSION });
    expect(event.spec_version).toBe('0.2.0');
    expect(event.previous_content_hash).toBeUndefined();
    // Before any receipt evaluated under it (log spec 6).
    expect(sink.receipts).toHaveLength(0);
  });

  it('records policy_swapped naming the hash it replaced', () => {
    const sink = recorder();
    const guard = HushGuard.fromYaml(POLICY, { sink });
    const before = guard.resolution.content_hash;

    guard.swapPolicy(parseOrThrow(SWAPPED_POLICY));

    expect(sink.events).toHaveLength(2);
    const event = sink.events[1]!;
    expect(event.event).toBe('swapped');
    expect(event.previous_content_hash).toBe(before);
    expect(event.policy.content_hash).toBe(guard.resolution.content_hash);
    expect(event.policy.version).toBe(4);
    expect(event.policy.content_hash).not.toBe(before);
  });

  it('carries the guard enforcement mode into the event', () => {
    const sink = recorder();
    HushGuard.fromYaml(POLICY, { sink, enforcement: { mode: 'monitor' } });
    expect(sink.events[0]!.enforcement_mode).toBe('monitor');
  });

  it('never lets a throwing sink break policy loading', () => {
    expect(() =>
      HushGuard.fromYaml(POLICY, {
        sink: {
          send: () => {},
          recordPolicyEvent: () => {
            throw new Error('sink down');
          },
        },
      }),
    ).not.toThrow();
  });

  it('a sink that carries only receipts is unaffected', () => {
    const receipts: DecisionReceipt[] = [];
    const guard = HushGuard.fromYaml(POLICY, { sink: { send: (r) => receipts.push(r) } });
    guard.gate({ type: 'tool_call', target: 'read_file' });
    expect(receipts).toHaveLength(1);
  });
});

describe('HushGuard with a hash-linked log', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'hushspec-guard-log-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('writes a verifiable chain of the policy in force and every decision', () => {
    const file = path.join(dir, 'audit.jsonl');
    const sink = ChainedFileSink.open(file);
    const guard = HushGuard.fromYaml(POLICY, { sink });

    guard.gate({ type: 'tool_call', target: 'read_file' });
    guard.gate({ type: 'tool_call', target: 'dangerous_tool' });
    guard.swapPolicy(parseOrThrow(SWAPPED_POLICY));
    guard.gate({ type: 'tool_call', target: 'write_file' });

    const text = readFileSync(file, 'utf8');
    const report = verifyLog('audit.jsonl', text);
    expect(report.ok).toBe(true);
    expect(report.entries).toBe(5);
    expect(report.receipts).toBe(3);
    expect(report.policy_events).toBe(2);

    const entries = text
      .split('\n')
      .filter((line) => line.trim() !== '')
      .map((line) => JSON.parse(line) as LogEntry);
    expect(entries.map((entry) => entry.entry_type)).toEqual([
      'policy_loaded',
      'receipt',
      'receipt',
      'policy_swapped',
      'receipt',
    ]);
    // Every receipt maps to the policy event above it.
    expect(entries[1]!.receipt!.policy.content_hash).toBe(
      entries[0]!.policy_event!.policy.content_hash,
    );
    expect(entries[4]!.receipt!.policy.content_hash).toBe(
      entries[3]!.policy_event!.policy.content_hash,
    );
    expect(entries[4]!.receipt!.decision).toBe('allow');
  });
});

describe('HushGuard refusing an unverified policy', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'hushspec-guard-verify-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function keyring() {
    return loadKeyring(readFileSync(path.join(keysDir, 'keyring.json'), 'utf8'));
  }

  /** Write `POLICY` with a `.sig` made by `key`, and return its path. */
  function writePolicy(signWith?: string): string {
    const file = path.join(dir, 'policy.yaml');
    writeFileSync(file, POLICY);
    if (signWith !== undefined) {
      const resolved = resolveWithOptions(parseOrThrow(POLICY), { source: file });
      writeFileSync(
        `${file}.sig`,
        JSON.stringify(signPolicy(resolved.spec, readFileSync(signWith, 'utf8'))),
      );
    }
    return file;
  }

  it('emits the reserved unverified-policy receipt for every refused action', () => {
    const sink = recorder();
    const file = writePolicy(); // no signature at all
    const guard = HushGuard.fromFile(file, {
      sink,
      requireSignature: true,
      keyring: keyring(),
    });

    const outcome = guard.gate({ type: 'tool_call', target: 'read_file' });
    expect(outcome.proceed).toBe(false);

    expect(sink.receipts).toHaveLength(1);
    const receipt = sink.receipts[0]!;
    expect(receipt.decision).toBe('deny');
    expect(receipt.matched_rule).toBe('__hushspec_policy_unverified__');
    expect(receipt.rule_trace).toEqual([]);
    expect(receipt.policy.signature).toBeDefined();
    expect(receipt.policy.signature!.verified).toBe(false);
    expect(receipt.reason).toContain(receipt.policy.signature!.reason!);
    expect(receipt.enforcement).toEqual({ mode: 'enforce', outcome: 'blocked' });
    expect(receipt.policy.content_hash).toBe(contentHash(parseOrThrow(POLICY)));
    expect(schemaErrors(receiptSchema, wire(receipt))).toEqual([]);
  });

  it('refuses in monitor mode too: there is no policy to monitor against', () => {
    const sink = recorder();
    const file = writePolicy();
    const guard = HushGuard.fromFile(file, {
      sink,
      requireSignature: true,
      keyring: keyring(),
      enforcement: { mode: 'monitor' },
    });
    const outcome = guard.gate({ type: 'tool_call', target: 'read_file' });
    expect(outcome.proceed).toBe(false);
    expect(sink.receipts[0]!.enforcement).toEqual({ mode: 'enforce', outcome: 'blocked' });
  });

  it('evaluates normally once the policy verifies', () => {
    const sink = recorder();
    const file = writePolicy(path.join(keysDir, 'test-signing.key.pem'));
    const guard = HushGuard.fromFile(file, {
      sink,
      requireSignature: true,
      keyring: keyring(),
    });

    expect(guard.resolution.signature?.verified).toBe(true);
    expect(sink.events[0]!.policy.signature?.verified).toBe(true);
    expect(sink.events[0]!.policy.signature?.verified_at).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
    );

    const outcome = guard.gate({ type: 'tool_call', target: 'read_file' });
    expect(outcome.proceed).toBe(true);
    const receipt = sink.receipts[0]!;
    expect(receipt.policy.signature?.verified).toBe(true);
    expect(receipt.policy.signature?.key_id).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(receipt.rule_trace.length).toBeGreaterThan(0);
    expect(schemaErrors(receiptSchema, wire(receipt))).toEqual([]);
  });
});
