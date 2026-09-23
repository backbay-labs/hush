import { createHash } from 'node:crypto';
import { canonicalizeValue, type JsonValue } from '../canonical.js';
import type { EvaluationAction } from '../evaluate.js';
import { compactObject, parseReceipt, receiptHash, type DecisionReceipt } from '../receipt.js';
import { keyIdFromPublicKey, verifyContentHash } from '../signing.js';
import { hashJson, snapshotJson } from './json.js';
import { AuthenticatedPolicy } from './policy.js';
import { JOURNAL_LIMITS } from './journal.js';
import { assertEvent, callBinding, closedObject, hashField, idField, natural, timestampField,
  type InvocationAttempt, type InvocationDecision, type InvocationEvent } from './model.js';

export interface InvocationTrust {
  runtimePublicKeyPem: string;
  policyPublicKeyPem: string;
  expectedStreamId: string;
  expectedHeadHash?: string;
  lastSeenVersion?: number;
}
export interface InvocationVerification {
  complete: boolean;
  streamId: string;
  entryCount: number;
  headHash: string | null;
  calls: { callId: string; outcome: 'rejected' | 'blocked' | 'completed' | 'error' | 'aborted_before_dispatch' | 'unknown' }[];
}
function same(a: unknown, b: unknown): boolean { return hashJson(a) === hashJson(b); }
function check(condition: unknown, reason: string): asserts condition { if (!condition) throw new Error(reason); }

/** Check the receipt's evaluated action, not just its independently valid schema. */
export function assertBoundReceipt(receipt: DecisionReceipt, action: EvaluationAction, policy: AuthenticatedPolicy): void {
  parseReceipt(receipt);
  const expected: Record<string, unknown> = { type: action.type, target: action.target };
  if (action.content !== undefined) {
    expected.content_hash = `sha256:${createHash('sha256').update(action.content).digest('hex')}`;
    expected.content_size = Buffer.byteLength(action.content);
  }
  if (action.args_size !== undefined) expected.args_size = action.args_size;
  const context = compactObject(action.context);
  if (context !== undefined) expected.context = context;
  check(same(receipt.action, expected), 'receipt action binding mismatch');
  check(receipt.policy.content_hash === policy.resolution.content_hash &&
    receipt.policy.name === policy.resolution.spec.name &&
    receipt.policy.version === policy.resolution.spec.metadata!.policy_version &&
    receipt.policy.spec_version === policy.resolution.spec.hushspec &&
    receipt.policy.signature?.verified === true &&
    receipt.policy.signature.key_id === policy.envelope.key_id, 'receipt policy binding mismatch');
  check(receipt.enforcement.mode === 'enforce' && receipt.enforcement.outcome !== 'would_block', 'receipt is not enforcing');
}

interface CallState {
  attempt?: InvocationAttempt;
  policy?: AuthenticatedPolicy;
  decision?: InvocationDecision;
  permit: boolean;
  outcome: InvocationVerification['calls'][number]['outcome'];
}
interface Replay extends InvocationVerification { lastTimestamp: string }

function replay(jsonl: string, trust: InvocationTrust): Replay {
  idField(trust.expectedStreamId);
  check(keyIdFromPublicKey(trust.runtimePublicKeyPem) !== keyIdFromPublicKey(trust.policyPublicKeyPem), 'policy/runtime keys must be distinct');
  check(typeof jsonl === 'string' && Buffer.byteLength(jsonl) <= JOURNAL_LIMITS.streamBytes, 'journal stream limit');
  check(jsonl === '' || jsonl.endsWith('\n'), 'truncated journal line');
  const lines = jsonl === '' ? [] : jsonl.slice(0, -1).split('\n');
  check(lines.length <= JOURNAL_LIMITS.entries, 'journal entry limit');
  let head: string | null = null;
  let lastTimestamp = '';
  let generation = 0;
  let policy: AuthenticatedPolicy | undefined;
  let policyName: string | undefined;
  let lastVersion = trust.lastSeenVersion;
  let panicEpoch = 0;
  let panic = false;
  let globalEpoch = 0;
  const calls = new Map<string, CallState>();
  const receiptIds = new Set<string>();
  for (const [index, line] of lines.entries()) {
    const entry = closedObject(snapshotJson(line, { maxBytes: JOURNAL_LIMITS.entryBytes, maxDepth: 56, maxNodes: 180_000 }),
      ['kind', 'format_version', 'stream_id', 'sequence', 'previous_hash', 'timestamp', 'event', 'entry_hash', 'signature']);
    check(entry.kind === 'hush.invocation.entry' && entry.format_version === '0.1.0', 'unsupported journal format');
    check(entry.stream_id === trust.expectedStreamId && entry.sequence === index + 1 && entry.previous_hash === head, 'journal sequence/stream mismatch');
    timestampField(entry.timestamp); hashField(entry.entry_hash);
    check(entry.timestamp >= lastTimestamp, 'journal time moved backwards');
    lastTimestamp = entry.timestamp;
    const { signature, entry_hash: entryHash, ...body } = entry;
    check(hashJson(body) === entryHash, 'journal hash mismatch');
    const verified = verifyContentHash(signature, entryHash, { publicKeyPem: trust.runtimePublicKeyPem, now: entry.timestamp });
    check(verified.ok, 'journal signature refused');
    check(verified.signedAt === entry.timestamp, 'journal signature time mismatch');
    head = entryHash;
    const event: unknown = entry.event;
    assertEvent(event);
    if (event.type === 'policy') {
      check(event.generation === generation + 1, 'nonconsecutive policy generation');
      generation = event.generation; policy = undefined;
      if (event.status === 'accepted') {
        policy = new AuthenticatedPolicy(canonicalizeValue(event.policy as unknown as JsonValue), event.envelope,
          trust.policyPublicKeyPem, undefined, lastVersion, new Date(entry.timestamp));
        check(policyName === undefined || policyName === policy.resolution.spec.name, 'policy name changed');
        policyName = policy.resolution.spec.name;
        lastVersion = policy.resolution.spec.metadata!.policy_version;
      }
      continue;
    }
    if (event.type === 'panic') {
      check(event.epoch === panicEpoch + 1, 'nonconsecutive panic epoch');
      panicEpoch = event.epoch; panic = event.active; continue;
    }
    if (event.type === 'rejected') {
      check(!calls.has(event.call_id), 'duplicate call ID');
      calls.set(event.call_id, { permit: false, outcome: 'rejected' }); continue;
    }
    if (event.type === 'attempt') {
      check(!calls.has(event.call_id) && calls.size < 2000, 'duplicate call ID or call limit');
      check(policy && event.generation === generation && event.policy_hash === policy.resolution.content_hash, 'attempt policy mismatch');
      check(!panic && event.panic_epoch === panicEpoch && event.global_panic_epoch >= globalEpoch, 'attempt panic mismatch');
      globalEpoch = event.global_panic_epoch;
      check(/^mcp:[a-z][a-z0-9_-]{0,63}\//.test(event.target), 'unqualified tool identity');
      const separator = event.target.indexOf('/');
      const encoded = event.target.slice(separator + 1);
      let decoded: string;
      try { decoded = decodeURIComponent(encoded); } catch { throw new Error('invalid qualified tool escaping'); }
      check(decoded.length > 0 && decoded.normalize('NFC') === decoded && encodeURIComponent(decoded) === encoded &&
        Buffer.byteLength(decoded) <= 128 && !/[\u0000-\u001f\u007f-\u009f]/.test(decoded), 'invalid qualified tool identity');
      check(hashJson(event.arguments) === event.arguments_hash && hashJson(event.actions) === event.effects_hash, 'attempt snapshot hash mismatch');
      const args = canonicalizeValue(event.arguments);
      snapshotJson(args);
      check(event.actions[0].target === event.target && event.actions[0].args_size === Buffer.byteLength(args), 'tool action binding mismatch');
      snapshotJson(canonicalizeValue(event.context as JsonValue), { maxBytes: 16_384 });
      timestampField(event.context.current_time);
      check(event.actions.every(action => same(action.context, event.context)), 'action context mismatch');
      calls.set(event.call_id, { attempt: event, policy, permit: false, outcome: 'unknown' }); continue;
    }
    const call = calls.get(event.call_id);
    check(call?.attempt && call.policy && call.outcome === 'unknown', 'foreign or already terminal call');
    if (event.type === 'decision') {
      check(!call.decision && !call.permit && event.receipts.length === call.attempt.actions.length &&
        event.receipt_hashes.length === event.receipts.length, 'invalid decision ownership/count');
      let aggregate: 'allow' | 'warn' | 'deny' = 'allow';
      for (const [i, receipt] of event.receipts.entries()) {
        assertBoundReceipt(receipt, call.attempt!.actions[i], call.policy!);
        check(!receiptIds.has(receipt.receipt_id), 'duplicate receipt ID'); receiptIds.add(receipt.receipt_id);
        check(receiptHash(receipt) === event.receipt_hashes[i], 'receipt hash mismatch');
        if (receipt.decision === 'deny' || (receipt.decision === 'warn' && aggregate === 'allow')) aggregate = receipt.decision;
      }
      check(aggregate === event.aggregate, 'aggregate decision mismatch');
      check(event.aggregate === 'warn' ? event.confirmation !== 'not_required' : event.confirmation === 'not_required', 'invalid confirmation disposition');
      const admitted = event.aggregate === 'allow' || (event.aggregate === 'warn' && event.confirmation === 'confirmed');
      for (const receipt of event.receipts) {
        const outcome = !admitted ? 'blocked' : receipt.decision === 'warn' ? 'confirmed' : 'allowed';
        check(receipt.enforcement.outcome === outcome, 'component enforcement mismatch');
      }
      call.decision = event;
    } else if (event.type === 'blocked') {
      check(!call.permit, 'blocked after permit'); call.outcome = 'blocked';
    } else if (event.type === 'permit') {
      check(!call.permit && call.decision && call.decision.aggregate !== 'deny' &&
        (call.decision.aggregate !== 'warn' || call.decision.confirmation === 'confirmed'), 'permit lacks authorized decision');
      check(policy && generation === call.attempt.generation && !panic && panicEpoch === event.panic_epoch &&
        event.global_panic_epoch >= globalEpoch, 'stale admission');
      globalEpoch = event.global_panic_epoch;
      policy.verifyAt(new Date(entry.timestamp));
      check(same(callBinding(event), callBinding(call.attempt)), 'permit attempt binding mismatch');
      check(same(event.receipt_ids, call.decision.receipts.map(r => r.receipt_id)) &&
        same(event.receipt_hashes, call.decision.receipt_hashes), 'permit receipt binding mismatch');
      call.permit = true;
    } else if (event.type === 'terminal') {
      check(call.permit, 'terminal without permit'); call.outcome = event.outcome;
    }
  }
  return { complete: false, streamId: trust.expectedStreamId, entryCount: lines.length, headHash: head,
    calls: [...calls].map(([callId, state]) => ({ callId, outcome: state.outcome })), lastTimestamp };
}

/** Forensics only: even a valid fully-terminal prefix is not a closed run. */
export function inspectInvocationJournal(jsonl: string, trust: InvocationTrust): InvocationVerification {
  const { lastTimestamp: _last, ...result } = replay(jsonl, trust);
  return result;
}

export function verifyInvocationJournal(jsonl: string, checkpointJson: string, trust: InvocationTrust): InvocationVerification {
  const result = replay(jsonl, trust);
  const checkpoint = closedObject(snapshotJson(checkpointJson, { maxBytes: 16_384 }),
    ['kind', 'format_version', 'stream_id', 'entry_count', 'head_hash', 'closed', 'timestamp', 'signature']);
  timestampField(checkpoint.timestamp); natural(checkpoint.entry_count);
  check(checkpoint.kind === 'hush.invocation.checkpoint' && checkpoint.format_version === '0.1.0' &&
    checkpoint.closed === true && checkpoint.stream_id === trust.expectedStreamId &&
    checkpoint.entry_count === result.entryCount && checkpoint.head_hash === result.headHash &&
    checkpoint.timestamp >= result.lastTimestamp, 'checkpoint coverage mismatch');
  const { signature, ...body } = checkpoint;
  const verified = verifyContentHash(signature, hashJson(body), { publicKeyPem: trust.runtimePublicKeyPem, now: checkpoint.timestamp });
  check(verified.ok && verified.signedAt === checkpoint.timestamp, 'checkpoint signature refused');
  if (trust.expectedHeadHash !== undefined) check(trust.expectedHeadHash === result.headHash, 'expected head mismatch');
  check(result.calls.every(call => call.outcome !== 'unknown'), 'incomplete invocation run');
  const { lastTimestamp: _last, ...publicResult } = result;
  return { ...publicResult, complete: true };
}
