import type { JsonValue } from '../canonical.js';
import type { EvaluationAction, Decision } from '../evaluate.js';
import type { RuntimeContext } from '../conditions.js';
import type { HushSpec } from '../schema.js';
import { parseReceipt, type DecisionReceipt } from '../receipt.js';
import { parseEnvelope, type Envelope } from '../signing.js';
import { jsonObject } from './json.js';
import type { InvocationEngineIdentity } from './policy.js';

export interface InvocationCallBinding {
  call_id: string;
  generation: number;
  policy_hash: string;
  target: string;
  arguments_hash: string;
  effects_hash: string;
  panic_epoch: number;
  global_panic_epoch: number;
}
export interface InvocationAttempt extends InvocationCallBinding {
  type: 'attempt';
  arguments: Record<string, JsonValue>;
  actions: EvaluationAction[];
  context: RuntimeContext;
}
export type ConfirmationDisposition = 'not_required' | 'confirmed' | 'refused' | 'error' | 'timeout';
export interface InvocationDecision {
  type: 'decision'; call_id: string; aggregate: Decision; confirmation: ConfirmationDisposition;
  receipts: DecisionReceipt[]; receipt_hashes: string[];
}
export type TerminalDisposition = 'completed' | 'error' | 'aborted_before_dispatch';
export type InvocationEvent =
  | { type: 'policy'; generation: number; status: 'accepted'; policy: HushSpec; envelope: Envelope; engine: InvocationEngineIdentity }
  | { type: 'policy'; generation: number; status: 'refused'; reason: string }
  | { type: 'panic'; epoch: number; active: boolean }
  | { type: 'rejected'; call_id: string; reason: string }
  | InvocationAttempt
  | InvocationDecision
  | (InvocationCallBinding & { type: 'permit'; receipt_ids: string[]; receipt_hashes: string[] })
  | { type: 'blocked'; call_id: string; reason: string }
  | { type: 'terminal'; call_id: string; outcome: TerminalDisposition; reason?: string };

export interface InvocationEntryBody {
  kind: 'hush.invocation.entry'; format_version: '0.1.0'; stream_id: string;
  sequence: number; previous_hash: string | null; timestamp: string; event: InvocationEvent;
}
export interface InvocationEntry extends InvocationEntryBody { entry_hash: string; signature: Envelope }
export interface InvocationCheckpoint {
  kind: 'hush.invocation.checkpoint'; format_version: '0.1.0'; stream_id: string;
  entry_count: number; head_hash: string | null; closed: true; timestamp: string; signature: Envelope;
}

export function closedObject(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, JsonValue> {
  const object = jsonObject(value);
  if (required.some(key => !Object.hasOwn(object, key)) ||
      Object.keys(object).some(key => !required.includes(key) && !optional.includes(key))) {
    throw new Error('invalid or unknown journal fields');
  }
  return object;
}
export function natural(value: unknown): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new Error('invalid journal integer');
}
export function textField(value: unknown, maxBytes = 1024): asserts value is string {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > maxBytes) throw new Error('invalid journal string');
}
export function hashField(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(value)) throw new Error('invalid journal hash');
}
export function idField(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-7[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value)) {
    throw new Error('invalid journal UUID v7');
  }
}
export function timestampField(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) throw new Error('invalid timestamp');
}
export function arrayField(value: unknown, min = 1, max = 17): asserts value is unknown[] {
  if (!Array.isArray(value) || value.length < min || value.length > max) throw new Error('invalid journal array');
}
const BINDING_FIELDS = ['call_id', 'generation', 'policy_hash', 'target', 'arguments_hash', 'effects_hash', 'panic_epoch', 'global_panic_epoch'];
export function callBinding(attempt: InvocationCallBinding): InvocationCallBinding {
  return { call_id: attempt.call_id, generation: attempt.generation, policy_hash: attempt.policy_hash,
    target: attempt.target, arguments_hash: attempt.arguments_hash, effects_hash: attempt.effects_hash,
    panic_epoch: attempt.panic_epoch, global_panic_epoch: attempt.global_panic_epoch };
}
function checkBinding(value: Record<string, JsonValue>): void {
  idField(value.call_id); natural(value.generation); textField(value.target, 512);
  if (value.generation === 0) throw new Error('invalid policy generation');
  for (const field of ['policy_hash', 'arguments_hash', 'effects_hash']) hashField(value[field]);
  natural(value.panic_epoch); natural(value.global_panic_epoch);
}

export function assertAction(value: unknown, tool: boolean, withContext = true): asserts value is EvaluationAction {
  const a = closedObject(value, ['type', 'target', ...(withContext ? ['context'] : [])],
    ['content', ...(tool ? ['args_size'] : []), ...(!tool ? ['url'] : [])]);
  textField(a.target, 4096);
  if (tool ? a.type !== 'tool_call' : !['file_read', 'file_write', 'patch_apply', 'egress'].includes(a.type as string)) {
    throw new Error('unsupported effect type');
  }
  if (withContext) jsonObject(a.context);
  if (tool) natural(a.args_size);
  if (a.type === 'file_write' || a.type === 'patch_apply') {
    if (typeof a.content !== 'string') throw new Error('effect requires content');
  } else if (a.content !== undefined) throw new Error('unexpected effect content');
  if (a.url !== undefined && (a.type !== 'egress' || typeof a.url !== 'string' || !a.url)) {
    throw new Error('invalid effect URL');
  }
}

export function assertEvent(value: unknown): asserts value is InvocationEvent {
  const o = jsonObject(value);
  switch (o.type) {
    case 'policy':
      natural(o.generation);
      if (o.generation === 0) throw new Error('invalid generation');
      if (o.status === 'accepted') {
        closedObject(o, ['type', 'generation', 'status', 'policy', 'envelope', 'engine']);
        jsonObject(o.policy); parseEnvelope(o.envelope);
        const identity = closedObject(o.engine, ['name', 'version'], ['artifact_sha256', 'qualification_sha256']);
        textField(identity.name); textField(identity.version);
        for (const field of ['artifact_sha256', 'qualification_sha256']) if (identity[field] !== undefined) hashField(identity[field]);
      } else if (o.status === 'refused') {
        closedObject(o, ['type', 'generation', 'status', 'reason']); textField(o.reason);
      } else throw new Error('invalid policy status');
      break;
    case 'panic':
      closedObject(o, ['type', 'epoch', 'active']); natural(o.epoch);
      if (typeof o.active !== 'boolean') throw new Error('invalid panic');
      break;
    case 'rejected': case 'blocked':
      closedObject(o, ['type', 'call_id', 'reason']); idField(o.call_id); textField(o.reason); break;
    case 'attempt':
      closedObject(o, ['type', ...BINDING_FIELDS, 'arguments', 'actions', 'context']); checkBinding(o);
      jsonObject(o.arguments); jsonObject(o.context); arrayField(o.actions, 2);
      o.actions.forEach((a, i) => assertAction(a, i === 0)); break;
    case 'decision':
      closedObject(o, ['type', 'call_id', 'aggregate', 'confirmation', 'receipts', 'receipt_hashes']);
      idField(o.call_id); arrayField(o.receipts); arrayField(o.receipt_hashes);
      if (!['allow', 'warn', 'deny'].includes(o.aggregate as string) ||
          !['not_required', 'confirmed', 'refused', 'error', 'timeout'].includes(o.confirmation as string)) throw new Error('invalid decision');
      o.receipts.forEach(parseReceipt); o.receipt_hashes.forEach(hashField); break;
    case 'permit':
      closedObject(o, ['type', ...BINDING_FIELDS, 'receipt_ids', 'receipt_hashes']); checkBinding(o);
      arrayField(o.receipt_ids); arrayField(o.receipt_hashes);
      o.receipt_ids.forEach(idField); o.receipt_hashes.forEach(hashField); break;
    case 'terminal':
      closedObject(o, ['type', 'call_id', 'outcome'], ['reason']); idField(o.call_id);
      if (!['completed', 'error', 'aborted_before_dispatch'].includes(o.outcome as string)) throw new Error('invalid terminal');
      if (o.reason !== undefined) textField(o.reason); break;
    default: throw new Error('unknown invocation event');
  }
}
