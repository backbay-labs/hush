import { createHash, randomBytes } from 'node:crypto';
import type { HushSpec } from './schema.js';
import type {
  Decision,
  EvaluationAction,
  PostureResult,
  RuleEvaluation,
  RuleOutcome,
} from './evaluate.js';
import { UNKNOWN_ACTION_TYPE_RULE } from './evaluate.js';
import type { Condition, RuntimeContext } from './conditions.js';
import type { DetectorEvaluation, TracedEvaluationWithDetection } from './detection.js';
import { compiledFor, compiledForResolution } from './compiled.js';
import type { ChainLink, Resolution, SignatureStatus } from './resolve.js';
import { createBuiltinLoader, resolve as resolveSpec } from './resolve.js';
import { canonicalizeValue, contentHash, type JsonValue } from './canonical.js';
import { utf8ByteLength } from './utf8.js';

/**
 * Decision receipts, format 0.2 (spec/hushspec-receipt.md).
 *
 * A receipt is the unit of evidence: which resolved policy was in force (by
 * canonical content hash), who acted, what was attempted (never the content
 * itself), what the policy decided and why, which rule blocks and detectors
 * actually ran, and what the enforcement point did with the decision.
 *
 * Receipts are built from a {@link Resolution} so that policy identity,
 * `extends_chain`, and signature status come from the load step and cost
 * nothing per evaluation. The rule trace is the evaluator's own recording
 * ({@link evaluateWithDetectionTraced}); nothing here is reconstructed from
 * the decision afterwards.
 */

/** The rule trace is recorded by the evaluator, in evaluation order. */
export type { RuleEvaluation, RuleOutcome } from './evaluate.js';
export type { DetectorEvaluation, DetectorLevel } from './detection.js';
export type { SignatureStatus } from './resolve.js';

/** The receipt format this module writes and accepts. */
export const RECEIPT_VERSION = '0.2';

/** The `rule_block` id a receipt uses for the unknown-action-type stage. */
export const UNKNOWN_ACTION_TYPE_BLOCK = 'unknown_action_type';

/** The `rule_block` id a receipt uses for the origins stage. */
export const ORIGIN_PROFILE_BLOCK = 'origin_profile';

/**
 * `matched_rule` of a receipt for an action refused because the policy did
 * not verify (receipt spec 4.5).
 */
export const POLICY_UNVERIFIED_RULE = '__hushspec_policy_unverified__';

// --------------------------------------------------------------------------
// Wire types
// --------------------------------------------------------------------------

/** How much to trust `timestamp` (receipt spec 3.3). */
export type TimeSource = 'system' | 'monotonic_adjusted' | 'trusted' | 'unknown';

/** Who the action was evaluated for (receipt spec 4.1). */
export interface Actor {
  agent_id?: string;
  session_id?: string;
  principal?: string;
  runtime?: string;
}

/** True when no field is set (such an actor is omitted from receipts). */
export function actorIsEmpty(actor: Actor): boolean {
  return (
    actor.agent_id === undefined &&
    actor.session_id === undefined &&
    actor.principal === undefined &&
    actor.runtime === undefined
  );
}

/**
 * One link of `policy.extends_chain` (receipt spec 4.2): a document's source
 * and its own content hash. The load-time signature outcome stays on
 * {@link ChainLink}; a receipt records only the leaf's, under
 * `policy.signature`.
 */
export interface ReceiptChainLink {
  source: string;
  content_hash: string;
}

/** Identity of the resolved policy (receipt spec 4.2). */
export interface PolicySummary {
  name?: string;
  /** `metadata.policy_version`, when present. An integer, never a string. */
  version?: number;
  /** The policy's `hushspec` field. */
  spec_version: string;
  /** Canonical content hash of the resolved policy (`sha256:` + hex). */
  content_hash: string;
  extends_chain?: ReceiptChainLink[];
  signature?: SignatureStatus;
}

/** The evaluated action, minus its content (receipt spec 4.4). */
export interface ActionSummary {
  type: string;
  target?: string;
  /** `sha256:` over the UTF-8 bytes of the content, when content was supplied. */
  content_hash?: string;
  /** Size of the content in UTF-8 bytes. */
  content_size?: number;
  args_size?: number;
  /** The origin descriptor as supplied; see {@link compactObject}. */
  origin?: JsonValue;
  /** The runtime context as supplied; see {@link compactObject}. */
  context?: JsonValue;
}

/** One rule block's or engine stage's contribution (receipt spec 4.3). */
export interface RuleTraceEntry {
  rule_block: string;
  rule_path?: string;
  outcome: RuleOutcome;
  evaluated: boolean;
  reason?: string;
}

export type EnforcementMode = 'enforce' | 'monitor';

export type EnforcementOutcome = 'allowed' | 'confirmed' | 'blocked' | 'would_block';

/** What the enforcement point did with the decision (receipt spec 4.7). */
export interface EnforcementSummary {
  mode: EnforcementMode;
  outcome: EnforcementOutcome;
}

/** A decision receipt, format 0.2. */
export interface DecisionReceipt {
  receipt_version: string;
  /** UUID v7, lowercase hyphenated. */
  receipt_id: string;
  /** RFC 3339 UTC, exactly millisecond precision, `Z` suffix. */
  timestamp: string;
  time_source: TimeSource;
  actor?: Actor;
  policy: PolicySummary;
  action: ActionSummary;
  decision: Decision;
  matched_rule?: string;
  reason?: string;
  rule_trace: RuleTraceEntry[];
  /** Present when the detection pipeline ran, even if empty. */
  detection_trace?: DetectorEvaluation[];
  enforcement: EnforcementSummary;
  origin_profile?: string;
  posture?: PostureResult;
  duration_us?: number;
}

/** A receipt could not be read (wrong version, unknown field, bad JSON). */
export class ReceiptError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReceiptError';
  }
}

// --------------------------------------------------------------------------
// Canonical form, hash, parsing
// --------------------------------------------------------------------------

/**
 * The receipt's canonical form: RFC 8785 over the receipt object, with no
 * projection step (receipt spec 6). Absent members are absent; there are no
 * schema defaults to materialize.
 */
export function canonicalJson(receipt: DecisionReceipt): string {
  return canonicalizeValue(receipt as unknown as JsonValue);
}

/**
 * `sha256:` over the canonical form (receipt spec 6): the value a log links
 * and a receipt signature covers.
 *
 * Because the hash covers every field, a receipt MUST NOT be mutated after
 * its hash is computed -- `duration_us` included.
 */
export function receiptHash(receipt: DecisionReceipt): string {
  return `sha256:${createHash('sha256').update(canonicalJson(receipt), 'utf8').digest('hex')}`;
}

const RECEIPT_KEYS: ReadonlySet<string> = new Set([
  'receipt_version',
  'receipt_id',
  'timestamp',
  'time_source',
  'actor',
  'policy',
  'action',
  'decision',
  'matched_rule',
  'reason',
  'rule_trace',
  'detection_trace',
  'enforcement',
  'origin_profile',
  'posture',
  'duration_us',
]);

/**
 * Parse a receipt, rejecting unknown fields, any version other than the one
 * this module implements, and any document that is not shaped like a 0.2
 * receipt (receipt spec 3.1).
 *
 * @throws {ReceiptError}
 */
export function parseReceipt(json: string | unknown): DecisionReceipt {
  let value: unknown;
  if (typeof json === 'string') {
    try {
      value = JSON.parse(json) as unknown;
    } catch (error) {
      throw new ReceiptError(
        `receipt is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  } else {
    value = json;
  }
  const object = requireObject(value, 'receipt', RECEIPT_KEYS);
  if (object.receipt_version !== RECEIPT_VERSION) {
    throw new ReceiptError(
      `unsupported receipt_version ${JSON.stringify(object.receipt_version)}, ` +
        `expected ${JSON.stringify(RECEIPT_VERSION)}`,
    );
  }
  validateReceiptShape(object);
  return object as unknown as DecisionReceipt;
}

// --------------------------------------------------------------------------
// Structural validation (receipt spec 2, item 4)
// --------------------------------------------------------------------------

/**
 * A TypeScript interface says nothing at runtime, so the parser checks what
 * the 0.2 schema states and a typed model would otherwise enforce: required
 * members, member types, closed enums, and no unknown member at any level.
 * Without them a consumer -- a log verifier above all -- would count an
 * arbitrary JSON object as evidence.
 */

type JsonObject = Record<string, unknown>;

const ACTOR_KEYS: ReadonlySet<string> = new Set([
  'agent_id',
  'session_id',
  'principal',
  'runtime',
]);

const POLICY_KEYS: ReadonlySet<string> = new Set([
  'name',
  'version',
  'spec_version',
  'content_hash',
  'extends_chain',
  'signature',
]);

const CHAIN_LINK_KEYS: ReadonlySet<string> = new Set(['source', 'content_hash']);

const SIGNATURE_STATUS_KEYS: ReadonlySet<string> = new Set([
  'verified',
  'key_id',
  'verified_at',
  'reason',
]);

const ACTION_KEYS: ReadonlySet<string> = new Set([
  'type',
  'target',
  'content_hash',
  'content_size',
  'args_size',
  'origin',
  'context',
]);

const RULE_TRACE_KEYS: ReadonlySet<string> = new Set([
  'rule_block',
  'rule_path',
  'outcome',
  'evaluated',
  'reason',
]);

const DETECTION_TRACE_KEYS: ReadonlySet<string> = new Set([
  'detector_id',
  'category',
  'score',
  'level',
  'matched',
]);

const ENFORCEMENT_KEYS: ReadonlySet<string> = new Set(['mode', 'outcome']);

const POSTURE_KEYS: ReadonlySet<string> = new Set(['current', 'next']);

const TIME_SOURCES: ReadonlySet<string> = new Set([
  'system',
  'monotonic_adjusted',
  'trusted',
  'unknown',
]);

const DECISIONS: ReadonlySet<string> = new Set(['allow', 'warn', 'deny']);

const RULE_OUTCOMES: ReadonlySet<string> = new Set(['allow', 'warn', 'deny', 'skip']);

const ENFORCEMENT_MODES: ReadonlySet<string> = new Set(['enforce', 'monitor']);

const ENFORCEMENT_OUTCOMES: ReadonlySet<string> = new Set([
  'allowed',
  'confirmed',
  'blocked',
  'would_block',
]);

const DETECTION_CATEGORIES: ReadonlySet<string> = new Set([
  'prompt_injection',
  'jailbreak',
  'data_exfiltration',
  'threat_intel',
]);

const DETECTOR_LEVELS: ReadonlySet<string> = new Set([
  'none',
  'low',
  'suspicious',
  'high',
  'critical',
]);

/** `$.timestamp`: RFC 3339 UTC with exactly three fractional digits. */
const TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;

function requireObject(
  value: unknown,
  label: string,
  allowed: ReadonlySet<string>,
): JsonObject {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ReceiptError(`${label} must be a JSON object`);
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new ReceiptError(`unknown field ${JSON.stringify(key)} in ${label}`);
    }
  }
  return value as JsonObject;
}

function requireArray(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new ReceiptError(`${label} must be an array`);
  }
  return value;
}

function requireMembers(object: JsonObject, label: string, keys: readonly string[]): void {
  for (const key of keys) {
    if (object[key] === undefined) {
      throw new ReceiptError(`${label} is missing ${JSON.stringify(key)}`);
    }
  }
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string') {
    throw new ReceiptError(`${label} must be a string`);
  }
  return value;
}

function optionalString(value: unknown, label: string): void {
  if (value !== undefined) requireString(value, label);
}

function requireBoolean(value: unknown, label: string): void {
  if (typeof value !== 'boolean') {
    throw new ReceiptError(`${label} must be a boolean`);
  }
}

function optionalSize(value: unknown, label: string): void {
  if (value === undefined) return;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new ReceiptError(`${label} must be a non-negative integer`);
  }
}

function requireEnum(value: unknown, label: string, allowed: ReadonlySet<string>): void {
  const text = requireString(value, label);
  if (!allowed.has(text)) {
    throw new ReceiptError(`${label} ${JSON.stringify(text)} is outside the closed enum`);
  }
}

function requireTimestamp(value: unknown, label: string): void {
  const text = requireString(value, label);
  if (!TIMESTAMP_PATTERN.test(text)) {
    throw new ReceiptError(
      `${label} ${JSON.stringify(text)} is not an RFC 3339 UTC instant with ` +
        'millisecond precision',
    );
  }
}

function validateReceiptShape(receipt: JsonObject): void {
  requireMembers(receipt, 'receipt', [
    'receipt_id',
    'timestamp',
    'time_source',
    'policy',
    'action',
    'decision',
    'rule_trace',
    'enforcement',
  ]);
  requireString(receipt.receipt_id, 'receipt_id');
  requireTimestamp(receipt.timestamp, 'timestamp');
  requireEnum(receipt.time_source, 'time_source', TIME_SOURCES);
  requireEnum(receipt.decision, 'decision', DECISIONS);
  optionalString(receipt.matched_rule, 'matched_rule');
  optionalString(receipt.reason, 'reason');
  optionalString(receipt.origin_profile, 'origin_profile');
  optionalSize(receipt.duration_us, 'duration_us');

  if (receipt.actor !== undefined) {
    const actor = requireObject(receipt.actor, 'actor', ACTOR_KEYS);
    for (const key of ACTOR_KEYS) optionalString(actor[key], `actor.${key}`);
  }

  validatePolicy(requireObject(receipt.policy, 'policy', POLICY_KEYS));
  validateAction(requireObject(receipt.action, 'action', ACTION_KEYS));
  validateRuleTrace(requireArray(receipt.rule_trace, 'rule_trace'));
  if (receipt.detection_trace !== undefined) {
    validateDetectionTrace(requireArray(receipt.detection_trace, 'detection_trace'));
  }

  const enforcement = requireObject(receipt.enforcement, 'enforcement', ENFORCEMENT_KEYS);
  requireMembers(enforcement, 'enforcement', ['mode', 'outcome']);
  requireEnum(enforcement.mode, 'enforcement.mode', ENFORCEMENT_MODES);
  requireEnum(enforcement.outcome, 'enforcement.outcome', ENFORCEMENT_OUTCOMES);

  if (receipt.posture !== undefined) {
    const posture = requireObject(receipt.posture, 'posture', POSTURE_KEYS);
    requireMembers(posture, 'posture', ['current', 'next']);
    requireString(posture.current, 'posture.current');
    requireString(posture.next, 'posture.next');
  }
}

function validatePolicy(policy: JsonObject): void {
  requireMembers(policy, 'policy', ['spec_version', 'content_hash']);
  requireString(policy.spec_version, 'policy.spec_version');
  requireString(policy.content_hash, 'policy.content_hash');
  optionalString(policy.name, 'policy.name');
  optionalSize(policy.version, 'policy.version');

  if (policy.extends_chain !== undefined) {
    requireArray(policy.extends_chain, 'policy.extends_chain').forEach((raw, index) => {
      const label = `policy.extends_chain[${index}]`;
      const link = requireObject(raw, label, CHAIN_LINK_KEYS);
      requireMembers(link, label, ['source', 'content_hash']);
      requireString(link.source, `${label}.source`);
      requireString(link.content_hash, `${label}.content_hash`);
    });
  }

  if (policy.signature !== undefined) {
    const status = requireObject(policy.signature, 'policy.signature', SIGNATURE_STATUS_KEYS);
    requireMembers(status, 'policy.signature', ['verified']);
    requireBoolean(status.verified, 'policy.signature.verified');
    optionalString(status.key_id, 'policy.signature.key_id');
    optionalString(status.reason, 'policy.signature.reason');
    if (status.verified_at !== undefined) {
      requireTimestamp(status.verified_at, 'policy.signature.verified_at');
    }
  }
}

function validateAction(action: JsonObject): void {
  requireMembers(action, 'action', ['type']);
  requireString(action.type, 'action.type');
  optionalString(action.target, 'action.target');
  optionalString(action.content_hash, 'action.content_hash');
  optionalSize(action.content_size, 'action.content_size');
  optionalSize(action.args_size, 'action.args_size');
  // `origin` and `context` are the descriptors the caller supplied, carried
  // verbatim (receipt spec 4.4); any JSON value is in range.
}

function validateRuleTrace(entries: readonly unknown[]): void {
  entries.forEach((raw, index) => {
    const label = `rule_trace[${index}]`;
    const entry = requireObject(raw, label, RULE_TRACE_KEYS);
    requireMembers(entry, label, ['rule_block', 'outcome', 'evaluated']);
    requireString(entry.rule_block, `${label}.rule_block`);
    optionalString(entry.rule_path, `${label}.rule_path`);
    requireEnum(entry.outcome, `${label}.outcome`, RULE_OUTCOMES);
    requireBoolean(entry.evaluated, `${label}.evaluated`);
    optionalString(entry.reason, `${label}.reason`);
  });
}

function validateDetectionTrace(entries: readonly unknown[]): void {
  entries.forEach((raw, index) => {
    const label = `detection_trace[${index}]`;
    const entry = requireObject(raw, label, DETECTION_TRACE_KEYS);
    requireMembers(entry, label, ['detector_id', 'category', 'score', 'level', 'matched']);
    requireString(entry.detector_id, `${label}.detector_id`);
    requireEnum(entry.category, `${label}.category`, DETECTION_CATEGORIES);
    const score = entry.score;
    if (typeof score !== 'number' || !Number.isFinite(score) || score < 0 || score > 1) {
      throw new ReceiptError(`${label}.score must be a number in [0, 1]`);
    }
    requireEnum(entry.level, `${label}.level`, DETECTOR_LEVELS);
    requireBoolean(entry.matched, `${label}.matched`);
  });
}

// --------------------------------------------------------------------------
// Identity and time
// --------------------------------------------------------------------------

/** Format an instant the way receipts and envelopes spell it. */
export function formatTimestamp(instant: Date | number = new Date()): string {
  const date = typeof instant === 'number' ? new Date(instant) : instant;
  return date.toISOString();
}

/** `YYYY-MM-DDTHH:MM:SS.sssZ`, the one instant form these formats accept. */
const MILLISECOND_TIMESTAMP =
  /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;

/**
 * Whether `value` is an RFC 3339 UTC instant with millisecond precision and a
 * `Z` suffix -- the one form receipts, signature envelopes, keyrings and
 * bundles spell an instant in.
 *
 * The shape check alone is not enough: `Date.parse` accepts and normalizes
 * impossible calendar dates, so `2026-02-30T00:00:00.000Z` would pass as
 * March 2 and go on to take part in expiry and retirement comparisons. Rust,
 * Python and Go all reject it, so the round-trip through `toISOString` makes
 * the calendar date part of the check here too.
 */
export function isMillisecondTimestamp(value: string): boolean {
  if (!MILLISECOND_TIMESTAMP.test(value)) return false;
  const date = new Date(value);
  return !Number.isNaN(date.getTime()) && date.toISOString() === value;
}

function uuidFromBytes(bytes: Uint8Array): string {
  const hex = Buffer.from(bytes).toString('hex');
  return (
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-` +
    `${hex.slice(16, 20)}-${hex.slice(20, 32)}`
  );
}

/** A fresh UUID version 7 (receipt spec 3.2): 48-bit time, random tail. */
export function uuidV7(unixMillis: number = Date.now()): string {
  const bytes = randomBytes(16);
  const ms = BigInt(Math.trunc(unixMillis)) & 0x0000_ffff_ffff_ffffn;
  for (let index = 0; index < 6; index += 1) {
    bytes[index] = Number((ms >> BigInt(8 * (5 - index))) & 0xffn);
  }
  bytes[6] = 0x70 | (bytes[6]! & 0x0f);
  bytes[8] = 0x80 | (bytes[8]! & 0x3f);
  return uuidFromBytes(bytes);
}

/**
 * A UUID v7 whose random bits come from `seed` instead of an RNG, so a
 * conformance vector can name the receipt id it expects.
 *
 * `rand_a` (12 bits) is `seed & 0xfff`; `rand_b` (62 bits) is `seed >> 12`.
 * The derivation is identical in every SDK, so the expected receipts under
 * `fixtures/receipts/expected/` reproduce byte for byte.
 */
export function deterministicUuidV7(unixMillis: number, seed: number | bigint): string {
  const bytes = new Uint8Array(16);
  const ms = BigInt(Math.trunc(unixMillis)) & 0x0000_ffff_ffff_ffffn;
  for (let index = 0; index < 6; index += 1) {
    bytes[index] = Number((ms >> BigInt(8 * (5 - index))) & 0xffn);
  }
  const seedBits = BigInt(seed) & 0xffff_ffff_ffff_ffffn;
  const randA = seedBits & 0x0fffn;
  bytes[6] = 0x70 | Number(randA >> 8n);
  bytes[7] = Number(randA & 0xffn);
  const randB = (seedBits >> 12n) & 0x3fff_ffff_ffff_ffffn;
  // The 62-bit `rand_b`, big-endian across bytes 8..15, with the top two bits
  // replaced by the variant marker `10`.
  for (let index = 0; index < 8; index += 1) {
    bytes[8 + index] = Number((randB >> BigInt(8 * (7 - index))) & 0xffn);
  }
  bytes[8] = 0x80 | (bytes[8]! & 0x3f);
  return uuidFromBytes(bytes);
}

// --------------------------------------------------------------------------
// Building receipts
// --------------------------------------------------------------------------

/**
 * What to record. `enabled: false` skips timing and the trace (the decision
 * and policy identity are always correct; identity costs nothing because it
 * comes from the {@link Resolution}).
 */
export interface AuditConfig {
  enabled: boolean;
  includeRuleTrace: boolean;
  /**
   * Record `duration_us`. Off for conformance vectors, whose bytes must not
   * depend on the machine that produced them.
   */
  recordDuration: boolean;
}

export const DEFAULT_AUDIT_CONFIG: AuditConfig = {
  enabled: true,
  includeRuleTrace: true,
  recordDuration: true,
};

/**
 * Everything about the evaluation that is not the policy or the action: who
 * is acting, what the enforcement point does, and the clock.
 *
 * `clock` and `receiptId` exist so tests and conformance vectors can be
 * deterministic; production callers leave them unset.
 */
export interface AuditContext {
  actor?: Actor;
  /**
   * The enforcement point's disposition. Unset records the disposition
   * implied by the decision under {@link AuditContext.enforcementMode}.
   */
  enforcement?: EnforcementSummary;
  enforcementMode?: EnforcementMode;
  timeSource?: TimeSource;
  /** Fixed evaluation time (defaults to now). */
  clock?: Date;
  /** Fixed receipt id (defaults to a fresh UUID v7). */
  receiptId?: string;
  /** Explicit runtime context; replaces `action.context` during evaluation. */
  context?: RuntimeContext;
  /** Out-of-band conditions keyed by rule-block name. */
  conditions?: Record<string, Condition>;
}

/**
 * The disposition implied by a decision when there is no enforcement point to
 * say otherwise: an allow proceeds; a warn with no confirmation channel is a
 * deny (core spec 6); under monitor mode a warn or deny proceeds and is
 * recorded as `would_block`.
 */
export function impliedEnforcement(
  decision: Decision,
  mode: EnforcementMode = 'enforce',
): EnforcementSummary {
  if (decision === 'allow') return { mode, outcome: 'allowed' };
  return { mode, outcome: mode === 'monitor' ? 'would_block' : 'blocked' };
}

/**
 * Serialize a supplied descriptor "verbatim" (receipt spec 4.4) in the one
 * form every SDK can reproduce: its JSON object with top-level members that
 * are absent, `null`, `{}`, or `[]` removed. Typed models differ in which
 * empty members they materialize; the document the caller supplied did not
 * have them.
 */
export function compactObject(value: unknown): JsonValue | undefined {
  if (value === null || value === undefined) return undefined;
  if (typeof value !== 'object' || Array.isArray(value)) {
    return value as JsonValue;
  }
  const out: Record<string, JsonValue> = {};
  for (const [key, member] of Object.entries(value as Record<string, unknown>)) {
    if (member === null || member === undefined) continue;
    if (typeof member === 'object') {
      if (Array.isArray(member)) {
        if (member.length === 0) continue;
      } else if (Object.keys(member as object).length === 0) {
        continue;
      }
    }
    out[key] = member as JsonValue;
  }
  return out;
}

/** The policy identity a receipt carries, taken from the resolution. */
export function policySummary(resolution: Resolution): PolicySummary {
  const spec = resolution.spec;
  const version = spec.metadata?.policy_version;
  const summary: PolicySummary = {
    ...(spec.name === undefined ? {} : { name: spec.name }),
    ...(version === undefined ? {} : { version }),
    spec_version: spec.hushspec,
    content_hash: resolution.content_hash,
  };
  if (resolution.chain.length > 1) {
    summary.extends_chain = resolution.chain.map((link: ChainLink) => ({
      source: link.source,
      content_hash: link.content_hash,
    }));
  }
  if (resolution.signature !== undefined) {
    summary.signature = resolution.signature;
  }
  return summary;
}

function actionSummary(action: EvaluationAction): ActionSummary {
  const summary: ActionSummary = { type: action.type };
  if (action.target !== undefined) summary.target = action.target;
  if (action.content !== undefined) {
    summary.content_hash = `sha256:${createHash('sha256')
      .update(action.content, 'utf8')
      .digest('hex')}`;
    summary.content_size = utf8ByteLength(action.content);
  }
  if (action.args_size !== undefined) summary.args_size = action.args_size;
  const origin = compactObject(action.origin);
  if (origin !== undefined) summary.origin = origin;
  const context = compactObject(action.context);
  if (context !== undefined) summary.context = context;
  return summary;
}

/**
 * Convert the evaluator's recorded trace to receipt entries and add the
 * origins stage when a profile was selected (receipt spec 4.3, item 5).
 *
 * The evaluator records the unknown-action stage under `default` with the
 * reserved `__unknown_action_type__` rule, and the origins guard under
 * `origins`; receipts use the closed ids `unknown_action_type` and
 * `origin_profile` for those stages.
 *
 * The selected profile is a recorded fact of the same evaluation (the
 * evaluator returns it alongside the decision); it is placed first because
 * the origins guard runs before the posture guard and every rule block.
 */
function buildTrace(trace: readonly RuleEvaluation[], originProfile?: string): RuleTraceEntry[] {
  const entries: RuleTraceEntry[] = trace.map((entry) => {
    const block =
      entry.rule_block === 'default' && entry.matched_rule === UNKNOWN_ACTION_TYPE_RULE
        ? UNKNOWN_ACTION_TYPE_BLOCK
        : entry.rule_block === 'origins'
          ? ORIGIN_PROFILE_BLOCK
          : entry.rule_block;
    return {
      rule_block: block,
      ...(entry.matched_rule === undefined ? {} : { rule_path: entry.matched_rule }),
      outcome: entry.outcome,
      evaluated: entry.evaluated,
      ...(entry.reason === undefined ? {} : { reason: entry.reason }),
    };
  });
  if (
    originProfile !== undefined &&
    !entries.some((entry) => entry.rule_block === ORIGIN_PROFILE_BLOCK)
  ) {
    entries.unshift({
      rule_block: ORIGIN_PROFILE_BLOCK,
      rule_path: `extensions.origins.profiles.${originProfile}`,
      outcome: 'allow',
      evaluated: true,
      reason: 'origin profile selected',
    });
  }
  return entries;
}

/**
 * Evaluate `action` against a resolved policy and record the receipt.
 *
 * Routes through the detection pipeline when the policy has a `detection:`
 * extension, so the receipt's decision is the one an enforcement point acts
 * on and `detection_trace` is present whenever detection ran.
 */
export function evaluateAudited(
  resolution: Resolution,
  action: EvaluationAction,
  config: AuditConfig = DEFAULT_AUDIT_CONFIG,
  ctx: AuditContext = {},
): DecisionReceipt {
  return compiledForResolution(resolution).evaluateAudited(action, config, ctx);
}

/**
 * The receipt for an evaluation that has already run.
 *
 * Split out of {@link evaluateAudited} so a {@link CompiledPolicy} -- which
 * owns the evaluation and its timing -- records the same receipt without
 * re-entering the engine through the document. Not part of the public API.
 *
 * @internal
 */
export function receiptFromEvaluation(
  resolution: Resolution,
  action: EvaluationAction,
  detected: TracedEvaluationWithDetection,
  durationUs: number | undefined,
  config: AuditConfig,
  ctx: AuditContext,
): DecisionReceipt {
  const result = detected.evaluation;

  const ruleTrace =
    config.enabled && config.includeRuleTrace
      ? buildTrace(detected.traced.trace, result.origin_profile)
      : [];

  const actor = ctx.actor !== undefined && !actorIsEmpty(ctx.actor) ? ctx.actor : undefined;
  const enforcement =
    ctx.enforcement ?? impliedEnforcement(result.decision, ctx.enforcementMode ?? 'enforce');

  return {
    receipt_version: RECEIPT_VERSION,
    receipt_id: ctx.receiptId ?? uuidV7(ctx.clock?.getTime()),
    timestamp: formatTimestamp(ctx.clock ?? new Date()),
    time_source: ctx.timeSource ?? 'system',
    ...(actor === undefined ? {} : { actor }),
    policy: policySummary(resolution),
    action: actionSummary(action),
    decision: result.decision,
    ...(result.matched_rule === undefined ? {} : { matched_rule: result.matched_rule }),
    ...(result.reason === undefined ? {} : { reason: result.reason }),
    rule_trace: ruleTrace,
    ...(detected.detectorTrace === undefined ? {} : { detection_trace: detected.detectorTrace }),
    enforcement,
    ...(result.origin_profile === undefined ? {} : { origin_profile: result.origin_profile }),
    ...(result.posture === undefined ? {} : { posture: result.posture }),
    ...(durationUs === undefined ? {} : { duration_us: durationUs }),
  };
}

/**
 * {@link evaluateAudited} for a document that is already resolved and has no
 * provenance to record: the receipt names the document's own content hash and
 * a single-link chain. Hold a {@link Resolution} instead when the policy was
 * loaded from somewhere and the chain matters.
 *
 * @throws {CanonicalError} when the document still declares `extends` or
 * otherwise has no canonical form.
 */
export function evaluateAuditedSpec(
  spec: HushSpec,
  action: EvaluationAction,
  config: AuditConfig = DEFAULT_AUDIT_CONFIG,
  ctx: AuditContext = {},
): DecisionReceipt {
  return compiledFor(spec).evaluateAudited(action, config, ctx);
}

/**
 * The receipt an enforcement point that requires signatures emits when the
 * policy did not verify (signing spec 6.5): a deny with an empty trace,
 * `policy.signature.verified: false`, and the reason the verifier gave.
 */
export function unverifiedPolicyReceipt(
  policy: PolicySummary,
  action: EvaluationAction,
  ctx: AuditContext = {},
): DecisionReceipt {
  const reason = policy.signature?.reason ?? 'unverified';
  const actor = ctx.actor !== undefined && !actorIsEmpty(ctx.actor) ? ctx.actor : undefined;
  return {
    receipt_version: RECEIPT_VERSION,
    receipt_id: ctx.receiptId ?? uuidV7(ctx.clock?.getTime()),
    timestamp: formatTimestamp(ctx.clock ?? new Date()),
    time_source: ctx.timeSource ?? 'system',
    ...(actor === undefined ? {} : { actor }),
    policy,
    action: actionSummary(action),
    decision: 'deny',
    matched_rule: POLICY_UNVERIFIED_RULE,
    reason: `policy signature did not verify: ${reason}`,
    rule_trace: [],
    enforcement: ctx.enforcement ?? impliedEnforcement('deny', ctx.enforcementMode ?? 'enforce'),
  };
}

/**
 * The canonical content hash of the *resolved* policy (Canonical Form
 * specification section 5): `sha256:` followed by 64 lowercase hex digits.
 *
 * Hashing an unresolved leaf would identify a document that is not what was
 * enforced (every block inherited from the base would be missing), so an
 * `extends` still present here is resolved against the embedded builtins
 * first and, if that is impossible, rejected rather than hashed. Guards
 * resolve on load, so this is a backstop for direct callers.
 *
 * Since format 0.2 this is the same value every SDK produces -- the 0.1
 * per-SDK `JSON.stringify` digest is gone.
 */
export function computePolicyHash(spec: HushSpec): string {
  let resolved = spec;
  if (spec.extends != null) {
    const result = resolveSpec(spec, { loader: createBuiltinLoader() });
    if (!result.ok) {
      throw new Error(
        `cannot hash an unresolved policy (extends: ${spec.extends}): ${result.error}`,
      );
    }
    resolved = result.value;
  }
  return contentHash(resolved);
}
