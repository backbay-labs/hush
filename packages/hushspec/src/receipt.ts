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
 * Parse a receipt, rejecting unknown top-level fields and any version other
 * than the one this module implements (receipt spec 3.1).
 *
 * Structural validation beyond that is the schema's job; this is the
 * fail-closed gate a consumer needs before it treats a document as a 0.2
 * receipt.
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
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ReceiptError('receipt must be a JSON object');
  }
  for (const key of Object.keys(value)) {
    if (!RECEIPT_KEYS.has(key)) {
      throw new ReceiptError(`unknown receipt field ${JSON.stringify(key)}`);
    }
  }
  const receipt = value as DecisionReceipt;
  if (receipt.receipt_version !== RECEIPT_VERSION) {
    throw new ReceiptError(
      `unsupported receipt_version ${JSON.stringify(receipt.receipt_version)}, ` +
        `expected ${JSON.stringify(RECEIPT_VERSION)}`,
    );
  }
  return receipt;
}

// --------------------------------------------------------------------------
// Identity and time
// --------------------------------------------------------------------------

/** Format an instant the way receipts and envelopes spell it. */
export function formatTimestamp(instant: Date | number = new Date()): string {
  const date = typeof instant === 'number' ? new Date(instant) : instant;
  return date.toISOString();
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
