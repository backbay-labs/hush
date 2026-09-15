import { createHash, randomUUID } from 'node:crypto';
import type { HushSpec } from './schema.js';
import type { PostureResult, RuleEvaluation } from './evaluate.js';
import { evaluateTraced } from './evaluate.js';
import { createBuiltinLoader, resolve as resolveSpec } from './resolve.js';
import { HUSHSPEC_VERSION } from './version.js';
import type { EvaluationAction, Decision } from './evaluate.js';

/**
 * The rule trace is produced by the evaluator itself (core spec 6.1), so a
 * receipt records exactly the blocks that ran, in evaluation order.
 */
export type { RuleEvaluation, RuleOutcome } from './evaluate.js';

export interface DecisionReceipt {
  receipt_id: string;
  timestamp: string;
  hushspec_version: string;
  action: ActionSummary;
  decision: Decision;
  matched_rule?: string;
  reason?: string;
  rule_trace: RuleEvaluation[];
  policy: PolicySummary;
  origin_profile?: string;
  posture?: PostureResult;
  enforcement?: EnforcementSummary;
  evaluation_duration_us: number;
}

export interface ActionSummary {
  type: string;
  target?: string;
  /** True when action content was present but omitted for privacy. Omitted (not `false`) when there was nothing to redact. */
  content_redacted?: boolean;
}

export interface PolicySummary {
  name?: string;
  version: string;
  /**
   * SHA-256 hex digest of the canonical JSON serialization. Omitted when
   * audit is disabled -- the zero-overhead disabled-audit fast path never
   * computes a hash, so the field is absent rather than an empty string.
   */
  content_hash?: string;
}

export type EnforcementMode = 'enforce' | 'monitor';

export type EnforcementOutcome = 'allowed' | 'confirmed' | 'blocked' | 'would_block';

/**
 * How the runtime applied a decision. `DecisionReceipt.decision` is always
 * the evaluated policy decision; this records what the enforcement point did.
 */
export interface EnforcementSummary {
  mode: EnforcementMode;
  outcome: EnforcementOutcome;
}

export interface AuditConfig {
  /** When false, skip timing, rule tracing, and policy hashing. */
  enabled: boolean;
  include_rule_trace: boolean;
  redact_content: boolean;
}

export const DEFAULT_AUDIT_CONFIG: AuditConfig = {
  enabled: true,
  include_rule_trace: true,
  redact_content: true,
};

export function evaluateAudited(
  spec: HushSpec,
  action: EvaluationAction,
  config: AuditConfig,
): DecisionReceipt {
  const startHr = config.enabled ? performance.now() : 0;
  const traced = evaluateTraced(spec, action);
  const result = traced.result;

  const durationUs = config.enabled
    ? Math.round((performance.now() - startHr) * 1000)
    : 0;

  const ruleTrace = config.enabled && config.include_rule_trace ? traced.trace : [];

  const policy: PolicySummary = config.enabled
    ? buildPolicySummary(spec)
    : {
        name: spec.name,
        version: spec.hushspec,
      };

  const contentRedacted = config.redact_content && action.content != null;
  const actionSummary: ActionSummary = {
    type: action.type,
    target: action.target,
    // `|| undefined` (rather than the boolean itself) so JSON.stringify
    // drops the key when false, matching Rust/Go's skip-if-false behavior.
    content_redacted: contentRedacted || undefined,
  };

  return {
    receipt_id: randomUUID(),
    timestamp: new Date().toISOString(),
    hushspec_version: HUSHSPEC_VERSION,
    action: actionSummary,
    decision: result.decision,
    matched_rule: result.matched_rule,
    reason: result.reason,
    rule_trace: ruleTrace,
    policy,
    origin_profile: result.origin_profile,
    posture: result.posture,
    evaluation_duration_us: durationUs,
  };
}

/**
 * Hash of the *resolved* policy -- the document evaluation actually runs
 * against.
 *
 * Hashing an unresolved leaf would make the receipt's `content_hash` identify
 * a document that is not what was enforced (every block inherited from the
 * base is missing from it), so an `extends` still present here is resolved
 * against the embedded builtins first and, if that is impossible, rejected
 * rather than hashed. Guards resolve on load, so this is a backstop for
 * direct callers.
 *
 * NOTE: this is the legacy 0.1 digest -- a bare 64-hex SHA-256 over
 * `JSON.stringify` of the resolved document, which differs per SDK because
 * each serializes differently. It is *not* the canonical content hash.
 * {@link canonicalJson}/{@link contentHash} in `canonical.ts` implement
 * spec/hushspec-canonical.md and produce the same `sha256:<hex>` value in
 * every SDK; receipts switch to it in P2-04 together with the receipt v0.2
 * schema. Until then the two must not be compared (canonical spec section 5,
 * "Migration").
 */
export function computePolicyHash(spec: HushSpec): string {
  let resolved = spec;
  if (spec.extends != null) {
    const result = resolveSpec(spec, { load: createBuiltinLoader() });
    if (!result.ok) {
      throw new Error(
        `cannot hash an unresolved policy (extends: ${spec.extends}): ${result.error}`,
      );
    }
    resolved = result.value;
  }
  const json = JSON.stringify(resolved);
  return createHash('sha256').update(json).digest('hex');
}

function buildPolicySummary(spec: HushSpec): PolicySummary {
  return {
    name: spec.name,
    version: spec.hushspec,
    content_hash: computePolicyHash(spec),
  };
}
