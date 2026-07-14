import { createHash, randomUUID } from 'node:crypto';
import type { HushSpec } from './schema.js';
import type { PostureResult } from './evaluate.js';
import { evaluate } from './evaluate.js';
import { HUSHSPEC_VERSION } from './version.js';
import type { EvaluationAction, EvaluationResult, Decision } from './evaluate.js';

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

export type RuleOutcome = 'allow' | 'warn' | 'deny' | 'skip';

export interface RuleEvaluation {
  rule_block: string;
  outcome: RuleOutcome;
  matched_rule?: string;
  reason?: string;
  evaluated: boolean;
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
  const result = evaluate(spec, action);

  const durationUs = config.enabled
    ? Math.round((performance.now() - startHr) * 1000)
    : 0;

  const ruleTrace =
    config.enabled && config.include_rule_trace
      ? collectRuleTrace(spec, action, result)
      : [];

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

export function computePolicyHash(spec: HushSpec): string {
  const json = JSON.stringify(spec);
  return createHash('sha256').update(json).digest('hex');
}

function buildPolicySummary(spec: HushSpec): PolicySummary {
  return {
    name: spec.name,
    version: spec.hushspec,
    content_hash: computePolicyHash(spec),
  };
}

function collectRuleTrace(
  spec: HushSpec,
  action: EvaluationAction,
  result: EvaluationResult,
): RuleEvaluation[] {
  const trace: RuleEvaluation[] = [];

  if (result.posture != null) {
    const postureDenied =
      result.matched_rule != null &&
      result.matched_rule.startsWith('extensions.posture.states.');

    if (postureDenied) {
      trace.push({
        rule_block: 'posture_capability',
        outcome: 'deny',
        matched_rule: result.matched_rule,
        reason: result.reason,
        evaluated: true,
      });
      appendSkippedRules(action, trace, 'short-circuited by posture deny');
      return trace;
    }

    trace.push({
      rule_block: 'posture_capability',
      outcome: 'allow',
      matched_rule: undefined,
      reason: 'posture capabilities satisfied',
      evaluated: true,
    });
  }

  switch (action.type) {
    case 'tool_call':
      traceToolAccess(spec, action, result, trace);
      break;
    case 'egress':
      traceEgress(spec, result, trace);
      break;
    case 'file_read':
      tracePathGuards(spec, result, trace);
      break;
    case 'file_write':
      tracePathGuards(spec, result, trace);
      traceSecretPatterns(spec, result, trace);
      break;
    case 'patch_apply':
      tracePathGuards(spec, result, trace);
      tracePatchIntegrity(spec, result, trace);
      break;
    case 'shell_command':
      traceShellCommands(spec, result, trace);
      break;
    case 'computer_use':
      traceComputerUse(spec, result, trace);
      break;
    default:
      trace.push({
        rule_block: 'default',
        outcome: result.decision,
        matched_rule: result.matched_rule,
        reason: result.reason,
        evaluated: true,
      });
      break;
  }

  return trace;
}

function traceToolAccess(
  spec: HushSpec,
  action: EvaluationAction,
  result: EvaluationResult,
  trace: RuleEvaluation[],
): void {
  const hasOriginRule =
    result.matched_rule != null &&
    result.matched_rule.startsWith('extensions.origins.profiles.');

  const hasRule =
    hasOriginRule ||
    spec.rules?.tool_access != null ||
    action.origin != null;

  if (hasRule) {
    trace.push({
      rule_block: 'tool_access',
      outcome: result.decision,
      matched_rule: result.matched_rule,
      reason: result.reason,
      evaluated: true,
    });
  } else {
    trace.push({
      rule_block: 'tool_access',
      outcome: 'skip',
      matched_rule: undefined,
      reason: 'no tool_access rule configured',
      evaluated: false,
    });
  }
}

function traceEgress(
  spec: HushSpec,
  result: EvaluationResult,
  trace: RuleEvaluation[],
): void {
  const hasOriginRule =
    result.matched_rule != null &&
    result.matched_rule.includes('egress');

  const hasRule = hasOriginRule || spec.rules?.egress != null;

  if (hasRule) {
    trace.push({
      rule_block: 'egress',
      outcome: result.decision,
      matched_rule: result.matched_rule,
      reason: result.reason,
      evaluated: true,
    });
  } else {
    trace.push({
      rule_block: 'egress',
      outcome: 'skip',
      matched_rule: undefined,
      reason: 'no egress rule configured',
      evaluated: false,
    });
  }
}

function tracePathGuards(
  spec: HushSpec,
  result: EvaluationResult,
  trace: RuleEvaluation[],
): void {
  const rules = spec.rules;
  const decidedByForbidden =
    result.matched_rule != null &&
    result.matched_rule.includes('forbidden_paths');
  const decidedByAllowlist =
    result.matched_rule != null &&
    result.matched_rule.includes('path_allowlist');

  const fp = rules?.forbidden_paths;
  if (fp != null) {
    if (fp.enabled !== false) {
      if (decidedByForbidden) {
        trace.push({
          rule_block: 'forbidden_paths',
          outcome: result.decision,
          matched_rule: result.matched_rule,
          reason: result.reason,
          evaluated: true,
        });
      } else {
        trace.push({
          rule_block: 'forbidden_paths',
          outcome: 'allow',
          matched_rule: undefined,
          reason: 'path did not match any forbidden pattern',
          evaluated: true,
        });
      }
    } else {
      trace.push({
        rule_block: 'forbidden_paths',
        outcome: 'skip',
        matched_rule: undefined,
        reason: 'rule disabled',
        evaluated: false,
      });
    }
  }

  const pa = rules?.path_allowlist;
  if (pa != null) {
    if (pa.enabled !== false) {
      const shortCircuited =
        decidedByForbidden && result.decision === 'deny';
      if (shortCircuited) {
        trace.push({
          rule_block: 'path_allowlist',
          outcome: 'skip',
          matched_rule: undefined,
          reason: 'short-circuited by prior deny',
          evaluated: false,
        });
      } else if (decidedByAllowlist) {
        trace.push({
          rule_block: 'path_allowlist',
          outcome: result.decision,
          matched_rule: result.matched_rule,
          reason: result.reason,
          evaluated: true,
        });
      } else {
        trace.push({
          rule_block: 'path_allowlist',
          outcome: 'allow',
          matched_rule: undefined,
          reason: 'path matched allowlist',
          evaluated: true,
        });
      }
    } else {
      trace.push({
        rule_block: 'path_allowlist',
        outcome: 'skip',
        matched_rule: undefined,
        reason: 'rule disabled',
        evaluated: false,
      });
    }
  }
}

function traceSecretPatterns(
  spec: HushSpec,
  result: EvaluationResult,
  trace: RuleEvaluation[],
): void {
  const decidedBySecret =
    result.matched_rule != null &&
    result.matched_rule.includes('secret_patterns');
  const priorDeny = trace.some(
    (t) => t.outcome === 'deny' && t.evaluated,
  );

  const sp = spec.rules?.secret_patterns;
  if (sp != null) {
    if (sp.enabled !== false) {
      if (priorDeny) {
        trace.push({
          rule_block: 'secret_patterns',
          outcome: 'skip',
          matched_rule: undefined,
          reason: 'short-circuited by prior deny',
          evaluated: false,
        });
      } else if (decidedBySecret) {
        trace.push({
          rule_block: 'secret_patterns',
          outcome: result.decision,
          matched_rule: result.matched_rule,
          reason: result.reason,
          evaluated: true,
        });
      } else {
        trace.push({
          rule_block: 'secret_patterns',
          outcome: 'allow',
          matched_rule: undefined,
          reason: 'content did not match any secret pattern',
          evaluated: true,
        });
      }
    } else {
      trace.push({
        rule_block: 'secret_patterns',
        outcome: 'skip',
        matched_rule: undefined,
        reason: 'rule disabled',
        evaluated: false,
      });
    }
  }
}

function tracePatchIntegrity(
  spec: HushSpec,
  result: EvaluationResult,
  trace: RuleEvaluation[],
): void {
  const decidedByPatch =
    result.matched_rule != null &&
    result.matched_rule.includes('patch_integrity');
  const priorDeny = trace.some(
    (t) => t.outcome === 'deny' && t.evaluated,
  );

  const pi = spec.rules?.patch_integrity;
  if (pi != null) {
    if (pi.enabled !== false) {
      if (priorDeny) {
        trace.push({
          rule_block: 'patch_integrity',
          outcome: 'skip',
          matched_rule: undefined,
          reason: 'short-circuited by prior deny',
          evaluated: false,
        });
      } else if (decidedByPatch) {
        trace.push({
          rule_block: 'patch_integrity',
          outcome: result.decision,
          matched_rule: result.matched_rule,
          reason: result.reason,
          evaluated: true,
        });
      } else {
        trace.push({
          rule_block: 'patch_integrity',
          outcome: 'allow',
          matched_rule: undefined,
          reason: 'patch passed integrity checks',
          evaluated: true,
        });
      }
    } else {
      trace.push({
        rule_block: 'patch_integrity',
        outcome: 'skip',
        matched_rule: undefined,
        reason: 'rule disabled',
        evaluated: false,
      });
    }
  }
}

function traceShellCommands(
  spec: HushSpec,
  result: EvaluationResult,
  trace: RuleEvaluation[],
): void {
  const decidedByShell =
    result.matched_rule != null &&
    result.matched_rule.includes('shell_commands');

  const sc = spec.rules?.shell_commands;
  if (sc != null) {
    if (sc.enabled !== false) {
      if (decidedByShell) {
        trace.push({
          rule_block: 'shell_commands',
          outcome: result.decision,
          matched_rule: result.matched_rule,
          reason: result.reason,
          evaluated: true,
        });
      } else {
        trace.push({
          rule_block: 'shell_commands',
          outcome: 'allow',
          matched_rule: undefined,
          reason: 'command did not match any forbidden pattern',
          evaluated: true,
        });
      }
    } else {
      trace.push({
        rule_block: 'shell_commands',
        outcome: 'skip',
        matched_rule: undefined,
        reason: 'rule disabled',
        evaluated: false,
      });
    }
  }
}

function traceComputerUse(
  spec: HushSpec,
  result: EvaluationResult,
  trace: RuleEvaluation[],
): void {
  const decidedByComputer =
    result.matched_rule != null &&
    result.matched_rule.includes('computer_use');

  const cu = spec.rules?.computer_use;
  if (cu != null) {
    if (cu.enabled !== false) {
      if (decidedByComputer) {
        trace.push({
          rule_block: 'computer_use',
          outcome: result.decision,
          matched_rule: result.matched_rule,
          reason: result.reason,
          evaluated: true,
        });
      } else {
        trace.push({
          rule_block: 'computer_use',
          outcome: 'allow',
          matched_rule: undefined,
          reason: 'action allowed by computer_use rule',
          evaluated: true,
        });
      }
    } else {
      trace.push({
        rule_block: 'computer_use',
        outcome: 'skip',
        matched_rule: undefined,
        reason: 'rule disabled',
        evaluated: false,
      });
    }
  }
}

function appendSkippedRules(
  action: EvaluationAction,
  trace: RuleEvaluation[],
  reason: string,
): void {
  let blocks: string[];
  switch (action.type) {
    case 'tool_call':
      blocks = ['tool_access'];
      break;
    case 'egress':
      blocks = ['egress'];
      break;
    case 'file_read':
      blocks = ['forbidden_paths', 'path_allowlist'];
      break;
    case 'file_write':
      blocks = ['forbidden_paths', 'path_allowlist', 'secret_patterns'];
      break;
    case 'patch_apply':
      blocks = ['forbidden_paths', 'path_allowlist', 'patch_integrity'];
      break;
    case 'shell_command':
      blocks = ['shell_commands'];
      break;
    case 'computer_use':
      blocks = ['computer_use'];
      break;
    default:
      blocks = [];
      break;
  }

  for (const block of blocks) {
    trace.push({
      rule_block: block,
      outcome: 'skip',
      matched_rule: undefined,
      reason,
      evaluated: false,
    });
  }
}
