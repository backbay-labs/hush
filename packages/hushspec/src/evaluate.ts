/**
 * Reference evaluator for HushSpec 0.2 (core spec Sections 3, 5, and 6).
 *
 * Evaluation of one action is:
 * 1. extension guards (panic, origins `default_behavior`, posture capability),
 * 2. every applicable rule block for the action type -- present, `enabled`,
 *    and with a satisfied `when` condition -- evaluated in the order of the
 *    Section 5 table, never short-circuiting on an allow,
 * 3. aggregation: deny beats warn beats allow; `matched_rule`/`reason` come
 *    from the first block in evaluation order whose decision equals the
 *    aggregate and which named a rule.
 *
 * Unknown action types deny (`__unknown_action_type__`). Hosts and paths are
 * normalized as specified in Section 3.14 before any pattern is consulted.
 *
 * This file is a port of `crates/hushspec/src/evaluate.rs`, which is the
 * normative reference implementation; keep the two in lockstep.
 */
import type { HushSpec } from './schema.js';
import type {
  BrowserAutomationRule,
  CodeExecutionRule,
  ComputerUseRule,
  EgressRule,
  ForbiddenPathsRule,
  InputInjectionRule,
  PatchIntegrityRule,
  PathAllowlistRule,
  RemoteDesktopChannelsRule,
  SecretPatternsRule,
  Severity,
  ShellCommandsRule,
  ToolAccessRule,
} from './rules.js';
import type {
  OriginEgressOverlay,
  OriginMatch,
  OriginProfile,
  OriginToolAccessOverlay,
  PostureExtension,
} from './extensions.js';
import type { Condition, RuntimeContext } from './conditions.js';
import { evaluateCondition } from './conditions.js';
import { parseOrThrow } from './parse.js';
import { compileProfileRegex } from './regex.js';

/** `matched_rule` reported when the action type is unknown to the specification. */
export const UNKNOWN_ACTION_TYPE_RULE = '__unknown_action_type__';
/** `matched_rule` reported when the emergency panic protocol is active. */
export const PANIC_RULE = '__hushspec_panic__';

export type Decision = 'allow' | 'warn' | 'deny';

export interface EvaluationAction {
  type: string;
  target?: string;
  content?: string;
  origin?: OriginContext;
  posture?: PostureContext;
  args_size?: number;
  /** `browser_action`: navigation destination (core spec 3.11). */
  url?: string;
  /** `code_exec`: whether the call requests network access (core spec 3.12). */
  network?: boolean;
  /** `code_exec`: requested execution time in milliseconds (core spec 3.12). */
  timeout_ms?: number;
  /**
   * Runtime context consulted by `when` conditions (core spec 3.13). When
   * absent, conditions see an empty context and the engine clock.
   */
  context?: RuntimeContext;
  /** Set on the redacted copy emitted to observers when content is stripped. */
  content_redacted?: boolean;
}

export interface OriginContext {
  provider?: string;
  tenant_id?: string;
  space_id?: string;
  space_type?: string;
  visibility?: string;
  external_participants?: boolean;
  tags?: string[];
  sensitivity?: string;
  actor_role?: string;
}

export interface PostureContext {
  current?: string;
  signal?: string;
}

export interface EvaluationResult {
  decision: Decision;
  matched_rule?: string;
  reason?: string;
  origin_profile?: string;
  posture?: PostureResult;
}

export interface PostureResult {
  current: string;
  next: string;
}

export type RuleOutcome = 'allow' | 'warn' | 'deny' | 'skip';

/**
 * One recorded rule-block consultation. Produced by the evaluator itself, in
 * evaluation order, so receipts reflect exactly what ran.
 */
export interface RuleEvaluation {
  rule_block: string;
  outcome: RuleOutcome;
  matched_rule?: string;
  reason?: string;
  evaluated: boolean;
}

/** An evaluation result together with its recorded rule trace. */
export interface TracedEvaluation {
  result: EvaluationResult;
  trace: RuleEvaluation[];
}

const enum PathOperation {
  Read,
  Write,
  Patch,
}

interface PatchStats {
  additions: number;
  deletions: number;
}

function decisionRank(decision: Decision): number {
  switch (decision) {
    case 'allow': return 1;
    case 'warn': return 2;
    case 'deny': return 3;
  }
}

/** Decision contributed by one rule block. */
interface BlockDecision {
  decision: Decision;
  matched_rule?: string;
  reason?: string;
}

function blockAllow(matchedRule?: string, reason?: string): BlockDecision {
  return { decision: 'allow', matched_rule: matchedRule, reason };
}

function blockWarn(matchedRule: string, reason: string): BlockDecision {
  return { decision: 'warn', matched_rule: matchedRule, reason };
}

function blockDeny(matchedRule: string, reason: string): BlockDecision {
  return { decision: 'deny', matched_rule: matchedRule, reason };
}

/** Why an applicable block was not evaluated. */
type InactiveReason = 'absent' | 'disabled' | 'condition_false' | 'out_of_band_condition_false';

function inactiveReasonText(reason: InactiveReason, block: string): string {
  switch (reason) {
    case 'absent': return `no ${block} rule configured`;
    case 'disabled': return 'rule disabled';
    case 'condition_false': return 'when condition is false';
    case 'out_of_band_condition_false': return 'out-of-band condition is false';
  }
}

interface Inactive {
  inactive: InactiveReason;
}

function isInactive(value: BlockDecision | Inactive): value is Inactive {
  return (value as Inactive).inactive !== undefined;
}

/**
 * Rule blocks applicable to each reference action type, in evaluation order
 * (core spec Section 5). `undefined` means the type is unknown to the
 * specification.
 */
function applicableBlocks(actionType: string): readonly string[] | undefined {
  switch (actionType) {
    case 'file_read': return ['forbidden_paths', 'path_allowlist'];
    case 'file_write': return ['forbidden_paths', 'path_allowlist', 'secret_patterns'];
    case 'patch_apply': return ['forbidden_paths', 'path_allowlist', 'patch_integrity', 'secret_patterns'];
    case 'shell_command': return ['shell_commands'];
    case 'egress': return ['egress', 'secret_patterns'];
    case 'tool_call': return ['tool_access', 'secret_patterns'];
    case 'computer_use': return ['computer_use', 'remote_desktop_channels'];
    case 'input_inject': return ['input_injection'];
    case 'browser_action': return ['browser_automation'];
    case 'code_exec': return ['code_execution'];
    case 'custom': return [];
    default: return undefined;
  }
}

const EMPTY_CONTEXT: RuntimeContext = {};

/**
 * Evaluate `action` against a resolved document.
 *
 * `when` conditions are evaluated against `action.context` (an empty context
 * and the engine clock when absent).
 */
export function evaluate(spec: HushSpec, action: EvaluationAction): EvaluationResult {
  return evaluateTraced(spec, action).result;
}

/**
 * Like {@link evaluate} with an explicit runtime context and an out-of-band map
 * of conditions keyed by rule-block name. The explicit `context` replaces
 * `action.context`; out-of-band conditions are ANDed with each block's own
 * `when` (core spec 3.13).
 */
export function evaluateWithContext(
  spec: HushSpec,
  action: EvaluationAction,
  context: RuntimeContext,
  conditions: Record<string, Condition>,
): EvaluationResult {
  return evaluateTraced(spec, action, context, conditions).result;
}

/** Full evaluation with the recorded rule trace (used by receipts). */
export function evaluateTraced(
  spec: HushSpec,
  action: EvaluationAction,
  context?: RuntimeContext,
  conditions: Record<string, Condition> = {},
): TracedEvaluation {
  const effectiveContext = context ?? action.context ?? EMPTY_CONTEXT;
  return new Evaluator(spec, action, effectiveContext, conditions).run();
}

class Evaluator {
  private readonly trace: RuleEvaluation[] = [];

  constructor(
    private readonly spec: HushSpec,
    private readonly action: EvaluationAction,
    private readonly context: RuntimeContext,
    private readonly conditions: Record<string, Condition>,
  ) {}

  run(): TracedEvaluation {
    if (panicActive) {
      this.record('panic', 'deny', PANIC_RULE, 'emergency panic mode is active', true);
      return this.finish('deny', PANIC_RULE, 'emergency panic mode is active', undefined, undefined);
    }

    const actionType = this.action.type;
    const blocks = applicableBlocks(actionType);
    if (blocks == null) {
      const reason = `action type '${actionType}' is unknown to the specification`;
      this.record('default', 'deny', UNKNOWN_ACTION_TYPE_RULE, reason, true);
      return this.finish('deny', UNKNOWN_ACTION_TYPE_RULE, reason, undefined, undefined);
    }

    // Origins guard: select a profile or apply default_behavior.
    const origins = this.spec.extensions?.origins;
    const matchedProfile = selectOriginProfile(this.spec, this.action.origin);
    const originProfileId = matchedProfile?.id;
    if (
      origins != null
      && matchedProfile == null
      && (origins.default_behavior ?? 'deny') === 'deny'
    ) {
      const reason = 'no origin profile matched and default_behavior is deny';
      this.record('origins', 'deny', 'extensions.origins.default_behavior', reason, true);
      this.skipAll(blocks, 'short-circuited by origins deny');
      return this.finish('deny', 'extensions.origins.default_behavior', reason, undefined, undefined);
    }

    // Posture guard.
    const posture = resolvePosture(this.spec, matchedProfile, this.action.posture);
    const denied = this.postureCapabilityGuard(posture);
    if (denied != null) {
      this.skipAll(blocks, 'short-circuited by posture deny');
      return this.finish('deny', denied.matched_rule, denied.reason, originProfileId, posture);
    }

    if (actionType === 'custom') {
      // Only a posture state granting the `custom` capability can vouch for an
      // engine-defined action (core spec Section 5).
      if (posture == null) {
        const reason = 'custom actions require a posture state granting the custom capability';
        this.record('default', 'deny', UNKNOWN_ACTION_TYPE_RULE, reason, true);
        return this.finish('deny', UNKNOWN_ACTION_TYPE_RULE, reason, originProfileId, undefined);
      }
      return this.finish('allow', undefined, undefined, originProfileId, posture);
    }

    // Block evaluation and aggregation (core spec 6.1).
    const normalizedPath = this.action.target != null ? normalizePath(this.action.target) : undefined;
    const decisions: BlockDecision[] = [];
    for (const block of blocks) {
      const outcome = this.evaluateBlock(block, matchedProfile, normalizedPath);
      if (isInactive(outcome)) {
        this.record(block, 'skip', undefined, inactiveReasonText(outcome.inactive, block), false);
      } else {
        this.record(block, outcome.decision, outcome.matched_rule, outcome.reason, true);
        decisions.push(outcome);
      }
    }

    let aggregate: Decision = 'allow';
    for (const decision of decisions) {
      if (decisionRank(decision.decision) > decisionRank(aggregate)) {
        aggregate = decision.decision;
      }
    }
    const winner = decisions.find(
      decision => decision.decision === aggregate && decision.matched_rule != null,
    );

    return this.finish(
      aggregate,
      winner?.matched_rule,
      winner?.reason,
      originProfileId,
      posture,
    );
  }

  private finish(
    decision: Decision,
    matchedRule: string | undefined,
    reason: string | undefined,
    originProfile: string | undefined,
    posture: PostureResult | undefined,
  ): TracedEvaluation {
    return {
      result: {
        decision,
        matched_rule: matchedRule,
        reason,
        origin_profile: originProfile,
        posture,
      },
      trace: this.trace,
    };
  }

  private record(
    block: string,
    outcome: RuleOutcome,
    matchedRule: string | undefined,
    reason: string | undefined,
    evaluated: boolean,
  ): void {
    this.trace.push({
      rule_block: block,
      outcome,
      matched_rule: matchedRule,
      reason,
      evaluated,
    });
  }

  private skipAll(blocks: readonly string[], reason: string): void {
    for (const block of blocks) {
      this.record(block, 'skip', undefined, reason, false);
    }
  }

  /**
   * Whether a present block is active: enabled, and its `when` plus any
   * out-of-band condition hold for the runtime context.
   */
  private activity(
    block: string,
    enabled: boolean,
    when: Condition | undefined,
  ): Inactive | undefined {
    if (!enabled) {
      return { inactive: 'disabled' };
    }
    if (when != null && !evaluateCondition(when, this.context)) {
      return { inactive: 'condition_false' };
    }
    const outOfBand = Object.prototype.hasOwnProperty.call(this.conditions, block)
      ? this.conditions[block]
      : undefined;
    if (outOfBand != null && !evaluateCondition(outOfBand, this.context)) {
      return { inactive: 'out_of_band_condition_false' };
    }
    return undefined;
  }

  private evaluateBlock(
    block: string,
    matchedProfile: OriginProfile | undefined,
    normalizedPath: string | undefined,
  ): BlockDecision | Inactive {
    const rules = this.spec.rules;
    const action = this.action;
    const content = action.content;

    switch (block) {
      case 'forbidden_paths': {
        const rule = rules?.forbidden_paths;
        if (rule == null) return { inactive: 'absent' };
        const inactive = this.activity(block, rule.enabled ?? true, rule.when);
        if (inactive) return inactive;
        return evaluateForbiddenPaths(rule, normalizedPath ?? '');
      }
      case 'path_allowlist': {
        const rule = rules?.path_allowlist;
        if (rule == null) return { inactive: 'absent' };
        const inactive = this.activity(block, rule.enabled ?? false, rule.when);
        if (inactive) return inactive;
        const operation = action.type === 'file_read'
          ? PathOperation.Read
          : action.type === 'patch_apply'
            ? PathOperation.Patch
            : PathOperation.Write;
        return evaluatePathAllowlist(rule, normalizedPath ?? '', operation);
      }
      case 'secret_patterns': {
        const rule = rules?.secret_patterns;
        if (rule == null) return { inactive: 'absent' };
        const pathBearing = action.type === 'file_write' || action.type === 'patch_apply';
        // egress and tool_call are scanned only when they carry content.
        if (!pathBearing && content == null) return { inactive: 'absent' };
        const inactive = this.activity(block, rule.enabled ?? true, rule.when);
        if (inactive) return inactive;
        const skipPath = pathBearing ? normalizedPath : undefined;
        return evaluateSecretPatterns(rule, skipPath, content ?? '');
      }
      case 'patch_integrity': {
        const rule = rules?.patch_integrity;
        if (rule == null) return { inactive: 'absent' };
        const inactive = this.activity(block, rule.enabled ?? true, rule.when);
        if (inactive) return inactive;
        return evaluatePatchIntegrity(rule, content ?? '');
      }
      case 'shell_commands': {
        const rule = rules?.shell_commands;
        if (rule == null) return { inactive: 'absent' };
        const inactive = this.activity(block, rule.enabled ?? true, rule.when);
        if (inactive) return inactive;
        return evaluateShellCommands(rule, action.target ?? '');
      }
      case 'tool_access': {
        const base = rules?.tool_access;
        const overlayRule = matchedProfile?.tool_access;
        const overlay: OverlayRef<OriginToolAccessOverlay> | undefined =
          matchedProfile != null && overlayRule != null
            ? { id: matchedProfile.id, rule: overlayRule }
            : undefined;
        if (base == null && overlay == null) return { inactive: 'absent' };
        if (base != null) {
          const inactive = this.activity(block, base.enabled ?? true, base.when);
          if (inactive) return inactive;
        }
        return evaluateToolAccess(base, overlay, action);
      }
      case 'egress': {
        const base = rules?.egress;
        const overlayRule = matchedProfile?.egress;
        const overlay: OverlayRef<OriginEgressOverlay> | undefined =
          matchedProfile != null && overlayRule != null
            ? { id: matchedProfile.id, rule: overlayRule }
            : undefined;
        if (base == null && overlay == null) return { inactive: 'absent' };
        if (base != null) {
          const inactive = this.activity(block, base.enabled ?? true, base.when);
          if (inactive) return inactive;
        }
        const host = action.target != null ? normalizeHost(action.target) : undefined;
        return evaluateEgress(base, overlay, host);
      }
      case 'computer_use': {
        const rule = rules?.computer_use;
        if (rule == null) return { inactive: 'absent' };
        const inactive = this.activity(block, rule.enabled ?? false, rule.when);
        if (inactive) return inactive;
        return evaluateComputerUse(rule, action.target ?? '');
      }
      case 'remote_desktop_channels': {
        const rule = rules?.remote_desktop_channels;
        if (rule == null) return { inactive: 'absent' };
        const inactive = this.activity(block, rule.enabled ?? false, rule.when);
        if (inactive) return inactive;
        return evaluateRemoteDesktopChannels(rule, action.target ?? '') ?? { inactive: 'absent' };
      }
      case 'input_injection': {
        const rule = rules?.input_injection;
        if (rule == null) return { inactive: 'absent' };
        const inactive = this.activity(block, rule.enabled ?? false, rule.when);
        if (inactive) return inactive;
        return evaluateInputInjection(rule, action.target ?? '');
      }
      case 'browser_automation': {
        const rule = rules?.browser_automation;
        if (rule == null) return { inactive: 'absent' };
        const inactive = this.activity(block, rule.enabled ?? false, rule.when);
        if (inactive) return inactive;
        return evaluateBrowserAutomation(rule, action);
      }
      case 'code_execution': {
        const rule = rules?.code_execution;
        if (rule == null) return { inactive: 'absent' };
        const inactive = this.activity(block, rule.enabled ?? false, rule.when);
        if (inactive) return inactive;
        return evaluateCodeExecution(rule, action);
      }
      default:
        return { inactive: 'absent' };
    }
  }

  private postureCapabilityGuard(posture: PostureResult | undefined): BlockDecision | undefined {
    if (posture == null) return undefined;
    const postureExtension = this.spec.extensions?.posture;
    if (postureExtension == null) return undefined;
    const capability = requiredCapability(this.action.type);
    if (capability == null) return undefined;

    const currentState = postureExtension.states?.[posture.current];
    if (currentState == null) {
      const rule = `extensions.posture.states.${posture.current}`;
      const reason = `unknown posture state '${posture.current}'`;
      this.record('posture_capability', 'deny', rule, reason, true);
      return blockDeny(rule, reason);
    }

    if ((currentState.capabilities ?? []).includes(capability)) {
      this.record('posture_capability', 'allow', undefined, 'posture capabilities satisfied', true);
      return undefined;
    }

    const rule = `extensions.posture.states.${posture.current}.capabilities`;
    const reason = `posture '${posture.current}' does not allow capability '${capability}'`;
    this.record('posture_capability', 'deny', rule, reason, true);
    return blockDeny(rule, reason);
  }
}

// ---------------------------------------------------------------------------
// Rule blocks
// ---------------------------------------------------------------------------

function evaluateForbiddenPaths(rule: ForbiddenPathsRule, path: string): BlockDecision {
  if (anyPathGlobMatches(rule.exceptions, path)) {
    return blockAllow('rules.forbidden_paths.exceptions', 'path matched an explicit exception');
  }
  if (anyPathGlobMatches(rule.patterns, path)) {
    return blockDeny('rules.forbidden_paths.patterns', 'path matched a forbidden pattern');
  }
  return blockAllow(undefined, 'path did not match any forbidden pattern');
}

function evaluatePathAllowlist(
  rule: PathAllowlistRule,
  path: string,
  operation: PathOperation,
): BlockDecision {
  let patterns: string[] | undefined;
  switch (operation) {
    case PathOperation.Read:
      patterns = rule.read;
      break;
    case PathOperation.Write:
      patterns = rule.write;
      break;
    case PathOperation.Patch:
      patterns = (rule.patch?.length ?? 0) > 0 ? rule.patch : rule.write;
      break;
  }
  if (anyPathGlobMatches(patterns, path)) {
    return blockAllow('rules.path_allowlist', 'path matched allowlist');
  }
  return blockDeny('rules.path_allowlist', 'path did not match allowlist');
}

function severityRank(severity: Severity): number {
  switch (severity) {
    case 'warn': return 1;
    case 'error': return 2;
    case 'critical': return 3;
    default: return 0;
  }
}

function evaluateSecretPatterns(
  rule: SecretPatternsRule,
  skipPath: string | undefined,
  content: string,
): BlockDecision {
  if (skipPath != null && anyPathGlobMatches(rule.skip_paths, skipPath)) {
    return blockAllow('rules.secret_patterns.skip_paths', 'path is excluded from secret scanning');
  }

  let bestRank = 0;
  let best: { name: string; severity: Severity } | undefined;
  for (const pattern of rule.patterns ?? []) {
    // Fail closed: a pattern that will not compile under the HushSpec regex
    // profile denies the action rather than being skipped (core spec 3.14.3).
    let matched: boolean;
    try {
      matched = compileProfileRegex(pattern.pattern).regex.test(content);
    } catch (error) {
      return blockDeny(
        `rules.secret_patterns.patterns.${pattern.name}.pattern`,
        `secret pattern '${pattern.name}' is invalid: ${errorMessage(error)}`,
      );
    }
    if (matched) {
      const rank = severityRank(pattern.severity);
      // Strictly greater keeps the first pattern in document order among
      // those at the highest matched severity.
      if (best == null || rank > bestRank) {
        bestRank = rank;
        best = pattern;
      }
    }
  }

  if (best == null) {
    return blockAllow(undefined, 'content did not match any secret pattern');
  }

  const matchedRule = `rules.secret_patterns.patterns.${best.name}`;
  const reason = `content matched secret pattern '${best.name}'`;
  return best.severity === 'warn'
    ? blockWarn(matchedRule, reason)
    : blockDeny(matchedRule, reason);
}

function evaluatePatchIntegrity(rule: PatchIntegrityRule, content: string): BlockDecision {
  const forbiddenPatterns = rule.forbidden_patterns ?? [];
  for (let index = 0; index < forbiddenPatterns.length; index++) {
    let matched: boolean;
    try {
      matched = compileProfileRegex(forbiddenPatterns[index]).regex.test(content);
    } catch (error) {
      return blockDeny(
        `rules.patch_integrity.forbidden_patterns[${index}]`,
        `patch forbidden pattern is invalid: ${errorMessage(error)}`,
      );
    }
    if (matched) {
      return blockDeny(
        `rules.patch_integrity.forbidden_patterns[${index}]`,
        'patch content matched a forbidden pattern',
      );
    }
  }

  const stats = patchStats(content);
  if (stats.additions > (rule.max_additions ?? 1000)) {
    return blockDeny('rules.patch_integrity.max_additions', 'patch additions exceeded max_additions');
  }
  if (stats.deletions > (rule.max_deletions ?? 500)) {
    return blockDeny('rules.patch_integrity.max_deletions', 'patch deletions exceeded max_deletions');
  }

  if (rule.require_balance === true) {
    const oneSided = (stats.additions === 0) !== (stats.deletions === 0);
    if (oneSided) {
      return blockDeny(
        'rules.patch_integrity.max_imbalance_ratio',
        'patch has changes on only one side; the imbalance ratio is infinite',
      );
    }
    if (stats.additions > 0 && stats.deletions > 0) {
      const larger = Math.max(stats.additions, stats.deletions);
      const smaller = Math.min(stats.additions, stats.deletions);
      if (larger / smaller > (rule.max_imbalance_ratio ?? 10.0)) {
        return blockDeny(
          'rules.patch_integrity.max_imbalance_ratio',
          'patch exceeded max imbalance ratio',
        );
      }
    }
  }

  return blockAllow(undefined, 'patch passed integrity checks');
}

function evaluateShellCommands(rule: ShellCommandsRule, command: string): BlockDecision {
  const forbiddenPatterns = rule.forbidden_patterns ?? [];
  for (let index = 0; index < forbiddenPatterns.length; index++) {
    let matched: boolean;
    try {
      matched = compileProfileRegex(forbiddenPatterns[index]).regex.test(command);
    } catch (error) {
      return blockDeny(
        `rules.shell_commands.forbidden_patterns[${index}]`,
        `shell forbidden pattern is invalid: ${errorMessage(error)}`,
      );
    }
    if (matched) {
      return blockDeny(
        `rules.shell_commands.forbidden_patterns[${index}]`,
        'shell command matched a forbidden pattern',
      );
    }
  }
  return blockAllow(undefined, 'command did not match any forbidden pattern');
}

interface OverlayRef<T> {
  id: string;
  rule: T;
}

/**
 * Tool names are exact, case-sensitive strings after NFC normalization
 * (core spec 3.7); no glob or regex metacharacters.
 */
function toolListContains(entries: string[] | undefined, tool: string): boolean {
  if (entries == null) return false;
  const normalizedTool = tool.normalize('NFC');
  return entries.some(entry => entry.normalize('NFC') === normalizedTool);
}

function nonEmpty(list: string[] | undefined): string[] | undefined {
  return list != null && list.length > 0 ? list : undefined;
}

function evaluateToolAccess(
  base: ToolAccessRule | undefined,
  overlay: OverlayRef<OriginToolAccessOverlay> | undefined,
  action: EvaluationAction,
): BlockDecision {
  const tool = action.target ?? '';
  const prefix = overlay != null
    ? `extensions.origins.profiles.${overlay.id}.tool_access`
    : undefined;
  const overlayRule = overlay?.rule;

  // 1. max_args_size: the smaller of the two when both are specified.
  const baseLimit = base?.max_args_size != null
    ? { limit: base.max_args_size, matchedRule: 'rules.tool_access.max_args_size' }
    : undefined;
  const overlayLimit = overlayRule?.max_args_size != null && prefix != null
    ? { limit: overlayRule.max_args_size, matchedRule: `${prefix}.max_args_size` }
    : undefined;
  const limit = baseLimit != null && overlayLimit != null
    ? (overlayLimit.limit < baseLimit.limit ? overlayLimit : baseLimit)
    : (baseLimit ?? overlayLimit);
  if (limit != null && (action.args_size ?? 0) > limit.limit) {
    return blockDeny(limit.matchedRule, 'tool arguments exceeded max_args_size');
  }

  // 2. block: union of both lists.
  if (base != null && toolListContains(base.block, tool)) {
    return blockDeny('rules.tool_access.block', 'tool is explicitly blocked');
  }
  if (overlayRule != null && prefix != null && toolListContains(overlayRule.block, tool)) {
    return blockDeny(`${prefix}.block`, 'tool is explicitly blocked');
  }

  // 3. require_confirmation: union of both lists.
  if (base != null && toolListContains(base.require_confirmation, tool)) {
    return blockWarn('rules.tool_access.require_confirmation', 'tool requires confirmation');
  }
  if (overlayRule != null && prefix != null && toolListContains(overlayRule.require_confirmation, tool)) {
    return blockWarn(`${prefix}.require_confirmation`, 'tool requires confirmation');
  }

  // 4/5. allowlist mode: intersection when both lists are non-empty.
  const baseAllow = base != null ? nonEmpty(base.allow) : undefined;
  const overlayAllow = overlayRule != null ? nonEmpty(overlayRule.allow) : undefined;
  if (baseAllow != null || overlayAllow != null) {
    if (baseAllow != null && !toolListContains(baseAllow, tool)) {
      return blockDeny('rules.tool_access.allow', 'tool is not in the allowlist');
    }
    if (overlayAllow != null && prefix != null && !toolListContains(overlayAllow, tool)) {
      return blockDeny(`${prefix}.allow`, 'tool is not in the allowlist');
    }
    const matchedRule = overlayAllow != null && prefix != null
      ? `${prefix}.allow`
      : 'rules.tool_access.allow';
    return blockAllow(matchedRule, 'tool is explicitly allowed');
  }

  // 6. default: block when the base says block or the overlay specifies block.
  const baseDefault = base?.default ?? 'allow';
  const overlayDefault = overlayRule?.default;
  const effective = baseDefault === 'block' || overlayDefault === 'block' ? 'block' : 'allow';
  const matchedRule = defaultRulePath(
    base != null,
    baseDefault,
    overlayDefault,
    effective,
    'rules.tool_access.default',
    prefix,
  );
  return effective === 'allow'
    ? blockAllow(matchedRule, 'tool matched default allow')
    : blockDeny(matchedRule, 'tool matched default block');
}

/**
 * Path reported for a `default` decision: the object whose `default` field
 * determined the effective value.
 */
function defaultRulePath(
  basePresent: boolean,
  baseDefault: 'allow' | 'block',
  overlayDefault: 'allow' | 'block' | undefined,
  effective: 'allow' | 'block',
  basePath: string,
  prefix: string | undefined,
): string {
  if (prefix == null) return basePath;
  const overlayPath = `${prefix}.default`;
  if (effective === 'block') {
    return basePresent && baseDefault === 'block' ? basePath : overlayPath;
  }
  return basePresent || overlayDefault == null ? basePath : overlayPath;
}

function evaluateEgress(
  base: EgressRule | undefined,
  overlay: OverlayRef<OriginEgressOverlay> | undefined,
  host: string | undefined,
): BlockDecision {
  const prefix = overlay != null
    ? `extensions.origins.profiles.${overlay.id}.egress`
    : undefined;
  const overlayRule = overlay?.rule;

  // 1. block: union of both lists.
  if (base != null && anyHostPatternMatches(base.block, host)) {
    return blockDeny('rules.egress.block', 'domain is explicitly blocked');
  }
  if (overlayRule != null && prefix != null && anyHostPatternMatches(overlayRule.block, host)) {
    return blockDeny(`${prefix}.block`, 'domain is explicitly blocked');
  }

  // 2. allow: intersection when both lists are non-empty.
  const baseAllow = base != null ? nonEmpty(base.allow) : undefined;
  const overlayAllow = overlayRule != null ? nonEmpty(overlayRule.allow) : undefined;
  if (baseAllow != null || overlayAllow != null) {
    const baseOk = baseAllow == null || anyHostPatternMatches(baseAllow, host);
    const overlayOk = overlayAllow == null || anyHostPatternMatches(overlayAllow, host);
    if (baseOk && overlayOk) {
      const matchedRule = overlayAllow != null && prefix != null
        ? `${prefix}.allow`
        : 'rules.egress.allow';
      return blockAllow(matchedRule, 'domain is explicitly allowed');
    }
  }

  // 3. default.
  const baseDefault = base?.default ?? 'block';
  const overlayDefault = overlayRule?.default;
  const effective = baseDefault === 'block' || overlayDefault === 'block' ? 'block' : 'allow';
  const matchedRule = defaultRulePath(
    base != null,
    baseDefault,
    overlayDefault,
    effective,
    'rules.egress.default',
    prefix,
  );
  return effective === 'allow'
    ? blockAllow(matchedRule, 'domain matched default allow')
    : blockDeny(matchedRule, 'domain matched default block');
}

function evaluateComputerUse(rule: ComputerUseRule, target: string): BlockDecision {
  if ((rule.allowed_actions ?? []).includes(target)) {
    return blockAllow(
      'rules.computer_use.allowed_actions',
      'computer-use action is explicitly allowed',
    );
  }
  if ((rule.mode ?? 'guardrail') === 'observe') {
    return blockAllow('rules.computer_use.mode', 'observe mode does not block unlisted actions');
  }
  // guardrail and fail_closed have identical reference semantics (D9).
  return blockDeny('rules.computer_use.mode', 'unlisted computer-use action is denied');
}

function evaluateRemoteDesktopChannels(
  rule: RemoteDesktopChannelsRule,
  target: string,
): BlockDecision | undefined {
  let field: string;
  let allowed: boolean;
  switch (target) {
    case 'remote.clipboard':
      field = 'clipboard';
      allowed = rule.clipboard ?? false;
      break;
    case 'remote.file_transfer':
      field = 'file_transfer';
      allowed = rule.file_transfer ?? false;
      break;
    case 'remote.audio':
      field = 'audio';
      allowed = rule.audio ?? true;
      break;
    case 'remote.drive_mapping':
      field = 'drive_mapping';
      allowed = rule.drive_mapping ?? false;
      break;
    default:
      return undefined;
  }

  const matchedRule = `rules.remote_desktop_channels.${field}`;
  return allowed
    ? blockAllow(matchedRule, `remote desktop channel '${field}' is enabled`)
    : blockDeny(matchedRule, `remote desktop channel '${field}' is disabled`);
}

function evaluateInputInjection(rule: InputInjectionRule, target: string): BlockDecision {
  const allowedTypes = rule.allowed_types ?? [];
  if (allowedTypes.length === 0) {
    return blockDeny(
      'rules.input_injection.allowed_types',
      'input injection is not allowed when allowed_types is empty',
    );
  }
  if (allowedTypes.includes(target)) {
    return blockAllow(
      'rules.input_injection.allowed_types',
      'input injection type is explicitly allowed',
    );
  }
  return blockDeny('rules.input_injection.allowed_types', 'input injection type is not allowed');
}

/**
 * Built-in credential detectors consulted by `browser_automation` when
 * `credential_detection` is true (core spec 3.11). Documents needing portable
 * detection list their own patterns in `extra_credential_patterns`.
 */
export const BUILTIN_CREDENTIAL_PATTERNS: ReadonlyArray<readonly [string, string]> = [
  ['aws_access_key', '(AKIA|ASIA)[0-9A-Z]{16}'],
  ['github_token', 'gh[opsur]_[A-Za-z0-9]{36}'],
  ['github_fine_grained_pat', 'github_pat_[0-9a-zA-Z_]{50,}'],
  ['openai_key', 'sk-[A-Za-z0-9_-]{20,}'],
  ['slack_token', 'xox[baprs]-[0-9A-Za-z-]{10,}'],
  ['private_key', '-----BEGIN[ \\t]+(RSA[ \\t]+|EC[ \\t]+|OPENSSH[ \\t]+)?PRIVATE[ \\t]+KEY-----'],
  ['jwt', 'eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}'],
];

function evaluateBrowserAutomation(
  rule: BrowserAutomationRule,
  action: EvaluationAction,
): BlockDecision {
  const verb = action.target ?? '';

  // 1. verb allowlist (exact match).
  const allowedVerbs = rule.allowed_verbs ?? [];
  if (allowedVerbs.length > 0 && !allowedVerbs.includes(verb)) {
    return blockDeny(
      'rules.browser_automation.allowed_verbs',
      'browser verb is not in the allowlist',
    );
  }

  // 2. destination host.
  if (action.url != null) {
    const host = normalizeHost(action.url);
    if (anyHostPatternMatches(rule.blocked_domains, host)) {
      return blockDeny(
        'rules.browser_automation.blocked_domains',
        'destination host is explicitly blocked',
      );
    }
    const allowedDomains = rule.allowed_domains ?? [];
    if (allowedDomains.length > 0 && !anyHostPatternMatches(allowedDomains, host)) {
      return blockDeny(
        'rules.browser_automation.allowed_domains',
        'destination host is not in the allowlist',
      );
    }
  }

  // 3. credential detection on typed input.
  if ((rule.credential_detection ?? true) && action.content != null) {
    const content = action.content;
    for (const [name, pattern] of BUILTIN_CREDENTIAL_PATTERNS) {
      let matched = false;
      try {
        matched = compileProfileRegex(pattern).regex.test(content);
      } catch {
        matched = false;
      }
      if (matched) {
        return blockDeny(
          'rules.browser_automation.credential_detection',
          `typed input matched built-in credential detector '${name}'`,
        );
      }
    }
    const extras = rule.extra_credential_patterns ?? [];
    for (let index = 0; index < extras.length; index++) {
      let matched: boolean;
      try {
        matched = compileProfileRegex(extras[index]).regex.test(content);
      } catch (error) {
        return blockDeny(
          `rules.browser_automation.extra_credential_patterns[${index}]`,
          `credential pattern is invalid: ${errorMessage(error)}`,
        );
      }
      if (matched) {
        return blockDeny(
          'rules.browser_automation.credential_detection',
          `typed input matched extra_credential_patterns[${index}]`,
        );
      }
    }
  }

  return blockAllow('rules.browser_automation', 'browser action is permitted');
}

function evaluateCodeExecution(
  rule: CodeExecutionRule,
  action: EvaluationAction,
): BlockDecision {
  const language = action.target ?? '';

  // 1. language allowlist (exact, case-sensitive).
  const languageAllowlist = rule.language_allowlist ?? [];
  if (languageAllowlist.length > 0 && !languageAllowlist.includes(language)) {
    return blockDeny(
      'rules.code_execution.language_allowlist',
      'language is not in the allowlist',
    );
  }

  // 2. network access.
  if (action.network === true && rule.network_access !== true) {
    return blockDeny(
      'rules.code_execution.network_access',
      'network access is not permitted for code execution',
    );
  }

  // 3. execution time bound.
  if (
    rule.max_execution_time_ms != null
    && action.timeout_ms != null
    && action.timeout_ms > rule.max_execution_time_ms
  ) {
    return blockDeny(
      'rules.code_execution.max_execution_time_ms',
      'requested execution time exceeds max_execution_time_ms',
    );
  }

  // 4. module denylist: literal word match within the scanned prefix.
  if (action.content != null) {
    const scanned = rule.max_scan_bytes != null
      ? truncateUtf8(action.content, rule.max_scan_bytes)
      : action.content;
    for (const module of rule.module_denylist ?? []) {
      if (containsWord(scanned, module)) {
        return blockDeny(
          'rules.code_execution.module_denylist',
          `code references denied module '${module}'`,
        );
      }
    }
  }

  return blockAllow('rules.code_execution', 'code execution is permitted');
}

/** Truncate `content` to at most `limit` UTF-8 bytes, on a code-point boundary. */
function truncateUtf8(content: string, limit: number): string {
  const bytes = new TextEncoder().encode(content);
  if (bytes.length <= limit) return content;
  let end = limit;
  // UTF-8 continuation bytes are 0b10xxxxxx; back off until a lead byte.
  while (end > 0 && (bytes[end] & 0xc0) === 0x80) {
    end -= 1;
  }
  return new TextDecoder().decode(bytes.subarray(0, end));
}

/**
 * Whether `word` occurs in `text` bounded by non-`[A-Za-z0-9_]` characters or
 * the text boundaries (core spec 3.12 step 4).
 */
function containsWord(text: string, word: string): boolean {
  if (word.length === 0) return false;
  const isWordChar = (ch: string | undefined): boolean =>
    ch != null && /[A-Za-z0-9_]/.test(ch);

  let start = 0;
  for (;;) {
    const at = text.indexOf(word, start);
    if (at < 0) return false;
    const end = at + word.length;
    const beforeOk = at === 0 || !isWordChar(text[at - 1]);
    const afterOk = end === text.length || !isWordChar(text[end]);
    if (beforeOk && afterOk) return true;
    start = at + 1;
  }
}

// ---------------------------------------------------------------------------
// Posture and origins
// ---------------------------------------------------------------------------

function resolvePosture(
  spec: HushSpec,
  matchedProfile: OriginProfile | undefined,
  posture: PostureContext | undefined,
): PostureResult | undefined {
  const postureExtension = spec.extensions?.posture;
  if (postureExtension == null) return undefined;

  const current = matchedProfile?.posture ?? posture?.current ?? postureExtension.initial;

  const rawSignal = posture?.signal;
  const signal = rawSignal != null && rawSignal !== 'none' ? rawSignal : undefined;
  const next = signal != null
    ? nextPostureState(postureExtension, current, signal) ?? current
    : current;

  return { current, next };
}

function nextPostureState(
  posture: PostureExtension,
  current: string,
  signal: string,
): string | undefined {
  // D18 (pending): first matching transition in document order.
  for (const transition of posture.transitions ?? []) {
    if (transition.from !== '*' && transition.from !== current) continue;
    if (transition.on !== signal) continue;
    return transition.to;
  }
  return undefined;
}

/**
 * Origin profile selection (origins spec Section 3): candidates are profiles
 * with a `match` object every present field of which is satisfied; a
 * `space_id` match wins outright, then the greatest matched-field count, then
 * document order.
 */
function selectOriginProfile(
  spec: HushSpec,
  origin: OriginContext | undefined,
): OriginProfile | undefined {
  if (origin == null) return undefined;
  const profiles = spec.extensions?.origins?.profiles;
  if (profiles == null) return undefined;

  let bestCount = -1;
  let best: OriginProfile | undefined;
  for (const profile of profiles) {
    const rules = profile.match;
    if (rules == null) continue;
    const matchedFields = matchOrigin(rules, origin);
    if (matchedFields == null) continue;
    if (rules.space_id != null) {
      return profile;
    }
    if (matchedFields > bestCount) {
      bestCount = matchedFields;
      best = profile;
    }
  }
  return best;
}

/**
 * Number of `match` fields satisfied by `origin`, or `undefined` when any
 * present field is not satisfied. `tags` counts as one field.
 */
function matchOrigin(rules: OriginMatch, origin: OriginContext): number | undefined {
  let count = 0;
  const stringFields: Array<[string | undefined, string | undefined]> = [
    [rules.provider, origin.provider],
    [rules.tenant_id, origin.tenant_id],
    [rules.space_id, origin.space_id],
    [rules.space_type, origin.space_type],
    [rules.visibility, origin.visibility],
    [rules.sensitivity, origin.sensitivity],
    [rules.actor_role, origin.actor_role],
  ];
  for (const [expected, actual] of stringFields) {
    if (expected == null) continue;
    if (actual !== expected) return undefined;
    count += 1;
  }

  if (rules.external_participants != null) {
    if (origin.external_participants !== rules.external_participants) return undefined;
    count += 1;
  }

  if (rules.tags != null && rules.tags.length > 0) {
    const originTags = origin.tags ?? [];
    if (!rules.tags.every(tag => originTags.includes(tag))) return undefined;
    count += 1;
  }

  return count;
}

/** Capability the posture guard requires per action type (posture spec 3.3). */
function requiredCapability(actionType: string): string | undefined {
  switch (actionType) {
    case 'file_read': return 'file_access';
    case 'file_write': return 'file_write';
    case 'patch_apply': return 'patch';
    case 'shell_command': return 'shell';
    case 'tool_call': return 'tool_call';
    case 'egress': return 'egress';
    case 'custom': return 'custom';
    default: return undefined;
  }
}

// ---------------------------------------------------------------------------
// Path globs (core spec 3.14.1)
// ---------------------------------------------------------------------------

/**
 * Normalize a filesystem path for matching: NFC, `\` to `/`, collapsed
 * separators, lexical `.`/`..` resolution, no trailing `/`.
 */
export function normalizePath(target: string): string {
  const unified = target.normalize('NFC').replace(/\\/g, '/');
  const absolute = unified.startsWith('/');
  const segments: string[] = [];
  for (const segment of unified.split('/')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      const last = segments[segments.length - 1];
      if (last != null && last !== '..') {
        segments.pop();
      } else if (!absolute) {
        segments.push('..');
      }
      continue;
    }
    segments.push(segment);
  }
  const joined = segments.join('/');
  return absolute ? `/${joined}` : joined;
}

/** Escape one character for use as a literal in a `u`-flagged RegExp source. */
function regexEscape(ch: string): string {
  return /[.*+?^${}()|[\]\\/]/.test(ch) ? `\\${ch}` : ch;
}

/**
 * Compiled-glob caches. Bounded so a process that hot-reloads many distinct
 * policies cannot accumulate compiled patterns without limit; on overflow the
 * cache is cleared rather than grown.
 */
const MAX_COMPILED_PATTERN_CACHE = 4096;

function cachePut<K, V>(cache: Map<K, V>, key: K, value: V): V {
  if (cache.size >= MAX_COMPILED_PATTERN_CACHE) {
    cache.clear();
  }
  cache.set(key, value);
  return value;
}

const pathGlobCache = new Map<string, RegExp | undefined>();

/** Compile a path glob (core spec 3.14.1) into an anchored regex. */
function pathGlobRegex(pattern: string): RegExp | undefined {
  const cached = pathGlobCache.get(pattern);
  if (cached !== undefined || pathGlobCache.has(pattern)) return cached;

  const chars = Array.from(pattern.normalize('NFC'));
  let source = '^';
  let index = 0;
  while (index < chars.length) {
    const ch = chars[index];
    if (ch === '*' && chars[index + 1] === '*') {
      const atSegmentStart = index === 0 || chars[index - 1] === '/';
      if (atSegmentStart && chars[index + 2] === '/') {
        // `**/`: zero or more complete leading segments.
        source += '(?:[^/]*/)*';
        index += 3;
      } else {
        // The reference engine's `.` excludes only `\n`; JavaScript's `.`
        // additionally excludes `\r`, U+2028 and U+2029, so spell it out.
        source += '[^\\n]*';
        index += 2;
      }
      continue;
    }
    if (ch === '*') {
      source += '[^/]*';
    } else if (ch === '?') {
      source += '[^/]';
    } else {
      source += regexEscape(ch);
    }
    index += 1;
  }
  source += '$';

  let compiled: RegExp | undefined;
  try {
    compiled = new RegExp(source, 'u');
  } catch {
    compiled = undefined;
  }
  return cachePut(pathGlobCache, pattern, compiled);
}

/** Whether `path` (already normalized) matches the path glob `pattern`. */
export function pathGlobMatches(pattern: string, path: string): boolean {
  const regex = pathGlobRegex(pattern);
  return regex != null && regex.test(path);
}

function anyPathGlobMatches(patterns: string[] | undefined, path: string): boolean {
  if (patterns == null) return false;
  return patterns.some(pattern => pathGlobMatches(pattern, path));
}

/**
 * Match a raw path target against a path glob, normalizing the target first.
 * Kept for callers outside the evaluator; prefer {@link pathGlobMatches} with
 * an already-normalized path.
 */
export function globMatches(pattern: string, target: string): boolean {
  return pathGlobMatches(pattern, normalizePath(target));
}

// ---------------------------------------------------------------------------
// Host patterns (core spec 3.14.2)
// ---------------------------------------------------------------------------

function isAscii(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) > 127) return false;
  }
  return true;
}

function asciiLowercase(value: string): string {
  let out = '';
  for (const ch of value) {
    const code = ch.charCodeAt(0);
    out += code >= 65 && code <= 90 && ch.length === 1 ? String.fromCharCode(code + 32) : ch;
  }
  return out;
}

/**
 * Reduce an egress target (host, `host:port`, or URL) to a normalized host.
 * Returns `undefined` when the target cannot be reduced to a syntactically
 * valid host, in which case it matches nothing.
 */
export function normalizeHost(target: string): string | undefined {
  const trimmed = target.trim();
  const schemeIndex = trimmed.indexOf('://');
  let authority = schemeIndex >= 0 ? trimmed.slice(schemeIndex + 3) : trimmed;
  const end = firstIndexOfAny(authority, ['/', '?', '#']);
  authority = end >= 0 ? authority.slice(0, end) : authority;
  const at = authority.lastIndexOf('@');
  if (at >= 0) {
    authority = authority.slice(at + 1);
  }
  if (authority.length === 0) return undefined;

  if (authority.startsWith('[')) {
    const rest = authority.slice(1);
    const close = rest.indexOf(']');
    if (close < 0) return undefined;
    const inner = rest.slice(0, close);
    if (inner.length === 0 || !/^[0-9A-Fa-f:.]+$/.test(inner)) return undefined;
    return `[${asciiLowercase(inner)}]`;
  }

  let host = authority;
  const colon = host.lastIndexOf(':');
  if (colon >= 0) {
    const port = host.slice(colon + 1);
    if (port.length > 0 && /^[0-9]+$/.test(port)) {
      host = host.slice(0, colon);
    }
  }
  if (host.includes(':')) return undefined;
  if (host.endsWith('.')) {
    host = host.slice(0, -1);
  }
  if (host.length === 0) return undefined;

  const labels: string[] = [];
  for (const label of host.split('.')) {
    if (label.length === 0) return undefined;
    const normalized = normalizeHostLabel(label);
    if (normalized == null) return undefined;
    labels.push(normalized);
  }
  const normalized = labels.join('.');
  if (!/^[A-Za-z0-9\-._]*$/.test(normalized)) return undefined;
  return normalized;
}

function firstIndexOfAny(value: string, needles: string[]): number {
  let best = -1;
  for (const needle of needles) {
    const index = value.indexOf(needle);
    if (index >= 0 && (best < 0 || index < best)) best = index;
  }
  return best;
}

/**
 * Normalize one host label: ASCII lowercase, or the IDNA A-label (punycode)
 * of the NFC-normalized, lowercased label when it is not ASCII.
 */
function normalizeHostLabel(label: string): string | undefined {
  if (isAscii(label)) {
    return asciiLowercase(label);
  }
  const folded = label.toLowerCase().normalize('NFC');
  if (isAscii(folded)) {
    return folded;
  }
  const encoded = punycodeEncode(folded);
  return encoded != null ? `xn--${encoded}` : undefined;
}

/** Normalize a host pattern (steps 5-7 of core spec 3.14.2), preserving `*`. */
function normalizeHostPattern(pattern: string): string {
  let normalized = pattern.trim();
  if (normalized.endsWith('.')) {
    normalized = normalized.slice(0, -1);
  }
  if (normalized.startsWith('[')) {
    return asciiLowercase(normalized);
  }
  return normalized
    .split('.')
    .map(label => (isAscii(label)
      ? asciiLowercase(label)
      : normalizeHostLabel(label) ?? label.toLowerCase()))
    .join('.');
}

function isIpv4Literal(host: string): boolean {
  const octets = host.split('.');
  return octets.length === 4
    && octets.every(octet =>
      octet.length > 0
      && octet.length <= 3
      && /^[0-9]+$/.test(octet)
      && Number(octet) <= 255);
}

function isIpLiteral(host: string): boolean {
  return host.startsWith('[') || isIpv4Literal(host);
}

const hostPatternCache = new Map<string, RegExp | undefined>();

/**
 * Whether a normalized host matches a host pattern (core spec 3.14.2): `*` is
 * one or more non-dot characters, `**` one or more characters including dots,
 * everything else literal. IP literals match only exactly.
 */
export function hostPatternMatches(pattern: string, host: string): boolean {
  const normalizedPattern = normalizeHostPattern(pattern);
  if (isIpLiteral(host)) {
    return normalizedPattern === host;
  }

  let regex = hostPatternCache.get(normalizedPattern);
  if (regex === undefined && !hostPatternCache.has(normalizedPattern)) {
    let source = '^';
    const chars = Array.from(normalizedPattern);
    let index = 0;
    while (index < chars.length) {
      if (chars[index] === '*') {
        if (chars[index + 1] === '*') {
          // Reference `.` excludes only `\n`; spell it out for JS parity.
          source += '[^\\n]+';
          index += 2;
        } else {
          source += '[^.]+';
          index += 1;
        }
        continue;
      }
      source += regexEscape(chars[index]);
      index += 1;
    }
    source += '$';
    try {
      regex = new RegExp(source, 'u');
    } catch {
      regex = undefined;
    }
    cachePut(hostPatternCache, normalizedPattern, regex);
  }
  return regex != null && regex.test(host);
}

function anyHostPatternMatches(patterns: string[] | undefined, host: string | undefined): boolean {
  if (host == null || patterns == null) return false;
  return patterns.some(pattern => hostPatternMatches(pattern, host));
}

/** RFC 3492 punycode encoding of one label (without the `xn--` prefix). */
export function punycodeEncode(input: string): string | undefined {
  const BASE = 36;
  const TMIN = 1;
  const TMAX = 26;
  const SKEW = 38;
  const DAMP = 700;
  const INITIAL_BIAS = 72;
  const INITIAL_N = 128;
  const MAX_U32 = 0xffffffff;

  const adapt = (delta: number, numPoints: number, firstTime: boolean): number => {
    let d = Math.floor(firstTime ? delta / DAMP : delta / 2);
    d += Math.floor(d / numPoints);
    let k = 0;
    while (d > Math.floor(((BASE - TMIN) * TMAX) / 2)) {
      d = Math.floor(d / (BASE - TMIN));
      k += BASE;
    }
    return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
  };

  const digit = (value: number): string =>
    value < 26
      ? String.fromCharCode(0x61 + value)
      : String.fromCharCode(0x30 + (value - 26));

  const codePoints = Array.from(input).map(ch => ch.codePointAt(0) as number);
  const output: string[] = [];
  for (const cp of codePoints) {
    if (cp < 128) output.push(String.fromCharCode(cp));
  }
  const basicCount = output.length;
  let handled = basicCount;
  if (basicCount > 0) {
    output.push('-');
  }

  let n = INITIAL_N;
  let delta = 0;
  let bias = INITIAL_BIAS;
  while (handled < codePoints.length) {
    let m = Number.POSITIVE_INFINITY;
    for (const cp of codePoints) {
      if (cp >= n && cp < m) m = cp;
    }
    if (!Number.isFinite(m)) return undefined;
    delta += (m - n) * (handled + 1);
    if (delta > MAX_U32) return undefined;
    n = m;
    for (const cp of codePoints) {
      if (cp < n) {
        delta += 1;
        if (delta > MAX_U32) return undefined;
      }
      if (cp === n) {
        let q = delta;
        let k = BASE;
        for (;;) {
          const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
          if (q < t) break;
          output.push(digit(t + ((q - t) % (BASE - t))));
          q = Math.floor((q - t) / (BASE - t));
          k += BASE;
        }
        output.push(digit(q));
        bias = adapt(delta, handled + 1, handled === basicCount);
        delta = 0;
        handled += 1;
      }
    }
    delta += 1;
    n += 1;
    if (delta > MAX_U32 || n > MAX_U32) return undefined;
  }

  return output.join('');
}

// ---------------------------------------------------------------------------
// Patch statistics
// ---------------------------------------------------------------------------

function patchStats(content: string): PatchStats {
  let additions = 0;
  let deletions = 0;

  for (const line of splitLines(content)) {
    if (line.startsWith('+++') || line.startsWith('---')) continue;
    if (line.startsWith('+')) {
      additions += 1;
    } else if (line.startsWith('-')) {
      deletions += 1;
    }
  }

  return { additions, deletions };
}

/**
 * Mirrors Rust's `str::lines`: split on `\n`, drop a trailing `\r`, and treat a
 * trailing newline as a terminator rather than producing a final empty line.
 */
function splitLines(content: string): string[] {
  if (content.length === 0) return [];
  const parts = content.split('\n');
  if (parts[parts.length - 1] === '') parts.pop();
  return parts.map(line => (line.endsWith('\r') ? line.slice(0, -1) : line));
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

// ---------------------------------------------------------------------------
// Panic protocol
// ---------------------------------------------------------------------------

let panicActive = false;
const PANIC_POLICY_YAML = `hushspec: "0.2.0"
name: "__hushspec_panic__"
description: "Emergency deny-all policy. Activated by panic mode."

rules:
  forbidden_paths:
    enabled: true
    patterns:
      - "**"
    exceptions: []

  egress:
    enabled: true
    allow: []
    block:
      - "*"
    default: block

  shell_commands:
    enabled: true
    forbidden_patterns:
      - ".*"

  tool_access:
    enabled: true
    allow: []
    block:
      - "*"
    require_confirmation: []
    default: block

  computer_use:
    enabled: true
    mode: fail_closed
    allowed_actions: []

  input_injection:
    enabled: true
    allowed_types: []
`;

export function activatePanic(): void {
  panicActive = true;
}

export function deactivatePanic(): void {
  panicActive = false;
}

export function isPanicActive(): boolean {
  return panicActive;
}

export function panicPolicy(): HushSpec {
  return parseOrThrow(PANIC_POLICY_YAML);
}
