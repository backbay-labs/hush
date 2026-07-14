import type { HushSpec } from './schema.js';
import type { EvaluationAction, EvaluationResult } from './evaluate.js';
import { evaluate, isPanicActive } from './evaluate.js';
import { parse } from './parse.js';
import { readFileSync } from 'node:fs';
import type { PolicyProvider } from './policy-provider.js';
import type { EvaluationObserver } from './observer.js';
import { ObservableEvaluator } from './observer.js';
import type { AuditConfig, DecisionReceipt, EnforcementMode, EnforcementSummary } from './receipt.js';
import { computePolicyHash, DEFAULT_AUDIT_CONFIG, evaluateAudited } from './receipt.js';
import type { ReceiptSink } from './sinks.js';
import { EXTENSION_KEYS_SET, RULE_KEYS_SET } from './generated/contract.js';

export type WarnHandler = (result: EvaluationResult, action: EvaluationAction) => boolean;

export interface EnforcementConfig {
  /** Guard-level mode. Default: 'enforce' (existing behavior). */
  mode?: EnforcementMode;
  /** Rule-path prefix -> mode. Longest matching prefix wins over `mode`. */
  overrides?: Record<string, EnforcementMode>;
}

export interface GateOutcome {
  result: EvaluationResult;
  proceed: boolean;
  enforcement: EnforcementSummary;
}

export interface HushGuardOptions {
  onWarn?: WarnHandler;
  observer?: EvaluationObserver;
  provider?: PolicyProvider;
  enforcement?: EnforcementConfig;
  sink?: ReceiptSink;
  audit?: AuditConfig;
}

const ENFORCEMENT_MODES: ReadonlySet<string> = new Set(['enforce', 'monitor']);

/**
 * True when `matchedRule` equals `key` or continues past it at a segment
 * boundary ('.' or '['). Exported for direct unit testing.
 */
export function matchesRulePathPrefix(matchedRule: string, key: string): boolean {
  if (matchedRule === key) return true;
  return matchedRule.startsWith(key + '.') || matchedRule.startsWith(key + '[');
}

function validateEnforcementConfig(config: EnforcementConfig, observable: boolean): void {
  const mode = config.mode ?? 'enforce';
  if (!ENFORCEMENT_MODES.has(mode)) {
    throw new Error(`invalid enforcement mode: ${String(config.mode)}`);
  }
  let monitorReachable = mode === 'monitor';
  for (const [key, value] of Object.entries(config.overrides ?? {})) {
    if (!ENFORCEMENT_MODES.has(value)) {
      throw new Error(`invalid enforcement mode for override '${key}': ${String(value)}`);
    }
    if (value === 'monitor') monitorReachable = true;
    if (key.startsWith('rules.')) {
      const segment = key.split('.')[1] ?? '';
      if (!RULE_KEYS_SET.has(segment)) {
        throw new Error(
          `unknown rule in enforcement override '${key}': '${segment}' is not a core rule`,
        );
      }
    } else if (key.startsWith('extensions.')) {
      const segment = key.split('.')[1] ?? '';
      // Only the top extension segment (posture/origins/detection) is validated
      // here; deeper segments are policy-dependent and hot-swappable, mirroring
      // how 'rules.' overrides only validate their top segment.
      if (!EXTENSION_KEYS_SET.has(segment)) {
        throw new Error(
          `unknown extension in enforcement override '${key}': '${segment}' is not a core extension`,
        );
      }
    } else {
      throw new Error(
        `enforcement override keys must start with 'rules.' or 'extensions.': '${key}'`,
      );
    }
  }
  if (monitorReachable && !observable) {
    throw new Error(
      'monitor mode requires an observer or a receipt sink: shadow decisions would be unobservable',
    );
  }
}

/** Fail-closed: warn decisions without an onWarn handler are treated as deny. */
export class HushGuard {
  private policy: HushSpec;
  private onWarn: WarnHandler;
  private observableEvaluator: ObservableEvaluator | null = null;
  private policyHash: string | null = null;
  private provider: PolicyProvider | null = null;
  private enforcementMode: EnforcementMode = 'enforce';
  private enforcementOverrides: Record<string, EnforcementMode> = {};
  private sink: ReceiptSink | null = null;
  private audit: AuditConfig = DEFAULT_AUDIT_CONFIG;

  constructor(policy: HushSpec, options?: HushGuardOptions) {
    const enforcementConfig = options?.enforcement ?? {};
    validateEnforcementConfig(
      enforcementConfig,
      options?.observer != null || options?.sink != null,
    );
    this.enforcementMode = enforcementConfig.mode ?? 'enforce';
    this.enforcementOverrides = { ...(enforcementConfig.overrides ?? {}) };
    this.sink = options?.sink ?? null;
    this.audit = options?.audit ?? DEFAULT_AUDIT_CONFIG;
    this.policy = policy;
    this.onWarn = options?.onWarn ?? (() => false);
    this.provider = options?.provider ?? null;
    if (options?.observer) {
      this.observableEvaluator = new ObservableEvaluator();
      this.observableEvaluator.addObserver(options.observer);
      this.policyHash = computePolicyHash(policy);
      this.observableEvaluator.notifyPolicyLoaded(policy.name, this.policyHash);
    }
  }

  static fromFile(path: string, options?: HushGuardOptions): HushGuard {
    const content = readFileSync(path, 'utf8');
    const result = parse(content);
    if (!result.ok) {
      throw new Error(`Failed to parse policy: ${result.error}`);
    }
    return new HushGuard(result.value, options);
  }

  static fromYaml(yaml: string, options?: HushGuardOptions): HushGuard {
    const result = parse(yaml);
    if (!result.ok) {
      throw new Error(`Failed to parse policy: ${result.error}`);
    }
    return new HushGuard(result.value, options);
  }

  static async fromProvider(
    provider: PolicyProvider,
    options?: HushGuardOptions,
  ): Promise<HushGuard> {
    const spec = await provider.load();
    const guard = new HushGuard(spec, { ...options, provider });
    provider.watch((newSpec) => guard.swapPolicy(newSpec));
    return guard;
  }

  evaluate(action: EvaluationAction): EvaluationResult {
    const policy = this.activePolicyResult();
    if ('decision' in policy) {
      return policy;
    }
    if (this.sink) {
      const { result, durationUs, receipt } = this.runEvaluation(policy, action);
      if (receipt) {
        try {
          this.sink.send(receipt);
        } catch {
          /* sinks must not break evaluation */
        }
      }
      this.observableEvaluator?.notifyEvaluationCompleted(
        this.observerAction(action),
        result,
        durationUs,
        undefined,
        receipt,
      );
      return result;
    }
    if (this.observableEvaluator) {
      return this.observableEvaluator.evaluate(policy, action, this.observerAction(action));
    }
    return evaluate(policy, action);
  }

  check(action: EvaluationAction): boolean {
    return this.gate(action).proceed;
  }

  enforce(action: EvaluationAction): void {
    const outcome = this.gate(action);
    if (!outcome.proceed) {
      throw new HushSpecDenied(outcome.result);
    }
  }

  /**
   * Evaluate an action, resolve the effective enforcement mode, record the
   * outcome, and report whether execution may proceed. The single
   * enforcement path: check() and enforce() delegate here.
   */
  gate(action: EvaluationAction): GateOutcome {
    const policy = this.activePolicyResult();
    if ('decision' in policy) {
      // Provider-failure deny: no loaded policy, so no receipt can be built,
      // but the decision must still be audited — a monitored provider outage
      // must never proceed silently. record() emits the observer event even
      // with an undefined receipt (a sink-only guard has nothing to send).
      const mode = this.effectiveMode(policy);
      const proceed = mode === 'monitor';
      const enforcement: EnforcementSummary = {
        mode,
        outcome: proceed ? 'would_block' : 'blocked',
      };
      this.record(action, policy, 0, enforcement, undefined);
      return { result: policy, proceed, enforcement };
    }

    const { result, durationUs, receipt } = this.runEvaluation(policy, action);
    const mode = this.effectiveMode(result);
    let proceed: boolean;
    let outcome: EnforcementSummary['outcome'];
    switch (result.decision) {
      case 'allow':
        proceed = true;
        outcome = 'allowed';
        break;
      case 'warn':
        if (mode === 'monitor') {
          proceed = true;
          outcome = 'would_block';
        } else if (this.onWarn(result, action)) {
          proceed = true;
          outcome = 'confirmed';
        } else {
          proceed = false;
          outcome = 'blocked';
        }
        break;
      case 'deny':
        proceed = mode === 'monitor';
        outcome = proceed ? 'would_block' : 'blocked';
        break;
    }

    const enforcement: EnforcementSummary = { mode, outcome };
    this.record(action, result, durationUs, enforcement, receipt);
    return { result, proceed, enforcement };
  }

  private effectiveMode(result: EvaluationResult): EnforcementMode {
    if (isPanicActive() || result.matched_rule === '__hushspec_panic__') {
      return 'enforce';
    }
    let matched = result.matched_rule;
    // detection.ts emits the bare literal 'detection' as matched_rule rather
    // than a hierarchical rule path (see packages/hushspec/src/detection.ts),
    // so an override keyed 'extensions.detection' would otherwise silently
    // never match. Normalize before prefix matching.
    if (matched === 'detection') {
      matched = 'extensions.detection';
    }
    if (matched != null) {
      let bestKey: string | undefined;
      let bestMode: EnforcementMode | undefined;
      for (const [key, mode] of Object.entries(this.enforcementOverrides)) {
        if (matchesRulePathPrefix(matched, key) && (bestKey == null || key.length > bestKey.length)) {
          bestKey = key;
          bestMode = mode;
        }
      }
      if (bestMode != null) return bestMode;
    }
    return this.enforcementMode;
  }

  private runEvaluation(policy: HushSpec, action: EvaluationAction): {
    result: EvaluationResult;
    durationUs: number;
    receipt?: DecisionReceipt;
  } {
    if (this.sink) {
      const receipt = evaluateAudited(policy, action, this.audit);
      return {
        result: {
          decision: receipt.decision,
          matched_rule: receipt.matched_rule,
          reason: receipt.reason,
          origin_profile: receipt.origin_profile,
          posture: receipt.posture,
        },
        durationUs: receipt.evaluation_duration_us,
        receipt,
      };
    }
    const start = performance.now();
    const result = evaluate(policy, action);
    const durationUs = Math.round((performance.now() - start) * 1000);
    return { result, durationUs };
  }

  private record(
    action: EvaluationAction,
    result: EvaluationResult,
    durationUs: number,
    enforcement: EnforcementSummary,
    receipt?: DecisionReceipt,
  ): void {
    if (receipt) {
      receipt.enforcement = enforcement;
      if (this.sink) {
        try {
          this.sink.send(receipt);
        } catch {
          /* sinks must not break enforcement */
        }
      }
    }
    this.observableEvaluator?.notifyEvaluationCompleted(
      this.observerAction(action),
      result,
      durationUs,
      enforcement,
      receipt,
    );
  }

  /**
   * Redact an action for observer emission the same way the receipt redacts it:
   * when `redact_content` is enabled and content is present, strip the content
   * and set the redacted flag so raw content never leaks into the observer stream.
   */
  private observerAction(action: EvaluationAction): EvaluationAction {
    if (this.audit.redact_content && action.content != null) {
      const { content: _content, ...rest } = action;
      return { ...rest, content_redacted: true };
    }
    return action;
  }

  static mapToolCall(toolName: string, args?: Record<string, unknown>): EvaluationAction {
    return {
      type: 'tool_call',
      target: toolName,
      args_size: args ? JSON.stringify(args).length : undefined,
    };
  }

  static mapFileRead(path: string): EvaluationAction {
    return { type: 'file_read', target: path };
  }

  static mapFileWrite(path: string, content?: string): EvaluationAction {
    return { type: 'file_write', target: path, content };
  }

  static mapEgress(domain: string): EvaluationAction {
    return { type: 'egress', target: domain };
  }

  static mapShellCommand(command: string): EvaluationAction {
    return { type: 'shell_command', target: command };
  }

  swapPolicy(newPolicy: HushSpec): void {
    const previousHash = this.policyHash;
    this.policy = newPolicy;
    if (this.observableEvaluator) {
      this.policyHash = computePolicyHash(newPolicy);
      this.observableEvaluator.notifyPolicyReloaded(
        newPolicy.name,
        this.policyHash,
        previousHash ?? undefined,
      );
    }
  }

  private activePolicyResult(): HushSpec | EvaluationResult {
    if (this.provider == null) {
      return this.policy;
    }

    try {
      const current = this.provider.current();
      if (current == null) {
        return {
          decision: 'deny',
          matched_rule: '__hushspec_policy_provider__',
          reason: 'policy provider has not loaded a policy yet',
        };
      }
      this.policy = current;
      return current;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        decision: 'deny',
        matched_rule: '__hushspec_policy_provider__',
        reason: `policy provider unavailable: ${message}`,
      };
    }
  }
}

export class HushSpecDenied extends Error {
  public readonly result: EvaluationResult;

  constructor(result: EvaluationResult) {
    super(`Action denied: ${result.reason ?? result.matched_rule ?? 'policy denial'}`);
    this.name = 'HushSpecDenied';
    this.result = result;
  }
}
