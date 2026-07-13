import type { HushSpec } from './schema.js';
import type { EvaluationAction, EvaluationResult } from './evaluate.js';
import { evaluate } from './evaluate.js';
import { parse } from './parse.js';
import { readFileSync } from 'node:fs';
import type { PolicyProvider } from './policy-provider.js';
import type { EvaluationObserver } from './observer.js';
import { ObservableEvaluator } from './observer.js';
import { computePolicyHash } from './receipt.js';
import type { EnforcementMode } from './receipt.js';
import { RULE_KEYS_SET } from './generated/contract.js';

export type WarnHandler = (result: EvaluationResult, action: EvaluationAction) => boolean;

export interface EnforcementConfig {
  /** Guard-level mode. Default: 'enforce' (existing behavior). */
  mode?: EnforcementMode;
  /** Rule-path prefix -> mode. Longest matching prefix wins over `mode`. */
  overrides?: Record<string, EnforcementMode>;
}

export interface HushGuardOptions {
  onWarn?: WarnHandler;
  observer?: EvaluationObserver;
  provider?: PolicyProvider;
  enforcement?: EnforcementConfig;
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
    } else if (!key.startsWith('extensions.')) {
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

  constructor(policy: HushSpec, options?: HushGuardOptions) {
    const enforcementConfig = options?.enforcement ?? {};
    validateEnforcementConfig(enforcementConfig, options?.observer != null);
    this.enforcementMode = enforcementConfig.mode ?? 'enforce';
    this.enforcementOverrides = { ...(enforcementConfig.overrides ?? {}) };
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
    if (this.observableEvaluator) {
      return this.observableEvaluator.evaluate(policy, action);
    }
    return evaluate(policy, action);
  }

  check(action: EvaluationAction): boolean {
    const result = this.evaluate(action);
    if (result.decision === 'allow') return true;
    if (result.decision === 'warn') return this.onWarn(result, action);
    return false;
  }

  enforce(action: EvaluationAction): void {
    const result = this.evaluate(action);
    if (result.decision === 'deny') {
      throw new HushSpecDenied(result);
    }
    if (result.decision === 'warn' && !this.onWarn(result, action)) {
      throw new HushSpecDenied(result);
    }
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
