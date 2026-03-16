import type { HushSpec } from './schema.js';
import type { EvaluationAction, EvaluationResult } from './evaluate.js';
import { evaluate } from './evaluate.js';
import { parse } from './parse.js';
import { readFileSync } from 'node:fs';
import type { PolicyProvider } from './policy-provider.js';
import type { EvaluationObserver } from './observer.js';
import { ObservableEvaluator } from './observer.js';
import { computePolicyHash } from './receipt.js';

export type WarnHandler = (result: EvaluationResult, action: EvaluationAction) => boolean;

/** Fail-closed: warn decisions without an onWarn handler are treated as deny. */
export class HushGuard {
  private policy: HushSpec;
  private onWarn: WarnHandler;
  private observableEvaluator: ObservableEvaluator | null = null;
  private policyHash: string | null = null;
  private provider: PolicyProvider | null = null;

  constructor(policy: HushSpec, options?: {
    onWarn?: WarnHandler;
    observer?: EvaluationObserver;
    provider?: PolicyProvider;
  }) {
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

  static fromFile(path: string, options?: { onWarn?: WarnHandler }): HushGuard {
    const content = readFileSync(path, 'utf8');
    const result = parse(content);
    if (!result.ok) {
      throw new Error(`Failed to parse policy: ${result.error}`);
    }
    return new HushGuard(result.value, options);
  }

  static fromYaml(yaml: string, options?: { onWarn?: WarnHandler }): HushGuard {
    const result = parse(yaml);
    if (!result.ok) {
      throw new Error(`Failed to parse policy: ${result.error}`);
    }
    return new HushGuard(result.value, options);
  }

  static async fromProvider(
    provider: PolicyProvider,
    options?: { onWarn?: WarnHandler },
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
