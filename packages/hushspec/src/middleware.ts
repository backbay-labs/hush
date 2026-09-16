import { createHash } from 'node:crypto';
import type { HushSpec } from './schema.js';
import type { EvaluationAction, EvaluationResult } from './evaluate.js';
import type { CompiledPolicy } from './compiled.js';
import { compiledForResolution } from './compiled.js';
import { isPanicActive } from './evaluate.js';
import { parse } from './parse.js';
import { readFileSync, realpathSync } from 'node:fs';
import nodePath from 'node:path';
import type { Loader, ResolveOptions, Resolution, SignatureStatus } from './resolve.js';
import {
  PolicyVerificationError,
  createBuiltinLoader,
  createCompositeLoader,
  resolutionFromResolved,
  resolveWithOptions,
} from './resolve.js';
import { Keyring, keyringFromPublicKey } from './signing.js';
import type { PolicyProvider } from './policy-provider.js';
import type { EvaluationObserver } from './observer.js';
import { ObservableEvaluator } from './observer.js';
import type {
  Actor,
  AuditConfig,
  AuditContext,
  DecisionReceipt,
  EnforcementMode,
  EnforcementSummary,
  PolicySummary,
  TimeSource,
} from './receipt.js';
import {
  POLICY_UNVERIFIED_RULE,
  DEFAULT_AUDIT_CONFIG,
  RECEIPT_VERSION,
  formatTimestamp,
  impliedEnforcement,
  policySummary,
  unverifiedPolicyReceipt,
  uuidV7,
} from './receipt.js';
import { argsSize } from './adapters/tool-mapping.js';
import type { PolicyEvent } from './log.js';
import { policyLoadedEvent, policySwappedEvent } from './log.js';
import type { ReceiptSink } from './sinks.js';
import { EXTENSION_KEYS_SET, RULE_KEYS_SET } from './generated/contract.js';
import { utf8ByteLength } from './utf8.js';

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
  /**
   * Who actions are evaluated for (Receipt specification section 4.1). An
   * enforcement point SHOULD populate every field it knows; receipts omit the
   * member entirely when nothing is set.
   */
  actor?: Actor;
  /** How much to trust the receipt clock (receipt spec 3.3). Default `system`. */
  timeSource?: TimeSource;
  /**
   * Loader for `extends` references. Defaults to builtin-only (or the
   * builtin+filesystem composite loader when `baseDir` is set).
   */
  loader?: Loader;
  /**
   * Directory that relative `extends` references resolve against.
   * `HushGuard.fromFile()` defaults it to the policy file's directory.
   */
  baseDir?: string;
  /**
   * The policy's own identity: the leaf's `source` in `resolution.chain`, and
   * where the default locator looks for its `.sig`. `fromFile()` sets it to
   * the policy's real path; a YAML string has none and is reported as
   * `<inline>`.
   */
  source?: string;
  /**
   * Refuse to evaluate unless every non-`builtin:` hop of the `extends` chain
   * is pinned by digest or validly signed (Signing specification section 6.5).
   * Needs `keyring` or `trustedKeys`.
   */
  requireSignature?: boolean;
  /** Trusted keys. Mutually exclusive with `trustedKeys`. */
  keyring?: Keyring;
  /** SPKI PEM public keys, assembled into a keyring. */
  trustedKeys?: readonly string[];
  /** Clock and rollback parameters for signature verification. */
  verify?: ResolveOptions['verify'];
  /**
   * An already-verified {@link Resolution} to adopt instead of resolving
   * again. `fromProvider()` uses it to carry the provider's own verified load
   * into the guard: re-resolving there would hand the resolver a document that
   * no longer has a source to find a signature next to.
   */
  resolution?: Resolution;
}

/**
 * `matched_rule` for every denial issued by a guard that refused its policy:
 * the receipt spec's reserved `__hushspec_policy_unverified__`, used both in
 * the in-memory result and in the receipt.
 *
 * Distinct from `__hushspec_policy_provider__` (the policy could not be
 * *obtained*) because this one means the policy was obtained and rejected --
 * the receipt has to be able to say which.
 */
export const POLICY_SIGNATURE_RULE: string = POLICY_UNVERIFIED_RULE;

/** The policy-loading half of {@link HushGuardOptions}. */
export type PolicyResolveOptions = Pick<
  HushGuardOptions,
  'loader' | 'baseDir' | 'source' | 'requireSignature' | 'keyring' | 'trustedKeys' | 'verify'
>;

/**
 * Build the keyring a guard verifies against. `trustedKeys` is the
 * convenience form -- bare SPKI PEMs, no revocation or retirement -- and a
 * real deployment passes a `keyring` loaded from a keyring document.
 */
function keyringOf(options?: PolicyResolveOptions): Keyring | undefined {
  if (options?.keyring !== undefined && options.trustedKeys !== undefined) {
    throw new Error('pass either `keyring` or `trustedKeys`, not both');
  }
  if (options?.keyring !== undefined) return options.keyring;
  const pems = options?.trustedKeys;
  if (pems === undefined) return undefined;
  if (pems.length === 0) {
    throw new Error('`trustedKeys` is empty: there would be nothing to verify against');
  }
  return new Keyring(pems.flatMap((pem) => keyringFromPublicKey(pem).keys));
}

function resolveOptionsOf(options?: PolicyResolveOptions): ResolveOptions {
  const keyring = keyringOf(options);
  return {
    ...(options?.requireSignature === true ? { requireSignature: true } : {}),
    ...(keyring === undefined ? {} : { keyring }),
    ...(options?.verify === undefined ? {} : { verify: options.verify }),
  };
}

/**
 * Resolve a policy the way a guard must: chain merged, every hop hashed, and
 * whatever the options require verified before the document is usable.
 *
 * @throws {PolicyVerificationError} when a hop fails to prove itself.
 */
export function resolvePolicyResolution(
  policy: HushSpec,
  options?: PolicyResolveOptions,
): Resolution {
  const load =
    options?.loader ?? (options?.baseDir != null ? createCompositeLoader() : createBuiltinLoader());
  // `resolveWithOptions()` treats `source` as the *file* a relative reference
  // is resolved from, so without a real one point it at a placeholder inside
  // baseDir.
  const anchor =
    options?.baseDir != null
      ? nodePath.join(nodePath.resolve(options.baseDir), '<policy>')
      : undefined;
  const source = options?.source ?? anchor;
  // Built before the try: a contradictory key configuration is the caller's
  // mistake, not a chain that would not resolve, and should not be reported
  // as one.
  const resolveOptions = resolveOptionsOf(options);

  try {
    return resolveWithOptions(policy, {
      source,
      loader: anchoredLoader(load, source, anchor),
      options: resolveOptions,
    });
  } catch (error) {
    if (error instanceof PolicyVerificationError || policy.extends == null) {
      throw error;
    }
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to resolve policy 'extends: ${policy.extends}': ${message}`);
  }
}

/**
 * Resolve a policy's `extends` chain, or throw.
 *
 * Every entry point into `HushGuard` funnels through this: the guard must
 * never hold a spec whose `extends` is still set. An unresolved leaf policy
 * silently drops every rule block its base declares -- `library/general/
 * recommended.yaml` extends `builtin:default` and declares no
 * `forbidden_paths`, so evaluating it unresolved would allow reads of
 * `~/.ssh/id_rsa` -- and hashes the wrong document into every receipt.
 * Fail closed: if the base cannot be loaded, no evaluation happens at all.
 */
export function resolvePolicyOrThrow(
  policy: HushSpec,
  options?: PolicyResolveOptions,
): HushSpec {
  if (policy.extends == null) {
    return policy;
  }

  const resolved = resolvePolicyResolution(policy, options).spec;
  if (resolved.extends != null) {
    throw new Error(
      `Failed to resolve policy 'extends: ${policy.extends}': resolver returned an unresolved policy`,
    );
  }
  return resolved;
}

/**
 * Keep `source` and `baseDir` doing their separate jobs.
 *
 * `source` names the policy -- the chain's leaf, and where the default locator
 * looks for its `.sig` -- while `baseDir` says which directory the *leaf's own*
 * relative `extends` resolves against, and a caller may legitimately set it to
 * somewhere other than the policy's own directory. Rewriting `from` for the
 * leaf's reference alone keeps both true; every reference below the leaf
 * already resolves against the file that declared it.
 */
function anchoredLoader(load: Loader, source?: string, anchor?: string): Loader {
  if (anchor === undefined || source === undefined || anchor === source) return load;
  return (reference, from) => load(reference, from === source ? anchor : from);
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

/**
 * Build a receipt for the provider-failure deny/would-block branch in
 * `gate()`, where there is no policy to run `evaluateAudited()` against --
 * only the already-computed `result`.
 *
 * A guard configured with a `sink` but no `observer` (monitor mode accepts
 * either) would otherwise go completely silent on a provider outage, since
 * `record()` forwards to the sink only when a receipt is present. A monitored
 * block is never silent.
 *
 * `policy` is the identity of the guard's last successfully loaded policy; it
 * was never evaluated against `action`, which is the whole point of this path,
 * so `rule_trace` is empty.
 */
function buildFailureReceipt(
  policy: PolicySummary,
  action: EvaluationAction,
  result: EvaluationResult,
  enforcement: EnforcementSummary,
  ctx: AuditContext,
): DecisionReceipt {
  const actor = ctx.actor;
  return {
    receipt_version: RECEIPT_VERSION,
    receipt_id: ctx.receiptId ?? uuidV7(ctx.clock?.getTime()),
    timestamp: formatTimestamp(ctx.clock ?? new Date()),
    time_source: ctx.timeSource ?? 'system',
    ...(actor === undefined ? {} : { actor }),
    policy,
    action: {
      type: action.type,
      ...(action.target === undefined ? {} : { target: action.target }),
      ...(action.content === undefined
        ? {}
        : {
            content_hash: `sha256:${createHash('sha256')
              .update(action.content, 'utf8')
              .digest('hex')}`,
            content_size: utf8ByteLength(action.content),
          }),
      ...(action.args_size === undefined ? {} : { args_size: action.args_size }),
    },
    decision: result.decision,
    ...(result.matched_rule === undefined ? {} : { matched_rule: result.matched_rule }),
    ...(result.reason === undefined ? {} : { reason: result.reason }),
    rule_trace: [],
    enforcement,
  };
}

/**
 * The provider's own resolution for exactly this document, or `undefined`.
 *
 * Identity, not equality: a provider that reloaded between `load()` and this
 * call would otherwise hand back a resolution describing a different document,
 * and the guard would report -- and trust -- the wrong chain.
 */
function resolutionFor(provider: PolicyProvider, spec: HushSpec): Resolution | undefined {
  const resolution = provider.resolution?.();
  return resolution != null && resolution.spec === spec ? resolution : undefined;
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
  private actor: Actor | undefined;
  private timeSource: TimeSource;
  private resolveOptions: PolicyResolveOptions;
  private resolutionValue: Resolution;
  /**
   * The policy in force, compiled. Built once per policy -- at construction,
   * on `swapPolicy()`, and when a provider hands back a document the guard has
   * not seen -- so an action costs a match, never a compile.
   */
  private compiledValue: CompiledPolicy;
  /**
   * Set when verification was required and did not pass. The guard still holds
   * the document it was handed -- so `resolution` and the policy hash report
   * what was loaded -- but every action is denied against it.
   */
  private refusal: { source: string; status: SignatureStatus } | null = null;

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
    this.actor = options?.actor;
    this.timeSource = options?.timeSource ?? 'system';
    this.resolveOptions = {
      loader: options?.loader,
      baseDir: options?.baseDir,
      source: options?.source,
      requireSignature: options?.requireSignature,
      keyring: options?.keyring,
      trustedKeys: options?.trustedKeys,
      verify: options?.verify,
    };
    // Resolve before anything else touches the spec: a guard never holds an
    // unresolved document, and the receipt hash covers the resolved policy.
    const resolution = this.loadResolution(policy, options?.resolution);
    this.policy = resolution.spec;
    this.resolutionValue = resolution;
    this.compiledValue = compiledForResolution(resolution);
    this.onWarn = options?.onWarn ?? (() => false);
    this.provider = options?.provider ?? null;
    this.policyHash = resolution.content_hash;
    if (options?.observer) {
      this.observableEvaluator = new ObservableEvaluator();
      this.observableEvaluator.addObserver(options.observer);
      this.observableEvaluator.notifyPolicyLoaded(this.policy.name, this.policyHash);
    }
    // A policy-in-effect record before any receipt evaluated under it
    // (log spec 6): a reader maps every receipt to the policy in force by
    // walking back to the nearest policy event.
    this.emitPolicyEvent(policyLoadedEvent(this.policySummary(), this.enforcementMode));
  }

  /** The identity of the policy in force, as a receipt and a log entry carry it. */
  private policySummary(): PolicySummary {
    return policySummary(this.resolutionValue);
  }

  /** The audit context every receipt this guard emits is built with. */
  private auditContext(enforcement?: EnforcementSummary): AuditContext {
    return {
      ...(this.actor === undefined ? {} : { actor: this.actor }),
      ...(enforcement === undefined ? {} : { enforcement }),
      enforcementMode: this.enforcementMode,
      timeSource: this.timeSource,
    };
  }

  private emitPolicyEvent(event: PolicyEvent): void {
    try {
      this.sink?.recordPolicyEvent?.(event);
    } catch (error) {
      // Sinks must not break policy loading; the observers still hear about it.
      this.reportSinkFailure(error);
    }
  }

  /**
   * Load a policy file and resolve its `extends` chain. Relative references
   * resolve against the policy file's own directory (overridable with
   * `options.baseDir`/`options.loader`); `builtin:` references come from the
   * embedded rulesets. Throws if the chain cannot be resolved.
   */
  static fromFile(path: string, options?: HushGuardOptions): HushGuard {
    const content = readFileSync(path, 'utf8');
    const result = parse(content);
    if (!result.ok) {
      throw new Error(`Failed to parse policy: ${result.error}`);
    }
    let source = options?.source;
    if (source == null) {
      try {
        source = realpathSync(path);
      } catch {
        source = nodePath.resolve(path);
      }
    }
    const baseDir = options?.baseDir ?? nodePath.dirname(source);
    return new HushGuard(result.value, { ...options, baseDir, source });
  }

  /**
   * Parse a policy document and resolve its `extends` chain. `builtin:`
   * references resolve out of the box; file references need an explicit
   * `options.baseDir` (or `options.loader`) since a YAML string has no
   * directory of its own. Throws if the chain cannot be resolved.
   */
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
    // A provider resolves (and verifies) against the source it loaded from;
    // re-doing it here would hand the resolver a document with no source to
    // find a `.sig` next to, so adopt the provider's own resolution when it
    // offers one for exactly this document.
    const guard = new HushGuard(spec, {
      ...options,
      provider,
      resolution: resolutionFor(provider, spec),
    });
    provider.watch((newSpec, resolution) =>
      guard.swapPolicy(newSpec, resolution ?? resolutionFor(provider, newSpec)),
    );
    return guard;
  }

  /**
   * The chain, hashes and signature outcome of the policy in force -- what a
   * receipt's `policy.content_hash`, `policy.extends_chain` and
   * `policy.signature` are taken from.
   */
  get resolution(): Resolution {
    return this.resolutionValue;
  }

  /**
   * The compiled form of the policy in force -- the same object the guard
   * evaluates through. Hold it to evaluate outside the guard (a benchmark, a
   * batch of actions) without recompiling.
   */
  get compiled(): CompiledPolicy {
    return this.compiledValue;
  }

  /**
   * Load a policy, and on a verification failure under `requireSignature`
   * enter the refused state rather than throwing.
   *
   * Refusing beats throwing here because a guard that never came into
   * existence emits nothing: no receipt, no observer event, no record that an
   * agent tried to act under an unverified policy. Specification section 6.5
   * requires exactly that record ("MUST refuse to evaluate ... recording
   * `policy.signature.verified: false` with the reason in receipts it emits
   * for refused actions"). Every other load failure -- a base that will not
   * load, a chain that will not merge -- still throws: there is no document to
   * refuse against.
   */
  private loadResolution(policy: HushSpec, adopted?: Resolution): Resolution {
    if (adopted !== undefined) return adopted;
    try {
      return resolvePolicyResolution(policy, this.resolveOptions);
    } catch (error) {
      if (
        error instanceof PolicyVerificationError &&
        this.resolveOptions.requireSignature === true &&
        error.resolution !== undefined
      ) {
        this.refusal = { source: error.source, status: error.status };
        return error.resolution;
      }
      throw error;
    }
  }

  evaluate(action: EvaluationAction): EvaluationResult {
    const active = this.activePolicy();
    if ('decision' in active) {
      // Provider-failure (or signature-refusal) deny, audited exactly as
      // gate() audits it so a sink-only guard is never silent here either.
      const enforcement = impliedEnforcement(active.decision, this.effectiveMode(active));
      const receipt = this.sink ? this.refusedReceipt(action, active, enforcement) : undefined;
      this.send(receipt);
      this.observableEvaluator?.notifyEvaluationCompleted(
        this.observerAction(action),
        active,
        0,
        undefined,
        receipt,
      );
      return active;
    }
    if (this.sink) {
      const { result, durationUs, receipt } = this.runEvaluation(active, action);
      this.send(receipt);
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
      // Route through runEvaluation() (not ObservableEvaluator.evaluate(),
      // which calls the plain evaluate()) so a policy's detection extension
      // is honored here too, then emit through the same public notification
      // ObservableEvaluator.evaluate() would otherwise have sent.
      const { result, durationUs } = this.runEvaluation(active, action);
      this.observableEvaluator.notifyEvaluationCompleted(this.observerAction(action), result, durationUs);
      return result;
    }
    return this.runEvaluation(active, action).result;
  }

  private send(receipt?: DecisionReceipt): void {
    if (receipt === undefined || this.sink === null) return;
    try {
      this.sink.send(receipt);
    } catch (error) {
      // A sink must never break enforcement: a full disk is not a reason to
      // let an action through, nor to stop one. The failure still reaches the
      // observers, so the gap in the evidence is visible.
      this.reportSinkFailure(error);
    }
  }

  /**
   * Put a sink failure on the observer channel as a `sink.error` event, named
   * by the sink that refused.
   */
  private reportSinkFailure(error: unknown): void {
    this.observableEvaluator?.notifySinkError(
      error instanceof Error ? error.message : String(error),
      this.sink?.constructor?.name,
    );
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
    const active = this.activePolicy();
    if ('decision' in active) {
      // Provider failure or a policy that would not verify: no policy to run
      // evaluateAudited() against, but the decision must still be audited, so
      // a receipt is built whenever a sink is configured (see
      // buildFailureReceipt).
      const mode = this.effectiveMode(active);
      const proceed = mode === 'monitor';
      const enforcement: EnforcementSummary = {
        mode,
        outcome: proceed ? 'would_block' : 'blocked',
      };
      const receipt = this.sink ? this.refusedReceipt(action, active, enforcement) : undefined;
      this.record(action, active, 0, enforcement, receipt);
      return { result: active, proceed, enforcement };
    }

    const { result, durationUs, receipt } = this.runEvaluation(active, action);
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
    // A guard that could not verify its policy has no policy to monitor
    // against: specification section 6.5 says refuse, and letting monitor mode
    // wave the action through would be exactly the fail-open it forbids.
    if (result.matched_rule === POLICY_SIGNATURE_RULE) {
      return 'enforce';
    }
    let matched = result.matched_rule;
    // A detection escalation reports the bare `matched_rule` 'detection'
    // rather than a hierarchical rule path, so an override keyed
    // 'extensions.detection' would silently never match. Normalize first.
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

  private runEvaluation(compiled: CompiledPolicy, action: EvaluationAction): {
    result: EvaluationResult;
    durationUs: number;
    receipt?: DecisionReceipt;
  } {
    if (this.sink) {
      // evaluateAudited() routes through the detection pipeline itself, so a
      // sink-backed guard honors a policy's `detection:` extension identically
      // to the receipt-free path below -- and `detection_trace` records what
      // ran rather than being reconstructed afterwards.
      const receipt = compiled.evaluateAudited(action, this.audit, this.auditContext());
      return {
        result: {
          decision: receipt.decision,
          matched_rule: receipt.matched_rule,
          reason: receipt.reason,
          origin_profile: receipt.origin_profile,
          posture: receipt.posture,
        },
        durationUs: receipt.duration_us ?? 0,
        receipt,
      };
    }
    const start = performance.now();
    const result = compiled.evaluateWithDetection(action).evaluation;
    const durationUs = Math.round((performance.now() - start) * 1000);
    return { result, durationUs };
  }

  /**
   * The receipt for an action that was refused without an evaluation.
   *
   * A policy that did not verify gets the reserved
   * `__hushspec_policy_unverified__` receipt of signing spec 6.5, which
   * records `policy.signature.verified: false` and the verifier's reason; a
   * provider outage gets the same shape with the decision that was made.
   */
  private refusedReceipt(
    action: EvaluationAction,
    result: EvaluationResult,
    enforcement: EnforcementSummary,
  ): DecisionReceipt {
    if (result.matched_rule === POLICY_SIGNATURE_RULE) {
      return unverifiedPolicyReceipt(
        this.unverifiedPolicySummary(),
        action,
        this.auditContext(enforcement),
      );
    }
    return buildFailureReceipt(
      this.policySummary(),
      action,
      result,
      enforcement,
      this.auditContext(enforcement),
    );
  }

  /**
   * The policy identity for a refused load: the resolution the guard was
   * handed, with the failing hop's verification outcome recorded even when
   * the resolver never got as far as filling in the leaf's (signing spec
   * 6.5, "recording policy.signature.verified: false with the reason").
   */
  private unverifiedPolicySummary(): PolicySummary {
    const summary = this.policySummary();
    if (summary.signature === undefined && this.refusal !== null) {
      summary.signature = this.refusal.status;
    }
    return summary;
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
      this.send(receipt);
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
   * Redact an action for observer emission the way a receipt does: content is
   * never carried (receipt spec 4.4 records only its hash and size), so it is
   * stripped here too and the redacted flag is set -- raw content must not
   * leak into the observer stream either.
   */
  private observerAction(action: EvaluationAction): EvaluationAction {
    if (action.content != null) {
      const { content: _content, ...rest } = action;
      return { ...rest, content_redacted: true };
    }
    return action;
  }

  static mapToolCall(toolName: string, args?: Record<string, unknown>): EvaluationAction {
    return {
      type: 'tool_call',
      target: toolName,
      args_size: args ? argsSize(args) : undefined,
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

  swapPolicy(newPolicy: HushSpec, resolution?: Resolution): void {
    // Hot-reload is a policy load like any other: an unresolved or unverified
    // document is rejected here rather than swapped in. The throw propagates
    // to the provider's `onError`, leaving the previously resolved policy in
    // force -- which is why this path never enters the refused state: the
    // policy already in force was verified, and keeping it is strictly safer
    // than replacing it with one that was not.
    const next =
      resolution !== undefined && resolution.spec === newPolicy
        ? resolution
        : resolvePolicyResolution(newPolicy, this.resolveOptions);
    const resolved = next.spec;
    const previousHash = this.policyHash;
    this.policy = resolved;
    this.resolutionValue = next;
    this.compiledValue = compiledForResolution(next);
    this.policyHash = next.content_hash;
    if (this.observableEvaluator) {
      this.observableEvaluator.notifyPolicyReloaded(
        resolved.name,
        this.policyHash,
        previousHash ?? undefined,
      );
    }
    // Log spec 6: a `policy_swapped` record before any receipt evaluated
    // under the new policy, naming the hash it replaced.
    this.emitPolicyEvent(
      policySwappedEvent(
        this.policySummary(),
        this.enforcementMode,
        previousHash ?? undefined,
      ),
    );
  }

  /**
   * The compiled policy every action is evaluated through, or the deny that
   * stands in for it when there is none. Resolving the active policy is what
   * may swap the compilation (a provider that reloaded underneath the guard);
   * the compiled form is never rebuilt per action.
   */
  private activePolicy(): CompiledPolicy | EvaluationResult {
    const active = this.activeResolution();
    return 'decision' in active ? active : this.compiledValue;
  }

  /**
   * The resolution every action is evaluated against, or the deny that stands
   * in for it when there is none: a policy that did not verify (signing spec
   * 6.5) or a provider that cannot serve one.
   */
  private activeResolution(): Resolution | EvaluationResult {
    if (this.refusal != null) {
      return {
        decision: 'deny',
        matched_rule: POLICY_SIGNATURE_RULE,
        reason:
          `policy signature verification failed for ${this.refusal.source}: ` +
          `${this.refusal.status.reason ?? 'unverified'}`,
      };
    }
    if (this.provider == null) {
      return this.resolutionValue;
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
      if (current.extends != null) {
        // Defense in depth: the built-in providers resolve on load and on
        // reload, so this only fires for a third-party provider that hands
        // back a leaf document. Evaluating it would silently drop every rule
        // block its base declares -- deny instead.
        return {
          decision: 'deny',
          matched_rule: '__hushspec_policy_provider__',
          reason: `policy provider returned an unresolved policy (extends: ${current.extends})`,
        };
      }
      if (current !== this.policy) {
        // A provider that reloaded without notifying the guard: adopt its own
        // resolution when it has one for exactly this document, otherwise
        // re-derive the identity so receipts never name a stale hash.
        this.policy = current;
        this.resolutionValue =
          resolutionFor(this.provider, current) ?? resolutionFromResolved(current);
        this.compiledValue = compiledForResolution(this.resolutionValue);
        this.policyHash = this.resolutionValue.content_hash;
      }
      return this.resolutionValue;
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
