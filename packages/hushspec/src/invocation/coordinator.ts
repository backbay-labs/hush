import { canonicalizeValue, type JsonValue } from '../canonical.js';
import type { RuntimeContext } from '../conditions.js';
import { getPanicEpoch, isPanicActive, type EvaluationAction } from '../evaluate.js';
import { parseReceipt, receiptHash, uuidV7, type DecisionReceipt } from '../receipt.js';
import { copyJson, hashJson, jsonObject, snapshotJson } from './json.js';
import type { InvocationJournal } from './journal.js';
import { assertAction, callBinding, closedObject, hashField, type ConfirmationDisposition,
  type InvocationAttempt, type InvocationEvent } from './model.js';
import { AuthenticatedPolicy, typescriptInvocationEngine, type InvocationEngine } from './policy.js';
import { InvocationRegistry, qualifiedToolTarget } from './registry.js';
import { assertBoundReceipt } from './verify.js';

export interface InvocationPrompt {
  readonly callId: string;
  readonly target: string;
  readonly generation: number;
  readonly policyHash: string;
  readonly argumentsHash: string;
  readonly effectsHash: string;
  readonly arguments: Readonly<Record<string, JsonValue>>;
  readonly actions: readonly EvaluationAction[];
}
export type InvocationResult =
  | { status: 'completed'; callId: string; value: JsonValue }
  | { status: 'blocked' | 'error' | 'unknown'; callId: string; reason: string };
export interface InvocationCoordinatorOptions {
  registry: InvocationRegistry;
  journal: InvocationJournal;
  policyPublicKeyPem: string;
  engine?: InvocationEngine;
  confirm?: (prompt: InvocationPrompt) => boolean | Promise<boolean>;
  mode?: 'enforce';
  timeoutMs?: number;
  lastSeenVersion?: number;
}
export class InvocationEvidenceError extends Error {
  constructor(readonly callId: string | undefined, readonly admitted: boolean, cause?: unknown) {
    super('authoritative invocation evidence unavailable', { cause });
    this.name = 'InvocationEvidenceError';
  }
}
class DeadlineError extends Error {}
async function deadline<T>(value: PromiseLike<T> | T, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([Promise.resolve(value), new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new DeadlineError('invocation deadline')), timeoutMs);
    })]);
  } finally { if (timer !== undefined) clearTimeout(timer); }
}

/** One enforcing host boundary. No method returns a transferable/reusable permit. */
export class InvocationCoordinator {
  readonly #registry: InvocationRegistry;
  readonly #journal: InvocationJournal;
  readonly #policyKey: string;
  readonly #engine: InvocationEngine;
  readonly #confirm: InvocationCoordinatorOptions['confirm'];
  readonly #timeoutMs: number;
  #policy: AuthenticatedPolicy | undefined;
  #policyName: string | undefined;
  #lastVersion: number | undefined;
  #generation = 0;
  #installing = false;
  #panic = false;
  #panicEpoch = 0;
  #sequence = 0;
  #pending = 0;
  #closed = false;
  #unavailable = false;
  readonly #calls = new Set<string>();
  readonly #receipts = new Set<string>();

  constructor(options: InvocationCoordinatorOptions) {
    if (options.mode !== undefined && options.mode !== 'enforce') throw new Error('invocation requires enforce mode');
    this.#timeoutMs = options.timeoutMs ?? 30_000;
    if (!Number.isSafeInteger(this.#timeoutMs) || this.#timeoutMs < 1 || this.#timeoutMs > 60_000) {
      throw new Error('invalid invocation timeout');
    }
    if (!(options.registry instanceof InvocationRegistry) || typeof options.journal?.append !== 'function' ||
        typeof options.journal.close !== 'function') throw new Error('invalid invocation host configuration');
    this.#registry = options.registry;
    // Capture callbacks; mutation of the options object cannot replace authority later.
    this.#journal = { append: options.journal.append.bind(options.journal), close: options.journal.close.bind(options.journal) };
    this.#policyKey = options.policyPublicKeyPem;
    const engine = options.engine ?? typescriptInvocationEngine;
    this.#engine = { prepare: engine.prepare.bind(engine) };
    this.#confirm = options.confirm;
    this.#lastVersion = options.lastSeenVersion;
  }

  installPolicy(document: string, envelope: unknown): void {
    this.#assertAvailable();
    if (this.#installing) throw new Error('policy installation in progress');
    // Engine and journal callbacks may reenter. Nested installation must not
    // observe an uncommitted version/name floor or skip a journal generation.
    this.#installing = true;
    try {
      const generation = ++this.#generation;
      this.#policy = undefined;
      let policy: AuthenticatedPolicy;
      try {
        policy = new AuthenticatedPolicy(document, envelope, this.#policyKey, this.#engine, this.#lastVersion);
        if (this.#policyName !== undefined && policy.resolution.spec.name !== this.#policyName) throw new Error('policy name changed');
      } catch (error) {
        this.#append({ type: 'policy', generation, status: 'refused', reason: 'policy_installation_refused' });
        throw error;
      }
      this.#append({ type: 'policy', generation, status: 'accepted', policy: policy.resolution.spec,
        envelope: policy.envelope, engine: policy.prepared.identity });
      this.#policy = policy;
      this.#policyName = policy.resolution.spec.name;
      this.#lastVersion = policy.resolution.spec.metadata!.policy_version;
    } finally { this.#installing = false; }
  }

  setPanic(active: boolean): void {
    this.#assertAvailable();
    if (typeof active !== 'boolean') throw new Error('invalid panic state');
    this.#panic = active;
    this.#append({ type: 'panic', epoch: ++this.#panicEpoch, active });
  }

  async invoke(connectionId: string, toolName: string, argumentsJson: string,
    trustedContext: RuntimeContext = {}): Promise<InvocationResult> {
    this.#assertAvailable();
    if (this.#calls.size >= 2000) throw new Error('invocation stream call limit; start a new reconciled stream');
    const callId = uuidV7();
    if (this.#calls.has(callId)) { this.#unavailable = true; throw new Error('duplicate invocation call ID'); }
    this.#calls.add(callId);
    if (this.#pending >= 16) return this.#reject(callId, 'pending_call_limit');
    this.#pending++;
    let attempt: InvocationAttempt | undefined;
    let permitted = false;
    let dispatched = false;
    try {
      const policy = this.#policy;
      if (!policy || this.#panic || isPanicActive()) return this.#reject(callId, 'policy_or_panic_refusal');
      const generation = this.#generation;
      const panicEpoch = this.#panicEpoch;
      const globalEpoch = getPanicEpoch();
      const target = qualifiedToolTarget(connectionId, toolName);
      const binding = this.#registry.get(connectionId, toolName);
      const args = jsonObject(snapshotJson(argumentsJson));
      const context = copyJson({ ...trustedContext, current_time: new Date().toISOString() }, { maxBytes: 16_384 });
      const effects = copyJson(binding.extract(args), { maxBytes: 1_100_000, maxNodes: 100_000, maxDepth: 20 });
      if (!Array.isArray(effects) || effects.length === 0 || effects.length > 16) throw new Error('unsupported effect plan');
      effects.forEach(effect => assertAction(effect, false, false));
      const actions = copyJson([{ type: 'tool_call', target, args_size: Buffer.byteLength(canonicalizeValue(args)), context },
        ...effects.map(effect => ({ ...effect, context }))], { maxBytes: 1_500_000, maxDepth: 24, maxNodes: 120_000 });
      const captured: InvocationAttempt = copyJson({ type: 'attempt', call_id: callId, generation,
        policy_hash: policy.resolution.content_hash, target, arguments: args,
        arguments_hash: hashJson(args), effects_hash: hashJson(actions), actions, context,
        panic_epoch: panicEpoch, global_panic_epoch: globalEpoch },
      { maxBytes: 1_800_000, maxDepth: 28, maxNodes: 130_000 });
      this.#assertCurrent(captured, policy);
      this.#append(captured, callId);
      attempt = captured;
      const receipts: DecisionReceipt[] = [];
      const evaluationDeadline = Date.now() + this.#timeoutMs;
      for (const action of actions) {
        const remaining = evaluationDeadline - Date.now();
        if (remaining <= 0) throw new DeadlineError('evaluation deadline');
        const receipt = copyJson(await deadline(policy.prepared.evaluate(action, context), remaining),
          { maxBytes: 262_144, maxNodes: 20_000, maxDepth: 24 });
        parseReceipt(receipt); assertBoundReceipt(receipt, action, policy);
        if (this.#receipts.has(receipt.receipt_id)) throw new Error('duplicate component receipt ID');
        this.#receipts.add(receipt.receipt_id);
        // Enforcement disposition is assigned only after aggregate confirmation.
        receipts.push(structuredClone(receipt));
      }
      const aggregate = receipts.some(r => r.decision === 'deny') ? 'deny' : receipts.some(r => r.decision === 'warn') ? 'warn' : 'allow';
      let confirmation: ConfirmationDisposition = 'not_required';
      if (aggregate === 'warn') {
        this.#assertCurrent(captured, policy);
        const prompt: InvocationPrompt = copyJson({ callId, target, generation, policyHash: captured.policy_hash,
          argumentsHash: captured.arguments_hash, effectsHash: captured.effects_hash, arguments: args, actions },
        { maxBytes: 1_800_000, maxNodes: 130_000, maxDepth: 28 });
        try {
          confirmation = this.#confirm && await deadline(this.#confirm(prompt), this.#timeoutMs) === true ? 'confirmed' : 'refused';
        } catch (error) { confirmation = error instanceof DeadlineError ? 'timeout' : 'error'; }
      }
      const allowed = aggregate === 'allow' || (aggregate === 'warn' && confirmation === 'confirmed');
      for (const receipt of receipts) receipt.enforcement = { mode: 'enforce',
        outcome: !allowed ? 'blocked' : receipt.decision === 'warn' ? 'confirmed' : 'allowed' };
      const hashes = receipts.map(receiptHash);
      this.#append({ type: 'decision', call_id: callId, aggregate, confirmation, receipts, receipt_hashes: hashes }, callId);
      if (!allowed) return this.#block(callId, aggregate === 'deny' ? 'policy_denied' : 'confirmation_not_granted');
      this.#assertCurrent(captured, policy);
      this.#append({ type: 'permit', ...callBinding(captured), receipt_ids: receipts.map(r => r.receipt_id), receipt_hashes: hashes }, callId);
      permitted = true;
      // No await from this final check through the dispatch call. A later reload cannot retract it.
      this.#assertCurrent(captured, policy);
      dispatched = true;
      const dispatchResult = binding.dispatch(args, Object.freeze({ callId }));
      let value: unknown;
      try { value = await deadline(dispatchResult, this.#timeoutMs); }
      catch (error) {
        if (error instanceof DeadlineError) {
          this.#unavailable = true;
          return { status: 'unknown', callId, reason: 'dispatch_deadline_outcome_unknown' };
        }
        throw error;
      }
      const result = copyJson(value, { maxBytes: 131_072, maxDepth: 24, maxNodes: 20_000 }) as JsonValue;
      this.#append({ type: 'terminal', call_id: callId, outcome: 'completed' }, callId, true);
      return { status: 'completed', callId, value: result };
    } catch (error) {
      if (this.#unavailable || error instanceof InvocationEvidenceError) {
        throw new InvocationEvidenceError(callId, permitted || dispatched, error);
      }
      if (permitted) {
        this.#append({ type: 'terminal', call_id: callId, outcome: dispatched ? 'error' : 'aborted_before_dispatch',
          reason: dispatched ? 'dispatch_error_partial_effect_possible' : 'admission_invalidated' }, callId, true);
        return { status: dispatched ? 'error' : 'blocked', callId, reason: dispatched ? 'dispatch_error_partial_effect_possible' : 'admission_invalidated' };
      }
      return attempt ? this.#block(callId, 'invocation_refused') : this.#reject(callId, 'invalid_or_unavailable_invocation');
    } finally { this.#pending--; }
  }

  close() {
    this.#assertAvailable();
    if (this.#pending) throw new Error('invocation calls pending');
    try { const checkpoint = this.#journal.close(); this.#closed = true; return checkpoint; }
    catch (error) { this.#unavailable = true; throw new InvocationEvidenceError(undefined, false, error); }
  }
  #assertAvailable(): void {
    if (this.#unavailable) throw new Error('invocation coordinator unavailable; reconcile incomplete evidence');
    if (this.#closed) throw new Error('invocation coordinator closed');
  }
  #assertCurrent(attempt: InvocationAttempt, policy: AuthenticatedPolicy): void {
    this.#assertAvailable();
    if (this.#generation !== attempt.generation || this.#policy !== policy || this.#panic || isPanicActive() ||
        this.#panicEpoch !== attempt.panic_epoch || getPanicEpoch() !== attempt.global_panic_epoch) throw new Error('stale invocation admission');
    policy.verifyAt(new Date());
  }
  #append(event: InvocationEvent, callId?: string, admitted = false): void {
    this.#assertAvailable();
    const sequence = ++this.#sequence;
    try {
      const ack = this.#journal.append(event);
      const shape = closedObject(ack, ['sequence', 'entryHash']);
      if (shape.sequence !== sequence) throw new Error('invalid authoritative acknowledgment sequence');
      hashField(shape.entryHash);
    } catch (error) { this.#unavailable = true; throw new InvocationEvidenceError(callId, admitted, error); }
  }
  #reject(callId: string, reason: string): InvocationResult {
    this.#append({ type: 'rejected', call_id: callId, reason }, callId);
    return { status: 'blocked', callId, reason };
  }
  #block(callId: string, reason: string): InvocationResult {
    this.#append({ type: 'blocked', call_id: callId, reason }, callId);
    return { status: 'blocked', callId, reason };
  }
}
