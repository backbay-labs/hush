import { compileResolution } from '../compiled.js';
import type { RuntimeContext } from '../conditions.js';
import type { EvaluationAction } from '../evaluate.js';
import { parseOrThrow } from '../parse.js';
import { DEFAULT_AUDIT_CONFIG, type DecisionReceipt } from '../receipt.js';
import { resolutionFromResolved, type Resolution } from '../resolve.js';
import { verifyPolicy, type Envelope } from '../signing.js';
import { copyJson } from './json.js';

export interface InvocationEngineIdentity {
  readonly name: string;
  readonly version: string;
  /** Operator-declared identities, not build attestations or conformance verdicts. */
  readonly artifact_sha256?: string;
  readonly qualification_sha256?: string;
}
export interface PreparedInvocationEngine {
  readonly policyHash: string;
  readonly identity: InvocationEngineIdentity;
  readonly evaluate: (action: EvaluationAction, context: RuntimeContext) => DecisionReceipt | Promise<DecisionReceipt>;
}
export interface InvocationEngine {
  readonly prepare: (resolution: Resolution) => PreparedInvocationEngine;
}

export const typescriptInvocationEngine: InvocationEngine = Object.freeze({
  prepare(resolution: Resolution): PreparedInvocationEngine {
    const compiled = compileResolution(resolution);
    return Object.freeze({
      policyHash: compiled.contentHash,
      identity: Object.freeze({ name: '@hushspec/core', version: '1.0.0' }),
      evaluate: (action: EvaluationAction, context: RuntimeContext) => compiled.evaluateAudited(
        action, { ...DEFAULT_AUDIT_CONFIG, recordDuration: false },
        { context, enforcementMode: 'enforce' }),
    });
  },
});

/** Authenticates the actual resolved document, not a caller's verification flag. */
export class AuthenticatedPolicy {
  readonly resolution: Resolution;
  readonly envelope: Envelope;
  readonly prepared: PreparedInvocationEngine;
  readonly #publicKeyPem: string;
  readonly #lastSeenVersion: number | undefined;

  constructor(document: string, envelope: unknown, publicKeyPem: string,
    engine: InvocationEngine = typescriptInvocationEngine, lastSeenVersion?: number, now = new Date()) {
    const parsed = parseOrThrow(document);
    if (parsed.extends !== undefined || parsed.merge_strategy !== undefined) {
      throw new Error('invocation requires a resolved policy');
    }
    if (typeof parsed.name !== 'string' || !parsed.name ||
        !Number.isSafeInteger(parsed.metadata?.policy_version) || parsed.metadata!.policy_version! < 0) {
      throw new Error('policy identity requires name and integer version');
    }
    if (lastSeenVersion !== undefined && (!Number.isSafeInteger(lastSeenVersion) || lastSeenVersion < 0)) {
      throw new Error('invalid last-seen policy version');
    }
    this.#publicKeyPem = publicKeyPem;
    this.#lastSeenVersion = lastSeenVersion;
    this.envelope = copyJson(envelope, { maxBytes: 16_384 }) as Envelope;
    const spec = copyJson(parsed, { maxBytes: 1_048_576, maxDepth: 32, maxNodes: 100_000 });
    const verified = verifyPolicy(spec, this.envelope, { publicKeyPem, now });
    if (!verified.ok) throw new Error(`policy refused: ${verified.reason}`);
    if (this.envelope.policy_name !== spec.name ||
        this.envelope.policy_version !== spec.metadata!.policy_version) {
      throw new Error('signed policy identity differs from document');
    }
    if (lastSeenVersion !== undefined && spec.metadata!.policy_version! < lastSeenVersion) {
      throw new Error('policy version rollback');
    }
    const resolution = resolutionFromResolved(spec, 'host:invocation');
    resolution.signature = { verified: true, key_id: verified.keyId, verified_at: now.toISOString() };
    this.resolution = copyJson(resolution, { maxBytes: 1_100_000, maxDepth: 36, maxNodes: 100_100 });
    const prepared = engine.prepare(this.resolution);
    if (prepared.policyHash !== resolution.content_hash || typeof prepared.evaluate !== 'function') {
      throw new Error('engine is not bound to policy');
    }
    const identity = copyJson(prepared.identity, { maxBytes: 4096 });
    if (!identity || typeof identity.name !== 'string' || !identity.name ||
        typeof identity.version !== 'string' || !identity.version ||
        Object.keys(identity).some(key => !['name', 'version', 'artifact_sha256', 'qualification_sha256'].includes(key)) ||
        [identity.artifact_sha256, identity.qualification_sha256].some(hash => hash !== undefined && !/^sha256:[a-f0-9]{64}$/.test(hash))) {
      throw new Error('invalid engine identity');
    }
    this.prepared = Object.freeze({ policyHash: prepared.policyHash, identity,
      evaluate: prepared.evaluate.bind(prepared) });
    Object.freeze(this);
  }

  verifyAt(now: Date): void {
    const verified = verifyPolicy(this.resolution.spec, this.envelope,
      { publicKeyPem: this.#publicKeyPem, lastSeenVersion: this.#lastSeenVersion, now });
    if (!verified.ok) throw new Error(`policy refused: ${verified.reason}`);
  }
}
