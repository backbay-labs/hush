import { existsSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import type { HushSpec } from './schema.js';
import { merge } from './merge.js';
import { parse } from './parse.js';
import { loadBuiltin } from './builtin.js';
import { contentHash } from './canonical.js';
import { fetchSignature } from './http-loader.js';
import {
  verifyPolicy,
  type Keyring,
  type ReasonCode,
  type VerificationOutcome,
  type VerifyOptions,
} from './signing.js';

export interface LoadedSpec {
  source: string;
  spec: HushSpec;
}

export type ResolveResult =
  | { ok: true; value: HushSpec }
  | {
    ok: false;
    error: string;
    /**
     * The registered code for a refused chain: always `E010`
     * (`spec/registries/error-codes.yaml`), whatever the reason -- a
     * reference no loader serves, a digest pin that does not match, a cycle,
     * a chain past the depth cap, or a hop that fails a required signature
     * check.
     */
    code: 'E010';
  };

/** Synchronous `extends` loader. */
export type Loader = (reference: string, from?: string) => LoadedSpec;

/** Loader that may go to the network; accepted by the async resolvers only. */
export type AsyncLoader = (reference: string, from?: string) => LoadedSpec | Promise<LoadedSpec>;

/**
 * How a document reaches the resolver: where it came from, how its `extends`
 * references are loaded, and (in `options`) what must be true of its
 * signatures before it may be used.
 *
 * `source` does double duty, exactly as it always has: it anchors relative
 * `extends` references *and* it is the identity the leaf carries into
 * {@link Resolution.chain} and into the signature locator. A caller that has a
 * real file path should pass it; a caller holding only a YAML string should
 * not invent one, and the leaf is then reported as {@link MEMORY_SOURCE}.
 */
export interface ResolveInput {
  source?: string;
  /** Loader for `extends` references. */
  loader?: Loader;
  /** Deprecated spelling of {@link ResolveInput.loader}; still honored. */
  load?: Loader;
  /** Verification policy; see {@link ResolveOptions}. */
  options?: ResolveOptions;
}

/** Async counterpart of {@link ResolveInput}. */
export interface AsyncResolveInput {
  source?: string;
  loader?: AsyncLoader;
  load?: AsyncLoader;
  options?: ResolveOptions;
}

/**
 * Verification policy for a load (Signing specification section 6.5).
 *
 * Defaults are the pre-signing behavior: nothing is verified, nothing is
 * required. Turning on `requireSignature` makes every non-`builtin:` hop of
 * the `extends` chain prove itself -- with a matching digest pin or with a
 * detached envelope that verifies against `keyring` -- before the resolved
 * policy may be used at all.
 */
export interface ResolveOptions {
  /**
   * Refuse the load unless every non-`builtin:` hop is pinned by digest or
   * carries a valid signature. Requires `keyring` (a policy that demands
   * signatures with no keys to check them against is a configuration error,
   * not an allow-everything default).
   */
  requireSignature?: boolean;
  /** Keys signatures are checked against. Without it nothing is verified. */
  keyring?: Keyring;
  /** Clock and rollback parameters handed to `verifyPolicy`. */
  verify?: VerifyClockOptions;
  /**
   * Where a hop's detached envelope lives. Defaults to
   * {@link defaultSignatureLocator} (sync) / {@link defaultAsyncSignatureLocator}.
   */
  signatureLocator?: SignatureLocator;
}

/** The clock- and rollback-sensitive half of {@link VerifyOptions}. */
export interface VerifyClockOptions {
  now?: Date | string;
  maxClockSkewSeconds?: number;
  /**
   * Applied to the **leaf** only. A base pulled in through `extends` is a
   * different policy with its own version line, so checking the leaf's
   * last-seen version against a base's envelope would report a rollback that
   * did not happen.
   */
  lastSeenVersion?: number;
}

/**
 * Locates the detached envelope for one chain hop, by the `source` the loader
 * reported. Returns the envelope bytes/text, or `null` when there is none.
 */
export type SignatureLocator = (
  source: string,
) => Promise<Uint8Array | string | null> | Uint8Array | string | null;

/**
 * The outcome of verifying one document at load time (Receipt specification
 * section 4.2). Wire-shaped -- `snake_case` -- because it is copied verbatim
 * into `receipt.policy.signature`.
 */
export interface SignatureStatus {
  verified: boolean;
  key_id?: string;
  /**
   * When verification ran -- the verifier's clock, not the envelope's
   * `signed_at` (Receipt specification section 4.2). RFC 3339 UTC with
   * milliseconds and a `Z` suffix.
   */
  verified_at?: string;
  reason?: string;
}

/**
 * One document of a resolved `extends` chain.
 *
 * `content_hash` is that document canonicalized **on its own**, with its own
 * `extends` and `merge_strategy` stripped (Receipt specification section 4.2),
 * so an auditor can confirm a specific base was in force without re-resolving
 * -- and so a digest pin has something stable to pin to.
 */
export interface ChainLink {
  source: string;
  content_hash: string;
  signature?: SignatureStatus;
}

/** A resolved policy together with the evidence gathered while loading it. */
export interface Resolution {
  /**
   * The merged document: resolution consumes `extends` and `merge_strategy`,
   * so neither is ever present (Core section 2.3).
   */
  spec: HushSpec;
  /** Content hash of {@link Resolution.spec} (Canonical Form section 5). */
  content_hash: string;
  /** Root first, leaf last. Always non-empty: the leaf is a link too. */
  chain: ChainLink[];
  /** The leaf's verification outcome, when one was attempted. */
  signature?: SignatureStatus;
}

/**
 * The reasons a load can be refused: the closed set of Signing section 6.4,
 * plus the two that only verification-on-load can produce.
 */
export type LoadReasonCode = ReasonCode | 'digest_mismatch' | 'missing_signature';

/**
 * Wrap a document that is already resolved (no `extends`) as a single-link
 * resolution, so a caller that holds a bare spec can still build receipts
 * that name a real content hash.
 *
 * `source` names the leaf in {@link Resolution.chain}; it defaults to
 * {@link MEMORY_SOURCE}, the identity a document that was not loaded from
 * anywhere carries.
 *
 * @throws {CanonicalError} when the document has no canonical form, including
 * when it still declares `extends`.
 */
export function resolutionFromResolved(spec: HushSpec, source?: string): Resolution {
  const hash = contentHash(spec);
  return {
    // A resolution's document carries no resolution instructions, however it
    // was obtained: `contentHash` above already refused a lingering `extends`,
    // and `merge_strategy` is inert here (Core section 2.3).
    spec: stripResolutionFields(spec),
    content_hash: hash,
    chain: [{ source: source ?? MEMORY_SOURCE, content_hash: hash }],
  };
}

/**
 * Why a chain could not be resolved at all, in the vocabulary
 * `fixtures/core/resolve/` uses. `digest_mismatch` and `missing_signature`
 * come back as a {@link PolicyVerificationError}, which carries the same
 * codes.
 */
export type ResolveReasonCode =
  | 'invalid_pin'
  | 'not_found'
  | 'cycle'
  | 'max_depth'
  | 'http'
  | 'parse'
  | 'read';

/**
 * A chain could not be walked: a malformed digest pin, a reference no loader
 * serves, a cycle, or a chain deeper than the cap.
 *
 * Carries the machine-readable `reason` so a caller (and the resolve vectors)
 * can distinguish the cases without matching on message text.
 */
export class ResolveError extends Error {
  readonly reason: ResolveReasonCode;

  constructor(reason: ResolveReasonCode, message: string) {
    super(message);
    this.name = 'ResolveError';
    this.reason = reason;
  }
}

/**
 * The reason code a thrown resolution failure reports, or `undefined` for an
 * error this resolver did not classify.
 */
export function resolveErrorReason(
  error: unknown,
): ResolveReasonCode | LoadReasonCode | undefined {
  if (error instanceof PolicyVerificationError) return error.reason;
  if (error instanceof ResolveError) return error.reason;
  return undefined;
}

/**
 * A hop of the chain did not prove itself: its digest pin did not match, it
 * carried no signature where one was required, or its signature did not
 * verify.
 *
 * `resolution` carries what was loaded when the merge itself succeeded, so a
 * caller that must keep going -- `HushGuard`, which refuses every action but
 * still reports the hash of what it was handed -- has the document without
 * ever being able to mistake it for a verified one.
 */
export class PolicyVerificationError extends Error {
  readonly source: string;
  readonly reason: LoadReasonCode;
  readonly status: SignatureStatus;
  readonly resolution?: Resolution;

  constructor(
    source: string,
    reason: LoadReasonCode,
    detail: string,
    resolution?: Resolution,
    status?: SignatureStatus,
  ) {
    super(`policy verification failed for ${source}: ${detail}`);
    this.name = 'PolicyVerificationError';
    this.source = source;
    this.reason = reason;
    this.status = status ?? { verified: false, reason };
    this.resolution = resolution;
  }
}

/**
 * Maximum `extends` chain depth. Cycle detection only catches exact repeats, so
 * a long *acyclic* chain would otherwise recurse unbounded until a stack
 * overflow. 32 is far above any realistic composition (shipped policies are
 * depth <= 2); the cap fails closed with a clean error.
 */
const MAX_EXTENDS_DEPTH = 32;

/**
 * The chain identity of a document that was not loaded from anywhere -- a
 * spec handed to the resolver in memory. The same spelling in every SDK, and
 * what `fixtures/core/resolve/` pins.
 */
export const MEMORY_SOURCE = 'memory';

/** @deprecated Older spelling of {@link MEMORY_SOURCE}; same value. */
export const INLINE_POLICY_SOURCE = MEMORY_SOURCE;

/**
 * Resolve an `extends` chain, returning the merged document.
 *
 * {@link resolveWithOptions} with the default options: nothing is verified
 * against a keyring, but digest pins are still enforced -- a pin is written
 * into the document by its author, not configured by its loader, so no path
 * that loads the chain may quietly ignore one.
 *
 * Result-shaped, and hashes only the hops that carry a pin, so a caller with
 * no interest in either keeps exactly the behavior it had.
 */
export function resolve(spec: HushSpec, options: ResolveInput = {}): ResolveResult {
  try {
    const hops = collectChain(spec, options.source, loaderOf(options));
    enforcePins(hops);
    return { ok: true, value: foldChain(hops)[hops.length - 1]! };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error), code: 'E010' };
  }
}

/**
 * Check every pinned hop against its own content hash, hashing nothing else.
 *
 * {@link buildResolution} does this inline instead, because by then every hop
 * has been hashed anyway for the chain.
 */
function enforcePins(hops: readonly Hop[]): void {
  for (const hop of hops) {
    if (hop.pin === undefined) continue;
    const hash = contentHash(stripResolutionFields(hop.spec));
    if (hash !== hop.pin) {
      throw digestMismatch(hop, hash);
    }
  }
}

function digestMismatch(hop: Hop, hash: string, resolution?: Resolution): PolicyVerificationError {
  return new PolicyVerificationError(
    hop.source,
    'digest_mismatch',
    `pinned digest ${hop.pin} but the document hashes to ${hash}`,
    resolution,
  );
}

export function resolveFromFile(filePath: string): ResolveResult {
  let source: string;
  let spec: HushSpec;
  try {
    ({ source, spec } = readPolicyFile(filePath));
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error), code: 'E010' };
  }
  return resolve(spec, { source, loader: createCompositeLoader() });
}

/**
 * Resolve an `extends` chain, hash every hop, and verify what the options ask
 * to be verified (Signing specification section 6.5).
 *
 * Fail-closed in both directions it can fail:
 *
 *  - a digest pin that does not match is refused **always**, signatures
 *    required or not -- the document on disk is not the document the author
 *    pinned, and nothing else about the load can be trusted after that;
 *  - with `requireSignature`, a hop that is neither `builtin:` nor pinned nor
 *    validly signed is refused.
 *
 * Without `requireSignature` but with a `keyring`, signatures are still
 * verified where they are found and the outcome is recorded on the link
 * (section 6.5, second paragraph) -- opportunistic verification never turns a
 * load into a failure.
 *
 * @throws {PolicyVerificationError} when a hop fails to prove itself.
 * @throws {Error} when the chain cannot be loaded, merged, or hashed.
 */
export function resolveWithOptions(spec: HushSpec, input: ResolveInput = {}): Resolution {
  const options = input.options ?? {};
  const hops = collectChain(spec, input.source, loaderOf(input));
  const locator = options.keyring ? options.signatureLocator ?? defaultSignatureLocator : undefined;
  const envelopes = hops.map((hop) => {
    if (locator === undefined || isBuiltinSource(hop.source)) return null;
    const located = locator(hop.source);
    if (isPromise(located)) {
      throw new Error(
        'signatureLocator returned a Promise: use resolveWithOptionsAsync() for an async locator',
      );
    }
    return located;
  });
  return buildResolution(hops, envelopes, options);
}

/**
 * Async {@link resolveWithOptions}: accepts loaders and signature locators
 * that go to the network (`https:` bases, `<url>.sig` sidecars).
 */
export async function resolveWithOptionsAsync(
  spec: HushSpec,
  input: AsyncResolveInput = {},
): Promise<Resolution> {
  const options = input.options ?? {};
  const hops = await collectChainAsync(spec, input.source, asyncLoaderOf(input));
  const locator = options.keyring
    ? options.signatureLocator ?? defaultAsyncSignatureLocator
    : undefined;
  const envelopes: (Uint8Array | string | null)[] = [];
  for (const hop of hops) {
    envelopes.push(
      locator === undefined || isBuiltinSource(hop.source) ? null : await locator(hop.source),
    );
  }
  return buildResolution(hops, envelopes, options);
}

/** {@link resolveWithOptions} starting from a policy file on disk. */
export function resolveFromFileWithOptions(
  filePath: string,
  options: ResolveOptions = {},
): Resolution {
  const { source, spec } = readPolicyFile(filePath);
  return resolveWithOptions(spec, { source, loader: createCompositeLoader(), options });
}

/**
 * Loader that serves `builtin:<name>` (and bare builtin names) from the
 * embedded rulesets and refuses everything else.
 *
 * This is the default for callers that have no filesystem root to resolve
 * relative references against -- `HushGuard.fromYaml()`, a provider that
 * hands back an already-parsed spec, a poller loader returning raw YAML.
 * Refusing (rather than guessing a root, or silently skipping the base) keeps
 * those paths fail-closed: a policy whose base cannot be loaded is never
 * evaluated as if the base said nothing.
 */
export function createBuiltinLoader(): Loader {
  return (reference: string): LoadedSpec => {
    const spec = loadBuiltin(reference);
    if (spec) {
      const source = reference.startsWith('builtin:') ? reference : `builtin:${reference}`;
      return { source, spec };
    }
    if (reference.startsWith('builtin:')) {
      throw new ResolveError('not_found', `unknown builtin ruleset '${reference}'`);
    }
    throw new ResolveError(
      'not_found',
      `cannot resolve 'extends: ${reference}': this loader only serves builtin rulesets ` +
        `(${BUILTIN_REFERENCE_HINT})`,
    );
  };
}

const BUILTIN_REFERENCE_HINT =
  "pass a `baseDir` to resolve relative paths, or a custom `loader`";

export function createCompositeLoader(): Loader {
  return (reference: string, from?: string): LoadedSpec => {
    if (reference.startsWith('builtin:')) {
      return loadBuiltinOrThrow(reference);
    }

    if (reference.startsWith('https://') || reference.startsWith('http://')) {
      throw new ResolveError(
        'http',
        `HTTP-based policy loading is not supported in the synchronous loader; ` +
          `use createHttpLoader() for '${reference}'`,
      );
    }

    // Bare name without dots/slashes: try as builtin first
    if (!reference.includes('/') && !reference.includes('\\') && !reference.includes('.')) {
      const spec = loadBuiltin(reference);
      if (spec) {
        const source = `builtin:${reference}`;
        return { source, spec };
      }
    }

    return loadFromFilesystem(reference, from);
  };
}

function loadBuiltinOrThrow(reference: string): LoadedSpec {
  const spec = loadBuiltin(reference);
  if (!spec) {
    throw new ResolveError('not_found', `unknown builtin ruleset '${reference}'`);
  }
  return { source: reference, spec };
}

// --------------------------------------------------------------------------
// Digest pinning
// --------------------------------------------------------------------------

/** `extends: "<ref>#sha256:<64 hex>"` -- the pin is a URI fragment. */
const DIGEST_PIN_PATTERN = /#(sha256:[0-9a-f]{64})$/;

/**
 * Split `extends: "<ref>#sha256:<digest>"` into the reference the loader sees
 * and the digest the loaded document must hash to.
 *
 * A fragment that *looks* like a pin but is not one (wrong algorithm, wrong
 * length, uppercase hex) is an error rather than part of the path: silently
 * treating `base.yaml#sha256:abcd` as a filename would turn a typo'd pin into
 * an unpinned load, which is precisely the downgrade pinning exists to stop.
 */
export function splitDigestPin(reference: string): { reference: string; pin?: string } {
  const match = DIGEST_PIN_PATTERN.exec(reference);
  if (match === null) {
    const hash = reference.lastIndexOf('#');
    if (hash >= 0 && /^#sha(256)?:/i.test(reference.slice(hash))) {
      throw new ResolveError(
        'invalid_pin',
        `malformed digest pin in 'extends: ${reference}': ` +
          'expected "#sha256:" followed by 64 lowercase hex digits',
      );
    }
    return { reference };
  }
  const base = reference.slice(0, match.index);
  if (base === '') {
    throw new ResolveError(
      'invalid_pin',
      `'extends: ${reference}' pins a digest but names no policy`,
    );
  }
  return { reference: base, pin: match[1] };
}

// --------------------------------------------------------------------------
// Chain walk
// --------------------------------------------------------------------------

interface Hop {
  source: string;
  spec: HushSpec;
  /** The digest the *child* pinned this document to, when it pinned one. */
  pin?: string;
}

function loaderOf(input: ResolveInput): Loader {
  return input.loader ?? input.load ?? createCompositeLoader();
}

function asyncLoaderOf(input: AsyncResolveInput): AsyncLoader {
  return input.loader ?? input.load ?? createCompositeLoader();
}

function isPromise(value: unknown): value is Promise<unknown> {
  return typeof (value as { then?: unknown } | null)?.then === 'function';
}

function isBuiltinSource(source: string): boolean {
  return source.startsWith('builtin:');
}

/** Root first, leaf last; the leaf is always the last element. */
function collectChain(spec: HushSpec, source: string | undefined, load: Loader): Hop[] {
  const walk = startWalk(spec, source);
  while (walk.current.extends != null) {
    const step = walk.step();
    walk.accept(load(step.reference, walk.currentSource), step.pin);
  }
  return walk.finish();
}

async function collectChainAsync(
  spec: HushSpec,
  source: string | undefined,
  load: AsyncLoader,
): Promise<Hop[]> {
  const walk = startWalk(spec, source);
  while (walk.current.extends != null) {
    const step = walk.step();
    walk.accept(await load(step.reference, walk.currentSource), step.pin);
  }
  return walk.finish();
}

/**
 * The shared bookkeeping of the two chain walks: depth cap, cycle detection,
 * and pin extraction. Only the `load` call differs between them, and that is
 * the one thing a shared helper cannot abstract over without making the
 * synchronous path async.
 */
function startWalk(spec: HushSpec, source: string | undefined) {
  const hops: Hop[] = [{ source: source ?? MEMORY_SOURCE, spec }];
  const stack: string[] = source != null ? [source] : [];
  let current = spec;
  let currentSource = source;
  let depth = 0;

  return {
    get current(): HushSpec {
      return current;
    },
    get currentSource(): string | undefined {
      return currentSource;
    },
    step(): { reference: string; pin?: string } {
      if (depth >= MAX_EXTENDS_DEPTH) {
        throw new ResolveError(
          'max_depth',
          `extends chain exceeds maximum depth of ${MAX_EXTENDS_DEPTH}`,
        );
      }
      depth += 1;
      return splitDigestPin(current.extends!);
    },
    accept(loaded: LoadedSpec, pin?: string): void {
      const cycleIndex = stack.indexOf(loaded.source);
      if (cycleIndex >= 0) {
        throw new ResolveError(
          'cycle',
          `circular extends detected: ${[...stack.slice(cycleIndex), loaded.source].join(' -> ')}`,
        );
      }
      stack.push(loaded.source);
      hops.push({ source: loaded.source, spec: loaded.spec, pin });
      current = loaded.spec;
      currentSource = loaded.source;
    },
    finish(): Hop[] {
      return hops.reverse();
    },
  };
}

/**
 * `partials[i]` is the chain merged from the root down to hop `i` -- which is
 * the document hop `i`'s own signature covers (Signing section 3: a signature
 * is over the *resolved* policy, and a base resolved on its own is the base
 * plus everything it extends).
 */
function foldChain(hops: Hop[]): HushSpec[] {
  // The root carries no `extends` (that is what ended the walk) and its
  // `merge_strategy`, if any, is inert with nothing above it -- but a resolved
  // document declares neither field (Core section 2.3), and a chain of one
  // never reaches `merge`, so the root is stripped on the way in.
  const partials: HushSpec[] = [stripResolutionFields(hops[0]!.spec)];
  for (let index = 1; index < hops.length; index += 1) {
    partials.push(merge(partials[index - 1]!, hops[index]!.spec));
  }
  return partials;
}

/**
 * The document as the chain sees it: `extends` and `merge_strategy` are
 * resolution instructions, not policy, and Receipt section 4.2 hashes each
 * link without them. (`canonicalJson` already drops `merge_strategy`; it
 * *rejects* a document that still carries `extends`, which is exactly why this
 * has to happen first.)
 */
function stripResolutionFields(spec: HushSpec): HushSpec {
  if (spec.extends == null && spec.merge_strategy == null) return spec;
  return { ...spec, extends: undefined, merge_strategy: undefined };
}

// --------------------------------------------------------------------------
// Verification (Signing specification section 6.5)
// --------------------------------------------------------------------------

function buildResolution(
  hops: Hop[],
  envelopes: readonly (Uint8Array | string | null)[],
  options: ResolveOptions,
): Resolution {
  if (options.requireSignature === true && options.keyring === undefined) {
    throw new Error(
      'requireSignature needs a keyring: there is nothing to verify signatures against',
    );
  }

  const partials = foldChain(hops);
  const leafIndex = hops.length - 1;
  const chain: ChainLink[] = hops.map((hop) => ({
    source: hop.source,
    content_hash: contentHash(stripResolutionFields(hop.spec)),
  }));
  const resolved = partials[leafIndex]!;
  const resolution: Resolution = {
    spec: resolved,
    content_hash: leafIndex === 0 ? chain[0]!.content_hash : contentHash(resolved),
    chain,
  };

  for (let index = 0; index < hops.length; index += 1) {
    const hop = hops[index]!;
    const link = chain[index]!;

    // A pin is checked before anything else and regardless of
    // `requireSignature`: past a mismatch nothing about this load is what the
    // author described.
    const pinned = hop.pin !== undefined;
    if (pinned && hop.pin !== link.content_hash) {
      throw digestMismatch(hop, link.content_hash, resolution);
    }

    const envelope = envelopes[index] ?? null;
    if (options.keyring !== undefined && !isBuiltinSource(hop.source)) {
      // Verification was attempted, so the outcome is always recorded
      // (signing spec section 6.5): a hop with no envelope carries
      // `missing_signature` rather than nothing at all, which a reader could
      // only take for "no check was configured".
      link.signature = envelope === null
        ? { verified: false, reason: 'missing_signature' }
        : verifyLink(partials[index]!, envelope, options, index === leafIndex);
    }

    if (options.requireSignature !== true || isBuiltinSource(hop.source) || pinned) {
      continue;
    }
    const status = link.signature ?? { verified: false, reason: 'missing_signature' };
    if (!status.verified) {
      resolution.signature = chain[leafIndex]!.signature;
      throw new PolicyVerificationError(
        hop.source,
        (status.reason as LoadReasonCode | undefined) ?? 'missing_signature',
        status.reason === 'missing_signature' || status.reason === undefined
          ? 'no detached signature was found and no digest was pinned'
          : `signature did not verify (${status.reason})`,
        resolution,
        status,
      );
    }
  }

  resolution.signature = chain[leafIndex]!.signature;
  return resolution;
}

/**
 * The instant a verification ran, as `verified_at` spells it: RFC 3339 UTC,
 * milliseconds, `Z`. The verifier's own clock (`options.verify.now`, or now),
 * never the envelope's `signed_at` -- an auditor needs to know when the check
 * happened, and the signing time is already inside the envelope.
 */
function verifiedAt(options: ResolveOptions): string {
  const value = options.verify?.now;
  const date = value === undefined ? new Date() : typeof value === 'string' ? new Date(value) : value;
  return Number.isNaN(date.getTime()) ? new Date().toISOString() : date.toISOString();
}

function verifyLink(
  partial: HushSpec,
  envelope: Uint8Array | string,
  options: ResolveOptions,
  isLeaf: boolean,
): SignatureStatus {
  const text = typeof envelope === 'string' ? envelope : new TextDecoder().decode(envelope);
  let document: unknown;
  try {
    document = JSON.parse(text) as unknown;
  } catch {
    return { verified: false, reason: 'malformed_envelope' };
  }

  const verifyOptions: VerifyOptions = {
    keyring: options.keyring,
    ...(options.verify?.now === undefined ? {} : { now: options.verify.now }),
    ...(options.verify?.maxClockSkewSeconds === undefined
      ? {}
      : { maxClockSkewSeconds: options.verify.maxClockSkewSeconds }),
    // Rollback protection is scoped to the policy the caller tracks a version
    // for -- the leaf. See VerifyClockOptions.lastSeenVersion.
    ...(isLeaf && options.verify?.lastSeenVersion !== undefined
      ? { lastSeenVersion: options.verify.lastSeenVersion }
      : {}),
  };

  const outcome: VerificationOutcome = verifyPolicy(partial, document, verifyOptions);
  if (outcome.ok) {
    return {
      verified: true,
      key_id: outcome.keyId,
      verified_at: verifiedAt(options),
    };
  }
  return {
    ...describeEnvelopeKey(document),
    verified: false,
    reason: outcome.reason,
  };
}

/** `sha256:` plus 64 lowercase hex: the only `key_id` the receipt schema admits. */
const KEY_ID_PATTERN = /^sha256:[0-9a-f]{64}$/;

/**
 * The `key_id` a failed envelope *claimed*, for the receipt. Claimed, not
 * trusted: verification already refused it, and recording which key was named
 * is what makes a rotation mistake distinguishable from an attack.
 *
 * An envelope that failed its own shape check may carry anything at all under
 * `key_id`, so only a well-formed one is surfaced.
 */
function describeEnvelopeKey(document: unknown): { key_id?: string } {
  if (typeof document !== 'object' || document === null) return {};
  const keyId = (document as { key_id?: unknown }).key_id;
  return typeof keyId === 'string' && KEY_ID_PATTERN.test(keyId) ? { key_id: keyId } : {};
}

// --------------------------------------------------------------------------
// Signature location (Signing specification section 7.1)
// --------------------------------------------------------------------------

/**
 * Where a detached envelope lives for a synchronously loaded hop.
 *
 * Files: `<path>.sig` first, then `<stem>.sig` for 0.1 layouts -- the
 * preference order section 7.1 makes normative. `builtin:` sources are part of
 * the engine and carry no envelope; `https:` sources need the async locator.
 */
export function defaultSignatureLocator(source: string): string | null {
  if (isBuiltinSource(source) || source === MEMORY_SOURCE) return null;
  if (/^https?:\/\//i.test(source)) return null;
  return readSidecar(source);
}

/** {@link defaultSignatureLocator} plus `<url>.sig` for `https:` sources. */
export async function defaultAsyncSignatureLocator(source: string): Promise<string | null> {
  if (isBuiltinSource(source) || source === MEMORY_SOURCE) return null;
  if (/^https?:\/\//i.test(source)) return fetchSignature(`${source}.sig`);
  return readSidecar(source);
}

function readSidecar(filePath: string): string | null {
  const appended = `${filePath}.sig`;
  if (existsSync(appended)) return readFileSync(appended, 'utf8');
  const extension = path.extname(filePath);
  if (extension !== '') {
    const replaced = `${filePath.slice(0, -extension.length)}.sig`;
    if (existsSync(replaced)) return readFileSync(replaced, 'utf8');
  }
  return null;
}

// --------------------------------------------------------------------------
// Filesystem
// --------------------------------------------------------------------------

function readPolicyFile(filePath: string): LoadedSpec {
  let source: string;
  let text: string;
  try {
    source = realpathSync(filePath);
    text = readFileSync(source, 'utf8');
  } catch (error) {
    throw new ResolveError(
      'read',
      `Failed to read HushSpec at ${filePath}: ` +
        `${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const parsed = parse(text);
  if (!parsed.ok) {
    throw new ResolveError('parse', `Failed to parse HushSpec at ${source}: ${parsed.error}`);
  }
  return { source, spec: parsed.value };
}

function loadFromFilesystem(reference: string, from?: string): LoadedSpec {
  const resolvedPath = path.isAbsolute(reference)
    ? reference
    : from
      ? path.resolve(path.dirname(from), reference)
      : path.resolve(reference);
  return readPolicyFile(resolvedPath);
}
