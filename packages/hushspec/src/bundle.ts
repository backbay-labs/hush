import {
  createHash,
  createPrivateKey,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from 'node:crypto';
import path from 'node:path';
import { canonicalJson, canonicalizeValue, contentHash, type JsonValue } from './canonical.js';
import {
  Keyring,
  keyIdFromPublicKey,
  keyringFromPublicKey,
  loadKeyring,
  publicKeyPemFromPrivateKey,
  type KeyringDocument,
} from './signing.js';
import { isMillisecondTimestamp } from './receipt.js';
import { resolutionFromResolved, type ChainLink, type Resolution, type SignatureStatus } from './resolve.js';
import type { HushSpec } from './schema.js';
import { SDK_NAME, SDK_VERSION } from './version.js';

/**
 * Policy bundle verification (spec/hushspec-bundle.md, format 0.1).
 *
 * A bundle is a [DSSE] envelope over an [in-toto Statement v1] whose
 * predicate carries the resolved policy, every hop of the `extends` chain
 * that produced it, and the resolver that produced them -- the evidence a
 * signature and a receipt each name by content hash but neither carries.
 *
 * {@link createBundle} builds one from a {@link Resolution} and
 * {@link verifyBundle} checks one. Creation is deterministic: the payload is
 * the RFC 8785 serialization of the statement and Ed25519 is deterministic, so
 * the same resolution, `createdAt`, and resolver always yield the same bytes
 * (bundle spec 4).
 *
 * {@link verifyBundle} runs the four ordered checks of bundle spec 5.2 and
 * stops at the first failure, reporting the {@link BundleReason} that check
 * owns:
 *
 * 1. shape -- envelope, statement, predicate;
 * 2. signature -- Ed25519 over `PAE(payloadType, payload)`, under a key the
 *    keyring holds whose id is recomputed from the key itself;
 * 3. subject -- `predicate.resolved` must hash to what the statement claims;
 * 4. policy -- optionally, the caller's own resolution must be the bundled one.
 *
 * Check 2 precedes check 3 deliberately: an edit in transit breaks the
 * signature first, so `subject_digest_mismatch` means a correctly signed but
 * internally inconsistent statement -- a bundler bug -- rather than tampering.
 *
 * The normative vectors live in `fixtures/bundle/`;
 * `tests/bundle-vectors.test.ts` runs them all.
 *
 * [DSSE]: https://github.com/secure-systems-lab/dsse
 * [in-toto Statement v1]: https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
 */

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

/** The predicate format version this module accepts. */
export const BUNDLE_VERSION = '0.1';

/** The DSSE `payloadType` of every bundle. */
export const BUNDLE_PAYLOAD_TYPE = 'application/vnd.in-toto+json';

/** The in-toto statement type of every bundle payload. */
export const BUNDLE_STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';

/** The predicate type that names the bundle specification. */
export const BUNDLE_PREDICATE_TYPE = 'https://hushspec.dev/attestation/policy-bundle/v0.1';

/** The DSSE PAE version prefix (bundle spec 3.1). */
const PAE_PREFIX = 'DSSEv1';

const HEX_DIGEST = /^[0-9a-f]{64}$/;
const CONTENT_HASH = /^sha256:[0-9a-f]{64}$/;
const ED25519_SIGNATURE_BYTES = 64;

// --------------------------------------------------------------------------
// The wire format (bundle spec 3 and 4)
// --------------------------------------------------------------------------

/** One DSSE signature over the payload's PAE. */
export interface DsseSignature {
  /** The signing key's `key_id` (signing spec 5.2). Never trusted as declared. */
  keyid: string;
  /** Standard base64 with padding of the 64 signature bytes. */
  sig: string;
}

/** A policy bundle: a DSSE envelope carrying an in-toto statement. */
export interface DsseEnvelope {
  /** Always {@link BUNDLE_PAYLOAD_TYPE}. */
  payloadType: string;
  /** Standard base64 with padding of the statement's canonical bytes. */
  payload: string;
  /** Zero or more signatures. Empty means unsigned, which is not evidence. */
  signatures: DsseSignature[];
}

/** The digest of an in-toto subject. Only `sha256` is defined. */
export interface SubjectDigest {
  /** 64 lowercase hex digits: the content hash **without** its prefix. */
  sha256: string;
}

/** The attested artifact: the canonical form of the resolved policy. */
export interface BundleSubject {
  /** Informational label: the policy's `name`, else the leaf file name. */
  name: string;
  digest: SubjectDigest;
}

/** What produced the bundle. */
export interface BundleResolver {
  /** `"h2h"` for the reference CLI. */
  tool: string;
  version: string;
}

/**
 * Identity of the resolved policy -- the same fields a receipt's `policy`
 * block carries (receipt spec 4.2), so a receipt and a bundle join on
 * `content_hash`.
 */
export interface BundlePolicyIdentity {
  /** `sha256:`-prefixed content hash of the resolved policy. */
  content_hash: string;
  /** The resolved document's `hushspec` field. */
  spec_version: string;
  name?: string;
  policy_version?: number;
}

/** The policy-bundle predicate (bundle spec 4.2). */
export interface PolicyBundlePredicate {
  /** Always {@link BUNDLE_VERSION}. */
  bundle_version: string;
  policy: BundlePolicyIdentity;
  /** The `extends` chain, root first and leaf last. */
  chain: ChainLink[];
  /** The canonical projection of the resolved document. */
  resolved: JsonValue;
  resolver: BundleResolver;
  /** RFC 3339 UTC, millisecond precision, `Z` suffix. */
  created_at: string;
  /** The leaf policy's own signature status at bundling time. */
  signature_verification?: SignatureStatus;
}

/** An in-toto Statement v1 carrying a policy-bundle predicate. */
export interface BundleStatement {
  /** Always {@link BUNDLE_STATEMENT_TYPE}. */
  _type: string;
  /** Exactly one subject. */
  subject: BundleSubject[];
  /** Always {@link BUNDLE_PREDICATE_TYPE}. */
  predicateType: string;
  predicate: PolicyBundlePredicate;
}

// --------------------------------------------------------------------------
// Outcomes (bundle spec 5.4)
// --------------------------------------------------------------------------

/**
 * The closed set of bundle verification reason codes (bundle spec 5.4). A
 * verifier never invents a code outside it.
 */
export type BundleReason =
  /** Check 1: not a well-formed bundle, statement, or predicate. */
  | 'malformed_bundle'
  /** Check 2: no signature names a key the keyring holds. */
  | 'unknown_key_id'
  /** Check 2: the only keys that signed are revoked (signing spec 5.3). */
  | 'key_revoked'
  /**
   * Check 2: the only keys that signed were retired before the bundle was
   * created (signing spec 5.3).
   */
  | 'key_retired'
  /** Check 2: a usable key was found but no signature verifies over the PAE. */
  | 'dsse_signature_mismatch'
  /** Check 3: `predicate.resolved` does not hash to the declared subject. */
  | 'subject_digest_mismatch'
  /** Check 4: the policy the verifier holds is not the bundled one. */
  | 'policy_mismatch';

/** Every reason code, in check order. */
export const BUNDLE_REASONS: readonly BundleReason[] = [
  'malformed_bundle',
  'unknown_key_id',
  'key_revoked',
  'key_retired',
  'dsse_signature_mismatch',
  'subject_digest_mismatch',
  'policy_mismatch',
];

/** The claims of a bundle that passed every check. */
export interface BundleVerified {
  readonly ok: true;
  /** Every key whose signature verified. */
  readonly keyIds: string[];
  /** The subject label. */
  readonly subjectName: string;
  /** The resolved policy's content hash, `sha256:`-prefixed. */
  readonly contentHash: string;
  readonly policyName?: string;
  readonly policyVersion?: number;
  readonly createdAt: string;
  /** Number of `extends` hops the bundle records. */
  readonly chainLength: number;
  /** Whether check 4 ran (a policy was supplied). */
  readonly policyChecked: boolean;
  /** The verifier's clock, in the receipt timestamp form. */
  readonly verifiedAt: string;
}

/** A verification that failed, carrying the reason code of bundle spec 5.4. */
export interface BundleVerificationFailure {
  readonly ok: false;
  readonly reason: BundleReason;
  /** Free-text detail; informational, never a substitute for {@link reason}. */
  readonly detail: string;
}

export type BundleVerificationOutcome = BundleVerified | BundleVerificationFailure;

/**
 * A bundle *configuration* failure -- unreadable JSON handed to
 * {@link parseBundle}, or key material that will not load.
 *
 * Verification failures are not errors: they come back as a
 * {@link BundleVerificationFailure} carrying a {@link BundleReason}.
 */
export class BundleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BundleError';
  }
}

// --------------------------------------------------------------------------
// PAE (bundle spec 3.1)
// --------------------------------------------------------------------------

/**
 * The DSSE Pre-Authentication Encoding (bundle spec 3.1).
 *
 * `PAE(t, b) = "DSSEv1" SP LEN(t) SP t SP LEN(b) SP b`, with lengths in ASCII
 * decimal over **bytes**. Binding the type into the signed bytes is what stops
 * a payload being replayed under a different type.
 */
export function pae(payloadType: string, payload: Buffer | Uint8Array): Buffer {
  const type = Buffer.from(payloadType, 'utf8');
  const body = Buffer.from(payload);
  const header = Buffer.from(
    `${PAE_PREFIX} ${type.length} ${payloadType} ${body.length} `,
    'utf8',
  );
  return Buffer.concat([header, body]);
}

// --------------------------------------------------------------------------
// Parsing (bundle spec 5.2 check 1)
// --------------------------------------------------------------------------

/**
 * Parse a bundle from JSON text (or an already-parsed value), checking the
 * envelope's shape.
 *
 * @throws {BundleError} when the text is not JSON, carries an unknown member,
 *   is missing a required one, or names a payload type this specification
 *   does not define. A caller that needs the reason code calls
 *   {@link verifyBundle}, which reports `malformed_bundle` instead.
 */
export function parseBundle(json: string | unknown): DsseEnvelope {
  const outcome = readEnvelope(json);
  if (!outcome.ok) throw new BundleError(outcome.detail);
  return outcome.envelope;
}

/**
 * The decoded, shape-checked statement of a bundle.
 *
 * @throws {BundleError} when the payload is not base64, not UTF-8 JSON, or
 *   not a policy-bundle statement.
 */
export function bundleStatement(envelope: DsseEnvelope): BundleStatement {
  const outcome = readStatement(envelope);
  if (!outcome.ok) throw new BundleError(outcome.detail);
  return outcome.statement;
}

// --------------------------------------------------------------------------
// Creation (bundle spec 4)
// --------------------------------------------------------------------------

/** The reference CLI's `resolver.tool` (bundle spec 4.2). */
export const BUNDLE_RESOLVER_TOOL = 'h2h';

/** Options for {@link createBundle} and {@link buildBundleStatement}. */
export interface CreateBundleOptions {
  /**
   * PKCS#8 PEM Ed25519 private key that signs the bundle. Omitting it produces
   * an **unsigned** bundle: a well-formed envelope with an empty `signatures`
   * array, which bundle spec 3 says is not evidence and {@link verifyBundle}
   * rejects. A tool that produces one must say so.
   */
  privateKeyPem?: string;
  /**
   * `predicate.created_at`. Default now. Pinning it is what makes a bundle
   * byte-reproducible: two bundlers given the same resolution, the same
   * `createdAt`, and the same resolver produce identical bytes (bundle spec 4).
   */
  createdAt?: Date | string;
  /**
   * `resolver.tool`. Default {@link SDK_NAME}. Overriding it is how a bundle
   * some other tool produced is reproduced byte-for-byte: the vectors in
   * `fixtures/bundle/` come from the reference CLI, so rebuilding them here
   * needs `tool: 'h2h'` and that CLI's `version`.
   */
  tool?: string;
  /** `resolver.version`. Default {@link SDK_VERSION}. */
  version?: string;
  /** Overrides the subject name, which otherwise comes from the policy. */
  subjectName?: string;
  /**
   * Directory that filesystem chain sources are recorded relative to (bundle
   * spec 4.4), so a bundle built in CI neither leaks nor depends on a runner's
   * workspace path. `builtin:` and URL sources are already portable and are
   * recorded unchanged, as is any path outside the directory.
   */
  baseDir?: string;
}

/**
 * Build the in-toto statement for a resolved policy (bundle spec 4).
 *
 * The subject digest is recomputed from the canonical projection that goes
 * into `predicate.resolved`, so the statement is internally consistent by
 * construction: there is no path by which a bundle names the hash of a
 * document other than the one it carries.
 *
 * @throws {BundleError} when the resolved document has no canonical form,
 *   which for a {@link Resolution} means a resolver bug.
 */
export function buildBundleStatement(
  resolution: Resolution,
  options: CreateBundleOptions = {},
): BundleStatement {
  let resolved: JsonValue;
  try {
    // `canonicalJson` serializes the projection of canonical spec 3; parsing
    // it back yields that projection as a JSON object, which is what
    // `predicate.resolved` holds. Re-serializing it with RFC 8785 reproduces
    // the same bytes, so the digest below is the policy's content hash.
    resolved = JSON.parse(canonicalJson(resolution.spec)) as JsonValue;
  } catch (error) {
    throw new BundleError(`the resolved policy has no canonical form: ${describe(error)}`);
  }
  const hash = digestOf(canonicalizeValue(resolved));

  const chain: ChainLink[] = resolution.chain.map(link => ({
    source: relativeSource(link.source, options.baseDir),
    content_hash: link.content_hash,
    ...(link.signature === undefined ? {} : { signature: link.signature }),
  }));

  const spec = resolution.spec;
  const policyVersion = spec.metadata?.policy_version;

  return {
    _type: BUNDLE_STATEMENT_TYPE,
    subject: [
      {
        // The subject needs at least one character (bundle spec 4.1), so a
        // policy that declares an empty name falls through to the file name.
        name: nonEmpty(options.subjectName) ?? nonEmpty(spec.name) ?? leafFileName(chain) ?? 'policy',
        // The `sha256:` prefix is stripped here and only here, because that is
        // the form in-toto requires of a subject digest (bundle spec 4.1).
        digest: { sha256: hash.replace(/^sha256:/, '') },
      },
    ],
    predicateType: BUNDLE_PREDICATE_TYPE,
    predicate: {
      bundle_version: BUNDLE_VERSION,
      policy: {
        content_hash: hash,
        spec_version: spec.hushspec,
        ...(nonEmpty(spec.name) === undefined ? {} : { name: spec.name }),
        ...(policyVersion === undefined ? {} : { policy_version: policyVersion }),
      },
      chain,
      resolved,
      resolver: {
        tool: options.tool ?? SDK_NAME,
        version: options.version ?? SDK_VERSION,
      },
      created_at: timestamp(options.createdAt ?? new Date()),
      // A bundler that attempted no verification omits the member rather than
      // recording `verified: false`, which would assert a check that never ran
      // (bundle spec 4.5).
      ...(resolution.signature === undefined
        ? {}
        : { signature_verification: resolution.signature }),
    },
  };
}

/**
 * The payload bytes of a statement: its RFC 8785 canonical serialization,
 * UTF-8 encoded (bundle spec 4).
 *
 * @throws {BundleError} for a value RFC 8785 cannot represent, which a
 *   statement's own members never are.
 */
export function bundleStatementBytes(statement: BundleStatement): Buffer {
  try {
    return Buffer.from(canonicalizeValue(statement as unknown as JsonValue), 'utf8');
  } catch (error) {
    throw new BundleError(`the statement has no canonical form: ${describe(error)}`);
  }
}

/**
 * Build a bundle for a resolution: signed when a private key is given,
 * unsigned otherwise (bundle spec 3 and 4).
 *
 * The payload is canonical and Ed25519 is deterministic, so the result is a
 * pure function of the resolution, `createdAt`, the resolver, and the key.
 * `tests/bundle-create.test.ts` proves it by rebuilding
 * `fixtures/bundle/bundles/valid.bundle.json` byte-for-byte.
 *
 * @throws {BundleError} when the resolved policy has no canonical form, or
 *   when the private key will not load as Ed25519.
 */
export function createBundle(
  resolution: Resolution,
  options: CreateBundleOptions = {},
): DsseEnvelope {
  const payloadBytes = bundleStatementBytes(buildBundleStatement(resolution, options));
  const payload = payloadBytes.toString('base64');
  const signatures =
    options.privateKeyPem === undefined
      ? []
      : [signPayload(payloadBytes, options.privateKeyPem)];
  return { payloadType: BUNDLE_PAYLOAD_TYPE, payload, signatures };
}

/**
 * Serialize a bundle the way the reference CLI writes one: pretty-printed with
 * a trailing newline.
 */
export function bundleToJson(envelope: DsseEnvelope): string {
  return `${JSON.stringify(envelope, null, 2)}\n`;
}

/** One DSSE signature over `PAE(payloadType, payload)` (bundle spec 3.1). */
function signPayload(payloadBytes: Buffer, privateKeyPem: string): DsseSignature {
  let key: KeyObject;
  try {
    key = createPrivateKey(privateKeyPem);
  } catch (error) {
    throw new BundleError(`could not read the PKCS#8 private key: ${describe(error)}`);
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new BundleError(
      `private key is ${String(key.asymmetricKeyType)}, not Ed25519; `
        + 'bundle format 0.1 defines Ed25519 only',
    );
  }
  return {
    // The id is derived from the key itself, never declared independently: a
    // verifier recomputes it and would reject any other value (signing 5.2).
    keyid: keyIdFromPublicKey(publicKeyPemFromPrivateKey(privateKeyPem)),
    sig: edSign(null, pae(BUNDLE_PAYLOAD_TYPE, payloadBytes), key).toString('base64'),
  };
}

/**
 * Record a filesystem source relative to `base` when it lies beneath it
 * (bundle spec 4.4). `builtin:` and URL sources are already portable and are
 * returned unchanged, as is any path that is not beneath `base`.
 */
function relativeSource(source: string, base?: string): string {
  if (base === undefined || source.startsWith('builtin:') || source.includes('://')) {
    return source;
  }
  const relative = path.relative(base, source);
  // Only a `..` *segment* leaves `base`: a name that merely starts with two
  // dots (`..cache/policy.yaml`) is beneath it like any other.
  if (
    relative === ''
    || relative === '..'
    || relative.startsWith(`..${path.sep}`)
    || path.isAbsolute(relative)
  ) {
    return source;
  }
  // A bundle is JSON read on every platform, so the separator is `/`.
  return relative.split(path.sep).join('/');
}

/** `value` when it has one character or more: the bundle schema admits no empty name. */
function nonEmpty(value: string | undefined): string | undefined {
  return value === undefined || value === '' ? undefined : value;
}

/** The leaf's file name, for a policy that declares no `name`. */
function leafFileName(chain: ChainLink[]): string | undefined {
  const source = chain[chain.length - 1]?.source;
  const base = source?.split(/[/\\]/).pop();
  return base === undefined || base === '' ? undefined : base;
}

// --------------------------------------------------------------------------
// Verification (bundle spec 5)
// --------------------------------------------------------------------------

/** Options for {@link verifyBundle}. Exactly one key source is required. */
export interface VerifyBundleOptions {
  /**
   * The keys the verifier trusts. A {@link Keyring}, a keyring document, or
   * the JSON text of one; anything but a `Keyring` goes through
   * `loadKeyring`, which recomputes every `key_id`.
   */
  keyring?: Keyring | KeyringDocument | string;
  /**
   * A single SPKI PEM public key, treated as a one-key keyring with its
   * `key_id` recomputed from it (signing spec 5.3).
   */
  publicKeyPem?: string;
  /**
   * The verifier's clock. A bundle carries no expiry, so this only stamps
   * {@link BundleVerified.verifiedAt}. Default now.
   */
  now?: Date | string;
  /**
   * The verifier's own resolution of the policy to cross-check against
   * (check 4). A bare resolved document is wrapped as a single-link
   * resolution; omit to skip check 4.
   */
  policy?: Resolution | HushSpec;
}

/**
 * Run the four ordered checks of bundle spec 5.2, stopping at the first
 * failure.
 *
 * @throws {import('./signing.js').SigningError} when the key material itself
 *   will not load. A bundle that fails verification is not an error: it comes
 *   back as a {@link BundleVerificationFailure}.
 */
export function verifyBundle(
  bundleJson: string | DsseEnvelope | unknown,
  options: VerifyBundleOptions,
): BundleVerificationOutcome {
  const keyring = resolveKeyring(options);

  // 1. Shape.
  const parsed = readEnvelope(bundleJson);
  if (!parsed.ok) return failure('malformed_bundle', parsed.detail);
  const envelope = parsed.envelope;

  const payload = decodePayload(envelope);
  if (!payload.ok) return failure('malformed_bundle', payload.detail);

  const read = readStatement(envelope, payload.bytes);
  if (!read.ok) return failure('malformed_bundle', read.detail);
  const statement = read.statement;
  const predicate = statement.predicate;

  // 2. Signature. A bundle may carry several; one that verifies under a key
  //    the keyring still trusts is enough, and the reason code distinguishes
  //    "we trust nobody who signed this" from "the key is withdrawn" from
  //    "the signature is wrong".
  const paeBytes = pae(envelope.payloadType, payload.bytes);
  const keyIds: string[] = [];
  let refusal: BundleVerificationFailure | undefined;
  const record = (candidate: BundleVerificationFailure): void => {
    const held = refusal;
    if (held === undefined || reasonPrecedence(candidate.reason) < reasonPrecedence(held.reason)) {
      refusal = candidate;
    }
  };
  for (const signature of envelope.signatures) {
    const entry = keyring.get(signature.keyid);
    if (entry === undefined) continue;
    // The declared id is never enough (signing spec 5.2): `loadKeyring`
    // recomputes every entry's id from its own public key, so a keyring hit
    // is already a hit on the recomputed id.
    //
    // The keyring holds the key; whether it still vouches for it is the next
    // question (signing spec 5.3).
    if (entry.revoked) {
      record(failure('key_revoked', `key ${signature.keyid} is revoked`));
      continue;
    }
    if (entry.notAfter !== undefined && retiredAt(entry.notAfter, predicate.created_at)) {
      record(failure(
        'key_retired',
        `key ${signature.keyid} was retired at ${entry.notAfter}; the bundle is dated `
        + `${predicate.created_at}`,
      ));
      continue;
    }
    const bytes = decodeBase64(signature.sig);
    if (bytes === undefined || bytes.length !== ED25519_SIGNATURE_BYTES) {
      record(failure('dsse_signature_mismatch', `signature by ${signature.keyid} is not 64 bytes`));
      continue;
    }
    if (ed25519Verify(paeBytes, bytes, entry.publicKey)) {
      keyIds.push(signature.keyid);
    } else {
      record(failure(
        'dsse_signature_mismatch',
        `Ed25519 verification failed for ${signature.keyid}`,
      ));
    }
  }
  if (keyIds.length === 0) {
    if (refusal !== undefined) return refusal;
    if (envelope.signatures.length === 0) {
      return failure(
        'dsse_signature_mismatch',
        'the bundle is unsigned; an unsigned bundle is not evidence',
      );
    }
    return failure(
      'unknown_key_id',
      `none of the ${envelope.signatures.length} signature(s) names a key in the keyring `
      + `(${keyring.keys.length} trusted)`,
    );
  }

  // 3. Subject: the bundle must hash to what it claims to be about.
  let recomputed: string;
  try {
    recomputed = digestOf(canonicalizeValue(predicate.resolved));
  } catch (error) {
    return failure(
      'subject_digest_mismatch',
      `predicate.resolved has no canonical form: ${describe(error)}`,
    );
  }
  if (recomputed !== predicate.policy.content_hash) {
    return failure(
      'subject_digest_mismatch',
      `predicate.resolved hashes to ${recomputed}, but policy.content_hash is `
      + `${predicate.policy.content_hash}`,
    );
  }
  const declared = statement.subject[0].digest.sha256;
  const expected = recomputed.slice('sha256:'.length);
  if (declared !== expected) {
    return failure(
      'subject_digest_mismatch',
      `the subject digest is ${declared}, but predicate.resolved hashes to ${expected}`,
    );
  }

  // 4. Policy: is the bundle about the policy the verifier holds?
  if (options.policy !== undefined) {
    const mismatch = comparePolicy(predicate, asResolution(options.policy));
    if (mismatch !== undefined) return mismatch;
  }

  return {
    ok: true,
    keyIds,
    subjectName: statement.subject[0].name,
    contentHash: predicate.policy.content_hash,
    ...(predicate.policy.name === undefined ? {} : { policyName: predicate.policy.name }),
    ...(predicate.policy.policy_version === undefined
      ? {}
      : { policyVersion: predicate.policy.policy_version }),
    createdAt: predicate.created_at,
    chainLength: predicate.chain.length,
    policyChecked: options.policy !== undefined,
    verifiedAt: timestamp(options.now ?? new Date()),
  };
}

/**
 * Check 4 (bundle spec 5.3): the resolved documents and the chain hashes must
 * agree. `source` is a provenance label and is never compared.
 *
 * The resolved documents are compared through their canonical forms, not as
 * JSON values: a value tree that has been through a JSON round trip can hold
 * `10` where the projection held `10.0`, which RFC 8785 serializes identically
 * (canonical spec 4.3). Check 3 has already tied
 * `predicate.policy.content_hash` to `predicate.resolved`, so comparing hashes
 * here is comparing the bytes.
 */
function comparePolicy(
  predicate: PolicyBundlePredicate,
  resolution: Resolution | undefined,
): BundleVerificationFailure | undefined {
  if (resolution === undefined) {
    return failure('policy_mismatch', 'the policy did not resolve, so there is nothing to compare');
  }

  let resolved: string;
  try {
    resolved = contentHash(resolution.spec);
  } catch (error) {
    return failure('policy_mismatch', `the policy has no canonical form: ${describe(error)}`);
  }
  if (resolved !== predicate.policy.content_hash) {
    return failure(
      'policy_mismatch',
      `the policy resolves to ${resolved}, but the bundle attests ${predicate.policy.content_hash}`,
    );
  }
  if (resolution.chain.length !== predicate.chain.length) {
    return failure(
      'policy_mismatch',
      `the policy resolves through ${resolution.chain.length} document(s), the bundle records `
      + `${predicate.chain.length}`,
    );
  }
  for (const [index, actual] of resolution.chain.entries()) {
    const bundled = predicate.chain[index];
    if (actual.content_hash !== bundled.content_hash) {
      return failure(
        'policy_mismatch',
        `chain hop ${JSON.stringify(actual.source)} hashes to ${actual.content_hash}, but the `
        + `bundle records ${bundled.content_hash} for ${JSON.stringify(bundled.source)}`,
      );
    }
  }
  return undefined;
}

// --------------------------------------------------------------------------
// Shape helpers
// --------------------------------------------------------------------------

type EnvelopeRead =
  | { ok: true; envelope: DsseEnvelope }
  | { ok: false; detail: string };

const ENVELOPE_KEYS = new Set(['payloadType', 'payload', 'signatures']);
const SIGNATURE_KEYS = new Set(['keyid', 'sig']);
const STATEMENT_KEYS = new Set(['_type', 'subject', 'predicateType', 'predicate']);
const SUBJECT_KEYS = new Set(['name', 'digest']);
const DIGEST_KEYS = new Set(['sha256']);
const PREDICATE_KEYS = new Set([
  'bundle_version',
  'policy',
  'chain',
  'resolved',
  'resolver',
  'created_at',
  'signature_verification',
]);
const POLICY_KEYS = new Set(['content_hash', 'spec_version', 'name', 'policy_version']);
const RESOLVER_KEYS = new Set(['tool', 'version']);
const CHAIN_LINK_KEYS = new Set(['source', 'content_hash', 'signature']);

function readEnvelope(json: string | unknown): EnvelopeRead {
  let value: unknown = json;
  if (typeof json === 'string') {
    try {
      value = JSON.parse(json) as unknown;
    } catch (error) {
      return { ok: false, detail: `the bundle is not JSON: ${describe(error)}` };
    }
  }
  if (!isRecord(value)) {
    return { ok: false, detail: 'a bundle is a JSON object' };
  }
  const unknownKey = firstUnknownKey(value, ENVELOPE_KEYS);
  if (unknownKey !== undefined) {
    return { ok: false, detail: `unknown envelope member ${JSON.stringify(unknownKey)}` };
  }
  if (typeof value.payloadType !== 'string') {
    return { ok: false, detail: 'payloadType is required and must be a string' };
  }
  if (value.payloadType !== BUNDLE_PAYLOAD_TYPE) {
    return {
      ok: false,
      detail: `payloadType ${JSON.stringify(value.payloadType)}, expected `
        + `${JSON.stringify(BUNDLE_PAYLOAD_TYPE)}`,
    };
  }
  if (typeof value.payload !== 'string') {
    return { ok: false, detail: 'payload is required and must be a base64 string' };
  }
  if (!Array.isArray(value.signatures)) {
    return { ok: false, detail: 'signatures is required and must be an array' };
  }
  const signatures: DsseSignature[] = [];
  for (const entry of value.signatures) {
    if (!isRecord(entry)) {
      return { ok: false, detail: 'every signature is a JSON object' };
    }
    const unknownSignatureKey = firstUnknownKey(entry, SIGNATURE_KEYS);
    if (unknownSignatureKey !== undefined) {
      return {
        ok: false,
        detail: `unknown signature member ${JSON.stringify(unknownSignatureKey)}`,
      };
    }
    if (typeof entry.keyid !== 'string' || typeof entry.sig !== 'string') {
      return { ok: false, detail: 'a signature carries a string keyid and a string sig' };
    }
    signatures.push({ keyid: entry.keyid, sig: entry.sig });
  }
  return {
    ok: true,
    envelope: { payloadType: value.payloadType, payload: value.payload, signatures },
  };
}

function decodePayload(
  envelope: DsseEnvelope,
): { ok: true; bytes: Buffer } | { ok: false; detail: string } {
  const bytes = decodeBase64(envelope.payload);
  if (bytes === undefined) {
    return { ok: false, detail: 'payload is not standard base64' };
  }
  return { ok: true, bytes };
}

type StatementRead =
  | { ok: true; statement: BundleStatement }
  | { ok: false; detail: string };

function readStatement(envelope: DsseEnvelope, decoded?: Buffer): StatementRead {
  let bytes = decoded;
  if (bytes === undefined) {
    const payload = decodePayload(envelope);
    if (!payload.ok) return payload;
    bytes = payload.bytes;
  }

  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (error) {
    return { ok: false, detail: `the payload is not UTF-8: ${describe(error)}` };
  }

  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch (error) {
    return { ok: false, detail: `the payload is not a policy-bundle statement: ${describe(error)}` };
  }
  return checkStatement(value);
}

/** Everything bundle spec 5.2 check 1 constrains beyond the envelope. */
function checkStatement(value: unknown): StatementRead {
  const bad = (detail: string): StatementRead => ({ ok: false, detail });

  if (!isRecord(value)) return bad('the payload is not a JSON object');
  const unknownKey = firstUnknownKey(value, STATEMENT_KEYS);
  if (unknownKey !== undefined) {
    return bad(`unknown statement member ${JSON.stringify(unknownKey)}`);
  }
  if (value._type !== BUNDLE_STATEMENT_TYPE) {
    return bad(
      `_type ${JSON.stringify(value._type)}, expected ${JSON.stringify(BUNDLE_STATEMENT_TYPE)}`,
    );
  }
  if (value.predicateType !== BUNDLE_PREDICATE_TYPE) {
    return bad(
      `predicateType ${JSON.stringify(value.predicateType)}, expected `
      + `${JSON.stringify(BUNDLE_PREDICATE_TYPE)}`,
    );
  }
  if (!Array.isArray(value.subject) || value.subject.length !== 1) {
    return bad(
      `a bundle attests exactly one subject, found `
      + `${Array.isArray(value.subject) ? value.subject.length : 'none'}`,
    );
  }
  const subject = value.subject[0] as unknown;
  if (!isRecord(subject)) return bad('the subject is not a JSON object');
  const unknownSubjectKey = firstUnknownKey(subject, SUBJECT_KEYS);
  if (unknownSubjectKey !== undefined) {
    return bad(`unknown subject member ${JSON.stringify(unknownSubjectKey)}`);
  }
  if (typeof subject.name !== 'string' || subject.name.length === 0) {
    return bad('the subject name is empty');
  }
  if (!isRecord(subject.digest)) return bad('the subject digest is not a JSON object');
  const unknownDigestKey = firstUnknownKey(subject.digest, DIGEST_KEYS);
  if (unknownDigestKey !== undefined) {
    return bad(`unknown subject digest member ${JSON.stringify(unknownDigestKey)}`);
  }
  const sha256 = subject.digest.sha256;
  if (typeof sha256 !== 'string' || !HEX_DIGEST.test(sha256)) {
    return bad(`subject digest ${JSON.stringify(sha256)} is not 64 lowercase hex characters`);
  }

  if (!isRecord(value.predicate)) return bad('the predicate is not a JSON object');
  const predicate = value.predicate;
  const unknownPredicateKey = firstUnknownKey(predicate, PREDICATE_KEYS);
  if (unknownPredicateKey !== undefined) {
    return bad(`unknown predicate member ${JSON.stringify(unknownPredicateKey)}`);
  }
  if (predicate.bundle_version !== BUNDLE_VERSION) {
    return bad(
      `bundle_version ${JSON.stringify(predicate.bundle_version)}, expected `
      + `${JSON.stringify(BUNDLE_VERSION)}`,
    );
  }
  if (!isRecord(predicate.policy)) return bad('predicate.policy is not a JSON object');
  const unknownPolicyKey = firstUnknownKey(predicate.policy, POLICY_KEYS);
  if (unknownPolicyKey !== undefined) {
    return bad(`unknown predicate.policy member ${JSON.stringify(unknownPolicyKey)}`);
  }
  const policyHash = predicate.policy.content_hash;
  if (typeof policyHash !== 'string' || !CONTENT_HASH.test(policyHash)) {
    return bad(
      `policy.content_hash ${JSON.stringify(policyHash)} is not sha256:<64 lowercase hex>`,
    );
  }
  if (typeof predicate.policy.spec_version !== 'string'
    || predicate.policy.spec_version.length === 0) {
    return bad('policy.spec_version is empty');
  }
  if (predicate.policy.name !== undefined && typeof predicate.policy.name !== 'string') {
    return bad('policy.name must be a string');
  }
  if (predicate.policy.policy_version !== undefined
    && !Number.isInteger(predicate.policy.policy_version)) {
    return bad('policy.policy_version must be an integer');
  }
  if (typeof predicate.created_at !== 'string'
    || !isMillisecondTimestamp(predicate.created_at)) {
    return bad(
      `created_at ${JSON.stringify(predicate.created_at)} is not RFC 3339 UTC with millisecond `
      + 'precision',
    );
  }
  if (!isRecord(predicate.resolver)) return bad('predicate.resolver is not a JSON object');
  const unknownResolverKey = firstUnknownKey(predicate.resolver, RESOLVER_KEYS);
  if (unknownResolverKey !== undefined) {
    return bad(`unknown predicate.resolver member ${JSON.stringify(unknownResolverKey)}`);
  }
  if (typeof predicate.resolver.tool !== 'string' || predicate.resolver.tool.length === 0
    || typeof predicate.resolver.version !== 'string'
    || predicate.resolver.version.length === 0) {
    return bad('resolver.tool and resolver.version are required and must be non-empty');
  }
  if (!Array.isArray(predicate.chain) || predicate.chain.length === 0) {
    return bad('the chain must hold at least one link (the policy itself)');
  }
  for (const link of predicate.chain) {
    if (!isRecord(link)) return bad('every chain link is a JSON object');
    const unknownLinkKey = firstUnknownKey(link, CHAIN_LINK_KEYS);
    if (unknownLinkKey !== undefined) {
      return bad(`unknown chain link member ${JSON.stringify(unknownLinkKey)}`);
    }
    if (typeof link.source !== 'string' || link.source.length === 0) {
      return bad('a chain link has an empty source');
    }
    if (typeof link.content_hash !== 'string' || !CONTENT_HASH.test(link.content_hash)) {
      return bad(
        `chain link ${JSON.stringify(link.source)} has content_hash `
        + `${JSON.stringify(link.content_hash)}, not sha256:<64 lowercase hex>`,
      );
    }
  }
  if (!isRecord(predicate.resolved)) {
    return bad('predicate.resolved is not a JSON object');
  }

  return { ok: true, statement: value as unknown as BundleStatement };
}

// --------------------------------------------------------------------------
// Small helpers
// --------------------------------------------------------------------------

function failure(reason: BundleReason, detail: string): BundleVerificationFailure {
  return { ok: false, reason, detail };
}

/**
 * Rank of the reason a failed signature contributes, lowest first: bundle spec
 * 5.2 check 2 reports a withdrawn key ahead of a wrong signature, the way the
 * signing specification's own checks 5 and 6 precede its check 8.
 */
function reasonPrecedence(reason: BundleReason): number {
  if (reason === 'key_revoked') return 0;
  if (reason === 'key_retired') return 1;
  return 2;
}

/**
 * Whether a key whose retirement instant is `notAfter` had already been retired
 * when a bundle dated `createdAt` was produced (bundle spec 5.2 check 2).
 *
 * Both are `YYYY-MM-DDTHH:MM:SS.sssZ` -- the keyring schema and the statement
 * shape check admit no other form -- so an unparseable one is a keyring this
 * verifier will not read a retirement out of, and the key is treated as
 * current.
 */
function retiredAt(notAfter: string, createdAt: string): boolean {
  const retired = Date.parse(notAfter);
  const created = Date.parse(createdAt);
  if (Number.isNaN(retired) || Number.isNaN(created)) return false;
  return created >= retired;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function firstUnknownKey(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
): string | undefined {
  return Object.keys(value).find(key => !allowed.has(key));
}

/**
 * Standard base64 with padding, rejecting anything else. `Buffer.from(.., 'base64')`
 * silently skips characters outside the alphabet, so a round trip through
 * `toString` is what actually enforces the encoding.
 */
function decodeBase64(text: string): Buffer | undefined {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) return undefined;
  const bytes = Buffer.from(text, 'base64');
  return bytes.toString('base64') === text ? bytes : undefined;
}

function ed25519Verify(message: Buffer, signature: Buffer, publicKey: KeyObject): boolean {
  try {
    return edVerify(null, message, publicKey, signature);
  } catch {
    // A key or signature Node refuses to touch is a failed verification, not
    // an exception to propagate: fail closed.
    return false;
  }
}

function digestOf(canonical: string): string {
  return `sha256:${createHash('sha256').update(canonical, 'utf8').digest('hex')}`;
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function timestamp(value: Date | string): string {
  const date = typeof value === 'string' ? new Date(value) : value;
  if (Number.isNaN(date.getTime())) {
    throw new BundleError(`${JSON.stringify(String(value))} is not a timestamp`);
  }
  // `toISOString` widens the year field outside 0000-9999 (`+275760-09-13`),
  // so the fixed slice would silently produce a malformed `created_at`. Refuse
  // it here, where the caller still has the input, rather than at read time.
  const formatted = `${date.toISOString().slice(0, 23)}Z`;
  if (!isMillisecondTimestamp(formatted)) {
    throw new BundleError(
      `${JSON.stringify(String(value))} is outside the range created_at can express`,
    );
  }
  return formatted;
}

function resolveKeyring(options: VerifyBundleOptions): Keyring {
  if (options.keyring !== undefined && options.publicKeyPem !== undefined) {
    throw new BundleError('pass either a keyring or a publicKeyPem, not both');
  }
  if (options.publicKeyPem !== undefined) {
    return keyringFromPublicKey(options.publicKeyPem);
  }
  if (options.keyring === undefined) {
    throw new BundleError('verifyBundle needs a keyring or a publicKeyPem');
  }
  return options.keyring instanceof Keyring ? options.keyring : loadKeyring(options.keyring);
}

/** A bare resolved document counts as a single-link resolution of itself. */
function asResolution(policy: Resolution | HushSpec): Resolution | undefined {
  if (isResolution(policy)) return policy;
  try {
    return resolutionFromResolved(policy);
  } catch {
    // A document with no canonical form has nothing to compare: check 4's own
    // failure, reported by comparePolicy.
    return undefined;
  }
}

function isResolution(value: Resolution | HushSpec): value is Resolution {
  return Object.prototype.hasOwnProperty.call(value, 'spec')
    && Object.prototype.hasOwnProperty.call(value, 'chain');
}
