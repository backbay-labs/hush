import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from 'node:crypto';
import { canonicalizeValue, contentHash, type JsonValue } from './canonical.js';
import type { HushSpec } from './schema.js';
import { validate } from './validate.js';

/**
 * Policy signing and verification (spec/hushspec-signing.md, format 0.2).
 *
 * What is signed is the **content hash of the resolved policy** (Canonical
 * Form spec section 5), never the file bytes: reformatting the YAML keeps a
 * signature valid, changing a base policy pulled in through `extends` does
 * not (signing spec section 3).
 *
 * The signature itself covers the RFC 8785 canonical form of the envelope
 * with `signature` removed (section 4.1), so every claim in the envelope --
 * algorithm, key id, timestamps, policy version -- is inside the signature and
 * an attacker cannot edit one afterwards.
 *
 * Everything here is fail-closed. An unknown `format_version`, an unknown
 * algorithm, a key that is not on the keyring, a keyring entry whose declared
 * `key_id` does not match its own public key: all are rejected, never guessed
 * around.
 *
 * ```ts
 * const resolved = resolveOrThrow(policy);
 * const envelope = signPolicy(resolved, readFileSync('h2h.key.pem', 'utf8'), {
 *   signer: 'security@example.com',
 * });
 *
 * const keyring = loadKeyring(readFileSync('keyring.json', 'utf8'));
 * const outcome = verifyPolicy(resolved, envelope, { keyring });
 * if (!outcome.ok) throw new Error(outcome.reason);
 * ```
 *
 * The normative vectors live in `fixtures/signing/`; `tests/signing-vectors.test.ts`
 * runs all sixteen of them.
 */

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

/** The envelope format this module produces and the only one it verifies. */
export const SIGNATURE_FORMAT_VERSION = '0.2';

/** The only algorithm defined in 0.2: RFC 8032 pure Ed25519, no pre-hash. */
export const SIGNATURE_ALGORITHM = 'ed25519';

/** The keyring document version this module accepts (spec section 5.3). */
export const KEYRING_VERSION = '0.2';

/** Spec section 6.3: the RECOMMENDED tolerance on a signer's clock, seconds. */
export const DEFAULT_MAX_CLOCK_SKEW_SECONDS = 300;

/** `sha256:` + 64 lowercase hex digits -- key ids and content hashes alike. */
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;

/** RFC 3339 UTC, millisecond precision, `Z` suffix (spec section 4). */
const TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;

/** base64url without padding over 64 signature bytes (RFC 4648 section 5). */
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;

const ED25519_SIGNATURE_BYTES = 64;

// --------------------------------------------------------------------------
// Types
// --------------------------------------------------------------------------

/**
 * The closed set of verification failure reasons (spec section 6.4). Verifiers
 * MUST expose these programmatically: they are what a receipt's
 * `policy.signature.reason` carries.
 */
export type ReasonCode =
  | 'malformed_envelope'
  | 'unsupported_format_version'
  | 'unsupported_algorithm'
  | 'unknown_key_id'
  | 'key_revoked'
  | 'key_retired'
  | 'signed_at_in_future'
  | 'expired'
  | 'signature_mismatch'
  | 'content_hash_mismatch'
  | 'policy_version_rollback';

/**
 * A detached signature envelope (spec section 4). Every member except
 * `signature` is a signed claim.
 *
 * Wire form: JSON, stored next to the policy as `<policy>.sig`.
 */
export interface Envelope {
  /** Always `"0.2"`. */
  format_version: string;
  /** Always `"ed25519"`. */
  algorithm: string;
  /** `sha256:` + hex SHA-256 of the signing key's SPKI DER (section 5.2). */
  key_id: string;
  /** RFC 3339 UTC, milliseconds, `Z`. */
  signed_at: string;
  /** Optional expiry; the signature is invalid at or after this instant. */
  expires_at?: string;
  /** `metadata.policy_version` at signing time; scopes rollback protection. */
  policy_version?: number;
  /** The policy's `name` at signing time. */
  policy_name?: string;
  /** Content hash of the resolved policy. */
  content_hash: string;
  /** Human-readable signer identity. */
  signer?: string;
  /** base64url without padding of the 64-byte Ed25519 signature. */
  signature: string;
}

/** Options for {@link signPolicy}. */
export interface SignOptions {
  /**
   * Signing time, default now. Truncated to milliseconds in the envelope, so
   * the value here is what the verifier's clock checks are measured against.
   */
  signedAt?: Date | string;
  /**
   * Optional expiry. Signers SHOULD set it for policies re-approved on a
   * cadence and MUST NOT set it beyond the approval interval (section 4.2).
   */
  expiresAt?: Date | string;
  /** Defaults to the policy's `metadata.policy_version` when it has one. */
  policyVersion?: number;
  /** Defaults to the policy's `name` when it has one. */
  policyName?: string;
  /** Human-readable signer identity, e.g. an approver's address. */
  signer?: string;
}

/** One trusted key, with its `key_id` recomputed from `public_key`. */
export interface TrustedKey {
  /** Recomputed from {@link publicKey}; never the value the file declared. */
  readonly keyId: string;
  readonly name?: string;
  /** Signatures with `signed_at` at or after this instant are rejected. */
  readonly notAfter?: string;
  readonly revoked: boolean;
  readonly publicKey: KeyObject;
}

/** A keyring document as it appears on disk (`hushspec-keyring.v0.schema.json`). */
export interface KeyringDocument {
  keyring_version: string;
  keys: TrustedKeyDocument[];
}

/** One entry of a {@link KeyringDocument}. */
export interface TrustedKeyDocument {
  key_id: string;
  algorithm: string;
  public_key: string;
  name?: string;
  not_after?: string;
  revoked?: boolean;
}

/** A verification that passed every check of spec section 6.2. */
export interface VerificationSuccess {
  readonly ok: true;
  /** The key that signed, as selected from the keyring. */
  readonly keyId: string;
  readonly signedAt: string;
  readonly expiresAt?: string;
  readonly policyName?: string;
  /**
   * The envelope's `policy_version`. A verifier that accepts an envelope
   * SHOULD record this as the new last-seen value (section 6.2, check 10).
   */
  readonly policyVersion?: number;
  readonly signer?: string;
  /** The verified content hash of the resolved policy. */
  readonly contentHash: string;
}

/** A verification that failed, carrying the reason code of section 6.4. */
export interface VerificationFailure {
  readonly ok: false;
  readonly reason: ReasonCode;
  /** Free-text detail; informational, never a substitute for {@link reason}. */
  readonly detail: string;
}

export type VerificationOutcome = VerificationSuccess | VerificationFailure;

/** Options for {@link verifyPolicy}. Exactly one key source is required. */
export interface VerifyOptions {
  /**
   * The keys the verifier trusts. A {@link Keyring}, a keyring document, or
   * the JSON text of one; anything but a `Keyring` goes through
   * {@link loadKeyring}, which recomputes every `key_id`.
   */
  keyring?: Keyring | KeyringDocument | string;
  /**
   * A single SPKI PEM public key, treated as a one-key keyring with its
   * `key_id` recomputed from it (spec section 5.3, last paragraph).
   */
  publicKeyPem?: string;
  /** The verifier's clock, default now. */
  now?: Date | string;
  /** Tolerance on `signed_at`, default {@link DEFAULT_MAX_CLOCK_SKEW_SECONDS}. */
  maxClockSkewSeconds?: number;
  /**
   * The last `policy_version` this verifier accepted for the policy's name.
   * When set, an envelope carrying a lower version is a rollback.
   */
  lastSeenVersion?: number;
}

/**
 * A signing or keyring *configuration* failure -- bad key material, a keyring
 * that does not validate, a policy that cannot be hashed.
 *
 * Verification failures are not errors: they come back as a
 * {@link VerificationFailure} carrying a {@link ReasonCode}.
 */
export class SigningError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SigningError';
  }
}

// --------------------------------------------------------------------------
// Key material (spec section 5)
// --------------------------------------------------------------------------

/**
 * The first PEM block with the given label.
 *
 * PEM files carry preambles -- the published test keys in `fixtures/signing/`
 * open with a DO-NOT-USE comment -- so the block is extracted rather than the
 * whole file handed to OpenSSL, which would accept surrounding text silently.
 * `ENCRYPTED PRIVATE KEY` deliberately does not match `PRIVATE KEY`: this
 * module does not take passphrases (spec section 5.1 leaves that to tooling).
 */
function pemBlock(text: string, label: 'PRIVATE KEY' | 'PUBLIC KEY'): string {
  if (typeof text !== 'string') {
    throw new SigningError(`expected a PEM-encoded ${label.toLowerCase()} as a string`);
  }
  const pattern = new RegExp(
    `-----BEGIN ${label}-----[A-Za-z0-9+/=\\r\\n\\t ]*-----END ${label}-----`,
  );
  const match = pattern.exec(text);
  if (match === null) {
    throw new SigningError(`no PEM "${label}" block found`);
  }
  return match[0];
}

function requireEd25519(key: KeyObject, what: string): KeyObject {
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new SigningError(
      `${what} is ${key.asymmetricKeyType ?? 'of an unknown type'}, not ed25519`,
    );
  }
  return key;
}

/** Parse an SPKI PEM public key (spec section 5.1). */
function publicKeyFromPem(pem: string): KeyObject {
  let key: KeyObject;
  try {
    key = createPublicKey(pemBlock(pem, 'PUBLIC KEY'));
  } catch (error) {
    if (error instanceof SigningError) throw error;
    throw new SigningError(`could not read public key: ${describe(error)}`);
  }
  return requireEd25519(key, 'public key');
}

/** Parse a PKCS#8 PEM private key (spec section 5.1). */
function privateKeyFromPem(pem: string): KeyObject {
  let key: KeyObject;
  try {
    key = createPrivateKey(pemBlock(pem, 'PRIVATE KEY'));
  } catch (error) {
    if (error instanceof SigningError) throw error;
    throw new SigningError(`could not read private key: ${describe(error)}`);
  }
  return requireEd25519(key, 'private key');
}

function keyIdOf(publicKey: KeyObject): string {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return `sha256:${createHash('sha256').update(der).digest('hex')}`;
}

/**
 * The key identifier of an SPKI PEM public key (spec section 5.2):
 * `sha256:` + lowercase hex SHA-256 of the DER SubjectPublicKeyInfo.
 *
 * Hashing the SPKI rather than the raw 32 key bytes ties the id to the
 * algorithm as well as to the key.
 *
 * @throws {SigningError} if the PEM is unreadable or not an Ed25519 key.
 */
export function keyIdFromPublicKey(pem: string): string {
  return keyIdOf(publicKeyFromPem(pem));
}

/**
 * The public key matching a PKCS#8 PEM private key, as an SPKI PEM.
 *
 * `h2h keygen`'s two files, from one: the private half is enough to write the
 * public half and print the `key_id` (spec section 8).
 *
 * @throws {SigningError} if the PEM is unreadable or not an Ed25519 key.
 */
export function publicKeyPemFromPrivateKey(pem: string): string {
  const publicKey = createPublicKey(privateKeyFromPem(pem));
  return publicKey.export({ type: 'spki', format: 'pem' }).toString();
}

/** A fresh Ed25519 signing keypair, PEM-encoded. */
export interface GeneratedKeypair {
  /** PKCS#8 PEM, `-----BEGIN PRIVATE KEY-----`. */
  privateKeyPem: string;
  /** SPKI PEM, `-----BEGIN PUBLIC KEY-----`. */
  publicKeyPem: string;
  /** The key identifier of {@link publicKeyPem} (spec section 5.2). */
  keyId: string;
}

/**
 * Generate an Ed25519 signing keypair in the formats spec section 5.1
 * defines -- what `h2h keygen` writes as `<name>.key.pem` and `<name>.pub.pem`.
 *
 * The private key is unencrypted PKCS#8: protecting it at rest is the
 * deployment's job (section 5.1 leaves passphrases to tooling).
 */
export function generateKeypair(): GeneratedKeypair {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    keyId: keyIdOf(publicKey),
  };
}

// --------------------------------------------------------------------------
// Keyring (spec section 5.3)
// --------------------------------------------------------------------------

/**
 * The set of public keys a verifier trusts.
 *
 * Key selection is by exact `key_id` and nothing else: when the named key is
 * absent the outcome is `unknown_key_id`, never an attempt with some other
 * key on the ring.
 */
export class Keyring {
  private readonly byId: Map<string, TrustedKey>;

  constructor(keys: readonly TrustedKey[]) {
    this.byId = new Map();
    for (const key of keys) {
      this.byId.set(key.keyId, key);
    }
  }

  /** Every trusted key, in insertion order. */
  get keys(): readonly TrustedKey[] {
    return [...this.byId.values()];
  }

  /** The key with this exact id, or `undefined`. */
  get(keyId: string): TrustedKey | undefined {
    return this.byId.get(keyId);
  }
}

function asRecord(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new SigningError(`${what} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function parseJson(value: string | unknown, what: string): unknown {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value) as unknown;
  } catch (error) {
    throw new SigningError(`${what} is not valid JSON: ${describe(error)}`);
  }
}

const KEYRING_KEYS = new Set(['keyring_version', 'keys']);
const TRUSTED_KEY_KEYS = new Set([
  'key_id',
  'algorithm',
  'public_key',
  'name',
  'not_after',
  'revoked',
]);

function rejectUnknown(
  record: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  what: string,
): void {
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      throw new SigningError(`${what}: unknown field '${key}'`);
    }
  }
}

/**
 * Load a keyring document (spec section 5.3), validating it structurally and
 * **recomputing every entry's `key_id` from its own `public_key`**.
 *
 * A declared id that does not match the key it sits next to is the whole
 * attack this check exists for, so it is a hard failure rather than a
 * correction: the file is not what it claims to be.
 *
 * `not_after` and `revoked` are carried through to
 * {@link verifyPolicy}, which turns them into `key_retired` and `key_revoked`.
 *
 * @param json the document, or its JSON text.
 * @throws {SigningError} if the document does not validate or an id mismatches.
 */
export function loadKeyring(json: string | KeyringDocument | unknown): Keyring {
  const document = asRecord(parseJson(json, 'keyring'), 'keyring');
  rejectUnknown(document, KEYRING_KEYS, 'keyring');

  if (document['keyring_version'] !== KEYRING_VERSION) {
    throw new SigningError(
      `unsupported keyring_version ${JSON.stringify(document['keyring_version'])}, ` +
        `expected "${KEYRING_VERSION}"`,
    );
  }

  const entries = document['keys'];
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new SigningError('keyring.keys must be a non-empty array');
  }

  const keys: TrustedKey[] = [];
  const seen = new Set<string>();
  for (let index = 0; index < entries.length; index += 1) {
    const key = loadTrustedKey(entries[index], `keyring.keys[${index}]`);
    if (seen.has(key.keyId)) {
      throw new SigningError(`keyring.keys[${index}]: duplicate key_id ${key.keyId}`);
    }
    seen.add(key.keyId);
    keys.push(key);
  }
  return new Keyring(keys);
}

function loadTrustedKey(value: unknown, where: string): TrustedKey {
  const entry = asRecord(value, where);
  rejectUnknown(entry, TRUSTED_KEY_KEYS, where);

  if (entry['algorithm'] !== SIGNATURE_ALGORITHM) {
    throw new SigningError(
      `${where}: unsupported algorithm ${JSON.stringify(entry['algorithm'])}`,
    );
  }
  const declaredId = entry['key_id'];
  if (typeof declaredId !== 'string' || !SHA256_PATTERN.test(declaredId)) {
    throw new SigningError(`${where}.key_id must be "sha256:" + 64 lowercase hex digits`);
  }
  const pem = entry['public_key'];
  if (typeof pem !== 'string') {
    throw new SigningError(`${where}.public_key must be a PEM string`);
  }

  const publicKey = publicKeyFromPem(pem);
  const keyId = keyIdOf(publicKey);
  // Spec section 5.2: verifiers MUST NOT trust a declared id that differs from
  // the recomputed one.
  if (keyId !== declaredId) {
    throw new SigningError(
      `${where}: declared key_id ${declaredId} does not match the public key (${keyId})`,
    );
  }

  const name = entry['name'];
  if (name !== undefined && typeof name !== 'string') {
    throw new SigningError(`${where}.name must be a string`);
  }
  const notAfter = entry['not_after'];
  if (notAfter !== undefined && (typeof notAfter !== 'string' || !isTimestamp(notAfter))) {
    throw new SigningError(`${where}.not_after must be an RFC 3339 UTC timestamp with milliseconds`);
  }
  const revoked = entry['revoked'];
  if (revoked !== undefined && typeof revoked !== 'boolean') {
    throw new SigningError(`${where}.revoked must be a boolean`);
  }

  return {
    keyId,
    ...(name === undefined ? {} : { name }),
    ...(notAfter === undefined ? {} : { notAfter }),
    revoked: revoked === true,
    publicKey,
  };
}

/**
 * A one-key keyring from a bare SPKI PEM public key, with its `key_id`
 * recomputed (spec section 5.3, last paragraph).
 *
 * The convenience `h2h verify --key pub.pem` offers. It trusts the key
 * unconditionally -- there is no `not_after` or `revoked` on a bare file -- so
 * a deployment with rotation wants a real keyring.
 */
export function keyringFromPublicKey(pem: string, name?: string): Keyring {
  const publicKey = publicKeyFromPem(pem);
  return new Keyring([
    {
      keyId: keyIdOf(publicKey),
      ...(name === undefined ? {} : { name }),
      revoked: false,
      publicKey,
    },
  ]);
}

// --------------------------------------------------------------------------
// Envelope (spec section 4)
// --------------------------------------------------------------------------

const ENVELOPE_KEYS = new Set([
  'format_version',
  'algorithm',
  'key_id',
  'signed_at',
  'expires_at',
  'policy_version',
  'policy_name',
  'content_hash',
  'signer',
  'signature',
]);

/** The `required` list of the signature schema; all six are strings. */
const REQUIRED_ENVELOPE_KEYS = [
  'format_version',
  'algorithm',
  'key_id',
  'signed_at',
  'content_hash',
  'signature',
] as const;

function isTimestamp(value: string): boolean {
  return TIMESTAMP_PATTERN.test(value) && !Number.isNaN(Date.parse(value));
}

/**
 * Structural validation of an envelope: spec section 6.2 check 1, whose
 * failure is `malformed_envelope`.
 *
 * Deliberately **not** the const constraints on `format_version` and
 * `algorithm`, even though the schema states them: checks 2 and 3 exist
 * precisely to tell a 0.1 envelope and an RSA envelope apart from a garbled
 * one, and folding their schema `const`s into check 1 would make
 * `unsupported_format_version` and `unsupported_algorithm` unreachable. Here
 * the two are required to be present and to be strings; their values are
 * judged by the checks that own them.
 *
 * Returns the reason detail, or `undefined` when the shape is good.
 */
function envelopeShapeError(value: unknown): string | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return 'envelope must be a JSON object';
  }
  const envelope = value as Record<string, unknown>;

  for (const key of Object.keys(envelope)) {
    if (!ENVELOPE_KEYS.has(key)) return `unknown field '${key}'`;
  }
  for (const key of REQUIRED_ENVELOPE_KEYS) {
    if (typeof envelope[key] !== 'string') return `${key} is required and must be a string`;
  }
  if (!SHA256_PATTERN.test(envelope['key_id'] as string)) {
    return 'key_id must be "sha256:" + 64 lowercase hex digits';
  }
  if (!SHA256_PATTERN.test(envelope['content_hash'] as string)) {
    return 'content_hash must be "sha256:" + 64 lowercase hex digits';
  }
  if (!isTimestamp(envelope['signed_at'] as string)) {
    return 'signed_at must be an RFC 3339 UTC instant with milliseconds and a Z suffix';
  }
  if (!SIGNATURE_PATTERN.test(envelope['signature'] as string)) {
    return 'signature must be 86 base64url characters without padding';
  }

  const expiresAt = envelope['expires_at'];
  if (expiresAt !== undefined && (typeof expiresAt !== 'string' || !isTimestamp(expiresAt))) {
    return 'expires_at must be an RFC 3339 UTC instant with milliseconds and a Z suffix';
  }
  const policyVersion = envelope['policy_version'];
  if (
    policyVersion !== undefined &&
    (typeof policyVersion !== 'number' || !Number.isInteger(policyVersion) || policyVersion < 0)
  ) {
    return 'policy_version must be a non-negative integer';
  }
  for (const key of ['policy_name', 'signer']) {
    const text = envelope[key];
    if (text !== undefined && (typeof text !== 'string' || text.length === 0)) {
      return `${key} must be a non-empty string`;
    }
  }
  return undefined;
}

/**
 * Parse a `.sig` document into an {@link Envelope}, fail-closed.
 *
 * Strict: an unknown `format_version` or `algorithm` is rejected here rather
 * than carried forward, because a caller who parses an envelope is about to
 * treat it as one. **Verification does not go through this function** -- pass
 * the raw parsed JSON to {@link verifyPolicy}, which runs the ordered checks
 * of section 6.2 and reports `unsupported_format_version` /
 * `unsupported_algorithm` as reason codes instead of throwing.
 *
 * @throws {SigningError} if the document is not a well-formed 0.2 envelope.
 */
export function parseEnvelope(json: string | unknown): Envelope {
  const value = parseJson(json, 'signature envelope');
  const shapeError = envelopeShapeError(value);
  if (shapeError !== undefined) {
    throw new SigningError(`malformed signature envelope: ${shapeError}`);
  }
  const envelope = value as Envelope;
  if (envelope.format_version !== SIGNATURE_FORMAT_VERSION) {
    throw new SigningError(
      `unsupported signature format_version ${JSON.stringify(envelope.format_version)}, ` +
        `expected "${SIGNATURE_FORMAT_VERSION}"`,
    );
  }
  if (envelope.algorithm !== SIGNATURE_ALGORITHM) {
    throw new SigningError(
      `unsupported signature algorithm ${JSON.stringify(envelope.algorithm)}, ` +
        `expected "${SIGNATURE_ALGORITHM}"`,
    );
  }
  return envelope;
}

/**
 * The bytes a signature covers (spec section 4.1): the RFC 8785 canonical
 * form of the envelope with `signature` absent, UTF-8.
 *
 * Exported because it is the one thing an outside tool needs to re-verify an
 * envelope by hand -- `openssl pkeyutl -verify -rawin` over exactly this.
 */
export function envelopeSigningInput(envelope: Omit<Envelope, 'signature'>): string {
  const claims: Record<string, JsonValue> = {};
  for (const [key, value] of Object.entries(envelope)) {
    if (key === 'signature' || value === undefined) continue;
    claims[key] = value as JsonValue;
  }
  return canonicalizeValue(claims);
}

// --------------------------------------------------------------------------
// Signing (spec section 4.2)
// --------------------------------------------------------------------------

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** The first validation error, for the message of a refusal. */
function describeValidation(spec: HushSpec): string | undefined {
  const validation = validate(spec);
  if (validation.valid) return undefined;
  const first = validation.errors[0];
  return first === undefined ? 'validation failed' : `${first.code}: ${first.message}`;
}

/** An instant as the envelope spells it: RFC 3339 UTC, milliseconds, `Z`. */
function timestamp(value: Date | string, field: string): string {
  const date = typeof value === 'string' ? new Date(value) : value;
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) {
    throw new SigningError(`${field} is not a valid instant`);
  }
  const text = date.toISOString();
  if (!TIMESTAMP_PATTERN.test(text)) {
    // Years outside 0000-9999 render in the extended form the schema rejects.
    throw new SigningError(`${field} (${text}) is outside the representable range`);
  }
  return text;
}

/**
 * Sign a **resolved** policy (spec section 4.2).
 *
 * The policy must already be resolved and must validate: a signer that cannot
 * resolve or validate a chain MUST refuse to sign (spec section 3), because
 * the signature would otherwise attest to a document nobody checked. Pass the
 * output of `resolve()`, not the file as written.
 *
 * `policy_version` and `policy_name` default to the policy's own
 * `metadata.policy_version` and `name`; pass them explicitly to override.
 *
 * Ed25519 is deterministic and the signing input is canonical, so signing the
 * same policy with the same key and the same `signedAt` twice produces
 * byte-identical envelopes.
 *
 * @throws {SigningError} if the key is unusable, the policy does not validate,
 * or it cannot be hashed (for instance because it still carries `extends`).
 */
export function signPolicy(
  resolvedSpec: HushSpec,
  privateKeyPem: string,
  options: SignOptions = {},
): Envelope {
  const privateKey = privateKeyFromPem(privateKeyPem);
  const keyId = keyIdOf(createPublicKey(privateKey));

  const invalid = describeValidation(resolvedSpec);
  if (invalid !== undefined) {
    throw new SigningError(`refusing to sign an invalid policy: ${invalid}`);
  }

  let hash: string;
  try {
    hash = contentHash(resolvedSpec);
  } catch (error) {
    throw new SigningError(`refusing to sign: ${describe(error)}`);
  }

  const policyVersion = options.policyVersion ?? resolvedSpec.metadata?.policy_version;
  if (policyVersion !== undefined && (!Number.isInteger(policyVersion) || policyVersion < 0)) {
    throw new SigningError('policy_version must be a non-negative integer');
  }
  const policyName = options.policyName ?? resolvedSpec.name;

  // Member order follows the table in spec section 4; JSON object order is not
  // significant, and the signing input re-sorts anyway.
  const claims: Omit<Envelope, 'signature'> = {
    format_version: SIGNATURE_FORMAT_VERSION,
    algorithm: SIGNATURE_ALGORITHM,
    key_id: keyId,
    signed_at: timestamp(options.signedAt ?? new Date(), 'signedAt'),
    ...(options.expiresAt === undefined
      ? {}
      : { expires_at: timestamp(options.expiresAt, 'expiresAt') }),
    ...(policyVersion === undefined ? {} : { policy_version: policyVersion }),
    ...(policyName === undefined || policyName === '' ? {} : { policy_name: policyName }),
    content_hash: hash,
    ...(options.signer === undefined ? {} : { signer: options.signer }),
  };

  const signature = edSign(null, Buffer.from(envelopeSigningInput(claims), 'utf8'), privateKey);
  return { ...claims, signature: signature.toString('base64url') };
}

// --------------------------------------------------------------------------
// Verification (spec section 6)
// --------------------------------------------------------------------------

function fail(reason: ReasonCode, detail: string): VerificationFailure {
  return { ok: false, reason, detail };
}

function resolveKeyring(options: VerifyOptions): Keyring {
  const { keyring, publicKeyPem } = options;
  if (keyring !== undefined && publicKeyPem !== undefined) {
    throw new SigningError('pass either `keyring` or `publicKeyPem`, not both');
  }
  if (publicKeyPem !== undefined) return keyringFromPublicKey(publicKeyPem);
  if (keyring === undefined) {
    throw new SigningError('verifyPolicy requires a `keyring` or a `publicKeyPem`');
  }
  return keyring instanceof Keyring ? keyring : loadKeyring(keyring);
}

/**
 * Verify a signature envelope against a **resolved** policy, running the
 * checks of spec section 6.2 in order and stopping at the first failure.
 *
 * | # | Check | Reason on failure |
 * |---|---|---|
 * | 1 | envelope shape | `malformed_envelope` |
 * | 2 | `format_version` is `"0.2"` | `unsupported_format_version` |
 * | 3 | `algorithm` is `"ed25519"` | `unsupported_algorithm` |
 * | 4 | key is on the keyring | `unknown_key_id` |
 * | 5 | key is not revoked | `key_revoked` |
 * | 6 | `signed_at` is before `not_after` | `key_retired` |
 * | 7 | clock window | `signed_at_in_future`, `expired` |
 * | 8 | Ed25519 over the signing input | `signature_mismatch` |
 * | 9 | content hash of the policy | `content_hash_mismatch` |
 * | 10 | rollback | `policy_version_rollback` |
 *
 * The order is normative, not an implementation detail: a caller that acts on
 * `key_revoked` must not have that masked by an expiry, and a tampered policy
 * must be distinguishable from a forged signature.
 *
 * `envelope` is deliberately `unknown`: pass the parsed `.sig` JSON straight
 * in, so a 0.1 envelope comes back as `unsupported_format_version` rather than
 * as a thrown parse error.
 *
 * @throws {SigningError} only for a configuration problem -- no keyring, or a
 * keyring that does not load. Every envelope and policy problem is a
 * {@link VerificationFailure}.
 */
export function verifyPolicy(
  resolvedSpec: HushSpec,
  envelope: Envelope | unknown,
  options: VerifyOptions,
): VerificationOutcome {
  const keyring = resolveKeyring(options);
  const skewSeconds = options.maxClockSkewSeconds ?? DEFAULT_MAX_CLOCK_SKEW_SECONDS;
  if (!Number.isFinite(skewSeconds) || skewSeconds < 0) {
    throw new SigningError('maxClockSkewSeconds must be a non-negative number');
  }
  const nowValue = options.now ?? new Date();
  const now = typeof nowValue === 'string' ? new Date(nowValue) : nowValue;
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    throw new SigningError('`now` is not a valid instant');
  }

  // 1. Envelope shape.
  const shapeError = envelopeShapeError(envelope);
  if (shapeError !== undefined) return fail('malformed_envelope', shapeError);
  const claims = envelope as Envelope;

  // 2. Format version.
  if (claims.format_version !== SIGNATURE_FORMAT_VERSION) {
    return fail(
      'unsupported_format_version',
      `format_version ${JSON.stringify(claims.format_version)} is not "${SIGNATURE_FORMAT_VERSION}"`,
    );
  }

  // 3. Algorithm.
  if (claims.algorithm !== SIGNATURE_ALGORITHM) {
    return fail(
      'unsupported_algorithm',
      `algorithm ${JSON.stringify(claims.algorithm)} is not "${SIGNATURE_ALGORITHM}"`,
    );
  }

  // 4. Key lookup -- by exact id, with no fallback to any other key on the ring.
  const key = keyring.get(claims.key_id);
  if (key === undefined) {
    return fail('unknown_key_id', `no key ${claims.key_id} on the keyring`);
  }

  // 5. Revocation.
  if (key.revoked) {
    return fail('key_revoked', `key ${key.keyId} is revoked`);
  }

  // 6. Retirement: signatures made before `not_after` stay valid.
  if (key.notAfter !== undefined && Date.parse(claims.signed_at) >= Date.parse(key.notAfter)) {
    return fail(
      'key_retired',
      `key ${key.keyId} was retired at ${key.notAfter}; signed_at is ${claims.signed_at}`,
    );
  }

  // 7. Time. `signed_at` guards a wrong or fabricated signer clock; it is
  //    never a freshness test (spec section 6.3).
  const signedAt = Date.parse(claims.signed_at);
  const latestAcceptable = now.getTime() + skewSeconds * 1000;
  if (signedAt > latestAcceptable) {
    return fail(
      'signed_at_in_future',
      `signed_at ${claims.signed_at} is more than ${skewSeconds}s ahead of ${now.toISOString()}`,
    );
  }
  if (claims.expires_at !== undefined && now.getTime() >= Date.parse(claims.expires_at)) {
    return fail('expired', `signature expired at ${claims.expires_at}`);
  }

  // 8. Signature over the canonical envelope.
  if (!signatureMatches(claims, key.publicKey)) {
    return fail('signature_mismatch', `signature does not verify under key ${key.keyId}`);
  }

  // 9. Content. A policy that cannot be resolved or validated has no hash to
  //    compare, which the spec folds into this same reason.
  let hash: string;
  try {
    const invalid = describeValidation(resolvedSpec);
    if (invalid !== undefined) {
      return fail('content_hash_mismatch', `policy does not validate: ${invalid}`);
    }
    hash = contentHash(resolvedSpec);
  } catch (error) {
    return fail('content_hash_mismatch', `policy cannot be hashed: ${describe(error)}`);
  }
  if (hash !== claims.content_hash) {
    return fail(
      'content_hash_mismatch',
      `policy hashes to ${hash}, the envelope covers ${claims.content_hash}`,
    );
  }

  // 10. Rollback.
  const lastSeen = options.lastSeenVersion;
  const version = claims.policy_version;
  if (lastSeen !== undefined && version !== undefined && version < lastSeen) {
    return fail(
      'policy_version_rollback',
      `policy_version ${version} is older than the last seen ${lastSeen}`,
    );
  }

  return {
    ok: true,
    keyId: key.keyId,
    signedAt: claims.signed_at,
    ...(claims.expires_at === undefined ? {} : { expiresAt: claims.expires_at }),
    ...(claims.policy_name === undefined ? {} : { policyName: claims.policy_name }),
    ...(claims.policy_version === undefined ? {} : { policyVersion: claims.policy_version }),
    ...(claims.signer === undefined ? {} : { signer: claims.signer }),
    contentHash: hash,
  };
}

function signatureMatches(envelope: Envelope, publicKey: KeyObject): boolean {
  const signature = Buffer.from(envelope.signature, 'base64url');
  if (signature.length !== ED25519_SIGNATURE_BYTES) return false;
  try {
    return edVerify(
      null,
      Buffer.from(envelopeSigningInput(envelope), 'utf8'),
      publicKey,
      signature,
    );
  } catch {
    // A key or signature Node refuses to touch is a failed verification, not
    // an exception to propagate: fail closed.
    return false;
  }
}
