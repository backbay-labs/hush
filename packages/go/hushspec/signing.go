package hushspec

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// Policy signing (spec/hushspec-signing.md, format 0.2).
//
// A signed policy proves that the controls an enforcement point applied are
// the controls an authorized party approved. The signature covers the
// *content hash of the resolved policy* (canonical.go, [ContentHash]) rather
// than the bytes of the policy file, so reformatting the YAML keeps a
// signature valid while a changed base policy in an `extends` chain does not
// (spec section 3).
//
// The unit of exchange is an [Envelope]: a small JSON object carrying the
// content hash and the claims around it (who signed, when, which key, which
// policy version). Every member except `signature` is covered by the
// signature, so no claim can be edited after the fact. The signing input is
// the RFC 8785 canonical serialization of the envelope with `signature`
// removed, which is why this file reuses canonical.go's JCS writer instead of
// encoding/json (spec section 4.1).
//
// Everything here fails closed. An unknown `format_version`, an unknown
// algorithm, a key that is not in the keyring, a keyring entry whose declared
// `key_id` does not match its public key, a policy that no longer resolves:
// each is a rejection with a reason code, never a fallback.
//
// This file stops at sign and verify. Wiring verification into policy loading
// -- `require_signature`, digest-pinned `extends` hops, a signature outcome
// per chain hop -- is resolve.go's [ResolveWithOptions], which calls
// [VerifyPolicy] once per hop against that hop's own resolved document. That
// is what spec section 10 requires of a verify-on-load implementation: verify
// the in-memory resolved document, not a file that is re-read afterwards.

// SignatureFormatVersion is the only envelope format this SDK produces or
// accepts (spec section 4). Verifiers never negotiate: any other value is
// [ReasonUnsupportedFormatVersion].
const SignatureFormatVersion = "0.2"

// SignatureAlgorithm is the only signature algorithm defined in 0.2: pure
// Ed25519 (RFC 8032), no pre-hash and no context string.
const SignatureAlgorithm = "ed25519"

// KeyringFormatVersion is the only keyring document version defined in 0.2
// (spec section 5.3).
const KeyringFormatVersion = "0.2"

// DefaultMaxClockSkewSeconds is the RECOMMENDED tolerance applied to
// `signed_at` when a verifier does not choose its own (spec section 6.3). It
// absorbs a signer whose clock runs slightly fast; it is not a freshness
// check, and a verifier MUST NOT use `signed_at` to decide freshness.
const DefaultMaxClockSkewSeconds = 300

// envelopeTimeLayout is RFC 3339 UTC at millisecond precision. The trailing
// "Z" is appended separately rather than written into the layout, where a
// lone "Z" is only a literal by accident of Go's layout grammar.
const envelopeTimeLayout = "2006-01-02T15:04:05.000"

// Reason codes from spec section 6.4. A verifier exposes exactly these
// strings: they are what a receipt's `policy.signature.reason` carries and
// what a CLI prints, so they are part of the wire contract and are spelled
// here exactly as the specification spells them.
const (
	// ReasonMalformedEnvelope: the envelope does not satisfy the signature
	// schema (check 1).
	ReasonMalformedEnvelope = "malformed_envelope"
	// ReasonUnsupportedFormatVersion: `format_version` is not "0.2" (check 2).
	ReasonUnsupportedFormatVersion = "unsupported_format_version"
	// ReasonUnsupportedAlgorithm: `algorithm` is not "ed25519" (check 3).
	ReasonUnsupportedAlgorithm = "unsupported_algorithm"
	// ReasonUnknownKeyID: no keyring entry carries the envelope's `key_id`,
	// or the entry's id does not match its own public key (check 4).
	ReasonUnknownKeyID = "unknown_key_id"
	// ReasonKeyRevoked: the selected key is revoked (check 5).
	ReasonKeyRevoked = "key_revoked"
	// ReasonKeyRetired: the signature was made at or after the key's
	// `not_after` (check 6).
	ReasonKeyRetired = "key_retired"
	// ReasonSignedAtInFuture: `signed_at` is beyond now plus the permitted
	// clock skew (check 7).
	ReasonSignedAtInFuture = "signed_at_in_future"
	// ReasonExpired: now is at or after `expires_at` (check 7).
	ReasonExpired = "expired"
	// ReasonSignatureMismatch: Ed25519 verification of the signing input
	// failed (check 8).
	ReasonSignatureMismatch = "signature_mismatch"
	// ReasonContentHashMismatch: the resolved policy hashes to something
	// other than the envelope's `content_hash`, or does not resolve or
	// validate at all (check 9).
	ReasonContentHashMismatch = "content_hash_mismatch"
	// ReasonPolicyVersionRollback: the envelope's `policy_version` is below
	// the last-seen version for this policy name (check 10).
	ReasonPolicyVersionRollback = "policy_version_rollback"
)

// Patterns from schemas/hushspec-signature.v1.schema.json and
// hushspec-keyring.v1.schema.json (0.2). Shape validation (check 1) is the
// schema, so these are transcribed rather than approximated.
var (
	signingDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	envelopeTimePattern  = regexp.MustCompile(
		`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)
	envelopeSignaturePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{86}$`)
	publicKeyPEMPattern      = regexp.MustCompile(
		`^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n?$`)
)

// Envelope is a detached policy signature (spec section 4), the object stored
// in the `.sig` file next to a policy. Every member except Signature is a
// signed claim.
//
// Timestamps are kept as their wire strings rather than as time.Time: the
// signing input is the envelope verbatim, so re-rendering a parsed timestamp
// could only ever change bytes the signature covers. [Envelope.SignedAtTime]
// and [Envelope.ExpiresAtTime] parse them on demand.
//
// Optional string members follow the SDK-wide convention that "" means
// absent (see canonicalPresence in canonical.go). The schema gives
// `policy_name` and `signer` a minimum length of one, so an explicitly empty
// one is not a legal envelope anyway; [ParseEnvelope], which can still see
// the raw document, rejects it as [ReasonMalformedEnvelope].
type Envelope struct {
	// FormatVersion is always "0.2" in this SDK.
	FormatVersion string `json:"format_version"`
	// Algorithm is always "ed25519" in this SDK.
	Algorithm string `json:"algorithm"`
	// KeyID identifies the signing key: "sha256:" and the hex SHA-256 of its
	// DER SubjectPublicKeyInfo (spec section 5.2).
	KeyID string `json:"key_id"`
	// SignedAt is when the signature was made, RFC 3339 UTC, milliseconds, Z.
	SignedAt string `json:"signed_at"`
	// ExpiresAt is the optional instant at or after which the signature is
	// invalid, in the same format.
	ExpiresAt string `json:"expires_at,omitempty"`
	// PolicyVersion is the policy's metadata.policy_version at signing time,
	// when it has one. It drives rollback protection (check 10).
	PolicyVersion *int64 `json:"policy_version,omitempty"`
	// PolicyName is the policy's name at signing time, when present. It
	// scopes rollback protection.
	PolicyName string `json:"policy_name,omitempty"`
	// ContentHash is the content hash of the resolved policy: the signed
	// claim itself.
	ContentHash string `json:"content_hash"`
	// Signer is an optional human-readable signer identity. It is covered by
	// the signature but carries no authority of its own; trust comes from
	// KeyID.
	Signer string `json:"signer,omitempty"`
	// Signature is the 64-byte Ed25519 signature over the signing input,
	// base64url encoded without padding.
	Signature string `json:"signature"`
}

// SignOptions carries the claims a signer chooses. The zero value signs with
// the current time and copies `policy_name` and `policy_version` from the
// resolved policy.
type SignOptions struct {
	// SignedAt overrides the signing timestamp. Nil means now. It is
	// truncated to milliseconds and rendered in UTC.
	SignedAt *time.Time
	// ExpiresAt sets an optional expiry. Signers SHOULD set it for policies
	// that are re-approved on a cadence, and MUST NOT set it further out
	// than the approval interval (spec section 4.2).
	ExpiresAt *time.Time
	// PolicyVersion overrides the version claim. Nil copies the resolved
	// policy's metadata.policy_version when it has one, which is what the
	// specification recommends.
	PolicyVersion *int64
	// PolicyName overrides the name claim. Empty copies the resolved
	// policy's name.
	PolicyName string
	// Signer is an optional human-readable identity, omitted when empty.
	Signer string
}

// VerifyOptions carries the verifier's inputs (spec section 6.1).
type VerifyOptions struct {
	// Keyring is the set of trusted keys. When nil, PublicKeyPEM is used as
	// a one-key keyring; when both are empty no key is trusted and every
	// envelope is rejected with [ReasonUnknownKeyID].
	Keyring *Keyring
	// PublicKeyPEM is a single SPKI PEM public key accepted as a one-key
	// keyring, with its key id recomputed from the key (spec section 5.3).
	// Ignored when Keyring is non-nil.
	PublicKeyPEM []byte
	// Now is the verifier's clock. The zero time means time.Now().
	Now time.Time
	// MaxClockSkewSeconds is the tolerance applied to `signed_at`. Zero
	// means [DefaultMaxClockSkewSeconds]; a negative value means no
	// tolerance at all.
	MaxClockSkewSeconds int
	// LastSeenVersion is the highest `policy_version` this verifier has
	// already accepted for the policy's name, when it records one. Scoping
	// it to the right policy name is the caller's job.
	LastSeenVersion *int64
}

// VerifyResult is the outcome of [VerifyPolicy]. OK and Reason are the
// programmatic contract: Reason is "" exactly when OK is true, and otherwise
// one of the section 6.4 codes. Detail is free text for humans and MUST NOT
// be parsed.
type VerifyResult struct {
	// OK reports whether every check in spec section 6.2 passed.
	OK bool
	// Reason is the section 6.4 reason code for the first failed check.
	Reason string
	// Detail explains the failure for a human. Informational only.
	Detail string
	// KeyID is the envelope's key id, when it carried a readable one.
	KeyID string
	// PolicyName and PolicyVersion echo the envelope's claims, so a caller
	// that accepts the envelope can record the version as the new last-seen
	// value (spec section 6.2, check 10).
	PolicyName    string
	PolicyVersion *int64
	// ContentHash is the hash the verifier computed from the policy, set
	// once check 9 runs. On a mismatch it is the *computed* hash, not the
	// claimed one.
	ContentHash string
	// Resolved is the resolved document that was hashed, set once check 9
	// runs. Spec section 10 requires a verify-on-load caller to evaluate
	// this document rather than re-reading the file, so it is returned
	// rather than discarded.
	Resolved *HushSpec
}

// EnvelopeError is a parse failure that maps onto a verification reason code,
// so a caller that rejects a `.sig` file at parse time reports the same code
// a verifier would have reported for it.
type EnvelopeError struct {
	// Reason is one of [ReasonMalformedEnvelope],
	// [ReasonUnsupportedFormatVersion] or [ReasonUnsupportedAlgorithm].
	Reason string
	// Detail explains the failure for a human.
	Detail string
}

func (e *EnvelopeError) Error() string {
	return fmt.Sprintf("invalid signature envelope (%s): %s", e.Reason, e.Detail)
}

func envelopeErr(reason, format string, args ...any) *EnvelopeError {
	return &EnvelopeError{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// ReasonFromError returns the verification reason code carried by an
// [EnvelopeError], a [DigestMismatchError] or a [SignatureRequiredError], so a
// caller can turn a parse or load failure into the reason code it reports
// without type-switching by hand.
func ReasonFromError(err error) (string, bool) {
	var envErr *EnvelopeError
	if errors.As(err, &envErr) {
		return envErr.Reason, true
	}
	// Verification on load (resolve.go) refuses a chain with two failures of
	// its own, both of which a caller reports the same way as an envelope
	// check: a hop whose pinned digest did not match, and a hop that required
	// a signature and had none that verified.
	var digestErr *DigestMismatchError
	if errors.As(err, &digestErr) {
		return ReasonDigestMismatch, true
	}
	var signatureErr *SignatureRequiredError
	if errors.As(err, &signatureErr) {
		reason := signatureErr.Status.Reason
		if reason == "" {
			reason = ReasonMissingSignature
		}
		return reason, true
	}
	return "", false
}

// --------------------------------------------------------------------------
// Keys (spec section 5)
// --------------------------------------------------------------------------

// TrustedKey is one entry of a [Keyring]: a public key plus the deployment's
// statements about it.
type TrustedKey struct {
	// KeyID is the declared key id. Verifiers recompute it from PublicKeyPEM
	// and MUST NOT trust an entry where the two disagree (spec section 5.2).
	KeyID string `json:"key_id"`
	// Algorithm is always "ed25519" in 0.2.
	Algorithm string `json:"algorithm"`
	// PublicKeyPEM is the key as a PEM-encoded SubjectPublicKeyInfo.
	PublicKeyPEM string `json:"public_key"`
	// Name is an optional human-readable label.
	Name string `json:"name,omitempty"`
	// NotAfter retires the key: signatures made at or after this instant are
	// rejected, earlier ones stay valid. Empty means no retirement.
	NotAfter string `json:"not_after,omitempty"`
	// Revoked rejects every signature by the key regardless of when it was
	// made. Revocation answers compromise; retirement is routine rotation.
	Revoked bool `json:"revoked,omitempty"`
}

// Keyring is a verifier's root of trust (spec section 5.3): the set of public
// keys whose signatures it will accept. Key selection is by exact key id and
// never falls back to another key.
//
// A keyring is not itself signed by this specification. One an attacker can
// edit is a root of trust an attacker owns, so distribute it with the same
// integrity guarantees as the enforcement point's own binaries.
type Keyring struct {
	// Version is always "0.2" in this SDK.
	Version string `json:"keyring_version"`
	// Keys are the trusted entries, at least one.
	Keys []TrustedKey `json:"keys"`
}

// LoadKeyring parses and validates a keyring document (spec section 5.3).
//
// Beyond the schema it enforces the trust rules the schema cannot express:
// every entry's public key must parse as an Ed25519 SubjectPublicKeyInfo, its
// declared key id must equal the id recomputed from that key, and no key id
// may appear twice. Any violation rejects the whole document rather than the
// offending entry, because a keyring a verifier half-understands is not a
// root of trust.
func LoadKeyring(data []byte) (*Keyring, error) {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, fmt.Errorf("invalid keyring: %w", err)
	}

	var ring Keyring
	if err := strictUnmarshalJSON(data, &ring); err != nil {
		return nil, fmt.Errorf("invalid keyring: %w", err)
	}
	if ring.Version != KeyringFormatVersion {
		return nil, fmt.Errorf(
			"invalid keyring: unsupported keyring_version %q (this SDK accepts %q)",
			ring.Version, KeyringFormatVersion)
	}
	if len(ring.Keys) == 0 {
		return nil, errors.New("invalid keyring: `keys` must list at least one key")
	}

	seen := make(map[string]bool, len(ring.Keys))
	for i := range ring.Keys {
		entry := &ring.Keys[i]
		if err := entry.validate(); err != nil {
			return nil, fmt.Errorf("invalid keyring: keys[%d]: %w", i, err)
		}
		if seen[entry.KeyID] {
			return nil, fmt.Errorf("invalid keyring: keys[%d]: duplicate key_id %s", i, entry.KeyID)
		}
		seen[entry.KeyID] = true
	}
	return &ring, nil
}

// Find returns the entry whose key id matches, or nil. Selection is by exact
// match only: a verifier MUST NOT try another key when the named one is
// absent (spec section 5.3).
func (k *Keyring) Find(keyID string) *TrustedKey {
	if k == nil {
		return nil
	}
	for i := range k.Keys {
		if k.Keys[i].KeyID == keyID {
			return &k.Keys[i]
		}
	}
	return nil
}

// KeyringFromPublicKey builds a one-key keyring from an SPKI PEM public key,
// with the key id recomputed from the key itself (spec section 5.3, last
// paragraph). It is what `--key pub.pem` means for a verifier.
func KeyringFromPublicKey(publicKeyPEM []byte, name string) (*Keyring, error) {
	keyID, err := KeyIDFromPublicKey(publicKeyPEM)
	if err != nil {
		return nil, err
	}
	return &Keyring{
		Version: KeyringFormatVersion,
		Keys: []TrustedKey{{
			KeyID:        keyID,
			Algorithm:    SignatureAlgorithm,
			PublicKeyPEM: string(publicKeyPEM),
			Name:         name,
		}},
	}, nil
}

// validate checks one entry against the keyring schema and recomputes its id.
func (t *TrustedKey) validate() error {
	if !signingDigestPattern.MatchString(t.KeyID) {
		return fmt.Errorf("key_id %q is not `sha256:` and 64 lowercase hex digits", t.KeyID)
	}
	if t.Algorithm != SignatureAlgorithm {
		return fmt.Errorf("unsupported algorithm %q (this SDK accepts %q)",
			t.Algorithm, SignatureAlgorithm)
	}
	if !publicKeyPEMPattern.MatchString(t.PublicKeyPEM) {
		return errors.New("public_key is not a PEM-encoded SubjectPublicKeyInfo block")
	}
	if t.NotAfter != "" && !envelopeTimePattern.MatchString(t.NotAfter) {
		return fmt.Errorf(
			"not_after %q is not RFC 3339 UTC with millisecond precision and a Z suffix", t.NotAfter)
	}
	if _, _, err := t.publicKey(); err != nil {
		return err
	}
	return nil
}

// publicKey parses the entry's key material and returns it with the key id
// recomputed from it. It is deliberately not cached: a keyring is shared
// across goroutines, and one PEM decode plus one SHA-256 per verification is
// not worth a lock.
func (t *TrustedKey) publicKey() (ed25519.PublicKey, string, error) {
	public, err := ParsePublicKeyPEM([]byte(t.PublicKeyPEM))
	if err != nil {
		return nil, "", err
	}
	keyID, err := keyIDFromKey(public)
	if err != nil {
		return nil, "", err
	}
	if keyID != t.KeyID {
		return nil, "", fmt.Errorf(
			"declared key_id %s does not match the key id recomputed from public_key (%s)",
			t.KeyID, keyID)
	}
	return public, keyID, nil
}

// NotAfterTime parses the entry's retirement instant. It returns nil when the
// entry has none.
func (t *TrustedKey) NotAfterTime() (*time.Time, error) {
	if t.NotAfter == "" {
		return nil, nil
	}
	return parseEnvelopeTime(t.NotAfter, "not_after")
}

// KeyIDFromPublicKey returns the key identifier of a PEM-encoded
// SubjectPublicKeyInfo: "sha256:" followed by the lowercase hex SHA-256 of
// the DER SPKI (spec section 5.2). Deriving the id from the SPKI rather than
// from the raw key bits ties it to the algorithm as well as to the key.
func KeyIDFromPublicKey(publicKeyPEM []byte) (string, error) {
	public, err := ParsePublicKeyPEM(publicKeyPEM)
	if err != nil {
		return "", err
	}
	return keyIDFromKey(public)
}

func keyIDFromKey(public ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", fmt.Errorf("failed to encode the SubjectPublicKeyInfo: %w", err)
	}
	sum := sha256.Sum256(der)
	return contentHashPrefix + hex.EncodeToString(sum[:]), nil
}

// ParsePublicKeyPEM decodes a PEM-encoded Ed25519 SubjectPublicKeyInfo (spec
// section 5.1), the format `openssl pkey -pubout` writes. Comment lines
// before the block -- the DO-NOT-USE headers on the test keys, for instance
// -- are ignored; a second PEM block is not, because which key a file with
// two of them means is exactly the kind of ambiguity that must fail closed.
func ParsePublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, err := decodeSinglePEMBlock(data, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the SubjectPublicKeyInfo: %w", err)
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, not an Ed25519 key", parsed)
	}
	// An Ed25519 SPKI is a fixed 44-byte structure. If re-encoding the parsed
	// key does not reproduce the input, the DER was non-canonical and two
	// implementations could derive two different key ids from one file.
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, fmt.Errorf("failed to re-encode the SubjectPublicKeyInfo: %w", err)
	}
	if !bytes.Equal(der, block.Bytes) {
		return nil, errors.New(
			"public key is not canonical DER: re-encoding the SubjectPublicKeyInfo changes its bytes")
	}
	return public, nil
}

// ParsePrivateKeyPEM decodes a PEM-encoded PKCS#8 Ed25519 private key (spec
// section 5.1), the format `openssl genpkey -algorithm ed25519` writes.
// Encrypted PKCS#8 is out of scope for this SDK: decrypt it with the
// deployment's own tooling and pass the plaintext key.
func ParsePrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, err := decodeSinglePEMBlock(data, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the PKCS#8 private key: %w", err)
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, not an Ed25519 key", parsed)
	}
	return private, nil
}

// MarshalPublicKeyPEM encodes an Ed25519 public key as an SPKI PEM block.
func MarshalPublicKeyPEM(public ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, fmt.Errorf("failed to encode the SubjectPublicKeyInfo: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// MarshalPrivateKeyPEM encodes an Ed25519 private key as a PKCS#8 PEM block.
func MarshalPrivateKeyPEM(private ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("failed to encode the PKCS#8 private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func decodeSinglePEMBlock(data []byte, want string) (*pem.Block, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found; expected a %q block", want)
	}
	if block.Type != want {
		return nil, fmt.Errorf("PEM block is %q, expected %q", block.Type, want)
	}
	if next, _ := pem.Decode(rest); next != nil {
		return nil, fmt.Errorf("PEM input carries more than one block; expected a single %q block", want)
	}
	return block, nil
}

// --------------------------------------------------------------------------
// Envelopes (spec section 4)
// --------------------------------------------------------------------------

// ParseEnvelope decodes a `.sig` document, fully fail-closed: unknown members
// are rejected (the SDK-wide deny_unknown_fields rule), duplicate members are
// rejected because two parsers could disagree on which one is signed, and an
// unknown `format_version` or `algorithm` is rejected here rather than
// deferred.
//
// The returned error is an [EnvelopeError] carrying the reason code a
// verifier would have reported, so a caller can surface the same vocabulary.
// A verifier that must report reason codes for these cases in the
// specification's order should call [VerifyPolicyBytes] instead, which does
// exactly that.
func ParseEnvelope(data []byte) (*Envelope, error) {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, envelopeErr(ReasonMalformedEnvelope, "%s", err)
	}

	var env Envelope
	if err := strictUnmarshalJSON(data, &env); err != nil {
		return nil, envelopeErr(ReasonMalformedEnvelope, "%s", err)
	}

	// The Go model reads an optional string as absent when it is empty, so
	// the one distinction it cannot make -- `"signer": ""` against no
	// `signer` at all -- is made here, while the raw document is still
	// available. Both are illegal: the schema gives each a minimum length.
	var presence struct {
		PolicyName *string `json:"policy_name"`
		Signer     *string `json:"signer"`
	}
	if err := json.Unmarshal(data, &presence); err == nil {
		if presence.PolicyName != nil && *presence.PolicyName == "" {
			return nil, envelopeErr(ReasonMalformedEnvelope, "policy_name must not be empty")
		}
		if presence.Signer != nil && *presence.Signer == "" {
			return nil, envelopeErr(ReasonMalformedEnvelope, "signer must not be empty")
		}
	}

	if err := env.validateShape(); err != nil {
		return nil, envelopeErr(ReasonMalformedEnvelope, "%s", err)
	}
	if env.FormatVersion != SignatureFormatVersion {
		return nil, envelopeErr(ReasonUnsupportedFormatVersion,
			"format_version %q is not %q", env.FormatVersion, SignatureFormatVersion)
	}
	if env.Algorithm != SignatureAlgorithm {
		return nil, envelopeErr(ReasonUnsupportedAlgorithm,
			"algorithm %q is not %q", env.Algorithm, SignatureAlgorithm)
	}
	return &env, nil
}

// MarshalEnvelope renders an envelope in its canonical wire form: the RFC
// 8785 serialization of the whole object, `signature` included. Canonical
// rather than pretty-printed, because an envelope is a signed artifact and
// two SDKs writing the same envelope must write the same bytes -- which is
// also what makes signing deterministic and the vectors reproducible.
//
// [ParseEnvelope] accepts any well-formed JSON encoding of an envelope, so a
// `.sig` file written by other tooling with indentation still loads.
func MarshalEnvelope(env *Envelope) ([]byte, error) {
	if env == nil {
		return nil, errors.New("cannot marshal a nil signature envelope")
	}
	if err := env.validateShape(); err != nil {
		return nil, fmt.Errorf("cannot marshal an invalid signature envelope: %w", err)
	}
	members := env.claims()
	members["signature"] = env.Signature
	encoded, err := canonicalJSONValue(members)
	if err != nil {
		return nil, err
	}
	return []byte(encoded), nil
}

// SigningInput returns the bytes the signature covers: the RFC 8785 canonical
// form of the envelope with `signature` absent (spec section 4.1). Every
// other member is inside it, so editing any claim after signing invalidates
// the signature.
func (e *Envelope) SigningInput() ([]byte, error) {
	encoded, err := canonicalJSONValue(e.claims())
	if err != nil {
		return nil, err
	}
	return []byte(encoded), nil
}

// claims builds the signed members of the envelope. Optional members are
// present exactly when they carry a value, which is what makes the signing
// input reproduce byte for byte on the verifier's side.
func (e *Envelope) claims() map[string]any {
	members := map[string]any{
		"format_version": e.FormatVersion,
		"algorithm":      e.Algorithm,
		"key_id":         e.KeyID,
		"signed_at":      e.SignedAt,
		"content_hash":   e.ContentHash,
	}
	if e.ExpiresAt != "" {
		members["expires_at"] = e.ExpiresAt
	}
	if e.PolicyVersion != nil {
		members["policy_version"] = *e.PolicyVersion
	}
	if e.PolicyName != "" {
		members["policy_name"] = e.PolicyName
	}
	if e.Signer != "" {
		members["signer"] = e.Signer
	}
	return members
}

// SignedAtTime parses the envelope's `signed_at`.
func (e *Envelope) SignedAtTime() (time.Time, error) {
	parsed, err := parseEnvelopeTime(e.SignedAt, "signed_at")
	if err != nil {
		return time.Time{}, err
	}
	return *parsed, nil
}

// ExpiresAtTime parses the envelope's `expires_at`, returning nil when the
// envelope carries none.
func (e *Envelope) ExpiresAtTime() (*time.Time, error) {
	if e.ExpiresAt == "" {
		return nil, nil
	}
	return parseEnvelopeTime(e.ExpiresAt, "expires_at")
}

// validateShape is check 1 of spec section 6.2: the envelope against
// schemas/hushspec-signature.v1.schema.json.
//
// The two `const` members are deliberately excluded. The schema pins
// `format_version` to "0.2" and `algorithm` to "ed25519", but section 6.2
// gives each its own check and its own reason code, and a verifier that
// folded them into the shape check would answer `malformed_envelope` where
// the specification requires `unsupported_format_version`. Their presence and
// type are still checked here; only their values are left to checks 2 and 3.
func (e *Envelope) validateShape() error {
	if e.FormatVersion == "" {
		return errors.New("format_version is required")
	}
	if e.Algorithm == "" {
		return errors.New("algorithm is required")
	}
	if !signingDigestPattern.MatchString(e.KeyID) {
		return fmt.Errorf("key_id %q is not `sha256:` and 64 lowercase hex digits", e.KeyID)
	}
	if !envelopeTimePattern.MatchString(e.SignedAt) {
		return fmt.Errorf(
			"signed_at %q is not RFC 3339 UTC with millisecond precision and a Z suffix", e.SignedAt)
	}
	if e.ExpiresAt != "" && !envelopeTimePattern.MatchString(e.ExpiresAt) {
		return fmt.Errorf(
			"expires_at %q is not RFC 3339 UTC with millisecond precision and a Z suffix", e.ExpiresAt)
	}
	if e.PolicyVersion != nil && *e.PolicyVersion < 0 {
		return fmt.Errorf("policy_version %d is negative", *e.PolicyVersion)
	}
	if !signingDigestPattern.MatchString(e.ContentHash) {
		return fmt.Errorf("content_hash %q is not `sha256:` and 64 lowercase hex digits", e.ContentHash)
	}
	if !envelopeSignaturePattern.MatchString(e.Signature) {
		return errors.New(
			"signature is not 86 base64url characters (a 64-byte Ed25519 signature, unpadded)")
	}
	// The timestamps match the schema pattern but could still be nonsense
	// dates such as month 13; a calendar the verifier cannot read is a
	// malformed envelope, not a time-check failure.
	if _, err := e.SignedAtTime(); err != nil {
		return err
	}
	if _, err := e.ExpiresAtTime(); err != nil {
		return err
	}
	return nil
}

// --------------------------------------------------------------------------
// Signing (spec section 4.2)
// --------------------------------------------------------------------------

// SignPolicy signs a policy with a PEM-encoded PKCS#8 Ed25519 private key and
// returns the detached envelope.
//
// The policy is resolved and validated first, with the same resolver a
// verifier uses: the signature covers the resolved document, so a signer that
// cannot resolve the chain MUST refuse to sign rather than sign a fragment
// (spec section 3). `policy_name` and `policy_version` are read from the
// resolved document unless [SignOptions] overrides them.
//
// Signing is deterministic. Ed25519 produces no randomness of its own and the
// signing input is canonical, so the same policy, key and [SignOptions]
// always yield byte-identical envelopes.
func SignPolicy(spec *HushSpec, privateKeyPEM []byte, opts SignOptions) (*Envelope, error) {
	if spec == nil {
		return nil, errors.New("cannot sign a nil HushSpec document")
	}
	resolved, err := resolveForHashing(spec)
	if err != nil {
		return nil, fmt.Errorf("cannot sign: %w", err)
	}
	if result := Validate(resolved); !result.IsValid() {
		return nil, fmt.Errorf("cannot sign an invalid policy: %s", summarizeValidationErrors(result))
	}
	contentHash, err := ContentHash(resolved)
	if err != nil {
		return nil, fmt.Errorf("cannot sign: %w", err)
	}

	// `policy_name` and `policy_version` default to the policy's own
	// (spec section 4.2); SignOptions overrides either.
	if opts.PolicyName == "" {
		opts.PolicyName = resolved.Name
	}
	if opts.PolicyVersion == nil &&
		resolved.Metadata != nil && resolved.Metadata.PolicyVersion != nil {
		version := int64(*resolved.Metadata.PolicyVersion)
		opts.PolicyVersion = &version
	}
	return SignContentHash(contentHash, privateKeyPEM, opts)
}

// SignContentHash signs a content hash that is already in hand: the canonical
// hash of a resolved policy, a receipt hash (receipt spec 6), or a log entry's
// `entry_hash` (log spec 7). The envelope is produced exactly as spec section
// 4.2 describes, whatever the hash covers.
//
// Prefer [SignPolicy] for a policy: it computes the hash the way a verifier
// will, and refuses to sign a document that does not resolve or validate.
func SignContentHash(contentHash string, privateKeyPEM []byte, opts SignOptions) (*Envelope, error) {
	if !signingDigestPattern.MatchString(contentHash) {
		return nil, fmt.Errorf(
			"cannot sign: content_hash %q is not \"sha256:\" followed by 64 lowercase hex digits",
			contentHash)
	}
	private, err := ParsePrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("cannot sign: %w", err)
	}
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("cannot sign: private key does not carry an Ed25519 public key")
	}
	keyID, err := keyIDFromKey(public)
	if err != nil {
		return nil, fmt.Errorf("cannot sign: %w", err)
	}

	signedAt := time.Now()
	if opts.SignedAt != nil {
		signedAt = *opts.SignedAt
	}
	signedAtText, err := formatEnvelopeTime(signedAt, "signed_at")
	if err != nil {
		return nil, fmt.Errorf("cannot sign: %w", err)
	}

	env := &Envelope{
		FormatVersion: SignatureFormatVersion,
		Algorithm:     SignatureAlgorithm,
		KeyID:         keyID,
		SignedAt:      signedAtText,
		ContentHash:   contentHash,
		PolicyName:    opts.PolicyName,
		Signer:        opts.Signer,
	}

	if opts.ExpiresAt != nil {
		expiresAtText, err := formatEnvelopeTime(*opts.ExpiresAt, "expires_at")
		if err != nil {
			return nil, fmt.Errorf("cannot sign: %w", err)
		}
		// An envelope that expires at or before it is signed is born invalid;
		// refuse to mint one rather than hand back a signature that can never
		// verify.
		if expiresAtText <= signedAtText {
			return nil, fmt.Errorf(
				"cannot sign: expires_at %s is not after signed_at %s", expiresAtText, signedAtText)
		}
		env.ExpiresAt = expiresAtText
	}

	if opts.PolicyVersion != nil {
		version := *opts.PolicyVersion
		env.PolicyVersion = &version
	}

	if err := env.validateShapeBeforeSigning(); err != nil {
		return nil, fmt.Errorf("cannot sign: %w", err)
	}
	input, err := env.SigningInput()
	if err != nil {
		return nil, fmt.Errorf("cannot sign: %w", err)
	}
	env.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, input))
	return env, nil
}

// validateShapeBeforeSigning runs the shape checks that apply to an envelope
// that does not carry its signature yet.
func (e *Envelope) validateShapeBeforeSigning() error {
	probe := *e
	probe.Signature = strings.Repeat("A", 86)
	return probe.validateShape()
}

// --------------------------------------------------------------------------
// Verification (spec section 6)
// --------------------------------------------------------------------------

// VerifyPolicyBytes parses a `.sig` document and verifies it, mapping a parse
// failure onto the reason code the corresponding check would have produced.
// It is the entry point for a verifier reading envelopes off disk or off the
// wire, and the one the normative vectors exercise.
func VerifyPolicyBytes(spec *HushSpec, envelopeJSON []byte, opts VerifyOptions) VerifyResult {
	env, err := ParseEnvelope(envelopeJSON)
	if err != nil {
		reason, ok := ReasonFromError(err)
		if !ok {
			reason = ReasonMalformedEnvelope
		}
		result := VerifyResult{Reason: reason, Detail: err.Error()}
		// A rejected envelope may still have been readable enough to name the
		// key it claims, which is worth reporting even though nothing about
		// it was trusted.
		var partial Envelope
		if json.Unmarshal(envelopeJSON, &partial) == nil {
			result.KeyID = partial.KeyID
			result.PolicyName = partial.PolicyName
			result.PolicyVersion = partial.PolicyVersion
		}
		return result
	}
	return VerifyPolicy(spec, env, opts)
}

// VerifyPolicy verifies a policy against a detached envelope, performing the
// checks of spec section 6.2 in order and stopping at the first failure.
//
// spec is the policy as loaded: [VerifyPolicy] resolves it with the SDK's own
// resolver before hashing, because the signature covers the resolved
// document. Passing an already-resolved document is equally valid and is what
// a verify-on-load caller should do -- spec section 10 requires the verified
// document and the evaluated document to be the same object in memory, and
// [VerifyResult.Resolved] hands it back for exactly that.
//
// Resolution here uses the composite loader, which serves `builtin:` from the
// embedded rulesets and resolves other references relative to the process's
// working directory. A policy that extends a file by relative path should
// therefore be resolved by the caller first.
func VerifyPolicy(spec *HushSpec, env *Envelope, opts VerifyOptions) VerifyResult {
	return verifyEnvelope(env, opts, policyContent(spec))
}

// VerifyContentHash verifies an envelope whose claim is a content hash the
// caller already holds: a receipt hash (receipt spec 6) or a log entry's
// `entry_hash` (log spec 7), as well as a resolved policy the caller hashed
// itself.
//
// It runs the same ten ordered checks as [VerifyPolicy]; check 9 compares the
// supplied hash instead of re-resolving a document. An empty contentHash means
// the caller had nothing to compare -- a receipt that would not canonicalize,
// say -- which the specification folds into [ReasonContentHashMismatch], there
// being no hash to compare.
func VerifyContentHash(env *Envelope, contentHash string, opts VerifyOptions) VerifyResult {
	return verifyEnvelope(env, opts, func() (*HushSpec, string, string) {
		if contentHash == "" {
			return nil, "", "no content hash was available to compare"
		}
		return nil, contentHash, ""
	})
}

// envelopeContent supplies check 9's input: the resolved document (when there
// was one), its content hash, and a human-readable failure when no hash could
// be produced at all.
type envelopeContent func() (resolved *HushSpec, contentHash string, failure string)

// policyContent resolves, validates and hashes a policy for check 9. A policy
// that no longer resolves or validates has no hash to compare, which the
// specification folds into the same reason code.
func policyContent(spec *HushSpec) envelopeContent {
	return func() (*HushSpec, string, string) {
		resolved, err := resolveForHashing(spec)
		if err != nil {
			return nil, "", "the policy could not be resolved: " + err.Error()
		}
		if validation := Validate(resolved); !validation.IsValid() {
			return nil, "", "the policy is not valid: " + summarizeValidationErrors(validation)
		}
		contentHash, err := ContentHash(resolved)
		if err != nil {
			return resolved, "", "the policy could not be hashed: " + err.Error()
		}
		return resolved, contentHash, ""
	}
}

func verifyEnvelope(env *Envelope, opts VerifyOptions, content envelopeContent) VerifyResult {
	if env == nil {
		return VerifyResult{Reason: ReasonMalformedEnvelope, Detail: "no signature envelope was supplied"}
	}
	result := VerifyResult{
		KeyID:         env.KeyID,
		PolicyName:    env.PolicyName,
		PolicyVersion: env.PolicyVersion,
	}
	fail := func(reason, format string, args ...any) VerifyResult {
		result.OK = false
		result.Reason = reason
		result.Detail = fmt.Sprintf(format, args...)
		return result
	}

	// 1. Envelope shape.
	if err := env.validateShape(); err != nil {
		return fail(ReasonMalformedEnvelope, "%s", err)
	}
	// 2. Format version.
	if env.FormatVersion != SignatureFormatVersion {
		return fail(ReasonUnsupportedFormatVersion,
			"format_version %q is not %q", env.FormatVersion, SignatureFormatVersion)
	}
	// 3. Algorithm.
	if env.Algorithm != SignatureAlgorithm {
		return fail(ReasonUnsupportedAlgorithm,
			"algorithm %q is not %q", env.Algorithm, SignatureAlgorithm)
	}

	// 4. Key lookup. Selection is by exact key id, and the entry's own id is
	// recomputed from its key material here as well as at load: a keyring
	// built in code never got the load-time check.
	keyring := opts.Keyring
	if keyring == nil {
		if len(opts.PublicKeyPEM) == 0 {
			return fail(ReasonUnknownKeyID,
				"no keyring was supplied, so no key is trusted for key_id %s", env.KeyID)
		}
		built, err := KeyringFromPublicKey(opts.PublicKeyPEM, "")
		if err != nil {
			return fail(ReasonUnknownKeyID, "the supplied public key is unusable: %s", err)
		}
		keyring = built
	}
	entry := keyring.Find(env.KeyID)
	if entry == nil {
		return fail(ReasonUnknownKeyID, "key_id %s is not in the keyring", env.KeyID)
	}
	if entry.Algorithm != SignatureAlgorithm {
		return fail(ReasonUnknownKeyID,
			"keyring entry for %s declares algorithm %q, not %q",
			env.KeyID, entry.Algorithm, SignatureAlgorithm)
	}
	public, _, err := entry.publicKey()
	if err != nil {
		return fail(ReasonUnknownKeyID, "keyring entry for %s is not trustworthy: %s", env.KeyID, err)
	}

	signedAt, err := env.SignedAtTime()
	if err != nil {
		return fail(ReasonMalformedEnvelope, "%s", err)
	}

	// 5. Revocation, then 6. retirement. Revocation first: a compromised key
	// is rejected whenever it signed, a retired one only from its retirement.
	if entry.Revoked {
		return fail(ReasonKeyRevoked, "key %s is revoked", env.KeyID)
	}
	notAfter, err := entry.NotAfterTime()
	if err != nil {
		return fail(ReasonUnknownKeyID, "keyring entry for %s is not trustworthy: %s", env.KeyID, err)
	}
	if notAfter != nil && !signedAt.Before(*notAfter) {
		return fail(ReasonKeyRetired,
			"key %s was retired at %s and the signature was made at %s",
			env.KeyID, entry.NotAfter, env.SignedAt)
	}

	// 7. Time. `signed_at` may not run ahead of the verifier's clock by more
	// than the permitted skew, and an expiry, when present, is exclusive of
	// its own instant.
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	skew := time.Duration(opts.MaxClockSkewSeconds) * time.Second
	switch {
	case opts.MaxClockSkewSeconds == 0:
		skew = DefaultMaxClockSkewSeconds * time.Second
	case opts.MaxClockSkewSeconds < 0:
		skew = 0
	}
	if signedAt.After(now.Add(skew)) {
		return fail(ReasonSignedAtInFuture,
			"signed_at %s is more than %s ahead of the verifier's clock (%s)",
			env.SignedAt, skew, now.UTC().Format(time.RFC3339Nano))
	}
	expiresAt, err := env.ExpiresAtTime()
	if err != nil {
		return fail(ReasonMalformedEnvelope, "%s", err)
	}
	if expiresAt != nil && !now.Before(*expiresAt) {
		return fail(ReasonExpired, "the signature expired at %s", env.ExpiresAt)
	}

	// 8. Signature over the canonical envelope.
	signature, err := base64.RawURLEncoding.DecodeString(env.Signature)
	if err != nil {
		return fail(ReasonSignatureMismatch, "signature is not valid unpadded base64url: %s", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return fail(ReasonSignatureMismatch,
			"signature is %d bytes, expected %d", len(signature), ed25519.SignatureSize)
	}
	input, err := env.SigningInput()
	if err != nil {
		return fail(ReasonMalformedEnvelope, "cannot compute the signing input: %s", err)
	}
	if !ed25519.Verify(public, input, signature) {
		return fail(ReasonSignatureMismatch,
			"the signature does not verify under key %s over the envelope's claims", env.KeyID)
	}

	// 9. Content. A document that no longer resolves, validates or
	// canonicalizes has no hash to compare, which the specification folds into
	// the same reason code.
	resolved, contentHash, failure := content()
	result.Resolved = resolved
	result.ContentHash = contentHash
	if failure != "" {
		return fail(ReasonContentHashMismatch, "%s", failure)
	}
	if contentHash != env.ContentHash {
		return fail(ReasonContentHashMismatch,
			"the signed content hashes to %s but the envelope claims %s",
			contentHash, env.ContentHash)
	}

	// 10. Rollback. Only meaningful when the verifier remembers a version for
	// this policy name and the envelope claims one.
	if opts.LastSeenVersion != nil && env.PolicyVersion != nil &&
		*env.PolicyVersion < *opts.LastSeenVersion {
		return fail(ReasonPolicyVersionRollback,
			"policy_version %d is below the last accepted version %d for %q",
			*env.PolicyVersion, *opts.LastSeenVersion, env.PolicyName)
	}

	result.OK = true
	return result
}

// --------------------------------------------------------------------------
// Shared helpers
// --------------------------------------------------------------------------

// resolveForHashing flattens an extends chain so the document that gets
// hashed is the document that gets enforced. An already-resolved document is
// returned untouched.
func resolveForHashing(spec *HushSpec) (*HushSpec, error) {
	if spec == nil {
		return nil, errors.New("no policy was supplied")
	}
	if spec.Extends == "" {
		return spec, nil
	}
	return Resolve(spec, "", nil)
}

func summarizeValidationErrors(result *ValidationResult) string {
	messages := make([]string, 0, len(result.Errors))
	for _, err := range result.Errors {
		messages = append(messages, err.Code+": "+err.Message)
	}
	return strings.Join(messages, "; ")
}

// canonicalJSONValue serializes an arbitrary JSON value in RFC 8785 canonical
// form using canonical.go's writer. The envelope is canonicalized as a plain
// value rather than as a HushSpec document: it carries no schema defaults, so
// no projection step applies (spec section 4.1).
func canonicalJSONValue(value any) (string, error) {
	var out strings.Builder
	if err := writeJCS(&out, value); err != nil {
		return "", err
	}
	return out.String(), nil
}

// formatEnvelopeTime renders an instant as RFC 3339 UTC with millisecond
// precision and a Z suffix. Sub-millisecond digits are truncated, never
// rounded, so a signature's `signed_at` never lands in the future by a
// rounding artifact.
func formatEnvelopeTime(value time.Time, field string) (string, error) {
	utc := value.UTC()
	if year := utc.Year(); year < 1 || year > 9999 {
		return "", fmt.Errorf("%s year %d cannot be written as RFC 3339", field, year)
	}
	return utc.Format(envelopeTimeLayout) + "Z", nil
}

// parseEnvelopeTime reads a timestamp in the envelope's fixed format. The
// format is a single fixed shape, so anything else -- an offset instead of Z,
// a missing millisecond, a month of 13 -- is an error rather than a lenient
// reinterpretation.
func parseEnvelopeTime(value, field string) (*time.Time, error) {
	if !envelopeTimePattern.MatchString(value) {
		return nil, fmt.Errorf(
			"%s %q is not RFC 3339 UTC with millisecond precision and a Z suffix", field, value)
	}
	parsed, err := time.Parse(envelopeTimeLayout+"Z07:00", value)
	if err != nil {
		return nil, fmt.Errorf("%s %q is not a valid instant: %w", field, value, err)
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

// strictUnmarshalJSON decodes exactly one JSON value into target, rejecting
// unknown members (the SDK-wide deny_unknown_fields rule) and trailing data.
func strictUnmarshalJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the JSON document")
	}
	return nil
}

// rejectDuplicateJSONKeys fails a document that names any member twice.
// encoding/json keeps the last one silently, so a duplicate `content_hash`
// would let two conformant implementations sign and verify different claims
// from one file. Signed documents cannot afford that ambiguity.
func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("not a JSON document: %w", err)
	}
	return walkJSONDuplicates(decoder, token, "")
}

func walkJSONDuplicates(decoder *json.Decoder, token json.Token, path string) error {
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for {
			key, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("truncated JSON object: %w", err)
			}
			if closing, ok := key.(json.Delim); ok && closing == '}' {
				return nil
			}
			name, ok := key.(string)
			if !ok {
				return fmt.Errorf("object member name is %T, not a string", key)
			}
			if seen[name] {
				return fmt.Errorf("duplicate member %q", path+name)
			}
			seen[name] = true
			value, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("truncated JSON object: %w", err)
			}
			if err := walkJSONDuplicates(decoder, value, path+name+"."); err != nil {
				return err
			}
		}
	case '[':
		for {
			item, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("truncated JSON array: %w", err)
			}
			if closing, ok := item.(json.Delim); ok && closing == ']' {
				return nil
			}
			if err := walkJSONDuplicates(decoder, item, path); err != nil {
				return err
			}
		}
	}
	return nil
}
