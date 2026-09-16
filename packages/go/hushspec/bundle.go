package hushspec

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Policy bundle attestation (spec/hushspec-bundle.md).
//
// A signature says a policy was approved; a receipt says a decision was made
// under it. Both name the policy by content hash, and neither carries the
// document that hash identifies. A **bundle** does: it is a DSSE envelope over
// an in-toto Statement v1 whose predicate holds the resolved policy, every hop
// of the `extends` chain that produced it, and the resolver that produced them.
//
// The envelope is ordinary DSSE and the payload an ordinary in-toto Statement,
// so `cosign verify-blob-attestation` and any in-toto consumer read a bundle
// without knowing this specification. HushSpec fixes two things DSSE leaves
// open: the payload bytes are the RFC 8785 canonical serialization of the
// statement, and `keyid` is the signing specification's key id, so one keyring
// serves policies, receipts, log entries, and bundles.
//
// [CreateBundle] builds one and [VerifyBundle] checks one. Creation is
// deterministic: the payload is the RFC 8785 serialization of the statement
// and Ed25519 is deterministic, so the same resolution, CreatedAt and resolver
// always produce the same bytes (bundle spec 4).
//
// [VerifyBundle] runs the four ordered checks of bundle spec 5.2 and stops at
// the first failure, reporting the reason code that check owns. Signature
// verification precedes the subject-digest check on purpose: an edit in
// transit breaks the signature first, so subject_digest_mismatch means an
// internally inconsistent statement that was signed anyway.

const (
	// BundleVersion is the predicate format version this SDK accepts.
	BundleVersion = "0.1"
	// BundlePayloadType is the DSSE `payloadType` of every bundle.
	BundlePayloadType = "application/vnd.in-toto+json"
	// BundleStatementType is the in-toto statement type of every payload.
	BundleStatementType = "https://in-toto.io/Statement/v1"
	// BundlePredicateType names this specification.
	BundlePredicateType = "https://hushspec.dev/attestation/policy-bundle/v0.1"
	// BundleResolverTool is the reference CLI's `resolver.tool`.
	BundleResolverTool = "h2h"
	// bundlePAEPrefix is the DSSE PAE version prefix (bundle spec 3.1).
	bundlePAEPrefix = "DSSEv1"
)

// The closed set of bundle verification reason codes (bundle spec 5.4). A
// verifier never invents a code.
const (
	// BundleReasonMalformed: not a well-formed bundle, statement, or
	// predicate (check 1).
	BundleReasonMalformed = "malformed_bundle"
	// BundleReasonUnknownKeyID: no signature names a key the keyring holds
	// (check 2).
	BundleReasonUnknownKeyID = "unknown_key_id"
	// BundleReasonSignatureMismatch: a trusted key was found but no signature
	// verifies over the PAE; also an empty `signatures` array (check 2).
	BundleReasonSignatureMismatch = "dsse_signature_mismatch"
	// BundleReasonSubjectDigestMismatch: `predicate.resolved` does not hash to
	// the declared subject (check 3).
	BundleReasonSubjectDigestMismatch = "subject_digest_mismatch"
	// BundleReasonPolicyMismatch: the policy the verifier holds is not the
	// bundled one (check 4).
	BundleReasonPolicyMismatch = "policy_mismatch"
)

// BundleReasons is every reason code, in check order. The set is closed.
var BundleReasons = []string{
	BundleReasonMalformed,
	BundleReasonUnknownKeyID,
	BundleReasonSignatureMismatch,
	BundleReasonSubjectDigestMismatch,
	BundleReasonPolicyMismatch,
}

// Patterns transcribed from schemas/hushspec-bundle.v1.schema.json, so shape
// validation is the schema rather than an approximation of it.
var (
	bundleHexDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	bundleBase64Pattern    = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
)

// --------------------------------------------------------------------------
// The envelope (bundle spec 3)
// --------------------------------------------------------------------------

// DSSESignature is one DSSE signature over the payload's PAE.
type DSSESignature struct {
	// KeyID is the signing key's key id (signing spec 5.2). A verifier
	// recomputes it from the public key it holds and never trusts this value.
	KeyID string `json:"keyid"`
	// Sig is standard base64 with padding of the 64 signature bytes.
	Sig string `json:"sig"`
}

// DSSEEnvelope is a policy bundle: a DSSE envelope carrying an in-toto
// statement.
type DSSEEnvelope struct {
	// PayloadType is always [BundlePayloadType].
	PayloadType string `json:"payloadType"`
	// Payload is standard base64 with padding of the statement's canonical
	// bytes.
	Payload string `json:"payload"`
	// Signatures may be empty, which means unsigned -- and an unsigned bundle
	// is not evidence (bundle spec 3).
	Signatures []DSSESignature `json:"signatures"`
}

// BundleSubjectDigest is the digest of an in-toto subject. Only sha256 is
// defined.
type BundleSubjectDigest struct {
	// SHA256 is 64 lowercase hex digits: the content hash *without* its
	// "sha256:" prefix, as in-toto requires.
	SHA256 string `json:"sha256"`
}

// BundleSubject is the attested artifact: the canonical form of the resolved
// policy.
type BundleSubject struct {
	// Name is an informational label: the policy's name, else the leaf source's
	// file name.
	Name   string              `json:"name"`
	Digest BundleSubjectDigest `json:"digest"`
}

// BundleResolver is what produced the bundle.
type BundleResolver struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
}

// BundlePolicyIdentity identifies the resolved policy with the fields a
// receipt's `policy` block carries (receipt spec 4.2), so a receipt and a
// bundle join on content_hash.
type BundlePolicyIdentity struct {
	ContentHash string `json:"content_hash"`
	SpecVersion string `json:"spec_version"`
	// Name is the policy's own `name`, copied as written: a policy that
	// declares an empty name claims an empty name, and only a policy that
	// declares none leaves this absent.
	Name          *string `json:"name,omitempty"`
	PolicyVersion *int64  `json:"policy_version,omitempty"`
}

// PolicyBundlePredicate is the policy-bundle predicate (bundle spec 4.2).
type PolicyBundlePredicate struct {
	// BundleVersion is always [BundleVersion]; an unknown value is rejected.
	BundleVersion string               `json:"bundle_version"`
	Policy        BundlePolicyIdentity `json:"policy"`
	// Chain is the extends chain, root first and leaf last, at least one link.
	Chain []ChainLink `json:"chain"`
	// Resolved is the canonical projection of the resolved document, as a JSON
	// object. Re-serializing it with RFC 8785 reproduces the canonical form
	// whose digest the subject names.
	Resolved map[string]any `json:"resolved"`
	Resolver BundleResolver `json:"resolver"`
	// CreatedAt is RFC 3339 UTC with millisecond precision and a Z suffix.
	CreatedAt string `json:"created_at"`
	// SignatureVerification is the leaf policy's own signature status at
	// bundling time, absent when the bundler attempted no verification.
	SignatureVerification *SignatureStatus `json:"signature_verification,omitempty"`
}

// BundleStatement is an in-toto Statement v1 carrying a policy-bundle
// predicate.
type BundleStatement struct {
	Type          string                `json:"_type"`
	Subject       []BundleSubject       `json:"subject"`
	PredicateType string                `json:"predicateType"`
	Predicate     PolicyBundlePredicate `json:"predicate"`
}

// BundleError is a bundle parse failure that carries the verification reason
// code a verifier would have reported for it, so a caller that rejects a
// bundle at parse time reports the same code.
type BundleError struct {
	// Reason is a bundle spec 5.4 code; parse failures are always
	// [BundleReasonMalformed].
	Reason string
	// Detail explains the failure for a human. Informational only.
	Detail string
}

func (e *BundleError) Error() string {
	return fmt.Sprintf("invalid policy bundle (%s): %s", e.Reason, e.Detail)
}

func bundleErr(format string, args ...any) *BundleError {
	return &BundleError{Reason: BundleReasonMalformed, Detail: fmt.Sprintf(format, args...)}
}

// ParseBundle decodes and shape-checks a bundle file (bundle spec 5.2 check 1,
// envelope half). Unknown members, a duplicate member anywhere in the
// document, and a payload type this specification does not define are all
// refusals: a signed document cannot afford an ambiguity a verifier resolves
// differently from the signer.
func ParseBundle(data []byte) (*DSSEEnvelope, error) {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, bundleErr("%v", err)
	}
	var envelope DSSEEnvelope
	if err := strictUnmarshalJSON(data, &envelope); err != nil {
		return nil, bundleErr("%v", err)
	}
	if envelope.PayloadType != BundlePayloadType {
		return nil, bundleErr("payloadType %q, expected %q", envelope.PayloadType, BundlePayloadType)
	}
	if envelope.Payload == "" || !bundleBase64Pattern.MatchString(envelope.Payload) {
		return nil, bundleErr("payload is not standard base64 with padding")
	}
	if envelope.Signatures == nil {
		return nil, bundleErr("`signatures` is required; an unsigned bundle spells it as []")
	}
	for index, signature := range envelope.Signatures {
		if !isBundleContentHash(signature.KeyID) {
			return nil, bundleErr("signatures[%d].keyid %q is not sha256:<64 lowercase hex>",
				index, signature.KeyID)
		}
		if signature.Sig == "" || !bundleBase64Pattern.MatchString(signature.Sig) {
			return nil, bundleErr("signatures[%d].sig is not standard base64 with padding", index)
		}
	}
	return &envelope, nil
}

// PayloadBytes decodes the DSSE payload.
func (e *DSSEEnvelope) PayloadBytes() ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, bundleErr("payload is not standard base64: %v", err)
	}
	return raw, nil
}

// PAE is the bytes a signature covers: PAE(payloadType, payload bytes)
// (bundle spec 3.1).
func (e *DSSEEnvelope) PAE() ([]byte, error) {
	payload, err := e.PayloadBytes()
	if err != nil {
		return nil, err
	}
	return BundlePAE(e.PayloadType, payload), nil
}

// Statement decodes and shape-checks the payload (bundle spec 5.2 check 1).
func (e *DSSEEnvelope) Statement() (*BundleStatement, error) {
	payload, err := e.PayloadBytes()
	if err != nil {
		return nil, err
	}
	// A payload a verifier and a signer read differently is exactly what
	// check 1 exists to stop, and encoding/json replaces ill-formed bytes
	// rather than refusing them.
	if !utf8.Valid(payload) {
		return nil, bundleErr("the payload is not UTF-8")
	}
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return nil, bundleErr("the payload is not a policy-bundle statement: %v", err)
	}
	var statement BundleStatement
	if err := strictUnmarshalJSON(payload, &statement); err != nil {
		return nil, bundleErr("the payload is not a policy-bundle statement: %v", err)
	}
	if err := statement.checkShape(); err != nil {
		return nil, err
	}
	return &statement, nil
}

// BundlePAE is the DSSE Pre-Authentication Encoding (bundle spec 3.1):
//
//	PAE(t, b) = "DSSEv1" SP LEN(t) SP t SP LEN(b) SP b
//
// with lengths in ASCII decimal over *bytes*. Binding the type into the signed
// bytes is what stops a payload being replayed under a different type.
func BundlePAE(payloadType string, payload []byte) []byte {
	header := fmt.Sprintf("%s %d %s %d ", bundlePAEPrefix, len(payloadType), payloadType, len(payload))
	out := make([]byte, 0, len(header)+len(payload))
	out = append(out, header...)
	return append(out, payload...)
}

// checkShape is everything bundle spec 5.2 check 1 constrains beyond the
// envelope.
func (s *BundleStatement) checkShape() error {
	if s.Type != BundleStatementType {
		return bundleErr("_type %q, expected %q", s.Type, BundleStatementType)
	}
	if s.PredicateType != BundlePredicateType {
		return bundleErr("predicateType %q, expected %q", s.PredicateType, BundlePredicateType)
	}
	if len(s.Subject) != 1 {
		return bundleErr("a bundle attests exactly one subject, found %d", len(s.Subject))
	}
	subject := s.Subject[0]
	if subject.Name == "" {
		return bundleErr("the subject name is empty")
	}
	if !bundleHexDigestPattern.MatchString(subject.Digest.SHA256) {
		return bundleErr("subject digest %q is not 64 lowercase hex characters", subject.Digest.SHA256)
	}

	predicate := &s.Predicate
	if predicate.BundleVersion != BundleVersion {
		return bundleErr("bundle_version %q, expected %q", predicate.BundleVersion, BundleVersion)
	}
	if !isBundleContentHash(predicate.Policy.ContentHash) {
		return bundleErr("policy.content_hash %q is not sha256:<64 lowercase hex>",
			predicate.Policy.ContentHash)
	}
	if predicate.Policy.SpecVersion == "" {
		return bundleErr("policy.spec_version is empty")
	}
	// The one timestamp form 0.2 accepts, shared with the signature envelope.
	if _, err := parseEnvelopeTime(predicate.CreatedAt, "created_at"); err != nil {
		return bundleErr("%v", err)
	}
	if predicate.Resolver.Tool == "" || predicate.Resolver.Version == "" {
		return bundleErr("resolver.tool and resolver.version are required and must be non-empty")
	}
	if len(predicate.Chain) == 0 {
		return bundleErr("the chain must hold at least one link (the policy itself)")
	}
	for _, link := range predicate.Chain {
		if link.Source == "" {
			return bundleErr("a chain link has an empty source")
		}
		if !isBundleContentHash(link.ContentHash) {
			return bundleErr("chain link %q has content_hash %q, not sha256:<64 lowercase hex>",
				link.Source, link.ContentHash)
		}
	}
	if predicate.Resolved == nil {
		return bundleErr("predicate.resolved is not a JSON object")
	}
	return nil
}

// --------------------------------------------------------------------------
// Creation (bundle spec 4)
// --------------------------------------------------------------------------

// CreateBundleOptions is what a bundler decides beyond the resolution itself.
type CreateBundleOptions struct {
	// PrivateKeyPEM is the PKCS#8 PEM Ed25519 key that signs the bundle. Nil
	// produces an *unsigned* bundle: a well-formed envelope with an empty
	// signatures array, which bundle spec 3 says is not evidence and
	// [VerifyBundle] rejects. A tool that produces one must say so.
	PrivateKeyPEM []byte
	// CreatedAt is `predicate.created_at`. The zero time means now. Pinning it
	// is what makes a bundle byte-reproducible: two bundlers given the same
	// resolution, the same CreatedAt and the same resolver produce identical
	// bytes (bundle spec 4).
	CreatedAt time.Time
	// Tool is `resolver.tool`. Empty means [SDKName]. Overriding it is how a
	// bundle some other tool produced is reproduced byte-for-byte: the vectors
	// in fixtures/bundle/ come from the reference CLI, so rebuilding them here
	// needs [BundleResolverTool] and that CLI's version.
	Tool string
	// Version is `resolver.version`. Empty means this SDK's [Version].
	Version string
	// SubjectName overrides the subject name, which otherwise comes from the
	// policy.
	SubjectName string
	// BaseDir is the directory filesystem chain sources are recorded relative
	// to (bundle spec 4.4), so a bundle built in CI neither leaks nor depends
	// on a runner's workspace path. `builtin:` and URL sources are already
	// portable and are recorded unchanged, as is any path outside BaseDir.
	BaseDir string
}

// BuildBundleStatement builds the in-toto statement for a resolved policy
// (bundle spec 4).
//
// The subject digest is recomputed here from the canonical projection that
// goes into `predicate.resolved`, never copied from the resolution, so the
// statement is internally consistent by construction: there is no path by
// which a bundle names the hash of a document other than the one it carries.
func BuildBundleStatement(resolution *Resolution, opts CreateBundleOptions) (*BundleStatement, error) {
	if resolution == nil || resolution.Spec == nil {
		return nil, errors.New("cannot bundle a nil resolution")
	}
	resolved, err := bundleResolvedValue(resolution.Spec)
	if err != nil {
		return nil, fmt.Errorf("the resolved policy has no canonical form: %w", err)
	}
	canonical, err := canonicalJSONValue(resolved)
	if err != nil {
		return nil, fmt.Errorf("the resolved policy has no canonical form: %w", err)
	}
	sum := sha256.Sum256([]byte(canonical))
	contentHash := contentHashPrefix + hex.EncodeToString(sum[:])

	createdAt := opts.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	created, err := formatEnvelopeTime(createdAt, "created_at")
	if err != nil {
		return nil, err
	}

	chain := make([]ChainLink, len(resolution.Chain))
	for i, link := range resolution.Chain {
		chain[i] = ChainLink{
			Source:      bundleRelativeSource(link.Source, opts.BaseDir),
			ContentHash: link.ContentHash,
			Signature:   link.Signature,
		}
	}

	spec := resolution.Spec
	name := bundleSubjectName(opts.SubjectName, spec, chain)

	tool := opts.Tool
	if tool == "" {
		tool = SDKName
	}
	version := opts.Version
	if version == "" {
		version = Version
	}

	var policyVersion *int64
	if spec.Metadata != nil && spec.Metadata.PolicyVersion != nil {
		value := int64(*spec.Metadata.PolicyVersion)
		policyVersion = &value
	}

	return &BundleStatement{
		Type: BundleStatementType,
		Subject: []BundleSubject{{
			Name: name,
			// The prefix is stripped here and only here: in-toto requires a
			// bare hex digest for a subject (bundle spec 4.1), while every
			// content hash inside the predicate keeps it.
			Digest: BundleSubjectDigest{SHA256: strings.TrimPrefix(contentHash, contentHashPrefix)},
		}},
		PredicateType: BundlePredicateType,
		Predicate: PolicyBundlePredicate{
			BundleVersion: BundleVersion,
			Policy: BundlePolicyIdentity{
				ContentHash:   contentHash,
				SpecVersion:   spec.HushSpecVersion,
				Name:          bundlePolicyName(spec),
				PolicyVersion: policyVersion,
			},
			Chain:     chain,
			Resolved:  resolved,
			Resolver:  BundleResolver{Tool: tool, Version: version},
			CreatedAt: created,
			// A bundler that attempted no verification leaves this nil rather
			// than recording `verified: false`, which would assert a check
			// that never ran (bundle spec 4.5).
			SignatureVerification: resolution.Signature,
		},
	}, nil
}

// BundleStatementBytes is the payload a bundle carries: the RFC 8785 canonical
// serialization of the statement, UTF-8 encoded (bundle spec 4).
func BundleStatementBytes(statement *BundleStatement) ([]byte, error) {
	if statement == nil {
		return nil, errors.New("cannot serialize a nil statement")
	}
	// Round-tripping through encoding/json applies the struct's own json tags
	// -- including every omitempty an optional member depends on -- and yields
	// the plain value tree writeJCS canonicalizes. It is the same path a
	// bundle takes on the way in, so a statement this SDK builds and one it
	// parses canonicalize identically.
	value, err := bundleValueOf(statement)
	if err != nil {
		return nil, err
	}
	canonical, err := canonicalJSONValue(value)
	if err != nil {
		return nil, fmt.Errorf("the statement has no canonical form: %w", err)
	}
	return []byte(canonical), nil
}

// CreateBundle builds a bundle for a resolution: signed when
// [CreateBundleOptions.PrivateKeyPEM] is set, unsigned otherwise (bundle spec
// 3 and 4).
//
// The payload is canonical and Ed25519 is deterministic, so the result is a
// pure function of the resolution, CreatedAt, the resolver and the key.
// bundle_create_test.go proves it by rebuilding
// fixtures/bundle/bundles/valid.bundle.json byte for byte.
func CreateBundle(resolution *Resolution, opts CreateBundleOptions) (*DSSEEnvelope, error) {
	statement, err := BuildBundleStatement(resolution, opts)
	if err != nil {
		return nil, err
	}
	payload, err := BundleStatementBytes(statement)
	if err != nil {
		return nil, err
	}
	envelope := &DSSEEnvelope{
		PayloadType: BundlePayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []DSSESignature{},
	}
	if len(opts.PrivateKeyPEM) == 0 {
		return envelope, nil
	}

	private, err := ParsePrivateKeyPEM(opts.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("the private key has no Ed25519 public half")
	}
	// The id is derived from the key itself, never declared independently: a
	// verifier recomputes it and would reject any other value (signing 5.2).
	keyID, err := keyIDFromKey(public)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(private, BundlePAE(BundlePayloadType, payload))
	envelope.Signatures = []DSSESignature{{
		KeyID: keyID,
		Sig:   base64.StdEncoding.EncodeToString(signature),
	}}
	return envelope, nil
}

// MarshalBundle writes a bundle the way the reference CLI writes one:
// pretty-printed with a trailing newline.
func MarshalBundle(envelope *DSSEEnvelope) ([]byte, error) {
	if envelope == nil {
		return nil, errors.New("cannot marshal a nil bundle")
	}
	encoded, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// bundleResolvedValue is the canonical projection of a resolved document as
// the plain JSON object `predicate.resolved` holds (canonical spec 3).
func bundleResolvedValue(spec *HushSpec) (map[string]any, error) {
	if spec.Extends != nil {
		return nil, fmt.Errorf(
			"cannot canonicalize an unresolved HushSpec document: resolve extends %q first",
			*spec.Extends,
		)
	}
	projected, err := canonicalProjectStruct(reflect.ValueOf(*spec))
	if err != nil {
		return nil, err
	}
	return bundleValueOf(projected)
}

// bundleValueOf is a value as encoding/json sees it: a tree of map[string]any,
// []any, string, float64, bool and nil, which is what writeJCS canonicalizes.
func bundleValueOf(value any) (map[string]any, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var plain map[string]any
	if err := json.Unmarshal(encoded, &plain); err != nil {
		return nil, err
	}
	return plain, nil
}

// bundleRelativeSource records a filesystem source relative to base when it
// lies beneath it (bundle spec 4.4). `builtin:` and URL sources are already
// portable and are returned unchanged, as is any path not beneath base.
func bundleRelativeSource(source, base string) string {
	if base == "" || strings.HasPrefix(source, "builtin:") || strings.Contains(source, "://") {
		return source
	}
	relative, err := filepath.Rel(base, source)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return source
	}
	// A bundle is JSON read on every platform, so the separator is `/`.
	return filepath.ToSlash(relative)
}

// bundleSubjectName is the subject's informational label: the first of an
// explicit override, the policy's own name, the leaf source's file name, and a
// constant. The subject needs at least one character (bundle spec 4.1), so a
// policy that declares an empty name falls through to the file name.
// bundlePolicyName is the policy's `name` when it has one character or more:
// the bundle schema admits no empty subject name or policy name claim.
func bundlePolicyName(spec *HushSpec) *string {
	if spec.Name == nil || *spec.Name == "" {
		return nil
	}
	return spec.Name
}

func bundleSubjectName(override string, spec *HushSpec, chain []ChainLink) string {
	if override != "" {
		return override
	}
	if name := bundlePolicyName(spec); name != nil {
		return *name
	}
	if leaf := bundleLeafFileName(chain); leaf != "" {
		return leaf
	}
	return "policy"
}

// bundleLeafFileName is the leaf's file name, for a policy with no `name`.
func bundleLeafFileName(chain []ChainLink) string {
	if len(chain) == 0 {
		return ""
	}
	source := strings.ReplaceAll(chain[len(chain)-1].Source, `\`, "/")
	name := path.Base(source)
	if name == "." || name == "/" {
		return ""
	}
	return name
}

// --------------------------------------------------------------------------
// Verification (bundle spec 5)
// --------------------------------------------------------------------------

// VerifyBundleOptions is what a verifier knows besides the bundle itself
// (bundle spec 5.1).
type VerifyBundleOptions struct {
	// Keyring is the set of trusted keys. When nil, PublicKeyPEM is used as a
	// one-key keyring; when both are empty no key is trusted and every
	// signature is rejected with [BundleReasonUnknownKeyID].
	Keyring *Keyring
	// PublicKeyPEM is a single SPKI PEM public key accepted as a one-key
	// keyring, with its key id recomputed from the key. Ignored when Keyring
	// is non-nil.
	PublicKeyPEM []byte
	// Now is the verifier's clock. A bundle carries no expiry, so this only
	// stamps the report's VerifiedAt. The zero time means time.Now().
	Now time.Time
	// Policy is the caller's own resolved policy to cross-check (check 4).
	// Nil skips check 4. Only the content hash is compared, because a bare
	// document carries no chain; supply PolicyResolution instead to compare
	// the chain as well.
	Policy *HushSpec
	// PolicyResolution is Policy with the evidence of how it was resolved. It
	// takes precedence over Policy and is what a caller who resolved an
	// `extends` chain should pass: check 4 then compares the chain hop hashes
	// in order, as bundle spec 5.3 requires.
	PolicyResolution *Resolution
}

// VerifyBundleResult is the outcome of [VerifyBundle]. OK and Reason are the
// programmatic contract: Reason is "" exactly when OK is true, and otherwise
// one of the bundle spec 5.4 codes. Detail is free text for humans and MUST
// NOT be parsed.
type VerifyBundleResult struct {
	// OK reports whether every check of bundle spec 5.2 passed.
	OK bool
	// Reason is the bundle spec 5.4 reason code for the first failed check.
	Reason string
	// Detail explains the failure for a human. Informational only.
	Detail string
	// KeyIDs are the keys whose signature verified, when check 2 ran.
	KeyIDs []string
	// SubjectName is the subject's informational label.
	SubjectName string
	// ContentHash is the resolved policy's content hash, "sha256:"-prefixed.
	ContentHash string
	// PolicyName and PolicyVersion echo the predicate's claims. PolicyName is
	// nil when the bundle records no policy name.
	PolicyName    *string
	PolicyVersion *int64
	// CreatedAt is the predicate's own timestamp.
	CreatedAt string
	// ChainLength is the number of `extends` hops the bundle records.
	ChainLength int
	// PolicyChecked reports whether check 4 ran (a policy was supplied).
	PolicyChecked bool
	// VerifiedAt is the verifier's clock, in the receipt timestamp form.
	VerifiedAt string
	// Statement is the decoded statement, available from check 1 onward so a
	// caller can inspect a bundle it rejected.
	Statement *BundleStatement
}

func bundleFailure(reason, format string, args ...any) VerifyBundleResult {
	return VerifyBundleResult{OK: false, Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// VerifyBundle runs the four ordered checks of bundle spec 5.2 against a
// bundle file's bytes, stopping at the first failure and reporting the reason
// code that check owns:
//
//  1. Shape: the document is a bundle whose payload decodes into a statement
//     with this specification's constants and exactly one subject.
//  2. Signature: at least one entry of `signatures` names a key the keyring
//     holds, and at least one such entry verifies as Ed25519 over the PAE,
//     with the key's id recomputed from the public key.
//  3. Subject: the RFC 8785 canonical form of `predicate.resolved` hashes to
//     `predicate.policy.content_hash`, and the subject digest is that hash
//     without its prefix.
//  4. Policy: only when a policy was supplied, it resolves to the same
//     canonical form and (with a [Resolution]) the same chain hashes.
//
// Nothing here authorizes loading `predicate.resolved` and enforcing it: a
// bundle is evidence about a policy, not a way to distribute one.
func VerifyBundle(bundle []byte, opts VerifyBundleOptions) VerifyBundleResult {
	// 1. Shape.
	envelope, err := ParseBundle(bundle)
	if err != nil {
		return bundleFailure(bundleReasonOf(err), "%s", bundleDetailOf(err))
	}
	statement, err := envelope.Statement()
	if err != nil {
		return bundleFailure(bundleReasonOf(err), "%s", bundleDetailOf(err))
	}
	predicate := &statement.Predicate

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	verifiedAt, err := formatEnvelopeTime(now, "now")
	if err != nil {
		return bundleFailure(BundleReasonMalformed, "%v", err)
	}

	result := VerifyBundleResult{
		SubjectName:   statement.Subject[0].Name,
		ContentHash:   predicate.Policy.ContentHash,
		PolicyName:    predicate.Policy.Name,
		PolicyVersion: predicate.Policy.PolicyVersion,
		CreatedAt:     predicate.CreatedAt,
		ChainLength:   len(predicate.Chain),
		VerifiedAt:    verifiedAt,
		Statement:     statement,
	}

	// 2. Signature. A bundle may carry several; one that verifies under a
	//    trusted key is enough, and the reason code distinguishes "we trust
	//    nobody who signed this" from "the signature is wrong".
	keyring, err := bundleKeyring(opts)
	if err != nil {
		result.Reason, result.Detail = BundleReasonUnknownKeyID, err.Error()
		return result
	}
	pae, err := envelope.PAE()
	if err != nil {
		result.Reason, result.Detail = bundleReasonOf(err), bundleDetailOf(err)
		return result
	}

	namedATrustedKey := false
	mismatchDetail := ""
	for _, signature := range envelope.Signatures {
		entry := keyring.Find(signature.KeyID)
		if entry == nil {
			continue
		}
		// The declared id is never enough (signing spec 5.2).
		public, recomputed, keyErr := entry.publicKey()
		if keyErr != nil || recomputed != signature.KeyID {
			continue
		}
		namedATrustedKey = true
		raw, decodeErr := base64.StdEncoding.DecodeString(signature.Sig)
		if decodeErr != nil || len(raw) != ed25519.SignatureSize {
			mismatchDetail = fmt.Sprintf("signature by %s is not 64 bytes", signature.KeyID)
			continue
		}
		if ed25519.Verify(public, pae, raw) {
			result.KeyIDs = append(result.KeyIDs, signature.KeyID)
			continue
		}
		mismatchDetail = fmt.Sprintf("Ed25519 verification failed for %s", signature.KeyID)
	}
	if len(result.KeyIDs) == 0 {
		switch {
		case namedATrustedKey:
			result.Reason, result.Detail = BundleReasonSignatureMismatch, mismatchDetail
		case len(envelope.Signatures) == 0:
			result.Reason = BundleReasonSignatureMismatch
			result.Detail = "the bundle is unsigned; an unsigned bundle is not evidence"
		default:
			result.Reason = BundleReasonUnknownKeyID
			result.Detail = fmt.Sprintf(
				"none of the %d signature(s) names a key in the keyring (%d trusted)",
				len(envelope.Signatures), len(keyring.Keys))
		}
		return result
	}

	// 3. Subject: the bundle must hash to what it claims to be about.
	canonical, err := canonicalJSONValue(predicate.Resolved)
	if err != nil {
		result.Reason = BundleReasonSubjectDigestMismatch
		result.Detail = fmt.Sprintf("predicate.resolved has no canonical form: %v", err)
		return result
	}
	sum := sha256.Sum256([]byte(canonical))
	recomputed := contentHashPrefix + hex.EncodeToString(sum[:])
	if recomputed != predicate.Policy.ContentHash {
		result.Reason = BundleReasonSubjectDigestMismatch
		result.Detail = fmt.Sprintf(
			"predicate.resolved hashes to %s, but policy.content_hash is %s",
			recomputed, predicate.Policy.ContentHash)
		return result
	}
	declared := statement.Subject[0].Digest.SHA256
	expected := strings.TrimPrefix(recomputed, contentHashPrefix)
	if declared != expected {
		result.Reason = BundleReasonSubjectDigestMismatch
		result.Detail = fmt.Sprintf(
			"the subject digest is %s, but predicate.resolved hashes to %s", declared, expected)
		return result
	}

	// 4. Policy: is the bundle about the policy the verifier holds?
	resolution := opts.PolicyResolution
	if resolution == nil && opts.Policy != nil {
		resolution = &Resolution{Spec: opts.Policy}
	}
	if resolution != nil {
		result.PolicyChecked = true
		if detail := compareBundlePolicy(predicate, resolution); detail != "" {
			result.Reason, result.Detail = BundleReasonPolicyMismatch, detail
			return result
		}
	}

	result.OK = true
	return result
}

// compareBundlePolicy is check 4 (bundle spec 5.3): the resolved documents and
// the chain hashes must agree. `source` is a provenance label and is never
// compared -- the same policy resolved on a different host, in a different
// checkout, or through a mirror is the same policy.
//
// The resolved documents are compared through their canonical forms, not as
// JSON values: a value tree that has been through a JSON round trip can hold
// 10 where the projection held 10.0, which RFC 8785 serializes identically
// (canonical spec 4.3) but a Go value comparison does not. Check 3 has already
// tied predicate.policy.content_hash to predicate.resolved, so comparing
// hashes here is comparing the bytes.
//
// A resolution with no recorded chain compares the document only: the chain is
// unknown, not empty, and an unknown chain is nothing to disagree with.
func compareBundlePolicy(predicate *PolicyBundlePredicate, resolution *Resolution) string {
	resolved, err := ContentHash(resolution.Spec)
	if err != nil {
		return fmt.Sprintf("the policy has no canonical form: %v", err)
	}
	if resolved != predicate.Policy.ContentHash {
		return fmt.Sprintf("the policy resolves to %s, but the bundle attests %s",
			resolved, predicate.Policy.ContentHash)
	}
	if len(resolution.Chain) == 0 {
		return ""
	}
	if len(resolution.Chain) != len(predicate.Chain) {
		return fmt.Sprintf("the policy resolves through %d document(s), the bundle records %d",
			len(resolution.Chain), len(predicate.Chain))
	}
	for index, actual := range resolution.Chain {
		bundled := predicate.Chain[index]
		if actual.ContentHash != bundled.ContentHash {
			return fmt.Sprintf("chain hop %q hashes to %s, but the bundle records %s for %q",
				actual.Source, actual.ContentHash, bundled.ContentHash, bundled.Source)
		}
	}
	return ""
}

// bundleKeyring resolves the verifier's root of trust: an explicit keyring, or
// a single public key promoted to a one-key keyring with its id recomputed
// from the key itself.
func bundleKeyring(opts VerifyBundleOptions) (*Keyring, error) {
	if opts.Keyring != nil {
		return opts.Keyring, nil
	}
	if len(opts.PublicKeyPEM) == 0 {
		return &Keyring{Version: KeyringFormatVersion}, nil
	}
	keyring, err := KeyringFromPublicKey(opts.PublicKeyPEM, "")
	if err != nil {
		return nil, fmt.Errorf("the supplied public key is unusable: %w", err)
	}
	return keyring, nil
}

func bundleReasonOf(err error) string {
	var bundleError *BundleError
	if errors.As(err, &bundleError) {
		return bundleError.Reason
	}
	return BundleReasonMalformed
}

func bundleDetailOf(err error) string {
	var bundleError *BundleError
	if errors.As(err, &bundleError) {
		return bundleError.Detail
	}
	return err.Error()
}

func isBundleContentHash(value string) bool {
	rest, ok := strings.CutPrefix(value, contentHashPrefix)
	return ok && bundleHexDigestPattern.MatchString(rest)
}
