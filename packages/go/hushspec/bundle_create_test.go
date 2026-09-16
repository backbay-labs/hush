package hushspec

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Bundle creation (spec/hushspec-bundle.md section 4).
//
// The contract a bundler has to meet is reproducibility: "two bundlers given
// the same resolution, the same created_at, and the same resolver therefore
// produce byte-identical payloads and -- Ed25519 being deterministic --
// byte-identical bundles" (bundle spec 4). The normative vector
// fixtures/bundle/bundles/valid.bundle.json was produced by the reference CLI,
// so rebuilding it here from the same policy, key and created_at puts that
// claim under test across two independent implementations.

// bundleVectorCreatedAt is the created_at the vectors pin so the bundles are
// byte-reproducible.
const bundleVectorCreatedAt = "2026-09-15T12:00:00.000Z"

// bundleVectorPolicy is the policy every bundle vector attests
// (fixtures/bundle/README.md).
var bundleVectorPolicy = filepath.Join("library", "healthcare", "hipaa-base.yaml")

// readBundleTestKey reads a published test key, minus the DO-NOT-USE header
// above its PEM block.
func readBundleTestKey(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureRepoRoot(t), "fixtures", "signing", "keys", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if index := bytes.Index(data, []byte("-----BEGIN")); index > 0 {
		data = data[index:]
	}
	return data
}

func readBundleVector(t *testing.T, name string) *DSSEEnvelope {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureRepoRoot(t), "fixtures", "bundle", "bundles", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	envelope, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return envelope
}

// bundleVectorResolver is the reference CLI's resolver, read back from the
// vector it produced rather than hardcoded a second time.
func bundleVectorResolver(t *testing.T) BundleResolver {
	t.Helper()
	statement, err := readBundleVector(t, "valid.bundle.json").Statement()
	if err != nil {
		t.Fatalf("decode the valid vector: %v", err)
	}
	return statement.Predicate.Resolver
}

func bundleVectorResolution(t *testing.T) *Resolution {
	t.Helper()
	policy := filepath.Join(fixtureRepoRoot(t), bundleVectorPolicy)
	resolution, err := ResolveFileWithOptions(policy, ResolveOptions{})
	if err != nil {
		t.Fatalf("resolve %s: %v", policy, err)
	}
	return resolution
}

func bundleVectorOptions(t *testing.T, key string) CreateBundleOptions {
	t.Helper()
	resolver := bundleVectorResolver(t)
	created, err := time.Parse(time.RFC3339, bundleVectorCreatedAt)
	if err != nil {
		t.Fatalf("parse the pinned created_at: %v", err)
	}
	options := CreateBundleOptions{
		CreatedAt: created,
		Tool:      resolver.Tool,
		Version:   resolver.Version,
		BaseDir:   fixtureRepoRoot(t),
	}
	if key != "" {
		options.PrivateKeyPEM = readBundleTestKey(t, key)
	}
	return options
}

// bundleVectorKeyring is the keyring the vectors verify against.
func bundleVectorKeyring(t *testing.T) *Keyring {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureRepoRoot(t), "fixtures", "signing", "keys", "keyring.json"))
	if err != nil {
		t.Fatalf("read the keyring: %v", err)
	}
	keyring, err := LoadKeyring(data)
	if err != nil {
		t.Fatalf("load the keyring: %v", err)
	}
	return keyring
}

// --------------------------------------------------------------------------
// Reproducing the normative vectors
// --------------------------------------------------------------------------

func TestCreateBundleReproducesTheSignedVector(t *testing.T) {
	expected := readBundleVector(t, "valid.bundle.json")
	built, err := CreateBundle(bundleVectorResolution(t), bundleVectorOptions(t, "test-signing.key.pem"))
	if err != nil {
		t.Fatalf("CreateBundle: %v", err)
	}

	// Equal payloads mean the two bundlers agree on every member of the
	// statement, not merely on its meaning.
	if built.Payload != expected.Payload {
		t.Errorf("payload differs from the vector\n got %s\nwant %s", built.Payload, expected.Payload)
	}
	if built.PayloadType != expected.PayloadType {
		t.Errorf("payloadType = %q, want %q", built.PayloadType, expected.PayloadType)
	}
	if len(built.Signatures) != 1 || built.Signatures[0] != expected.Signatures[0] {
		t.Errorf("signatures = %+v, want %+v", built.Signatures, expected.Signatures)
	}

	encoded, err := MarshalBundle(built)
	if err != nil {
		t.Fatalf("MarshalBundle: %v", err)
	}
	onDisk, err := os.ReadFile(filepath.Join(fixtureRepoRoot(t), "fixtures", "bundle", "bundles", "valid.bundle.json"))
	if err != nil {
		t.Fatalf("read the vector file: %v", err)
	}
	if !bytes.Equal(encoded, onDisk) {
		t.Errorf("the serialized bundle is not the vector file byte for byte")
	}
}

func TestCreateBundleReproducesTheUnsignedVector(t *testing.T) {
	expected := readBundleVector(t, "unsigned.bundle.json")
	built, err := CreateBundle(bundleVectorResolution(t), bundleVectorOptions(t, ""))
	if err != nil {
		t.Fatalf("CreateBundle: %v", err)
	}
	if len(built.Signatures) != 0 {
		t.Errorf("an unsigned bundle carries %d signature(s), want none", len(built.Signatures))
	}
	if built.Payload != expected.Payload {
		t.Errorf("payload differs from the unsigned vector")
	}
}

func TestCreateBundleReproducesTheUntrustedKeyVector(t *testing.T) {
	expected := readBundleVector(t, "wrong-key.bundle.json")
	built, err := CreateBundle(bundleVectorResolution(t), bundleVectorOptions(t, "test-untrusted.key.pem"))
	if err != nil {
		t.Fatalf("CreateBundle: %v", err)
	}
	if built.Payload != expected.Payload || built.Signatures[0] != expected.Signatures[0] {
		t.Errorf("the bundle signed with the untrusted key is not the vector")
	}
}

func TestCreateBundleIsDeterministic(t *testing.T) {
	options := bundleVectorOptions(t, "test-signing.key.pem")
	first, err := CreateBundle(bundleVectorResolution(t), options)
	if err != nil {
		t.Fatalf("CreateBundle: %v", err)
	}
	second, err := CreateBundle(bundleVectorResolution(t), options)
	if err != nil {
		t.Fatalf("CreateBundle: %v", err)
	}
	if first.Payload != second.Payload || first.Signatures[0] != second.Signatures[0] {
		t.Errorf("the same inputs produced two different bundles")
	}
}

// --------------------------------------------------------------------------
// Round trip
// --------------------------------------------------------------------------

func TestCreatedBundleVerifies(t *testing.T) {
	resolution := bundleVectorResolution(t)
	bundle, err := CreateBundle(resolution, bundleVectorOptions(t, "test-signing.key.pem"))
	if err != nil {
		t.Fatalf("CreateBundle: %v", err)
	}
	encoded, err := MarshalBundle(bundle)
	if err != nil {
		t.Fatalf("MarshalBundle: %v", err)
	}
	now, _ := time.Parse(time.RFC3339, bundleVectorCreatedAt)
	result := VerifyBundle(encoded, VerifyBundleOptions{
		Keyring:          bundleVectorKeyring(t),
		Now:              now,
		PolicyResolution: resolution,
	})
	if !result.OK {
		t.Fatalf("a bundle this SDK created did not verify: %s: %s", result.Reason, result.Detail)
	}
	if result.ContentHash != resolution.ContentHash {
		t.Errorf("content hash = %q, want %q", result.ContentHash, resolution.ContentHash)
	}
	if !result.PolicyChecked {
		t.Errorf("check 4 did not run even though a resolution was supplied")
	}
}

func TestCreatedUnsignedBundleIsRefused(t *testing.T) {
	// Bundle spec 3: an unsigned bundle is well formed and is not evidence.
	bundle, err := CreateBundle(bundleVectorResolution(t), bundleVectorOptions(t, ""))
	if err != nil {
		t.Fatalf("CreateBundle: %v", err)
	}
	encoded, err := MarshalBundle(bundle)
	if err != nil {
		t.Fatalf("MarshalBundle: %v", err)
	}
	result := VerifyBundle(encoded, VerifyBundleOptions{Keyring: bundleVectorKeyring(t)})
	if result.OK || result.Reason != BundleReasonSignatureMismatch {
		t.Errorf("an unsigned bundle verified as %+v, want %s", result, BundleReasonSignatureMismatch)
	}
}

// --------------------------------------------------------------------------
// The statement (bundle spec 4)
// --------------------------------------------------------------------------

func TestBuildBundleStatementNamesTheSpecConstants(t *testing.T) {
	statement, err := BuildBundleStatement(bundleVectorResolution(t), bundleVectorOptions(t, ""))
	if err != nil {
		t.Fatalf("BuildBundleStatement: %v", err)
	}
	if statement.Type != BundleStatementType {
		t.Errorf("_type = %q, want %q", statement.Type, BundleStatementType)
	}
	if statement.PredicateType != BundlePredicateType {
		t.Errorf("predicateType = %q, want %q", statement.PredicateType, BundlePredicateType)
	}
	if statement.Predicate.BundleVersion != BundleVersion {
		t.Errorf("bundle_version = %q, want %q", statement.Predicate.BundleVersion, BundleVersion)
	}
	if len(statement.Subject) != 1 {
		t.Errorf("a bundle attests %d subjects, want exactly 1", len(statement.Subject))
	}
}

func TestBuildBundleStatementIsInternallyConsistent(t *testing.T) {
	statement, err := BuildBundleStatement(bundleVectorResolution(t), bundleVectorOptions(t, ""))
	if err != nil {
		t.Fatalf("BuildBundleStatement: %v", err)
	}
	canonical, err := canonicalJSONValue(statement.Predicate.Resolved)
	if err != nil {
		t.Fatalf("canonicalize predicate.resolved: %v", err)
	}
	sum := sha256.Sum256([]byte(canonical))
	recomputed := contentHashPrefix + hex.EncodeToString(sum[:])
	if statement.Predicate.Policy.ContentHash != recomputed {
		t.Errorf("policy.content_hash = %q, but predicate.resolved hashes to %q",
			statement.Predicate.Policy.ContentHash, recomputed)
	}
	want := strings.TrimPrefix(recomputed, contentHashPrefix)
	if statement.Subject[0].Digest.SHA256 != want {
		t.Errorf("subject digest = %q, want %q", statement.Subject[0].Digest.SHA256, want)
	}
}

func TestBuildBundleStatementRecordsTheChainRootFirst(t *testing.T) {
	resolution := bundleVectorResolution(t)
	statement, err := BuildBundleStatement(resolution, bundleVectorOptions(t, ""))
	if err != nil {
		t.Fatalf("BuildBundleStatement: %v", err)
	}
	wantSources := []string{"builtin:strict", "library/healthcare/hipaa-base.yaml"}
	for i, link := range statement.Predicate.Chain {
		if link.Source != wantSources[i] {
			t.Errorf("chain[%d].source = %q, want %q", i, link.Source, wantSources[i])
		}
		if link.ContentHash != resolution.Chain[i].ContentHash {
			t.Errorf("chain[%d].content_hash does not match the resolution", i)
		}
	}
}

func TestBuildBundleStatementLeavesPortableAndOutsideSourcesAlone(t *testing.T) {
	resolution := bundleVectorResolution(t)
	options := bundleVectorOptions(t, "")
	options.BaseDir = filepath.Join(fixtureRepoRoot(t), "crates")
	statement, err := BuildBundleStatement(resolution, options)
	if err != nil {
		t.Fatalf("BuildBundleStatement: %v", err)
	}
	// `builtin:strict` is portable already; the leaf is not beneath `crates/`.
	if statement.Predicate.Chain[0].Source != "builtin:strict" {
		t.Errorf("a builtin source was rewritten: %q", statement.Predicate.Chain[0].Source)
	}
	if statement.Predicate.Chain[1].Source != resolution.Chain[1].Source {
		t.Errorf("a source outside BaseDir was rewritten: %q", statement.Predicate.Chain[1].Source)
	}
}

func TestBuildBundleStatementOmitsUnattemptedVerification(t *testing.T) {
	statement, err := BuildBundleStatement(bundleVectorResolution(t), bundleVectorOptions(t, ""))
	if err != nil {
		t.Fatalf("BuildBundleStatement: %v", err)
	}
	// Recording `verified: false` would assert a check that never ran
	// (bundle spec 4.5).
	if statement.Predicate.SignatureVerification != nil {
		t.Errorf("signature_verification was recorded without a verification")
	}
	payload, err := BundleStatementBytes(statement)
	if err != nil {
		t.Fatalf("BundleStatementBytes: %v", err)
	}
	if strings.Contains(string(payload), "signature_verification") {
		t.Errorf("the payload carries signature_verification for a bundler that verified nothing")
	}
}

func TestBuildBundleStatementFallsBackToTheLeafFileName(t *testing.T) {
	resolution := bundleVectorResolution(t)
	unnamed := *resolution.Spec
	unnamed.Name = ""
	statement, err := BuildBundleStatement(
		&Resolution{Spec: &unnamed, ContentHash: resolution.ContentHash, Chain: resolution.Chain},
		bundleVectorOptions(t, ""),
	)
	if err != nil {
		t.Fatalf("BuildBundleStatement: %v", err)
	}
	if statement.Subject[0].Name != "hipaa-base.yaml" {
		t.Errorf("subject name = %q, want the leaf file name", statement.Subject[0].Name)
	}
	if statement.Predicate.Policy.Name != "" {
		t.Errorf("policy.name = %q, want it absent", statement.Predicate.Policy.Name)
	}
}

func TestBuildBundleStatementHonoursAnExplicitSubjectName(t *testing.T) {
	options := bundleVectorOptions(t, "")
	options.SubjectName = "release-2026-09"
	statement, err := BuildBundleStatement(bundleVectorResolution(t), options)
	if err != nil {
		t.Fatalf("BuildBundleStatement: %v", err)
	}
	if statement.Subject[0].Name != "release-2026-09" {
		t.Errorf("subject name = %q, want the override", statement.Subject[0].Name)
	}
}

func TestBuildBundleStatementWritesMillisecondTimestamps(t *testing.T) {
	options := bundleVectorOptions(t, "")
	options.CreatedAt = time.Date(2026, 9, 15, 12, 0, 0, 500_000_000, time.UTC)
	statement, err := BuildBundleStatement(bundleVectorResolution(t), options)
	if err != nil {
		t.Fatalf("BuildBundleStatement: %v", err)
	}
	if statement.Predicate.CreatedAt != "2026-09-15T12:00:00.500Z" {
		t.Errorf("created_at = %q, want millisecond precision with a Z suffix",
			statement.Predicate.CreatedAt)
	}
}

func TestBuildBundleStatementDefaultsTheResolverToThisSDK(t *testing.T) {
	statement, err := BuildBundleStatement(bundleVectorResolution(t), CreateBundleOptions{})
	if err != nil {
		t.Fatalf("BuildBundleStatement: %v", err)
	}
	if statement.Predicate.Resolver != (BundleResolver{Tool: SDKName, Version: Version}) {
		t.Errorf("resolver = %+v, want this SDK's identity", statement.Predicate.Resolver)
	}
	if BundleResolverTool != "h2h" {
		t.Errorf("BundleResolverTool = %q, want the reference CLI's name", BundleResolverTool)
	}
}

func TestBuildBundleStatementRefusesAnUnresolvedDocument(t *testing.T) {
	spec, _, err := loadSpecFile(filepath.Join(fixtureRepoRoot(t), bundleVectorPolicy))
	if err != nil {
		t.Fatalf("load the policy: %v", err)
	}
	if _, err := BuildBundleStatement(&Resolution{Spec: spec}, CreateBundleOptions{}); err == nil {
		t.Errorf("a document that still declares extends was bundled")
	}
}

func TestCreateBundleRefusesANilResolution(t *testing.T) {
	if _, err := CreateBundle(nil, CreateBundleOptions{}); err == nil {
		t.Errorf("a nil resolution was bundled")
	}
}

func TestCreateBundleRefusesAKeyThatIsNotEd25519(t *testing.T) {
	options := bundleVectorOptions(t, "")
	options.PrivateKeyPEM = []byte("not a pem")
	if _, err := CreateBundle(bundleVectorResolution(t), options); err == nil {
		t.Errorf("a bundle was signed with unreadable key material")
	}
}

func TestBundleStatementBytesIsWhatThePayloadCarries(t *testing.T) {
	resolution := bundleVectorResolution(t)
	options := bundleVectorOptions(t, "")
	statement, err := BuildBundleStatement(resolution, options)
	if err != nil {
		t.Fatalf("BuildBundleStatement: %v", err)
	}
	payload, err := BundleStatementBytes(statement)
	if err != nil {
		t.Fatalf("BundleStatementBytes: %v", err)
	}
	bundle, err := CreateBundle(resolution, options)
	if err != nil {
		t.Fatalf("CreateBundle: %v", err)
	}
	if base64.StdEncoding.EncodeToString(payload) != bundle.Payload {
		t.Errorf("the statement bytes are not the envelope's payload")
	}

	// The payload must decode as the statement it was built from.
	var round BundleStatement
	if err := json.Unmarshal(payload, &round); err != nil {
		t.Fatalf("the payload is not a statement: %v", err)
	}
	if round.Predicate.Policy.ContentHash != statement.Predicate.Policy.ContentHash {
		t.Errorf("the payload does not round trip to the statement")
	}
}
