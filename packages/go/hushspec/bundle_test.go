package hushspec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBundlePAEMatchesTheDSSEDefinition checks the PAE against the DSSE
// specification's own test vector and the prefix bundle spec 3.1 quotes.
func TestBundlePAEMatchesTheDSSEDefinition(t *testing.T) {
	cases := []struct {
		payloadType string
		payload     string
		want        string
	}{
		{"http://example.com/HelloWorld", "hello world", "DSSEv1 29 http://example.com/HelloWorld 11 hello world"},
		// An empty payload still carries its length.
		{"a", "", "DSSEv1 1 a 0 "},
		// Lengths are byte counts, not character counts.
		{"t", "é", "DSSEv1 1 t 2 é"},
		{BundlePayloadType, "{}", "DSSEv1 28 application/vnd.in-toto+json 2 {}"},
	}
	for _, tc := range cases {
		if got := string(BundlePAE(tc.payloadType, []byte(tc.payload))); got != tc.want {
			t.Errorf("PAE(%q, %q) = %q, want %q", tc.payloadType, tc.payload, got, tc.want)
		}
	}
}

func bundleFixturePath(t *testing.T, parts ...string) string {
	t.Helper()
	return filepath.Join(append([]string{fixtureRepoRoot(t), "fixtures"}, parts...)...)
}

func readBundleFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(bundleFixturePath(t, parts...))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	return data
}

// TestVerifyBundleWithASinglePublicKey covers the `--key pub.pem` shape of
// bundle spec 6: one SPKI PEM promoted to a one-key keyring, with its id
// recomputed from the key rather than read from the bundle.
func TestVerifyBundleWithASinglePublicKey(t *testing.T) {
	bundle := readBundleFixture(t, "bundle", "bundles", "valid.bundle.json")
	trusted := readBundleFixture(t, "signing", "keys", "test-signing.pub.pem")
	untrusted := readBundleFixture(t, "signing", "keys", "test-untrusted.pub.pem")
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	if result := VerifyBundle(bundle, VerifyBundleOptions{PublicKeyPEM: trusted, Now: now}); !result.OK {
		t.Fatalf("the published bundle must verify under its own key: %s (%s)",
			result.Reason, result.Detail)
	}
	result := VerifyBundle(bundle, VerifyBundleOptions{PublicKeyPEM: untrusted, Now: now})
	if result.Reason != BundleReasonUnknownKeyID {
		t.Errorf("a key that signed nothing here is unknown_key_id, got %q", result.Reason)
	}
	// No key at all trusts nobody.
	result = VerifyBundle(bundle, VerifyBundleOptions{Now: now})
	if result.Reason != BundleReasonUnknownKeyID {
		t.Errorf("an empty root of trust is unknown_key_id, got %q", result.Reason)
	}
}

// TestVerifyBundleReportsThePredicateClaims checks the claims a caller reads
// off a bundle it accepted.
func TestVerifyBundleReportsThePredicateClaims(t *testing.T) {
	bundle := readBundleFixture(t, "bundle", "bundles", "valid.bundle.json")
	trusted := readBundleFixture(t, "signing", "keys", "test-signing.pub.pem")
	result := VerifyBundle(bundle, VerifyBundleOptions{
		PublicKeyPEM: trusted,
		Now:          time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC),
	})
	if !result.OK {
		t.Fatalf("expected a valid bundle: %s (%s)", result.Reason, result.Detail)
	}
	if result.SubjectName != "hipaa-base" || stringValue(result.PolicyName) != "hipaa-base" {
		t.Errorf("unexpected labels: subject %q, policy %q", result.SubjectName, stringValue(result.PolicyName))
	}
	if !strings.HasPrefix(result.ContentHash, "sha256:") {
		t.Errorf("the content hash keeps its prefix inside the predicate, got %q", result.ContentHash)
	}
	if result.CreatedAt != "2026-09-15T12:00:00.000Z" {
		t.Errorf("unexpected created_at %q", result.CreatedAt)
	}
	if result.ChainLength != 2 {
		t.Errorf("hipaa-base resolves through builtin:strict, expected 2 hops, got %d", result.ChainLength)
	}
	if result.PolicyChecked {
		t.Error("check 4 did not run: no policy was supplied")
	}
	if result.Statement == nil || result.Statement.Predicate.BundleVersion != BundleVersion {
		t.Error("the decoded statement should be returned to the caller")
	}
}

// TestVerifyBundleAgainstABarePolicyDocument covers the Policy option: a
// resolved document with no chain evidence compares by content hash alone,
// because an unknown chain is nothing to disagree with.
func TestVerifyBundleAgainstABarePolicyDocument(t *testing.T) {
	bundle := readBundleFixture(t, "bundle", "bundles", "valid.bundle.json")
	trusted := readBundleFixture(t, "signing", "keys", "test-signing.pub.pem")
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	resolved, err := ResolveFile(filepath.Join(
		fixtureRepoRoot(t), "library", "healthcare", "hipaa-base.yaml"))
	if err != nil {
		t.Fatalf("the library policy must resolve: %v", err)
	}
	result := VerifyBundle(bundle, VerifyBundleOptions{
		PublicKeyPEM: trusted, Now: now, Policy: resolved,
	})
	if !result.OK || !result.PolicyChecked {
		t.Fatalf("expected check 4 to run and pass: %s (%s)", result.Reason, result.Detail)
	}

	other, err := ResolveFile(filepath.Join(
		fixtureRepoRoot(t), "library", "finance", "pci-dss.yaml"))
	if err != nil {
		t.Fatalf("the library policy must resolve: %v", err)
	}
	result = VerifyBundle(bundle, VerifyBundleOptions{
		PublicKeyPEM: trusted, Now: now, Policy: other,
	})
	if result.Reason != BundleReasonPolicyMismatch {
		t.Errorf("a different policy is policy_mismatch, got %q (%s)", result.Reason, result.Detail)
	}
}

// TestVerifyBundleChainLengthIsCompared pins bundle spec 5.3: a policy that
// reaches the same result through a different chain is not the policy the
// bundle attests.
func TestVerifyBundleChainLengthIsCompared(t *testing.T) {
	bundle := readBundleFixture(t, "bundle", "bundles", "valid.bundle.json")
	trusted := readBundleFixture(t, "signing", "keys", "test-signing.pub.pem")
	resolved, err := ResolveFile(filepath.Join(
		fixtureRepoRoot(t), "library", "healthcare", "hipaa-base.yaml"))
	if err != nil {
		t.Fatalf("the library policy must resolve: %v", err)
	}
	// The same document, but presented as a one-hop resolution.
	single, err := NewResolutionFromResolved(resolved, "hipaa-base.yaml")
	if err != nil {
		t.Fatalf("failed to wrap the resolved document: %v", err)
	}
	result := VerifyBundle(bundle, VerifyBundleOptions{
		PublicKeyPEM:     trusted,
		Now:              time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC),
		PolicyResolution: single,
	})
	if result.Reason != BundleReasonPolicyMismatch {
		t.Errorf("a shorter chain is policy_mismatch, got %q (%s)", result.Reason, result.Detail)
	}
	if !strings.Contains(result.Detail, "document(s)") {
		t.Errorf("the detail should name the chain length, got %q", result.Detail)
	}
}

// TestParseBundleRejectsMalformedDocuments covers check 1's envelope half.
func TestParseBundleRejectsMalformedDocuments(t *testing.T) {
	valid := readBundleFixture(t, "bundle", "bundles", "valid.bundle.json")
	var envelope map[string]any
	if err := json.Unmarshal(valid, &envelope); err != nil {
		t.Fatalf("the published bundle is not JSON: %v", err)
	}
	mutate := func(apply func(map[string]any)) []byte {
		copied := map[string]any{}
		for key, value := range envelope {
			copied[key] = value
		}
		apply(copied)
		encoded, err := json.Marshal(copied)
		if err != nil {
			t.Fatalf("failed to re-encode: %v", err)
		}
		return encoded
	}

	cases := []struct {
		name string
		data []byte
	}{
		{"not JSON", []byte("{")},
		{"unknown member", mutate(func(m map[string]any) { m["extra"] = 1 })},
		{"wrong payload type", mutate(func(m map[string]any) { m["payloadType"] = "application/json" })},
		{"absent signatures", mutate(func(m map[string]any) { delete(m, "signatures") })},
		{"payload is not base64", mutate(func(m map[string]any) { m["payload"] = "not base64!" })},
		{"duplicate member", []byte(`{"payloadType":"x","payloadType":"y","payload":"e30=","signatures":[]}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseBundle(tc.data); err == nil {
				t.Fatal("expected a refusal")
			}
			result := VerifyBundle(tc.data, VerifyBundleOptions{})
			if result.Reason != BundleReasonMalformed {
				t.Errorf("expected malformed_bundle, got %q (%s)", result.Reason, result.Detail)
			}
		})
	}
}

// TestVerifyBundleRejectsAStatementThisBuildDoesNotKnow covers the closed-by-
// default rule of bundle spec 1.2: an unknown statement type, predicate type,
// or bundle version is a verification failure, not a warning.
func TestVerifyBundleRejectsAStatementThisBuildDoesNotKnow(t *testing.T) {
	bundle := readBundleFixture(t, "bundle", "bundles", "malformed-predicate-type.bundle.json")
	trusted := readBundleFixture(t, "signing", "keys", "test-signing.pub.pem")
	result := VerifyBundle(bundle, VerifyBundleOptions{
		PublicKeyPEM: trusted,
		Now:          time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC),
	})
	if result.Reason != BundleReasonMalformed {
		t.Errorf("expected malformed_bundle, got %q (%s)", result.Reason, result.Detail)
	}
	// The shape check runs before the signature check, so a good signature
	// over an unknown predicate is still a shape failure.
	if !strings.Contains(result.Detail, "predicateType") {
		t.Errorf("the detail should name the offending member, got %q", result.Detail)
	}
}

// TestBundleErrorCarriesItsReasonCode keeps the parse-time and verify-time
// vocabularies identical: errors.As on a ParseBundle failure yields the same
// code VerifyBundle would have reported.
func TestBundleErrorCarriesItsReasonCode(t *testing.T) {
	_, err := ParseBundle([]byte(`{"payloadType":"nope","payload":"e30=","signatures":[]}`))
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if got := bundleReasonOf(err); got != BundleReasonMalformed {
		t.Errorf("expected malformed_bundle, got %q", got)
	}
	if !strings.Contains(err.Error(), BundleReasonMalformed) {
		t.Errorf("the error text names its reason code, got %q", err.Error())
	}
}
