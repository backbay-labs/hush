package hushspec

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// The normative policy-signing vectors (spec/hushspec-signing.md section 9,
// fixtures/signing/). An implementation conforms as a verifier exactly when
// every case here returns the expected outcome, so this runner is the Go
// SDK's conformance statement for signing.

// signingVectorsVersion is the `hushspec_signing_vectors` manifest version
// this runner understands.
const signingVectorsVersion = "0.1.0"

// signingVectorCaseCount is the number of cases the specification's table
// enumerates. Pinning it means a vector added upstream cannot be silently
// skipped by a runner that only iterates what it finds.
const signingVectorCaseCount = 18

// signingReasonCodes is the closed set from spec section 6.4. A vector that
// expects a code outside it is a manifest this SDK does not understand, which
// fails rather than passes vacuously.
var signingReasonCodes = map[string]bool{
	ReasonMalformedEnvelope:        true,
	ReasonUnsupportedFormatVersion: true,
	ReasonUnsupportedAlgorithm:     true,
	ReasonUnknownKeyID:             true,
	ReasonKeyRevoked:               true,
	ReasonKeyRetired:               true,
	ReasonSignedAtInFuture:         true,
	ReasonExpired:                  true,
	ReasonSignatureMismatch:        true,
	ReasonContentHashMismatch:      true,
	ReasonPolicyVersionRollback:    true,
}

type signingVectorFile struct {
	Version     string                `yaml:"hushspec_signing_vectors"`
	Description string                `yaml:"description"`
	Defaults    signingVectorDefaults `yaml:"defaults"`
	Cases       []signingVectorCase   `yaml:"cases"`
}

type signingVectorDefaults struct {
	Keyring             string `yaml:"keyring"`
	Now                 string `yaml:"now"`
	MaxClockSkewSeconds *int   `yaml:"max_clock_skew_seconds"`
}

type signingVectorCase struct {
	Name                string             `yaml:"name"`
	Policy              string             `yaml:"policy"`
	Signature           string             `yaml:"signature"`
	Keyring             string             `yaml:"keyring"`
	Now                 string             `yaml:"now"`
	LastSeenVersion     *int64             `yaml:"last_seen_version"`
	MaxClockSkewSeconds *int               `yaml:"max_clock_skew_seconds"`
	Expect              signingExpectation `yaml:"expect"`
	Note                string             `yaml:"note"`
}

// signingExpectation is either the scalar `valid` or the mapping
// `{invalid: <reason code>}`.
type signingExpectation struct {
	Valid  bool
	Reason string
}

func (e *signingExpectation) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var outcome string
		if err := node.Decode(&outcome); err != nil {
			return err
		}
		if outcome != "valid" {
			return fmt.Errorf("unknown expected outcome %q", outcome)
		}
		e.Valid = true
		return nil
	}
	var invalid struct {
		Invalid string `yaml:"invalid"`
	}
	if err := node.Decode(&invalid); err != nil {
		return err
	}
	if invalid.Invalid == "" {
		return errors.New("an invalid expectation must name a reason code")
	}
	e.Reason = invalid.Invalid
	return nil
}

func signingFixtureDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(fixtureRepoRoot(t), "fixtures", "signing")
}

// TestSigningVectors runs every normative verification vector: resolve the
// policy, verify the detached envelope under the case's keyring, clock and
// last-seen version, and require the expected outcome or the exact reason
// code.
func TestSigningVectors(t *testing.T) {
	dir := signingFixtureDir(t)
	data, err := os.ReadFile(filepath.Join(dir, "vectors.yaml"))
	if err != nil {
		t.Fatalf("failed to read the signing vectors: %v", err)
	}

	var vectors signingVectorFile
	if err := yaml.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("failed to decode the signing vectors: %v", err)
	}
	if vectors.Version != signingVectorsVersion {
		t.Fatalf("unsupported hushspec_signing_vectors version %q (this runner understands %q)",
			vectors.Version, signingVectorsVersion)
	}
	if len(vectors.Cases) != signingVectorCaseCount {
		t.Fatalf("expected %d signing vectors, found %d", signingVectorCaseCount, len(vectors.Cases))
	}

	for _, vector := range vectors.Cases {
		t.Run(vector.Name, func(t *testing.T) {
			if !vector.Expect.Valid && !signingReasonCodes[vector.Expect.Reason] {
				t.Fatalf("vector expects reason code %q, which is not in spec section 6.4",
					vector.Expect.Reason)
			}

			spec := parseSigningVectorPolicy(t, filepath.Join(dir, vector.Policy))
			envelopeJSON, err := os.ReadFile(filepath.Join(dir, vector.Signature))
			if err != nil {
				t.Fatalf("failed to read the envelope: %v", err)
			}

			keyringPath := vector.Keyring
			if keyringPath == "" {
				keyringPath = vectors.Defaults.Keyring
			}
			keyringJSON, err := os.ReadFile(filepath.Join(dir, keyringPath))
			if err != nil {
				t.Fatalf("failed to read the keyring: %v", err)
			}
			keyring, err := LoadKeyring(keyringJSON)
			if err != nil {
				t.Fatalf("failed to load the keyring %s: %v", keyringPath, err)
			}

			nowText := vector.Now
			if nowText == "" {
				nowText = vectors.Defaults.Now
			}
			now, err := time.Parse(time.RFC3339, nowText)
			if err != nil {
				t.Fatalf("failed to parse the verifier clock %q: %v", nowText, err)
			}

			skew := DefaultMaxClockSkewSeconds
			if vectors.Defaults.MaxClockSkewSeconds != nil {
				skew = *vectors.Defaults.MaxClockSkewSeconds
			}
			if vector.MaxClockSkewSeconds != nil {
				skew = *vector.MaxClockSkewSeconds
			}

			result := VerifyPolicyBytes(spec, envelopeJSON, VerifyOptions{
				Keyring:             keyring,
				Now:                 now,
				MaxClockSkewSeconds: skew,
				LastSeenVersion:     vector.LastSeenVersion,
			})

			switch {
			case vector.Expect.Valid && !result.OK:
				t.Fatalf("expected the signature to verify, got %s: %s", result.Reason, result.Detail)
			case !vector.Expect.Valid && result.OK:
				t.Fatalf("expected %s, but the signature verified", vector.Expect.Reason)
			case !vector.Expect.Valid && result.Reason != vector.Expect.Reason:
				t.Fatalf("expected reason %s, got %s: %s",
					vector.Expect.Reason, result.Reason, result.Detail)
			}
			if result.OK && result.Reason != "" {
				t.Fatalf("a valid outcome must carry no reason code, got %q", result.Reason)
			}
		})
	}
}

// TestEnvelopeRejectsAnEmptyOptionalClaim covers a claim that is present and
// empty. The schema gives `policy_name` and `signer` a minimum length of one,
// so an envelope carrying one cannot be read past check 1 of spec section 6.2
// -- on either path into the model, the `.sig` parser or the typed member a
// log entry's signature arrives as.
func TestEnvelopeRejectsAnEmptyOptionalClaim(t *testing.T) {
	dir := signingFixtureDir(t)
	data, err := os.ReadFile(filepath.Join(dir, "policies", "basic.sig"))
	if err != nil {
		t.Fatalf("cannot read the vector: %v", err)
	}
	keyringJSON, err := os.ReadFile(filepath.Join(dir, "keys", "keyring.json"))
	if err != nil {
		t.Fatalf("cannot read the keyring: %v", err)
	}
	keyring, err := LoadKeyring(keyringJSON)
	if err != nil {
		t.Fatalf("cannot load the keyring: %v", err)
	}
	now, err := time.Parse(time.RFC3339, "2026-09-15T12:00:00Z")
	if err != nil {
		t.Fatalf("cannot parse the verifier clock: %v", err)
	}

	for _, member := range []string{"policy_name", "signer"} {
		t.Run(member, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(data, &document); err != nil {
				t.Fatalf("cannot read the envelope: %v", err)
			}
			document[member] = ""
			edited, err := json.Marshal(document)
			if err != nil {
				t.Fatalf("cannot re-encode the envelope: %v", err)
			}

			if envelope, err := ParseEnvelope(edited); err == nil {
				t.Fatalf("an empty %s must be refused, got %+v", member, envelope)
			} else if reason, _ := ReasonFromError(err); reason != ReasonMalformedEnvelope {
				t.Errorf("expected %s, got %q: %v", ReasonMalformedEnvelope, reason, err)
			}

			var typed Envelope
			if err := json.Unmarshal(edited, &typed); err != nil {
				t.Fatalf("cannot read the envelope: %v", err)
			}
			result := VerifyContentHash(&typed, typed.ContentHash, VerifyOptions{
				Keyring: keyring,
				Now:     now,
			})
			if result.Reason != ReasonMalformedEnvelope {
				t.Errorf("expected %s, got %q: %s",
					ReasonMalformedEnvelope, result.Reason, result.Detail)
			}
		})
	}
}

// parseSigningVectorPolicy loads a vector's policy the way a verifier sees
// it: as parsed but unresolved, leaving the resolution that the content hash
// depends on to the verifier itself.
func parseSigningVectorPolicy(t *testing.T, path string) *HushSpec {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read the policy: %v", err)
	}
	spec, err := Parse(string(data))
	if err != nil {
		t.Fatalf("failed to parse the policy %s: %v", path, err)
	}
	return spec
}

// TestSigningVectorsReproduceReferenceSignatures re-signs two vector policies
// with the published test key and requires the reference envelopes back, byte
// for byte. Verifying the vectors only proves the Go verifier agrees with the
// reference signer; this proves the Go *signer* does, which is what conformance
// as a signer means (spec section 2) and what makes a signature made in Go
// verifiable by the other three SDKs.
func TestSigningVectorsReproduceReferenceSignatures(t *testing.T) {
	dir := signingFixtureDir(t)
	privateKeyPEM, err := os.ReadFile(filepath.Join(dir, "keys", "test-signing.key.pem"))
	if err != nil {
		t.Fatalf("failed to read the test signing key: %v", err)
	}
	signedAt := time.Date(2026, 9, 15, 9, 0, 0, 0, time.UTC)

	cases := []struct {
		policy string
		sig    string
		opts   SignOptions
	}{
		// basic.sig carries every optional claim the signer derives from the
		// policy: policy_name, policy_version and an explicit signer.
		{"basic.yaml", "basic.sig", SignOptions{SignedAt: &signedAt, Signer: "security@example.com"}},
		// extends-child.sig covers the resolved document, and its policy has
		// no metadata.policy_version, so the signer must omit that claim
		// rather than invent one.
		{"extends-child.yaml", "extends-child.sig", SignOptions{SignedAt: &signedAt}},
	}

	for _, testCase := range cases {
		t.Run(testCase.policy, func(t *testing.T) {
			spec := parseSigningVectorPolicy(t, filepath.Join(dir, "policies", testCase.policy))
			envelope, err := SignPolicy(spec, privateKeyPEM, testCase.opts)
			if err != nil {
				t.Fatalf("SignPolicy failed: %v", err)
			}

			reference := readEnvelopeFixture(t, filepath.Join(dir, "policies", testCase.sig))
			produced, err := MarshalEnvelope(envelope)
			if err != nil {
				t.Fatalf("MarshalEnvelope failed: %v", err)
			}
			expected, err := MarshalEnvelope(reference)
			if err != nil {
				t.Fatalf("MarshalEnvelope failed for the reference envelope: %v", err)
			}
			if string(produced) != string(expected) {
				t.Fatalf("produced envelope does not match the reference\n  expected %s\n  actual   %s",
					expected, produced)
			}
		})
	}
}

func readEnvelopeFixture(t *testing.T, path string) *Envelope {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read the envelope: %v", err)
	}
	envelope, err := ParseEnvelope(data)
	if err != nil {
		t.Fatalf("failed to parse the envelope %s: %v", path, err)
	}
	return envelope
}

// TestSignVerifyRoundTrip signs with a freshly generated key and verifies
// with a keyring built from its public half, then walks the ways that round
// trip is supposed to break.
func TestSignVerifyRoundTrip(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate a key: %v", err)
	}
	privateKeyPEM, err := MarshalPrivateKeyPEM(private)
	if err != nil {
		t.Fatalf("failed to encode the private key: %v", err)
	}
	publicKeyPEM, err := MarshalPublicKeyPEM(public)
	if err != nil {
		t.Fatalf("failed to encode the public key: %v", err)
	}
	keyring, err := KeyringFromPublicKey(publicKeyPEM, "round trip")
	if err != nil {
		t.Fatalf("failed to build a keyring: %v", err)
	}

	spec := parseSigningVectorPolicy(t,
		filepath.Join(signingFixtureDir(t), "policies", "basic.yaml"))
	signedAt := time.Date(2026, 9, 15, 9, 0, 0, 0, time.UTC)
	expiresAt := signedAt.Add(24 * time.Hour)
	now := signedAt.Add(time.Hour)

	envelope, err := SignPolicy(spec, privateKeyPEM, SignOptions{
		SignedAt:  &signedAt,
		ExpiresAt: &expiresAt,
		Signer:    "connor@backbay.io",
	})
	if err != nil {
		t.Fatalf("SignPolicy failed: %v", err)
	}

	keyID, err := KeyIDFromPublicKey(publicKeyPEM)
	if err != nil {
		t.Fatalf("KeyIDFromPublicKey failed: %v", err)
	}
	if envelope.KeyID != keyID {
		t.Fatalf("envelope key_id %s does not match the key id of the signing key %s",
			envelope.KeyID, keyID)
	}
	if stringValue(envelope.PolicyName) != "signed-basic" {
		t.Fatalf("expected policy_name signed-basic, got %q", stringValue(envelope.PolicyName))
	}
	if envelope.PolicyVersion == nil || *envelope.PolicyVersion != 4 {
		t.Fatalf("expected policy_version 4 copied from the policy, got %v", envelope.PolicyVersion)
	}
	if envelope.SignedAt != "2026-09-15T09:00:00.000Z" {
		t.Fatalf("unexpected signed_at %q", envelope.SignedAt)
	}
	if stringValue(envelope.ExpiresAt) != "2026-09-16T09:00:00.000Z" {
		t.Fatalf("unexpected expires_at %q", stringValue(envelope.ExpiresAt))
	}

	options := VerifyOptions{Keyring: keyring, Now: now}
	if result := VerifyPolicy(spec, envelope, options); !result.OK {
		t.Fatalf("expected the round trip to verify, got %s: %s", result.Reason, result.Detail)
	}

	// A bare public key is a one-key keyring with the id recomputed from it.
	if result := VerifyPolicy(spec, envelope, VerifyOptions{PublicKeyPEM: publicKeyPEM, Now: now}); !result.OK {
		t.Fatalf("expected the single-key form to verify, got %s: %s", result.Reason, result.Detail)
	}

	// The verifier hands back the document it hashed, which is what a
	// verify-on-load caller must evaluate (spec section 10).
	result := VerifyPolicy(spec, envelope, options)
	if result.Resolved == nil {
		t.Fatal("a valid result must carry the resolved document it hashed")
	}
	if result.ContentHash != envelope.ContentHash {
		t.Fatalf("result content hash %s does not match the envelope %s",
			result.ContentHash, envelope.ContentHash)
	}

	// The envelope survives its own wire form.
	wire, err := MarshalEnvelope(envelope)
	if err != nil {
		t.Fatalf("MarshalEnvelope failed: %v", err)
	}
	reparsed, err := ParseEnvelope(wire)
	if err != nil {
		t.Fatalf("ParseEnvelope failed on the produced wire form: %v", err)
	}
	if result := VerifyPolicy(spec, reparsed, options); !result.OK {
		t.Fatalf("expected the reparsed envelope to verify, got %s: %s", result.Reason, result.Detail)
	}

	t.Run("no trust anchor", func(t *testing.T) {
		if result := VerifyPolicy(spec, envelope, VerifyOptions{Now: now}); result.Reason != ReasonUnknownKeyID {
			t.Fatalf("expected %s with no keyring, got %q", ReasonUnknownKeyID, result.Reason)
		}
	})

	t.Run("another key is never tried", func(t *testing.T) {
		otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate a key: %v", err)
		}
		otherPEM, err := MarshalPublicKeyPEM(otherPublic)
		if err != nil {
			t.Fatalf("failed to encode the public key: %v", err)
		}
		otherKeyring, err := KeyringFromPublicKey(otherPEM, "someone else")
		if err != nil {
			t.Fatalf("failed to build a keyring: %v", err)
		}
		result := VerifyPolicy(spec, envelope, VerifyOptions{Keyring: otherKeyring, Now: now})
		if result.Reason != ReasonUnknownKeyID {
			t.Fatalf("expected %s, got %q: %s", ReasonUnknownKeyID, result.Reason, result.Detail)
		}
	})

	t.Run("edited claim", func(t *testing.T) {
		edited := *envelope
		attacker := "attacker@example.com"
		edited.Signer = &attacker
		result := VerifyPolicy(spec, &edited, options)
		if result.Reason != ReasonSignatureMismatch {
			t.Fatalf("expected %s, got %q: %s", ReasonSignatureMismatch, result.Reason, result.Detail)
		}
	})

	t.Run("changed policy", func(t *testing.T) {
		tampered := parseSigningVectorPolicy(t,
			filepath.Join(signingFixtureDir(t), "policies", "tampered.yaml"))
		result := VerifyPolicy(tampered, envelope, options)
		if result.Reason != ReasonContentHashMismatch {
			t.Fatalf("expected %s, got %q: %s", ReasonContentHashMismatch, result.Reason, result.Detail)
		}
	})

	t.Run("expiry is exclusive of its own instant", func(t *testing.T) {
		atExpiry := VerifyOptions{Keyring: keyring, Now: expiresAt}
		if result := VerifyPolicy(spec, envelope, atExpiry); result.Reason != ReasonExpired {
			t.Fatalf("expected %s at the expiry instant, got %q", ReasonExpired, result.Reason)
		}
		justBefore := VerifyOptions{Keyring: keyring, Now: expiresAt.Add(-time.Millisecond)}
		if result := VerifyPolicy(spec, envelope, justBefore); !result.OK {
			t.Fatalf("expected validity one millisecond before expiry, got %s", result.Reason)
		}
	})

	t.Run("clock skew", func(t *testing.T) {
		// Default tolerance absorbs a signer five minutes fast, and no more.
		within := VerifyOptions{Keyring: keyring, Now: signedAt.Add(-DefaultMaxClockSkewSeconds * time.Second)}
		if result := VerifyPolicy(spec, envelope, within); !result.OK {
			t.Fatalf("expected the default skew to absorb the offset, got %s", result.Reason)
		}
		beyond := VerifyOptions{Keyring: keyring, Now: signedAt.Add(-DefaultMaxClockSkewSeconds*time.Second - time.Millisecond)}
		if result := VerifyPolicy(spec, envelope, beyond); result.Reason != ReasonSignedAtInFuture {
			t.Fatalf("expected %s beyond the default skew, got %q", ReasonSignedAtInFuture, result.Reason)
		}
		// A negative value asks for no tolerance at all.
		strict := VerifyOptions{Keyring: keyring, Now: signedAt.Add(-time.Millisecond), MaxClockSkewSeconds: -1}
		if result := VerifyPolicy(spec, envelope, strict); result.Reason != ReasonSignedAtInFuture {
			t.Fatalf("expected %s with no tolerance, got %q", ReasonSignedAtInFuture, result.Reason)
		}
	})

	t.Run("rollback", func(t *testing.T) {
		older := int64(5)
		rolled := VerifyOptions{Keyring: keyring, Now: now, LastSeenVersion: &older}
		if result := VerifyPolicy(spec, envelope, rolled); result.Reason != ReasonPolicyVersionRollback {
			t.Fatalf("expected %s, got %q", ReasonPolicyVersionRollback, result.Reason)
		}
		same := int64(4)
		accepted := VerifyOptions{Keyring: keyring, Now: now, LastSeenVersion: &same}
		if result := VerifyPolicy(spec, envelope, accepted); !result.OK {
			t.Fatalf("re-signing the same version is not a rollback, got %s", result.Reason)
		}
	})
}

// TestSigningIsDeterministic pins the property the vectors depend on: Ed25519
// contributes no randomness and the signing input is canonical, so the same
// inputs always produce the same envelope bytes.
func TestSigningIsDeterministic(t *testing.T) {
	dir := signingFixtureDir(t)
	privateKeyPEM, err := os.ReadFile(filepath.Join(dir, "keys", "test-signing.key.pem"))
	if err != nil {
		t.Fatalf("failed to read the test signing key: %v", err)
	}
	spec := parseSigningVectorPolicy(t, filepath.Join(dir, "policies", "basic.yaml"))
	signedAt := time.Date(2026, 9, 15, 9, 0, 0, 0, time.UTC)
	opts := SignOptions{SignedAt: &signedAt, Signer: "security@example.com"}

	first, err := SignPolicy(spec, privateKeyPEM, opts)
	if err != nil {
		t.Fatalf("SignPolicy failed: %v", err)
	}
	firstWire, err := MarshalEnvelope(first)
	if err != nil {
		t.Fatalf("MarshalEnvelope failed: %v", err)
	}

	for i := 0; i < 4; i++ {
		again, err := SignPolicy(spec, privateKeyPEM, opts)
		if err != nil {
			t.Fatalf("SignPolicy failed on attempt %d: %v", i, err)
		}
		againWire, err := MarshalEnvelope(again)
		if err != nil {
			t.Fatalf("MarshalEnvelope failed on attempt %d: %v", i, err)
		}
		if string(againWire) != string(firstWire) {
			t.Fatalf("signing is not deterministic\n  first %s\n  again %s", firstWire, againWire)
		}
	}

	// A reformatted policy is the same policy, so it is the same envelope.
	reformatted := parseSigningVectorPolicy(t, filepath.Join(dir, "policies", "reformatted.yaml"))
	sameMeaning, err := SignPolicy(reformatted, privateKeyPEM, opts)
	if err != nil {
		t.Fatalf("SignPolicy failed for the reformatted policy: %v", err)
	}
	sameWire, err := MarshalEnvelope(sameMeaning)
	if err != nil {
		t.Fatalf("MarshalEnvelope failed: %v", err)
	}
	if string(sameWire) != string(firstWire) {
		t.Fatalf("reformatting the policy changed the envelope\n  %s\n  %s", firstWire, sameWire)
	}
}

// TestProducedEnvelopeMatchesSignatureSchema validates a produced envelope
// against the published signature schema: every required member present, no
// member the schema does not define, and every `const` and `pattern`
// satisfied. Conformance as a signer starts here (spec section 2).
func TestProducedEnvelopeMatchesSignatureSchema(t *testing.T) {
	schema := loadSignatureSchema(t)
	dir := signingFixtureDir(t)
	privateKeyPEM, err := os.ReadFile(filepath.Join(dir, "keys", "test-signing.key.pem"))
	if err != nil {
		t.Fatalf("failed to read the test signing key: %v", err)
	}
	signedAt := time.Date(2026, 9, 15, 9, 0, 0, 0, time.UTC)
	expiresAt := signedAt.Add(30 * 24 * time.Hour)

	cases := []struct {
		name   string
		policy string
		opts   SignOptions
	}{
		// Minimal: only the members a signer cannot omit, plus the claims
		// copied from the policy.
		{"minimal", "extends-child.yaml", SignOptions{SignedAt: &signedAt}},
		// Maximal: every optional member populated.
		{"every member", "basic.yaml", SignOptions{
			SignedAt:  &signedAt,
			ExpiresAt: &expiresAt,
			Signer:    "security@example.com",
		}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			spec := parseSigningVectorPolicy(t, filepath.Join(dir, "policies", testCase.policy))
			envelope, err := SignPolicy(spec, privateKeyPEM, testCase.opts)
			if err != nil {
				t.Fatalf("SignPolicy failed: %v", err)
			}
			wire, err := MarshalEnvelope(envelope)
			if err != nil {
				t.Fatalf("MarshalEnvelope failed: %v", err)
			}
			var document map[string]any
			if err := json.Unmarshal(wire, &document); err != nil {
				t.Fatalf("the produced envelope is not JSON: %v", err)
			}
			schema.assertValid(t, document)
		})
	}
}

// jsonSchemaShape is the slice of JSON Schema the signature envelope uses:
// required members, a closed property set, and per-property `const`, `pattern`
// and `type`. It is not a general validator -- the SDK ships no schema
// library -- but it covers every constraint the signature schema states.
type jsonSchemaShape struct {
	path       string
	required   []string
	properties map[string]map[string]any
	closed     bool
}

func (s jsonSchemaShape) assertValid(t *testing.T, document map[string]any) {
	t.Helper()
	for _, name := range s.required {
		if _, ok := document[name]; !ok {
			t.Errorf("%s: required member %q is missing", s.path, name)
		}
	}
	for name, value := range document {
		property, ok := s.properties[name]
		if !ok {
			if s.closed {
				t.Errorf("%s: member %q is not defined by the schema", s.path, name)
			}
			continue
		}
		if expected, ok := property["const"]; ok && value != expected {
			t.Errorf("%s: %s is %v, the schema pins it to %v", s.path, name, value, expected)
		}
		if pattern, ok := property["pattern"].(string); ok {
			text, isText := value.(string)
			if !isText {
				t.Errorf("%s: %s is %T, the schema constrains a string", s.path, name, value)
				continue
			}
			if !regexp.MustCompile(pattern).MatchString(text) {
				t.Errorf("%s: %s = %q does not match %s", s.path, name, text, pattern)
			}
		}
		switch property["type"] {
		case "string":
			if _, ok := value.(string); !ok {
				t.Errorf("%s: %s is %T, the schema declares a string", s.path, name, value)
			}
		case "integer":
			number, ok := value.(float64)
			if !ok || number != float64(int64(number)) {
				t.Errorf("%s: %s is %v, the schema declares an integer", s.path, name, value)
			}
		}
	}
}

// loadSignatureSchema reads the published 0.2 signature schema.
func loadSignatureSchema(t *testing.T) jsonSchemaShape {
	t.Helper()
	root := fixtureRepoRoot(t)
	candidates := []string{
		filepath.Join(root, "schemas", "hushspec-signature.v1.schema.json"),
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var document map[string]any
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatalf("failed to parse %s: %v", path, err)
		}
		properties := map[string]map[string]any{}
		raw, _ := document["properties"].(map[string]any)
		for name, node := range raw {
			if property, ok := node.(map[string]any); ok {
				properties[name] = property
			}
		}
		// The 0.1 schema lives at the published path until the 0.2 one is
		// promoted; tell them apart by the version they pin.
		if version, ok := properties["format_version"]; !ok ||
			version["const"] != SignatureFormatVersion {
			continue
		}
		shape := jsonSchemaShape{path: filepath.Base(path), properties: properties}
		if additional, ok := document["additionalProperties"].(bool); ok {
			shape.closed = !additional
		}
		for _, name := range document["required"].([]any) {
			shape.required = append(shape.required, name.(string))
		}
		return shape
	}

	t.Skipf("no %s signature schema found at %v", SignatureFormatVersion, candidates)
	return jsonSchemaShape{}
}
