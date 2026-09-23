package hushspec

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Unit coverage for the parts of signing.go the normative vectors do not
// reach: key material handling, keyring trust rules, and the fail-closed
// edges of envelope parsing.

func testSigningKeyPEM(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(signingFixtureDir(t), "keys", "test-signing.key.pem"))
	if err != nil {
		t.Fatalf("failed to read the test signing key: %v", err)
	}
	return data
}

func testSigningPublicKeyPEM(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(signingFixtureDir(t), "keys", "test-signing.pub.pem"))
	if err != nil {
		t.Fatalf("failed to read the test public key: %v", err)
	}
	return data
}

// TestKeyIDFromPublicKey pins the key identifier of the published test key.
// The id is the hash of the SubjectPublicKeyInfo, not of the raw key bits, so
// it is stable across every implementation that reads the same PEM -- which
// is what lets a keyring name a key at all.
func TestKeyIDFromPublicKey(t *testing.T) {
	const expected = "sha256:1187bb3ca0fd60b25cb90390812fb3a90823466b499e9c29effcc9f3c4ce6142"

	keyID, err := KeyIDFromPublicKey(testSigningPublicKeyPEM(t))
	if err != nil {
		t.Fatalf("KeyIDFromPublicKey failed: %v", err)
	}
	if keyID != expected {
		t.Fatalf("expected key id %s, got %s", expected, keyID)
	}

	// The DO-NOT-USE comment lines above the PEM block must not change it.
	stripped := strings.Join([]string{
		"-----BEGIN PUBLIC KEY-----",
		"MCowBQYDK2VwAyEAoe42nUGYC2vRO56gfvX8YOl50EwsnCsN5tBwtwdULpo=",
		"-----END PUBLIC KEY-----",
		"",
	}, "\n")
	bare, err := KeyIDFromPublicKey([]byte(stripped))
	if err != nil {
		t.Fatalf("KeyIDFromPublicKey failed on the bare PEM: %v", err)
	}
	if bare != expected {
		t.Fatalf("comment headers changed the key id: %s", bare)
	}
}

// TestKeyPEMRoundTrip checks that the key encodings this SDK writes are the
// ones it reads, and that everything else is refused.
func TestKeyPEMRoundTrip(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate a key: %v", err)
	}
	privatePEM, err := MarshalPrivateKeyPEM(private)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyPEM failed: %v", err)
	}
	publicPEM, err := MarshalPublicKeyPEM(public)
	if err != nil {
		t.Fatalf("MarshalPublicKeyPEM failed: %v", err)
	}

	parsedPrivate, err := ParsePrivateKeyPEM(privatePEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM failed: %v", err)
	}
	if !parsedPrivate.Equal(private) {
		t.Fatal("the private key did not survive the PEM round trip")
	}
	parsedPublic, err := ParsePublicKeyPEM(publicPEM)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM failed: %v", err)
	}
	if !parsedPublic.Equal(public) {
		t.Fatal("the public key did not survive the PEM round trip")
	}

	t.Run("rejects the wrong block type", func(t *testing.T) {
		if _, err := ParsePublicKeyPEM(privatePEM); err == nil {
			t.Fatal("expected a private key to be refused where a public key is required")
		}
		if _, err := ParsePrivateKeyPEM(publicPEM); err == nil {
			t.Fatal("expected a public key to be refused where a private key is required")
		}
	})

	t.Run("rejects an ambiguous file", func(t *testing.T) {
		twoKeys := append(append([]byte{}, publicPEM...), publicPEM...)
		if _, err := ParsePublicKeyPEM(twoKeys); err == nil {
			t.Fatal("expected a file carrying two PEM blocks to be refused")
		}
	})

	t.Run("rejects a non-Ed25519 key", func(t *testing.T) {
		// An RSA SubjectPublicKeyInfo parses as PKIX but is not a key this
		// format can use.
		const rsaPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf
9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==
-----END PUBLIC KEY-----
`
		if _, err := ParsePublicKeyPEM([]byte(rsaPublicKeyPEM)); err == nil {
			t.Fatal("expected an RSA key to be refused")
		}
	})

	t.Run("rejects input that is not PEM", func(t *testing.T) {
		if _, err := ParsePublicKeyPEM([]byte("not a key")); err == nil {
			t.Fatal("expected non-PEM input to be refused")
		}
	})
}

// TestLoadKeyringRejectsUntrustworthyEntries covers the trust rules the
// keyring schema cannot state. Each of these is a keyring a verifier must not
// half-accept, so the whole document is refused rather than the entry.
func TestLoadKeyringRejectsUntrustworthyEntries(t *testing.T) {
	trusted := string(readTestFile(t, filepath.Join(signingFixtureDir(t), "keys", "keyring.json")))
	if _, err := LoadKeyring([]byte(trusted)); err != nil {
		t.Fatalf("the reference keyring must load: %v", err)
	}

	cases := []struct {
		name     string
		document string
		want     string
	}{
		{
			// The declared id names a key the entry does not hold: exactly
			// the substitution recomputing the id is there to catch.
			name: "key_id does not match the key",
			document: strings.Replace(trusted,
				"sha256:1187bb3ca0fd60b25cb90390812fb3a90823466b499e9c29effcc9f3c4ce6142",
				"sha256:"+strings.Repeat("0", 64), 1),
			want: "does not match",
		},
		{
			name:     "unknown keyring version",
			document: strings.Replace(trusted, `"keyring_version": "0.2"`, `"keyring_version": "0.3"`, 1),
			want:     "unsupported keyring_version",
		},
		{
			name:     "unknown algorithm",
			document: strings.Replace(trusted, `"algorithm": "ed25519"`, `"algorithm": "rsa-pss"`, 1),
			want:     "unsupported algorithm",
		},
		{
			name:     "unknown member",
			document: strings.Replace(trusted, `"keys": [`, `"trust_everything": true, "keys": [`, 1),
			want:     "unknown field",
		},
		{
			name:     "no keys",
			document: `{"keyring_version": "0.2", "keys": []}`,
			want:     "at least one key",
		},
		{
			name:     "duplicate member",
			document: strings.Replace(trusted, `"keyring_version": "0.2"`, `"keyring_version": "0.2", "keyring_version": "0.3"`, 1),
			want:     "duplicate member",
		},
		{
			name:     "not a keyring at all",
			document: `[]`,
			want:     "invalid keyring",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := LoadKeyring([]byte(testCase.document))
			if err == nil {
				t.Fatal("expected the keyring to be refused")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("expected an error mentioning %q, got %v", testCase.want, err)
			}
		})
	}

	t.Run("duplicate key_id", func(t *testing.T) {
		var ring map[string]any
		if err := json.Unmarshal([]byte(trusted), &ring); err != nil {
			t.Fatalf("failed to decode the reference keyring: %v", err)
		}
		keys := ring["keys"].([]any)
		ring["keys"] = append(keys, keys[0])
		document, err := json.Marshal(ring)
		if err != nil {
			t.Fatalf("failed to encode the keyring: %v", err)
		}
		if _, err := LoadKeyring(document); err == nil || !strings.Contains(err.Error(), "duplicate key_id") {
			t.Fatalf("expected a duplicate key_id to be refused, got %v", err)
		}
	})
}

// TestVerifyRecomputesKeyIDForHandBuiltKeyrings covers the keyring that never
// went through LoadKeyring. Recomputing the id at verification time is what
// makes "the entry's recomputed id matches" (check 4) true of every keyring,
// however it was built.
func TestVerifyRecomputesKeyIDForHandBuiltKeyrings(t *testing.T) {
	dir := signingFixtureDir(t)
	spec := parseSigningVectorPolicy(t, filepath.Join(dir, "policies", "basic.yaml"))
	envelope := readEnvelopeFixture(t, filepath.Join(dir, "policies", "basic.sig"))
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	// The entry claims the envelope's key id but holds a different key.
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate a key: %v", err)
	}
	otherPEM, err := MarshalPublicKeyPEM(other)
	if err != nil {
		t.Fatalf("failed to encode the public key: %v", err)
	}
	lying := &Keyring{
		Version: KeyringFormatVersion,
		Keys: []TrustedKey{{
			KeyID:        envelope.KeyID,
			Algorithm:    SignatureAlgorithm,
			PublicKeyPEM: string(otherPEM),
		}},
	}

	result := VerifyPolicy(spec, envelope, VerifyOptions{Keyring: lying, Now: now})
	if result.Reason != ReasonUnknownKeyID {
		t.Fatalf("expected %s for an entry whose id does not match its key, got %q: %s",
			ReasonUnknownKeyID, result.Reason, result.Detail)
	}

	// The same keyring holding the real key verifies.
	honest := &Keyring{
		Version: KeyringFormatVersion,
		Keys: []TrustedKey{{
			KeyID:        envelope.KeyID,
			Algorithm:    SignatureAlgorithm,
			PublicKeyPEM: string(testSigningPublicKeyPEM(t)),
		}},
	}
	if result := VerifyPolicy(spec, envelope, VerifyOptions{Keyring: honest, Now: now}); !result.OK {
		t.Fatalf("expected the hand-built keyring to verify, got %s: %s", result.Reason, result.Detail)
	}
}

// TestParseEnvelopeFailsClosed covers the envelope documents a verifier must
// refuse, and the reason code each maps onto.
func TestParseEnvelopeFailsClosed(t *testing.T) {
	trusted := string(readTestFile(t,
		filepath.Join(signingFixtureDir(t), "policies", "basic.sig")))

	cases := []struct {
		name     string
		document string
		reason   string
	}{
		{"unknown member", strings.Replace(trusted,
			`"format_version": "0.2"`, `"format_version": "0.2", "trusted": true`, 1),
			ReasonMalformedEnvelope},
		{"duplicate member", strings.Replace(trusted,
			`"content_hash": "sha256:386fb3d6955b04d671dd2777c6417bf322489c9e820572993923d5f9e1fa563a"`,
			`"content_hash": "sha256:`+strings.Repeat("0", 64)+`", "content_hash": "sha256:386fb3d6955b04d671dd2777c6417bf322489c9e820572993923d5f9e1fa563a"`, 1),
			ReasonMalformedEnvelope},
		{"missing signature", strings.Replace(trusted,
			`"signature": "1k24VahVUzLFtpA530wBXYdf5nG5ywq8yAd4rbSB0c6S1ph3ksZkPp0LDoRz8SEFqFSCB74OV8V0a32m3IfWCw"`,
			`"signer_note": "none"`, 1),
			ReasonMalformedEnvelope},
		{"padded base64 signature", strings.Replace(trusted,
			`"1k24VahVUzLFtpA530wBXYdf5nG5ywq8yAd4rbSB0c6S1ph3ksZkPp0LDoRz8SEFqFSCB74OV8V0a32m3IfWCw"`,
			`"1k24VahVUzLFtpA530wBXYdf5nG5ywq8yAd4rbSB0c6S1ph3ksZkPp0LDoRz8SEFqFSCB74OV8V0a32m3IfWCw=="`, 1),
			ReasonMalformedEnvelope},
		{"bare hex content hash", strings.Replace(trusted,
			`"sha256:386fb3d6955b04d671dd2777c6417bf322489c9e820572993923d5f9e1fa563a"`,
			`"386fb3d6955b04d671dd2777c6417bf322489c9e820572993923d5f9e1fa563a"`, 1),
			ReasonMalformedEnvelope},
		{"second-precision timestamp", strings.Replace(trusted,
			`"2026-09-15T09:00:00.000Z"`, `"2026-09-15T09:00:00Z"`, 1),
			ReasonMalformedEnvelope},
		{"timestamp with an offset", strings.Replace(trusted,
			`"2026-09-15T09:00:00.000Z"`, `"2026-09-15T09:00:00.000+00:00"`, 1),
			ReasonMalformedEnvelope},
		{"impossible date", strings.Replace(trusted,
			`"2026-09-15T09:00:00.000Z"`, `"2026-13-15T09:00:00.000Z"`, 1),
			ReasonMalformedEnvelope},
		{"empty signer", strings.Replace(trusted,
			`"security@example.com"`, `""`, 1),
			ReasonMalformedEnvelope},
		{"negative policy version", strings.Replace(trusted,
			`"policy_version": 4`, `"policy_version": -1`, 1),
			ReasonMalformedEnvelope},
		{"fractional policy version", strings.Replace(trusted,
			`"policy_version": 4`, `"policy_version": 4.5`, 1),
			ReasonMalformedEnvelope},
		{"trailing data", trusted + "{}", ReasonMalformedEnvelope},
		{"not JSON", "hushspec: 0.2.0", ReasonMalformedEnvelope},
		{"future format", strings.Replace(trusted,
			`"format_version": "0.2"`, `"format_version": "0.3"`, 1),
			ReasonUnsupportedFormatVersion},
		{"future algorithm", strings.Replace(trusted,
			`"algorithm": "ed25519"`, `"algorithm": "ml-dsa-65"`, 1),
			ReasonUnsupportedAlgorithm},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.document == trusted {
				t.Fatal("the test case did not alter the envelope")
			}
			_, err := ParseEnvelope([]byte(testCase.document))
			if err == nil {
				t.Fatal("expected the envelope to be refused")
			}
			reason, ok := ReasonFromError(err)
			if !ok {
				t.Fatalf("expected an EnvelopeError carrying a reason code, got %v", err)
			}
			if reason != testCase.reason {
				t.Fatalf("expected reason %s, got %s (%v)", testCase.reason, reason, err)
			}
		})
	}
}

// TestSignPolicyRefusesWhatItCannotSign covers spec section 3: a signer that
// cannot resolve or validate a policy must refuse rather than sign a fragment
// or a document a verifier will reject.
func TestSignPolicyRefusesWhatItCannotSign(t *testing.T) {
	privateKeyPEM := testSigningKeyPEM(t)
	signedAt := time.Date(2026, 9, 15, 9, 0, 0, 0, time.UTC)

	t.Run("unresolvable extends", func(t *testing.T) {
		spec, err := Parse("hushspec: 0.2.0\nname: orphan\nextends: builtin:nonexistent\n")
		if err != nil {
			t.Fatalf("failed to parse the policy: %v", err)
		}
		if _, err := SignPolicy(spec, privateKeyPEM, SignOptions{SignedAt: &signedAt}); err == nil {
			t.Fatal("expected a policy whose base cannot be loaded to be refused")
		}
	})

	t.Run("invalid policy", func(t *testing.T) {
		spec := &HushSpec{HushSpecVersion: "9.0.0", Name: strPtr("from the future")}
		if _, err := SignPolicy(spec, privateKeyPEM, SignOptions{SignedAt: &signedAt}); err == nil {
			t.Fatal("expected an unsupported policy version to be refused")
		}
	})

	t.Run("expiry at or before signing", func(t *testing.T) {
		spec := parseSigningVectorPolicy(t,
			filepath.Join(signingFixtureDir(t), "policies", "basic.yaml"))
		if _, err := SignPolicy(spec, privateKeyPEM, SignOptions{
			SignedAt:  &signedAt,
			ExpiresAt: &signedAt,
		}); err == nil {
			t.Fatal("expected an envelope that expires when it is signed to be refused")
		}
	})

	t.Run("wrong key material", func(t *testing.T) {
		spec := parseSigningVectorPolicy(t,
			filepath.Join(signingFixtureDir(t), "policies", "basic.yaml"))
		if _, err := SignPolicy(spec, testSigningPublicKeyPEM(t), SignOptions{SignedAt: &signedAt}); err == nil {
			t.Fatal("expected a public key to be refused as a signing key")
		}
	})

	t.Run("nil policy", func(t *testing.T) {
		if _, err := SignPolicy(nil, privateKeyPEM, SignOptions{}); err == nil {
			t.Fatal("expected a nil policy to be refused")
		}
	})
}

// TestSigningInputIsTheCanonicalEnvelope pins the exact bytes the signature
// covers (spec section 4.1): canonical JSON, members in UTF-16 code unit
// order, `signature` absent, optional members present only when they carry a
// value.
func TestSigningInputIsTheCanonicalEnvelope(t *testing.T) {
	envelope := readEnvelopeFixture(t,
		filepath.Join(signingFixtureDir(t), "policies", "basic.sig"))

	input, err := envelope.SigningInput()
	if err != nil {
		t.Fatalf("SigningInput failed: %v", err)
	}
	const expected = `{"algorithm":"ed25519",` +
		`"content_hash":"sha256:386fb3d6955b04d671dd2777c6417bf322489c9e820572993923d5f9e1fa563a",` +
		`"format_version":"0.2",` +
		`"key_id":"sha256:1187bb3ca0fd60b25cb90390812fb3a90823466b499e9c29effcc9f3c4ce6142",` +
		`"policy_name":"signed-basic","policy_version":4,` +
		`"signed_at":"2026-09-15T09:00:00.000Z","signer":"security@example.com"}`
	if string(input) != expected {
		t.Fatalf("signing input mismatch\n  expected %s\n  actual   %s", expected, input)
	}

	// The wire form is the same document with the signature added back --
	// sorted into place rather than appended, because the ordering is the
	// canonical one and "signature" falls between "policy_version" and
	// "signed_at".
	wire, err := MarshalEnvelope(envelope)
	if err != nil {
		t.Fatalf("MarshalEnvelope failed: %v", err)
	}
	const expectedWire = `{"algorithm":"ed25519",` +
		`"content_hash":"sha256:386fb3d6955b04d671dd2777c6417bf322489c9e820572993923d5f9e1fa563a",` +
		`"format_version":"0.2",` +
		`"key_id":"sha256:1187bb3ca0fd60b25cb90390812fb3a90823466b499e9c29effcc9f3c4ce6142",` +
		`"policy_name":"signed-basic","policy_version":4,` +
		`"signature":"1k24VahVUzLFtpA530wBXYdf5nG5ywq8yAd4rbSB0c6S1ph3ksZkPp0LDoRz8SEFqFSCB74OV8V0a32m3IfWCw",` +
		`"signed_at":"2026-09-15T09:00:00.000Z","signer":"security@example.com"}`
	if string(wire) != expectedWire {
		t.Fatalf("wire form mismatch\n  expected %s\n  actual   %s", expectedWire, wire)
	}

	// An envelope with no optional claims carries only the required five.
	minimal := readEnvelopeFixture(t,
		filepath.Join(signingFixtureDir(t), "policies", "raw-bytes-hash.sig"))
	minimalInput, err := minimal.SigningInput()
	if err != nil {
		t.Fatalf("SigningInput failed: %v", err)
	}
	for _, absent := range []string{"policy_name", "policy_version", "signer", "expires_at", "signature"} {
		if strings.Contains(string(minimalInput), absent) {
			t.Fatalf("signing input carries %q for an envelope that has none: %s", absent, minimalInput)
		}
	}
}

// TestVerifyPolicyRejectsHandBuiltEnvelopes checks that the ordered checks
// apply to an Envelope a caller constructed in code, not only to one that
// came through ParseEnvelope.
func TestVerifyPolicyRejectsHandBuiltEnvelopes(t *testing.T) {
	dir := signingFixtureDir(t)
	spec := parseSigningVectorPolicy(t, filepath.Join(dir, "policies", "basic.yaml"))
	keyring, err := LoadKeyring(readTestFile(t, filepath.Join(dir, "keys", "keyring.json")))
	if err != nil {
		t.Fatalf("failed to load the keyring: %v", err)
	}
	options := VerifyOptions{Keyring: keyring, Now: time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)}
	valid := readEnvelopeFixture(t, filepath.Join(dir, "policies", "basic.sig"))

	cases := []struct {
		name   string
		mutate func(*Envelope)
		reason string
	}{
		{"unknown format", func(e *Envelope) { e.FormatVersion = "0.1.0" }, ReasonUnsupportedFormatVersion},
		{"unknown algorithm", func(e *Envelope) { e.Algorithm = "rsa-pss" }, ReasonUnsupportedAlgorithm},
		{"malformed key id", func(e *Envelope) { e.KeyID = "deadbeef" }, ReasonMalformedEnvelope},
		{"unknown key", func(e *Envelope) { e.KeyID = contentHashPrefix + strings.Repeat("a", 64) }, ReasonUnknownKeyID},
		{"malformed signature", func(e *Envelope) { e.Signature = "short" }, ReasonMalformedEnvelope},
		{"changed hash", func(e *Envelope) { e.ContentHash = contentHashPrefix + strings.Repeat("b", 64) }, ReasonSignatureMismatch},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			envelope := *valid
			testCase.mutate(&envelope)
			result := VerifyPolicy(spec, &envelope, options)
			if result.OK {
				t.Fatalf("expected %s, but the envelope verified", testCase.reason)
			}
			if result.Reason != testCase.reason {
				t.Fatalf("expected %s, got %s: %s", testCase.reason, result.Reason, result.Detail)
			}
		})
	}

	t.Run("no envelope", func(t *testing.T) {
		if result := VerifyPolicy(spec, nil, options); result.Reason != ReasonMalformedEnvelope {
			t.Fatalf("expected %s for a missing envelope, got %q", ReasonMalformedEnvelope, result.Reason)
		}
	})

	t.Run("no policy", func(t *testing.T) {
		if result := VerifyPolicy(nil, valid, options); result.Reason != ReasonContentHashMismatch {
			t.Fatalf("expected %s for a missing policy, got %q", ReasonContentHashMismatch, result.Reason)
		}
	})
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return data
}
