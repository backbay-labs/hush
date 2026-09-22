package hushspec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Normative receipt vectors (receipt spec 8, conformance item 4).
//
// fixtures/receipts/valid/*.json MUST be accepted by a conformant receipt
// parser and fixtures/receipts/invalid/*.json MUST be rejected; each invalid
// file name says which rule it breaks. fixtures/receipts/signed carries the
// receipt-signing vectors.

func receiptVectorFiles(t *testing.T, parts ...string) []string {
	t.Helper()
	dir := filepath.Join(append([]string{fixtureRepoRoot(t), "fixtures", "receipts"}, parts...)...)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read %s: %v", dir, err)
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}
	if len(files) == 0 {
		t.Fatalf("no vectors found in %s", dir)
	}
	return files
}

func TestValidReceiptVectorsAreAccepted(t *testing.T) {
	files := receiptVectorFiles(t, "valid")
	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("cannot read: %v", err)
			}
			receipt, err := ParseReceipt(data)
			if err != nil {
				t.Fatalf("a valid vector must be accepted: %v", err)
			}
			// Round-tripping a receipt the parser accepted must reproduce the
			// same canonical form, and therefore the same receipt hash
			// (receipt spec 2, conformance item 5).
			first, err := receipt.ReceiptHash()
			if err != nil {
				t.Fatalf("ReceiptHash failed: %v", err)
			}
			reparsed, err := ParseReceipt([]byte(mustCanonical(t, receipt)))
			if err != nil {
				t.Fatalf("the canonical form must re-parse: %v", err)
			}
			second, err := reparsed.ReceiptHash()
			if err != nil {
				t.Fatalf("ReceiptHash failed: %v", err)
			}
			if first != second {
				t.Errorf("receipt hash is not stable across a round trip: %q vs %q", first, second)
			}
		})
	}
	t.Logf("accepted %d valid receipt vectors", len(files))
}

// invalidReceiptVectorReasons names the member each invalid vector breaks
// (receipt spec 8). A vector rejected for the wrong reason is a latent bug --
// an unrelated strictness that happens to mask a rule this SDK does not
// actually enforce -- so the runner pins the field, not just the refusal.
var invalidReceiptVectorReasons = map[string]string{
	"missing-receipt-version.json":         "receipt_version",
	"unsupported-receipt-version.json":     "receipt_version",
	"timestamp-second-precision.json":      "timestamp",
	"timestamp-microsecond-precision.json": "timestamp",
	"bare-hex-content-hash.json":           "content_hash",
	"unknown-hash-algorithm.json":          "content_hash",
	"unknown-field-legacy-version.json":    "hushspec_version",
	"open-enum-outcome.json":               "outcome",
	"open-enum-time-source.json":           "time_source",
	"rule-block-with-prefix.json":          "rule_block",
	"receipt-id-uuid-v4.json":              "receipt_id",
	"missing-enforcement.json":             "enforcement",
	"action-carries-content.json":          "content",
	"policy-version-not-integer.json":      "version",
	"empty-matched-rule.json":              "matched_rule",
}

func TestInvalidReceiptVectorsAreRejected(t *testing.T) {
	files := receiptVectorFiles(t, "invalid")
	for _, path := range files {
		name := filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("cannot read: %v", err)
			}
			receipt, err := ParseReceipt(data)
			if err == nil {
				t.Fatalf("an invalid vector must be rejected, got %+v", receipt)
			}
			want, ok := invalidReceiptVectorReasons[name]
			if !ok {
				t.Fatalf("no expected rejection reason recorded for the vector %q", name)
			}
			if !strings.Contains(err.Error(), want) {
				t.Errorf("expected the rejection to name %q, got: %v", want, err)
			}
		})
	}
	t.Logf("rejected %d invalid receipt vectors", len(files))
}

// TestExplicitNullIsNotAnAbsentMember covers the one distinction the typed
// model cannot make: `"reason": null` and no `reason` at all unmarshal to the
// same receipt, but they are different documents and a log entry's hash covers
// the difference.
func TestExplicitNullIsNotAnAbsentMember(t *testing.T) {
	path := filepath.Join(fixtureRepoRoot(t), "fixtures", "receipts", "valid", "allow-egress.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("cannot read the vector: %v", err)
	}
	document["reason"] = nil
	edited, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("cannot re-encode the vector: %v", err)
	}
	receipt, err := ParseReceipt(edited)
	if err == nil {
		t.Fatalf("an explicit null must be rejected, got %+v", receipt)
	}
	if !strings.Contains(err.Error(), "reason must not be null") {
		t.Errorf("expected the rejection to name the null member, got: %v", err)
	}
}

func mustCanonical(t *testing.T, receipt *DecisionReceipt) string {
	t.Helper()
	canonical, err := receipt.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON failed: %v", err)
	}
	return canonical
}

// --------------------------------------------------------------------------
// Receipt signing
// --------------------------------------------------------------------------

// signedReceiptVectorClock is the instant the signed vectors were made under.
func signedReceiptVectorClock(t *testing.T) time.Time {
	t.Helper()
	instant, err := time.Parse(time.RFC3339, "2026-09-15T12:00:00Z")
	if err != nil {
		t.Fatalf("cannot parse the vector clock: %v", err)
	}
	return instant
}

func TestSignedReceiptVectors(t *testing.T) {
	keyring := testKeyring(t)
	opts := VerifyOptions{Keyring: keyring, Now: signedReceiptVectorClock(t)}

	t.Run("valid", func(t *testing.T) {
		for _, path := range receiptVectorFiles(t, "signed", "valid") {
			t.Run(filepath.Base(path), func(t *testing.T) {
				signed := parseSignedVector(t, path)
				result := VerifyReceipt(signed, opts)
				if !result.OK {
					t.Fatalf("a valid signed receipt must verify, got %s: %s",
						result.Reason, result.Detail)
				}
				// The envelope's claim is the receipt hash, not the receipt.
				hash, err := signed.Receipt.ReceiptHash()
				if err != nil {
					t.Fatalf("ReceiptHash failed: %v", err)
				}
				if signed.Signature.ContentHash != hash {
					t.Errorf("the envelope must name the receipt hash %s, got %s",
						hash, signed.Signature.ContentHash)
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		// Each file name says which check must fail.
		wantReason := map[string]string{
			"tampered-after-signing.signed.json": ReasonContentHashMismatch,
			"untrusted-key.signed.json":          ReasonUnknownKeyID,
		}
		for _, path := range receiptVectorFiles(t, "signed", "invalid") {
			name := filepath.Base(path)
			t.Run(name, func(t *testing.T) {
				signed := parseSignedVector(t, path)
				result := VerifyReceipt(signed, opts)
				if result.OK {
					t.Fatal("an invalid signed receipt must not verify")
				}
				want, ok := wantReason[name]
				if !ok {
					t.Fatalf("no expected reason recorded for the vector %q", name)
				}
				if result.Reason != want {
					t.Errorf("expected reason %q, got %q: %s", want, result.Reason, result.Detail)
				}
			})
		}
	})
}

func parseSignedVector(t *testing.T, path string) *SignedReceipt {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	signed, err := ParseSignedReceipt(data)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return signed
}

// TestSignReceiptRoundTrip locks in that a receipt signed by this SDK verifies
// under the same keyring, and that editing any field afterwards breaks it:
// the envelope covers the receipt hash, which covers every member.
func TestSignReceiptRoundTrip(t *testing.T) {
	receipt := auditReceipt(t, specWithToolAccess(),
		&EvaluationAction{Type: "tool_call", Target: "read_file"}, disabledConfig())
	signedAt := signedReceiptVectorClock(t)

	signed, err := SignReceipt(&receipt, testSigningKeyPEM(t),
		SignOptions{SignedAt: &signedAt, Signer: "go-test"})
	if err != nil {
		t.Fatalf("SignReceipt failed: %v", err)
	}
	opts := VerifyOptions{Keyring: testKeyring(t), Now: signedAt}
	if result := VerifyReceipt(signed, opts); !result.OK {
		t.Fatalf("a freshly signed receipt must verify, got %s: %s", result.Reason, result.Detail)
	}
	// A receipt already names its policy, so the envelope leaves the policy
	// claims unset unless the caller asks for them.
	if signed.Signature.PolicyName != nil || signed.Signature.PolicyVersion != nil {
		t.Errorf("expected no policy claims on a receipt envelope, got %+v", signed.Signature)
	}

	signed.Receipt.Decision = DecisionDeny
	result := VerifyReceipt(signed, opts)
	if result.OK {
		t.Fatal("editing a signed receipt must break the signature")
	}
	if result.Reason != ReasonContentHashMismatch {
		t.Errorf("expected %s, got %q", ReasonContentHashMismatch, result.Reason)
	}
}
