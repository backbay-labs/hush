package hushspec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Coverage for verification on load and digest pinning
// (spec/hushspec-signing.md sections 6.5 and 7.1, spec/hushspec-receipt.md
// section 4.2).

// policyDir returns a temporary directory with symlinks resolved, because the
// resolver canonicalizes every source it loads and the tests compare those
// canonical sources and place `.sig` sidecars beside them.
func policyDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("failed to canonicalize the temp dir: %v", err)
	}
	return dir
}

func testKeyring(t *testing.T) *Keyring {
	t.Helper()
	keyring, err := LoadKeyring(readTestFile(t, filepath.Join(signingFixtureDir(t), "keys", "keyring.json")))
	if err != nil {
		t.Fatalf("failed to load the test keyring: %v", err)
	}
	return keyring
}

func testUntrustedKeyPEM(t *testing.T) []byte {
	t.Helper()
	return readTestFile(t, filepath.Join(signingFixtureDir(t), "keys", "test-untrusted.key.pem"))
}

// signSidecar signs resolved with keyPEM and writes the envelope to the
// detached location for policyPath (spec section 7.1).
func signSidecar(t *testing.T, policyPath string, resolved *HushSpec, keyPEM []byte) *Envelope {
	t.Helper()
	env, err := SignPolicy(resolved, keyPEM, SignOptions{})
	if err != nil {
		t.Fatalf("failed to sign %s: %v", policyPath, err)
	}
	data, err := MarshalEnvelope(env)
	if err != nil {
		t.Fatalf("failed to marshal the envelope for %s: %v", policyPath, err)
	}
	if err := os.WriteFile(policyPath+".sig", data, 0o644); err != nil {
		t.Fatalf("failed to write the signature for %s: %v", policyPath, err)
	}
	return env
}

// resolveNow resolves a file with default options and fails the test if it
// cannot, for setting up the document a signature must cover.
func resolveNow(t *testing.T, path string) *HushSpec {
	t.Helper()
	resolved, err := ResolveFile(path)
	if err != nil {
		t.Fatalf("failed to resolve %s: %v", path, err)
	}
	return resolved
}

// ownHashOf is the hash a chain link records for a document: that document
// canonicalized on its own (receipt section 4.2).
func ownHashOf(t *testing.T, path string) string {
	t.Helper()
	hash, err := hopContentHash(parseFixtureOrFail(t, path))
	if err != nil {
		t.Fatalf("failed to hash %s on its own: %v", path, err)
	}
	return hash
}

// writeThreeHopChain lays out builtin:permissive <- base.yaml <- child.yaml and
// returns the two file paths.
func writeThreeHopChain(t *testing.T, dir string) (string, string) {
	t.Helper()
	basePath := filepath.Join(dir, "base.yaml")
	childPath := filepath.Join(dir, "child.yaml")
	writeFixtureFile(t, basePath, `
hushspec: "0.2.0"
name: base
extends: builtin:permissive
rules:
  tool_access:
    allow: [read_file]
    default: block
`)
	writeFixtureFile(t, childPath, `
hushspec: "0.2.0"
name: child
extends: base.yaml
rules:
  egress:
    allow: [api.example.com]
    default: block
`)
	return basePath, childPath
}

// TestResolveWithOptionsRecordsTheChain pins the evidence a receipt carries:
// every hop of the chain, root first and leaf last, each with the hash of that
// document on its own rather than of the merge up to that point.
func TestResolveWithOptionsRecordsTheChain(t *testing.T) {
	dir := policyDir(t)
	basePath, childPath := writeThreeHopChain(t, dir)

	resolution, err := ResolveFileWithOptions(childPath, ResolveOptions{})
	if err != nil {
		t.Fatalf("ResolveFileWithOptions returned error: %v", err)
	}

	wantSources := []string{"builtin:permissive", basePath, childPath}
	if len(resolution.Chain) != len(wantSources) {
		t.Fatalf("expected %d chain links, got %d: %+v", len(wantSources), len(resolution.Chain), resolution.Chain)
	}
	for index, want := range wantSources {
		if got := resolution.Chain[index].Source; got != want {
			t.Fatalf("chain[%d].Source = %q, want %q", index, got, want)
		}
		if resolution.Chain[index].Signature != nil {
			t.Fatalf("chain[%d] recorded a signature without any keys configured", index)
		}
	}

	// The merge really happened: rules from all three hops survive.
	if resolution.Spec.Rules.ToolAccess == nil || len(resolution.Spec.Rules.ToolAccess.Allow) != 1 {
		t.Fatalf("expected the base's tool_access to survive, got %#v", resolution.Spec.Rules.ToolAccess)
	}
	if resolution.Spec.Rules.PatchIntegrity == nil {
		t.Fatal("expected builtin:permissive's patch_integrity to survive")
	}

	// Each link hashes its own document, not the running merge.
	if got, want := resolution.Chain[1].ContentHash, ownHashOf(t, basePath); got != want {
		t.Fatalf("chain[1].ContentHash = %q, want the base's own hash %q", got, want)
	}
	if got, want := resolution.Chain[2].ContentHash, ownHashOf(t, childPath); got != want {
		t.Fatalf("chain[2].ContentHash = %q, want the child's own hash %q", got, want)
	}
	if resolution.Chain[2].ContentHash == resolution.ContentHash {
		t.Fatal("the leaf's own hash must differ from the resolved policy's hash")
	}

	resolvedHash, err := ContentHash(resolution.Spec)
	if err != nil {
		t.Fatalf("failed to hash the resolved policy: %v", err)
	}
	if resolution.ContentHash != resolvedHash {
		t.Fatalf("Resolution.ContentHash = %q, want %q", resolution.ContentHash, resolvedHash)
	}
	if resolution.Signature != nil {
		t.Fatal("expected no leaf signature when no keys are configured")
	}
}

// TestResolveWithOptionsChainHoldsALoneDocument keeps the chain uniform: a
// policy with no `extends` still reports itself as the one link, so a receipt
// builder can omit `extends_chain` on len(Chain) == 1 rather than special-case
// a nil.
func TestResolveWithOptionsChainHoldsALoneDocument(t *testing.T) {
	dir := policyDir(t)
	path := filepath.Join(dir, "lone.yaml")
	writeFixtureFile(t, path, `
hushspec: "0.2.0"
name: lone
rules:
  egress:
    allow: [api.example.com]
    default: block
`)

	resolution, err := ResolveFileWithOptions(path, ResolveOptions{})
	if err != nil {
		t.Fatalf("ResolveFileWithOptions returned error: %v", err)
	}
	if len(resolution.Chain) != 1 || resolution.Chain[0].Source != path {
		t.Fatalf("expected a single self link, got %+v", resolution.Chain)
	}
	if resolution.Chain[0].ContentHash != resolution.ContentHash {
		t.Fatal("a policy that extends nothing hashes the same on its own as resolved")
	}
}

// TestHopHashStripsExtendsAndMergeStrategy proves the hop-hash definition of
// receipt section 4.2: two documents that differ only in their `extends` and
// `merge_strategy` fields have the same chain-link hash, which is what lets an
// auditor recognize a base policy by hash wherever it was composed.
func TestHopHashStripsExtendsAndMergeStrategy(t *testing.T) {
	dir := policyDir(t)
	body := `
hushspec: "0.2.0"
name: shared-body
rules:
  egress:
    allow: [api.example.com]
    default: block
`
	barePath := filepath.Join(dir, "bare.yaml")
	extendingPath := filepath.Join(dir, "extending.yaml")
	writeFixtureFile(t, barePath, body)
	writeFixtureFile(t, extendingPath, strings.Replace(
		body,
		"name: shared-body\n",
		"name: shared-body\nextends: bare.yaml\nmerge_strategy: merge\n",
		1,
	))

	resolution, err := ResolveFileWithOptions(extendingPath, ResolveOptions{})
	if err != nil {
		t.Fatalf("ResolveFileWithOptions returned error: %v", err)
	}
	if len(resolution.Chain) != 2 {
		t.Fatalf("expected two chain links, got %+v", resolution.Chain)
	}
	if resolution.Chain[0].ContentHash != resolution.Chain[1].ContentHash {
		t.Fatalf(
			"documents differing only in extends/merge_strategy must hash alike: %q vs %q",
			resolution.Chain[0].ContentHash, resolution.Chain[1].ContentHash,
		)
	}
}

// TestResolveDigestPinMatches accepts a hop whose loaded bytes hash to the
// digest the child pinned.
func TestResolveDigestPinMatches(t *testing.T) {
	dir := policyDir(t)
	basePath := filepath.Join(dir, "base.yaml")
	writeFixtureFile(t, basePath, `
hushspec: "0.2.0"
name: pinned-base
rules:
  tool_access:
    allow: [read_file]
    default: block
`)
	childPath := filepath.Join(dir, "child.yaml")
	writeFixtureFile(t, childPath, `
hushspec: "0.2.0"
name: pinned-child
extends: base.yaml#`+ownHashOf(t, basePath)+`
rules:
  egress:
    allow: [api.example.com]
    default: block
`)

	resolution, err := ResolveFileWithOptions(childPath, ResolveOptions{})
	if err != nil {
		t.Fatalf("a matching digest pin must resolve: %v", err)
	}
	if got := resolution.Chain[0].Source; got != basePath {
		t.Fatalf("the pin fragment must not leak into the loaded source: %q", got)
	}
	if resolution.Spec.Rules.ToolAccess == nil {
		t.Fatal("expected the pinned base to be merged in")
	}
}

// TestResolveDigestPinMismatchAlwaysRejects is the fail-closed core of digest
// pinning: a changed base is refused even for a caller that asked for nothing,
// because the child has already stated which bytes it was written against.
func TestResolveDigestPinMismatchAlwaysRejects(t *testing.T) {
	dir := policyDir(t)
	basePath := filepath.Join(dir, "base.yaml")
	writeFixtureFile(t, basePath, `
hushspec: "0.2.0"
name: pinned-base
rules:
  tool_access:
    allow: [read_file]
    default: block
`)
	pinned := ownHashOf(t, basePath)
	childPath := filepath.Join(dir, "child.yaml")
	writeFixtureFile(t, childPath, `
hushspec: "0.2.0"
name: pinned-child
extends: base.yaml#`+pinned+`
rules:
  egress:
    allow: [api.example.com]
    default: block
`)

	// The base is relaxed after the child pinned it.
	writeFixtureFile(t, basePath, `
hushspec: "0.2.0"
name: pinned-base
rules:
  tool_access:
    allow: [read_file, shell_exec]
    default: allow
`)

	// Plain Resolve, with no options at all, must still refuse.
	if _, err := ResolveFile(childPath); err == nil {
		t.Fatal("expected ResolveFile to reject a mismatched digest pin")
	}

	_, err := ResolveFileWithOptions(childPath, ResolveOptions{})
	if err == nil {
		t.Fatal("expected a mismatched digest pin to be rejected")
	}
	var mismatch *DigestMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected a *DigestMismatchError, got %T: %v", err, err)
	}
	if mismatch.Source != basePath {
		t.Fatalf("DigestMismatchError.Source = %q, want %q", mismatch.Source, basePath)
	}
	if mismatch.Expected != pinned {
		t.Fatalf("DigestMismatchError.Expected = %q, want %q", mismatch.Expected, pinned)
	}
	if mismatch.Actual == pinned || !strings.HasPrefix(mismatch.Actual, "sha256:") {
		t.Fatalf("DigestMismatchError.Actual = %q, want the hash of the changed base", mismatch.Actual)
	}
	if reason, ok := ReasonFromError(err); !ok || reason != ReasonDigestMismatch {
		t.Fatalf("ReasonFromError = (%q, %v), want (%q, true)", reason, ok, ReasonDigestMismatch)
	}
}

// TestResolveRejectsMalformedDigestPins refuses to guess: a fragment shaped
// like a pin but not a well-formed sha256 one is an error rather than part of
// the filename, so a typo cannot silently drop the pin.
func TestResolveRejectsMalformedDigestPins(t *testing.T) {
	cases := map[string]string{
		"short hex":            "base.yaml#sha256:abc123",
		"uppercase hex":        "base.yaml#sha256:" + strings.ToUpper(strings.Repeat("ab", 32)),
		"unknown algorithm":    "base.yaml#sha512:" + strings.Repeat("ab", 32),
		"pin without a target": "#sha256:" + strings.Repeat("ab", 32),
	}
	for name, reference := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := splitDigestPin(reference); err == nil {
				t.Fatalf("expected %q to be rejected", reference)
			}
		})
	}

	t.Run("fragment that is not a pin", func(t *testing.T) {
		ref, pin, err := splitDigestPin("weird#name.yaml")
		if err != nil || pin != "" || ref != "weird#name.yaml" {
			t.Fatalf("expected a non-pin fragment to pass through, got (%q, %q, %v)", ref, pin, err)
		}
	})
}

// TestResolveRequireSignatureAcceptsASignedLeaf is the happy path of section
// 6.5: the leaf's detached envelope verifies, the `builtin:` root needs no
// verification of its own, and the outcome is recorded for the receipt.
func TestResolveRequireSignatureAcceptsASignedLeaf(t *testing.T) {
	dir := policyDir(t)
	childPath := filepath.Join(dir, "child.yaml")
	writeFixtureFile(t, childPath, `
hushspec: "0.2.0"
name: signed-leaf
extends: builtin:permissive
metadata:
  policy_version: 7
rules:
  egress:
    allow: [api.example.com]
    default: block
`)
	env := signSidecar(t, childPath, resolveNow(t, childPath), testSigningKeyPEM(t))

	resolution, err := ResolveFileWithOptions(childPath, ResolveOptions{
		RequireSignature: true,
		Keyring:          testKeyring(t),
	})
	if err != nil {
		t.Fatalf("a correctly signed policy must load: %v", err)
	}
	if resolution.Signature == nil || !resolution.Signature.Verified {
		t.Fatalf("expected a verified leaf signature, got %+v", resolution.Signature)
	}
	if resolution.Signature.Reason != "" {
		t.Fatalf("a verified signature carries no reason, got %q", resolution.Signature.Reason)
	}
	if resolution.Signature.KeyID != env.KeyID {
		t.Fatalf("SignatureStatus.KeyID = %q, want %q", resolution.Signature.KeyID, env.KeyID)
	}
	// VerifiedAt records when the verifier ran, not the signer's claim: the
	// envelope's own signed_at is trustworthy only once Verified is true.
	if !receiptTimeRE.MatchString(resolution.Signature.VerifiedAt) {
		t.Fatalf("SignatureStatus.VerifiedAt = %q, want a millisecond timestamp",
			resolution.Signature.VerifiedAt)
	}
	if resolution.Chain[0].Signature != nil {
		t.Fatal("a builtin: hop is embedded in the engine and needs no signature of its own")
	}
	if resolution.Signature != resolution.Chain[1].Signature {
		t.Fatal("Resolution.Signature must be the leaf link's outcome")
	}
}

// TestResolveRequireSignatureRefusesUnsignedHops covers the refusals of
// section 6.5, including the one that matters most: an unsigned *base* denies
// even when the leaf itself is signed.
func TestResolveRequireSignatureRefusesUnsignedHops(t *testing.T) {
	t.Run("unsigned leaf", func(t *testing.T) {
		dir := policyDir(t)
		path := filepath.Join(dir, "policy.yaml")
		writeFixtureFile(t, path, `
hushspec: "0.2.0"
name: unsigned
rules:
  egress:
    allow: [api.example.com]
    default: block
`)
		_, err := ResolveFileWithOptions(path, ResolveOptions{RequireSignature: true, Keyring: testKeyring(t)})
		var required *SignatureRequiredError
		if !errors.As(err, &required) {
			t.Fatalf("expected a *SignatureRequiredError, got %T: %v", err, err)
		}
		if required.Source != path {
			t.Fatalf("SignatureRequiredError.Source = %q, want %q", required.Source, path)
		}
		if required.Status.Verified || required.Status.Reason != ReasonMissingSignature {
			t.Fatalf("expected an unverified %s status, got %+v", ReasonMissingSignature, required.Status)
		}
		if reason, ok := ReasonFromError(err); !ok || reason != ReasonMissingSignature {
			t.Fatalf("ReasonFromError = (%q, %v), want (%q, true)", reason, ok, ReasonMissingSignature)
		}
	})

	t.Run("unsigned base under a signed leaf", func(t *testing.T) {
		dir := policyDir(t)
		basePath, childPath := writeThreeHopChain(t, dir)
		signSidecar(t, childPath, resolveNow(t, childPath), testSigningKeyPEM(t))

		_, err := ResolveFileWithOptions(childPath, ResolveOptions{RequireSignature: true, Keyring: testKeyring(t)})
		var required *SignatureRequiredError
		if !errors.As(err, &required) {
			t.Fatalf("expected a *SignatureRequiredError, got %T: %v", err, err)
		}
		if required.Source != basePath {
			t.Fatalf("expected the unsigned base %q to be named, got %q", basePath, required.Source)
		}
	})

	t.Run("signature from a key outside the keyring", func(t *testing.T) {
		dir := policyDir(t)
		path := filepath.Join(dir, "policy.yaml")
		writeFixtureFile(t, path, `
hushspec: "0.2.0"
name: untrusted-signer
rules:
  egress:
    allow: [api.example.com]
    default: block
`)
		signSidecar(t, path, resolveNow(t, path), testUntrustedKeyPEM(t))

		_, err := ResolveFileWithOptions(path, ResolveOptions{RequireSignature: true, Keyring: testKeyring(t)})
		var required *SignatureRequiredError
		if !errors.As(err, &required) {
			t.Fatalf("expected a *SignatureRequiredError, got %T: %v", err, err)
		}
		if required.Status.Reason != ReasonUnknownKeyID {
			t.Fatalf("expected %s, got %+v", ReasonUnknownKeyID, required.Status)
		}
	})

	t.Run("policy edited after signing", func(t *testing.T) {
		dir := policyDir(t)
		path := filepath.Join(dir, "policy.yaml")
		writeFixtureFile(t, path, `
hushspec: "0.2.0"
name: edited
rules:
  egress:
    allow: [api.example.com]
    default: block
`)
		signSidecar(t, path, resolveNow(t, path), testSigningKeyPEM(t))
		writeFixtureFile(t, path, `
hushspec: "0.2.0"
name: edited
rules:
  egress:
    allow: [api.example.com, exfil.example.net]
    default: allow
`)

		_, err := ResolveFileWithOptions(path, ResolveOptions{RequireSignature: true, Keyring: testKeyring(t)})
		var required *SignatureRequiredError
		if !errors.As(err, &required) {
			t.Fatalf("expected a *SignatureRequiredError, got %T: %v", err, err)
		}
		if required.Status.Reason != ReasonContentHashMismatch {
			t.Fatalf("expected %s, got %+v", ReasonContentHashMismatch, required.Status)
		}
	})

	t.Run("no trusted keys at all", func(t *testing.T) {
		dir := policyDir(t)
		path := filepath.Join(dir, "policy.yaml")
		writeFixtureFile(t, path, `
hushspec: "0.2.0"
name: no-keys
rules:
  egress:
    allow: [api.example.com]
    default: block
`)
		signSidecar(t, path, resolveNow(t, path), testSigningKeyPEM(t))

		if _, err := ResolveFileWithOptions(path, ResolveOptions{RequireSignature: true}); err == nil {
			t.Fatal("requiring signatures without a keyring must deny, not trust the envelope")
		}
	})
}

// TestResolveDigestPinSatisfiesRequireSignature: a hop the child pinned by
// digest needs no envelope of its own -- the pin already fixes its bytes.
func TestResolveDigestPinSatisfiesRequireSignature(t *testing.T) {
	dir := policyDir(t)
	basePath := filepath.Join(dir, "base.yaml")
	writeFixtureFile(t, basePath, `
hushspec: "0.2.0"
name: pinned-base
rules:
  tool_access:
    allow: [read_file]
    default: block
`)
	childBody := `
hushspec: "0.2.0"
name: pinned-child
extends: base.yaml%s
rules:
  egress:
    allow: [api.example.com]
    default: block
`
	childPath := filepath.Join(dir, "child.yaml")
	writeFixtureFile(t, childPath, strings.Replace(childBody, "%s", "#"+ownHashOf(t, basePath), 1))
	signSidecar(t, childPath, resolveNow(t, childPath), testSigningKeyPEM(t))

	opts := ResolveOptions{RequireSignature: true, Keyring: testKeyring(t)}
	resolution, err := ResolveFileWithOptions(childPath, opts)
	if err != nil {
		t.Fatalf("a pinned base must satisfy the signature requirement: %v", err)
	}
	// Verification was attempted (signatures are required), so the outcome
	// is recorded even though the pin alone satisfied the hop: no envelope
	// means missing_signature, never a silent nil (signing spec 6.5).
	if got := resolution.Chain[0].Signature; got == nil || got.Verified || got.Reason != ReasonMissingSignature {
		t.Fatalf("the pinned base has no envelope, so missing_signature should be recorded: %+v", got)
	}
	if resolution.Signature == nil || !resolution.Signature.Verified {
		t.Fatalf("expected the leaf's own signature to be verified, got %+v", resolution.Signature)
	}

	// Drop the pin and the same base is no longer acceptable. The leaf's
	// signature has to be redone because its resolved hash is unchanged only
	// if the pin is not part of the canonical form -- it is not, so the same
	// envelope still applies.
	writeFixtureFile(t, childPath, strings.Replace(childBody, "%s", "", 1))
	if _, err := ResolveFileWithOptions(childPath, opts); err == nil {
		t.Fatal("an unpinned, unsigned base must be refused when signatures are required")
	}
}

// TestResolveVerifiesOpportunistically: without RequireSignature but with a
// keyring, section 6.5 says a runtime MAY verify and SHOULD record what it
// found. Resolution still succeeds either way.
func TestResolveVerifiesOpportunistically(t *testing.T) {
	dir := policyDir(t)
	path := filepath.Join(dir, "policy.yaml")
	body := `
hushspec: "0.2.0"
name: opportunistic
rules:
  egress:
    allow: [api.example.com]
    default: block
`
	writeFixtureFile(t, path, body)
	signSidecar(t, path, resolveNow(t, path), testSigningKeyPEM(t))

	t.Run("valid signature is recorded", func(t *testing.T) {
		resolution, err := ResolveFileWithOptions(path, ResolveOptions{Keyring: testKeyring(t)})
		if err != nil {
			t.Fatalf("opportunistic verification must not fail the load: %v", err)
		}
		if resolution.Signature == nil || !resolution.Signature.Verified {
			t.Fatalf("expected a recorded valid signature, got %+v", resolution.Signature)
		}
	})

	t.Run("no keys means no lookup", func(t *testing.T) {
		resolution, err := ResolveFileWithOptions(path, ResolveOptions{})
		if err != nil {
			t.Fatalf("ResolveFileWithOptions returned error: %v", err)
		}
		if resolution.Signature != nil {
			t.Fatalf("a caller that configured no keys asked for no verification, got %+v", resolution.Signature)
		}
	})

	t.Run("failed signature is recorded but still loads", func(t *testing.T) {
		writeFixtureFile(t, path, strings.Replace(body, "default: block", "default: allow", 1))
		resolution, err := ResolveFileWithOptions(path, ResolveOptions{Keyring: testKeyring(t)})
		if err != nil {
			t.Fatalf("opportunistic verification must not fail the load: %v", err)
		}
		if resolution.Signature == nil || resolution.Signature.Verified {
			t.Fatalf("expected a recorded failure, got %+v", resolution.Signature)
		}
		if resolution.Signature.Reason != ReasonContentHashMismatch {
			t.Fatalf("expected %s, got %q", ReasonContentHashMismatch, resolution.Signature.Reason)
		}
		if resolution.Signature.VerifiedAt != "" {
			t.Fatalf("a failed check records no verified_at, got %q",
				resolution.Signature.VerifiedAt)
		}
	})
}

// TestDefaultSignatureLocatorLookupOrder pins the two detached locations of
// spec section 7.1 and their precedence.
func TestDefaultSignatureLocatorLookupOrder(t *testing.T) {
	dir := policyDir(t)
	policyPath := filepath.Join(dir, "policy.yaml")
	writeFixtureFile(t, policyPath, "hushspec: \"0.2.0\"\n")

	t.Run("neither present", func(t *testing.T) {
		data, found, err := DefaultSignatureLocator(policyPath)
		if err != nil || found || data != nil {
			t.Fatalf("expected a clean not-found, got (%q, %v, %v)", data, found, err)
		}
	})

	t.Run("0.1 layout only", func(t *testing.T) {
		writeFixtureFile(t, filepath.Join(dir, "policy.sig"), "stem\n")
		data, found, err := DefaultSignatureLocator(policyPath)
		if err != nil || !found || strings.TrimSpace(string(data)) != "stem" {
			t.Fatalf("expected the <stem>.sig fallback, got (%q, %v, %v)", data, found, err)
		}
	})

	t.Run("appended layout wins", func(t *testing.T) {
		writeFixtureFile(t, policyPath+".sig", "appended\n")
		data, found, err := DefaultSignatureLocator(policyPath)
		if err != nil || !found || strings.TrimSpace(string(data)) != "appended" {
			t.Fatalf("expected <path>.sig to win, got (%q, %v, %v)", data, found, err)
		}
	})

	t.Run("sources with no sidecar", func(t *testing.T) {
		for _, source := range []string{"", "builtin:default", "https://policies.example.com/base.yaml"} {
			data, found, err := DefaultSignatureLocator(source)
			if err != nil || found || data != nil {
				t.Fatalf("expected %q to have no sidecar, got (%q, %v, %v)", source, data, found, err)
			}
		}
	})
}

// TestResolveUsesTheSuppliedSignatureLocator lets a caller with its own
// transport (an https loader, a bundle) plug in where envelopes come from.
func TestResolveUsesTheSuppliedSignatureLocator(t *testing.T) {
	dir := policyDir(t)
	path := filepath.Join(dir, "policy.yaml")
	writeFixtureFile(t, path, `
hushspec: "0.2.0"
name: custom-locator
rules:
  egress:
    allow: [api.example.com]
    default: block
`)
	env, err := SignPolicy(resolveNow(t, path), testSigningKeyPEM(t), SignOptions{})
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	envelopeJSON, err := MarshalEnvelope(env)
	if err != nil {
		t.Fatalf("failed to marshal the envelope: %v", err)
	}

	asked := make([]string, 0, 1)
	resolution, err := ResolveFileWithOptions(path, ResolveOptions{
		RequireSignature: true,
		Keyring:          testKeyring(t),
		SignatureLocator: func(source string) ([]byte, bool, error) {
			asked = append(asked, source)
			return envelopeJSON, true, nil
		},
	})
	if err != nil {
		t.Fatalf("expected the supplied locator's envelope to be used: %v", err)
	}
	if len(asked) != 1 || asked[0] != path {
		t.Fatalf("expected the locator to be asked once for %q, got %v", path, asked)
	}
	if resolution.Signature == nil || !resolution.Signature.Verified {
		t.Fatalf("expected a verified signature, got %+v", resolution.Signature)
	}

	t.Run("a locator error fails the load", func(t *testing.T) {
		_, err := ResolveFileWithOptions(path, ResolveOptions{
			Keyring: testKeyring(t),
			SignatureLocator: func(string) ([]byte, bool, error) {
				return nil, false, errors.New("transport exploded")
			},
		})
		if err == nil || !strings.Contains(err.Error(), "transport exploded") {
			t.Fatalf("expected the locator's error to propagate, got %v", err)
		}
	})
}
