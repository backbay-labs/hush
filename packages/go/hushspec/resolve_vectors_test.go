package hushspec

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// Resolution vectors (core spec 2.3, receipt spec 4.2): digest pins and chain
// provenance, under fixtures/core/resolve.
//
// Each vector is an inline leaf document whose `extends` references only
// builtins, so every SDK resolves it with its embedded rulesets and no
// filesystem. The expectation is either the resolved content hash plus the
// chain links (root first, the leaf recorded as `memory`), or a rejection
// reason. Rust generates the vectors; this runner checks the Go resolver
// against the committed ones.

type resolveVector struct {
	HushSpecResolve string         `yaml:"hushspec_resolve"`
	Description     string         `yaml:"description"`
	Policy          map[string]any `yaml:"policy"`
	Expect          struct {
		Resolves    *bool               `yaml:"resolves"`
		ContentHash string              `yaml:"content_hash"`
		Chain       []resolveVectorLink `yaml:"chain"`
		Rejects     string              `yaml:"rejects"`
	} `yaml:"expect"`
}

type resolveVectorLink struct {
	Source      string `yaml:"source"`
	ContentHash string `yaml:"content_hash"`
}

func TestResolveVectors(t *testing.T) {
	root := fixtureRepoRoot(t)
	dir := filepath.Join(root, "fixtures", "core", "resolve")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read %s: %v", dir, err)
	}

	checked := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		t.Run(entry.Name(), func(t *testing.T) {
			runResolveVector(t, path)
		})
		checked++
	}
	if checked < 7 {
		t.Fatalf("expected at least 7 resolve vectors, found %d", checked)
	}
}

func runResolveVector(t *testing.T, path string) {
	t.Helper()
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	var vector resolveVector
	if err := yaml.Unmarshal(source, &vector); err != nil {
		t.Fatalf("%s: cannot parse the vector: %v", path, err)
	}
	if vector.HushSpecResolve != "0.1.0" {
		t.Fatalf("%s: unsupported vector version %q", path, vector.HushSpecResolve)
	}

	policyYAML, err := yaml.Marshal(vector.Policy)
	if err != nil {
		t.Fatalf("%s: cannot re-encode the policy: %v", path, err)
	}
	spec, err := Parse(string(policyYAML))
	if err != nil {
		t.Fatalf("%s: the policy does not parse: %v", path, err)
	}

	// An empty source is the in-memory leaf the vectors describe.
	resolution, err := ResolveWithOptions(spec, "", nil, ResolveOptions{})

	if vector.Expect.Rejects != "" {
		if err == nil {
			t.Fatalf("%s: expected rejection %q, but it resolved", path, vector.Expect.Rejects)
		}
		reason, ok := ResolveReason(err)
		if !ok {
			t.Fatalf("%s: expected rejection %q, got an uncoded error: %v",
				path, vector.Expect.Rejects, err)
		}
		if reason != vector.Expect.Rejects {
			t.Fatalf("%s: expected rejection %q, got %q: %v",
				path, vector.Expect.Rejects, reason, err)
		}
		return
	}

	if err != nil {
		t.Fatalf("%s: expected the vector to resolve, got %v", path, err)
	}
	if vector.Expect.ContentHash != "" && resolution.ContentHash != vector.Expect.ContentHash {
		t.Errorf("%s: content_hash: expected %s, got %s",
			path, vector.Expect.ContentHash, resolution.ContentHash)
	}
	if vector.Expect.Chain == nil {
		return
	}
	if len(resolution.Chain) != len(vector.Expect.Chain) {
		t.Fatalf("%s: expected %d chain links, got %d: %+v",
			path, len(vector.Expect.Chain), len(resolution.Chain), resolution.Chain)
	}
	for index, want := range vector.Expect.Chain {
		got := resolution.Chain[index]
		if got.Source != want.Source {
			t.Errorf("%s: chain[%d].source: expected %q, got %q",
				path, index, want.Source, got.Source)
		}
		if got.ContentHash != want.ContentHash {
			t.Errorf("%s: chain[%d].content_hash: expected %s, got %s",
				path, index, want.ContentHash, got.ContentHash)
		}
	}
}

// TestPinsSatisfyASignatureRequirementForThatHop locks in the pinned-hop rule
// of signing spec 6.5: a hop needs a signature only when nothing else vouches
// for it, so `required = RequireSignature && !pinned`.
//
// With signatures required and no keyring, the pinned builtin hop passes
// (builtins are embedded in the engine and never verified anyway) but the
// in-memory leaf cannot be verified, so resolution fails closed on the leaf.
func TestPinsSatisfyASignatureRequirementForThatHop(t *testing.T) {
	defaultOwn := ownHashOfBuiltin(t, "default")
	spec, err := Parse("hushspec: \"0.1.0\"\nextends: \"builtin:default#" + defaultOwn + "\"\n")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	_, err = ResolveWithOptions(spec, "", nil, ResolveOptions{RequireSignature: true})
	if err == nil {
		t.Fatal("an unsigned, unpinned leaf must fail closed under RequireSignature")
	}
	var required *SignatureRequiredError
	if !errors.As(err, &required) {
		t.Fatalf("expected a SignatureRequiredError, got %T: %v", err, err)
	}
	if required.Source != MemorySource {
		t.Errorf("expected the in-memory leaf to be named, got %q", required.Source)
	}
}

func ownHashOfBuiltin(t *testing.T, name string) string {
	t.Helper()
	spec, ok := LoadBuiltin("builtin:" + name)
	if !ok {
		t.Fatalf("unknown builtin %q", name)
	}
	hash, err := OwnContentHash(spec)
	if err != nil {
		t.Fatalf("cannot hash builtin %q: %v", name, err)
	}
	return hash
}
