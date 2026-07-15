package hushspec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveFileMergesExtendsChain(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, filepath.Join(dir, "base.yaml"), `
hushspec: "0.1.0"
name: base
rules:
  tool_access:
    allow: [read_file]
    default: block
`)
	writeFixtureFile(t, filepath.Join(dir, "child.yaml"), `
hushspec: "0.1.0"
extends: base.yaml
name: child
rules:
  egress:
    allow: [api.example.com]
    default: allow
`)

	resolved, err := ResolveFile(filepath.Join(dir, "child.yaml"))
	if err != nil {
		t.Fatalf("ResolveFile returned error: %v", err)
	}
	if resolved.Extends != "" {
		t.Fatalf("expected resolved spec to clear extends, got %q", resolved.Extends)
	}
	if resolved.Name != "child" {
		t.Fatalf("expected child name to win, got %q", resolved.Name)
	}
	if resolved.Rules == nil || resolved.Rules.ToolAccess == nil {
		t.Fatal("expected merged tool_access rule")
	}
	if got := resolved.Rules.ToolAccess.Allow; len(got) != 1 || got[0] != "read_file" {
		t.Fatalf("expected inherited allow list, got %#v", got)
	}
	if resolved.Rules.ToolAccess.Default != DefaultActionBlock {
		t.Fatalf("expected base tool access default to remain block, got %q", resolved.Rules.ToolAccess.Default)
	}
	if resolved.Rules.Egress == nil || len(resolved.Rules.Egress.Allow) != 1 || resolved.Rules.Egress.Allow[0] != "api.example.com" {
		t.Fatalf("expected child egress rule, got %#v", resolved.Rules.Egress)
	}
}

func TestResolveFileDetectsCycles(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, filepath.Join(dir, "a.yaml"), `
hushspec: "0.1.0"
extends: b.yaml
`)
	writeFixtureFile(t, filepath.Join(dir, "b.yaml"), `
hushspec: "0.1.0"
extends: a.yaml
`)

	_, err := ResolveFile(filepath.Join(dir, "a.yaml"))
	if err == nil || !strings.Contains(err.Error(), "circular extends detected") {
		t.Fatalf("expected cycle error, got %v", err)
	}
}

func TestResolveSupportsCustomLoader(t *testing.T) {
	child, err := Parse(`
hushspec: "0.1.0"
extends: parent
`)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	resolved, err := Resolve(child, "memory://child", func(reference string, from string) (*LoadedSpec, error) {
		if reference != "parent" {
			t.Fatalf("expected reference parent, got %q", reference)
		}
		if from != "memory://child" {
			t.Fatalf("expected source memory://child, got %q", from)
		}
		spec, err := Parse(`
hushspec: "0.1.0"
name: parent
`)
		if err != nil {
			return nil, err
		}
		return &LoadedSpec{Source: "memory://parent", Spec: spec}, nil
	})
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if resolved.Extends != "" || resolved.Name != "parent" {
		t.Fatalf("unexpected resolved output: %#v", resolved)
	}
}

func TestCompositeLoaderRejectsHTTPReferences(t *testing.T) {
	loader := createCompositeLoader()
	for _, ref := range []string{
		"http://example.com/policy.yaml",
		"https://example.com/policy.yaml",
	} {
		if _, err := loader(ref, ""); err == nil {
			t.Errorf("expected the composite loader to reject %q, got no error", ref)
		}
	}

	// Reached through the exported Resolve entry point (nil loader -> composite).
	for _, ref := range []string{
		"http://example.com/policy.yaml",
		"https://example.com/policy.yaml",
	} {
		spec := &HushSpec{HushSpecVersion: "0.1.0", Extends: ref}
		if _, err := Resolve(spec, "", nil); err == nil {
			t.Errorf("expected Resolve to reject an %q extends reference, got no error", ref)
		}
	}
}

// buildExtendsChain builds n distinct in-memory specs "spec0".."spec{n-1}"
// where each extends the next (spec[i] -> spec[i+1]) and the last is
// terminal (no extends).
func buildExtendsChain(t *testing.T, n int) map[string]*HushSpec {
	t.Helper()
	specs := make(map[string]*HushSpec, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("spec%d", i)
		yaml := fmt.Sprintf("hushspec: \"0.1.0\"\nname: %s\n", name)
		if i < n-1 {
			yaml += fmt.Sprintf("extends: spec%d\n", i+1)
		}
		spec, err := Parse(yaml)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", name, err)
		}
		specs[name] = spec
	}
	return specs
}

// memoryLoader resolves extends references purely from an in-memory map,
// keyed by name, with a synthetic "memory://<name>" source.
func memoryLoader(specs map[string]*HushSpec) ResolveLoader {
	return func(reference string, from string) (*LoadedSpec, error) {
		spec, ok := specs[reference]
		if !ok {
			return nil, fmt.Errorf("unknown in-memory spec %q", reference)
		}
		return &LoadedSpec{Source: "memory://" + reference, Spec: spec}, nil
	}
}

// TestResolveExtendsChainDepthCapErrorsCleanly covers parity fix S2: cycle
// detection alone does not bound a long ACYCLIC extends chain, which would
// otherwise recurse without limit. A chain of 40 distinct specs, each
// extending the next, must be rejected cleanly (no crash) once the chain
// exceeds the maximum depth of 32.
func TestResolveExtendsChainDepthCapErrorsCleanly(t *testing.T) {
	specs := buildExtendsChain(t, 40)
	loader := memoryLoader(specs)

	_, err := Resolve(specs["spec0"], "memory://spec0", loader)
	if err == nil {
		t.Fatal("expected a 40-deep extends chain to error")
	}
	if !strings.Contains(err.Error(), "extends chain exceeds maximum depth of 32") {
		t.Fatalf("expected a maximum-depth error, got: %v", err)
	}
}

// TestResolveShallowExtendsChainStillResolves is the control for the depth
// cap: a realistic, shallow chain (3 hops) must still resolve normally.
func TestResolveShallowExtendsChainStillResolves(t *testing.T) {
	specs := buildExtendsChain(t, 4) // spec0 -> spec1 -> spec2 -> spec3 (3 hops)
	loader := memoryLoader(specs)

	resolved, err := Resolve(specs["spec0"], "memory://spec0", loader)
	if err != nil {
		t.Fatalf("expected a 3-deep extends chain to resolve cleanly, got error: %v", err)
	}
	if resolved.Extends != "" {
		t.Fatalf("expected resolved spec to clear extends, got %q", resolved.Extends)
	}
	if resolved.Name != "spec0" {
		t.Fatalf("expected resolved spec name to be spec0, got %q", resolved.Name)
	}
}

func writeFixtureFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.TrimLeft(content, "\n")), 0o644); err != nil {
		t.Fatalf("failed to write fixture file %s: %v", path, err)
	}
}
