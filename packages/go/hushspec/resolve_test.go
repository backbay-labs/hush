package hushspec

import (
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

func writeFixtureFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.TrimLeft(content, "\n")), 0o644); err != nil {
		t.Fatalf("failed to write fixture file %s: %v", path, err)
	}
}
