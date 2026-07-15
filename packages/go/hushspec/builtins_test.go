package hushspec

import "testing"

func TestResolveBuiltinExtends(t *testing.T) {
	child, err := Parse("hushspec: \"0.1.0\"\nname: child\nextends: \"builtin:strict\"\nrules:\n  egress:\n    default: allow\n")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := Resolve(child, "", nil)
	if err != nil {
		t.Fatalf("resolve builtin:strict: %v", err)
	}
	// tool_access is inherited from builtin:strict (child does not define it).
	if resolved.Rules == nil || resolved.Rules.ToolAccess == nil || resolved.Rules.ToolAccess.Default != "block" {
		t.Errorf("expected tool_access.default=block from strict, got %+v", resolved.Rules)
	}
	// The child's egress replaces the builtin's.
	if resolved.Rules.Egress == nil || resolved.Rules.Egress.Default != "allow" {
		t.Errorf("expected egress.default=allow, got %+v", resolved.Rules.Egress)
	}
}

func TestResolveBareBuiltinName(t *testing.T) {
	child, err := Parse("hushspec: \"0.1.0\"\nname: c\nextends: strict\n")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := Resolve(child, "", nil)
	if err != nil {
		t.Fatalf("resolve bare strict: %v", err)
	}
	if resolved.Rules == nil || resolved.Rules.ToolAccess == nil || resolved.Rules.ToolAccess.Default != "block" {
		t.Errorf("expected tool_access.default=block")
	}
}

func TestResolveUnknownBuiltinErrors(t *testing.T) {
	if _, err := Resolve(&HushSpec{Extends: "builtin:nope"}, "", nil); err == nil {
		t.Fatal("expected unknown builtin error")
	}
}

func TestLoadBuiltin(t *testing.T) {
	if _, ok := LoadBuiltin("builtin:nope"); ok {
		t.Fatal("expected LoadBuiltin to return false for an unknown name")
	}
	if spec, ok := LoadBuiltin("strict"); !ok || spec == nil || spec.Name != "strict" {
		t.Fatalf("expected LoadBuiltin to find strict, got ok=%v spec=%v", ok, spec)
	}
	if spec, ok := LoadBuiltin("builtin:default"); !ok || spec == nil || spec.Name != "default" {
		t.Fatalf("expected LoadBuiltin to find default, got ok=%v spec=%v", ok, spec)
	}
}
