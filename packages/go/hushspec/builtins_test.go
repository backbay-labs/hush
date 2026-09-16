package hushspec

import (
	"slices"
	"strings"
	"testing"
)

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
	if _, err := Resolve(&HushSpec{Extends: strPtr("builtin:nope")}, "", nil); err == nil {
		t.Fatal("expected unknown builtin error")
	}
}

func TestLoadBuiltin(t *testing.T) {
	if _, ok := LoadBuiltin("builtin:nope"); ok {
		t.Fatal("expected LoadBuiltin to return false for an unknown name")
	}
	if spec, ok := LoadBuiltin("strict"); !ok || spec == nil || stringValue(spec.Name) != "strict" {
		t.Fatalf("expected LoadBuiltin to find strict, got ok=%v spec=%v", ok, spec)
	}
	if spec, ok := LoadBuiltin("builtin:default"); !ok || spec == nil || stringValue(spec.Name) != "default" {
		t.Fatalf("expected LoadBuiltin to find default, got ok=%v spec=%v", ok, spec)
	}
}

// The vertical library is embedded under `library/<vertical>/<name>`, so a
// policy can extend it with no file system.
func TestLoadBuiltinLibrary(t *testing.T) {
	spec, ok := LoadBuiltin("builtin:library/healthcare/hipaa-base")
	if !ok || spec == nil {
		t.Fatal("expected the library to be embedded as a builtin")
	}
	// The prefix is a location, not a rename: the document keeps its own name.
	if stringValue(spec.Name) != "hipaa-base" {
		t.Errorf("expected name hipaa-base, got %q", stringValue(spec.Name))
	}
	if stringValue(spec.Extends) != "builtin:strict" {
		t.Errorf("expected the leaf to keep its base, got %q", stringValue(spec.Extends))
	}

	child, err := Parse("hushspec: \"0.1.0\"\nname: c\nextends: \"builtin:library/healthcare/hipaa-base\"\n")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := Resolve(child, "", nil)
	if err != nil {
		t.Fatalf("resolve the library builtin: %v", err)
	}
	if resolved.Rules == nil || resolved.Rules.SecretPatterns == nil {
		t.Fatal("expected the resolved document to carry the library's rules")
	}
	if !slices.ContainsFunc(resolved.Rules.SecretPatterns.Patterns, func(p SecretPattern) bool {
		return p.Name == "medical_record_number"
	}) {
		t.Error("expected the HIPAA patterns in the resolved document")
	}
}

// Every name in the table loads, and the library is in it.
func TestBuiltinNamesAreAllLoadable(t *testing.T) {
	if len(BuiltinNames) <= 6 {
		t.Fatalf("expected the library alongside the presets, got %d names", len(BuiltinNames))
	}
	library := 0
	for _, name := range BuiltinNames {
		spec, ok := LoadBuiltin(name)
		if !ok || spec == nil {
			t.Fatalf("builtin %q does not load", name)
		}
		want := name[strings.LastIndex(name, "/")+1:]
		if stringValue(spec.Name) != want {
			t.Errorf("builtin %q: expected document name %q, got %q", name, want, stringValue(spec.Name))
		}
		if strings.HasPrefix(name, "library/") {
			library++
		}
	}
	if library != 8 {
		t.Errorf("expected the eight library policies, got %d", library)
	}
}

// TestBuiltinsPassValidation covers the embedded copies, the library included.
// TestBuiltInRulesetsPassValidation checks the six presets as they sit on disk;
// what an `extends: builtin:...` actually resolves to is what is embedded here.
func TestBuiltinsPassValidation(t *testing.T) {
	for _, name := range BuiltinNames {
		t.Run(name, func(t *testing.T) {
			spec, ok := LoadBuiltin(name)
			if !ok {
				t.Fatalf("builtin %q does not load", name)
			}
			if result := Validate(spec); !result.IsValid() {
				t.Errorf("builtin %q does not validate: %+v", name, result.Errors)
			}
		})
	}
}
