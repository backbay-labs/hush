package hushspec

import (
	"encoding/json"
	"strings"
	"testing"
)

// A posture whose transition table is empty. `transitions` is a required
// property (core spec 9.1), so an empty one is a present-but-empty container,
// not an absent key.
const emptyTransitionsPolicy = `hushspec: "0.2.0"
name: empty-required-collection
extensions:
  posture:
    initial: standard
    states:
      standard:
        capabilities: ["tool_call"]
    transitions: []
`

// TestRequiredCollectionsRoundTripWhenEmpty pins the wire shape of the
// collections the model marks as always emitted -- `extensions.posture.states`
// and `.transitions` (core spec 9.1) and `metadata.controls[].rule_paths`
// (core spec 2.5). Rust, TypeScript and Python serialize those whether or not
// they hold anything; Go would drop them with an `omitempty` tag, and would
// write a nil slice as JSON `null` even without one, so the generated tags
// carry no `omitempty` and Parse fills a nil collection in.
func TestRequiredCollectionsRoundTripWhenEmpty(t *testing.T) {
	spec := mustParse(t, emptyTransitionsPolicy)
	posture := spec.Extensions.Posture
	if posture.Transitions == nil {
		t.Fatal("expected an empty transition table to decode as an empty slice, not nil")
	}

	yamlOut, err := Marshal(spec)
	if err != nil {
		t.Fatalf("failed to marshal the parsed policy: %v", err)
	}
	if !strings.Contains(yamlOut, "transitions: []") {
		t.Fatalf("expected an empty `transitions` in the YAML output, got:\n%s", yamlOut)
	}

	jsonOut, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("failed to marshal the parsed policy as JSON: %v", err)
	}
	if !strings.Contains(string(jsonOut), `"transitions":[]`) {
		t.Fatalf("expected an empty `transitions` in the JSON output, got:\n%s", jsonOut)
	}

	// The second pass proves the field survives the trip rather than merely
	// appearing once: what Marshal writes, Parse reads back the same way.
	again := mustParse(t, yamlOut)
	if again.Extensions.Posture.Transitions == nil {
		t.Fatal("expected `transitions` to survive a YAML round trip as an empty slice")
	}
	if len(again.Extensions.Posture.Transitions) != 0 {
		t.Fatalf("expected an empty transition table, got %d entries",
			len(again.Extensions.Posture.Transitions))
	}
}

// TestParseFillsAbsentRequiredCollections covers the decoder side: a required
// collection the document omits decodes to nil in Go, which serializes as
// `null` rather than as an empty container. Parse fills it the way the Python
// model's `from_dict` does, so absent and empty reach the wire identically in
// all four SDKs.
func TestParseFillsAbsentRequiredCollections(t *testing.T) {
	spec := mustParse(t, `hushspec: "0.2.0"
name: absent-states
extensions:
  posture:
    initial: standard
    transitions: []
`)
	if spec.Extensions.Posture.States == nil {
		t.Fatal("expected an absent `states` to decode as an empty map, not nil")
	}
	yamlOut, err := Marshal(spec)
	if err != nil {
		t.Fatalf("failed to marshal the parsed policy: %v", err)
	}
	if !strings.Contains(yamlOut, "states: {}") {
		t.Fatalf("expected an empty `states` in the YAML output, got:\n%s", yamlOut)
	}
}

// TestANullRequiredCollectionIsRefused draws the line the fill stops at. A
// present-but-null `transitions:` decodes to a nil slice without failing the
// typed decode, so filling it would have Go accept -- and hash, as
// `"transitions":[]` -- a document Rust, TypeScript and Python all refuse at
// parse. Filling an absent-in-the-Go-model collection is a serialization
// detail; inventing a value the author did not write is not.
func TestANullRequiredCollectionIsRefused(t *testing.T) {
	_, err := Parse(`hushspec: "0.2.0"
name: null-transitions
extensions:
  posture:
    initial: standard
    states:
      standard: {}
    transitions:
`)
	if err == nil {
		t.Fatal("a null `transitions` was accepted; the other SDKs refuse it")
	}
	if !strings.Contains(err.Error(), "transitions must be an array") {
		t.Errorf("error = %v, want it to name `transitions`", err)
	}
}

// TestControlMappingAlwaysEmitsRulePaths pins the same tag rule on the other
// always-emitted collection. A control mapping with no rule paths is refused
// by validation, so the shape is asserted on the struct directly.
func TestControlMappingAlwaysEmitsRulePaths(t *testing.T) {
	mapping := ControlMapping{Framework: "soc2-tsc-2017", ControlID: "CC6.1", RulePaths: []string{}}
	encoded, err := json.Marshal(mapping)
	if err != nil {
		t.Fatalf("failed to marshal a control mapping: %v", err)
	}
	if !strings.Contains(string(encoded), `"rule_paths":[]`) {
		t.Fatalf("expected `rule_paths` in the JSON output, got: %s", encoded)
	}

	mapping.RulePaths = nil
	mapping.initEmptyCollections()
	if mapping.RulePaths == nil {
		t.Fatal("expected initEmptyCollections to fill a nil rule_paths")
	}
}
