package hushspec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestParseRefusalsCarryARegisteredCode: every refusal [Parse] returns is a
// *ValidationError whose Code is a registered identifier, reachable with
// errors.As rather than by matching on the message.
func TestParseRefusalsCarryARegisteredCode(t *testing.T) {
	cases := []struct {
		name     string
		document string
		want     string
	}{
		{"unknown top-level field", "hushspec: \"0.2.0\"\nnope: 1\n", ErrorCodeParse},
		{"missing version", "name: p\n", ErrorCodeParse},
		{"YAML profile violation", "hushspec: &a \"0.2.0\"\n", ErrorCodeParse},
		{
			"unknown enum variant",
			"hushspec: \"0.2.0\"\nrules:\n  egress:\n    default: maybe\n",
			ErrorCodeParse,
		},
		{
			"structural constraint",
			"hushspec: \"0.2.0\"\nmetadata:\n  controls:\n    - framework: \"SOC 2\"\n      control_id: cc1\n      rule_paths: [rules.egress]\n",
			ErrorCodeConstraint,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.document)
			if err == nil {
				t.Fatal("expected a refusal")
			}
			var validationError *ValidationError
			if !errors.As(err, &validationError) {
				t.Fatalf("a refusal must be a *ValidationError, got %T: %v", err, err)
			}
			if validationError.Code != tc.want {
				t.Errorf("expected %s, got %s: %s", tc.want, validationError.Code, validationError.Message)
			}
			code, ok := ErrorCodeOf(err)
			if !ok || code != tc.want {
				t.Errorf("ErrorCodeOf gave (%q, %v)", code, ok)
			}
			if !slices.Contains(ErrorCodes, code) {
				t.Errorf("%q is not a registered code", code)
			}
			// A refusal wrapped by a caller keeps its code.
			if code, ok := ErrorCodeOf(fmt.Errorf("while loading: %w", err)); !ok || code != tc.want {
				t.Errorf("a wrapped refusal lost its code: (%q, %v)", code, ok)
			}
		})
	}
}

// TestValidationErrorsCarryRegisteredCodes maps each condition onto the code
// the Rust reference reports for it.
func TestValidationErrorsCarryRegisteredCodes(t *testing.T) {
	cases := []struct {
		name     string
		document string
		want     string
		kind     string
	}{
		{
			"unsupported version", "hushspec: \"9.9.9\"\n",
			ErrorCodeUnsupportedVersion, "UNSUPPORTED_VERSION",
		},
		{
			"duplicate pattern name",
			"hushspec: \"0.2.0\"\nrules:\n  secret_patterns:\n    patterns:\n" +
				"      - {name: dup, pattern: \"a\", severity: warn}\n" +
				"      - {name: dup, pattern: \"b\", severity: warn}\n",
			ErrorCodeDuplicatePatternName, "DUPLICATE_PATTERN_NAME",
		},
		{
			"invalid regex",
			"hushspec: \"0.2.0\"\nrules:\n  shell_commands:\n    forbidden_patterns: [\"a(?i)b\"]\n",
			ErrorCodeInvalidRegex, "INVALID_REGEX",
		},
		{
			"invalid date",
			"hushspec: \"0.2.0\"\nmetadata:\n  expiry_date: \"2026-13-45\"\n",
			ErrorCodeInvalidDate, "INVALID_DATE",
		},
		{
			"constraint violation",
			"hushspec: \"0.2.0\"\nrules:\n  egress:\n    when:\n      time_window: {start: \"25:00\", end: \"06:00\"}\n",
			ErrorCodeConstraint, "INVALID_CONDITION",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := Parse(tc.document)
			if err != nil {
				t.Fatalf("the document should parse and fail validation: %v", err)
			}
			result := Validate(spec)
			if result.IsValid() {
				t.Fatal("expected a validation failure")
			}
			first := result.Errors[0]
			if first.Code != tc.want || first.Kind != tc.kind {
				t.Errorf("expected %s/%s, got %s/%s: %s",
					tc.want, tc.kind, first.Code, first.Kind, first.Message)
			}
		})
	}
}

// TestConditionRefusalsNameTheirPath: a condition diagnostic carries the
// document path it is about, so a caller need not parse the message for it.
func TestConditionRefusalsNameTheirPath(t *testing.T) {
	spec, err := Parse("hushspec: \"0.2.0\"\nrules:\n  egress:\n    when:\n      capability: Shell\n")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	result := Validate(spec)
	if result.IsValid() {
		t.Fatal("expected a validation failure")
	}
	if got := result.Errors[0].Path; got != "rules.egress.when.capability" {
		t.Errorf("expected the condition's path, got %q", got)
	}
}

// TestResolveAndInputFailuresCarryCodes: an unresolvable `extends` chain is
// E010 and an unreadable input is E000, so one helper reports a code for every
// refusal a loader can hit.
func TestResolveAndInputFailuresCarryCodes(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.yaml")
	if _, err := os.ReadFile(missing); err == nil {
		t.Fatal("the fixture path must not exist")
	} else if code, ok := ErrorCodeOf(err); !ok || code != ErrorCodeInput {
		t.Errorf("an unreadable input is E000, got (%q, %v)", code, ok)
	}

	spec, err := Parse("hushspec: \"0.2.0\"\nextends: \"builtin:does-not-exist\"\n")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	_, err = Resolve(spec, "memory", createCompositeLoader())
	if err == nil {
		t.Fatal("expected the chain to fail to resolve")
	}
	if code, ok := ErrorCodeOf(err); !ok || code != ErrorCodeExtends {
		t.Errorf("an unresolvable chain is E010, got (%q, %v): %v", code, ok, err)
	}
}

// TestNormalizeDecoderMessage keeps gopkg.in/yaml.v3's diagnostics in the
// vocabulary the other SDKs use, so one refusal reads the same in all four.
func TestNormalizeDecoderMessage(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"line 3: field nope not found in type hushspec.Rules",
			"line 3: unknown field `nope` in hushspec.Rules"},
		{"line 8: cannot unmarshal !!int `-1` into uint64",
			"line 8: invalid type: int `-1`, expected uint64"},
		{"line 2: cannot unmarshal !!map into string",
			"line 2: invalid type: map, expected string"},
		{`line 4: mapping key "name" already defined at line 3`,
			`line 4: duplicate entry with key "name" (already defined at line 3)`},
		{"line 1: did not find expected node content", "line 1: did not find expected node content"},
	}
	for _, tc := range cases {
		if got := normalizeDecoderMessage(tc.raw); got != tc.want {
			t.Errorf("normalizeDecoderMessage(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// TestValidationErrorTextNamesItsCode: the rendered error carries the code, so
// a log line a human reads and the code a program switches on agree.
func TestValidationErrorTextNamesItsCode(t *testing.T) {
	err := &ValidationError{Code: ErrorCodeConstraint, Path: "rules.egress.when", Message: "bad"}
	if got := err.Error(); !strings.HasPrefix(got, "E004: ") || !strings.Contains(got, "rules.egress.when") {
		t.Errorf("unexpected rendering %q", got)
	}
	// A message that already spells the path does not repeat it.
	err = &ValidationError{Code: ErrorCodeConstraint, Path: "rules.egress", Message: "rules.egress: bad"}
	if got := err.Error(); got != "E004: rules.egress: bad" {
		t.Errorf("unexpected rendering %q", got)
	}
}
