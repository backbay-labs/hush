package hushspec

import (
	"strings"
	"testing"
)

// TestES6NumberFormatting pins the ECMAScript Number::toString boundaries of
// spec/hushspec-canonical.md section 4.3. The hash vectors exercise whole
// floats and short fractions; the exponent boundaries at 1e21 and 1e-7 have no
// vector, and Go's own %v formatting disagrees with ECMAScript on every one of
// them.
func TestES6NumberFormatting(t *testing.T) {
	cases := []struct {
		value float64
		want  string
	}{
		{0, "0"},
		{negativeZero(), "0"},
		{10, "10"},
		{10.0, "10"},
		{-10.5, "-10.5"},
		{0.35, "0.35"},
		{0.7, "0.7"},
		{0.1, "0.1"},
		{1e16, "10000000000000000"},
		{1e20, "100000000000000000000"},
		{1e21, "1e+21"},
		{1.5e21, "1.5e+21"},
		{1e-6, "0.000001"},
		{1e-7, "1e-7"},
		{2.5e-8, "2.5e-8"},
		{1234.5678, "1234.5678"},
		{-1e-7, "-1e-7"},
	}
	for _, tc := range cases {
		got, err := es6Number(tc.value)
		if err != nil {
			t.Fatalf("es6Number(%v) failed: %v", tc.value, err)
		}
		if got != tc.want {
			t.Errorf("es6Number(%v) = %q, want %q", tc.value, got, tc.want)
		}
	}
}

func negativeZero() float64 {
	zero := 0.0
	return -zero
}

// TestUTF16KeyOrder covers the RFC 8785 section 3.2.3 ordering rule that Go's
// native string comparison gets wrong. An astral character encodes as a
// surrogate pair in D800..DFFF, so by UTF-16 code units U+1F600 sorts BEFORE
// U+FFFD -- while by code point, and by the UTF-8 byte order Go's own string
// comparison uses, U+FFFD comes first.
func TestUTF16KeyOrder(t *testing.T) {
	object := map[string]any{
		"\U0001F600": int64(4), // astral, surrogate pair D83D DE00
		"\uFFFD":     int64(5), // BMP, above the surrogate range
		"\u20AC":     int64(3), // euro sign
		"Z":          int64(1),
		"a":          int64(2),
	}
	var out strings.Builder
	if err := writeJCS(&out, object); err != nil {
		t.Fatalf("writeJCS failed: %v", err)
	}
	want := "{\"Z\":1,\"a\":2,\"\u20AC\":3,\"\U0001F600\":4,\"\uFFFD\":5}"
	if out.String() != want {
		t.Fatalf("UTF-16 key order mismatch\n  expected %q\n  actual   %q", want, out.String())
	}
}

// TestJCSStringEscapes pins the escape set of spec section 4.2 against
// encoding/json's defaults, which escape <, >, & and the line separators.
func TestJCSStringEscapes(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"plain", `"plain"`},
		{"quote\" backslash\\", `"quote\" backslash\\"`},
		{"\b\t\n\f\r", `"\b\t\n\f\r"`},
		{"\x00\x01\x1f", "\"\\u0000\\u0001\\u001f\""},
		{"<script>&</script>", `"<script>&</script>"`},
		{"line\u2028sep\u2029par", "\"line\u2028sep\u2029par\""},
		{"del\u007Fnbsp\u00A0", "\"del\u007Fnbsp\u00A0\""},
		{"slash/", `"slash/"`},
		{"astral\U0001F600", "\"astral\U0001F600\""},
	}
	for _, tc := range cases {
		var out strings.Builder
		writeJCSString(&out, tc.input)
		if out.String() != tc.want {
			t.Errorf("writeJCSString(%q) = %q, want %q", tc.input, out.String(), tc.want)
		}
	}
}

// TestCanonicalJSONRequiresResolvedDocument covers spec section 2.1: a
// document that still carries `extends` identifies a fragment, not the policy
// that is enforced, so canonicalizing it is refused rather than guessed at.
func TestCanonicalJSONRequiresResolvedDocument(t *testing.T) {
	spec, err := Parse("hushspec: \"0.1.0\"\nextends: \"builtin:default\"\n")
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if _, err := CanonicalJSON(spec); err == nil {
		t.Fatal("expected CanonicalJSON to refuse an unresolved document")
	}
	if _, err := ContentHash(spec); err == nil {
		t.Fatal("expected ContentHash to refuse an unresolved document")
	}

	if _, err := CanonicalJSON(nil); err == nil {
		t.Fatal("expected CanonicalJSON to refuse a nil document")
	}

	resolved, err := Resolve(spec, "", nil)
	if err != nil {
		t.Fatalf("failed to resolve: %v", err)
	}
	digest, err := ContentHash(resolved)
	if err != nil {
		t.Fatalf("ContentHash failed after resolution: %v", err)
	}
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
		t.Fatalf("content hash %q is not sha256:<64 hex>", digest)
	}
	if strings.ToLower(digest) != digest {
		t.Fatalf("content hash %q is not lowercase hex", digest)
	}
}

// TestCanonicalJSONNeverEmitsMergeStrategy covers spec section 3.1: the
// resolution fields carry a schema default but must never be materialized.
func TestCanonicalJSONNeverEmitsMergeStrategy(t *testing.T) {
	spec, err := Parse("hushspec: \"0.1.0\"\nmerge_strategy: deep_merge\nname: resolved\n")
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	canonical, err := CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalJSON failed: %v", err)
	}
	if strings.Contains(canonical, "merge_strategy") {
		t.Fatalf("canonical form leaked merge_strategy: %s", canonical)
	}
	if canonical != `{"hushspec":"0.1.0","name":"resolved"}` {
		t.Fatalf("unexpected canonical form: %s", canonical)
	}
}

// contextPolicy is a document whose only free-form value is the given
// literal, written where the schema constrains nothing.
func contextPolicy(literal string) string {
	return strings.Join([]string{
		"hushspec: \"0.1.0\"",
		"rules:",
		"  egress:",
		"    when:",
		"      context:",
		"        budget: " + literal,
		"",
	}, "\n")
}

// TestParseRefusesIntegerLiteralsBeyondTheSafeRange covers spec section 4.3:
// an integer literal an IEEE 754 double cannot hold exactly is refused, never
// silently rounded. The literal is the only place the bound can be applied,
// because gopkg.in/yaml.v3 hands one past uint64 over as a float64.
func TestParseRefusesIntegerLiteralsBeyondTheSafeRange(t *testing.T) {
	for _, literal := range []string{"9007199254740993", "18446744073709551617"} {
		if _, err := Parse(contextPolicy(literal)); err == nil {
			t.Fatalf("expected Parse to refuse the integer literal %s", literal)
		} else if !strings.Contains(err.Error(), "integer "+literal+" exceeds the safe range") {
			t.Fatalf("unexpected refusal for %s: %v", literal, err)
		}
	}

	spec, err := Parse(contextPolicy("9007199254740991"))
	if err != nil {
		t.Fatalf("failed to parse an integer inside the range: %v", err)
	}
	canonical, err := CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalJSON failed: %v", err)
	}
	if !strings.Contains(canonical, `"budget":9007199254740991`) {
		t.Fatalf("unexpected canonical form: %s", canonical)
	}
}

// TestCanonicalJSONLeavesFloatSyntaxUnbounded covers the other half of spec
// section 4.3: a number written in float syntax is emitted by the ECMAScript
// algorithm at any magnitude.
func TestCanonicalJSONLeavesFloatSyntaxUnbounded(t *testing.T) {
	spec, err := Parse(strings.Join([]string{
		"hushspec: \"0.1.0\"",
		"rules:",
		"  egress:",
		"    when:",
		"      context:",
		"        a: 1.0e+16",
		"        b: 1.0e+21",
		"        c: 1.5e+300",
		"        d: -0.0",
		"",
	}, "\n"))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	canonical, err := CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalJSON failed: %v", err)
	}
	const expected = `"context":{"a":10000000000000000,"b":1e+21,"c":1.5e+300,"d":0}`
	if !strings.Contains(canonical, expected) {
		t.Fatalf("unexpected canonical form: %s", canonical)
	}
}

// TestCanonicalJSONRefusesUnsafeInteger covers the serializer's own guard, for
// an integer a caller builds in memory rather than parses.
func TestCanonicalJSONRefusesUnsafeInteger(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Rules: &Rules{Egress: &EgressRule{
			When: &Condition{Context: map[string]any{"budget": int64(1) << 53}},
		}},
	}
	if _, err := CanonicalJSON(spec); err == nil {
		t.Fatal("expected CanonicalJSON to refuse an integer beyond 2^53-1")
	}
}

// TestPresentEmptyConditionStringsSurviveTheProjection covers spec sections
// 3.2 and 3.3: `timezone` and `capability` are optional strings, so a written
// "" is a present value the canonical form keeps, where an absent `timezone`
// takes its schema default. Both are refused by validation, which is what
// makes them distinguishable in the first place.
func TestPresentEmptyConditionStringsSurviveTheProjection(t *testing.T) {
	empty := ""
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Rules: &Rules{Egress: &EgressRule{
			When: &Condition{
				Capability: &empty,
				TimeWindow: &TimeWindowCondition{Start: "09:00", End: "17:00", Timezone: &empty},
			},
		}},
	}
	canonical, err := CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalJSON failed: %v", err)
	}
	for _, want := range []string{`"capability":""`, `"timezone":""`} {
		if !strings.Contains(canonical, want) {
			t.Fatalf("canonical form dropped %s: %s", want, canonical)
		}
	}

	absent := &HushSpec{
		HushSpecVersion: "0.1.0",
		Rules: &Rules{Egress: &EgressRule{
			When: &Condition{TimeWindow: &TimeWindowCondition{Start: "09:00", End: "17:00"}},
		}},
	}
	canonical, err = CanonicalJSON(absent)
	if err != nil {
		t.Fatalf("CanonicalJSON failed: %v", err)
	}
	if !strings.Contains(canonical, `"timezone":"UTC"`) {
		t.Fatalf("an absent timezone did not take its default: %s", canonical)
	}
}

// TestValidateRefusesPresentEmptyConditionStrings locks in that a written ""
// is a value, not an absence: the other three SDKs refuse both, and a document
// Go accepted here would carry a content hash no engine agrees to enforce.
func TestValidateRefusesPresentEmptyConditionStrings(t *testing.T) {
	cases := map[string]string{
		"capability": strings.Join([]string{
			"hushspec: \"0.1.0\"",
			"rules:",
			"  egress:",
			"    when:",
			"      capability: \"\"",
			"",
		}, "\n"),
		"time_window.timezone": strings.Join([]string{
			"hushspec: \"0.1.0\"",
			"rules:",
			"  egress:",
			"    when:",
			"      time_window:",
			"        start: \"09:00\"",
			"        end: \"17:00\"",
			"        timezone: \"\"",
			"",
		}, "\n"),
	}
	for field, document := range cases {
		spec, err := Parse(document)
		if err != nil {
			t.Fatalf("%s: failed to parse: %v", field, err)
		}
		result := Validate(spec)
		if result.IsValid() {
			t.Fatalf("%s: expected a present empty value to be invalid", field)
		}
		if !strings.Contains(result.Errors[0].Path, field) {
			t.Fatalf("%s: unexpected error path %q", field, result.Errors[0].Path)
		}
	}
}

// TestCanonicalJSONIsStableAcrossRuns guards against Go's randomized map
// iteration leaking into the output.
func TestCanonicalJSONIsStableAcrossRuns(t *testing.T) {
	spec, err := Parse(strings.Join([]string{
		"hushspec: \"0.1.0\"",
		"rules:",
		"  egress:",
		"    when:",
		"      context:",
		"        b: 2",
		"        a: 1",
		"        c: 3",
		"        d: 4",
		"        e: 5",
		"    allow: [\"api.example.com\"]",
		"",
	}, "\n"))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	first, err := CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalJSON failed: %v", err)
	}
	for i := 0; i < 50; i++ {
		again, err := CanonicalJSON(spec)
		if err != nil {
			t.Fatalf("CanonicalJSON failed: %v", err)
		}
		if again != first {
			t.Fatalf("canonical form is not stable:\n  %s\n  %s", first, again)
		}
	}
}
