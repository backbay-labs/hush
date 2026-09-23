package hushspec

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// HushSpec regex profile (CompileProfileRegex) unit tests.
//
// The cases below are the shared profile case list; keep them in sync with
// crates/hushspec/src/regex_profile.rs,
// packages/hushspec/tests/regex-profile.test.ts and
// packages/python/tests/test_regex_profile.py, which must answer identically.

func profileMatches(t *testing.T, pattern, haystack string) bool {
	t.Helper()
	re, err := CompileProfileRegex(pattern)
	if err != nil {
		t.Fatalf("%q should compile: %v", pattern, err)
	}
	return re.MatchString(haystack)
}

func profileRejects(t *testing.T, pattern string) string {
	t.Helper()
	if _, err := CompileProfileRegex(pattern); err != nil {
		return err.Error()
	}
	t.Fatalf("%q should be rejected", pattern)
	return ""
}

func assertMatch(t *testing.T, pattern, haystack string, want bool) {
	t.Helper()
	if got := profileMatches(t, pattern, haystack); got != want {
		t.Fatalf("%q against %q: got %v, want %v", pattern, haystack, got, want)
	}
}

func assertRejectContains(t *testing.T, pattern, substring string) {
	t.Helper()
	if message := profileRejects(t, pattern); !strings.Contains(message, substring) {
		t.Fatalf("%q rejected with %q, expected it to contain %q", pattern, message, substring)
	}
}

func TestProfileDigitShorthandIsASCIIOnly(t *testing.T) {
	assertMatch(t, `key\d{3}`, "key123", true)
	// Arabic-Indic digits are digits to a Unicode-aware \d, but not to the
	// profile (and not to RE2's own ASCII \d either).
	assertMatch(t, `key\d{3}`, "key١٢٣", false)
}

func TestProfileWordShorthandIsASCIIOnly(t *testing.T) {
	assertMatch(t, `\w+`, "abc_123", true)
	assertMatch(t, `^\w$`, "é", false)
}

func TestProfileDollarIsEndOfTextOnly(t *testing.T) {
	assertMatch(t, `token$`, "token", true)
	assertMatch(t, `token$`, "token\n", false)
	assertMatch(t, `(?m)token$`, "token\nmore", true)
	// Only \n breaks a line: JavaScript's `m` flag would also break at \r,
	// U+2028 and U+2029, so the TypeScript SDK spells (?m) out.
	assertMatch(t, `(?m)token$`, "token\rmore", false)
	assertMatch(t, `(?m)^more`, "token\nmore", true)
	assertMatch(t, `(?m)^more`, "token\rmore", false)
}

func TestProfileWordBoundaryIsASCII(t *testing.T) {
	assertMatch(t, `\bfoo`, "éfoo", true)
	assertMatch(t, `\bfoo\b`, "éfoo", true)
	assertMatch(t, `\bfoo\b`, "foobar", false)
	assertMatch(t, `\Bfoo`, "barfoo", true)
}

func TestProfileDotExcludesOnlyNewline(t *testing.T) {
	assertMatch(t, `a.b`, "a\rb", true)
	assertMatch(t, `a.b`, "a\nb", false)
	assertMatch(t, `(?s)a.b`, "a\nb", true)
	// `.` consumes one code point, astral included.
	assertMatch(t, `^a.b$`, "a\U0001F600b", true)
}

func TestProfileSpaceShorthandIncludesVerticalTab(t *testing.T) {
	// RE2's own \s omits \v; the profile includes it.
	assertMatch(t, `a\sb`, "a\vb", true)
	assertMatch(t, `a\sb`, "a b", true)
	assertMatch(t, `a\sb`, "a\tb", true)
	assertMatch(t, `a\sb`, "a b", false)
	assertMatch(t, `a\Sb`, "a b", false)
	assertMatch(t, `a\Sb`, "axb", true)
}

func TestProfileInlineFlagsOnlyLeading(t *testing.T) {
	for _, pattern := range []string{"(?i)foobar", "(?is)foobar", "(?i)(?m)foobar"} {
		if _, err := CompileProfileRegex(pattern); err != nil {
			t.Fatalf("%q should compile: %v", pattern, err)
		}
	}
	// Go RE2 accepts all of these natively; the profile rejects them.
	assertRejectContains(t, "foo(?i)bar", "leading group")
	assertRejectContains(t, "(?i:foo)", "leading group")
	assertRejectContains(t, "foo(?-i)bar", "leading group")
	assertRejectContains(t, "(?i)foo(?s)bar", "leading group")
}

func TestProfileEscapedBackslashIsNotAShorthand(t *testing.T) {
	assertMatch(t, `\\d`, `\d`, true)
	assertMatch(t, `\\d`, "5", false)
}

func TestProfileShorthandsInsideCharacterClasses(t *testing.T) {
	assertMatch(t, `[\d_]+`, "_1", true)
	assertMatch(t, `^[\d_]+$`, "١", false)
	assertMatch(t, `[\w-]+`, "a-b_1", true)
	assertMatch(t, `a[\s]b`, "a\vb", true)
}

func TestProfileEscapedBracketStaysLiteral(t *testing.T) {
	assertMatch(t, `[\]]`, "]", true)
	assertMatch(t, `a\[b`, "a[b", true)
}

func TestProfileRejectsNegatedShorthandsInsideClasses(t *testing.T) {
	assertRejectContains(t, `[\D]`, "character class")
	assertRejectContains(t, `[\W]`, "character class")
	assertRejectContains(t, `[a\S]`, "character class")
	assertRejectContains(t, `[\b]`, "character class")
	assertRejectContains(t, `[\B]`, "character class")
}

func TestProfileRejectsNonPortableEscapes(t *testing.T) {
	// \Q...\E and \p{...} are Go-only among the four SDK engines.
	assertRejectContains(t, `\Qa.b\E`, `\Q`)
	assertRejectContains(t, `\Afoo`, "anchor with")
	// \Z / \z are caught by the shared RE2 portability pre-check.
	assertRejectContains(t, `foo\Z`, "not portable")
	assertRejectContains(t, `foo\z`, "not portable")
	assertRejectContains(t, `\p{L}`, "Unicode property")
	assertRejectContains(t, `\P{L}`, "Unicode property")
	assertRejectContains(t, "\\u00a0", "profile escape")
	assertRejectContains(t, `\a`, "profile escape")
	assertRejectContains(t, `\0`, "profile escape")
	assertRejectContains(t, `a\x{41}`, "two hex digits")
	assertRejectContains(t, `foo\`, "trailing backslash")
	assertRejectContains(t, "\\é", "non-ASCII")
}

func TestProfileSupportedEscapesSurvive(t *testing.T) {
	assertMatch(t, `a\x41b`, "aAb", true)
	assertMatch(t, `a\tb`, "a\tb", true)
	assertMatch(t, `a\vb`, "a\vb", true)
	assertMatch(t, `a\.b`, "a.b", true)
	assertMatch(t, `a\.b`, "axb", false)
	assertMatch(t, `a\-b`, "a-b", true)
}

func TestProfileRejectsEmptyCharacterClasses(t *testing.T) {
	assertRejectContains(t, "[]", "empty character class")
	assertRejectContains(t, "[^]", "empty character class")
}

func TestProfileNormalizesJavaScriptNamedGroups(t *testing.T) {
	assertMatch(t, `(?<year>[0-9]{4})`, "in 2026", true)
	assertMatch(t, `(?P<year>[0-9]{4})`, "in 2026", true)
}

func TestProfileRejectsNonIdentifierGroupNames(t *testing.T) {
	assertRejectContains(t, `(?<1st>x)`, "named group's name")
	assertRejectContains(t, `(?<année>x)`, "named group's name")
	assertRejectContains(t, `(?<year x)`, "named group's name")
}

func TestProfileRejectsNonProfileGroupOpeners(t *testing.T) {
	for _, pattern := range []string{
		"a(?#comment)b",
		"a(?=b)",
		"a(?!b)",
		"(?<=a)b",
		"(?<!a)b",
		"(?>a)",
		"(?(1)a|b)",
		"(?R)",
		"(?1)",
		"(?P<a>x)(?P=a)",
	} {
		assertRejectContains(t, pattern, "group form")
	}
	if _, err := CompileProfileRegex("(?:ab)+"); err != nil {
		t.Fatalf("(?:ab)+ should compile: %v", err)
	}
}

func TestProfileRejectsPOSIXBracketExpressions(t *testing.T) {
	assertRejectContains(t, "[[:alpha:]]", "unescaped [")
	assertRejectContains(t, "[a[b]", "unescaped [")
	assertMatch(t, `[a\[]`, "[", true)
}

func TestProfileRejectsOpenLowerBoundQuantifier(t *testing.T) {
	assertRejectContains(t, "a{,3}", "{,n} quantifier")
	if _, err := CompileProfileRegex("a{0,3}"); err != nil {
		t.Fatalf("a{0,3} should compile: %v", err)
	}
}

func TestProfileRejectsOverLongPatterns(t *testing.T) {
	assertRejectContains(t, strings.Repeat("a", 2049), "2048 bytes")
	if _, err := CompileProfileRegex(strings.Repeat("a", 2048)); err != nil {
		t.Fatalf("a 2048-byte pattern should compile: %v", err)
	}
}

func TestProfileClassRangesStayInsideTheBMP(t *testing.T) {
	assertRejectContains(t, "[\U0001F600-\U0001F64F]", "Basic Multilingual Plane")
	assertMatch(t, "^[\U0001F600a]$", "\U0001F600", true)
	assertMatch(t, "^[\U0001F600a]$", "a", true)
	assertMatch(t, "^[^\U0001F600]$", "\U0001F600", false)
	assertMatch(t, "^[^\U0001F600]$", "a", true)
}

func TestProfileCaseInsensitiveFoldsASCIIOnly(t *testing.T) {
	assertMatch(t, "(?i)stra", "STRA", true)
	assertMatch(t, "(?i)stra", "Stra", true)
	// U+017F (long s) and U+212A (Kelvin sign) simple-case-fold to ASCII under
	// the full Unicode table, which RE2's own (?i) applies; the profile folds
	// ASCII only.
	assertMatch(t, "(?i)s", "ſ", false)
	assertMatch(t, "(?i)k", "K", false)
}

func TestProfileCaseInsensitiveFoldsClassMembersAndRanges(t *testing.T) {
	assertMatch(t, "(?i)^[a-f]$", "C", true)
	assertMatch(t, "(?i)^[a-f]$", "G", false)
	assertMatch(t, "(?i)^[sq]$", "S", true)
	assertMatch(t, "(?i)^[sq]$", "ſ", false)
	assertMatch(t, "(?i)^[^s]$", "S", false)
	assertMatch(t, "(?i)^[^s]$", "ſ", true)
	assertMatch(t, `(?i)\x41`, "a", true)
	assertMatch(t, `(?i)\x61`, "A", true)
}

func TestProfileLibraryPatternsStillMatch(t *testing.T) {
	assertMatch(t, `\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`, "ssn 123-45-6789.", true)
	assertMatch(t, `(AKIA|ASIA)[0-9A-Z]{16}`, "AKIA1234567890ABCDEF", true)
	assertMatch(
		t,
		`(?i)\b(mrn|medical[ \t\n\r\f_-]?record)[ \t\n\r\f]*:?[ \t\n\r\f]*[A-Z0-9]{6,15}\b`,
		"MRN: AB12345",
		true,
	)
}

func TestProfileRejectsRE2UnsafePatterns(t *testing.T) {
	assertRejectContains(t, "(a+)+", "nested unbounded quantifier")
	assertRejectContains(t, "(?=foo)bar", "group form")
	assertRejectContains(t, `(foo)\1`, "profile escape")
	assertRejectContains(t, "a*+", "possessive")
}

// TestRegexDialectFixtureEvaluates runs fixtures/core/evaluation/
// regex-dialect.test.yaml through Evaluate. The shared fixture runner in
// fixtures_test.go only parses and validates each evaluator fixture, so this
// test asserts the engine's decisions on the regex-profile fixture directly.
func TestRegexDialectFixtureEvaluates(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test file path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "../../.."))
	fixturePath := filepath.Join(repoRoot, "fixtures", "core", "evaluation", "regex-dialect.test.yaml")

	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", fixturePath, err)
	}

	var fixture struct {
		Policy map[string]any `yaml:"policy"`
		Cases  []struct {
			Description string           `yaml:"description"`
			Action      EvaluationAction `yaml:"action"`
			Expect      struct {
				Decision    string `yaml:"decision"`
				MatchedRule string `yaml:"matched_rule"`
			} `yaml:"expect"`
		} `yaml:"cases"`
	}
	if err := yaml.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("failed to parse %s: %v", fixturePath, err)
	}

	policyBytes, err := yaml.Marshal(fixture.Policy)
	if err != nil {
		t.Fatalf("failed to re-encode policy: %v", err)
	}
	spec, err := Parse(string(policyBytes))
	if err != nil {
		t.Fatalf("embedded policy failed to parse: %v", err)
	}
	if result := Validate(spec); !result.IsValid() {
		t.Fatalf("embedded policy failed validation: %+v", result.Errors)
	}

	for index, testCase := range fixture.Cases {
		action := testCase.Action
		result := Evaluate(spec, &action)
		if string(result.Decision) != testCase.Expect.Decision {
			t.Fatalf("cases[%d] %q: decision %q, want %q",
				index, testCase.Description, result.Decision, testCase.Expect.Decision)
		}
		if testCase.Expect.MatchedRule != "" && result.MatchedRule != testCase.Expect.MatchedRule {
			t.Fatalf("cases[%d] %q: matched_rule %q, want %q",
				index, testCase.Description, result.MatchedRule, testCase.Expect.MatchedRule)
		}
	}
}
