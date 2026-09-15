package hushspec

import (
	"fmt"
	"strings"
	"testing"
)

// TestNormalizePathIsLexical covers D6 (core 3.1, 3.14.1): NFC, `\` to `/`,
// collapsed separators, lexical `.`/`..` resolution, no trailing `/`. The
// cleaner is deliberately not filepath.Clean -- that is OS-specific and would
// leave `C:\proj\..\.env` untouched on Linux.
func TestNormalizePathIsLexical(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/proj/../.env", "/.env"},
		{`C:\proj\..\.env`, "C:/.env"},
		{"//data//x//", "/data/x"},
		{"/", "/"},
		{"/a/../../b", "/b"},
		{"../a", "../a"},
		{"./a/./b", "a/b"},
		{"/data/cafe\u0301/x", "/data/caf\u00e9/x"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := NormalizePath(tc.in); got != tc.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestPathGlobsFollowTheSpecTable covers the path-glob grammar of core spec
// 3.14.1: `?` and `*` never cross `/`, `**` spans whole segments, and `[` is
// a literal character rather than a character class.
func TestPathGlobsFollowTheSpecTable(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"**/.env", ".env", true},
		{"**/.env", "a/.env", true},
		{"**/.env", "/home/u/.env", true},
		{"/home/**", "/home/x/y", true},
		{"/home/**", "/home", false},
		{"/proj/**/secret.txt", "/proj/secret.txt", true},
		{"/tmp/*.log", "/tmp/a.log", true},
		{"/tmp/*.log", "/tmp/sub/a.log", false},
		{"/a?b", "/axb", true},
		{"/a?b", "/a/b", false},
		{"/logs/[old]/**", "/logs/[old]/a", true},
		{"/logs/[old]/**", "/logs/o/a", false},
	}
	for _, tc := range cases {
		if got := PathGlobMatches(tc.pattern, tc.path); got != tc.want {
			t.Errorf("PathGlobMatches(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

// TestNormalizeHost covers D5 (core 3.14.2): scheme, userinfo, path, query,
// port, and trailing dot are stripped, the host is lowercased, and non-ASCII
// labels are compared in IDNA A-label form.
func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		in   string
		want string // "" means nil (no usable host)
	}{
		{"API.EXAMPLE.COM:443", "api.example.com"},
		{"https://user:pw@api.example.com:8443/v1?x=1#f", "api.example.com"},
		{"api.example.com.", "api.example.com"},
		{"[::1]:8080", "[::1]"},
		{"[2001:DB8::1]", "[2001:db8::1]"},
		{"B\u00dcCHER.example", "xn--bcher-kva.example"},
		{"10.0.0.1", "10.0.0.1"},
		{"", ""},
		{"a..b", ""},
		{"bad host", ""},
		{"[not-ipv6", ""},
		{"host:port:more", ""},
	}
	for _, tc := range cases {
		got := NormalizeHost(tc.in)
		if tc.want == "" {
			if got != nil {
				t.Errorf("NormalizeHost(%q) = %q, want nil", tc.in, *got)
			}
			continue
		}
		if got == nil {
			t.Errorf("NormalizeHost(%q) = nil, want %q", tc.in, tc.want)
		} else if *got != tc.want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", tc.in, *got, tc.want)
		}
	}
}

// TestHostPatternsFollowTheSpecTable covers the host-glob grammar of core spec
// 3.14.2: `*` is exactly one label, `**` is one or more labels (so neither
// matches the apex), and a wildcard never matches an IP literal.
func TestHostPatternsFollowTheSpecTable(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "example.com", false},
		{"api-*.example.com", "api-1.example.com", true},
		{"**.example.com", "a.b.example.com", true},
		{"**.example.com", "example.com", false},
		{"b\u00fccher.example", "xn--bcher-kva.example", true},
		{"10.0.*.*", "10.0.0.1", false},
		{"10.0.0.1", "10.0.0.1", true},
		{"[::1]", "[::1]", true},
		{"**", "10.0.0.1", false},
		{"api.example.com.", "api.example.com", true},
	}
	for _, tc := range cases {
		if got := HostPatternMatches(tc.pattern, tc.host); got != tc.want {
			t.Errorf("HostPatternMatches(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

// TestPunycodeMatchesRFCExamples checks the in-tree RFC 3492 encoder against
// the canonical IDNA examples. The encoder is deliberately not
// golang.org/x/net/idna: that would apply UTS-46 mapping on top, which core
// spec 3.14.2 does not specify.
func TestPunycodeMatchesRFCExamples(t *testing.T) {
	cases := []struct{ in, want string }{
		{"b\u00fccher", "bcher-kva"},
		{"m\u00fcnchen", "mnchen-3ya"},
		{"\u00fc", "tda"},
	}
	for _, tc := range cases {
		got, ok := PunycodeEncode(tc.in)
		if !ok || got != tc.want {
			t.Errorf("PunycodeEncode(%q) = %q, %v; want %q, true", tc.in, got, ok, tc.want)
		}
	}
}

// TestVersionAcceptanceFollowsD14 covers core spec 2.2: an engine declaring
// support for minor X.Y accepts every X.Y.Z document.
func TestVersionAcceptanceFollowsD14(t *testing.T) {
	for _, version := range []string{"0.1.0", "0.1.1", "0.1.99", "0.2.0", "0.2.7"} {
		if !IsSupported(version) {
			t.Errorf("expected %q to be supported", version)
		}
	}
	for _, version := range []string{"0.3.0", "1.0.0", "0.1", "0.1.0.0", "0.1.x", "+0.1.0", "", "0.1.-1"} {
		if IsSupported(version) {
			t.Errorf("expected %q to be rejected", version)
		}
	}
	if Version != "0.2.0" {
		t.Errorf("expected engine version 0.2.0, got %q", Version)
	}
	if SupportedMinor("0.1.7") != "0.1" || SupportedMinor("0.2.7") != "0.2" {
		t.Error("expected SupportedMinor to report the X.Y minor of a supported version")
	}
}

func TestValidateAcceptsAnyPatchOfASupportedMinor(t *testing.T) {
	spec, err := Parse("hushspec: \"0.1.1\"\nrules:\n  egress:\n    default: block\n")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if result := Validate(spec); !result.IsValid() {
		t.Fatalf("expected 0.1.1 to validate, got %+v", result.Errors)
	}
}

// TestYAMLProfileRejections covers D17 (core 2.4): anchors, aliases, merge
// keys, multi-document streams, YAML 1.1 booleans in boolean-typed fields,
// duplicate keys, and tab indentation are all parse errors.
func TestYAMLProfileRejections(t *testing.T) {
	cases := []struct{ name, source string }{
		{"anchor", "hushspec: \"0.2.0\"\nrules:\n  forbidden_paths:\n    patterns: &secrets\n      - \"**/.env\"\n"},
		{"alias", "hushspec: \"0.2.0\"\nrules:\n  forbidden_paths:\n    patterns: &secrets\n      - \"**/.env\"\n    exceptions: *secrets\n"},
		{"merge-key", "hushspec: \"0.2.0\"\nrules:\n  egress:\n    <<: {default: block}\n"},
		{"multi-doc", "hushspec: \"0.2.0\"\nname: first\n---\nhushspec: \"0.2.0\"\nname: second\n"},
		{"bool-yes", "hushspec: \"0.2.0\"\nrules:\n  egress:\n    enabled: yes\n    default: block\n"},
		{"bool-off", "hushspec: \"0.2.0\"\nrules:\n  egress:\n    enabled: off\n    default: block\n"},
		{"nested-bool-on", "hushspec: \"0.2.0\"\nrules:\n  remote_desktop_channels:\n    clipboard: on\n"},
		{"duplicate-key", "hushspec: \"0.2.0\"\nname: first\nname: second\n"},
		{"tab-indent", "hushspec: \"0.2.0\"\nrules:\n\tegress:\n\t\tdefault: block\n"},
		{"oversized", "hushspec: \"0.2.0\"\nname: \"" + strings.Repeat("x", MaxDocumentBytes) + "\"\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.source); err == nil {
				t.Fatalf("expected %s to be rejected by the YAML profile", tc.name)
			}
		})
	}
}

// TestYAMLProfileAcceptsPlainDocuments guards against over-rejection: the
// profile must not flag `*`, `&`, or a YAML 1.1 boolean token in a position
// where it is an ordinary string.
func TestYAMLProfileAcceptsPlainDocuments(t *testing.T) {
	cases := []struct{ name, source string }{
		{"glob-and-ampersand", "hushspec: \"0.2.0\"\nname: a*b & c\nrules:\n  egress:\n    allow: [\"*.example.com\", \"**.x\"]\n    default: block\n"},
		{"leading-doc-marker", "---\nhushspec: \"0.2.0\"\n"},
		{"block-scalar", "hushspec: \"0.2.0\"\ndescription: |\n  * bullet\n  & ampersand\nname: \"*not-an-alias\"\n"},
		{"bool-token-as-string", "hushspec: \"0.2.0\"\nname: yes\ndescription: \"off\"\n"},
		{"bool-token-in-list", "hushspec: \"0.2.0\"\nrules:\n  tool_access:\n    allow: [yes, no, on]\n    default: block\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.source); err != nil {
				t.Fatalf("expected %s to parse, got %v", tc.name, err)
			}
		})
	}
}

// TestYAMLProfileBoundsNestingAndNodes covers the depth and node-count caps of
// core spec 2.4.
func TestYAMLProfileBoundsNestingAndNodes(t *testing.T) {
	var deep strings.Builder
	deep.WriteString("hushspec: \"0.2.0\"\nrules:\n  shell_commands:\n    when:\n")
	indent := 6
	for i := 0; i < 40; i++ {
		deep.WriteString(fmt.Sprintf("%snot:\n", strings.Repeat(" ", indent)))
		indent += 2
	}
	deep.WriteString(fmt.Sprintf("%scontext: {a: 1}\n", strings.Repeat(" ", indent)))
	if _, err := Parse(deep.String()); err == nil {
		t.Error("expected deeply nested document to be rejected")
	}

	var wide strings.Builder
	wide.WriteString("hushspec: \"0.2.0\"\nrules:\n  forbidden_paths:\n    patterns:\n")
	for i := 0; i < MaxDocumentNodeCount+10; i++ {
		wide.WriteString(fmt.Sprintf("      - \"/p%d\"\n", i))
	}
	if _, err := Parse(wide.String()); err == nil {
		t.Error("expected a document past the node-count cap to be rejected")
	}
}

// TestToolNamesMatchExactly covers D3 (core 3.7): tool names are compared as
// exact strings, so glob metacharacters are literal.
func TestToolNamesMatchExactly(t *testing.T) {
	spec, err := Parse(`
hushspec: "0.2.0"
rules:
  tool_access:
    block: ["danger_*"]
    default: allow
`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if result := Evaluate(spec, &EvaluationAction{Type: "tool_call", Target: "danger_zone"}); result.Decision != DecisionAllow {
		t.Errorf("expected danger_* not to glob-match danger_zone, got %q", result.Decision)
	}
	if result := Evaluate(spec, &EvaluationAction{Type: "tool_call", Target: "danger_*"}); result.Decision != DecisionDeny {
		t.Errorf("expected the literal name danger_* to be blocked, got %q", result.Decision)
	}
}

// TestNoEarlyReturnAggregatesEveryBlock covers D2 (core 6.1): an allowlist or
// exception match never short-circuits a later block, and the aggregate is the
// strictest decision of every block that ran.
func TestNoEarlyReturnAggregatesEveryBlock(t *testing.T) {
	spec, err := Parse(`
hushspec: "0.2.0"
rules:
  forbidden_paths:
    patterns: ["**/.env"]
    exceptions: ["/proj/allowed/**"]
  path_allowlist:
    enabled: true
    write: ["/proj/**"]
  secret_patterns:
    patterns:
      - name: aws
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	traced := EvaluateTraced(spec, &EvaluationAction{
		Type:    "file_write",
		Target:  "/proj/allowed/.env",
		Content: strPtr("AKIAABCDEFGHIJKLMNOP"),
	}, nil, nil)
	if traced.Result.Decision != DecisionDeny {
		t.Fatalf("expected the secret to deny past the forbidden-path exception, got %q", traced.Result.Decision)
	}
	if traced.Result.MatchedRule != "rules.secret_patterns.patterns.aws" {
		t.Fatalf("expected the secret pattern to be reported, got %q", traced.Result.MatchedRule)
	}

	want := []string{"forbidden_paths", "path_allowlist", "secret_patterns"}
	if len(traced.Trace) != len(want) {
		t.Fatalf("expected every applicable block in the trace, got %+v", traced.Trace)
	}
	for index, block := range want {
		if traced.Trace[index].RuleBlock != block {
			t.Errorf("trace[%d] = %q, want %q", index, traced.Trace[index].RuleBlock, block)
		}
		if !traced.Trace[index].Evaluated {
			t.Errorf("expected %q to have been evaluated", block)
		}
	}
}

// TestBrowserAndCodeActionsDispatch covers D13 (core 3.11, 3.12): the
// browser_action and code_exec action types reach their rule blocks.
func TestBrowserAndCodeActionsDispatch(t *testing.T) {
	spec, err := Parse(`
hushspec: "0.2.0"
rules:
  browser_automation:
    enabled: true
    allowed_domains: ["*.example.com"]
    allowed_verbs: [navigate]
  code_execution:
    enabled: true
    language_allowlist: [python]
    module_denylist: [subprocess]
    network_access: false
    max_execution_time_ms: 5000
`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	url := "https://other.org/"
	if result := Evaluate(spec, &EvaluationAction{Type: "browser_action", Target: "navigate", URL: &url}); result.Decision != DecisionDeny {
		t.Errorf("expected an off-allowlist destination to deny, got %q", result.Decision)
	}
	// A nil URL skips the destination check entirely.
	if result := Evaluate(spec, &EvaluationAction{Type: "browser_action", Target: "navigate"}); result.Decision != DecisionAllow {
		t.Errorf("expected a browser action without a url to allow, got %q", result.Decision)
	}

	network := true
	if result := Evaluate(spec, &EvaluationAction{Type: "code_exec", Target: "python", Network: &network}); result.Decision != DecisionDeny {
		t.Errorf("expected a network request to deny when network_access is false, got %q", result.Decision)
	}
	timeout := 6000
	if result := Evaluate(spec, &EvaluationAction{Type: "code_exec", Target: "python", TimeoutMs: &timeout}); result.Decision != DecisionDeny {
		t.Errorf("expected an over-limit timeout to deny, got %q", result.Decision)
	}
	if result := Evaluate(spec, &EvaluationAction{Type: "code_exec", Target: "python", Content: strPtr("subprocessing = 1")}); result.Decision != DecisionAllow {
		t.Errorf("expected a denied module name inside a longer identifier not to match, got %q", result.Decision)
	}
}

// TestPostureWithEmptyCapabilitiesDeniesEverything covers D11 (posture 3): a
// state that grants no capabilities permits nothing.
func TestPostureWithEmptyCapabilitiesDeniesEverything(t *testing.T) {
	spec, err := Parse(`
hushspec: "0.2.0"
rules:
  tool_access:
    default: allow
extensions:
  posture:
    initial: locked
    states:
      locked:
        capabilities: []
    transitions: []
`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	for _, actionType := range []string{"file_read", "file_write", "patch_apply", "shell_command", "tool_call", "egress"} {
		result := Evaluate(spec, &EvaluationAction{Type: actionType, Target: "anything"})
		if result.Decision != DecisionDeny {
			t.Errorf("expected %s to deny under an empty capability set, got %q", actionType, result.Decision)
		}
	}
}
