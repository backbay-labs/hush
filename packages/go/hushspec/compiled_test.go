package hushspec

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixedReceiptTime pins the receipt clock so two receipts of the same action
// differ only where the policy identity does.
var fixedReceiptTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const compiledParitySpec = `
hushspec: "0.1.0"
name: compiled-parity
rules:
  forbidden_paths:
    enabled: true
    patterns: ["**/.ssh/**", "/etc/shadow"]
    exceptions: ["**/.ssh/known_hosts"]
  path_allowlist:
    enabled: true
    read: ["src/**", "docs/**"]
    write: ["src/**"]
  secret_patterns:
    enabled: true
    skip_paths: ["tests/**"]
    patterns:
      - name: aws_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: todo_note
        pattern: "(?i)todo:\\s*secret"
        severity: warn
  shell_commands:
    enabled: true
    forbidden_patterns: ["rm[ \\t]+-rf[ \\t]+/"]
  egress:
    enabled: true
    allow: ["*.github.com", "api.example.com"]
    block: ["evil.example.com"]
    default: block
  tool_access:
    enabled: true
    allow: ["read_file", "write_file"]
    block: ["shell"]
`

func compiledParityActions() []*EvaluationAction {
	secret := "token AKIA0123456789ABCDEF here"
	note := "TODO: secret rotation"
	clean := "nothing to see"
	return []*EvaluationAction{
		{Type: "file_read", Target: "src/main.go"},
		{Type: "file_read", Target: "/home/a/.ssh/id_rsa"},
		{Type: "file_read", Target: "/home/a/.ssh/known_hosts"},
		{Type: "file_write", Target: "src/main.go", Content: &secret},
		{Type: "file_write", Target: "tests/fixture.go", Content: &secret},
		{Type: "file_write", Target: "src/notes.go", Content: &note},
		{Type: "egress", Target: "https://api.github.com/x"},
		{Type: "egress", Target: "evil.example.com", Content: &clean},
		{Type: "egress", Target: "unlisted.example.org"},
		{Type: "tool_call", Target: "read_file", Content: &clean},
		{Type: "tool_call", Target: "shell"},
		{Type: "shell_command", Target: "rm -rf /"},
		{Type: "shell_command", Target: "git status"},
		{Type: "unknown_action", Target: "whatever"},
	}
}

// TestCompiledPolicyMatchesFreeFunctions pins the contract compilation makes:
// compiling a policy changes nothing an enforcement point can observe.
func TestCompiledPolicyMatchesFreeFunctions(t *testing.T) {
	spec, err := Parse(compiledParitySpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	policy, err := CompilePolicy(spec)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	for _, action := range compiledParityActions() {
		want := EvaluateTraced(spec, action, nil, nil)
		got := policy.EvaluateTraced(action, nil, nil)
		if !evaluationResultsEqual(want.Result, got.Result) {
			t.Errorf("%s %q: result %+v, want %+v", action.Type, action.Target, got.Result, want.Result)
		}
		if len(want.Trace) != len(got.Trace) {
			t.Fatalf("%s %q: trace length %d, want %d", action.Type, action.Target, len(got.Trace), len(want.Trace))
		}
		for index := range want.Trace {
			if want.Trace[index] != got.Trace[index] {
				t.Errorf("%s %q: trace[%d] = %+v, want %+v",
					action.Type, action.Target, index, got.Trace[index], want.Trace[index])
			}
		}
	}
}

// TestCompilePolicyRejectsPatternOutsideProfile is the fail-closed half:
// compilation refuses a pattern the engine cannot evaluate, naming its rule
// path, while evaluation still denies on exactly that pattern.
func TestCompilePolicyRejectsPatternOutsideProfile(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Name:            strPtr("bad-pattern"),
		Rules: &Rules{
			SecretPatterns: &SecretPatternsRule{
				Enabled: true,
				Patterns: []SecretPattern{
					{Name: "lookahead", Pattern: "(?=secret)", Severity: SeverityCritical},
				},
			},
		},
	}

	policy, err := CompilePolicy(spec)
	if err == nil {
		t.Fatal("expected a compile error for a pattern outside the regex profile")
	}
	if policy != nil {
		t.Error("expected no policy alongside a compile error")
	}
	var compileErr *CompileError
	if !errors.As(err, &compileErr) {
		t.Fatalf("expected a *CompileError, got %T", err)
	}
	if compileErr.RulePath != "rules.secret_patterns.patterns.lookahead.pattern" {
		t.Errorf("rule path = %q", compileErr.RulePath)
	}
	if compileErr.Pattern != "(?=secret)" {
		t.Errorf("pattern = %q", compileErr.Pattern)
	}

	content := "secret"
	result := Evaluate(spec, &EvaluationAction{Type: "file_write", Target: "a.txt", Content: &content})
	if result.Decision != DecisionDeny {
		t.Fatalf("decision = %q, want deny", result.Decision)
	}
	if result.MatchedRule != "rules.secret_patterns.patterns.lookahead.pattern" {
		t.Errorf("matched_rule = %q", result.MatchedRule)
	}
	if !strings.HasPrefix(result.Reason, "secret pattern 'lookahead' is invalid:") {
		t.Errorf("reason = %q", result.Reason)
	}
}

func TestCompilePolicyRejectsNilSpec(t *testing.T) {
	if _, err := CompilePolicy(nil); err == nil {
		t.Fatal("expected an error compiling a nil document")
	}
}

// Core spec 2.3: compiling an unresolved document would drop every rule block
// its base contributes.
func TestCompilePolicyRejectsADocumentThatStillExtends(t *testing.T) {
	spec, err := Parse("hushspec: \"0.1.0\"\nextends: \"builtin:default\"\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err = CompilePolicy(spec)
	if err == nil || !strings.Contains(err.Error(), "builtin:default") {
		t.Fatalf("expected a refusal naming the unresolved reference, got %v", err)
	}
}

// TestCompiledPolicyConcurrentUse exercises the shared-policy path the race
// detector is there to police.
func TestCompiledPolicyConcurrentUse(t *testing.T) {
	spec, err := Parse(compiledParitySpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	policy, err := CompilePolicy(spec)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	actions := compiledParityActions()

	want := make([]EvaluationResult, len(actions))
	for index, action := range actions {
		want[index] = policy.Evaluate(action)
	}

	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for round := 0; round < 25; round++ {
				for index, action := range actions {
					if !evaluationResultsEqual(policy.Evaluate(action), want[index]) {
						t.Errorf("concurrent evaluation diverged for %s %q", action.Type, action.Target)
						return
					}
				}
				if _, err := policy.ContentHash(); err != nil {
					t.Errorf("content hash: %v", err)
					return
				}
			}
		}()
	}
	group.Wait()
}

// TestCompiledPolicyContentHashIsCached checks the receipt path reuses one hash
// rather than re-canonicalizing the document.
func TestCompiledPolicyContentHashIsCached(t *testing.T) {
	spec, err := Parse(compiledParitySpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	policy, err := CompilePolicy(spec)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	direct, err := ContentHash(spec)
	if err != nil {
		t.Fatalf("content hash: %v", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		got, err := policy.ContentHash()
		if err != nil {
			t.Fatalf("compiled content hash: %v", err)
		}
		if got != direct {
			t.Fatalf("content hash = %q, want %q", got, direct)
		}
	}
}

// TestCompiledEvaluateAuditedMatchesSpecReceipt pins the nil-resolution receipt
// against the one EvaluateAuditedSpec builds.
func TestCompiledEvaluateAuditedMatchesSpecReceipt(t *testing.T) {
	spec, err := Parse(compiledParitySpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	policy, err := CompilePolicy(spec)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	action := &EvaluationAction{Type: "egress", Target: "evil.example.com"}
	config := DefaultAuditConfig()
	config.RecordDuration = false
	ctx := &AuditContext{ReceiptID: "rcpt-fixed", Clock: func() time.Time { return fixedReceiptTime }}

	want, err := EvaluateAuditedSpec(spec, action, &config, ctx)
	if err != nil {
		t.Fatalf("audited spec: %v", err)
	}
	got := policy.EvaluateAudited(nil, action, &config, ctx)

	if got.Policy.ContentHash != want.Policy.ContentHash ||
		got.Policy.Name != want.Policy.Name ||
		got.Policy.SpecVersion != want.Policy.SpecVersion {
		t.Errorf("policy summary = %+v, want %+v", got.Policy, want.Policy)
	}
	if got.Decision != want.Decision || got.MatchedRule != want.MatchedRule || got.Reason != want.Reason {
		t.Errorf("decision = %q/%q/%q, want %q/%q/%q",
			got.Decision, got.MatchedRule, got.Reason, want.Decision, want.MatchedRule, want.Reason)
	}
	if len(got.RuleTrace) != len(want.RuleTrace) {
		t.Errorf("rule trace length = %d, want %d", len(got.RuleTrace), len(want.RuleTrace))
	}
}
