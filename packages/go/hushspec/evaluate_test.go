package hushspec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type evaluatorTestFixture struct {
	HushSpecTest string                     `yaml:"hushspec_test"`
	Description  string                     `yaml:"description"`
	Policy       map[string]any             `yaml:"policy"`
	Cases        []evaluatorTestFixtureCase `yaml:"cases"`
}

type evaluatorTestFixtureCase struct {
	Description string          `yaml:"description"`
	Action      map[string]any  `yaml:"action"`
	Context     *RuntimeContext `yaml:"context,omitempty"`
	// Controls is the evidence this case carries (evaluator-test 0.2). It is
	// reporting metadata: a conformance verdict does not depend on it.
	Controls []map[string]string `yaml:"controls,omitempty"`
	// Tags are free-form labels (evaluator-test 0.2).
	Tags   []string `yaml:"tags,omitempty"`
	Expect struct {
		Decision      string         `yaml:"decision"`
		MatchedRule   string         `yaml:"matched_rule,omitempty"`
		Reason        string         `yaml:"reason,omitempty"`
		OriginProfile string         `yaml:"origin_profile,omitempty"`
		Posture       *PostureResult `yaml:"posture,omitempty"`
		// RuleTrace is asserted in order and in full (evaluator-test 0.2).
		RuleTrace []ruleTraceExpectation `yaml:"rule_trace,omitempty"`
		// Receipt is a partial format 0.2 receipt (evaluator-test 0.2).
		Receipt map[string]any `yaml:"receipt,omitempty"`
	} `yaml:"expect"`
}

// ruleTraceExpectation is one expected `rule_trace` entry; `rule_path` is
// compared only where the fixture spells it.
type ruleTraceExpectation struct {
	RuleBlock string `yaml:"rule_block"`
	Outcome   string `yaml:"outcome"`
	RulePath  string `yaml:"rule_path,omitempty"`
}

// receiptIgnoredMembers are receipt members that are inputs rather than
// outcomes, and are never compared even when a fixture spells them.
var receiptIgnoredMembers = map[string]bool{
	"actor": true, "timestamp": true, "receipt_id": true,
}

// renderTraceEntry is `rule_block:outcome[@rule_path]`, the spelling a trace
// mismatch reports.
func renderTraceEntry(ruleBlock, outcome, rulePath string) string {
	if rulePath != "" {
		return fmt.Sprintf("%s:%s@%s", ruleBlock, outcome, rulePath)
	}
	return fmt.Sprintf("%s:%s", ruleBlock, outcome)
}

// assertRuleTrace compares expect.rule_trace with the recorded trace (receipt
// spec 4.3): in order, in full, and member by member.
func assertRuleTrace(t *testing.T, expected []ruleTraceExpectation, actual []RuleTraceEntry) {
	t.Helper()
	rendered := make([]string, 0, len(actual))
	for _, entry := range actual {
		rendered = append(rendered, renderTraceEntry(entry.RuleBlock, string(entry.Outcome), entry.RulePath))
	}
	if len(expected) != len(actual) {
		t.Errorf("rule_trace: expected %d entries, got %d [%s]",
			len(expected), len(actual), strings.Join(rendered, ", "))
		return
	}
	for index, want := range expected {
		got := actual[index]
		matches := want.RuleBlock == got.RuleBlock &&
			want.Outcome == string(got.Outcome) &&
			(want.RulePath == "" || want.RulePath == got.RulePath)
		if !matches {
			t.Errorf("rule_trace[%d]: expected %s, got %s", index,
				renderTraceEntry(want.RuleBlock, want.Outcome, want.RulePath), rendered[index])
		}
	}
}

// assertReceiptMembers compares a partial expect.receipt with the receipt
// produced under the fixed inputs: nested objects member-wise, everything
// else exactly. Both sides go through JSON first so a YAML integer and a JSON
// number are the same value.
func assertReceiptMembers(t *testing.T, expected map[string]any, receipt DecisionReceipt) {
	t.Helper()
	want, err := normalizeJSON(expected)
	if err != nil {
		t.Fatalf("expect.receipt is not JSON-encodable: %v", err)
	}
	got, err := normalizeJSON(receipt)
	if err != nil {
		t.Fatalf("the produced receipt is not JSON-encodable: %v", err)
	}
	wantMap, _ := want.(map[string]any)
	gotMap, _ := got.(map[string]any)
	for key, value := range wantMap {
		if receiptIgnoredMembers[key] {
			continue
		}
		compareReceiptMember(t, key, value, gotMap[key], gotMap != nil && hasKey(gotMap, key))
	}
}

func hasKey(object map[string]any, key string) bool {
	_, ok := object[key]
	return ok
}

func compareReceiptMember(t *testing.T, path string, want, got any, present bool) {
	t.Helper()
	if wantObject, ok := want.(map[string]any); ok {
		gotObject, ok := got.(map[string]any)
		if !ok {
			t.Errorf("receipt.%s: expected an object, got %#v", path, got)
			return
		}
		for key, value := range wantObject {
			compareReceiptMember(t, path+"."+key, value, gotObject[key], hasKey(gotObject, key))
		}
		return
	}
	if !present {
		t.Errorf("receipt.%s: expected %#v, got (absent)", path, want)
		return
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("receipt.%s: expected %#v, got %#v", path, want, got)
	}
}

// normalizeJSON round-trips a value through JSON so both sides of a receipt
// comparison use the same representation (numbers as float64, no typed nils).
func normalizeJSON(value any) (any, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func TestEvaluationFixtures(t *testing.T) {
	repoRoot := evaluatorRepoRoot(t)

	dirs := []string{
		"core/evaluation",
		"posture/evaluation",
		"origins/evaluation",
		"detection/evaluation",
	}

	for _, dir := range dirs {
		fixtureDir := filepath.Join(repoRoot, "fixtures", dir)
		entries, err := os.ReadDir(fixtureDir)
		if err != nil {
			t.Logf("skipping %s: %v", dir, err)
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml")) {
				continue
			}

			fixturePath := filepath.Join(fixtureDir, entry.Name())
			t.Run(filepath.Join(dir, entry.Name()), func(t *testing.T) {
				data, err := os.ReadFile(fixturePath)
				if err != nil {
					t.Fatalf("failed to read fixture %s: %v", fixturePath, err)
				}
				runEvaluationFixture(t, fixturePath, string(data))
			})
		}
	}
}

// runEvaluationFixture parses an evaluator fixture's embedded policy and
// asserts every case against the reference evaluator. It is shared with
// TestSharedFixtures so the CI job that runs only the shared-fixture test
// really evaluates rather than shape-checking.
func runEvaluationFixture(t *testing.T, fixturePath, source string) {
	t.Helper()

	var fixture evaluatorTestFixture
	if err := yaml.Unmarshal([]byte(source), &fixture); err != nil {
		t.Fatalf("failed to parse fixture %s: %v", fixturePath, err)
	}

	policyBytes, err := yaml.Marshal(fixture.Policy)
	if err != nil {
		t.Fatalf("failed to re-encode policy: %v", err)
	}
	spec, err := Parse(string(policyBytes))
	if err != nil {
		t.Fatalf("embedded policy failed to parse: %v", err)
	}
	// A fixture whose embedded policy extends is resolved before it runs: a
	// bare leaf would drop every block its base declares.
	if spec.Extends != "" {
		resolved, err := Resolve(spec, fixturePath, createCompositeLoader())
		if err != nil {
			t.Fatalf("embedded policy failed to resolve: %v", err)
		}
		spec = resolved
	}

	for i, tc := range fixture.Cases {
		t.Run(fmt.Sprintf("case_%d_%s", i, tc.Description), func(t *testing.T) {
			action := buildEvaluationAction(t, tc.Action)
			// The per-case `context` of the evaluator-test schema feeds the
			// `when` conditions of core spec 3.13.
			action.Context = tc.Context
			// Route through EvaluateWithDetection so fixtures that declare
			// a `detection:` extension exercise it; §1 of the detection-
			// wiring spec makes this an exact no-op for every fixture that
			// doesn't (i.e. every fixture outside detection/evaluation), so
			// pre-existing coverage is unaffected.
			result := EvaluateWithDetection(spec, action).Evaluation

			if string(result.Decision) != tc.Expect.Decision {
				t.Errorf("decision mismatch: got %q, want %q (action: %+v)",
					result.Decision, tc.Expect.Decision, tc.Action)
			}

			if tc.Expect.MatchedRule != "" && result.MatchedRule != tc.Expect.MatchedRule {
				t.Errorf("matched_rule mismatch: got %q, want %q",
					result.MatchedRule, tc.Expect.MatchedRule)
			}

			if tc.Expect.Reason != "" && result.Reason != tc.Expect.Reason {
				t.Errorf("reason mismatch: got %q, want %q", result.Reason, tc.Expect.Reason)
			}

			if tc.Expect.OriginProfile != "" && result.OriginProfile != tc.Expect.OriginProfile {
				t.Errorf("origin_profile mismatch: got %q, want %q",
					result.OriginProfile, tc.Expect.OriginProfile)
			}

			if tc.Expect.Posture != nil {
				if result.Posture == nil {
					t.Errorf("expected posture %+v, got nil", tc.Expect.Posture)
				} else {
					if result.Posture.Current != tc.Expect.Posture.Current {
						t.Errorf("posture.current mismatch: got %q, want %q",
							result.Posture.Current, tc.Expect.Posture.Current)
					}
					if result.Posture.Next != tc.Expect.Posture.Next {
						t.Errorf("posture.next mismatch: got %q, want %q",
							result.Posture.Next, tc.Expect.Posture.Next)
					}
				}
			}

			// rule_trace and receipt are asserted through the audited path,
			// because a receipt is where both are published (receipt spec
			// 4.3), under the fixed inputs of
			// fixtures/receipts/expected/README.md.
			if len(tc.Expect.RuleTrace) > 0 || len(tc.Expect.Receipt) > 0 {
				resolution, err := NewResolutionFromResolved(spec, "")
				if err != nil {
					t.Fatalf("expect.rule_trace/receipt needs a resolvable policy: %v", err)
				}
				receipt := EvaluateAudited(resolution, action, expectedReceiptConfig(),
					expectedReceiptContext(i))
				if len(tc.Expect.RuleTrace) > 0 {
					assertRuleTrace(t, tc.Expect.RuleTrace, receipt.RuleTrace)
				}
				if len(tc.Expect.Receipt) > 0 {
					assertReceiptMembers(t, tc.Expect.Receipt, receipt)
				}
			}
		})
	}
}

// TestEvaluateUnknownActionType locks in core spec 5: an action type the
// specification does not define denies, it does not fall through to allow.
func TestEvaluateUnknownActionType(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.2.0",
	}
	action := &EvaluationAction{Type: "unknown_action"}
	result := Evaluate(spec, action)
	if result.Decision != DecisionDeny {
		t.Errorf("expected deny for unknown action type, got %q", result.Decision)
	}
	if result.MatchedRule != UnknownActionTypeRule {
		t.Errorf("expected matched_rule %q, got %q", UnknownActionTypeRule, result.MatchedRule)
	}
	if result.Reason != "action type 'unknown_action' is unknown to the specification" {
		t.Errorf("unexpected reason: %q", result.Reason)
	}
}

// TestEvaluateCustomActionRequiresPostureCapability locks in core spec 5:
// `custom` is permitted only when the current posture state grants the `custom`
// capability.
func TestEvaluateCustomActionRequiresPostureCapability(t *testing.T) {
	withoutPosture := &HushSpec{HushSpecVersion: "0.2.0"}
	result := Evaluate(withoutPosture, &EvaluationAction{Type: "custom", Target: "anything"})
	if result.Decision != DecisionDeny || result.MatchedRule != UnknownActionTypeRule {
		t.Fatalf("expected a custom action without posture to deny, got %q / %q", result.Decision, result.MatchedRule)
	}

	withCapability, err := Parse(`
hushspec: "0.2.0"
extensions:
  posture:
    initial: open
    states:
      open:
        capabilities: [custom]
      locked:
        capabilities: []
    transitions: []
`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	open := "open"
	granted := Evaluate(withCapability, &EvaluationAction{
		Type:    "custom",
		Target:  "engine-defined",
		Posture: &PostureContext{Current: &open},
	})
	if granted.Decision != DecisionAllow {
		t.Fatalf("expected the custom capability to permit a custom action, got %q", granted.Decision)
	}
	locked := "locked"
	denied := Evaluate(withCapability, &EvaluationAction{
		Type:    "custom",
		Target:  "engine-defined",
		Posture: &PostureContext{Current: &locked},
	})
	if denied.Decision != DecisionDeny || denied.MatchedRule != "extensions.posture.states.locked.capabilities" {
		t.Fatalf("expected a posture without the custom capability to deny, got %q / %q",
			denied.Decision, denied.MatchedRule)
	}
}

func TestGlobMatches(t *testing.T) {
	tests := []struct {
		pattern string
		target  string
		match   bool
	}{
		{"*.com", "example.com", true},
		{"*.com", "sub.example.com", true}, // * matches any non-/ chars, including dots
		{"**/.ssh/**", "/home/user/.ssh/id_rsa", true},
		{"**/.ssh/**", "/home/user/.ssh/config", true},
		{"read_file", "read_file", true},
		{"read_file", "read_files", false},
		{"?oo", "foo", true},
		{"?oo", "fooo", false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_vs_%s", tt.pattern, tt.target), func(t *testing.T) {
			got := globMatches(tt.pattern, tt.target)
			if got != tt.match {
				t.Errorf("globMatches(%q, %q) = %v, want %v", tt.pattern, tt.target, got, tt.match)
			}
		})
	}
}

func TestImbalanceRatio(t *testing.T) {
	tests := []struct {
		add, del int
		expected float64
	}{
		{0, 0, 0.0},
		{0, 5, 5.0},
		{5, 0, 5.0},
		{10, 2, 5.0},
		{2, 10, 5.0},
		{4, 4, 1.0},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d_%d", tt.add, tt.del), func(t *testing.T) {
			got := imbalanceRatio(tt.add, tt.del)
			if got != tt.expected {
				t.Errorf("imbalanceRatio(%d, %d) = %f, want %f", tt.add, tt.del, got, tt.expected)
			}
		})
	}
}

func TestPatchStats(t *testing.T) {
	content := "--- a/file.rs\n+++ b/file.rs\n@@ -1,3 +1,5 @@\n fn main() {\n+    println!(\"hello\");\n+    println!(\"world\");\n }"
	stats := computePatchStats(content)
	if stats.additions != 2 {
		t.Errorf("expected 2 additions, got %d", stats.additions)
	}
	if stats.deletions != 0 {
		t.Errorf("expected 0 deletions, got %d", stats.deletions)
	}
}

func TestEvaluateEgressDisabledAllowsAction(t *testing.T) {
	spec, err := Parse(`
hushspec: "0.1.0"
rules:
  egress:
    enabled: false
    allow: []
    block: []
    default: block
`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	result := Evaluate(spec, &EvaluationAction{Type: "egress", Target: "blocked.example.com"})
	if result.Decision != DecisionAllow {
		t.Fatalf("expected disabled egress rule to allow, got %q (%s)", result.Decision, result.Reason)
	}
	if result.MatchedRule != "" {
		t.Fatalf("expected no matched rule for disabled egress, got %q", result.MatchedRule)
	}
}

func TestEvaluateToolAccessDisabledAllowsAction(t *testing.T) {
	spec, err := Parse(`
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: false
    block: ["deploy"]
    default: block
`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	result := Evaluate(spec, &EvaluationAction{Type: "tool_call", Target: "deploy"})
	if result.Decision != DecisionAllow {
		t.Fatalf("expected disabled tool_access rule to allow, got %q (%s)", result.Decision, result.Reason)
	}
}

func TestEvaluateForbiddenPathsDisabledAllowsAction(t *testing.T) {
	spec, err := Parse(`
hushspec: "0.1.0"
rules:
  forbidden_paths:
    enabled: false
    patterns: ["**/.ssh/**"]
`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	result := Evaluate(spec, &EvaluationAction{Type: "file_read", Target: "/tmp/.ssh/id_rsa"})
	if result.Decision != DecisionAllow {
		t.Fatalf("expected disabled forbidden_paths rule to allow, got %q (%s)", result.Decision, result.Reason)
	}
}

func TestEvaluatePatchIntegrityHonorsExplicitZeroLimits(t *testing.T) {
	spec, err := Parse(`
hushspec: "0.1.0"
rules:
  patch_integrity:
    enabled: true
    max_additions: 0
    max_deletions: 0
    forbidden_patterns: []
`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	patch := "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1,2 @@\n line1\n+line2\n"
	result := Evaluate(spec, &EvaluationAction{
		Type:    "patch_apply",
		Target:  "file.txt",
		Content: strPtr(patch),
	})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected explicit zero patch limits to deny additions, got %q (%s)", result.Decision, result.Reason)
	}
	if result.MatchedRule != "rules.patch_integrity.max_additions" {
		t.Fatalf("expected max_additions denial, got %q", result.MatchedRule)
	}
}

func TestOriginProfileToolAccessStillRespectsBaseBlocklist(t *testing.T) {
	spec, err := Parse(`
hushspec: "0.2.0"
rules:
  tool_access:
    enabled: true
    block: ["dangerous_tool"]
    require_confirmation: []
    default: allow
extensions:
  origins:
    default_behavior: deny
    profiles:
      - id: slack
        match:
          provider: slack
        tool_access:
          block: []
          require_confirmation: []
          default: allow
`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	result := Evaluate(spec, &EvaluationAction{
		Type:   "tool_call",
		Target: "dangerous_tool",
		Origin: &OriginContext{Provider: "slack"},
	})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected base blocklist to deny, got %q (%s)", result.Decision, result.Reason)
	}
	if result.MatchedRule != "rules.tool_access.block" {
		t.Fatalf("expected rules.tool_access.block, got %q", result.MatchedRule)
	}
}

// TestOriginProfileEgressCannotBypassBaseDefaultBlock locks in origins spec 4: an overlay
// `default: allow` cannot relax a base `default: block` -- the stricter of the
// two wins -- and the reported rule is the base's, since the base's `block` is
// what determined the effective value.
func TestOriginProfileEgressCannotBypassBaseDefaultBlock(t *testing.T) {
	spec, err := Parse(`
hushspec: "0.2.0"
rules:
  egress:
    enabled: true
    allow: ["api.safe.example.com"]
    block: []
    default: block
extensions:
  origins:
    default_behavior: deny
    profiles:
      - id: slack
        match:
          provider: slack
        egress:
          allow: []
          block: []
          default: allow
`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	result := Evaluate(spec, &EvaluationAction{
		Type:   "egress",
		Target: "evil.example.com",
		Origin: &OriginContext{Provider: "slack"},
	})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected base default block to deny, got %q (%s)", result.Decision, result.Reason)
	}
	if result.MatchedRule != "rules.egress.default" {
		t.Fatalf("expected base default match, got %q", result.MatchedRule)
	}
}

func TestForbiddenPathExceptionStillRespectsPathAllowlist(t *testing.T) {
	spec, err := Parse(`
hushspec: "0.1.0"
rules:
  forbidden_paths:
    enabled: true
    patterns: ["**/*.key"]
    exceptions: ["/workspace/allowed.key"]
  path_allowlist:
    enabled: true
    write: ["/workspace/reports/**"]
`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	result := Evaluate(spec, &EvaluationAction{
		Type:   "file_write",
		Target: "/workspace/allowed.key",
	})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected path allowlist to deny, got %q (%s)", result.Decision, result.Reason)
	}
	if result.MatchedRule != "rules.path_allowlist" {
		t.Fatalf("expected path allowlist match, got %q", result.MatchedRule)
	}
}

func TestInputInjectDeniesUnlistedType(t *testing.T) {
	spec, err := Parse(`
hushspec: "0.1.0"
rules:
  input_injection:
    enabled: true
    allowed_types: [keyboard]
`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	result := Evaluate(spec, &EvaluationAction{Type: "input_inject", Target: "mouse"})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected input injection deny, got %q (%s)", result.Decision, result.Reason)
	}
	if result.MatchedRule != "rules.input_injection.allowed_types" {
		t.Fatalf("expected allowed_types denial, got %q", result.MatchedRule)
	}
}

func TestComputerUseRespectsRemoteDesktopChannelBlocks(t *testing.T) {
	spec, err := Parse(`
hushspec: "0.1.0"
rules:
  computer_use:
    enabled: true
    mode: observe
    allowed_actions: [remote.clipboard]
  remote_desktop_channels:
    enabled: true
    clipboard: false
    file_transfer: false
    audio: true
    drive_mapping: false
`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	result := Evaluate(spec, &EvaluationAction{Type: "computer_use", Target: "remote.clipboard"})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected remote desktop rule to deny, got %q (%s)", result.Decision, result.Reason)
	}
	if result.MatchedRule != "rules.remote_desktop_channels.clipboard" {
		t.Fatalf("expected remote_desktop_channels match, got %q", result.MatchedRule)
	}
}

func buildEvaluationAction(t *testing.T, actionMap map[string]any) *EvaluationAction {
	t.Helper()
	jsonBytes, err := json.Marshal(actionMap)
	if err != nil {
		t.Fatalf("failed to marshal action map to JSON: %v", err)
	}

	var action EvaluationAction
	if err := json.Unmarshal(jsonBytes, &action); err != nil {
		t.Fatalf("failed to unmarshal action from JSON: %v", err)
	}
	return &action
}

func evaluatorRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	root := filepath.Clean(filepath.Join(wd, "../../.."))
	if _, err := os.Stat(filepath.Join(root, "fixtures")); err != nil {
		t.Fatalf("cannot find fixtures directory at %s: %v", root, err)
	}
	return root
}
