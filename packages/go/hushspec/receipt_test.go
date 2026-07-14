package hushspec

import (
	"regexp"
	"testing"
)

var (
	uuidRE   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	isoRE    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`)
	sha256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func minimalSpec() *HushSpec {
	return &HushSpec{
		HushSpecVersion: "0.1.0",
		Name:            "test-policy",
	}
}

func specWithToolAccess() *HushSpec {
	return &HushSpec{
		HushSpecVersion: "0.1.0",
		Name:            "tool-policy",
		Rules: &Rules{
			ToolAccess: &ToolAccessRule{
				Enabled: true,
				Allow:   []string{"read_file", "write_file"},
				Block:   []string{"dangerous_tool"},
				Default: DefaultActionBlock,
			},
		},
	}
}

func enabledConfig() *AuditConfig {
	c := DefaultAuditConfig()
	return &c
}

func disabledConfig() *AuditConfig {
	return &AuditConfig{
		Enabled:          false,
		IncludeRuleTrace: false,
		RedactContent:    true,
	}
}

func TestEvaluateAuditedDecisionParity(t *testing.T) {
	spec := specWithToolAccess()
	action := &EvaluationAction{Type: "tool_call", Target: "read_file"}
	receipt := EvaluateAudited(spec, action, enabledConfig())
	result := Evaluate(spec, action)

	if receipt.Decision != result.Decision {
		t.Errorf("decision mismatch: receipt=%q, evaluate=%q", receipt.Decision, result.Decision)
	}
	if receipt.Decision != DecisionAllow {
		t.Errorf("expected allow, got %q", receipt.Decision)
	}
}

func TestEvaluateAuditedDenyParity(t *testing.T) {
	spec := specWithToolAccess()
	action := &EvaluationAction{Type: "tool_call", Target: "dangerous_tool"}
	receipt := EvaluateAudited(spec, action, enabledConfig())
	result := Evaluate(spec, action)

	if receipt.Decision != result.Decision {
		t.Errorf("decision mismatch: receipt=%q, evaluate=%q", receipt.Decision, result.Decision)
	}
	if receipt.Decision != DecisionDeny {
		t.Errorf("expected deny, got %q", receipt.Decision)
	}
	if receipt.MatchedRule != result.MatchedRule {
		t.Errorf("matched_rule mismatch: receipt=%q, evaluate=%q", receipt.MatchedRule, result.MatchedRule)
	}
}

func TestReceiptHasValidUUID(t *testing.T) {
	spec := minimalSpec()
	action := &EvaluationAction{Type: "tool_call", Target: "test"}
	receipt := EvaluateAudited(spec, action, enabledConfig())

	if !uuidRE.MatchString(receipt.ReceiptID) {
		t.Errorf("receipt_id %q does not match UUID pattern", receipt.ReceiptID)
	}
}

func TestReceiptHasValidTimestamp(t *testing.T) {
	spec := minimalSpec()
	action := &EvaluationAction{Type: "tool_call", Target: "test"}
	receipt := EvaluateAudited(spec, action, enabledConfig())

	if !isoRE.MatchString(receipt.Timestamp) {
		t.Errorf("timestamp %q does not match ISO 8601 pattern", receipt.Timestamp)
	}
}

func TestReceiptSetsHushSpecVersion(t *testing.T) {
	spec := minimalSpec()
	action := &EvaluationAction{Type: "tool_call", Target: "test"}
	receipt := EvaluateAudited(spec, action, enabledConfig())

	if receipt.HushSpecVersion != Version {
		t.Errorf("expected hushspec_version %q, got %q", Version, receipt.HushSpecVersion)
	}
}

func TestRuleTracePopulatedWhenEnabled(t *testing.T) {
	spec := specWithToolAccess()
	action := &EvaluationAction{Type: "tool_call", Target: "read_file"}
	receipt := EvaluateAudited(spec, action, enabledConfig())

	if len(receipt.RuleTrace) == 0 {
		t.Fatal("expected non-empty rule trace")
	}
	if receipt.RuleTrace[0].RuleBlock != "tool_access" {
		t.Errorf("expected first trace block to be tool_access, got %q", receipt.RuleTrace[0].RuleBlock)
	}
	if !receipt.RuleTrace[0].Evaluated {
		t.Error("expected first trace to be evaluated")
	}
}

func TestEmptyTraceWhenDisabled(t *testing.T) {
	spec := specWithToolAccess()
	action := &EvaluationAction{Type: "tool_call", Target: "read_file"}
	receipt := EvaluateAudited(spec, action, disabledConfig())

	if len(receipt.RuleTrace) != 0 {
		t.Errorf("expected empty trace, got %d entries", len(receipt.RuleTrace))
	}
	if receipt.EvaluationDurationUs != 0 {
		t.Errorf("expected zero duration, got %d", receipt.EvaluationDurationUs)
	}
}

func TestEmptyPolicyHashWhenDisabled(t *testing.T) {
	spec := specWithToolAccess()
	action := &EvaluationAction{Type: "tool_call", Target: "read_file"}
	receipt := EvaluateAudited(spec, action, disabledConfig())

	if receipt.Policy.ContentHash != "" {
		t.Errorf("expected empty content_hash, got %q", receipt.Policy.ContentHash)
	}
}

func TestContentRedactedWhenContentPresent(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Rules: &Rules{
			ShellCommands: &ShellCommandsRule{
				Enabled:           true,
				ForbiddenPatterns: []string{},
			},
		},
	}
	action := &EvaluationAction{
		Type:    "shell_command",
		Target:  "echo hello",
		Content: "some content here",
	}
	receipt := EvaluateAudited(spec, action, enabledConfig())

	if !receipt.Action.ContentRedacted {
		t.Error("expected content_redacted to be true")
	}
}

func TestContentNotRedactedWhenNoContent(t *testing.T) {
	spec := minimalSpec()
	action := &EvaluationAction{Type: "tool_call", Target: "test"}
	receipt := EvaluateAudited(spec, action, enabledConfig())

	if receipt.Action.ContentRedacted {
		t.Error("expected content_redacted to be false")
	}
}

func TestNonNegativeDurationWhenEnabled(t *testing.T) {
	spec := specWithToolAccess()
	action := &EvaluationAction{Type: "tool_call", Target: "read_file"}
	receipt := EvaluateAudited(spec, action, enabledConfig())

	if receipt.EvaluationDurationUs < 0 {
		t.Errorf("expected non-negative duration, got %d", receipt.EvaluationDurationUs)
	}
}

func TestUniqueReceiptIDs(t *testing.T) {
	spec := minimalSpec()
	action := &EvaluationAction{Type: "tool_call", Target: "test"}
	r1 := EvaluateAudited(spec, action, enabledConfig())
	r2 := EvaluateAudited(spec, action, enabledConfig())

	if r1.ReceiptID == r2.ReceiptID {
		t.Error("expected unique receipt IDs")
	}
}

func TestActionSummaryFields(t *testing.T) {
	spec := minimalSpec()
	action := &EvaluationAction{Type: "egress", Target: "api.example.com"}
	receipt := EvaluateAudited(spec, action, enabledConfig())

	if receipt.Action.Type != "egress" {
		t.Errorf("expected action type egress, got %q", receipt.Action.Type)
	}
	if receipt.Action.Target != "api.example.com" {
		t.Errorf("expected target api.example.com, got %q", receipt.Action.Target)
	}
}

func TestPolicyNameFromSpec(t *testing.T) {
	spec := minimalSpec()
	action := &EvaluationAction{Type: "tool_call", Target: "test"}
	receipt := EvaluateAudited(spec, action, enabledConfig())

	if receipt.Policy.Name != "test-policy" {
		t.Errorf("expected policy name test-policy, got %q", receipt.Policy.Name)
	}
	if receipt.Policy.Version != "0.1.0" {
		t.Errorf("expected policy version 0.1.0, got %q", receipt.Policy.Version)
	}
}

func TestComputePolicyHashValid(t *testing.T) {
	spec := minimalSpec()
	hash := ComputePolicyHash(spec)

	if !sha256RE.MatchString(hash) {
		t.Errorf("hash %q does not match SHA-256 pattern", hash)
	}
}

func TestComputePolicyHashDeterministic(t *testing.T) {
	spec := minimalSpec()
	h1 := ComputePolicyHash(spec)
	h2 := ComputePolicyHash(spec)

	if h1 != h2 {
		t.Errorf("hash not deterministic: %q vs %q", h1, h2)
	}
}

func TestComputePolicyHashDiffersForDifferentSpecs(t *testing.T) {
	spec1 := minimalSpec()
	spec2 := &HushSpec{
		HushSpecVersion: "0.1.0",
		Name:            "different-policy",
	}

	if ComputePolicyHash(spec1) == ComputePolicyHash(spec2) {
		t.Error("expected different hashes for different specs")
	}
}

func TestTraceEgressRule(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Rules: &Rules{
			Egress: &EgressRule{
				Enabled: true,
				Allow:   []string{"api.example.com"},
				Default: DefaultActionBlock,
			},
		},
	}
	action := &EvaluationAction{Type: "egress", Target: "api.example.com"}
	receipt := EvaluateAudited(spec, action, enabledConfig())

	if receipt.Decision != DecisionAllow {
		t.Errorf("expected allow, got %q", receipt.Decision)
	}

	found := false
	for _, tr := range receipt.RuleTrace {
		if tr.RuleBlock == "egress" {
			found = true
			if !tr.Evaluated {
				t.Error("expected egress trace to be evaluated")
			}
			if tr.Outcome != RuleOutcomeAllow {
				t.Errorf("expected allow outcome, got %q", tr.Outcome)
			}
		}
	}
	if !found {
		t.Error("no egress trace entry found")
	}
}

func TestTraceShellCommands(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Rules: &Rules{
			ShellCommands: &ShellCommandsRule{
				Enabled:           true,
				ForbiddenPatterns: []string{`rm\s+-rf`},
			},
		},
	}
	action := &EvaluationAction{Type: "shell_command", Target: "ls -la"}
	receipt := EvaluateAudited(spec, action, enabledConfig())

	if receipt.Decision != DecisionAllow {
		t.Errorf("expected allow, got %q", receipt.Decision)
	}

	found := false
	for _, tr := range receipt.RuleTrace {
		if tr.RuleBlock == "shell_commands" {
			found = true
			if !tr.Evaluated {
				t.Error("expected shell_commands trace to be evaluated")
			}
			if tr.Outcome != RuleOutcomeAllow {
				t.Errorf("expected allow outcome, got %q", tr.Outcome)
			}
		}
	}
	if !found {
		t.Error("no shell_commands trace entry found")
	}
}

func TestTraceSkipUnconfiguredToolAccess(t *testing.T) {
	spec := &HushSpec{HushSpecVersion: "0.1.0"}
	action := &EvaluationAction{Type: "tool_call", Target: "test"}
	receipt := EvaluateAudited(spec, action, enabledConfig())

	found := false
	for _, tr := range receipt.RuleTrace {
		if tr.RuleBlock == "tool_access" {
			found = true
			if tr.Evaluated {
				t.Error("expected tool_access trace to not be evaluated")
			}
			if tr.Outcome != RuleOutcomeSkip {
				t.Errorf("expected skip outcome, got %q", tr.Outcome)
			}
		}
	}
	if !found {
		t.Error("no tool_access trace entry found")
	}
}

func TestTraceUnknownActionType(t *testing.T) {
	spec := &HushSpec{HushSpecVersion: "0.1.0"}
	action := &EvaluationAction{Type: "unknown_action", Target: "test"}
	receipt := EvaluateAudited(spec, action, enabledConfig())

	if receipt.Decision != DecisionAllow {
		t.Errorf("expected allow, got %q", receipt.Decision)
	}

	found := false
	for _, tr := range receipt.RuleTrace {
		if tr.RuleBlock == "default" {
			found = true
			if !tr.Evaluated {
				t.Error("expected default trace to be evaluated")
			}
		}
	}
	if !found {
		t.Error("no default trace entry found")
	}
}
