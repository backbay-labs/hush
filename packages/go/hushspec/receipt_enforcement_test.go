package hushspec

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReceiptEnforcementRoundTrip(t *testing.T) {
	receipt := DecisionReceipt{
		ReceiptID:            "11111111-2222-4333-8444-555555555555",
		Timestamp:            "2026-07-12T00:00:00.000Z",
		HushSpecVersion:      "0.1.0",
		Action:               ActionSummary{Type: "tool_call", Target: "dangerous_tool"},
		Decision:             DecisionDeny,
		RuleTrace:            []RuleEvaluation{},
		Policy:               PolicySummary{Version: "0.1.0", ContentHash: strings.Repeat("a", 64)},
		EvaluationDurationUs: 12,
		Enforcement:          &EnforcementSummary{Mode: "monitor", Outcome: "would_block"},
	}

	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if !strings.Contains(string(data), `"enforcement":{"mode":"monitor","outcome":"would_block"}`) {
		t.Fatalf("expected enforcement in JSON, got: %s", data)
	}

	var parsed DecisionReceipt
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if parsed.Enforcement == nil || parsed.Enforcement.Mode != "monitor" || parsed.Enforcement.Outcome != "would_block" {
		t.Fatalf("enforcement did not round-trip: %+v", parsed.Enforcement)
	}
}

func TestReceiptEnforcementOmittedWhenAbsent(t *testing.T) {
	receipt := DecisionReceipt{
		ReceiptID:       "11111111-2222-4333-8444-555555555555",
		Timestamp:       "2026-07-12T00:00:00.000Z",
		HushSpecVersion: "0.1.0",
		Action:          ActionSummary{Type: "tool_call", Target: "safe_tool"},
		Decision:        DecisionAllow,
		RuleTrace:       []RuleEvaluation{},
		Policy:          PolicySummary{Version: "0.1.0", ContentHash: strings.Repeat("a", 64)},
	}

	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if strings.Contains(string(data), "enforcement") {
		t.Fatalf("absent enforcement must be omitted, got: %s", data)
	}

	var parsed DecisionReceipt
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if parsed.Enforcement != nil {
		t.Fatalf("expected nil enforcement, got: %+v", parsed.Enforcement)
	}
}
