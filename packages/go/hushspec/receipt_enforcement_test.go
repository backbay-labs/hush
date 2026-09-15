package hushspec

import (
	"encoding/json"
	"strings"
	"testing"
)

func minimalReceipt() DecisionReceipt {
	return DecisionReceipt{
		ReceiptVersion: ReceiptVersion,
		ReceiptID:      "01994b7e-2c1a-7c3e-8f4a-0123456789ab",
		Timestamp:      "2026-07-12T00:00:00.000Z",
		TimeSource:     TimeSourceSystem,
		Action:         ActionSummary{Type: "tool_call", Target: "dangerous_tool"},
		Decision:       DecisionDeny,
		RuleTrace:      []RuleTraceEntry{},
		Policy: PolicySummary{
			SpecVersion: "0.1.0",
			ContentHash: contentHashPrefix + strings.Repeat("a", 64),
		},
		Enforcement: EnforcementSummary{
			Mode:    EnforcementModeMonitor,
			Outcome: EnforcementOutcomeWouldBlock,
		},
	}
}

func TestReceiptEnforcementRoundTrip(t *testing.T) {
	data, err := json.Marshal(minimalReceipt())
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if !strings.Contains(string(data), `"enforcement":{"mode":"monitor","outcome":"would_block"}`) {
		t.Fatalf("expected enforcement in JSON, got: %s", data)
	}

	parsed, err := ParseReceipt(data)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if parsed.Enforcement.Mode != EnforcementModeMonitor ||
		parsed.Enforcement.Outcome != EnforcementOutcomeWouldBlock {
		t.Fatalf("enforcement did not round-trip: %+v", parsed.Enforcement)
	}
}

// TestReceiptEnforcementAlwaysPresent locks in the 0.2 change that made
// `enforcement` required: a decision without a disposition is not evidence
// that a control operated, so it is never omitted, even for a receipt built
// from the zero value.
func TestReceiptEnforcementAlwaysPresent(t *testing.T) {
	receipt := minimalReceipt()
	receipt.Enforcement = EnforcementSummary{}

	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if !strings.Contains(string(data), `"enforcement":`) {
		t.Fatalf("enforcement must always be written, got: %s", data)
	}
}

// TestImpliedEnforcementBlocksUnconfirmedWarn locks in receipt spec 4.7: an
// engine with no enforcement point records the disposition the decision
// implies, and a warn with no confirmation channel is a deny (core spec 6).
func TestImpliedEnforcementBlocksUnconfirmedWarn(t *testing.T) {
	cases := []struct {
		decision Decision
		mode     EnforcementMode
		want     EnforcementOutcome
	}{
		{DecisionAllow, EnforcementModeEnforce, EnforcementOutcomeAllowed},
		{DecisionWarn, EnforcementModeEnforce, EnforcementOutcomeBlocked},
		{DecisionDeny, EnforcementModeEnforce, EnforcementOutcomeBlocked},
		{DecisionAllow, EnforcementModeMonitor, EnforcementOutcomeAllowed},
		{DecisionWarn, EnforcementModeMonitor, EnforcementOutcomeWouldBlock},
		{DecisionDeny, EnforcementModeMonitor, EnforcementOutcomeWouldBlock},
	}
	for _, testCase := range cases {
		got := ImpliedEnforcement(testCase.decision, testCase.mode)
		if got.Outcome != testCase.want || got.Mode != testCase.mode {
			t.Errorf("ImpliedEnforcement(%q, %q) = %+v, want outcome %q",
				testCase.decision, testCase.mode, got, testCase.want)
		}
	}
	// An unset mode is enforce, never an empty string on the wire.
	if got := ImpliedEnforcement(DecisionDeny, ""); got.Mode != EnforcementModeEnforce {
		t.Errorf("an unset mode must default to enforce, got %q", got.Mode)
	}
}
