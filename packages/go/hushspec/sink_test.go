package hushspec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeTestReceipt(decision Decision) *DecisionReceipt {
	duration := int64(42)
	return &DecisionReceipt{
		ReceiptVersion: ReceiptVersion,
		ReceiptID:      "01994b7e-2c1a-7c3e-8f4a-0123456789ab",
		Timestamp:      "2026-03-15T00:00:00.000Z",
		TimeSource:     TimeSourceSystem,
		Action: ActionSummary{
			Type:   "tool_call",
			Target: "test_tool",
		},
		Decision:    decision,
		MatchedRule: "rules.tool_access.allow",
		Reason:      "tool is explicitly allowed",
		RuleTrace: []RuleTraceEntry{
			{
				RuleBlock: "tool_access",
				RulePath:  "rules.tool_access.allow",
				Outcome:   RuleOutcomeAllow,
				Reason:    "tool is explicitly allowed",
				Evaluated: true,
			},
		},
		Policy: PolicySummary{
			Name:        strPtr("test-policy"),
			SpecVersion: "0.1.0",
			ContentHash: DigestOf("test-policy"),
		},
		Enforcement: ImpliedEnforcement(decision, EnforcementModeEnforce),
		DurationUs:  &duration,
	}
}

func TestFileReceiptSinkWritesJSONLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipts.jsonl")
	sink := NewFileReceiptSink(path)

	if err := sink.Send(makeTestReceipt(DecisionAllow)); err != nil {
		t.Fatalf("send 1 failed: %v", err)
	}
	if err := sink.Send(makeTestReceipt(DecisionDeny)); err != nil {
		t.Fatalf("send 2 failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	var r1 DecisionReceipt
	if err := json.Unmarshal([]byte(lines[0]), &r1); err != nil {
		t.Fatalf("unmarshal line 1: %v", err)
	}
	if r1.ReceiptID != "01994b7e-2c1a-7c3e-8f4a-0123456789ab" {
		t.Errorf("expected receipt_id 01994b7e-2c1a-7c3e-8f4a-0123456789ab, got %q", r1.ReceiptID)
	}

	var r2 DecisionReceipt
	if err := json.Unmarshal([]byte(lines[1]), &r2); err != nil {
		t.Fatalf("unmarshal line 2: %v", err)
	}
	if r2.Decision != DecisionDeny {
		t.Errorf("expected deny, got %q", r2.Decision)
	}
}

func TestFileReceiptSinkAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipts.jsonl")
	sink := NewFileReceiptSink(path)

	for i := 0; i < 3; i++ {
		if err := sink.Send(makeTestReceipt(DecisionAllow)); err != nil {
			t.Fatalf("send %d failed: %v", i, err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
}

func TestFilteredSinkDenyOnly(t *testing.T) {
	var collected []Decision
	inner := NewCallbackSink(func(r *DecisionReceipt) error {
		collected = append(collected, r.Decision)
		return nil
	})
	filtered := NewDenyOnlySink(inner)

	_ = filtered.Send(makeTestReceipt(DecisionAllow))
	_ = filtered.Send(makeTestReceipt(DecisionWarn))
	_ = filtered.Send(makeTestReceipt(DecisionDeny))
	_ = filtered.Send(makeTestReceipt(DecisionAllow))
	_ = filtered.Send(makeTestReceipt(DecisionDeny))

	if len(collected) != 2 {
		t.Fatalf("expected 2 deny receipts, got %d", len(collected))
	}
	if collected[0] != DecisionDeny || collected[1] != DecisionDeny {
		t.Errorf("expected [deny, deny], got %v", collected)
	}
}

func TestFilteredSinkCustomDecisions(t *testing.T) {
	var collected []Decision
	inner := NewCallbackSink(func(r *DecisionReceipt) error {
		collected = append(collected, r.Decision)
		return nil
	})
	filtered := NewFilteredSink(inner, []Decision{DecisionAllow})

	_ = filtered.Send(makeTestReceipt(DecisionAllow))
	_ = filtered.Send(makeTestReceipt(DecisionDeny))
	_ = filtered.Send(makeTestReceipt(DecisionWarn))

	if len(collected) != 1 {
		t.Fatalf("expected 1, got %d", len(collected))
	}
	if collected[0] != DecisionAllow {
		t.Errorf("expected allow, got %q", collected[0])
	}
}

func TestMultiSinkSendsToAll(t *testing.T) {
	count1, count2 := 0, 0
	sink1 := NewCallbackSink(func(*DecisionReceipt) error { count1++; return nil })
	sink2 := NewCallbackSink(func(*DecisionReceipt) error { count2++; return nil })

	multi := NewMultiSink([]ReceiptSink{sink1, sink2})
	_ = multi.Send(makeTestReceipt(DecisionAllow))
	_ = multi.Send(makeTestReceipt(DecisionDeny))

	if count1 != 2 {
		t.Errorf("sink1 expected 2 calls, got %d", count1)
	}
	if count2 != 2 {
		t.Errorf("sink2 expected 2 calls, got %d", count2)
	}
}

func TestMultiSinkContinuesAfterError(t *testing.T) {
	count := 0
	failing := NewCallbackSink(func(*DecisionReceipt) error {
		return fmt.Errorf("test error")
	})
	counting := NewCallbackSink(func(*DecisionReceipt) error {
		count++
		return nil
	})

	multi := NewMultiSink([]ReceiptSink{failing, counting})
	err := multi.Send(makeTestReceipt(DecisionAllow))

	if err == nil {
		t.Error("expected error from failing sink")
	}
	if count != 1 {
		t.Errorf("counting sink should still execute, got count=%d", count)
	}
}

func TestNullSinkDoesNotCrash(t *testing.T) {
	sink := &NullSink{}

	if err := sink.Send(makeTestReceipt(DecisionAllow)); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := sink.Send(makeTestReceipt(DecisionDeny)); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := sink.Send(makeTestReceipt(DecisionWarn)); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCallbackSinkInvokesCallback(t *testing.T) {
	var ids []string
	sink := NewCallbackSink(func(r *DecisionReceipt) error {
		ids = append(ids, r.ReceiptID)
		return nil
	})

	_ = sink.Send(makeTestReceipt(DecisionAllow))
	_ = sink.Send(makeTestReceipt(DecisionDeny))

	if len(ids) != 2 {
		t.Fatalf("expected 2 callbacks, got %d", len(ids))
	}
	if ids[0] != "01994b7e-2c1a-7c3e-8f4a-0123456789ab" || ids[1] != "01994b7e-2c1a-7c3e-8f4a-0123456789ab" {
		t.Errorf("unexpected IDs: %v", ids)
	}
}

func TestStderrSinkDoesNotCrash(t *testing.T) {
	sink := &StderrReceiptSink{}
	if err := sink.Send(makeTestReceipt(DecisionAllow)); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
