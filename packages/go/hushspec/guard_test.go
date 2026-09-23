package hushspec

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

// recordingSink captures everything a guard records, so a test can assert on
// the audit trail as well as the decision.
type recordingSink struct {
	mu            sync.Mutex
	receipts      []*DecisionReceipt
	events        []*PolicyEvent
	failWith      error
	failEventWith error
}

func (s *recordingSink) Send(receipt *DecisionReceipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receipts = append(s.receipts, receipt)
	return s.failWith
}

func (s *recordingSink) RecordPolicyEvent(event *PolicyEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return s.failEventWith
}

func (s *recordingSink) snapshot() ([]*DecisionReceipt, []*PolicyEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*DecisionReceipt(nil), s.receipts...), append([]*PolicyEvent(nil), s.events...)
}

func newTestGuard(t *testing.T, options GuardOptions) *Guard {
	t.Helper()
	guard, err := NewGuard(guardResolution(t, guardSpec()), options)
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	return guard
}

func TestGuardCheckAllowsAndDenies(t *testing.T) {
	sink := &recordingSink{}
	guard := newTestGuard(t, GuardOptions{Sink: sink})

	allowed, err := guard.Check(context.Background(), &EvaluationAction{
		Type: "egress", Target: "api.github.com",
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !allowed.Allowed() || allowed.Result.Decision != DecisionAllow {
		t.Fatalf("expected an allow, got %+v", allowed)
	}
	if !allowed.Enforced || allowed.Enforcement.Outcome != EnforcementOutcomeAllowed {
		t.Fatalf("expected enforcement allowed, got %+v", allowed.Enforcement)
	}

	denied, err := guard.Check(context.Background(), &EvaluationAction{
		Type: "egress", Target: "evil.example.com",
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if denied.Allowed() || denied.Result.Decision != DecisionDeny {
		t.Fatalf("expected a deny, got %+v", denied)
	}
	if denied.Enforcement.Outcome != EnforcementOutcomeBlocked {
		t.Fatalf("expected blocked, got %q", denied.Enforcement.Outcome)
	}

	receipts, events := sink.snapshot()
	if len(receipts) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(receipts))
	}
	if receipts[1].Enforcement.Outcome != EnforcementOutcomeBlocked {
		t.Fatalf("receipt enforcement not recorded: %+v", receipts[1].Enforcement)
	}
	if len(events) != 1 || events[0].Event != PolicyEventLoaded {
		t.Fatalf("expected one policy_loaded event, got %+v", events)
	}
	if events[0].Policy.ContentHash != guard.Resolution().ContentHash {
		t.Fatal("policy event does not name the policy in force")
	}
}

func TestGuardWarnFailsClosedWithoutHandler(t *testing.T) {
	guard := newTestGuard(t, GuardOptions{})
	content := "token WARNME here"
	decision, err := guard.Check(context.Background(), &EvaluationAction{
		Type: "file_write", Target: "notes.txt", Content: &content,
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if decision.Result.Decision != DecisionWarn {
		t.Fatalf("expected a warn, got %q", decision.Result.Decision)
	}
	if decision.Allowed() || decision.Enforcement.Outcome != EnforcementOutcomeBlocked {
		t.Fatalf("a warn with no handler must block, got %+v", decision.Enforcement)
	}
}

func TestGuardWarnConfirmedByHandler(t *testing.T) {
	var sawAction *EvaluationAction
	guard := newTestGuard(t, GuardOptions{
		OnWarn: func(result EvaluationResult, action *EvaluationAction) bool {
			sawAction = action
			return true
		},
	})
	content := "token WARNME here"
	decision, err := guard.Check(context.Background(), &EvaluationAction{
		Type: "file_write", Target: "notes.txt", Content: &content,
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !decision.Allowed() || decision.Enforcement.Outcome != EnforcementOutcomeConfirmed {
		t.Fatalf("expected a confirmed warn, got %+v", decision.Enforcement)
	}
	if sawAction == nil || sawAction.Target != "notes.txt" {
		t.Fatal("the warn handler was not given the action")
	}
}

func TestGuardWarnPanicRecordsBeforeResuming(t *testing.T) {
	marker := errors.New("confirmation-marker")
	sink := &recordingSink{}
	guard := newTestGuard(t, GuardOptions{Sink: sink, OnWarn: func(EvaluationResult, *EvaluationAction) bool { panic(marker) }})
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		content := "token WARNME here"
		_, _ = guard.Check(context.Background(), &EvaluationAction{Type: "file_write", Target: "a.txt", Content: &content})
	}()
	receipts, _ := sink.snapshot()
	if recovered != marker || len(receipts) != 1 {
		t.Fatalf("panic=%v receipts=%d", recovered, len(receipts))
	}
	if receipts[0].Decision != DecisionWarn || receipts[0].Enforcement.Outcome != EnforcementOutcomeBlocked {
		t.Fatal("missing blocked warn")
	}
}

type panicSendSink struct{ recordingSink }

func (s *panicSendSink) Send(receipt *DecisionReceipt) error {
	_ = s.recordingSink.Send(receipt)
	panic("sink-marker")
}

func TestGuardWarnPanicSurvivesSinkPanicAndReuse(t *testing.T) {
	marker := errors.New("confirmation-marker")
	sink := &panicSendSink{}
	content := "token WARNME here"
	action := &EvaluationAction{Type: "file_write", Target: "a.txt", Content: &content}
	baselineSink := &recordingSink{}
	baseline, err := newTestGuard(t, GuardOptions{Sink: baselineSink}).Check(context.Background(), action)
	if err != nil {
		t.Fatal(err)
	}
	guard := newTestGuard(t, GuardOptions{Sink: sink, OnWarn: func(EvaluationResult, *EvaluationAction) bool { panic(marker) }})
	for count := 1; count <= 2; count++ {
		var recovered any
		func() {
			defer func() { recovered = recover() }()
			_, _ = guard.Check(context.Background(), action)
		}()
		receipts, _ := sink.snapshot()
		if recovered != marker || len(receipts) != count {
			t.Fatalf("panic=%v receipts=%d", recovered, len(receipts))
		}
		receipt := receipts[count-1]
		if receipt.Reason != baseline.Receipt.Reason || !reflect.DeepEqual(receipt.RuleTrace, baseline.Receipt.RuleTrace) {
			t.Fatal("policy explanation changed")
		}
		if receipt.Enforcement.Outcome != EnforcementOutcomeBlocked {
			t.Fatal("not blocked")
		}
	}
}

func TestGuardWarnNilPanic(t *testing.T) {
	sink := &recordingSink{}
	guard := newTestGuard(t, GuardOptions{Sink: sink, OnWarn: func(EvaluationResult, *EvaluationAction) bool { panic(nil) }})
	completed := false
	func() {
		defer func() { _ = recover() }()
		content := "token WARNME here"
		_, _ = guard.Check(context.Background(), &EvaluationAction{Type: "file_write", Target: "a.txt", Content: &content})
		completed = true
	}()
	receipts, _ := sink.snapshot()
	if completed || len(receipts) != 1 {
		t.Fatalf("completed=%v receipts=%d", completed, len(receipts))
	}
	if receipts[0].Enforcement.Outcome != EnforcementOutcomeBlocked {
		t.Fatal("not blocked")
	}
}

func TestGuardWarnMonitorSkipsPanickingConfirmation(t *testing.T) {
	sink := &recordingSink{}
	guard := newTestGuard(t, GuardOptions{Sink: sink, EnforcementMode: EnforcementModeMonitor, OnWarn: func(EvaluationResult, *EvaluationAction) bool { panic("must not confirm") }})
	content := "token WARNME here"
	decision, err := guard.Check(context.Background(), &EvaluationAction{Type: "file_write", Target: "a.txt", Content: &content})
	if err != nil || !decision.Allowed() || decision.Enforcement.Outcome != EnforcementOutcomeWouldBlock {
		t.Fatalf("decision=%+v error=%v", decision, err)
	}
	receipts, _ := sink.snapshot()
	if len(receipts) != 1 {
		t.Fatal("missing monitor receipt")
	}
}

func TestGuardEvaluateDoesNotConsultWarnHandler(t *testing.T) {
	called := false
	guard := newTestGuard(t, GuardOptions{
		OnWarn: func(EvaluationResult, *EvaluationAction) bool { called = true; return true },
	})
	content := "token WARNME here"
	decision, err := guard.Evaluate(context.Background(), &EvaluationAction{
		Type: "file_write", Target: "notes.txt", Content: &content,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if called {
		t.Fatal("Evaluate must not gate through the warn handler")
	}
	// Implied enforcement for a warn under enforce mode is a block (core spec 6).
	if decision.Enforcement.Outcome != EnforcementOutcomeBlocked {
		t.Fatalf("expected implied blocked, got %q", decision.Enforcement.Outcome)
	}
}

func TestGuardMonitorModeRequiresObservability(t *testing.T) {
	_, err := NewGuard(guardResolution(t, guardSpec()), GuardOptions{
		EnforcementMode: EnforcementModeMonitor,
	})
	if err == nil || !strings.Contains(err.Error(), "monitor mode requires") {
		t.Fatalf("monitor mode must fail closed without a sink or observer, got %v", err)
	}

	if _, err := NewGuard(guardResolution(t, guardSpec()), GuardOptions{
		RuleOverrides: map[string]EnforcementMode{"rules.egress": EnforcementModeMonitor},
	}); err == nil {
		t.Fatal("a monitor override must fail closed without a sink or observer")
	}

	observer := &recordingObserver{}
	if _, err := NewGuard(guardResolution(t, guardSpec()), GuardOptions{
		EnforcementMode: EnforcementModeMonitor,
		Observer:        observer,
	}); err != nil {
		t.Fatalf("monitor mode with an observer must be accepted: %v", err)
	}
}

func TestGuardMonitorModeRefusesASinkWithAuditingOff(t *testing.T) {
	// With auditing off no receipt is built, so the sink is handed nothing and
	// the shadow decision leaves no trace at all.
	off := AuditConfig{Enabled: false}
	_, err := NewGuard(guardResolution(t, guardSpec()), GuardOptions{
		EnforcementMode: EnforcementModeMonitor,
		Sink:            &recordingSink{},
		Audit:           &off,
	})
	if err == nil || !strings.Contains(err.Error(), "monitor mode requires") {
		t.Fatalf("an unrecorded shadow decision must not build, got %v", err)
	}

	// An observer still reports every decision, whatever auditing records.
	if _, err := NewGuard(guardResolution(t, guardSpec()), GuardOptions{
		EnforcementMode: EnforcementModeMonitor,
		Observer:        &recordingObserver{},
		Audit:           &off,
	}); err != nil {
		t.Fatalf("monitor mode with an observer must be accepted: %v", err)
	}
}

func TestGuardMonitorModeRecordsWouldBlock(t *testing.T) {
	sink := &recordingSink{}
	guard := newTestGuard(t, GuardOptions{EnforcementMode: EnforcementModeMonitor, Sink: sink})

	decision, err := guard.Check(context.Background(), &EvaluationAction{
		Type: "egress", Target: "evil.example.com",
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !decision.Allowed() {
		t.Fatal("monitor mode must let the action proceed")
	}
	if decision.Enforced {
		t.Fatal("a would_block decision was not enforced")
	}
	if decision.Enforcement.Outcome != EnforcementOutcomeWouldBlock {
		t.Fatalf("expected would_block, got %q", decision.Enforcement.Outcome)
	}
	receipts, _ := sink.snapshot()
	if len(receipts) != 1 || receipts[0].Enforcement.Outcome != EnforcementOutcomeWouldBlock {
		t.Fatal("a monitored block must never be silent")
	}
}

func TestGuardRuleOverrideLongestPrefixWins(t *testing.T) {
	sink := &recordingSink{}
	guard := newTestGuard(t, GuardOptions{
		EnforcementMode: EnforcementModeEnforce,
		RuleOverrides: map[string]EnforcementMode{
			"rules.egress": EnforcementModeMonitor,
		},
		Sink: sink,
	})
	decision, err := guard.Check(context.Background(), &EvaluationAction{
		Type: "egress", Target: "evil.example.com",
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if decision.Enforcement.Mode != EnforcementModeMonitor {
		t.Fatalf("the override did not apply: %+v", decision.Enforcement)
	}

	result := EvaluationResult{Decision: DecisionDeny, MatchedRule: "rules.egress.block[0]"}
	overrides := map[string]EnforcementMode{
		"rules.egress":          EnforcementModeMonitor,
		"rules.egress.block[0]": EnforcementModeEnforce,
	}
	if mode := effectiveMode(result, EnforcementModeMonitor, overrides); mode != EnforcementModeEnforce {
		t.Fatalf("the longest matching prefix must win, got %q", mode)
	}
}

func TestGuardRejectsUnknownOverrideKeys(t *testing.T) {
	cases := map[string]map[string]EnforcementMode{
		"not a rule path": {"egress": EnforcementModeEnforce},
		"unknown rule":    {"rules.not_a_rule": EnforcementModeEnforce},
		"unknown ext":     {"extensions.not_an_extension": EnforcementModeEnforce},
		"bad mode":        {"rules.egress": EnforcementMode("audit")},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewGuard(guardResolution(t, guardSpec()), GuardOptions{
				RuleOverrides: overrides,
			}); err == nil {
				t.Fatal("expected the configuration to be rejected")
			}
		})
	}
}

func TestMatchesRulePathPrefix(t *testing.T) {
	cases := []struct {
		matched, key string
		want         bool
	}{
		{"rules.egress", "rules.egress", true},
		{"rules.egress.allow[0]", "rules.egress", true},
		{"rules.egress[0]", "rules.egress", true},
		{"rules.egress_extra.allow", "rules.egress", false},
		{"rules.forbidden_paths.paths[1]", "rules.egress", false},
	}
	for _, c := range cases {
		if got := MatchesRulePathPrefix(c.matched, c.key); got != c.want {
			t.Fatalf("MatchesRulePathPrefix(%q, %q) = %v", c.matched, c.key, got)
		}
	}
}

func TestGuardPanicModeAlwaysEnforces(t *testing.T) {
	sink := &recordingSink{}
	guard := newTestGuard(t, GuardOptions{EnforcementMode: EnforcementModeMonitor, Sink: sink})

	ActivatePanic()
	defer DeactivatePanic()

	decision, err := guard.Check(context.Background(), &EvaluationAction{
		Type: "egress", Target: "api.github.com",
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if decision.Allowed() {
		t.Fatal("panic mode must deny even under monitor mode")
	}
	if decision.Enforcement.Mode != EnforcementModeEnforce {
		t.Fatalf("panic mode must enforce, got %q", decision.Enforcement.Mode)
	}
}

func TestGuardRefusedPolicyDeniesEverything(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	policy := "hushspec: \"0.2.0\"\nname: unsigned-policy\nrules:\n  egress:\n    enabled: true\n    allow: [\"api.github.com\"]\n    default: block\n"
	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	sink := &recordingSink{}
	guard, err := NewGuardFromFile(path, GuardOptions{
		RequireSignature: true,
		Sink:             sink,
	})
	if err != nil {
		t.Fatalf("a guard must refuse rather than fail to exist: %v", err)
	}
	refused, status := guard.Refused()
	if !refused {
		t.Fatal("expected the guard to be in its refused state")
	}
	if status.Verified || status.Reason == "" {
		t.Fatalf("expected a failed signature status, got %+v", status)
	}

	decision, err := guard.Check(context.Background(), &EvaluationAction{
		Type: "egress", Target: "api.github.com",
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if decision.Allowed() {
		t.Fatal("a refused policy must deny an action its rules would allow")
	}
	if decision.Result.MatchedRule != PolicyUnverifiedRule {
		t.Fatalf("expected %q, got %q", PolicyUnverifiedRule, decision.Result.MatchedRule)
	}
	if decision.Receipt == nil {
		t.Fatal("a refused action must still produce a receipt")
	}
	if decision.Receipt.Policy.Signature == nil || decision.Receipt.Policy.Signature.Verified {
		t.Fatalf("the receipt must record the failed verification: %+v", decision.Receipt.Policy)
	}
	if decision.Receipt.Policy.ContentHash == "" {
		t.Fatal("the receipt must still name the document that was refused")
	}
	receipts, events := sink.snapshot()
	if len(receipts) != 1 {
		t.Fatalf("expected the refusal to be recorded, got %d receipts", len(receipts))
	}
	if len(events) != 1 || events[0].Policy.Signature == nil {
		t.Fatalf("the policy event must record the refusal: %+v", events)
	}
}

func TestGuardSwapPolicy(t *testing.T) {
	sink := &recordingSink{}
	observer := &recordingObserver{}
	guard := newTestGuard(t, GuardOptions{Sink: sink, Observer: observer})
	first := guard.Resolution().ContentHash

	next := guardSpec()
	next.Name = strPtr("guard-policy-v2")
	next.Rules.Egress.Allow = []string{"api.github.com", "api.example.com"}
	if err := guard.SwapPolicy(guardResolution(t, next)); err != nil {
		t.Fatalf("SwapPolicy: %v", err)
	}
	if guard.Resolution().ContentHash == first {
		t.Fatal("the policy in force did not change")
	}

	decision, err := guard.Check(context.Background(), &EvaluationAction{
		Type: "egress", Target: "api.example.com",
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !decision.Allowed() {
		t.Fatal("the new policy is not in force")
	}

	_, events := sink.snapshot()
	if len(events) != 2 || events[1].Event != PolicyEventSwapped {
		t.Fatalf("expected a policy_swapped record, got %+v", events)
	}
	if events[1].PreviousContentHash != first {
		t.Fatalf("the swap must name the hash it replaced, got %q", events[1].PreviousContentHash)
	}
	loads, _, _ := observer.counts()
	if loads != 2 {
		t.Fatalf("expected two policy load notifications, got %d", loads)
	}
}

func TestGuardSwapPolicyKeepsLastGoodPolicy(t *testing.T) {
	guard := newTestGuard(t, GuardOptions{})
	before := guard.Resolution().ContentHash

	if err := guard.SwapPolicy(nil); err == nil {
		t.Fatal("a nil resolution must be rejected")
	}

	unresolved := guardSpec()
	unresolved.Extends = strPtr("builtin:default")
	resolution := &Resolution{Spec: unresolved, ContentHash: "sha256:" + strings.Repeat("0", 64)}
	if err := guard.SwapPolicy(resolution); err == nil {
		t.Fatal("an unresolved policy must be rejected")
	}

	broken := guardSpec()
	broken.Rules.SecretPatterns.Patterns = []SecretPattern{
		{Name: "bad", Pattern: "(unclosed", Severity: SeverityError},
	}
	if err := guard.SwapPolicy(guardResolution(t, broken)); err == nil {
		t.Fatal("a policy that does not compile must be rejected")
	}

	if guard.Resolution().ContentHash != before {
		t.Fatal("a failed swap must leave the previous policy in force")
	}
	decision, err := guard.Check(context.Background(), &EvaluationAction{
		Type: "egress", Target: "api.github.com",
	})
	if err != nil || !decision.Allowed() {
		t.Fatalf("the previous policy must keep working, got %+v %v", decision, err)
	}
}

func TestGuardSwapPolicyClearsRefusal(t *testing.T) {
	guard, err := NewGuard(guardResolution(t, guardSpec()), GuardOptions{
		Refusal: &GuardRefusal{
			Source: "policy.yaml",
			Status: FailedSignature(ReasonMissingSignature, ""),
		},
	})
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	if refused, _ := guard.Refused(); !refused {
		t.Fatal("expected a refused guard")
	}
	if err := guard.SwapPolicy(guardResolution(t, guardSpec())); err != nil {
		t.Fatalf("SwapPolicy: %v", err)
	}
	if refused, _ := guard.Refused(); refused {
		t.Fatal("a verified policy must clear the refusal")
	}
}

func TestGuardRejectsUnresolvedPolicy(t *testing.T) {
	spec := guardSpec()
	spec.Extends = strPtr("builtin:default")
	resolution := &Resolution{Spec: spec}
	if _, err := NewGuard(resolution, GuardOptions{}); err == nil {
		t.Fatal("a guard must never hold an unresolved policy")
	}
}

func TestGuardSinkFailureIsReportedButDecisionStands(t *testing.T) {
	sink := &recordingSink{failWith: errors.New("no space left on device")}
	observer := &recordingObserver{}
	guard := newTestGuard(t, GuardOptions{Sink: sink, Observer: observer})

	decision, err := guard.Check(context.Background(), &EvaluationAction{
		Type: "egress", Target: "api.github.com",
	})
	if err != nil {
		t.Fatalf("a sink failure must not reach the caller, got %v", err)
	}
	if !decision.Allowed() {
		t.Fatal("the decision stands even when recording it failed")
	}
	denied, err := guard.Check(context.Background(), &EvaluationAction{
		Type: "egress", Target: "evil.example.com",
	})
	if err != nil {
		t.Fatalf("a sink failure must not reach the caller, got %v", err)
	}
	if denied.Allowed() {
		t.Fatal("a sink failure must not let a denied action through")
	}

	errs := observer.errors()
	if len(errs) != 2 {
		t.Fatalf("expected one report per refused receipt, got %d", len(errs))
	}
	event := errorObserverEvent(errs[0])
	if event.Type != ObserverEventSinkError {
		t.Fatalf("expected a %s event, got %s", ObserverEventSinkError, event.Type)
	}
	if event.Source != "recordingSink" {
		t.Fatalf("the event must name the sink that refused, got %q", event.Source)
	}
	if !strings.Contains(event.Error, "no space left on device") {
		t.Fatalf("the event must carry the sink's own error, got %q", event.Error)
	}
}

func TestGuardPolicyEventSinkFailureIsReported(t *testing.T) {
	sink := &recordingSink{failEventWith: errors.New("no space left on device")}
	observer := &recordingObserver{}
	guard := newTestGuard(t, GuardOptions{Sink: sink, Observer: observer})

	if _, err := guard.Check(context.Background(), &EvaluationAction{
		Type: "egress", Target: "api.github.com",
	}); err != nil {
		t.Fatalf("Check: %v", err)
	}

	errs := observer.errors()
	if len(errs) != 1 {
		t.Fatalf("expected the policy load to report one sink failure, got %d", len(errs))
	}
	event := errorObserverEvent(errs[0])
	if event.Type != ObserverEventSinkError {
		t.Fatalf("expected a %s event, got %s", ObserverEventSinkError, event.Type)
	}
	if event.Source != "recordingSink" {
		t.Fatalf("the event must name the sink that refused, got %q", event.Source)
	}
	if !strings.Contains(event.Error, "no space left on device") {
		t.Fatalf("the event must carry the sink's own error, got %q", event.Error)
	}
}

func TestGuardCancelledContextDenies(t *testing.T) {
	guard := newTestGuard(t, GuardOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	decision, err := guard.Check(ctx, &EvaluationAction{Type: "egress", Target: "api.github.com"})
	if err == nil {
		t.Fatal("expected the cancellation to be reported")
	}
	if decision.Allowed() {
		t.Fatal("a cancelled check must fail closed")
	}
}

func TestGuardObserverSeesRedactedAction(t *testing.T) {
	observer := &recordingObserver{}
	guard := newTestGuard(t, GuardOptions{Observer: observer})
	content := "hunter2"
	if _, err := guard.Check(context.Background(), &EvaluationAction{
		Type: "file_write", Target: "notes.txt", Content: &content,
	}); err != nil {
		t.Fatalf("Check: %v", err)
	}
	_, results, errs := observer.counts()
	if results != 1 {
		t.Fatalf("expected one observed evaluation, got %d", results)
	}
	if errs != 0 {
		t.Fatal("the observer must never see raw action content")
	}
}

func TestGuardObservationCarriesTheEnforcementSummary(t *testing.T) {
	observer := &recordingObserver{}
	guard := newTestGuard(t, GuardOptions{Observer: observer})
	decision, err := guard.Check(context.Background(), &EvaluationAction{
		Type: "egress", Target: "evil.example.com",
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if decision.Allowed() {
		t.Fatal("the test policy must deny this egress")
	}

	observer.mu.Lock()
	defer observer.mu.Unlock()
	if len(observer.evaluations) != 1 {
		t.Fatalf("expected one observed evaluation, got %d", len(observer.evaluations))
	}
	enforcement := observer.evaluations[0].Enforcement
	if enforcement == nil {
		t.Fatal("an observed evaluation must say what the enforcement point did")
	}
	if enforcement.Mode != EnforcementModeEnforce ||
		enforcement.Outcome != EnforcementOutcomeBlocked {
		t.Fatalf("unexpected enforcement summary: %+v", enforcement)
	}
}

func TestGuardIsSafeForConcurrentUse(t *testing.T) {
	sink := &recordingSink{}
	guard := newTestGuard(t, GuardOptions{Sink: sink})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				if _, err := guard.Check(context.Background(), &EvaluationAction{
					Type: "egress", Target: "api.github.com",
				}); err != nil {
					t.Errorf("Check: %v", err)
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 10; j++ {
			spec := guardSpec()
			spec.Rules.Egress.Allow = []string{"api.github.com", "host" + string(rune('a'+j)) + ".example.com"}
			resolution, err := NewResolutionFromResolved(spec, "")
			if err != nil {
				t.Errorf("resolve: %v", err)
				return
			}
			if err := guard.SwapPolicy(resolution); err != nil {
				t.Errorf("SwapPolicy: %v", err)
				return
			}
		}
	}()
	wg.Wait()

	receipts, _ := sink.snapshot()
	if len(receipts) != 200 {
		t.Fatalf("expected 200 receipts, got %d", len(receipts))
	}
}

func TestGuardFansOutThroughObservableEvaluator(t *testing.T) {
	metrics := NewMetricsCollector()
	var buffer bytes.Buffer
	guard := newTestGuard(t, GuardOptions{
		Observer: NewObservableEvaluator(metrics, NewJSONLineObserver(&buffer)),
	})
	if _, err := guard.Check(context.Background(), &EvaluationAction{
		Type: "egress", Target: "evil.example.com",
	}); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := metrics.Snapshot().Evaluations[EvaluationMetricKey{
		Decision: DecisionDeny, ActionType: "egress",
	}]; got != 1 {
		t.Fatalf("metrics did not see the decision: %d", got)
	}
	if !strings.Contains(buffer.String(), ObserverEventPolicyLoaded) {
		t.Fatal("the JSON line stream did not record the policy load")
	}
}

// adoptedProvider hands a guard a resolution that was built elsewhere, which
// is what a control-plane provider does: the chain is already merged and the
// source its signatures were checked against is gone.
type adoptedProvider struct {
	resolution *Resolution
}

func (p *adoptedProvider) Load() (*Resolution, error) { return p.resolution, nil }

func (p *adoptedProvider) Source() string { return "adopted://policy.yaml" }

// signedResolution is a one-hop resolution that carries a verified signature,
// as a provider that verified its own load reports one.
func signedResolution(t *testing.T, spec *HushSpec, source string) *Resolution {
	t.Helper()
	resolution := guardResolution(t, spec)
	resolution.Chain[0].Source = source
	resolution.Chain[0].Signature = &SignatureStatus{
		Verified: true,
		KeyID:    "sha256:" + strings.Repeat("a", 64),
	}
	resolution.Signature = resolution.Chain[0].Signature
	return resolution
}

func TestGuardFromProviderRefusesUnprovenChain(t *testing.T) {
	provider := &adoptedProvider{resolution: guardResolution(t, guardSpec())}
	guard, err := NewGuardFromProvider(provider, GuardOptions{RequireSignature: true})
	if err != nil {
		t.Fatalf("a guard must refuse rather than fail to exist: %v", err)
	}
	refused, status := guard.Refused()
	if !refused {
		t.Fatal("an adopted resolution with no verified signature must refuse")
	}
	if status.Verified || status.Reason != ReasonMissingSignature {
		t.Fatalf("expected a missing-signature status, got %+v", status)
	}
	decision, err := guard.Check(context.Background(), &EvaluationAction{
		Type: "egress", Target: "api.github.com",
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if decision.Allowed() {
		t.Fatal("a refused policy must deny an action its rules would allow")
	}
	if decision.Result.MatchedRule != PolicyUnverifiedRule {
		t.Fatalf("expected %q, got %q", PolicyUnverifiedRule, decision.Result.MatchedRule)
	}
}

func TestGuardFromProviderAcceptsVerifiedChain(t *testing.T) {
	provider := &adoptedProvider{
		resolution: signedResolution(t, guardSpec(), "adopted://policy.yaml"),
	}
	guard, err := NewGuardFromProvider(provider, GuardOptions{RequireSignature: true})
	if err != nil {
		t.Fatalf("NewGuardFromProvider: %v", err)
	}
	if refused, _ := guard.Refused(); refused {
		t.Fatal("a chain whose every hop verified must not refuse")
	}
}

func TestGuardFromProviderExemptsBuiltinHops(t *testing.T) {
	resolution := guardResolution(t, guardSpec())
	resolution.Chain[0].Source = "builtin:default"
	provider := &adoptedProvider{resolution: resolution}
	guard, err := NewGuardFromProvider(provider, GuardOptions{RequireSignature: true})
	if err != nil {
		t.Fatalf("NewGuardFromProvider: %v", err)
	}
	if refused, _ := guard.Refused(); refused {
		t.Fatal("a `builtin:` hop is embedded in the SDK and signs nothing")
	}
}

func TestGuardSwapPolicyRejectsUnprovenChain(t *testing.T) {
	guard, err := NewGuard(
		signedResolution(t, guardSpec(), "adopted://policy.yaml"),
		GuardOptions{RequireSignature: true},
	)
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	before := guard.Resolution().ContentHash

	replacement := guardSpec()
	replacement.Rules.Egress.Allow = []string{"api.github.com", "evil.example.com"}
	err = guard.SwapPolicy(guardResolution(t, replacement))
	var required *SignatureRequiredError
	if !errors.As(err, &required) {
		t.Fatalf("expected a signature requirement failure, got %v", err)
	}
	if required.Status.Reason != ReasonMissingSignature {
		t.Fatalf("expected a missing-signature status, got %+v", required.Status)
	}
	if guard.Resolution().ContentHash != before {
		t.Fatal("a rejected swap must leave the previous policy in force")
	}
	if refused, _ := guard.Refused(); refused {
		t.Fatal("a rejected swap must not refuse the policy already in force")
	}
}

func TestGuardSwapPolicyKeepsRefusalOnUnprovenChain(t *testing.T) {
	provider := &adoptedProvider{resolution: guardResolution(t, guardSpec())}
	guard, err := NewGuardFromProvider(provider, GuardOptions{RequireSignature: true})
	if err != nil {
		t.Fatalf("NewGuardFromProvider: %v", err)
	}
	if err := guard.SwapPolicy(guardResolution(t, guardSpec())); err == nil {
		t.Fatal("an unproven swap must be rejected")
	}
	if refused, _ := guard.Refused(); !refused {
		t.Fatal("a rejected swap must not clear an existing refusal")
	}
}

// TestPolicyProviderRuleMatchesTheRegistry pins the reserved `matched_rule`
// against spec/registries/rule-paths.yaml, so renaming it in one place fails
// here rather than quietly leaving the registry describing a value no receipt
// carries. This guard never issues the denial itself -- its policy provider
// pushes each reload into SwapPolicy, so a failed reload leaves the policy
// already in force (core spec 6.2) -- but a reader of receipts an enforcement
// point of the other kind emitted needs the spelling.
func TestPolicyProviderRuleMatchesTheRegistry(t *testing.T) {
	path := filepath.Join(fixtureRepoRoot(t), "spec", "registries", "rule-paths.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the rule-path registry: %v", err)
	}
	var registry struct {
		Entries []struct {
			ID   string `yaml:"id"`
			Kind string `yaml:"kind"`
		} `yaml:"entries"`
	}
	if err := yaml.Unmarshal(raw, &registry); err != nil {
		t.Fatalf("parse the rule-path registry: %v", err)
	}
	for _, entry := range registry.Entries {
		if entry.Kind == "reserved_matched_rule" && entry.ID == PolicyProviderRule {
			return
		}
	}
	t.Fatalf("%q is not a reserved matched_rule in %s", PolicyProviderRule, path)
}

// TestGuardAcceptsASignedLeafOverAPinnedBase: a hop the child pinned by digest
// proves itself without an envelope (signing spec 6.5), and the guard's
// re-check of an adopted chain accepts exactly what resolution accepted.
func TestGuardAcceptsASignedLeafOverAPinnedBase(t *testing.T) {
	dir := policyDir(t)
	basePath := filepath.Join(dir, "base.yaml")
	writeFixtureFile(t, basePath, `
hushspec: "0.2.0"
name: pinned-base
rules:
  tool_access:
    allow: [read_file]
    default: block
`)
	childBody := `
hushspec: "0.2.0"
name: pinned-child
extends: base.yaml%s
rules:
  egress:
    allow: [api.github.com]
    default: block
`
	childPath := filepath.Join(dir, "child.yaml")
	writeFixtureFile(t, childPath, strings.Replace(childBody, "%s", "#"+ownHashOf(t, basePath), 1))
	signSidecar(t, childPath, resolveNow(t, childPath), testSigningKeyPEM(t))

	options := GuardOptions{RequireSignature: true, Keyring: testKeyring(t)}
	provider := NewFileProvider(childPath, ResolveOptions{
		RequireSignature: true,
		Keyring:          testKeyring(t),
	})
	guard, err := NewGuardFromProvider(provider, options)
	if err != nil {
		t.Fatalf("NewGuardFromProvider: %v", err)
	}
	if refused, status := guard.Refused(); refused {
		t.Fatalf("a matching pin proves the base on its own, got %+v", status)
	}
	if !egressAllowed(t, guard, "api.github.com") {
		t.Fatal("the pinned chain is not in force")
	}

	// The same chain without the pin: the base proves nothing.
	writeFixtureFile(t, childPath, strings.Replace(childBody, "%s", "", 1))
	signSidecar(t, childPath, resolveNow(t, childPath), testSigningKeyPEM(t))
	unpinned, err := ResolveFileWithOptions(childPath, ResolveOptions{Keyring: testKeyring(t)})
	if err != nil {
		t.Fatalf("resolve the unpinned chain: %v", err)
	}
	refusing, err := NewGuardFromProvider(&adoptedProvider{resolution: unpinned}, options)
	if err != nil {
		t.Fatalf("NewGuardFromProvider: %v", err)
	}
	refused, status := refusing.Refused()
	if !refused {
		t.Fatal("an unpinned, unsigned base must refuse when signatures are required")
	}
	if status.Verified || status.Reason != ReasonMissingSignature {
		t.Fatalf("expected a missing-signature status, got %+v", status)
	}
}

// TestGuardSwapPolicyLeavesTheRefusedState: a guard built refused evaluates
// again the moment a policy that proves itself is swapped in (signing spec
// 6.5).
func TestGuardSwapPolicyLeavesTheRefusedState(t *testing.T) {
	provider := &adoptedProvider{resolution: guardResolution(t, guardSpec())}
	guard, err := NewGuardFromProvider(provider, GuardOptions{RequireSignature: true})
	if err != nil {
		t.Fatalf("NewGuardFromProvider: %v", err)
	}
	if refused, _ := guard.Refused(); !refused {
		t.Fatal("an adopted chain with no verified signature must refuse")
	}

	verified := signedResolution(t, guardSpec(), "adopted://policy.yaml")
	if err := guard.SwapPolicy(verified); err != nil {
		t.Fatalf("a verified policy must be accepted: %v", err)
	}
	if refused, _ := guard.Refused(); refused {
		t.Fatal("a verified policy must leave the refused state")
	}
	if !egressAllowed(t, guard, "api.github.com") {
		t.Fatal("the swapped policy is not in force")
	}
}
