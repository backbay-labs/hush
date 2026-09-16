package hushspec

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

var (
	// uuidV7RE is the receipt schema's receipt_id pattern: the version nibble
	// is 7 and the variant nibble is 8, 9, a or b.
	uuidV7RE = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	// receiptTimeRE is the receipt schema's timestamp pattern: exactly
	// millisecond precision with a Z suffix.
	receiptTimeRE = regexp.MustCompile(
		`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)
	contentHashRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func minimalSpec() *HushSpec {
	return &HushSpec{
		HushSpecVersion: "0.1.0",
		Name:            strPtr("test-policy"),
	}
}

func specWithToolAccess() *HushSpec {
	return &HushSpec{
		HushSpecVersion: "0.1.0",
		Name:            strPtr("tool-policy"),
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
	config := DefaultAuditConfig()
	return &config
}

func disabledConfig() *AuditConfig {
	return &AuditConfig{Enabled: false, IncludeRuleTrace: false, RecordDuration: false}
}

// auditReceipt is the common shape of these tests: evaluate spec/action and
// return the receipt, failing the test if the document does not resolve.
func auditReceipt(t *testing.T, spec *HushSpec, action *EvaluationAction, config *AuditConfig) DecisionReceipt {
	t.Helper()
	receipt, err := EvaluateAuditedSpec(spec, action, config, nil)
	if err != nil {
		t.Fatalf("EvaluateAuditedSpec failed: %v", err)
	}
	return receipt
}

func TestEvaluateAuditedDecisionParity(t *testing.T) {
	spec := specWithToolAccess()
	action := &EvaluationAction{Type: "tool_call", Target: "read_file"}
	receipt := auditReceipt(t, spec, action, enabledConfig())
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
	receipt := auditReceipt(t, spec, action, enabledConfig())
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
	// A deny with no enforcement point is a blocked action (receipt spec 4.7).
	if receipt.Enforcement.Outcome != EnforcementOutcomeBlocked {
		t.Errorf("expected a blocked disposition, got %q", receipt.Enforcement.Outcome)
	}
}

func TestReceiptVersionAndIDAreFormat02(t *testing.T) {
	receipt := auditReceipt(t, minimalSpec(),
		&EvaluationAction{Type: "tool_call", Target: "test"}, enabledConfig())

	if receipt.ReceiptVersion != ReceiptVersion {
		t.Errorf("expected receipt_version %q, got %q", ReceiptVersion, receipt.ReceiptVersion)
	}
	if !uuidV7RE.MatchString(receipt.ReceiptID) {
		t.Errorf("receipt_id %q is not a UUID v7", receipt.ReceiptID)
	}
}

func TestReceiptTimestampIsMillisecondPrecision(t *testing.T) {
	receipt := auditReceipt(t, minimalSpec(),
		&EvaluationAction{Type: "tool_call", Target: "test"}, enabledConfig())

	if !receiptTimeRE.MatchString(receipt.Timestamp) {
		t.Errorf("timestamp %q is not RFC 3339 UTC with millisecond precision", receipt.Timestamp)
	}
	if receipt.TimeSource != TimeSourceSystem {
		t.Errorf("an unconfigured engine records the system clock, got %q", receipt.TimeSource)
	}
}

// TestFormatTimestampTruncates locks in that sub-millisecond digits are
// truncated, never rounded: a rounded timestamp could land in the future.
func TestFormatTimestampTruncates(t *testing.T) {
	instant := time.Date(2026, 9, 15, 12, 0, 0, 999_999_999, time.UTC)
	if got := FormatTimestamp(instant); got != "2026-09-15T12:00:00.999Z" {
		t.Errorf("FormatTimestamp truncates to milliseconds, got %q", got)
	}
}

func TestReceiptRecordsResolvedPolicyIdentity(t *testing.T) {
	receipt := auditReceipt(t, minimalSpec(),
		&EvaluationAction{Type: "tool_call", Target: "test"}, enabledConfig())

	if stringValue(receipt.Policy.Name) != "test-policy" {
		t.Errorf("expected policy name test-policy, got %q", stringValue(receipt.Policy.Name))
	}
	// 0.2 moved the `hushspec` field to policy.spec_version; policy.version is
	// now metadata.policy_version, which this document does not have.
	if receipt.Policy.SpecVersion != "0.1.0" {
		t.Errorf("expected spec_version 0.1.0, got %q", receipt.Policy.SpecVersion)
	}
	if receipt.Policy.Version != nil {
		t.Errorf("expected no policy version, got %d", *receipt.Policy.Version)
	}
	if !contentHashRE.MatchString(receipt.Policy.ContentHash) {
		t.Errorf("content_hash %q is not a canonical content hash", receipt.Policy.ContentHash)
	}
	if receipt.Policy.ExtendsChain != nil {
		t.Errorf("a policy with no extends records no chain, got %+v", receipt.Policy.ExtendsChain)
	}
}

func TestReceiptRecordsPolicyVersionAsAnInteger(t *testing.T) {
	version := 4
	spec := minimalSpec()
	spec.Metadata = &GovernanceMetadata{PolicyVersion: &version}
	receipt := auditReceipt(t, spec,
		&EvaluationAction{Type: "tool_call", Target: "test"}, enabledConfig())

	if receipt.Policy.Version == nil || *receipt.Policy.Version != 4 {
		t.Fatalf("expected policy version 4, got %+v", receipt.Policy.Version)
	}
	data, err := json.Marshal(receipt.Policy)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if !regexp.MustCompile(`"version":4`).Match(data) {
		t.Errorf("policy.version must serialize as an integer, got %s", data)
	}
}

func TestReceiptRecordsTheExtendsChain(t *testing.T) {
	spec, err := Parse("hushspec: \"0.1.0\"\nname: child\nextends: \"builtin:default\"\n")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	resolution, err := ResolveWithOptions(spec, "", nil, ResolveOptions{})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	receipt := EvaluateAudited(resolution,
		&EvaluationAction{Type: "tool_call", Target: "test"}, enabledConfig(), nil)

	chain := receipt.Policy.ExtendsChain
	if len(chain) != 2 {
		t.Fatalf("expected two chain links, got %+v", chain)
	}
	if chain[0].Source != "builtin:default" {
		t.Errorf("expected the base first, got %q", chain[0].Source)
	}
	if chain[1].Source != MemorySource {
		t.Errorf("expected the in-memory leaf last, got %q", chain[1].Source)
	}
	if chain[1].ContentHash == receipt.Policy.ContentHash {
		t.Error("a link's hash is that document alone, not the merged result")
	}
}

func TestRuleTracePopulatedWhenEnabled(t *testing.T) {
	receipt := auditReceipt(t, specWithToolAccess(),
		&EvaluationAction{Type: "tool_call", Target: "read_file"}, enabledConfig())

	if len(receipt.RuleTrace) == 0 {
		t.Fatal("expected non-empty rule trace")
	}
	if receipt.RuleTrace[0].RuleBlock != "tool_access" {
		t.Errorf("expected first trace block to be tool_access, got %q", receipt.RuleTrace[0].RuleBlock)
	}
	if !receipt.RuleTrace[0].Evaluated {
		t.Error("expected first trace to be evaluated")
	}
	if receipt.RuleTrace[0].RulePath == "" {
		t.Error("an evaluated block that matched records the rule path that did it")
	}
}

func TestEmptyTraceAndNoDurationWhenDisabled(t *testing.T) {
	receipt := auditReceipt(t, specWithToolAccess(),
		&EvaluationAction{Type: "tool_call", Target: "read_file"}, disabledConfig())

	if len(receipt.RuleTrace) != 0 {
		t.Errorf("expected empty trace, got %d entries", len(receipt.RuleTrace))
	}
	if receipt.DurationUs != nil {
		t.Errorf("expected no duration, got %d", *receipt.DurationUs)
	}
	// The decision and the policy identity are always correct: identity comes
	// from the resolution and costs nothing.
	if receipt.Policy.ContentHash == "" {
		t.Error("policy identity is recorded even with audit disabled")
	}
	if receipt.Decision != DecisionAllow {
		t.Errorf("expected allow, got %q", receipt.Decision)
	}
}

func TestReceiptRecordsContentHashNotContent(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Rules: &Rules{
			ShellCommands: &ShellCommandsRule{Enabled: true, ForbiddenPatterns: []string{}},
		},
	}
	action := &EvaluationAction{
		Type:    "shell_command",
		Target:  "echo hello",
		Content: strPtr("some content here"),
	}
	receipt := auditReceipt(t, spec, action, enabledConfig())

	if receipt.Action.ContentHash != DigestOf("some content here") {
		t.Errorf("expected the sha256 of the content, got %q", receipt.Action.ContentHash)
	}
	if receipt.Action.ContentSize == nil || *receipt.Action.ContentSize != 17 {
		t.Errorf("expected content_size 17, got %+v", receipt.Action.ContentSize)
	}
	data, err := json.Marshal(receipt.Action)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if regexp.MustCompile(`some content here`).Match(data) {
		t.Errorf("a receipt must never carry content: %s", data)
	}
}

// TestEmptyContentIsRecordedWithSizeZero locks in that presence is what
// matters: an explicitly empty payload records a hash and a zero size rather
// than being dropped by omitempty.
func TestEmptyContentIsRecordedWithSizeZero(t *testing.T) {
	receipt := auditReceipt(t, minimalSpec(), &EvaluationAction{
		Type: "egress", Target: "api.example.com", Content: strPtr(""),
	}, enabledConfig())

	if receipt.Action.ContentSize == nil || *receipt.Action.ContentSize != 0 {
		t.Fatalf("expected content_size 0, got %+v", receipt.Action.ContentSize)
	}
	data, err := json.Marshal(receipt.Action)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if !regexp.MustCompile(`"content_size":0`).Match(data) {
		t.Errorf("content_size 0 must survive serialization, got %s", data)
	}
}

func TestNoContentHashWhenNoContent(t *testing.T) {
	receipt := auditReceipt(t, minimalSpec(),
		&EvaluationAction{Type: "tool_call", Target: "test"}, enabledConfig())

	if receipt.Action.ContentHash != "" || receipt.Action.ContentSize != nil {
		t.Errorf("expected no content hash or size, got %+v", receipt.Action)
	}
}

func TestNonNegativeDurationWhenEnabled(t *testing.T) {
	receipt := auditReceipt(t, specWithToolAccess(),
		&EvaluationAction{Type: "tool_call", Target: "read_file"}, enabledConfig())

	if receipt.DurationUs == nil {
		t.Fatal("expected a recorded duration")
	}
	if *receipt.DurationUs < 0 {
		t.Errorf("expected non-negative duration, got %d", *receipt.DurationUs)
	}
}

func TestUniqueReceiptIDs(t *testing.T) {
	spec := minimalSpec()
	action := &EvaluationAction{Type: "tool_call", Target: "test"}
	first := auditReceipt(t, spec, action, enabledConfig())
	second := auditReceipt(t, spec, action, enabledConfig())

	if first.ReceiptID == second.ReceiptID {
		t.Error("expected unique receipt IDs")
	}
}

func TestAuditContextFixesClockActorAndID(t *testing.T) {
	clock := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	ctx := &AuditContext{
		Actor:      &Actor{AgentID: "deploy-bot-3", Runtime: "hushspec-go/0.2.0"},
		TimeSource: TimeSourceTrusted,
		Clock:      func() time.Time { return clock },
		ReceiptID:  DeterministicUUIDv7(1789473600000, 0),
	}
	receipt, err := EvaluateAuditedSpec(minimalSpec(),
		&EvaluationAction{Type: "tool_call", Target: "test"}, enabledConfig(), ctx)
	if err != nil {
		t.Fatalf("EvaluateAuditedSpec failed: %v", err)
	}

	if receipt.Timestamp != "2026-09-15T12:00:00.000Z" {
		t.Errorf("expected the fixed clock, got %q", receipt.Timestamp)
	}
	if receipt.TimeSource != TimeSourceTrusted {
		t.Errorf("expected a trusted time source, got %q", receipt.TimeSource)
	}
	if receipt.ReceiptID != "01a0a4f0-3200-7000-8000-000000000000" {
		t.Errorf("unexpected deterministic receipt id %q", receipt.ReceiptID)
	}
	if receipt.Actor == nil || receipt.Actor.AgentID != "deploy-bot-3" {
		t.Fatalf("expected the actor to be recorded, got %+v", receipt.Actor)
	}
	if receipt.Actor.SessionID != "" {
		t.Errorf("an unset actor field stays absent, got %q", receipt.Actor.SessionID)
	}
}

// TestEmptyActorIsOmitted locks in that an actor with nothing in it is absent
// rather than an empty object, which the schema's minLength rules would
// otherwise let through as noise.
func TestEmptyActorIsOmitted(t *testing.T) {
	receipt, err := EvaluateAuditedSpec(minimalSpec(),
		&EvaluationAction{Type: "tool_call", Target: "test"},
		enabledConfig(), &AuditContext{Actor: &Actor{}})
	if err != nil {
		t.Fatalf("EvaluateAuditedSpec failed: %v", err)
	}
	if receipt.Actor != nil {
		t.Errorf("expected no actor, got %+v", receipt.Actor)
	}
}

func TestDeterministicUUIDv7IsStableAndWellFormed(t *testing.T) {
	first := DeterministicUUIDv7(1757930400123, 42)
	if first != DeterministicUUIDv7(1757930400123, 42) {
		t.Error("the same inputs must produce the same id")
	}
	if first == DeterministicUUIDv7(1757930400123, 43) {
		t.Error("a different seed must produce a different id")
	}
	if !uuidV7RE.MatchString(first) {
		t.Errorf("%q is not a well-formed UUID v7", first)
	}
	// The high 48 bits are the millisecond timestamp, so ids sort by time.
	wantPrefix := fmt.Sprintf("%08x", uint64(1757930400123)>>16)
	if first[:8] != wantPrefix {
		t.Errorf("expected the timestamp %s in the high bits, got %q", wantPrefix, first)
	}
	if DeterministicUUIDv7(1757930400124, 42) <= first {
		t.Error("a later timestamp must sort after an earlier one")
	}
}

func TestUnverifiedPolicyReceipt(t *testing.T) {
	policy := PolicySummary{
		Name:        strPtr("signed-basic"),
		SpecVersion: "0.1.0",
		ContentHash: DigestOf("whatever"),
		Signature:   &SignatureStatus{Verified: false, Reason: ReasonContentHashMismatch},
	}
	receipt := UnverifiedPolicyReceipt(policy,
		&EvaluationAction{Type: "egress", Target: "api.example.com"}, nil)

	if receipt.Decision != DecisionDeny {
		t.Errorf("an unverified policy denies, got %q", receipt.Decision)
	}
	if receipt.MatchedRule != PolicyUnverifiedRule {
		t.Errorf("expected matched_rule %q, got %q", PolicyUnverifiedRule, receipt.MatchedRule)
	}
	if len(receipt.RuleTrace) != 0 {
		t.Errorf("no rule ran, so the trace is empty: %+v", receipt.RuleTrace)
	}
	if receipt.Enforcement.Outcome != EnforcementOutcomeBlocked {
		t.Errorf("expected a blocked disposition, got %q", receipt.Enforcement.Outcome)
	}
	if receipt.Policy.Signature == nil || receipt.Policy.Signature.Verified {
		t.Errorf("expected verified:false to be recorded, got %+v", receipt.Policy.Signature)
	}
}

func TestComputePolicyHashIsTheCanonicalHash(t *testing.T) {
	spec := minimalSpec()
	hash := ComputePolicyHash(spec)

	if !contentHashRE.MatchString(hash) {
		t.Errorf("hash %q is not a \"sha256:\"-prefixed content hash", hash)
	}
	canonical, err := ContentHash(spec)
	if err != nil {
		t.Fatalf("ContentHash failed: %v", err)
	}
	if hash != canonical {
		t.Errorf("ComputePolicyHash must be the canonical hash: %q vs %q", hash, canonical)
	}
	if hash != ComputePolicyHash(spec) {
		t.Error("hash not deterministic")
	}
	other := &HushSpec{HushSpecVersion: "0.1.0", Name: strPtr("different-policy")}
	if hash == ComputePolicyHash(other) {
		t.Error("expected different hashes for different specs")
	}
}

// TestComputePolicyHashRefusesAnUnresolvedDocument locks in that a document
// still declaring `extends` has no canonical form and therefore no identity.
func TestComputePolicyHashRefusesAnUnresolvedDocument(t *testing.T) {
	spec := minimalSpec()
	spec.Extends = strPtr("builtin:default")
	if got := ComputePolicyHash(spec); got != "" {
		t.Errorf("an unresolved document has no content hash, got %q", got)
	}
}

func TestReceiptCanonicalFormAndHash(t *testing.T) {
	receipt := auditReceipt(t, specWithToolAccess(),
		&EvaluationAction{Type: "tool_call", Target: "read_file"}, disabledConfig())

	canonical, err := receipt.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON failed: %v", err)
	}
	// RFC 8785: no whitespace between tokens, members in UTF-16 code-unit
	// order. (Whitespace inside a string value is content, not formatting.)
	for _, formatting := range []string{"\n", "\t", `": `, `", `, "{ ", "[ "} {
		if strings.Contains(canonical, formatting) {
			t.Errorf("the canonical form carries no whitespace between tokens: %s", canonical)
		}
	}
	if canonical[:8] != `{"action` {
		t.Errorf("expected members in code-unit order, got %s", canonical[:32])
	}
	hash, err := receipt.ReceiptHash()
	if err != nil {
		t.Fatalf("ReceiptHash failed: %v", err)
	}
	if hash != DigestOf(canonical) {
		t.Errorf("the receipt hash is sha256 over the canonical form, got %q", hash)
	}
}

func TestReceiptRoundTripsThroughParse(t *testing.T) {
	receipt := auditReceipt(t, specWithToolAccess(),
		&EvaluationAction{Type: "tool_call", Target: "read_file"}, disabledConfig())

	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	parsed, err := ParseReceipt(data)
	if err != nil {
		t.Fatalf("ParseReceipt failed: %v", err)
	}
	before, err := receipt.ReceiptHash()
	if err != nil {
		t.Fatalf("ReceiptHash failed: %v", err)
	}
	after, err := parsed.ReceiptHash()
	if err != nil {
		t.Fatalf("ReceiptHash failed: %v", err)
	}
	if before != after {
		t.Errorf("a parsed receipt must re-serialize to the same canonical form: %q vs %q", before, after)
	}
}

func TestParseReceiptRejectsOtherVersionsAndUnknownFields(t *testing.T) {
	if _, err := ParseReceipt([]byte(`{"receipt_version":"0.1"}`)); err == nil {
		t.Error("expected 0.1 to be rejected")
	}
	// 0.1's top-level hushspec_version is an unknown field in 0.2.
	legacy := []byte(`{"receipt_version":"0.2","hushspec_version":"0.1.0"}`)
	if _, err := ParseReceipt(legacy); err == nil {
		t.Error("expected an unknown field to be rejected")
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
	receipt := auditReceipt(t, spec,
		&EvaluationAction{Type: "egress", Target: "api.example.com"}, enabledConfig())

	if receipt.Decision != DecisionAllow {
		t.Errorf("expected allow, got %q", receipt.Decision)
	}
	entry := findTraceEntry(t, receipt, "egress")
	if !entry.Evaluated {
		t.Error("expected egress trace to be evaluated")
	}
	if entry.Outcome != RuleOutcomeAllow {
		t.Errorf("expected allow outcome, got %q", entry.Outcome)
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
	receipt := auditReceipt(t, spec,
		&EvaluationAction{Type: "shell_command", Target: "ls -la"}, enabledConfig())

	if receipt.Decision != DecisionAllow {
		t.Errorf("expected allow, got %q", receipt.Decision)
	}
	entry := findTraceEntry(t, receipt, "shell_commands")
	if !entry.Evaluated || entry.Outcome != RuleOutcomeAllow {
		t.Errorf("expected an evaluated allow, got %+v", entry)
	}
}

func TestTraceSkipUnconfiguredToolAccess(t *testing.T) {
	receipt := auditReceipt(t, &HushSpec{HushSpecVersion: "0.1.0"},
		&EvaluationAction{Type: "tool_call", Target: "test"}, enabledConfig())

	entry := findTraceEntry(t, receipt, "tool_access")
	if entry.Evaluated {
		t.Error("an absent block is applicable but inert, not evaluated")
	}
	if entry.Outcome != RuleOutcomeSkip {
		t.Errorf("expected skip outcome, got %q", entry.Outcome)
	}
	if entry.Reason == "" {
		t.Error("a skip entry names why the block was inert")
	}
}

// TestTraceUnknownActionType locks in receipt spec 4.3 item 5: the engine
// stage the evaluator records under `default` is written to a receipt under
// the closed id `unknown_action_type`.
func TestTraceUnknownActionType(t *testing.T) {
	receipt := auditReceipt(t, &HushSpec{HushSpecVersion: "0.1.0"},
		&EvaluationAction{Type: "unknown_action", Target: "test"}, enabledConfig())

	// An action type unknown to the specification denies (core spec 5).
	if receipt.Decision != DecisionDeny {
		t.Errorf("expected deny, got %q", receipt.Decision)
	}
	if receipt.MatchedRule != UnknownActionTypeRule {
		t.Errorf("expected matched_rule %q, got %q", UnknownActionTypeRule, receipt.MatchedRule)
	}
	entry := findTraceEntry(t, receipt, UnknownActionTypeBlock)
	if !entry.Evaluated {
		t.Error("expected the unknown-action stage to be evaluated")
	}
	for _, other := range receipt.RuleTrace {
		if other.RuleBlock == "default" {
			t.Error("the receipt spelling is unknown_action_type, never default")
		}
	}
}

func findTraceEntry(t *testing.T, receipt DecisionReceipt, block string) RuleTraceEntry {
	t.Helper()
	for _, entry := range receipt.RuleTrace {
		if entry.RuleBlock == block {
			return entry
		}
	}
	t.Fatalf("no %q trace entry found in %+v", block, receipt.RuleTrace)
	return RuleTraceEntry{}
}
