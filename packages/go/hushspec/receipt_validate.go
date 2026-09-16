package hushspec

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Structural validation of a decision receipt against
// schemas/hushspec-receipt.v1.schema.json.
//
// Parsing already enforces the schema's types and `additionalProperties:
// false` (unknown members are a parse error). What a typed model cannot say is
// the rest: which string values are in a closed enum, which match a pattern,
// and which members are required. This file closes that gap, so that
// [ParseReceipt] accepts exactly the documents the schema does -- receipt spec
// section 2, conformance item 4.
//
// It is a focused checker rather than a general JSON Schema engine: the schema
// is normative and stable, and a dependency-free SDK cannot carry a validator.
// Every rule below cites the member it comes from.

var (
	// receiptIDPattern is $.receipt_id: a UUID v7, lowercase, with the version
	// nibble 7 and the RFC 4122 variant bits.
	receiptIDPattern = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	// receiptTimestampPattern is $.timestamp: RFC 3339 UTC with exactly three
	// fractional digits and a Z suffix.
	receiptTimestampPattern = regexp.MustCompile(
		`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)
	// receiptSpecVersionPattern is $defs.PolicySummary.spec_version. The v1
	// schema widened it to the 1.x lineage, so a receipt for a 1.0.z policy
	// validates (core spec 10.2).
	receiptSpecVersionPattern = regexp.MustCompile(`^(0|1)\.[0-9]+\.[0-9]+$`)
)

// receiptTimeSources is $.time_source (receipt spec 3.3).
var receiptTimeSources = []TimeSource{
	TimeSourceSystem, TimeSourceMonotonicAdjusted, TimeSourceTrusted, TimeSourceUnknown,
}

// receiptDecisions is $.decision (core spec 6).
var receiptDecisions = []Decision{DecisionAllow, DecisionWarn, DecisionDeny}

// receiptRuleOutcomes is $defs.RuleEvaluation.outcome.
var receiptRuleOutcomes = []RuleOutcome{
	RuleOutcomeAllow, RuleOutcomeWarn, RuleOutcomeDeny, RuleOutcomeSkip,
}

// ReceiptRuleBlocks is $defs.RuleEvaluation.rule_block: the twelve rule-block
// ids, which are the keys of `rules` exactly, followed by the five engine
// stages of receipt spec 4.3 item 5.
//
// The bare spellings are normative: format 0.1 mixed `egress` and
// `rules.egress`, and 0.2 closed the enum on the bare ids.
var ReceiptRuleBlocks = []string{
	"forbidden_paths",
	"path_allowlist",
	"egress",
	"secret_patterns",
	"patch_integrity",
	"shell_commands",
	"tool_access",
	"computer_use",
	"remote_desktop_channels",
	"input_injection",
	"browser_automation",
	"code_execution",
	"posture_capability",
	"origin_profile",
	"panic",
	"unknown_action_type",
	"default",
}

// receiptDetectionCategories is $defs.DetectorEvaluation.category.
var receiptDetectionCategories = []DetectionCategory{
	DetectionCategoryPromptInjection,
	DetectionCategoryJailbreak,
	DetectionCategoryDataExfil,
	"threat_intel",
}

// receiptDetectorLevels is $defs.DetectorEvaluation.level.
var receiptDetectorLevels = []DetectorLevel{
	DetectorLevelNone, DetectorLevelLow, DetectorLevelSuspicious,
	DetectorLevelHigh, DetectorLevelCritical,
}

// receiptEnforcementModes and receiptEnforcementOutcomes are
// $defs.EnforcementSummary.
var (
	receiptEnforcementModes    = []EnforcementMode{EnforcementModeEnforce, EnforcementModeMonitor}
	receiptEnforcementOutcomes = []EnforcementOutcome{
		EnforcementOutcomeAllowed, EnforcementOutcomeConfirmed,
		EnforcementOutcomeBlocked, EnforcementOutcomeWouldBlock,
	}
)

// Validate checks a receipt against the structural rules of the 0.2 schema
// that a typed model cannot express: closed enums, string patterns, required
// members, and non-negative sizes.
//
// It reports every problem it finds rather than the first, because a receipt
// that fails several rules is usually one bug, and an auditor reading the
// report wants the whole picture.
func (r *DecisionReceipt) Validate() error {
	problems := r.structuralProblems()
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("receipt does not satisfy the 0.2 schema: %s", strings.Join(problems, "; "))
}

func (r *DecisionReceipt) structuralProblems() []string {
	var problems []string
	report := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}
	requirePattern := func(field, value string, pattern *regexp.Regexp) {
		if !pattern.MatchString(value) {
			report("%s %q does not match %s", field, value, pattern)
		}
	}
	requireContentHash := func(field, value string) {
		requirePattern(field, value, signingDigestPattern)
	}
	// The pattern fixes the spelling; parsing rejects an impossible calendar
	// date such as February 30, as the other SDKs do.
	requireTimestamp := func(field, value string) {
		if !receiptTimestampPattern.MatchString(value) {
			report("%s %q does not match %s", field, value, receiptTimestampPattern)
			return
		}
		if _, err := time.Parse("2006-01-02T15:04:05.000Z", value); err != nil {
			report("%s %q is not a calendar instant", field, value)
		}
	}

	if r.ReceiptVersion != ReceiptVersion {
		report("receipt_version %q is not %q", r.ReceiptVersion, ReceiptVersion)
	}
	requirePattern("receipt_id", r.ReceiptID, receiptIDPattern)
	requireTimestamp("timestamp", r.Timestamp)
	if !slices.Contains(receiptTimeSources, r.TimeSource) {
		report("time_source %q is outside the closed enum", r.TimeSource)
	}

	// policy (receipt spec 4.2).
	requirePattern("policy.spec_version", r.Policy.SpecVersion, receiptSpecVersionPattern)
	requireContentHash("policy.content_hash", r.Policy.ContentHash)
	if r.Policy.Version != nil && *r.Policy.Version < 0 {
		report("policy.version %d is negative", *r.Policy.Version)
	}
	for index, link := range r.Policy.ExtendsChain {
		if link.Source == "" {
			report("policy.extends_chain[%d].source is empty", index)
		}
		requireContentHash(fmt.Sprintf("policy.extends_chain[%d].content_hash", index), link.ContentHash)
	}
	if status := r.Policy.Signature; status != nil {
		if status.KeyID != "" {
			requireContentHash("policy.signature.key_id", status.KeyID)
		}
		if status.VerifiedAt != "" {
			requireTimestamp("policy.signature.verified_at", status.VerifiedAt)
		}
	}

	// action (receipt spec 4.4).
	if r.Action.Type == "" {
		report("action.type is empty")
	}
	if r.Action.ContentHash != "" {
		requireContentHash("action.content_hash", r.Action.ContentHash)
	}
	if r.Action.ContentSize != nil && *r.Action.ContentSize < 0 {
		report("action.content_size %d is negative", *r.Action.ContentSize)
	}
	if r.Action.ArgsSize != nil && *r.Action.ArgsSize < 0 {
		report("action.args_size %d is negative", *r.Action.ArgsSize)
	}

	if !slices.Contains(receiptDecisions, r.Decision) {
		report("decision %q is outside the closed enum", r.Decision)
	}

	// rule_trace (receipt spec 4.3).
	for index, entry := range r.RuleTrace {
		if !slices.Contains(ReceiptRuleBlocks, entry.RuleBlock) {
			report("rule_trace[%d].rule_block %q is outside the closed enum", index, entry.RuleBlock)
		}
		if !slices.Contains(receiptRuleOutcomes, entry.Outcome) {
			report("rule_trace[%d].outcome %q is outside the closed enum", index, entry.Outcome)
		}
	}

	// detection_trace (receipt spec 4.6).
	if r.DetectionTrace != nil {
		for index, entry := range *r.DetectionTrace {
			if entry.DetectorID == "" {
				report("detection_trace[%d].detector_id is empty", index)
			}
			if !slices.Contains(receiptDetectionCategories, entry.Category) {
				report("detection_trace[%d].category %q is outside the closed enum",
					index, entry.Category)
			}
			if entry.Score < 0 || entry.Score > 1 {
				report("detection_trace[%d].score %v is outside [0, 1]", index, entry.Score)
			}
			if !slices.Contains(receiptDetectorLevels, entry.Level) {
				report("detection_trace[%d].level %q is outside the closed enum", index, entry.Level)
			}
		}
	}

	// enforcement (receipt spec 4.7): required in 0.2, so an absent member
	// arrives here as the zero value and fails both enum checks.
	if !slices.Contains(receiptEnforcementModes, r.Enforcement.Mode) {
		report("enforcement.mode %q is outside the closed enum", r.Enforcement.Mode)
	}
	if !slices.Contains(receiptEnforcementOutcomes, r.Enforcement.Outcome) {
		report("enforcement.outcome %q is outside the closed enum", r.Enforcement.Outcome)
	}

	// posture (receipt spec 4.8).
	if r.Posture != nil {
		if r.Posture.Current == "" {
			report("posture.current is empty")
		}
		if r.Posture.Next == "" {
			report("posture.next is empty")
		}
	}

	if r.DurationUs != nil && *r.DurationUs < 0 {
		report("duration_us %d is negative", *r.DurationUs)
	}
	return problems
}
