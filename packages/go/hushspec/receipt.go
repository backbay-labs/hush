package hushspec

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// DecisionReceipt is an auditable record of a single policy evaluation.
type DecisionReceipt struct {
	ReceiptID            string              `json:"receipt_id"`
	Timestamp            string              `json:"timestamp"`
	HushSpecVersion      string              `json:"hushspec_version"`
	Action               ActionSummary       `json:"action"`
	Decision             Decision            `json:"decision"`
	MatchedRule          string              `json:"matched_rule,omitempty"`
	Reason               string              `json:"reason,omitempty"`
	RuleTrace            []RuleEvaluation    `json:"rule_trace"`
	Policy               PolicySummary       `json:"policy"`
	OriginProfile        string              `json:"origin_profile,omitempty"`
	Posture              *PostureResult      `json:"posture,omitempty"`
	EvaluationDurationUs int64               `json:"evaluation_duration_us"`
	Enforcement          *EnforcementSummary `json:"enforcement,omitempty"`
}

// EnforcementSummary records how the runtime applied a decision. The
// Decision field on the receipt is always the evaluated policy decision;
// this records what the enforcement point did with it.
type EnforcementSummary struct {
	Mode    string `json:"mode"`    // "enforce" | "monitor"
	Outcome string `json:"outcome"` // "allowed" | "confirmed" | "blocked" | "would_block"
}

type ActionSummary struct {
	Type            string `json:"type"`
	Target          string `json:"target,omitempty"`
	ContentRedacted bool   `json:"content_redacted,omitempty"`
}

type RuleOutcome string

const (
	RuleOutcomeAllow RuleOutcome = "allow"
	RuleOutcomeWarn  RuleOutcome = "warn"
	RuleOutcomeDeny  RuleOutcome = "deny"
	RuleOutcomeSkip  RuleOutcome = "skip"
)

type RuleEvaluation struct {
	RuleBlock   string      `json:"rule_block"`
	Outcome     RuleOutcome `json:"outcome"`
	MatchedRule string      `json:"matched_rule,omitempty"`
	Reason      string      `json:"reason,omitempty"`
	Evaluated   bool        `json:"evaluated"`
}

type PolicySummary struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version"`
	// ContentHash is the SHA-256 hex digest of the canonical JSON
	// serialization of the resolved policy document. Omitted when audit is
	// disabled -- the zero-overhead disabled-audit fast path never computes
	// a hash, so the field is absent rather than an empty string.
	ContentHash string `json:"content_hash,omitempty"`
}

// AuditConfig controls receipt verbosity. When Enabled is false, the receipt
// contains the correct decision but skips timing, rule trace, and policy hashing.
type AuditConfig struct {
	Enabled          bool
	IncludeRuleTrace bool
	RedactContent    bool
}

// DefaultAuditConfig returns an AuditConfig with all features enabled.
func DefaultAuditConfig() AuditConfig {
	return AuditConfig{
		Enabled:          true,
		IncludeRuleTrace: true,
		RedactContent:    true,
	}
}

// EvaluateAudited wraps Evaluate with timing, rule trace collection, and
// policy hashing, returning a full DecisionReceipt.
func EvaluateAudited(spec *HushSpec, action *EvaluationAction, config *AuditConfig) DecisionReceipt {
	var start time.Time
	if config.Enabled {
		start = time.Now()
	}

	traced := EvaluateTraced(spec, action, nil, nil)
	result := traced.Result

	var durationUs int64
	if config.Enabled {
		durationUs = time.Since(start).Microseconds()
	}

	// The trace is recorded by the evaluator itself, in evaluation order, so it
	// reflects exactly the blocks that ran under the Section 6.1 aggregation
	// rather than being reconstructed from the final decision.
	ruleTrace := []RuleEvaluation{}
	if config.Enabled && config.IncludeRuleTrace {
		ruleTrace = traced.Trace
	}

	var policy PolicySummary
	if config.Enabled {
		policy = buildPolicySummary(spec)
	} else {
		policy = PolicySummary{
			Name:        spec.Name,
			Version:     spec.HushSpecVersion,
			ContentHash: "",
		}
	}

	actionSummary := ActionSummary{
		Type:            action.Type,
		Target:          action.Target,
		ContentRedacted: config.RedactContent && action.HasContent(),
	}

	return DecisionReceipt{
		ReceiptID:            generateUUIDv4(),
		Timestamp:            time.Now().UTC().Format(time.RFC3339Nano),
		HushSpecVersion:      Version,
		Action:               actionSummary,
		Decision:             result.Decision,
		MatchedRule:          result.MatchedRule,
		Reason:               result.Reason,
		RuleTrace:            ruleTrace,
		Policy:               policy,
		OriginProfile:        result.OriginProfile,
		Posture:              result.Posture,
		EvaluationDurationUs: durationUs,
	}
}

// ComputePolicyHash returns the SHA-256 hex digest of the JSON-serialized spec.
//
// Deprecated for policy identity: this digest covers Go's own struct
// serialization, so the same document hashes differently in each SDK. The
// portable policy identity is [ContentHash], the "sha256:"-prefixed digest of
// the canonical form defined by spec/hushspec-canonical.md. Receipts keep this
// legacy bare-hex digest until they move to the v0.2 schema (RFC 09 P2-04),
// which switches PolicySummary.ContentHash to the canonical digest.
func ComputePolicyHash(spec *HushSpec) string {
	jsonBytes, err := json.Marshal(spec)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(jsonBytes)
	return fmt.Sprintf("%x", hash[:])
}

func generateUUIDv4() string {
	var uuid [16]byte
	_, _ = rand.Read(uuid[:])
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

func buildPolicySummary(spec *HushSpec) PolicySummary {
	return PolicySummary{
		Name:        spec.Name,
		Version:     spec.HushSpecVersion,
		ContentHash: ComputePolicyHash(spec),
	}
}

func outcomeFromDecision(decision Decision) RuleOutcome {
	switch decision {
	case DecisionAllow:
		return RuleOutcomeAllow
	case DecisionWarn:
		return RuleOutcomeWarn
	case DecisionDeny:
		return RuleOutcomeDeny
	default:
		return RuleOutcomeAllow
	}
}
