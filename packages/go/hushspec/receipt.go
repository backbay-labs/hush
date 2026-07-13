package hushspec

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
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
	Name        string `json:"name,omitempty"`
	Version     string `json:"version"`
	ContentHash string `json:"content_hash"`
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

	result := Evaluate(spec, action)

	var durationUs int64
	if config.Enabled {
		durationUs = time.Since(start).Microseconds()
	}

	var ruleTrace []RuleEvaluation
	if config.Enabled && config.IncludeRuleTrace {
		ruleTrace = collectRuleTrace(spec, action, &result)
	} else {
		ruleTrace = []RuleEvaluation{}
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
		ContentRedacted: config.RedactContent && action.Content != "",
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

func collectRuleTrace(
	spec *HushSpec,
	action *EvaluationAction,
	result *EvaluationResult,
) []RuleEvaluation {
	var trace []RuleEvaluation

	if result.Posture != nil {
		postureDenied := result.MatchedRule != "" &&
			strings.HasPrefix(result.MatchedRule, "extensions.posture.states.")

		if postureDenied {
			trace = append(trace, RuleEvaluation{
				RuleBlock:   "posture_capability",
				Outcome:     RuleOutcomeDeny,
				MatchedRule: result.MatchedRule,
				Reason:      result.Reason,
				Evaluated:   true,
			})
			appendSkippedRules(action, &trace, "short-circuited by posture deny")
			return trace
		}

		trace = append(trace, RuleEvaluation{
			RuleBlock: "posture_capability",
			Outcome:   RuleOutcomeAllow,
			Reason:    "posture capabilities satisfied",
			Evaluated: true,
		})
	}

	switch action.Type {
	case "tool_call":
		traceToolAccess(spec, action, result, &trace)
	case "egress":
		traceEgressBlock(spec, result, &trace)
	case "file_read":
		tracePathGuards(spec, result, &trace)
	case "file_write":
		tracePathGuards(spec, result, &trace)
		traceSecretPatterns(spec, result, &trace)
	case "patch_apply":
		tracePathGuards(spec, result, &trace)
		tracePatchIntegrity(spec, result, &trace)
	case "shell_command":
		traceShellCommands(spec, result, &trace)
	case "computer_use":
		traceComputerUse(spec, result, &trace)
	default:
		trace = append(trace, RuleEvaluation{
			RuleBlock:   "default",
			Outcome:     outcomeFromDecision(result.Decision),
			MatchedRule: result.MatchedRule,
			Reason:      result.Reason,
			Evaluated:   true,
		})
	}

	return trace
}

func traceToolAccess(
	spec *HushSpec,
	action *EvaluationAction,
	result *EvaluationResult,
	trace *[]RuleEvaluation,
) {
	hasOriginRule := result.MatchedRule != "" &&
		strings.HasPrefix(result.MatchedRule, "extensions.origins.profiles.")

	hasRule := hasOriginRule ||
		(spec.Rules != nil && spec.Rules.ToolAccess != nil) ||
		action.Origin != nil

	if hasRule {
		*trace = append(*trace, RuleEvaluation{
			RuleBlock:   "tool_access",
			Outcome:     outcomeFromDecision(result.Decision),
			MatchedRule: result.MatchedRule,
			Reason:      result.Reason,
			Evaluated:   true,
		})
	} else {
		*trace = append(*trace, RuleEvaluation{
			RuleBlock: "tool_access",
			Outcome:   RuleOutcomeSkip,
			Reason:    "no tool_access rule configured",
			Evaluated: false,
		})
	}
}

func traceEgressBlock(
	spec *HushSpec,
	result *EvaluationResult,
	trace *[]RuleEvaluation,
) {
	hasOriginRule := result.MatchedRule != "" &&
		strings.Contains(result.MatchedRule, "egress")

	hasRule := hasOriginRule ||
		(spec.Rules != nil && spec.Rules.Egress != nil)

	if hasRule {
		*trace = append(*trace, RuleEvaluation{
			RuleBlock:   "egress",
			Outcome:     outcomeFromDecision(result.Decision),
			MatchedRule: result.MatchedRule,
			Reason:      result.Reason,
			Evaluated:   true,
		})
	} else {
		*trace = append(*trace, RuleEvaluation{
			RuleBlock: "egress",
			Outcome:   RuleOutcomeSkip,
			Reason:    "no egress rule configured",
			Evaluated: false,
		})
	}
}

func tracePathGuards(
	spec *HushSpec,
	result *EvaluationResult,
	trace *[]RuleEvaluation,
) {
	rules := spec.Rules
	decidedByForbidden := result.MatchedRule != "" &&
		strings.Contains(result.MatchedRule, "forbidden_paths")
	decidedByAllowlist := result.MatchedRule != "" &&
		strings.Contains(result.MatchedRule, "path_allowlist")

	if rules != nil && rules.ForbiddenPaths != nil {
		fp := rules.ForbiddenPaths
		if fp.Enabled {
			if decidedByForbidden {
				*trace = append(*trace, RuleEvaluation{
					RuleBlock:   "forbidden_paths",
					Outcome:     outcomeFromDecision(result.Decision),
					MatchedRule: result.MatchedRule,
					Reason:      result.Reason,
					Evaluated:   true,
				})
			} else {
				*trace = append(*trace, RuleEvaluation{
					RuleBlock: "forbidden_paths",
					Outcome:   RuleOutcomeAllow,
					Reason:    "path did not match any forbidden pattern",
					Evaluated: true,
				})
			}
		} else {
			*trace = append(*trace, RuleEvaluation{
				RuleBlock: "forbidden_paths",
				Outcome:   RuleOutcomeSkip,
				Reason:    "rule disabled",
				Evaluated: false,
			})
		}
	}

	if rules != nil && rules.PathAllowlist != nil {
		pa := rules.PathAllowlist
		if pa.Enabled {
			shortCircuited := decidedByForbidden && result.Decision == DecisionDeny
			if shortCircuited {
				*trace = append(*trace, RuleEvaluation{
					RuleBlock: "path_allowlist",
					Outcome:   RuleOutcomeSkip,
					Reason:    "short-circuited by prior deny",
					Evaluated: false,
				})
			} else if decidedByAllowlist {
				*trace = append(*trace, RuleEvaluation{
					RuleBlock:   "path_allowlist",
					Outcome:     outcomeFromDecision(result.Decision),
					MatchedRule: result.MatchedRule,
					Reason:      result.Reason,
					Evaluated:   true,
				})
			} else {
				*trace = append(*trace, RuleEvaluation{
					RuleBlock: "path_allowlist",
					Outcome:   RuleOutcomeAllow,
					Reason:    "path matched allowlist",
					Evaluated: true,
				})
			}
		} else {
			*trace = append(*trace, RuleEvaluation{
				RuleBlock: "path_allowlist",
				Outcome:   RuleOutcomeSkip,
				Reason:    "rule disabled",
				Evaluated: false,
			})
		}
	}
}

func traceSecretPatterns(
	spec *HushSpec,
	result *EvaluationResult,
	trace *[]RuleEvaluation,
) {
	decidedBySecret := result.MatchedRule != "" &&
		strings.Contains(result.MatchedRule, "secret_patterns")
	priorDeny := hasPriorDeny(*trace)

	if spec.Rules != nil && spec.Rules.SecretPatterns != nil {
		sp := spec.Rules.SecretPatterns
		if sp.Enabled {
			if priorDeny {
				*trace = append(*trace, RuleEvaluation{
					RuleBlock: "secret_patterns",
					Outcome:   RuleOutcomeSkip,
					Reason:    "short-circuited by prior deny",
					Evaluated: false,
				})
			} else if decidedBySecret {
				*trace = append(*trace, RuleEvaluation{
					RuleBlock:   "secret_patterns",
					Outcome:     outcomeFromDecision(result.Decision),
					MatchedRule: result.MatchedRule,
					Reason:      result.Reason,
					Evaluated:   true,
				})
			} else {
				*trace = append(*trace, RuleEvaluation{
					RuleBlock: "secret_patterns",
					Outcome:   RuleOutcomeAllow,
					Reason:    "content did not match any secret pattern",
					Evaluated: true,
				})
			}
		} else {
			*trace = append(*trace, RuleEvaluation{
				RuleBlock: "secret_patterns",
				Outcome:   RuleOutcomeSkip,
				Reason:    "rule disabled",
				Evaluated: false,
			})
		}
	}
}

func tracePatchIntegrity(
	spec *HushSpec,
	result *EvaluationResult,
	trace *[]RuleEvaluation,
) {
	decidedByPatch := result.MatchedRule != "" &&
		strings.Contains(result.MatchedRule, "patch_integrity")
	priorDeny := hasPriorDeny(*trace)

	if spec.Rules != nil && spec.Rules.PatchIntegrity != nil {
		pi := spec.Rules.PatchIntegrity
		if pi.Enabled {
			if priorDeny {
				*trace = append(*trace, RuleEvaluation{
					RuleBlock: "patch_integrity",
					Outcome:   RuleOutcomeSkip,
					Reason:    "short-circuited by prior deny",
					Evaluated: false,
				})
			} else if decidedByPatch {
				*trace = append(*trace, RuleEvaluation{
					RuleBlock:   "patch_integrity",
					Outcome:     outcomeFromDecision(result.Decision),
					MatchedRule: result.MatchedRule,
					Reason:      result.Reason,
					Evaluated:   true,
				})
			} else {
				*trace = append(*trace, RuleEvaluation{
					RuleBlock: "patch_integrity",
					Outcome:   RuleOutcomeAllow,
					Reason:    "patch passed integrity checks",
					Evaluated: true,
				})
			}
		} else {
			*trace = append(*trace, RuleEvaluation{
				RuleBlock: "patch_integrity",
				Outcome:   RuleOutcomeSkip,
				Reason:    "rule disabled",
				Evaluated: false,
			})
		}
	}
}

func traceShellCommands(
	spec *HushSpec,
	result *EvaluationResult,
	trace *[]RuleEvaluation,
) {
	decidedByShell := result.MatchedRule != "" &&
		strings.Contains(result.MatchedRule, "shell_commands")

	if spec.Rules != nil && spec.Rules.ShellCommands != nil {
		sc := spec.Rules.ShellCommands
		if sc.Enabled {
			if decidedByShell {
				*trace = append(*trace, RuleEvaluation{
					RuleBlock:   "shell_commands",
					Outcome:     outcomeFromDecision(result.Decision),
					MatchedRule: result.MatchedRule,
					Reason:      result.Reason,
					Evaluated:   true,
				})
			} else {
				*trace = append(*trace, RuleEvaluation{
					RuleBlock: "shell_commands",
					Outcome:   RuleOutcomeAllow,
					Reason:    "command did not match any forbidden pattern",
					Evaluated: true,
				})
			}
		} else {
			*trace = append(*trace, RuleEvaluation{
				RuleBlock: "shell_commands",
				Outcome:   RuleOutcomeSkip,
				Reason:    "rule disabled",
				Evaluated: false,
			})
		}
	}
}

func traceComputerUse(
	spec *HushSpec,
	result *EvaluationResult,
	trace *[]RuleEvaluation,
) {
	decidedByComputer := result.MatchedRule != "" &&
		strings.Contains(result.MatchedRule, "computer_use")

	if spec.Rules != nil && spec.Rules.ComputerUse != nil {
		cu := spec.Rules.ComputerUse
		if cu.Enabled {
			if decidedByComputer {
				*trace = append(*trace, RuleEvaluation{
					RuleBlock:   "computer_use",
					Outcome:     outcomeFromDecision(result.Decision),
					MatchedRule: result.MatchedRule,
					Reason:      result.Reason,
					Evaluated:   true,
				})
			} else {
				*trace = append(*trace, RuleEvaluation{
					RuleBlock: "computer_use",
					Outcome:   RuleOutcomeAllow,
					Reason:    "action allowed by computer_use rule",
					Evaluated: true,
				})
			}
		} else {
			*trace = append(*trace, RuleEvaluation{
				RuleBlock: "computer_use",
				Outcome:   RuleOutcomeSkip,
				Reason:    "rule disabled",
				Evaluated: false,
			})
		}
	}
}

func hasPriorDeny(trace []RuleEvaluation) bool {
	for _, t := range trace {
		if t.Outcome == RuleOutcomeDeny && t.Evaluated {
			return true
		}
	}
	return false
}

func appendSkippedRules(
	action *EvaluationAction,
	trace *[]RuleEvaluation,
	reason string,
) {
	var blocks []string
	switch action.Type {
	case "tool_call":
		blocks = []string{"tool_access"}
	case "egress":
		blocks = []string{"egress"}
	case "file_read":
		blocks = []string{"forbidden_paths", "path_allowlist"}
	case "file_write":
		blocks = []string{"forbidden_paths", "path_allowlist", "secret_patterns"}
	case "patch_apply":
		blocks = []string{"forbidden_paths", "path_allowlist", "patch_integrity"}
	case "shell_command":
		blocks = []string{"shell_commands"}
	case "computer_use":
		blocks = []string{"computer_use"}
	}

	for _, block := range blocks {
		*trace = append(*trace, RuleEvaluation{
			RuleBlock: block,
			Outcome:   RuleOutcomeSkip,
			Reason:    reason,
			Evaluated: false,
		})
	}
}
