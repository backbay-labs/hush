package hushspec

import "fmt"

// ValidationResult holds the outcome of validating a HushSpec document.
type ValidationResult struct {
	Errors   []ValidationError
	Warnings []string
}

// ValidationError represents a single validation failure.
type ValidationError struct {
	Code    string
	Message string
}

// IsValid returns true when no validation errors were found.
func (r *ValidationResult) IsValid() bool {
	return len(r.Errors) == 0
}

// addError is a helper for appending a validation error.
func (r *ValidationResult) addError(code, msg string) {
	r.Errors = append(r.Errors, ValidationError{Code: code, Message: msg})
}

// addWarning is a helper for appending a warning.
func (r *ValidationResult) addWarning(msg string) {
	r.Warnings = append(r.Warnings, msg)
}

// Validate performs structural validation of a parsed HushSpec document.
// It checks version support, cross-field constraints, and internal
// consistency of rules and extensions.
func Validate(spec *HushSpec) *ValidationResult {
	result := &ValidationResult{}

	// Version check.
	if spec.HushSpecVersion == "" {
		result.addError("MISSING_VERSION", "missing or empty 'hushspec' version field")
	} else if !IsSupported(spec.HushSpecVersion) {
		result.addError("UNSUPPORTED_VERSION",
			fmt.Sprintf("unsupported HushSpec version %q; supported: %v", spec.HushSpecVersion, SupportedVersions))
	}

	// Validate merge strategy if present.
	if spec.MergeStrategy != "" {
		switch spec.MergeStrategy {
		case MergeStrategyReplace, MergeStrategyMerge, MergeStrategyDeepMerge:
			// valid
		default:
			result.addError("INVALID_MERGE_STRATEGY",
				fmt.Sprintf("invalid merge_strategy %q; must be one of: replace, merge, deep_merge", spec.MergeStrategy))
		}
	}

	// Validate rules.
	if spec.Rules != nil {
		validateRules(spec.Rules, result)
	}

	// Validate extensions.
	if spec.Extensions != nil {
		validateExtensions(spec.Extensions, result)
	}

	return result
}

// validateRules checks rule-level constraints.
func validateRules(rules *Rules, result *ValidationResult) {
	// Duplicate secret pattern names.
	if rules.SecretPatterns != nil && len(rules.SecretPatterns.Patterns) > 0 {
		seen := make(map[string]bool)
		for _, p := range rules.SecretPatterns.Patterns {
			if p.Name == "" {
				result.addError("EMPTY_PATTERN_NAME", "secret pattern has an empty name")
				continue
			}
			if seen[p.Name] {
				result.addError("DUPLICATE_PATTERN_NAME",
					fmt.Sprintf("duplicate secret pattern name %q", p.Name))
			}
			seen[p.Name] = true
		}
	}

	// Egress: default action must be valid.
	if rules.Egress != nil && rules.Egress.Enabled {
		switch rules.Egress.Default {
		case DefaultActionAllow, DefaultActionBlock:
			// valid
		case "":
			result.addWarning("egress rule enabled but no default action specified; will default to allow")
		default:
			result.addError("INVALID_DEFAULT_ACTION",
				fmt.Sprintf("egress default action %q must be 'allow' or 'block'", rules.Egress.Default))
		}
	}

	// Tool access: default action must be valid.
	if rules.ToolAccess != nil && rules.ToolAccess.Enabled {
		switch rules.ToolAccess.Default {
		case DefaultActionAllow, DefaultActionBlock:
			// valid
		case "":
			result.addWarning("tool_access rule enabled but no default action specified; will default to allow")
		default:
			result.addError("INVALID_DEFAULT_ACTION",
				fmt.Sprintf("tool_access default action %q must be 'allow' or 'block'", rules.ToolAccess.Default))
		}
	}

	// Patch integrity: negative limits.
	if rules.PatchIntegrity != nil && rules.PatchIntegrity.Enabled {
		if rules.PatchIntegrity.MaxAdditions < 0 {
			result.addError("NEGATIVE_LIMIT", "patch_integrity max_additions must be non-negative")
		}
		if rules.PatchIntegrity.MaxDeletions < 0 {
			result.addError("NEGATIVE_LIMIT", "patch_integrity max_deletions must be non-negative")
		}
		if rules.PatchIntegrity.MaxImbalanceRatio < 0 {
			result.addError("NEGATIVE_LIMIT", "patch_integrity max_imbalance_ratio must be non-negative")
		}
	}
}

// validateExtensions checks extension-level constraints.
func validateExtensions(ext *Extensions, result *ValidationResult) {
	if ext.Posture != nil {
		validatePosture(ext.Posture, result)
	}
	if ext.Origins != nil {
		validateOrigins(ext.Origins, result)
	}
	if ext.Detection != nil {
		validateDetection(ext.Detection, result)
	}
}

// validatePosture checks posture state machine consistency.
func validatePosture(p *PostureExtension, result *ValidationResult) {
	stateNames := make(map[string]bool)
	for _, s := range p.States {
		if s.Name == "" {
			result.addError("EMPTY_STATE_NAME", "posture state has an empty name")
			continue
		}
		stateNames[s.Name] = true
	}

	// Initial state must exist.
	if p.InitialState == "" {
		result.addError("MISSING_INITIAL_STATE", "posture initial_state is empty")
	} else if !stateNames[p.InitialState] {
		result.addError("INVALID_INITIAL_STATE",
			fmt.Sprintf("posture initial_state %q is not a defined state", p.InitialState))
	}

	// Transitions must reference valid states.
	for i, t := range p.Transitions {
		if !stateNames[t.From] {
			result.addError("INVALID_TRANSITION_STATE",
				fmt.Sprintf("transition[%d] 'from' state %q is not defined", i, t.From))
		}
		if !stateNames[t.To] {
			result.addError("INVALID_TRANSITION_STATE",
				fmt.Sprintf("transition[%d] 'to' state %q is not defined", i, t.To))
		}
		// Timeout requires 'after'.
		if t.Timeout != nil {
			if t.Timeout.After == "" {
				result.addError("MISSING_TIMEOUT_AFTER",
					fmt.Sprintf("transition[%d] has a timeout but 'after' is empty", i))
			}
			if t.Timeout.ReturnTo != "" && !stateNames[t.Timeout.ReturnTo] {
				result.addError("INVALID_TRANSITION_STATE",
					fmt.Sprintf("transition[%d] timeout return_to state %q is not defined", i, t.Timeout.ReturnTo))
			}
		}
	}
}

// validateOrigins checks origin profile and bridge consistency.
func validateOrigins(o *OriginsExtension, result *ValidationResult) {
	profileIDs := make(map[string]bool)
	for _, p := range o.Profiles {
		if p.ID == "" {
			result.addError("EMPTY_ORIGIN_ID", "origin profile has an empty id")
			continue
		}
		if profileIDs[p.ID] {
			result.addError("DUPLICATE_ORIGIN_ID",
				fmt.Sprintf("duplicate origin profile id %q", p.ID))
		}
		profileIDs[p.ID] = true

		// Negative budgets.
		if p.Budgets != nil {
			if p.Budgets.MaxTokensPerMinute < 0 {
				result.addError("NEGATIVE_BUDGET",
					fmt.Sprintf("origin %q max_tokens_per_minute must be non-negative", p.ID))
			}
			if p.Budgets.MaxActionsPerHour < 0 {
				result.addError("NEGATIVE_BUDGET",
					fmt.Sprintf("origin %q max_actions_per_hour must be non-negative", p.ID))
			}
		}
	}

	// Bridges must reference valid profile IDs.
	for i, b := range o.Bridges {
		if !profileIDs[b.From.OriginID] {
			result.addError("INVALID_BRIDGE_ORIGIN",
				fmt.Sprintf("bridge[%d] from origin_id %q is not a defined profile", i, b.From.OriginID))
		}
		if !profileIDs[b.To.OriginID] {
			result.addError("INVALID_BRIDGE_ORIGIN",
				fmt.Sprintf("bridge[%d] to origin_id %q is not a defined profile", i, b.To.OriginID))
		}
		if b.MaxTrustPropagation < 0 {
			result.addError("NEGATIVE_TRUST_PROPAGATION",
				fmt.Sprintf("bridge[%d] max_trust_propagation must be non-negative", i))
		}
	}
}

// validateDetection checks detection threshold ordering and range.
func validateDetection(d *DetectionExtension, result *ValidationResult) {
	// Prompt injection threshold range.
	if d.PromptInjection != nil && d.PromptInjection.Enabled {
		if d.PromptInjection.Threshold < 0.0 || d.PromptInjection.Threshold > 1.0 {
			result.addError("THRESHOLD_OUT_OF_RANGE",
				fmt.Sprintf("prompt_injection threshold %.4f must be in [0.0, 1.0]", d.PromptInjection.Threshold))
		}
	}

	// Jailbreak threshold ordering and range.
	if d.Jailbreak != nil && d.Jailbreak.Enabled {
		thresholds := []struct {
			name  string
			value float64
		}{
			{"heuristic_threshold", d.Jailbreak.HeuristicThreshold},
			{"statistical_threshold", d.Jailbreak.StatisticalThreshold},
			{"ml_threshold", d.Jailbreak.MLThreshold},
		}
		for _, t := range thresholds {
			if t.value < 0.0 || t.value > 1.0 {
				result.addError("THRESHOLD_OUT_OF_RANGE",
					fmt.Sprintf("jailbreak %s %.4f must be in [0.0, 1.0]", t.name, t.value))
			}
		}
	}

	// Threat intel similarity threshold range.
	if d.ThreatIntel != nil && d.ThreatIntel.Enabled {
		if d.ThreatIntel.SimilarityThreshold < 0.0 || d.ThreatIntel.SimilarityThreshold > 1.0 {
			result.addError("THRESHOLD_OUT_OF_RANGE",
				fmt.Sprintf("threat_intel similarity_threshold %.4f must be in [0.0, 1.0]",
					d.ThreatIntel.SimilarityThreshold))
		}
	}
}
