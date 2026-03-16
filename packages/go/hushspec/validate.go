package hushspec

import (
	"fmt"
	"regexp"
)

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

	if spec.HushSpecVersion == "" {
		result.addError("MISSING_VERSION", "missing or empty 'hushspec' version field")
	} else if !IsSupported(spec.HushSpecVersion) {
		result.addError("UNSUPPORTED_VERSION",
			fmt.Sprintf("unsupported HushSpec version %q; supported: %v", spec.HushSpecVersion, SupportedVersions))
	}

	if spec.MergeStrategy != "" && !containsTyped(spec.MergeStrategy, MergeStrategies) {
		result.addError("INVALID_MERGE_STRATEGY",
			fmt.Sprintf("invalid merge_strategy %q; must be one of: replace, merge, deep_merge", spec.MergeStrategy))
	}

	if spec.Rules != nil {
		validateRules(spec.Rules, result)
	}
	if spec.Extensions != nil {
		validateExtensions(spec.Extensions, result)
	}

	return result
}

func validateRules(rules *Rules, result *ValidationResult) {
	if rules.SecretPatterns != nil {
		seen := make(map[string]bool)
		for _, pattern := range rules.SecretPatterns.Patterns {
			if pattern.Name == "" {
				result.addError("EMPTY_PATTERN_NAME", "secret pattern has an empty name")
				continue
			}
			if seen[pattern.Name] {
				result.addError("DUPLICATE_PATTERN_NAME",
					fmt.Sprintf("duplicate secret pattern name %q", pattern.Name))
			}
			seen[pattern.Name] = true
			if !containsString(string(pattern.Severity), Severities) {
				result.addError("INVALID_SEVERITY",
					fmt.Sprintf("secret_patterns.patterns.%s.severity %q must be critical, error, or warn", pattern.Name, pattern.Severity))
			}
			validateRegex(pattern.Pattern, fmt.Sprintf("secret_patterns.patterns.%s", pattern.Name), result)
		}
	}

	if rules.Egress != nil {
		switch {
		case rules.Egress.Default == "":
			result.addWarning("egress rule has no default action specified; will default to block")
		case !containsTyped(rules.Egress.Default, DefaultActions):
			result.addError("INVALID_DEFAULT_ACTION",
				fmt.Sprintf("egress default action %q must be 'allow' or 'block'", rules.Egress.Default))
		}
	}

	if rules.ToolAccess != nil {
		switch {
		case rules.ToolAccess.Default == "":
			result.addWarning("tool_access rule has no default action specified; will default to allow")
		case !containsTyped(rules.ToolAccess.Default, DefaultActions):
			result.addError("INVALID_DEFAULT_ACTION",
				fmt.Sprintf("tool_access default action %q must be 'allow' or 'block'", rules.ToolAccess.Default))
		}
		if rules.ToolAccess.MaxArgsSize != nil && *rules.ToolAccess.MaxArgsSize < 1 {
			result.addError("INVALID_MAX_ARGS_SIZE", "rules.tool_access.max_args_size must be >= 1")
		}
	}

	if rules.ComputerUse != nil && rules.ComputerUse.Mode != "" && !containsTyped(rules.ComputerUse.Mode, ComputerUseModes) {
		result.addError("INVALID_COMPUTER_USE_MODE",
			fmt.Sprintf("rules.computer_use.mode %q must be observe, guardrail, or fail_closed", rules.ComputerUse.Mode))
	}

	if rules.PatchIntegrity != nil {
		if rules.PatchIntegrity.MaxAdditions < 0 {
			result.addError("NEGATIVE_LIMIT", "patch_integrity max_additions must be non-negative")
		}
		if rules.PatchIntegrity.MaxDeletions < 0 {
			result.addError("NEGATIVE_LIMIT", "patch_integrity max_deletions must be non-negative")
		}
		if rules.PatchIntegrity.MaxImbalanceRatio != nil && *rules.PatchIntegrity.MaxImbalanceRatio <= 0 {
			result.addError("INVALID_RATIO", "patch_integrity max_imbalance_ratio must be > 0")
		}
		for index, pattern := range rules.PatchIntegrity.ForbiddenPatterns {
			validateRegex(pattern, fmt.Sprintf("rules.patch_integrity.forbidden_patterns[%d]", index), result)
		}
	}

	if rules.ShellCommands != nil {
		for index, pattern := range rules.ShellCommands.ForbiddenPatterns {
			validateRegex(pattern, fmt.Sprintf("rules.shell_commands.forbidden_patterns[%d]", index), result)
		}
	}
}

func validateExtensions(ext *Extensions, result *ValidationResult) {
	if ext.Posture != nil {
		validatePosture(ext.Posture, result)
	}
	if ext.Origins != nil {
		validateOrigins(ext, result)
	}
	if ext.Detection != nil {
		validateDetection(ext.Detection, result)
	}
}

func validatePosture(posture *PostureExtension, result *ValidationResult) {
	if len(posture.States) == 0 {
		result.addError("EMPTY_STATES", "posture.states must define at least one state")
	}

	if posture.Initial == "" {
		result.addError("MISSING_INITIAL_STATE", "posture.initial is required")
	} else if _, ok := posture.States[posture.Initial]; !ok {
		result.addError("INVALID_INITIAL_STATE",
			fmt.Sprintf("posture.initial %q does not reference a defined state", posture.Initial))
	}

	for stateName, state := range posture.States {
		for _, capability := range state.Capabilities {
			if !isKnownCapability(capability) {
				result.addWarning(
					fmt.Sprintf("posture.states.%s.capabilities includes unknown capability %q", stateName, capability),
				)
			}
		}
		for budgetKey, value := range state.Budgets {
			if value < 0 {
				result.addError("NEGATIVE_BUDGET",
					fmt.Sprintf("posture.states.%s.budgets.%s must be non-negative, got %d", stateName, budgetKey, value))
			}
			if !isKnownBudgetKey(budgetKey) {
				result.addWarning(
					fmt.Sprintf("posture.states.%s.budgets uses unknown budget key %q", stateName, budgetKey),
				)
			}
		}
	}

	for index, transition := range posture.Transitions {
		if transition.From != "*" {
			if _, ok := posture.States[transition.From]; !ok {
				result.addError("INVALID_TRANSITION_STATE",
					fmt.Sprintf("posture.transitions[%d].from %q does not reference a defined state", index, transition.From))
			}
		}

		if transition.To == "*" {
			result.addError("INVALID_TRANSITION_STATE",
				fmt.Sprintf("posture.transitions[%d].to cannot be '*'", index))
		} else if _, ok := posture.States[transition.To]; !ok {
			result.addError("INVALID_TRANSITION_STATE",
				fmt.Sprintf("posture.transitions[%d].to %q does not reference a defined state", index, transition.To))
		}

		if !isKnownTransitionTrigger(transition.On) {
			result.addError("INVALID_TRANSITION_TRIGGER",
				fmt.Sprintf("posture.transitions[%d].on %q is not a valid trigger", index, transition.On))
		}

		if transition.On == TransitionTriggerTimeout {
			if transition.After == nil {
				result.addError("MISSING_TIMEOUT_AFTER",
					fmt.Sprintf("posture.transitions[%d]: timeout trigger requires 'after' field", index))
			} else if !isValidDuration(*transition.After) {
				result.addError("INVALID_DURATION",
					fmt.Sprintf("posture.transitions[%d].after must match ^\\d+[smhd]$", index))
			}
		} else if transition.After != nil && !isValidDuration(*transition.After) {
			result.addError("INVALID_DURATION",
				fmt.Sprintf("posture.transitions[%d].after must match ^\\d+[smhd]$", index))
		}
	}
}

func validateOrigins(ext *Extensions, result *ValidationResult) {
	origins := ext.Origins
	seen := make(map[string]bool)
	postureStates := map[string]bool{}
	if ext.Posture != nil {
		for stateName := range ext.Posture.States {
			postureStates[stateName] = true
		}
	}

	if origins.DefaultBehavior != nil && !containsTyped(*origins.DefaultBehavior, OriginDefaultBehaviors) {
		result.addError("INVALID_DEFAULT_BEHAVIOR",
			fmt.Sprintf("origins.default_behavior %q must be 'deny' or 'minimal_profile'", *origins.DefaultBehavior))
	}

	for index, profile := range origins.Profiles {
		if profile.ID == "" {
			result.addError("EMPTY_ORIGIN_ID", "origin profile has an empty id")
			continue
		}
		if seen[profile.ID] {
			result.addError("DUPLICATE_ORIGIN_ID",
				fmt.Sprintf("duplicate origin profile id %q", profile.ID))
		}
		seen[profile.ID] = true

		if profile.Match != nil {
			if profile.Match.SpaceType != "" && !containsString(profile.Match.SpaceType, OriginSpaceTypes) {
				result.addError("INVALID_ORIGIN_SPACE_TYPE",
					fmt.Sprintf("origins.profiles[%d].match.space_type %q is not valid", index, profile.Match.SpaceType))
			}
			if profile.Match.Visibility != "" && !containsString(profile.Match.Visibility, OriginVisibilities) {
				result.addError("INVALID_ORIGIN_VISIBILITY",
					fmt.Sprintf("origins.profiles[%d].match.visibility %q is not valid", index, profile.Match.Visibility))
			}
		}

		if profile.Posture != nil {
			if len(postureStates) == 0 {
				result.addError("INVALID_ORIGIN_POSTURE",
					fmt.Sprintf("origins.profiles[%d].posture requires extensions.posture to be defined", index))
			} else if !postureStates[*profile.Posture] {
				result.addError("INVALID_ORIGIN_POSTURE",
					fmt.Sprintf("origins.profiles[%d].posture %q does not reference a defined posture state", index, *profile.Posture))
			}
		}

		if profile.Budgets != nil {
			validateOptionalNonNegativeInt(profile.Budgets.ToolCalls, "NEGATIVE_BUDGET",
				fmt.Sprintf("origins.profiles[%d].budgets.tool_calls must be non-negative", index), result)
			validateOptionalNonNegativeInt(profile.Budgets.EgressCalls, "NEGATIVE_BUDGET",
				fmt.Sprintf("origins.profiles[%d].budgets.egress_calls must be non-negative", index), result)
			validateOptionalNonNegativeInt(profile.Budgets.ShellCommands, "NEGATIVE_BUDGET",
				fmt.Sprintf("origins.profiles[%d].budgets.shell_commands must be non-negative", index), result)
		}

		if profile.Bridge != nil {
			for targetIndex, target := range profile.Bridge.AllowedTargets {
				if target.SpaceType != "" && !containsString(target.SpaceType, OriginSpaceTypes) {
					result.addError("INVALID_BRIDGE_SPACE_TYPE",
						fmt.Sprintf("origins.profiles[%d].bridge.allowed_targets[%d].space_type %q is not valid", index, targetIndex, target.SpaceType))
				}
				if target.Visibility != "" && !containsString(target.Visibility, OriginVisibilities) {
					result.addError("INVALID_BRIDGE_VISIBILITY",
						fmt.Sprintf("origins.profiles[%d].bridge.allowed_targets[%d].visibility %q is not valid", index, targetIndex, target.Visibility))
				}
			}
		}
	}
}

func validateDetection(detection *DetectionExtension, result *ValidationResult) {
	if detection.PromptInjection != nil {
		prompt := detection.PromptInjection
		if prompt.WarnAtOrAbove != nil && !isKnownDetectionLevel(*prompt.WarnAtOrAbove) {
			result.addError("INVALID_DETECTION_LEVEL",
				fmt.Sprintf("detection.prompt_injection.warn_at_or_above %q is not valid", *prompt.WarnAtOrAbove))
		}
		if prompt.BlockAtOrAbove != nil && !isKnownDetectionLevel(*prompt.BlockAtOrAbove) {
			result.addError("INVALID_DETECTION_LEVEL",
				fmt.Sprintf("detection.prompt_injection.block_at_or_above %q is not valid", *prompt.BlockAtOrAbove))
		}
		if prompt.MaxScanBytes != nil && *prompt.MaxScanBytes < 1 {
			result.addError("INVALID_MAX_SCAN_BYTES", "detection.prompt_injection.max_scan_bytes must be >= 1")
		}

		warnLevel := DetectionLevelSuspicious
		if prompt.WarnAtOrAbove != nil {
			warnLevel = *prompt.WarnAtOrAbove
		}
		blockLevel := DetectionLevelHigh
		if prompt.BlockAtOrAbove != nil {
			blockLevel = *prompt.BlockAtOrAbove
		}
		if isKnownDetectionLevel(warnLevel) && isKnownDetectionLevel(blockLevel) && detectionRank(blockLevel) < detectionRank(warnLevel) {
			result.addWarning("detection.prompt_injection: block_at_or_above is less strict than warn_at_or_above")
		}
	}

	if detection.Jailbreak != nil {
		jailbreak := detection.Jailbreak
		if jailbreak.BlockThreshold != nil && (*jailbreak.BlockThreshold < 0 || *jailbreak.BlockThreshold > 100) {
			result.addError("INVALID_BLOCK_THRESHOLD", "detection.jailbreak.block_threshold must be between 0 and 100")
		}
		if jailbreak.WarnThreshold != nil && (*jailbreak.WarnThreshold < 0 || *jailbreak.WarnThreshold > 100) {
			result.addError("INVALID_WARN_THRESHOLD", "detection.jailbreak.warn_threshold must be between 0 and 100")
		}
		if jailbreak.MaxInputBytes != nil && *jailbreak.MaxInputBytes < 1 {
			result.addError("INVALID_MAX_INPUT_BYTES", "detection.jailbreak.max_input_bytes must be >= 1")
		}

		blockThreshold := 80
		if jailbreak.BlockThreshold != nil {
			blockThreshold = *jailbreak.BlockThreshold
		}
		warnThreshold := 50
		if jailbreak.WarnThreshold != nil {
			warnThreshold = *jailbreak.WarnThreshold
		}
		if blockThreshold < warnThreshold {
			result.addWarning("detection.jailbreak: block_threshold is lower than warn_threshold")
		}
	}

	if detection.ThreatIntel != nil {
		threatIntel := detection.ThreatIntel
		if threatIntel.SimilarityThreshold != nil {
			if *threatIntel.SimilarityThreshold < 0.0 || *threatIntel.SimilarityThreshold > 1.0 {
				result.addError("THRESHOLD_OUT_OF_RANGE",
					"detection.threat_intel.similarity_threshold must be between 0.0 and 1.0")
			}
		}
		if threatIntel.TopK != nil && *threatIntel.TopK < 1 {
			result.addError("INVALID_TOP_K", "detection.threat_intel.top_k must be >= 1")
		}
	}
}

func validateOptionalNonNegativeInt(value *int, code, msg string, result *ValidationResult) {
	if value != nil && *value < 0 {
		result.addError(code, msg)
	}
}

func validateRegex(pattern, path string, result *ValidationResult) {
	if _, err := regexp.Compile(pattern); err != nil {
		result.addError("INVALID_REGEX",
			fmt.Sprintf("%s must be a valid regular expression: %v", path, err))
	}
}

func isKnownCapability(value string) bool {
	switch value {
	case "file_access", "file_write", "egress", "shell", "tool_call", "patch", "custom":
		return true
	default:
		return false
	}
}

func isKnownBudgetKey(value string) bool {
	switch value {
	case "file_writes", "egress_calls", "shell_commands", "tool_calls", "patches", "custom_calls":
		return true
	default:
		return false
	}
}

func isKnownTransitionTrigger(value TransitionTrigger) bool {
	return containsTyped(value, TransitionTriggers)
}

func isValidDuration(value string) bool {
	matched, _ := regexp.MatchString(`^\d+[smhd]$`, value)
	return matched
}

func isKnownDetectionLevel(value DetectionLevel) bool {
	return containsTyped(value, DetectionLevels)
}

func containsString(value string, allowed map[string]struct{}) bool {
	_, ok := allowed[value]
	return ok
}

func containsTyped[T comparable](value T, allowed map[T]struct{}) bool {
	_, ok := allowed[value]
	return ok
}

func detectionRank(value DetectionLevel) int {
	switch value {
	case DetectionLevelSafe:
		return 0
	case DetectionLevelSuspicious:
		return 1
	case DetectionLevelHigh:
		return 2
	case DetectionLevelCritical:
		return 3
	default:
		return -1
	}
}
