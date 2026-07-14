package hushspec

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

type ValidationResult struct {
	Errors   []ValidationError
	Warnings []string
}

type ValidationError struct {
	Code    string
	Message string
}

func (r *ValidationResult) IsValid() bool {
	return len(r.Errors) == 0
}

func (r *ValidationResult) addError(code, msg string) {
	r.Errors = append(r.Errors, ValidationError{Code: code, Message: msg})
}

func (r *ValidationResult) addWarning(msg string) {
	r.Warnings = append(r.Warnings, msg)
}

// Validate checks version support, cross-field constraints, regex syntax,
// and extension consistency. Returns errors and advisory warnings.
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

	validateGovernance(spec, result)

	return result
}

func validateGovernance(spec *HushSpec, result *ValidationResult) {
	if spec.Metadata == nil {
		return
	}
	m := spec.Metadata

	if m.LifecycleState == LifecycleStateDeprecated || m.LifecycleState == LifecycleStateArchived {
		result.addWarning(fmt.Sprintf("policy lifecycle state is '%s'", m.LifecycleState))
	}

	if m.ExpiryDate != "" {
		today := currentDateISO()
		if m.ExpiryDate < today {
			result.addWarning(fmt.Sprintf("policy expiry_date '%s' is in the past", m.ExpiryDate))
		}
	}

	if m.ApprovedBy != "" && m.ApprovalDate == "" {
		result.addWarning("approved_by is set but approval_date is missing")
	}

	if m.Classification == ClassificationRestricted && m.ApprovedBy == "" {
		result.addWarning("classification is 'restricted' but no approved_by is set")
	}
}

// isNonFiniteFloat reports whether x is NaN or +/-Infinity. YAML's `.nan`,
// `.inf`, and `-.inf` scalars decode to these values, and every float-typed
// config field must reject them here, before any range check runs: NaN
// fails every `<= 0` / `< lo || > hi` bounds check (comparisons against NaN
// are always false), so an unchecked NaN silently passes validation and
// then makes downstream comparisons like `ratio > max_imbalance_ratio` fail
// open. It also can't reach encoding/json, which errors on NaN/Infinity and
// would otherwise silently blank out a receipt's content_hash. Must stay in
// lockstep with the Rust `!x.is_finite()`, TypeScript `!Number.isFinite(x)`,
// and Python `not math.isfinite(x)` checks.
func isNonFiniteFloat(x float64) bool {
	return math.IsNaN(x) || math.IsInf(x, 0)
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
			if !containsTyped(string(pattern.Severity), Severities) {
				result.addError("INVALID_SEVERITY",
					fmt.Sprintf("secret_patterns.patterns.%s.severity %q must be critical, error, or warn", pattern.Name, pattern.Severity))
			}
			if pattern.Pattern == "" {
				result.addError("MISSING_PATTERN",
					fmt.Sprintf("secret_patterns.patterns.%s is missing required field pattern", pattern.Name))
			} else {
				validateRegex(pattern.Pattern, fmt.Sprintf("secret_patterns.patterns.%s", pattern.Name), result)
			}
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
		if rules.PatchIntegrity.MaxImbalanceRatio != nil {
			ratio := *rules.PatchIntegrity.MaxImbalanceRatio
			if isNonFiniteFloat(ratio) {
				result.addError("NON_FINITE_FLOAT", "rules.patch_integrity.max_imbalance_ratio must be a finite number, got NaN or Infinity")
			} else if ratio <= 0 {
				result.addError("INVALID_RATIO", "patch_integrity max_imbalance_ratio must be > 0")
			}
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

		if !containsTyped(transition.On, TransitionTriggers) {
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

		if profile.ToolAccess != nil && profile.ToolAccess.Default != "" && !containsTyped(profile.ToolAccess.Default, DefaultActions) {
			result.addError("INVALID_DEFAULT_ACTION",
				fmt.Sprintf("origins.profiles[%d].tool_access default action %q must be 'allow' or 'block'", index, profile.ToolAccess.Default))
		}
		if profile.Egress != nil && profile.Egress.Default != "" && !containsTyped(profile.Egress.Default, DefaultActions) {
			result.addError("INVALID_DEFAULT_ACTION",
				fmt.Sprintf("origins.profiles[%d].egress default action %q must be 'allow' or 'block'", index, profile.Egress.Default))
		}

		if profile.Match != nil {
			if profile.Match.SpaceType != "" && !containsTyped(profile.Match.SpaceType, OriginSpaceTypes) {
				result.addError("INVALID_ORIGIN_SPACE_TYPE",
					fmt.Sprintf("origins.profiles[%d].match.space_type %q is not valid", index, profile.Match.SpaceType))
			}
			if profile.Match.Visibility != "" && !containsTyped(profile.Match.Visibility, OriginVisibilities) {
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
				if target.SpaceType != "" && !containsTyped(target.SpaceType, OriginSpaceTypes) {
					result.addError("INVALID_BRIDGE_SPACE_TYPE",
						fmt.Sprintf("origins.profiles[%d].bridge.allowed_targets[%d].space_type %q is not valid", index, targetIndex, target.SpaceType))
				}
				if target.Visibility != "" && !containsTyped(target.Visibility, OriginVisibilities) {
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
		if prompt.WarnAtOrAbove != nil && !containsTyped(*prompt.WarnAtOrAbove, DetectionLevels) {
			result.addError("INVALID_DETECTION_LEVEL",
				fmt.Sprintf("detection.prompt_injection.warn_at_or_above %q is not valid", *prompt.WarnAtOrAbove))
		}
		if prompt.BlockAtOrAbove != nil && !containsTyped(*prompt.BlockAtOrAbove, DetectionLevels) {
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
		if containsTyped(warnLevel, DetectionLevels) && containsTyped(blockLevel, DetectionLevels) && detectionRank(blockLevel) < detectionRank(warnLevel) {
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
			threshold := *threatIntel.SimilarityThreshold
			if isNonFiniteFloat(threshold) {
				result.addError("NON_FINITE_FLOAT",
					"detection.threat_intel.similarity_threshold must be a finite number, got NaN or Infinity")
			} else if threshold < 0.0 || threshold > 1.0 {
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

// validateRegex rejects ReDoS-unsafe patterns. Go's regexp is RE2-only, so the
// RE2-feature check comes for free at compile time; the nested-quantifier check
// then rejects catastrophic-backtracking shapes (e.g. (a+)+) that RE2 tolerates
// but the backtracking SDK engines (JS RegExp, Python re) do not, keeping the
// safety contract identical across all four SDKs.
func validateRegex(pattern, path string, result *ValidationResult) {
	if _, err := regexp.Compile(pattern); err != nil {
		result.addError("INVALID_REGEX",
			fmt.Sprintf("%s must be a valid regular expression: %v", path, err))
		return
	}
	if hasNestedQuantifier(pattern) {
		result.addError("INVALID_REGEX",
			fmt.Sprintf("%s contains a nested unbounded quantifier (e.g. (a+)+) that can cause catastrophic backtracking (ReDoS)", path))
	}
}

type quantKind int

const (
	quantNone quantKind = iota
	quantBounded
	quantUnbounded
)

// hasNestedQuantifier is a fail-closed over-approximation that flags nested
// unbounded quantifiers such as (a+)+, ([0-9]+)*, or ((ab)+)+. It scans
// ( ... ) group nesting -- ignoring escaped parens and character-class contents
// -- and returns true when a group whose body contains an unbounded quantifier
// (*, +, {n,}) is itself immediately followed by an unbounded quantifier.
// Bounded quantifiers ((a{1,3}){1,3}, (abc)+) are accepted. Must stay identical
// to the Rust, TypeScript, and Python implementations.
func hasNestedQuantifier(pattern string) bool {
	chars := []rune(pattern)
	n := len(chars)
	// Per open group: whether its body has seen an unbounded quantifier.
	stack := []bool{}
	inClass := false
	i := 0
	for i < n {
		c := chars[i]
		if c == '\\' {
			// Escaped char (e.g. \(, \), \[, \+) -- skip both.
			i += 2
			continue
		}
		if inClass {
			if c == ']' {
				inClass = false
			}
			i++
			continue
		}
		switch c {
		case '[':
			inClass = true
			i++
		case '(':
			stack = append(stack, false)
			i++
		case ')':
			closedUnbounded := false
			if len(stack) > 0 {
				closedUnbounded = stack[len(stack)-1]
				stack = stack[:len(stack)-1]
			}
			kind, qlen := classifyQuantifier(chars, i+1)
			if kind == quantUnbounded {
				if closedUnbounded {
					return true
				}
				// The just-closed group is unbounded-quantified, so it is an
				// unbounded quantifier within the parent group's body.
				if len(stack) > 0 {
					stack[len(stack)-1] = true
				}
				i += 1 + qlen
			} else {
				i++
			}
		default:
			kind, qlen := classifyQuantifier(chars, i)
			switch kind {
			case quantUnbounded:
				if len(stack) > 0 {
					stack[len(stack)-1] = true
				}
				i += qlen
			case quantBounded:
				i += qlen
			default:
				i++
			}
		}
	}
	return false
}

// classifyQuantifier classifies the quantifier token starting at pos, returning
// its kind and the number of chars it spans (including any trailing
// lazy/possessive marker).
func classifyQuantifier(chars []rune, pos int) (quantKind, int) {
	if pos >= len(chars) {
		return quantNone, 0
	}
	switch chars[pos] {
	case '*', '+':
		if markerFollows(chars, pos+1) {
			return quantUnbounded, 2
		}
		return quantUnbounded, 1
	case '?':
		if markerFollows(chars, pos+1) {
			return quantBounded, 2
		}
		return quantBounded, 1
	case '{':
		j := pos + 1
		for j < len(chars) && chars[j] != '}' {
			j++
		}
		if j >= len(chars) {
			return quantNone, 0 // unterminated '{' -> literal
		}
		kind := braceKind(string(chars[pos+1 : j]))
		if kind == quantNone {
			return quantNone, 0
		}
		length := j - pos + 1
		if markerFollows(chars, j+1) {
			length++
		}
		return kind, length
	default:
		return quantNone, 0
	}
}

func markerFollows(chars []rune, pos int) bool {
	return pos < len(chars) && (chars[pos] == '?' || chars[pos] == '+')
}

func isASCIIDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// braceKind classifies {...} content: {n,} is unbounded, {n} and {n,m} are
// bounded, anything else is a literal brace (not a quantifier).
func braceKind(inner string) quantKind {
	if len(inner) == 0 {
		return quantNone
	}
	commas := strings.Count(inner, ",")
	if commas == 0 {
		if isASCIIDigits(inner) {
			return quantBounded
		}
		return quantNone
	}
	if commas == 1 {
		parts := strings.SplitN(inner, ",", 2)
		lo, hi := parts[0], parts[1]
		loOk := lo == "" || isASCIIDigits(lo)
		hiOk := hi == "" || isASCIIDigits(hi)
		if !loOk || !hiOk || (lo == "" && hi == "") {
			return quantNone
		}
		if hi == "" {
			return quantUnbounded
		}
		return quantBounded
	}
	return quantNone
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

func isValidDuration(value string) bool {
	matched, _ := regexp.MatchString(`^\d+[smhd]$`, value)
	return matched
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

func currentDateISO() string {
	return time.Now().UTC().Format("2006-01-02")
}
