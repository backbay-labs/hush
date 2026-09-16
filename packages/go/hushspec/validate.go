package hushspec

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The registered error codes of spec/registries/error-codes.yaml. Every
// refusal this SDK reports carries one, so "the document was rejected" can be
// checked as "rejected for this reason" (core spec 8, Level 1). A registered
// code's meaning never changes and is never reused for a different condition.
const (
	// ErrorCodeInput: the policy file does not exist, or reading it failed.
	// A transport-level failure: nothing was parsed.
	ErrorCodeInput = "E000"
	// ErrorCodeParse: the input is not a single YAML 1.2 Core document that
	// deserializes into the HushSpec model. Covers syntax errors, YAML profile
	// violations, a missing required field, an unknown field at any nesting
	// level, a value of the wrong type, and an unknown enum variant.
	ErrorCodeParse = "E001"
	// ErrorCodeUnsupportedVersion: the `hushspec` field names a version this
	// engine does not accept.
	ErrorCodeUnsupportedVersion = "E002"
	// ErrorCodeDuplicatePatternName: two `rules.secret_patterns.patterns`
	// entries share a `name`.
	ErrorCodeDuplicatePatternName = "E003"
	// ErrorCodeConstraint: a structural constraint of core Section 7 or of an
	// extension module is violated.
	ErrorCodeConstraint = "E004"
	// ErrorCodeInvalidRegex: a pattern field holds a regular expression
	// outside the HushSpec regex profile (core Section 3.14).
	ErrorCodeInvalidRegex = "E005"
	// ErrorCodeExtends: the `extends` chain could not be resolved.
	ErrorCodeExtends = "E010"
	// ErrorCodeInvalidDate: a `metadata` date field is not an ISO 8601
	// calendar date.
	ErrorCodeInvalidDate = "E011"
)

// ErrorCodes is every code this SDK emits, in registry order. The set is
// closed: a code outside it is not a code.
var ErrorCodes = []string{
	ErrorCodeInput,
	ErrorCodeParse,
	ErrorCodeUnsupportedVersion,
	ErrorCodeDuplicatePatternName,
	ErrorCodeConstraint,
	ErrorCodeInvalidRegex,
	ErrorCodeExtends,
	ErrorCodeInvalidDate,
}

// validationKindCodes maps this SDK's own symbolic error kinds onto the
// registered codes. Anything not listed is a constraint violation, which is
// what E004 covers.
var validationKindCodes = map[string]string{
	// A document with no `hushspec` never reaches Validate -- Parse refuses it
	// as a missing required field, which is a parse refusal in every SDK.
	"MISSING_VERSION":        ErrorCodeParse,
	"UNSUPPORTED_VERSION":    ErrorCodeUnsupportedVersion,
	"DUPLICATE_PATTERN_NAME": ErrorCodeDuplicatePatternName,
	"INVALID_REGEX":          ErrorCodeInvalidRegex,
	"INVALID_DATE":           ErrorCodeInvalidDate,
	// A value outside an enum's closed set is an unknown variant, which the
	// schema refuses at parse time. [Parse] refuses these at parse time too
	// (see raw_validate.go); the checks below catch a document a caller built
	// in memory, and must name the same code.
	"INVALID_MERGE_STRATEGY":     ErrorCodeParse,
	"INVALID_DEFAULT_ACTION":     ErrorCodeParse,
	"INVALID_SEVERITY":           ErrorCodeParse,
	"INVALID_COMPUTER_USE_MODE":  ErrorCodeParse,
	"INVALID_DETECTION_LEVEL":    ErrorCodeParse,
	"INVALID_TRANSITION_TRIGGER": ErrorCodeParse,
	"INVALID_DEFAULT_BEHAVIOR":   ErrorCodeParse,
}

// RegistryErrorCode is the registered code for one of this SDK's symbolic
// error kinds.
func RegistryErrorCode(kind string) string {
	if code, ok := validationKindCodes[kind]; ok {
		return code
	}
	return ErrorCodeConstraint
}

// ValidationResult is everything [Validate] found: refusals that make the
// document invalid, and advisory warnings that do not.
type ValidationResult struct {
	Errors   []ValidationError
	Warnings []string
}

// ValidationError is one refusal. Code is the registered identifier of
// spec/registries/error-codes.yaml and is the programmatic contract; Kind is
// this SDK's finer-grained symbolic name for the same condition; Path names
// the offending member when the producer knows it; Message is free text for
// humans and MUST NOT be parsed.
//
// A *ValidationError is an error, so a refusal returned by [Parse] can be
// inspected with errors.As to read its code.
type ValidationError struct {
	Code    string
	Kind    string
	Path    string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Path != "" && !strings.Contains(e.Message, e.Path) {
		return fmt.Sprintf("%s: %s: %s", e.Code, e.Path, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// ErrorCodeOf reports the registered error code an error carries, and whether
// it carried one at all.
//
// A [*ValidationError] carries its own code. Beyond that, a failure to resolve
// an `extends` chain is E010 and a failure to read the input at all is E000,
// so a caller can report one code for every refusal without type-switching by
// hand. A parse failure found inside a resolve failure keeps its own E001: the
// chain was walked, and a document on it was not a HushSpec document.
func ErrorCodeOf(err error) (string, bool) {
	var validationError *ValidationError
	if errors.As(err, &validationError) {
		return validationError.Code, true
	}
	if _, ok := ResolveReason(err); ok {
		return ErrorCodeExtends, true
	}
	var pathError *fs.PathError
	if errors.As(err, &pathError) {
		return ErrorCodeInput, true
	}
	return "", false
}

// IsValid reports whether the document passed validation. Warnings do not
// make a document invalid.
func (r *ValidationResult) IsValid() bool {
	return len(r.Errors) == 0
}

func (r *ValidationResult) addError(kind, msg string) {
	r.Errors = append(r.Errors, ValidationError{
		Code: RegistryErrorCode(kind), Kind: kind, Message: msg,
	})
}

func (r *ValidationResult) addErrorAt(kind, path, msg string) {
	r.Errors = append(r.Errors, ValidationError{
		Code: RegistryErrorCode(kind), Kind: kind, Path: path, Message: msg,
	})
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
			fmt.Sprintf("unsupported hushspec version: %s (this engine accepts minor versions %s)",
				spec.HushSpecVersion, strings.Join(SupportedMinors, ", ")))
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
	today := currentDateISO()

	for _, field := range []struct {
		path  string
		value string
	}{
		{"metadata.approval_date", m.ApprovalDate},
		{"metadata.effective_date", m.EffectiveDate},
		{"metadata.expiry_date", m.ExpiryDate},
		{"metadata.next_review_date", m.NextReviewDate},
	} {
		if field.value != "" && !isISODate(field.value) {
			result.addError("INVALID_DATE", fmt.Sprintf(
				"%s: %q is not an ISO 8601 date (YYYY-MM-DD)", field.path, field.value))
		}
	}

	for i, entry := range m.Changelog {
		if !isISODate(entry.Date) {
			result.addError("INVALID_DATE", fmt.Sprintf(
				"metadata.changelog[%d].date: %q is not an ISO 8601 date (YYYY-MM-DD)", i, entry.Date))
		}
	}

	// GOV_SELF_SUPERSEDES: a document that replaces its own version describes
	// an impossible lineage, so it is an error rather than an advisory warning.
	if m.Supersedes != "" && m.PolicyVersion != nil &&
		strings.TrimSpace(m.Supersedes) == strconv.Itoa(*m.PolicyVersion) {
		result.addError("INVALID_VALUE", fmt.Sprintf(
			"metadata.supersedes '%s' is the policy's own policy_version", m.Supersedes))
	}

	if m.LifecycleState == LifecycleStateDeprecated || m.LifecycleState == LifecycleStateArchived {
		result.addWarning(fmt.Sprintf("policy lifecycle state is '%s'", m.LifecycleState))
	}

	if m.ExpiryDate != "" && isISODate(m.ExpiryDate) && m.ExpiryDate < today {
		result.addWarning(fmt.Sprintf("policy expiry_date '%s' is in the past", m.ExpiryDate))
	}

	if m.ApprovedBy != "" && m.ApprovalDate == "" {
		result.addWarning("approved_by is set but approval_date is missing")
	}

	if m.Classification == ClassificationRestricted && m.ApprovedBy == "" {
		result.addWarning("classification is 'restricted' but no approved_by is set")
	}

	// GOV_SOD_VIOLATION. Compared trimmed and case-insensitively: a check that
	// a copy-paste with different capitalization defeats is no check at all.
	if author := strings.TrimSpace(m.Author); author != "" &&
		strings.EqualFold(author, strings.TrimSpace(m.ApprovedBy)) {
		result.addWarning(fmt.Sprintf(
			"author and approved_by are the same identity '%s': separation of duties requires a different approver",
			author))
	}

	// GOV_UNAPPROVED_STATE.
	if (m.LifecycleState == LifecycleStateApproved || m.LifecycleState == LifecycleStateDeployed) &&
		m.ApprovedBy == "" {
		result.addWarning(fmt.Sprintf(
			"lifecycle_state is '%s' but no approved_by is set", m.LifecycleState))
	}

	// GOV_REVIEW_OVERDUE.
	if m.NextReviewDate != "" && isISODate(m.NextReviewDate) && m.NextReviewDate < today {
		result.addWarning(fmt.Sprintf(
			"policy next_review_date '%s' is in the past", m.NextReviewDate))
	}

	// GOV_CHANGELOG_ORDER.
	if index := changelogDisorder(m.Changelog); index >= 0 {
		result.addWarning(fmt.Sprintf(
			"changelog entries are not in descending version/date order at entry %d", index))
	}
}

// isISODate reports whether value is `YYYY-MM-DD` and names a date that
// actually exists. Dates are compared as strings throughout the toolchain --
// which is calendar order only for this shape -- so an unchecked `01/02/2026`
// would make an expired policy compare as current instead of failing loudly.
func isISODate(value string) bool {
	if !isoDatePattern.MatchString(value) {
		return false
	}
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		return false
	}
	// time.Parse normalizes out-of-range days (2023-02-29 -> 2023-03-01), so
	// round-trip the result to reject a date that does not exist.
	return parsed.Format("2006-01-02") == value
}

var isoDatePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

// compareChangelogVersions orders two versions numerically when both are plain
// integers (the shape metadata.policy_version takes), lexicographically
// otherwise.
func compareChangelogVersions(left, right string) int {
	a, errA := strconv.Atoi(strings.TrimSpace(left))
	b, errB := strconv.Atoi(strings.TrimSpace(right))
	if errA == nil && errB == nil {
		switch {
		case a == b:
			return 0
		case a < b:
			return -1
		default:
			return 1
		}
	}
	return strings.Compare(left, right)
}

// changelogDisorder returns the index of the first entry that is not ordered
// after the one above it (the list runs newest first), or -1 when ordered.
func changelogDisorder(entries []ChangelogEntry) int {
	for index := 1; index < len(entries); index++ {
		previous, current := entries[index-1], entries[index]
		versionOrder := compareChangelogVersions(previous.Version, current.Version)
		ordered := versionOrder > 0 || (versionOrder == 0 && previous.Date >= current.Date)
		if !ordered {
			return index
		}
	}
	return -1
}

// isNonFiniteFloat reports whether x is NaN or +/-Infinity. YAML's `.nan`,
// `.inf`, and `-.inf` scalars decode to these values, and every float-typed
// config field must reject them here, before any range check runs: NaN
// fails every `<= 0` / `< lo || > hi` bounds check (comparisons against NaN
// are always false), so an unchecked NaN silently passes validation and
// then makes downstream comparisons like `ratio > max_imbalance_ratio` fail
// open. It also cannot reach encoding/json, which errors on NaN/Infinity and
// would otherwise silently blank out a receipt's content_hash.
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

	if rules.BrowserAutomation != nil {
		for index, pattern := range rules.BrowserAutomation.ExtraCredentialPatterns {
			validateRegex(pattern, fmt.Sprintf("rules.browser_automation.extra_credential_patterns[%d]", index), result)
		}
	}

	if rules.CodeExecution != nil && rules.CodeExecution.MaxScanBytes != nil && *rules.CodeExecution.MaxScanBytes < 1 {
		result.addError("INVALID_MAX_SCAN_BYTES", "rules.code_execution.max_scan_bytes must be >= 1")
	}

	// Core spec 3.13: every rule block's `when` condition is validated at parse
	// time; a bad HH:MM, timezone, day, or excessive nesting is an error.
	for _, message := range ValidateConditions(rules) {
		// Every condition diagnostic is `<path>: <what is wrong>`, so the path
		// the refusal reports is the part before the first colon.
		path, _, _ := strings.Cut(message, ": ")
		result.addErrorAt("INVALID_CONDITION", path, message)
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

		// Profile rule blocks are tri-state overlays (origins spec 4): an absent
		// `default` inherits the base document's, so only a present value is
		// checked.
		if profile.ToolAccess != nil && profile.ToolAccess.Default != nil && !containsTyped(*profile.ToolAccess.Default, DefaultActions) {
			result.addError("INVALID_DEFAULT_ACTION",
				fmt.Sprintf("origins.profiles[%d].tool_access default action %q must be 'allow' or 'block'", index, *profile.ToolAccess.Default))
		}
		if profile.Egress != nil && profile.Egress.Default != nil && !containsTyped(*profile.Egress.Default, DefaultActions) {
			result.addError("INVALID_DEFAULT_ACTION",
				fmt.Sprintf("origins.profiles[%d].egress default action %q must be 'allow' or 'block'", index, *profile.Egress.Default))
		}
		if profile.ToolAccess != nil && profile.ToolAccess.MaxArgsSize != nil && *profile.ToolAccess.MaxArgsSize < 1 {
			result.addError("INVALID_MAX_ARGS_SIZE",
				fmt.Sprintf("origins.profiles[%d].tool_access.max_args_size must be >= 1", index))
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

// validateRegex rejects ReDoS-unsafe and non-portable patterns. A portability
// pre-check runs first, rejecting constructs that are unsupported by, or behave
// differently across, the four SDK regex engines (possessive quantifiers,
// \Z/\z end-anchors, empty character classes). The nested-quantifier check then
// rejects catastrophic-backtracking shapes (e.g. (a+)+) that RE2 tolerates but
// the backtracking SDK engines (JS RegExp, Python re) do not. The HushSpec
// regex profile check comes last, and carries the RE2-feature rejection with it
// because Go's regexp is RE2-only.
func validateRegex(pattern, path string, result *ValidationResult) {
	if message, bad := disallowedRegexFeature(pattern); bad {
		result.addError("INVALID_REGEX",
			fmt.Sprintf("%s must be a valid regular expression: %s", path, message))
		return
	}
	if hasNestedQuantifier(pattern) {
		result.addError("INVALID_REGEX",
			fmt.Sprintf("%s contains a nested unbounded quantifier (e.g. (a+)+) that can cause catastrophic backtracking (ReDoS)", path))
		return
	}
	// CompileProfileRegex is the exact call the evaluator makes: it repeats the
	// two checks above, applies the HushSpec regex profile (ASCII \d/\w/\s/\b,
	// leading-only inline flags, portable escapes) and then compiles. Routing
	// validation through it means a pattern that validates here can never fail
	// to compile at evaluation time -- and vice versa.
	if _, err := CompileProfileRegex(pattern); err != nil {
		result.addError("INVALID_REGEX",
			fmt.Sprintf("%s must be a valid regular expression: %v", path, err))
	}
}

// possessiveRegexMessage is the shared rejection message for possessive
// quantifiers.
const possessiveRegexMessage = "possessive quantifiers (*+, ++, ?+, {n}+, {n,}+, {n,m}+) are not portable across the HushSpec SDK regex engines"

// disallowedRegexFeature is a portability pre-check: it rejects regex
// constructs that are unsupported by, or behave differently across, the four
// SDK engines so a pattern validates identically everywhere. Scanning outside
// character classes and honoring \-escapes, it rejects:
//   - possessive quantifiers *+, ++, ?+ and possessive braces {n}+, {n,}+,
//     {n,m}+ (Rust's `regex` silently downgrades possessive to greedy; JS
//     RegExp and Go RE2 reject them at compile time),
//   - \Z and \z end-anchors (Rust/Python/Go accept them with differing
//     semantics; JS reads \Z/\z as a literal letter -- users anchor with $),
//   - empty character classes [] and [^] (JS accepts them; the others reject).
//
// The rules are part of the HushSpec regex profile, so every engine must apply
// them identically.
func disallowedRegexFeature(pattern string) (string, bool) {
	chars := []rune(pattern)
	n := len(chars)
	inClass := false
	i := 0
	for i < n {
		c := chars[i]
		if c == '\\' {
			// \Z / \z are end-anchors only outside a character class; inside
			// one they are an escaped literal letter, so ignore them there.
			if !inClass && i+1 < n && (chars[i+1] == 'Z' || chars[i+1] == 'z') {
				return "\\Z and \\z end-anchors are not portable across the HushSpec SDK regex engines; anchor with $", true
			}
			i += 2 // skip the escaped char
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
			// Empty class [] or negated-empty [^] (JS matches none/any; the
			// other engines reject the bare form).
			j := i + 1
			if j < n && chars[j] == '^' {
				j++
			}
			if j < n && chars[j] == ']' {
				return "empty character classes [] and [^] are not portable across the HushSpec SDK regex engines", true
			}
			inClass = true
			i++
		case '*', '+', '?':
			// A quantifier immediately followed by + is possessive.
			if i+1 < n && chars[i+1] == '+' {
				return possessiveRegexMessage, true
			}
			i++
		case '{':
			// Treat {...} as a quantifier only when it parses as one; a literal
			// { is scanned through. A quantifier brace followed by + is
			// possessive ({n}+, {n,}+, {n,m}+).
			j := i + 1
			for j < n && chars[j] != '}' {
				j++
			}
			if j < n {
				inner := string(chars[i+1 : j])
				if braceKind(inner) != quantNone {
					if j+1 < n && chars[j+1] == '+' {
						return possessiveRegexMessage, true
					}
					i = j + 1
					continue
				}
			}
			i++
		default:
			i++
		}
	}
	return "", false
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
// Bounded quantifiers ((a{1,3}){1,3}, (abc)+) are accepted. The heuristic is
// part of the HushSpec regex profile, so every engine must apply it
// identically.
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

// durationPattern is the `after` grammar of a posture timeout transition.
var durationPattern = regexp.MustCompile(`^[0-9]+[smhd]$`)

func isValidDuration(value string) bool {
	return durationPattern.MatchString(value)
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
