package hushspec

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionWarn  Decision = "warn"
	DecisionDeny  Decision = "deny"
)

// EvaluationAction is the input to the reference evaluator.
type EvaluationAction struct {
	Type     string          `json:"type" yaml:"type"`
	Target   string          `json:"target,omitempty" yaml:"target,omitempty"`
	Content  string          `json:"content,omitempty" yaml:"content,omitempty"`
	Origin   *OriginContext  `json:"origin,omitempty" yaml:"origin,omitempty"`
	Posture  *PostureContext `json:"posture,omitempty" yaml:"posture,omitempty"`
	ArgsSize *int            `json:"args_size,omitempty" yaml:"args_size,omitempty"`
}

type OriginContext struct {
	Provider             string   `json:"provider,omitempty" yaml:"provider,omitempty"`
	TenantID             string   `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`
	SpaceID              string   `json:"space_id,omitempty" yaml:"space_id,omitempty"`
	SpaceType            string   `json:"space_type,omitempty" yaml:"space_type,omitempty"`
	Visibility           string   `json:"visibility,omitempty" yaml:"visibility,omitempty"`
	ExternalParticipants *bool    `json:"external_participants,omitempty" yaml:"external_participants,omitempty"`
	Tags                 []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	Sensitivity          string   `json:"sensitivity,omitempty" yaml:"sensitivity,omitempty"`
	ActorRole            string   `json:"actor_role,omitempty" yaml:"actor_role,omitempty"`
}

type PostureContext struct {
	Current string `json:"current,omitempty" yaml:"current,omitempty"`
	Signal  string `json:"signal,omitempty" yaml:"signal,omitempty"`
}

type EvaluationResult struct {
	Decision      Decision       `json:"decision" yaml:"decision"`
	MatchedRule   string         `json:"matched_rule,omitempty" yaml:"matched_rule,omitempty"`
	Reason        string         `json:"reason,omitempty" yaml:"reason,omitempty"`
	OriginProfile string         `json:"origin_profile,omitempty" yaml:"origin_profile,omitempty"`
	Posture       *PostureResult `json:"posture,omitempty" yaml:"posture,omitempty"`
}

type PostureResult struct {
	Current string `json:"current" yaml:"current"`
	Next    string `json:"next" yaml:"next"`
}

type pathOperation int

const (
	pathOperationRead pathOperation = iota
	pathOperationWrite
	pathOperationPatch
)

type patchStats struct {
	additions int
	deletions int
}

// Evaluate runs the reference evaluator: checks panic mode, resolves origin
// and posture context, then dispatches to the appropriate rule evaluator.
func Evaluate(spec *HushSpec, action *EvaluationAction) EvaluationResult {
	if IsPanicActive() {
		return EvaluationResult{
			Decision:    DecisionDeny,
			MatchedRule: "__hushspec_panic__",
			Reason:      "emergency panic mode is active",
		}
	}

	matchedProfile := selectOriginProfile(spec, action.Origin)
	var originProfileID string
	if matchedProfile != nil {
		originProfileID = matchedProfile.ID
	}
	posture := resolvePosture(spec, matchedProfile, action.Posture)

	if denied := postureCapabilityGuard(action, posture, spec, originProfileID); denied != nil {
		return *denied
	}

	switch action.Type {
	case "tool_call":
		return evaluateToolCall(spec, action, matchedProfile, posture, originProfileID)
	case "egress":
		return evaluateEgress(spec, action, matchedProfile, posture, originProfileID)
	case "file_read":
		return evaluateFileRead(spec, action, posture, originProfileID)
	case "file_write":
		return evaluateFileWrite(spec, action, posture, originProfileID)
	case "patch_apply":
		return evaluatePatch(spec, action, posture, originProfileID)
	case "shell_command":
		return evaluateShellCommand(spec, action, posture, originProfileID)
	case "computer_use":
		return evaluateComputerUse(spec, action, posture, originProfileID)
	case "input_inject":
		return evaluateInputInjection(spec, action, posture, originProfileID)
	default:
		return allowResult("", "no reference evaluator rule for this action type", originProfileID, posture)
	}
}

func evaluateToolCall(
	spec *HushSpec,
	action *EvaluationAction,
	matchedProfile *OriginProfile,
	posture *PostureResult,
	originProfileID string,
) EvaluationResult {
	var baseRule *ToolAccessRule
	var profileRule *ToolAccessRule
	var profilePrefix string

	if spec.Rules != nil && spec.Rules.ToolAccess != nil && spec.Rules.ToolAccess.Enabled {
		baseRule = spec.Rules.ToolAccess
	}
	if matchedProfile != nil && matchedProfile.ToolAccess != nil && matchedProfile.ToolAccess.Enabled {
		profileRule = matchedProfile.ToolAccess
		profilePrefix = profileRulePrefix(matchedProfile.ID, "tool_access")
	}

	if baseRule == nil && profileRule == nil {
		return allowResult("", "", originProfileID, posture)
	}

	if limit, matchedRule, ok := smallestToolArgLimit(baseRule, profileRule, profilePrefix); ok {
		actual := 0
		if action.ArgsSize != nil {
			actual = *action.ArgsSize
		}
		if actual > limit {
			return denyResult(
				matchedRule,
				"tool arguments exceeded max_args_size",
				originProfileID, posture,
			)
		}
	}

	target := action.Target
	if baseRule != nil && findFirstMatch(target, baseRule.Block) >= 0 {
		return denyResult("rules.tool_access.block", "tool is explicitly blocked", originProfileID, posture)
	}
	if profileRule != nil && findFirstMatch(target, profileRule.Block) >= 0 {
		return denyResult(profilePrefix+".block", "tool is explicitly blocked", originProfileID, posture)
	}

	if baseRule != nil && findFirstMatch(target, baseRule.RequireConfirmation) >= 0 {
		return warnResult("rules.tool_access.require_confirmation", "tool requires confirmation", originProfileID, posture)
	}
	if profileRule != nil && findFirstMatch(target, profileRule.RequireConfirmation) >= 0 {
		return warnResult(profilePrefix+".require_confirmation", "tool requires confirmation", originProfileID, posture)
	}

	baseHasAllow := baseRule != nil && hasPatterns(baseRule.Allow)
	profileHasAllow := profileRule != nil && hasPatterns(profileRule.Allow)
	baseAllowMatch := !baseHasAllow || (baseRule != nil && findFirstMatch(target, baseRule.Allow) >= 0)
	profileAllowMatch := !profileHasAllow || (profileRule != nil && findFirstMatch(target, profileRule.Allow) >= 0)
	if (baseHasAllow || profileHasAllow) && baseAllowMatch && profileAllowMatch {
		matchedRule := ""
		if profileHasAllow {
			matchedRule = profilePrefix + ".allow"
		} else if baseHasAllow {
			matchedRule = "rules.tool_access.allow"
		}
		return allowResult(matchedRule, "tool is explicitly allowed", originProfileID, posture)
	}

	defaultAction := DefaultActionAllow
	if (baseRule != nil && baseRule.Default == DefaultActionBlock) || (profileRule != nil && profileRule.Default == DefaultActionBlock) {
		defaultAction = DefaultActionBlock
	}
	matchedRule := ""
	if profileRule != nil {
		matchedRule = profilePrefix + ".default"
	} else if baseRule != nil {
		matchedRule = "rules.tool_access.default"
	}

	if defaultAction == DefaultActionBlock {
		return denyResult(matchedRule, "tool matched default block", originProfileID, posture)
	}
	return allowResult(matchedRule, "tool matched default allow", originProfileID, posture)
}

func evaluateEgress(
	spec *HushSpec,
	action *EvaluationAction,
	matchedProfile *OriginProfile,
	posture *PostureResult,
	originProfileID string,
) EvaluationResult {
	var baseRule *EgressRule
	var profileRule *EgressRule
	var profilePrefix string

	if spec.Rules != nil && spec.Rules.Egress != nil && spec.Rules.Egress.Enabled {
		baseRule = spec.Rules.Egress
	}
	if matchedProfile != nil && matchedProfile.Egress != nil && matchedProfile.Egress.Enabled {
		profileRule = matchedProfile.Egress
		profilePrefix = profileRulePrefix(matchedProfile.ID, "egress")
	}

	if baseRule == nil && profileRule == nil {
		return allowResult("", "", originProfileID, posture)
	}

	target := action.Target
	if baseRule != nil && findFirstMatch(target, baseRule.Block) >= 0 {
		return denyResult("rules.egress.block", "domain is explicitly blocked", originProfileID, posture)
	}
	if profileRule != nil && findFirstMatch(target, profileRule.Block) >= 0 {
		return denyResult(profilePrefix+".block", "domain is explicitly blocked", originProfileID, posture)
	}

	baseHasAllow := baseRule != nil && hasPatterns(baseRule.Allow)
	profileHasAllow := profileRule != nil && hasPatterns(profileRule.Allow)
	baseAllowMatch := !baseHasAllow || (baseRule != nil && findFirstMatch(target, baseRule.Allow) >= 0)
	profileAllowMatch := !profileHasAllow || (profileRule != nil && findFirstMatch(target, profileRule.Allow) >= 0)
	if (baseHasAllow || profileHasAllow) && baseAllowMatch && profileAllowMatch {
		matchedRule := ""
		if profileHasAllow {
			matchedRule = profilePrefix + ".allow"
		} else if baseHasAllow {
			matchedRule = "rules.egress.allow"
		}
		return allowResult(matchedRule, "domain is explicitly allowed", originProfileID, posture)
	}

	defaultAction := DefaultActionAllow
	if (baseRule != nil && baseRule.Default == DefaultActionBlock) || (profileRule != nil && profileRule.Default == DefaultActionBlock) {
		defaultAction = DefaultActionBlock
	}
	matchedRule := ""
	if profileRule != nil {
		matchedRule = profilePrefix + ".default"
	} else if baseRule != nil {
		matchedRule = "rules.egress.default"
	}

	if defaultAction == DefaultActionBlock {
		return denyResult(matchedRule, "domain matched default block", originProfileID, posture)
	}
	return allowResult(matchedRule, "domain matched default allow", originProfileID, posture)
}

func evaluateFileRead(
	spec *HushSpec,
	action *EvaluationAction,
	posture *PostureResult,
	originProfileID string,
) EvaluationResult {
	if result := evaluatePathGuards(spec, action.Target, pathOperationRead, posture, originProfileID); result != nil {
		return *result
	}
	return allowResult("", "", originProfileID, posture)
}

func evaluateFileWrite(
	spec *HushSpec,
	action *EvaluationAction,
	posture *PostureResult,
	originProfileID string,
) EvaluationResult {
	if result := evaluatePathGuards(spec, action.Target, pathOperationWrite, posture, originProfileID); result != nil {
		return *result
	}

	if spec.Rules != nil && spec.Rules.SecretPatterns != nil {
		return evaluateSecretPatterns(spec.Rules.SecretPatterns, action.Target, action.Content, posture, originProfileID)
	}

	return allowResult("", "", originProfileID, posture)
}

func evaluatePatch(
	spec *HushSpec,
	action *EvaluationAction,
	posture *PostureResult,
	originProfileID string,
) EvaluationResult {
	if result := evaluatePathGuards(spec, action.Target, pathOperationPatch, posture, originProfileID); result != nil {
		return *result
	}

	if spec.Rules != nil && spec.Rules.PatchIntegrity != nil {
		return evaluatePatchIntegrity(spec.Rules.PatchIntegrity, action.Content, posture, originProfileID)
	}

	return allowResult("", "", originProfileID, posture)
}

func evaluateShellCommand(
	spec *HushSpec,
	action *EvaluationAction,
	posture *PostureResult,
	originProfileID string,
) EvaluationResult {
	if spec.Rules != nil && spec.Rules.ShellCommands != nil {
		return evaluateShellRule(spec.Rules.ShellCommands, action.Target, posture, originProfileID)
	}
	return allowResult("", "", originProfileID, posture)
}

func evaluateComputerUse(
	spec *HushSpec,
	action *EvaluationAction,
	posture *PostureResult,
	originProfileID string,
) EvaluationResult {
	var computerUseResult *EvaluationResult
	if spec.Rules != nil && spec.Rules.ComputerUse != nil {
		result := evaluateComputerUseRule(spec.Rules.ComputerUse, action.Target, posture, originProfileID)
		computerUseResult = &result
	}
	var remoteDesktopResult *EvaluationResult
	if spec.Rules != nil && spec.Rules.RemoteDesktopChannels != nil {
		if result := evaluateRemoteDesktopChannelsRule(spec.Rules.RemoteDesktopChannels, action.Target, posture, originProfileID); result != nil {
			remoteDesktopResult = result
		}
	}

	switch {
	case computerUseResult != nil && remoteDesktopResult != nil:
		return moreRestrictiveResult(*computerUseResult, *remoteDesktopResult)
	case computerUseResult != nil:
		return *computerUseResult
	case remoteDesktopResult != nil:
		return *remoteDesktopResult
	default:
		return allowResult("", "", originProfileID, posture)
	}
}

func evaluateInputInjection(
	spec *HushSpec,
	action *EvaluationAction,
	posture *PostureResult,
	originProfileID string,
) EvaluationResult {
	if spec.Rules != nil && spec.Rules.InputInjection != nil {
		return evaluateInputInjectionRule(spec.Rules.InputInjection, action.Target, posture, originProfileID)
	}
	return allowResult("", "", originProfileID, posture)
}

func evaluateToolAccessRule(
	rule *ToolAccessRule,
	prefix string,
	target string,
	argsSize *int,
	posture *PostureResult,
	originProfileID string,
) EvaluationResult {
	if rule == nil {
		return allowResult("", "", originProfileID, posture)
	}
	if !rule.Enabled {
		return allowResult("", "", originProfileID, posture)
	}

	if rule.MaxArgsSize != nil {
		actual := 0
		if argsSize != nil {
			actual = *argsSize
		}
		if actual > *rule.MaxArgsSize {
			return denyResult(
				prefixedRule(prefix, "max_args_size"),
				"tool arguments exceeded max_args_size",
				originProfileID, posture,
			)
		}
	}

	if findFirstMatch(target, rule.Block) >= 0 {
		return denyResult(
			prefixedRule(prefix, "block"),
			"tool is explicitly blocked",
			originProfileID, posture,
		)
	}
	if findFirstMatch(target, rule.RequireConfirmation) >= 0 {
		return warnResult(
			prefixedRule(prefix, "require_confirmation"),
			"tool requires confirmation",
			originProfileID, posture,
		)
	}
	if findFirstMatch(target, rule.Allow) >= 0 {
		return allowResult(
			prefixedRule(prefix, "allow"),
			"tool is explicitly allowed",
			originProfileID, posture,
		)
	}

	def := rule.Default
	if def == "" {
		def = DefaultActionAllow
	}
	switch def {
	case DefaultActionBlock:
		return denyResult(
			prefixedRule(prefix, "default"),
			"tool matched default block",
			originProfileID, posture,
		)
	default: // DefaultActionAllow
		return allowResult(
			prefixedRule(prefix, "default"),
			"tool matched default allow",
			originProfileID, posture,
		)
	}
}

func evaluateEgressRule(
	rule *EgressRule,
	prefix string,
	target string,
	posture *PostureResult,
	originProfileID string,
) EvaluationResult {
	if !rule.Enabled {
		return allowResult("", "", originProfileID, posture)
	}

	if findFirstMatch(target, rule.Block) >= 0 {
		return denyResult(
			prefixedRule(prefix, "block"),
			"domain is explicitly blocked",
			originProfileID, posture,
		)
	}
	if findFirstMatch(target, rule.Allow) >= 0 {
		return allowResult(
			prefixedRule(prefix, "allow"),
			"domain is explicitly allowed",
			originProfileID, posture,
		)
	}

	switch rule.Default {
	case DefaultActionAllow:
		return allowResult(
			prefixedRule(prefix, "default"),
			"domain matched default allow",
			originProfileID, posture,
		)
	default: // DefaultActionBlock or empty
		return denyResult(
			prefixedRule(prefix, "default"),
			"domain matched default block",
			originProfileID, posture,
		)
	}
}

func evaluateSecretPatterns(
	rule *SecretPatternsRule,
	target string,
	content string,
	posture *PostureResult,
	originProfileID string,
) EvaluationResult {
	if !rule.Enabled {
		return allowResult("", "", originProfileID, posture)
	}

	if findFirstMatch(target, rule.SkipPaths) >= 0 {
		return allowResult(
			"rules.secret_patterns.skip_paths",
			"path is excluded from secret scanning",
			originProfileID, posture,
		)
	}

	for _, pattern := range rule.Patterns {
		re, err := regexp.Compile(pattern.Pattern)
		if err != nil {
			continue
		}
		if re.MatchString(content) {
			return denyResult(
				fmt.Sprintf("rules.secret_patterns.patterns.%s", pattern.Name),
				fmt.Sprintf("content matched secret pattern '%s'", pattern.Name),
				originProfileID, posture,
			)
		}
	}

	return allowResult("", "", originProfileID, posture)
}

func evaluatePatchIntegrity(
	rule *PatchIntegrityRule,
	content string,
	posture *PostureResult,
	originProfileID string,
) EvaluationResult {
	if !rule.Enabled {
		return allowResult("", "", originProfileID, posture)
	}

	for index, pattern := range rule.ForbiddenPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(content) {
			return denyResult(
				fmt.Sprintf("rules.patch_integrity.forbidden_patterns[%d]", index),
				"patch content matched a forbidden pattern",
				originProfileID, posture,
			)
		}
	}

	stats := computePatchStats(content)
	if stats.additions > rule.MaxAdditions {
		return denyResult(
			"rules.patch_integrity.max_additions",
			"patch additions exceeded max_additions",
			originProfileID, posture,
		)
	}
	if stats.deletions > rule.MaxDeletions {
		return denyResult(
			"rules.patch_integrity.max_deletions",
			"patch deletions exceeded max_deletions",
			originProfileID, posture,
		)
	}
	if rule.RequireBalance && rule.MaxImbalanceRatio != nil {
		ratio := imbalanceRatio(stats.additions, stats.deletions)
		if ratio > *rule.MaxImbalanceRatio {
			return denyResult(
				"rules.patch_integrity.max_imbalance_ratio",
				"patch exceeded max imbalance ratio",
				originProfileID, posture,
			)
		}
	}

	return allowResult("", "", originProfileID, posture)
}

func evaluateShellRule(
	rule *ShellCommandsRule,
	target string,
	posture *PostureResult,
	originProfileID string,
) EvaluationResult {
	if !rule.Enabled {
		return allowResult("", "", originProfileID, posture)
	}

	for index, pattern := range rule.ForbiddenPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(target) {
			return denyResult(
				fmt.Sprintf("rules.shell_commands.forbidden_patterns[%d]", index),
				"shell command matched a forbidden pattern",
				originProfileID, posture,
			)
		}
	}

	return allowResult("", "", originProfileID, posture)
}

func evaluateComputerUseRule(
	rule *ComputerUseRule,
	target string,
	posture *PostureResult,
	originProfileID string,
) EvaluationResult {
	if !rule.Enabled {
		return allowResult("", "", originProfileID, posture)
	}

	for _, allowed := range rule.AllowedActions {
		if allowed == target {
			return allowResult(
				"rules.computer_use.allowed_actions",
				"computer-use action is explicitly allowed",
				originProfileID, posture,
			)
		}
	}

	mode := rule.Mode
	if mode == "" {
		mode = ComputerUseModeGuardrail
	}
	switch mode {
	case ComputerUseModeObserve:
		return allowResult(
			"rules.computer_use.mode",
			"observe mode does not block unlisted actions",
			originProfileID, posture,
		)
	case ComputerUseModeFailClosed:
		return denyResult(
			"rules.computer_use.mode",
			"fail_closed mode denies unlisted actions",
			originProfileID, posture,
		)
	default: // guardrail
		return warnResult(
			"rules.computer_use.mode",
			"guardrail mode warns on unlisted actions",
			originProfileID, posture,
		)
	}
}

func evaluateRemoteDesktopChannelsRule(
	rule *RemoteDesktopChannelsRule,
	target string,
	posture *PostureResult,
	originProfileID string,
) *EvaluationResult {
	if !rule.Enabled {
		return nil
	}

	field := ""
	allowed := false
	switch target {
	case "remote.clipboard":
		field = "clipboard"
		allowed = rule.Clipboard
	case "remote.file_transfer":
		field = "file_transfer"
		allowed = rule.FileTransfer
	case "remote.audio":
		field = "audio"
		allowed = rule.Audio
	case "remote.drive_mapping":
		field = "drive_mapping"
		allowed = rule.DriveMapping
	default:
		return nil
	}

	var result EvaluationResult
	if allowed {
		result = allowResult(
			"rules.remote_desktop_channels."+field,
			fmt.Sprintf("remote desktop channel '%s' is enabled", field),
			originProfileID,
			posture,
		)
	} else {
		result = denyResult(
			"rules.remote_desktop_channels."+field,
			fmt.Sprintf("remote desktop channel '%s' is disabled", field),
			originProfileID,
			posture,
		)
	}
	return &result
}

func evaluateInputInjectionRule(
	rule *InputInjectionRule,
	target string,
	posture *PostureResult,
	originProfileID string,
) EvaluationResult {
	if !rule.Enabled {
		return allowResult("", "", originProfileID, posture)
	}

	if len(rule.AllowedTypes) == 0 {
		return denyResult(
			"rules.input_injection.allowed_types",
			"input injection is not allowed when allowed_types is empty",
			originProfileID,
			posture,
		)
	}

	for _, allowedType := range rule.AllowedTypes {
		if allowedType == target {
			return allowResult(
				"rules.input_injection.allowed_types",
				"input injection type is explicitly allowed",
				originProfileID,
				posture,
			)
		}
	}

	return denyResult(
		"rules.input_injection.allowed_types",
		"input injection type is not allowed",
		originProfileID,
		posture,
	)
}

func evaluatePathGuards(
	spec *HushSpec,
	target string,
	operation pathOperation,
	posture *PostureResult,
	originProfileID string,
) *EvaluationResult {
	if spec.Rules == nil {
		return nil
	}

	forbiddenExceptionMatched := false

	if spec.Rules.ForbiddenPaths != nil {
		denied, exceptionMatched := evaluateForbiddenPaths(spec.Rules.ForbiddenPaths, target, posture, originProfileID)
		if denied != nil {
			return denied
		}
		forbiddenExceptionMatched = exceptionMatched
	}

	if spec.Rules.PathAllowlist != nil {
		if result := evaluatePathAllowlist(spec.Rules.PathAllowlist, target, operation, posture, originProfileID); result != nil {
			return result
		}
	}

	if forbiddenExceptionMatched {
		result := allowResult(
			"rules.forbidden_paths.exceptions",
			"path matched an explicit exception",
			originProfileID, posture,
		)
		return &result
	}

	return nil
}

func evaluateForbiddenPaths(
	rule *ForbiddenPathsRule,
	target string,
	posture *PostureResult,
	originProfileID string,
) (*EvaluationResult, bool) {
	if !rule.Enabled {
		return nil, false
	}

	if findFirstMatch(target, rule.Exceptions) >= 0 {
		return nil, true
	}

	if findFirstMatch(target, rule.Patterns) >= 0 {
		result := denyResult(
			"rules.forbidden_paths.patterns",
			"path matched a forbidden pattern",
			originProfileID, posture,
		)
		return &result, false
	}

	return nil, false
}

func evaluatePathAllowlist(
	rule *PathAllowlistRule,
	target string,
	operation pathOperation,
	posture *PostureResult,
	originProfileID string,
) *EvaluationResult {
	if !rule.Enabled {
		return nil
	}

	var patterns []string
	switch operation {
	case pathOperationRead:
		patterns = rule.Read
	case pathOperationWrite:
		patterns = rule.Write
	case pathOperationPatch:
		if len(rule.Patch) > 0 {
			patterns = rule.Patch
		} else {
			patterns = rule.Write
		}
	}

	if findFirstMatch(target, patterns) >= 0 {
		result := allowResult(
			"rules.path_allowlist",
			"path matched allowlist",
			originProfileID, posture,
		)
		return &result
	}

	result := denyResult(
		"rules.path_allowlist",
		"path did not match allowlist",
		originProfileID, posture,
	)
	return &result
}

// postureCapabilityGuard denies if the current posture state lacks the
// capability required by the action type.
func postureCapabilityGuard(
	action *EvaluationAction,
	posture *PostureResult,
	spec *HushSpec,
	originProfileID string,
) *EvaluationResult {
	if posture == nil {
		return nil
	}
	if spec.Extensions == nil || spec.Extensions.Posture == nil {
		return nil
	}
	postureExtension := spec.Extensions.Posture

	capability := requiredCapability(action.Type)
	if capability == "" {
		return nil
	}

	currentState, ok := postureExtension.States[posture.Current]
	if !ok {
		result := denyResult(
			fmt.Sprintf("extensions.posture.states.%s", posture.Current),
			fmt.Sprintf("unknown posture state '%s'", posture.Current),
			originProfileID,
			posture,
		)
		return &result
	}

	for _, cap := range currentState.Capabilities {
		if cap == capability {
			return nil
		}
	}

	result := denyResult(
		fmt.Sprintf("extensions.posture.states.%s.capabilities", posture.Current),
		fmt.Sprintf("posture '%s' does not allow capability '%s'", posture.Current, capability),
		originProfileID,
		posture,
	)
	return &result
}

// resolvePosture determines the current and next posture state from the
// origin profile, action context, and posture extension (in priority order).
func resolvePosture(
	spec *HushSpec,
	matchedProfile *OriginProfile,
	postureCtx *PostureContext,
) *PostureResult {
	if spec.Extensions == nil || spec.Extensions.Posture == nil {
		return nil
	}
	postureExtension := spec.Extensions.Posture

	current := ""
	if matchedProfile != nil && matchedProfile.Posture != nil {
		current = *matchedProfile.Posture
	}
	if current == "" && postureCtx != nil && postureCtx.Current != "" {
		current = postureCtx.Current
	}
	if current == "" {
		current = postureExtension.Initial
	}

	signal := ""
	if postureCtx != nil && postureCtx.Signal != "" && postureCtx.Signal != "none" {
		signal = postureCtx.Signal
	}

	next := current
	if signal != "" {
		if nextState := nextPostureState(postureExtension, current, signal); nextState != "" {
			next = nextState
		}
	}

	return &PostureResult{Current: current, Next: next}
}

func nextPostureState(posture *PostureExtension, current string, signal string) string {
	for _, transition := range posture.Transitions {
		if transition.From != "*" && transition.From != current {
			continue
		}
		if string(transition.On) != signal {
			continue
		}
		return transition.To
	}
	return ""
}

// selectOriginProfile returns the highest-scoring origin profile for the
// given context, or nil if none match.
func selectOriginProfile(spec *HushSpec, origin *OriginContext) *OriginProfile {
	if origin == nil {
		return nil
	}
	if spec.Extensions == nil || spec.Extensions.Origins == nil {
		return nil
	}
	profiles := spec.Extensions.Origins.Profiles

	bestScore := -1
	var bestProfile *OriginProfile

	for i := range profiles {
		profile := &profiles[i]
		if profile.Match == nil {
			continue
		}
		score := matchOrigin(profile.Match, origin)
		if score < 0 {
			continue
		}
		if score > bestScore {
			bestScore = score
			bestProfile = profile
		}
	}

	return bestProfile
}

// matchOrigin returns -1 if any field mismatches, or a non-negative
// specificity score (higher = more fields matched).
func matchOrigin(rules *OriginMatch, origin *OriginContext) int {
	score := 0

	if rules.Provider != "" {
		if origin.Provider != rules.Provider {
			return -1
		}
		score += 4
	}
	if rules.TenantID != "" {
		if origin.TenantID != rules.TenantID {
			return -1
		}
		score += 6
	}
	if rules.SpaceID != "" {
		if origin.SpaceID != rules.SpaceID {
			return -1
		}
		score += 8
	}
	if rules.SpaceType != "" {
		if origin.SpaceType != rules.SpaceType {
			return -1
		}
		score += 4
	}
	if rules.Visibility != "" {
		if origin.Visibility != rules.Visibility {
			return -1
		}
		score += 4
	}
	if rules.ExternalParticipants != nil {
		if origin.ExternalParticipants == nil || *origin.ExternalParticipants != *rules.ExternalParticipants {
			return -1
		}
		score += 2
	}
	if len(rules.Tags) > 0 {
		for _, tag := range rules.Tags {
			found := false
			for _, candidate := range origin.Tags {
				if candidate == tag {
					found = true
					break
				}
			}
			if !found {
				return -1
			}
		}
		score += len(rules.Tags)
	}
	if rules.Sensitivity != "" {
		if origin.Sensitivity != rules.Sensitivity {
			return -1
		}
		score += 4
	}
	if rules.ActorRole != "" {
		if origin.ActorRole != rules.ActorRole {
			return -1
		}
		score += 4
	}

	return score
}

func requiredCapability(actionType string) string {
	switch actionType {
	case "file_read":
		return "file_access"
	case "file_write":
		return "file_write"
	case "patch_apply":
		return "patch"
	case "shell_command":
		return "shell"
	case "tool_call":
		return "tool_call"
	case "egress":
		return "egress"
	default:
		return ""
	}
}

func prefixedRule(prefix, suffix string) string {
	if prefix == "" {
		return ""
	}
	return prefix + "." + suffix
}

func profileRulePrefix(profileID, field string) string {
	return fmt.Sprintf("extensions.origins.profiles.%s.%s", profileID, field)
}

func hasPatterns(patterns []string) bool {
	return len(patterns) > 0
}

func smallestToolArgLimit(baseRule, profileRule *ToolAccessRule, profilePrefix string) (int, string, bool) {
	limit := 0
	matchedRule := ""
	ok := false

	if baseRule != nil && baseRule.MaxArgsSize != nil {
		limit = *baseRule.MaxArgsSize
		matchedRule = "rules.tool_access.max_args_size"
		ok = true
	}
	if profileRule != nil && profileRule.MaxArgsSize != nil {
		if !ok || *profileRule.MaxArgsSize < limit {
			limit = *profileRule.MaxArgsSize
			matchedRule = profilePrefix + ".max_args_size"
			ok = true
		}
	}

	return limit, matchedRule, ok
}

func decisionRank(decision Decision) int {
	switch decision {
	case DecisionAllow:
		return 1
	case DecisionWarn:
		return 2
	case DecisionDeny:
		return 3
	default:
		return 0
	}
}

func moreRestrictiveResult(left, right EvaluationResult) EvaluationResult {
	leftRank := decisionRank(left.Decision)
	rightRank := decisionRank(right.Decision)
	if rightRank > leftRank {
		return right
	}
	if leftRank > rightRank {
		return left
	}
	if right.MatchedRule != "" {
		return right
	}
	return left
}

func allowResult(matchedRule, reason, originProfile string, posture *PostureResult) EvaluationResult {
	return EvaluationResult{
		Decision:      DecisionAllow,
		MatchedRule:   matchedRule,
		Reason:        reason,
		OriginProfile: originProfile,
		Posture:       posture,
	}
}

func warnResult(matchedRule, reason, originProfile string, posture *PostureResult) EvaluationResult {
	return EvaluationResult{
		Decision:      DecisionWarn,
		MatchedRule:   matchedRule,
		Reason:        reason,
		OriginProfile: originProfile,
		Posture:       posture,
	}
}

func denyResult(matchedRule, reason, originProfile string, posture *PostureResult) EvaluationResult {
	return EvaluationResult{
		Decision:      DecisionDeny,
		MatchedRule:   matchedRule,
		Reason:        reason,
		OriginProfile: originProfile,
		Posture:       posture,
	}
}

func findFirstMatch(target string, patterns []string) int {
	for i, pattern := range patterns {
		if globMatches(pattern, target) {
			return i
		}
	}
	return -1
}

// globMatches tests whether target matches a glob pattern.
// * matches non-/ characters, ** matches everything, ? matches one character.
func globMatches(pattern, target string) bool {
	var regex strings.Builder
	regex.WriteByte('^')

	chars := []rune(pattern)
	for i := 0; i < len(chars); i++ {
		ch := chars[i]
		switch ch {
		case '*':
			if i+1 < len(chars) && chars[i+1] == '*' {
				if i+2 < len(chars) && chars[i+2] == '/' {
					// "**/" matches any number of leading path segments,
					// including zero, so "**/.env" matches both ".env" and
					// "a/b/.env".
					i += 2
					regex.WriteString("(?:.*/)?")
				} else {
					i++
					regex.WriteString(".*")
				}
			} else {
				regex.WriteString("[^/]*")
			}
		case '?':
			regex.WriteByte('.')
		case '.', '+', '(', ')', '{', '}', '[', ']', '^', '$', '|', '\\':
			regex.WriteByte('\\')
			regex.WriteRune(ch)
		default:
			regex.WriteRune(ch)
		}
	}
	regex.WriteByte('$')

	re, err := regexp.Compile(regex.String())
	if err != nil {
		return false
	}
	return re.MatchString(target)
}

// computePatchStats counts +/- lines in unified diff content, skipping
// file header lines (+++ / ---).
func computePatchStats(content string) patchStats {
	var stats patchStats
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---") {
			continue
		}
		if strings.HasPrefix(line, "+") {
			stats.additions++
		} else if strings.HasPrefix(line, "-") {
			stats.deletions++
		}
	}
	return stats
}

func imbalanceRatio(additions, deletions int) float64 {
	if additions == 0 && deletions == 0 {
		return 0.0
	}
	if additions == 0 {
		return float64(deletions)
	}
	if deletions == 0 {
		return float64(additions)
	}
	larger := math.Max(float64(additions), float64(deletions))
	smaller := math.Min(float64(additions), float64(deletions))
	return larger / smaller
}
