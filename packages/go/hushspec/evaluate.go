// Reference evaluator for HushSpec 0.2 (core spec Sections 3, 5, and 6).
//
// Evaluation of one action is:
//  1. extension guards (panic, origins `default_behavior`, posture capability),
//  2. every applicable rule block for the action type -- present, `enabled`,
//     and with a satisfied `when` condition -- evaluated in the order of the
//     Section 5 table, never short-circuiting on an allow,
//  3. aggregation: deny beats warn beats allow; matched_rule/reason come from
//     the first block in evaluation order whose decision equals the aggregate
//     and which named a rule.
//
// Unknown action types deny (`__unknown_action_type__`). Hosts and paths are
// normalized as specified in Section 3.14 before any pattern is consulted.
package hushspec

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"
)

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionWarn  Decision = "warn"
	DecisionDeny  Decision = "deny"
)

// UnknownActionTypeRule is the matched_rule reported when the action type is
// unknown to the specification (D1, core spec 5).
const UnknownActionTypeRule = "__unknown_action_type__"

// PanicRule is the matched_rule reported when the emergency panic protocol is
// active.
const PanicRule = "__hushspec_panic__"

// EvaluationAction is the input to the reference evaluator.
type EvaluationAction struct {
	Type    string `json:"type" yaml:"type"`
	Target  string `json:"target,omitempty" yaml:"target,omitempty"`
	Content string `json:"content,omitempty" yaml:"content,omitempty"`
	// URL is the navigation destination of a browser_action (core spec 3.11).
	// A nil URL skips the destination-host check entirely; a present-but-empty
	// URL is an unusable host that matches no pattern.
	URL *string `json:"url,omitempty" yaml:"url,omitempty"`
	// Network reports whether a code_exec call requests network access
	// (core spec 3.12).
	Network *bool `json:"network,omitempty" yaml:"network,omitempty"`
	// TimeoutMs is the execution time a code_exec call requests, in
	// milliseconds (core spec 3.12).
	TimeoutMs *int            `json:"timeout_ms,omitempty" yaml:"timeout_ms,omitempty"`
	Origin    *OriginContext  `json:"origin,omitempty" yaml:"origin,omitempty"`
	Posture   *PostureContext `json:"posture,omitempty" yaml:"posture,omitempty"`
	ArgsSize  *int            `json:"args_size,omitempty" yaml:"args_size,omitempty"`
	// Context is the runtime context consulted by `when` conditions (core spec
	// 3.13). When absent, conditions see an empty context and the engine clock.
	Context *RuntimeContext `json:"context,omitempty" yaml:"context,omitempty"`
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
	// Current is a pointer so an explicitly-supplied empty string ("") is
	// distinguishable from an absent field, mirroring Rust's Option<String>.
	// An empty/unknown current state is an unknown posture state (fail-closed
	// deny), while an absent field falls back to the posture's initial state.
	Current *string `json:"current,omitempty" yaml:"current,omitempty"`
	Signal  string  `json:"signal,omitempty" yaml:"signal,omitempty"`
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

// TracedEvaluation is an evaluation result together with its recorded rule
// trace, in evaluation order, so receipts reflect exactly what ran.
type TracedEvaluation struct {
	Result EvaluationResult `json:"result"`
	Trace  []RuleEvaluation `json:"trace"`
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

// Evaluate runs the reference evaluator against a resolved document.
//
// `when` conditions are evaluated against action.Context (an empty context and
// the engine clock when absent).
func Evaluate(spec *HushSpec, action *EvaluationAction) EvaluationResult {
	return EvaluateTraced(spec, action, nil, nil).Result
}

// EvaluateTraced is the full evaluation with the recorded rule trace (used by
// receipts and `h2h explain`). The explicit context replaces action.Context;
// out-of-band conditions keyed by rule-block name are ANDed with each block's
// own `when` (core spec 3.13).
func EvaluateTraced(
	spec *HushSpec,
	action *EvaluationAction,
	context *RuntimeContext,
	conditions map[string]*Condition,
) TracedEvaluation {
	effective := context
	if effective == nil {
		effective = action.Context
	}
	if effective == nil {
		effective = &RuntimeContext{}
	}
	evaluator := &evaluator{
		spec:       spec,
		action:     action,
		context:    effective,
		conditions: conditions,
		trace:      []RuleEvaluation{},
	}
	return evaluator.run()
}

// applicableBlocks lists the rule blocks applicable to each reference action
// type, in evaluation order (core spec Section 5). ok is false when the type is
// unknown to the specification.
func applicableBlocks(actionType string) (blocks []string, ok bool) {
	switch actionType {
	case "file_read":
		return []string{"forbidden_paths", "path_allowlist"}, true
	case "file_write":
		return []string{"forbidden_paths", "path_allowlist", "secret_patterns"}, true
	case "patch_apply":
		return []string{"forbidden_paths", "path_allowlist", "patch_integrity", "secret_patterns"}, true
	case "shell_command":
		return []string{"shell_commands"}, true
	case "egress":
		return []string{"egress", "secret_patterns"}, true
	case "tool_call":
		return []string{"tool_access", "secret_patterns"}, true
	case "computer_use":
		return []string{"computer_use", "remote_desktop_channels"}, true
	case "input_inject":
		return []string{"input_injection"}, true
	case "browser_action":
		return []string{"browser_automation"}, true
	case "code_exec":
		return []string{"code_execution"}, true
	case "custom":
		return nil, true
	default:
		return nil, false
	}
}

// blockDecision is the decision contributed by one rule block. An empty
// matchedRule means the block named no rule.
type blockDecision struct {
	decision    Decision
	matchedRule string
	reason      string
}

func allowDecision(matchedRule, reason string) blockDecision {
	return blockDecision{decision: DecisionAllow, matchedRule: matchedRule, reason: reason}
}

func warnDecision(matchedRule, reason string) blockDecision {
	return blockDecision{decision: DecisionWarn, matchedRule: matchedRule, reason: reason}
}

func denyDecision(matchedRule, reason string) blockDecision {
	return blockDecision{decision: DecisionDeny, matchedRule: matchedRule, reason: reason}
}

// inactive records why an applicable block was not evaluated.
type inactive struct{ reason string }

func inactiveAbsent(block string) *inactive {
	return &inactive{reason: fmt.Sprintf("no %s rule configured", block)}
}

var (
	inactiveDisabled           = &inactive{reason: "rule disabled"}
	inactiveConditionFalse     = &inactive{reason: "when condition is false"}
	inactiveOutOfBandCondition = &inactive{reason: "out-of-band condition is false"}
)

type evaluator struct {
	spec       *HushSpec
	action     *EvaluationAction
	context    *RuntimeContext
	conditions map[string]*Condition
	trace      []RuleEvaluation
}

func (e *evaluator) run() TracedEvaluation {
	if IsPanicActive() {
		e.record("panic", RuleOutcomeDeny, PanicRule, "emergency panic mode is active", true)
		return e.finish(DecisionDeny, PanicRule, "emergency panic mode is active", "", nil)
	}

	blocks, known := applicableBlocks(e.action.Type)
	if !known {
		reason := fmt.Sprintf("action type '%s' is unknown to the specification", e.action.Type)
		e.record("default", RuleOutcomeDeny, UnknownActionTypeRule, reason, true)
		return e.finish(DecisionDeny, UnknownActionTypeRule, reason, "", nil)
	}

	// Origins guard: select a profile or apply default_behavior.
	var origins *OriginsExtension
	if e.spec.Extensions != nil {
		origins = e.spec.Extensions.Origins
	}
	matchedProfile := selectOriginProfile(e.spec, e.action.Origin)
	originProfileID := ""
	if matchedProfile != nil {
		originProfileID = matchedProfile.ID
	}
	if origins != nil && matchedProfile == nil && originDefaultBehavior(origins) == OriginDefaultBehaviorDeny {
		const reason = "no origin profile matched and default_behavior is deny"
		e.record("origins", RuleOutcomeDeny, "extensions.origins.default_behavior", reason, true)
		e.skipAll(blocks, "short-circuited by origins deny")
		return e.finish(DecisionDeny, "extensions.origins.default_behavior", reason, "", nil)
	}

	// Posture guard.
	posture := resolvePosture(e.spec, matchedProfile, e.action.Posture)
	if denied := e.postureCapabilityGuard(posture); denied != nil {
		e.skipAll(blocks, "short-circuited by posture deny")
		return e.finish(DecisionDeny, denied.matchedRule, denied.reason, originProfileID, posture)
	}

	if e.action.Type == "custom" {
		// Only a posture state granting the `custom` capability can vouch for
		// an engine-defined action (core spec Section 5).
		if posture == nil {
			const reason = "custom actions require a posture state granting the custom capability"
			e.record("default", RuleOutcomeDeny, UnknownActionTypeRule, reason, true)
			return e.finish(DecisionDeny, UnknownActionTypeRule, reason, originProfileID, nil)
		}
		return e.finish(DecisionAllow, "", "", originProfileID, posture)
	}

	// Block evaluation and aggregation (core spec 6.1).
	normalizedPath := NormalizePath(e.action.Target)
	decisions := make([]blockDecision, 0, len(blocks))
	for _, block := range blocks {
		decision, skipped := e.evaluateBlock(block, matchedProfile, normalizedPath)
		if skipped != nil {
			e.record(block, RuleOutcomeSkip, "", skipped.reason, false)
			continue
		}
		e.record(block, outcomeFromDecision(decision.decision), decision.matchedRule, decision.reason, true)
		decisions = append(decisions, decision)
	}

	aggregate := DecisionAllow
	for _, decision := range decisions {
		if decisionRank(decision.decision) > decisionRank(aggregate) {
			aggregate = decision.decision
		}
	}
	matchedRule, reason := "", ""
	for _, decision := range decisions {
		if decision.decision == aggregate && decision.matchedRule != "" {
			matchedRule, reason = decision.matchedRule, decision.reason
			break
		}
	}
	return e.finish(aggregate, matchedRule, reason, originProfileID, posture)
}

func (e *evaluator) finish(
	decision Decision,
	matchedRule, reason, originProfile string,
	posture *PostureResult,
) TracedEvaluation {
	return TracedEvaluation{
		Result: EvaluationResult{
			Decision:      decision,
			MatchedRule:   matchedRule,
			Reason:        reason,
			OriginProfile: originProfile,
			Posture:       posture,
		},
		Trace: e.trace,
	}
}

func (e *evaluator) record(block string, outcome RuleOutcome, matchedRule, reason string, evaluated bool) {
	e.trace = append(e.trace, RuleEvaluation{
		RuleBlock:   block,
		Outcome:     outcome,
		MatchedRule: matchedRule,
		Reason:      reason,
		Evaluated:   evaluated,
	})
}

func (e *evaluator) skipAll(blocks []string, reason string) {
	for _, block := range blocks {
		e.record(block, RuleOutcomeSkip, "", reason, false)
	}
}

// activity reports whether a present block is active: enabled, and its `when`
// plus any out-of-band condition hold for the runtime context.
func (e *evaluator) activity(block string, enabled bool, when *Condition) *inactive {
	if !enabled {
		return inactiveDisabled
	}
	if when != nil && !EvaluateCondition(when, e.context) {
		return inactiveConditionFalse
	}
	if condition, ok := e.conditions[block]; ok && condition != nil && !EvaluateCondition(condition, e.context) {
		return inactiveOutOfBandCondition
	}
	return nil
}

func (e *evaluator) evaluateBlock(
	block string,
	matchedProfile *OriginProfile,
	normalizedPath string,
) (blockDecision, *inactive) {
	var rules *Rules
	if e.spec != nil {
		rules = e.spec.Rules
	}
	action := e.action

	switch block {
	case "forbidden_paths":
		if rules == nil || rules.ForbiddenPaths == nil {
			return blockDecision{}, inactiveAbsent(block)
		}
		rule := rules.ForbiddenPaths
		if skipped := e.activity(block, rule.Enabled, rule.When); skipped != nil {
			return blockDecision{}, skipped
		}
		return evaluateForbiddenPaths(rule, normalizedPath), nil

	case "path_allowlist":
		if rules == nil || rules.PathAllowlist == nil {
			return blockDecision{}, inactiveAbsent(block)
		}
		rule := rules.PathAllowlist
		if skipped := e.activity(block, rule.Enabled, rule.When); skipped != nil {
			return blockDecision{}, skipped
		}
		operation := pathOperationWrite
		switch action.Type {
		case "file_read":
			operation = pathOperationRead
		case "patch_apply":
			operation = pathOperationPatch
		}
		return evaluatePathAllowlist(rule, normalizedPath, operation), nil

	case "secret_patterns":
		if rules == nil || rules.SecretPatterns == nil {
			return blockDecision{}, inactiveAbsent(block)
		}
		rule := rules.SecretPatterns
		pathBearing := action.Type == "file_write" || action.Type == "patch_apply"
		// egress and tool_call are scanned only when they carry content.
		if !pathBearing && action.Content == "" {
			return blockDecision{}, inactiveAbsent(block)
		}
		if skipped := e.activity(block, rule.Enabled, rule.When); skipped != nil {
			return blockDecision{}, skipped
		}
		// skip_paths only applies to the path-bearing action types; an egress
		// or tool_call payload has no path to exclude.
		var skipPath *string
		if pathBearing {
			skipPath = &normalizedPath
		}
		return evaluateSecretPatterns(rule, skipPath, action.Content), nil

	case "patch_integrity":
		if rules == nil || rules.PatchIntegrity == nil {
			return blockDecision{}, inactiveAbsent(block)
		}
		rule := rules.PatchIntegrity
		if skipped := e.activity(block, rule.Enabled, rule.When); skipped != nil {
			return blockDecision{}, skipped
		}
		return evaluatePatchIntegrity(rule, action.Content), nil

	case "shell_commands":
		if rules == nil || rules.ShellCommands == nil {
			return blockDecision{}, inactiveAbsent(block)
		}
		rule := rules.ShellCommands
		if skipped := e.activity(block, rule.Enabled, rule.When); skipped != nil {
			return blockDecision{}, skipped
		}
		return evaluateShellCommands(rule, action.Target), nil

	case "tool_access":
		var base *ToolAccessRule
		if rules != nil {
			base = rules.ToolAccess
		}
		var overlay *OriginToolAccessOverlay
		overlayPrefix := ""
		if matchedProfile != nil && matchedProfile.ToolAccess != nil {
			overlay = matchedProfile.ToolAccess
			overlayPrefix = profileRulePrefix(matchedProfile.ID, "tool_access")
		}
		if base == nil && overlay == nil {
			return blockDecision{}, inactiveAbsent(block)
		}
		if base != nil {
			if skipped := e.activity(block, base.Enabled, base.When); skipped != nil {
				return blockDecision{}, skipped
			}
		}
		return evaluateToolAccess(base, overlay, overlayPrefix, action), nil

	case "egress":
		var base *EgressRule
		if rules != nil {
			base = rules.Egress
		}
		var overlay *OriginEgressOverlay
		overlayPrefix := ""
		if matchedProfile != nil && matchedProfile.Egress != nil {
			overlay = matchedProfile.Egress
			overlayPrefix = profileRulePrefix(matchedProfile.ID, "egress")
		}
		if base == nil && overlay == nil {
			return blockDecision{}, inactiveAbsent(block)
		}
		if base != nil {
			if skipped := e.activity(block, base.Enabled, base.When); skipped != nil {
				return blockDecision{}, skipped
			}
		}
		return evaluateEgressRule(base, overlay, overlayPrefix, NormalizeHost(action.Target)), nil

	case "computer_use":
		if rules == nil || rules.ComputerUse == nil {
			return blockDecision{}, inactiveAbsent(block)
		}
		rule := rules.ComputerUse
		if skipped := e.activity(block, rule.Enabled, rule.When); skipped != nil {
			return blockDecision{}, skipped
		}
		return evaluateComputerUse(rule, action.Target), nil

	case "remote_desktop_channels":
		if rules == nil || rules.RemoteDesktopChannels == nil {
			return blockDecision{}, inactiveAbsent(block)
		}
		rule := rules.RemoteDesktopChannels
		if skipped := e.activity(block, rule.Enabled, rule.When); skipped != nil {
			return blockDecision{}, skipped
		}
		decision, ok := evaluateRemoteDesktopChannels(rule, action.Target)
		if !ok {
			return blockDecision{}, inactiveAbsent(block)
		}
		return decision, nil

	case "input_injection":
		if rules == nil || rules.InputInjection == nil {
			return blockDecision{}, inactiveAbsent(block)
		}
		rule := rules.InputInjection
		if skipped := e.activity(block, rule.Enabled, rule.When); skipped != nil {
			return blockDecision{}, skipped
		}
		return evaluateInputInjection(rule, action.Target), nil

	case "browser_automation":
		if rules == nil || rules.BrowserAutomation == nil {
			return blockDecision{}, inactiveAbsent(block)
		}
		rule := rules.BrowserAutomation
		if skipped := e.activity(block, rule.Enabled, rule.When); skipped != nil {
			return blockDecision{}, skipped
		}
		return evaluateBrowserAutomation(rule, action), nil

	case "code_execution":
		if rules == nil || rules.CodeExecution == nil {
			return blockDecision{}, inactiveAbsent(block)
		}
		rule := rules.CodeExecution
		if skipped := e.activity(block, rule.Enabled, rule.When); skipped != nil {
			return blockDecision{}, skipped
		}
		return evaluateCodeExecution(rule, action), nil

	default:
		return blockDecision{}, inactiveAbsent(block)
	}
}

// postureCapabilityGuard denies when the current posture state lacks the
// capability required by the action type.
func (e *evaluator) postureCapabilityGuard(posture *PostureResult) *blockDecision {
	if posture == nil {
		return nil
	}
	if e.spec.Extensions == nil || e.spec.Extensions.Posture == nil {
		return nil
	}
	capability := requiredCapability(e.action.Type)
	if capability == "" {
		return nil
	}

	currentState, ok := e.spec.Extensions.Posture.States[posture.Current]
	if !ok {
		rule := fmt.Sprintf("extensions.posture.states.%s", posture.Current)
		reason := fmt.Sprintf("unknown posture state '%s'", posture.Current)
		e.record("posture_capability", RuleOutcomeDeny, rule, reason, true)
		denied := denyDecision(rule, reason)
		return &denied
	}

	for _, granted := range currentState.Capabilities {
		if granted == capability {
			e.record("posture_capability", RuleOutcomeAllow, "", "posture capabilities satisfied", true)
			return nil
		}
	}

	rule := fmt.Sprintf("extensions.posture.states.%s.capabilities", posture.Current)
	reason := fmt.Sprintf("posture '%s' does not allow capability '%s'", posture.Current, capability)
	e.record("posture_capability", RuleOutcomeDeny, rule, reason, true)
	denied := denyDecision(rule, reason)
	return &denied
}

// ---------------------------------------------------------------------------
// Rule blocks
// ---------------------------------------------------------------------------

func evaluateForbiddenPaths(rule *ForbiddenPathsRule, path string) blockDecision {
	if anyPathGlobMatches(rule.Exceptions, path) {
		return allowDecision("rules.forbidden_paths.exceptions", "path matched an explicit exception")
	}
	if anyPathGlobMatches(rule.Patterns, path) {
		return denyDecision("rules.forbidden_paths.patterns", "path matched a forbidden pattern")
	}
	return allowDecision("", "path did not match any forbidden pattern")
}

func evaluatePathAllowlist(rule *PathAllowlistRule, path string, operation pathOperation) blockDecision {
	var patterns []string
	switch operation {
	case pathOperationRead:
		patterns = rule.Read
	case pathOperationPatch:
		if len(rule.Patch) > 0 {
			patterns = rule.Patch
		} else {
			patterns = rule.Write
		}
	default:
		patterns = rule.Write
	}
	if anyPathGlobMatches(patterns, path) {
		return allowDecision("rules.path_allowlist", "path matched allowlist")
	}
	return denyDecision("rules.path_allowlist", "path did not match allowlist")
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityWarn:
		return 1
	case SeverityError:
		return 2
	case SeverityCritical:
		return 3
	default:
		return 0
	}
}

// evaluateSecretPatterns scans content and maps the highest matched severity to
// a decision (D8): critical and error deny, warn warns. A pattern that will not
// compile under the HushSpec regex profile denies the action rather than being
// skipped (core spec 3.14.3).
func evaluateSecretPatterns(rule *SecretPatternsRule, skipPath *string, content string) blockDecision {
	if skipPath != nil && anyPathGlobMatches(rule.SkipPaths, *skipPath) {
		return allowDecision("rules.secret_patterns.skip_paths", "path is excluded from secret scanning")
	}

	bestRank := 0
	var best *SecretPattern
	for index := range rule.Patterns {
		pattern := &rule.Patterns[index]
		re, err := CompileProfileRegex(pattern.Pattern)
		if err != nil {
			return denyDecision(
				fmt.Sprintf("rules.secret_patterns.patterns.%s.pattern", pattern.Name),
				fmt.Sprintf("secret pattern '%s' is invalid: %v", pattern.Name, err),
			)
		}
		if !re.MatchString(content) {
			continue
		}
		// Strictly greater keeps the first pattern in document order among
		// those at the highest matched severity.
		if rank := severityRank(pattern.Severity); best == nil || rank > bestRank {
			bestRank, best = rank, pattern
		}
	}

	if best == nil {
		return allowDecision("", "content did not match any secret pattern")
	}
	matchedRule := fmt.Sprintf("rules.secret_patterns.patterns.%s", best.Name)
	reason := fmt.Sprintf("content matched secret pattern '%s'", best.Name)
	if best.Severity == SeverityWarn {
		return warnDecision(matchedRule, reason)
	}
	return denyDecision(matchedRule, reason)
}

func evaluatePatchIntegrity(rule *PatchIntegrityRule, content string) blockDecision {
	for index, pattern := range rule.ForbiddenPatterns {
		re, err := CompileProfileRegex(pattern)
		if err != nil {
			return denyDecision(
				fmt.Sprintf("rules.patch_integrity.forbidden_patterns[%d]", index),
				fmt.Sprintf("patch forbidden pattern is invalid: %v", err),
			)
		}
		if re.MatchString(content) {
			return denyDecision(
				fmt.Sprintf("rules.patch_integrity.forbidden_patterns[%d]", index),
				"patch content matched a forbidden pattern",
			)
		}
	}

	stats := computePatchStats(content)
	if stats.additions > rule.MaxAdditions {
		return denyDecision("rules.patch_integrity.max_additions", "patch additions exceeded max_additions")
	}
	if stats.deletions > rule.MaxDeletions {
		return denyDecision("rules.patch_integrity.max_deletions", "patch deletions exceeded max_deletions")
	}
	if rule.RequireBalance {
		// D10 (core 3.5 item 4): exactly one side at zero is an infinite
		// imbalance ratio and denies regardless of the configured limit.
		if (stats.additions == 0) != (stats.deletions == 0) {
			return denyDecision(
				"rules.patch_integrity.max_imbalance_ratio",
				"patch has changes on only one side; the imbalance ratio is infinite",
			)
		}
		if stats.additions > 0 && stats.deletions > 0 {
			limit := 10.0
			if rule.MaxImbalanceRatio != nil {
				limit = *rule.MaxImbalanceRatio
			}
			larger := math.Max(float64(stats.additions), float64(stats.deletions))
			smaller := math.Min(float64(stats.additions), float64(stats.deletions))
			if larger/smaller > limit {
				return denyDecision("rules.patch_integrity.max_imbalance_ratio", "patch exceeded max imbalance ratio")
			}
		}
	}

	return allowDecision("", "patch passed integrity checks")
}

func evaluateShellCommands(rule *ShellCommandsRule, command string) blockDecision {
	for index, pattern := range rule.ForbiddenPatterns {
		re, err := CompileProfileRegex(pattern)
		if err != nil {
			return denyDecision(
				fmt.Sprintf("rules.shell_commands.forbidden_patterns[%d]", index),
				fmt.Sprintf("shell forbidden pattern is invalid: %v", err),
			)
		}
		if re.MatchString(command) {
			return denyDecision(
				fmt.Sprintf("rules.shell_commands.forbidden_patterns[%d]", index),
				"shell command matched a forbidden pattern",
			)
		}
	}
	return allowDecision("", "command did not match any forbidden pattern")
}

// toolListContains compares tool names as exact, case-sensitive strings after
// NFC normalization (D3, core spec 3.7); glob and regex metacharacters are
// literal.
func toolListContains(entries []string, tool string) bool {
	normalized := norm.NFC.String(tool)
	for _, entry := range entries {
		if norm.NFC.String(entry) == normalized {
			return true
		}
	}
	return false
}

func evaluateToolAccess(
	base *ToolAccessRule,
	overlay *OriginToolAccessOverlay,
	overlayPrefix string,
	action *EvaluationAction,
) blockDecision {
	tool := action.Target

	// 1. max_args_size: the smaller of the two when both are specified.
	limit, limitRule, hasLimit := 0, "", false
	if base != nil && base.MaxArgsSize != nil {
		limit, limitRule, hasLimit = *base.MaxArgsSize, "rules.tool_access.max_args_size", true
	}
	if overlay != nil && overlay.MaxArgsSize != nil {
		if !hasLimit || *overlay.MaxArgsSize < limit {
			limit, limitRule, hasLimit = *overlay.MaxArgsSize, overlayPrefix+".max_args_size", true
		}
	}
	if hasLimit {
		actual := 0
		if action.ArgsSize != nil {
			actual = *action.ArgsSize
		}
		if actual > limit {
			return denyDecision(limitRule, "tool arguments exceeded max_args_size")
		}
	}

	// 2. block: union of both lists.
	if base != nil && toolListContains(base.Block, tool) {
		return denyDecision("rules.tool_access.block", "tool is explicitly blocked")
	}
	if overlay != nil && toolListContains(overlay.Block, tool) {
		return denyDecision(overlayPrefix+".block", "tool is explicitly blocked")
	}

	// 3. require_confirmation: union of both lists.
	if base != nil && toolListContains(base.RequireConfirmation, tool) {
		return warnDecision("rules.tool_access.require_confirmation", "tool requires confirmation")
	}
	if overlay != nil && toolListContains(overlay.RequireConfirmation, tool) {
		return warnDecision(overlayPrefix+".require_confirmation", "tool requires confirmation")
	}

	// 4/5. allowlist mode: intersection when both lists are non-empty.
	baseAllow := base != nil && len(base.Allow) > 0
	overlayAllow := overlay != nil && len(overlay.Allow) > 0
	if baseAllow || overlayAllow {
		if baseAllow && !toolListContains(base.Allow, tool) {
			return denyDecision("rules.tool_access.allow", "tool is not in the allowlist")
		}
		if overlayAllow && !toolListContains(overlay.Allow, tool) {
			return denyDecision(overlayPrefix+".allow", "tool is not in the allowlist")
		}
		matchedRule := "rules.tool_access.allow"
		if overlayAllow {
			matchedRule = overlayPrefix + ".allow"
		}
		return allowDecision(matchedRule, "tool is explicitly allowed")
	}

	// 6. default: block when the base says block or the overlay specifies block.
	baseDefault := DefaultActionAllow
	if base != nil && base.Default != "" {
		baseDefault = base.Default
	}
	var overlayDefault *DefaultAction
	if overlay != nil {
		overlayDefault = overlay.Default
	}
	effective := DefaultActionAllow
	if baseDefault == DefaultActionBlock || (overlayDefault != nil && *overlayDefault == DefaultActionBlock) {
		effective = DefaultActionBlock
	}
	matchedRule := defaultRulePath(
		base != nil, baseDefault, overlayDefault, effective,
		"rules.tool_access.default", overlayPrefix, overlay != nil,
	)
	if effective == DefaultActionBlock {
		return denyDecision(matchedRule, "tool matched default block")
	}
	return allowDecision(matchedRule, "tool matched default allow")
}

// defaultRulePath names the object whose `default` field determined the
// effective value.
func defaultRulePath(
	basePresent bool,
	baseDefault DefaultAction,
	overlayDefault *DefaultAction,
	effective DefaultAction,
	basePath, overlayPrefix string,
	overlayPresent bool,
) string {
	if !overlayPresent {
		return basePath
	}
	overlayPath := overlayPrefix + ".default"
	if effective == DefaultActionBlock {
		if basePresent && baseDefault == DefaultActionBlock {
			return basePath
		}
		return overlayPath
	}
	if basePresent || overlayDefault == nil {
		return basePath
	}
	return overlayPath
}

func evaluateEgressRule(
	base *EgressRule,
	overlay *OriginEgressOverlay,
	overlayPrefix string,
	host *string,
) blockDecision {
	// 1. block: union of both lists.
	if base != nil && anyHostPatternMatches(base.Block, host) {
		return denyDecision("rules.egress.block", "domain is explicitly blocked")
	}
	if overlay != nil && anyHostPatternMatches(overlay.Block, host) {
		return denyDecision(overlayPrefix+".block", "domain is explicitly blocked")
	}

	// 2. allow: intersection when both lists are non-empty.
	baseAllow := base != nil && len(base.Allow) > 0
	overlayAllow := overlay != nil && len(overlay.Allow) > 0
	if baseAllow || overlayAllow {
		baseOK := !baseAllow || anyHostPatternMatches(base.Allow, host)
		overlayOK := !overlayAllow || anyHostPatternMatches(overlay.Allow, host)
		if baseOK && overlayOK {
			matchedRule := "rules.egress.allow"
			if overlayAllow {
				matchedRule = overlayPrefix + ".allow"
			}
			return allowDecision(matchedRule, "domain is explicitly allowed")
		}
	}

	// 3. default.
	baseDefault := DefaultActionBlock
	if base != nil && base.Default != "" {
		baseDefault = base.Default
	}
	var overlayDefault *DefaultAction
	if overlay != nil {
		overlayDefault = overlay.Default
	}
	effective := DefaultActionAllow
	if baseDefault == DefaultActionBlock || (overlayDefault != nil && *overlayDefault == DefaultActionBlock) {
		effective = DefaultActionBlock
	}
	matchedRule := defaultRulePath(
		base != nil, baseDefault, overlayDefault, effective,
		"rules.egress.default", overlayPrefix, overlay != nil,
	)
	if effective == DefaultActionBlock {
		return denyDecision(matchedRule, "domain matched default block")
	}
	return allowDecision(matchedRule, "domain matched default allow")
}

func evaluateComputerUse(rule *ComputerUseRule, target string) blockDecision {
	for _, allowed := range rule.AllowedActions {
		if allowed == target {
			return allowDecision("rules.computer_use.allowed_actions", "computer-use action is explicitly allowed")
		}
	}
	mode := rule.Mode
	if mode == "" {
		mode = ComputerUseModeGuardrail
	}
	if mode == ComputerUseModeObserve {
		return allowDecision("rules.computer_use.mode", "observe mode does not block unlisted actions")
	}
	// guardrail and fail_closed have identical reference semantics (D9).
	return denyDecision("rules.computer_use.mode", "unlisted computer-use action is denied")
}

func evaluateRemoteDesktopChannels(rule *RemoteDesktopChannelsRule, target string) (blockDecision, bool) {
	field, allowed := "", false
	switch target {
	case "remote.clipboard":
		field, allowed = "clipboard", rule.Clipboard
	case "remote.file_transfer":
		field, allowed = "file_transfer", rule.FileTransfer
	case "remote.audio":
		field, allowed = "audio", rule.Audio
	case "remote.drive_mapping":
		field, allowed = "drive_mapping", rule.DriveMapping
	default:
		return blockDecision{}, false
	}
	matchedRule := "rules.remote_desktop_channels." + field
	if allowed {
		return allowDecision(matchedRule, fmt.Sprintf("remote desktop channel '%s' is enabled", field)), true
	}
	return denyDecision(matchedRule, fmt.Sprintf("remote desktop channel '%s' is disabled", field)), true
}

func evaluateInputInjection(rule *InputInjectionRule, target string) blockDecision {
	if len(rule.AllowedTypes) == 0 {
		return denyDecision(
			"rules.input_injection.allowed_types",
			"input injection is not allowed when allowed_types is empty",
		)
	}
	for _, allowed := range rule.AllowedTypes {
		if allowed == target {
			return allowDecision("rules.input_injection.allowed_types", "input injection type is explicitly allowed")
		}
	}
	return denyDecision("rules.input_injection.allowed_types", "input injection type is not allowed")
}

// builtinCredentialPattern is one built-in credential detector consulted by
// browser_automation when credential_detection is true (core spec 3.11).
type builtinCredentialPattern struct {
	name    string
	pattern string
}

// BuiltinCredentialPatterns are the built-in credential detectors. Documents
// needing portable detection list their own patterns in
// extra_credential_patterns.
var builtinCredentialPatterns = []builtinCredentialPattern{
	{"aws_access_key", "(AKIA|ASIA)[0-9A-Z]{16}"},
	{"github_token", "gh[opsur]_[A-Za-z0-9]{36}"},
	{"github_fine_grained_pat", "github_pat_[0-9a-zA-Z_]{50,}"},
	{"openai_key", "sk-[A-Za-z0-9_-]{20,}"},
	{"slack_token", "xox[baprs]-[0-9A-Za-z-]{10,}"},
	{"private_key", `-----BEGIN[ \t]+(RSA[ \t]+|EC[ \t]+|OPENSSH[ \t]+)?PRIVATE[ \t]+KEY-----`},
	{"jwt", `eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`},
}

func evaluateBrowserAutomation(rule *BrowserAutomationRule, action *EvaluationAction) blockDecision {
	verb := action.Target

	// 1. verb allowlist (exact match).
	if len(rule.AllowedVerbs) > 0 {
		found := false
		for _, allowed := range rule.AllowedVerbs {
			if allowed == verb {
				found = true
				break
			}
		}
		if !found {
			return denyDecision("rules.browser_automation.allowed_verbs", "browser verb is not in the allowlist")
		}
	}

	// 2. destination host.
	if action.URL != nil {
		host := NormalizeHost(*action.URL)
		if anyHostPatternMatches(rule.BlockedDomains, host) {
			return denyDecision("rules.browser_automation.blocked_domains", "destination host is explicitly blocked")
		}
		if len(rule.AllowedDomains) > 0 && !anyHostPatternMatches(rule.AllowedDomains, host) {
			return denyDecision("rules.browser_automation.allowed_domains", "destination host is not in the allowlist")
		}
	}

	// 3. credential detection on typed input.
	if rule.CredentialDetection && action.Content != "" {
		for _, builtin := range builtinCredentialPatterns {
			re, err := CompileProfileRegex(builtin.pattern)
			if err == nil && re.MatchString(action.Content) {
				return denyDecision(
					"rules.browser_automation.credential_detection",
					fmt.Sprintf("typed input matched built-in credential detector '%s'", builtin.name),
				)
			}
		}
		for index, pattern := range rule.ExtraCredentialPatterns {
			re, err := CompileProfileRegex(pattern)
			if err != nil {
				return denyDecision(
					fmt.Sprintf("rules.browser_automation.extra_credential_patterns[%d]", index),
					fmt.Sprintf("credential pattern is invalid: %v", err),
				)
			}
			if re.MatchString(action.Content) {
				return denyDecision(
					"rules.browser_automation.credential_detection",
					fmt.Sprintf("typed input matched extra_credential_patterns[%d]", index),
				)
			}
		}
	}

	return allowDecision("rules.browser_automation", "browser action is permitted")
}

func evaluateCodeExecution(rule *CodeExecutionRule, action *EvaluationAction) blockDecision {
	language := action.Target

	// 1. language allowlist (exact, case-sensitive).
	if len(rule.LanguageAllowlist) > 0 {
		found := false
		for _, allowed := range rule.LanguageAllowlist {
			if allowed == language {
				found = true
				break
			}
		}
		if !found {
			return denyDecision("rules.code_execution.language_allowlist", "language is not in the allowlist")
		}
	}

	// 2. network access.
	if action.Network != nil && *action.Network && !rule.NetworkAccess {
		return denyDecision(
			"rules.code_execution.network_access",
			"network access is not permitted for code execution",
		)
	}

	// 3. execution time bound.
	if rule.MaxExecutionTimeMs != nil && action.TimeoutMs != nil && *action.TimeoutMs > *rule.MaxExecutionTimeMs {
		return denyDecision(
			"rules.code_execution.max_execution_time_ms",
			"requested execution time exceeds max_execution_time_ms",
		)
	}

	// 4. module denylist: literal word match within the scanned prefix.
	if action.Content != "" {
		scanned := action.Content
		if rule.MaxScanBytes != nil && *rule.MaxScanBytes < len(scanned) {
			end := *rule.MaxScanBytes
			for end > 0 && !isUTF8Boundary(scanned, end) {
				end--
			}
			scanned = scanned[:end]
		}
		for _, module := range rule.ModuleDenylist {
			if containsWord(scanned, module) {
				return denyDecision(
					"rules.code_execution.module_denylist",
					fmt.Sprintf("code references denied module '%s'", module),
				)
			}
		}
	}

	return allowDecision("rules.code_execution", "code execution is permitted")
}

// isUTF8Boundary reports whether index sits on a UTF-8 character boundary of s.
func isUTF8Boundary(s string, index int) bool {
	if index <= 0 || index >= len(s) {
		return true
	}
	return s[index]&0xC0 != 0x80
}

// containsWord reports whether word occurs in text bounded by non-[A-Za-z0-9_]
// characters or the text boundaries (core spec 3.12 step 4).
func containsWord(text, word string) bool {
	if word == "" {
		return false
	}
	isWordByte := func(b byte) bool {
		return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
	}
	start := 0
	for start <= len(text)-len(word) {
		offset := strings.Index(text[start:], word)
		if offset < 0 {
			return false
		}
		at := start + offset
		end := at + len(word)
		beforeOK := at == 0 || !isWordByte(text[at-1])
		afterOK := end == len(text) || !isWordByte(text[end])
		if beforeOK && afterOK {
			return true
		}
		start = at + 1
	}
	return false
}

// ---------------------------------------------------------------------------
// Posture and origins
// ---------------------------------------------------------------------------

func originDefaultBehavior(origins *OriginsExtension) OriginDefaultBehavior {
	// The reference default is deny (D12, origins 2.1).
	if origins.DefaultBehavior == nil {
		return OriginDefaultBehaviorDeny
	}
	return *origins.DefaultBehavior
}

// resolvePosture determines the current and next posture state from the origin
// profile, action context, and posture extension (in priority order).
func resolvePosture(
	spec *HushSpec,
	matchedProfile *OriginProfile,
	postureCtx *PostureContext,
) *PostureResult {
	if spec.Extensions == nil || spec.Extensions.Posture == nil {
		return nil
	}
	postureExtension := spec.Extensions.Posture

	// The matched profile's posture wins, then the action context's current (a
	// present-but-empty "" is a real value, not a fallback trigger), then the
	// posture extension's initial state.
	current := ""
	set := false
	if matchedProfile != nil && matchedProfile.Posture != nil {
		current, set = *matchedProfile.Posture, true
	}
	if !set && postureCtx != nil && postureCtx.Current != nil {
		current, set = *postureCtx.Current, true
	}
	if !set {
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

// selectOriginProfile implements origin profile selection (origins spec
// Section 3): candidates are profiles with a `match` object every present field
// of which is satisfied; a `space_id` match wins outright, then the greatest
// matched-field count, then document order.
func selectOriginProfile(spec *HushSpec, origin *OriginContext) *OriginProfile {
	if origin == nil {
		return nil
	}
	if spec.Extensions == nil || spec.Extensions.Origins == nil {
		return nil
	}
	profiles := spec.Extensions.Origins.Profiles

	bestCount := -1
	var best *OriginProfile
	for index := range profiles {
		profile := &profiles[index]
		// A profile without a `match` field is never a candidate (D12).
		if profile.Match == nil {
			continue
		}
		matchedFields, ok := matchOrigin(profile.Match, origin)
		if !ok {
			continue
		}
		if profile.Match.SpaceID != "" {
			return profile
		}
		if matchedFields > bestCount {
			bestCount, best = matchedFields, profile
		}
	}
	return best
}

// matchOrigin returns the number of `match` fields satisfied by origin, or
// ok=false when any present field is not satisfied. `tags` counts as one field
// and there is no per-field weighting (D12).
func matchOrigin(rules *OriginMatch, origin *OriginContext) (int, bool) {
	count := 0
	checkString := func(expected, actual string) bool {
		if expected == "" {
			return true
		}
		if actual != expected {
			return false
		}
		count++
		return true
	}
	if !checkString(rules.Provider, origin.Provider) ||
		!checkString(rules.TenantID, origin.TenantID) ||
		!checkString(rules.SpaceID, origin.SpaceID) ||
		!checkString(rules.SpaceType, origin.SpaceType) ||
		!checkString(rules.Visibility, origin.Visibility) ||
		!checkString(rules.Sensitivity, origin.Sensitivity) ||
		!checkString(rules.ActorRole, origin.ActorRole) {
		return 0, false
	}
	if rules.ExternalParticipants != nil {
		if origin.ExternalParticipants == nil || *origin.ExternalParticipants != *rules.ExternalParticipants {
			return 0, false
		}
		count++
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
				return 0, false
			}
		}
		count++
	}
	// NOTE: a match rule with all fields absent legitimately matches every
	// origin with count 0 (the explicit `match: {}` default profile), so count
	// 0 must NOT be read as "no match". A present-but-empty match field such as
	// `provider: ""` -- a real, unsatisfiable constraint in the reference SDKs
	// -- is rejected at parse (validateRawDocument) instead, because the
	// generated Go model collapses "" and an absent field.
	return count, true
}

// requiredCapability names the posture capability each action type requires
// (posture spec 3.3).
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
	case "custom":
		return "custom"
	default:
		return ""
	}
}

func profileRulePrefix(profileID, field string) string {
	return fmt.Sprintf("extensions.origins.profiles.%s.%s", profileID, field)
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

// ---------------------------------------------------------------------------
// Path globs (core spec 3.14.1)
// ---------------------------------------------------------------------------

// NormalizePath normalizes a filesystem path for matching (D6, core spec
// 3.14.1): NFC, `\` to `/`, collapsed separators, lexical `.`/`..` resolution,
// no trailing `/`. It is deliberately lexical -- it never touches the
// filesystem and never applies OS-specific rules.
func NormalizePath(target string) string {
	unified := strings.ReplaceAll(norm.NFC.String(target), `\`, "/")
	absolute := strings.HasPrefix(unified, "/")
	segments := make([]string, 0, 8)
	for _, segment := range strings.Split(unified, "/") {
		switch segment {
		case "", ".":
			// Dropped.
		case "..":
			if len(segments) > 0 && segments[len(segments)-1] != ".." {
				segments = segments[:len(segments)-1]
			} else if !absolute {
				segments = append(segments, "..")
			}
		default:
			segments = append(segments, segment)
		}
	}
	joined := strings.Join(segments, "/")
	if absolute {
		return "/" + joined
	}
	return joined
}

// pathGlobRegex compiles a path glob (core spec 3.14.1) into an anchored
// regex. `?` and `*` never cross `/`; `**` spans zero or more segments; `[` and
// `{` are literal.
func pathGlobRegex(pattern string) (*regexp.Regexp, error) {
	chars := []rune(norm.NFC.String(pattern))
	var out strings.Builder
	out.WriteByte('^')
	for index := 0; index < len(chars); {
		ch := chars[index]
		if ch == '*' && index+1 < len(chars) && chars[index+1] == '*' {
			atSegmentStart := index == 0 || chars[index-1] == '/'
			if atSegmentStart && index+2 < len(chars) && chars[index+2] == '/' {
				// `**/`: zero or more complete leading segments.
				out.WriteString("(?:[^/]*/)*")
				index += 3
			} else {
				out.WriteString(".*")
				index += 2
			}
			continue
		}
		switch ch {
		case '*':
			out.WriteString("[^/]*")
		case '?':
			out.WriteString("[^/]")
		default:
			out.WriteString(regexp.QuoteMeta(string(ch)))
		}
		index++
	}
	out.WriteByte('$')
	return regexp.Compile(out.String())
}

// PathGlobMatches reports whether an already-normalized path matches the path
// glob pattern.
func PathGlobMatches(pattern, path string) bool {
	re, err := pathGlobRegex(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(path)
}

func anyPathGlobMatches(patterns []string, path string) bool {
	for _, pattern := range patterns {
		if PathGlobMatches(pattern, path) {
			return true
		}
	}
	return false
}

// globMatches matches a raw path target against a path glob, normalizing the
// target first. Kept for callers outside the evaluator; prefer
// [PathGlobMatches] with an already-normalized path.
func globMatches(pattern, target string) bool {
	return PathGlobMatches(pattern, NormalizePath(target))
}

// ---------------------------------------------------------------------------
// Host patterns (core spec 3.14.2)
// ---------------------------------------------------------------------------

// NormalizeHost reduces an egress target (host, `host:port`, or URL) to a
// normalized host (D5, core spec 3.14.2): lowercased, scheme, userinfo, path,
// query, port, and trailing dot removed, non-ASCII labels in IDNA A-label
// (punycode) form. It returns nil when the target cannot be reduced to a
// syntactically valid host, in which case it matches nothing.
func NormalizeHost(target string) *string {
	target = strings.TrimSpace(target)
	authority := target
	if index := strings.Index(authority, "://"); index >= 0 {
		authority = authority[index+3:]
	}
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = authority[at+1:]
	}
	if authority == "" {
		return nil
	}

	if strings.HasPrefix(authority, "[") {
		rest := authority[1:]
		close := strings.Index(rest, "]")
		if close < 0 {
			return nil
		}
		inner := rest[:close]
		if inner == "" {
			return nil
		}
		for index := 0; index < len(inner); index++ {
			b := inner[index]
			if !isASCIIHexByte(b) && b != ':' && b != '.' {
				return nil
			}
		}
		result := "[" + asciiLower(inner) + "]"
		return &result
	}

	host := authority
	if colon := strings.LastIndex(host, ":"); colon >= 0 {
		port := host[colon+1:]
		if port != "" && isASCIIDigits(port) {
			host = host[:colon]
		}
	}
	if strings.Contains(host, ":") {
		return nil
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return nil
	}

	labels := strings.Split(host, ".")
	normalizedLabels := make([]string, 0, len(labels))
	for _, label := range labels {
		if label == "" {
			return nil
		}
		normalized, ok := normalizeHostLabel(label)
		if !ok {
			return nil
		}
		normalizedLabels = append(normalizedLabels, normalized)
	}
	normalized := strings.Join(normalizedLabels, ".")
	for index := 0; index < len(normalized); index++ {
		b := normalized[index]
		isAlnum := (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
		if !isAlnum && b != '-' && b != '.' && b != '_' {
			return nil
		}
	}
	return &normalized
}

func isASCIIHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// asciiLower lowercases only the ASCII letters of s, mirroring Rust's
// to_ascii_lowercase: non-ASCII code points are left untouched.
func asciiLower(s string) string {
	var out []byte
	for index := 0; index < len(s); index++ {
		b := s[index]
		if b >= 'A' && b <= 'Z' {
			if out == nil {
				out = []byte(s)
			}
			out[index] = b + ('a' - 'A')
		}
	}
	if out == nil {
		return s
	}
	return string(out)
}

func isASCIIString(s string) bool {
	for index := 0; index < len(s); index++ {
		if s[index] >= 0x80 {
			return false
		}
	}
	return true
}

// normalizeHostLabel normalizes one host label: ASCII lowercase, or the IDNA
// A-label (punycode) of the NFC-normalized, lowercased label when it is not
// ASCII. No UTS-46 mapping is applied -- this is RFC 3492 punycode over NFC.
func normalizeHostLabel(label string) (string, bool) {
	if isASCIIString(label) {
		return strings.ToLower(label), true
	}
	folded := norm.NFC.String(strings.ToLower(label))
	if isASCIIString(folded) {
		return folded, true
	}
	encoded, ok := PunycodeEncode(folded)
	if !ok {
		return "", false
	}
	return "xn--" + encoded, true
}

// normalizeHostPattern applies steps 5-7 of core spec 3.14.2 to a pattern,
// preserving `*`.
func normalizeHostPattern(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	pattern = strings.TrimSuffix(pattern, ".")
	if strings.HasPrefix(pattern, "[") {
		return asciiLower(pattern)
	}
	labels := strings.Split(pattern, ".")
	for index, label := range labels {
		if isASCIIString(label) {
			labels[index] = asciiLower(label)
			continue
		}
		if normalized, ok := normalizeHostLabel(label); ok {
			labels[index] = normalized
		} else {
			labels[index] = strings.ToLower(label)
		}
	}
	return strings.Join(labels, ".")
}

func isIPv4Literal(host string) bool {
	octets := strings.Split(host, ".")
	if len(octets) != 4 {
		return false
	}
	for _, octet := range octets {
		if octet == "" || len(octet) > 3 || !isASCIIDigits(octet) {
			return false
		}
		value := 0
		for index := 0; index < len(octet); index++ {
			value = value*10 + int(octet[index]-'0')
		}
		if value > 255 {
			return false
		}
	}
	return true
}

func isIPLiteral(host string) bool {
	return strings.HasPrefix(host, "[") || isIPv4Literal(host)
}

// HostPatternMatches reports whether a normalized host matches a host pattern
// (core spec 3.14.2): `*` is one or more non-dot characters, `**` one or more
// characters including dots, everything else literal. IP literals match only
// an exact entry.
func HostPatternMatches(pattern, host string) bool {
	pattern = normalizeHostPattern(pattern)
	if isIPLiteral(host) {
		return pattern == host
	}
	chars := []rune(pattern)
	var out strings.Builder
	out.WriteByte('^')
	for index := 0; index < len(chars); {
		if chars[index] == '*' {
			if index+1 < len(chars) && chars[index+1] == '*' {
				out.WriteString(".+")
				index += 2
			} else {
				out.WriteString("[^.]+")
				index++
			}
			continue
		}
		out.WriteString(regexp.QuoteMeta(string(chars[index])))
		index++
	}
	out.WriteByte('$')
	re, err := regexp.Compile(out.String())
	if err != nil {
		return false
	}
	return re.MatchString(host)
}

func anyHostPatternMatches(patterns []string, host *string) bool {
	if host == nil {
		return false
	}
	for _, pattern := range patterns {
		if HostPatternMatches(pattern, *host) {
			return true
		}
	}
	return false
}

// PunycodeEncode is the RFC 3492 punycode encoding of one label, without the
// `xn--` prefix. It returns ok=false when the label cannot be encoded.
func PunycodeEncode(input string) (string, bool) {
	const (
		base        = uint32(36)
		tmin        = uint32(1)
		tmax        = uint32(26)
		skew        = uint32(38)
		damp        = uint32(700)
		initialBias = uint32(72)
		initialN    = uint32(128)
	)

	adapt := func(delta uint32, numPoints uint32, firstTime bool) uint32 {
		if firstTime {
			delta /= damp
		} else {
			delta /= 2
		}
		delta += delta / numPoints
		k := uint32(0)
		for delta > ((base-tmin)*tmax)/2 {
			delta /= base - tmin
			k += base
		}
		return k + (((base - tmin + 1) * delta) / (delta + skew))
	}

	digit := func(value uint32) byte {
		if value < 26 {
			return byte('a' + value)
		}
		return byte('0' + (value - 26))
	}

	codePoints := []rune(input)
	output := make([]byte, 0, len(input)*2)
	for _, cp := range codePoints {
		if cp < 128 {
			output = append(output, byte(cp))
		}
	}
	basicCount := uint32(len(output))
	handled := basicCount
	if basicCount > 0 {
		output = append(output, '-')
	}

	n := initialN
	delta := uint32(0)
	bias := initialBias
	for int(handled) < len(codePoints) {
		m := uint32(0)
		found := false
		for _, cp := range codePoints {
			if uint32(cp) >= n && (!found || uint32(cp) < m) {
				m, found = uint32(cp), true
			}
		}
		if !found {
			return "", false
		}
		add, ok := checkedMul(m-n, handled+1)
		if !ok {
			return "", false
		}
		delta, ok = checkedAdd(delta, add)
		if !ok {
			return "", false
		}
		n = m
		for _, cp := range codePoints {
			if uint32(cp) < n {
				if delta, ok = checkedAdd(delta, 1); !ok {
					return "", false
				}
			}
			if uint32(cp) == n {
				q := delta
				for k := base; ; k += base {
					t := tmax
					switch {
					case k <= bias:
						t = tmin
					case k >= bias+tmax:
						t = tmax
					default:
						t = k - bias
					}
					if q < t {
						break
					}
					output = append(output, digit(t+(q-t)%(base-t)))
					q = (q - t) / (base - t)
				}
				output = append(output, digit(q))
				bias = adapt(delta, handled+1, handled == basicCount)
				delta = 0
				handled++
			}
		}
		if delta, ok = checkedAdd(delta, 1); !ok {
			return "", false
		}
		if n, ok = checkedAdd(n, 1); !ok {
			return "", false
		}
	}
	return string(output), true
}

func checkedAdd(a, b uint32) (uint32, bool) {
	sum := a + b
	if sum < a {
		return 0, false
	}
	return sum, true
}

func checkedMul(a, b uint32) (uint32, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	product := a * b
	if product/a != b {
		return 0, false
	}
	return product, true
}

// ---------------------------------------------------------------------------
// Patch statistics
// ---------------------------------------------------------------------------

// computePatchStats counts +/- lines in unified diff content, skipping file
// header lines (+++ / ---).
func computePatchStats(content string) patchStats {
	var stats patchStats
	for _, line := range splitLines(content) {
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

// splitLines mirrors Rust's str::lines: it splits on \n, strips a trailing \r,
// and yields no final empty line for content ending in a newline.
func splitLines(content string) []string {
	if content == "" {
		return nil
	}
	trimmed := strings.TrimSuffix(content, "\n")
	lines := strings.Split(trimmed, "\n")
	for index, line := range lines {
		lines[index] = strings.TrimSuffix(line, "\r")
	}
	return lines
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
