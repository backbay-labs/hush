// Compiled policies: the one-time translation of a resolved HushSpec document
// into the matchers the evaluator actually runs.
//
// The reference evaluator is specified over the document itself, so the
// straightforward implementation recompiles every regex, path glob and host
// pattern on every action. A [CompiledPolicy] does that work once -- regexes
// under the HushSpec regex profile, anchored path-glob and host-pattern
// regexes, NFC-folded tool name lists, severity ranks, per-block applicability
// and the detection extension's detectors -- and then answers actions from the
// precompiled form.
//
// Compilation is a pure performance concern: a compiled policy produces exactly
// the decisions, traces and receipts the free functions produce, including the
// fail-closed denies a pattern outside the regex profile causes. A pattern that
// will not compile is kept as a recorded error carrying the rule path, so the
// evaluator denies with the same matched_rule and reason it always did, and
// [CompilePolicy] reports it to callers that want compilation itself to fail.
//
// A [CompiledPolicy] is immutable once built and safe for concurrent use. It
// keeps a reference to the source document for receipts and hashing, and
// assumes that document is not mutated afterwards.
package hushspec

import (
	"errors"
	"fmt"
	"regexp"
	"sync"
	"sync/atomic"

	"golang.org/x/text/unicode/norm"
)

// ---------------------------------------------------------------------------
// Rule blocks
// ---------------------------------------------------------------------------

// blockID identifies one rule block. The evaluator works in these instead of
// block-name strings so applicability, activity and the trace can be indexed
// and masked; [blockNames] maps back to the spelling the trace records.
type blockID int

const (
	blockForbiddenPaths blockID = iota
	blockPathAllowlist
	blockSecretPatterns
	blockPatchIntegrity
	blockShellCommands
	blockToolAccess
	blockEgress
	blockComputerUse
	blockRemoteDesktopChannels
	blockInputInjection
	blockBrowserAutomation
	blockCodeExecution
	blockCount
)

// blockNames are the rule-block names the trace and out-of-band condition map
// are keyed by (core spec Section 5).
var blockNames = [blockCount]string{
	blockForbiddenPaths:        "forbidden_paths",
	blockPathAllowlist:         "path_allowlist",
	blockSecretPatterns:        "secret_patterns",
	blockPatchIntegrity:        "patch_integrity",
	blockShellCommands:         "shell_commands",
	blockToolAccess:            "tool_access",
	blockEgress:                "egress",
	blockComputerUse:           "computer_use",
	blockRemoteDesktopChannels: "remote_desktop_channels",
	blockInputInjection:        "input_injection",
	blockBrowserAutomation:     "browser_automation",
	blockCodeExecution:         "code_execution",
}

// The applicable-block lists of core spec Section 5, allocated once instead of
// per evaluation. They are read-only.
var (
	blocksFileRead       = []blockID{blockForbiddenPaths, blockPathAllowlist}
	blocksFileWrite      = []blockID{blockForbiddenPaths, blockPathAllowlist, blockSecretPatterns}
	blocksPatchApply     = []blockID{blockForbiddenPaths, blockPathAllowlist, blockPatchIntegrity, blockSecretPatterns}
	blocksShellCommand   = []blockID{blockShellCommands}
	blocksEgress         = []blockID{blockEgress, blockSecretPatterns}
	blocksToolCall       = []blockID{blockToolAccess, blockSecretPatterns}
	blocksComputerUse    = []blockID{blockComputerUse, blockRemoteDesktopChannels}
	blocksInputInject    = []blockID{blockInputInjection}
	blocksBrowserAction  = []blockID{blockBrowserAutomation}
	blocksCodeExec       = []blockID{blockCodeExecution}
	inactiveAbsentBlocks = newInactiveAbsentBlocks()
)

func newInactiveAbsentBlocks() [blockCount]*inactive {
	var out [blockCount]*inactive
	for id := blockID(0); id < blockCount; id++ {
		out[id] = &inactive{reason: fmt.Sprintf("no %s rule configured", blockNames[id])}
	}
	return out
}

// applicableBlocks lists the rule blocks applicable to each reference action
// type, in evaluation order (core spec Section 5). ok is false when the type is
// unknown to the specification.
func applicableBlocks(actionType string) (blocks []blockID, ok bool) {
	switch actionType {
	case "file_read":
		return blocksFileRead, true
	case "file_write":
		return blocksFileWrite, true
	case "patch_apply":
		return blocksPatchApply, true
	case "shell_command":
		return blocksShellCommand, true
	case "egress":
		return blocksEgress, true
	case "tool_call":
		return blocksToolCall, true
	case "computer_use":
		return blocksComputerUse, true
	case "input_inject":
		return blocksInputInject, true
	case "browser_action":
		return blocksBrowserAction, true
	case "code_exec":
		return blocksCodeExec, true
	case "custom":
		return nil, true
	default:
		return nil, false
	}
}

// ---------------------------------------------------------------------------
// Compiled matchers
// ---------------------------------------------------------------------------

// compiledGlobSet is a path-glob list compiled to anchored regexes. A pattern
// that does not compile is a nil entry, which matches nothing -- the behaviour
// [PathGlobMatches] has always had for an uncompilable glob.
type compiledGlobSet []*regexp.Regexp

func compileGlobSet(patterns []string) compiledGlobSet {
	if len(patterns) == 0 {
		return nil
	}
	set := make(compiledGlobSet, len(patterns))
	for index, pattern := range patterns {
		if re, err := pathGlobRegex(pattern); err == nil {
			set[index] = re
		}
	}
	return set
}

func (s compiledGlobSet) matches(path string) bool {
	for _, re := range s {
		if re != nil && re.MatchString(path) {
			return true
		}
	}
	return false
}

// compiledHostPattern is one host pattern with its normalization (core spec
// 3.14.2 steps 5-7) and its anchored regex already built. The normalized form
// is kept because an IP-literal host matches only an exact entry, never the
// wildcard regex.
type compiledHostPattern struct {
	normalized string
	re         *regexp.Regexp
}

func compileHostPattern(pattern string) compiledHostPattern {
	normalized := normalizeHostPattern(pattern)
	re, err := regexp.Compile(hostPatternSource(normalized))
	if err != nil {
		return compiledHostPattern{normalized: normalized}
	}
	return compiledHostPattern{normalized: normalized, re: re}
}

func (p compiledHostPattern) matches(host string) bool {
	if isIPLiteral(host) {
		return p.normalized == host
	}
	return p.re != nil && p.re.MatchString(host)
}

type compiledHostSet []compiledHostPattern

func compileHostSet(patterns []string) compiledHostSet {
	if len(patterns) == 0 {
		return nil
	}
	set := make(compiledHostSet, len(patterns))
	for index, pattern := range patterns {
		set[index] = compileHostPattern(pattern)
	}
	return set
}

func (s compiledHostSet) matches(host *string) bool {
	if host == nil {
		return false
	}
	for _, pattern := range s {
		if pattern.matches(*host) {
			return true
		}
	}
	return false
}

// compiledPatternEntry is one policy-authored regex compiled under the HushSpec
// regex profile, together with the rule path and reasons the evaluator reports
// for it. A pattern outside the profile keeps its error: the block denies with
// exactly the message the on-the-fly compile produced (core spec 3.14.3).
type compiledPatternEntry struct {
	source      string
	re          *regexp.Regexp
	err         error
	errRule     string
	errReason   string
	matchRule   string
	matchReason string
}

func compilePatternEntry(pattern, errRule, errFormat, matchRule, matchReason string) compiledPatternEntry {
	entry := compiledPatternEntry{
		source:      pattern,
		errRule:     errRule,
		matchRule:   matchRule,
		matchReason: matchReason,
	}
	re, err := CompileProfileRegex(pattern)
	if err != nil {
		entry.err = err
		entry.errReason = fmt.Sprintf(errFormat, err)
		return entry
	}
	entry.re = re
	return entry
}

// ---------------------------------------------------------------------------
// Compiled rule blocks
// ---------------------------------------------------------------------------

// blockGate is the presence/activity configuration of one rule block, lifted
// out of the document so the active-block mask needs no spec walk.
type blockGate struct {
	present bool
	enabled bool
	when    *Condition
}

type compiledForbiddenPaths struct {
	patterns   compiledGlobSet
	exceptions compiledGlobSet
}

type compiledPathAllowlist struct {
	read  compiledGlobSet
	write compiledGlobSet
	// patch is the `patch` list, or the `write` list when `patch` is empty
	// (core spec 3.3) -- resolved here so evaluation never re-derives it.
	patch compiledGlobSet
}

type compiledSecretPattern struct {
	severity    Severity
	rank        int
	re          *regexp.Regexp
	err         error
	errRule     string
	errReason   string
	matchRule   string
	matchReason string
}

type compiledSecretPatterns struct {
	skipPaths compiledGlobSet
	patterns  []compiledSecretPattern
}

type compiledPatchIntegrity struct {
	rule              *PatchIntegrityRule
	forbiddenPatterns []compiledPatternEntry
}

type compiledShellCommands struct {
	forbiddenPatterns []compiledPatternEntry
}

type compiledToolAccess struct {
	rule *ToolAccessRule
	// Tool names are compared as exact, case-sensitive strings after NFC
	// normalization (D3, core spec 3.7), so the lists are folded once.
	allow               []string
	block               []string
	requireConfirmation []string
}

type compiledEgress struct {
	rule  *EgressRule
	allow compiledHostSet
	block compiledHostSet
}

type compiledComputerUse struct {
	rule *ComputerUseRule
	mode ComputerUseMode
}

type compiledBrowserAutomation struct {
	rule                    *BrowserAutomationRule
	allowedDomains          compiledHostSet
	blockedDomains          compiledHostSet
	extraCredentialPatterns []compiledPatternEntry
}

// ---------------------------------------------------------------------------
// Compiled origins
// ---------------------------------------------------------------------------

type compiledToolAccessOverlay struct {
	overlay             *OriginToolAccessOverlay
	prefix              string
	allow               []string
	block               []string
	requireConfirmation []string
}

type compiledEgressOverlay struct {
	overlay *OriginEgressOverlay
	prefix  string
	allow   compiledHostSet
	block   compiledHostSet
}

type compiledOriginProfile struct {
	id         string
	match      *OriginMatch
	posture    *string
	toolAccess *compiledToolAccessOverlay
	egress     *compiledEgressOverlay
}

type compiledOrigins struct {
	defaultBehavior OriginDefaultBehavior
	profiles        []compiledOriginProfile
}

// selectProfile implements origin profile selection (origins spec Section 3):
// candidates are profiles with a `match` object every present field of which is
// satisfied; a `space_id` match wins outright, then the greatest matched-field
// count, then document order.
func (c *compiledOrigins) selectProfile(origin *OriginContext) *compiledOriginProfile {
	if c == nil || origin == nil {
		return nil
	}
	bestCount := -1
	var best *compiledOriginProfile
	for index := range c.profiles {
		profile := &c.profiles[index]
		// A profile without a `match` field is never a candidate (D12).
		if profile.match == nil {
			continue
		}
		matchedFields, ok := matchOrigin(profile.match, origin)
		if !ok {
			continue
		}
		if profile.match.SpaceID != "" {
			return profile
		}
		if matchedFields > bestCount {
			bestCount, best = matchedFields, profile
		}
	}
	return best
}

// ---------------------------------------------------------------------------
// CompiledPolicy
// ---------------------------------------------------------------------------

// CompiledPolicy is a resolved HushSpec document with every matcher it needs
// already built. Evaluating through it is the same evaluation the free
// functions run -- same decisions, same traces, same receipts -- with the
// per-action pattern compilation hoisted out.
//
// Build one with [CompilePolicy] and share it: it is immutable and safe for
// concurrent use. The source document is retained for receipts and hashing and
// must not be mutated after compilation.
type CompiledPolicy struct {
	spec *HushSpec

	gates [blockCount]blockGate

	forbiddenPaths *compiledForbiddenPaths
	pathAllowlist  *compiledPathAllowlist
	secretPatterns *compiledSecretPatterns
	patchIntegrity *compiledPatchIntegrity
	shellCommands  *compiledShellCommands
	toolAccess     *compiledToolAccess
	egress         *compiledEgress
	computerUse    *compiledComputerUse
	remoteDesktop  *RemoteDesktopChannelsRule
	inputInjection *InputInjectionRule
	browser        *compiledBrowserAutomation
	codeExecution  *CodeExecutionRule

	origins   *compiledOrigins
	posture   *PostureExtension
	detection *compiledDetection

	// compileErr is the first pattern that failed the regex profile, in
	// document order. Evaluation still denies on exactly that pattern with its
	// own rule path; this is what [CompilePolicy] reports.
	compileErr error

	hashOnce sync.Once
	hash     string
	hashErr  error
}

// CompileError is a policy pattern that does not compile under the HushSpec
// regex profile. It names the rule path of the offending pattern, so a fail-fast
// caller gets the same location the evaluator's deny would have reported.
type CompileError struct {
	// RulePath is the dotted path of the pattern, e.g.
	// "rules.secret_patterns.patterns.aws_key.pattern".
	RulePath string
	// Pattern is the offending pattern as written in the document.
	Pattern string
	// Err is the regex-profile rejection.
	Err error
}

func (e *CompileError) Error() string {
	return fmt.Sprintf("%s: %v", e.RulePath, e.Err)
}

func (e *CompileError) Unwrap() error { return e.Err }

// CompilePolicy compiles a resolved HushSpec document once, so repeated
// evaluations do no pattern compilation at all.
//
// It is fail-closed: any pattern outside the HushSpec regex profile is a
// [CompileError] rather than a policy that denies later, since a pattern the
// engine cannot evaluate is a policy the author cannot rely on. Path globs and
// host patterns are not regexes and are never an error -- an uncompilable one
// matches nothing, exactly as it does during evaluation.
//
// The returned policy is safe for concurrent use and keeps a reference to spec,
// which must not be mutated afterwards.
func CompilePolicy(spec *HushSpec) (*CompiledPolicy, error) {
	if spec == nil {
		return nil, errors.New("cannot compile a nil HushSpec document")
	}
	policy := compilePolicy(spec)
	if policy.compileErr != nil {
		return nil, policy.compileErr
	}
	return policy, nil
}

// Spec is the resolved document this policy was compiled from.
func (p *CompiledPolicy) Spec() *HushSpec {
	if p == nil {
		return nil
	}
	return p.spec
}

// ContentHash is the content hash of the source document, computed once and
// cached (canonical spec section 5). Receipts built from this policy reuse it
// instead of re-canonicalizing the document per action.
func (p *CompiledPolicy) ContentHash() (string, error) {
	if p == nil {
		return "", errors.New("cannot hash a nil compiled policy")
	}
	p.hashOnce.Do(func() {
		if p.spec == nil {
			p.hashErr = errors.New("cannot hash a nil HushSpec document")
			return
		}
		p.hash, p.hashErr = ContentHash(p.spec)
	})
	return p.hash, p.hashErr
}

// compilePolicy compiles without failing: a pattern outside the regex profile
// is recorded on the entry that owns it (so the evaluator denies with the same
// rule path and reason it always did) and remembered in compileErr for
// [CompilePolicy]. A nil spec compiles to an empty policy.
func compilePolicy(spec *HushSpec) *CompiledPolicy {
	policy := &CompiledPolicy{spec: spec}
	if spec == nil {
		return policy
	}

	if rules := spec.Rules; rules != nil {
		policy.compileRules(rules)
	}

	if extensions := spec.Extensions; extensions != nil {
		policy.posture = extensions.Posture
		if origins := extensions.Origins; origins != nil {
			policy.origins = compileOrigins(origins)
		}
		if detection := extensions.Detection; detection != nil {
			policy.detection = compileDetection(detection)
		}
	}

	return policy
}

func (p *CompiledPolicy) compileRules(rules *Rules) {
	if rule := rules.ForbiddenPaths; rule != nil {
		p.gates[blockForbiddenPaths] = blockGate{present: true, enabled: rule.Enabled, when: rule.When}
		p.forbiddenPaths = &compiledForbiddenPaths{
			patterns:   compileGlobSet(rule.Patterns),
			exceptions: compileGlobSet(rule.Exceptions),
		}
	}

	if rule := rules.PathAllowlist; rule != nil {
		p.gates[blockPathAllowlist] = blockGate{present: true, enabled: rule.Enabled, when: rule.When}
		compiled := &compiledPathAllowlist{
			read:  compileGlobSet(rule.Read),
			write: compileGlobSet(rule.Write),
		}
		if len(rule.Patch) > 0 {
			compiled.patch = compileGlobSet(rule.Patch)
		} else {
			compiled.patch = compiled.write
		}
		p.pathAllowlist = compiled
	}

	if rule := rules.SecretPatterns; rule != nil {
		p.gates[blockSecretPatterns] = blockGate{present: true, enabled: rule.Enabled, when: rule.When}
		compiled := &compiledSecretPatterns{
			skipPaths: compileGlobSet(rule.SkipPaths),
			patterns:  make([]compiledSecretPattern, len(rule.Patterns)),
		}
		for index := range rule.Patterns {
			pattern := &rule.Patterns[index]
			entry := compiledSecretPattern{
				severity:    pattern.Severity,
				rank:        severityRank(pattern.Severity),
				errRule:     fmt.Sprintf("rules.secret_patterns.patterns.%s.pattern", pattern.Name),
				matchRule:   fmt.Sprintf("rules.secret_patterns.patterns.%s", pattern.Name),
				matchReason: fmt.Sprintf("content matched secret pattern '%s'", pattern.Name),
			}
			re, err := CompileProfileRegex(pattern.Pattern)
			if err != nil {
				entry.err = err
				entry.errReason = fmt.Sprintf("secret pattern '%s' is invalid: %v", pattern.Name, err)
				p.recordCompileError(entry.errRule, pattern.Pattern, err)
			} else {
				entry.re = re
			}
			compiled.patterns[index] = entry
		}
		p.secretPatterns = compiled
	}

	if rule := rules.PatchIntegrity; rule != nil {
		p.gates[blockPatchIntegrity] = blockGate{present: true, enabled: rule.Enabled, when: rule.When}
		p.patchIntegrity = &compiledPatchIntegrity{
			rule: rule,
			forbiddenPatterns: p.compilePatternList(
				rule.ForbiddenPatterns,
				"rules.patch_integrity.forbidden_patterns[%d]",
				"patch forbidden pattern is invalid: %v",
				"patch content matched a forbidden pattern",
			),
		}
	}

	if rule := rules.ShellCommands; rule != nil {
		p.gates[blockShellCommands] = blockGate{present: true, enabled: rule.Enabled, when: rule.When}
		p.shellCommands = &compiledShellCommands{
			forbiddenPatterns: p.compilePatternList(
				rule.ForbiddenPatterns,
				"rules.shell_commands.forbidden_patterns[%d]",
				"shell forbidden pattern is invalid: %v",
				"shell command matched a forbidden pattern",
			),
		}
	}

	if rule := rules.ToolAccess; rule != nil {
		p.gates[blockToolAccess] = blockGate{present: true, enabled: rule.Enabled, when: rule.When}
		p.toolAccess = &compiledToolAccess{
			rule:                rule,
			allow:               normalizeToolNames(rule.Allow),
			block:               normalizeToolNames(rule.Block),
			requireConfirmation: normalizeToolNames(rule.RequireConfirmation),
		}
	}

	if rule := rules.Egress; rule != nil {
		p.gates[blockEgress] = blockGate{present: true, enabled: rule.Enabled, when: rule.When}
		p.egress = &compiledEgress{
			rule:  rule,
			allow: compileHostSet(rule.Allow),
			block: compileHostSet(rule.Block),
		}
	}

	if rule := rules.ComputerUse; rule != nil {
		p.gates[blockComputerUse] = blockGate{present: true, enabled: rule.Enabled, when: rule.When}
		mode := rule.Mode
		if mode == "" {
			mode = ComputerUseModeGuardrail
		}
		p.computerUse = &compiledComputerUse{rule: rule, mode: mode}
	}

	if rule := rules.RemoteDesktopChannels; rule != nil {
		p.gates[blockRemoteDesktopChannels] = blockGate{present: true, enabled: rule.Enabled, when: rule.When}
		p.remoteDesktop = rule
	}

	if rule := rules.InputInjection; rule != nil {
		p.gates[blockInputInjection] = blockGate{present: true, enabled: rule.Enabled, when: rule.When}
		p.inputInjection = rule
	}

	if rule := rules.BrowserAutomation; rule != nil {
		p.gates[blockBrowserAutomation] = blockGate{present: true, enabled: rule.Enabled, when: rule.When}
		p.browser = &compiledBrowserAutomation{
			rule:           rule,
			allowedDomains: compileHostSet(rule.AllowedDomains),
			blockedDomains: compileHostSet(rule.BlockedDomains),
			extraCredentialPatterns: p.compilePatternList(
				rule.ExtraCredentialPatterns,
				"rules.browser_automation.extra_credential_patterns[%d]",
				"credential pattern is invalid: %v",
				"",
			),
		}
		for index := range p.browser.extraCredentialPatterns {
			entry := &p.browser.extraCredentialPatterns[index]
			entry.matchRule = "rules.browser_automation.credential_detection"
			entry.matchReason = fmt.Sprintf("typed input matched extra_credential_patterns[%d]", index)
		}
	}

	if rule := rules.CodeExecution; rule != nil {
		p.gates[blockCodeExecution] = blockGate{present: true, enabled: rule.Enabled, when: rule.When}
		p.codeExecution = rule
	}
}

// compilePatternList compiles an indexed list of policy-authored regexes whose
// rule path is "<prefix>[index]".
func (p *CompiledPolicy) compilePatternList(
	patterns []string,
	ruleFormat, errFormat, matchReason string,
) []compiledPatternEntry {
	if len(patterns) == 0 {
		return nil
	}
	entries := make([]compiledPatternEntry, len(patterns))
	for index, pattern := range patterns {
		rulePath := fmt.Sprintf(ruleFormat, index)
		entries[index] = compilePatternEntry(pattern, rulePath, errFormat, rulePath, matchReason)
		if entries[index].err != nil {
			p.recordCompileError(rulePath, pattern, entries[index].err)
		}
	}
	return entries
}

func (p *CompiledPolicy) recordCompileError(rulePath, pattern string, err error) {
	if p.compileErr == nil {
		p.compileErr = &CompileError{RulePath: rulePath, Pattern: pattern, Err: err}
	}
}

// normalizeToolNames NFC-folds a tool-name list once, so matching is a plain
// string comparison (D3, core spec 3.7).
func normalizeToolNames(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := make([]string, len(names))
	for index, name := range names {
		out[index] = norm.NFC.String(name)
	}
	return out
}

func containsNormalizedName(names []string, normalized string) bool {
	for _, name := range names {
		if name == normalized {
			return true
		}
	}
	return false
}

func compileOrigins(origins *OriginsExtension) *compiledOrigins {
	compiled := &compiledOrigins{
		defaultBehavior: originDefaultBehavior(origins),
		profiles:        make([]compiledOriginProfile, len(origins.Profiles)),
	}
	for index := range origins.Profiles {
		profile := &origins.Profiles[index]
		entry := compiledOriginProfile{
			id:      profile.ID,
			match:   profile.Match,
			posture: profile.Posture,
		}
		if overlay := profile.ToolAccess; overlay != nil {
			entry.toolAccess = &compiledToolAccessOverlay{
				overlay:             overlay,
				prefix:              profileRulePrefix(profile.ID, "tool_access"),
				allow:               normalizeToolNames(overlay.Allow),
				block:               normalizeToolNames(overlay.Block),
				requireConfirmation: normalizeToolNames(overlay.RequireConfirmation),
			}
		}
		if overlay := profile.Egress; overlay != nil {
			entry.egress = &compiledEgressOverlay{
				overlay: overlay,
				prefix:  profileRulePrefix(profile.ID, "egress"),
				allow:   compileHostSet(overlay.Allow),
				block:   compileHostSet(overlay.Block),
			}
		}
		compiled.profiles[index] = entry
	}
	return compiled
}

// ---------------------------------------------------------------------------
// Evaluation entry points
// ---------------------------------------------------------------------------

// Evaluate runs the reference evaluator against the compiled policy.
//
// `when` conditions are evaluated against action.Context (an empty context and
// the engine clock when absent).
func (p *CompiledPolicy) Evaluate(action *EvaluationAction) EvaluationResult {
	return p.EvaluateTraced(action, nil, nil).Result
}

// EvaluateTraced is the full evaluation with the recorded rule trace (used by
// receipts and `h2h explain`). The explicit context replaces action.Context;
// out-of-band conditions keyed by rule-block name are ANDed with each block's
// own `when` (core spec 3.13).
func (p *CompiledPolicy) EvaluateTraced(
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
		policy:     p,
		action:     action,
		context:    effective,
		conditions: conditions,
		trace:      []RuleEvaluation{},
	}
	return evaluator.run()
}

// EvaluateWithContext evaluates with an explicit runtime context and an
// out-of-band map of conditions keyed by rule-block name. The explicit context
// replaces action.Context; out-of-band conditions are ANDed with each block's
// own in-document `when` (core spec 3.13). A block whose condition is false is
// inert for this evaluation.
func (p *CompiledPolicy) EvaluateWithContext(
	action *EvaluationAction,
	context *RuntimeContext,
	conditions map[string]*Condition,
) EvaluationResult {
	return p.EvaluateTraced(action, context, conditions).Result
}

// ---------------------------------------------------------------------------
// Compilation cache for the free functions
// ---------------------------------------------------------------------------

// compiledCacheLimit bounds the number of documents the free-function cache
// holds. Past it, evaluation still works -- it just compiles on the fly, as it
// did before there was a cache.
const compiledCacheLimit = 64

var (
	// compiledCache maps a *HushSpec to its compiled form, so back-to-back
	// free-function calls on one document compile once. Keying on the pointer
	// means the entry keeps the document alive, so an address is never reused
	// for a different document; it also means a document mutated after it was
	// evaluated keeps its old compilation. Resolved documents are treated as
	// immutable everywhere in this SDK; a caller that edits one should hold a
	// [CompiledPolicy] of its own instead.
	compiledCache      sync.Map
	compiledCacheCount atomic.Int64
)

// cachedCompile is the compiled form of spec for the free functions: cached
// when there is room, compiled on the fly otherwise. It never fails -- an
// invalid pattern denies during evaluation exactly as it always has.
func cachedCompile(spec *HushSpec) *CompiledPolicy {
	if spec == nil {
		return compilePolicy(nil)
	}
	if cached, ok := compiledCache.Load(spec); ok {
		return cached.(*CompiledPolicy)
	}
	compiled := compilePolicy(spec)
	if compiledCacheCount.Load() >= compiledCacheLimit {
		return compiled
	}
	if actual, loaded := compiledCache.LoadOrStore(spec, compiled); loaded {
		return actual.(*CompiledPolicy)
	}
	compiledCacheCount.Add(1)
	return compiled
}
