package hushspec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// WarnHandler decides whether a `warn` may proceed. Returning true records the
// action as `confirmed` (a human or a policy-aware confirmation channel
// approved it); returning false blocks it.
//
// A guard with no handler denies every warn: a warn nobody can confirm is a
// deny (core spec 6).
type WarnHandler func(result EvaluationResult, action *EvaluationAction) bool

// PolicyProviderRule is the `matched_rule` for a denial issued because an
// enforcement point's policy provider cannot serve a policy to evaluate
// against: it has not loaded one, it handed back a document that still
// declares `extends`, or it failed when asked (core spec 6.2).
//
// A [Guard] takes its policy from a provider that pushes each reload into
// [Guard.SwapPolicy], so a reload that fails leaves the policy already in
// force and the guard never reaches that state. The value is exported for
// readers of receipts an enforcement point of the other kind emitted.
//
// Distinct from [PolicyUnverifiedRule], which means the policy was obtained
// and rejected -- a receipt has to be able to say which.
const PolicyProviderRule = "__hushspec_policy_provider__"

// GuardRefusal is the verification failure a guard is holding a policy under.
//
// A guard in this state has the document -- [Guard.Resolution] reports its
// hash and chain -- but denies every action against it with
// [PolicyUnverifiedRule], because signing spec 6.5 requires an enforcement
// point that cannot verify its policy to refuse *and record the refusal*. A
// guard that simply failed to construct would emit nothing at all.
type GuardRefusal struct {
	Source string
	Status SignatureStatus
}

// PolicyProvider is where a runtime gets its policy from: a file, an object
// store, a control plane.
//
// Load must return a *resolved* policy -- the `extends` chain merged and
// whatever verification the deployment requires already done -- because that
// is what a [Guard] evaluates and what a receipt's `policy.content_hash`
// names. Source names the origin for diagnostics and log records.
//
// Implementations must be safe for concurrent use: a [PolicyWatcher] loads on
// its own goroutine while the guard evaluates on others.
type PolicyProvider interface {
	Load() (*Resolution, error)
	Source() string
}

// GuardPolicyLoader is a provider that can hand over a policy it loaded but
// could not verify, so a guard enters its refused state -- denying every
// action with a receipt (signing spec 6.5) -- instead of never existing.
type GuardPolicyLoader interface {
	PolicyProvider
	LoadForGuard() (*Resolution, *GuardRefusal, error)
}

// GuardOptions configures a [Guard].
//
// The zero value is a usable enforcing guard: enforce mode, no overrides, no
// receipts, warns denied.
type GuardOptions struct {
	// EnforcementMode is the guard-level mode. Empty means
	// [EnforcementModeEnforce].
	EnforcementMode EnforcementMode
	// RuleOverrides maps a rule-path prefix ("rules.egress",
	// "extensions.detection") to the mode that applies when the decision
	// matched under it. The longest matching prefix wins over EnforcementMode.
	RuleOverrides map[string]EnforcementMode
	// RequireSignature refuses to evaluate unless every non-`builtin:` hop of
	// the `extends` chain is pinned by digest or validly signed (signing spec
	// 6.5). Needs Keyring (or Verify.PublicKeyPEM) to have anything to verify
	// against.
	RequireSignature bool
	// Keyring is the set of trusted keys signatures are checked against.
	Keyring *Keyring
	// Verify carries the rest of the verifier inputs: the clock, the skew
	// tolerance and the last seen policy version.
	Verify VerifyOptions
	// SignatureLocator finds each hop's detached envelope. Nil means
	// [DefaultSignatureLocator].
	SignatureLocator SignatureLocator
	// Loader resolves `extends` references. Nil means `builtin:` from the
	// embedded rulesets and everything else from the filesystem.
	Loader ResolveLoader
	// Sink receives a [DecisionReceipt] per decision, and the
	// `policy_loaded` / `policy_swapped` records when it implements
	// [PolicyEventSink]. Nil means no receipts are built at all.
	Sink ReceiptSink
	// Observer is told about every decision and every policy load. Use
	// [ObservableEvaluator] for more than one.
	Observer EvaluationObserver
	// Actor is who actions are evaluated for (receipt spec 4.1).
	Actor *Actor
	// TimeSource is how much the receipt clock is to be trusted (receipt spec
	// 3.3). Empty means [TimeSourceSystem].
	TimeSource TimeSource
	// OnWarn decides whether a `warn` proceeds. Nil denies every warn.
	OnWarn WarnHandler
	// Audit says how much of each evaluation to record. Nil means
	// [DefaultAuditConfig].
	Audit *AuditConfig
	// Refusal marks the policy as one that did not verify: every action is
	// denied with an [UnverifiedPolicyReceipt]. [NewGuardFromFile] sets it;
	// callers that resolve for themselves can set it directly.
	Refusal *GuardRefusal
	// Clock fixes the receipt clock. Nil means time.Now.
	Clock func() time.Time
	// SDK names the engine in policy events. The zero value means [ThisSDK].
	SDK SdkInfo
}

// GuardDecision is what a guard decided about one action.
type GuardDecision struct {
	// Result is the policy's own decision.
	Result EvaluationResult
	// Receipt is the audit record, when the guard built one -- always for a
	// refused policy, and otherwise whenever a sink is configured.
	Receipt *DecisionReceipt
	// Enforced reports whether the decision was applied to the action. It is
	// false exactly when the effective mode was monitor and a warn or deny was
	// let through, recorded as `would_block`.
	Enforced bool
	// Enforcement is the disposition recorded in the receipt.
	Enforcement EnforcementSummary
}

// Allowed reports whether the action may proceed: an allow, a confirmed warn,
// or anything monitor mode let through.
func (d GuardDecision) Allowed() bool {
	switch d.Enforcement.Outcome {
	case EnforcementOutcomeAllowed, EnforcementOutcomeConfirmed, EnforcementOutcomeWouldBlock:
		return true
	default:
		return false
	}
}

// Guard is an enforcement point: a compiled policy, the enforcement mode it
// runs under, and the audit trail it writes.
//
// Safe for concurrent use. [Guard.SwapPolicy] replaces the policy in force
// without stopping in-flight evaluations, which see either the old policy or
// the new one, never a half-swapped mix.
type Guard struct {
	mu         sync.RWMutex
	resolution *Resolution
	compiled   *CompiledPolicy
	refusal    *GuardRefusal

	mode      EnforcementMode
	overrides map[string]EnforcementMode

	sink       ReceiptSink
	observer   EvaluationObserver
	actor      *Actor
	timeSource TimeSource
	onWarn     WarnHandler
	audit      AuditConfig
	clock      func() time.Time
	sdk        SdkInfo
	provider   PolicyProvider
	// requireSignature is [GuardOptions.RequireSignature], kept so that a
	// resolution adopted from elsewhere -- a provider's load, a hot swap --
	// is held to the same requirement as one the guard resolved itself.
	requireSignature bool
}

// NewGuard builds a guard around an already-resolved policy.
//
// resolution must be the output of the resolver (or
// [NewResolutionFromResolved]): a guard never holds a document that still
// declares `extends`, because evaluating one silently drops every rule block
// its base contributed.
func NewGuard(resolution *Resolution, options GuardOptions) (*Guard, error) {
	if resolution == nil || resolution.Spec == nil {
		return nil, errors.New("guard: a resolved policy is required")
	}
	if resolution.Spec.Extends != nil {
		return nil, fmt.Errorf(
			"guard: policy still declares 'extends: %s'; resolve it first",
			*resolution.Spec.Extends,
		)
	}

	mode := options.EnforcementMode
	if mode == "" {
		mode = EnforcementModeEnforce
	}
	audit := DefaultAuditConfig()
	if options.Audit != nil {
		audit = *options.Audit
	}
	// A sink only counts as observability when auditing is on: with
	// Enabled false no receipt is built, so the sink is handed nothing and
	// the shadow decision leaves no trace at all.
	observable := (options.Sink != nil && audit.Enabled) || options.Observer != nil
	overrides, err := validateEnforcement(mode, options.RuleOverrides, observable)
	if err != nil {
		return nil, err
	}

	compiled, err := CompilePolicy(resolution.Spec)
	if err != nil {
		return nil, fmt.Errorf("guard: policy does not compile: %w", err)
	}

	sdk := options.SDK
	if sdk.Name == "" && sdk.Version == "" {
		sdk = ThisSDK()
	}

	guard := &Guard{
		resolution: resolution,
		compiled:   compiled,
		refusal:    options.Refusal,
		mode:       mode,
		overrides:  overrides,
		sink:       options.Sink,
		observer:   options.Observer,
		actor:      options.Actor,
		timeSource: options.TimeSource,
		onWarn:     options.OnWarn,
		audit:      audit,
		clock:      options.Clock,
		sdk:        sdk,

		requireSignature: options.RequireSignature,
	}

	// A policy-in-effect record before any receipt evaluated under it (log
	// spec 6): a reader maps every receipt to the policy in force by walking
	// back to the nearest policy event.
	event := NewPolicyLoadedEvent(resolution, mode, sdk)
	if guard.refusal != nil {
		event.Policy = guard.unverifiedPolicySummary(resolution)
	}
	guard.emitPolicyEvent(&event)
	guard.notifyPolicyLoaded(resolution, "")
	return guard, nil
}

// NewGuardFromFile loads a policy from disk, resolves and verifies its
// `extends` chain, and guards with it.
//
// Under [GuardOptions.RequireSignature] a chain that does not verify does not
// fail construction: the guard is built in its refused state, denying every
// action with a receipt that records `policy.signature.verified: false` and the
// verifier's reason. Every other load failure -- a base that cannot be loaded,
// a chain that will not merge, a pattern that does not compile -- is an error,
// because there is no document to refuse against.
func NewGuardFromFile(path string, options GuardOptions) (*Guard, error) {
	resolution, refusal, err := resolveFileForGuard(path, options.resolveOptions(), options.Loader)
	if err != nil {
		return nil, err
	}
	if refusal != nil {
		options.Refusal = refusal
	}
	return NewGuard(resolution, options)
}

// NewGuardFromProvider loads a policy through a provider and guards with it.
//
// The guard adopts the provider's own resolution rather than resolving again:
// by the time a provider hands over a policy the chain is already merged and
// the source its signatures were checked against is gone. A provider that
// implements [GuardPolicyLoader] can also hand over a policy it refused, which
// puts the guard in its refused state instead of failing construction.
//
// Under [GuardOptions.RequireSignature] the adopted chain is held to the
// guard's own requirement: a resolution the provider produced without
// verifying every non-`builtin:` hop puts the guard in its refused state.
//
// Hot reload is wired separately, by pointing a [PolicyWatcher] or
// [PolicyPoller] at the same provider with this guard as its target.
func NewGuardFromProvider(provider PolicyProvider, options GuardOptions) (*Guard, error) {
	if provider == nil {
		return nil, errors.New("guard: a policy provider is required")
	}
	var (
		resolution *Resolution
		refusal    *GuardRefusal
		err        error
	)
	if loader, ok := provider.(GuardPolicyLoader); ok {
		resolution, refusal, err = loader.LoadForGuard()
	} else {
		resolution, err = provider.Load()
	}
	if err != nil {
		return nil, fmt.Errorf("guard: policy provider %s: %w", provider.Source(), err)
	}
	if refusal == nil {
		refusal = unprovenHop(resolution, options.RequireSignature)
	}
	if refusal != nil {
		options.Refusal = refusal
	}
	guard, err := NewGuard(resolution, options)
	if err != nil {
		return nil, err
	}
	guard.mu.Lock()
	guard.provider = provider
	guard.mu.Unlock()
	return guard, nil
}

// unprovenHop reports the first hop of an adopted chain that has not proved
// itself under [GuardOptions.RequireSignature], or nil when the chain is
// acceptable.
//
// A provider resolves against the source it loaded from -- which the guard
// cannot reach a second time -- so its resolution is adopted rather than
// rebuilt. It was built under the provider's options, though, not the guard's,
// so the requirement the guard was given is re-applied here: without it,
// RequireSignature would be dropped by handing the policy in pre-resolved,
// which is exactly the fail-open the requirement exists to prevent.
//
// `builtin:` hops are exempt, as they are during resolution: they are embedded
// in the SDK, not loaded from anywhere signable. Every other hop proves itself
// by a verified signature on its link. A hop proved by a digest pin cannot be
// re-checked from a resolution -- the chain records the hash each hop had, not
// the digest its child pinned it to -- so an adopted chain has to carry
// signatures.
func unprovenHop(resolution *Resolution, requireSignature bool) *GuardRefusal {
	if !requireSignature || resolution == nil {
		return nil
	}
	for _, link := range resolution.Chain {
		if strings.HasPrefix(link.Source, "builtin:") {
			continue
		}
		if link.Signature != nil && link.Signature.Verified {
			continue
		}
		status := SignatureStatus{Verified: false, Reason: ReasonMissingSignature}
		if link.Signature != nil {
			status = *link.Signature
		}
		return &GuardRefusal{Source: link.Source, Status: status}
	}
	return nil
}

// resolveFileForGuard resolves path under the given verification options, so a
// [FileProvider] refuses a policy exactly as a guard built straight from the
// file does.
//
// A chain that would not verify under RequireSignature is resolved a second
// time with the requirement lifted, purely to recover the evidence -- the
// chain, the hashes and the failing hop's status -- that the refused guard
// reports. The document is never treated as verified: the returned refusal is
// what makes every action deny.
func resolveFileForGuard(
	path string,
	resolveOptions ResolveOptions,
	loader ResolveLoader,
) (*Resolution, *GuardRefusal, error) {
	spec, source, err := loadSpecFile(path)
	if err != nil {
		return nil, nil, err
	}
	resolution, err := ResolveWithOptions(spec, source, loader, resolveOptions)
	if err == nil {
		return resolution, nil, nil
	}

	var required *SignatureRequiredError
	if !resolveOptions.RequireSignature || !errors.As(err, &required) {
		return nil, nil, err
	}
	resolveOptions.RequireSignature = false
	refused, refusedErr := ResolveWithOptions(spec, source, loader, resolveOptions)
	if refusedErr != nil {
		// Nothing to refuse against: report the original verification failure.
		return nil, nil, err
	}
	return refused, &GuardRefusal{Source: required.Source, Status: required.Status}, nil
}

func (o GuardOptions) resolveOptions() ResolveOptions {
	return ResolveOptions{
		RequireSignature: o.RequireSignature,
		Keyring:          o.Keyring,
		Verify:           o.Verify,
		SignatureLocator: o.SignatureLocator,
	}
}

// validateEnforcement checks the mode and the override keys, and refuses a
// configuration in which a monitored decision would be invisible.
//
// observable says whether a shadow decision is recorded anywhere: an observer,
// or a sink that auditing actually writes receipts to.
func validateEnforcement(
	mode EnforcementMode,
	overrides map[string]EnforcementMode,
	observable bool,
) (map[string]EnforcementMode, error) {
	if mode != EnforcementModeEnforce && mode != EnforcementModeMonitor {
		return nil, fmt.Errorf("guard: invalid enforcement mode: %q", string(mode))
	}
	monitorReachable := mode == EnforcementModeMonitor

	copied := make(map[string]EnforcementMode, len(overrides))
	for key, value := range overrides {
		if value != EnforcementModeEnforce && value != EnforcementModeMonitor {
			return nil, fmt.Errorf(
				"guard: invalid enforcement mode for override %q: %q", key, string(value))
		}
		if value == EnforcementModeMonitor {
			monitorReachable = true
		}
		switch {
		case strings.HasPrefix(key, "rules."):
			segment := firstPathSegment(key[len("rules."):])
			if _, ok := RuleKeys[segment]; !ok {
				return nil, fmt.Errorf(
					"guard: unknown rule in enforcement override %q: %q is not a core rule",
					key, segment)
			}
		case strings.HasPrefix(key, "extensions."):
			// Only the top extension segment (posture/origins/detection) is
			// checked: deeper segments are policy-defined and hot-swappable.
			segment := firstPathSegment(key[len("extensions."):])
			if _, ok := ExtensionKeys[segment]; !ok {
				return nil, fmt.Errorf(
					"guard: unknown extension in enforcement override %q: %q is not a core extension",
					key, segment)
			}
		default:
			return nil, fmt.Errorf(
				"guard: enforcement override keys must start with 'rules.' or 'extensions.': %q", key)
		}
		copied[key] = value
	}

	if monitorReachable && !observable {
		return nil, errors.New(
			"guard: monitor mode requires an observer or a receipt sink: " +
				"shadow decisions would be unobservable")
	}
	return copied, nil
}

// MatchesRulePathPrefix reports whether matchedRule is key or continues past it
// at a path-segment boundary: "rules.egress" matches "rules.egress.allow[0]"
// but never "rules.egress_extra".
func MatchesRulePathPrefix(matchedRule, key string) bool {
	if matchedRule == key {
		return true
	}
	return strings.HasPrefix(matchedRule, key+".") || strings.HasPrefix(matchedRule, key+"[")
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

// Resolution is the chain, hashes and signature outcome of the policy in
// force -- what a receipt's `policy` member is taken from.
func (g *Guard) Resolution() *Resolution {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.resolution
}

// Compiled is the compiled policy the guard evaluates through. Hold it to
// evaluate outside the guard (a benchmark, a batch) without recompiling.
func (g *Guard) Compiled() *CompiledPolicy {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.compiled
}

// Refused reports whether the guard is denying every action because its policy
// did not verify, and the signature status it will record.
func (g *Guard) Refused() (bool, SignatureStatus) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.refusal == nil {
		return false, SignatureStatus{}
	}
	return true, g.refusal.Status
}

// Provider is the policy provider the guard was built from, or nil. A
// [PolicyWatcher] or [PolicyPoller] is pointed at it to wire hot reload.
func (g *Guard) Provider() PolicyProvider {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.provider
}

// EnforcementMode is the guard-level mode, before per-rule overrides.
func (g *Guard) EnforcementMode() EnforcementMode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.mode
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

// Check evaluates an action, applies the enforcement mode, records the
// decision, and reports whether execution may proceed
// ([GuardDecision.Allowed]).
//
// The returned decision is always usable: a guard that cannot evaluate denies.
// A non-nil error reports a caller-side failure that prevented the evaluation
// -- a missing action, a cancelled context -- and the decision then denies. A
// sink that would not take the receipt is not one of them: it reaches the
// observers as a `sink.error` event and never the caller, because a full disk
// is no reason to let an action through, nor to stop one.
func (g *Guard) Check(ctx context.Context, action *EvaluationAction) (GuardDecision, error) {
	return g.decide(ctx, action, true)
}

// Evaluate evaluates an action and records it without gating: the decision
// reports what the policy said and what [Guard.Check] would have enforced, but
// no [WarnHandler] is consulted and nothing is blocked.
func (g *Guard) Evaluate(ctx context.Context, action *EvaluationAction) (GuardDecision, error) {
	return g.decide(ctx, action, false)
}

// guardState is a consistent snapshot of everything one evaluation needs, so
// a concurrent SwapPolicy cannot change the policy under an in-flight action.
type guardState struct {
	resolution *Resolution
	compiled   *CompiledPolicy
	refusal    *GuardRefusal
	mode       EnforcementMode
	overrides  map[string]EnforcementMode
	sink       ReceiptSink
	observer   EvaluationObserver
	onWarn     WarnHandler
	audit      AuditConfig
}

func (g *Guard) state() guardState {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return guardState{
		resolution: g.resolution,
		compiled:   g.compiled,
		refusal:    g.refusal,
		mode:       g.mode,
		overrides:  g.overrides,
		sink:       g.sink,
		observer:   g.observer,
		onWarn:     g.onWarn,
		audit:      g.audit,
	}
}

func (g *Guard) decide(
	ctx context.Context,
	action *EvaluationAction,
	gate bool,
) (GuardDecision, error) {
	if action == nil {
		return deniedDecision(EvaluationResult{
			Decision: DecisionDeny,
			Reason:   "no action supplied",
		}), errors.New("guard: an action is required")
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			// Fail closed: a caller that went away gets a deny, never a pass.
			return deniedDecision(EvaluationResult{
				Decision: DecisionDeny,
				Reason:   "evaluation context ended: " + err.Error(),
			}), err
		}
	}

	state := g.state()
	if state.refusal != nil {
		return g.refuse(state, action), nil
	}

	result, receipt, duration, err := g.runEvaluation(state, action)
	if err != nil {
		// A guard with a sink configured does not decide off the record, and
		// a policy with no content hash cannot be named in one: fail closed.
		return deniedDecision(EvaluationResult{
			Decision: DecisionDeny,
			Reason:   "the policy in force cannot be recorded: " + err.Error(),
		}), err
	}
	mode := effectiveMode(result, state.mode, state.overrides)
	enforcement := gateOutcome(result, mode, action, gate, state.onWarn)
	if receipt != nil {
		receipt.Enforcement = enforcement
	}

	decision := GuardDecision{
		Result:      result,
		Receipt:     receipt,
		Enforced:    enforcement.Outcome != EnforcementOutcomeWouldBlock,
		Enforcement: enforcement,
	}
	g.record(state, action, decision, duration)
	return decision, nil
}

// runEvaluation evaluates the action, building a receipt when a sink is
// configured. The receipt's own duration is preferred when the audit config
// recorded one, so the observer and the receipt report the same number.
func (g *Guard) runEvaluation(
	state guardState,
	action *EvaluationAction,
) (EvaluationResult, *DecisionReceipt, time.Duration, error) {
	if state.sink != nil {
		start := time.Now()
		receipt, err := state.compiled.EvaluateAudited(
			state.resolution, action, &state.audit, g.auditContext(nil))
		if err != nil {
			return EvaluationResult{}, nil, 0, err
		}
		duration := time.Since(start)
		if receipt.DurationUs != nil {
			duration = time.Duration(*receipt.DurationUs) * time.Microsecond
		}
		result := EvaluationResult{
			Decision:      receipt.Decision,
			MatchedRule:   receipt.MatchedRule,
			Reason:        receipt.Reason,
			OriginProfile: receipt.OriginProfile,
			Posture:       receipt.Posture,
		}
		return result, &receipt, duration, nil
	}
	start := time.Now()
	result := state.compiled.EvaluateWithDetection(action).Evaluation
	return result, nil, time.Since(start), nil
}

// refuse is the decision for a policy that did not verify: a deny under
// [PolicyUnverifiedRule] with the receipt signing spec 6.5 requires, whatever
// the enforcement mode says -- a guard that cannot verify its policy has
// nothing to monitor against, and letting monitor mode wave the action through
// would be exactly the fail-open the spec forbids.
func (g *Guard) refuse(state guardState, action *EvaluationAction) GuardDecision {
	reason := state.refusal.Status.Reason
	if reason == "" {
		reason = "unverified"
	}
	result := EvaluationResult{
		Decision:    DecisionDeny,
		MatchedRule: PolicyUnverifiedRule,
		Reason: fmt.Sprintf("policy signature verification failed for %s: %s",
			state.refusal.Source, reason),
	}
	enforcement := EnforcementSummary{
		Mode:    EnforcementModeEnforce,
		Outcome: EnforcementOutcomeBlocked,
	}
	receipt := UnverifiedPolicyReceipt(
		g.unverifiedPolicySummary(state.resolution),
		action,
		g.auditContext(&enforcement),
	)
	decision := GuardDecision{
		Result:      result,
		Receipt:     &receipt,
		Enforced:    true,
		Enforcement: enforcement,
	}
	// The record is the point of refusing rather than failing to construct:
	// an agent that tried to act under an unverified policy leaves evidence.
	g.record(state, action, decision, 0)
	return decision
}

func deniedDecision(result EvaluationResult) GuardDecision {
	return GuardDecision{
		Result:   result,
		Enforced: true,
		Enforcement: EnforcementSummary{
			Mode:    EnforcementModeEnforce,
			Outcome: EnforcementOutcomeBlocked,
		},
	}
}

// gateOutcome resolves what the enforcement point does with a decision.
func gateOutcome(
	result EvaluationResult,
	mode EnforcementMode,
	action *EvaluationAction,
	gate bool,
	onWarn WarnHandler,
) EnforcementSummary {
	if !gate {
		return ImpliedEnforcement(result.Decision, mode)
	}
	switch result.Decision {
	case DecisionAllow:
		return EnforcementSummary{Mode: mode, Outcome: EnforcementOutcomeAllowed}
	case DecisionWarn:
		switch {
		case mode == EnforcementModeMonitor:
			return EnforcementSummary{Mode: mode, Outcome: EnforcementOutcomeWouldBlock}
		case onWarn != nil && onWarn(result, action):
			return EnforcementSummary{Mode: mode, Outcome: EnforcementOutcomeConfirmed}
		default:
			// Fail closed: a warn nobody can confirm is a deny (core spec 6).
			return EnforcementSummary{Mode: mode, Outcome: EnforcementOutcomeBlocked}
		}
	default:
		if mode == EnforcementModeMonitor {
			return EnforcementSummary{Mode: mode, Outcome: EnforcementOutcomeWouldBlock}
		}
		return EnforcementSummary{Mode: mode, Outcome: EnforcementOutcomeBlocked}
	}
}

// effectiveMode resolves the mode for one decision: the longest matching rule
// override, else the guard's own mode. Panic and an unverified policy always
// enforce.
func effectiveMode(
	result EvaluationResult,
	mode EnforcementMode,
	overrides map[string]EnforcementMode,
) EnforcementMode {
	if IsPanicActive() || result.MatchedRule == PanicRule {
		return EnforcementModeEnforce
	}
	if result.MatchedRule == PolicyUnverifiedRule {
		return EnforcementModeEnforce
	}
	matched := result.MatchedRule
	if matched == "" {
		return mode
	}
	// The detection pipeline reports the bare literal `detection` rather than
	// a hierarchical path, so an override keyed `extensions.detection` would
	// otherwise never match. Normalize before prefix matching.
	if matched == "detection" {
		matched = "extensions.detection"
	}
	bestKey := ""
	bestMode := EnforcementMode("")
	for key, candidate := range overrides {
		if !MatchesRulePathPrefix(matched, key) {
			continue
		}
		if bestMode == "" || len(key) > len(bestKey) {
			bestKey, bestMode = key, candidate
		}
	}
	if bestMode != "" {
		return bestMode
	}
	return mode
}

// record sends the receipt to the sink and notifies the observer. Neither can
// change the decision: a sink failure goes to the observers as a [SinkError]
// and no further, and an observer failure is swallowed.
func (g *Guard) record(
	state guardState,
	action *EvaluationAction,
	decision GuardDecision,
	duration time.Duration,
) {
	var sinkErr error
	if state.sink != nil && decision.Receipt != nil {
		if err := state.sink.Send(decision.Receipt); err != nil {
			sinkErr = &SinkError{Sink: sinkName(state.sink), Err: err}
		}
	}
	if state.observer != nil {
		enforcement := decision.Enforcement
		observation := EvaluationObservation{
			Action:      action,
			Result:      decision.Result,
			Enforcement: &enforcement,
			Receipt:     decision.Receipt,
			Duration:    duration,
		}.redact()
		notifyObserver(state.observer, func(observer EvaluationObserver) {
			observer.OnEvaluation(observation)
		})
		if sinkErr != nil {
			notifyObserver(state.observer, func(observer EvaluationObserver) {
				observer.OnError(sinkErr)
			})
		}
	}
}

// notifyObserver calls an observer without letting it break enforcement.
func notifyObserver(observer EvaluationObserver, notify func(EvaluationObserver)) {
	defer func() { _ = recover() }()
	notify(observer)
}

func (g *Guard) auditContext(enforcement *EnforcementSummary) *AuditContext {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return &AuditContext{
		Actor:           g.actor,
		Enforcement:     enforcement,
		EnforcementMode: g.mode,
		TimeSource:      g.timeSource,
		Clock:           g.clock,
	}
}

// unverifiedPolicySummary is the policy identity for a refused load: the
// resolution the guard was handed, with the failing hop's outcome filled in
// when the resolver never got as far as recording the leaf's (signing spec
// 6.5, "recording policy.signature.verified: false with the reason").
func (g *Guard) unverifiedPolicySummary(resolution *Resolution) PolicySummary {
	summary := NewPolicySummary(resolution)
	g.mu.RLock()
	refusal := g.refusal
	g.mu.RUnlock()
	if summary.Signature == nil && refusal != nil {
		status := refusal.Status
		summary.Signature = &status
	}
	return summary
}

// ---------------------------------------------------------------------------
// Hot swap
// ---------------------------------------------------------------------------

// SwapPolicy replaces the policy in force.
//
// A resolution that is unusable -- absent, still extending, holding a pattern
// that does not compile, or carrying a hop that does not prove itself under
// [GuardOptions.RequireSignature] -- is rejected and the policy already in
// force stays: keeping a policy that was verified is strictly safer than
// replacing it with one that was not. This is also why a swap never enters the refused
// state; a caller that wants a refused policy builds a new guard with
// [GuardOptions.Refusal].
//
// On success it writes a `policy_swapped` record to the sink before any
// receipt evaluated under the new policy (log spec 6).
func (g *Guard) SwapPolicy(resolution *Resolution) error {
	if resolution == nil || resolution.Spec == nil {
		return errors.New("guard: a resolved policy is required")
	}
	if resolution.Spec.Extends != nil {
		return fmt.Errorf(
			"guard: policy still declares 'extends: %s'; resolve it first",
			*resolution.Spec.Extends,
		)
	}
	g.mu.RLock()
	requireSignature := g.requireSignature
	g.mu.RUnlock()
	if unproven := unprovenHop(resolution, requireSignature); unproven != nil {
		return &SignatureRequiredError{Source: unproven.Source, Status: unproven.Status}
	}
	compiled, err := CompilePolicy(resolution.Spec)
	if err != nil {
		return fmt.Errorf("guard: policy does not compile: %w", err)
	}

	g.mu.Lock()
	previous := ""
	if g.resolution != nil {
		previous = g.resolution.ContentHash
	}
	g.resolution = resolution
	g.compiled = compiled
	// A policy that replaces a refused one clears the refusal: the document
	// now in force is the one that was checked.
	g.refusal = nil
	mode, sdk := g.mode, g.sdk
	g.mu.Unlock()

	event := NewPolicySwappedEvent(resolution, mode, sdk, previous)
	g.emitPolicyEvent(&event)
	g.notifyPolicyLoaded(resolution, previous)
	return nil
}

// emitPolicyEvent records which policy is in force. A sink that cannot carry
// policy events is not an error, and a sink that fails must not stop the
// policy from taking effect: the failure goes to the observer.
func (g *Guard) emitPolicyEvent(event *PolicyEvent) {
	g.mu.RLock()
	sink, observer := g.sink, g.observer
	g.mu.RUnlock()
	if sink == nil {
		return
	}
	if _, err := RecordPolicyEvent(sink, event); err != nil && observer != nil {
		sinkErr := &SinkError{Sink: sinkName(sink), Err: err}
		notifyObserver(observer, func(o EvaluationObserver) {
			o.OnError(sinkErr)
		})
	}
}

func (g *Guard) notifyPolicyLoaded(resolution *Resolution, previousHash string) {
	g.mu.RLock()
	observer, mode := g.observer, g.mode
	g.mu.RUnlock()
	if observer == nil {
		return
	}
	load := PolicyLoadObservation{
		ContentHash:         resolution.ContentHash,
		PreviousContentHash: previousHash,
		EnforcementMode:     mode,
	}
	if resolution.Spec != nil {
		load.Name = resolution.Spec.Name
	}
	if len(resolution.Chain) > 0 {
		load.Source = resolution.Chain[len(resolution.Chain)-1].Source
	}
	notifyObserver(observer, func(o EvaluationObserver) { o.OnPolicyLoaded(load) })
}

// ReportError hands a failure the runtime absorbed -- a reload that would not
// verify, a provider that could not load -- to the guard's observer. The
// watcher and the poller use it so a failed reload is visible wherever
// decisions are.
func (g *Guard) ReportError(err error) {
	if err == nil {
		return
	}
	g.mu.RLock()
	observer := g.observer
	g.mu.RUnlock()
	if observer == nil {
		return
	}
	notifyObserver(observer, func(o EvaluationObserver) { o.OnError(err) })
}
