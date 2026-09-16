package hushspec

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Decision receipts, format 0.2 (spec/hushspec-receipt.md).
//
// A receipt is the unit of evidence: which resolved policy was in force (by
// canonical content hash), who acted, what was attempted (never the content
// itself), what the policy decided and why, which rule blocks and detectors
// actually ran, and what the enforcement point did with the decision.
//
// Receipts are built from a [Resolution] so that the policy identity,
// `extends_chain`, and signature outcome come from the load step and cost
// nothing per evaluation. The rule trace is the evaluator's own recording
// ([EvaluateTraced]); nothing here is reconstructed from the decision.

// ReceiptVersion is the receipt format this file writes and accepts.
const ReceiptVersion = "0.2"

// UnknownActionTypeBlock is the `rule_block` id a receipt uses for the
// unknown-action-type engine stage (receipt spec 4.3, item 5). The evaluator
// records that stage under `default` with the reserved
// [UnknownActionTypeRule]; the receipt schema's closed enum spells it out.
const UnknownActionTypeBlock = "unknown_action_type"

// OriginProfileBlock is the `rule_block` id a receipt uses for the origins
// engine stage. The evaluator records it under `origins`.
const OriginProfileBlock = "origin_profile"

// PolicyUnverifiedRule is the `matched_rule` of a receipt for an action
// refused because the policy's signature did not verify (receipt spec 4.5,
// signing spec 6.5).
const PolicyUnverifiedRule = "__hushspec_policy_unverified__"

// receiptTimeLayout renders RFC 3339 UTC with exactly three fractional
// digits; the Z suffix is appended (receipt spec 3.3).
const receiptTimeLayout = "2006-01-02T15:04:05.000"

// --------------------------------------------------------------------------
// Wire types
// --------------------------------------------------------------------------

// TimeSource says how much to trust a receipt's `timestamp` (receipt spec
// 3.3). Engines MUST NOT claim [TimeSourceTrusted] unless configured to; the
// default is [TimeSourceSystem].
type TimeSource string

const (
	// TimeSourceSystem is the local system clock, as read.
	TimeSourceSystem TimeSource = "system"
	// TimeSourceMonotonicAdjusted is a monotonic clock re-based on the system
	// clock once at startup; immune to clock steps during the run.
	TimeSourceMonotonicAdjusted TimeSource = "monotonic_adjusted"
	// TimeSourceTrusted is a time source the operator considers
	// authoritative. What qualifies is deployment policy.
	TimeSourceTrusted TimeSource = "trusted"
	// TimeSourceUnknown is an engine that cannot characterize its clock.
	TimeSourceUnknown TimeSource = "unknown"
)

// Actor is who the action was evaluated for (receipt spec 4.1). Every field
// is optional because runtimes differ in what identity is available; an
// enforcement point SHOULD populate every field it knows.
type Actor struct {
	AgentID   string `json:"agent_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Principal string `json:"principal,omitempty"`
	Runtime   string `json:"runtime,omitempty"`
}

// IsEmpty reports whether no field is set. Such an actor is omitted from a
// receipt rather than written as an empty object.
func (a *Actor) IsEmpty() bool {
	return a == nil ||
		(a.AgentID == "" && a.SessionID == "" && a.Principal == "" && a.Runtime == "")
}

// ReceiptChainLink is one link of `policy.extends_chain` (receipt spec 4.2):
// a document's source and its own content hash, canonicalized alone. It drops
// the per-hop signature a [ChainLink] carries, which the receipt schema does
// not define.
type ReceiptChainLink struct {
	Source      string `json:"source"`
	ContentHash string `json:"content_hash"`
}

// PolicySummary is the identity of the resolved policy a decision was
// evaluated against (receipt spec 4.2).
type PolicySummary struct {
	// Name is the policy's `name`, copied as written: a policy that declares
	// an empty name is summarized with one, and only a policy that declares no
	// name leaves this absent.
	Name *string `json:"name,omitempty"`
	// Version is the policy's `metadata.policy_version`, when present. An
	// integer, never a string -- a pointer so an explicit 0 survives.
	Version *int64 `json:"version,omitempty"`
	// SpecVersion is the policy's `hushspec` field.
	SpecVersion string `json:"spec_version"`
	// ContentHash is the canonical content hash of the resolved policy
	// ("sha256:" + 64 hex). It is the join key between receipts, signature
	// envelopes, and policy bundles.
	ContentHash string `json:"content_hash"`
	// ExtendsChain records the merged documents root first, leaf last, when
	// the policy had an `extends`. Absent otherwise.
	ExtendsChain []ReceiptChainLink `json:"extends_chain,omitempty"`
	// Signature is the outcome of signature verification at load time. Nil
	// when the runtime did not attempt verification.
	Signature *SignatureStatus `json:"signature,omitempty"`
}

// ActionSummary is the evaluated action, minus its content (receipt spec 4.4).
//
// ContentSize and ArgsSize are pointers because a present-but-zero size is
// meaningful -- an explicitly empty payload was supplied and scanned -- and
// must not be dropped by `omitempty`.
type ActionSummary struct {
	Type string `json:"type"`
	// Target is the target string as supplied, NOT normalized: an auditor
	// sees what the agent asked for.
	Target string `json:"target,omitempty"`
	// ContentHash is "sha256:" over the UTF-8 bytes of the content, when
	// content was supplied. Content itself never appears in a receipt.
	ContentHash string `json:"content_hash,omitempty"`
	ContentSize *int64 `json:"content_size,omitempty"`
	// ArgsSize is the serialized size of tool-call arguments when the runtime
	// measured it against `tool_access.max_args_size`.
	ArgsSize *int64 `json:"args_size,omitempty"`
	// Origin is the origin descriptor as supplied, compacted by
	// [CompactObject].
	//
	// A pointer for the same reason DetectionTrace is: a descriptor that was
	// supplied but compacted down to nothing is `{}`, which is a different
	// fact from a descriptor that was never supplied at all, and `omitempty`
	// drops an empty map as readily as a nil one.
	Origin *map[string]any `json:"origin,omitempty"`
	// Context is the runtime context as supplied, compacted by
	// [CompactObject].
	Context *map[string]any `json:"context,omitempty"`
}

// RuleOutcome is one rule block's own decision, before aggregation. Skip means
// the block was applicable but inert (absent, disabled, or a false `when`).
type RuleOutcome string

const (
	RuleOutcomeAllow RuleOutcome = "allow"
	RuleOutcomeWarn  RuleOutcome = "warn"
	RuleOutcomeDeny  RuleOutcome = "deny"
	RuleOutcomeSkip  RuleOutcome = "skip"
)

// RuleEvaluation is one entry of the evaluator's own recorded trace, appended
// as each block runs. [ReceiptRuleTraceEntry] maps it to the receipt spelling.
type RuleEvaluation struct {
	RuleBlock   string      `json:"rule_block"`
	Outcome     RuleOutcome `json:"outcome"`
	MatchedRule string      `json:"matched_rule,omitempty"`
	Reason      string      `json:"reason,omitempty"`
	Evaluated   bool        `json:"evaluated"`
}

// RuleTraceEntry is one rule block's or engine stage's contribution to a
// decision, recorded as it happened (receipt spec 4.3).
//
// It is the receipt spelling of a [RuleEvaluation]: `rule_block` comes from
// the schema's closed enum and the matched rule is called `rule_path`.
type RuleTraceEntry struct {
	RuleBlock string      `json:"rule_block"`
	RulePath  string      `json:"rule_path,omitempty"`
	Outcome   RuleOutcome `json:"outcome"`
	Evaluated bool        `json:"evaluated"`
	Reason    string      `json:"reason,omitempty"`
}

// EnforcementMode is the effective mode after per-rule overrides and panic
// resolution (panic always enforces).
type EnforcementMode string

const (
	EnforcementModeEnforce EnforcementMode = "enforce"
	EnforcementModeMonitor EnforcementMode = "monitor"
)

// EnforcementOutcome is what the enforcement point actually did.
type EnforcementOutcome string

const (
	// EnforcementOutcomeAllowed: the action proceeded on an allow.
	EnforcementOutcomeAllowed EnforcementOutcome = "allowed"
	// EnforcementOutcomeConfirmed: a warn was approved through a confirmation
	// channel.
	EnforcementOutcomeConfirmed EnforcementOutcome = "confirmed"
	// EnforcementOutcomeBlocked: execution was prevented.
	EnforcementOutcomeBlocked EnforcementOutcome = "blocked"
	// EnforcementOutcomeWouldBlock: monitor mode let a warn or deny proceed.
	EnforcementOutcomeWouldBlock EnforcementOutcome = "would_block"
)

// EnforcementSummary records how the runtime applied a decision (receipt spec
// 4.7). It is required in 0.2: a decision without a disposition is not
// evidence that a control operated.
type EnforcementSummary struct {
	Mode    EnforcementMode    `json:"mode"`
	Outcome EnforcementOutcome `json:"outcome"`
}

// ImpliedEnforcement is the disposition implied by a decision when there is no
// enforcement point to say otherwise: an allow proceeds; a warn with no
// confirmation channel is a deny (core spec 6); under monitor mode a warn or
// deny proceeds and is recorded as would_block.
func ImpliedEnforcement(decision Decision, mode EnforcementMode) EnforcementSummary {
	if mode == "" {
		mode = EnforcementModeEnforce
	}
	switch {
	case decision == DecisionAllow:
		return EnforcementSummary{Mode: mode, Outcome: EnforcementOutcomeAllowed}
	case mode == EnforcementModeMonitor:
		return EnforcementSummary{Mode: mode, Outcome: EnforcementOutcomeWouldBlock}
	default:
		return EnforcementSummary{Mode: mode, Outcome: EnforcementOutcomeBlocked}
	}
}

// DecisionReceipt is a format 0.2 decision receipt: the auditable record of
// one policy evaluation.
//
// DetectionTrace is a pointer to a slice because "the pipeline ran and no
// detector was enabled" (an empty array) and "the pipeline did not run"
// (absent) are different facts, and `omitempty` cannot tell an empty slice
// from a nil one.
type DecisionReceipt struct {
	ReceiptVersion string     `json:"receipt_version"`
	ReceiptID      string     `json:"receipt_id"`
	Timestamp      string     `json:"timestamp"`
	TimeSource     TimeSource `json:"time_source"`

	Actor  *Actor        `json:"actor,omitempty"`
	Policy PolicySummary `json:"policy"`
	Action ActionSummary `json:"action"`

	Decision    Decision `json:"decision"`
	MatchedRule string   `json:"matched_rule,omitempty"`
	Reason      string   `json:"reason,omitempty"`

	RuleTrace      []RuleTraceEntry      `json:"rule_trace"`
	DetectionTrace *[]DetectorEvaluation `json:"detection_trace,omitempty"`

	Enforcement EnforcementSummary `json:"enforcement"`

	OriginProfile string         `json:"origin_profile,omitempty"`
	Posture       *PostureResult `json:"posture,omitempty"`
	DurationUs    *int64         `json:"duration_us,omitempty"`
}

// ParseReceipt reads a receipt, rejecting unknown fields, any version other
// than the one this SDK implements (receipt spec 3.1), and anything the 0.2
// schema's enums, patterns and required members refuse
// ([DecisionReceipt.Validate]).
//
// Accepting exactly what the schema accepts is conformance item 4 of receipt
// spec section 2: every vector under fixtures/receipts/valid parses and every
// one under fixtures/receipts/invalid does not.
func ParseReceipt(data []byte) (*DecisionReceipt, error) {
	var receipt DecisionReceipt
	if err := strictUnmarshalJSON(data, &receipt); err != nil {
		return nil, fmt.Errorf("receipt is not a well-formed 0.2 document: %w", err)
	}
	if receipt.ReceiptVersion != ReceiptVersion {
		return nil, fmt.Errorf(
			"unsupported receipt_version %q, expected %q", receipt.ReceiptVersion, ReceiptVersion)
	}
	if err := receipt.Validate(); err != nil {
		return nil, err
	}
	return &receipt, nil
}

// CanonicalJSON is the receipt's canonical form: RFC 8785 over the receipt
// object with no projection step (receipt spec 6). Receipts have no schema
// defaults to materialize and no resolution fields to strip, so every optional
// field is simply present or absent.
func (r *DecisionReceipt) CanonicalJSON() (string, error) {
	return canonicalJSONOf(r)
}

// ReceiptHash is "sha256:" over the canonical form (receipt spec 6): the value
// a log links and a receipt signature covers.
//
// Because the hash covers every field, an engine MUST NOT mutate a receipt
// after computing it.
func (r *DecisionReceipt) ReceiptHash() (string, error) {
	canonical, err := r.CanonicalJSON()
	if err != nil {
		return "", err
	}
	return DigestOf(canonical), nil
}

// canonicalJSONOf renders any JSON-serializable value in RFC 8785 canonical
// form. No projection step applies: receipts, log entries and envelopes carry
// no schema defaults.
func canonicalJSONOf(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("cannot serialize for canonicalization: %w", err)
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return "", fmt.Errorf("cannot re-read for canonicalization: %w", err)
	}
	return canonicalJSONValue(decoded)
}

// DigestOf is the content hash of a string: "sha256:" and the lowercase hex
// SHA-256 of its UTF-8 bytes (canonical spec 5).
func DigestOf(text string) string {
	sum := sha256.Sum256([]byte(text))
	return contentHashPrefix + hex.EncodeToString(sum[:])
}

// FormatTimestamp renders an instant the way receipts, log entries and
// signature envelopes spell it: RFC 3339 UTC, exactly millisecond precision,
// Z suffix. Sub-millisecond digits are truncated, never rounded, so a
// timestamp never lands in the future by a rounding artifact.
func FormatTimestamp(instant time.Time) string {
	return instant.UTC().Format(receiptTimeLayout) + "Z"
}

// CompactObject serializes a supplied descriptor "verbatim" (receipt spec 4.4)
// in the one form every typed model can reproduce: its JSON object with
// top-level members that are absent, null, {} or [] removed.
//
// Typed models differ in which empty members they materialize; the document
// the caller supplied did not have them.
func CompactObject(value any) (map[string]any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("cannot serialize the descriptor: %w", err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, fmt.Errorf("the descriptor is not a JSON object: %w", err)
	}
	for key, member := range object {
		switch typed := member.(type) {
		case nil:
			delete(object, key)
		case map[string]any:
			if len(typed) == 0 {
				delete(object, key)
			}
		case []any:
			if len(typed) == 0 {
				delete(object, key)
			}
		}
	}
	return object, nil
}

// --------------------------------------------------------------------------
// Building receipts
// --------------------------------------------------------------------------

// AuditConfig says what to record. Enabled false skips timing and the trace;
// the decision and the policy identity are always correct, because identity
// comes from the [Resolution] and costs nothing.
type AuditConfig struct {
	Enabled          bool
	IncludeRuleTrace bool
	// RecordDuration records `duration_us`. Off for conformance vectors,
	// whose bytes must not depend on the machine that produced them.
	RecordDuration bool
}

// DefaultAuditConfig returns an AuditConfig with every feature enabled.
func DefaultAuditConfig() AuditConfig {
	return AuditConfig{Enabled: true, IncludeRuleTrace: true, RecordDuration: true}
}

// AuditContext is everything about an evaluation that is not the policy or the
// action: who is acting, what the enforcement point does, and the clock.
//
// Clock and ReceiptID exist so tests and conformance vectors can be
// deterministic; production callers leave them nil/empty.
type AuditContext struct {
	Actor *Actor
	// Enforcement is the enforcement point's disposition. Nil records the
	// disposition implied by the decision under EnforcementMode.
	Enforcement     *EnforcementSummary
	EnforcementMode EnforcementMode
	TimeSource      TimeSource
	// Clock supplies the evaluation time. Nil means time.Now.
	Clock func() time.Time
	// ReceiptID fixes the receipt id. Empty means a fresh UUID v7.
	ReceiptID string
	// Context is an explicit runtime context; it replaces action.Context when
	// set (core spec 3.13).
	Context *RuntimeContext
	// Conditions are out-of-band conditions keyed by rule-block name, ANDed
	// with each block's own `when`.
	Conditions map[string]*Condition
}

func (ctx *AuditContext) now() time.Time {
	if ctx != nil && ctx.Clock != nil {
		return ctx.Clock()
	}
	return time.Now()
}

func (ctx *AuditContext) receiptID() string {
	if ctx != nil && ctx.ReceiptID != "" {
		return ctx.ReceiptID
	}
	return NewUUIDv7()
}

func (ctx *AuditContext) actor() *Actor {
	if ctx == nil || ctx.Actor.IsEmpty() {
		return nil
	}
	clone := *ctx.Actor
	return &clone
}

func (ctx *AuditContext) enforcement(decision Decision) EnforcementSummary {
	if ctx != nil && ctx.Enforcement != nil {
		return *ctx.Enforcement
	}
	mode := EnforcementModeEnforce
	if ctx != nil && ctx.EnforcementMode != "" {
		mode = ctx.EnforcementMode
	}
	return ImpliedEnforcement(decision, mode)
}

func (ctx *AuditContext) timeSource() TimeSource {
	if ctx == nil || ctx.TimeSource == "" {
		return TimeSourceSystem
	}
	return ctx.TimeSource
}

// EvaluateAudited evaluates an action against a resolved policy and records
// the receipt.
//
// It routes through the detection pipeline whenever the policy has a
// `detection:` extension, so the receipt's decision is the one an enforcement
// point acts on, and `detection_trace` is present whenever detection ran.
//
// config nil means [DefaultAuditConfig]; ctx nil means the zero context (no
// actor, enforce mode, the system clock, a fresh receipt id).
func EvaluateAudited(
	resolution *Resolution,
	action *EvaluationAction,
	config *AuditConfig,
	ctx *AuditContext,
) DecisionReceipt {
	var spec *HushSpec
	if resolution != nil {
		spec = resolution.Spec
	}
	return cachedCompile(spec).EvaluateAudited(resolution, action, config, ctx)
}

// EvaluateAudited is [EvaluateAudited] against a compiled policy.
//
// resolution supplies the policy identity the receipt records (content hash,
// signature, `extends` chain) and must wrap the document this policy was
// compiled from. A nil resolution records the compiled policy's own identity,
// with its cached content hash and no provenance -- what [EvaluateAuditedSpec]
// reports, without re-canonicalizing the document per action.
func (p *CompiledPolicy) EvaluateAudited(
	resolution *Resolution,
	action *EvaluationAction,
	config *AuditConfig,
	ctx *AuditContext,
) DecisionReceipt {
	effective := DefaultAuditConfig()
	if config != nil {
		effective = *config
	}

	var start time.Time
	timed := effective.Enabled && effective.RecordDuration
	if timed {
		start = time.Now()
	}

	var contextOverride *RuntimeContext
	var conditions map[string]*Condition
	if ctx != nil {
		contextOverride, conditions = ctx.Context, ctx.Conditions
	}
	detected := p.EvaluateWithDetectionTraced(action, contextOverride, conditions)

	var durationUs *int64
	if timed {
		micros := time.Since(start).Microseconds()
		durationUs = &micros
	}
	result := detected.Evaluation

	ruleTrace := []RuleTraceEntry{}
	if effective.Enabled && effective.IncludeRuleTrace {
		ruleTrace = buildRuleTrace(detected.Traced.Trace, result.OriginProfile)
	}

	policy := NewPolicySummary(resolution)
	if resolution == nil {
		policy = p.policySummary()
	}

	return DecisionReceipt{
		ReceiptVersion: ReceiptVersion,
		ReceiptID:      ctx.receiptID(),
		Timestamp:      FormatTimestamp(ctx.now()),
		TimeSource:     ctx.timeSource(),
		Actor:          ctx.actor(),
		Policy:         policy,
		Action:         NewActionSummary(action),
		Decision:       result.Decision,
		MatchedRule:    result.MatchedRule,
		Reason:         result.Reason,
		RuleTrace:      ruleTrace,
		DetectionTrace: detected.DetectorTrace,
		Enforcement:    ctx.enforcement(result.Decision),
		OriginProfile:  result.OriginProfile,
		Posture:        result.Posture,
		DurationUs:     durationUs,
	}
}

// EvaluateAuditedSpec is [EvaluateAudited] for a document that is already
// resolved and has no provenance to record. The content hash is computed on
// every call; hold a [Resolution] instead when evaluating repeatedly.
func EvaluateAuditedSpec(
	spec *HushSpec,
	action *EvaluationAction,
	config *AuditConfig,
	ctx *AuditContext,
) (DecisionReceipt, error) {
	resolution, err := NewResolutionFromResolved(spec, "")
	if err != nil {
		return DecisionReceipt{}, err
	}
	return EvaluateAudited(resolution, action, config, ctx), nil
}

// UnverifiedPolicyReceipt is the receipt an enforcement point that requires
// signatures emits when the policy did not verify (signing spec 6.5): a deny
// with an empty trace, `policy.signature.verified: false`, and the reason the
// verifier gave.
func UnverifiedPolicyReceipt(
	policy PolicySummary,
	action *EvaluationAction,
	ctx *AuditContext,
) DecisionReceipt {
	reason := "unverified"
	if policy.Signature != nil && policy.Signature.Reason != "" {
		reason = policy.Signature.Reason
	}
	return DecisionReceipt{
		ReceiptVersion: ReceiptVersion,
		ReceiptID:      ctx.receiptID(),
		Timestamp:      FormatTimestamp(ctx.now()),
		TimeSource:     ctx.timeSource(),
		Actor:          ctx.actor(),
		Policy:         policy,
		Action:         NewActionSummary(action),
		Decision:       DecisionDeny,
		MatchedRule:    PolicyUnverifiedRule,
		Reason:         "policy signature did not verify: " + reason,
		RuleTrace:      []RuleTraceEntry{},
		Enforcement:    ctx.enforcement(DecisionDeny),
	}
}

// policySummary is the policy identity of a compiled policy that was not
// resolved through the resolver: name, version and the cached content hash,
// with no chain and no signature.
func (p *CompiledPolicy) policySummary() PolicySummary {
	if p == nil || p.spec == nil {
		return PolicySummary{}
	}
	hash, err := p.ContentHash()
	if err != nil {
		hash = ""
	}
	summary := PolicySummary{
		Name:        p.spec.Name,
		SpecVersion: p.spec.HushSpecVersion,
		ContentHash: hash,
	}
	if p.spec.Metadata != nil && p.spec.Metadata.PolicyVersion != nil {
		version := int64(*p.spec.Metadata.PolicyVersion)
		summary.Version = &version
	}
	return summary
}

// NewPolicySummary is the policy identity a receipt carries, taken from the
// resolution (receipt spec 4.2).
func NewPolicySummary(resolution *Resolution) PolicySummary {
	if resolution == nil || resolution.Spec == nil {
		return PolicySummary{}
	}
	spec := resolution.Spec
	summary := PolicySummary{
		Name:        spec.Name,
		SpecVersion: spec.HushSpecVersion,
		ContentHash: resolution.ContentHash,
		Signature:   resolution.Signature,
	}
	if spec.Metadata != nil && spec.Metadata.PolicyVersion != nil {
		version := int64(*spec.Metadata.PolicyVersion)
		summary.Version = &version
	}
	if resolution.HadExtends() {
		chain := make([]ReceiptChainLink, 0, len(resolution.Chain))
		for _, link := range resolution.Chain {
			chain = append(chain, ReceiptChainLink{
				Source:      link.Source,
				ContentHash: link.ContentHash,
			})
		}
		summary.ExtendsChain = chain
	}
	return summary
}

// NewActionSummary records the action minus its content (receipt spec 4.4).
func NewActionSummary(action *EvaluationAction) ActionSummary {
	if action == nil {
		return ActionSummary{}
	}
	summary := ActionSummary{Type: action.Type, Target: action.Target}
	if action.Content != nil {
		size := int64(len(*action.Content))
		summary.ContentHash = DigestOf(*action.Content)
		summary.ContentSize = &size
	}
	if action.ArgsSize != nil {
		size := int64(*action.ArgsSize)
		summary.ArgsSize = &size
	}
	if action.Origin != nil {
		if origin, err := CompactObject(action.Origin); err == nil {
			summary.Origin = &origin
		}
	}
	if action.Context != nil {
		if context, err := CompactObject(action.Context); err == nil {
			summary.Context = &context
		}
	}
	return summary
}

// buildRuleTrace converts the evaluator's recorded trace to receipt entries
// and adds the origins stage when a profile was selected (receipt spec 4.3,
// item 5).
//
// The selected profile is a recorded fact of the same evaluation (the
// evaluator returns it alongside the decision); it goes first because the
// origins guard runs before the posture guard and every rule block.
func buildRuleTrace(trace []RuleEvaluation, originProfile string) []RuleTraceEntry {
	entries := make([]RuleTraceEntry, 0, len(trace)+1)
	hasOriginStage := false
	for _, recorded := range trace {
		entry := ReceiptRuleTraceEntry(recorded)
		if entry.RuleBlock == OriginProfileBlock {
			hasOriginStage = true
		}
		entries = append(entries, entry)
	}
	if originProfile != "" && !hasOriginStage {
		entries = append([]RuleTraceEntry{{
			RuleBlock: OriginProfileBlock,
			RulePath:  "extensions.origins.profiles." + originProfile,
			Outcome:   RuleOutcomeAllow,
			Evaluated: true,
			Reason:    "origin profile selected",
		}}, entries...)
	}
	return entries
}

// ReceiptRuleTraceEntry maps one recorded evaluator entry to the receipt
// spelling: the unknown-action stage is recorded under `default` with the
// reserved [UnknownActionTypeRule], and the origins guard under `origins`;
// receipts use the closed ids [UnknownActionTypeBlock] and
// [OriginProfileBlock] for those stages (receipt spec 4.3, item 5).
func ReceiptRuleTraceEntry(recorded RuleEvaluation) RuleTraceEntry {
	block := recorded.RuleBlock
	switch {
	case block == "default" && recorded.MatchedRule == UnknownActionTypeRule:
		block = UnknownActionTypeBlock
	case block == "origins":
		block = OriginProfileBlock
	}
	return RuleTraceEntry{
		RuleBlock: block,
		RulePath:  recorded.MatchedRule,
		Outcome:   recorded.Outcome,
		Evaluated: recorded.Evaluated,
		Reason:    recorded.Reason,
	}
}

// ComputePolicyHash returns the canonical content hash of a resolved policy:
// "sha256:" and the hex SHA-256 of its RFC 8785 canonical form
// (spec/hushspec-canonical.md section 5). It is the portable policy identity
// every SDK computes identically, and what a receipt's `policy.content_hash`
// carries.
//
// It returns "" for a document with no canonical form -- one that still
// declares `extends`, say. Callers that want the reason should use
// [ContentHash].
func ComputePolicyHash(spec *HushSpec) string {
	hash, err := ContentHash(spec)
	if err != nil {
		return ""
	}
	return hash
}

// --------------------------------------------------------------------------
// Receipt ids (UUID v7, RFC 9562)
// --------------------------------------------------------------------------

// NewUUIDv7 returns a fresh UUID version 7: the current Unix time in
// milliseconds in the high 48 bits, then 74 random bits. Version 7 embeds the
// timestamp, so receipts sort by creation time lexically and a log reader can
// detect reordering without parsing timestamps (receipt spec 3.2).
func NewUUIDv7() string {
	var uuid [16]byte
	writeUUIDv7Millis(&uuid, uint64(time.Now().UnixMilli()))
	if _, err := rand.Read(uuid[6:]); err != nil {
		// crypto/rand does not fail on any supported platform. Fall back to
		// the nanosecond clock rather than panic in an audit path: a weaker
		// id is still evidence, a crashed enforcement point is not.
		nanos := uint64(time.Now().UnixNano())
		for index := 6; index < 16; index++ {
			uuid[index] = byte(nanos >> (8 * uint(index%8)))
		}
	}
	uuid[6] = 0x70 | (uuid[6] & 0x0f) // version 7
	uuid[8] = 0x80 | (uuid[8] & 0x3f) // variant 10
	return formatUUID(uuid)
}

// DeterministicUUIDv7 returns a UUID v7 whose random bits come from seed
// instead of an RNG, so a conformance vector can name the receipt id it
// expects: rand_a (12 bits) is seed & 0xfff, rand_b (62 bits) is seed >> 12,
// with the version nibble 7 and the variant bits 10.
func DeterministicUUIDv7(unixMillis uint64, seed uint64) string {
	var uuid [16]byte
	writeUUIDv7Millis(&uuid, unixMillis)

	randA := uint16(seed & 0x0fff)
	uuid[6] = 0x70 | byte(randA>>8)
	uuid[7] = byte(randA & 0xff)

	randB := (seed >> 12) & 0x3fffffffffffffff
	var tail [8]byte
	for index := 0; index < 8; index++ {
		tail[index] = byte(randB >> (8 * uint(7-index)))
	}
	uuid[8] = 0x80 | (tail[0] & 0x3f)
	copy(uuid[9:], tail[1:])
	return formatUUID(uuid)
}

// writeUUIDv7Millis puts the low 48 bits of a millisecond timestamp into the
// high 48 bits of a UUID.
func writeUUIDv7Millis(uuid *[16]byte, unixMillis uint64) {
	ms := unixMillis & 0x0000ffffffffffff
	for index := 0; index < 6; index++ {
		uuid[index] = byte(ms >> (8 * uint(5-index)))
	}
}

func formatUUID(uuid [16]byte) string {
	text := hex.EncodeToString(uuid[:])
	var out strings.Builder
	out.Grow(36)
	out.WriteString(text[0:8])
	out.WriteByte('-')
	out.WriteString(text[8:12])
	out.WriteByte('-')
	out.WriteString(text[12:16])
	out.WriteByte('-')
	out.WriteString(text[16:20])
	out.WriteByte('-')
	out.WriteString(text[20:32])
	return out.String()
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
