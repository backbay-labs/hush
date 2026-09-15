// Command hushspec-diffeval evaluates a HushSpec differential case bundle
// and prints a JSON report for the cross-SDK differential runner.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	hushspec "github.com/backbay-labs/hush/packages/go/hushspec"
	"gopkg.in/yaml.v3"
)

type caseBundle struct {
	HushspecDiff string      `json:"hushspec_diff"`
	Seed         uint64      `json:"seed"`
	GeneratedBy  string      `json:"generated_by"`
	Audit        *auditSpec  `json:"audit"`
	Groups       []caseGroup `json:"groups"`
}

// auditSpec is the audited-evaluation input every SDK replays so the receipts
// they record for a case are byte-identical
// (fixtures/receipts/expected/README.md). A bundle written before the `audit`
// block existed replays defaultAudit, which is the same thing.
type auditSpec struct {
	Clock           string          `json:"clock"`
	TimeSource      string          `json:"time_source"`
	EnforcementMode string          `json:"enforcement_mode"`
	Actor           *hushspec.Actor `json:"actor"`
	IndexBase       uint64          `json:"index_base"`
	EmitReceipts    bool            `json:"emit_receipts"`
}

func defaultAudit() auditSpec {
	return auditSpec{
		Clock:           "2026-09-15T12:00:00.000Z",
		TimeSource:      "trusted",
		EnforcementMode: "enforce",
		Actor: &hushspec.Actor{
			AgentID:   "fixture-agent",
			SessionID: "fixture-session",
			Principal: "fixture@hushspec.dev",
			Runtime:   "hushspec-conformance/0.2",
		},
	}
}

// withDefaults fills in the members a bundle left out, member by member, which
// is what a bundle carrying only `{"emit_receipts": true}` relies on. An empty
// actor (`"actor": {}`) is a deliberate "no actor", which is why it is a
// pointer: only an absent one is replaced.
func (s auditSpec) withDefaults() auditSpec {
	fallback := defaultAudit()
	if s.Clock == "" {
		s.Clock = fallback.Clock
	}
	if s.TimeSource == "" {
		s.TimeSource = fallback.TimeSource
	}
	if s.EnforcementMode == "" {
		s.EnforcementMode = fallback.EnforcementMode
	}
	if s.Actor == nil {
		s.Actor = fallback.Actor
	}
	return s
}

type caseGroup struct {
	ID      string         `json:"id"`
	Policy  map[string]any `json:"policy"`
	Actions []caseAction   `json:"actions"`
}

type caseAction struct {
	ID     string          `json:"id"`
	Action json.RawMessage `json:"action"`
}

type verdict struct {
	Status  string            `json:"status"`
	Phase   string            `json:"phase,omitempty"`
	Message string            `json:"message,omitempty"`
	Result  *normalizedResult `json:"result,omitempty"`
}

type normalizedResult struct {
	Decision      string                    `json:"decision"`
	MatchedRule   string                    `json:"matched_rule,omitempty"`
	Reason        string                    `json:"reason,omitempty"`
	OriginProfile string                    `json:"origin_profile,omitempty"`
	Posture       *hushspec.PostureResult   `json:"posture,omitempty"`
	RuleTrace     []hushspec.RuleEvaluation `json:"rule_trace,omitempty"`
	// ReceiptHash is `sha256:` over the canonical form of the format 0.2
	// receipt this case recorded (receipt spec 6) -- the evidence an auditor
	// keeps, not just the answer the enforcement point acted on.
	ReceiptHash string `json:"receipt_hash,omitempty"`
	// Receipt is the whole receipt, reported only when the bundle asked for it
	// (audit.emit_receipts), so a hash mismatch can be rendered as the first
	// differing member instead of two opaque digests.
	Receipt *hushspec.DecisionReceipt `json:"receipt,omitempty"`
}

// groupReport carries the per-group facts that are not tied to a single
// action. ContentHash is the canonical content hash
// (spec/hushspec-canonical.md section 5) of the resolved policy this harness
// evaluated; ReceiptHash is the hash of this group's policy-identity receipt
// (see policyIdentityHash). Both are absent only when the policy was rejected
// and no spec was evaluated. The differential runner compares them across
// SDKs, so a missing hash for an accepted policy is a divergence.
type groupReport struct {
	ContentHash string `json:"content_hash,omitempty"`
	ReceiptHash string `json:"receipt_hash,omitempty"`
}

type report struct {
	SDK     string                 `json:"sdk"`
	Groups  map[string]groupReport `json:"groups"`
	Results map[string]verdict     `json:"results"`
}

// auditInputs is the bundle's audit block resolved into the typed values one
// audited evaluation needs, parsed once per bundle.
type auditInputs struct {
	spec        auditSpec
	clock       time.Time
	clockMillis uint64
	config      hushspec.AuditConfig
}

func newAuditInputs(spec auditSpec) (auditInputs, error) {
	clock, err := time.Parse(time.RFC3339, spec.Clock)
	if err != nil {
		return auditInputs{}, fmt.Errorf("unreadable audit.clock %q: %w", spec.Clock, err)
	}
	switch hushspec.TimeSource(spec.TimeSource) {
	case hushspec.TimeSourceSystem, hushspec.TimeSourceMonotonicAdjusted,
		hushspec.TimeSourceTrusted, hushspec.TimeSourceUnknown:
	default:
		return auditInputs{}, fmt.Errorf("unknown audit.time_source %q", spec.TimeSource)
	}
	switch hushspec.EnforcementMode(spec.EnforcementMode) {
	case hushspec.EnforcementModeEnforce, hushspec.EnforcementModeMonitor:
	default:
		return auditInputs{}, fmt.Errorf("unknown audit.enforcement_mode %q", spec.EnforcementMode)
	}
	return auditInputs{
		spec:        spec,
		clock:       clock.UTC(),
		clockMillis: uint64(clock.UnixMilli()),
		// Record the trace but never the duration: a receipt's bytes must not
		// depend on the machine that produced them.
		config: hushspec.AuditConfig{Enabled: true, IncludeRuleTrace: true, RecordDuration: false},
	}, nil
}

// context returns the audit context of the case at position in the bundle.
func (a auditInputs) context(position uint64) *hushspec.AuditContext {
	actor := *a.spec.Actor
	clock := a.clock
	return &hushspec.AuditContext{
		Actor:           &actor,
		EnforcementMode: hushspec.EnforcementMode(a.spec.EnforcementMode),
		TimeSource:      hushspec.TimeSource(a.spec.TimeSource),
		Clock:           func() time.Time { return clock },
		ReceiptID:       hushspec.DeterministicUUIDv7(a.clockMillis, a.spec.IndexBase+position),
	}
}

// policyIdentityHash is the group-level receipt_hash: a receipt carrying this
// policy's summary and nothing else that varies (fixed id, the bundle's clock,
// a reserved action, a deny with an empty trace). Hashing it through this SDK's
// own receipt canonicalizer isolates the policy identity a receipt records --
// name, version, spec_version, content_hash, extends_chain, signature -- so a
// disagreement there is reported independently of any one action.
func (a auditInputs) policyIdentityHash(spec *hushspec.HushSpec) (string, error) {
	resolution, err := hushspec.NewResolutionFromResolved(spec, "")
	if err != nil {
		return "", err
	}
	receipt := hushspec.DecisionReceipt{
		ReceiptVersion: hushspec.ReceiptVersion,
		ReceiptID:      "00000000-0000-7000-8000-000000000000",
		Timestamp:      hushspec.FormatTimestamp(a.clock),
		TimeSource:     hushspec.TimeSource(a.spec.TimeSource),
		Policy:         hushspec.NewPolicySummary(resolution),
		Action:         hushspec.ActionSummary{Type: "__hushspec_policy_identity__"},
		Decision:       hushspec.DecisionDeny,
		RuleTrace:      []hushspec.RuleTraceEntry{},
		Enforcement: hushspec.ImpliedEnforcement(
			hushspec.DecisionDeny,
			hushspec.EnforcementMode(a.spec.EnforcementMode),
		),
	}
	return receipt.ReceiptHash()
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: hushspec-diffeval <bundle.json>")
		os.Exit(2)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read %s: %v\n", os.Args[1], err)
		os.Exit(2)
	}

	var bundle caseBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse bundle: %v\n", err)
		os.Exit(2)
	}
	if bundle.HushspecDiff != "0.1.0" {
		fmt.Fprintf(os.Stderr, "unsupported hushspec_diff version: %s\n", bundle.HushspecDiff)
		os.Exit(2)
	}

	spec := defaultAudit()
	if bundle.Audit != nil {
		spec = bundle.Audit.withDefaults()
	}
	// Fail closed: audit inputs we cannot read have no reproducible receipts,
	// and falling back to "now" would make this harness disagree with every
	// other one while still looking like it answered.
	audit, err := newAuditInputs(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(2)
	}

	results := make(map[string]verdict)
	groups := make(map[string]groupReport)
	// Position of the next case in the bundle, counting every action of every
	// group in order (rejected policies included). index_base + position seeds
	// that case's receipt id in every SDK, so the counter advances even when
	// there is no receipt to record.
	position := uint64(0)
	for _, group := range bundle.Groups {
		spec, rejection := parsePolicy(group.Policy)
		entry := groupReport{}
		if rejection == nil {
			// The canonical content hash identifies the policy that was
			// actually enforced, so it is taken from the same resolved spec
			// the actions below are evaluated against.
			digest, err := hushspec.ContentHash(spec)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to compute content hash for %s: %v\n", group.ID, err)
				os.Exit(2)
			}
			entry.ContentHash = digest
			identity, err := audit.policyIdentityHash(spec)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to hash policy identity for %s: %v\n", group.ID, err)
				os.Exit(2)
			}
			entry.ReceiptHash = identity
		}
		groups[group.ID] = entry
		for _, action := range group.Actions {
			key := group.ID + "/" + action.ID
			caseIndex := position
			position++
			if rejection != nil {
				results[key] = *rejection
				continue
			}
			results[key] = evaluateCase(spec, action.Action, audit, caseIndex)
		}
	}

	out, err := json.Marshal(report{SDK: "go", Groups: groups, Results: results})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to serialize report: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(out))
}

// parsePolicy runs the pipeline every SDK in the differential run applies:
// parse, flatten the `extends` chain (the generator emits only `builtin:`
// references, which the default composite loader serves from the SDK's embedded
// rulesets), then validate.
func parsePolicy(policy map[string]any) (*hushspec.HushSpec, *verdict) {
	policyBytes, err := yaml.Marshal(policy)
	if err != nil {
		return nil, &verdict{Status: "error", Message: fmt.Sprintf("failed to re-encode policy: %v", err)}
	}
	spec, err := hushspec.Parse(string(policyBytes))
	if err != nil {
		return nil, &verdict{Status: "rejected", Phase: "parse", Message: err.Error()}
	}
	if spec.Extends != "" {
		resolved, err := hushspec.Resolve(spec, "", nil)
		if err != nil {
			return nil, &verdict{Status: "rejected", Phase: "resolve", Message: err.Error()}
		}
		spec = resolved
	}
	if result := hushspec.Validate(spec); !result.IsValid() {
		return nil, &verdict{Status: "rejected", Phase: "validate", Message: fmt.Sprintf("%v", result.Errors[0])}
	}
	return spec, nil
}

func evaluateCase(
	spec *hushspec.HushSpec,
	raw json.RawMessage,
	audit auditInputs,
	position uint64,
) verdict {
	var action hushspec.EvaluationAction
	if err := json.Unmarshal(raw, &action); err != nil {
		return verdict{Status: "error", Message: fmt.Sprintf("invalid action: %v", err)}
	}
	// The audited path is the one an enforcement point runs: it routes through
	// the detection pipeline and records the evidence, so the verdict reported
	// here is read back out of the receipt. The rule trace comes from an
	// explicit EvaluateTraced call over the same inputs; detection never re-runs
	// the rule blocks, so the two agree by construction.
	traced := hushspec.EvaluateTraced(spec, &action, nil, nil)
	receipt, err := hushspec.EvaluateAuditedSpec(spec, &action, &audit.config, audit.context(position))
	if err != nil {
		return verdict{Status: "error", Message: fmt.Sprintf("audited evaluation failed: %v", err)}
	}
	hash, err := receipt.ReceiptHash()
	if err != nil {
		return verdict{Status: "error", Message: fmt.Sprintf("receipt has no canonical form: %v", err)}
	}
	result := &normalizedResult{
		Decision:      string(receipt.Decision),
		MatchedRule:   receipt.MatchedRule,
		Reason:        receipt.Reason,
		OriginProfile: receipt.OriginProfile,
		Posture:       receipt.Posture,
		RuleTrace:     traced.Trace,
		ReceiptHash:   hash,
	}
	if audit.spec.EmitReceipts {
		result.Receipt = &receipt
	}
	return verdict{Status: "ok", Result: result}
}
