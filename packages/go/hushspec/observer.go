package hushspec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Observer event type names. They are the wire spelling a [JSONLineObserver]
// and a [WebhookObserver] write, and match the other SDKs' observer streams.
const (
	ObserverEventEvaluation     = "evaluation.completed"
	ObserverEventPolicyLoaded   = "policy.loaded"
	ObserverEventPolicyReloaded = "policy.reloaded"
	ObserverEventPolicyFailed   = "policy.load_failed"
	ObserverEventSinkError      = "sink.error"
	ObserverEventError          = "error"
)

// PolicyLoadObservation is a policy taking effect, as an observer sees it.
//
// PreviousContentHash is set only for a swap: an observer distinguishes the
// first load of a policy from a hot reload by its presence, which is also what
// decides the event type a serializing observer writes.
type PolicyLoadObservation struct {
	// Name is the policy's own `name`, nil when it declares none.
	Name                *string
	ContentHash         string
	PreviousContentHash string
	Source              string
	EnforcementMode     EnforcementMode
}

// IsSwap reports whether this load replaced a policy already in force.
func (o PolicyLoadObservation) IsSwap() bool {
	return o.PreviousContentHash != ""
}

// EvaluationObserver is told what a [Guard] decided, without being able to
// change it.
//
// Every method is called on the evaluating goroutine, so an implementation
// that does real work (a network call, a disk write) must hand it off -- see
// [WebhookObserver]. An observer that panics never reaches the caller: the
// guard recovers and reports the panic through [EvaluationObserver.OnError] of
// the remaining observers.
type EvaluationObserver interface {
	// OnPolicyLoaded reports the policy now in force.
	OnPolicyLoaded(load PolicyLoadObservation)
	// OnEvaluation reports one completed evaluation. action has its content
	// stripped (receipts record only a hash and a size, and the observer
	// stream must not be the place raw payloads leak). receipt is nil when the
	// guard built none.
	OnEvaluation(action *EvaluationAction, result EvaluationResult, receipt *DecisionReceipt, duration time.Duration)
	// OnError reports a failure the guard absorbed: a reload that would not
	// verify, a sink that refused a receipt, a provider that could not load.
	OnError(err error)
}

// redactedAction is the action as an observer may see it: everything the
// receipt's action summary carries, and never the content itself.
func redactedAction(action *EvaluationAction) *EvaluationAction {
	if action == nil {
		return nil
	}
	clone := *action
	clone.Content = nil
	return &clone
}

// ---------------------------------------------------------------------------
// ObservableEvaluator
// ---------------------------------------------------------------------------

// ObservableEvaluator fans one guard's events out to several observers.
//
// It is itself an [EvaluationObserver], so a guard takes a fan-out and a
// single observer through the same option. Registration is safe for concurrent
// use, and one observer's panic never stops the others.
type ObservableEvaluator struct {
	mu        sync.RWMutex
	observers []EvaluationObserver
}

// NewObservableEvaluator fans out to observers.
func NewObservableEvaluator(observers ...EvaluationObserver) *ObservableEvaluator {
	e := &ObservableEvaluator{}
	for _, observer := range observers {
		e.AddObserver(observer)
	}
	return e
}

// AddObserver registers observer. A nil observer is ignored.
func (e *ObservableEvaluator) AddObserver(observer EvaluationObserver) {
	if observer == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.observers = append(e.observers, observer)
}

// RemoveObserver unregisters the first registration of observer.
func (e *ObservableEvaluator) RemoveObserver(observer EvaluationObserver) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, candidate := range e.observers {
		if candidate == observer {
			e.observers = append(e.observers[:i:i], e.observers[i+1:]...)
			return
		}
	}
}

// Observers is the registered set, in registration order.
func (e *ObservableEvaluator) Observers() []EvaluationObserver {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]EvaluationObserver(nil), e.observers...)
}

// Evaluate runs an evaluation against a compiled policy, times it, and
// notifies every observer. It builds no receipt: a caller that wants one
// evaluates through a [Guard] with a sink, or calls
// [CompiledPolicy.EvaluateAudited] directly.
func (e *ObservableEvaluator) Evaluate(policy *CompiledPolicy, action *EvaluationAction) EvaluationResult {
	start := time.Now()
	result := policy.EvaluateWithDetection(action).Evaluation
	e.OnEvaluation(redactedAction(action), result, nil, time.Since(start))
	return result
}

// OnPolicyLoaded forwards to every observer.
func (e *ObservableEvaluator) OnPolicyLoaded(load PolicyLoadObservation) {
	for _, observer := range e.Observers() {
		func() {
			defer recoverObserver(observer)
			observer.OnPolicyLoaded(load)
		}()
	}
}

// OnEvaluation forwards to every observer.
func (e *ObservableEvaluator) OnEvaluation(
	action *EvaluationAction,
	result EvaluationResult,
	receipt *DecisionReceipt,
	duration time.Duration,
) {
	for _, observer := range e.Observers() {
		func() {
			defer recoverObserver(observer)
			observer.OnEvaluation(action, result, receipt, duration)
		}()
	}
}

// OnError forwards to every observer.
func (e *ObservableEvaluator) OnError(err error) {
	for _, observer := range e.Observers() {
		func() {
			defer recoverObserver(observer)
			observer.OnError(err)
		}()
	}
}

// recoverObserver absorbs an observer's panic. An observer is a bystander:
// it must never decide whether an action proceeds, and a panic in one must not
// stop the rest of the fan-out.
func recoverObserver(observer EvaluationObserver) {
	recovered := recover()
	if recovered == nil {
		return
	}
	func() {
		// The report is best-effort too: an observer that panics in OnError as
		// well is simply dropped.
		defer func() { _ = recover() }()
		observer.OnError(fmt.Errorf("observer panicked: %v", recovered))
	}()
}

// ---------------------------------------------------------------------------
// Serializable observer events
// ---------------------------------------------------------------------------

// ObserverEvent is the JSON form of an observer notification, as written by
// [JSONLineObserver] and posted by [WebhookObserver].
//
// Action carries the action summary a receipt would record -- type, target,
// sizes -- and never the content payload.
type ObserverEvent struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`

	Action     *ActionSummary    `json:"action,omitempty"`
	Result     *EvaluationResult `json:"result,omitempty"`
	DurationUs *int64            `json:"duration_us,omitempty"`
	Receipt    *DecisionReceipt  `json:"receipt,omitempty"`

	PolicyName      *string         `json:"policy_name,omitempty"`
	ContentHash     string          `json:"content_hash,omitempty"`
	PreviousHash    string          `json:"previous_hash,omitempty"`
	Source          string          `json:"source,omitempty"`
	EnforcementMode EnforcementMode `json:"enforcement_mode,omitempty"`

	Error string `json:"error,omitempty"`
}

func policyLoadObserverEvent(load PolicyLoadObservation) ObserverEvent {
	eventType := ObserverEventPolicyLoaded
	if load.IsSwap() {
		eventType = ObserverEventPolicyReloaded
	}
	return ObserverEvent{
		Type:            eventType,
		Timestamp:       FormatTimestamp(time.Now()),
		PolicyName:      load.Name,
		ContentHash:     load.ContentHash,
		PreviousHash:    load.PreviousContentHash,
		Source:          load.Source,
		EnforcementMode: load.EnforcementMode,
	}
}

func evaluationObserverEvent(
	action *EvaluationAction,
	result EvaluationResult,
	receipt *DecisionReceipt,
	duration time.Duration,
) ObserverEvent {
	event := ObserverEvent{
		Type:      ObserverEventEvaluation,
		Timestamp: FormatTimestamp(time.Now()),
		Result:    &result,
		Receipt:   receipt,
	}
	micros := duration.Microseconds()
	event.DurationUs = &micros
	if action != nil {
		// NewActionSummary is itself the redaction: it records the content's
		// hash and size (receipt spec 4.4) and never the content. An action a
		// guard already stripped simply has neither.
		summary := NewActionSummary(action)
		event.Action = &summary
	} else if receipt != nil {
		summary := receipt.Action
		event.Action = &summary
	}
	return event
}

func errorObserverEvent(err error) ObserverEvent {
	message := ""
	if err != nil {
		message = err.Error()
	}
	event := ObserverEvent{
		Type:      ObserverEventError,
		Timestamp: FormatTimestamp(time.Now()),
		Error:     message,
	}
	// A policy that could not be loaded is its own event: it says which source
	// failed, and it is what an operator alerts on -- not the same thing as a
	// sink that would not take a receipt.
	var loadErr *PolicyLoadError
	if errors.As(err, &loadErr) {
		event.Type = ObserverEventPolicyFailed
		event.Source = loadErr.Source
		return event
	}
	var sinkErr *SinkError
	if errors.As(err, &sinkErr) {
		event.Type = ObserverEventSinkError
		event.Source = sinkErr.Sink
	}
	return event
}

// PolicyLoadError is a policy that could not be obtained or adopted: a source
// that would not read, a chain that would not resolve or verify, a document
// that would not compile. The policy already in force is unaffected.
type PolicyLoadError struct {
	Source string
	Err    error
}

func (e *PolicyLoadError) Error() string {
	return fmt.Sprintf("policy load from %s: %v", e.Source, e.Err)
}

func (e *PolicyLoadError) Unwrap() error { return e.Err }

// SinkError is a receipt sink that refused what it was handed: a receipt, or
// the policy-in-effect record for a load. The decision it belonged to stands
// and the policy still takes effect -- a full disk is not a reason to let an
// action through, nor to stop one -- so it is reported to the observers as a
// `sink.error` event and never returned to the caller.
type SinkError struct {
	// Sink names the sink that refused, by its type.
	Sink string
	Err  error
}

func (e *SinkError) Error() string {
	return fmt.Sprintf("sink %s: %v", e.Sink, e.Err)
}

func (e *SinkError) Unwrap() error { return e.Err }

// ---------------------------------------------------------------------------
// JSONLineObserver
// ---------------------------------------------------------------------------

// JSONLineObserver writes one JSON object per event, newline-terminated.
//
// Writes are serialized by a mutex, so concurrent evaluations produce whole
// lines rather than interleaved fragments. A write failure is dropped: an
// observer never fails an evaluation.
type JSONLineObserver struct {
	mu     sync.Mutex
	writer io.Writer
	// ErrorHandler, when set, is told about a write that failed. It is not
	// called OnError because that is the observer method itself.
	ErrorHandler func(error)
}

// NewJSONLineObserver writes events to w as JSON Lines.
func NewJSONLineObserver(w io.Writer) *JSONLineObserver {
	return &JSONLineObserver{writer: w}
}

func (o *JSONLineObserver) write(event ObserverEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		o.report(fmt.Errorf("observer: marshal %s: %w", event.Type, err))
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, err := o.writer.Write(append(data, '\n')); err != nil {
		o.report(fmt.Errorf("observer: write %s: %w", event.Type, err))
	}
}

func (o *JSONLineObserver) report(err error) {
	if o.ErrorHandler != nil {
		o.ErrorHandler(err)
	}
}

// OnPolicyLoaded writes a `policy.loaded` (or `policy.reloaded`) line.
func (o *JSONLineObserver) OnPolicyLoaded(load PolicyLoadObservation) {
	o.write(policyLoadObserverEvent(load))
}

// OnEvaluation writes an `evaluation.completed` line.
func (o *JSONLineObserver) OnEvaluation(
	action *EvaluationAction,
	result EvaluationResult,
	receipt *DecisionReceipt,
	duration time.Duration,
) {
	o.write(evaluationObserverEvent(action, result, receipt, duration))
}

// OnError writes an `error` line.
func (o *JSONLineObserver) OnError(err error) {
	o.write(errorObserverEvent(err))
}

// ---------------------------------------------------------------------------
// StderrObserver
// ---------------------------------------------------------------------------

// StderrObserver writes one human-readable line per event to stderr.
//
// DenyOnly limits evaluation lines to denials; policy and error events are
// always written, because a policy nobody can see taking effect is exactly
// what an operator needs to know about.
type StderrObserver struct {
	mu       sync.Mutex
	writer   io.Writer
	DenyOnly bool
}

// NewStderrObserver writes every event to stderr.
func NewStderrObserver() *StderrObserver {
	return &StderrObserver{writer: os.Stderr}
}

// NewDenyOnlyStderrObserver writes policy and error events plus denials.
func NewDenyOnlyStderrObserver() *StderrObserver {
	return &StderrObserver{writer: os.Stderr, DenyOnly: true}
}

// NewWriterObserver is [NewStderrObserver] against an arbitrary writer, for
// tests and for a runtime that has its own log stream.
func NewWriterObserver(w io.Writer) *StderrObserver {
	return &StderrObserver{writer: w}
}

func (o *StderrObserver) printf(format string, args ...any) {
	o.mu.Lock()
	defer o.mu.Unlock()
	target := o.writer
	if target == nil {
		target = os.Stderr
	}
	fmt.Fprintf(target, "[hushspec] "+format+"\n", args...)
}

// OnPolicyLoaded reports the policy now in force.
func (o *StderrObserver) OnPolicyLoaded(load PolicyLoadObservation) {
	name := "<unnamed>"
	if load.Name != nil {
		name = *load.Name
	}
	if load.IsSwap() {
		o.printf("policy swapped: %s %s (was %s)", name, load.ContentHash, load.PreviousContentHash)
		return
	}
	o.printf("policy loaded: %s %s", name, load.ContentHash)
}

// OnEvaluation reports one decision.
func (o *StderrObserver) OnEvaluation(
	action *EvaluationAction,
	result EvaluationResult,
	receipt *DecisionReceipt,
	duration time.Duration,
) {
	if o.DenyOnly && result.Decision != DecisionDeny {
		return
	}
	actionType, target := "", ""
	if action != nil {
		actionType, target = action.Type, action.Target
	} else if receipt != nil {
		actionType, target = receipt.Action.Type, receipt.Action.Target
	}
	o.printf(
		"%s %s %q -> %s (%s) in %dus",
		ObserverEventEvaluation, actionType, target, result.Decision,
		observedRule(result), duration.Microseconds(),
	)
}

// OnError reports a failure the guard absorbed.
func (o *StderrObserver) OnError(err error) {
	o.printf("error: %v", err)
}

func observedRule(result EvaluationResult) string {
	if result.MatchedRule == "" {
		return "no rule"
	}
	return result.MatchedRule
}

// ---------------------------------------------------------------------------
// MetricsCollector
// ---------------------------------------------------------------------------

// DefaultDurationBucketsUs is the latency histogram's upper bounds, in
// microseconds. It matches the exposition in docs (`hushspec_evaluate_duration_us`).
var DefaultDurationBucketsUs = []float64{10, 50, 100, 500, 1000, 5000}

// EvaluationMetricKey counts one decision for one action type.
type EvaluationMetricKey struct {
	Decision   Decision
	ActionType string
}

// RuleMetricKey counts one rule block's contribution to one decision.
type RuleMetricKey struct {
	RuleBlock string
	Decision  Decision
}

// DurationBucket is one cumulative histogram bucket. LE is the inclusive upper
// bound in microseconds; math.Inf(1) is the overflow bucket.
type DurationBucket struct {
	LE    float64
	Count uint64
}

// MetricsSnapshot is a consistent copy of a [MetricsCollector]'s counters.
type MetricsSnapshot struct {
	Evaluations     map[EvaluationMetricKey]uint64
	RuleMatches     map[RuleMetricKey]uint64
	PolicyLoads     map[string]uint64
	DurationBuckets []DurationBucket
	DurationSumUs   uint64
	DurationCount   uint64
	Errors          uint64
}

// MetricsCollector counts decisions, rule-block matches, policy loads and
// evaluation latency, and renders them in Prometheus exposition format.
//
// Safe for concurrent use.
type MetricsCollector struct {
	mu           sync.Mutex
	buckets      []float64
	bucketCounts []uint64
	sumUs        uint64
	count        uint64
	evaluations  map[EvaluationMetricKey]uint64
	ruleMatches  map[RuleMetricKey]uint64
	policyLoads  map[string]uint64
	errors       uint64
}

// NewMetricsCollector collects with [DefaultDurationBucketsUs].
func NewMetricsCollector() *MetricsCollector {
	return NewMetricsCollectorWithBuckets(DefaultDurationBucketsUs)
}

// NewMetricsCollectorWithBuckets collects with explicit histogram bounds, in
// microseconds. Bounds are sorted ascending; the +Inf bucket is implicit.
func NewMetricsCollectorWithBuckets(bucketsUs []float64) *MetricsCollector {
	bounds := append([]float64(nil), bucketsUs...)
	sort.Float64s(bounds)
	return &MetricsCollector{
		buckets:      bounds,
		bucketCounts: make([]uint64, len(bounds)),
		evaluations:  map[EvaluationMetricKey]uint64{},
		ruleMatches:  map[RuleMetricKey]uint64{},
		policyLoads:  map[string]uint64{},
	}
}

// OnPolicyLoaded counts a policy load.
func (m *MetricsCollector) OnPolicyLoaded(load PolicyLoadObservation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policyLoads["success"]++
}

// OnEvaluation counts one decision and records its latency.
func (m *MetricsCollector) OnEvaluation(
	action *EvaluationAction,
	result EvaluationResult,
	receipt *DecisionReceipt,
	duration time.Duration,
) {
	actionType := ""
	switch {
	case action != nil:
		actionType = action.Type
	case receipt != nil:
		actionType = receipt.Action.Type
	}

	micros := duration.Microseconds()
	if micros < 0 {
		micros = 0
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.evaluations[EvaluationMetricKey{Decision: result.Decision, ActionType: actionType}]++
	if block := RuleBlockOf(result.MatchedRule); block != "" {
		m.ruleMatches[RuleMetricKey{RuleBlock: block, Decision: result.Decision}]++
	}

	m.count++
	m.sumUs += uint64(micros)
	for i, bound := range m.buckets {
		if float64(micros) <= bound {
			m.bucketCounts[i]++
		}
	}
}

// OnError counts a failure the guard absorbed. A policy that would not load
// is counted as a failed load as well; a sink that refused a receipt is not,
// since the policy in force is unaffected by it.
func (m *MetricsCollector) OnError(err error) {
	var loadErr *PolicyLoadError
	loadFailed := errors.As(err, &loadErr)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors++
	if loadFailed {
		m.policyLoads["failure"]++
	}
}

// Snapshot copies every counter.
func (m *MetricsCollector) Snapshot() MetricsSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	snapshot := MetricsSnapshot{
		Evaluations:   make(map[EvaluationMetricKey]uint64, len(m.evaluations)),
		RuleMatches:   make(map[RuleMetricKey]uint64, len(m.ruleMatches)),
		PolicyLoads:   make(map[string]uint64, len(m.policyLoads)),
		DurationSumUs: m.sumUs,
		DurationCount: m.count,
		Errors:        m.errors,
	}
	for key, value := range m.evaluations {
		snapshot.Evaluations[key] = value
	}
	for key, value := range m.ruleMatches {
		snapshot.RuleMatches[key] = value
	}
	for key, value := range m.policyLoads {
		snapshot.PolicyLoads[key] = value
	}
	// Cumulative: a Prometheus histogram bucket counts every observation at or
	// below its bound, and +Inf counts them all.
	snapshot.DurationBuckets = make([]DurationBucket, 0, len(m.buckets)+1)
	for i, bound := range m.buckets {
		snapshot.DurationBuckets = append(snapshot.DurationBuckets, DurationBucket{
			LE: bound, Count: m.bucketCounts[i],
		})
	}
	snapshot.DurationBuckets = append(snapshot.DurationBuckets, DurationBucket{
		LE: math.Inf(1), Count: m.count,
	})
	return snapshot
}

// Reset zeroes every counter.
func (m *MetricsCollector) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bucketCounts = make([]uint64, len(m.buckets))
	m.sumUs, m.count, m.errors = 0, 0, 0
	m.evaluations = map[EvaluationMetricKey]uint64{}
	m.ruleMatches = map[RuleMetricKey]uint64{}
	m.policyLoads = map[string]uint64{}
}

// RenderPrometheus renders the counters in Prometheus text exposition format,
// with the metric names of the observability specification:
// `hushspec_evaluate_total`, `hushspec_evaluate_duration_us`,
// `hushspec_rule_match_total` and `hushspec_policy_load_total`.
//
// Series are sorted, so the output of two identical snapshots is byte-equal.
func (m *MetricsCollector) RenderPrometheus() string {
	snapshot := m.Snapshot()
	var b strings.Builder

	b.WriteString("# HELP hushspec_evaluate_total Total HushSpec evaluations\n")
	b.WriteString("# TYPE hushspec_evaluate_total counter\n")
	evaluationKeys := make([]EvaluationMetricKey, 0, len(snapshot.Evaluations))
	for key := range snapshot.Evaluations {
		evaluationKeys = append(evaluationKeys, key)
	}
	sort.Slice(evaluationKeys, func(i, j int) bool {
		if evaluationKeys[i].Decision != evaluationKeys[j].Decision {
			return evaluationKeys[i].Decision < evaluationKeys[j].Decision
		}
		return evaluationKeys[i].ActionType < evaluationKeys[j].ActionType
	})
	for _, key := range evaluationKeys {
		fmt.Fprintf(&b, "hushspec_evaluate_total{decision=%q,action_type=%q} %d\n",
			string(key.Decision), key.ActionType, snapshot.Evaluations[key])
	}

	b.WriteString("# HELP hushspec_evaluate_duration_us Evaluation duration in microseconds\n")
	b.WriteString("# TYPE hushspec_evaluate_duration_us histogram\n")
	for _, bucket := range snapshot.DurationBuckets {
		fmt.Fprintf(&b, "hushspec_evaluate_duration_us_bucket{le=%q} %d\n",
			formatBucketBound(bucket.LE), bucket.Count)
	}
	fmt.Fprintf(&b, "hushspec_evaluate_duration_us_sum %d\n", snapshot.DurationSumUs)
	fmt.Fprintf(&b, "hushspec_evaluate_duration_us_count %d\n", snapshot.DurationCount)

	b.WriteString("# HELP hushspec_rule_match_total Rule block match counts\n")
	b.WriteString("# TYPE hushspec_rule_match_total counter\n")
	ruleKeys := make([]RuleMetricKey, 0, len(snapshot.RuleMatches))
	for key := range snapshot.RuleMatches {
		ruleKeys = append(ruleKeys, key)
	}
	sort.Slice(ruleKeys, func(i, j int) bool {
		if ruleKeys[i].RuleBlock != ruleKeys[j].RuleBlock {
			return ruleKeys[i].RuleBlock < ruleKeys[j].RuleBlock
		}
		return ruleKeys[i].Decision < ruleKeys[j].Decision
	})
	for _, key := range ruleKeys {
		fmt.Fprintf(&b, "hushspec_rule_match_total{rule_block=%q,decision=%q} %d\n",
			key.RuleBlock, string(key.Decision), snapshot.RuleMatches[key])
	}

	b.WriteString("# HELP hushspec_policy_load_total Policy load operations\n")
	b.WriteString("# TYPE hushspec_policy_load_total counter\n")
	loadKeys := make([]string, 0, len(snapshot.PolicyLoads))
	for key := range snapshot.PolicyLoads {
		loadKeys = append(loadKeys, key)
	}
	sort.Strings(loadKeys)
	for _, key := range loadKeys {
		fmt.Fprintf(&b, "hushspec_policy_load_total{status=%q} %d\n", key, snapshot.PolicyLoads[key])
	}

	return b.String()
}

func formatBucketBound(bound float64) string {
	if math.IsInf(bound, 1) {
		return "+Inf"
	}
	return strconv.FormatFloat(bound, 'f', -1, 64)
}

// RuleBlockOf is the rule block a matched rule path belongs to:
// "rules.egress.allow[0]" is `egress`, "extensions.origins.profiles.x" is
// `origins`, and a reserved engine rule (`__hushspec_panic__`) is its own
// block. It reports "" for a decision that matched no rule.
func RuleBlockOf(matchedRule string) string {
	switch {
	case matchedRule == "":
		return ""
	case strings.HasPrefix(matchedRule, "__"):
		return strings.Trim(matchedRule, "_")
	case strings.HasPrefix(matchedRule, "rules."):
		return firstPathSegment(matchedRule[len("rules."):])
	case strings.HasPrefix(matchedRule, "extensions."):
		return firstPathSegment(matchedRule[len("extensions."):])
	default:
		return firstPathSegment(matchedRule)
	}
}

func firstPathSegment(path string) string {
	end := len(path)
	if index := strings.IndexAny(path, ".["); index >= 0 {
		end = index
	}
	return path[:end]
}

// ---------------------------------------------------------------------------
// WebhookObserver
// ---------------------------------------------------------------------------

// WebhookOptions configures a [WebhookObserver].
type WebhookOptions struct {
	// URL is the endpoint each event is POSTed to as JSON. Required.
	URL string
	// Headers are sent with every request (an API token, say).
	Headers map[string]string
	// MaxQueue bounds the in-flight event queue. Zero means 256. Past it,
	// events are dropped and counted rather than blocking an evaluation.
	MaxQueue int
	// Timeout bounds one POST. Zero means 5s.
	Timeout time.Duration
	// Client overrides the HTTP client (a test server, a proxy).
	Client *http.Client
	// OnError is told about a drop or a failed POST. Best-effort delivery is
	// the contract: nothing is retried.
	OnError func(error)
	// DenyOnly posts only denials, plus policy and error events.
	DenyOnly bool
}

// WebhookObserver POSTs each event to an HTTP endpoint from a background
// goroutine.
//
// Delivery is best-effort and never blocks an evaluation: a full queue drops
// the event, increments [WebhookObserver.Dropped] and reports through OnError.
// Close drains what is queued and stops the goroutine.
type WebhookObserver struct {
	url     string
	headers map[string]string
	client  *http.Client
	// timeout bounds one POST through a per-request context, so it applies to
	// a caller-supplied Client as well as to the default one.
	timeout  time.Duration
	onError  func(error)
	denyOnly bool

	queue    chan ObserverEvent
	done     chan struct{}
	stopOnce sync.Once
	finished chan struct{}
	dropped  atomic.Uint64
}

// NewWebhookObserver starts a webhook observer. It fails only on an empty URL.
func NewWebhookObserver(options WebhookOptions) (*WebhookObserver, error) {
	if strings.TrimSpace(options.URL) == "" {
		return nil, fmt.Errorf("webhook observer: URL is required")
	}
	maxQueue := options.MaxQueue
	if maxQueue <= 0 {
		maxQueue = 256
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	client := options.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	headers := make(map[string]string, len(options.Headers))
	for key, value := range options.Headers {
		headers[key] = value
	}

	observer := &WebhookObserver{
		url:      options.URL,
		headers:  headers,
		client:   client,
		timeout:  timeout,
		onError:  options.OnError,
		denyOnly: options.DenyOnly,
		queue:    make(chan ObserverEvent, maxQueue),
		done:     make(chan struct{}),
		finished: make(chan struct{}),
	}
	go observer.run()
	return observer, nil
}

func (o *WebhookObserver) run() {
	defer close(o.finished)
	for {
		select {
		case event := <-o.queue:
			o.post(event)
		case <-o.done:
			// Drain what is already queued, then stop.
			for {
				select {
				case event := <-o.queue:
					o.post(event)
				default:
					return
				}
			}
		}
	}
}

func (o *WebhookObserver) post(event ObserverEvent) {
	body, err := json.Marshal(event)
	if err != nil {
		o.report(fmt.Errorf("webhook observer: marshal %s: %w", event.Type, err))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, o.url, bytes.NewReader(body))
	if err != nil {
		o.report(fmt.Errorf("webhook observer: build request: %w", err))
		return
	}
	request.Header.Set("Content-Type", "application/json")
	for key, value := range o.headers {
		request.Header.Set(key, value)
	}
	response, err := o.client.Do(request)
	if err != nil {
		o.report(fmt.Errorf("webhook observer: post %s: %w", event.Type, err))
		return
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode >= 400 {
		o.report(fmt.Errorf("webhook observer: post %s: status %d", event.Type, response.StatusCode))
	}
}

func (o *WebhookObserver) enqueue(event ObserverEvent) {
	select {
	case <-o.done:
		o.drop(event)
		return
	default:
	}
	select {
	case o.queue <- event:
	default:
		o.drop(event)
	}
}

func (o *WebhookObserver) drop(event ObserverEvent) {
	o.dropped.Add(1)
	o.report(fmt.Errorf("webhook observer: queue full, dropped %s", event.Type))
}

func (o *WebhookObserver) report(err error) {
	if o.onError != nil {
		o.onError(err)
	}
}

// Dropped counts events the queue could not take.
func (o *WebhookObserver) Dropped() uint64 {
	return o.dropped.Load()
}

// OnPolicyLoaded queues a policy event.
func (o *WebhookObserver) OnPolicyLoaded(load PolicyLoadObservation) {
	o.enqueue(policyLoadObserverEvent(load))
}

// OnEvaluation queues an evaluation event.
func (o *WebhookObserver) OnEvaluation(
	action *EvaluationAction,
	result EvaluationResult,
	receipt *DecisionReceipt,
	duration time.Duration,
) {
	if o.denyOnly && result.Decision != DecisionDeny {
		return
	}
	o.enqueue(evaluationObserverEvent(action, result, receipt, duration))
}

// OnError queues an error event.
func (o *WebhookObserver) OnError(err error) {
	o.enqueue(errorObserverEvent(err))
}

// Close stops the background goroutine after delivering what is queued.
func (o *WebhookObserver) Close() error {
	o.stopOnce.Do(func() { close(o.done) })
	<-o.finished
	return nil
}
