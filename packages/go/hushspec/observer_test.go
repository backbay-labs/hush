package hushspec

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingObserver captures observer callbacks.
type recordingObserver struct {
	mu      sync.Mutex
	loads   []PolicyLoadObservation
	results []EvaluationResult
	errs    []error
}

func (o *recordingObserver) OnPolicyLoaded(load PolicyLoadObservation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.loads = append(o.loads, load)
}

func (o *recordingObserver) OnEvaluation(
	action *EvaluationAction,
	result EvaluationResult,
	receipt *DecisionReceipt,
	duration time.Duration,
) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if action != nil && action.Content != nil {
		o.errs = append(o.errs, errors.New("observer saw raw action content"))
	}
	o.results = append(o.results, result)
}

func (o *recordingObserver) OnError(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.errs = append(o.errs, err)
}

func (o *recordingObserver) counts() (int, int, int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.loads), len(o.results), len(o.errs)
}

func guardSpec() *HushSpec {
	return &HushSpec{
		HushSpecVersion: "0.2.0",
		Name:            "guard-policy",
		Rules: &Rules{
			Egress: &EgressRule{
				Enabled: true,
				Allow:   []string{"api.github.com"},
				Block:   []string{"evil.example.com"},
				Default: DefaultActionBlock,
			},
			SecretPatterns: &SecretPatternsRule{
				Enabled: true,
				Patterns: []SecretPattern{
					{Name: "warn_token", Pattern: "WARNME", Severity: SeverityWarn},
				},
			},
		},
	}
}

func guardResolution(t *testing.T, spec *HushSpec) *Resolution {
	t.Helper()
	resolution, err := NewResolutionFromResolved(spec, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return resolution
}

func TestRuleBlockOf(t *testing.T) {
	cases := map[string]string{
		"":                                 "",
		"rules.egress.block[0]":            "egress",
		"rules.forbidden_paths.paths[2]":   "forbidden_paths",
		"extensions.origins.profiles.demo": "origins",
		"detection":                        "detection",
		"__hushspec_panic__":               "hushspec_panic",
	}
	for matched, want := range cases {
		if got := RuleBlockOf(matched); got != want {
			t.Fatalf("RuleBlockOf(%q) = %q, want %q", matched, got, want)
		}
	}
}

func TestMetricsCollectorCountsDecisions(t *testing.T) {
	metrics := NewMetricsCollector()
	metrics.OnPolicyLoaded(PolicyLoadObservation{Name: "p", ContentHash: "sha256:x"})
	metrics.OnEvaluation(
		&EvaluationAction{Type: "egress", Target: "evil.example.com"},
		EvaluationResult{Decision: DecisionDeny, MatchedRule: "rules.egress.block[0]"},
		nil, 40*time.Microsecond,
	)
	metrics.OnEvaluation(
		&EvaluationAction{Type: "egress", Target: "api.github.com"},
		EvaluationResult{Decision: DecisionAllow, MatchedRule: "rules.egress.allow[0]"},
		nil, 8*time.Microsecond,
	)
	metrics.OnEvaluation(
		&EvaluationAction{Type: "tool_call", Target: "slow"},
		EvaluationResult{Decision: DecisionAllow},
		nil, 90*time.Millisecond,
	)
	metrics.OnError(errors.New("sink down"))

	snapshot := metrics.Snapshot()
	if got := snapshot.Evaluations[EvaluationMetricKey{Decision: DecisionDeny, ActionType: "egress"}]; got != 1 {
		t.Fatalf("expected one egress deny, got %d", got)
	}
	if got := snapshot.RuleMatches[RuleMetricKey{RuleBlock: "egress", Decision: DecisionAllow}]; got != 1 {
		t.Fatalf("expected one egress allow match, got %d", got)
	}
	if snapshot.DurationCount != 3 {
		t.Fatalf("expected 3 timed evaluations, got %d", snapshot.DurationCount)
	}
	if snapshot.PolicyLoads["success"] != 1 || snapshot.PolicyLoads["failure"] != 1 {
		t.Fatalf("policy load counters are wrong: %+v", snapshot.PolicyLoads)
	}
	if snapshot.Errors != 1 {
		t.Fatalf("expected one error, got %d", snapshot.Errors)
	}

	// Cumulative buckets: 8us lands in every bucket, 40us in all but the first,
	// and the 90ms outlier only in +Inf.
	first, last := snapshot.DurationBuckets[0], snapshot.DurationBuckets[len(snapshot.DurationBuckets)-1]
	if first.LE != 10 || first.Count != 1 {
		t.Fatalf("unexpected first bucket: %+v", first)
	}
	if last.Count != 3 {
		t.Fatalf("the +Inf bucket must count every observation, got %d", last.Count)
	}

	rendered := metrics.RenderPrometheus()
	for _, want := range []string{
		`hushspec_evaluate_total{decision="deny",action_type="egress"} 1`,
		`hushspec_evaluate_duration_us_bucket{le="+Inf"} 3`,
		`hushspec_evaluate_duration_us_count 3`,
		`hushspec_rule_match_total{rule_block="egress",decision="deny"} 1`,
		`hushspec_policy_load_total{status="success"} 1`,
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("exposition is missing %q:\n%s", want, rendered)
		}
	}
	if rendered != metrics.RenderPrometheus() {
		t.Fatal("exposition must be stable across renders")
	}

	metrics.Reset()
	if metrics.Snapshot().DurationCount != 0 {
		t.Fatal("Reset must zero the counters")
	}
}

func TestJSONLineObserverWritesEventsWithoutContent(t *testing.T) {
	var buffer bytes.Buffer
	observer := NewJSONLineObserver(&buffer)
	observer.OnPolicyLoaded(PolicyLoadObservation{Name: "p", ContentHash: "sha256:aa"})
	observer.OnPolicyLoaded(PolicyLoadObservation{
		Name: "p", ContentHash: "sha256:bb", PreviousContentHash: "sha256:aa",
	})
	content := "super secret"
	observer.OnEvaluation(
		&EvaluationAction{Type: "file_write", Target: "notes.txt", Content: &content},
		EvaluationResult{Decision: DecisionDeny, MatchedRule: "rules.forbidden_paths.paths[0]"},
		nil, 12*time.Microsecond,
	)
	observer.OnError(errors.New("reload failed"))

	lines := strings.Split(strings.TrimSpace(buffer.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 lines, got %d: %q", len(lines), buffer.String())
	}
	if strings.Contains(buffer.String(), "super secret") {
		t.Fatal("the observer stream must never carry raw action content")
	}

	var loaded, reloaded, evaluation, failure ObserverEvent
	mustDecode(t, lines[0], &loaded)
	mustDecode(t, lines[1], &reloaded)
	mustDecode(t, lines[2], &evaluation)
	mustDecode(t, lines[3], &failure)

	if loaded.Type != ObserverEventPolicyLoaded || reloaded.Type != ObserverEventPolicyReloaded {
		t.Fatalf("unexpected policy event types: %q %q", loaded.Type, reloaded.Type)
	}
	if reloaded.PreviousHash != "sha256:aa" {
		t.Fatalf("a reload must name the hash it replaced, got %q", reloaded.PreviousHash)
	}
	if evaluation.Type != ObserverEventEvaluation || evaluation.Action == nil {
		t.Fatalf("unexpected evaluation event: %+v", evaluation)
	}
	if evaluation.Action.ContentHash == "" || evaluation.Action.ContentSize == nil {
		t.Fatal("the action summary must still record the content hash and size")
	}
	if evaluation.DurationUs == nil || *evaluation.DurationUs != 12 {
		t.Fatalf("unexpected duration: %+v", evaluation.DurationUs)
	}
	if failure.Type != ObserverEventError || failure.Error != "reload failed" {
		t.Fatalf("unexpected error event: %+v", failure)
	}
}

func mustDecode(t *testing.T, line string, into *ObserverEvent) {
	t.Helper()
	if err := json.Unmarshal([]byte(line), into); err != nil {
		t.Fatalf("decode %q: %v", line, err)
	}
}

// panickingObserver panics on every callback, to prove an observer cannot
// break enforcement.
type panickingObserver struct {
	mu     sync.Mutex
	errors int
}

func (o *panickingObserver) OnPolicyLoaded(PolicyLoadObservation) { panic("boom") }
func (o *panickingObserver) OnEvaluation(
	*EvaluationAction, EvaluationResult, *DecisionReceipt, time.Duration,
) {
	panic("boom")
}

func (o *panickingObserver) OnError(error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.errors++
}

func TestObservableEvaluatorFansOutAndSurvivesPanics(t *testing.T) {
	first := &recordingObserver{}
	second := &recordingObserver{}
	bad := &panickingObserver{}
	fanout := NewObservableEvaluator(bad, first)
	fanout.AddObserver(second)
	fanout.AddObserver(nil)

	if len(fanout.Observers()) != 3 {
		t.Fatalf("expected 3 observers, got %d", len(fanout.Observers()))
	}

	fanout.OnPolicyLoaded(PolicyLoadObservation{Name: "p"})
	fanout.OnEvaluation(&EvaluationAction{Type: "egress"}, EvaluationResult{Decision: DecisionAllow}, nil, 0)
	fanout.OnError(errors.New("boom"))

	for _, observer := range []*recordingObserver{first, second} {
		loads, results, errs := observer.counts()
		if loads != 1 || results != 1 || errs != 1 {
			t.Fatalf("observer missed events: %d %d %d", loads, results, errs)
		}
	}
	bad.mu.Lock()
	reported := bad.errors
	bad.mu.Unlock()
	if reported < 2 {
		t.Fatalf("a panicking observer must be told about its own panics, got %d", reported)
	}

	fanout.RemoveObserver(second)
	if len(fanout.Observers()) != 2 {
		t.Fatal("RemoveObserver did not unregister")
	}
}

func TestObservableEvaluatorEvaluate(t *testing.T) {
	observer := &recordingObserver{}
	fanout := NewObservableEvaluator(observer)
	compiled, err := CompilePolicy(guardSpec())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	result := fanout.Evaluate(compiled, &EvaluationAction{Type: "egress", Target: "evil.example.com"})
	if result.Decision != DecisionDeny {
		t.Fatalf("expected a deny, got %q", result.Decision)
	}
	if _, results, _ := observer.counts(); results != 1 {
		t.Fatalf("expected one observed evaluation, got %d", results)
	}
}

func TestWebhookObserverPostsEvents(t *testing.T) {
	posted := make(chan ObserverEvent, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Token") != "secret" {
			t.Errorf("headers were not sent: %v", r.Header)
		}
		var event ObserverEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Errorf("decode: %v", err)
		}
		posted <- event
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	observer, err := NewWebhookObserver(WebhookOptions{
		URL:     server.URL,
		Headers: map[string]string{"X-Token": "secret"},
		Client:  server.Client(),
	})
	if err != nil {
		t.Fatalf("NewWebhookObserver: %v", err)
	}
	defer observer.Close()

	observer.OnEvaluation(
		&EvaluationAction{Type: "egress", Target: "evil.example.com"},
		EvaluationResult{Decision: DecisionDeny, MatchedRule: "rules.egress.block[0]"},
		nil, time.Millisecond,
	)

	select {
	case event := <-posted:
		if event.Type != ObserverEventEvaluation || event.Result.Decision != DecisionDeny {
			t.Fatalf("unexpected event: %+v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the webhook was never called")
	}
}

func TestWebhookObserverDropsOnOverflow(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var dropErrors int
	var mu sync.Mutex
	observer, err := NewWebhookObserver(WebhookOptions{
		URL:      server.URL,
		MaxQueue: 1,
		Client:   server.Client(),
		OnError: func(error) {
			mu.Lock()
			defer mu.Unlock()
			dropErrors++
		},
	})
	if err != nil {
		t.Fatalf("NewWebhookObserver: %v", err)
	}

	for i := 0; i < 50; i++ {
		observer.OnError(errors.New("event"))
	}
	if observer.Dropped() == 0 {
		t.Fatal("a full queue must drop rather than block")
	}
	mu.Lock()
	reported := dropErrors
	mu.Unlock()
	if reported == 0 {
		t.Fatal("drops must be reported through OnError")
	}

	close(release)
	if err := observer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestStderrObserverDenyOnly(t *testing.T) {
	var buffer bytes.Buffer
	observer := NewWriterObserver(&buffer)
	observer.DenyOnly = true
	observer.OnEvaluation(&EvaluationAction{Type: "egress"}, EvaluationResult{Decision: DecisionAllow}, nil, 0)
	if buffer.Len() != 0 {
		t.Fatalf("deny_only must skip allows, got %q", buffer.String())
	}
	observer.OnEvaluation(
		&EvaluationAction{Type: "egress", Target: "evil.example.com"},
		EvaluationResult{Decision: DecisionDeny, MatchedRule: "rules.egress.block[0]"},
		nil, 0,
	)
	observer.OnPolicyLoaded(PolicyLoadObservation{Name: "p", ContentHash: "sha256:aa"})
	if !strings.Contains(buffer.String(), "evil.example.com") ||
		!strings.Contains(buffer.String(), "policy loaded") {
		t.Fatalf("unexpected output: %q", buffer.String())
	}
}
