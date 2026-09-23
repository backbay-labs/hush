package hushspec

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"
)

// collector is a stand-in OTLP/HTTP receiver.
type collector struct {
	mu       sync.Mutex
	payloads []otlpLogsPayload
	paths    []string
	headers  []http.Header
	status   []int
	block    chan struct{}
}

func (c *collector) handler(w http.ResponseWriter, r *http.Request) {
	if c.block != nil {
		<-c.block
	}
	body, _ := io.ReadAll(r.Body)
	var payload otlpLogsPayload
	_ = json.Unmarshal(body, &payload)

	c.mu.Lock()
	c.payloads = append(c.payloads, payload)
	c.paths = append(c.paths, r.URL.Path)
	c.headers = append(c.headers, r.Header.Clone())
	status := http.StatusOK
	if len(c.status) > 0 {
		status = c.status[0]
		c.status = c.status[1:]
	}
	c.mu.Unlock()

	w.WriteHeader(status)
}

func (c *collector) requests() []otlpLogsPayload {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]otlpLogsPayload(nil), c.payloads...)
}

func (c *collector) records() []otlpLogRecord {
	var records []otlpLogRecord
	for _, payload := range c.requests() {
		for _, resource := range payload.ResourceLogs {
			for _, scope := range resource.ScopeLogs {
				records = append(records, scope.LogRecords...)
			}
		}
	}
	return records
}

// waitForRequests blocks until the collector has received want requests, so a
// test can order its assertions against the sink's background exporter instead
// of racing it.
func (c *collector) waitForRequests(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if len(c.requests()) >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected %d exports, got %d", want, len(c.requests()))
		}
		time.Sleep(time.Millisecond)
	}
}

func startCollector(t *testing.T, c *collector) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(c.handler))
	t.Cleanup(server.Close)
	return server
}

func otlpTestReceipt(t *testing.T, decision Decision) *DecisionReceipt {
	t.Helper()
	receipt := makeTestReceipt(decision)
	receipt.Enforcement = ImpliedEnforcement(decision, EnforcementModeEnforce)
	return receipt
}

func TestOTLPSinkExportsReceiptShape(t *testing.T) {
	c := &collector{}
	server := startCollector(t, c)

	sink, err := NewOTLPReceiptSink(OTLPOptions{
		Endpoint:      server.URL,
		Headers:       map[string]string{"X-Tenant": "acme"},
		ServiceName:   "agent-runtime",
		FlushInterval: time.Minute,
		Client:        server.Client(),
	})
	if err != nil {
		t.Fatalf("NewOTLPReceiptSink: %v", err)
	}
	defer sink.Close()

	receipt := otlpTestReceipt(t, DecisionDeny)
	if err := sink.Send(receipt); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	payloads := c.requests()
	if len(payloads) != 1 {
		t.Fatalf("expected one export, got %d", len(payloads))
	}
	if c.paths[0] != "/v1/logs" {
		t.Fatalf("expected /v1/logs, got %q", c.paths[0])
	}
	if c.headers[0].Get("X-Tenant") != "acme" {
		t.Fatal("configured headers were not sent")
	}
	if c.headers[0].Get("Content-Type") != "application/json" {
		t.Fatalf("unexpected content type %q", c.headers[0].Get("Content-Type"))
	}

	resource := payloads[0].ResourceLogs[0].Resource
	wantResource := map[string]string{
		otlpResourceServiceName: "agent-runtime",
		otlpResourceSDK:         SDKName,
		otlpResourceSDKVersion:  Version,
		otlpResourceSpecVersion: Version,
	}
	for key, want := range wantResource {
		if got := attributeValue(resource.Attributes, key); got != want {
			t.Fatalf("resource attribute %s = %q, want %q", key, got, want)
		}
	}

	scope := payloads[0].ResourceLogs[0].ScopeLogs[0].Scope
	if scope.Name != SDKName || scope.Version != Version {
		t.Fatalf("the scope must name this SDK, got %+v", scope)
	}

	records := c.records()
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	record := records[0]
	if record.SeverityText != "ERROR" {
		t.Fatalf("a deny must be ERROR, got %q", record.SeverityText)
	}
	canonical, err := receipt.CanonicalJSON()
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if record.Body.StringValue != canonical {
		t.Fatal("the body must be the receipt's canonical JSON")
	}
	instant, err := time.Parse(time.RFC3339Nano, receipt.Timestamp)
	if err != nil {
		t.Fatalf("parse timestamp: %v", err)
	}
	if record.TimeUnixNano != strconv.FormatInt(instant.UnixNano(), 10) {
		t.Fatalf("unexpected timeUnixNano %q", record.TimeUnixNano)
	}

	receiptHash, err := receipt.ReceiptHash()
	if err != nil {
		t.Fatalf("receipt hash: %v", err)
	}
	wantAttributes := map[string]string{
		otlpAttrEntryType:          string(EntryTypeReceipt),
		otlpAttrReceiptVersion:     receipt.ReceiptVersion,
		otlpAttrDecision:           string(DecisionDeny),
		otlpAttrActionType:         receipt.Action.Type,
		otlpAttrMatchedRule:        receipt.MatchedRule,
		otlpAttrPolicyContentHash:  receipt.Policy.ContentHash,
		otlpAttrReceiptHash:        receiptHash,
		otlpAttrEnforcementMode:    string(EnforcementModeEnforce),
		otlpAttrEnforcementOutcome: string(EnforcementOutcomeBlocked),
	}
	for key, want := range wantAttributes {
		if got := attributeValue(record.Attributes, key); got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
}

func TestOTLPRecordMembersAreTheSameForEveryEntry(t *testing.T) {
	// The wire mapping every HushSpec SDK's exporter emits, so one collector
	// pipeline and one set of dashboard queries read all four.
	want := []string{
		"attributes",
		"body",
		"observedTimeUnixNano",
		"severityNumber",
		"severityText",
		"timeUnixNano",
	}

	resolution, err := NewResolutionFromResolved(guardSpec(), "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	event := NewPolicyLoadedEvent(resolution, EnforcementModeEnforce, SdkInfo{})
	eventRecord, err := policyEventLogRecord(&event)
	if err != nil {
		t.Fatalf("policyEventLogRecord: %v", err)
	}
	receiptRecord, err := receiptLogRecord(otlpTestReceipt(t, DecisionDeny))
	if err != nil {
		t.Fatalf("receiptLogRecord: %v", err)
	}

	for _, record := range []otlpLogRecord{receiptRecord, eventRecord} {
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &members); err != nil {
			t.Fatalf("unmarshal record: %v", err)
		}
		got := make([]string, 0, len(members))
		for member := range members {
			got = append(got, member)
		}
		sort.Strings(got)
		if !slices.Equal(got, want) {
			t.Fatalf("record members = %v, want %v", got, want)
		}
	}
}

func TestOTLPSinkSeverityPerDecision(t *testing.T) {
	type severity struct {
		text   string
		number int
	}
	cases := map[Decision]severity{
		DecisionAllow: {"INFO", 9},
		DecisionWarn:  {"WARN", 13},
		DecisionDeny:  {"ERROR", 17},
	}
	for decision, want := range cases {
		record, err := receiptLogRecord(otlpTestReceipt(t, decision))
		if err != nil {
			t.Fatalf("receiptLogRecord: %v", err)
		}
		if record.SeverityText != want.text || record.SeverityNumber != want.number {
			t.Fatalf("%s severity = %q/%d, want %q/%d",
				decision, record.SeverityText, record.SeverityNumber, want.text, want.number)
		}
	}
}

func TestOTLPSinkExportsPolicyEvents(t *testing.T) {
	c := &collector{}
	server := startCollector(t, c)
	sink, err := NewOTLPReceiptSink(OTLPOptions{
		Endpoint:      server.URL + "/v1/logs",
		FlushInterval: time.Minute,
		Client:        server.Client(),
	})
	if err != nil {
		t.Fatalf("NewOTLPReceiptSink: %v", err)
	}
	defer sink.Close()

	resolution, err := NewResolutionFromResolved(guardSpec(), "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	event := NewPolicySwappedEvent(resolution, EnforcementModeMonitor, SdkInfo{}, "sha256:old")
	if err := sink.RecordPolicyEvent(&event); err != nil {
		t.Fatalf("RecordPolicyEvent: %v", err)
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	records := c.records()
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	if records[0].SeverityText != "INFO" {
		t.Fatalf("a policy event is informational, got %q", records[0].SeverityText)
	}
	if got := attributeValue(records[0].Attributes, otlpAttrEntryType); got != string(EntryTypePolicySwapped) {
		t.Fatalf("entry type = %q", got)
	}
	if got := attributeValue(records[0].Attributes, otlpAttrPolicyContentHash); got != resolution.ContentHash {
		t.Fatalf("policy hash = %q", got)
	}
	if got := attributeValue(records[0].Attributes, otlpAttrEnforcementMode); got != string(EnforcementModeMonitor) {
		t.Fatalf("enforcement mode = %q", got)
	}
	if c.paths[0] != "/v1/logs" {
		t.Fatalf("an endpoint that already names /v1/logs must not be doubled: %q", c.paths[0])
	}
}

func TestOTLPSinkBatches(t *testing.T) {
	c := &collector{}
	server := startCollector(t, c)
	sink, err := NewOTLPReceiptSink(OTLPOptions{
		Endpoint:      server.URL,
		BatchSize:     3,
		FlushInterval: time.Minute,
		Client:        server.Client(),
	})
	if err != nil {
		t.Fatalf("NewOTLPReceiptSink: %v", err)
	}
	defer sink.Close()

	// A full batch exports on its own, with no flush and no tick. Each batch is
	// awaited before the next is queued: a flush observed while records are
	// still queued legitimately drains them into one request, so sending all
	// six at once would not pin the batch shape.
	for batch := 1; batch <= 2; batch++ {
		for i := 0; i < 3; i++ {
			if err := sink.Send(otlpTestReceipt(t, DecisionAllow)); err != nil {
				t.Fatalf("Send: %v", err)
			}
		}
		c.waitForRequests(t, batch)
	}

	if err := sink.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	payloads := c.requests()
	if len(payloads) != 2 {
		t.Fatalf("expected 2 batched exports, got %d", len(payloads))
	}
	for _, payload := range payloads {
		records := payload.ResourceLogs[0].ScopeLogs[0].LogRecords
		if len(records) != 3 {
			t.Fatalf("expected 3 records per batch, got %d", len(records))
		}
	}
	if sink.Exported() != 6 {
		t.Fatalf("expected 6 exported records, got %d", sink.Exported())
	}
}

func TestOTLPSinkRetriesABusyCollector(t *testing.T) {
	c := &collector{status: []int{http.StatusServiceUnavailable, http.StatusTooManyRequests}}
	server := startCollector(t, c)

	// OnError is called from the exporter goroutine, so the slice it appends to
	// is read under the same mutex.
	var mu sync.Mutex
	var failures []error
	sink, err := NewOTLPReceiptSink(OTLPOptions{
		Endpoint:      server.URL,
		FlushInterval: time.Minute,
		RetryBackoff:  time.Millisecond,
		MaxRetries:    3,
		Client:        server.Client(),
		OnError: func(err error) {
			mu.Lock()
			defer mu.Unlock()
			failures = append(failures, err)
		},
	})
	if err != nil {
		t.Fatalf("NewOTLPReceiptSink: %v", err)
	}
	defer sink.Close()

	if err := sink.Send(otlpTestReceipt(t, DecisionAllow)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if got := len(c.requests()); got != 3 {
		t.Fatalf("expected two retries and a success, got %d requests", got)
	}
	mu.Lock()
	reported := append([]error(nil), failures...)
	mu.Unlock()
	if len(reported) != 0 {
		t.Fatalf("a retried export that succeeds is not an error: %v", reported)
	}
	if sink.Exported() != 1 {
		t.Fatalf("expected one exported record, got %d", sink.Exported())
	}
}

func TestOTLPSinkRetriesOnlyTheSharedStatuses(t *testing.T) {
	want := []int{429, 502, 503, 504}
	if len(RetryableStatuses) != len(want) {
		t.Fatalf("unexpected retryable set: %v", RetryableStatuses)
	}
	for i, status := range want {
		if RetryableStatuses[i] != status {
			t.Fatalf("unexpected retryable set: %v", RetryableStatuses)
		}
	}

	// A 503 is the collector saying "not now": the same bytes are worth
	// sending again. A 500 is not in the set, so it is a final failure.
	for _, testCase := range []struct {
		name     string
		status   int
		requests int
		exported uint64
	}{
		{"retried", http.StatusServiceUnavailable, 2, 1},
		{"final", http.StatusInternalServerError, 1, 0},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			c := &collector{status: []int{testCase.status}}
			server := startCollector(t, c)

			sink, err := NewOTLPReceiptSink(OTLPOptions{
				Endpoint:      server.URL,
				FlushInterval: time.Minute,
				RetryBackoff:  time.Millisecond,
				MaxRetries:    3,
				Client:        server.Client(),
				OnError:       func(error) {},
			})
			if err != nil {
				t.Fatalf("NewOTLPReceiptSink: %v", err)
			}
			defer sink.Close()

			if err := sink.Send(otlpTestReceipt(t, DecisionAllow)); err != nil {
				t.Fatalf("Send: %v", err)
			}
			if err := sink.Flush(context.Background()); err != nil {
				t.Fatalf("Flush: %v", err)
			}
			if got := len(c.requests()); got != testCase.requests {
				t.Fatalf("expected %d requests, got %d", testCase.requests, got)
			}
			if got := sink.Exported(); got != testCase.exported {
				t.Fatalf("expected %d exported, got %d", testCase.exported, got)
			}
		})
	}
}

func TestOTLPSinkDoesNotRetryClientErrors(t *testing.T) {
	c := &collector{status: []int{http.StatusBadRequest}}
	server := startCollector(t, c)

	reported := make(chan error, 4)
	sink, err := NewOTLPReceiptSink(OTLPOptions{
		Endpoint:      server.URL,
		FlushInterval: time.Minute,
		RetryBackoff:  time.Millisecond,
		Client:        server.Client(),
		OnError:       func(err error) { reported <- err },
	})
	if err != nil {
		t.Fatalf("NewOTLPReceiptSink: %v", err)
	}
	defer sink.Close()

	if err := sink.Send(otlpTestReceipt(t, DecisionAllow)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := len(c.requests()); got != 1 {
		t.Fatalf("a 4xx must not be retried, got %d requests", got)
	}
	select {
	case <-reported:
	case <-time.After(time.Second):
		t.Fatal("a rejected export must be reported")
	}
}

func TestOTLPSinkDropsOnOverflow(t *testing.T) {
	c := &collector{block: make(chan struct{})}
	server := startCollector(t, c)

	var mu sync.Mutex
	var drops int
	sink, err := NewOTLPReceiptSink(OTLPOptions{
		Endpoint:      server.URL,
		MaxQueue:      2,
		BatchSize:     1,
		FlushInterval: time.Minute,
		Client:        server.Client(),
		OnError: func(error) {
			mu.Lock()
			defer mu.Unlock()
			drops++
		},
	})
	if err != nil {
		t.Fatalf("NewOTLPReceiptSink: %v", err)
	}
	// Torn down on every path, in this order: the handler is released first so
	// the in-flight export can finish, and only then does Close wait for the
	// exporter goroutine. A failed assertion would otherwise wedge both, and
	// the server's cleanup waits for the blocked handler.
	defer func() {
		close(c.block)
		_ = sink.Close()
	}()

	receipt := otlpTestReceipt(t, DecisionAllow)
	for i := 0; i < 100; i++ {
		if err := sink.Send(receipt); err != nil {
			t.Fatalf("Send must not fail on a backlog: %v", err)
		}
	}
	if sink.Dropped() == 0 {
		t.Fatal("a full queue must drop rather than block an evaluation")
	}
	mu.Lock()
	reported := drops
	mu.Unlock()
	if reported == 0 {
		t.Fatal("drops must be reported through OnError")
	}

}

func TestOTLPSinkRejectsBadEndpoints(t *testing.T) {
	for _, endpoint := range []string{"", "   ", "file:///tmp/evidence", "localhost:4318", "http://"} {
		if _, err := NewOTLPReceiptSink(OTLPOptions{Endpoint: endpoint}); err == nil {
			t.Fatalf("endpoint %q must be rejected", endpoint)
		}
	}
	for endpoint, want := range map[string]string{
		"http://localhost:4318":            "http://localhost:4318/v1/logs",
		"http://localhost:4318/":           "http://localhost:4318/v1/logs",
		"https://otel.example.com/v1/logs": "https://otel.example.com/v1/logs",
	} {
		got, err := logsEndpoint(endpoint)
		if err != nil {
			t.Fatalf("logsEndpoint(%q): %v", endpoint, err)
		}
		if got != want {
			t.Fatalf("logsEndpoint(%q) = %q, want %q", endpoint, got, want)
		}
	}
}

func TestOTLPRecordFallsBackToExportTime(t *testing.T) {
	receipt := otlpTestReceipt(t, DecisionAllow)
	receipt.Timestamp = "not a timestamp"
	record, err := receiptLogRecord(receipt)
	if err != nil {
		t.Fatalf("receiptLogRecord: %v", err)
	}
	nanos, err := strconv.ParseInt(record.TimeUnixNano, 10, 64)
	if err != nil {
		t.Fatalf("parse timeUnixNano %q: %v", record.TimeUnixNano, err)
	}
	// A record with no time at all is dropped by collectors, so an unreadable
	// clock falls back to the time the sink took the entry rather than to zero.
	if time.Since(time.Unix(0, nanos)) > time.Minute {
		t.Fatalf("expected the observed time, got %q", record.TimeUnixNano)
	}
	if record.TimeUnixNano != record.ObservedTimeUnixNano {
		t.Fatalf("the fallback is the observed time, got %q and %q",
			record.TimeUnixNano, record.ObservedTimeUnixNano)
	}
}

func TestOTLPSeverityFailsClosed(t *testing.T) {
	text, number := severityOf(Decision("quarantine"))
	if text != "ERROR" || number != 17 {
		t.Fatalf("an unknown decision is not an INFO, got %q/%d", text, number)
	}
}

func TestOTLPSinkCloseFlushes(t *testing.T) {
	c := &collector{}
	server := startCollector(t, c)
	sink, err := NewOTLPReceiptSink(OTLPOptions{
		Endpoint:      server.URL,
		FlushInterval: time.Minute,
		Client:        server.Client(),
	})
	if err != nil {
		t.Fatalf("NewOTLPReceiptSink: %v", err)
	}
	if err := sink.Send(otlpTestReceipt(t, DecisionAllow)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close must be idempotent: %v", err)
	}
	if len(c.records()) != 1 {
		t.Fatal("Close must export what is queued")
	}
}

func TestGuardExportsThroughOTLPSink(t *testing.T) {
	c := &collector{}
	server := startCollector(t, c)
	sink, err := NewOTLPReceiptSink(OTLPOptions{
		Endpoint:      server.URL,
		FlushInterval: time.Minute,
		Client:        server.Client(),
	})
	if err != nil {
		t.Fatalf("NewOTLPReceiptSink: %v", err)
	}
	defer sink.Close()

	guard := newTestGuard(t, GuardOptions{Sink: sink})
	if _, err := guard.Check(context.Background(), &EvaluationAction{
		Type: "egress", Target: "evil.example.com",
	}); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	records := c.records()
	if len(records) != 2 {
		t.Fatalf("expected a policy event and a receipt, got %d records", len(records))
	}
	if got := attributeValue(records[0].Attributes, otlpAttrEntryType); got != string(EntryTypePolicyLoaded) {
		t.Fatalf("the policy event must come first, got %q", got)
	}
	if got := attributeValue(records[1].Attributes, otlpAttrDecision); got != string(DecisionDeny) {
		t.Fatalf("decision attribute = %q", got)
	}
}
