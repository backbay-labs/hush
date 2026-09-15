package hushspec

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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

func TestOTLPSinkSeverityPerDecision(t *testing.T) {
	cases := map[Decision]string{
		DecisionAllow: "INFO",
		DecisionWarn:  "WARN",
		DecisionDeny:  "ERROR",
	}
	for decision, want := range cases {
		record, err := receiptLogRecord(otlpTestReceipt(t, decision))
		if err != nil {
			t.Fatalf("receiptLogRecord: %v", err)
		}
		if record.SeverityText != want {
			t.Fatalf("%s severity = %q, want %q", decision, record.SeverityText, want)
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

	for i := 0; i < 6; i++ {
		if err := sink.Send(otlpTestReceipt(t, DecisionAllow)); err != nil {
			t.Fatalf("Send: %v", err)
		}
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

func TestOTLPSinkRetriesServerErrors(t *testing.T) {
	c := &collector{status: []int{http.StatusServiceUnavailable, http.StatusInternalServerError}}
	server := startCollector(t, c)

	var failures []error
	sink, err := NewOTLPReceiptSink(OTLPOptions{
		Endpoint:      server.URL,
		FlushInterval: time.Minute,
		RetryBackoff:  time.Millisecond,
		MaxRetries:    3,
		Client:        server.Client(),
		OnError:       func(err error) { failures = append(failures, err) },
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
	if len(failures) != 0 {
		t.Fatalf("a retried export that succeeds is not an error: %v", failures)
	}
	if sink.Exported() != 1 {
		t.Fatalf("expected one exported record, got %d", sink.Exported())
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

	close(c.block)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestOTLPSinkRequiresEndpoint(t *testing.T) {
	if _, err := NewOTLPReceiptSink(OTLPOptions{}); err == nil {
		t.Fatal("an endpoint is required")
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
