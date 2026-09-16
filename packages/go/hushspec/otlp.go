package hushspec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// OTLP export defaults.
const (
	// DefaultOTLPServiceName is the `service.name` resource attribute when the
	// caller sets none.
	DefaultOTLPServiceName = "hushspec"
	// DefaultOTLPBatchSize is how many records are exported in one request.
	DefaultOTLPBatchSize = 64
	// DefaultOTLPFlushInterval is how long a partial batch waits.
	DefaultOTLPFlushInterval = 5 * time.Second
	// DefaultOTLPTimeout bounds one export request.
	DefaultOTLPTimeout = 10 * time.Second
	// DefaultOTLPMaxQueue bounds the queue of records awaiting export.
	DefaultOTLPMaxQueue = 2048
	// DefaultOTLPMaxRetries is how many times a retriable export is retried.
	DefaultOTLPMaxRetries = 3
	// DefaultOTLPRetryBackoff is the first retry delay; it doubles per attempt.
	DefaultOTLPRetryBackoff = 250 * time.Millisecond
)

// Attribute keys of an exported record. They are the join keys between a trace
// in a collector and the receipts in a hash-linked log, and are identical in
// every SDK.
const (
	otlpAttrEntryType          = "hushspec.entry_type"
	otlpAttrReceiptVersion     = "hushspec.receipt_version"
	otlpAttrDecision           = "hushspec.decision"
	otlpAttrActionType         = "hushspec.action_type"
	otlpAttrMatchedRule        = "hushspec.matched_rule"
	otlpAttrPolicyContentHash  = "hushspec.policy.content_hash"
	otlpAttrReceiptHash        = "hushspec.receipt_hash"
	otlpAttrEnforcementMode    = "hushspec.enforcement.mode"
	otlpAttrEnforcementOutcome = "hushspec.enforcement.outcome"

	otlpResourceServiceName = "service.name"
	otlpResourceSDK         = "hushspec.sdk"
	otlpResourceSDKVersion  = "hushspec.sdk.version"
	otlpResourceSpecVersion = "hushspec.spec_version"
)

// OTLPOptions configures an [OTLPReceiptSink].
type OTLPOptions struct {
	// Endpoint is the collector's base URL, e.g. "http://localhost:4318".
	// Records are POSTed to "<endpoint>/v1/logs"; an endpoint that already
	// ends in "/v1/logs" is used as given.
	Endpoint string
	// Headers are sent with every export (authentication, tenancy).
	Headers map[string]string
	// ServiceName fills the `service.name` resource attribute. Empty means
	// [DefaultOTLPServiceName].
	ServiceName string
	// BatchSize exports as soon as this many records are queued. Zero means
	// [DefaultOTLPBatchSize].
	BatchSize int
	// FlushInterval exports a partial batch this often. Zero means
	// [DefaultOTLPFlushInterval].
	FlushInterval time.Duration
	// Timeout bounds one export request. Zero means [DefaultOTLPTimeout].
	Timeout time.Duration
	// MaxQueue bounds the queue of records awaiting export. Zero means
	// [DefaultOTLPMaxQueue]. Past it, records are dropped and counted rather
	// than blocking an evaluation.
	MaxQueue int
	// OnError is told about every drop and every export that failed.
	OnError func(error)
	// MaxRetries is how many times a retriable failure (a network error, a
	// 429 or a 5xx) is retried. Zero means [DefaultOTLPMaxRetries].
	MaxRetries int
	// RetryBackoff is the first retry delay, doubling per attempt. Zero means
	// [DefaultOTLPRetryBackoff].
	RetryBackoff time.Duration
	// Client overrides the HTTP client (a test server, a proxy, mTLS).
	Client *http.Client
}

// OTLPReceiptSink exports receipts and policy events to an OpenTelemetry
// collector as OTLP/HTTP JSON logs.
//
// One record per entry: the canonical JSON of the receipt (or the policy
// event) as the body, so a collector holds exactly the bytes the receipt hash
// covers, and the decision, action type, matched rule, policy hash, receipt
// hash and enforcement disposition as attributes, so a query never has to
// parse the body. A record is stamped with the entry's own timestamp in
// `timeUnixNano` and with the moment the sink took it in
// `observedTimeUnixNano`, and carries `severityText` and `severityNumber` of
// INFO/9, WARN/13 or ERROR/17 for an allow, a warn or a deny -- the mapping
// every HushSpec SDK emits.
//
// Export happens on a background goroutine: [OTLPReceiptSink.Send] queues and
// returns, and never blocks an evaluation. A full queue drops the record,
// counts it in [OTLPReceiptSink.Dropped] and reports through OnError -- a
// telemetry backlog must not become an enforcement outage. It is therefore
// best-effort, and not a substitute for a [ChainedFileSink] when the audit
// trail has to be complete.
type OTLPReceiptSink struct {
	endpoint string
	headers  map[string]string
	client   *http.Client
	// timeout bounds one export request through a per-request context, so it
	// applies to a caller-supplied Client as well as to the default one.
	timeout time.Duration

	batchSize     int
	flushInterval time.Duration
	maxRetries    int
	retryBackoff  time.Duration
	onError       func(error)

	resource []otlpAttribute
	scope    otlpScope

	queue    chan otlpLogRecord
	flushCh  chan chan struct{}
	done     chan struct{}
	finished chan struct{}
	stopOnce sync.Once

	dropped  atomic.Uint64
	exported atomic.Uint64
}

var (
	_ ReceiptSink     = (*OTLPReceiptSink)(nil)
	_ PolicyEventSink = (*OTLPReceiptSink)(nil)
)

// NewOTLPReceiptSink starts an exporter against a collector endpoint.
func NewOTLPReceiptSink(options OTLPOptions) (*OTLPReceiptSink, error) {
	endpoint, err := logsEndpoint(options.Endpoint)
	if err != nil {
		return nil, err
	}

	serviceName := options.ServiceName
	if serviceName == "" {
		serviceName = DefaultOTLPServiceName
	}
	batchSize := options.BatchSize
	if batchSize <= 0 {
		batchSize = DefaultOTLPBatchSize
	}
	flushInterval := options.FlushInterval
	if flushInterval <= 0 {
		flushInterval = DefaultOTLPFlushInterval
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DefaultOTLPTimeout
	}
	maxQueue := options.MaxQueue
	if maxQueue <= 0 {
		maxQueue = DefaultOTLPMaxQueue
	}
	maxRetries := options.MaxRetries
	if maxRetries <= 0 {
		maxRetries = DefaultOTLPMaxRetries
	}
	retryBackoff := options.RetryBackoff
	if retryBackoff <= 0 {
		retryBackoff = DefaultOTLPRetryBackoff
	}
	client := options.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	headers := make(map[string]string, len(options.Headers))
	for key, value := range options.Headers {
		headers[key] = value
	}

	sdk := ThisSDK()
	sink := &OTLPReceiptSink{
		endpoint:      endpoint,
		headers:       headers,
		client:        client,
		timeout:       timeout,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		maxRetries:    maxRetries,
		retryBackoff:  retryBackoff,
		onError:       options.OnError,
		scope:         otlpScope{Name: sdk.Name, Version: sdk.Version},
		resource: []otlpAttribute{
			stringAttribute(otlpResourceServiceName, serviceName),
			stringAttribute(otlpResourceSDK, sdk.Name),
			stringAttribute(otlpResourceSDKVersion, sdk.Version),
			stringAttribute(otlpResourceSpecVersion, Version),
		},
		queue:    make(chan otlpLogRecord, maxQueue),
		flushCh:  make(chan chan struct{}),
		done:     make(chan struct{}),
		finished: make(chan struct{}),
	}
	go sink.run()
	return sink, nil
}

// Send queues a receipt for export. It never blocks and never fails on a
// backlog: a record the queue cannot take is dropped, counted and reported.
func (s *OTLPReceiptSink) Send(receipt *DecisionReceipt) error {
	if receipt == nil {
		return errors.New("otlp sink: nil receipt")
	}
	record, err := receiptLogRecord(receipt)
	if err != nil {
		s.report(err)
		return err
	}
	s.enqueue(record)
	return nil
}

// RecordPolicyEvent queues a policy-in-effect record for export.
func (s *OTLPReceiptSink) RecordPolicyEvent(event *PolicyEvent) error {
	if event == nil {
		return errors.New("otlp sink: nil policy event")
	}
	record, err := policyEventLogRecord(event)
	if err != nil {
		s.report(err)
		return err
	}
	s.enqueue(record)
	return nil
}

// Dropped counts records the queue could not take.
func (s *OTLPReceiptSink) Dropped() uint64 { return s.dropped.Load() }

// Exported counts records successfully delivered to the collector.
func (s *OTLPReceiptSink) Exported() uint64 { return s.exported.Load() }

// Flush exports everything queued and waits for it, or until ctx ends.
func (s *OTLPReceiptSink) Flush(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	acknowledged := make(chan struct{})
	select {
	case s.flushCh <- acknowledged:
	case <-s.done:
		return errors.New("otlp sink: closed")
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-acknowledged:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close exports what is queued and stops the background goroutine. It is safe
// to call more than once.
func (s *OTLPReceiptSink) Close() error {
	s.stopOnce.Do(func() { close(s.done) })
	<-s.finished
	return nil
}

func (s *OTLPReceiptSink) enqueue(record otlpLogRecord) {
	select {
	case <-s.done:
		s.drop(record)
		return
	default:
	}
	select {
	case s.queue <- record:
	default:
		s.drop(record)
	}
}

func (s *OTLPReceiptSink) drop(record otlpLogRecord) {
	s.dropped.Add(1)
	s.report(fmt.Errorf(
		"otlp sink: queue full, dropped %s record (%d dropped in total)",
		attributeValue(record.Attributes, otlpAttrEntryType), s.dropped.Load(),
	))
}

func (s *OTLPReceiptSink) report(err error) {
	if s.onError != nil && err != nil {
		s.onError(err)
	}
}

func (s *OTLPReceiptSink) run() {
	defer close(s.finished)
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	batch := make([]otlpLogRecord, 0, s.batchSize)
	for {
		select {
		case record := <-s.queue:
			batch = append(batch, record)
			if len(batch) >= s.batchSize {
				batch = s.export(batch)
			}
		case <-ticker.C:
			batch = s.export(batch)
		case acknowledged := <-s.flushCh:
			batch = s.export(s.drain(batch))
			close(acknowledged)
		case <-s.done:
			s.export(s.drain(batch))
			return
		}
	}
}

// drain moves everything already queued into the batch without waiting.
func (s *OTLPReceiptSink) drain(batch []otlpLogRecord) []otlpLogRecord {
	for {
		select {
		case record := <-s.queue:
			batch = append(batch, record)
		default:
			return batch
		}
	}
}

// export sends the batch and returns an empty batch to fill again. The batch
// is exported whole: a collector sees one request per batch, with every record
// under a single resource.
func (s *OTLPReceiptSink) export(batch []otlpLogRecord) []otlpLogRecord {
	if len(batch) == 0 {
		return batch[:0]
	}
	payload := otlpLogsPayload{
		ResourceLogs: []otlpResourceLogs{{
			Resource:  otlpResource{Attributes: s.resource},
			ScopeLogs: []otlpScopeLogs{{Scope: s.scope, LogRecords: batch}},
		}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		s.report(fmt.Errorf("otlp sink: serialize %d records: %w", len(batch), err))
		return batch[:0]
	}

	backoff := s.retryBackoff
	for attempt := 0; ; attempt++ {
		retriable, err := s.post(body)
		if err == nil {
			s.exported.Add(uint64(len(batch)))
			return batch[:0]
		}
		if !retriable || attempt >= s.maxRetries {
			s.report(fmt.Errorf("otlp sink: export %d records: %w", len(batch), err))
			return batch[:0]
		}
		select {
		case <-time.After(backoff):
		case <-s.done:
			// A close during a retry gets one last attempt, then gives up:
			// telemetry must not hold up shutdown.
			if _, err := s.post(body); err != nil {
				s.report(fmt.Errorf("otlp sink: export %d records on close: %w", len(batch), err))
			} else {
				s.exported.Add(uint64(len(batch)))
			}
			return batch[:0]
		}
		backoff *= 2
	}
}

// post sends one request and reports whether a failure is worth retrying: a
// network error, a 429, or a 5xx. A 4xx is the collector rejecting the payload
// and retrying it would only repeat the rejection.
func (s *OTLPReceiptSink) post(body []byte) (retriable bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	request.Header.Set("Content-Type", "application/json")
	for key, value := range s.headers {
		request.Header.Set(key, value)
	}

	response, err := s.client.Do(request)
	if err != nil {
		return true, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)

	switch {
	case response.StatusCode < 300:
		return false, nil
	case response.StatusCode == http.StatusTooManyRequests, response.StatusCode >= 500:
		return true, fmt.Errorf("collector returned %d", response.StatusCode)
	default:
		return false, fmt.Errorf("collector returned %d", response.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// OTLP/HTTP JSON payload
// ---------------------------------------------------------------------------

type otlpValue struct {
	StringValue string `json:"stringValue"`
}

type otlpAttribute struct {
	Key   string    `json:"key"`
	Value otlpValue `json:"value"`
}

type otlpResource struct {
	Attributes []otlpAttribute `json:"attributes"`
}

type otlpLogRecord struct {
	// TimeUnixNano is a decimal string: OTLP's JSON mapping spells 64-bit
	// integers as strings so no consumer loses precision to a float. It is the
	// entry's own timestamp; ObservedTimeUnixNano is when the sink took it.
	TimeUnixNano         string          `json:"timeUnixNano"`
	ObservedTimeUnixNano string          `json:"observedTimeUnixNano"`
	SeverityNumber       int             `json:"severityNumber"`
	SeverityText         string          `json:"severityText"`
	Body                 otlpValue       `json:"body"`
	Attributes           []otlpAttribute `json:"attributes"`
}

// otlpScope names the instrumentation that produced the records. Every SDK
// reports its own name and version here, so a collector can tell which
// enforcement point a record came from without reading the resource.
type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type otlpScopeLogs struct {
	Scope      otlpScope       `json:"scope"`
	LogRecords []otlpLogRecord `json:"logRecords"`
}

type otlpResourceLogs struct {
	Resource  otlpResource    `json:"resource"`
	ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
}

type otlpLogsPayload struct {
	ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
}

func stringAttribute(key, value string) otlpAttribute {
	return otlpAttribute{Key: key, Value: otlpValue{StringValue: value}}
}

func appendAttribute(attributes []otlpAttribute, key, value string) []otlpAttribute {
	if value == "" {
		return attributes
	}
	return append(attributes, stringAttribute(key, value))
}

func attributeValue(attributes []otlpAttribute, key string) string {
	for _, attribute := range attributes {
		if attribute.Key == key {
			return attribute.Value.StringValue
		}
	}
	return ""
}

// receiptLogRecord is one receipt as an OTLP log record.
//
// The body is the receipt's canonical JSON -- the exact bytes its receipt hash
// covers -- so a record pulled out of a collector can be verified against a
// log entry without re-canonicalizing anything.
func receiptLogRecord(receipt *DecisionReceipt) (otlpLogRecord, error) {
	canonical, err := receipt.CanonicalJSON()
	if err != nil {
		return otlpLogRecord{}, fmt.Errorf("otlp sink: canonicalize receipt: %w", err)
	}
	receiptHash := DigestOf(canonical)
	observed := nowUnixNano()
	severityText, severityNumber := severityOf(receipt.Decision)

	attributes := make([]otlpAttribute, 0, 9)
	attributes = appendAttribute(attributes, otlpAttrEntryType, string(EntryTypeReceipt))
	attributes = appendAttribute(attributes, otlpAttrReceiptVersion, receipt.ReceiptVersion)
	attributes = appendAttribute(attributes, otlpAttrDecision, string(receipt.Decision))
	attributes = appendAttribute(attributes, otlpAttrActionType, receipt.Action.Type)
	attributes = appendAttribute(attributes, otlpAttrMatchedRule, receipt.MatchedRule)
	attributes = appendAttribute(attributes, otlpAttrPolicyContentHash, receipt.Policy.ContentHash)
	attributes = appendAttribute(attributes, otlpAttrReceiptHash, receiptHash)
	attributes = appendAttribute(attributes, otlpAttrEnforcementMode, string(receipt.Enforcement.Mode))
	attributes = appendAttribute(attributes, otlpAttrEnforcementOutcome, string(receipt.Enforcement.Outcome))

	return otlpLogRecord{
		TimeUnixNano:         unixNanoOf(receipt.Timestamp, observed),
		ObservedTimeUnixNano: observed,
		SeverityNumber:       severityNumber,
		SeverityText:         severityText,
		Body:                 otlpValue{StringValue: canonical},
		Attributes:           attributes,
	}, nil
}

// policyEventLogRecord is one policy-in-effect record as an OTLP log record.
// It is informational whatever the policy says: nothing was decided.
func policyEventLogRecord(event *PolicyEvent) (otlpLogRecord, error) {
	canonical, err := canonicalJSONOf(event)
	if err != nil {
		return otlpLogRecord{}, fmt.Errorf("otlp sink: canonicalize policy event: %w", err)
	}
	observed := nowUnixNano()

	entryType := EntryTypePolicyLoaded
	if event.Event == PolicyEventSwapped {
		entryType = EntryTypePolicySwapped
	}
	attributes := make([]otlpAttribute, 0, 3)
	attributes = appendAttribute(attributes, otlpAttrEntryType, string(entryType))
	attributes = appendAttribute(attributes, otlpAttrPolicyContentHash, event.Policy.ContentHash)
	attributes = appendAttribute(attributes, otlpAttrEnforcementMode, string(event.EnforcementMode))

	return otlpLogRecord{
		TimeUnixNano:         unixNanoOf(event.Timestamp, observed),
		ObservedTimeUnixNano: observed,
		SeverityNumber:       otlpSeverityInfo,
		SeverityText:         "INFO",
		Body:                 otlpValue{StringValue: canonical},
		Attributes:           attributes,
	}, nil
}

// Severity numbers of the OpenTelemetry logs data model, for the severities an
// exported record carries.
const (
	otlpSeverityInfo  = 9
	otlpSeverityWarn  = 13
	otlpSeverityError = 17
)

// severityOf maps a decision to the severity a collector filters on: an allow
// is routine, a warn is worth a look, a denial is an incident. A decision this
// build does not know is not an "INFO".
func severityOf(decision Decision) (string, int) {
	switch decision {
	case DecisionAllow:
		return "INFO", otlpSeverityInfo
	case DecisionWarn:
		return "WARN", otlpSeverityWarn
	default:
		return "ERROR", otlpSeverityError
	}
}

// unixNanoOf converts a receipt timestamp (RFC 3339 UTC, millisecond
// precision) to the decimal nanoseconds OTLP records.
//
// A timestamp that will not parse falls back to observed, the moment the sink
// took the entry, rather than to zero: a record with no time at all is dropped
// by collectors, and the body still carries the entry's own timestamp
// verbatim.
func unixNanoOf(timestamp, observed string) string {
	instant, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return observed
	}
	return strconv.FormatInt(instant.UnixNano(), 10)
}

// nowUnixNano is the current time as the decimal nanoseconds OTLP records.
func nowUnixNano() string {
	return strconv.FormatInt(time.Now().UnixNano(), 10)
}

// logsEndpoint is "<endpoint>/v1/logs", without doubling a path the caller
// already gave.
//
// Anything that is not HTTP(S) is rejected up front: a sink that silently
// accepted a "file:" endpoint would turn a misconfiguration into evidence
// nobody is looking at.
func logsEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", errors.New("otlp sink: endpoint is required")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("otlp sink: endpoint %q: %w", endpoint, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf(
			"otlp sink: endpoint must be http:// or https://, got %q", endpoint)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("otlp sink: endpoint has no host: %q", endpoint)
	}
	trimmed := strings.TrimRight(endpoint, "/")
	if strings.HasSuffix(trimmed, "/v1/logs") {
		return trimmed, nil
	}
	return trimmed + "/v1/logs", nil
}
