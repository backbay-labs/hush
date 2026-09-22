//! OTLP/HTTP receipt sink: decision receipts and policy events as
//! OpenTelemetry logs.
//!
//! [`OtlpSink`] is a [`ReceiptSink`] that batches entries onto a background
//! thread and `POST`s them to an OpenTelemetry collector as OTLP/HTTP JSON at
//! `<endpoint>/v1/logs`. Evaluation never waits on the network: the sink hands
//! each entry to a bounded queue and returns.
//!
//! ```no_run
//! use hushspec::{HushGuard, OtlpSink, Policy};
//!
//! let guard = HushGuard::builder()
//!     .sink(Box::new(OtlpSink::new("http://localhost:4318")?))
//!     .build_from_policy(Policy::from_path("policy.yaml")?)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Wire mapping
//!
//! Normative for every HushSpec SDK: the four ports emit the same records, so
//! one collector pipeline and one set of dashboard queries work whichever SDK
//! wrote them.
//!
//! One `logRecord` per entry, in a single `resourceLogs` -> `scopeLogs`
//! envelope per request.
//!
//! | Log record field | Value |
//! |---|---|
//! | `timeUnixNano` | The receipt's (or policy event's) `timestamp`, as nanoseconds since the epoch, decimal string |
//! | `observedTimeUnixNano` | When the sink took the entry |
//! | `severityText` / `severityNumber` | `INFO` / 9 for `allow`, `WARN` / 13 for `warn`, `ERROR` / 17 for `deny`; a policy event is `INFO` |
//! | `body.stringValue` | The canonical JSON (RFC 8785) of the receipt, or of the policy event |
//!
//! Log record attributes -- absent members are omitted, never sent as null:
//!
//! | Attribute | Value |
//! |---|---|
//! | `hushspec.entry_type` | `receipt`, `policy_loaded` or `policy_swapped` |
//! | `hushspec.receipt_version` | `receipt.receipt_version` (receipts only) |
//! | `hushspec.decision` | `allow` / `warn` / `deny` (receipts only) |
//! | `hushspec.action_type` | `receipt.action.type` (receipts only) |
//! | `hushspec.matched_rule` | `receipt.matched_rule` (receipts only, when set) |
//! | `hushspec.policy.content_hash` | `policy.content_hash` |
//! | `hushspec.receipt_hash` | `sha256:` over the receipt's canonical form (receipts only) |
//! | `hushspec.enforcement.mode` | `enforce` / `monitor` |
//! | `hushspec.enforcement.outcome` | `allowed` / `confirmed` / `blocked` / `would_block` (receipts only) |
//!
//! Resource attributes:
//!
//! | Attribute | Value |
//! |---|---|
//! | `service.name` | [`OtlpConfig::service_name`], default `hushspec` |
//! | `hushspec.sdk` | `hushspec-rust` |
//! | `hushspec.sdk.version` | This crate's version |
//! | `hushspec.spec_version` | [`HUSHSPEC_VERSION`] |
//!
//! # Delivery
//!
//! Best-effort, and deliberately so: telemetry is not the audit trail. Pair an
//! OTLP sink with a [`ChainedFileSink`](crate::ChainedFileSink) through a
//! [`MultiSink`](crate::MultiSink) when the receipts are evidence.
//!
//! - **Bounded queue.** [`OtlpConfig::queue_capacity`] entries. When the
//!   collector is slower than the agent, the *newest* entry is dropped rather
//!   than blocking the evaluation that produced it. Every drop increments
//!   [`OtlpSink::dropped`], returns an error from `send()`, and -- with
//!   [`OtlpSink::with_observer`] -- raises a `sink.error` observer event.
//! - **Retries.** A `5xx` or a transport error is retried up to
//!   [`OtlpConfig::max_retries`] times with exponential backoff. A `4xx` is
//!   not: the collector rejected the payload and resending it will not help.
//! - **Flush.** The worker exports when the batch reaches
//!   [`OtlpConfig::batch_size`] or [`OtlpConfig::flush_interval`] elapses.
//!   [`OtlpSink::flush`] blocks until the queue is exported, and dropping the
//!   sink flushes and joins the worker.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::canonical;
use crate::evaluate::Decision;
use crate::log::{PolicyEvent, PolicyEventKind};
use crate::observer::{ErrorEvent, EvaluationObserver};
use crate::receipt::{DecisionReceipt, EnforcementMode, EnforcementOutcome};
use crate::sink::{ReceiptSink, SinkError};
use crate::version::HUSHSPEC_VERSION;

/// The `hushspec.sdk` resource attribute this SDK reports.
pub const SDK_NAME: &str = "hushspec-rust";

/// How to reach the collector and how hard to try.
#[derive(Clone, Debug)]
pub struct OtlpConfig {
    /// Collector base URL. `/v1/logs` is appended; a trailing slash is fine.
    /// Plain `http` is accepted -- a collector is usually a sidecar on
    /// loopback -- so use `https` when it is not.
    pub endpoint: String,
    /// Extra request headers (an API key, a tenant id).
    pub headers: Vec<(String, String)>,
    /// Export once this many entries are queued.
    pub batch_size: usize,
    /// Export at least this often, even with a part-full batch.
    pub flush_interval: Duration,
    /// Per-request timeout.
    pub timeout: Duration,
    /// How many entries may wait to be exported before the newest is dropped.
    pub queue_capacity: usize,
    /// Retries after a `5xx` or a transport error.
    pub max_retries: u32,
    /// The `service.name` resource attribute.
    pub service_name: String,
}

impl OtlpConfig {
    /// Defaults for `endpoint`: 64-entry batches, a 5-second flush interval, a
    /// 10-second timeout, a 2048-entry queue, 3 retries, `service.name` of
    /// `hushspec`.
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            headers: Vec::new(),
            batch_size: 64,
            flush_interval: Duration::from_secs(5),
            timeout: Duration::from_secs(10),
            queue_capacity: 2048,
            max_retries: 3,
            service_name: "hushspec".to_string(),
        }
    }

    /// Add a request header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the `service.name` resource attribute.
    #[must_use]
    pub fn with_service_name(mut self, name: impl Into<String>) -> Self {
        self.service_name = name.into();
        self
    }

    /// Export once `size` entries are queued.
    #[must_use]
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Export at least this often.
    #[must_use]
    pub fn with_flush_interval(mut self, interval: Duration) -> Self {
        self.flush_interval = interval;
        self
    }

    /// The URL entries are posted to.
    #[must_use]
    pub fn logs_url(&self) -> String {
        format!("{}/v1/logs", self.endpoint.trim_end_matches('/'))
    }
}

/// One thing to export, stamped with the moment the sink took it.
#[derive(Clone, Debug)]
struct Entry {
    observed: u64,
    payload: Payload,
}

impl Entry {
    fn new(payload: Payload) -> Self {
        Self {
            observed: nanos_now(),
            payload,
        }
    }
}

#[derive(Clone, Debug)]
enum Payload {
    Receipt(Box<DecisionReceipt>),
    Policy(Box<PolicyEvent>),
}

enum Message {
    Entry(Box<Entry>),
    /// Export everything queued, then acknowledge.
    Flush(mpsc::Sender<()>),
}

/// Exports receipts and policy events to an OpenTelemetry collector. See the
/// module documentation for the wire mapping and the delivery guarantees.
pub struct OtlpSink {
    sender: Option<mpsc::SyncSender<Message>>,
    counters: Arc<Counters>,
    observer: Option<Arc<dyn EvaluationObserver>>,
    endpoint: String,
    worker: Option<std::thread::JoinHandle<()>>,
}

#[derive(Debug, Default)]
struct Counters {
    dropped: AtomicU64,
    exported: AtomicU64,
    failed: AtomicU64,
}

impl std::fmt::Debug for OtlpSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtlpSink")
            .field("endpoint", &self.endpoint)
            .field("dropped", &self.dropped())
            .field("exported", &self.exported())
            .finish()
    }
}

impl OtlpSink {
    /// Export to `endpoint` with [`OtlpConfig::new`]'s defaults.
    ///
    /// # Errors
    ///
    /// [`SinkError::Io`] when the HTTP client or the worker thread cannot be
    /// created.
    pub fn new(endpoint: impl Into<String>) -> Result<Self, SinkError> {
        Self::with_config(OtlpConfig::new(endpoint))
    }

    /// Export with an explicit configuration.
    ///
    /// # Errors
    ///
    /// As [`OtlpSink::new`].
    pub fn with_config(config: OtlpConfig) -> Result<Self, SinkError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|error| SinkError::Io(std::io::Error::other(error)))?;

        let counters = Arc::new(Counters::default());
        let (sender, receiver) = mpsc::sync_channel::<Message>(config.queue_capacity.max(1));
        let endpoint = config.endpoint.clone();
        let worker_counters = counters.clone();
        let worker = std::thread::Builder::new()
            .name("hushspec-otlp".to_string())
            .spawn(move || run_worker(&receiver, &client, &config, &worker_counters))
            .map_err(SinkError::Io)?;

        Ok(Self {
            sender: Some(sender),
            counters,
            observer: None,
            endpoint,
            worker: Some(worker),
        })
    }

    /// Report dropped batches and failed exports to `observer` as `sink.error`
    /// events.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn EvaluationObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Entries dropped because the queue was full.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.counters.dropped.load(Ordering::Relaxed)
    }

    /// Entries the collector accepted.
    #[must_use]
    pub fn exported(&self) -> u64 {
        self.counters.exported.load(Ordering::Relaxed)
    }

    /// Entries that could not be exported after every retry.
    #[must_use]
    pub fn failed(&self) -> u64 {
        self.counters.failed.load(Ordering::Relaxed)
    }

    /// Block until everything queued so far has been exported (or given up
    /// on). Returns `false` if the worker is gone.
    pub fn flush(&self) -> bool {
        let Some(sender) = self.sender.as_ref() else {
            return false;
        };
        let (ack, done) = mpsc::channel();
        if sender.send(Message::Flush(ack)).is_err() {
            return false;
        }
        done.recv().is_ok()
    }

    fn enqueue(&self, payload: Payload) -> Result<(), SinkError> {
        let entry = Entry::new(payload);
        let Some(sender) = self.sender.as_ref() else {
            return Err(SinkError::Io(std::io::Error::other(
                "OTLP sink is shut down",
            )));
        };
        if sender.try_send(Message::Entry(Box::new(entry))).is_ok() {
            return Ok(());
        }
        // Full (or closed): drop rather than stall the evaluation that
        // produced this entry. The counter and the observer make the gap
        // visible; the return value tells the caller this one is gone.
        let dropped = self.counters.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(observer) = self.observer.as_ref() {
            observer.on_error(&ErrorEvent::sink_error(
                format!("OTLP queue full: {dropped} entries dropped"),
                Some(self.endpoint.clone()),
            ));
        }
        Err(SinkError::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "OTLP export queue is full; entry dropped",
        )))
    }
}

impl ReceiptSink for OtlpSink {
    fn send(&self, receipt: &DecisionReceipt) -> Result<(), SinkError> {
        self.enqueue(Payload::Receipt(Box::new(receipt.clone())))
    }

    fn record_policy_event(&self, event: &PolicyEvent) -> Result<(), SinkError> {
        self.enqueue(Payload::Policy(Box::new(event.clone())))
    }
}

impl Drop for OtlpSink {
    /// Flush what is queued and join the worker, so a process that exits right
    /// after a denial still exports the receipt for it.
    fn drop(&mut self) {
        // Dropping the sender ends the worker's loop after it drains.
        self.sender = None;
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

// --------------------------------------------------------------------------
// Worker
// --------------------------------------------------------------------------

fn run_worker(
    receiver: &mpsc::Receiver<Message>,
    client: &reqwest::blocking::Client,
    config: &OtlpConfig,
    counters: &Counters,
) {
    let url = config.logs_url();
    let mut batch: Vec<Entry> = Vec::with_capacity(config.batch_size);
    let mut deadline = Instant::now() + config.flush_interval;

    loop {
        let wait = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(wait) {
            Ok(Message::Entry(entry)) => {
                batch.push(*entry);
                if batch.len() >= config.batch_size.max(1) {
                    export(client, &url, config, counters, &mut batch);
                    deadline = Instant::now() + config.flush_interval;
                }
            }
            Ok(Message::Flush(ack)) => {
                // Take everything already queued, so `flush()` means "queued
                // before this call" and not merely "batched so far".
                while let Ok(Message::Entry(entry)) = receiver.try_recv() {
                    batch.push(*entry);
                }
                export(client, &url, config, counters, &mut batch);
                deadline = Instant::now() + config.flush_interval;
                let _ = ack.send(());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                export(client, &url, config, counters, &mut batch);
                deadline = Instant::now() + config.flush_interval;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                export(client, &url, config, counters, &mut batch);
                return;
            }
        }
    }
}

fn export(
    client: &reqwest::blocking::Client,
    url: &str,
    config: &OtlpConfig,
    counters: &Counters,
    batch: &mut Vec<Entry>,
) {
    if batch.is_empty() {
        return;
    }
    let count = batch.len() as u64;
    let payload = request_body(batch, config);
    batch.clear();

    let Ok(body) = serde_json::to_vec(&payload) else {
        counters.failed.fetch_add(count, Ordering::Relaxed);
        return;
    };

    let mut backoff = Duration::from_millis(100);
    for attempt in 0..=config.max_retries {
        let mut request = client
            .post(url)
            .header("content-type", "application/json")
            .body(body.clone());
        for (name, value) in &config.headers {
            request = request.header(name.as_str(), value.as_str());
        }

        match request.send() {
            Ok(response) if response.status().is_success() => {
                counters.exported.fetch_add(count, Ordering::Relaxed);
                return;
            }
            // The collector rejected the payload itself. Resending the same
            // bytes cannot make it acceptable, so give up rather than burn
            // retries on a permanent failure.
            Ok(response) if response.status().is_client_error() => break,
            Ok(_) | Err(_) => {}
        }

        if attempt < config.max_retries {
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(Duration::from_secs(5));
        }
    }
    counters.failed.fetch_add(count, Ordering::Relaxed);
}

// --------------------------------------------------------------------------
// Wire mapping
// --------------------------------------------------------------------------

/// The OTLP/HTTP JSON `ExportLogsServiceRequest` for `batch`.
fn request_body(batch: &[Entry], config: &OtlpConfig) -> Value {
    let records: Vec<Value> = batch.iter().map(log_record).collect();

    json!({
        "resourceLogs": [{
            "resource": {
                "attributes": [
                    attribute("service.name", &config.service_name),
                    attribute("hushspec.sdk", SDK_NAME),
                    attribute("hushspec.sdk.version", env!("CARGO_PKG_VERSION")),
                    attribute("hushspec.spec_version", HUSHSPEC_VERSION),
                ],
            },
            "scopeLogs": [{
                "scope": { "name": SDK_NAME, "version": env!("CARGO_PKG_VERSION") },
                "logRecords": records,
            }],
        }],
    })
}

fn log_record(entry: &Entry) -> Value {
    let observed = entry.observed;
    let mut attributes = Vec::new();
    let (timestamp, severity_text, severity_number, body) = match &entry.payload {
        Payload::Receipt(receipt) => {
            attributes.push(attribute("hushspec.entry_type", "receipt"));
            attributes.push(attribute(
                "hushspec.receipt_version",
                &receipt.receipt_version,
            ));
            attributes.push(attribute(
                "hushspec.decision",
                decision_text(receipt.decision),
            ));
            attributes.push(attribute(
                "hushspec.action_type",
                &receipt.action.action_type,
            ));
            if let Some(matched) = receipt.matched_rule.as_deref() {
                attributes.push(attribute("hushspec.matched_rule", matched));
            }
            attributes.push(attribute(
                "hushspec.policy.content_hash",
                &receipt.policy.content_hash,
            ));
            if let Ok(hash) = receipt.receipt_hash() {
                attributes.push(attribute("hushspec.receipt_hash", &hash));
            }
            attributes.push(attribute(
                "hushspec.enforcement.mode",
                mode_text(receipt.enforcement.mode),
            ));
            attributes.push(attribute(
                "hushspec.enforcement.outcome",
                outcome_text(receipt.enforcement.outcome),
            ));
            let (text, number) = severity(receipt.decision);
            (
                receipt.timestamp.as_str(),
                text,
                number,
                receipt.canonical_json().unwrap_or_default(),
            )
        }
        Payload::Policy(event) => {
            attributes.push(attribute(
                "hushspec.entry_type",
                match event.event {
                    PolicyEventKind::Loaded => "policy_loaded",
                    PolicyEventKind::Swapped => "policy_swapped",
                },
            ));
            attributes.push(attribute(
                "hushspec.policy.content_hash",
                &event.policy.content_hash,
            ));
            attributes.push(attribute(
                "hushspec.enforcement.mode",
                mode_text(event.enforcement_mode),
            ));
            (
                event.timestamp.as_str(),
                "INFO",
                9,
                canonical_of(event).unwrap_or_default(),
            )
        }
    };

    json!({
        "timeUnixNano": nanos_of(timestamp).unwrap_or(observed).to_string(),
        "observedTimeUnixNano": observed.to_string(),
        "severityNumber": severity_number,
        "severityText": severity_text,
        "body": { "stringValue": body },
        "attributes": attributes,
    })
}

fn attribute(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": value } })
}

fn canonical_of<T: serde::Serialize>(value: &T) -> Option<String> {
    let value = serde_json::to_value(value).ok()?;
    canonical::serialize_jcs(&value).ok()
}

/// `INFO` for a decision that let the action through, `WARN` for one that asked
/// a human, `ERROR` for one that stopped it -- so a collector's default
/// severity filters surface denials without a custom rule.
fn severity(decision: Decision) -> (&'static str, i64) {
    match decision {
        Decision::Allow => ("INFO", 9),
        Decision::Warn => ("WARN", 13),
        Decision::Deny => ("ERROR", 17),
    }
}

fn decision_text(decision: Decision) -> &'static str {
    crate::observer::decision_label(decision)
}

fn mode_text(mode: EnforcementMode) -> &'static str {
    match mode {
        EnforcementMode::Enforce => "enforce",
        EnforcementMode::Monitor => "monitor",
    }
}

fn outcome_text(outcome: EnforcementOutcome) -> &'static str {
    match outcome {
        EnforcementOutcome::Allowed => "allowed",
        EnforcementOutcome::Confirmed => "confirmed",
        EnforcementOutcome::Blocked => "blocked",
        EnforcementOutcome::WouldBlock => "would_block",
    }
}

fn nanos_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos() as u64)
}

/// Nanoseconds since the epoch for an RFC 3339 timestamp, or `None` when it
/// will not parse or predates the epoch.
fn nanos_of(timestamp: &str) -> Option<u64> {
    let parsed = chrono::DateTime::parse_from_rfc3339(timestamp).ok()?;
    u64::try_from(parsed.timestamp_nanos_opt()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluate::EvaluationAction;
    use crate::receipt::{AuditConfig, AuditContext};
    use crate::resolve::Resolution;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Mutex;

    /// A one-request-at-a-time HTTP stub that records each body it is posted.
    struct Collector {
        endpoint: String,
        bodies: Arc<Mutex<Vec<Value>>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Collector {
        /// Serve `statuses` in order, then `200` for everything after.
        fn start(statuses: Vec<u16>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            listener
                .set_nonblocking(true)
                .expect("nonblocking so the thread can notice `stop`");
            let bodies = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

            let thread = {
                let bodies = bodies.clone();
                let stop = stop.clone();
                std::thread::spawn(move || {
                    let mut remaining = statuses.into_iter();
                    while !stop.load(Ordering::SeqCst) {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                let status = remaining.next().unwrap_or(200);
                                serve(stream, status, &bodies);
                            }
                            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(5));
                            }
                            Err(_) => return,
                        }
                    }
                })
            };

            Self {
                endpoint: format!("http://127.0.0.1:{port}"),
                bodies,
                stop,
                thread: Some(thread),
            }
        }

        fn bodies(&self) -> Vec<Value> {
            self.bodies.lock().expect("lock").clone()
        }

        fn requests(&self) -> usize {
            self.bodies.lock().expect("lock").len()
        }
    }

    impl Drop for Collector {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn serve(mut stream: TcpStream, status: u16, bodies: &Arc<Mutex<Vec<Value>>>) {
        stream
            .set_nonblocking(false)
            .expect("blocking reads on an accepted connection");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut length = 0usize;
        let mut path = String::new();
        let mut line = String::new();
        // Request line, then headers until the blank line.
        if reader.read_line(&mut line).is_ok() {
            path = line.split_whitespace().nth(1).unwrap_or("").to_string();
        }
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some(value) = trimmed
                        .strip_prefix("content-length:")
                        .or_else(|| trimmed.strip_prefix("Content-Length:"))
                    {
                        length = value.trim().parse().unwrap_or(0);
                    }
                }
                Err(_) => break,
            }
        }
        let mut body = vec![0u8; length];
        if reader.read_exact(&mut body).is_ok()
            && let Ok(mut value) = serde_json::from_slice::<Value>(&body)
        {
            // Carry the path along so a test can assert the /v1/logs suffix.
            if let Some(object) = value.as_object_mut() {
                object.insert("__path".to_string(), json!(path));
            }
            bodies.lock().expect("lock").push(value);
        }
        let _ = write!(
            stream,
            "HTTP/1.1 {status} X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        );
        let _ = stream.flush();
    }

    fn receipt(decision_target: &str) -> DecisionReceipt {
        let spec = crate::HushSpec::parse(
            r#"hushspec: "0.1.0"
name: otlp-test
rules:
  egress:
    allow: ["*.example.com"]
    default: block
"#,
        )
        .expect("parses");
        let resolution = Resolution::from_resolved(&spec, Some("memory")).expect("resolves");
        let action = EvaluationAction {
            action_type: "egress".to_string(),
            target: Some(decision_target.to_string()),
            ..Default::default()
        };
        crate::receipt::evaluate_audited(
            &resolution,
            &action,
            &AuditConfig::default(),
            &AuditContext::default(),
        )
    }

    fn one_record(bodies: &[Value]) -> Value {
        bodies[0]["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0].clone()
    }

    fn attributes(record: &Value) -> std::collections::BTreeMap<String, String> {
        record["attributes"]
            .as_array()
            .expect("attributes")
            .iter()
            .map(|attribute| {
                (
                    attribute["key"].as_str().expect("key").to_string(),
                    attribute["value"]["stringValue"]
                        .as_str()
                        .expect("stringValue")
                        .to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn posts_a_receipt_to_v1_logs_in_the_documented_shape() {
        let collector = Collector::start(vec![]);
        let sink = OtlpSink::with_config(
            OtlpConfig::new(&collector.endpoint)
                .with_batch_size(1)
                .with_service_name("agent-gateway"),
        )
        .expect("builds");

        let denied = receipt("evil.test");
        assert_eq!(denied.decision, Decision::Deny);
        sink.send(&denied).expect("queued");
        assert!(sink.flush(), "flush waits for the export");

        let bodies = collector.bodies();
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0]["__path"], "/v1/logs");

        let resource = &bodies[0]["resourceLogs"][0]["resource"];
        let resource_attributes: std::collections::BTreeMap<String, String> =
            resource["attributes"]
                .as_array()
                .expect("attributes")
                .iter()
                .map(|a| {
                    (
                        a["key"].as_str().expect("key").to_string(),
                        a["value"]["stringValue"].as_str().expect("v").to_string(),
                    )
                })
                .collect();
        assert_eq!(resource_attributes["service.name"], "agent-gateway");
        assert_eq!(resource_attributes["hushspec.sdk"], "hushspec-rust");
        assert_eq!(
            resource_attributes["hushspec.sdk.version"],
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(
            resource_attributes["hushspec.spec_version"],
            HUSHSPEC_VERSION
        );

        let record = one_record(&bodies);
        assert_eq!(record["severityText"], "ERROR");
        assert_eq!(record["severityNumber"], 17);
        assert_eq!(
            record["timeUnixNano"].as_str().expect("string"),
            nanos_of(&denied.timestamp).expect("parses").to_string(),
            "the record is stamped with the receipt's own timestamp, not the export time"
        );

        let body = record["body"]["stringValue"].as_str().expect("body");
        assert_eq!(
            body,
            denied.canonical_json().expect("canonical"),
            "the body is the receipt's canonical form, byte for byte"
        );
        let parsed: DecisionReceipt = serde_json::from_str(body).expect("round-trips");
        assert_eq!(parsed, denied);

        let attributes = attributes(&record);
        assert_eq!(attributes["hushspec.entry_type"], "receipt");
        assert_eq!(
            attributes["hushspec.receipt_version"],
            denied.receipt_version
        );
        assert_eq!(attributes["hushspec.decision"], "deny");
        assert_eq!(attributes["hushspec.action_type"], "egress");
        assert_eq!(attributes["hushspec.matched_rule"], "rules.egress.default");
        assert_eq!(
            attributes["hushspec.policy.content_hash"],
            denied.policy.content_hash
        );
        assert_eq!(
            attributes["hushspec.receipt_hash"],
            denied.receipt_hash().expect("hash")
        );
        assert_eq!(attributes["hushspec.enforcement.mode"], "enforce");
        assert_eq!(attributes["hushspec.enforcement.outcome"], "blocked");
        assert_eq!(sink.exported(), 1);
    }

    /// The `logRecord` members every HushSpec SDK's exporter emits, so one
    /// collector pipeline reads all four (see the module's wire mapping).
    const LOG_RECORD_MEMBERS: [&str; 6] = [
        "timeUnixNano",
        "observedTimeUnixNano",
        "severityNumber",
        "severityText",
        "body",
        "attributes",
    ];

    #[test]
    fn a_receipt_and_a_policy_event_carry_the_same_record_members() {
        let receipt = receipt("evil.test");
        let event = PolicyEvent::loaded(receipt.policy.clone(), EnforcementMode::Enforce);
        let entries = [
            Entry::new(Payload::Receipt(Box::new(receipt))),
            Entry::new(Payload::Policy(Box::new(event))),
        ];
        let mut expected = LOG_RECORD_MEMBERS.to_vec();
        expected.sort_unstable();

        for entry in &entries {
            let record = log_record(entry);
            let mut members: Vec<&str> = record
                .as_object()
                .expect("a record is an object")
                .keys()
                .map(String::as_str)
                .collect();
            members.sort_unstable();
            assert_eq!(members, expected);
        }
    }

    #[test]
    fn maps_each_decision_to_its_severity() {
        for (decision, text, number) in [
            (Decision::Allow, "INFO", 9),
            (Decision::Warn, "WARN", 13),
            (Decision::Deny, "ERROR", 17),
        ] {
            assert_eq!(severity(decision), (text, number));
        }
    }

    #[test]
    fn a_policy_event_carries_its_own_entry_type_and_no_receipt_members() {
        let collector = Collector::start(vec![]);
        let sink = OtlpSink::with_config(OtlpConfig::new(&collector.endpoint).with_batch_size(1))
            .expect("builds");

        let summary = receipt("evil.test").policy;
        let event = PolicyEvent::swapped(
            summary.clone(),
            EnforcementMode::Monitor,
            "sha256:old".into(),
        );
        sink.record_policy_event(&event).expect("queued");
        assert!(sink.flush());

        let record = one_record(&collector.bodies());
        assert_eq!(record["severityText"], "INFO");
        let attributes = attributes(&record);
        assert_eq!(attributes["hushspec.entry_type"], "policy_swapped");
        assert_eq!(
            attributes["hushspec.policy.content_hash"],
            summary.content_hash
        );
        assert_eq!(attributes["hushspec.enforcement.mode"], "monitor");
        assert!(!attributes.contains_key("hushspec.decision"));
        assert!(!attributes.contains_key("hushspec.receipt_hash"));

        let body = record["body"]["stringValue"].as_str().expect("body");
        let parsed: PolicyEvent = serde_json::from_str(body).expect("round-trips");
        assert_eq!(parsed, event);
    }

    #[test]
    fn batches_several_entries_into_one_request() {
        let collector = Collector::start(vec![]);
        let sink = OtlpSink::with_config(
            OtlpConfig::new(&collector.endpoint)
                .with_batch_size(16)
                .with_flush_interval(Duration::from_secs(60)),
        )
        .expect("builds");

        let allowed = receipt("api.example.com");
        for _ in 0..5 {
            sink.send(&allowed).expect("queued");
        }
        assert_eq!(collector.requests(), 0, "a part-full batch waits");
        assert!(sink.flush());

        let bodies = collector.bodies();
        assert_eq!(bodies.len(), 1, "one request for the whole batch");
        let records = bodies[0]["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
            .as_array()
            .expect("records");
        assert_eq!(records.len(), 5);
        assert_eq!(sink.exported(), 5);
    }

    #[test]
    fn retries_a_5xx_and_gives_up_on_a_4xx() {
        let collector = Collector::start(vec![503, 500]);
        let sink = OtlpSink::with_config(OtlpConfig::new(&collector.endpoint).with_batch_size(1))
            .expect("builds");
        sink.send(&receipt("evil.test")).expect("queued");
        assert!(sink.flush());
        assert_eq!(collector.requests(), 3, "two failures, then success");
        assert_eq!(sink.exported(), 1);
        assert_eq!(sink.failed(), 0);
        drop(sink);

        let collector = Collector::start(vec![400]);
        let sink = OtlpSink::with_config(OtlpConfig::new(&collector.endpoint).with_batch_size(1))
            .expect("builds");
        sink.send(&receipt("evil.test")).expect("queued");
        assert!(sink.flush());
        assert_eq!(
            collector.requests(),
            1,
            "a rejected payload is not worth resending"
        );
        assert_eq!(sink.failed(), 1);
        assert_eq!(sink.exported(), 0);
    }

    #[test]
    fn a_full_queue_drops_rather_than_blocking_the_evaluation() {
        #[derive(Default)]
        struct Errors(Mutex<Vec<String>>);
        impl EvaluationObserver for Errors {
            fn on_error(&self, event: &ErrorEvent) {
                self.0.lock().expect("lock").push(event.error.clone());
            }
        }

        // The collector accepts every connection and never answers, so the
        // worker is held on its first request for the whole of the send loop
        // and the one-entry queue stays full however the threads are scheduled.
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        listener.set_nonblocking(true).expect("nonblocking");
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stalled = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut held = Vec::new();
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => held.push(stream),
                        Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => return,
                    }
                }
            })
        };

        // A batch of one makes the worker send each entry as it arrives, so it
        // is blocked on the stalled request from its first entry onward and
        // the sender, not the worker, decides when the queue is full.
        let observer = Arc::new(Errors::default());
        let sink = OtlpSink::with_config(OtlpConfig {
            queue_capacity: 1,
            batch_size: 1,
            flush_interval: Duration::from_secs(60),
            timeout: Duration::from_millis(500),
            max_retries: 0,
            ..OtlpConfig::new(format!("http://127.0.0.1:{port}"))
        })
        .expect("builds")
        .with_observer(observer.clone());

        let denied = receipt("evil.test");
        let mut refused = 0;
        for _ in 0..64 {
            if sink.send(&denied).is_err() {
                refused += 1;
            }
        }
        assert!(refused > 0, "a full queue must refuse rather than block");
        assert_eq!(sink.dropped(), refused);
        {
            let errors = observer.0.lock().expect("lock");
            assert_eq!(errors.len() as u64, sink.dropped());
            assert!(errors[0].contains("queue full"), "{}", errors[0]);
        }

        drop(sink);
        stop.store(true, Ordering::SeqCst);
        stalled.join().expect("collector thread");
    }

    #[test]
    fn dropping_the_sink_flushes_what_is_queued() {
        let collector = Collector::start(vec![]);
        let sink = OtlpSink::with_config(
            OtlpConfig::new(&collector.endpoint)
                .with_batch_size(1024)
                .with_flush_interval(Duration::from_secs(60)),
        )
        .expect("builds");
        sink.send(&receipt("evil.test")).expect("queued");
        assert_eq!(collector.requests(), 0);
        drop(sink);
        assert_eq!(
            collector.requests(),
            1,
            "a process exiting after a denial still exports its receipt"
        );
    }

    #[test]
    fn the_logs_url_tolerates_a_trailing_slash() {
        assert_eq!(
            OtlpConfig::new("http://collector:4318/").logs_url(),
            "http://collector:4318/v1/logs"
        );
        assert_eq!(
            OtlpConfig::new("https://collector.example.com").logs_url(),
            "https://collector.example.com/v1/logs"
        );
    }

    #[test]
    fn configured_headers_reach_the_collector() {
        // A stub that keeps the raw header block rather than the JSON body.
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let seen = Arc::new(Mutex::new(String::new()));
        let captured = seen.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
                    break;
                }
                headers.push_str(&line);
            }
            *captured.lock().expect("lock") = headers;
            let _ = write!(
                stream,
                "HTTP/1.1 200 X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            );
        });

        let sink = OtlpSink::with_config(
            OtlpConfig::new(format!("http://127.0.0.1:{port}"))
                .with_batch_size(1)
                .with_header("x-api-key", "s3cret"),
        )
        .expect("builds");
        sink.send(&receipt("evil.test")).expect("queued");
        sink.flush();
        server.join().expect("stub finished");

        let headers = seen.lock().expect("lock").to_lowercase();
        assert!(headers.contains("x-api-key: s3cret"), "{headers}");
        assert!(
            headers.contains("content-type: application/json"),
            "{headers}"
        );
    }
}
