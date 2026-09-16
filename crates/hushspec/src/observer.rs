//! Evaluation observers: the read-only stream of what an enforcement point
//! decided.
//!
//! An observer sees every decision a [`HushGuard`](crate::HushGuard) makes and
//! every policy it loads, but never changes one. Receipts are the *evidence*
//! channel (durable, hash-linked, spec'd); observers are the *telemetry*
//! channel (best-effort, structured, cheap), and a guard drives both from the
//! same evaluation.
//!
//! Three hooks, one per kind of event:
//!
//! - [`EvaluationObserver::on_policy_loaded`] -- a policy came into force
//! - [`EvaluationObserver::on_evaluation`] -- an action was decided
//! - [`EvaluationObserver::on_error`] -- a load or an export failed
//!
//! Every method has a no-op default, so an observer implements only what it
//! cares about. Batteries included: [`JsonLineObserver`] (JSON Lines to any
//! writer), [`StderrObserver`], [`MetricsCollector`] (counters, a latency
//! histogram, and Prometheus text exposition), and -- behind the `http`
//! feature -- [`WebhookObserver`].
//!
//! ```
//! use hushspec::{EvaluationObserver, MetricsCollector};
//! use std::sync::Arc;
//!
//! let metrics = Arc::new(MetricsCollector::new());
//! // guard.builder().observer(metrics.clone()) ...
//! println!("{}", metrics.render_prometheus());
//! ```
//!
//! # Content is never carried
//!
//! An [`EvaluationAction`]'s `content` is stripped before it reaches an
//! observer, exactly as a receipt records only its hash and size (receipt spec
//! 4.4). [`EvaluationCompletedEvent::content_redacted`] records that it
//! happened.
//!
//! # Observers must not panic
//!
//! An observer runs inline on the evaluation thread. A panicking observer
//! takes the caller down with it; there is no `catch_unwind` around these
//! hooks because swallowing a panic would leave the observer in an unknown
//! state. Do the fallible work off-thread (see [`WebhookObserver`]).

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Mutex;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::evaluate::{Decision, EvaluationAction, EvaluationResult};
use crate::guard::top_segment as segment;
use crate::receipt::{DecisionReceipt, EnforcementSummary, format_timestamp};

/// What an [`ObserverEvent`] is about. The wire spelling matches the
/// TypeScript and Python SDKs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObserverEventType {
    /// An action was evaluated.
    #[serde(rename = "evaluation.completed")]
    EvaluationCompleted,
    /// A policy came into force for the first time.
    #[serde(rename = "policy.loaded")]
    PolicyLoaded,
    /// A policy replaced one already in force.
    #[serde(rename = "policy.reloaded")]
    PolicyReloaded,
    /// A policy could not be loaded; the previous one stays in force.
    #[serde(rename = "policy.load_failed")]
    PolicyLoadFailed,
    /// A sink could not record what it was handed; the decision it belonged
    /// to stands and the policy still takes effect.
    #[serde(rename = "sink.error")]
    SinkError,
}

impl ObserverEventType {
    /// The wire spelling, for a metrics key or a log line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EvaluationCompleted => "evaluation.completed",
            Self::PolicyLoaded => "policy.loaded",
            Self::PolicyReloaded => "policy.reloaded",
            Self::PolicyLoadFailed => "policy.load_failed",
            Self::SinkError => "sink.error",
        }
    }
}

/// A policy came into force.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyLoadedEvent {
    /// [`ObserverEventType::PolicyLoaded`] or
    /// [`ObserverEventType::PolicyReloaded`].
    #[serde(rename = "type")]
    pub event_type: ObserverEventType,
    /// RFC 3339 UTC, millisecond precision.
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    /// Canonical content hash of the resolved policy (`sha256:` + hex) -- the
    /// same value its receipts carry in `policy.content_hash`.
    pub content_hash: String,
    /// For a reload: the hash of the policy that was replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
}

impl PolicyLoadedEvent {
    /// A first load, stamped now.
    #[must_use]
    pub fn loaded(policy_name: Option<String>, content_hash: String) -> Self {
        Self {
            event_type: ObserverEventType::PolicyLoaded,
            timestamp: format_timestamp(Utc::now()),
            policy_name,
            content_hash,
            previous_hash: None,
        }
    }

    /// A hot swap, stamped now.
    #[must_use]
    pub fn reloaded(
        policy_name: Option<String>,
        content_hash: String,
        previous_hash: Option<String>,
    ) -> Self {
        Self {
            event_type: ObserverEventType::PolicyReloaded,
            previous_hash,
            ..Self::loaded(policy_name, content_hash)
        }
    }
}

/// An action was evaluated.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvaluationCompletedEvent {
    /// Always [`ObserverEventType::EvaluationCompleted`].
    #[serde(rename = "type")]
    pub event_type: ObserverEventType,
    /// RFC 3339 UTC, millisecond precision.
    pub timestamp: String,
    /// The action, with `content` stripped (see the module docs).
    pub action: EvaluationAction,
    /// True when `action.content` was present and removed. Rust carries the
    /// flag on the event rather than on the action, because
    /// [`EvaluationAction`] is a closed (`deny_unknown_fields`) wire type.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub content_redacted: bool,
    pub result: EvaluationResult,
    /// Wall time of the evaluation.
    pub duration_us: u64,
    /// What the enforcement point did, when a guard drove the evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement: Option<EnforcementSummary>,
    /// The receipt, when one was built.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<DecisionReceipt>,
}

/// A load or an export failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorEvent {
    /// [`ObserverEventType::PolicyLoadFailed`] or
    /// [`ObserverEventType::SinkError`].
    #[serde(rename = "type")]
    pub event_type: ObserverEventType,
    /// RFC 3339 UTC, millisecond precision.
    pub timestamp: String,
    pub error: String,
    /// What failed: a policy source, or a sink name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl ErrorEvent {
    /// A policy that would not load, stamped now.
    #[must_use]
    pub fn load_failed(error: impl Into<String>, source: Option<String>) -> Self {
        Self {
            event_type: ObserverEventType::PolicyLoadFailed,
            timestamp: format_timestamp(Utc::now()),
            error: error.into(),
            source,
        }
    }

    /// A sink that could not export, stamped now.
    #[must_use]
    pub fn sink_error(error: impl Into<String>, source: Option<String>) -> Self {
        Self {
            event_type: ObserverEventType::SinkError,
            ..Self::load_failed(error, source)
        }
    }
}

/// Any observer event, for an observer that treats them uniformly (a JSON
/// Lines writer, say). Serializes as the inner event: the `type` member is
/// already on it.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ObserverEvent<'a> {
    Policy(&'a PolicyLoadedEvent),
    Evaluation(&'a EvaluationCompletedEvent),
    Error(&'a ErrorEvent),
}

impl ObserverEvent<'_> {
    /// The event's type discriminant.
    #[must_use]
    pub fn event_type(&self) -> ObserverEventType {
        match self {
            Self::Policy(event) => event.event_type,
            Self::Evaluation(event) => event.event_type,
            Self::Error(event) => event.event_type,
        }
    }

    /// When the event was raised (RFC 3339 UTC).
    #[must_use]
    pub fn timestamp(&self) -> &str {
        match self {
            Self::Policy(event) => &event.timestamp,
            Self::Evaluation(event) => &event.timestamp,
            Self::Error(event) => &event.timestamp,
        }
    }
}

/// A sink for telemetry about evaluation. See the module docs.
pub trait EvaluationObserver: Send + Sync {
    /// A policy came into force (first load or hot swap).
    fn on_policy_loaded(&self, _event: &PolicyLoadedEvent) {}

    /// An action was decided. `event.receipt` is present when the guard built
    /// one; `event.duration_us` is the evaluation's wall time.
    fn on_evaluation(&self, _event: &EvaluationCompletedEvent) {}

    /// A load or an export failed.
    fn on_error(&self, _event: &ErrorEvent) {}
}

// --------------------------------------------------------------------------
// Fan-out
// --------------------------------------------------------------------------

/// Fans every event out to a list of observers, and times plain evaluations.
///
/// A [`HushGuard`](crate::HushGuard) holds one of these; a caller who wants
/// observability without enforcement can drive it directly:
///
/// ```
/// use hushspec::{EvaluationAction, ObservableEvaluator, Policy, StderrObserver};
/// use std::sync::Arc;
///
/// let policy = Policy::from_str("hushspec: \"0.1.0\"\n")?.compile()?;
/// let mut evaluator = ObservableEvaluator::new();
/// evaluator.add_observer(Arc::new(StderrObserver::deny_only()));
///
/// let action = EvaluationAction {
///     action_type: "tool_call".to_string(),
///     target: Some("read_file".to_string()),
///     ..Default::default()
/// };
/// let result = evaluator.evaluate(&policy, &action);
/// # Ok::<(), hushspec::PolicyError>(())
/// ```
#[derive(Clone, Default)]
pub struct ObservableEvaluator {
    observers: Vec<std::sync::Arc<dyn EvaluationObserver>>,
}

impl std::fmt::Debug for ObservableEvaluator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObservableEvaluator")
            .field("observers", &self.observers.len())
            .finish()
    }
}

impl ObservableEvaluator {
    /// An evaluator with no observers: every `notify_*` is a no-op.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an observer. Events reach observers in registration order.
    pub fn add_observer(&mut self, observer: std::sync::Arc<dyn EvaluationObserver>) {
        self.observers.push(observer);
    }

    /// How many observers are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.observers.len()
    }

    /// Whether any observer is registered. A guard consults this to decide
    /// whether monitor mode has somewhere to report to.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observers.is_empty()
    }

    /// Evaluate through `policy`, time it, and announce the result.
    ///
    /// Routes through the detection pipeline, so a policy's `detection:`
    /// extension is honoured exactly as it is in a guard.
    #[must_use]
    pub fn evaluate(
        &self,
        policy: &crate::compiled::CompiledPolicy,
        action: &EvaluationAction,
    ) -> EvaluationResult {
        let start = std::time::Instant::now();
        let result = policy.evaluate_with_detection(action).evaluation;
        let duration_us = start.elapsed().as_micros() as u64;
        self.notify_evaluation_completed(action, &result, duration_us, None, None);
        result
    }

    /// Announce a decision. `action` is redacted here; callers pass the real
    /// one.
    pub fn notify_evaluation_completed(
        &self,
        action: &EvaluationAction,
        result: &EvaluationResult,
        duration_us: u64,
        enforcement: Option<EnforcementSummary>,
        receipt: Option<&DecisionReceipt>,
    ) {
        if self.observers.is_empty() {
            return;
        }
        let (action, content_redacted) = redact(action);
        let event = EvaluationCompletedEvent {
            event_type: ObserverEventType::EvaluationCompleted,
            timestamp: format_timestamp(Utc::now()),
            action,
            content_redacted,
            result: result.clone(),
            duration_us,
            enforcement,
            receipt: receipt.cloned(),
        };
        for observer in &self.observers {
            observer.on_evaluation(&event);
        }
    }

    /// Announce the policy now in force.
    pub fn notify_policy_loaded(&self, name: Option<&str>, content_hash: &str) {
        self.emit_policy(PolicyLoadedEvent::loaded(
            name.map(str::to_string),
            content_hash.to_string(),
        ));
    }

    /// Announce a hot swap, naming the hash it replaced.
    pub fn notify_policy_reloaded(
        &self,
        name: Option<&str>,
        content_hash: &str,
        previous_hash: Option<&str>,
    ) {
        self.emit_policy(PolicyLoadedEvent::reloaded(
            name.map(str::to_string),
            content_hash.to_string(),
            previous_hash.map(str::to_string),
        ));
    }

    /// Announce a load that failed; the previous policy stays in force.
    pub fn notify_policy_load_failed(&self, error: &str, source: Option<&str>) {
        self.emit_error(ErrorEvent::load_failed(error, source.map(str::to_string)));
    }

    /// Announce an error raised by something other than a policy load.
    pub fn notify_error(&self, event: ErrorEvent) {
        self.emit_error(event);
    }

    fn emit_policy(&self, event: PolicyLoadedEvent) {
        for observer in &self.observers {
            observer.on_policy_loaded(&event);
        }
    }

    fn emit_error(&self, event: ErrorEvent) {
        for observer in &self.observers {
            observer.on_error(&event);
        }
    }
}

/// Strip `content` for observer emission (receipt spec 4.4: evidence records
/// the hash and the size, never the bytes).
fn redact(action: &EvaluationAction) -> (EvaluationAction, bool) {
    if action.content.is_none() {
        return (action.clone(), false);
    }
    let mut redacted = action.clone();
    redacted.content = None;
    (redacted, true)
}

// --------------------------------------------------------------------------
// Built-in observers
// --------------------------------------------------------------------------

/// Writes one JSON object per line to any writer.
///
/// The line is the event as the TypeScript and Python SDKs spell it: a `type`
/// member (`evaluation.completed`, `policy.loaded`, `policy.reloaded`,
/// `policy.load_failed`, `sink.error`), a `timestamp`, and the event's own
/// members.
pub struct JsonLineObserver<W: Write + Send> {
    writer: Mutex<W>,
}

impl<W: Write + Send> JsonLineObserver<W> {
    /// Write events to `writer`.
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
        }
    }

    fn write(&self, event: ObserverEvent<'_>) {
        let Ok(mut line) = serde_json::to_string(&event) else {
            return;
        };
        line.push('\n');
        // Telemetry is best-effort: a closed pipe must not take an agent down.
        if let Ok(mut writer) = self.writer.lock() {
            let _ = writer.write_all(line.as_bytes());
            let _ = writer.flush();
        }
    }
}

impl JsonLineObserver<std::io::Stderr> {
    /// Write events to stderr.
    #[must_use]
    pub fn stderr() -> Self {
        Self::new(std::io::stderr())
    }
}

impl<W: Write + Send> EvaluationObserver for JsonLineObserver<W> {
    fn on_policy_loaded(&self, event: &PolicyLoadedEvent) {
        self.write(ObserverEvent::Policy(event));
    }

    fn on_evaluation(&self, event: &EvaluationCompletedEvent) {
        self.write(ObserverEvent::Evaluation(event));
    }

    fn on_error(&self, event: &ErrorEvent) {
        self.write(ObserverEvent::Error(event));
    }
}

/// Which decisions a [`StderrObserver`] prints.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ObserverLevel {
    /// Every event.
    #[default]
    All,
    /// Policy events, errors, and denied evaluations only.
    DenyOnly,
}

/// Prints a one-line human summary of each event to stderr, prefixed
/// `[hushspec]`. The SDK-isomorphic spelling of TypeScript's
/// `ConsoleObserver` and Python's `ConsoleObserver`.
#[derive(Clone, Copy, Debug, Default)]
pub struct StderrObserver {
    level: ObserverLevel,
}

impl StderrObserver {
    /// Print every event.
    #[must_use]
    pub fn new() -> Self {
        Self {
            level: ObserverLevel::All,
        }
    }

    /// Print policy events, errors, and denials only.
    #[must_use]
    pub fn deny_only() -> Self {
        Self {
            level: ObserverLevel::DenyOnly,
        }
    }
}

impl EvaluationObserver for StderrObserver {
    fn on_policy_loaded(&self, event: &PolicyLoadedEvent) {
        eprintln!(
            "[hushspec] {} at {} policy={} hash={}",
            event.event_type.as_str(),
            event.timestamp,
            event.policy_name.as_deref().unwrap_or("<unnamed>"),
            event.content_hash
        );
    }

    fn on_evaluation(&self, event: &EvaluationCompletedEvent) {
        if self.level == ObserverLevel::DenyOnly && event.result.decision != Decision::Deny {
            return;
        }
        eprintln!(
            "[hushspec] {} at {} {} {} -> {} ({}) in {}us",
            event.event_type.as_str(),
            event.timestamp,
            event.action.action_type,
            event.action.target.as_deref().unwrap_or("-"),
            decision_label(event.result.decision),
            event.result.matched_rule.as_deref().unwrap_or("-"),
            event.duration_us
        );
    }

    fn on_error(&self, event: &ErrorEvent) {
        eprintln!(
            "[hushspec] {} at {} {}: {}",
            event.event_type.as_str(),
            event.timestamp,
            event.source.as_deref().unwrap_or("-"),
            event.error
        );
    }
}

// --------------------------------------------------------------------------
// Metrics
// --------------------------------------------------------------------------

/// Upper bounds of the latency histogram, in microseconds. The last bucket is
/// `+Inf`, which the exposition adds.
pub const DURATION_BUCKETS_US: &[u64] = &[10, 25, 50, 100, 250, 500, 1_000, 5_000, 10_000];

/// Counters and a latency histogram over the evaluation stream, rendered as
/// Prometheus text.
///
/// The exposed series are the ones the observability spec names
/// (`docs/plans/02-audit-trail.md` section 4.2), so an existing dashboard or
/// recording rule works unchanged:
///
/// | Series | Type | Labels |
/// |---|---|---|
/// | `hushspec_evaluate_total` | counter | `decision`, `action_type` |
/// | `hushspec_evaluate_duration_us` | histogram | `action_type` |
/// | `hushspec_rule_match_total` | counter | `rule_block`, `decision` |
/// | `hushspec_policy_load_total` | counter | `status` |
///
/// Cheap enough to sit in the hot path: one mutex, integer counters, no
/// allocation per event beyond the label key.
#[derive(Debug, Default)]
pub struct MetricsCollector {
    inner: Mutex<Metrics>,
}

#[derive(Debug, Default)]
struct Metrics {
    /// (decision, action_type) -> count
    evaluations: BTreeMap<(&'static str, String), u64>,
    /// (rule_block, decision) -> count
    rule_matches: BTreeMap<(String, &'static str), u64>,
    /// status -> count
    policy_loads: BTreeMap<&'static str, u64>,
    /// action_type -> cumulative bucket counts (one per DURATION_BUCKETS_US) +
    /// sum and count.
    durations: BTreeMap<String, Histogram>,
}

#[derive(Clone, Debug)]
struct Histogram {
    buckets: Vec<u64>,
    sum: u64,
    count: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            buckets: vec![0; DURATION_BUCKETS_US.len()],
            sum: 0,
            count: 0,
        }
    }
}

/// A point-in-time copy of a [`MetricsCollector`]'s counters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct MetricsSnapshot {
    /// `decision` -> count, summed over action types.
    pub by_decision: BTreeMap<String, u64>,
    /// `action_type` -> count, summed over decisions.
    pub by_action_type: BTreeMap<String, u64>,
    /// `rule_block` -> count, summed over decisions.
    pub by_rule_block: BTreeMap<String, u64>,
    /// `success` / `failure` -> count.
    pub policy_loads: BTreeMap<String, u64>,
    /// Every evaluation counted.
    pub total_evaluations: u64,
    /// Sum of every recorded `duration_us`.
    pub total_duration_us: u64,
    /// Cumulative histogram counts, aligned with [`DURATION_BUCKETS_US`].
    pub duration_buckets_us: Vec<u64>,
}

impl MetricsSnapshot {
    /// Mean evaluation latency in microseconds, or `0.0` with no data.
    #[must_use]
    pub fn average_duration_us(&self) -> f64 {
        if self.total_evaluations == 0 {
            return 0.0;
        }
        self.total_duration_us as f64 / self.total_evaluations as f64
    }
}

impl MetricsCollector {
    /// An empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A copy of every counter, for a `/metrics` handler that renders its own
    /// format or a test that asserts on counts.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        let metrics = self.lock();
        let mut snapshot = MetricsSnapshot {
            duration_buckets_us: vec![0; DURATION_BUCKETS_US.len()],
            ..MetricsSnapshot::default()
        };
        for ((decision, action_type), count) in &metrics.evaluations {
            *snapshot
                .by_decision
                .entry((*decision).to_string())
                .or_default() += count;
            *snapshot
                .by_action_type
                .entry(action_type.clone())
                .or_default() += count;
        }
        for ((rule_block, _), count) in &metrics.rule_matches {
            *snapshot
                .by_rule_block
                .entry(rule_block.clone())
                .or_default() += count;
        }
        for (status, count) in &metrics.policy_loads {
            snapshot.policy_loads.insert((*status).to_string(), *count);
        }
        for histogram in metrics.durations.values() {
            snapshot.total_evaluations += histogram.count;
            snapshot.total_duration_us += histogram.sum;
            for (total, bucket) in snapshot
                .duration_buckets_us
                .iter_mut()
                .zip(&histogram.buckets)
            {
                *total += bucket;
            }
        }
        snapshot
    }

    /// Prometheus text exposition (version 0.0.4) of every series.
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        let metrics = self.lock();
        let mut out = String::new();

        out.push_str("# HELP hushspec_evaluate_total Total HushSpec evaluations\n");
        out.push_str("# TYPE hushspec_evaluate_total counter\n");
        for ((decision, action_type), count) in &metrics.evaluations {
            out.push_str(&format!(
                "hushspec_evaluate_total{{decision=\"{decision}\",action_type=\"{}\"}} {count}\n",
                escape_label(action_type)
            ));
        }

        out.push_str("# HELP hushspec_evaluate_duration_us Evaluation duration in microseconds\n");
        out.push_str("# TYPE hushspec_evaluate_duration_us histogram\n");
        for (action_type, histogram) in &metrics.durations {
            let action_type = escape_label(action_type);
            for (bound, count) in DURATION_BUCKETS_US.iter().zip(&histogram.buckets) {
                out.push_str(&format!(
                    "hushspec_evaluate_duration_us_bucket{{action_type=\"{action_type}\",le=\"{bound}\"}} {count}\n"
                ));
            }
            out.push_str(&format!(
                "hushspec_evaluate_duration_us_bucket{{action_type=\"{action_type}\",le=\"+Inf\"}} {}\n",
                histogram.count
            ));
            out.push_str(&format!(
                "hushspec_evaluate_duration_us_sum{{action_type=\"{action_type}\"}} {}\n",
                histogram.sum
            ));
            out.push_str(&format!(
                "hushspec_evaluate_duration_us_count{{action_type=\"{action_type}\"}} {}\n",
                histogram.count
            ));
        }

        out.push_str("# HELP hushspec_rule_match_total Rule block match counts\n");
        out.push_str("# TYPE hushspec_rule_match_total counter\n");
        for ((rule_block, decision), count) in &metrics.rule_matches {
            out.push_str(&format!(
                "hushspec_rule_match_total{{rule_block=\"{}\",decision=\"{decision}\"}} {count}\n",
                escape_label(rule_block)
            ));
        }

        out.push_str("# HELP hushspec_policy_load_total Policy load operations\n");
        out.push_str("# TYPE hushspec_policy_load_total counter\n");
        for (status, count) in &metrics.policy_loads {
            out.push_str(&format!(
                "hushspec_policy_load_total{{status=\"{status}\"}} {count}\n"
            ));
        }

        out
    }

    /// Drop every counter.
    pub fn reset(&self) {
        *self.lock() = Metrics::default();
    }

    /// A poisoned metrics mutex means a previous holder panicked while
    /// counting. The counters are integers -- there is no torn state to
    /// recover from -- so keep counting rather than propagating the panic
    /// into an evaluation path.
    fn lock(&self) -> std::sync::MutexGuard<'_, Metrics> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl EvaluationObserver for MetricsCollector {
    fn on_policy_loaded(&self, _event: &PolicyLoadedEvent) {
        *self.lock().policy_loads.entry("success").or_default() += 1;
    }

    fn on_evaluation(&self, event: &EvaluationCompletedEvent) {
        let decision = decision_label(event.result.decision);
        let mut metrics = self.lock();

        *metrics
            .evaluations
            .entry((decision, event.action.action_type.clone()))
            .or_default() += 1;

        if let Some(rule_block) = rule_block_of(event.result.matched_rule.as_deref()) {
            *metrics
                .rule_matches
                .entry((rule_block, decision))
                .or_default() += 1;
        }

        let histogram = metrics
            .durations
            .entry(event.action.action_type.clone())
            .or_default();
        histogram.count += 1;
        histogram.sum += event.duration_us;
        for (bound, bucket) in DURATION_BUCKETS_US.iter().zip(&mut histogram.buckets) {
            if event.duration_us <= *bound {
                *bucket += 1;
            }
        }
    }

    fn on_error(&self, event: &ErrorEvent) {
        if event.event_type == ObserverEventType::PolicyLoadFailed {
            *self.lock().policy_loads.entry("failure").or_default() += 1;
        }
    }
}

/// The rule block a `matched_rule` belongs to, for the
/// `hushspec_rule_match_total` label.
///
/// `rules.egress.default` -> `egress`; `extensions.posture.budgets` ->
/// `posture`; the bare `detection` the detection pipeline emits ->
/// `detection`; a reserved `__hushspec_x__` id -> `x`. `None` for an
/// evaluation no rule decided (a default allow).
fn rule_block_of(matched_rule: Option<&str>) -> Option<String> {
    let matched = matched_rule?;
    if let Some(rest) = matched.strip_prefix("rules.") {
        return Some(segment(rest).to_string());
    }
    if let Some(rest) = matched.strip_prefix("extensions.") {
        return Some(segment(rest).to_string());
    }
    if matched == "detection" {
        return Some("detection".to_string());
    }
    // `__hushspec_panic__` -> `hushspec_panic`, `__unknown_action_type__` ->
    // `unknown_action_type`: a reserved engine stage, not a rule block, but
    // still worth a series of its own.
    Some(matched.trim_matches('_').to_string())
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// The wire spelling of a decision, for a metrics label or a log line.
#[must_use]
pub fn decision_label(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Warn => "warn",
        Decision::Deny => "deny",
    }
}

// --------------------------------------------------------------------------
// Webhook
// --------------------------------------------------------------------------

/// POSTs each event as JSON to an HTTP endpoint, off the evaluation thread.
///
/// Best-effort by construction: events go onto a bounded queue and a worker
/// thread drains it. When the queue is full the event is dropped and
/// [`WebhookObserver::dropped`] counts it -- an observer must never be the
/// reason an agent stalls.
#[cfg(feature = "http")]
pub struct WebhookObserver {
    sender: std::sync::mpsc::SyncSender<String>,
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
    worker: Option<std::thread::JoinHandle<()>>,
}

#[cfg(feature = "http")]
impl WebhookObserver {
    /// Default queue depth.
    pub const DEFAULT_CAPACITY: usize = 1024;

    /// POST events to `url` with a 1024-event queue and a 5-second timeout.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] when the HTTP client cannot be built.
    pub fn new(url: impl Into<String>) -> Result<Self, std::io::Error> {
        Self::with_capacity(
            url,
            Self::DEFAULT_CAPACITY,
            std::time::Duration::from_secs(5),
        )
    }

    /// POST events to `url`, queueing at most `capacity` of them.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] when the HTTP client cannot be built.
    pub fn with_capacity(
        url: impl Into<String>,
        capacity: usize,
        timeout: std::time::Duration,
    ) -> Result<Self, std::io::Error> {
        let url = url.into();
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(std::io::Error::other)?;
        let (sender, receiver) = std::sync::mpsc::sync_channel::<String>(capacity.max(1));
        let worker = std::thread::Builder::new()
            .name("hushspec-webhook".to_string())
            .spawn(move || {
                for body in receiver {
                    let _ = client
                        .post(&url)
                        .header("content-type", "application/json")
                        .body(body)
                        .send();
                }
            })?;
        Ok(Self {
            sender,
            dropped: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            worker: Some(worker),
        })
    }

    /// How many events were dropped because the queue was full.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn post(&self, event: ObserverEvent<'_>) {
        let Ok(body) = serde_json::to_string(&event) else {
            return;
        };
        if self.sender.try_send(body).is_err() {
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

#[cfg(feature = "http")]
impl EvaluationObserver for WebhookObserver {
    fn on_policy_loaded(&self, event: &PolicyLoadedEvent) {
        self.post(ObserverEvent::Policy(event));
    }

    fn on_evaluation(&self, event: &EvaluationCompletedEvent) {
        self.post(ObserverEvent::Evaluation(event));
    }

    fn on_error(&self, event: &ErrorEvent) {
        self.post(ObserverEvent::Error(event));
    }
}

#[cfg(feature = "http")]
impl Drop for WebhookObserver {
    /// Close the queue and let the worker finish what it already accepted.
    fn drop(&mut self) {
        // Replacing the sender closes the channel, which ends the worker's
        // `for` loop once the queue drains.
        let (closed, _) = std::sync::mpsc::sync_channel(1);
        let _ = std::mem::replace(&mut self.sender, closed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluate::EvaluationResult;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn action(action_type: &str, target: &str) -> EvaluationAction {
        EvaluationAction {
            action_type: action_type.to_string(),
            target: Some(target.to_string()),
            ..Default::default()
        }
    }

    fn allow() -> EvaluationResult {
        EvaluationResult {
            decision: Decision::Allow,
            matched_rule: None,
            reason: None,
            origin_profile: None,
            posture: None,
        }
    }

    fn completed(
        action: &EvaluationAction,
        decision: Decision,
        matched_rule: Option<&str>,
        duration_us: u64,
    ) -> EvaluationCompletedEvent {
        EvaluationCompletedEvent {
            event_type: ObserverEventType::EvaluationCompleted,
            timestamp: "2026-01-01T00:00:00.000Z".to_string(),
            action: action.clone(),
            content_redacted: false,
            result: EvaluationResult {
                decision,
                matched_rule: matched_rule.map(str::to_string),
                reason: None,
                origin_profile: None,
                posture: None,
            },
            duration_us,
            enforcement: None,
            receipt: None,
        }
    }

    #[test]
    fn strips_content_before_an_observer_sees_it() {
        let mut act = action("file_write", "/tmp/x");
        act.content = Some("hunter2".to_string());
        let (redacted, flagged) = redact(&act);
        assert!(redacted.content.is_none());
        assert!(flagged);
        assert_eq!(redacted.target.as_deref(), Some("/tmp/x"));
    }

    #[test]
    fn leaves_a_contentless_action_alone() {
        let (redacted, flagged) = redact(&action("egress", "example.com"));
        assert!(!flagged, "nothing was removed, so nothing is flagged");
        assert_eq!(redacted.action_type, "egress");
    }

    #[test]
    fn json_lines_carry_the_sdk_isomorphic_type_member() {
        let event = PolicyLoadedEvent::loaded(Some("p".into()), "sha256:ab".into());
        let json = serde_json::to_value(ObserverEvent::Policy(&event)).expect("serializes");
        assert_eq!(json["type"], "policy.loaded");
        assert_eq!(json["content_hash"], "sha256:ab");
        assert!(json.get("previous_hash").is_none(), "absent, not null");

        let swapped =
            PolicyLoadedEvent::reloaded(None, "sha256:cd".into(), Some("sha256:ab".into()));
        let json = serde_json::to_value(ObserverEvent::Policy(&swapped)).expect("serializes");
        assert_eq!(json["type"], "policy.reloaded");
        assert_eq!(json["previous_hash"], "sha256:ab");
    }

    #[test]
    fn json_line_observer_writes_one_object_per_line() {
        #[derive(Clone, Default)]
        struct Shared(std::sync::Arc<Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("lock").extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buffer = Shared::default();
        let observer = JsonLineObserver::new(buffer.clone());
        observer.on_policy_loaded(&PolicyLoadedEvent::loaded(None, "sha256:ab".into()));
        let act = action("egress", "example.com");
        observer.on_evaluation(&completed(
            &act,
            Decision::Deny,
            Some("rules.egress.default"),
            12,
        ));
        observer.on_error(&ErrorEvent::load_failed("boom", Some("p.yaml".into())));

        let written = String::from_utf8(buffer.0.lock().expect("lock").clone()).expect("utf-8");
        let lines: Vec<&str> = written.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in lines {
            serde_json::from_str::<serde_json::Value>(line).expect("each line is one JSON object");
        }
    }

    #[test]
    fn metrics_count_by_decision_action_type_and_rule_block() {
        let metrics = MetricsCollector::new();
        let egress = action("egress", "evil.test");
        metrics.on_evaluation(&completed(
            &egress,
            Decision::Deny,
            Some("rules.egress.default"),
            40,
        ));
        metrics.on_evaluation(&completed(&egress, Decision::Allow, None, 5));
        let tool = action("tool_call", "read_file");
        metrics.on_evaluation(&completed(
            &tool,
            Decision::Warn,
            Some("rules.tool_access.warn"),
            300,
        ));
        metrics.on_policy_loaded(&PolicyLoadedEvent::loaded(None, "sha256:ab".into()));
        metrics.on_error(&ErrorEvent::load_failed("nope", None));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.total_evaluations, 3);
        assert_eq!(snapshot.by_decision["deny"], 1);
        assert_eq!(snapshot.by_decision["allow"], 1);
        assert_eq!(snapshot.by_decision["warn"], 1);
        assert_eq!(snapshot.by_action_type["egress"], 2);
        assert_eq!(snapshot.by_rule_block["egress"], 1);
        assert_eq!(snapshot.by_rule_block["tool_access"], 1);
        assert_eq!(snapshot.policy_loads["success"], 1);
        assert_eq!(snapshot.policy_loads["failure"], 1);
        assert_eq!(snapshot.total_duration_us, 345);
        assert!((snapshot.average_duration_us() - 115.0).abs() < 1e-9);

        // Cumulative buckets: 5us and 40us are <= 50, 300us is not.
        let le_50 = snapshot.duration_buckets_us[DURATION_BUCKETS_US
            .iter()
            .position(|b| *b == 50)
            .expect("bucket")];
        assert_eq!(le_50, 2);
    }

    #[test]
    fn prometheus_exposition_uses_the_documented_series_names() {
        let metrics = MetricsCollector::new();
        let egress = action("egress", "evil.test");
        metrics.on_evaluation(&completed(
            &egress,
            Decision::Deny,
            Some("rules.egress.default"),
            40,
        ));
        metrics.on_policy_loaded(&PolicyLoadedEvent::loaded(None, "sha256:ab".into()));

        let text = metrics.render_prometheus();
        assert!(
            text.contains("hushspec_evaluate_total{decision=\"deny\",action_type=\"egress\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("hushspec_rule_match_total{rule_block=\"egress\",decision=\"deny\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("hushspec_policy_load_total{status=\"success\"} 1"),
            "{text}"
        );
        assert!(
            text.contains(
                "hushspec_evaluate_duration_us_bucket{action_type=\"egress\",le=\"+Inf\"} 1"
            ),
            "{text}"
        );
        assert!(
            text.contains("hushspec_evaluate_duration_us_sum{action_type=\"egress\"} 40"),
            "{text}"
        );
        assert!(
            text.contains("# TYPE hushspec_evaluate_duration_us histogram"),
            "{text}"
        );
    }

    #[test]
    fn rule_block_labels_follow_the_matched_rule_path() {
        assert_eq!(
            rule_block_of(Some("rules.egress.default")).as_deref(),
            Some("egress")
        );
        assert_eq!(
            rule_block_of(Some("rules.secret_patterns.patterns[0]")).as_deref(),
            Some("secret_patterns")
        );
        assert_eq!(
            rule_block_of(Some("extensions.posture.state")).as_deref(),
            Some("posture")
        );
        assert_eq!(
            rule_block_of(Some("detection")).as_deref(),
            Some("detection")
        );
        assert_eq!(
            rule_block_of(Some("__hushspec_panic__")).as_deref(),
            Some("hushspec_panic")
        );
        assert_eq!(rule_block_of(None), None, "a default allow matched no rule");
    }

    #[test]
    fn resetting_clears_every_counter() {
        let metrics = MetricsCollector::new();
        metrics.on_evaluation(&completed(&action("egress", "x"), Decision::Allow, None, 1));
        assert_eq!(metrics.snapshot().total_evaluations, 1);
        metrics.reset();
        assert_eq!(metrics.snapshot().total_evaluations, 0);
    }

    #[test]
    fn a_fan_out_with_no_observers_costs_nothing() {
        let evaluator = ObservableEvaluator::new();
        assert!(evaluator.is_empty());
        // Must not panic, must not allocate an event.
        evaluator.notify_policy_loaded(Some("p"), "sha256:ab");
        evaluator.notify_evaluation_completed(&action("egress", "x"), &allow(), 1, None, None);
    }

    #[test]
    fn fan_out_reaches_every_observer() {
        #[derive(Default)]
        struct Counting {
            evaluations: AtomicU64,
            policies: AtomicU64,
            errors: AtomicU64,
        }
        impl EvaluationObserver for Counting {
            fn on_policy_loaded(&self, _: &PolicyLoadedEvent) {
                self.policies.fetch_add(1, Ordering::Relaxed);
            }
            fn on_evaluation(&self, _: &EvaluationCompletedEvent) {
                self.evaluations.fetch_add(1, Ordering::Relaxed);
            }
            fn on_error(&self, _: &ErrorEvent) {
                self.errors.fetch_add(1, Ordering::Relaxed);
            }
        }

        let first = std::sync::Arc::new(Counting::default());
        let second = std::sync::Arc::new(Counting::default());
        let mut evaluator = ObservableEvaluator::new();
        evaluator.add_observer(first.clone());
        evaluator.add_observer(second.clone());
        assert_eq!(evaluator.len(), 2);

        evaluator.notify_policy_loaded(None, "sha256:ab");
        evaluator.notify_policy_reloaded(None, "sha256:cd", Some("sha256:ab"));
        evaluator.notify_evaluation_completed(&action("egress", "x"), &allow(), 3, None, None);
        evaluator.notify_policy_load_failed("boom", None);

        for observer in [&first, &second] {
            assert_eq!(observer.policies.load(Ordering::Relaxed), 2);
            assert_eq!(observer.evaluations.load(Ordering::Relaxed), 1);
            assert_eq!(observer.errors.load(Ordering::Relaxed), 1);
        }
    }
}
