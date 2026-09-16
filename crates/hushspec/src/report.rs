//! Evidence aggregation over receipts and policy events.
//!
//! A receipt proves one evaluation; a log proves a sequence of them. A
//! *report* answers the question an auditor actually asks: over this window,
//! what did the policy decide, which controls ran, how often did they fire,
//! and which policy was in force while they did.
//!
//! Nothing here re-evaluates anything. Every number is counted from the
//! recorded receipts, so a report can never disagree with the evidence it
//! summarizes. The aggregation lives in the library rather than the CLI so
//! that the other SDKs can port it against the same expected documents
//! (`fixtures/report/`).
//!
//! The one section this module does not compute is [`ControlsEvidence`]: the
//! `metadata.controls` join needs the resolved policy and the framework
//! registry, which are `h2h`'s business (`crates/hushspec-cli/src/controls.rs`).
//! The types are declared here so the whole report has one schema
//! (`schemas/hushspec-report.v0.schema.json`) and one serialization.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::detection::DetectionCategory;
use crate::evaluate::{Decision, RuleOutcome};
use crate::log::{PolicyEvent, PolicyEventKind};
use crate::receipt::{
    DecisionReceipt, DetectorLevel, EnforcementMode, EnforcementOutcome, format_timestamp,
};

/// The report document format this module writes.
pub const REPORT_VERSION: &str = "0.1";

/// How many `rule_path`s a rule-block row lists by default.
pub const DEFAULT_TOP_RULE_PATHS: usize = 5;

// --------------------------------------------------------------------------
// Counters
// --------------------------------------------------------------------------

/// Receipts by evaluated policy decision (core spec 6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionTotals {
    pub allow: u64,
    pub warn: u64,
    pub deny: u64,
}

impl DecisionTotals {
    fn count(&mut self, decision: Decision) {
        match decision {
            Decision::Allow => self.allow += 1,
            Decision::Warn => self.warn += 1,
            Decision::Deny => self.deny += 1,
        }
    }

    /// Every receipt counted here.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.allow + self.warn + self.deny
    }
}

/// Receipts by the enforcement mode in force (receipt spec 4.7).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModeTotals {
    pub enforce: u64,
    pub monitor: u64,
}

impl ModeTotals {
    fn count(&mut self, mode: EnforcementMode) {
        match mode {
            EnforcementMode::Enforce => self.enforce += 1,
            EnforcementMode::Monitor => self.monitor += 1,
        }
    }
}

/// Receipts by what the enforcement point did (receipt spec 4.7).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeTotals {
    pub allowed: u64,
    pub confirmed: u64,
    pub blocked: u64,
    pub would_block: u64,
}

impl OutcomeTotals {
    fn count(&mut self, outcome: EnforcementOutcome) {
        match outcome {
            EnforcementOutcome::Allowed => self.allowed += 1,
            EnforcementOutcome::Confirmed => self.confirmed += 1,
            EnforcementOutcome::Blocked => self.blocked += 1,
            EnforcementOutcome::WouldBlock => self.would_block += 1,
        }
    }
}

/// Detector evaluations by the level their score mapped to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LevelTotals {
    pub none: u64,
    pub low: u64,
    pub suspicious: u64,
    pub high: u64,
    pub critical: u64,
}

impl LevelTotals {
    fn count(&mut self, level: DetectorLevel) {
        match level {
            DetectorLevel::None => self.none += 1,
            DetectorLevel::Low => self.low += 1,
            DetectorLevel::Suspicious => self.suspicious += 1,
            DetectorLevel::High => self.high += 1,
            DetectorLevel::Critical => self.critical += 1,
        }
    }
}

// --------------------------------------------------------------------------
// Rows
// --------------------------------------------------------------------------

/// One `rule_path` and how often the window recorded it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulePathCount {
    pub rule_path: String,
    pub count: u64,
}

/// One rule block (or engine stage) across the window.
///
/// `evaluated` counts trace entries whose matching logic ran; `skipped`
/// counts entries the evaluator recorded as applicable but inert. `fired` is
/// the subset of `evaluated` whose outcome was not `allow` -- exactly
/// `warn + deny`, because an evaluated entry has no other outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleBlockRow {
    pub rule_block: String,
    /// Receipts whose trace named this block.
    pub receipts: u64,
    pub evaluated: u64,
    pub skipped: u64,
    pub fired: u64,
    pub warn: u64,
    pub deny: u64,
    /// The most frequent `rule_path`s recorded for this block, most frequent
    /// first and ties broken by path.
    pub top_rule_paths: Vec<RulePathCount>,
}

/// One action type across the window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionTypeRow {
    pub action_type: String,
    pub receipts: u64,
    pub by_decision: DecisionTotals,
    pub by_outcome: OutcomeTotals,
}

/// One policy, identified the way a receipt identifies it: by content hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRow {
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    pub spec_version: String,
    pub receipts: u64,
    pub first_seen: String,
    pub last_seen: String,
    pub by_decision: DecisionTotals,
}

/// One `policy_loaded` / `policy_swapped` record, in log order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTimelineRow {
    pub event: PolicyEventKind,
    pub timestamp: String,
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_content_hash: Option<String>,
    pub enforcement_mode: EnforcementMode,
    pub sdk: String,
}

/// One actor across the window (receipt spec 4.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorRow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    pub receipts: u64,
    pub by_decision: DecisionTotals,
    pub by_outcome: OutcomeTotals,
}

/// One reason a policy signature did not verify, and how often.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReasonCount {
    pub reason: String,
    pub count: u64,
}

/// Policy-signature status across the window, as each receipt recorded it at
/// load time (signing spec 6).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureSummary {
    pub verified: u64,
    pub unverified: u64,
    /// Receipts whose runtime did not attempt verification.
    pub absent: u64,
    pub reasons: Vec<ReasonCount>,
}

/// One detector across the window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorRow {
    pub detector_id: String,
    pub category: DetectionCategory,
    /// Receipts in which this detector ran.
    pub evaluated: u64,
    /// Evaluations that met a policy threshold and contributed to a decision.
    pub matched: u64,
    pub by_level: LevelTotals,
}

// --------------------------------------------------------------------------
// Control evidence (filled in by `h2h report`)
// --------------------------------------------------------------------------

/// One control's evidence: what it maps to, and what the window recorded
/// against those paths.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlEvidenceRow {
    pub control_id: String,
    /// `metadata.controls[].rule_paths`, verbatim.
    pub rule_paths: Vec<String>,
    /// The rule blocks those paths were observed under in the receipts.
    pub rule_blocks: Vec<String>,
    /// Receipts in which at least one mapped path was consulted.
    pub receipts: u64,
    pub evaluated: u64,
    pub fired: u64,
    pub denied: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
}

/// One framework's control rows, in the order the policy declared them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrameworkEvidence {
    pub framework: String,
    /// `false` when the id is not in `spec/registries/frameworks.yaml`.
    pub registered: bool,
    pub controls: Vec<ControlEvidenceRow>,
}

/// The `metadata.controls` join: control -> evidence, plus what fired with no
/// control behind it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlsEvidence {
    /// The policy the mappings were read from, as the caller named it.
    pub policy_source: String,
    pub policy_content_hash: String,
    /// Receipts in the window that name `policy_content_hash`. Evidence for a
    /// control is only as good as this number: a receipt evaluated under a
    /// different policy proves nothing about these mappings.
    pub receipts_matching_policy: u64,
    pub frameworks: Vec<FrameworkEvidence>,
    /// Rule blocks that fired in the window with no control mapping (the
    /// coverage gap lint L011 flags statically, observed dynamically).
    pub unmapped_fired_rule_blocks: Vec<String>,
}

// --------------------------------------------------------------------------
// Report
// --------------------------------------------------------------------------

/// The window the report covers, as asked for and as observed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    /// Timestamp of the earliest receipt counted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_receipt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_receipt: Option<String>,
}

/// What the log chain verifier said about the inputs, when the inputs were
/// logs. Absent for a plain receipt JSONL.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainSummary {
    pub verified: bool,
    pub files: u64,
    pub entries: u64,
    pub receipts: u64,
    pub policy_events: u64,
    pub signed_entries: u64,
    pub last_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_entry_hash: Option<String>,
    /// Why verification failed, when it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Window-wide counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Totals {
    pub receipts: u64,
    pub policy_events: u64,
    /// Lines skipped under `--lenient`.
    pub skipped_lines: u64,
    pub by_decision: DecisionTotals,
    pub by_mode: ModeTotals,
    pub by_outcome: OutcomeTotals,
}

/// An evidence report over one window of receipts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub report_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    pub sources: Vec<String>,
    /// `false` stamps a report produced over a log whose chain did not verify
    /// (`--unverified`). Absent when the inputs were not logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<ChainSummary>,
    pub window: Window,
    pub totals: Totals,
    pub rule_blocks: Vec<RuleBlockRow>,
    pub action_types: Vec<ActionTypeRow>,
    pub policies: Vec<PolicyRow>,
    pub policy_timeline: Vec<PolicyTimelineRow>,
    pub actors: Vec<ActorRow>,
    pub signatures: SignatureSummary,
    pub detections: Vec<DetectorRow>,
    /// The `metadata.controls` join, when a policy was supplied. Filled in by
    /// the caller (see the module docs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controls: Option<ControlsEvidence>,
}

/// What to aggregate and how to stamp it.
#[derive(Clone, Debug, Default)]
pub struct ReportOptions {
    /// The inputs, as the caller named them.
    pub sources: Vec<String>,
    /// Inclusive lower bound on receipt and event timestamps.
    pub since: Option<DateTime<Utc>>,
    /// Inclusive upper bound.
    pub until: Option<DateTime<Utc>>,
    /// Stamped as `generated_at`. Left unstamped when `None` so a vector is
    /// byte-stable.
    pub generated_at: Option<DateTime<Utc>>,
    pub chain: Option<ChainSummary>,
    pub skipped_lines: u64,
    /// `0` uses [`DEFAULT_TOP_RULE_PATHS`].
    pub top_rule_paths: usize,
}

/// Is `timestamp` inside `[since, until]`?
///
/// A timestamp that is not RFC 3339 is inside an unbounded window and outside
/// a bounded one: a bound cannot be honoured for a record that will not place
/// itself in time, and a report must not quietly widen its own window.
#[must_use]
pub fn in_window(
    timestamp: &str,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
) -> bool {
    if since.is_none() && until.is_none() {
        return true;
    }
    let Ok(parsed) = DateTime::parse_from_rfc3339(timestamp) else {
        return false;
    };
    let instant = parsed.with_timezone(&Utc);
    since.is_none_or(|bound| instant >= bound) && until.is_none_or(|bound| instant <= bound)
}

#[derive(Default)]
struct BlockAccumulator {
    receipts: u64,
    evaluated: u64,
    skipped: u64,
    fired: u64,
    warn: u64,
    deny: u64,
    paths: BTreeMap<String, u64>,
}

#[derive(Default)]
struct ActionAccumulator {
    receipts: u64,
    by_decision: DecisionTotals,
    by_outcome: OutcomeTotals,
}

struct PolicyAccumulator {
    name: Option<String>,
    version: Option<u64>,
    spec_version: String,
    receipts: u64,
    first_seen: String,
    last_seen: String,
    by_decision: DecisionTotals,
}

#[derive(Default)]
struct ActorAccumulator {
    receipts: u64,
    by_decision: DecisionTotals,
    by_outcome: OutcomeTotals,
}

struct DetectorAccumulator {
    category: DetectionCategory,
    evaluated: u64,
    matched: u64,
    by_level: LevelTotals,
}

/// Aggregate `receipts` and `events` into a [`Report`].
///
/// Both inputs are filtered by the window in `options`; nothing is
/// re-evaluated and nothing is inferred from a decision. Rows are ordered
/// deterministically (by key, except the policy timeline which keeps log
/// order) so two runs over the same input produce the same bytes.
#[must_use]
pub fn build_report(
    receipts: &[DecisionReceipt],
    events: &[PolicyEvent],
    options: &ReportOptions,
) -> Report {
    let top = if options.top_rule_paths == 0 {
        DEFAULT_TOP_RULE_PATHS
    } else {
        options.top_rule_paths
    };

    let mut totals = Totals {
        skipped_lines: options.skipped_lines,
        ..Totals::default()
    };
    let mut blocks: BTreeMap<String, BlockAccumulator> = BTreeMap::new();
    let mut action_types: BTreeMap<String, ActionAccumulator> = BTreeMap::new();
    let mut policies: BTreeMap<String, PolicyAccumulator> = BTreeMap::new();
    let mut actors: BTreeMap<(String, String, String), ActorAccumulator> = BTreeMap::new();
    let mut detectors: BTreeMap<String, DetectorAccumulator> = BTreeMap::new();
    let mut signatures = SignatureSummary::default();
    let mut reasons: BTreeMap<String, u64> = BTreeMap::new();
    let mut first_receipt: Option<String> = None;
    let mut last_receipt: Option<String> = None;

    for receipt in receipts
        .iter()
        .filter(|receipt| in_window(&receipt.timestamp, options.since, options.until))
    {
        totals.receipts += 1;
        totals.by_decision.count(receipt.decision);
        totals.by_mode.count(receipt.enforcement.mode);
        totals.by_outcome.count(receipt.enforcement.outcome);

        // Receipt timestamps are fixed-width RFC 3339 UTC (receipt spec 3.3),
        // so lexical order is chronological order.
        if first_receipt
            .as_ref()
            .is_none_or(|t| receipt.timestamp < *t)
        {
            first_receipt = Some(receipt.timestamp.clone());
        }
        if last_receipt.as_ref().is_none_or(|t| receipt.timestamp > *t) {
            last_receipt = Some(receipt.timestamp.clone());
        }

        let action = action_types
            .entry(receipt.action.action_type.clone())
            .or_default();
        action.receipts += 1;
        action.by_decision.count(receipt.decision);
        action.by_outcome.count(receipt.enforcement.outcome);

        policies
            .entry(receipt.policy.content_hash.clone())
            .and_modify(|entry| {
                entry.receipts += 1;
                entry.by_decision.count(receipt.decision);
                if receipt.timestamp < entry.first_seen {
                    entry.first_seen.clone_from(&receipt.timestamp);
                }
                if receipt.timestamp > entry.last_seen {
                    entry.last_seen.clone_from(&receipt.timestamp);
                }
            })
            .or_insert_with(|| {
                let mut by_decision = DecisionTotals::default();
                by_decision.count(receipt.decision);
                PolicyAccumulator {
                    name: receipt.policy.name.clone(),
                    version: receipt.policy.version,
                    spec_version: receipt.policy.spec_version.clone(),
                    receipts: 1,
                    first_seen: receipt.timestamp.clone(),
                    last_seen: receipt.timestamp.clone(),
                    by_decision,
                }
            });

        let actor = receipt.actor.as_ref();
        let key = (
            actor
                .and_then(|actor| actor.agent_id.clone())
                .unwrap_or_default(),
            actor
                .and_then(|actor| actor.session_id.clone())
                .unwrap_or_default(),
            actor
                .and_then(|actor| actor.principal.clone())
                .unwrap_or_default(),
        );
        let actor_row = actors.entry(key).or_default();
        actor_row.receipts += 1;
        actor_row.by_decision.count(receipt.decision);
        actor_row.by_outcome.count(receipt.enforcement.outcome);

        match &receipt.policy.signature {
            None => signatures.absent += 1,
            Some(status) if status.verified => signatures.verified += 1,
            Some(status) => {
                signatures.unverified += 1;
                let reason = status
                    .reason
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());
                *reasons.entry(reason).or_insert(0) += 1;
            }
        }

        let mut seen_blocks: BTreeSet<&str> = BTreeSet::new();
        for entry in &receipt.rule_trace {
            let block = blocks.entry(entry.rule_block.clone()).or_default();
            if seen_blocks.insert(entry.rule_block.as_str()) {
                block.receipts += 1;
            }
            if entry.evaluated {
                block.evaluated += 1;
            } else {
                block.skipped += 1;
            }
            match entry.outcome {
                RuleOutcome::Warn => {
                    block.warn += 1;
                    block.fired += 1;
                }
                RuleOutcome::Deny => {
                    block.deny += 1;
                    block.fired += 1;
                }
                RuleOutcome::Allow | RuleOutcome::Skip => {}
            }
            if let Some(path) = &entry.rule_path {
                *block.paths.entry(path.clone()).or_insert(0) += 1;
            }
        }

        for detection in receipt.detection_trace.iter().flatten() {
            let row = detectors
                .entry(detection.detector_id.clone())
                .or_insert_with(|| DetectorAccumulator {
                    category: detection.category.clone(),
                    evaluated: 0,
                    matched: 0,
                    by_level: LevelTotals::default(),
                });
            row.evaluated += 1;
            if detection.matched {
                row.matched += 1;
            }
            row.by_level.count(detection.level);
        }
    }

    let mut policy_timeline = Vec::new();
    for event in events
        .iter()
        .filter(|event| in_window(&event.timestamp, options.since, options.until))
    {
        totals.policy_events += 1;
        policy_timeline.push(PolicyTimelineRow {
            event: event.event,
            timestamp: event.timestamp.clone(),
            content_hash: event.policy.content_hash.clone(),
            name: event.policy.name.clone(),
            previous_content_hash: event.previous_content_hash.clone(),
            enforcement_mode: event.enforcement_mode,
            sdk: format!("{}/{}", event.sdk.name, event.sdk.version),
        });
    }

    signatures.reasons = reasons
        .into_iter()
        .map(|(reason, count)| ReasonCount { reason, count })
        .collect();

    Report {
        report_version: REPORT_VERSION.to_string(),
        generated_at: options.generated_at.map(format_timestamp),
        sources: options.sources.clone(),
        chain_verified: options.chain.as_ref().map(|chain| chain.verified),
        chain: options.chain.clone(),
        window: Window {
            since: options.since.map(format_timestamp),
            until: options.until.map(format_timestamp),
            first_receipt,
            last_receipt,
        },
        totals,
        rule_blocks: blocks
            .into_iter()
            .map(|(rule_block, acc)| RuleBlockRow {
                rule_block,
                receipts: acc.receipts,
                evaluated: acc.evaluated,
                skipped: acc.skipped,
                fired: acc.fired,
                warn: acc.warn,
                deny: acc.deny,
                top_rule_paths: top_paths(acc.paths, top),
            })
            .collect(),
        action_types: action_types
            .into_iter()
            .map(|(action_type, acc)| ActionTypeRow {
                action_type,
                receipts: acc.receipts,
                by_decision: acc.by_decision,
                by_outcome: acc.by_outcome,
            })
            .collect(),
        policies: policies
            .into_iter()
            .map(|(content_hash, acc)| PolicyRow {
                content_hash,
                name: acc.name,
                version: acc.version,
                spec_version: acc.spec_version,
                receipts: acc.receipts,
                first_seen: acc.first_seen,
                last_seen: acc.last_seen,
                by_decision: acc.by_decision,
            })
            .collect(),
        policy_timeline,
        actors: actors
            .into_iter()
            .map(|((agent_id, session_id, principal), acc)| ActorRow {
                agent_id: (!agent_id.is_empty()).then_some(agent_id),
                session_id: (!session_id.is_empty()).then_some(session_id),
                principal: (!principal.is_empty()).then_some(principal),
                receipts: acc.receipts,
                by_decision: acc.by_decision,
                by_outcome: acc.by_outcome,
            })
            .collect(),
        signatures,
        detections: detectors
            .into_iter()
            .map(|(detector_id, acc)| DetectorRow {
                detector_id,
                category: acc.category,
                evaluated: acc.evaluated,
                matched: acc.matched,
                by_level: acc.by_level,
            })
            .collect(),
        controls: None,
    }
}

/// The `limit` most frequent paths, most frequent first, ties by path.
fn top_paths(paths: BTreeMap<String, u64>, limit: usize) -> Vec<RulePathCount> {
    let mut counts: Vec<RulePathCount> = paths
        .into_iter()
        .map(|(rule_path, count)| RulePathCount { rule_path, count })
        .collect();
    counts.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.rule_path.cmp(&b.rule_path))
    });
    counts.truncate(limit);
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{
        ActionSummary, Actor, EnforcementSummary, PolicySummary, RECEIPT_VERSION, RuleTraceEntry,
    };

    fn receipt(
        timestamp: &str,
        decision: Decision,
        block: &str,
        outcome: RuleOutcome,
    ) -> DecisionReceipt {
        DecisionReceipt {
            receipt_version: RECEIPT_VERSION.to_string(),
            receipt_id: "01a0a4f0-3200-7000-8000-000000000000".to_string(),
            timestamp: timestamp.to_string(),
            time_source: crate::receipt::TimeSource::Trusted,
            actor: Some(Actor {
                agent_id: Some("agent".to_string()),
                ..Actor::default()
            }),
            policy: PolicySummary {
                name: Some("p".to_string()),
                version: None,
                spec_version: "0.1.0".to_string(),
                content_hash: format!("sha256:{}", "0".repeat(64)),
                extends_chain: None,
                signature: None,
            },
            action: ActionSummary {
                action_type: "egress".to_string(),
                target: Some("example.com".to_string()),
                content_hash: None,
                content_size: None,
                args_size: None,
                origin: None,
                context: None,
            },
            decision,
            matched_rule: None,
            reason: None,
            rule_trace: vec![RuleTraceEntry {
                rule_block: block.to_string(),
                rule_path: Some(format!("rules.{block}.block[0]")),
                outcome,
                evaluated: outcome != RuleOutcome::Skip,
                reason: None,
            }],
            detection_trace: None,
            enforcement: EnforcementSummary::implied(decision, EnforcementMode::Enforce),
            origin_profile: None,
            posture: None,
            duration_us: None,
        }
    }

    #[test]
    fn totals_and_rule_blocks_count_what_the_trace_recorded() {
        let receipts = vec![
            receipt(
                "2026-09-15T01:00:00.000Z",
                Decision::Allow,
                "egress",
                RuleOutcome::Allow,
            ),
            receipt(
                "2026-09-15T02:00:00.000Z",
                Decision::Deny,
                "egress",
                RuleOutcome::Deny,
            ),
            receipt(
                "2026-09-15T03:00:00.000Z",
                Decision::Warn,
                "egress",
                RuleOutcome::Warn,
            ),
            receipt(
                "2026-09-15T04:00:00.000Z",
                Decision::Allow,
                "egress",
                RuleOutcome::Skip,
            ),
        ];
        let report = build_report(&receipts, &[], &ReportOptions::default());
        assert_eq!(report.totals.receipts, 4);
        assert_eq!(report.totals.by_decision.allow, 2);
        assert_eq!(report.totals.by_decision.deny, 1);
        assert_eq!(report.totals.by_decision.warn, 1);
        assert_eq!(report.totals.by_outcome.blocked, 2);
        assert_eq!(report.totals.by_outcome.allowed, 2);

        let block = &report.rule_blocks[0];
        assert_eq!(block.rule_block, "egress");
        assert_eq!(block.receipts, 4);
        assert_eq!(block.evaluated, 3);
        assert_eq!(block.skipped, 1);
        assert_eq!(block.fired, 2);
        assert_eq!(block.top_rule_paths[0].count, 4);

        assert_eq!(
            report.window.first_receipt.as_deref(),
            Some("2026-09-15T01:00:00.000Z")
        );
        assert_eq!(
            report.window.last_receipt.as_deref(),
            Some("2026-09-15T04:00:00.000Z")
        );
        assert_eq!(report.actors.len(), 1);
        assert_eq!(report.signatures.absent, 4);
    }

    #[test]
    fn the_window_bounds_are_inclusive_and_exclude_unparsable_timestamps() {
        let receipts = vec![
            receipt(
                "2026-09-15T01:00:00.000Z",
                Decision::Allow,
                "egress",
                RuleOutcome::Allow,
            ),
            receipt(
                "2026-09-15T02:00:00.000Z",
                Decision::Deny,
                "egress",
                RuleOutcome::Deny,
            ),
            receipt(
                "not a timestamp",
                Decision::Deny,
                "egress",
                RuleOutcome::Deny,
            ),
        ];
        let options = ReportOptions {
            since: Some("2026-09-15T02:00:00Z".parse().unwrap()),
            ..ReportOptions::default()
        };
        let report = build_report(&receipts, &[], &options);
        assert_eq!(report.totals.receipts, 1);
        assert_eq!(report.totals.by_decision.deny, 1);

        // Unbounded, every receipt counts, timestamp or not.
        let all = build_report(&receipts, &[], &ReportOptions::default());
        assert_eq!(all.totals.receipts, 3);
    }

    #[test]
    fn detections_and_signature_outcomes_are_summarized() {
        use crate::detection::{DetectionCategory, DetectorEvaluation};
        use crate::resolve::SignatureStatus;

        let mut first = receipt(
            "2026-09-15T01:00:00.000Z",
            Decision::Deny,
            "input_injection",
            RuleOutcome::Deny,
        );
        first.detection_trace = Some(vec![
            DetectorEvaluation {
                detector_id: "regex_injection@1".to_string(),
                category: DetectionCategory::PromptInjection,
                score: 0.9,
                level: DetectorLevel::Critical,
                matched: true,
            },
            DetectorEvaluation {
                detector_id: "regex_jailbreak@1".to_string(),
                category: DetectionCategory::Jailbreak,
                score: 0.1,
                level: DetectorLevel::Low,
                matched: false,
            },
        ]);
        first.policy.signature = Some(SignatureStatus {
            verified: false,
            key_id: None,
            verified_at: None,
            reason: Some("unknown_key_id".to_string()),
        });

        let mut second = receipt(
            "2026-09-15T02:00:00.000Z",
            Decision::Allow,
            "input_injection",
            RuleOutcome::Allow,
        );
        second.detection_trace = Some(vec![DetectorEvaluation {
            detector_id: "regex_injection@1".to_string(),
            category: DetectionCategory::PromptInjection,
            score: 0.0,
            level: DetectorLevel::None,
            matched: false,
        }]);
        second.policy.signature = Some(SignatureStatus {
            verified: true,
            key_id: None,
            verified_at: None,
            reason: None,
        });

        let report = build_report(&[first, second], &[], &ReportOptions::default());
        assert_eq!(report.detections.len(), 2);
        let injection = &report.detections[0];
        assert_eq!(injection.detector_id, "regex_injection@1");
        assert_eq!(injection.evaluated, 2);
        assert_eq!(injection.matched, 1);
        assert_eq!(injection.by_level.critical, 1);
        assert_eq!(injection.by_level.none, 1);

        assert_eq!(report.signatures.verified, 1);
        assert_eq!(report.signatures.unverified, 1);
        assert_eq!(report.signatures.absent, 0);
        assert_eq!(report.signatures.reasons[0].reason, "unknown_key_id");
        assert_eq!(report.signatures.reasons[0].count, 1);
    }
}
