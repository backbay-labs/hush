//! Decision receipts, format 0.2 (spec/hushspec-receipt.md).
//!
//! A receipt is the unit of evidence: which resolved policy was in force
//! (by canonical content hash), who acted, what was attempted (never the
//! content itself), what the policy decided and why, which rule blocks and
//! detectors actually ran, and what the enforcement point did with the
//! decision.
//!
//! Receipts are built from a [`Resolution`] so that the policy identity,
//! `extends_chain`, and signature status come from the load step and cost
//! nothing per evaluation. The rule trace is the evaluator's own recording
//! ([`crate::evaluate::evaluate_traced`]); nothing here is reconstructed from
//! the decision.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;

use crate::canonical::{self, CanonicalError};
use crate::conditions::{Condition, RuntimeContext};
use crate::evaluate::{
    Decision, EvaluationAction, PostureResult, Recording, UNKNOWN_ACTION_TYPE_RULE,
};
use crate::resolve::{ChainLink, Resolution, ResolveError, SignatureStatus};
use crate::schema::HushSpec;

pub use crate::detection::{DetectorEvaluation, DetectorLevel};
pub use crate::evaluate::{RuleEvaluation, RuleOutcome};

/// The receipt format this module writes and accepts.
pub const RECEIPT_VERSION: &str = "0.2";

/// The `rule_block` id a receipt uses for the unknown-action-type engine stage.
pub const UNKNOWN_ACTION_TYPE_BLOCK: &str = "unknown_action_type";
/// The `rule_block` id a receipt uses for the origins engine stage.
pub const ORIGIN_PROFILE_BLOCK: &str = "origin_profile";

// --------------------------------------------------------------------------
// Wire types
// --------------------------------------------------------------------------

/// How much to trust `timestamp` (receipt spec 3.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeSource {
    #[default]
    System,
    MonotonicAdjusted,
    Trusted,
    Unknown,
}

/// Who the action was evaluated for (receipt spec 4.1).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
}

impl Actor {
    /// True when no field is set (such an actor is omitted from receipts).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.agent_id.is_none()
            && self.session_id.is_none()
            && self.principal.is_none()
            && self.runtime.is_none()
    }
}

/// One link of `policy.extends_chain` (receipt spec 4.2): a document's
/// source and its own content hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptChainLink {
    pub source: String,
    pub content_hash: String,
}

impl From<&ChainLink> for ReceiptChainLink {
    fn from(link: &ChainLink) -> Self {
        Self {
            source: link.source.clone(),
            content_hash: link.content_hash.clone(),
        }
    }
}

/// Identity of the resolved policy (receipt spec 4.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `metadata.policy_version`, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    /// The policy's `hushspec` field.
    pub spec_version: String,
    /// Canonical content hash of the resolved policy (`sha256:` + hex).
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extends_chain: Option<Vec<ReceiptChainLink>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureStatus>,
}

/// The evaluated action, minus its content (receipt spec 4.4).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSummary {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// `sha256:` over the UTF-8 bytes of the content, when content was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_size: Option<u64>,
    /// The origin descriptor as supplied, as a JSON object with empty members
    /// dropped (see [`compact_object`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<serde_json::Value>,
    /// The runtime context as supplied, as a JSON object with empty members
    /// dropped (see [`compact_object`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

/// Serialize a supplied descriptor "verbatim" (receipt spec 4.4) in the one
/// form every SDK can reproduce: its JSON object with top-level members that
/// are absent, `null`, `{}`, or `[]` removed. Typed models differ in which
/// empty members they materialize; the document the caller supplied did not
/// have them.
///
/// # Errors
///
/// [`CanonicalError::Serialize`] when the value cannot be serialized.
pub fn compact_object<T: Serialize>(value: &T) -> Result<serde_json::Value, CanonicalError> {
    let mut value = serde_json::to_value(value)
        .map_err(|error| CanonicalError::Serialize(error.to_string()))?;
    if let Some(object) = value.as_object_mut() {
        object.retain(|_, member| match member {
            serde_json::Value::Null => false,
            serde_json::Value::Object(inner) => !inner.is_empty(),
            serde_json::Value::Array(inner) => !inner.is_empty(),
            _ => true,
        });
    }
    Ok(value)
}

/// One rule block's or engine stage's contribution (receipt spec 4.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleTraceEntry {
    pub rule_block: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_path: Option<String>,
    pub outcome: RuleOutcome,
    pub evaluated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl From<&RuleEvaluation> for RuleTraceEntry {
    /// Map the evaluator's recorded entry to the receipt spelling: the
    /// unknown-action stage is recorded under `default` with the reserved
    /// `__unknown_action_type__` rule, and the origins guard under `origins`;
    /// receipts use the closed ids `unknown_action_type` and
    /// `origin_profile` for those stages (receipt spec 4.3, item 5).
    fn from(entry: &RuleEvaluation) -> Self {
        let rule_block = match entry.rule_block.as_str() {
            "default" if entry.matched_rule.as_deref() == Some(UNKNOWN_ACTION_TYPE_RULE) => {
                UNKNOWN_ACTION_TYPE_BLOCK.to_string()
            }
            "origins" => ORIGIN_PROFILE_BLOCK.to_string(),
            other => other.to_string(),
        };
        Self {
            rule_block,
            rule_path: entry.matched_rule.clone(),
            outcome: entry.outcome,
            evaluated: entry.evaluated,
            reason: entry.reason.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    #[default]
    Enforce,
    Monitor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementOutcome {
    Allowed,
    Confirmed,
    Blocked,
    WouldBlock,
}

/// What the enforcement point did with the decision (receipt spec 4.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementSummary {
    pub mode: EnforcementMode,
    pub outcome: EnforcementOutcome,
}

impl EnforcementSummary {
    /// The disposition implied by a decision when there is no enforcement
    /// point to say otherwise: an allow proceeds; a warn with no confirmation
    /// channel is a deny (core spec 6); under monitor mode a warn or deny
    /// proceeds and is recorded as `would_block`.
    #[must_use]
    pub fn implied(decision: Decision, mode: EnforcementMode) -> Self {
        let outcome = match (decision, mode) {
            (Decision::Allow, _) => EnforcementOutcome::Allowed,
            (_, EnforcementMode::Enforce) => EnforcementOutcome::Blocked,
            (_, EnforcementMode::Monitor) => EnforcementOutcome::WouldBlock,
        };
        Self { mode, outcome }
    }
}

/// A decision receipt, format 0.2.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionReceipt {
    pub receipt_version: String,
    /// UUID v7, lowercase hyphenated.
    pub receipt_id: String,
    /// RFC 3339 UTC, exactly millisecond precision, `Z` suffix.
    pub timestamp: String,
    pub time_source: TimeSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<Actor>,
    pub policy: PolicySummary,
    pub action: ActionSummary,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub rule_trace: Vec<RuleTraceEntry>,
    /// Present when the detection pipeline ran, even if empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection_trace: Option<Vec<DetectorEvaluation>>,
    pub enforcement: EnforcementSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_us: Option<u64>,
}

/// Why a receipt could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ReceiptError {
    #[error("receipt is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported receipt_version {0:?}, expected {RECEIPT_VERSION:?}")]
    UnsupportedVersion(String),
    #[error("receipt does not satisfy the 0.2 schema: {0}")]
    Structure(String),
    #[error("receipt has no canonical form: {0}")]
    Canonical(#[from] CanonicalError),
}

impl DecisionReceipt {
    /// Parse a receipt, rejecting unknown fields, any version other than the
    /// one this module implements, and any document that is not shaped like a
    /// 0.2 receipt (receipt spec 3.1).
    ///
    /// # Errors
    ///
    /// [`ReceiptError::Json`], [`ReceiptError::UnsupportedVersion`] or
    /// [`ReceiptError::Structure`].
    pub fn parse(json: &str) -> Result<Self, ReceiptError> {
        let document: serde_json::Value = serde_json::from_str(json)?;
        Self::from_document(&document)
    }

    /// [`DecisionReceipt::parse`] for a document that is already parsed, so a
    /// log verifier reads the receipt its line holds rather than a
    /// re-serialization of it.
    ///
    /// # Errors
    ///
    /// As [`DecisionReceipt::parse`].
    pub(crate) fn from_document(document: &serde_json::Value) -> Result<Self, ReceiptError> {
        let receipt = Self::deserialize(document)?;
        if receipt.receipt_version != RECEIPT_VERSION {
            return Err(ReceiptError::UnsupportedVersion(receipt.receipt_version));
        }
        let problems = document_problems(document, &receipt);
        if !problems.is_empty() {
            return Err(ReceiptError::Structure(problems.join("; ")));
        }
        Ok(receipt)
    }

    /// Check this receipt against the structural rules of the 0.2 schema that
    /// a typed model cannot express: string patterns, members that must not be
    /// empty, and numeric bounds.
    ///
    /// # Errors
    ///
    /// [`ReceiptError::Structure`], listing every rule the receipt breaks
    /// rather than the first: a receipt that breaks several is usually one
    /// bug, and an auditor reading the report wants the whole picture.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        let problems = self.structural_problems();
        if problems.is_empty() {
            return Ok(());
        }
        Err(ReceiptError::Structure(problems.join("; ")))
    }

    /// The receipt's canonical form: RFC 8785 over the receipt object, with
    /// no projection step (receipt spec 6).
    ///
    /// # Errors
    ///
    /// [`CanonicalError`] when a value cannot be serialized (never for a
    /// receipt this module built).
    pub fn canonical_json(&self) -> Result<String, CanonicalError> {
        let value = serde_json::to_value(self)
            .map_err(|error| CanonicalError::Serialize(error.to_string()))?;
        canonical::serialize_jcs(&value)
    }

    /// `sha256:` over the canonical form (receipt spec 6): the value a log
    /// links and a receipt signature covers.
    ///
    /// # Errors
    ///
    /// As [`DecisionReceipt::canonical_json`].
    pub fn receipt_hash(&self) -> Result<String, CanonicalError> {
        Ok(canonical::digest(&self.canonical_json()?))
    }

    fn structural_problems(&self) -> Vec<String> {
        let mut problems = Vec::new();

        if self.receipt_version != RECEIPT_VERSION {
            problems.push(format!(
                "receipt_version {:?} is not {RECEIPT_VERSION:?}",
                self.receipt_version
            ));
        }
        if !is_uuid_v7(&self.receipt_id) {
            problems.push(format!(
                "receipt_id {:?} is not a lowercase UUID v7",
                self.receipt_id
            ));
        }
        push_timestamp_problem(&mut problems, "timestamp", &self.timestamp);

        // policy (receipt spec 4.2).
        if !is_spec_version(&self.policy.spec_version) {
            problems.push(format!(
                "policy.spec_version {:?} is outside the 0.x and 1.x lineages",
                self.policy.spec_version
            ));
        }
        push_hash_problem(
            &mut problems,
            "policy.content_hash",
            &self.policy.content_hash,
        );
        for (index, link) in self.policy.extends_chain.iter().flatten().enumerate() {
            push_empty_problem(
                &mut problems,
                &format!("policy.extends_chain[{index}].source"),
                &link.source,
            );
            push_hash_problem(
                &mut problems,
                &format!("policy.extends_chain[{index}].content_hash"),
                &link.content_hash,
            );
        }
        if let Some(status) = &self.policy.signature {
            if let Some(key_id) = &status.key_id {
                push_hash_problem(&mut problems, "policy.signature.key_id", key_id);
            }
            if let Some(verified_at) = &status.verified_at {
                push_timestamp_problem(&mut problems, "policy.signature.verified_at", verified_at);
            }
        }

        // action (receipt spec 4.4).
        push_empty_problem(&mut problems, "action.type", &self.action.action_type);
        if let Some(content_hash) = &self.action.content_hash {
            push_hash_problem(&mut problems, "action.content_hash", content_hash);
        }

        // rule_trace (receipt spec 4.3).
        for (index, entry) in self.rule_trace.iter().enumerate() {
            if !is_rule_block(&entry.rule_block) {
                problems.push(format!(
                    "rule_trace[{index}].rule_block {:?} is outside the closed enum",
                    entry.rule_block
                ));
            }
        }

        // detection_trace (receipt spec 4.6).
        for (index, entry) in self.detection_trace.iter().flatten().enumerate() {
            push_empty_problem(
                &mut problems,
                &format!("detection_trace[{index}].detector_id"),
                &entry.detector_id,
            );
            if !(0.0..=1.0).contains(&entry.score) {
                problems.push(format!(
                    "detection_trace[{index}].score {} is outside [0, 1]",
                    entry.score
                ));
            }
        }

        // posture (receipt spec 4.8).
        if let Some(posture) = &self.posture {
            push_empty_problem(&mut problems, "posture.current", &posture.current);
            push_empty_problem(&mut problems, "posture.next", &posture.next);
        }

        problems
    }
}

// --------------------------------------------------------------------------
// Structural validation (receipt spec 2, item 4)
// --------------------------------------------------------------------------
//
// Deserializing already enforces the schema's types, its closed enums and
// `additionalProperties: false` (an unknown member is a parse error). What a
// typed model cannot state is the rest: which strings match a pattern, which
// must not be empty, which numbers are in range, and that an explicit `null`
// is not the same document as an absent member. The checks below close that
// gap, so [`DecisionReceipt::parse`] and the log verifier accept exactly the
// documents `schemas/hushspec-receipt.v1.schema.json` accepts.
//
// They are a focused checker rather than a JSON Schema engine: the schema is
// normative and stable, and the library carries no validator dependency. Every
// rule names the member it comes from.

/// Every way a receipt document departs from the 0.2 schema.
///
/// Both forms are needed: `receipt` carries the typed members to check, and
/// `document` is the JSON the receipt was read from, which is the only place
/// an explicit `null` still shows.
pub(crate) fn document_problems(
    document: &serde_json::Value,
    receipt: &DecisionReceipt,
) -> Vec<String> {
    let mut problems = Vec::new();
    push_null_problems(document, "", &mut problems);
    problems.extend(receipt.structural_problems());
    problems
}

/// `sha256:` followed by 64 lowercase hex digits (canonical spec 5).
#[must_use]
pub(crate) fn is_content_hash(value: &str) -> bool {
    let Some(hex) = value.strip_prefix(canonical::CONTENT_HASH_PREFIX) else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// `$.receipt_id`: a UUID v7, lowercase, with the version nibble 7 and the
/// RFC 4122 variant bits.
fn is_uuid_v7(value: &str) -> bool {
    let bytes = value.as_bytes();
    let shape = b"########-####-####-####-############";
    if bytes.len() != shape.len() {
        return false;
    }
    for (byte, expected) in bytes.iter().zip(shape) {
        let ok = match expected {
            b'#' => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
            other => byte == other,
        };
        if !ok {
            return false;
        }
    }
    bytes[14] == b'7' && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

/// `$defs.PolicySummary.spec_version`: the v1 schema widened it to the 1.x
/// lineage, so a receipt for a 1.0.z policy validates (core spec 10.2).
fn is_spec_version(value: &str) -> bool {
    let mut parts = value.split('.');
    let (Some(major), Some(minor), Some(patch), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    matches!(major, "0" | "1") && digits(minor) && digits(patch)
}

/// The engine stages a `rule_trace` entry may name besides a rule block
/// (receipt spec 4.3, item 5).
const ENGINE_STAGE_BLOCKS: &[&str] = &[
    "posture_capability",
    ORIGIN_PROFILE_BLOCK,
    "panic",
    UNKNOWN_ACTION_TYPE_BLOCK,
    "default",
];

/// `$defs.RuleEvaluation.rule_block`: the rule-block ids, which are the keys of
/// `rules` exactly, plus the engine stages.
///
/// The bare spellings are normative: format 0.1 mixed `egress` and
/// `rules.egress`, and 0.2 closed the enum on the bare ids.
fn is_rule_block(value: &str) -> bool {
    crate::generated_contract::RULE_KEYS.contains(&value) || ENGINE_STAGE_BLOCKS.contains(&value)
}

fn push_hash_problem(problems: &mut Vec<String>, field: &str, value: &str) {
    if !is_content_hash(value) {
        problems.push(format!(
            "{field} {value:?} is not `sha256:` and 64 lowercase hex digits"
        ));
    }
}

fn push_timestamp_problem(problems: &mut Vec<String>, field: &str, value: &str) {
    if !is_millisecond_timestamp(value) {
        problems.push(format!(
            "{field} {value:?} is not an RFC 3339 UTC instant with millisecond precision"
        ));
    }
}

fn push_empty_problem(problems: &mut Vec<String>, field: &str, value: &str) {
    if value.is_empty() {
        problems.push(format!("{field} is empty"));
    }
}

/// Report every member of `document` that is explicitly `null`.
///
/// No member the schema defines admits `null`, so `"reason": null` is not the
/// document a receipt without a `reason` is -- and deserializing collapses the
/// two, while a log's `entry_hash` covers the difference. `action.origin` and
/// `action.context` are skipped: they carry the descriptor the caller supplied
/// verbatim, whose own members are not this schema's to constrain.
fn push_null_problems(document: &serde_json::Value, path: &str, problems: &mut Vec<String>) {
    match document {
        serde_json::Value::Null => problems.push(format!("{path} must not be null")),
        serde_json::Value::Object(members) => {
            for (key, value) in members {
                if path == "action" && (key == "origin" || key == "context") {
                    continue;
                }
                let child = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                push_null_problems(value, &child, problems);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                push_null_problems(item, &format!("{path}[{index}]"), problems);
            }
        }
        _ => {}
    }
}

// --------------------------------------------------------------------------
// Building receipts
// --------------------------------------------------------------------------

/// What to record. `enabled: false` skips timing and the trace (the decision
/// and policy identity are always correct; identity costs nothing because it
/// comes from the [`Resolution`]).
#[derive(Clone, Debug)]
pub struct AuditConfig {
    pub enabled: bool,
    pub include_rule_trace: bool,
    /// Record `duration_us`. Off for conformance vectors, whose bytes must
    /// not depend on the machine that produced them.
    pub record_duration: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            include_rule_trace: true,
            record_duration: true,
        }
    }
}

/// Everything about the evaluation that is not the policy or the action:
/// who is acting, what the enforcement point does, and the clock.
///
/// `clock` and `receipt_id` exist so tests and conformance vectors can be
/// deterministic; production callers leave them `None`.
#[derive(Clone, Debug, Default)]
pub struct AuditContext {
    pub actor: Option<Actor>,
    /// The enforcement point's disposition. `None` records the disposition
    /// implied by the decision under `enforcement_mode`.
    pub enforcement: Option<EnforcementSummary>,
    pub enforcement_mode: EnforcementMode,
    pub time_source: TimeSource,
    /// Fixed evaluation time (defaults to now).
    pub clock: Option<DateTime<Utc>>,
    /// Fixed receipt id (defaults to a fresh UUID v7).
    pub receipt_id: Option<String>,
    /// Explicit runtime context; replaces `action.context` when set.
    pub context: Option<RuntimeContext>,
    /// Out-of-band conditions keyed by rule-block name (see
    /// [`crate::evaluate::evaluate_with_context`]).
    pub conditions: HashMap<String, Condition>,
}

/// Format an instant the way receipts and envelopes spell it.
#[must_use]
pub fn format_timestamp(instant: DateTime<Utc>) -> String {
    instant.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Whether `value` is exactly what [`format_timestamp`] produces: RFC 3339
/// UTC, millisecond precision, `Z` suffix.
///
/// The shape is checked before parsing because `parse_from_rfc3339` also
/// accepts offsets and other sub-second precisions, which receipts and
/// envelopes do not.
pub(crate) fn is_millisecond_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    let shape = b"####-##-##T##:##:##.###Z";
    if bytes.len() != shape.len() {
        return false;
    }
    for (byte, expected) in bytes.iter().zip(shape) {
        let ok = match expected {
            b'#' => byte.is_ascii_digit(),
            other => byte == other,
        };
        if !ok {
            return false;
        }
    }
    // `parse_from_rfc3339` reads second 60 as a leap second. The schemas pin
    // the field to `[0-5][0-9]`, so a leap second is not an instant these
    // formats can carry, and accepting one would compare an expiry against a
    // time the other engines reject outright.
    if &bytes[17..19] == b"60" {
        return false;
    }
    DateTime::parse_from_rfc3339(value).is_ok()
}

/// A UUID v7 whose random bits come from `seed` instead of an RNG, so a
/// conformance vector can name the receipt id it expects.
#[must_use]
pub fn deterministic_uuid_v7(unix_millis: u64, seed: u64) -> String {
    let mut bytes = [0u8; 16];
    let ms = unix_millis & 0x0000_ffff_ffff_ffff;
    bytes[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
    let rand_a = (seed & 0x0fff) as u16;
    bytes[6] = 0x70 | (rand_a >> 8) as u8;
    bytes[7] = (rand_a & 0xff) as u8;
    let rand_b = (seed >> 12) & 0x3fff_ffff_ffff_ffff;
    let tail = rand_b.to_be_bytes();
    bytes[8] = 0x80 | (tail[0] & 0x3f);
    bytes[9..].copy_from_slice(&tail[1..]);
    Uuid::from_bytes(bytes).hyphenated().to_string()
}

/// Evaluate `action` against a resolved policy and record the receipt.
///
/// Routes through the detection pipeline when the policy has a `detection:`
/// extension, so the receipt's decision is the one an enforcement point acts
/// on, and `detection_trace` is present whenever detection ran.
pub fn evaluate_audited(
    resolution: &Resolution,
    action: &EvaluationAction,
    config: &AuditConfig,
    ctx: &AuditContext,
) -> DecisionReceipt {
    let plan = AuditPlan::new(config);
    let start = plan.timed.then(Instant::now);

    let detected = crate::detection::run_with_detection(
        &resolution.spec,
        action,
        ctx.context.as_ref(),
        &ctx.conditions,
        plan.recording,
    );
    let duration_us = start.map(|s| s.elapsed().as_micros() as u64);
    finish_receipt(resolution, action, &plan, ctx, detected, duration_us)
}

/// [`CompiledPolicy::evaluate_audited`], routed here so the compiled and the
/// compile-on-the-fly paths build identical receipts.
///
/// [`CompiledPolicy::evaluate_audited`]: crate::CompiledPolicy::evaluate_audited
pub(crate) fn record_receipt(
    policy: &crate::compiled::CompiledPolicy,
    resolution: &Resolution,
    action: &EvaluationAction,
    config: &AuditConfig,
    ctx: &AuditContext,
) -> DecisionReceipt {
    let plan = AuditPlan::new(config);
    let start = plan.timed.then(Instant::now);
    let detected = policy.run_with_detection(
        action,
        ctx.context.as_ref(),
        &ctx.conditions,
        plan.recording,
    );
    let duration_us = start.map(|s| s.elapsed().as_micros() as u64);
    finish_receipt(resolution, action, &plan, ctx, detected, duration_us)
}

/// What an [`AuditConfig`] asks an evaluation to do, read once so the compiled
/// and the compile-on-the-fly paths cannot answer it differently.
struct AuditPlan {
    /// Whether the evaluation records a rule trace.
    recording: Recording,
    /// Whether the receipt carries that trace.
    keep_trace: bool,
    /// Whether the evaluation is timed.
    timed: bool,
}

impl AuditPlan {
    fn new(config: &AuditConfig) -> Self {
        let keep_trace = config.enabled && config.include_rule_trace;
        let timed = config.enabled && config.record_duration;
        Self {
            // A trace nobody keeps is not recorded. A timed evaluation records
            // one regardless, so `duration_us` always covers the same work.
            recording: if keep_trace || timed {
                Recording::On
            } else {
                Recording::Off
            },
            keep_trace,
            timed,
        }
    }
}

fn finish_receipt(
    resolution: &Resolution,
    action: &EvaluationAction,
    plan: &AuditPlan,
    ctx: &AuditContext,
    detected: crate::detection::TracedEvaluationWithDetection,
    duration_us: Option<u64>,
) -> DecisionReceipt {
    let result = detected.evaluation;

    let rule_trace = if plan.keep_trace {
        build_trace(&detected.traced.trace, result.origin_profile.as_deref())
    } else {
        Vec::new()
    };

    let now = ctx.clock.unwrap_or_else(Utc::now);
    let receipt_id = ctx
        .receipt_id
        .clone()
        .unwrap_or_else(|| Uuid::now_v7().hyphenated().to_string());

    let enforcement = ctx
        .enforcement
        .unwrap_or_else(|| EnforcementSummary::implied(result.decision, ctx.enforcement_mode));

    DecisionReceipt {
        receipt_version: RECEIPT_VERSION.to_string(),
        receipt_id,
        timestamp: format_timestamp(now),
        time_source: ctx.time_source,
        actor: ctx.actor.clone().filter(|actor| !actor.is_empty()),
        policy: policy_summary(resolution),
        action: action_summary(action),
        decision: result.decision,
        matched_rule: result.matched_rule,
        reason: result.reason,
        rule_trace,
        detection_trace: detected.detector_trace,
        enforcement,
        origin_profile: result.origin_profile,
        posture: result.posture,
        duration_us,
    }
}

/// [`evaluate_audited`] for a document that is already resolved and has no
/// provenance to record. The content hash is computed on every call; hold a
/// [`Resolution`] instead when evaluating repeatedly.
///
/// # Errors
///
/// [`ResolveError::Canonical`] when the document still declares `extends` or
/// otherwise has no canonical form.
pub fn evaluate_audited_spec(
    spec: &HushSpec,
    action: &EvaluationAction,
    config: &AuditConfig,
    ctx: &AuditContext,
) -> Result<DecisionReceipt, ResolveError> {
    let resolution = Resolution::from_resolved(spec, None)?;
    Ok(evaluate_audited(&resolution, action, config, ctx))
}

/// `matched_rule` of a receipt for an action refused because the policy
/// did not verify (receipt spec 4.5).
pub const POLICY_UNVERIFIED_RULE: &str = "__hushspec_policy_unverified__";

/// The receipt an enforcement point that requires signatures emits when the
/// policy did not verify (signing spec 6.5): a deny with an empty trace,
/// `policy.signature.verified: false`, and the reason the verifier gave.
#[must_use]
pub fn unverified_policy_receipt(
    policy: PolicySummary,
    action: &EvaluationAction,
    ctx: &AuditContext,
) -> DecisionReceipt {
    let now = ctx.clock.unwrap_or_else(Utc::now);
    let reason = policy
        .signature
        .as_ref()
        .and_then(|status| status.reason.clone())
        .unwrap_or_else(|| "unverified".to_string());
    let enforcement = ctx
        .enforcement
        .unwrap_or_else(|| EnforcementSummary::implied(Decision::Deny, ctx.enforcement_mode));
    DecisionReceipt {
        receipt_version: RECEIPT_VERSION.to_string(),
        receipt_id: ctx
            .receipt_id
            .clone()
            .unwrap_or_else(|| Uuid::now_v7().hyphenated().to_string()),
        timestamp: format_timestamp(now),
        time_source: ctx.time_source,
        actor: ctx.actor.clone().filter(|actor| !actor.is_empty()),
        policy,
        action: action_summary(action),
        decision: Decision::Deny,
        matched_rule: Some(POLICY_UNVERIFIED_RULE.to_string()),
        reason: Some(format!("policy signature did not verify: {reason}")),
        rule_trace: Vec::new(),
        detection_trace: None,
        enforcement,
        origin_profile: None,
        posture: None,
        duration_us: None,
    }
}

/// The policy identity a receipt carries, taken from the resolution.
#[must_use]
pub fn policy_summary(resolution: &Resolution) -> PolicySummary {
    let spec = &resolution.spec;
    PolicySummary {
        name: spec.name.clone(),
        version: spec
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.policy_version)
            .map(|version| version as u64),
        spec_version: spec.hushspec.clone(),
        content_hash: resolution.content_hash.clone(),
        extends_chain: resolution.had_extends().then(|| {
            resolution
                .chain
                .iter()
                .map(ReceiptChainLink::from)
                .collect()
        }),
        signature: resolution.signature.clone(),
    }
}

fn action_summary(action: &EvaluationAction) -> ActionSummary {
    ActionSummary {
        action_type: action.action_type.clone(),
        target: action.target.clone(),
        content_hash: action.content.as_deref().map(canonical::digest),
        content_size: action.content.as_ref().map(|content| content.len() as u64),
        args_size: action.args_size.map(|size| size as u64),
        origin: action
            .origin
            .as_ref()
            .and_then(|origin| compact_object(origin).ok()),
        context: action
            .context
            .as_ref()
            .and_then(|context| compact_object(context).ok()),
    }
}

/// Convert the evaluator's recorded trace to receipt entries and add the
/// origins stage when a profile was selected (receipt spec 4.3, item 5).
///
/// The selected profile is a recorded fact of the same evaluation (the
/// evaluator returns it alongside the decision); it is placed first because
/// the origins guard runs before the posture guard and every rule block.
fn build_trace(trace: &[RuleEvaluation], origin_profile: Option<&str>) -> Vec<RuleTraceEntry> {
    let mut entries: Vec<RuleTraceEntry> = trace.iter().map(RuleTraceEntry::from).collect();
    if let Some(profile) = origin_profile
        && !entries
            .iter()
            .any(|entry| entry.rule_block == ORIGIN_PROFILE_BLOCK)
    {
        entries.insert(
            0,
            RuleTraceEntry {
                rule_block: ORIGIN_PROFILE_BLOCK.to_string(),
                rule_path: Some(format!("extensions.origins.profiles.{profile}")),
                outcome: RuleOutcome::Allow,
                evaluated: true,
                reason: Some("origin profile selected".to_string()),
            },
        );
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_uuid_v7_has_version_and_variant_bits() {
        let id = deterministic_uuid_v7(1_757_930_400_123, 42);
        let parsed = Uuid::parse_str(&id).unwrap();
        assert_eq!(parsed.get_version_num(), 7);
        assert_eq!(parsed.get_variant(), uuid::Variant::RFC4122);
        assert_eq!(id, deterministic_uuid_v7(1_757_930_400_123, 42));
        assert_ne!(id, deterministic_uuid_v7(1_757_930_400_123, 43));
    }

    #[test]
    fn implied_enforcement_maps_decision_and_mode() {
        use EnforcementMode::{Enforce, Monitor};
        use EnforcementOutcome::{Allowed, Blocked, WouldBlock};
        assert_eq!(
            EnforcementSummary::implied(Decision::Allow, Enforce).outcome,
            Allowed
        );
        assert_eq!(
            EnforcementSummary::implied(Decision::Warn, Enforce).outcome,
            Blocked
        );
        assert_eq!(
            EnforcementSummary::implied(Decision::Deny, Enforce).outcome,
            Blocked
        );
        assert_eq!(
            EnforcementSummary::implied(Decision::Deny, Monitor).outcome,
            WouldBlock
        );
    }

    #[cfg(feature = "signing")]
    #[test]
    fn a_millisecond_timestamp_is_a_real_instant() {
        assert!(is_millisecond_timestamp("2026-09-15T12:00:00.000Z"));
        assert!(!is_millisecond_timestamp("2026-06-30T23:59:60.000Z"));
        assert!(!is_millisecond_timestamp("2026-02-30T00:00:00.000Z"));
        assert!(!is_millisecond_timestamp("2026-09-15T12:00:00Z"));
        assert!(!is_millisecond_timestamp("2026-09-15T12:00:00.000+01:00"));
    }

    #[test]
    fn engine_stage_ids_are_mapped_to_the_closed_enum() {
        let entry = RuleEvaluation {
            rule_block: "default".to_string(),
            outcome: RuleOutcome::Deny,
            matched_rule: Some(UNKNOWN_ACTION_TYPE_RULE.to_string()),
            reason: None,
            evaluated: true,
        };
        assert_eq!(
            RuleTraceEntry::from(&entry).rule_block,
            UNKNOWN_ACTION_TYPE_BLOCK
        );
        let origins = RuleEvaluation {
            rule_block: "origins".to_string(),
            outcome: RuleOutcome::Deny,
            matched_rule: None,
            reason: None,
            evaluated: true,
        };
        assert_eq!(
            RuleTraceEntry::from(&origins).rule_block,
            ORIGIN_PROFILE_BLOCK
        );
    }
}
