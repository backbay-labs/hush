use crate::bundle::{AuditSpec, CaseBundle};
use chrono::{DateTime, Utc};
use hushspec::evaluate::{RuleEvaluation, RuleOutcome, evaluate_traced};
use hushspec::receipt::{
    ActionSummary, Actor, AuditConfig, AuditContext, DecisionReceipt, EnforcementMode,
    EnforcementSummary, RECEIPT_VERSION, TimeSource, deterministic_uuid_v7, evaluate_audited,
    format_timestamp, policy_summary,
};
use hushspec::{Decision, EvaluationAction, EvaluationResult, HushSpec, Resolution};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum DiffError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{sdk} harness failed ({status}): {stderr}")]
    HarnessFailed {
        sdk: String,
        status: String,
        stderr: String,
    },
    #[error("{sdk} harness produced an invalid report: {message}")]
    InvalidReport { sdk: String, message: String },
    #[error("{0}")]
    Config(String),
}

/// Per-case outcome, normalized to a cross-SDK shape.
/// (No deny_unknown_fields here: serde does not enforce it on internally
/// tagged enums; the structs inside carry it, and SdkReport rejects
/// unknown top-level fields.)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CaseVerdict {
    Ok { result: NormalizedResult },
    Rejected { phase: String, message: String },
    Error { message: String },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedResult {
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<NormalizedPosture>,
    /// The evaluator's own rule trace, in evaluation order (core spec 5) --
    /// what each SDK's traced evaluation, and therefore its receipt
    /// `rule_trace`, records.
    ///
    /// Defaulted rather than required so an older harness's report still
    /// deserializes; its omitted trace then compares as empty against the
    /// oracle's populated one, which is exactly the `RuleTrace` divergence a
    /// stale harness should produce rather than silently pass.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_trace: Vec<NormalizedRuleEvaluation>,
    /// `sha256:` over the canonical form (RFC 8785) of the format 0.2 receipt
    /// the SDK recorded for this case under the bundle's `audit` inputs
    /// (receipt spec 6) -- the evidence an auditor keeps, not just the answer
    /// the enforcement point acted on.
    ///
    /// Defaulted rather than required so a harness that predates the audited
    /// protocol still deserializes; its missing hash then compares as `None`
    /// against the reference's, which is the `Receipt` divergence a stale harness
    /// should produce rather than a silent pass. `--ignore-receipts` opts out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_hash: Option<String>,
    /// The whole receipt, reported only when the bundle asked for it
    /// (`audit.emit_receipts`). Carried so a hash mismatch can be rendered as
    /// the first differing member instead of two opaque digests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<serde_json::Value>,
}

/// One rule-block consultation, normalized to the shape every SDK's traced
/// evaluation produces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedRuleEvaluation {
    pub rule_block: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub evaluated: bool,
}

impl From<&RuleEvaluation> for NormalizedRuleEvaluation {
    fn from(entry: &RuleEvaluation) -> Self {
        let outcome = match entry.outcome {
            RuleOutcome::Allow => "allow",
            RuleOutcome::Warn => "warn",
            RuleOutcome::Deny => "deny",
            RuleOutcome::Skip => "skip",
        }
        .to_string();
        NormalizedRuleEvaluation {
            rule_block: entry.rule_block.clone(),
            outcome,
            matched_rule: entry.matched_rule.clone(),
            reason: entry.reason.clone(),
            evaluated: entry.evaluated,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedPosture {
    pub current: String,
    pub next: String,
}

impl NormalizedResult {
    /// Normalize an evaluation outcome together with the rule trace that
    /// produced it. Detection may rewrite `decision`/`matched_rule`/`reason`
    /// afterwards (see `evaluate_with_detection`) but never re-runs the rule
    /// blocks, so the trace always comes from the base traced evaluation.
    pub fn with_trace(result: EvaluationResult, trace: &[RuleEvaluation]) -> Self {
        let decision = match result.decision {
            hushspec::Decision::Allow => "allow",
            hushspec::Decision::Warn => "warn",
            hushspec::Decision::Deny => "deny",
        }
        .to_string();
        NormalizedResult {
            decision,
            matched_rule: result.matched_rule,
            reason: result.reason,
            origin_profile: result.origin_profile,
            posture: result.posture.map(|posture| NormalizedPosture {
                current: posture.current,
                next: posture.next,
            }),
            rule_trace: trace.iter().map(NormalizedRuleEvaluation::from).collect(),
            receipt_hash: None,
            receipt: None,
        }
    }
}

/// One SDK's verdicts for a whole bundle, keyed "gNNNN/aNNNN", plus the
/// per-group policy identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkReport {
    pub sdk: String,
    pub results: BTreeMap<String, CaseVerdict>,
    /// Per-group data that is not per-action, keyed by the bundle's group id.
    ///
    /// Defaulted rather than required so an older harness's report still
    /// deserializes; its empty map then compares as a missing `content_hash`
    /// against the reference's populated one, which is exactly the divergence a
    /// stale harness should produce rather than a silent pass.
    #[serde(default)]
    pub groups: BTreeMap<String, GroupReport>,
}

/// What an SDK reports about a bundle group's policy, as opposed to about one
/// action evaluated against it.
///
/// **Harness contract.** Alongside `results`, a harness emits
/// `"groups": {"<group id>": {"content_hash": "sha256:<64 hex>",
/// "receipt_hash": "sha256:<64 hex>"}}`, one entry per group in the bundle, in
/// the same pass that evaluates the group. The
/// hash is its SDK's canonical content hash (spec/hushspec-canonical.md
/// section 5) of the **resolved** policy it evaluated -- computed after
/// `parse -> resolve`, before evaluation. A group whose policy the SDK
/// rejected (parse, resolve, or validate) reports `content_hash: null`, or
/// omits the key, which is the same thing: there is no policy to identify.
///
/// Alongside it the harness reports `receipt_hash`: the hash of the
/// *policy-identity receipt* (see [`policy_identity_receipt`]), which is the
/// policy summary every receipt in the group embeds, carried in a receipt
/// skeleton so each SDK hashes it with its own receipt canonicalizer. It
/// isolates "the SDKs disagree about the policy their receipts name" from
/// "they disagree about one action", and a group whose policy was rejected
/// reports none.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupReport {
    /// `sha256:<64 lowercase hex>` over the canonical form of the resolved
    /// policy, or `None` when the policy never resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    /// `sha256:<64 lowercase hex>` over the canonical form of this group's
    /// policy-identity receipt, or `None` when the policy never resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_hash: Option<String>,
}

pub trait CaseEvaluator {
    fn sdk_name(&self) -> &str;
    fn evaluate_bundle(&mut self, bundle: &CaseBundle) -> Result<SdkReport, DiffError>;
}

/// `receipt_id` of every policy-identity receipt: a fixed UUID v7, so the
/// hash varies with the policy summary and with nothing else.
pub const POLICY_IDENTITY_RECEIPT_ID: &str = "00000000-0000-7000-8000-000000000000";
/// `action.type` of a policy-identity receipt. Reserved, never evaluated: the
/// receipt is built directly, not by evaluating anything.
pub const POLICY_IDENTITY_ACTION: &str = "__hushspec_policy_identity__";

/// A receipt that carries a group's policy summary and nothing else that
/// varies: fixed id, the bundle's clock and time source, a reserved action, a
/// deny with no rule and an empty trace.
///
/// Its hash is the group-level `receipt_hash` of the harness protocol. Every
/// SDK builds the identical skeleton and hashes it with its own receipt
/// canonicalizer, so a disagreement means the policy identity their receipts
/// would record differs -- `name`, `version`, `spec_version`, `content_hash`,
/// `extends_chain` or `signature` -- independently of any one action.
#[must_use]
pub fn policy_identity_receipt(
    resolution: &Resolution,
    clock: DateTime<Utc>,
    time_source: TimeSource,
    enforcement_mode: EnforcementMode,
) -> DecisionReceipt {
    DecisionReceipt {
        receipt_version: RECEIPT_VERSION.to_string(),
        receipt_id: POLICY_IDENTITY_RECEIPT_ID.to_string(),
        timestamp: format_timestamp(clock),
        time_source,
        actor: None,
        policy: policy_summary(resolution),
        action: ActionSummary {
            action_type: POLICY_IDENTITY_ACTION.to_string(),
            target: None,
            content_hash: None,
            content_size: None,
            args_size: None,
            origin: None,
            context: None,
        },
        decision: Decision::Deny,
        matched_rule: None,
        reason: None,
        rule_trace: Vec::new(),
        detection_trace: None,
        enforcement: EnforcementSummary::implied(Decision::Deny, enforcement_mode),
        origin_profile: None,
        posture: None,
        duration_us: None,
    }
}

/// The receipt one case of a bundle records: the same audited evaluation the
/// oracle runs, for a caller that holds the policy and action rather than a
/// bundle (the fixture emitter).
///
/// # Errors
///
/// [`DiffError::Config`] when the audit inputs cannot be read or the document
/// has no canonical form.
pub fn case_receipt(
    spec: &HushSpec,
    action: &EvaluationAction,
    audit: &AuditSpec,
    position: u64,
) -> Result<DecisionReceipt, DiffError> {
    let inputs = AuditInputs::from_spec(audit)?;
    let resolution = Resolution::from_resolved(spec, None)
        .map_err(|error| DiffError::Config(error.to_string()))?;
    Ok(evaluate_audited(
        &resolution,
        action,
        &inputs.config,
        &inputs.context(position),
    ))
}

/// The bundle's `audit` block, resolved into the typed inputs one audited
/// evaluation needs. Built once per bundle: parsing the clock or an enum
/// spelling per case would be both wasteful and a chance to disagree with
/// itself.
struct AuditInputs {
    config: AuditConfig,
    clock: DateTime<Utc>,
    clock_millis: u64,
    time_source: TimeSource,
    enforcement_mode: EnforcementMode,
    actor: Actor,
    index_base: u64,
    emit_receipts: bool,
}

impl AuditInputs {
    /// Fail-closed: an unreadable clock or an enum spelling this receipt
    /// format does not define is a hard error, never a silent fallback to
    /// "now" or to the default -- either would make the receipts of a run
    /// incomparable while still looking like agreement.
    fn from_spec(audit: &AuditSpec) -> Result<Self, DiffError> {
        fn enum_value<T: serde::de::DeserializeOwned>(
            field: &str,
            spelling: &str,
        ) -> Result<T, DiffError> {
            serde_json::from_value(serde_json::Value::String(spelling.to_string()))
                .map_err(|error| DiffError::Config(format!("audit.{field} {spelling:?}: {error}")))
        }
        Ok(Self {
            config: AuditConfig {
                enabled: true,
                include_rule_trace: true,
                // A receipt whose bytes depend on how fast the machine was is
                // not comparable across four SDKs.
                record_duration: false,
            },
            clock: audit.clock_datetime().map_err(DiffError::Config)?,
            clock_millis: audit.clock_millis().map_err(DiffError::Config)?,
            time_source: enum_value("time_source", &audit.time_source)?,
            enforcement_mode: enum_value("enforcement_mode", &audit.enforcement_mode)?,
            actor: audit.actor.clone(),
            index_base: audit.index_base,
            emit_receipts: audit.emit_receipts,
        })
    }

    /// The audit context for the case at `position` in the bundle.
    fn context(&self, position: u64) -> AuditContext {
        AuditContext {
            actor: Some(self.actor.clone()),
            enforcement: None,
            enforcement_mode: self.enforcement_mode,
            time_source: self.time_source,
            clock: Some(self.clock),
            receipt_id: Some(deterministic_uuid_v7(
                self.clock_millis,
                self.index_base.saturating_add(position),
            )),
            context: None,
            conditions: std::collections::HashMap::new(),
        }
    }

    fn group_receipt_hash(&self, resolution: &Resolution) -> Option<String> {
        policy_identity_receipt(
            resolution,
            self.clock,
            self.time_source,
            self.enforcement_mode,
        )
        .receipt_hash()
        .ok()
    }
}

/// The reference evaluator: the answer every SDK harness is compared
/// against. Applies the testkit runner's fixture ingestion:
/// YAML re-encode -> parse -> validate -> evaluate, and records the receipt of
/// every case it evaluates.
pub struct InProcessEvaluator;

impl CaseEvaluator for InProcessEvaluator {
    fn sdk_name(&self) -> &str {
        "rust"
    }

    fn evaluate_bundle(&mut self, bundle: &CaseBundle) -> Result<SdkReport, DiffError> {
        let inputs = AuditInputs::from_spec(&bundle.audit)?;
        let mut results = BTreeMap::new();
        let mut groups = BTreeMap::new();
        let mut position = 0u64;
        for group in &bundle.groups {
            let parsed = parse_policy(&group.policy);
            // The identity of the policy this group is actually evaluated
            // under: the resolved document, never the unresolved fragment
            // (canonical spec 2.1). A rejected policy has no identity, and a
            // resolution is what carries that identity into every receipt.
            let resolution = parsed
                .as_ref()
                .ok()
                .and_then(|spec| Resolution::from_resolved(spec, None).ok());
            groups.insert(
                group.id.clone(),
                GroupReport {
                    content_hash: resolution
                        .as_ref()
                        .map(|resolution| resolution.content_hash.clone()),
                    receipt_hash: resolution
                        .as_ref()
                        .and_then(|resolution| inputs.group_receipt_hash(resolution)),
                },
            );
            for case in &group.actions {
                let key = format!("{}/{}", group.id, case.id);
                let verdict = match (&parsed, &resolution) {
                    (Ok(spec), Some(resolution)) => {
                        evaluate_action(spec, resolution, &case.action, &inputs, position)
                    }
                    // Accepted but not canonicalizable: no identity, so no
                    // receipt either. Reported as an error rather than an
                    // evaluated verdict so it cannot pass as agreement.
                    (Ok(_), None) => CaseVerdict::Error {
                        message: "policy has no canonical form".to_string(),
                    },
                    (Err(rejection), _) => rejection.clone(),
                };
                results.insert(key, verdict);
                position += 1;
            }
        }
        Ok(SdkReport {
            sdk: "rust".to_string(),
            results,
            groups,
        })
    }
}

/// Flatten a document's `extends` chain with the composite loader, which
/// serves `builtin:<name>` from the SDK's own embedded rulesets.
///
/// The generator only ever emits `builtin:` references, so the loader's
/// filesystem branch is unreachable here and every SDK resolves from bytes it
/// ships -- no repo layout, no network, no ordering dependency. All three
/// harnesses call their SDK's equivalent (`resolve` / `Resolve`) at the same
/// point in the pipeline: parse -> resolve -> validate -> evaluate.
pub fn resolve_builtin_extends(spec: &HushSpec) -> Result<HushSpec, String> {
    hushspec::resolve_with_loader(spec, None, &hushspec::create_composite_loader())
        .map_err(|error| error.to_string())
}

// CaseVerdict::Ok carries a full NormalizedResult, so it's a "large" Err
// payload by clippy's default threshold. This is a private, parse-time-only
// helper (not the hot evaluation path), so the extra stack bytes on the
// error path are immaterial; boxing would only add noise at every call site.
#[allow(clippy::result_large_err)]
fn parse_policy(policy: &serde_json::Value) -> Result<HushSpec, CaseVerdict> {
    let yaml = serde_yaml::to_string(policy).map_err(|error| CaseVerdict::Error {
        message: format!("failed to re-encode policy: {error}"),
    })?;
    let spec = HushSpec::parse(&yaml).map_err(|error| CaseVerdict::Rejected {
        phase: "parse".to_string(),
        message: error.to_string(),
    })?;
    let spec = if spec.extends.is_some() {
        resolve_builtin_extends(&spec).map_err(|message| CaseVerdict::Rejected {
            phase: "resolve".to_string(),
            message,
        })?
    } else {
        spec
    };
    let validation = hushspec::validate(&spec);
    if !validation.is_valid() {
        return Err(CaseVerdict::Rejected {
            phase: "validate".to_string(),
            message: validation.errors[0].to_string(),
        });
    }
    Ok(spec)
}

fn evaluate_action(
    spec: &HushSpec,
    resolution: &Resolution,
    action: &serde_json::Value,
    inputs: &AuditInputs,
    position: u64,
) -> CaseVerdict {
    let action: EvaluationAction = match serde_json::from_value(action.clone()) {
        Ok(action) => action,
        Err(error) => {
            return CaseVerdict::Error {
                message: format!("invalid action: {error}"),
            };
        }
    };
    // The audited path is the one an enforcement point actually runs: it
    // routes through the detection pipeline and records the evidence. The
    // verdict compared here is therefore read back *out of the receipt*, so a
    // receipt that disagrees with its own decision is impossible by
    // construction rather than by convention.
    //
    // The base evaluator's trace comes from an explicit `evaluate_traced` call
    // over the same inputs: the receipt's own `rule_trace` is the receipt
    // spelling (engine-stage ids, `rule_path`), while `rule_trace` here is the
    // evaluator's. Detection never re-runs the rule blocks, so the two agree
    // by construction, and every harness mirrors this pairing.
    let traced = evaluate_traced(spec, &action, None, &std::collections::HashMap::new());
    let receipt = evaluate_audited(
        resolution,
        &action,
        &inputs.config,
        &inputs.context(position),
    );
    let receipt_hash = match receipt.receipt_hash() {
        Ok(hash) => hash,
        Err(error) => {
            return CaseVerdict::Error {
                message: format!("receipt has no canonical form: {error}"),
            };
        }
    };
    let evaluation = EvaluationResult {
        decision: receipt.decision,
        matched_rule: receipt.matched_rule.clone(),
        reason: receipt.reason.clone(),
        origin_profile: receipt.origin_profile.clone(),
        posture: receipt.posture.clone(),
    };
    let mut result = NormalizedResult::with_trace(evaluation, &traced.trace);
    result.receipt_hash = Some(receipt_hash);
    if inputs.emit_receipts {
        result.receipt = serde_json::to_value(&receipt).ok();
    }
    CaseVerdict::Ok { result }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceKind {
    Acceptance,
    Decision,
    MatchedRule,
    Reason,
    OriginProfile,
    Posture,
    RuleTrace,
    /// The SDKs disagree on the policy's canonical content hash, or the
    /// harness did not report one. Same policy, same identity -- otherwise
    /// receipts and signatures made by different SDKs cannot be compared.
    ContentHash,
    /// The SDKs recorded different receipts for the same case (or the same
    /// policy identity, for a group-keyed divergence), or the harness reported
    /// no receipt hash at all. The decision may well agree: what diverges is
    /// the evidence, which is what an auditor keeps and a log chains.
    Receipt,
    MissingCase,
    /// One side, or both, failed to produce a verdict at all. An `Error` is a
    /// harness or engine failure rather than a policy outcome, so two of them
    /// are agreement only when they say the same thing: an SDK that fails for
    /// a wholly different reason -- or on every case -- is a finding, not a
    /// match.
    HarnessError,
    /// The harness answered for a case key the reference (and therefore the
    /// bundle) never produced. Both the reference and every SDK evaluate the
    /// identical bundle, so this should be geometrically impossible for a
    /// correct harness -- when it happens it is harness-integrity evidence,
    /// not an ordinary verdict disagreement.
    PhantomCase,
}

#[derive(Debug, Clone, Serialize)]
pub struct Divergence {
    pub case_key: String,
    pub sdk: String,
    pub kind: DivergenceKind,
    pub oracle: CaseVerdict,
    pub observed: CaseVerdict,
    /// For a `Receipt` divergence: the first member on which the two receipts
    /// differ. Absent when the receipts themselves were never fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_difference: Option<ReceiptDifference>,
}

impl Divergence {
    /// A divergence with no receipt diff attached yet.
    fn new(
        case_key: String,
        sdk: String,
        kind: DivergenceKind,
        oracle: CaseVerdict,
        observed: CaseVerdict,
    ) -> Self {
        Self {
            case_key,
            sdk,
            kind,
            oracle,
            observed,
            receipt_difference: None,
        }
    }
}

/// Where two receipts first part company, walking their canonical forms in
/// RFC 8785 order. A receipt hash says only "not the same"; this says which
/// member to go and look at.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReceiptDifference {
    /// JSON Pointer (RFC 6901) of the first differing member, e.g.
    /// `/detection_trace/0/score`. Empty for two values of different types at
    /// the root.
    pub member: String,
    /// The reference's value there, absent when the member is missing entirely.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oracle: Option<serde_json::Value>,
    /// The harness's value there, absent when the member is missing entirely.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed: Option<serde_json::Value>,
}

impl std::fmt::Display for ReceiptDifference {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let render = |value: &Option<serde_json::Value>| match value {
            Some(value) => value.to_string(),
            None => "<absent>".to_string(),
        };
        write!(
            formatter,
            "{}: oracle {} vs {}",
            if self.member.is_empty() {
                "<root>"
            } else {
                &self.member
            },
            render(&self.oracle),
            render(&self.observed)
        )
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CompareOptions {
    pub ignore_reason: bool,
    /// Escape hatch for bisecting a trace-only regression; off by default so
    /// the fuzzer compares the whole trace, not just the final verdict.
    pub ignore_rule_trace: bool,
    /// Escape hatch for running against harnesses that predate the
    /// `content_hash` group key; off by default so a harness that omits it is
    /// a divergence rather than a silent pass.
    pub ignore_content_hash: bool,
    /// Escape hatch for running against harnesses that predate the audited
    /// protocol; off by default so a harness that reports no `receipt_hash` is
    /// a divergence rather than a silent pass.
    pub ignore_receipts: bool,
}

/// Compare an SDK report against the reference evaluator. First difference wins per
/// case; iteration follows the reference's sorted key order. The comparison is
/// symmetric in key coverage: a case the reference has but the harness omits is
/// `MissingCase`, and a case the harness answers but the reference (and
/// therefore the bundle) never produced is `PhantomCase`. Neither direction
/// is allowed to pass silently -- a buggy harness that fabricates extra
/// case keys must be exposed exactly like one that drops cases.
///
/// After the per-case verdicts, each group's canonical content hash is
/// compared as well (`ContentHash`), so the SDKs are held to one policy
/// identity and not only to one decision.
pub fn compare_reports(
    oracle: &SdkReport,
    observed: &SdkReport,
    options: &CompareOptions,
) -> Vec<Divergence> {
    let mut divergences = Vec::new();
    for (key, oracle_verdict) in &oracle.results {
        let Some(observed_verdict) = observed.results.get(key) else {
            divergences.push(Divergence::new(
                key.clone(),
                observed.sdk.clone(),
                DivergenceKind::MissingCase,
                oracle_verdict.clone(),
                CaseVerdict::Error {
                    message: "case missing from harness report".to_string(),
                },
            ));
            continue;
        };
        if let Some(kind) = verdict_divergence(oracle_verdict, observed_verdict, options) {
            let mut divergence = Divergence::new(
                key.clone(),
                observed.sdk.clone(),
                kind,
                oracle_verdict.clone(),
                observed_verdict.clone(),
            );
            if kind == DivergenceKind::Receipt {
                divergence.receipt_difference =
                    receipt_difference(oracle_verdict, observed_verdict);
            }
            divergences.push(divergence);
        }
    }
    for (key, observed_verdict) in &observed.results {
        if !oracle.results.contains_key(key) {
            divergences.push(Divergence::new(
                key.clone(),
                observed.sdk.clone(),
                DivergenceKind::PhantomCase,
                CaseVerdict::Error {
                    message: "case not present in oracle report or bundle".to_string(),
                },
                observed_verdict.clone(),
            ));
        }
    }
    divergences.extend(compare_group_reports(oracle, observed, options));
    divergences
}

/// The first differing member of two verdicts' receipts, when both carried
/// one. A hash-only report yields `None`; the caller then re-runs the case
/// with `audit.emit_receipts` to get the receipts themselves.
fn receipt_difference(oracle: &CaseVerdict, observed: &CaseVerdict) -> Option<ReceiptDifference> {
    let (CaseVerdict::Ok { result: left }, CaseVerdict::Ok { result: right }) = (oracle, observed)
    else {
        return None;
    };
    first_difference(left.receipt.as_ref()?, right.receipt.as_ref()?, "")
}

/// Walk two JSON values in RFC 8785 order (object members by key, arrays by
/// index) and return the first place they differ, as a JSON Pointer.
///
/// Object keys are compared in the canonical order -- sorted by UTF-16 code
/// unit -- so the "first" difference is the first one a reader of the two
/// canonical forms would reach, not an artifact of insertion order.
fn first_difference(
    oracle: &serde_json::Value,
    observed: &serde_json::Value,
    pointer: &str,
) -> Option<ReceiptDifference> {
    use serde_json::Value;
    let here = |left: Option<&Value>, right: Option<&Value>| {
        Some(ReceiptDifference {
            member: pointer.to_string(),
            oracle: left.cloned(),
            observed: right.cloned(),
        })
    };
    match (oracle, observed) {
        (Value::Object(left), Value::Object(right)) => {
            let mut keys: Vec<&String> = left.keys().collect();
            keys.extend(right.keys().filter(|key| !left.contains_key(*key)));
            keys.sort_by(|a, b| canonical_key_order(a, b));
            for key in keys {
                let child = format!("{pointer}/{}", escape_pointer(key));
                match (left.get(key), right.get(key)) {
                    (Some(left), Some(right)) => {
                        if let Some(difference) = first_difference(left, right, &child) {
                            return Some(difference);
                        }
                    }
                    (left, right) => {
                        return Some(ReceiptDifference {
                            member: child,
                            oracle: left.cloned(),
                            observed: right.cloned(),
                        });
                    }
                }
            }
            None
        }
        (Value::Array(left), Value::Array(right)) => {
            for index in 0..left.len().max(right.len()) {
                let child = format!("{pointer}/{index}");
                match (left.get(index), right.get(index)) {
                    (Some(left), Some(right)) => {
                        if let Some(difference) = first_difference(left, right, &child) {
                            return Some(difference);
                        }
                    }
                    (left, right) => {
                        return Some(ReceiptDifference {
                            member: child,
                            oracle: left.cloned(),
                            observed: right.cloned(),
                        });
                    }
                }
            }
            None
        }
        (left, right) if left == right => None,
        (left, right) => here(Some(left), Some(right)),
    }
}

/// RFC 8785 member ordering: by UTF-16 code unit, which differs from Rust's
/// `str` ordering (by code point) only for characters outside the BMP.
fn canonical_key_order(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

/// RFC 6901 escaping: `~` becomes `~0` and `/` becomes `~1`.
fn escape_pointer(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// Every group the reference or the harness knows about must carry the same
/// policy identity. A group the harness left out of `groups` has no hash,
/// which diverges against the reference's -- fail-closed, exactly like a case
/// missing from `results`. The divergence is keyed by the group id, which has
/// no `/` and therefore is never mistaken for a case key.
fn compare_group_reports(
    oracle: &SdkReport,
    observed: &SdkReport,
    options: &CompareOptions,
) -> Vec<Divergence> {
    let mut divergences = Vec::new();
    let mut group_ids: Vec<&String> = oracle.groups.keys().collect();
    group_ids.extend(
        observed
            .groups
            .keys()
            .filter(|id| !oracle.groups.contains_key(*id)),
    );
    for group_id in group_ids {
        let expected = oracle.groups.get(group_id);
        let actual = observed.groups.get(group_id);
        fn field(
            report: Option<&GroupReport>,
            pick: fn(&GroupReport) -> &Option<String>,
        ) -> Option<&String> {
            report.and_then(|report| pick(report).as_ref())
        }
        if !options.ignore_content_hash {
            let left = field(expected, |group| &group.content_hash);
            let right = field(actual, |group| &group.content_hash);
            if left != right {
                divergences.push(Divergence::new(
                    group_id.clone(),
                    observed.sdk.clone(),
                    DivergenceKind::ContentHash,
                    group_hash_verdict("content_hash", left),
                    group_hash_verdict("content_hash", right),
                ));
            }
        }
        if !options.ignore_receipts {
            let left = field(expected, |group| &group.receipt_hash);
            let right = field(actual, |group| &group.receipt_hash);
            if left != right {
                divergences.push(Divergence::new(
                    group_id.clone(),
                    observed.sdk.clone(),
                    DivergenceKind::Receipt,
                    group_hash_verdict("receipt_hash", left),
                    group_hash_verdict("receipt_hash", right),
                ));
            }
        }
    }
    divergences
}

/// A group-level hash rendered into the per-case shape `Divergence` carries,
/// so the JSON report and the terminal summary need no special case.
fn group_hash_verdict(field: &str, hash: Option<&String>) -> CaseVerdict {
    CaseVerdict::Error {
        message: match hash {
            Some(hash) => format!("{field} {hash}"),
            None => format!("no {field} reported"),
        },
    }
}

fn verdict_divergence(
    oracle: &CaseVerdict,
    observed: &CaseVerdict,
    options: &CompareOptions,
) -> Option<DivergenceKind> {
    match (oracle, observed) {
        (CaseVerdict::Ok { result: left }, CaseVerdict::Ok { result: right }) => {
            if left.decision != right.decision {
                return Some(DivergenceKind::Decision);
            }
            if left.matched_rule != right.matched_rule {
                return Some(DivergenceKind::MatchedRule);
            }
            if !options.ignore_reason && left.reason != right.reason {
                return Some(DivergenceKind::Reason);
            }
            if left.origin_profile != right.origin_profile {
                return Some(DivergenceKind::OriginProfile);
            }
            if left.posture != right.posture {
                return Some(DivergenceKind::Posture);
            }
            if !options.ignore_rule_trace && left.rule_trace != right.rule_trace {
                return Some(DivergenceKind::RuleTrace);
            }
            // Last, so a receipt difference that is really a decision or trace
            // difference is reported as the more specific kind.
            if !options.ignore_receipts && left.receipt_hash != right.receipt_hash {
                return Some(DivergenceKind::Receipt);
            }
            None
        }
        (CaseVerdict::Rejected { phase: left, .. }, CaseVerdict::Rejected { phase: right, .. }) => {
            (left != right).then_some(DivergenceKind::Acceptance)
        }
        (CaseVerdict::Error { message: left }, CaseVerdict::Error { message: right }) => {
            (left != right).then_some(DivergenceKind::HarnessError)
        }
        (CaseVerdict::Error { .. }, _) | (_, CaseVerdict::Error { .. }) => {
            Some(DivergenceKind::HarnessError)
        }
        _ => Some(DivergenceKind::Acceptance),
    }
}

/// Runs an SDK harness as `command... <bundle.json>` and parses its stdout
/// report. Fail-closed: spawn failures, non-zero exits, and malformed
/// reports are hard errors, never skipped SDKs.
#[derive(Clone)]
pub struct SubprocessEvaluator {
    pub sdk: String,
    pub command: Vec<String>,
    pub cwd: Option<std::path::PathBuf>,
}

impl CaseEvaluator for SubprocessEvaluator {
    fn sdk_name(&self) -> &str {
        &self.sdk
    }

    fn evaluate_bundle(&mut self, bundle: &CaseBundle) -> Result<SdkReport, DiffError> {
        let dir = tempfile::tempdir()?;
        let bundle_path = dir.path().join("bundle.json");
        let json = bundle
            .to_json()
            .map_err(|error| DiffError::Config(error.to_string()))?;
        std::fs::write(&bundle_path, json)?;

        let (program, args) = self
            .command
            .split_first()
            .ok_or_else(|| DiffError::Config(format!("{}: empty harness command", self.sdk)))?;
        let mut command = std::process::Command::new(program);
        command.args(args).arg(&bundle_path);
        if let Some(cwd) = &self.cwd {
            command.current_dir(cwd);
        }
        let output = command.output().map_err(|error| DiffError::HarnessFailed {
            sdk: self.sdk.clone(),
            status: "spawn failed".to_string(),
            stderr: error.to_string(),
        })?;
        if !output.status.success() {
            return Err(DiffError::HarnessFailed {
                sdk: self.sdk.clone(),
                status: output.status.to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        let report: SdkReport =
            serde_json::from_slice(&output.stdout).map_err(|error| DiffError::InvalidReport {
                sdk: self.sdk.clone(),
                message: error.to_string(),
            })?;
        if report.sdk != self.sdk {
            return Err(DiffError::InvalidReport {
                sdk: self.sdk.clone(),
                message: format!("report claims sdk '{}'", report.sdk),
            });
        }
        Ok(report)
    }
}

/// The SDKs a difftest run compares against the Rust implementation.
///
/// One list, used by the CLI's `--sdk` value parser, its default, and
/// [`default_subprocess_evaluators`], so the three cannot drift apart.
pub const DEFAULT_SDKS: [&str; 3] = ["typescript", "python", "go"];

/// Harness commands for each of [`DEFAULT_SDKS`].
#[must_use]
pub fn default_subprocess_evaluators(repo_root: &std::path::Path) -> Vec<SubprocessEvaluator> {
    vec![
        SubprocessEvaluator {
            sdk: "typescript".to_string(),
            command: vec![
                "node".to_string(),
                repo_root
                    .join("scripts/diffeval_ts.mjs")
                    .display()
                    .to_string(),
            ],
            cwd: None,
        },
        SubprocessEvaluator {
            sdk: "python".to_string(),
            command: vec![
                "python3".to_string(),
                repo_root
                    .join("scripts/diffeval_python.py")
                    .display()
                    .to_string(),
            ],
            cwd: None,
        },
        SubprocessEvaluator {
            sdk: "go".to_string(),
            command: vec![
                "go".to_string(),
                "run".to_string(),
                "./cmd/hushspec-diffeval".to_string(),
            ],
            cwd: Some(repo_root.join("packages/go")),
        },
    ]
}

pub struct DifftestConfig {
    pub seed: u64,
    pub groups_per_chunk: usize,
    pub actions_per_group: usize,
    pub chunks: usize,
    pub max_seconds: Option<u64>,
    /// Subset of [`DEFAULT_SDKS`]; Rust is always the baseline.
    pub sdks: Vec<String>,
    pub minimize: bool,
    pub emit_fixtures_dir: Option<std::path::PathBuf>,
    pub report_path: Option<std::path::PathBuf>,
    pub bundles_dir: std::path::PathBuf,
    pub ignore_reason: bool,
    pub ignore_rule_trace: bool,
    pub ignore_content_hash: bool,
    pub ignore_receipts: bool,
    /// Ask every harness for the full receipt of every case, not only on the
    /// second pass that follows a mismatch. Costs report size; buys a readable
    /// diff for a divergence that will not reproduce.
    pub emit_receipts: bool,
    pub repo_root: std::path::PathBuf,
    /// Replay an existing bundle instead of generating (single chunk).
    pub bundle_path: Option<std::path::PathBuf>,
    /// Test seam: replaces every selected SDK's command (keeps sdk names).
    pub harness_override: Option<Vec<String>>,
}

impl DifftestConfig {
    fn compare_options(&self) -> CompareOptions {
        CompareOptions {
            ignore_reason: self.ignore_reason,
            ignore_rule_trace: self.ignore_rule_trace,
            ignore_content_hash: self.ignore_content_hash,
            ignore_receipts: self.ignore_receipts,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DifftestOutcome {
    pub seed: u64,
    pub chunks_run: usize,
    pub cases_run: usize,
    pub divergences: Vec<Divergence>,
    pub fixtures: Vec<std::path::PathBuf>,
}

pub fn run_difftest(config: &DifftestConfig) -> Result<DifftestOutcome, DiffError> {
    if hushspec::is_panic_active() {
        return Err(DiffError::Config(
            "HushSpec panic mode is active; differential results would be meaningless".to_string(),
        ));
    }
    if config.sdks.is_empty() {
        return Err(DiffError::Config(
            "at least one SDK is required (typescript, python, go)".to_string(),
        ));
    }
    std::fs::create_dir_all(&config.bundles_dir)?;

    let available = default_subprocess_evaluators(&config.repo_root);
    let mut evaluators: Vec<SubprocessEvaluator> = Vec::new();
    for sdk in &config.sdks {
        let mut evaluator = available
            .iter()
            .find(|candidate| candidate.sdk == *sdk)
            .cloned()
            .ok_or_else(|| {
                DiffError::Config(format!(
                    "unknown sdk '{sdk}' (expected {})",
                    DEFAULT_SDKS.join(", ")
                ))
            })?;
        if let Some(command) = &config.harness_override {
            evaluator.command = command.clone();
            evaluator.cwd = None;
        }
        evaluators.push(evaluator);
    }

    let start = std::time::Instant::now();
    let mut outcome = DifftestOutcome {
        seed: config.seed,
        chunks_run: 0,
        cases_run: 0,
        divergences: Vec::new(),
        fixtures: Vec::new(),
    };
    let mut emitted: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    let chunks = if config.bundle_path.is_some() {
        1
    } else {
        config.chunks
    };
    for chunk in 0..chunks {
        if let Some(budget) = config.max_seconds
            && chunk > 0
            && start.elapsed().as_secs() >= budget
        {
            break;
        }
        let chunk_seed = config.seed.wrapping_add(chunk as u64);
        let mut bundle = match &config.bundle_path {
            Some(path) => {
                CaseBundle::from_json(&std::fs::read_to_string(path)?).map_err(DiffError::Config)?
            }
            None => crate::r#gen::generate_bundle(
                chunk_seed,
                &crate::r#gen::GenConfig {
                    groups: config.groups_per_chunk,
                    actions_per_group: config.actions_per_group,
                },
            ),
        };
        // A replayed bundle keeps the audit inputs it was generated with --
        // otherwise its receipts would not be the receipts it recorded -- and
        // only `emit_receipts` is a property of this run rather than of the
        // bundle.
        if config.emit_receipts {
            bundle.audit.emit_receipts = true;
        }
        let bundle = bundle;
        let bundle_file = config.bundles_dir.join(format!("bundle-{chunk_seed}.json"));
        std::fs::write(
            &bundle_file,
            bundle
                .to_json()
                .map_err(|error| DiffError::Config(error.to_string()))?,
        )?;

        let mut oracle = InProcessEvaluator;
        let oracle_report = oracle.evaluate_bundle(&bundle)?;

        for evaluator in &mut evaluators {
            let report = evaluator.evaluate_bundle(&bundle)?;
            let options = config.compare_options();
            for mut divergence in compare_reports(&oracle_report, &report, &options) {
                // A receipt divergence reported as two hashes says nothing an
                // auditor can act on. Re-run that one case with the receipts
                // themselves -- under the same receipt id, so what comes back
                // is what was hashed -- and record where they first differ.
                if divergence.kind == DivergenceKind::Receipt
                    && divergence.receipt_difference.is_none()
                {
                    enrich_receipt_divergence(&bundle, &mut divergence, evaluator);
                }
                if config.minimize {
                    handle_divergence(
                        config,
                        &bundle,
                        divergence,
                        evaluator,
                        &mut outcome,
                        &mut emitted,
                    )?;
                } else {
                    outcome.divergences.push(divergence);
                }
            }
        }

        outcome.chunks_run += 1;
        outcome.cases_run += bundle.case_count();
    }

    if let Some(report_path) = &config.report_path {
        if let Some(parent) = report_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            report_path,
            serde_json::to_string_pretty(&outcome)
                .map_err(|error| DiffError::Config(error.to_string()))?,
        )?;
    }
    Ok(outcome)
}

/// Re-run one diverging case with `audit.emit_receipts`, on both sides, and
/// record what came back: the two receipts, on the verdicts the report
/// carries, and the member they first differ on.
///
/// Best-effort by design: a harness that fails or answers differently the
/// second time leaves the divergence reported as the two hashes it already
/// is. Doing nothing never hides a divergence, it only leaves it terse.
fn enrich_receipt_divergence(
    bundle: &CaseBundle,
    divergence: &mut Divergence,
    failing: &mut dyn CaseEvaluator,
) {
    // Group-keyed receipt divergences (the policy-identity receipt) have no
    // single action to re-run, and neither does a key this bundle never
    // produced.
    let Some((group, case, position)) = bundle.find_case(&divergence.case_key) else {
        return;
    };
    let probe = CaseBundle::single_case_at(
        group.policy.clone(),
        case.action.clone(),
        &bundle.audit,
        position,
    );
    let mut oracle = InProcessEvaluator;
    let (Ok(oracle_report), Ok(failing_report)) = (
        oracle.evaluate_bundle(&probe),
        failing.evaluate_bundle(&probe),
    ) else {
        return;
    };
    let key = "g0001/a0001";
    let (Some(oracle_verdict), Some(failing_verdict)) = (
        oracle_report.results.get(key),
        failing_report.results.get(key),
    ) else {
        return;
    };

    divergence.receipt_difference = receipt_difference(oracle_verdict, failing_verdict);
    // Carry the receipts themselves into the report, so the artifact a
    // nightly run uploads holds the evidence and not only a pointer at it.
    // Only the receipt is taken from the second pass; every other field stays
    // as the run observed it.
    for (target, probe) in [
        (&mut divergence.oracle, oracle_verdict),
        (&mut divergence.observed, failing_verdict),
    ] {
        if let (CaseVerdict::Ok { result: target }, CaseVerdict::Ok { result: probe }) =
            (target, probe)
        {
            target.receipt = probe.receipt.clone();
        }
    }
}

fn handle_divergence(
    config: &DifftestConfig,
    bundle: &CaseBundle,
    divergence: Divergence,
    failing: &mut SubprocessEvaluator,
    outcome: &mut DifftestOutcome,
    emitted: &mut std::collections::BTreeSet<String>,
) -> Result<(), DiffError> {
    // A divergence whose case_key is not a real bundle case (PhantomCase, or a
    // malformed key from a misbehaving harness) cannot be minimized. Record it
    // as-is rather than aborting the whole run and discarding the real
    // divergences already collected in this chunk.
    let Some((group, case, _)) = bundle.find_case(&divergence.case_key) else {
        outcome.divergences.push(divergence);
        return Ok(());
    };

    let mut oracle = InProcessEvaluator;
    let minimized = match crate::minimize::minimize_case(
        &group.policy,
        &case.action,
        &mut oracle,
        failing,
        &config.compare_options(),
        &crate::minimize::MinimizeConfig::default(),
    ) {
        Ok(minimized) => minimized,
        // Minimization could not reproduce/shrink (e.g. a flaky harness that
        // agrees once the case is isolated). Keep the original divergence.
        Err(_) => {
            outcome.divergences.push(divergence);
            return Ok(());
        }
    };

    if let Some(dir) = &config.emit_fixtures_dir {
        let probe = CaseBundle::single_case(minimized.policy.clone(), minimized.action.clone());
        let report = oracle.evaluate_bundle(&probe)?;
        let verdict = report
            .results
            .values()
            .next()
            .ok_or_else(|| DiffError::Config("empty oracle report".to_string()))?;
        match crate::emit::build_regression_fixture(&minimized, verdict, config.seed) {
            Ok((filename, yaml)) => {
                if emitted.insert(filename.clone()) {
                    let path = crate::emit::write_regression_fixture(dir, &filename, &yaml)?;
                    outcome.fixtures.push(path);
                }
            }
            // Say so: a caller who passed --emit-fixtures and got none has no
            // other way to learn the emitter refused this case.
            Err(error) => eprintln!(
                "note: no regression fixture for {}: {error}",
                divergence.case_key
            ),
        }
    }

    outcome.divergences.push(divergence);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the test that arms the process-wide panic latch against the
    /// ones that call `run_difftest`, which refuses to run while it is armed.
    /// `hushspec::activate_panic` sets one global flag and this binary runs
    /// its tests in parallel, so without a latch of our own an unrelated
    /// difftest can observe the arming and fail.
    static PANIC_LATCH: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Hold [`PANIC_LATCH`], ignoring poisoning: a panicking test has already
    /// reported its own failure, and blocking every later one behind it would
    /// only hide which test really broke.
    fn panic_latch() -> std::sync::MutexGuard<'static, ()> {
        PANIC_LATCH
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    /// `(decision, matched_rule, reason)` plus the `(rule_block, outcome)`
    /// sequence of the trace -- everything the differential comparison looks
    /// at, minus the trace's own reason strings, which the per-block reasons
    /// of `hushspec::evaluate` already pin in that crate's own suite.
    type VerdictShape<'a> = (
        &'a str,
        Option<&'a str>,
        Option<&'a str>,
        Vec<(&'a str, &'a str)>,
    );

    fn verdict_shape(verdict: &CaseVerdict) -> VerdictShape<'_> {
        let CaseVerdict::Ok { result } = verdict else {
            panic!("expected an evaluated verdict, got {verdict:?}");
        };
        (
            result.decision.as_str(),
            result.matched_rule.as_deref(),
            result.reason.as_deref(),
            result
                .rule_trace
                .iter()
                .map(|entry| (entry.rule_block.as_str(), entry.outcome.as_str()))
                .collect(),
        )
    }

    #[test]
    fn oracle_matches_hand_computed_verdicts_on_sample_bundle() {
        let bundle = CaseBundle::from_json(include_str!("../testdata/sample-bundle.json"))
            .expect("sample bundle parses");
        let mut oracle = InProcessEvaluator;
        let report = oracle.evaluate_bundle(&bundle).expect("oracle evaluates");
        assert_eq!(report.sdk, "rust");
        assert_eq!(report.results.len(), 4);

        assert_eq!(
            verdict_shape(report.results.get("g0001/a0001").expect("case present")),
            (
                "allow",
                Some("rules.tool_access.allow"),
                Some("tool is explicitly allowed"),
                vec![("tool_access", "allow"), ("secret_patterns", "skip")],
            )
        );

        assert_eq!(
            verdict_shape(report.results.get("g0001/a0002").expect("case present")),
            (
                "deny",
                Some("rules.tool_access.block"),
                Some("tool is explicitly blocked"),
                vec![("tool_access", "deny"), ("secret_patterns", "skip")],
            )
        );

        assert_eq!(
            verdict_shape(report.results.get("g0002/a0001").expect("case present")),
            (
                "deny",
                Some("rules.forbidden_paths.patterns"),
                Some("path matched a forbidden pattern"),
                vec![("forbidden_paths", "deny"), ("path_allowlist", "skip")],
            )
        );

        assert_eq!(
            verdict_shape(report.results.get("g0002/a0002").expect("case present")),
            (
                "allow",
                None,
                None,
                vec![("forbidden_paths", "allow"), ("path_allowlist", "skip")],
            )
        );
    }

    /// The reference must report the trace, not just the verdict: a trace-only
    /// disagreement is a real evaluator divergence (it is what a receipt
    /// records), so the bundle protocol carries the trace and not only the
    /// decision.
    #[test]
    fn oracle_reports_a_rule_trace_and_trace_only_differences_diverge() {
        let bundle = CaseBundle::single_case(
            serde_json::json!({
                "hushspec": "0.2.0",
                "rules": {"tool_access": {"allow": ["read_file"], "default": "block"}}
            }),
            serde_json::json!({"type": "tool_call", "target": "read_file"}),
        );
        let mut oracle = InProcessEvaluator;
        let report = oracle.evaluate_bundle(&bundle).expect("oracle evaluates");
        let verdict = report.results.get("g0001/a0001").expect("case present");
        let CaseVerdict::Ok { result } = verdict else {
            panic!("expected an evaluated verdict, got {verdict:?}");
        };
        assert!(
            !result.rule_trace.is_empty(),
            "the reference must surface the evaluator's rule trace"
        );

        // Same verdict, empty trace: exactly what a harness that forgot to
        // report `rule_trace` would send.
        let mut stripped = result.clone();
        stripped.rule_trace.clear();
        let observed = SdkReport {
            sdk: "go".to_string(),
            results: [(
                "g0001/a0001".to_string(),
                CaseVerdict::Ok { result: stripped },
            )]
            .into_iter()
            .collect(),
            groups: report.groups.clone(),
        };
        let divergences = compare_reports(&report, &observed, &CompareOptions::default());
        assert_eq!(divergences.len(), 1);
        assert_eq!(divergences[0].kind, DivergenceKind::RuleTrace);

        // ...and --ignore-rule-trace suppresses exactly that.
        let options = CompareOptions {
            ignore_rule_trace: true,
            ..CompareOptions::default()
        };
        assert!(compare_reports(&report, &observed, &options).is_empty());
    }

    /// The reference reports one canonical content hash per group, over the
    /// *resolved* policy. A harness that reports a different hash -- or none
    /// at all -- is a divergence, because a receipt or signature made by that
    /// SDK would name a policy the others cannot recognize.
    #[test]
    fn content_hashes_are_compared_per_group_and_missing_ones_diverge() {
        let bundle = CaseBundle::single_case(
            serde_json::json!({"hushspec": "0.2.0", "extends": "builtin:default"}),
            serde_json::json!({"type": "tool_call", "target": "shell_exec"}),
        );
        let mut oracle = InProcessEvaluator;
        let report = oracle.evaluate_bundle(&bundle).expect("oracle evaluates");

        // The identity is the resolved policy's, not the two-line fragment's.
        let expected = report.groups["g0001"]
            .content_hash
            .clone()
            .expect("the reference hashes an accepted policy");
        assert!(expected.starts_with("sha256:"), "{expected}");
        let resolved = parse_policy(&bundle.groups[0].policy).expect("policy resolves");
        assert_eq!(expected, hushspec::content_hash(&resolved).expect("hashes"));
        assert_ne!(
            expected,
            hushspec::canonical::content_hash_value(&bundle.groups[0].policy).unwrap_or_default(),
            "an unresolved document must not hash to the resolved identity"
        );

        let agreeing = SdkReport {
            sdk: "go".to_string(),
            ..report.clone()
        };
        assert!(compare_reports(&report, &agreeing, &CompareOptions::default()).is_empty());

        // A harness that never learned the group key reports nothing.
        let silent = SdkReport {
            sdk: "go".to_string(),
            groups: BTreeMap::new(),
            ..report.clone()
        };
        // ...and loses both group-level facts: the policy's identity and the
        // identity its receipts would record.
        let divergences = compare_reports(&report, &silent, &CompareOptions::default());
        assert_eq!(
            divergences
                .iter()
                .map(|divergence| (divergence.case_key.as_str(), divergence.kind))
                .collect::<Vec<_>>(),
            vec![
                ("g0001", DivergenceKind::ContentHash),
                ("g0001", DivergenceKind::Receipt),
            ]
        );

        // A harness that computes a different identity is the real bug this
        // comparison exists to catch.
        let mut wrong = report.clone();
        wrong.sdk = "python".to_string();
        wrong.groups.insert(
            "g0001".to_string(),
            GroupReport {
                content_hash: Some(format!("{}0", &expected[..expected.len() - 1])),
                receipt_hash: report.groups["g0001"].receipt_hash.clone(),
            },
        );
        let divergences = compare_reports(&report, &wrong, &CompareOptions::default());
        assert_eq!(divergences.len(), 1);
        assert_eq!(divergences[0].kind, DivergenceKind::ContentHash);

        // ...and --ignore-content-hash suppresses exactly that.
        let options = CompareOptions {
            ignore_content_hash: true,
            ..CompareOptions::default()
        };
        assert!(compare_reports(&report, &wrong, &options).is_empty());
        // The silent harness still loses its group-level receipt hash, which
        // `--ignore-content-hash` has no business suppressing.
        let both = CompareOptions {
            ignore_content_hash: true,
            ignore_receipts: true,
            ..CompareOptions::default()
        };
        assert!(compare_reports(&report, &silent, &both).is_empty());
    }

    /// A harness whose receipt differs -- even when its decision, rule trace
    /// and every other compared field agree -- is a divergence, and the report
    /// names the member that differs rather than two opaque digests.
    #[test]
    fn a_receipt_only_difference_diverges_and_names_the_differing_member() {
        let mut bundle = CaseBundle::single_case(
            serde_json::json!({
                "hushspec": "0.2.0",
                "rules": {"tool_access": {"allow": ["read_file"], "default": "block"}}
            }),
            serde_json::json!({"type": "tool_call", "target": "read_file"}),
        );
        bundle.audit.emit_receipts = true;
        let mut oracle = InProcessEvaluator;
        let report = oracle.evaluate_bundle(&bundle).expect("oracle evaluates");
        let CaseVerdict::Ok { result } = &report.results["g0001/a0001"] else {
            panic!("the reference must evaluate this case");
        };
        assert!(
            result.receipt_hash.is_some(),
            "the reference records a receipt"
        );

        // Everything the pre-receipt fuzzer compared still agrees; only the
        // recorded evidence differs -- here, an actor the SDK dropped.
        let mut stale = result.clone();
        let mut receipt = result.receipt.clone().expect("receipts were requested");
        receipt
            .as_object_mut()
            .expect("a receipt is an object")
            .remove("actor");
        stale.receipt_hash = Some(
            hushspec::receipt::DecisionReceipt::parse(&receipt.to_string())
                .expect("receipt round-trips")
                .receipt_hash()
                .expect("hashes"),
        );
        stale.receipt = Some(receipt);
        let observed = SdkReport {
            sdk: "python".to_string(),
            results: [("g0001/a0001".to_string(), CaseVerdict::Ok { result: stale })]
                .into_iter()
                .collect(),
            groups: report.groups.clone(),
        };

        let divergences = compare_reports(&report, &observed, &CompareOptions::default());
        assert_eq!(divergences.len(), 1);
        assert_eq!(divergences[0].kind, DivergenceKind::Receipt);
        let difference = divergences[0]
            .receipt_difference
            .as_ref()
            .expect("both receipts were reported, so the diff is right there");
        assert_eq!(difference.member, "/actor");
        assert!(difference.oracle.is_some());
        assert!(difference.observed.is_none());
        assert!(difference.to_string().contains("<absent>"));

        // ...and --ignore-receipts suppresses exactly that.
        let options = CompareOptions {
            ignore_receipts: true,
            ..CompareOptions::default()
        };
        assert!(compare_reports(&report, &observed, &options).is_empty());
    }

    /// A harness that predates the audited protocol reports no receipt hash at
    /// all. That must fail closed -- it is the difference between "the SDKs
    /// agree on the evidence" and "one of them was never asked".
    #[test]
    fn a_harness_that_reports_no_receipt_hash_diverges() {
        let bundle = CaseBundle::single_case(
            serde_json::json!({"hushspec": "0.2.0", "rules": {"tool_access": {"allow": ["x"]}}}),
            serde_json::json!({"type": "tool_call", "target": "x"}),
        );
        let mut oracle = InProcessEvaluator;
        let report = oracle.evaluate_bundle(&bundle).expect("oracle evaluates");
        let CaseVerdict::Ok { result } = &report.results["g0001/a0001"] else {
            panic!("the reference must evaluate this case");
        };
        let mut silent = result.clone();
        silent.receipt_hash = None;
        let observed = SdkReport {
            sdk: "typescript".to_string(),
            results: [(
                "g0001/a0001".to_string(),
                CaseVerdict::Ok { result: silent },
            )]
            .into_iter()
            .collect(),
            groups: report.groups.clone(),
        };
        let divergences = compare_reports(&report, &observed, &CompareOptions::default());
        assert_eq!(divergences.len(), 1);
        assert_eq!(divergences[0].kind, DivergenceKind::Receipt);
        // No receipts were reported, so there is nothing to diff: the run
        // re-runs the case to fetch them (see `enrich_receipt_divergence`).
        assert!(divergences[0].receipt_difference.is_none());
    }

    /// The group-level `receipt_hash` is the policy identity every receipt in
    /// the group embeds, and it changes with the summary -- not with the
    /// action, the clock, or the receipt id.
    #[test]
    fn the_group_receipt_hash_tracks_the_policy_summary() {
        let named = serde_json::json!({
            "hushspec": "0.2.0",
            "name": "alpha",
            "rules": {"tool_access": {"allow": ["read_file"]}}
        });
        let mut renamed = named.clone();
        renamed["name"] = serde_json::json!("beta");

        let mut oracle = InProcessEvaluator;
        let hash_of = |policy: serde_json::Value, oracle: &mut InProcessEvaluator| {
            let bundle = CaseBundle::single_case(
                policy,
                serde_json::json!({"type": "tool_call", "target": "read_file"}),
            );
            oracle.evaluate_bundle(&bundle).expect("evaluates").groups["g0001"]
                .receipt_hash
                .clone()
                .expect("an accepted policy has an identity receipt")
        };
        let first = hash_of(named.clone(), &mut oracle);
        assert!(first.starts_with("sha256:"), "{first}");
        assert_ne!(
            first,
            hash_of(renamed, &mut oracle),
            "a renamed policy is a different identity in every receipt"
        );

        // A different action against the same policy leaves it untouched.
        let other_action = CaseBundle::single_case(
            named,
            serde_json::json!({"type": "tool_call", "target": "shell_exec"}),
        );
        assert_eq!(
            oracle
                .evaluate_bundle(&other_action)
                .expect("evaluates")
                .groups["g0001"]
                .receipt_hash,
            Some(first)
        );
    }

    /// The first difference is the first one a reader of the two *canonical*
    /// forms reaches: members in RFC 8785 order, array entries by index, and
    /// a JSON Pointer that escapes `/` and `~`.
    #[test]
    fn first_difference_walks_canonical_order() {
        let left = serde_json::json!({"b": 1, "a": {"z": [1, 2, 3]}});
        let right = serde_json::json!({"b": 2, "a": {"z": [1, 9, 3]}});
        // "a" sorts before "b", so the nested array difference wins.
        let difference = first_difference(&left, &right, "").expect("they differ");
        assert_eq!(difference.member, "/a/z/1");
        assert_eq!(difference.oracle, Some(serde_json::json!(2)));
        assert_eq!(difference.observed, Some(serde_json::json!(9)));

        assert!(first_difference(&left, &left, "").is_none());

        // A member only one side has, and pointer escaping.
        let left = serde_json::json!({"a/b": 1});
        let right = serde_json::json!({"a/b": 1, "c~d": 2});
        let difference = first_difference(&left, &right, "").expect("they differ");
        assert_eq!(difference.member, "/c~0d");
        assert_eq!(difference.oracle, None);

        // Shorter array: the first missing index is the difference.
        let left = serde_json::json!([1, 2]);
        let right = serde_json::json!([1]);
        assert_eq!(
            first_difference(&left, &right, "")
                .expect("they differ")
                .member,
            "/1"
        );

        // Different types at the root have no member to name.
        let difference =
            first_difference(&serde_json::json!(1), &serde_json::json!("1"), "").expect("differ");
        assert_eq!(difference.member, "");
        assert!(difference.to_string().starts_with("<root>"));
    }

    /// Audit inputs the receipt format does not define must stop the run, not
    /// quietly fall back to a default: a bundle nobody can replay produces
    /// agreement about nothing.
    #[test]
    fn unreadable_audit_inputs_fail_closed() {
        let mut oracle = InProcessEvaluator;
        for broken in [
            AuditSpec {
                clock: "the day before yesterday".to_string(),
                ..AuditSpec::default()
            },
            AuditSpec {
                time_source: "vibes".to_string(),
                ..AuditSpec::default()
            },
            AuditSpec {
                enforcement_mode: "advisory".to_string(),
                ..AuditSpec::default()
            },
        ] {
            let mut bundle = CaseBundle::single_case(
                serde_json::json!({"hushspec": "0.2.0"}),
                serde_json::json!({"type": "tool_call", "target": "x"}),
            );
            bundle.audit = broken;
            assert!(
                matches!(oracle.evaluate_bundle(&bundle), Err(DiffError::Config(_))),
                "the reference must refuse audit inputs it cannot replay"
            );
        }
    }

    /// A policy the reference rejects has no identity to report, and a harness
    /// that rejects it too must agree by also reporting none.
    #[test]
    fn a_rejected_policy_reports_no_content_hash() {
        let bundle = CaseBundle::single_case(
            serde_json::json!({"hushspec": "0.2.0", "not_a_field": true}),
            serde_json::json!({"type": "tool_call", "target": "read_file"}),
        );
        let mut oracle = InProcessEvaluator;
        let report = oracle.evaluate_bundle(&bundle).expect("oracle evaluates");
        assert_eq!(report.groups["g0001"].content_hash, None);
        let observed = SdkReport {
            sdk: "typescript".to_string(),
            ..report.clone()
        };
        assert!(compare_reports(&report, &observed, &CompareOptions::default()).is_empty());
    }

    /// `extends` must be resolved before evaluation, or a policy whose rules
    /// all come from its base would evaluate as if it had none.
    #[test]
    fn oracle_resolves_builtin_extends_before_evaluating() {
        let bundle = CaseBundle::single_case(
            serde_json::json!({"hushspec": "0.2.0", "extends": "builtin:default"}),
            serde_json::json!({"type": "tool_call", "target": "shell_exec"}),
        );
        let mut oracle = InProcessEvaluator;
        let report = oracle.evaluate_bundle(&bundle).expect("oracle evaluates");
        let verdict = report.results.get("g0001/a0001").expect("case present");
        let CaseVerdict::Ok { result } = verdict else {
            panic!("expected an evaluated verdict, got {verdict:?}");
        };
        assert_eq!(result.decision, "deny");
        assert_eq!(
            result.matched_rule.as_deref(),
            Some("rules.tool_access.block"),
            "builtin:default blocks shell_exec; an unresolved document would allow it"
        );
    }

    /// Generating a 0.2 rule block is not the same as *reaching* it: a
    /// block that is disabled, gated off by a false `when`, or short-circuited
    /// by the origins/posture guards is traced as `skip` and proves nothing.
    /// Assert the reference actually evaluates the new blocks over a generated
    /// corpus, and that detection escalates at least one verdict.
    #[test]
    fn generated_corpus_actually_reaches_the_0_2_evaluators() {
        let bundle = crate::r#gen::generate_bundle(
            5,
            &crate::r#gen::GenConfig {
                groups: 200,
                actions_per_group: 4,
            },
        );
        let mut oracle = InProcessEvaluator;
        let report = oracle.evaluate_bundle(&bundle).expect("oracle evaluates");

        // The blocks and stages the 0.2 corpus exists to exercise.
        const REQUIRED_BLOCKS: [&str; 5] = [
            "browser_automation",
            "code_execution",
            "origins",
            "posture_capability",
            "default",
        ];

        let mut evaluated_blocks: std::collections::BTreeSet<&str> =
            std::collections::BTreeSet::new();
        let mut detection_escalations = 0usize;
        for verdict in report.results.values() {
            let CaseVerdict::Ok { result } = verdict else {
                continue;
            };
            if result.matched_rule.as_deref() == Some("detection") {
                detection_escalations += 1;
            }
            for entry in &result.rule_trace {
                if entry.evaluated {
                    evaluated_blocks.insert(entry.rule_block.as_str());
                }
            }
        }
        for expected in REQUIRED_BLOCKS {
            assert!(
                evaluated_blocks.contains(expected),
                "no generated case ever evaluated `{expected}` (saw {evaluated_blocks:?})"
            );
        }
        assert!(
            detection_escalations > 0,
            "no generated case was escalated by the detection extension"
        );
    }

    /// Detection is only *compared* if it actually runs. Assert that a
    /// generated corpus produces receipts whose `detection_trace` covers both
    /// wired categories, every level the receipt spec defines, both values of
    /// `matched`, and -- the case a byte budget exists for -- scans the policy
    /// truncated mid-content.
    ///
    /// Without this, `detection_trace` could be uniformly empty across all
    /// four SDKs and the fuzzer would report agreement about nothing.
    #[test]
    fn generated_corpus_exercises_the_detection_trace_inside_receipts() {
        let mut bundle = crate::r#gen::generate_bundle(
            11,
            &crate::r#gen::GenConfig {
                groups: 200,
                actions_per_group: 4,
            },
        );
        bundle.audit.emit_receipts = true;
        let mut oracle = InProcessEvaluator;
        let report = oracle.evaluate_bundle(&bundle).expect("oracle evaluates");

        let mut categories: std::collections::BTreeSet<String> = Default::default();
        let mut levels: std::collections::BTreeSet<String> = Default::default();
        let mut matched = std::collections::BTreeSet::new();
        let mut traces = 0usize;
        for verdict in report.results.values() {
            let CaseVerdict::Ok { result } = verdict else {
                continue;
            };
            let receipt = result.receipt.as_ref().expect("receipts were requested");
            let Some(trace) = receipt.get("detection_trace").and_then(|t| t.as_array()) else {
                continue;
            };
            traces += 1;
            for entry in trace {
                categories.insert(entry["category"].as_str().unwrap_or_default().to_string());
                levels.insert(entry["level"].as_str().unwrap_or_default().to_string());
                matched.insert(entry["matched"].as_bool().unwrap_or_default());
            }
        }

        assert!(traces > 0, "no generated case ran the detection pipeline");
        assert_eq!(
            categories,
            ["jailbreak", "prompt_injection"]
                .into_iter()
                .map(str::to_string)
                .collect()
        );
        for level in ["none", "low", "suspicious", "high", "critical"] {
            assert!(
                levels.contains(level),
                "no detector ever scored `{level}` (saw {levels:?})"
            );
        }
        assert_eq!(
            matched,
            [false, true].into_iter().collect(),
            "a detector must both meet and miss the policy's thresholds"
        );
        assert!(
            truncating_detection_cases(&bundle) > 0,
            "no generated case scanned less content than it carried: the \
             max_scan_bytes / max_input_bytes edge is never reached"
        );
    }

    /// Cases whose policy sets a detection byte budget smaller than the
    /// content the action carries -- the scans that actually truncate.
    fn truncating_detection_cases(bundle: &CaseBundle) -> usize {
        let mut count = 0;
        for group in &bundle.groups {
            let Some(detection) = group.policy.pointer("/extensions/detection") else {
                continue;
            };
            let budgets: Vec<u64> = [
                "/prompt_injection/max_scan_bytes",
                "/jailbreak/max_input_bytes",
            ]
            .into_iter()
            .filter_map(|path| detection.pointer(path).and_then(serde_json::Value::as_u64))
            .collect();
            if budgets.is_empty() {
                continue;
            }
            for case in &group.actions {
                let Some(content) = case.action.get("content").and_then(|c| c.as_str()) else {
                    continue;
                };
                if budgets.iter().any(|budget| *budget < content.len() as u64) {
                    count += 1;
                }
            }
        }
        count
    }

    /// Every case of a generated bundle records a receipt, and its id is the
    /// one the bundle's audit block dictates: the deterministic UUID v7 for
    /// that case's position. Four SDKs can only compare receipts if they all
    /// derive the id the same way from the bundle alone.
    #[test]
    fn every_evaluated_case_records_a_receipt_with_the_bundle_s_receipt_id() {
        let mut bundle = crate::r#gen::generate_bundle(
            13,
            &crate::r#gen::GenConfig {
                groups: 25,
                actions_per_group: 4,
            },
        );
        bundle.audit.emit_receipts = true;
        let mut oracle = InProcessEvaluator;
        let report = oracle.evaluate_bundle(&bundle).expect("oracle evaluates");
        let millis = bundle.audit.clock_millis().expect("clock parses");

        let mut checked = 0;
        for (key, verdict) in &report.results {
            let CaseVerdict::Ok { result } = verdict else {
                continue;
            };
            let receipt = result.receipt.as_ref().expect("receipts were requested");
            let position = bundle.case_position(key).expect("case is in the bundle");
            assert_eq!(
                receipt["receipt_id"].as_str().unwrap_or_default(),
                deterministic_uuid_v7(millis, bundle.audit.index_base + position),
                "{key}: receipt id must come from the bundle, not from an RNG"
            );
            assert_eq!(receipt["timestamp"], bundle.audit.clock);
            assert_eq!(receipt["time_source"], "trusted");
            assert_eq!(receipt["enforcement"]["mode"], "enforce");
            assert!(
                receipt.get("duration_us").is_none(),
                "{key}: a receipt whose bytes depend on the machine is not comparable"
            );
            assert_eq!(receipt["decision"], result.decision);
            assert_eq!(
                result.receipt_hash.as_deref(),
                Some(
                    hushspec::receipt::DecisionReceipt::parse(&receipt.to_string())
                        .expect("receipt round-trips")
                        .receipt_hash()
                        .expect("hashes")
                        .as_str()
                ),
                "{key}: the reported hash must be the hash of the reported receipt"
            );
            checked += 1;
        }
        assert!(checked > 50, "only {checked} cases evaluated");
    }

    /// A case carved out of a bundle for a second look must reproduce the very
    /// receipt that was hashed -- same id, same bytes -- or the "first
    /// differing member" the report shows would be the carving, not the bug.
    #[test]
    fn a_carved_out_case_reproduces_the_receipt_it_was_carved_from() {
        let mut bundle = crate::r#gen::generate_bundle(
            17,
            &crate::r#gen::GenConfig {
                groups: 5,
                actions_per_group: 4,
            },
        );
        bundle.audit.emit_receipts = true;
        let mut oracle = InProcessEvaluator;
        let report = oracle.evaluate_bundle(&bundle).expect("oracle evaluates");

        let mut compared = 0;
        for group in &bundle.groups {
            for case in &group.actions {
                let key = format!("{}/{}", group.id, case.id);
                let CaseVerdict::Ok { result } = &report.results[&key] else {
                    continue;
                };
                let position = bundle.case_position(&key).expect("case is in the bundle");
                let probe = CaseBundle::single_case_at(
                    group.policy.clone(),
                    case.action.clone(),
                    &bundle.audit,
                    position,
                );
                let carved = oracle.evaluate_bundle(&probe).expect("oracle evaluates");
                let CaseVerdict::Ok { result: carved } = &carved.results["g0001/a0001"] else {
                    panic!("{key}: the carved case must still evaluate");
                };
                assert_eq!(carved.receipt_hash, result.receipt_hash, "{key}");
                assert_eq!(carved.receipt, result.receipt, "{key}");
                compared += 1;
            }
        }
        assert_eq!(compared, 20);
    }

    /// An unresolvable `extends` is a rejection with its own phase, not a
    /// silent fall-through to evaluating the unresolved document.
    #[test]
    fn oracle_rejects_an_unknown_builtin_extends() {
        let bundle = CaseBundle::single_case(
            serde_json::json!({"hushspec": "0.2.0", "extends": "builtin:no-such-ruleset"}),
            serde_json::json!({"type": "tool_call", "target": "x"}),
        );
        let mut oracle = InProcessEvaluator;
        let report = oracle.evaluate_bundle(&bundle).expect("oracle evaluates");
        match report.results.get("g0001/a0001").expect("case present") {
            CaseVerdict::Rejected { phase, .. } => assert_eq!(phase, "resolve"),
            other => panic!("expected a resolve rejection, got {other:?}"),
        }
    }

    #[test]
    fn oracle_reports_parse_rejection_for_bad_policy() {
        let bundle = CaseBundle::single_case(
            serde_json::json!({"hushspec": "0.1.0", "no_such_key": true}),
            serde_json::json!({"type": "tool_call", "target": "x"}),
        );
        let mut oracle = InProcessEvaluator;
        let report = oracle.evaluate_bundle(&bundle).expect("oracle evaluates");
        match report.results.get("g0001/a0001").expect("case present") {
            CaseVerdict::Rejected { phase, .. } => assert_eq!(phase, "parse"),
            other => panic!("expected parse rejection, got {other:?}"),
        }
    }

    #[test]
    fn verdicts_serialize_with_status_tags() {
        let verdict = CaseVerdict::Rejected {
            phase: "validate".to_string(),
            message: "bad".to_string(),
        };
        let json = serde_json::to_string(&verdict).expect("serializes");
        assert_eq!(
            json,
            r#"{"status":"rejected","phase":"validate","message":"bad"}"#
        );
    }

    fn ok_verdict(decision: &str, matched_rule: Option<&str>, reason: Option<&str>) -> CaseVerdict {
        CaseVerdict::Ok {
            result: NormalizedResult {
                decision: decision.to_string(),
                matched_rule: matched_rule.map(str::to_string),
                reason: reason.map(str::to_string),
                origin_profile: None,
                posture: None,
                rule_trace: Vec::new(),
                receipt_hash: None,
                receipt: None,
            },
        }
    }

    fn report_of(sdk: &str, entries: &[(&str, CaseVerdict)]) -> SdkReport {
        SdkReport {
            sdk: sdk.to_string(),
            results: entries
                .iter()
                .map(|(key, verdict)| ((*key).to_string(), verdict.clone()))
                .collect(),
            groups: BTreeMap::new(),
        }
    }

    #[test]
    fn identical_reports_produce_no_divergence() {
        let oracle = report_of("rust", &[("g0001/a0001", ok_verdict("allow", None, None))]);
        let observed = report_of("go", &[("g0001/a0001", ok_verdict("allow", None, None))]);
        assert!(compare_reports(&oracle, &observed, &CompareOptions::default()).is_empty());
    }

    #[test]
    fn detects_every_divergence_kind() {
        let oracle = report_of(
            "rust",
            &[
                (
                    "k1",
                    ok_verdict("deny", Some("rules.egress.block"), Some("r")),
                ),
                (
                    "k2",
                    ok_verdict("allow", Some("rules.tool_access.allow"), None),
                ),
                ("k3", ok_verdict("allow", None, Some("left reason"))),
                ("k4", ok_verdict("allow", None, None)),
                (
                    "k5",
                    CaseVerdict::Rejected {
                        phase: "parse".to_string(),
                        message: "m".to_string(),
                    },
                ),
                ("k6", ok_verdict("allow", None, None)),
            ],
        );
        let observed = report_of(
            "go",
            &[
                (
                    "k1",
                    ok_verdict("allow", Some("rules.egress.block"), Some("r")),
                ),
                (
                    "k2",
                    ok_verdict("allow", Some("rules.tool_access.default"), None),
                ),
                ("k3", ok_verdict("allow", None, Some("right reason"))),
                (
                    "k4",
                    CaseVerdict::Rejected {
                        phase: "validate".to_string(),
                        message: "m".to_string(),
                    },
                ),
                (
                    "k5",
                    CaseVerdict::Rejected {
                        phase: "validate".to_string(),
                        message: "m".to_string(),
                    },
                ),
                // k6 missing entirely
            ],
        );
        let divergences = compare_reports(&oracle, &observed, &CompareOptions::default());
        let kinds: Vec<(String, DivergenceKind)> = divergences
            .iter()
            .map(|divergence| (divergence.case_key.clone(), divergence.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("k1".to_string(), DivergenceKind::Decision),
                ("k2".to_string(), DivergenceKind::MatchedRule),
                ("k3".to_string(), DivergenceKind::Reason),
                ("k4".to_string(), DivergenceKind::Acceptance),
                ("k5".to_string(), DivergenceKind::Acceptance),
                ("k6".to_string(), DivergenceKind::MissingCase),
            ]
        );
        assert!(divergences.iter().all(|divergence| divergence.sdk == "go"));
    }

    #[test]
    fn two_errors_agree_only_when_they_say_the_same_thing() {
        let oracle = report_of(
            "rust",
            &[
                (
                    "same",
                    CaseVerdict::Error {
                        message: "invalid action".to_string(),
                    },
                ),
                (
                    "different",
                    CaseVerdict::Error {
                        message: "invalid action".to_string(),
                    },
                ),
            ],
        );
        let observed = report_of(
            "go",
            &[
                (
                    "same",
                    CaseVerdict::Error {
                        message: "invalid action".to_string(),
                    },
                ),
                (
                    "different",
                    CaseVerdict::Error {
                        message: "harness panicked".to_string(),
                    },
                ),
            ],
        );
        let divergences = compare_reports(&oracle, &observed, &CompareOptions::default());
        let kinds: Vec<(String, DivergenceKind)> = divergences
            .iter()
            .map(|divergence| (divergence.case_key.clone(), divergence.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![("different".to_string(), DivergenceKind::HarnessError)]
        );
    }

    /// An SDK that could not produce a verdict at all did not agree with one
    /// that did.
    #[test]
    fn an_error_against_a_verdict_is_a_harness_error() {
        let oracle = report_of("rust", &[("k", ok_verdict("allow", None, None))]);
        let observed = report_of(
            "py",
            &[(
                "k",
                CaseVerdict::Error {
                    message: "receipt has no canonical form".to_string(),
                },
            )],
        );
        let divergences = compare_reports(&oracle, &observed, &CompareOptions::default());
        assert_eq!(divergences.len(), 1);
        assert_eq!(divergences[0].kind, DivergenceKind::HarnessError);
    }

    #[test]
    fn ignore_reason_suppresses_reason_only_divergence() {
        let oracle = report_of("rust", &[("k", ok_verdict("allow", None, Some("a")))]);
        let observed = report_of("py", &[("k", ok_verdict("allow", None, Some("b")))]);
        let options = CompareOptions {
            ignore_reason: true,
            ..CompareOptions::default()
        };
        assert!(compare_reports(&oracle, &observed, &options).is_empty());
    }

    #[test]
    fn compare_reports_flags_a_phantom_case_not_in_the_oracle() {
        // The reference-driven loop above only ever walks the reference's keys, so
        // a harness that *adds* a case key the reference (and therefore the
        // bundle) never produced would be invisible without a symmetric
        // check in the other direction. This must never be silent: it is
        // harness-integrity evidence, not an ordinary verdict disagreement.
        let oracle = report_of("rust", &[("k1", ok_verdict("allow", None, None))]);
        let observed = report_of(
            "go",
            &[
                ("k1", ok_verdict("allow", None, None)),
                ("k2", ok_verdict("deny", None, None)),
            ],
        );
        let divergences = compare_reports(&oracle, &observed, &CompareOptions::default());
        assert_eq!(divergences.len(), 1);
        assert_eq!(divergences[0].case_key, "k2");
        assert_eq!(divergences[0].kind, DivergenceKind::PhantomCase);
        assert_eq!(divergences[0].sdk, "go");
    }

    #[cfg(unix)]
    fn stub_harness(dir: &std::path::Path, body: &str) -> Vec<String> {
        let script = dir.join("stub.sh");
        std::fs::write(&script, body).expect("write stub");
        vec!["sh".to_string(), script.display().to_string()]
    }

    #[test]
    #[cfg(unix)]
    fn subprocess_evaluator_parses_a_valid_report() {
        let dir = tempfile::tempdir().expect("tempdir");
        let body = "#!/bin/sh\necho '{\"sdk\":\"stub\",\"results\":{\"g0001/a0001\":{\"status\":\"ok\",\"result\":{\"decision\":\"allow\"}}}}'\n";
        let mut evaluator = SubprocessEvaluator {
            sdk: "stub".to_string(),
            command: stub_harness(dir.path(), body),
            cwd: None,
        };
        let bundle = CaseBundle::single_case(
            serde_json::json!({"hushspec": "0.1.0"}),
            serde_json::json!({"type": "tool_call"}),
        );
        let report = evaluator
            .evaluate_bundle(&bundle)
            .expect("stub report parses");
        assert_eq!(report.sdk, "stub");
        assert_eq!(report.results.len(), 1);
    }

    #[test]
    #[cfg(unix)]
    fn subprocess_evaluator_fails_closed_on_nonzero_exit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut evaluator = SubprocessEvaluator {
            sdk: "stub".to_string(),
            command: stub_harness(dir.path(), "#!/bin/sh\necho boom >&2\nexit 3\n"),
            cwd: None,
        };
        let bundle = CaseBundle::single_case(
            serde_json::json!({"hushspec": "0.1.0"}),
            serde_json::json!({"type": "tool_call"}),
        );
        match evaluator.evaluate_bundle(&bundle) {
            Err(DiffError::HarnessFailed { sdk, stderr, .. }) => {
                assert_eq!(sdk, "stub");
                assert!(stderr.contains("boom"));
            }
            other => panic!("expected HarnessFailed, got {other:?}"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn subprocess_evaluator_fails_closed_on_spawn_failure() {
        let mut evaluator = SubprocessEvaluator {
            sdk: "stub".to_string(),
            command: vec!["/definitely-does-not-exist-xyz".to_string()],
            cwd: None,
        };
        let bundle = CaseBundle::single_case(
            serde_json::json!({"hushspec": "0.1.0"}),
            serde_json::json!({"type": "tool_call"}),
        );
        match evaluator.evaluate_bundle(&bundle) {
            Err(DiffError::HarnessFailed { status, .. }) => {
                assert_eq!(status, "spawn failed");
            }
            other => panic!("expected HarnessFailed, got {other:?}"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn subprocess_evaluator_fails_closed_on_unparseable_stdout() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut evaluator = SubprocessEvaluator {
            sdk: "stub".to_string(),
            command: stub_harness(dir.path(), "#!/bin/sh\necho 'not json at all'\n"),
            cwd: None,
        };
        let bundle = CaseBundle::single_case(
            serde_json::json!({"hushspec": "0.1.0"}),
            serde_json::json!({"type": "tool_call"}),
        );
        match evaluator.evaluate_bundle(&bundle) {
            Err(DiffError::InvalidReport { .. }) => {}
            other => panic!("expected InvalidReport, got {other:?}"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn subprocess_evaluator_fails_closed_on_sdk_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut evaluator = SubprocessEvaluator {
            sdk: "stub".to_string(),
            command: stub_harness(
                dir.path(),
                "#!/bin/sh\necho '{\"sdk\":\"wrong-sdk\",\"results\":{}}'\n",
            ),
            cwd: None,
        };
        let bundle = CaseBundle::single_case(
            serde_json::json!({"hushspec": "0.1.0"}),
            serde_json::json!({"type": "tool_call"}),
        );
        match evaluator.evaluate_bundle(&bundle) {
            Err(DiffError::InvalidReport { message, .. }) => {
                assert!(message.contains("wrong-sdk"));
            }
            other => panic!("expected InvalidReport, got {other:?}"),
        }
    }

    #[test]
    fn default_evaluators_cover_the_three_ported_sdks() {
        let evaluators = default_subprocess_evaluators(std::path::Path::new("/repo"));
        let names: Vec<&str> = evaluators.iter().map(|e| e.sdk.as_str()).collect();
        assert_eq!(names, vec!["typescript", "python", "go"]);
        assert_eq!(
            evaluators[2].cwd.as_deref(),
            Some(std::path::Path::new("/repo/packages/go"))
        );
    }

    #[test]
    #[cfg(unix)]
    fn run_difftest_detects_divergence_from_a_lying_harness() {
        let _latch = panic_latch();
        // A stub "typescript" harness that always answers allow-with-no-rule,
        // which must diverge from the reference on the deny cases the generator
        // produces (and at minimum differ in matched_rule/reason on others).
        let dir = tempfile::tempdir().expect("tempdir");
        let stub = r#"#!/bin/sh
python3 - "$1" <<'EOF'
import json, sys
bundle = json.load(open(sys.argv[1]))
results = {}
for group in bundle["groups"]:
    for case in group["actions"]:
        results[f"{group['id']}/{case['id']}"] = {
            "status": "ok",
            "result": {"decision": "allow"},
        }
print(json.dumps({"sdk": "typescript", "results": results}))
EOF
"#;
        std::fs::create_dir_all(dir.path().join("scripts")).expect("mkdir scripts");
        std::fs::write(dir.path().join("scripts/diffeval_ts.mjs"), stub).expect("write stub");

        // node isn't required: harness_override runs the stub via sh while
        // keeping the "typescript" sdk name.
        let config = DifftestConfig {
            seed: 7,
            groups_per_chunk: 20,
            actions_per_group: 3,
            chunks: 1,
            max_seconds: None,
            sdks: vec!["typescript".to_string()],
            minimize: false,
            emit_fixtures_dir: None,
            report_path: Some(dir.path().join("report.json")),
            bundles_dir: dir.path().join("bundles"),
            ignore_reason: false,
            ignore_rule_trace: false,
            ignore_content_hash: true,
            ignore_receipts: true,
            emit_receipts: false,
            repo_root: dir.path().to_path_buf(),
            bundle_path: None,
            harness_override: Some(vec![
                "sh".to_string(),
                dir.path()
                    .join("scripts/diffeval_ts.mjs")
                    .display()
                    .to_string(),
            ]),
        };
        let outcome = run_difftest(&config).expect("difftest runs");
        assert_eq!(outcome.chunks_run, 1);
        assert_eq!(outcome.cases_run, 60);
        assert!(
            !outcome.divergences.is_empty(),
            "a constant-allow harness must diverge somewhere in 60 generated cases"
        );
        assert!(config.report_path.as_ref().unwrap().exists());
        assert!(config.bundles_dir.join("bundle-7.json").exists());
    }

    #[test]
    fn run_difftest_requires_at_least_one_sdk() {
        let _latch = panic_latch();
        let config = DifftestConfig {
            seed: 1,
            groups_per_chunk: 1,
            actions_per_group: 1,
            chunks: 1,
            max_seconds: None,
            sdks: Vec::new(),
            minimize: false,
            emit_fixtures_dir: None,
            report_path: None,
            bundles_dir: std::env::temp_dir().join("hushspec-difftest-empty"),
            ignore_reason: false,
            ignore_rule_trace: false,
            ignore_content_hash: true,
            ignore_receipts: true,
            emit_receipts: false,
            repo_root: std::path::PathBuf::from("."),
            bundle_path: None,
            harness_override: None,
        };
        assert!(matches!(run_difftest(&config), Err(DiffError::Config(_))));
    }

    #[test]
    #[cfg(unix)]
    fn run_difftest_never_silently_drops_a_phantom_case_key() {
        let _latch = panic_latch();
        // A stub harness that answers correctly for every real case AND adds
        // one case key the bundle never produced. Even if every real answer
        // happened to agree with the reference, the invented key must still
        // surface as a divergence -- proof that run_difftest's comparison is
        // symmetric in key coverage, not just oracle-driven.
        let dir = tempfile::tempdir().expect("tempdir");
        let stub = r#"#!/bin/sh
python3 - "$1" <<'EOF'
import json, sys
bundle = json.load(open(sys.argv[1]))
results = {}
for group in bundle["groups"]:
    for case in group["actions"]:
        results[f"{group['id']}/{case['id']}"] = {
            "status": "ok",
            "result": {"decision": "allow"},
        }
results["g9999/a9999"] = {"status": "ok", "result": {"decision": "allow"}}
print(json.dumps({"sdk": "typescript", "results": results}))
EOF
"#;
        std::fs::create_dir_all(dir.path().join("scripts")).expect("mkdir scripts");
        std::fs::write(dir.path().join("scripts/diffeval_ts.mjs"), stub).expect("write stub");

        let config = DifftestConfig {
            seed: 3,
            groups_per_chunk: 2,
            actions_per_group: 2,
            chunks: 1,
            max_seconds: None,
            sdks: vec!["typescript".to_string()],
            minimize: false,
            emit_fixtures_dir: None,
            report_path: None,
            bundles_dir: dir.path().join("bundles"),
            ignore_reason: false,
            ignore_rule_trace: false,
            ignore_content_hash: true,
            ignore_receipts: true,
            emit_receipts: false,
            repo_root: dir.path().to_path_buf(),
            bundle_path: None,
            harness_override: Some(vec![
                "sh".to_string(),
                dir.path()
                    .join("scripts/diffeval_ts.mjs")
                    .display()
                    .to_string(),
            ]),
        };
        let outcome = run_difftest(&config).expect("difftest runs");
        assert!(
            outcome
                .divergences
                .iter()
                .any(|divergence| divergence.kind == DivergenceKind::PhantomCase
                    && divergence.case_key == "g9999/a9999"),
            "a harness-invented case key must surface as a divergence, not vanish: {:?}",
            outcome.divergences
        );
    }

    #[test]
    #[cfg(unix)]
    fn run_difftest_minimizes_and_emits_a_fixture_via_bundle_replay() {
        let _latch = panic_latch();
        // Neither of the two tests above ever sets `minimize: true`, so
        // `handle_divergence` (minimize_case + build_regression_fixture +
        // write_regression_fixture wiring) and the `bundle_path` replay
        // branch are otherwise completely untested by this suite. Use a
        // hand-built single-case bundle (replayed from disk, not generated)
        // with a guaranteed, deterministic divergence so minimization
        // terminates in at most a handful of subprocess spawns.
        //
        // The policy carries an `extends` and the action a runtime `context`
        // -- the two generated fields the fixture schema cannot express
        // verbatim (no `extends` resolver in the runners, no `context` on the
        // schema's `Action`). Putting them in the
        // input proves the minimize -> emit -> discover -> run_conformance
        // round-trip really does flatten and relocate them, rather than
        // emitting a fixture that is quietly wrong.
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle = CaseBundle::single_case(
            serde_json::json!({
                "hushspec": "0.2.0",
                "extends": "builtin:default",
                "rules": {"tool_access": {"block": ["shell_exec"], "default": "allow"}}
            }),
            serde_json::json!({
                "type": "tool_call",
                "target": "shell_exec",
                "context": {"environment": "production", "current_time": "2026-03-02T09:30:00Z"},
            }),
        );
        let bundle_path = dir.path().join("input-bundle.json");
        std::fs::write(&bundle_path, bundle.to_json().expect("bundle serializes"))
            .expect("write bundle");

        // Always answers "allow" for every case actually present in the
        // bundle it's given -- diverges from the reference's expected "deny" on
        // the input case, and (unlike a hardcoded single-key stub) still
        // answers correctly during minimization, which probes multi-group
        // candidate bundles, not just the original one-case bundle.
        let stub = r#"#!/bin/sh
python3 - "$1" <<'EOF'
import json, sys
bundle = json.load(open(sys.argv[1]))
results = {}
for group in bundle["groups"]:
    for case in group["actions"]:
        results[f"{group['id']}/{case['id']}"] = {
            "status": "ok",
            "result": {"decision": "allow"},
        }
print(json.dumps({"sdk": "typescript", "results": results}))
EOF
"#;
        std::fs::create_dir_all(dir.path().join("scripts")).expect("mkdir scripts");
        std::fs::write(dir.path().join("scripts/diffeval_ts.mjs"), stub).expect("write stub");

        // Nested under "core/evaluation" so the emitted fixture is
        // discoverable by the real fixture pipeline below (discover_fixtures
        // categorizes by subdirectory name -- see fixture.rs).
        let fixtures_dir = dir.path().join("core/evaluation");
        let config = DifftestConfig {
            seed: 99,
            groups_per_chunk: 0,
            actions_per_group: 0,
            chunks: 1,
            max_seconds: None,
            sdks: vec!["typescript".to_string()],
            minimize: true,
            emit_fixtures_dir: Some(fixtures_dir.clone()),
            report_path: None,
            bundles_dir: dir.path().join("bundles"),
            ignore_reason: false,
            ignore_rule_trace: false,
            ignore_content_hash: true,
            ignore_receipts: true,
            emit_receipts: false,
            repo_root: dir.path().to_path_buf(),
            bundle_path: Some(bundle_path),
            harness_override: Some(vec![
                "sh".to_string(),
                dir.path()
                    .join("scripts/diffeval_ts.mjs")
                    .display()
                    .to_string(),
            ]),
        };
        let outcome = run_difftest(&config).expect("difftest runs");

        assert_eq!(outcome.chunks_run, 1);
        assert_eq!(outcome.cases_run, 1);
        assert_eq!(outcome.divergences.len(), 1);
        assert_eq!(outcome.divergences[0].kind, DivergenceKind::Decision);

        // bundle_path replay still deposits a canonical copy under bundles_dir.
        assert!(config.bundles_dir.join("bundle-99.json").exists());

        assert_eq!(
            outcome.fixtures.len(),
            1,
            "the one real divergence must minimize to exactly one emitted fixture: {:?}",
            outcome.fixtures
        );
        let fixture_path = &outcome.fixtures[0];
        assert!(fixture_path.exists());
        assert!(fixture_path.starts_with(&fixtures_dir));
        let contents = std::fs::read_to_string(fixture_path).expect("read fixture");
        assert!(contents.contains("hushspec_test"));

        // Minimization is free to wander to a smaller divergence than the
        // one that triggered it -- e.g. it may end up pinning a
        // `matched_rule` disagreement rather than the original `decision`
        // one (see minimize.rs's greedy-shrink contract) -- so the
        // meaningful assertion isn't a specific expect value, it's that the
        // emitted fixture is a real, passing regression fixture: it must
        // round-trip through the exact discovery -> schema validation ->
        // parse -> evaluate -> expect pipeline the real conformance runner
        // uses.
        let discovered = crate::fixture::discover_fixtures(dir.path());
        assert_eq!(discovered.len(), 1);
        let results = crate::runner::run_conformance(&discovered);
        assert_eq!(results.len(), 1);
        assert!(
            results[0].passed,
            "emitted fixture failed the testkit runner: {}",
            results[0].message
        );
    }

    #[test]
    #[cfg(unix)]
    fn run_difftest_fetches_the_receipts_of_a_receipt_divergence() {
        // The first pass compares hashes, so a receipt divergence arrives as
        // two digests and nothing else. Prove the run then goes back for the
        // receipts themselves -- the stub only emits one when the bundle asks
        // (`audit.emit_receipts`), which the first pass never does -- and
        // reports where they first differ.
        let _latch = panic_latch();
        let dir = tempfile::tempdir().expect("tempdir");
        // No rules at all: the reference allows with no matched rule, which the
        // stub can mirror exactly, so the receipt is the only thing left to
        // disagree about.
        let bundle = CaseBundle::single_case(
            serde_json::json!({"hushspec": "0.2.0"}),
            serde_json::json!({"type": "tool_call", "target": "x"}),
        );
        let bundle_path = dir.path().join("input-bundle.json");
        std::fs::write(&bundle_path, bundle.to_json().expect("bundle serializes"))
            .expect("write bundle");

        // Agrees on the decision, disagrees on the evidence.
        let stub = r#"#!/bin/sh
python3 - "$1" <<'EOF'
import json, sys
bundle = json.load(open(sys.argv[1]))
emit = bundle.get("audit", {}).get("emit_receipts", False)
results = {}
for group in bundle["groups"]:
    for case in group["actions"]:
        result = {"decision": "allow", "receipt_hash": "sha256:" + "0" * 64}
        if emit:
            result["receipt"] = {"decision": "allow"}
        results[f"{group['id']}/{case['id']}"] = {"status": "ok", "result": result}
print(json.dumps({"sdk": "typescript", "results": results}))
EOF
"#;
        std::fs::create_dir_all(dir.path().join("scripts")).expect("mkdir scripts");
        std::fs::write(dir.path().join("scripts/diffeval_ts.mjs"), stub).expect("write stub");

        let config = DifftestConfig {
            seed: 4,
            groups_per_chunk: 0,
            actions_per_group: 0,
            chunks: 1,
            max_seconds: None,
            sdks: vec!["typescript".to_string()],
            minimize: false,
            emit_fixtures_dir: None,
            report_path: None,
            bundles_dir: dir.path().join("bundles"),
            ignore_reason: true,
            ignore_rule_trace: true,
            ignore_content_hash: true,
            ignore_receipts: false,
            emit_receipts: false,
            repo_root: dir.path().to_path_buf(),
            bundle_path: Some(bundle_path),
            harness_override: Some(vec![
                "sh".to_string(),
                dir.path()
                    .join("scripts/diffeval_ts.mjs")
                    .display()
                    .to_string(),
            ]),
        };
        let outcome = run_difftest(&config).expect("difftest runs");
        let divergence = outcome
            .divergences
            .iter()
            .find(|divergence| divergence.case_key == "g0001/a0001")
            .expect("the case's receipt must diverge");
        assert_eq!(divergence.kind, DivergenceKind::Receipt);
        let difference = divergence
            .receipt_difference
            .as_ref()
            .expect("the second pass must bring the receipts back");
        // `action` sorts first among the members the reference's receipt has and
        // the stub's does not.
        assert_eq!(difference.member, "/action");
        assert!(difference.observed.is_none());

        // ...and the receipts themselves land on the reported verdicts, so an
        // uploaded report holds the evidence rather than a pointer at it.
        let CaseVerdict::Ok { result } = &divergence.oracle else {
            panic!("the reference evaluated this case");
        };
        assert_eq!(
            result.receipt.as_ref().expect("oracle receipt")["decision"],
            "allow"
        );
        let CaseVerdict::Ok { result } = &divergence.observed else {
            panic!("the stub answered this case");
        };
        assert_eq!(
            result.receipt.as_ref().expect("harness receipt"),
            &serde_json::json!({"decision": "allow"})
        );
    }

    /// `PANIC_ACTIVE` is one global `AtomicBool` in the `hushspec` crate
    /// (see `hushspec::panic`), so any test that activates it risks a
    /// window where a test running in parallel observes it from its own
    /// `evaluate()` call. `hushspec`'s own test suite accepts the same tradeoff
    /// (see the `TEST_LOCK`-guarded tests in `hushspec::panic::tests`) with
    /// no cross-crate synchronization primitive exposed for us to share, so
    /// the best available mitigation here is a `Drop` guard that
    /// deactivates unconditionally -- including on assertion panic/unwind
    /// -- keeping the active window to a single synchronous, allocation-free
    /// `run_difftest` call that returns on its very first check.
    struct PanicModeGuard;
    impl Drop for PanicModeGuard {
        fn drop(&mut self) {
            hushspec::deactivate_panic();
        }
    }

    #[test]
    fn run_difftest_rejects_when_panic_mode_is_active() {
        let _latch = panic_latch();
        hushspec::activate_panic();
        let _guard = PanicModeGuard;
        let config = DifftestConfig {
            seed: 1,
            groups_per_chunk: 1,
            actions_per_group: 1,
            chunks: 1,
            max_seconds: None,
            sdks: vec!["typescript".to_string()],
            minimize: false,
            emit_fixtures_dir: None,
            report_path: None,
            bundles_dir: std::env::temp_dir().join("hushspec-difftest-panic-guard"),
            ignore_reason: false,
            ignore_rule_trace: false,
            ignore_content_hash: true,
            ignore_receipts: true,
            emit_receipts: false,
            repo_root: std::path::PathBuf::from("."),
            bundle_path: None,
            harness_override: None,
        };
        let result = run_difftest(&config);
        assert!(
            matches!(result, Err(DiffError::Config(_))),
            "run_difftest must refuse to run while panic mode is active, got {result:?}"
        );
    }
}
