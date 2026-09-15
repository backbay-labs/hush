use crate::bundle::CaseBundle;
use hushspec::evaluate::{RuleEvaluation, RuleOutcome, evaluate_traced};
use hushspec::{EvaluationAction, EvaluationResult, HushSpec};
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
        }
    }
}

impl From<EvaluationResult> for NormalizedResult {
    fn from(result: EvaluationResult) -> Self {
        NormalizedResult::with_trace(result, &[])
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
    /// against the oracle's populated one, which is exactly the divergence a
    /// stale harness should produce rather than a silent pass.
    #[serde(default)]
    pub groups: BTreeMap<String, GroupReport>,
}

/// What an SDK reports about a bundle group's policy, as opposed to about one
/// action evaluated against it.
///
/// **Harness contract.** Alongside `results`, a harness emits
/// `"groups": {"<group id>": {"content_hash": "sha256:<64 hex>"}}`, one entry
/// per group in the bundle, in the same pass that evaluates the group. The
/// hash is its SDK's canonical content hash (spec/hushspec-canonical.md
/// section 5) of the **resolved** policy it evaluated -- computed after
/// `parse -> resolve`, before evaluation. A group whose policy the SDK
/// rejected (parse, resolve, or validate) reports `content_hash: null`, or
/// omits the key, which is the same thing: there is no policy to identify.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupReport {
    /// `sha256:<64 lowercase hex>` over the canonical form of the resolved
    /// policy, or `None` when the policy never resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

pub trait CaseEvaluator {
    fn sdk_name(&self) -> &str;
    fn evaluate_bundle(&mut self, bundle: &CaseBundle) -> Result<SdkReport, DiffError>;
}

/// The Rust reference oracle. Mirrors the testkit runner's fixture ingestion:
/// YAML re-encode -> parse -> validate -> evaluate.
pub struct InProcessEvaluator;

impl CaseEvaluator for InProcessEvaluator {
    fn sdk_name(&self) -> &str {
        "rust"
    }

    fn evaluate_bundle(&mut self, bundle: &CaseBundle) -> Result<SdkReport, DiffError> {
        let mut results = BTreeMap::new();
        let mut groups = BTreeMap::new();
        for group in &bundle.groups {
            let parsed = parse_policy(&group.policy);
            // The identity of the policy this group is actually evaluated
            // under: the resolved document, never the unresolved fragment
            // (canonical spec 2.1). A rejected policy has no identity.
            groups.insert(
                group.id.clone(),
                GroupReport {
                    content_hash: parsed
                        .as_ref()
                        .ok()
                        .and_then(|spec| hushspec::content_hash(spec).ok()),
                },
            );
            for case in &group.actions {
                let key = format!("{}/{}", group.id, case.id);
                let verdict = match &parsed {
                    Ok(spec) => evaluate_action(spec, &case.action),
                    Err(rejection) => rejection.clone(),
                };
                results.insert(key, verdict);
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

fn evaluate_action(spec: &HushSpec, action: &serde_json::Value) -> CaseVerdict {
    let action: EvaluationAction = match serde_json::from_value(action.clone()) {
        Ok(action) => action,
        Err(error) => {
            return CaseVerdict::Error {
                message: format!("invalid action: {error}"),
            };
        }
    };
    // Detection-aware result + the base evaluator's trace. `evaluate_with_detection`
    // recomputes the base evaluation internally and returns no trace, so the
    // trace is taken from an explicit `evaluate_traced` call over the same
    // inputs -- the two agree by construction (detection never re-runs rule
    // blocks) and every harness mirrors this pairing.
    let traced = evaluate_traced(spec, &action, None, &std::collections::HashMap::new());
    let evaluation = hushspec::evaluate_with_detection(spec, &action).evaluation;
    CaseVerdict::Ok {
        result: NormalizedResult::with_trace(evaluation, &traced.trace),
    }
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
    MissingCase,
    /// The harness answered for a case key the oracle (and therefore the
    /// bundle) never produced. Both the oracle and every SDK evaluate the
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
}

/// Compare an SDK report against the Rust oracle. First difference wins per
/// case; iteration follows the oracle's sorted key order. The comparison is
/// symmetric in key coverage: a case the oracle has but the harness omits is
/// `MissingCase`, and a case the harness answers but the oracle (and
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
            divergences.push(Divergence {
                case_key: key.clone(),
                sdk: observed.sdk.clone(),
                kind: DivergenceKind::MissingCase,
                oracle: oracle_verdict.clone(),
                observed: CaseVerdict::Error {
                    message: "case missing from harness report".to_string(),
                },
            });
            continue;
        };
        if let Some(kind) = verdict_divergence(oracle_verdict, observed_verdict, options) {
            divergences.push(Divergence {
                case_key: key.clone(),
                sdk: observed.sdk.clone(),
                kind,
                oracle: oracle_verdict.clone(),
                observed: observed_verdict.clone(),
            });
        }
    }
    for (key, observed_verdict) in &observed.results {
        if !oracle.results.contains_key(key) {
            divergences.push(Divergence {
                case_key: key.clone(),
                sdk: observed.sdk.clone(),
                kind: DivergenceKind::PhantomCase,
                oracle: CaseVerdict::Error {
                    message: "case not present in oracle report or bundle".to_string(),
                },
                observed: observed_verdict.clone(),
            });
        }
    }
    if !options.ignore_content_hash {
        divergences.extend(compare_content_hashes(oracle, observed));
    }
    divergences
}

/// Every group the oracle or the harness knows about must carry the same
/// policy identity. A group the harness left out of `groups` has no hash,
/// which diverges against the oracle's -- fail-closed, exactly like a case
/// missing from `results`. The divergence is keyed by the group id, which has
/// no `/` and therefore is never mistaken for a case key.
fn compare_content_hashes(oracle: &SdkReport, observed: &SdkReport) -> Vec<Divergence> {
    let mut divergences = Vec::new();
    let mut group_ids: Vec<&String> = oracle.groups.keys().collect();
    group_ids.extend(
        observed
            .groups
            .keys()
            .filter(|id| !oracle.groups.contains_key(*id)),
    );
    for group_id in group_ids {
        let expected = oracle
            .groups
            .get(group_id)
            .and_then(|g| g.content_hash.as_ref());
        let actual = observed
            .groups
            .get(group_id)
            .and_then(|g| g.content_hash.as_ref());
        if expected == actual {
            continue;
        }
        divergences.push(Divergence {
            case_key: group_id.clone(),
            sdk: observed.sdk.clone(),
            kind: DivergenceKind::ContentHash,
            oracle: content_hash_verdict(expected),
            observed: content_hash_verdict(actual),
        });
    }
    divergences
}

/// A group-level hash rendered into the per-case shape `Divergence` carries,
/// so the JSON report and the terminal summary need no special case.
fn content_hash_verdict(hash: Option<&String>) -> CaseVerdict {
    CaseVerdict::Error {
        message: match hash {
            Some(hash) => format!("content_hash {hash}"),
            None => "no content_hash reported".to_string(),
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
            None
        }
        (CaseVerdict::Rejected { phase: left, .. }, CaseVerdict::Rejected { phase: right, .. }) => {
            (left != right).then_some(DivergenceKind::Acceptance)
        }
        (CaseVerdict::Error { .. }, CaseVerdict::Error { .. }) => None,
        _ => Some(DivergenceKind::Acceptance),
    }
}

/// Runs an SDK harness as `command... <bundle.json>` and parses its stdout
/// report. Fail-closed: spawn failures, non-zero exits, and malformed
/// reports are hard errors, never skipped SDKs.
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

/// Harness commands for the three ported SDKs (Tasks 8-10 provide the scripts).
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
    /// Subset of ["typescript", "python", "go"]; the Rust oracle always runs.
    pub sdks: Vec<String>,
    pub minimize: bool,
    pub emit_fixtures_dir: Option<std::path::PathBuf>,
    pub report_path: Option<std::path::PathBuf>,
    pub bundles_dir: std::path::PathBuf,
    pub ignore_reason: bool,
    pub ignore_rule_trace: bool,
    pub ignore_content_hash: bool,
    pub repo_root: std::path::PathBuf,
    /// Replay an existing bundle instead of generating (single chunk).
    pub bundle_path: Option<std::path::PathBuf>,
    /// Test seam: replaces every selected SDK's command (keeps sdk names).
    pub harness_override: Option<Vec<String>>,
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

    let mut evaluators: Vec<SubprocessEvaluator> = Vec::new();
    for sdk in &config.sdks {
        let mut evaluator = default_subprocess_evaluators(&config.repo_root)
            .into_iter()
            .find(|candidate| candidate.sdk == *sdk)
            .ok_or_else(|| {
                DiffError::Config(format!(
                    "unknown sdk '{sdk}' (expected typescript, python, or go)"
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
        let bundle = match &config.bundle_path {
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
            let options = CompareOptions {
                ignore_reason: config.ignore_reason,
                ignore_rule_trace: config.ignore_rule_trace,
                ignore_content_hash: config.ignore_content_hash,
            };
            for divergence in compare_reports(&oracle_report, &report, &options) {
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
    let resolved = divergence.case_key.split_once('/').and_then(|(gid, aid)| {
        let group = bundle.groups.iter().find(|group| group.id == gid)?;
        let case = group.actions.iter().find(|case| case.id == aid)?;
        Some((group, case))
    });
    let Some((group, case)) = resolved else {
        outcome.divergences.push(divergence);
        return Ok(());
    };

    let mut oracle = InProcessEvaluator;
    let minimized = match crate::minimize::minimize_case(
        &group.policy,
        &case.action,
        &mut oracle,
        failing,
        &CompareOptions {
            ignore_reason: config.ignore_reason,
            ignore_rule_trace: config.ignore_rule_trace,
            ignore_content_hash: config.ignore_content_hash,
        },
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
        if let Ok((filename, yaml)) =
            crate::emit::build_regression_fixture(&minimized, verdict, config.seed)
            && emitted.insert(filename.clone())
        {
            let path = crate::emit::write_regression_fixture(dir, &filename, &yaml)?;
            outcome.fixtures.push(path);
        }
    }

    outcome.divergences.push(divergence);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The oracle must report the trace, not just the verdict: a trace-only
    /// disagreement is a real evaluator divergence (it is what a receipt
    /// records), and before P1-12 it was invisible to the fuzzer.
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
            "the oracle must surface the evaluator's rule trace"
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

    /// The oracle reports one canonical content hash per group, over the
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
            .expect("the oracle hashes an accepted policy");
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
        let divergences = compare_reports(&report, &silent, &CompareOptions::default());
        assert_eq!(divergences.len(), 1);
        assert_eq!(divergences[0].kind, DivergenceKind::ContentHash);
        assert_eq!(divergences[0].case_key, "g0001");

        // A harness that computes a different identity is the real bug this
        // comparison exists to catch.
        let mut wrong = report.clone();
        wrong.sdk = "python".to_string();
        wrong.groups.insert(
            "g0001".to_string(),
            GroupReport {
                content_hash: Some(format!("{}0", &expected[..expected.len() - 1])),
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
        assert!(compare_reports(&report, &silent, &options).is_empty());
    }

    /// A policy the oracle rejects has no identity to report, and a harness
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

    /// Generating a Wave 2 rule block is not the same as *reaching* it: a
    /// block that is disabled, gated off by a false `when`, or short-circuited
    /// by the origins/posture guards is traced as `skip` and proves nothing.
    /// Assert the oracle actually evaluates the new blocks over a generated
    /// corpus, and that detection escalates at least one verdict.
    #[test]
    fn generated_corpus_actually_reaches_the_wave_two_evaluators() {
        let bundle = crate::r#gen::generate_bundle(
            5,
            &crate::r#gen::GenConfig {
                groups: 200,
                actions_per_group: 4,
            },
        );
        let mut oracle = InProcessEvaluator;
        let report = oracle.evaluate_bundle(&bundle).expect("oracle evaluates");

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
                    evaluated_blocks.insert(match entry.rule_block.as_str() {
                        "browser_automation" => "browser_automation",
                        "code_execution" => "code_execution",
                        "origins" => "origins",
                        "posture_capability" => "posture_capability",
                        "default" => "default",
                        _ => continue,
                    });
                }
            }
        }
        for expected in [
            "browser_automation",
            "code_execution",
            "origins",
            "posture_capability",
            "default",
        ] {
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
    fn ignore_reason_suppresses_reason_only_divergence() {
        let oracle = report_of("rust", &[("k", ok_verdict("allow", None, Some("a")))]);
        let observed = report_of("py", &[("k", ok_verdict("allow", None, Some("b")))]);
        let options = CompareOptions {
            ignore_rule_trace: false,
            ignore_content_hash: false,
            ignore_reason: true,
        };
        assert!(compare_reports(&oracle, &observed, &options).is_empty());
    }

    #[test]
    fn compare_reports_flags_a_phantom_case_not_in_the_oracle() {
        // The oracle-driven loop above only ever walks the oracle's keys, so
        // a harness that *adds* a case key the oracle (and therefore the
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
        // A stub "typescript" harness that always answers allow-with-no-rule,
        // which must diverge from the oracle on the deny cases the generator
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
            repo_root: std::path::PathBuf::from("."),
            bundle_path: None,
            harness_override: None,
        };
        assert!(matches!(run_difftest(&config), Err(DiffError::Config(_))));
    }

    #[test]
    #[cfg(unix)]
    fn run_difftest_never_silently_drops_a_phantom_case_key() {
        // A stub harness that answers correctly for every real case AND adds
        // one case key the bundle never produced. Even if every real answer
        // happened to agree with the oracle, the invented key must still
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
        // Neither of the two tests above ever sets `minimize: true`, so
        // `handle_divergence` (minimize_case + build_regression_fixture +
        // write_regression_fixture wiring) and the `bundle_path` replay
        // branch are otherwise completely untested by this suite. Use a
        // hand-built single-case bundle (replayed from disk, not generated)
        // with a guaranteed, deterministic divergence so minimization
        // terminates in at most a handful of subprocess spawns.
        //
        // The policy carries an `extends` and the action a runtime `context`
        // -- the two P1-12 fields the generator now emits and that the fixture
        // schema cannot express verbatim (no `extends` resolver in the
        // runners, no `context` on the schema's `Action`). Putting them in the
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
        // bundle it's given -- diverges from the oracle's expected "deny" on
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

    /// `PANIC_ACTIVE` is one global `AtomicBool` in the `hushspec` crate
    /// (see `hushspec::panic`), so any test that activates it risks a
    /// window where another concurrently-running test's `evaluate()` call
    /// observes it. `hushspec`'s own test suite accepts the same tradeoff
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
