use crate::bundle::CaseBundle;
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedPosture {
    pub current: String,
    pub next: String,
}

impl From<EvaluationResult> for NormalizedResult {
    fn from(result: EvaluationResult) -> Self {
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
        }
    }
}

/// One SDK's verdicts for a whole bundle, keyed "gNNNN/aNNNN".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkReport {
    pub sdk: String,
    pub results: BTreeMap<String, CaseVerdict>,
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
        for group in &bundle.groups {
            let parsed = parse_policy(&group.policy);
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
        })
    }
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
    CaseVerdict::Ok {
        result: hushspec::evaluate(spec, &action).into(),
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
}

/// Compare an SDK report against the Rust oracle. First difference wins per
/// case; iteration follows the oracle's sorted key order. The comparison is
/// symmetric in key coverage: a case the oracle has but the harness omits is
/// `MissingCase`, and a case the harness answers but the oracle (and
/// therefore the bundle) never produced is `PhantomCase`. Neither direction
/// is allowed to pass silently -- a buggy harness that fabricates extra
/// case keys must be exposed exactly like one that drops cases.
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
    divergences
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

    #[test]
    fn oracle_matches_hand_computed_verdicts_on_sample_bundle() {
        let bundle = CaseBundle::from_json(include_str!("../testdata/sample-bundle.json"))
            .expect("sample bundle parses");
        let mut oracle = InProcessEvaluator;
        let report = oracle.evaluate_bundle(&bundle).expect("oracle evaluates");
        assert_eq!(report.sdk, "rust");
        assert_eq!(report.results.len(), 4);

        let allow = report.results.get("g0001/a0001").expect("case present");
        assert_eq!(
            allow,
            &CaseVerdict::Ok {
                result: NormalizedResult {
                    decision: "allow".to_string(),
                    matched_rule: Some("rules.tool_access.allow".to_string()),
                    reason: Some("tool is explicitly allowed".to_string()),
                    origin_profile: None,
                    posture: None,
                }
            }
        );

        let deny = report.results.get("g0001/a0002").expect("case present");
        assert_eq!(
            deny,
            &CaseVerdict::Ok {
                result: NormalizedResult {
                    decision: "deny".to_string(),
                    matched_rule: Some("rules.tool_access.block".to_string()),
                    reason: Some("tool is explicitly blocked".to_string()),
                    origin_profile: None,
                    posture: None,
                }
            }
        );

        let forbidden = report.results.get("g0002/a0001").expect("case present");
        assert_eq!(
            forbidden,
            &CaseVerdict::Ok {
                result: NormalizedResult {
                    decision: "deny".to_string(),
                    matched_rule: Some("rules.forbidden_paths.patterns".to_string()),
                    reason: Some("path matched a forbidden pattern".to_string()),
                    origin_profile: None,
                    posture: None,
                }
            }
        );

        let fallthrough = report.results.get("g0002/a0002").expect("case present");
        assert_eq!(
            fallthrough,
            &CaseVerdict::Ok {
                result: NormalizedResult {
                    decision: "allow".to_string(),
                    matched_rule: None,
                    reason: None,
                    origin_profile: None,
                    posture: None,
                }
            }
        );
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
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle = CaseBundle::single_case(
            serde_json::json!({
                "hushspec": "0.1.0",
                "rules": {"tool_access": {"block": ["shell_exec"], "default": "allow"}}
            }),
            serde_json::json!({"type": "tool_call", "target": "shell_exec"}),
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
