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
/// case; iteration follows the oracle's sorted key order.
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
}
