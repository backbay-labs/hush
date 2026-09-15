use crate::diff::{CaseVerdict, DiffError, DivergenceKind};
use crate::minimize::MinimizedCase;
use sha2::{Digest, Sha256};

/// Flatten a minimized policy's `extends` chain into the document itself.
///
/// The four shared-fixture runners parse an evaluator fixture's embedded
/// policy and evaluate it directly -- none of them resolves `extends` -- so a
/// fixture that kept the reference would silently evaluate against an empty
/// base and stop reproducing anything. Bake the resolved document in instead,
/// which is also what makes the fixture readable without chasing a builtin.
fn flatten_extends(policy: &serde_json::Value) -> Result<serde_json::Value, DiffError> {
    let Some(serde_json::Value::String(_)) = policy.get("extends") else {
        return Ok(policy.clone());
    };
    let yaml = serde_yaml::to_string(policy)
        .map_err(|error| DiffError::Config(format!("failed to re-encode policy: {error}")))?;
    let spec = hushspec::HushSpec::parse(&yaml)
        .map_err(|error| DiffError::Config(format!("minimized policy does not parse: {error}")))?;
    let resolved = crate::diff::resolve_builtin_extends(&spec).map_err(DiffError::Config)?;
    serde_json::to_value(&resolved)
        .map_err(|error| DiffError::Config(format!("failed to re-encode resolved policy: {error}")))
}

/// Split an action into the `action` and case-level `context` the
/// evaluator-test schema expects.
///
/// `EvaluationAction` carries `context` inline, but the fixture schema's
/// `Action` is `additionalProperties: false` without it and puts the runtime
/// context on the case instead (where all four runners read it from). Emitting
/// the action verbatim would therefore produce a fixture that fails schema
/// validation in every runner.
fn split_action_context(
    action: &serde_json::Value,
) -> (serde_json::Value, Option<serde_json::Value>) {
    let Some(map) = action.as_object() else {
        return (action.clone(), None);
    };
    let mut stripped = map.clone();
    let context = stripped.remove("context").filter(|value| !value.is_null());
    (serde_json::Value::Object(stripped), context)
}

/// Build a standard evaluator fixture from a minimized diverging case.
/// The `expect` block comes from the Rust oracle; the failing SDK's suite
/// will fail on this fixture until the divergence is fixed.
///
/// `rule_trace` is deliberately not written into `expect`: the evaluator-test
/// schema's `ExpectedResult` is `additionalProperties: false` with no
/// `rule_trace` member, so a fixture carrying one would be rejected by every
/// runner. A trace-only divergence still emits (pinning `reason`, which the
/// trace is built from) and is still reported by the difftest run.
pub fn build_regression_fixture(
    min: &MinimizedCase,
    oracle_verdict: &CaseVerdict,
    seed: u64,
) -> Result<(String, String), DiffError> {
    let CaseVerdict::Ok { result } = oracle_verdict else {
        return Err(DiffError::Config(
            "refusing to emit a fixture: the Rust oracle did not evaluate the case (generator bug)"
                .to_string(),
        ));
    };

    let mut expect = serde_json::Map::new();
    expect.insert(
        "decision".to_string(),
        serde_json::Value::String(result.decision.clone()),
    );
    if let Some(matched_rule) = &result.matched_rule {
        expect.insert(
            "matched_rule".to_string(),
            serde_json::Value::String(matched_rule.clone()),
        );
    }
    // reason strings are only pinned when the divergence itself was about
    // them -- or about the rule trace, whose entries are made of the same
    // per-block reasons and which `expect` has no field for (see the
    // rule_trace note on `build_regression_fixture`).
    if matches!(min.kind, DivergenceKind::Reason | DivergenceKind::RuleTrace)
        && let Some(reason) = &result.reason
    {
        expect.insert(
            "reason".to_string(),
            serde_json::Value::String(reason.clone()),
        );
    }
    if let Some(origin_profile) = &result.origin_profile {
        expect.insert(
            "origin_profile".to_string(),
            serde_json::Value::String(origin_profile.clone()),
        );
    }
    if let Some(posture) = &result.posture {
        expect.insert(
            "posture".to_string(),
            serde_json::json!({"current": posture.current, "next": posture.next}),
        );
    }

    let kind_slug = serde_json::to_value(min.kind)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string());
    let policy = flatten_extends(&min.policy)?;
    let (action, context) = split_action_context(&min.action);
    let mut case = serde_json::Map::new();
    case.insert(
        "description".to_string(),
        serde_json::Value::String("minimized diverging case".to_string()),
    );
    case.insert("action".to_string(), action);
    if let Some(context) = context {
        case.insert("context".to_string(), context);
    }
    case.insert("expect".to_string(), serde_json::Value::Object(expect));
    let fixture = serde_json::json!({
        "hushspec_test": "0.1.0",
        "description": format!(
            "auto-minimized differential regression (sdk {}, seed {seed}, kind {kind_slug})",
            min.sdk
        ),
        "policy": policy,
        "cases": [serde_json::Value::Object(case)],
    });

    // The Rust reference evaluator accepts any string as `action.type`,
    // silently falling through to Allow for ones it doesn't recognize (see
    // `hushspec::evaluate`). The fuzz generator can and does produce such
    // actions, so a divergence can be reproduced with an action the oracle
    // happily evaluated but that the evaluator-test schema -- a closed enum
    // of known action types -- rejects. Emitting that fixture anyway would
    // hand the caller a fixture that is permanently red for a reason
    // unrelated to the real regression. Validate against the exact schema
    // the conformance runner uses and fail closed instead of emitting.
    if let Err(message) = crate::runner::validate_evaluator_schema(&fixture) {
        return Err(DiffError::Config(format!(
            "refusing to emit a fixture that would fail the evaluator-test schema: {message}"
        )));
    }

    let mut hasher = Sha256::new();
    hasher.update(min.policy.to_string().as_bytes());
    hasher.update(min.action.to_string().as_bytes());
    let digest = hasher.finalize();
    let hash8: String = format!("{digest:x}").chars().take(8).collect();

    let yaml = serde_yaml::to_string(&fixture)
        .map_err(|error| DiffError::Config(format!("failed to serialize fixture: {error}")))?;
    Ok((format!("regression-{hash8}.test.yaml"), yaml))
}

pub fn write_regression_fixture(
    dir: &std::path::Path,
    filename: &str,
    yaml: &str,
) -> std::io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(filename);
    std::fs::write(&path, yaml)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::CaseBundle;
    use crate::diff::{CaseEvaluator, InProcessEvaluator};

    fn minimized() -> MinimizedCase {
        MinimizedCase {
            policy: serde_json::json!({
                "hushspec": "0.1.0",
                "rules": {"tool_access": {"block": ["shell_exec"]}}
            }),
            action: serde_json::json!({"type": "tool_call", "target": "shell_exec"}),
            sdk: "go".to_string(),
            kind: DivergenceKind::Decision,
            rounds: 3,
        }
    }

    fn oracle_verdict(min: &MinimizedCase) -> CaseVerdict {
        let bundle = CaseBundle::single_case(min.policy.clone(), min.action.clone());
        let mut oracle = InProcessEvaluator;
        let report = oracle.evaluate_bundle(&bundle).expect("oracle evaluates");
        report
            .results
            .get("g0001/a0001")
            .expect("case present")
            .clone()
    }

    #[test]
    fn emitted_fixture_passes_the_testkit_runner() {
        let min = minimized();
        let verdict = oracle_verdict(&min);
        let (filename, yaml) =
            build_regression_fixture(&min, &verdict, 1729).expect("fixture builds");
        assert!(filename.starts_with("regression-"));
        assert!(filename.ends_with(".test.yaml"));
        assert!(yaml.contains("hushspec_test"));
        assert!(yaml.contains("sdk go"));

        // The emitted fixture must survive the real fixture pipeline:
        // discovery -> schema validation -> policy parse -> evaluate -> expect.
        let dir = tempfile::tempdir().expect("tempdir");
        let eval_dir = dir.path().join("core/evaluation");
        let path = write_regression_fixture(&eval_dir, &filename, &yaml).expect("writes");
        assert!(path.exists());

        let fixtures = crate::fixture::discover_fixtures(dir.path());
        assert_eq!(fixtures.len(), 1);
        let results = crate::runner::run_conformance(&fixtures);
        assert_eq!(results.len(), 1);
        assert!(
            results[0].passed,
            "emitted fixture failed the testkit runner: {}",
            results[0].message
        );
    }

    /// A repro whose policy still needs its base must round-trip: the runners
    /// do not resolve `extends`, so the emitted fixture has to carry the
    /// flattened document (and must not keep the reference).
    #[test]
    fn build_regression_fixture_flattens_builtin_extends() {
        let mut min = minimized();
        min.policy = serde_json::json!({"hushspec": "0.2.0", "extends": "builtin:default"});
        min.action = serde_json::json!({"type": "tool_call", "target": "shell_exec"});
        let verdict = oracle_verdict(&min);
        let CaseVerdict::Ok { result } = &verdict else {
            panic!("oracle must evaluate the extends case, got {verdict:?}");
        };
        assert_eq!(result.decision, "deny", "builtin:default blocks shell_exec");

        let (filename, yaml) = build_regression_fixture(&min, &verdict, 1).expect("fixture builds");
        assert!(
            !yaml.contains("extends:"),
            "the emitted fixture must not keep an unresolved extends:\n{yaml}"
        );
        assert!(yaml.contains("shell_exec"), "{yaml}");
        assert_round_trips_through_runner(&filename, &yaml);
    }

    /// `EvaluationAction` carries `context` inline; the fixture schema puts it
    /// on the case. Emitting it in the wrong place fails schema validation in
    /// all four runners, so the emitter has to move it.
    #[test]
    fn build_regression_fixture_moves_action_context_onto_the_case() {
        let mut min = reason_case();
        min.action = serde_json::json!({
            "type": "file_read",
            "target": "/home/user/.ssh/id_rsa",
            "context": {"environment": "production", "current_time": "2026-03-02T09:30:00Z"},
        });
        let verdict = oracle_verdict(&min);
        let (filename, yaml) = build_regression_fixture(&min, &verdict, 1).expect("fixture builds");

        let fixture: serde_json::Value = serde_yaml::from_str(&yaml).expect("fixture is YAML");
        let case = &fixture["cases"][0];
        assert!(
            case["action"].get("context").is_none(),
            "context must not stay on the action:\n{yaml}"
        );
        assert_eq!(case["context"]["environment"], "production");
        assert_eq!(case["context"]["current_time"], "2026-03-02T09:30:00Z");
        assert_round_trips_through_runner(&filename, &yaml);
    }

    /// A trace-only divergence still yields a fixture, and it pins the reason
    /// (the trace's own building block) since `expect` has no `rule_trace`.
    #[test]
    fn build_regression_fixture_emits_a_rule_trace_divergence() {
        let mut min = reason_case();
        min.kind = DivergenceKind::RuleTrace;
        let verdict = oracle_verdict(&min);
        let (filename, yaml) = build_regression_fixture(&min, &verdict, 1).expect("fixture builds");
        assert!(yaml.contains("reason:"), "{yaml}");
        let fixture: serde_json::Value = serde_yaml::from_str(&yaml).expect("fixture is YAML");
        assert!(
            fixture["cases"][0]["expect"].get("rule_trace").is_none(),
            "expect has no rule_trace member in the evaluator-test schema:\n{yaml}"
        );
        assert_round_trips_through_runner(&filename, &yaml);
    }

    #[test]
    fn same_case_produces_the_same_filename() {
        let min = minimized();
        let verdict = oracle_verdict(&min);
        let (first, _) = build_regression_fixture(&min, &verdict, 1).expect("builds");
        let (second, _) = build_regression_fixture(&min, &verdict, 2).expect("builds");
        assert_eq!(
            first, second,
            "filename is a content hash, independent of seed"
        );
    }

    #[test]
    fn refuses_to_emit_when_oracle_rejected() {
        let min = minimized();
        let rejected = CaseVerdict::Rejected {
            phase: "validate".to_string(),
            message: "bad".to_string(),
        };
        assert!(matches!(
            build_regression_fixture(&min, &rejected, 1),
            Err(DiffError::Config(_))
        ));
    }

    #[test]
    fn build_regression_fixture_emits_unknown_action_type_as_deny_vector() {
        // The fuzz generator (gen.rs `action_strategy`) has a low-weight
        // "unknown_action" branch so the oracle's fail-closed arm (any
        // unrecognized `action.type` -> Deny, core spec Section 5) gets
        // exercised. The evaluator-test schema accepts any type string for
        // exactly this reason, so such a case is a legitimate vector.
        let mut min = minimized();
        min.action = serde_json::json!({"type": "unknown_action", "target": "shell_exec"});
        let verdict = oracle_verdict(&min);
        assert!(
            matches!(&verdict, CaseVerdict::Ok { .. }),
            "the oracle must evaluate this action -- got {verdict:?}"
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let eval_dir = dir.path().join("core/evaluation");
        let (filename, yaml) = build_regression_fixture(&min, &verdict, 1).expect("builds");
        assert!(yaml.contains("__unknown_action_type__"), "{yaml}");
        write_regression_fixture(&eval_dir, &filename, &yaml).expect("writes");

        let fixtures = crate::fixture::discover_fixtures(dir.path());
        assert_eq!(fixtures.len(), 1);
        let results = crate::runner::run_conformance(&fixtures);
        assert!(results[0].passed, "{}", results[0].message);
    }

    /// Write an emitted fixture into a fresh tempdir and assert it survives
    /// the real pipeline: discovery -> schema validation -> policy parse ->
    /// evaluate -> `expect` comparison. Same proof `emitted_fixture_passes_the_testkit_runner`
    /// uses, factored out so the three branch-coverage tests below don't
    /// each repeat it.
    fn assert_round_trips_through_runner(filename: &str, yaml: &str) {
        let dir = tempfile::tempdir().expect("tempdir");
        let eval_dir = dir.path().join("core/evaluation");
        let path = write_regression_fixture(&eval_dir, filename, yaml).expect("writes");
        assert!(path.exists());

        let fixtures = crate::fixture::discover_fixtures(dir.path());
        assert_eq!(fixtures.len(), 1);
        let results = crate::runner::run_conformance(&fixtures);
        assert_eq!(results.len(), 1);
        assert!(
            results[0].passed,
            "emitted fixture failed the testkit runner: {}",
            results[0].message
        );
    }

    /// A divergence about the `reason` string. `forbidden_paths` is a core
    /// rule whose evaluator result carries a specific, non-generic reason
    /// ("path matched a forbidden pattern") for an in-schema action type
    /// (`file_read`) -- see `hushspec::evaluate_forbidden_paths`. No
    /// `extensions` block at all, so `origin_profile` and `posture` stay
    /// `None` and this exercises the `Reason` branch in isolation.
    fn reason_case() -> MinimizedCase {
        MinimizedCase {
            policy: serde_json::json!({
                "hushspec": "0.1.0",
                "rules": {"forbidden_paths": {"patterns": ["**/.ssh/**"]}}
            }),
            action: serde_json::json!({"type": "file_read", "target": "/home/user/.ssh/id_rsa"}),
            sdk: "python".to_string(),
            kind: DivergenceKind::Reason,
            rounds: 1,
        }
    }

    /// A divergence about `origin_profile`: `extensions.origins` with one
    /// profile matching the action's `origin` context. Deliberately no
    /// `extensions.posture` block and no profile-level `posture:` field
    /// (both optional -- see `validate_origins`), so `resolve_posture`
    /// returns `None` and this exercises `origin_profile` in isolation from
    /// the `posture` branch.
    fn origin_case() -> MinimizedCase {
        MinimizedCase {
            policy: serde_json::json!({
                "hushspec": "0.1.0",
                "rules": {"tool_access": {"default": "block"}},
                "extensions": {
                    "origins": {
                        "default_behavior": "minimal_profile",
                        "profiles": [{
                            "id": "exact-channel",
                            "match": {
                                "provider": "slack",
                                "space_id": "C123",
                                "visibility": "internal"
                            },
                            "tool_access": {"allow": ["github_search"], "default": "block"}
                        }]
                    }
                }
            }),
            action: serde_json::json!({
                "type": "tool_call",
                "target": "github_search",
                "origin": {
                    "provider": "slack",
                    "space_id": "C123",
                    "visibility": "internal"
                }
            }),
            sdk: "go".to_string(),
            kind: DivergenceKind::OriginProfile,
            rounds: 1,
        }
    }

    /// A divergence about `posture`: `extensions.posture` configured and the
    /// action carries a posture context. No `extensions.origins` and no
    /// `origin` on the action, so `select_origin_profile` returns `None`
    /// and this exercises `posture` in isolation from `origin_profile`.
    fn posture_case() -> MinimizedCase {
        MinimizedCase {
            policy: serde_json::json!({
                "hushspec": "0.1.0",
                "rules": {"tool_access": {"allow": ["read_file"], "default": "block"}},
                "extensions": {
                    "posture": {
                        "initial": "standard",
                        "states": {
                            "standard": {"capabilities": ["tool_call"]},
                            "restricted": {"capabilities": []}
                        },
                        "transitions": [
                            {"from": "standard", "to": "restricted", "on": "any_violation"}
                        ]
                    }
                }
            }),
            action: serde_json::json!({
                "type": "tool_call",
                "target": "read_file",
                "posture": {"current": "standard", "signal": "none"}
            }),
            sdk: "typescript".to_string(),
            kind: DivergenceKind::Posture,
            rounds: 1,
        }
    }

    #[test]
    fn build_regression_fixture_pins_reason_when_kind_is_reason() {
        let min = reason_case();
        let verdict = oracle_verdict(&min);
        let CaseVerdict::Ok { result } = &verdict else {
            panic!("oracle must evaluate the reason case, got {verdict:?}");
        };
        assert!(
            result.reason.is_some(),
            "fixture must actually produce a reason, else this test doesn't cover the branch"
        );

        let (filename, yaml) = build_regression_fixture(&min, &verdict, 1).expect("fixture builds");
        assert!(
            yaml.contains("reason:"),
            "reason must be pinned into expect when kind is Reason:\n{yaml}"
        );
        assert_round_trips_through_runner(&filename, &yaml);
    }

    #[test]
    fn build_regression_fixture_pins_origin_profile() {
        let min = origin_case();
        let verdict = oracle_verdict(&min);
        let CaseVerdict::Ok { result } = &verdict else {
            panic!("oracle must evaluate the origin case, got {verdict:?}");
        };
        assert!(
            result.origin_profile.is_some(),
            "fixture must actually match an origin profile, else this test doesn't cover the branch"
        );

        let (filename, yaml) = build_regression_fixture(&min, &verdict, 1).expect("fixture builds");
        assert!(
            yaml.contains("origin_profile:"),
            "origin_profile must be pinned into expect:\n{yaml}"
        );
        assert_round_trips_through_runner(&filename, &yaml);
    }

    #[test]
    fn build_regression_fixture_pins_posture() {
        let min = posture_case();
        let verdict = oracle_verdict(&min);
        let CaseVerdict::Ok { result } = &verdict else {
            panic!("oracle must evaluate the posture case, got {verdict:?}");
        };
        assert!(
            result.posture.is_some(),
            "fixture must actually carry posture, else this test doesn't cover the branch"
        );

        let (filename, yaml) = build_regression_fixture(&min, &verdict, 1).expect("fixture builds");
        assert!(
            yaml.contains("posture:"),
            "posture must be pinned into expect:\n{yaml}"
        );
        assert_round_trips_through_runner(&filename, &yaml);
    }
}
