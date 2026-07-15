use crate::diff::{CaseVerdict, DiffError, DivergenceKind};
use crate::minimize::MinimizedCase;
use sha2::{Digest, Sha256};

/// Build a standard evaluator fixture from a minimized diverging case.
/// The `expect` block comes from the Rust oracle; the failing SDK's suite
/// will fail on this fixture until the divergence is fixed.
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
    // reason strings are only pinned when the divergence itself was about them.
    if min.kind == DivergenceKind::Reason
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
    let fixture = serde_json::json!({
        "hushspec_test": "0.1.0",
        "description": format!(
            "auto-minimized differential regression (sdk {}, seed {seed}, kind {kind_slug})",
            min.sdk
        ),
        "policy": min.policy,
        "cases": [{
            "description": "minimized diverging case",
            "action": min.action,
            "expect": serde_json::Value::Object(expect),
        }],
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
    fn build_regression_fixture_refuses_off_schema_action_type() {
        // The fuzz generator (gen.rs `action_strategy`) has a low-weight
        // "unknown_action" branch specifically so the oracle's fallback arm
        // (any unrecognized `action.type` -> Allow) gets exercised. The Rust
        // evaluator happily evaluates it, but the evaluator-test schema's
        // `Action.type` is a closed 8-value enum that does not include it.
        let mut min = minimized();
        min.action = serde_json::json!({"type": "unknown_action", "target": "shell_exec"});
        let verdict = oracle_verdict(&min);
        assert!(
            matches!(&verdict, CaseVerdict::Ok { .. }),
            "the oracle must accept this action (that's the whole bug) -- got {verdict:?}"
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let eval_dir = dir.path().join("core/evaluation");

        // Mirror how a caller (e.g. a future fixture-emission loop) is
        // expected to use this API: only write a file when Ok comes back.
        match build_regression_fixture(&min, &verdict, 1) {
            Err(error) => {
                let message = error.to_string();
                assert!(
                    message.contains("unknown_action"),
                    "error should name the offending action type, got: {message}"
                );
            }
            Ok((filename, yaml)) => {
                write_regression_fixture(&eval_dir, &filename, &yaml).expect("writes");
                panic!(
                    "an action.type the evaluator-test schema doesn't recognize must be \
                     refused, not emitted (wrote {filename})"
                );
            }
        }

        assert!(
            !eval_dir.exists(),
            "no fixture file should be written when the fixture is schema-invalid"
        );
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
