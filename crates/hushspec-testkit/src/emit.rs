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
}
