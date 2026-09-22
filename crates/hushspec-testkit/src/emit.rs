use crate::bundle::AuditSpec;
use crate::diff::{CaseVerdict, DiffError, DivergenceKind, case_receipt};
use crate::minimize::MinimizedCase;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::OnceLock;

/// The optional `expect` members the evaluator-test schema defines *in this
/// checkout*, read from the schema file at runtime.
///
/// The fixture schema grows members (`rule_trace`, `receipt`) on its own
/// schedule. Reading the file rather than the copy compiled into this binary
/// means an emitter built before a member landed still pins it, and one built
/// after a member was removed still stops -- a fixture that names a member the
/// runners' schema does not define is rejected by every runner, which is worse
/// than a fixture that pins less.
fn schema_expect_members() -> &'static BTreeSet<String> {
    static MEMBERS: OnceLock<BTreeSet<String>> = OnceLock::new();
    MEMBERS.get_or_init(|| {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/hushspec-evaluator-test.v1.schema.json"
        );
        let text = std::fs::read_to_string(path)
            .map(std::borrow::Cow::Owned)
            // Falling back to the compiled-in copy keeps a published binary
            // (no repo around it) emitting exactly what it was built against.
            .unwrap_or_else(|_| {
                std::borrow::Cow::Borrowed(
                    crate::generated_schemas::schema_body("evaluator-test").unwrap_or_default(),
                )
            });
        let Ok(schema) = serde_json::from_str::<serde_json::Value>(&text) else {
            return BTreeSet::new();
        };
        schema
            .pointer("/$defs/ExpectedResult/properties")
            .and_then(serde_json::Value::as_object)
            .map(|properties| properties.keys().cloned().collect())
            .unwrap_or_default()
    })
}

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
/// The `expect` block comes from the reference; the failing SDK's suite
/// will fail on this fixture until the divergence is fixed.
///
/// The evidence -- `expect.rule_trace` and `expect.receipt` -- is pinned only
/// when the evaluator-test schema of this checkout defines those members
/// (`schema_expect_members`), because `ExpectedResult` is
/// `additionalProperties: false` and a fixture carrying an undefined member is
/// rejected by every runner. Where they are missing, a trace- or receipt-only
/// divergence still emits, pinning `reason` (which the trace is built from),
/// and is still reported by the difftest run.
pub fn build_regression_fixture(
    min: &MinimizedCase,
    oracle_verdict: &CaseVerdict,
    seed: u64,
) -> Result<(String, String), DiffError> {
    let CaseVerdict::Ok { result } = oracle_verdict else {
        return Err(DiffError::Config(
            "refusing to emit a fixture: the reference did not evaluate the case (generator bug)"
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
    // them -- or about the rule trace or the receipt, which are both made of
    // the same per-block reasons and which `expect` may have no field for
    // (see the note on `build_regression_fixture`). Without this a
    // trace-or-receipt-only repro would pin nothing but the decision the two
    // SDKs already agreed on, and be green everywhere from the day it landed.
    if matches!(
        min.kind,
        DivergenceKind::Reason | DivergenceKind::RuleTrace | DivergenceKind::Receipt
    ) && let Some(reason) = &result.reason
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
    let render = |expect: &serde_json::Map<String, serde_json::Value>| {
        let mut case = serde_json::Map::new();
        case.insert(
            "description".to_string(),
            serde_json::Value::String("minimized diverging case".to_string()),
        );
        case.insert("action".to_string(), action.clone());
        if let Some(context) = &context {
            case.insert("context".to_string(), context.clone());
        }
        case.insert(
            "expect".to_string(),
            serde_json::Value::Object(expect.clone()),
        );
        // `expect.rule_trace` and `expect.receipt` are 0.2.0 members, so a
        // fixture that pins either declares the format that defines them.
        let pins = |member: &str| expect.get(member).is_some_and(|value| !value.is_null());
        let version = if pins("rule_trace") || pins("receipt") {
            "0.2.0"
        } else {
            "0.1.0"
        };
        serde_json::json!({
            "hushspec_test": version,
            "description": format!(
                "auto-minimized differential regression (sdk {}, seed {seed}, kind {kind_slug})",
                min.sdk
            ),
            "policy": policy,
            "cases": [serde_json::Value::Object(case)],
        })
    };

    // Pin the evidence too, when the fixture schema has somewhere to put it:
    // `expect.rule_trace` (which block decided, and in what order) and
    // `expect.receipt` (the whole 0.2 receipt under the fixed audit inputs).
    // A trace- or receipt-only divergence otherwise emits a fixture that
    // pins only the decision -- green everywhere, including on the SDK that
    // diverged. Each member's spelling belongs to the schema, not to this
    // emitter, so candidates are offered in order and the first the schema
    // accepts wins; when none does, the member is left out rather than
    // emitted wrong.
    let receipt = receipt_for(min, &policy);
    for (member, candidates) in [
        ("rule_trace", trace_candidates(result, receipt.as_ref())),
        ("receipt", receipt_candidates(receipt.as_ref())),
    ] {
        if !schema_expect_members().contains(member) {
            continue;
        }
        for candidate in candidates {
            let mut probe = expect.clone();
            probe.insert(member.to_string(), candidate);
            if crate::runner::validate_evaluator_schema(&render(&probe)).is_ok() {
                expect = probe;
                break;
            }
        }
    }

    let fixture = render(&expect);

    // The evaluator-test schema closes every object with
    // `additionalProperties: false`, so a case or `expect` carrying a member
    // the schema does not define is rejected outright. The fuzz generator can
    // produce a case the evaluators all handled but whose emitted shape the
    // schema refuses; emitting it anyway would hand the caller a fixture that
    // is permanently red for a reason unrelated to the real regression.
    // Validate against the exact schema the conformance runner uses and fail
    // closed instead of emitting.
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

/// The receipt the minimized case records under the bundle's fixed audit
/// inputs at case index 0 -- the index the emitted single-case fixture has.
///
/// `policy` is the flattened document the fixture embeds, so the receipt names
/// the identity a runner reading the fixture computes, not the identity of the
/// unresolved fragment the minimizer happened to shrink to.
fn receipt_for(
    min: &MinimizedCase,
    policy: &serde_json::Value,
) -> Option<hushspec::receipt::DecisionReceipt> {
    let yaml = serde_yaml::to_string(policy).ok()?;
    let spec = hushspec::HushSpec::parse(&yaml).ok()?;
    // `context` is still on the action here; the emitted fixture moves it onto
    // the case, which is where a runner reads it back from and applies it to
    // an action that has none. Same evaluation either way.
    let action: hushspec::EvaluationAction = serde_json::from_value(min.action.clone()).ok()?;
    case_receipt(&spec, &action, &AuditSpec::default(), 0).ok()
}

/// Spellings of `expect.rule_trace`, most likely first: the evaluator's own
/// recording (what `evaluate_traced` returns in every SDK), then the receipt
/// spelling (engine-stage ids and `rule_path`, what the receipt carries).
fn trace_candidates(
    result: &crate::diff::NormalizedResult,
    receipt: Option<&hushspec::receipt::DecisionReceipt>,
) -> Vec<serde_json::Value> {
    let mut candidates = Vec::new();
    if !result.rule_trace.is_empty()
        && let Ok(value) = serde_json::to_value(&result.rule_trace)
    {
        candidates.push(value);
    }
    if let Some(receipt) = receipt
        && !receipt.rule_trace.is_empty()
        && let Ok(value) = serde_json::to_value(&receipt.rule_trace)
    {
        candidates.push(value);
    }
    // The schema's `RuleTraceExpectation` is `additionalProperties: false`
    // over exactly `rule_block`, `outcome` and an optional `rule_path`, so the
    // two full spellings above -- both of which always serialize `evaluated`
    // -- can never validate. Offer the projection last: it is the shape the
    // runner compares and the committed vectors use, so a trace-only
    // divergence gets a fixture that actually pins the trace.
    //
    // It is projected from the evaluator's trace, not the receipt's, because
    // that is the trace the runner recomputes; the two `rule_block` ids the
    // receipt spelling renames are applied here (receipt spec 4.3, item 5).
    if !result.rule_trace.is_empty() {
        let projected: Vec<serde_json::Value> = result
            .rule_trace
            .iter()
            .map(|entry| {
                let rule_block = match entry.rule_block.as_str() {
                    "default"
                        if entry.matched_rule.as_deref()
                            == Some(hushspec::evaluate::UNKNOWN_ACTION_TYPE_RULE) =>
                    {
                        hushspec::receipt::UNKNOWN_ACTION_TYPE_BLOCK
                    }
                    "origins" => hushspec::receipt::ORIGIN_PROFILE_BLOCK,
                    other => other,
                };
                let mut object = serde_json::Map::new();
                object.insert(
                    "rule_block".to_string(),
                    serde_json::Value::String(rule_block.to_string()),
                );
                object.insert(
                    "outcome".to_string(),
                    serde_json::Value::String(entry.outcome.clone()),
                );
                if let Some(rule_path) = &entry.matched_rule {
                    object.insert(
                        "rule_path".to_string(),
                        serde_json::Value::String(rule_path.clone()),
                    );
                }
                serde_json::Value::Object(object)
            })
            .collect();
        candidates.push(serde_json::Value::Array(projected));
    }
    candidates
}

/// The one spelling of `expect.receipt` the evaluator-test schema (0.2.0)
/// defines: a partial receipt object whose present members must equal the
/// receipt produced under the fixed inputs, with the members the runner
/// ignores (`actor`, `timestamp`, `receipt_id`) left out so the fixture pins
/// content, not the clock.
fn receipt_candidates(
    receipt: Option<&hushspec::receipt::DecisionReceipt>,
) -> Vec<serde_json::Value> {
    let Some(receipt) = receipt else {
        return Vec::new();
    };
    let Ok(mut value) = serde_json::to_value(receipt) else {
        return Vec::new();
    };
    if let Some(object) = value.as_object_mut() {
        for ignored in ["actor", "timestamp", "receipt_id"] {
            object.remove(ignored);
        }
    }
    vec![value]
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

    /// `expect.rule_trace` and `expect.receipt` are 0.2.0 members, so a
    /// fixture that pins either declares 0.2.0 and never mislabels itself as
    /// the format that has nowhere to put them.
    #[test]
    fn an_emitted_fixture_declares_the_version_its_assertions_need() {
        let min = minimized();
        let verdict = oracle_verdict(&min);
        let (_, yaml) = build_regression_fixture(&min, &verdict, 1729).expect("fixture builds");
        let fixture: serde_json::Value = serde_yaml::from_str(&yaml).expect("fixture parses");
        let expect = &fixture["cases"][0]["expect"];
        let pins_evidence = !expect["rule_trace"].is_null() || !expect["receipt"].is_null();
        assert_eq!(
            fixture["hushspec_test"],
            if pins_evidence { "0.2.0" } else { "0.1.0" },
            "{yaml}"
        );
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

    /// A trace-only divergence must pin the trace itself, not just the reason:
    /// a fixture that records only the decision is green on the very SDK whose
    /// trace diverged.
    #[test]
    fn build_regression_fixture_emits_a_rule_trace_divergence() {
        let mut min = reason_case();
        min.kind = DivergenceKind::RuleTrace;
        let verdict = oracle_verdict(&min);
        let (filename, yaml) = build_regression_fixture(&min, &verdict, 1).expect("fixture builds");
        assert!(yaml.contains("reason:"), "{yaml}");
        let fixture: serde_json::Value = serde_yaml::from_str(&yaml).expect("fixture is YAML");
        let trace = fixture["cases"][0]["expect"]["rule_trace"]
            .as_array()
            .unwrap_or_else(|| panic!("expect.rule_trace must be pinned:\n{yaml}"));
        assert!(!trace.is_empty(), "{yaml}");
        for entry in trace {
            let entry = entry.as_object().expect("a trace entry is an object");
            assert!(entry.contains_key("rule_block"), "{yaml}");
            assert!(entry.contains_key("outcome"), "{yaml}");
        }
        assert_round_trips_through_runner(&filename, &yaml);
    }

    /// The emitter pins the evidence only when the fixture schema has a home
    /// for it. Whichever way the schema in this checkout reads, the emitted
    /// fixture must (a) validate and (b) never carry a member the schema does
    /// not define -- a fixture the runners reject is worse than one that pins
    /// less.
    #[test]
    fn expect_members_follow_the_schema_of_this_checkout() {
        let mut min = reason_case();
        min.kind = DivergenceKind::RuleTrace;
        let verdict = oracle_verdict(&min);
        let (filename, yaml) = build_regression_fixture(&min, &verdict, 1).expect("fixture builds");
        let fixture: serde_json::Value = serde_yaml::from_str(&yaml).expect("fixture is YAML");
        let expect = fixture["cases"][0]["expect"]
            .as_object()
            .expect("expect is an object");

        for member in ["rule_trace", "receipt"] {
            let declared = schema_expect_members().contains(member);
            if !declared {
                assert!(
                    !expect.contains_key(member),
                    "emitted `expect.{member}` that the schema does not define:\n{yaml}"
                );
            }
        }
        // Whatever it chose, the whole fixture still round-trips through the
        // real discovery -> schema -> parse -> evaluate -> expect pipeline.
        assert_round_trips_through_runner(&filename, &yaml);
    }

    /// The candidate list is what makes the member's *spelling* the schema's
    /// business rather than the emitter's: the evaluator trace first, the
    /// receipt trace second, the schema's projection last, and nothing at all
    /// when there is no trace.
    #[test]
    fn trace_candidates_offer_every_spelling_including_the_schema_s() {
        let min = reason_case();
        let CaseVerdict::Ok { result } = oracle_verdict(&min) else {
            panic!("the reference did not evaluate the reason case");
        };
        let policy = flatten_extends(&min.policy).expect("flattens");
        let receipt = receipt_for(&min, &policy).expect("the case records a receipt");

        let candidates = trace_candidates(&result, Some(&receipt));
        assert_eq!(candidates.len(), 3, "{candidates:?}");
        // The evaluator's own spelling: `matched_rule`, no engine-stage ids.
        assert!(candidates[0][0].get("matched_rule").is_some());
        assert!(candidates[0][0].get("rule_path").is_none());
        // The receipt's: `rule_path`.
        assert!(candidates[1][0].get("rule_path").is_some());
        // The schema's: exactly rule_block, outcome and an optional rule_path.
        let projected = candidates[2][0].as_object().expect("an object");
        assert!(projected.contains_key("rule_block"));
        assert!(projected.contains_key("outcome"));
        assert!(
            projected
                .keys()
                .all(|key| matches!(key.as_str(), "rule_block" | "outcome" | "rule_path")),
            "the projected candidate must carry nothing the schema forbids: {projected:?}"
        );

        // Without a receipt: the evaluator spelling and the projection.
        assert_eq!(trace_candidates(&result, None).len(), 2);
        assert!(
            trace_candidates(&crate::diff::NormalizedResult::default(), None).is_empty(),
            "a case with no trace pins no trace"
        );
    }

    /// The receipt candidates are the hash, the hash in a wrapper, and the
    /// whole receipt -- and the hash is the one the receipt actually has, not
    /// a hash of something else.
    #[test]
    fn receipt_candidates_pin_this_case_s_receipt() {
        let min = reason_case();
        let policy = flatten_extends(&min.policy).expect("flattens");
        let receipt = receipt_for(&min, &policy).expect("the case records a receipt");
        let candidates = receipt_candidates(Some(&receipt));
        assert_eq!(candidates.len(), 1);
        let pinned = candidates[0].as_object().expect("partial receipt object");
        assert_eq!(pinned["receipt_version"], serde_json::json!("0.2"));
        // The runner ignores these three, so pinning them would only tie the
        // fixture to a clock; everything else is content and stays.
        for ignored in ["actor", "timestamp", "receipt_id"] {
            assert!(
                !pinned.contains_key(ignored),
                "{ignored} must not be pinned"
            );
        }
        assert!(pinned.contains_key("policy"));
        assert!(pinned.contains_key("rule_trace"));
        assert!(pinned.get("duration_us").is_none());
        assert!(receipt_candidates(None).is_empty());
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
        // "unknown_action" branch so the fail-closed arm (any unrecognized
        // `action.type` -> Deny, core spec Section 5) gets exercised. The evaluator-test schema accepts any type string for
        // exactly this reason, so such a case is a legitimate vector.
        let mut min = minimized();
        min.action = serde_json::json!({"type": "unknown_action", "target": "shell_exec"});
        let verdict = oracle_verdict(&min);
        assert!(
            matches!(&verdict, CaseVerdict::Ok { .. }),
            "the reference did not evaluate this action -- got {verdict:?}"
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
