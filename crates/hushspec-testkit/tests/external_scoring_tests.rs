use hushspec_testkit::external::{
    corpus::{Assertion, Case, Expectation, plan_cases, plan_cases_with_limits},
    model::{ErrorCodes, Observation, Operation, Phase, ProcessLimits, Request, Response, Slot},
    score::{normalize_document, score},
    snapshot::snapshot_corpus,
};
use hushspec_testkit::report::{self, Status};
use serde_json::{Value, json};
use std::path::Path;

fn case(operation: Operation, assertion: Assertion) -> Case {
    Case {
        id: "literal#case".into(),
        operation,
        input: json!({"policy":"hushspec: '1.0.0'","action":{"type":"unrecognized"}}),
        expectations: vec![Expectation {
            slot: Slot {
                path: "literal#case".into(),
                category: "evaluation".into(),
                level: 3,
            },
            assertion,
        }],
    }
}
fn response(case: &Case, result: Observation) -> Response {
    Response {
        protocol: "0.1.0".into(),
        run_id: "test".into(),
        case_id: case.id.clone(),
        operation: case.operation,
        input_sha256: "a".repeat(64),
        result,
    }
}
fn ok(value: Value) -> Observation {
    Observation::Ok { value }
}

#[test]
fn external_document_projection_uses_declared_schema_lineage() {
    assert!(normalize_document(&json!({"hushspec":"0.2.0","name":""}), false).is_ok());
    assert!(normalize_document(&json!({"hushspec":"1.0.0","name":""}), false).is_err());
}

#[test]
fn external_planning_budget_matches_exact_retained_wire_sizes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let corpus = snapshot_corpus(&root).unwrap();
    let plan = plan_cases(&corpus, 3).unwrap();
    let bytes: usize = plan
        .cases
        .iter()
        .map(|case| {
            let input = serde_json::to_vec(&case.input).unwrap();
            let request = Request {
                protocol: "0.1.0".into(),
                run_id: "a".repeat(64),
                case_id: case.id.clone(),
                operation: case.operation,
                input_sha256: "b".repeat(64),
                input: case.input.clone(),
            };
            input.len() + serde_json::to_vec(&request).unwrap().len()
        })
        .sum();
    let limits = ProcessLimits {
        total_request_bytes: bytes,
        ..Default::default()
    };
    assert!(plan_cases_with_limits(&corpus, 3, &limits).is_ok());
    let limits = ProcessLimits {
        total_request_bytes: bytes - 1,
        ..Default::default()
    };
    let error = plan_cases_with_limits(&corpus, 3, &limits).unwrap_err();
    assert!(error.contains("request/input byte limit"), "{error}");
}
fn status(case: &Case, observation: Observation, codes: ErrorCodes) -> Status {
    score(case, &response(case, observation), codes).unwrap()[0].status
}

#[test]
fn external_fabricated_allow_and_missing_asserted_fields_fail() {
    let c = case(
        Operation::Evaluate,
        Assertion::Fields(json!({"decision":"deny"})),
    );
    assert_eq!(
        status(&c, ok(json!({"decision":"allow"})), ErrorCodes::Registry),
        Status::Fail
    );
    assert_eq!(
        status(
            &c,
            ok(json!({"decision":"deny","reason":"unknown"})),
            ErrorCodes::Registry
        ),
        Status::Pass
    );
    let c = case(
        Operation::Evaluate,
        Assertion::Fields(json!({"decision":"deny","matched_rule":"egress"})),
    );
    assert_eq!(
        status(&c, ok(json!({"decision":"deny"})), ErrorCodes::Registry),
        Status::Fail
    );
    assert_eq!(
        status(&c, Observation::Unsupported, ErrorCodes::Registry),
        Status::NotAttempted
    );
    assert!(
        score(
            &c,
            &response(
                &c,
                Observation::Error {
                    diagnostic: "database offline".into()
                }
            ),
            ErrorCodes::Registry
        )
        .is_err()
    );
}

#[test]
fn external_refusals_respect_phase_and_conditional_registry_policy() {
    let c = case(
        Operation::Validate,
        Assertion::Reject {
            phases: vec![Phase::Parse, Phase::Validate],
            code: Some("E001".into()),
            message: Some("unknown".into()),
        },
    );
    let rejection = |code| Observation::Rejected {
        phase: Phase::Validate,
        diagnostic: "unknown field".into(),
        code,
    };
    assert_eq!(
        status(&c, rejection(None), ErrorCodes::Registry),
        Status::Fail
    );
    assert_eq!(status(&c, rejection(None), ErrorCodes::None), Status::Pass);
    assert_eq!(
        status(&c, rejection(Some("E002".into())), ErrorCodes::None),
        Status::Fail
    );
    assert_eq!(
        status(
            &c,
            Observation::Rejected {
                phase: Phase::Resolve,
                diagnostic: "unknown field".into(),
                code: Some("E001".into())
            },
            ErrorCodes::Registry
        ),
        Status::Fail
    );
    for mode in [ErrorCodes::None, ErrorCodes::Registry] {
        assert_eq!(
            status(
                &c,
                Observation::Rejected {
                    phase: Phase::Validate,
                    diagnostic: "unrelated".into(),
                    code: Some("E001".into())
                },
                mode
            ),
            Status::Fail
        );
    }
    let early = case(Operation::Parse, Assertion::ParseUnconstrained);
    assert_eq!(
        status(
            &early,
            ok(json!({"hushspec":"1.0.0","unknown":true})),
            ErrorCodes::None
        ),
        Status::Pass
    );
    assert_eq!(
        status(
            &early,
            Observation::Rejected {
                phase: Phase::Parse,
                diagnostic: "unknown field".into(),
                code: None
            },
            ErrorCodes::None
        ),
        Status::Pass
    );
    let yaml = case(
        Operation::Parse,
        Assertion::Reject {
            phases: vec![Phase::Parse],
            code: None,
            message: None,
        },
    );
    assert_eq!(
        status(&yaml, ok(json!({"hushspec":"1.0.0"})), ErrorCodes::None),
        Status::Fail
    );
}

#[test]
fn external_document_normalization_preserves_meaning_and_refuses_unresolved_output() {
    let a = json!({"hushspec":"1.0.0","rules":{"egress":{"allow":["good.example"]}},"metadata":{"policy_version":2}});
    let b = json!({"hushspec":"1.0.0","rules":{"egress":{"allow":["good.example"],"block":[],"enabled":true,"default":"block"}},"metadata":{"policy_version":2}});
    assert_eq!(
        normalize_document(&a, true).unwrap(),
        normalize_document(&b, true).unwrap()
    );
    let mut wrong = b.clone();
    wrong["metadata"]["policy_version"] = json!(3);
    assert_ne!(
        normalize_document(&a, true).unwrap(),
        normalize_document(&wrong, true).unwrap()
    );
    for key in ["extends", "merge_strategy", "extra"] {
        let mut wrong = a.clone();
        wrong[key] = json!("deep_merge");
        assert!(normalize_document(&wrong, true).is_err());
    }
    let unresolved = json!({"hushspec":"1.0.0","extends":"base","merge_strategy":"replace"});
    assert_eq!(
        normalize_document(&unresolved, false).unwrap()["extends"],
        "base"
    );
    let significant =
        json!({"hushspec":"1.0.0","extensions":{"origins":{"profiles":[{"id":"all","match":{}}]}}});
    assert_eq!(
        normalize_document(&significant, true).unwrap()["extensions"]["origins"]["profiles"][0]["match"],
        json!({})
    );
}

#[test]
fn external_complete_corpus_has_raw_spelling_and_no_expected_answers_in_requests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let corpus = snapshot_corpus(&root).unwrap();
    let plan = plan_cases(&corpus, 3).unwrap();
    assert!(plan.cases.len() > 500);
    let raw = plan
        .cases
        .iter()
        .find(|c| c.id.ends_with("#leading-zero/parse"))
        .unwrap();
    assert!(
        raw.input["policy"]
            .as_str()
            .unwrap()
            .contains("threshold: 010")
    );
    for c in &plan.cases {
        assert!(c.input.get("expected").is_none() && c.input.get("expect").is_none());
        if let Some(documents) = c.input.get("documents").and_then(Value::as_object) {
            if let Some(root) = c.input["source"].as_str().and_then(|s| documents.get(s)) {
                assert_eq!(root, &c.input["policy"], "{} root identity", c.id);
            }
            assert!(
                documents
                    .keys()
                    .all(|name| !name.contains("expected-") && !name.contains("expect.yaml"))
            );
        }
    }
    assert!(plan.cases.iter().any(|c| c.operation == Operation::Resolve));
    assert!(plan.unattempted.iter().any(|r| r.level == Some(4)));
    let results = plan.complete_results(&[]).unwrap();
    assert_eq!(
        results.len(),
        plan.cases
            .iter()
            .map(|c| c.expectations.len())
            .sum::<usize>()
            + plan.unattempted.len()
    );
    let report = report::build_from_snapshot(
        report::reference_implementation(),
        &corpus.manifest,
        corpus.manifest_snapshot.sha256,
        results,
        report::now_rfc3339(),
    )
    .unwrap();
    assert_eq!(report.highest_level, None);
    let mut duplicate = plan.complete_results(&[]).unwrap();
    duplicate.push(duplicate[0].clone());
    assert!(plan.complete_results(&duplicate).is_err());
}

#[test]
fn external_integer_assertions_do_not_round_distinct_large_integers_together() {
    let c = case(
        Operation::Parse,
        Assertion::ValueAt {
            path: vec!["number".into()],
            value: json!(9007199254740992u64),
        },
    );
    assert_eq!(
        status(
            &c,
            ok(json!({"hushspec":"1.0.0","number":9007199254740993u64})),
            ErrorCodes::None
        ),
        Status::Fail
    );
}

#[test]
fn external_fabricated_allow_cannot_bypass_block_precedence() {
    let mut c = case(
        Operation::Evaluate,
        Assertion::Fields(json!({"decision":"deny"})),
    );
    c.input = json!({"policy":"hushspec: '1.0.0'\nrules:\n  egress:\n    allow: ['*']\n    block: [blocked.example]\n", "action":{"type":"egress","target":"blocked.example"}});
    assert_eq!(
        status(&c, ok(json!({"decision":"allow"})), ErrorCodes::None),
        Status::Fail
    );
}

#[test]
fn external_missing_subcase_cannot_hide_behind_other_passes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let corpus = snapshot_corpus(&root).unwrap();
    let plan = plan_cases(&corpus, 3).unwrap();
    let mut simulated = Vec::new();
    for c in &plan.cases {
        for e in &c.expectations {
            simulated.push(hushspec_testkit::external::corpus::slot_result(
                &e.slot,
                Status::Pass,
                "simulated controller accounting test",
            ));
        }
    }
    let omitted = simulated.iter().position(|r| r.level == Some(3)).unwrap();
    simulated.remove(omitted);
    let results = plan.complete_results(&simulated).unwrap();
    let report = report::build_from_snapshot(
        report::reference_implementation(),
        &corpus.manifest,
        corpus.manifest_snapshot.sha256,
        results,
        report::now_rfc3339(),
    )
    .unwrap();
    assert_eq!(report.highest_level, Some(2));
    assert_eq!(report.levels["3"].skipped, 1);
}

#[test]
fn external_malformed_scored_containers_and_misclassified_levels_are_errors() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let mut corpus = snapshot_corpus(&root).unwrap();
    let index = corpus
        .manifest
        .files
        .iter()
        .position(|e| e.category == "evaluation")
        .unwrap();
    corpus.manifest.files[index].level = 1;
    assert!(plan_cases(&corpus, 3).is_err());
    corpus.manifest.files[index].level = 3;
    let path = corpus.manifest.files[index].path.clone();
    corpus.files.get_mut(&path).unwrap().bytes =
        b"version: '0.1.0'\npolicy: {}\ncases: []\n".to_vec();
    assert!(plan_cases(&corpus, 3).is_err());
}

#[test]
fn external_wrong_resolution_refusal_does_not_satisfy_cycle_detection() {
    let c = case(
        Operation::Resolve,
        Assertion::Reject {
            phases: vec![Phase::Resolve],
            code: Some("cycle".into()),
            message: None,
        },
    );
    assert_eq!(
        status(
            &c,
            Observation::Rejected {
                phase: Phase::Resolve,
                diagnostic: "not found".into(),
                code: Some("not_found".into())
            },
            ErrorCodes::None
        ),
        Status::Fail
    );
}

#[test]
fn external_merge_children_and_invalid_expected_documents_cannot_disappear() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let mut corpus = snapshot_corpus(&root).unwrap();
    let source = "fixtures/core/merge/child-merge.yaml";
    let missing = "fixtures/core/merge/child-extra.yml";
    let mut entry = corpus
        .manifest
        .files
        .iter()
        .find(|e| e.path == source)
        .unwrap()
        .clone();
    entry.path = missing.into();
    corpus.manifest.files.push(entry);
    corpus
        .files
        .insert(missing.into(), corpus.files[source].clone());
    assert!(plan_cases(&corpus, 3).is_err());
    corpus.manifest.files.pop();
    corpus.files.remove(missing);
    corpus
        .files
        .get_mut("fixtures/core/merge/expected-merge.yaml")
        .unwrap()
        .bytes = b"hushspec: '1.0.0'\nunknown: true\n".to_vec();
    assert!(plan_cases(&corpus, 3).is_err());
}

#[test]
fn external_explicit_parser_failure_is_not_overwritten_by_validator_passes() {
    use hushspec_testkit::external::corpus::slot_result;
    let manifest = hushspec_testkit::manifest::Manifest {
        manifest_version: "0.1".into(),
        fixtures_version: "1".into(),
        generated_at: "now".into(),
        files: vec![],
    };
    let results = vec![
        slot_result(
            &Slot {
                path: "p#parse".into(),
                category: "valid".into(),
                level: 0,
            },
            Status::Fail,
            "wrong parse",
        ),
        slot_result(
            &Slot {
                path: "p#validate".into(),
                category: "valid".into(),
                level: 1,
            },
            Status::Pass,
            "validated",
        ),
    ];
    let report = report::build_from_snapshot(
        report::reference_implementation(),
        &manifest,
        "a".repeat(64),
        results,
        report::now_rfc3339(),
    )
    .unwrap();
    assert_eq!(report.highest_level, None);
    assert_eq!(report.levels["0"].failed, 1);
}

#[test]
fn external_cycle_reason_does_not_require_uncommitted_diagnostic_wording() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let corpus = snapshot_corpus(&root).unwrap();
    let plan = plan_cases(&corpus, 3).unwrap();
    let c = plan
        .cases
        .iter()
        .find(|c| c.id.contains("/extends-cycle/"))
        .unwrap();
    assert_eq!(
        status(
            c,
            Observation::Rejected {
                phase: Phase::Resolve,
                diagnostic: "circular extends detected".into(),
                code: Some("cycle".into())
            },
            ErrorCodes::None
        ),
        Status::Pass
    );
}

#[test]
fn external_duplicate_yaml_case_lists_are_not_silently_replaced() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let mut corpus = snapshot_corpus(&root).unwrap();
    let path = corpus
        .manifest
        .files
        .iter()
        .find(|e| e.category == "evaluation")
        .unwrap()
        .path
        .clone();
    let valid = "hushspec_test: '0.1.0'\ndescription: duplicate regression\npolicy: {hushspec: '1.0.0'}\ncases: [{description: first, action: {type: unknown}, expect: {decision: deny}}]\n";
    corpus.files.get_mut(&path).unwrap().bytes = valid.as_bytes().to_vec();
    assert!(plan_cases(&corpus, 3).is_ok());
    corpus.files.get_mut(&path).unwrap().bytes=format!("{valid}cases: [{{description: second, action: {{type: unknown}}, expect: {{decision: allow}}}}]\n").into_bytes();
    assert!(plan_cases(&corpus, 3).is_err());
}
