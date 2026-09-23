#[path = "support/evidence.rs"]
mod evidence;
#[path = "support/oscal.rs"]
mod oscal;
use predicates::prelude::*;
use serde_json::json;

#[test]
fn documented_monitor_example_is_current_and_runnable() {
    let generated = evidence::Fixture::monitor();
    let example = generated.root.join("fixtures/assurance/monitor");
    if matches!(
        std::env::var("HUSHSPEC_UPDATE_MONITOR_EXAMPLE").as_deref(),
        Ok("1" | "true")
    ) {
        std::fs::create_dir_all(&example).unwrap();
        for name in ["policy.yaml", "profile.json", "evidence.jsonl"] {
            std::fs::copy(generated.dir.path().join(name), example.join(name)).unwrap();
        }
    }
    for name in ["policy.yaml", "profile.json", "evidence.jsonl"] {
        assert_eq!(
            std::fs::read(example.join(name)).unwrap(),
            std::fs::read(generated.dir.path().join(name)).unwrap(),
            "{name}"
        );
    }
    let output = tempfile::tempdir().unwrap();
    assert_cmd::Command::cargo_bin("h2h")
        .unwrap()
        .arg("report")
        .arg(example.join("evidence.jsonl"))
        .args([
            "--format",
            "json",
            "--now",
            "2026-09-15T12:00:00Z",
            "--evidence-profile",
        ])
        .arg(example.join("profile.json"))
        .arg("--keyring")
        .arg(generated.root.join("fixtures/signing/keys/keyring.json"))
        .arg("--out")
        .arg(output.path().join("report.json"))
        .arg("--verification-out")
        .arg(output.path().join("verification.json"))
        .assert()
        .success();
    let verification: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.path().join("verification.json")).unwrap())
            .unwrap();
    assert_eq!(
        verification["report_sha256"],
        evidence::digest(&std::fs::read(output.path().join("report.json")).unwrap())
    );
}

#[test]
fn signed_monitor_evidence_produces_observations_not_findings() {
    let fixture = evidence::Fixture::monitor();
    fixture.command_oscal().assert().success();
    let document = fixture.json("assessment-results.json");
    let result = &document["assessment-results"]["results"][0];
    assert!(result.get("findings").is_none());
    assert!(result.get("risks").is_none());
    for observation in result["observations"].as_array().unwrap() {
        assert_eq!(observation["methods"], json!(["EXAMINE"]));
        assert!(
            observation["description"]
                .as_str()
                .unwrap()
                .contains("would_block=1")
        );
        assert!(observation.get("target").is_none());
    }
    assert_eq!(
        document["assessment-results"]["import-ap"]["href"],
        "context/ap.json"
    );
    assert_eq!(
        fixture.json("report.json")["totals"]["by_outcome"]["would_block"],
        1
    );
    let resources = document["assessment-results"]["back-matter"]["resources"]
        .as_array()
        .unwrap();
    for resource in resources {
        let link = &resource["rlinks"][0];
        let bytes = std::fs::read(fixture.dir.path().join(link["href"].as_str().unwrap())).unwrap();
        assert_eq!(link["hashes"][0]["algorithm"], "SHA-256");
        assert_eq!(
            link["hashes"][0]["value"],
            evidence::digest(&bytes).trim_start_matches("sha256:")
        );
    }
    for observation in result["observations"].as_array().unwrap() {
        for reference in observation["relevant-evidence"].as_array().unwrap() {
            let id = reference["href"]
                .as_str()
                .unwrap()
                .strip_prefix('#')
                .unwrap();
            assert!(resources.iter().any(|resource| resource["uuid"] == id));
        }
    }
}

#[test]
fn native_json_still_works_without_assessment_context() {
    let fixture = evidence::Fixture::monitor();
    fixture.command().assert().success();
    assert_eq!(
        fixture.json("report.json")["totals"]["by_outcome"]["would_block"],
        1
    );
}

#[test]
fn unverified_is_never_an_oscal_fallback() {
    let fixture = evidence::Fixture::monitor();
    fixture
        .command_oscal()
        .arg("--unverified")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Configuration"));
    for name in [
        "report.json",
        "verification.json",
        "assessment-results.json",
    ] {
        assert!(!fixture.dir.path().join(name).exists());
    }
}

#[test]
fn bad_inputs_and_context_leave_no_packet() {
    for (case, code, exit) in [
        ("scope", "ContextInvalid", 2),
        ("context-digest", "InputDigestMismatch", 1),
        ("unsigned", "Malformed", 2),
        ("tampered", "SignatureInvalid", 1),
    ] {
        let mut fixture = evidence::Fixture::monitor();
        if case == "scope" {
            let path = fixture.dir.path().join("context/catalog.json");
            let mut catalog: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            catalog["catalog"]["controls"][0]["id"] = json!("different-control");
            let bytes = serde_json::to_vec(&catalog).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            let ap_path = fixture.dir.path().join("context/ap.json");
            let mut ap: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&ap_path).unwrap()).unwrap();
            ap["assessment-plan"]["reviewed-controls"]["control-selections"][0]["include-controls"]
                [0]["control-id"] = json!("different-control");
            let ap_bytes = serde_json::to_vec(&ap).unwrap();
            std::fs::write(ap_path, &ap_bytes).unwrap();
            let ssp_path = fixture.dir.path().join("context/ssp.json");
            let mut ssp: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&ssp_path).unwrap()).unwrap();
            ssp["system-security-plan"]["control-implementation"]["implemented-requirements"][0]
                ["control-id"] = json!("different-control");
            let ssp_bytes = serde_json::to_vec(&ssp).unwrap();
            std::fs::write(ssp_path, &ssp_bytes).unwrap();
            let manifest_path = fixture.dir.path().join("context/context.json");
            let mut manifest: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
            manifest["resolved_catalog"]["sha256"] = evidence::digest(&bytes).into();
            manifest["assessment_plan"]["sha256"] = evidence::digest(&ap_bytes).into();
            manifest["system_security_plan"]["sha256"] = evidence::digest(&ssp_bytes).into();
            std::fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        } else if case == "context-digest" {
            std::fs::write(fixture.dir.path().join("context/ap.json"), b"tampered").unwrap();
        } else {
            let path = fixture.dir.path().join("evidence.jsonl");
            let mut signed: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            if case == "unsigned" {
                signed = signed["receipt"].clone();
            } else {
                signed["receipt"]["action"]["target"] = json!("different-tool");
            }
            let bytes = serde_json::to_vec(&signed).unwrap();
            std::fs::write(path, &bytes).unwrap();
            fixture.profile["streams"][0]["files"][0]["sha256"] = evidence::digest(&bytes).into();
            fixture.save_profile();
        }
        let assertion = fixture
            .command_oscal()
            .assert()
            .code(exit)
            .stderr(predicate::str::contains(code));
        if case == "scope" {
            assertion.stderr(predicate::str::contains(
                "policy-mapped control is not selected by the assessment plan",
            ));
        }
        for name in [
            "report.json",
            "verification.json",
            "assessment-results.json",
        ] {
            assert!(!fixture.dir.path().join(name).exists(), "{case}: {name}");
        }
    }
}

#[test]
fn unresolved_context_references_leave_no_packet() {
    for case in [
        "scope-link",
        "selection-link",
        "subject-link",
        "ssp-control",
        "ssp-duplicate",
    ] {
        let fixture = evidence::Fixture::monitor();
        let (name, field) = if case.starts_with("ssp-") {
            ("ssp.json", "system_security_plan")
        } else {
            ("ap.json", "assessment_plan")
        };
        let path = fixture.dir.path().join("context").join(name);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        if case.starts_with("ssp-") {
            let requirements =
                value["system-security-plan"]["control-implementation"]["implemented-requirements"]
                    .as_array_mut()
                    .unwrap();
            if case == "ssp-control" {
                requirements[0]["control-id"] = json!("undefined-control");
            } else {
                let mut second = requirements[0].clone();
                second["uuid"] = json!("00000000-0000-4000-8000-000000000078");
                requirements.push(second);
            }
        } else {
            value["assessment-plan"]["back-matter"] = json!({"resources":[{
                "uuid":"00000000-0000-4000-8000-000000000077", "title":"AP-only resource"
            }]});
            let pointer = match case {
                "scope-link" => "/assessment-plan/reviewed-controls",
                "selection-link" => "/assessment-plan/reviewed-controls/control-selections/0",
                _ => "/assessment-plan/assessment-subjects/0/include-subjects/0",
            };
            value.pointer_mut(pointer).unwrap()["links"] = json!([{
                "href":"#00000000-0000-4000-8000-000000000077", "rel":"reference"
            }]);
        }
        let bytes = serde_json::to_vec(&value).unwrap();
        std::fs::write(path, &bytes).unwrap();
        let manifest_path = fixture.dir.path().join("context/context.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        manifest[field]["sha256"] = evidence::digest(&bytes).into();
        std::fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        fixture
            .command_oscal()
            .assert()
            .code(2)
            .stderr(predicate::str::contains("ContextInvalid"));
        for output in [
            "report.json",
            "verification.json",
            "assessment-results.json",
        ] {
            assert!(
                !fixture.dir.path().join(output).exists(),
                "{case}: {output}"
            );
        }
    }
}

#[test]
fn existing_oscal_target_is_preserved_without_publishing_any_other_output() {
    let fixture = evidence::Fixture::monitor();
    std::fs::write(
        fixture.dir.path().join("assessment-results.json"),
        b"operator document",
    )
    .unwrap();
    fixture
        .command_oscal()
        .assert()
        .code(2)
        .stderr(predicate::str::contains("OutputConflict"));
    assert_eq!(
        std::fs::read(fixture.dir.path().join("assessment-results.json")).unwrap(),
        b"operator document"
    );
    assert!(!fixture.dir.path().join("report.json").exists());
    assert!(!fixture.dir.path().join("verification.json").exists());
}

#[test]
fn empty_window_omits_observations_instead_of_inventing_findings() {
    let mut fixture = evidence::Fixture::monitor();
    fixture.profile["window"] =
        json!({"since":"2026-09-16T00:00:00.000Z","until":"2026-09-17T00:00:00.000Z"});
    fixture.save_profile();
    fixture.command_oscal().assert().success();
    let document = fixture.json("assessment-results.json");
    let result = &document["assessment-results"]["results"][0];
    for name in ["observations", "findings", "risks"] {
        assert!(result.get(name).is_none());
    }
    assert_eq!(fixture.json("report.json")["totals"]["receipts"], 0);
}

#[test]
fn output_reference_encoding_is_explicitly_bounded() {
    let fixture = evidence::Fixture::monitor();
    fixture
        .command_with(&[
            "--format",
            "oscal",
            "--experimental-oscal",
            "--assessment-context",
            "context/context.json",
            "--native-report-out",
            "report with spaces.json",
            "--out",
            "assessment-results.json",
            "--verification-out",
            "verification.json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("URI-unreserved"));
    for name in [
        "report with spaces.json",
        "verification.json",
        "assessment-results.json",
    ] {
        assert!(!fixture.dir.path().join(name).exists());
    }
}

#[test]
fn independent_stream_observations_use_interval_not_global_counts() {
    use hushspec::receipt::{AuditConfig, AuditContext, EnforcementMode, evaluate_audited};
    use hushspec::signing::{SignOptions, parse_private_key_pem, sign_receipt};
    let mut fixture = evidence::Fixture::monitor();
    let resolution = hushspec::resolve_path_with_options(
        &fixture.dir.path().join("policy.yaml"),
        &Default::default(),
    )
    .unwrap();
    let action =
        serde_json::from_value(json!({"type":"tool_call","target":"blocked-tool"})).unwrap();
    let clock = "2026-09-15T12:00:00Z".parse().unwrap();
    let receipt = evaluate_audited(
        &resolution,
        &action,
        &AuditConfig {
            record_duration: false,
            ..Default::default()
        },
        &AuditContext {
            clock: Some(clock),
            receipt_id: Some("01994b7e-2c1a-7c3e-8f4a-0123456789ac".into()),
            enforcement_mode: EnforcementMode::Enforce,
            ..Default::default()
        },
    );
    assert_eq!(receipt.decision, hushspec::Decision::Deny);
    let key = parse_private_key_pem(
        &std::fs::read_to_string(
            fixture
                .root
                .join("fixtures/signing/keys/test-signing.key.pem"),
        )
        .unwrap(),
    )
    .unwrap();
    let signed = sign_receipt(
        &receipt,
        &key,
        &SignOptions {
            signed_at: Some(clock),
            ..Default::default()
        },
    )
    .unwrap();
    let bytes = serde_json::to_vec(&signed).unwrap();
    std::fs::write(fixture.dir.path().join("other.jsonl"), &bytes).unwrap();
    let mut second = fixture.profile["streams"][0].clone();
    second["id"] = json!("agent-2");
    second["files"] = json!([{"path":"other.jsonl","sha256":evidence::digest(&bytes)}]);
    fixture.profile["streams"]
        .as_array_mut()
        .unwrap()
        .push(second);
    fixture.save_profile();
    fixture
        .command_oscal()
        .arg("other.jsonl")
        .assert()
        .success();
    let doc = fixture.json("assessment-results.json");
    let observations = doc["assessment-results"]["results"][0]["observations"]
        .as_array()
        .unwrap();
    assert_eq!(observations.len(), 2);
    let first = observations[0]["description"].as_str().unwrap();
    let second = observations[1]["description"].as_str().unwrap();
    assert!(first.contains("warn=1, deny=0") && first.contains("blocked=0, would_block=1"));
    assert!(second.contains("warn=0, deny=1") && second.contains("blocked=1, would_block=0"));
    assert_eq!(fixture.json("report.json")["totals"]["receipts"], 2);
}
