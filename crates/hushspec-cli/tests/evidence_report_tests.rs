#[path = "support/evidence.rs"]
mod evidence;
use predicates::prelude::*;

#[test]
fn strict_report_binds_authenticated_inputs_without_claiming_completeness() {
    let fixture = evidence::Fixture::new();
    fixture.command().assert().success();
    let verification = fixture.json("verification.json");
    assert_eq!(
        verification["streams"][0]["authenticity"]["status"],
        "verified"
    );
    assert_eq!(
        verification["streams"][0]["completeness"]["status"],
        "not-established"
    );
    let bytes = std::fs::read(fixture.dir.path().join("report.json")).unwrap();
    assert_eq!(verification["report_sha256"], evidence::digest(&bytes));
    assert_eq!(fixture.json("report.json")["totals"]["receipts"], 1);
}

#[test]
fn strict_refusals_publish_nothing() {
    for (extra, code, exit) in [
        (vec!["--lenient"], "Configuration", 2),
        (vec!["--unverified"], "Configuration", 2),
        (vec!["--by", "decision"], "Configuration", 2),
        (vec!["--since", "2026-09-14T00:00:00Z"], "Configuration", 2),
        (vec!["--max-skew=-1"], "Configuration", 2),
        (vec!["--max-evidence-line-bytes", "1"], "LimitExceeded", 2),
        (
            vec![
                "--max-evidence-file-bytes",
                "1",
                "--max-evidence-line-bytes",
                "1",
            ],
            "LimitExceeded",
            2,
        ),
        (vec!["--max-evidence-total-bytes", "1"], "Configuration", 2),
    ] {
        let fixture = evidence::Fixture::new();
        fixture
            .command()
            .args(extra)
            .assert()
            .code(exit)
            .stderr(predicate::str::contains(code));
        assert!(!fixture.dir.path().join("report.json").exists());
        assert!(!fixture.dir.path().join("verification.json").exists());
    }
}

#[test]
fn outputs_must_be_new_distinct_and_in_one_existing_directory() {
    for (report, sidecar) in [
        ("evidence.jsonl", "verification.json"),
        ("report.json", "report.json"),
        ("missing/report.json", "verification.json"),
        ("report.json", "child/verification.json"),
        ("profile.json", "verification.json"),
    ] {
        let fixture = evidence::Fixture::new();
        std::fs::create_dir(fixture.dir.path().join("child")).unwrap();
        let input = std::fs::read(fixture.dir.path().join("evidence.jsonl")).unwrap();
        let profile = std::fs::read(fixture.dir.path().join("profile.json")).unwrap();
        fixture
            .command_with(&[
                "--format",
                "json",
                "--out",
                report,
                "--verification-out",
                sidecar,
            ])
            .assert()
            .code(2)
            .stderr(predicate::str::contains("OutputConflict"));
        assert_eq!(
            std::fs::read(fixture.dir.path().join("evidence.jsonl")).unwrap(),
            input
        );
        assert_eq!(
            std::fs::read(fixture.dir.path().join("profile.json")).unwrap(),
            profile
        );
        assert!(!fixture.dir.path().join("report.json").exists());
        assert!(!fixture.dir.path().join("verification.json").exists());
        assert!(!fixture.dir.path().join("child/verification.json").exists());
    }
}

#[cfg(unix)]
#[test]
fn output_symlink_and_hardlink_aliases_are_refused() {
    for hardlink in [false, true] {
        let fixture = evidence::Fixture::new();
        let input = fixture.dir.path().join("evidence.jsonl");
        let output = fixture.dir.path().join("report.json");
        if hardlink {
            std::fs::hard_link(&input, &output).unwrap();
        } else {
            std::os::unix::fs::symlink(&input, &output).unwrap();
        }
        let bytes = std::fs::read(&input).unwrap();
        fixture
            .command()
            .assert()
            .code(2)
            .stderr(predicate::str::contains("OutputConflict"));
        assert_eq!(std::fs::read(input).unwrap(), bytes);
        assert!(!fixture.dir.path().join("verification.json").exists());
    }
}

#[test]
fn authentication_and_required_inventory_cannot_be_skipped() {
    for (case, code) in [
        ("unauthorized", "UnauthorizedKey"),
        ("tampered-outside-window", "SignatureInvalid"),
        ("required-inventory", "BoundaryMismatch"),
        ("digest", "InputDigestMismatch"),
    ] {
        let mut fixture = evidence::Fixture::new();
        match case {
            "unauthorized" => {
                fixture.profile["streams"][0]["allowed_signer_key_ids"][0] =
                    format!("sha256:{}", "f".repeat(64)).into()
            }
            "required-inventory" => {
                fixture.profile["requirements"]["boundary_inventory"] = true.into()
            }
            "digest" => {
                fixture.profile["streams"][0]["files"][0]["sha256"] =
                    format!("sha256:{}", "f".repeat(64)).into()
            }
            _ => {
                let path = fixture.dir.path().join("evidence.jsonl");
                let mut value: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                value["receipt"]["timestamp"] = "2026-09-14T12:00:00.000Z".into();
                let bytes = format!("{value}\n").into_bytes();
                std::fs::write(&path, &bytes).unwrap();
                fixture.profile["streams"][0]["files"][0]["sha256"] =
                    evidence::digest(&bytes).into();
            }
        }
        fixture.save_profile();
        fixture
            .command()
            .assert()
            .code(1)
            .stderr(predicate::str::contains(code));
        assert!(!fixture.dir.path().join("report.json").exists());
        assert!(!fixture.dir.path().join("verification.json").exists());
    }
}

#[test]
fn empty_window_keeps_full_input_authentication_but_no_satisfaction_claim() {
    let mut fixture = evidence::Fixture::new();
    fixture.profile["window"]["since"] = "2026-09-16T00:00:00.000Z".into();
    fixture.profile["window"]["until"] = "2026-09-17T00:00:00.000Z".into();
    fixture.save_profile();
    fixture.command().assert().success();
    assert_eq!(fixture.json("report.json")["totals"]["receipts"], 0);
    let result = fixture.json("verification.json");
    assert_eq!(result["sources"][0]["records"], 1);
    assert_eq!(result["streams"][0]["signatures_verified"], 1);
    assert_eq!(result["streams"][0]["intervals"][0]["receipts"], 0);
    assert!(
        result["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str().unwrap().contains("not control satisfaction"))
    );
}

#[test]
fn strict_mode_requires_all_of_its_inputs_and_outputs() {
    for omitted in [
        "--evidence-profile",
        "--keyring",
        "--out",
        "--verification-out",
    ] {
        let fixture = evidence::Fixture::new();
        let mut cmd = assert_cmd::Command::cargo_bin("h2h").unwrap();
        cmd.current_dir(fixture.dir.path()).args([
            "report",
            "evidence.jsonl",
            "--format",
            "json",
            "--now",
            "2026-09-15T12:00:00Z",
        ]);
        for (flag, value) in [
            (
                "--evidence-profile",
                fixture.dir.path().join("profile.json"),
            ),
            (
                "--keyring",
                fixture.root.join("fixtures/signing/keys/keyring.json"),
            ),
            ("--out", fixture.dir.path().join("report.json")),
            (
                "--verification-out",
                fixture.dir.path().join("verification.json"),
            ),
        ] {
            if flag != omitted {
                cmd.arg(flag).arg(value);
            }
        }
        cmd.assert()
            .code(2)
            .stderr(predicate::str::contains("Configuration"));
        assert!(!fixture.dir.path().join("report.json").exists());
        assert!(!fixture.dir.path().join("verification.json").exists());
    }
}

#[test]
fn a_single_pem_is_bound_by_its_exact_bytes() {
    let fixture = evidence::Fixture::new();
    let key = fixture
        .root
        .join("fixtures/signing/keys/test-signing.pub.pem");
    assert_cmd::Command::cargo_bin("h2h")
        .unwrap()
        .current_dir(fixture.dir.path())
        .args([
            "report",
            "evidence.jsonl",
            "--format",
            "json",
            "--evidence-profile",
            "profile.json",
            "--out",
            "report.json",
            "--verification-out",
            "verification.json",
            "--now",
            "2026-09-15T12:00:00Z",
            "--key",
        ])
        .arg(&key)
        .assert()
        .success();
    assert_eq!(
        fixture.json("verification.json")["keyring_sha256"],
        evidence::digest(&std::fs::read(key).unwrap())
    );
}

#[test]
fn total_budget_includes_profile_and_trust_input_not_only_evidence() {
    let fixture = evidence::Fixture::new();
    fixture
        .command()
        .args([
            "--max-evidence-file-bytes",
            "2048",
            "--max-evidence-total-bytes",
            "2048",
            "--max-evidence-line-bytes",
            "2048",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("LimitExceeded"));
    assert!(!fixture.dir.path().join("report.json").exists());
    assert!(!fixture.dir.path().join("verification.json").exists());
}
