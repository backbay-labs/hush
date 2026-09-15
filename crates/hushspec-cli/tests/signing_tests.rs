//! Integration coverage for `h2h audit`, `h2h sign` and `h2h verify`.
//!
//! The CLI depends on `hushspec` with the `signing` feature enabled, so the
//! signing commands are always present -- no extra cargo features are needed
//! to run these tests.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn h2h() -> Command {
    let mut cmd = Command::cargo_bin("h2h").unwrap();
    cmd.current_dir(workspace_root());
    cmd
}

const GOVERNED_POLICY: &str = r#"hushspec: "0.1.0"
name: governed
metadata:
  author: "security@example.com"
  approved_by: "ciso@example.com"
  approval_date: "2025-01-15"
  classification: internal
  lifecycle_state: deployed
  policy_version: 3
  change_ticket: "SEC-1234"
rules:
  egress:
    allow:
      - "api.github.com"
    block: []
    default: block
"#;

fn write_policy(dir: &Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, content).unwrap();
    path
}

/// Generate a keypair in `dir` and return (private, public) paths.
fn keygen(dir: &Path) -> (PathBuf, PathBuf) {
    h2h()
        .arg("keygen")
        .arg("--output-dir")
        .arg(dir.to_str().unwrap())
        .assert()
        .success();

    (dir.join("h2h.key"), dir.join("h2h.pub"))
}

#[test]
fn audit_reports_governance_metadata() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(tmp.path(), "governed.yaml", GOVERNED_POLICY);

    h2h()
        .arg("audit")
        .arg(policy.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("security@example.com"))
        .stdout(predicate::str::contains("ciso@example.com"));
}

#[test]
fn audit_json_output_carries_metadata_and_checks() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(tmp.path(), "governed.yaml", GOVERNED_POLICY);

    let output = h2h()
        .arg("audit")
        .arg("--format")
        .arg("json")
        .arg(policy.to_str().unwrap())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(parsed["author"], "security@example.com");
    assert_eq!(parsed["approved_by"], "ciso@example.com");
    assert_eq!(parsed["policy_version"], 3);
    assert!(
        parsed["checks"].as_array().is_some_and(|c| !c.is_empty()),
        "audit should report at least one check"
    );
}

#[test]
fn audit_missing_file_exits_2() {
    h2h()
        .arg("audit")
        .arg("no-such-policy.yaml")
        .assert()
        .code(2);
}

#[test]
fn audit_unparseable_policy_exits_1() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(tmp.path(), "broken.yaml", "hushspec: \"0.1.0\"\nbogus: 1\n");

    h2h()
        .arg("audit")
        .arg(policy.to_str().unwrap())
        .assert()
        .code(1);
}

#[test]
fn sign_then_verify_round_trips() {
    let tmp = TempDir::new().unwrap();
    let (private_key, public_key) = keygen(tmp.path());
    let policy = write_policy(tmp.path(), "policy.yaml", GOVERNED_POLICY);

    h2h()
        .arg("sign")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(private_key.to_str().unwrap())
        .arg("--signer")
        .arg("security@example.com")
        .assert()
        .success()
        .stdout(predicate::str::contains("Signed"));

    let sig_path = tmp.path().join("policy.yaml.sig");
    assert!(sig_path.exists(), "detached signature should be written");

    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature is valid"))
        .stdout(predicate::str::contains("security@example.com"));
}

#[test]
fn sign_honors_explicit_output_path_and_key_id() {
    let tmp = TempDir::new().unwrap();
    let (private_key, public_key) = keygen(tmp.path());
    let policy = write_policy(tmp.path(), "policy.yaml", GOVERNED_POLICY);
    let sig_path = tmp.path().join("custom.sig");

    h2h()
        .arg("sign")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(private_key.to_str().unwrap())
        .arg("--key-id")
        .arg("ops-rotation-2025")
        .arg("--output")
        .arg(sig_path.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("ops-rotation-2025"));

    assert!(sig_path.exists());
    assert!(
        !tmp.path().join("policy.yaml.sig").exists(),
        "--output should replace the default signature path"
    );

    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--sig")
        .arg(sig_path.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("ops-rotation-2025"));
}

#[test]
fn verify_fails_when_the_policy_is_modified_after_signing() {
    let tmp = TempDir::new().unwrap();
    let (private_key, public_key) = keygen(tmp.path());
    let policy = write_policy(tmp.path(), "policy.yaml", GOVERNED_POLICY);

    h2h()
        .arg("sign")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(private_key.to_str().unwrap())
        .assert()
        .success();

    // Tamper: relax the egress default after the signature was produced.
    fs::write(
        &policy,
        GOVERNED_POLICY.replace("default: block", "default: allow"),
    )
    .unwrap();

    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("verification failed"));
}

#[test]
fn verify_fails_against_a_different_keypair() {
    let tmp = TempDir::new().unwrap();
    let signer_dir = tmp.path().join("signer");
    let other_dir = tmp.path().join("other");
    fs::create_dir_all(&signer_dir).unwrap();
    fs::create_dir_all(&other_dir).unwrap();

    let (private_key, _) = keygen(&signer_dir);
    let (_, other_public) = keygen(&other_dir);
    let policy = write_policy(tmp.path(), "policy.yaml", GOVERNED_POLICY);

    h2h()
        .arg("sign")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(private_key.to_str().unwrap())
        .assert()
        .success();

    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(other_public.to_str().unwrap())
        .assert()
        .code(1);
}

#[test]
fn verify_without_a_signature_file_exits_1() {
    let tmp = TempDir::new().unwrap();
    let (_, public_key) = keygen(tmp.path());
    let policy = write_policy(tmp.path(), "policy.yaml", GOVERNED_POLICY);

    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("Failed to load signature"));
}

#[test]
fn sign_with_a_bogus_key_exits_1() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(tmp.path(), "policy.yaml", GOVERNED_POLICY);
    let bad_key = write_policy(tmp.path(), "bad.key", "not a pem file\n");

    h2h()
        .arg("sign")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(bad_key.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("Invalid private key"));
}

const DRAFT_POLICY: &str = r#"hushspec: "0.1.0"
name: draft
metadata:
  author: "security@example.com"
  lifecycle_state: draft
rules:
  egress:
    allow:
      - "api.github.com"
    block: []
    default: block
"#;

const SOD_VIOLATION_POLICY: &str = r#"hushspec: "0.2.0"
name: self-approved
metadata:
  author: "security@example.com"
  approved_by: "Security@Example.com"
  approval_date: "2025-01-15"
  classification: internal
  lifecycle_state: deployed
  policy_version: 2
  expiry_date: "2099-01-01"
rules:
  egress:
    allow:
      - "api.github.com"
    block: []
    default: block
"#;

#[test]
fn audit_reports_a_separation_of_duties_finding() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(tmp.path(), "sod.yaml", SOD_VIOLATION_POLICY);

    h2h()
        .arg("audit")
        .arg(policy.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("GOV_SOD_VIOLATION"))
        .stdout(predicate::str::contains("metadata.approved_by"));
}

#[test]
fn audit_findings_carry_code_severity_and_path_in_json() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(tmp.path(), "sod.yaml", SOD_VIOLATION_POLICY);

    let output = h2h()
        .arg("audit")
        .arg("--format")
        .arg("json")
        .arg(policy.to_str().unwrap())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let finding = report["findings"]
        .as_array()
        .and_then(|findings| {
            findings
                .iter()
                .find(|f| f["code"] == "GOV_SOD_VIOLATION")
                .cloned()
        })
        .unwrap_or_else(|| panic!("expected a SoD finding in {report:#}"));
    assert_eq!(finding["severity"], "warning");
    assert_eq!(finding["path"], "metadata.approved_by");
}

#[test]
fn audit_strict_fails_on_a_separation_of_duties_violation() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(tmp.path(), "sod.yaml", SOD_VIOLATION_POLICY);

    // Advisory by default...
    h2h()
        .arg("audit")
        .arg(policy.to_str().unwrap())
        .assert()
        .success();

    // ...fatal under --strict.
    h2h()
        .arg("audit")
        .arg("--strict")
        .arg(policy.to_str().unwrap())
        .assert()
        .code(1);
}

#[test]
fn audit_strict_fails_on_an_overdue_review() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(
        tmp.path(),
        "overdue.yaml",
        &GOVERNED_POLICY.replace(
            "  change_ticket: \"SEC-1234\"\n",
            "  change_ticket: \"SEC-1234\"\n  next_review_date: \"2020-01-01\"\n",
        ),
    );

    h2h()
        .arg("audit")
        .arg(policy.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("GOV_REVIEW_OVERDUE"));

    h2h()
        .arg("audit")
        .arg("--strict")
        .arg(policy.to_str().unwrap())
        .assert()
        .code(1);
}

#[test]
fn audit_fails_without_strict_on_an_error_severity_finding() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(
        tmp.path(),
        "self-supersedes.yaml",
        &GOVERNED_POLICY.replace(
            "  policy_version: 3\n",
            "  policy_version: 3\n  supersedes: \"3\"\n",
        ),
    );

    h2h()
        .arg("audit")
        .arg(policy.to_str().unwrap())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("GOV_SELF_SUPERSEDES"));
}

#[test]
fn audit_reports_no_findings_for_a_clean_policy() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(tmp.path(), "clean.yaml", GOVERNED_POLICY);

    h2h()
        .arg("audit")
        .arg(policy.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Governance findings:"))
        .stdout(predicate::str::contains("none"));
}

#[test]
fn sign_refuses_a_policy_that_is_not_approved() {
    let tmp = TempDir::new().unwrap();
    let (private_key, _) = keygen(tmp.path());
    let policy = write_policy(tmp.path(), "draft.yaml", DRAFT_POLICY);

    h2h()
        .arg("sign")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(private_key.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("lifecycle_state is 'draft'"));

    assert!(
        !tmp.path().join("draft.yaml.sig").exists(),
        "a refused signature must not be written"
    );
}

#[test]
fn sign_refuses_a_policy_with_no_lifecycle_state() {
    let tmp = TempDir::new().unwrap();
    let (private_key, _) = keygen(tmp.path());
    let policy = write_policy(
        tmp.path(),
        "bare.yaml",
        "hushspec: \"0.1.0\"\nname: bare\nrules:\n  egress:\n    default: block\n",
    );

    h2h()
        .arg("sign")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(private_key.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("not set"));
}

#[test]
fn sign_allows_an_unapproved_policy_with_the_override() {
    let tmp = TempDir::new().unwrap();
    let (private_key, public_key) = keygen(tmp.path());
    let policy = write_policy(tmp.path(), "draft.yaml", DRAFT_POLICY);

    h2h()
        .arg("sign")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(private_key.to_str().unwrap())
        .arg("--allow-unapproved")
        .assert()
        .success()
        .stdout(predicate::str::contains("Signed"));

    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .assert()
        .success();
}

#[test]
fn sign_signs_an_approved_policy() {
    let tmp = TempDir::new().unwrap();
    let (private_key, _) = keygen(tmp.path());
    let policy = write_policy(
        tmp.path(),
        "approved.yaml",
        &GOVERNED_POLICY.replace("lifecycle_state: deployed", "lifecycle_state: approved"),
    );

    h2h()
        .arg("sign")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(private_key.to_str().unwrap())
        .assert()
        .success();
}

#[test]
fn sign_refuses_an_unparseable_policy() {
    let tmp = TempDir::new().unwrap();
    let (private_key, _) = keygen(tmp.path());
    let policy = write_policy(tmp.path(), "broken.yaml", "hushspec: \"0.1.0\"\nbogus: 1\n");

    h2h()
        .arg("sign")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(private_key.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("unparseable"));
}
