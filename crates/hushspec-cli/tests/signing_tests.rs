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

    (dir.join("h2h.key.pem"), dir.join("h2h.pub.pem"))
}

fn envelope(path: &Path) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
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

// --------------------------------------------------------------- keygen 0.2

#[test]
fn keygen_writes_pem_key_files_and_prints_the_key_id() {
    let tmp = TempDir::new().unwrap();
    let output = h2h()
        .arg("keygen")
        .arg("--output-dir")
        .arg(tmp.path().to_str().unwrap())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let printed = String::from_utf8(output).unwrap();

    let private = fs::read_to_string(tmp.path().join("h2h.key.pem")).unwrap();
    let public = fs::read_to_string(tmp.path().join("h2h.pub.pem")).unwrap();
    assert!(
        private.starts_with("-----BEGIN PRIVATE KEY-----"),
        "{private}"
    );
    assert!(public.starts_with("-----BEGIN PUBLIC KEY-----"), "{public}");

    // The printed id is the SPKI digest, not an opaque label.
    let key_id = printed
        .lines()
        .find_map(|line| line.trim().strip_prefix("Key ID: "))
        .expect("keygen prints the key id");
    assert!(key_id.starts_with("sha256:"), "{key_id}");
    assert_eq!(key_id.len(), "sha256:".len() + 64);
}

#[test]
fn keygen_honors_name_and_refuses_to_clobber_without_force() {
    let tmp = TempDir::new().unwrap();
    h2h()
        .arg("keygen")
        .arg("--output-dir")
        .arg(tmp.path().to_str().unwrap())
        .arg("--name")
        .arg("release")
        .assert()
        .success();
    assert!(tmp.path().join("release.key.pem").exists());
    assert!(tmp.path().join("release.pub.pem").exists());

    h2h()
        .arg("keygen")
        .arg("--output-dir")
        .arg(tmp.path().to_str().unwrap())
        .arg("--name")
        .arg("release")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));

    h2h()
        .arg("keygen")
        .arg("--output-dir")
        .arg(tmp.path().to_str().unwrap())
        .arg("--name")
        .arg("release")
        .arg("--force")
        .assert()
        .success();
}

#[test]
fn keygen_convert_upgrades_a_zero_one_key_file() {
    let tmp = TempDir::new().unwrap();
    // A HushSpec 0.1 private key: the bespoke wrapper around 32 raw bytes.
    // These are the published test key's bytes, so the id is known.
    let legacy = write_policy(
        tmp.path(),
        "old.key",
        "-----BEGIN HUSHSPEC PRIVATE KEY-----\nZM91/PoRVm1ok4jlAIC5X3lCmOIJOxDCcnd1lJqQ+WQ=\n-----END HUSHSPEC PRIVATE KEY-----\n",
    );

    h2h()
        .arg("keygen")
        .arg("--output-dir")
        .arg(tmp.path().to_str().unwrap())
        .arg("--name")
        .arg("converted")
        .arg("--convert")
        .arg(legacy.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Converted"))
        .stdout(predicate::str::contains(
            "sha256:1187bb3ca0fd60b25cb90390812fb3a90823466b499e9c29effcc9f3c4ce6142",
        ));

    let converted = fs::read_to_string(tmp.path().join("converted.key.pem")).unwrap();
    assert!(converted.starts_with("-----BEGIN PRIVATE KEY-----"));
}

#[test]
fn keygen_convert_rejects_a_file_that_is_not_a_zero_one_key() {
    let tmp = TempDir::new().unwrap();
    let junk = write_policy(tmp.path(), "junk.key", "not a key at all\n");

    h2h()
        .arg("keygen")
        .arg("--output-dir")
        .arg(tmp.path().to_str().unwrap())
        .arg("--convert")
        .arg(junk.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("not a HushSpec 0.1 private key"));
}

// ----------------------------------------------------------------- sign 0.2

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
        .stdout(predicate::str::contains("Signed"))
        .stdout(predicate::str::contains("Content hash: sha256:"));

    let sig_path = tmp.path().join("policy.yaml.sig");
    assert!(sig_path.exists(), "detached signature should be written");

    let signed = envelope(&sig_path);
    assert_eq!(signed["format_version"], "0.2");
    assert_eq!(signed["algorithm"], "ed25519");
    assert_eq!(signed["policy_name"], "governed");
    assert_eq!(signed["policy_version"], 3);
    assert_eq!(signed["signer"], "security@example.com");
    assert!(signed["expires_at"].is_null(), "no --expires-in was passed");

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
fn the_signature_covers_meaning_not_bytes() {
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

    // `h2h hash` and the envelope agree on what identifies the policy.
    let digest = String::from_utf8(
        h2h()
            .arg("hash")
            .arg(policy.to_str().unwrap())
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    let signed = envelope(&tmp.path().join("policy.yaml.sig"));
    assert_eq!(signed["content_hash"], digest.trim());

    // Reformatting the file does not invalidate the signature.
    fs::write(
        &policy,
        "# reformatted\nrules:\n  egress:\n    default: block\n    block: []\n    allow: [\"api.github.com\"]\nmetadata:\n  policy_version: 3\n  change_ticket: \"SEC-1234\"\n  lifecycle_state: deployed\n  classification: internal\n  approval_date: \"2025-01-15\"\n  approved_by: \"ciso@example.com\"\n  author: \"security@example.com\"\nname: governed\nhushspec: \"0.1.0\"\n",
    )
    .unwrap();

    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .assert()
        .success();
}

#[test]
fn sign_resolves_the_extends_chain_before_hashing() {
    let tmp = TempDir::new().unwrap();
    let (private_key, public_key) = keygen(tmp.path());
    let policy = write_policy(
        tmp.path(),
        "child.yaml",
        "hushspec: \"0.2.0\"\nname: child\nextends: builtin:default\nmetadata:\n  lifecycle_state: approved\nrules:\n  egress:\n    default: block\n",
    );

    h2h()
        .arg("sign")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(private_key.to_str().unwrap())
        .assert()
        .success();

    let signed = envelope(&tmp.path().join("child.yaml.sig"));
    let digest = String::from_utf8(
        h2h()
            .arg("hash")
            .arg(policy.to_str().unwrap())
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert_eq!(
        signed["content_hash"],
        digest.trim(),
        "the envelope must cover the resolved document"
    );

    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .assert()
        .success();
}

#[test]
fn sign_refuses_a_policy_whose_extends_chain_does_not_resolve() {
    let tmp = TempDir::new().unwrap();
    let (private_key, _) = keygen(tmp.path());
    let policy = write_policy(
        tmp.path(),
        "orphan.yaml",
        "hushspec: \"0.2.0\"\nname: orphan\nextends: builtin:no-such-base\nmetadata:\n  lifecycle_state: approved\nrules:\n  egress:\n    default: block\n",
    );

    h2h()
        .arg("sign")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(private_key.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("does not resolve"));

    assert!(!tmp.path().join("orphan.yaml.sig").exists());
}

#[test]
fn sign_honors_expires_in_policy_version_signer_and_out() {
    let tmp = TempDir::new().unwrap();
    let (private_key, public_key) = keygen(tmp.path());
    let policy = write_policy(tmp.path(), "policy.yaml", GOVERNED_POLICY);
    let sig_path = tmp.path().join("custom.sig");

    h2h()
        .arg("sign")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(private_key.to_str().unwrap())
        .arg("--expires-in")
        .arg("30d")
        .arg("--policy-version")
        .arg("9")
        .arg("--signer")
        .arg("release-bot@example.com")
        .arg("--out")
        .arg(sig_path.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Expires at:"))
        .stdout(predicate::str::contains("Policy version: 9"));

    assert!(sig_path.exists());
    assert!(
        !tmp.path().join("policy.yaml.sig").exists(),
        "--out should replace the default signature path"
    );

    let signed = envelope(&sig_path);
    assert_eq!(signed["policy_version"], 9);
    assert_eq!(signed["signer"], "release-bot@example.com");
    let expires_at = signed["expires_at"].as_str().expect("an expiry");
    assert!(
        expires_at.ends_with('Z') && expires_at.len() == 24,
        "{expires_at}"
    );

    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--sig")
        .arg(sig_path.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .assert()
        .success();
}

#[test]
fn sign_rejects_a_malformed_expires_in() {
    let tmp = TempDir::new().unwrap();
    let (private_key, _) = keygen(tmp.path());
    let policy = write_policy(tmp.path(), "policy.yaml", GOVERNED_POLICY);

    h2h()
        .arg("sign")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(private_key.to_str().unwrap())
        .arg("--expires-in")
        .arg("a fortnight")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("is not a duration"));
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

#[test]
fn sign_missing_policy_exits_2() {
    let tmp = TempDir::new().unwrap();
    let (private_key, _) = keygen(tmp.path());

    h2h()
        .arg("sign")
        .arg("no-such-policy.yaml")
        .arg("--key")
        .arg(private_key.to_str().unwrap())
        .assert()
        .code(2);
}

// --------------------------------------------------------------- verify 0.2

/// Every failing path prints the signing spec 6.4 reason code, because that
/// string is the contract a receipt and a CI job both consume.
#[test]
fn verify_prints_the_reason_code_for_each_failure() {
    let tmp = TempDir::new().unwrap();
    let (private_key, public_key) = keygen(tmp.path());
    let policy = write_policy(tmp.path(), "policy.yaml", GOVERNED_POLICY);

    h2h()
        .arg("sign")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(private_key.to_str().unwrap())
        .arg("--expires-in")
        .arg("1d")
        .assert()
        .success();
    let sig_path = tmp.path().join("policy.yaml.sig");
    let signed = envelope(&sig_path);

    // content_hash_mismatch: the policy changed after signing.
    let tampered = write_policy(
        tmp.path(),
        "tampered.yaml",
        &GOVERNED_POLICY.replace("default: block", "default: allow"),
    );
    h2h()
        .arg("verify")
        .arg(tampered.to_str().unwrap())
        .arg("--sig")
        .arg(sig_path.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("content_hash_mismatch"));

    // unknown_key_id: a different keypair.
    let other = tmp.path().join("other");
    fs::create_dir_all(&other).unwrap();
    let (_, other_public) = keygen(&other);
    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(other_public.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("unknown_key_id"));

    // signature_mismatch: an edited claim.
    let mut edited = signed.clone();
    edited["signer"] = serde_json::Value::from("attacker@example.com");
    let edited_path = tmp.path().join("edited.sig");
    fs::write(&edited_path, serde_json::to_string_pretty(&edited).unwrap()).unwrap();
    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--sig")
        .arg(edited_path.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("signature_mismatch"));

    // expired / signed_at_in_future: the same envelope, two clocks.
    let expires_at = signed["expires_at"].as_str().unwrap();
    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .arg("--now")
        .arg(expires_at)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("expired"));

    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .arg("--now")
        .arg("2020-01-01T00:00:00Z")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("signed_at_in_future"));

    // policy_version_rollback: the envelope is at version 3.
    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .arg("--last-seen-version")
        .arg("4")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("policy_version_rollback"));

    // ...and passes when the envelope is the newer one.
    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .arg("--last-seen-version")
        .arg("3")
        .assert()
        .success();
}

#[test]
fn verify_max_skew_tightens_the_future_check() {
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
    let signed_at = envelope(&tmp.path().join("policy.yaml.sig"))["signed_at"]
        .as_str()
        .unwrap()
        .to_string();
    let earlier =
        chrono::DateTime::parse_from_rfc3339(&signed_at).unwrap() - chrono::Duration::seconds(60);
    let now = earlier.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    // Inside the 300s default...
    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .arg("--now")
        .arg(&now)
        .assert()
        .success();

    // ...outside a 10s allowance.
    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .arg("--now")
        .arg(&now)
        .arg("--max-skew")
        .arg("10")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("signed_at_in_future"));
}

#[test]
fn verify_json_reports_the_outcome_machine_readably() {
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

    let stdout = h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(report["valid"], true);
    assert_eq!(report["policy_name"], "governed");
    assert!(
        report["content_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );

    // The failure report is JSON on stderr, with the reason code.
    fs::write(
        &policy,
        GOVERNED_POLICY.replace("default: block", "default: allow"),
    )
    .unwrap();
    let stderr = h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .arg("--format")
        .arg("json")
        .assert()
        .code(1)
        .get_output()
        .stderr
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&stderr).unwrap();
    assert_eq!(report["valid"], false);
    assert_eq!(report["reason"], "content_hash_mismatch");
}

#[test]
fn verify_accepts_a_keyring_and_honors_revocation() {
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

    let key_id = envelope(&tmp.path().join("policy.yaml.sig"))["key_id"]
        .as_str()
        .unwrap()
        .to_string();
    let public_pem = fs::read_to_string(&public_key).unwrap();

    let keyring = tmp.path().join("keyring.json");
    let make = |revoked: bool| {
        serde_json::json!({
            "keyring_version": "0.2",
            "keys": [{
                "key_id": key_id,
                "algorithm": "ed25519",
                "public_key": public_pem,
                "name": "test",
                "revoked": revoked,
            }],
        })
    };

    fs::write(
        &keyring,
        serde_json::to_string_pretty(&make(false)).unwrap(),
    )
    .unwrap();
    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--keyring")
        .arg(keyring.to_str().unwrap())
        .assert()
        .success();

    fs::write(&keyring, serde_json::to_string_pretty(&make(true)).unwrap()).unwrap();
    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--keyring")
        .arg(keyring.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("key_revoked"));
}

#[test]
fn verify_rejects_a_keyring_whose_key_id_is_not_its_own_digest() {
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

    let keyring = tmp.path().join("keyring.json");
    fs::write(
        &keyring,
        serde_json::to_string_pretty(&serde_json::json!({
            "keyring_version": "0.2",
            "keys": [{
                "key_id": format!("sha256:{}", "0".repeat(64)),
                "algorithm": "ed25519",
                "public_key": fs::read_to_string(&public_key).unwrap(),
            }],
        }))
        .unwrap(),
    )
    .unwrap();

    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--keyring")
        .arg(keyring.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("not the digest"));
}

#[test]
fn verify_finds_the_zero_one_sig_layout_and_explains_a_zero_one_envelope() {
    let tmp = TempDir::new().unwrap();
    let (private_key, public_key) = keygen(tmp.path());
    let policy = write_policy(tmp.path(), "policy.yaml", GOVERNED_POLICY);

    // `policy.sig` (the 0.1 layout) is found when `policy.yaml.sig` is absent.
    h2h()
        .arg("sign")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(private_key.to_str().unwrap())
        .arg("--out")
        .arg(tmp.path().join("policy.sig").to_str().unwrap())
        .assert()
        .success();
    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .assert()
        .success();

    // A genuine 0.1 envelope is named, not dismissed as corrupt.
    fs::write(
        tmp.path().join("policy.sig"),
        r#"{
          "format_version": "0.1.0",
          "algorithm": "ed25519",
          "content_hash": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
          "signature": "Zm9vYmFy",
          "signed_at": "2025-01-15T00:00:00Z",
          "key_id": "ed25519:abcdef0123456789"
        }"#,
    )
    .unwrap();
    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("unsupported_format_version"))
        .stderr(predicate::str::contains("re-sign"));
}

#[test]
fn verify_without_a_signature_file_exits_2() {
    let tmp = TempDir::new().unwrap();
    let (_, public_key) = keygen(tmp.path());
    let policy = write_policy(tmp.path(), "policy.yaml", GOVERNED_POLICY);

    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("No signature file"));
}

#[test]
fn verify_without_anything_to_trust_is_a_usage_error() {
    let tmp = TempDir::new().unwrap();
    let (private_key, _) = keygen(tmp.path());
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
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Nothing to trust"));
}

#[test]
fn verify_rejects_a_bad_now() {
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

    h2h()
        .arg("verify")
        .arg(policy.to_str().unwrap())
        .arg("--key")
        .arg(public_key.to_str().unwrap())
        .arg("--now")
        .arg("yesterday")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not an RFC 3339 timestamp"));
}

// ------------------------------------------------ the lifecycle gate (P2-11)

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

// ---------------------------------------------------- the published vectors

/// The `h2h verify` path walks the same normative vectors the library does,
/// so a regression in argument handling cannot hide behind a green library
/// suite.
#[test]
fn the_cli_verifies_the_published_vectors() {
    let fixtures = workspace_root().join("fixtures/signing");

    for (policy, signature, keyring, expected) in [
        (
            "policies/basic.yaml",
            "policies/basic.sig",
            "keys/keyring.json",
            None,
        ),
        (
            "policies/extends-child.yaml",
            "policies/extends-child.sig",
            "keys/keyring.json",
            None,
        ),
        (
            "policies/tampered.yaml",
            "policies/tampered.sig",
            "keys/keyring.json",
            Some("content_hash_mismatch"),
        ),
        (
            "policies/basic.yaml",
            "policies/untrusted-key.sig",
            "keys/keyring.json",
            Some("unknown_key_id"),
        ),
        (
            "policies/basic.yaml",
            "policies/basic.sig",
            "keys/keyring-revoked.json",
            Some("key_revoked"),
        ),
        (
            "policies/basic.yaml",
            "policies/basic.sig",
            "keys/keyring-retired.json",
            Some("key_retired"),
        ),
    ] {
        let mut cmd = h2h();
        cmd.arg("verify")
            .arg(fixtures.join(policy).to_str().unwrap())
            .arg("--sig")
            .arg(fixtures.join(signature).to_str().unwrap())
            .arg("--keyring")
            .arg(fixtures.join(keyring).to_str().unwrap())
            .arg("--now")
            .arg("2026-09-15T12:00:00.000Z");

        match expected {
            None => {
                cmd.assert().success();
            }
            Some(reason) => {
                cmd.assert()
                    .code(1)
                    .stderr(predicate::str::contains(reason));
            }
        }
    }
}
