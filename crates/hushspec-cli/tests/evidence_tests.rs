//! The evidence chain end to end through the CLI: verify-on-load and digest
//! pins on `eval`, `--log` into a hash-linked log, `log verify`, and
//! `receipts verify`.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn h2h() -> Command {
    Command::cargo_bin("h2h").unwrap()
}

fn repo_root() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../..")).to_path_buf()
}

fn write(dir: &TempDir, name: &str, content: &str) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, content).unwrap();
    path
}

const POLICY: &str = r#"hushspec: "0.1.0"
name: evidence
rules:
  egress:
    allow: ["api.github.com"]
    default: block
"#;

fn test_key() -> PathBuf {
    repo_root().join("fixtures/signing/keys/test-signing.key.pem")
}

fn test_keyring() -> PathBuf {
    repo_root().join("fixtures/signing/keys/keyring.json")
}

// ------------------------------------------------------------- verify-on-load

#[test]
fn eval_requires_a_signature_when_asked_and_still_emits_evidence() {
    let dir = TempDir::new().unwrap();
    let policy = write(&dir, "policy.yaml", POLICY);
    let output = h2h()
        .args(["eval"])
        .arg(&policy)
        .args([
            "--type",
            "egress",
            "--target",
            "api.github.com",
            "--require-signature",
            "--keyring",
        ])
        .arg(test_keyring())
        .args(["--format", "receipt"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("signature_missing"))
        .get_output()
        .stdout
        .clone();
    let receipt: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(receipt["decision"], "deny");
    assert_eq!(receipt["matched_rule"], "__hushspec_policy_unverified__");
    assert_eq!(receipt["policy"]["signature"]["verified"], false);
    assert_eq!(receipt["enforcement"]["outcome"], "blocked");
}

#[test]
fn eval_accepts_a_signed_policy_and_records_the_key() {
    let dir = TempDir::new().unwrap();
    let policy = write(&dir, "policy.yaml", POLICY);
    h2h()
        .args(["sign"])
        .arg(&policy)
        .args(["--key"])
        .arg(test_key())
        .args(["--allow-unapproved"])
        .assert()
        .success();
    let output = h2h()
        .args(["eval"])
        .arg(&policy)
        .args([
            "--type",
            "egress",
            "--target",
            "api.github.com",
            "--require-signature",
            "--keyring",
        ])
        .arg(test_keyring())
        .args(["--format", "receipt"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let receipt: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(receipt["decision"], "allow");
    assert_eq!(receipt["policy"]["signature"]["verified"], true);
    assert!(
        receipt["policy"]["signature"]["key_id"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
}

#[test]
fn eval_rejects_a_mismatched_digest_pin() {
    let dir = TempDir::new().unwrap();
    let policy = write(
        &dir,
        "policy.yaml",
        "hushspec: \"0.1.0\"\nextends: \"builtin:default#sha256:0000000000000000000000000000000000000000000000000000000000000000\"\n",
    );
    h2h()
        .args(["eval"])
        .arg(&policy)
        .args(["--type", "egress", "--target", "api.github.com"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("digest_mismatch"));
}

#[test]
fn hash_own_prints_the_pinnable_digest() {
    h2h()
        .args(["hash", "builtin:default", "--own"])
        .assert()
        .success()
        .stdout(predicate::str::is_match("^sha256:[0-9a-f]{64}\n$").unwrap());
}

// ----------------------------------------------------------------- the log

fn eval_into_log(policy: &Path, log: &Path, target: &str, key: Option<&Path>) {
    let mut cmd = h2h();
    cmd.args(["eval"])
        .arg(policy)
        .args(["--type", "egress", "--target", target, "--log"])
        .arg(log);
    if let Some(key) = key {
        cmd.args(["--log-key"]).arg(key);
    }
    cmd.assert().code(predicate::in_iter([0, 1]));
}

#[test]
fn eval_log_writes_a_chain_that_log_verify_accepts() {
    let dir = TempDir::new().unwrap();
    let policy = write(&dir, "policy.yaml", POLICY);
    let log = dir.path().join("receipts.jsonl");
    eval_into_log(&policy, &log, "api.github.com", None);
    eval_into_log(&policy, &log, "evil.example.com", None);

    let text = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 4, "policy_loaded + receipt, twice");
    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first["entry_type"], "policy_loaded");
    assert_eq!(first["seq"], 1);
    let last: serde_json::Value = serde_json::from_str(lines[3]).unwrap();
    assert_eq!(last["entry_type"], "receipt");
    assert_eq!(last["receipt"]["decision"], "deny");

    h2h()
        .args(["log", "verify"])
        .arg(&log)
        .assert()
        .success()
        .stdout(predicate::str::contains("4 entries"));
    h2h()
        .args(["log", "verify"])
        .arg(&log)
        .args(["--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"receipts\": 2"));

    // Tamper with line 2 and the verifier names it.
    let tampered = text.replacen("\"allow\"", "\"deny\"", 1);
    let broken = write(&dir, "broken.jsonl", &tampered);
    h2h()
        .args(["log", "verify"])
        .arg(&broken)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("broken.jsonl:2"));

    // Delete a line: sequence gap.
    let deleted = write(
        &dir,
        "deleted.jsonl",
        &format!("{}\n{}\n{}\n", lines[0], lines[2], lines[3]),
    );
    h2h()
        .args(["log", "verify"])
        .arg(&deleted)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("sequence gap"));
}

#[test]
fn signed_log_entries_verify_against_the_keyring() {
    let dir = TempDir::new().unwrap();
    let policy = write(&dir, "policy.yaml", POLICY);
    let log = dir.path().join("signed.jsonl");
    eval_into_log(&policy, &log, "api.github.com", Some(&test_key()));

    h2h()
        .args(["log", "verify"])
        .arg(&log)
        .args(["--require-signatures", "--keyring"])
        .arg(test_keyring())
        .assert()
        .success()
        .stdout(predicate::str::contains("2 verified"));
    h2h()
        .args(["log", "verify"])
        .arg(&log)
        .args(["--require-signatures"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no_keyring"));
}

// ------------------------------------------------------------- receipts

#[test]
fn receipts_verify_checks_policy_identity_and_replays_the_decision() {
    let dir = TempDir::new().unwrap();
    let policy = write(&dir, "policy.yaml", POLICY);
    let log = dir.path().join("receipts.jsonl");
    eval_into_log(&policy, &log, "api.github.com", None);
    eval_into_log(&policy, &log, "evil.example.com", None);

    h2h()
        .args(["receipts", "verify"])
        .arg(&log)
        .args(["--policy"])
        .arg(&policy)
        .assert()
        .success()
        .stdout(predicate::str::contains("2 of 2 receipt(s) verified"))
        .stdout(predicate::str::contains("re-derived"));

    let other = write(
        &dir,
        "other.yaml",
        "hushspec: \"0.1.0\"\nname: other\nrules:\n  egress:\n    allow: [\"evil.example.com\"]\n    default: block\n",
    );
    h2h()
        .args(["receipts", "verify"])
        .arg(&log)
        .args(["--policy"])
        .arg(&other)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("receipt names"));
}

#[test]
fn receipts_verify_checks_signed_receipt_vectors() {
    let valid = repo_root().join("fixtures/receipts/signed/valid/allow-egress.signed.json");
    let tampered =
        repo_root().join("fixtures/receipts/signed/invalid/tampered-after-signing.signed.json");
    h2h()
        .args(["receipts", "verify"])
        .arg(&valid)
        .args(["--keyring"])
        .arg(test_keyring())
        .args(["--now", "2026-09-15T12:00:00Z", "--require-signatures"])
        .assert()
        .success()
        .stdout(predicate::str::contains("verified with sha256:"));
    h2h()
        .args(["receipts", "verify"])
        .arg(&tampered)
        .args(["--keyring"])
        .arg(test_keyring())
        .args(["--now", "2026-09-15T12:00:00Z"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("content_hash_mismatch"));
}

#[test]
fn explain_shows_chain_and_signature_lines() {
    let dir = TempDir::new().unwrap();
    let policy = write(
        &dir,
        "child.yaml",
        "hushspec: \"0.1.0\"\nname: child\nextends: \"builtin:default\"\n",
    );
    h2h()
        .args(["explain"])
        .arg(&policy)
        .args([
            "--type",
            "egress",
            "--target",
            "api.github.com",
            "--keyring",
        ])
        .arg(test_keyring())
        .assert()
        .stdout(predicate::str::contains("chain:"))
        .stdout(predicate::str::contains("builtin:default"))
        .stdout(predicate::str::contains("NOT verified: signature_missing"))
        .stdout(predicate::str::contains("enforce: enforce / allowed"));
}
