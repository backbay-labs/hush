//! Integration coverage for `h2h bundle create`, `verify`, and `inspect`
//! (spec/hushspec-bundle.md).

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

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

const POLICY: &str = "library/healthcare/hipaa-base.yaml";
const SIGNING_KEY: &str = "fixtures/signing/keys/test-signing.key.pem";
const PUBLIC_KEY: &str = "fixtures/signing/keys/test-signing.pub.pem";
const KEYRING: &str = "fixtures/signing/keys/keyring.json";
const VALID: &str = "fixtures/bundle/bundles/valid.bundle.json";

#[test]
fn create_then_verify_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("policy.bundle.json");

    h2h()
        .args(["bundle", "create", POLICY])
        .args(["--key", SIGNING_KEY])
        .args(["--created-at", "2026-09-15T12:00:00.000Z"])
        .arg("--out")
        .arg(&out)
        .assert()
        .success()
        .stdout(predicate::str::contains("Bundled"));

    // Pinning created_at makes the bundle byte-reproducible, which is what
    // lets the committed vector be a vector at all.
    let bytes = std::fs::read(&out).unwrap();
    assert_eq!(bytes, std::fs::read(workspace_root().join(VALID)).unwrap());

    h2h()
        .args(["bundle", "verify"])
        .arg(&out)
        .args(["--keyring", KEYRING])
        .args(["--policy", POLICY])
        .assert()
        .success()
        .stdout(predicate::str::contains("Bundle is valid"));
}

#[test]
fn a_single_public_key_is_accepted_as_a_one_key_keyring() {
    h2h()
        .args(["bundle", "verify", VALID])
        .args(["--key", PUBLIC_KEY])
        .assert()
        .success();
}

#[test]
fn an_unsigned_bundle_warns_on_create_and_fails_on_verify() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("unsigned.bundle.json");

    h2h()
        .args(["bundle", "create", POLICY])
        .arg("--out")
        .arg(&out)
        .assert()
        .success()
        .stderr(predicate::str::contains("is unsigned"));

    h2h()
        .args(["bundle", "verify"])
        .arg(&out)
        .args(["--keyring", KEYRING, "--format", "json"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("dsse_signature_mismatch"));
}

#[test]
fn verify_reports_a_policy_mismatch_against_a_different_policy() {
    h2h()
        .args(["bundle", "verify", VALID])
        .args(["--keyring", KEYRING])
        .args(["--policy", "library/finance/pci-dss.yaml"])
        .args(["--format", "json"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("policy_mismatch"));
}

/// Bundle spec 5.2 check 4: a policy that does not resolve is
/// `policy_mismatch` too, because there is nothing to compare.
#[test]
fn verify_reports_a_policy_mismatch_for_a_policy_that_does_not_resolve() {
    h2h()
        .args(["bundle", "verify", VALID])
        .args(["--keyring", KEYRING])
        .args(["--policy", "definitely-not-a-policy.yaml"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("policy_mismatch"));
}

#[test]
fn verify_without_a_trust_anchor_is_a_usage_error() {
    h2h()
        .args(["bundle", "verify", VALID])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("nothing to trust"));
}

#[test]
fn verify_of_a_missing_bundle_exits_2() {
    h2h()
        .args(["bundle", "verify", "definitely-not-a-bundle.json"])
        .args(["--keyring", KEYRING])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn inspect_prints_the_predicate_summary() {
    h2h()
        .args(["bundle", "inspect", VALID])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "https://hushspec.dev/attestation/policy-bundle/v0.1",
        ))
        .stdout(predicate::str::contains("builtin:strict"))
        .stdout(predicate::str::contains("hipaa-base"));
}

#[test]
fn inspect_json_emits_the_whole_statement() {
    let output = h2h()
        .args(["bundle", "inspect", VALID, "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let statement: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(statement["_type"], "https://in-toto.io/Statement/v1");
    assert_eq!(statement["predicate"]["bundle_version"], "0.1");
    assert!(statement["predicate"]["resolved"]["rules"].is_object());
}

/// `--require-signature` without a keyring cannot be satisfied by an unsigned
/// policy: the bundler refuses rather than attesting an unverified document.
#[test]
fn require_signature_refuses_an_unverified_policy() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("policy.bundle.json");

    h2h()
        .args(["bundle", "create", POLICY])
        .args(["--key", SIGNING_KEY, "--require-signature"])
        .args(["--keyring", KEYRING])
        .arg("--out")
        .arg(&out)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("signature"));
    assert!(
        !out.exists(),
        "no bundle is written when the policy is refused"
    );
}

/// A builtin ruleset has no file on disk, and bundling one still produces a
/// chain of exactly one link naming the builtin.
#[test]
fn a_builtin_ruleset_bundles_with_a_one_link_chain() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("strict.bundle.json");

    h2h()
        .args(["bundle", "create", "builtin:strict"])
        .args(["--key", SIGNING_KEY])
        .arg("--out")
        .arg(&out)
        .assert()
        .success();

    let bundle: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let payload = bundle["payload"].as_str().unwrap();
    let decoded = decode_base64(payload);
    let statement: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
    let chain = statement["predicate"]["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0]["source"], "builtin:strict");
}

fn decode_base64(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in text.bytes().filter(|byte| *byte != b'=') {
        let value = ALPHABET.iter().position(|c| *c == byte).expect("base64") as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    out
}
