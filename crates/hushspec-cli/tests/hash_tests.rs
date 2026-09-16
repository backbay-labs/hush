//! `h2h hash` prints the portable policy identity (canonical spec 5).

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

const SUBCOMMAND: &str = "hash";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn h2h() -> Command {
    let mut command = Command::cargo_bin("h2h").unwrap();
    command.current_dir(workspace_root());
    command
}

const MINIMAL: &str = "hushspec: \"0.1.0\"\n";

/// The `minimal.yaml` vector's expectations (fixtures/core/hash).
const MINIMAL_CANONICAL: &str = r#"{"hushspec":"0.1.0"}"#;
const MINIMAL_DIGEST: &str =
    "sha256:9aa550f8eed15366ce9db38b22818179d79c382fa6423f159ef0b228aca25108";

#[test]
fn prints_the_content_hash_by_default_and_the_canonical_text_on_request() {
    let tmp = TempDir::new().unwrap();
    let policy = tmp.path().join("minimal.yaml");
    fs::write(&policy, MINIMAL).unwrap();

    h2h()
        .arg(SUBCOMMAND)
        .arg(&policy)
        .assert()
        .success()
        .stdout(format!("{MINIMAL_DIGEST}\n"));

    h2h()
        .arg(SUBCOMMAND)
        .arg(&policy)
        .arg("--format")
        .arg("canonical")
        .assert()
        .success()
        .stdout(format!("{MINIMAL_CANONICAL}\n"));
}

/// The identity covers the *resolved* document, so a child that adds nothing
/// but `extends` still hashes as its base, not as its own two lines.
#[test]
fn resolves_the_extends_chain_through_builtins_before_hashing() {
    let tmp = TempDir::new().unwrap();
    let child = tmp.path().join("child.yaml");
    fs::write(
        &child,
        "hushspec: \"0.1.0\"\nname: child\nextends: \"builtin:default\"\n",
    )
    .unwrap();

    let child_digest = String::from_utf8(
        h2h()
            .arg(SUBCOMMAND)
            .arg(&child)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(child_digest.starts_with("sha256:"), "{child_digest}");
    assert_eq!(child_digest.trim().len(), "sha256:".len() + 64);

    // A builtin reference is accepted directly, and the child's extra `name`
    // means it is a different policy than the base it extends.
    let base_digest = String::from_utf8(
        h2h()
            .arg(SUBCOMMAND)
            .arg("builtin:default")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert_ne!(child_digest, base_digest);
}

#[test]
fn reads_a_document_from_stdin_and_still_resolves_its_chain() {
    h2h()
        .arg(SUBCOMMAND)
        .arg("-")
        .write_stdin(MINIMAL)
        .assert()
        .success()
        .stdout(format!("{MINIMAL_DIGEST}\n"));

    // stdin has no path to resolve relative references against, but a
    // `builtin:` chain still resolves rather than reporting "file not found".
    let piped = String::from_utf8(
        h2h()
            .arg(SUBCOMMAND)
            .arg("-")
            .write_stdin("hushspec: \"0.1.0\"\nname: child\nextends: \"builtin:default\"\n")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(piped.starts_with("sha256:"), "{piped}");
    assert_ne!(piped.trim(), MINIMAL_DIGEST);
}

/// Exit codes match `h2h validate`: 2 for a missing file, 1 for a document
/// that has no canonical form.
#[test]
fn exit_codes_match_validate() {
    h2h()
        .arg(SUBCOMMAND)
        .arg("definitely-not-a-policy.yaml")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("file not found"));

    let tmp = TempDir::new().unwrap();
    let invalid = tmp.path().join("invalid.yaml");
    fs::write(&invalid, "hushspec: \"0.1.0\"\nnot_a_field: true\n").unwrap();
    h2h().arg(SUBCOMMAND).arg(&invalid).assert().code(1);

    // An unresolvable base is a resolution failure, not a silent fragment hash.
    let dangling = tmp.path().join("dangling.yaml");
    fs::write(
        &dangling,
        "hushspec: \"0.1.0\"\nextends: \"builtin:nope\"\n",
    )
    .unwrap();
    h2h().arg(SUBCOMMAND).arg(&dangling).assert().code(1);
}

/// Every vector in `fixtures/core/hash/` is reproduced by the CLI, which is
/// the surface a CI pipeline calls.
///
/// `h2h` validates before it canonicalizes, because an invalid document has no
/// canonical form (canonical spec 2.3), so this also pins that every vector
/// policy is a document a conformant engine accepts.
#[test]
fn reproduces_the_canonical_form_vectors() {
    let vectors = workspace_root().join("fixtures").join("core").join("hash");
    let mut checked = 0;
    for entry in fs::read_dir(&vectors).unwrap().filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "yaml") {
            continue;
        }
        let vector: serde_yaml::Value =
            serde_yaml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let policy = vector.get("policy").expect("vector has a policy");
        let expected_digest = vector
            .get("content_hash")
            .and_then(serde_yaml::Value::as_str)
            .expect("vector has a content_hash");
        let expected_canonical = vector
            .get("canonical")
            .and_then(serde_yaml::Value::as_str)
            .expect("vector has a canonical form");

        let tmp = TempDir::new().unwrap();
        let policy_path = tmp.path().join("policy.yaml");
        fs::write(&policy_path, serde_yaml::to_string(policy).unwrap()).unwrap();

        h2h()
            .arg(SUBCOMMAND)
            .arg(&policy_path)
            .assert()
            .success()
            .stdout(format!("{expected_digest}\n"));
        h2h()
            .arg(SUBCOMMAND)
            .arg(&policy_path)
            .arg("--format")
            .arg("canonical")
            .assert()
            .success()
            .stdout(format!("{expected_canonical}\n"));
        checked += 1;
    }
    assert_eq!(
        checked, 15,
        "expected 15 canonical-form vectors in fixtures/core/hash/"
    );
}
