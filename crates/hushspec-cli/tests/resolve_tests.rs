//! `h2h diff`, `h2h lint` and `h2h test` must evaluate the *resolved*
//! document, and `h2h test` must reject fixtures that do not match the
//! evaluator-test schema.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
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

/// A leaf that inherits `forbidden_paths`, `egress` and `secret_patterns`
/// from `builtin:default` and declares only `tool_access` itself.
const LEAF_EXTENDING_DEFAULT: &str = r#"hushspec: "0.1.0"
name: leaf
extends: "builtin:default"
rules:
  tool_access:
    allow: [read_file]
    default: block
"#;

/// The same policy with no base: every inherited block is simply absent.
const LEAF_WITHOUT_BASE: &str = r#"hushspec: "0.1.0"
name: leaf
rules:
  tool_access:
    allow: [read_file]
    default: block
"#;

// ---------------------------------------------------------------------------
// lint
// ---------------------------------------------------------------------------

#[test]
fn lint_does_not_report_l009_for_inherited_secret_patterns() {
    let tmp = TempDir::new().unwrap();
    let policy = tmp.path().join("leaf.yaml");
    fs::write(&policy, LEAF_EXTENDING_DEFAULT).unwrap();

    // builtin:default declares secret_patterns, so the leaf must not be told
    // to add its own.
    h2h()
        .arg("lint")
        .arg(&policy)
        .assert()
        .success()
        .stdout(predicate::str::contains("L009").not());
}

#[test]
fn lint_reports_l009_when_no_base_supplies_secret_patterns() {
    let tmp = TempDir::new().unwrap();
    let policy = tmp.path().join("leaf.yaml");
    fs::write(&policy, LEAF_WITHOUT_BASE).unwrap();

    h2h()
        .arg("lint")
        .arg(&policy)
        .assert()
        .stdout(predicate::str::contains("L009"));
}

#[test]
fn lint_no_longer_reports_l009_on_the_extends_fixture() {
    // fixtures/core/valid/extends-basic.yaml carries `extends:
    // "hushspec:default"`, a reference form no loader in this repo resolves,
    // so linting it now reports the resolution failure instead of inventing
    // findings about blocks its base would have supplied.
    h2h()
        .arg("lint")
        .arg("fixtures/core/valid/extends-basic.yaml")
        .assert()
        .stdout(predicate::str::contains("L009").not())
        .stderr(predicate::str::contains("failed to resolve"));
}

#[test]
fn lint_fix_is_refused_for_policies_with_extends() {
    let tmp = TempDir::new().unwrap();
    let policy = tmp.path().join("leaf.yaml");
    fs::write(&policy, LEAF_EXTENDING_DEFAULT).unwrap();

    h2h()
        .arg("lint")
        .arg("--fix")
        .arg(&policy)
        .assert()
        .stderr(predicate::str::contains(
            "--fix/--dry-run is not supported for policies with `extends`",
        ));

    // The file on disk is untouched.
    assert_eq!(fs::read_to_string(&policy).unwrap(), LEAF_EXTENDING_DEFAULT);
}

// ---------------------------------------------------------------------------
// diff
// ---------------------------------------------------------------------------

#[test]
fn diff_resolves_extends_and_shows_inherited_blocks() {
    let tmp = TempDir::new().unwrap();
    let old = tmp.path().join("old.yaml");
    let new = tmp.path().join("new.yaml");
    fs::write(&old, LEAF_WITHOUT_BASE).unwrap();
    fs::write(&new, LEAF_EXTENDING_DEFAULT).unwrap();

    let output = h2h()
        .arg("diff")
        .arg(&old)
        .arg(&new)
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let changes: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let changes = changes.as_array().expect("diff emits an array");

    // This probe only exists because the inherited forbidden_paths block was
    // resolved out of builtin:default -- neither file declares one.
    let shadow = changes
        .iter()
        .find(|c| c["action"]["target"].as_str() == Some("/etc/shadow"))
        .expect("inherited forbidden_paths produced a probe");
    assert_eq!(shadow["old_decision"], "allow");
    assert_eq!(shadow["new_decision"], "deny");
    assert_eq!(shadow["new_rule"], "rules.forbidden_paths.patterns");
    assert_eq!(shadow["change_type"], "tightened");

    // ...and the inherited egress block flips the default for unlisted hosts.
    let egress = changes
        .iter()
        .find(|c| {
            c["action"]["type"].as_str() == Some("egress")
                && c["action"]["target"].as_str() == Some("example.com")
        })
        .expect("inherited egress produced a probe");
    assert_eq!(egress["new_decision"], "deny");
}

// ---------------------------------------------------------------------------
// test
// ---------------------------------------------------------------------------

/// A fixture whose embedded policy allows everything the cases probe, so the
/// suite only passes when the `--policy` override is the merged document.
const INHERITED_DENY_FIXTURE: &str = r#"hushspec_test: "0.1.0"
description: inherited forbidden_paths must deny
policy:
  hushspec: "0.1.0"
  name: embedded
  rules:
    tool_access:
      allow: [read_file]
      default: block
cases:
  - description: inherited forbidden_paths denies the ssh key
    action:
      type: file_read
      target: /home/user/.ssh/id_rsa
    expect:
      decision: deny
      matched_rule: rules.forbidden_paths.patterns
"#;

#[test]
fn test_policy_override_resolves_extends() {
    let tmp = TempDir::new().unwrap();
    let policy = tmp.path().join("leaf.yaml");
    let fixture = tmp.path().join("inherited.test.yaml");
    fs::write(&policy, LEAF_EXTENDING_DEFAULT).unwrap();
    fs::write(&fixture, INHERITED_DENY_FIXTURE).unwrap();

    // Unresolved, the leaf has no forbidden_paths at all and this case fails.
    h2h()
        .arg("test")
        .arg("--policy")
        .arg(&policy)
        .arg(&fixture)
        .assert()
        .success()
        .stdout(predicate::str::contains("1 passed, 0 failed"));
}

#[test]
fn test_embedded_policy_resolves_extends() {
    let tmp = TempDir::new().unwrap();
    let fixture = tmp.path().join("embedded.test.yaml");
    fs::write(
        &fixture,
        r#"hushspec_test: "0.1.0"
description: embedded policy extends a builtin
policy:
  hushspec: "0.1.0"
  name: embedded-leaf
  extends: "builtin:default"
  rules:
    tool_access:
      allow: [read_file]
      default: block
cases:
  - description: inherited forbidden_paths denies the ssh key
    action:
      type: file_read
      target: /home/user/.ssh/id_rsa
    expect:
      decision: deny
      matched_rule: rules.forbidden_paths.patterns
"#,
    )
    .unwrap();

    h2h()
        .arg("test")
        .arg(&fixture)
        .assert()
        .success()
        .stdout(predicate::str::contains("1 passed, 0 failed"));
}

#[test]
fn test_rejects_typo_in_expect() {
    let tmp = TempDir::new().unwrap();
    let fixture = tmp.path().join("typo.test.yaml");
    fs::write(
        &fixture,
        r#"hushspec_test: "0.1.0"
description: typo in expect must not pass
policy:
  hushspec: "0.1.0"
  name: embedded
  rules:
    tool_access:
      allow: [read_file]
      default: block
cases:
  - description: typo
    action:
      type: tool_call
      target: shell_exec
    expect:
      decision: deny
      matched_rul: rules.tool_access.default
"#,
    )
    .unwrap();

    h2h()
        .arg("test")
        .arg(&fixture)
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "does not match the hushspec-evaluator-test schema",
        ))
        // JSON-pointer path of the offending value.
        .stderr(predicate::str::contains("/cases/0/expect"))
        .stderr(predicate::str::contains("matched_rul"));
}

#[test]
fn test_rejects_unknown_top_level_key() {
    let tmp = TempDir::new().unwrap();
    let fixture = tmp.path().join("unknown.test.yaml");
    fs::write(
        &fixture,
        r#"hushspec_test: "0.1.0"
description: unknown top-level key must not pass
unexpected_key: true
policy:
  hushspec: "0.1.0"
  name: embedded
  rules:
    tool_access:
      allow: [read_file]
      default: block
cases:
  - description: allowed tool
    action:
      type: tool_call
      target: read_file
    expect:
      decision: allow
"#,
    )
    .unwrap();

    h2h()
        .arg("test")
        .arg(&fixture)
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "does not match the hushspec-evaluator-test schema",
        ))
        .stderr(predicate::str::contains("unexpected_key"));
}

#[test]
fn test_accepts_the_repo_fixtures() {
    h2h()
        .arg("test")
        .arg("--fixtures")
        .arg("fixtures/core/evaluation")
        .assert()
        .success();
}

/// The CLI embeds its own copy of the evaluator-test schema because
/// `cargo package` cannot reach the workspace root. Fail loudly if it drifts
/// from the canonical file.
#[test]
fn evaluator_schema_matches_workspace_copy() {
    let vendored: serde_json::Value = serde_json::from_str(include_str!(
        "../schemas/hushspec-evaluator-test.v1.schema.json"
    ))
    .unwrap();
    let canonical: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(
            workspace_root().join("schemas/hushspec-evaluator-test.v1.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        vendored, canonical,
        "crates/hushspec-cli/schemas/hushspec-evaluator-test.v1.schema.json is out of date -- \
         copy schemas/hushspec-evaluator-test.v1.schema.json over it"
    );
}
