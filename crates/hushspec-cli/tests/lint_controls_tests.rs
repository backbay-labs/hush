//! Integration coverage for lint L011, L012 and L013 -- the semantic checks
//! over `metadata.controls`.
//!
//! Control mappings never influence evaluation (core spec 2.5), so everything
//! asserted here is a tooling claim about the policy, not a decision.

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

fn write_policy(dir: &Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, content).unwrap();
    path
}

/// Two rule blocks, both mapped, registered framework, resolvable paths.
const CLEAN: &str = r#"hushspec: "0.2.0"
name: clean-controls
metadata:
  controls:
    - framework: soc2-tsc-2017
      control_id: CC6.1
      rule_paths:
        - rules.egress
    - framework: soc2-tsc-2017
      control_id: CC6.3
      rule_paths:
        - rules.tool_access
rules:
  egress:
    allow: ["api.github.com"]
    default: block
  tool_access:
    allow: ["read_file"]
    default: block
"#;

#[test]
fn clean_control_mappings_produce_no_findings() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(tmp.path(), "clean.yaml", CLEAN);

    h2h()
        .arg("lint")
        .arg("--fail-on-warnings")
        .arg(&policy)
        .assert()
        .success()
        .stdout(predicate::str::contains("L011").not())
        .stdout(predicate::str::contains("L012").not())
        .stdout(predicate::str::contains("L013").not());
}

#[test]
fn l011_flags_a_rule_block_with_no_control_mapping() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(
        tmp.path(),
        "unmapped.yaml",
        r#"hushspec: "0.2.0"
name: unmapped-block
metadata:
  controls:
    - framework: soc2-tsc-2017
      control_id: CC6.1
      rule_paths:
        - rules.egress
rules:
  egress:
    allow: ["api.github.com"]
    default: block
  tool_access:
    allow: ["read_file"]
    default: block
"#,
    );

    // A warning, so the plain run still succeeds; --fail-on-warnings promotes it.
    h2h()
        .arg("lint")
        .arg(&policy)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "warning[L011]: rule block `rules.tool_access` has no control mapping",
        ));

    h2h()
        .arg("lint")
        .arg("--fail-on-warnings")
        .arg(&policy)
        .assert()
        .code(1);
}

#[test]
fn l011_is_silent_when_the_policy_declares_no_mappings() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(
        tmp.path(),
        "no-controls.yaml",
        r#"hushspec: "0.2.0"
name: no-controls
rules:
  egress:
    allow: ["api.github.com"]
    default: block
"#,
    );

    h2h()
        .arg("lint")
        .arg("--fail-on-warnings")
        .arg(&policy)
        .assert()
        .success()
        .stdout(predicate::str::contains("L011").not());
}

#[test]
fn l011_treats_a_rules_mapping_as_covering_every_block() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(
        tmp.path(),
        "whole-rules.yaml",
        r#"hushspec: "0.2.0"
name: whole-rules
metadata:
  controls:
    - framework: soc2-tsc-2017
      control_id: CC6.1
      rule_paths:
        - rules
rules:
  egress:
    allow: ["api.github.com"]
    default: block
  tool_access:
    allow: ["read_file"]
    default: block
"#,
    );

    h2h()
        .arg("lint")
        .arg("--fail-on-warnings")
        .arg(&policy)
        .assert()
        .success()
        .stdout(predicate::str::contains("L011").not());
}

#[test]
fn l011_treats_a_pattern_selector_as_covering_its_block() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(
        tmp.path(),
        "selector.yaml",
        r#"hushspec: "0.2.0"
name: selector
metadata:
  controls:
    - framework: hipaa-2013
      control_id: "164.514(b)(2)"
      rule_paths:
        - rules.secret_patterns.patterns[ssn]
rules:
  secret_patterns:
    patterns:
      - name: ssn
        pattern: "[0-9]{3}-[0-9]{2}-[0-9]{4}"
        severity: critical
"#,
    );

    h2h()
        .arg("lint")
        .arg("--fail-on-warnings")
        .arg(&policy)
        .assert()
        .success()
        .stdout(predicate::str::contains("L011").not());
}

#[test]
fn l012_errors_on_a_rule_path_that_resolves_to_nothing() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(
        tmp.path(),
        "dangling.yaml",
        r#"hushspec: "0.2.0"
name: dangling-path
metadata:
  controls:
    - framework: soc2-tsc-2017
      control_id: CC6.1
      rule_paths:
        - rules.egress
        - rules.tool_access
        - rules.secret_patterns.patterns[nope]
rules:
  egress:
    allow: ["api.github.com"]
    default: block
  tool_access:
    allow: ["read_file"]
    default: block
  secret_patterns:
    patterns:
      - name: ssn
        pattern: "[0-9]{3}-[0-9]{2}-[0-9]{4}"
        severity: critical
"#,
    );

    // An error, so even the plain run exits non-zero.
    h2h()
        .arg("lint")
        .arg(&policy)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("error[L012]"))
        .stdout(predicate::str::contains("\"rules.tool_access\"").not())
        .stdout(predicate::str::contains(
            "does not resolve to anything in the resolved document",
        ));
}

#[test]
fn an_unresolvable_mapping_leaves_its_block_unmapped() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(
        tmp.path(),
        "unresolvable-only.yaml",
        r#"hushspec: "0.2.0"
name: unresolvable-only
metadata:
  controls:
    - framework: soc2-tsc-2017
      control_id: CC6.1
      rule_paths:
        - rules.egress.nope
rules:
  egress:
    allow: ["api.github.com"]
    default: block
"#,
    );

    // The mapping points at nothing, so it is both a broken claim (L012) and
    // no coverage for the block it names (L011).
    h2h()
        .arg("lint")
        .arg(&policy)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("error[L012]"))
        .stdout(predicate::str::contains("rules.egress.nope"))
        .stdout(predicate::str::contains(
            "warning[L011]: rule block `rules.egress` has no control mapping",
        ));
}

#[test]
fn l012_rejects_a_path_outside_the_grammar() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(
        tmp.path(),
        "bad-root.yaml",
        r#"hushspec: "0.2.0"
name: bad-root
metadata:
  author: "security@example.com"
  controls:
    - framework: soc2-tsc-2017
      control_id: CC6.1
      rule_paths:
        - rules
        - metadata.author
rules:
  egress:
    allow: ["api.github.com"]
    default: block
"#,
    );

    h2h()
        .arg("lint")
        .arg(&policy)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("error[L012]"))
        .stdout(predicate::str::contains("metadata.author"));
}

#[test]
fn l013_flags_an_unregistered_framework() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(
        tmp.path(),
        "unregistered.yaml",
        r#"hushspec: "0.2.0"
name: unregistered-framework
metadata:
  controls:
    - framework: acme-internal-1.0
      control_id: SEC-42
      rule_paths:
        - rules
rules:
  egress:
    allow: ["api.github.com"]
    default: block
"#,
    );

    h2h()
        .arg("lint")
        .arg(&policy)
        .assert()
        .success()
        .stdout(predicate::str::contains("warning[L013]"))
        .stdout(predicate::str::contains(
            "is not in the HushSpec framework registry (spec/registries/frameworks.yaml)",
        ));
}

#[test]
fn l013_flags_a_control_id_that_does_not_match_its_framework_pattern() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(
        tmp.path(),
        "bad-control-id.yaml",
        r#"hushspec: "0.2.0"
name: bad-control-id
metadata:
  controls:
    - framework: hipaa-2013
      control_id: CC6.1
      rule_paths:
        - rules
rules:
  egress:
    allow: ["api.github.com"]
    default: block
"#,
    );

    h2h()
        .arg("lint")
        .arg(&policy)
        .assert()
        .success()
        .stdout(predicate::str::contains("warning[L013]"))
        .stdout(predicate::str::contains(
            "does not match the hipaa-2013 control id pattern",
        ));
}

#[test]
fn lint_json_reports_the_control_codes() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(
        tmp.path(),
        "json.yaml",
        r#"hushspec: "0.2.0"
name: json-controls
metadata:
  controls:
    - framework: acme-internal
      control_id: SEC-1
      rule_paths:
        - rules.egress
rules:
  egress:
    allow: ["api.github.com"]
    default: block
  tool_access:
    allow: ["read_file"]
    default: block
"#,
    );

    let output = h2h()
        .arg("lint")
        .arg("--format")
        .arg("json")
        .arg(&policy)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let results: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let codes: Vec<&str> = results[0]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["code"].as_str())
        .collect();
    assert!(codes.contains(&"L011"), "expected L011 in {codes:?}");
    assert!(codes.contains(&"L013"), "expected L013 in {codes:?}");
}
