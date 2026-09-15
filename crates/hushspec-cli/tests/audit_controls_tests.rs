//! Integration coverage for `h2h audit --controls` and `--strict`.
//!
//! The control -> rule-path matrix is a report over the *resolved* document,
//! so the library policies (which all extend a builtin) are exercised directly.

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

#[test]
fn audit_controls_prints_the_matrix_and_coverage() {
    h2h()
        .arg("audit")
        .arg("--controls")
        .arg("library/healthcare/hipaa-base.yaml")
        .assert()
        .success()
        .stdout(predicate::str::contains("Control mappings:"))
        .stdout(predicate::str::contains(
            "hipaa-2013 -- HIPAA Security and Privacy Rules",
        ))
        .stdout(predicate::str::contains("164.312(e)(1)"))
        .stdout(predicate::str::contains("rules.egress"))
        .stdout(predicate::str::contains("6 of 6 rule blocks mapped"));
}

#[test]
fn audit_without_controls_keeps_the_original_output() {
    h2h()
        .arg("audit")
        .arg("library/healthcare/hipaa-base.yaml")
        .assert()
        .success()
        .stdout(predicate::str::contains("Governance checks:"))
        .stdout(predicate::str::contains("Control mappings:").not());
}

#[test]
fn audit_controls_json_carries_frameworks_and_coverage() {
    let output = h2h()
        .arg("audit")
        .arg("--controls")
        .arg("--format")
        .arg("json")
        .arg("library/finance/pci-dss.yaml")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let controls = &report["controls"];
    assert_eq!(controls["registry_version"], "0.1.0");
    assert_eq!(
        controls["coverage"]["mapped_rule_blocks"],
        controls["coverage"]["total_rule_blocks"]
    );
    assert!(
        controls["coverage"]["unmapped_rule_blocks"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let frameworks = controls["frameworks"].as_array().unwrap();
    assert_eq!(frameworks.len(), 1);
    assert_eq!(frameworks[0]["framework"], "pci-dss-4.0");
    assert_eq!(frameworks[0]["registered"], true);
    assert!(!frameworks[0]["controls"].as_array().unwrap().is_empty());
}

#[test]
fn audit_controls_json_is_absent_without_the_flag() {
    let output = h2h()
        .arg("audit")
        .arg("--format")
        .arg("json")
        .arg("library/finance/pci-dss.yaml")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(report.get("controls").is_none(), "{report:#}");
}

#[test]
fn audit_strict_fails_on_an_unresolvable_rule_path() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(
        tmp.path(),
        "dangling.yaml",
        r#"hushspec: "0.2.0"
name: dangling
metadata:
  author: "security@example.com"
  approved_by: "ciso@example.com"
  approval_date: "2025-01-15"
  classification: internal
  lifecycle_state: deployed
  policy_version: 1
  expiry_date: "2099-01-01"
  controls:
    - framework: soc2-tsc-2017
      control_id: CC6.1
      rule_paths:
        - rules
        - rules.tool_access
rules:
  egress:
    allow: ["api.github.com"]
    default: block
"#,
    );

    // Advisory by default...
    h2h()
        .arg("audit")
        .arg("--controls")
        .arg(&policy)
        .assert()
        .success()
        .stdout(predicate::str::contains("does not resolve"));

    // ...fatal under --strict.
    h2h()
        .arg("audit")
        .arg("--controls")
        .arg("--strict")
        .arg(&policy)
        .assert()
        .code(1);
}

#[test]
fn every_library_policy_is_fully_mapped() {
    for policy in [
        "library/devops/cicd-hardened.yaml",
        "library/education/ferpa-student.yaml",
        "library/finance/pci-dss.yaml",
        "library/finance/soc2-base.yaml",
        "library/general/air-gapped.yaml",
        "library/general/recommended.yaml",
        "library/government/fedramp-base.yaml",
        "library/healthcare/hipaa-base.yaml",
    ] {
        let output = h2h()
            .arg("audit")
            .arg("--controls")
            .arg("--format")
            .arg("json")
            .arg(policy)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let coverage = &report["controls"]["coverage"];
        assert_eq!(
            coverage["mapped_rule_blocks"], coverage["total_rule_blocks"],
            "{policy} has unmapped rule blocks: {:?}",
            coverage["unmapped_rule_blocks"]
        );
        assert!(
            coverage["total_rule_blocks"].as_u64().unwrap() > 0,
            "{policy} declares no rule blocks"
        );

        // Every framework and control id in the library is registered (L013).
        for framework in report["controls"]["frameworks"].as_array().unwrap() {
            assert_eq!(
                framework["registered"], true,
                "{policy}: unregistered framework {}",
                framework["framework"]
            );
            for control in framework["controls"].as_array().unwrap() {
                assert_eq!(
                    control["control_id_valid"], true,
                    "{policy}: {} does not match its framework pattern",
                    control["control_id"]
                );
                assert!(
                    control["unresolved_rule_paths"]
                        .as_array()
                        .unwrap()
                        .is_empty(),
                    "{policy}: {} has unresolved rule paths",
                    control["control_id"]
                );
            }
        }
    }
}
