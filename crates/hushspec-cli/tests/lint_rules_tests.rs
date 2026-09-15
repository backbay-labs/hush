//! Integration coverage for lint L014 through L020 -- the posture checks added
//! alongside spans and SARIF.
//!
//! The per-check logic is unit-tested in `cmd_lint::checks`; what is asserted
//! here is what a user actually sees: which code comes out, at which severity,
//! pointing at which key, and what that does to the exit code under
//! `--fail-on-warnings`.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
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

/// Lint `content` and return its findings as `(code, severity, path)` triples.
fn findings_of(content: &str) -> Vec<(String, String, String)> {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(tmp.path(), "policy.yaml", content);
    let output = h2h()
        .arg("lint")
        .arg("--format")
        .arg("json")
        .arg(&policy)
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    report[0]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["code"].as_str().unwrap_or_default().to_string(),
                f["severity"].as_str().unwrap_or_default().to_string(),
                f["path"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

fn find<'a>(
    findings: &'a [(String, String, String)],
    code: &str,
) -> Option<&'a (String, String, String)> {
    findings.iter().find(|(c, _, _)| c == code)
}

#[test]
fn l014_names_the_credential_locations_a_denylist_misses() {
    let findings = findings_of(
        r#"hushspec: "0.1.0"
name: partial-denylist
rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
      - "**/id_rsa*"
  secret_patterns:
    patterns:
      - name: aws
        pattern: "(AKIA|ASIA)[0-9A-Z]{16}"
        severity: critical
"#,
    );
    let (_, severity, path) = find(&findings, "L014").expect("L014");
    assert_eq!(severity, "warning");
    assert_eq!(path, "rules.forbidden_paths.patterns");
}

#[test]
fn l015_promotes_an_under_graded_credential_pattern_to_a_warning() {
    let findings = findings_of(
        r#"hushspec: "0.1.0"
name: under-graded
rules:
  secret_patterns:
    patterns:
      - name: github_token
        pattern: "gh[opsur]_[A-Za-z0-9]{36}"
        severity: warn
"#,
    );
    let (_, severity, path) = find(&findings, "L015").expect("L015");
    assert_eq!(severity, "warning");
    assert_eq!(path, "rules.secret_patterns.patterns[0].severity");
}

#[test]
fn l016_warns_when_a_broad_pattern_shadows_siblings_and_informs_when_it_is_alone() {
    let shadowing = findings_of(
        r#"hushspec: "0.1.0"
name: shadowing
rules:
  shell_commands:
    forbidden_patterns:
      - ".*"
      - "(?i)mkfs"
"#,
    );
    let (_, severity, path) = find(&shadowing, "L016").expect("L016");
    assert_eq!(severity, "warning");
    assert_eq!(path, "rules.shell_commands.forbidden_patterns[0]");

    // `rulesets/panic.yaml` is the shipped example of the sole-entry form.
    let panic = findings_of(
        r#"hushspec: "0.1.0"
name: deny-all-shell
rules:
  shell_commands:
    forbidden_patterns:
      - ".*"
"#,
    );
    assert_eq!(find(&panic, "L016").map(|f| f.1.as_str()), Some("info"));
}

#[test]
fn l017_reports_a_permissive_default_and_l005_is_gone() {
    let findings = findings_of(
        r#"hushspec: "0.1.0"
name: permissive-default
rules:
  egress:
    allow: ["api.example.com"]
    block: []
    default: allow
"#,
    );
    let (_, severity, path) = find(&findings, "L017").expect("L017");
    assert_eq!(severity, "warning");
    assert_eq!(path, "rules.egress.default");
    assert!(
        find(&findings, "L005").is_none(),
        "L005 is retired in favour of L017: {findings:?}"
    );
}

#[test]
fn l018_separates_a_deliberate_deny_all_from_a_self_contradicting_policy() {
    let deny_all = findings_of(
        r#"hushspec: "0.1.0"
name: deny-all-capabilities
rules:
  computer_use:
    enabled: true
    mode: fail_closed
    allowed_actions: []
  input_injection:
    enabled: true
    allowed_types: []
"#,
    );
    assert!(
        deny_all
            .iter()
            .filter(|(code, _, _)| code == "L018")
            .all(|(_, severity, _)| severity == "info"),
        "{deny_all:?}"
    );

    let contradictory = findings_of(
        r#"hushspec: "0.1.0"
name: contradictory
rules:
  computer_use:
    enabled: true
    mode: guardrail
    allowed_actions: ["input.inject"]
  input_injection:
    enabled: true
    allowed_types: []
"#,
    );
    let (_, severity, path) = find(&contradictory, "L018").expect("L018");
    assert_eq!(severity, "warning");
    assert_eq!(path, "rules.input_injection.allowed_types");
}

#[test]
fn l019_is_an_error_and_fails_the_run_without_fail_on_warnings() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(
        tmp.path(),
        "unreachable.yaml",
        r#"hushspec: "0.1.0"
name: unreachable-posture
extensions:
  posture:
    initial: normal
    states:
      normal: {}
      quarantine: {}
    transitions: []
"#,
    );

    h2h()
        .arg("lint")
        .arg(&policy)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("error[L019]"))
        .stdout(predicate::str::contains(
            "extensions.posture.states.quarantine is unreachable",
        ));
}

#[test]
fn l019_locates_an_unreachable_state_at_its_own_key() {
    let findings = findings_of(
        r#"hushspec: "0.1.0"
name: unreachable-posture
extensions:
  posture:
    initial: normal
    states:
      normal: {}
      quarantine: {}
    transitions: []
"#,
    );
    let (_, severity, path) = find(&findings, "L019").expect("L019");
    assert_eq!(severity, "error");
    assert_eq!(path, "extensions.posture.states.quarantine");
}

#[test]
fn l020_reports_a_window_that_narrows_nothing() {
    let findings = findings_of(
        r#"hushspec: "0.1.0"
name: inert-window
rules:
  egress:
    when:
      time_window:
        start: "00:00"
        end: "00:00"
    allow: ["api.example.com"]
    default: block
"#,
    );
    let (_, severity, path) = find(&findings, "L020").expect("L020");
    assert_eq!(severity, "info");
    assert_eq!(path, "rules.egress.when.time_window.start");
}

/// `--fail-on-warnings` is the CI gate. An `info`-only run must still pass it,
/// or the deny-all presets (`rulesets/panic.yaml`, `rulesets/strict.yaml`)
/// could not be gated at all.
#[test]
fn info_only_findings_do_not_fail_the_warning_gate() {
    let tmp = TempDir::new().unwrap();
    let policy = write_policy(
        tmp.path(),
        "deny-all.yaml",
        r#"hushspec: "0.1.0"
name: deny-all
rules:
  forbidden_paths:
    patterns: ["**"]
  shell_commands:
    forbidden_patterns: [".*"]
  computer_use:
    enabled: true
    mode: fail_closed
    allowed_actions: []
  input_injection:
    enabled: true
    allowed_types: []
  secret_patterns:
    patterns:
      - name: aws
        pattern: "(AKIA|ASIA)[0-9A-Z]{16}"
        severity: critical
"#,
    );

    h2h()
        .arg("lint")
        .arg("--fail-on-warnings")
        .arg(&policy)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("info[L016]"))
        .stdout(predicate::str::contains("info[L018]"));
}

/// The gate the CI job runs. Kept here so a new lint that the shipped policies
/// trip is caught by `cargo test`, not by a red pipeline.
#[test]
fn every_strictly_gated_shipped_policy_lints_clean() {
    let root = workspace_root();
    let mut cmd = h2h();
    cmd.arg("lint").arg("--fail-on-warnings");
    for entry in fs::read_dir(root.join("rulesets")).unwrap() {
        let path = entry.unwrap().path();
        // permissive.yaml is gated on errors only; it exists to permit.
        if path.extension().is_some_and(|ext| ext == "yaml")
            && path
                .file_name()
                .is_some_and(|name| name != "permissive.yaml")
        {
            cmd.arg(path);
        }
    }
    for vertical in fs::read_dir(root.join("library")).unwrap() {
        let vertical = vertical.unwrap().path();
        if !vertical.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&vertical).unwrap() {
            let path = entry.unwrap().path();
            if path
                .extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
            {
                cmd.arg(path);
            }
        }
    }
    cmd.assert().code(0);
}

#[test]
fn permissive_yaml_reports_warnings_but_no_errors() {
    let policy = workspace_root().join("rulesets/permissive.yaml");
    h2h().arg("lint").arg(&policy).assert().code(0);
    h2h()
        .arg("lint")
        .arg("--fail-on-warnings")
        .arg(&policy)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("warning[L017]"));
}
