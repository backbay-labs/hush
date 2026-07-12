use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Returns the workspace root (two levels up from this crate).
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

fn write_file(dir: &TempDir, name: &str, contents: &str) -> PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, contents).unwrap();
    path
}

const EVAL_POLICY: &str = r#"hushspec: "0.1.0"
name: "eval-fixture"
rules:
  egress:
    allow:
      - "api.github.com"
    default: block
  tool_access:
    block:
      - "shell_exec"
    require_confirmation:
      - "deploy"
    default: allow
"#;

#[test]
fn eval_allow_exits_0() {
    let dir = TempDir::new().unwrap();
    let policy = write_file(&dir, "policy.yaml", EVAL_POLICY);
    h2h()
        .arg("eval")
        .arg(&policy)
        .args(["--type", "egress", "--target", "api.github.com"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("ALLOW"))
        .stdout(predicate::str::contains("rules.egress.allow"));
}

#[test]
fn eval_deny_exits_1() {
    let dir = TempDir::new().unwrap();
    let policy = write_file(&dir, "policy.yaml", EVAL_POLICY);
    h2h()
        .arg("eval")
        .arg(&policy)
        .args(["--type", "egress", "--target", "evil.example.com"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("DENY"))
        .stdout(predicate::str::contains("rules.egress.default"));
}

#[test]
fn eval_warn_exits_4() {
    let dir = TempDir::new().unwrap();
    let policy = write_file(&dir, "policy.yaml", EVAL_POLICY);
    h2h()
        .arg("eval")
        .arg(&policy)
        .args(["--type", "tool_call", "--target", "deploy"])
        .assert()
        .code(4)
        .stdout(predicate::str::contains("WARN"))
        .stdout(predicate::str::contains(
            "rules.tool_access.require_confirmation",
        ));
}

#[test]
fn eval_missing_policy_exits_2() {
    h2h()
        .arg("eval")
        .arg("no-such-policy.yaml")
        .args(["--type", "egress", "--target", "example.com"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("file not found"));
}

#[test]
fn eval_invalid_policy_exits_2() {
    let dir = TempDir::new().unwrap();
    let policy = write_file(&dir, "policy.yaml", "hushspec: \"9.9.9\"\n");
    h2h()
        .arg("eval")
        .arg(&policy)
        .args(["--type", "egress", "--target", "example.com"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("policy failed validation"));
}

#[test]
fn eval_builtin_policy_reference() {
    // rulesets/permissive.yaml allows egress "*" with default allow.
    h2h()
        .arg("eval")
        .arg("builtin:permissive")
        .args(["--type", "egress", "--target", "example.com"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("ALLOW"));
}

#[test]
fn eval_resolves_extends_chain() {
    let dir = TempDir::new().unwrap();
    write_file(
        &dir,
        "base.yaml",
        "hushspec: \"0.1.0\"\nrules:\n  egress:\n    default: block\n",
    );
    let child = write_file(
        &dir,
        "child.yaml",
        "hushspec: \"0.1.0\"\nextends: ./base.yaml\nrules:\n  egress:\n    allow:\n      - \"api.github.com\"\n",
    );
    h2h()
        .arg("eval")
        .arg(&child)
        .args(["--type", "egress", "--target", "api.github.com"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("rules.egress.allow"));
}

#[test]
fn eval_unknown_action_type_allows_with_stderr_note() {
    // The reference evaluator allows unknown action types ("no reference
    // evaluator rule for this action type"); the CLI mirrors that and
    // surfaces likely typos on stderr without changing stdout or the code.
    let dir = TempDir::new().unwrap();
    let policy = write_file(&dir, "policy.yaml", EVAL_POLICY);
    h2h()
        .arg("eval")
        .arg(&policy)
        .args(["--type", "frobnicate", "--target", "anything"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("ALLOW"))
        .stderr(predicate::str::contains("not a reference action type"));
}

const CONTENT_POLICY: &str = r#"hushspec: "0.1.0"
name: "content-fixture"
rules:
  secret_patterns:
    patterns:
      - name: "aws-key"
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
  tool_access:
    max_args_size: 64
    default: allow
"#;

#[test]
fn eval_content_flag_triggers_secret_patterns() {
    let dir = TempDir::new().unwrap();
    let policy = write_file(&dir, "policy.yaml", CONTENT_POLICY);
    h2h()
        .arg("eval")
        .arg(&policy)
        .args([
            "--type",
            "file_write",
            "--target",
            "/tmp/creds.txt",
            "--content",
            "key = AKIAABCDEFGHIJKLMNOP",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains(
            "rules.secret_patterns.patterns.aws-key",
        ));
}

#[test]
fn eval_content_file_flag_reads_content() {
    let dir = TempDir::new().unwrap();
    let policy = write_file(&dir, "policy.yaml", CONTENT_POLICY);
    let body = write_file(&dir, "body.txt", "key = AKIAABCDEFGHIJKLMNOP");
    h2h()
        .arg("eval")
        .arg(&policy)
        .args(["--type", "file_write", "--target", "/tmp/creds.txt"])
        .arg("--content-file")
        .arg(&body)
        .assert()
        .code(1)
        .stdout(predicate::str::contains(
            "rules.secret_patterns.patterns.aws-key",
        ));
}

#[test]
fn eval_args_size_triggers_max_args_size() {
    let dir = TempDir::new().unwrap();
    let policy = write_file(&dir, "policy.yaml", CONTENT_POLICY);
    h2h()
        .arg("eval")
        .arg(&policy)
        .args([
            "--type",
            "tool_call",
            "--target",
            "search",
            "--args-size",
            "65",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("rules.tool_access.max_args_size"));
}

#[test]
fn eval_content_conflicts_with_content_file() {
    let dir = TempDir::new().unwrap();
    let policy = write_file(&dir, "policy.yaml", CONTENT_POLICY);
    h2h()
        .arg("eval")
        .arg(&policy)
        .args([
            "--type",
            "file_write",
            "--content",
            "x",
            "--content-file",
            "body.txt",
        ])
        .assert()
        .code(2);
}

const ORIGINS_POLICY: &str = r#"hushspec: "0.1.0"
name: "origins-fixture"
rules:
  egress:
    allow:
      - "api.github.com"
    default: block
extensions:
  origins:
    profiles:
      - id: "public-channel"
        match:
          visibility: "public"
        egress:
          block:
            - "api.github.com"
          default: block
"#;

const POSTURE_POLICY: &str = r#"hushspec: "0.1.0"
name: "posture-fixture"
extensions:
  posture:
    initial: "normal"
    states:
      normal:
        capabilities:
          - "egress"
      lockdown:
        capabilities: []
    transitions:
      - from: "normal"
        to: "lockdown"
        on: "critical_violation"
"#;

#[test]
fn eval_origin_flags_select_profile() {
    let dir = TempDir::new().unwrap();
    let policy = write_file(&dir, "policy.yaml", ORIGINS_POLICY);
    h2h()
        .arg("eval")
        .arg(&policy)
        .args(["--type", "egress", "--target", "api.github.com"])
        .args(["--origin", "visibility=public"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("origin:  public-channel"))
        .stdout(predicate::str::contains(
            "extensions.origins.profiles.public-channel.egress.block",
        ));
}

#[test]
fn eval_without_origin_uses_base_rules() {
    let dir = TempDir::new().unwrap();
    let policy = write_file(&dir, "policy.yaml", ORIGINS_POLICY);
    h2h()
        .arg("eval")
        .arg(&policy)
        .args(["--type", "egress", "--target", "api.github.com"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("rules.egress.allow"));
}

#[test]
fn eval_posture_state_denies_missing_capability() {
    let dir = TempDir::new().unwrap();
    let policy = write_file(&dir, "policy.yaml", POSTURE_POLICY);
    h2h()
        .arg("eval")
        .arg(&policy)
        .args(["--type", "egress", "--target", "example.com"])
        .args(["--posture", "lockdown"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains(
            "extensions.posture.states.lockdown.capabilities",
        ));
}

#[test]
fn eval_posture_signal_reports_transition() {
    let dir = TempDir::new().unwrap();
    let policy = write_file(&dir, "policy.yaml", POSTURE_POLICY);
    h2h()
        .arg("eval")
        .arg(&policy)
        .args(["--type", "egress", "--target", "example.com"])
        .args(["--signal", "critical_violation"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("posture: normal -> lockdown"));
}

#[test]
fn eval_action_json_evaluates() {
    let dir = TempDir::new().unwrap();
    let policy = write_file(&dir, "policy.yaml", EVAL_POLICY);
    h2h()
        .arg("eval")
        .arg(&policy)
        .args([
            "--action-json",
            r#"{"type": "tool_call", "target": "deploy"}"#,
        ])
        .assert()
        .code(4)
        .stdout(predicate::str::contains("WARN"));
}

#[test]
fn eval_action_file_evaluates() {
    let dir = TempDir::new().unwrap();
    let policy = write_file(&dir, "policy.yaml", EVAL_POLICY);
    let action = write_file(
        &dir,
        "action.yaml",
        "type: egress\ntarget: api.github.com\n",
    );
    let mut cmd = h2h();
    cmd.arg("eval")
        .arg(&policy)
        .arg("--action-file")
        .arg(&action);
    cmd.assert()
        .code(0)
        .stdout(predicate::str::contains("ALLOW"));
}

#[test]
fn eval_action_from_stdin() {
    let dir = TempDir::new().unwrap();
    let policy = write_file(&dir, "policy.yaml", EVAL_POLICY);
    h2h()
        .arg("eval")
        .arg(&policy)
        .args(["--action-file", "-"])
        .write_stdin("type: egress\ntarget: evil.example.com\n")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("DENY"));
}

#[test]
fn eval_action_json_conflicts_with_field_flags() {
    let dir = TempDir::new().unwrap();
    let policy = write_file(&dir, "policy.yaml", EVAL_POLICY);
    h2h()
        .arg("eval")
        .arg(&policy)
        .args(["--action-json", r#"{"type": "egress"}"#, "--type", "egress"])
        .assert()
        .code(2);
}

#[test]
fn eval_action_json_rejects_unknown_fields() {
    let dir = TempDir::new().unwrap();
    let policy = write_file(&dir, "policy.yaml", EVAL_POLICY);
    h2h()
        .arg("eval")
        .arg(&policy)
        .args(["--action-json", r#"{"type": "egress", "bogus": 1}"#])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid action"));
}
