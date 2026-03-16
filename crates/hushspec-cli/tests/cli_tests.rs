use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Returns the workspace root (two levels up from this crate).
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .unwrap()
        .parent() // workspace root
        .unwrap()
        .to_path_buf()
}

fn hushspec() -> Command {
    let mut cmd = Command::cargo_bin("hushspec").unwrap();
    cmd.current_dir(workspace_root());
    cmd
}

#[test]
fn validate_valid_rulesets() {
    hushspec()
        .arg("validate")
        .arg("rulesets/default.yaml")
        .arg("rulesets/strict.yaml")
        .arg("rulesets/permissive.yaml")
        .assert()
        .success()
        .stdout(predicate::str::contains("\u{2713} rulesets/default.yaml"))
        .stdout(predicate::str::contains("\u{2713} rulesets/strict.yaml"))
        .stdout(predicate::str::contains(
            "\u{2713} rulesets/permissive.yaml",
        ));
}

#[test]
fn validate_valid_fixture() {
    hushspec()
        .arg("validate")
        .arg("fixtures/core/valid/minimal.yaml")
        .assert()
        .success()
        .stdout(predicate::str::contains("\u{2713}"));
}

#[test]
fn validate_invalid_fixture_exits_1() {
    hushspec()
        .arg("validate")
        .arg("fixtures/core/invalid/missing-version.yaml")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\u{2717}"))
        .stdout(predicate::str::contains("error[E001]"));
}

#[test]
fn validate_duplicate_patterns() {
    hushspec()
        .arg("validate")
        .arg("fixtures/core/invalid/duplicate-pattern-names.yaml")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("error[E003]"));
}

#[test]
fn validate_missing_file_exits_2() {
    hushspec()
        .arg("validate")
        .arg("this-file-does-not-exist.yaml")
        .assert()
        .code(2);
}

#[test]
fn validate_json_output() {
    let output = hushspec()
        .arg("validate")
        .arg("--format")
        .arg("json")
        .arg("rulesets/default.yaml")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed.is_array(), "JSON output should be an array");
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["valid"], true);
}

#[test]
fn validate_json_output_invalid() {
    let output = hushspec()
        .arg("validate")
        .arg("--format")
        .arg("json")
        .arg("fixtures/core/invalid/missing-version.yaml")
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed.is_array(), "JSON output should be an array");
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["valid"], false);
    assert_eq!(arr[0]["errors"][0]["code"], "E001");
}

#[test]
fn validate_json_output_multiple_files_is_valid_json_array() {
    let output = hushspec()
        .arg("validate")
        .arg("--format")
        .arg("json")
        .arg("rulesets/default.yaml")
        .arg("fixtures/core/invalid/missing-version.yaml")
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = parsed.as_array().expect("JSON output should be an array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["valid"], true);
    assert_eq!(arr[1]["valid"], false);
}

#[test]
fn validate_strict_checks_full_extends_resolution() {
    let tmp = TempDir::new().unwrap();
    let base_path = tmp.path().join("base.yaml");
    let child_path = tmp.path().join("child.yaml");

    fs::write(
        &base_path,
        r#"name: invalid-base
rules:
  egress:
    default: block
"#,
    )
    .unwrap();
    fs::write(
        &child_path,
        format!(
            "hushspec: \"0.1.0\"\nextends: {}\n",
            base_path.file_name().unwrap().to_string_lossy()
        ),
    )
    .unwrap();

    hushspec()
        .arg("validate")
        .arg("--strict")
        .arg(child_path.to_str().unwrap())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("error[E010]"))
        .stdout(predicate::str::contains("extends resolution failed"));
}

#[test]
fn test_egress_fixtures() {
    hushspec()
        .arg("test")
        .arg("fixtures/core/evaluation/egress.test.yaml")
        .assert()
        .success()
        .stdout(predicate::str::contains("5 passed, 0 failed"));
}

#[test]
fn test_fixtures_directory() {
    hushspec()
        .arg("test")
        .arg("--fixtures")
        .arg("fixtures/core/evaluation")
        .assert()
        .success()
        .stdout(predicate::str::contains("passed, 0 failed"));
}

#[test]
fn test_tap_output() {
    hushspec()
        .arg("test")
        .arg("--format")
        .arg("tap")
        .arg("fixtures/core/evaluation/egress.test.yaml")
        .assert()
        .success()
        .stdout(predicate::str::contains("TAP version 14"))
        .stdout(predicate::str::contains("1..5"))
        .stdout(predicate::str::contains("ok 1 -"));
}

#[test]
fn test_json_output() {
    hushspec()
        .arg("test")
        .arg("--format")
        .arg("json")
        .arg("fixtures/core/evaluation/egress.test.yaml")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"passed\":"))
        .stdout(predicate::str::contains("\"failed\":"));
}

#[test]
fn init_creates_policy_and_tests() {
    let tmp = TempDir::new().unwrap();
    hushspec()
        .arg("init")
        .arg("--preset")
        .arg("default")
        .arg("--dir")
        .arg(tmp.path().to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Created"));

    let policy = tmp.path().join(".hushspec/policy.yaml");
    let test_file = tmp.path().join(".hushspec/tests/policy.test.yaml");
    assert!(policy.exists(), "policy.yaml should be created");
    assert!(test_file.exists(), "policy.test.yaml should be created");

    // Validate the generated policy
    hushspec()
        .arg("validate")
        .arg(policy.to_str().unwrap())
        .assert()
        .success();

    // Run the generated tests
    hushspec()
        .arg("test")
        .arg("--fixtures")
        .arg(tmp.path().join(".hushspec/tests").to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("3 passed, 0 failed"));
}

#[test]
fn init_strict_preset() {
    let tmp = TempDir::new().unwrap();
    hushspec()
        .arg("init")
        .arg("--preset")
        .arg("strict")
        .arg("--dir")
        .arg(tmp.path().to_str().unwrap())
        .assert()
        .success();

    let content = fs::read_to_string(tmp.path().join(".hushspec/policy.yaml")).unwrap();
    assert!(
        content.contains("default: block"),
        "strict preset should block by default"
    );

    // Validate and test
    hushspec()
        .arg("test")
        .arg("--fixtures")
        .arg(tmp.path().join(".hushspec/tests").to_str().unwrap())
        .assert()
        .success();
}

#[test]
fn init_permissive_preset() {
    let tmp = TempDir::new().unwrap();
    hushspec()
        .arg("init")
        .arg("--preset")
        .arg("permissive")
        .arg("--dir")
        .arg(tmp.path().to_str().unwrap())
        .assert()
        .success();

    let content = fs::read_to_string(tmp.path().join(".hushspec/policy.yaml")).unwrap();
    assert!(
        content.contains("default: allow"),
        "permissive preset should allow by default"
    );

    // Run tests
    hushspec()
        .arg("test")
        .arg("--fixtures")
        .arg(tmp.path().join(".hushspec/tests").to_str().unwrap())
        .assert()
        .success();
}

#[test]
fn init_fails_if_already_exists() {
    let tmp = TempDir::new().unwrap();
    // First init
    hushspec()
        .arg("init")
        .arg("--dir")
        .arg(tmp.path().to_str().unwrap())
        .assert()
        .success();

    // Second init should fail
    hushspec()
        .arg("init")
        .arg("--dir")
        .arg(tmp.path().to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn lint_detects_issues_in_crafted_policy() {
    let tmp = TempDir::new().unwrap();
    let policy_path = tmp.path().join("lint-test.yaml");
    fs::write(
        &policy_path,
        r#"hushspec: "0.1.0"
name: lint-test
rules:
  egress:
    allow:
      - "*"
      - "api.github.com"
      - "api.github.com"
    block:
      - "api.github.com"
    default: block
  tool_access:
    allow:
      - "bad_tool"
    block:
      - "bad_tool"
    default: allow
  remote_desktop_channels:
    enabled: false
  input_injection:
    enabled: false
"#,
    )
    .unwrap();

    hushspec()
        .arg("lint")
        .arg(policy_path.to_str().unwrap())
        .assert()
        .success()
        // L004: overly broad egress
        .stdout(predicate::str::contains("L004"))
        // L008: duplicate pattern
        .stdout(predicate::str::contains("L008"))
        // L010: unreachable allow
        .stdout(predicate::str::contains("L010"))
        // L007: explicitly disabled rule blocks
        .stdout(predicate::str::contains(
            "rules.remote_desktop_channels is explicitly disabled",
        ))
        .stdout(predicate::str::contains(
            "rules.input_injection is explicitly disabled",
        ))
        // L009: missing secret patterns
        .stdout(predicate::str::contains("L009"));
}

#[test]
fn lint_json_output() {
    let tmp = TempDir::new().unwrap();
    let policy_path = tmp.path().join("lint-json.yaml");
    fs::write(
        &policy_path,
        r#"hushspec: "0.1.0"
name: lint-json-test
rules:
  egress:
    allow:
      - "*"
    block: []
    default: block
"#,
    )
    .unwrap();

    let output = hushspec()
        .arg("lint")
        .arg("--format")
        .arg("json")
        .arg(policy_path.to_str().unwrap())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    // Validate it's valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed.is_array(), "JSON output should be an array");
    let arr = parsed.as_array().unwrap();
    assert!(!arr.is_empty(), "should have at least one file result");
    let first = &arr[0];
    assert!(
        first.get("findings").is_some(),
        "should have findings field"
    );
    let findings = first["findings"].as_array().unwrap();
    assert!(!findings.is_empty(), "should have at least one finding");
    // Each finding should have code, severity, message, location
    let f = &findings[0];
    assert!(f.get("code").is_some());
    assert!(f.get("severity").is_some());
    assert!(f.get("message").is_some());
    assert!(f.get("location").is_some());
}

#[test]
fn lint_clean_policy_exits_0() {
    // The default ruleset should lint cleanly (no errors/warnings that cause nonzero)
    // Note: it may produce info-level findings which are fine
    hushspec()
        .arg("lint")
        .arg("rulesets/default.yaml")
        .assert()
        .success();
}

#[test]
fn lint_fail_on_warnings() {
    let tmp = TempDir::new().unwrap();
    let policy_path = tmp.path().join("warn-test.yaml");
    fs::write(
        &policy_path,
        r#"hushspec: "0.1.0"
name: warn-test
rules:
  egress:
    allow:
      - "*"
    block: []
    default: block
"#,
    )
    .unwrap();

    // Without --fail-on-warnings, should exit 0 (warnings are not failures)
    hushspec()
        .arg("lint")
        .arg(policy_path.to_str().unwrap())
        .assert()
        .success();

    // With --fail-on-warnings, should exit 1
    hushspec()
        .arg("lint")
        .arg("--fail-on-warnings")
        .arg(policy_path.to_str().unwrap())
        .assert()
        .code(1);
}

#[test]
fn keygen_writes_private_key_with_restrictive_permissions() {
    let tmp = TempDir::new().unwrap();

    hushspec()
        .arg("keygen")
        .arg("--output-dir")
        .arg(tmp.path().to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Created"));

    let private_key = tmp.path().join("hushspec.key");
    let public_key = tmp.path().join("hushspec.pub");
    assert!(private_key.exists(), "private key should exist");
    assert!(public_key.exists(), "public key should exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(&private_key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "private key should be created with 0600");
    }
}

#[test]
fn diff_detects_decision_changes() {
    let tmp = TempDir::new().unwrap();

    let old_path = tmp.path().join("old.yaml");
    fs::write(
        &old_path,
        r#"hushspec: "0.1.0"
name: old
rules:
  egress:
    allow:
      - "api.github.com"
    block: []
    default: allow
  tool_access:
    allow: []
    block: []
    require_confirmation: []
    default: allow
"#,
    )
    .unwrap();

    let new_path = tmp.path().join("new.yaml");
    fs::write(
        &new_path,
        r#"hushspec: "0.1.0"
name: new
rules:
  egress:
    allow:
      - "api.github.com"
    block: []
    default: block
  tool_access:
    allow: []
    block:
      - shell_exec
    require_confirmation: []
    default: block
"#,
    )
    .unwrap();

    hushspec()
        .arg("diff")
        .arg(old_path.to_str().unwrap())
        .arg(new_path.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Decision changes"));
}

#[test]
fn diff_json_output() {
    let tmp = TempDir::new().unwrap();

    let old_path = tmp.path().join("old.yaml");
    fs::write(
        &old_path,
        r#"hushspec: "0.1.0"
name: old
rules:
  egress:
    allow:
      - "api.github.com"
    block: []
    default: allow
"#,
    )
    .unwrap();

    let new_path = tmp.path().join("new.yaml");
    fs::write(
        &new_path,
        r#"hushspec: "0.1.0"
name: new
rules:
  egress:
    allow:
      - "api.github.com"
    block: []
    default: block
"#,
    )
    .unwrap();

    let output = hushspec()
        .arg("diff")
        .arg("--format")
        .arg("json")
        .arg(old_path.to_str().unwrap())
        .arg(new_path.to_str().unwrap())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed.is_array(), "JSON output should be an array");
    let arr = parsed.as_array().unwrap();
    assert!(!arr.is_empty(), "should have at least one probe result");

    // Each entry should have the expected fields
    let first = &arr[0];
    assert!(first.get("action").is_some());
    assert!(first.get("old_decision").is_some());
    assert!(first.get("new_decision").is_some());
    assert!(first.get("change_type").is_some());
}

#[test]
fn diff_detects_path_allowlist_changes() {
    let tmp = TempDir::new().unwrap();

    let old_path = tmp.path().join("old-allowlist.yaml");
    fs::write(
        &old_path,
        r#"hushspec: "0.1.0"
name: old
rules:
  path_allowlist:
    enabled: true
    read:
      - "/workspace/**"
"#,
    )
    .unwrap();

    let new_path = tmp.path().join("new-allowlist.yaml");
    fs::write(
        &new_path,
        r#"hushspec: "0.1.0"
name: new
rules:
  path_allowlist:
    enabled: true
    read:
      - "/sandbox/**"
"#,
    )
    .unwrap();

    hushspec()
        .arg("diff")
        .arg(old_path.to_str().unwrap())
        .arg(new_path.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Decision changes"))
        .stdout(predicate::str::contains("file_read"));
}

#[test]
fn fmt_check_exits_0_for_already_formatted() {
    let tmp = TempDir::new().unwrap();
    let policy_path = tmp.path().join("formatted.yaml");

    // Write a policy, format it, then check it
    let content = r#"hushspec: "0.1.0"
name: test
rules:
  egress:
    allow:
      - "api.github.com"
    block: []
    default: block
"#;
    fs::write(&policy_path, content).unwrap();

    // First, format it
    hushspec()
        .arg("fmt")
        .arg(policy_path.to_str().unwrap())
        .assert()
        .success();

    // Now check -- should exit 0
    hushspec()
        .arg("fmt")
        .arg("--check")
        .arg(policy_path.to_str().unwrap())
        .assert()
        .success();
}

#[test]
fn fmt_check_exits_1_for_unformatted() {
    let tmp = TempDir::new().unwrap();
    let policy_path = tmp.path().join("unformatted.yaml");

    // Write a policy with tool_access before egress (wrong order)
    let content = r#"hushspec: "0.1.0"
name: unformatted
rules:
  tool_access:
    allow: []
    block: []
    require_confirmation: []
    default: allow
  egress:
    allow:
      - "z-domain.com"
      - "a-domain.com"
    block: []
    default: block
"#;
    fs::write(&policy_path, content).unwrap();

    // Check should exit 1 because the file needs reformatting
    hushspec()
        .arg("fmt")
        .arg("--check")
        .arg(policy_path.to_str().unwrap())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("would be reformatted"));
}

#[test]
fn fmt_diff_shows_changes() {
    let tmp = TempDir::new().unwrap();
    let policy_path = tmp.path().join("diff-test.yaml");

    // Write an unformatted policy
    let content = r#"hushspec: "0.1.0"
name: test
rules:
  tool_access:
    allow: []
    block: []
    require_confirmation: []
    default: allow
  egress:
    allow:
      - "z-domain.com"
      - "a-domain.com"
    block: []
    default: block
"#;
    fs::write(&policy_path, content).unwrap();

    hushspec()
        .arg("fmt")
        .arg("--diff")
        .arg(policy_path.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("---"))
        .stdout(predicate::str::contains("+++"))
        .stdout(predicate::str::contains("@@"));

    // File should not be modified (--diff is read-only)
    let after = fs::read_to_string(&policy_path).unwrap();
    assert_eq!(content, after, "file should not be modified by --diff");
}

#[test]
fn fmt_formats_in_place() {
    let tmp = TempDir::new().unwrap();
    let policy_path = tmp.path().join("reformat.yaml");

    let content = r#"hushspec: "0.1.0"
name: test
rules:
  tool_access:
    allow: []
    block: []
    require_confirmation: []
    default: allow
  egress:
    allow:
      - "z-domain.com"
      - "a-domain.com"
    block: []
    default: block
"#;
    fs::write(&policy_path, content).unwrap();

    // Format in place
    hushspec()
        .arg("fmt")
        .arg(policy_path.to_str().unwrap())
        .assert()
        .success();

    // Now check should pass
    hushspec()
        .arg("fmt")
        .arg("--check")
        .arg(policy_path.to_str().unwrap())
        .assert()
        .success();

    // And the formatted content should have egress before tool_access
    let formatted = fs::read_to_string(&policy_path).unwrap();
    let egress_pos = formatted.find("egress:").unwrap();
    let tool_pos = formatted.find("tool_access:").unwrap();
    assert!(
        egress_pos < tool_pos,
        "egress should come before tool_access in canonical order"
    );
}

#[test]
fn fmt_sorts_and_dedupes_path_allowlist_entries() {
    let tmp = TempDir::new().unwrap();
    let policy_path = tmp.path().join("allowlist.yaml");

    fs::write(
        &policy_path,
        r#"hushspec: "0.1.0"
name: allowlist
rules:
  path_allowlist:
    enabled: true
    read:
      - "/zeta/**"
      - "/alpha/**"
      - "/alpha/**"
    write:
      - "/tmp/**"
      - "/app/**"
      - "/app/**"
    patch:
      - "/patches/z/**"
      - "/patches/a/**"
      - "/patches/a/**"
"#,
    )
    .unwrap();

    hushspec()
        .arg("fmt")
        .arg(policy_path.to_str().unwrap())
        .assert()
        .success();

    let formatted = fs::read_to_string(&policy_path).unwrap();
    assert!(formatted.contains("read:\n      - \"/alpha/**\"\n      - \"/zeta/**\"\n"));
    assert!(formatted.contains("write:\n      - \"/app/**\"\n      - \"/tmp/**\"\n"));
    assert!(formatted.contains("patch:\n      - \"/patches/a/**\"\n      - \"/patches/z/**\"\n"));
}

#[test]
fn fmt_preserves_governance_metadata() {
    let tmp = TempDir::new().unwrap();
    let policy_path = tmp.path().join("metadata.yaml");

    let content = r#"hushspec: "0.1.0"
name: metadata-test
metadata:
  author: "security@example.com"
  approved_by: "ciso@example.com"
  classification: internal
  lifecycle_state: deployed
  policy_version: 7
rules:
  egress:
    allow:
      - "api.github.com"
    block: []
    default: block
"#;
    fs::write(&policy_path, content).unwrap();

    hushspec()
        .arg("fmt")
        .arg(policy_path.to_str().unwrap())
        .assert()
        .success();

    let formatted = fs::read_to_string(&policy_path).unwrap();
    assert!(formatted.contains("metadata:\n"));
    assert!(formatted.contains("author: security@example.com"));
    assert!(formatted.contains("approved_by: ciso@example.com"));
    assert!(formatted.contains("classification: internal"));
    assert!(formatted.contains("lifecycle_state: deployed"));
    assert!(formatted.contains("policy_version: 7"));
}

#[test]
fn panic_activate_creates_sentinel() {
    let tmp = TempDir::new().unwrap();
    let sentinel = tmp.path().join(".hushspec_panic");

    hushspec()
        .arg("panic")
        .arg("activate")
        .arg("--sentinel")
        .arg(sentinel.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("ACTIVATED"));

    assert!(sentinel.exists(), "sentinel file should be created");
}

#[test]
fn panic_deactivate_removes_sentinel() {
    let tmp = TempDir::new().unwrap();
    let sentinel = tmp.path().join(".hushspec_panic");

    // Create sentinel first
    fs::write(&sentinel, "").unwrap();
    assert!(sentinel.exists());

    hushspec()
        .arg("panic")
        .arg("deactivate")
        .arg("--sentinel")
        .arg(sentinel.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("DEACTIVATED"));

    assert!(!sentinel.exists(), "sentinel file should be removed");
}

#[test]
fn panic_deactivate_already_inactive() {
    let tmp = TempDir::new().unwrap();
    let sentinel = tmp.path().join(".hushspec_panic");

    hushspec()
        .arg("panic")
        .arg("deactivate")
        .arg("--sentinel")
        .arg(sentinel.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("already inactive"));
}

#[test]
fn panic_status_active() {
    let tmp = TempDir::new().unwrap();
    let sentinel = tmp.path().join(".hushspec_panic");
    fs::write(&sentinel, "").unwrap();

    hushspec()
        .arg("panic")
        .arg("status")
        .arg("--sentinel")
        .arg(sentinel.to_str().unwrap())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("ACTIVE"));
}

#[test]
fn panic_status_inactive() {
    let tmp = TempDir::new().unwrap();
    let sentinel = tmp.path().join(".hushspec_panic");

    hushspec()
        .arg("panic")
        .arg("status")
        .arg("--sentinel")
        .arg(sentinel.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("INACTIVE"));
}

#[test]
fn validate_panic_policy() {
    hushspec()
        .arg("validate")
        .arg("rulesets/panic.yaml")
        .assert()
        .success()
        .stdout(predicate::str::contains("\u{2713} rulesets/panic.yaml"));
}
