//! Integration coverage for `resolve`, `schema`, `completions`, `version`,
//! `diff --fail-on`, stdin input for `validate`/`lint`/`fmt`, and `fmt`'s
//! comment safety.

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

fn write(dir: &Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, content).unwrap();
    path
}

const SIMPLE_POLICY: &str = r#"hushspec: "0.1.0"
name: simple
rules:
  egress:
    allow:
      - "z-domain.com"
      - "a-domain.com"
    block: []
    default: block
"#;

// ---------------------------------------------------------------- resolve --

#[test]
fn resolve_consumes_the_extends_chain() {
    let tmp = TempDir::new().unwrap();
    let base = write(
        tmp.path(),
        "base.yaml",
        r#"hushspec: "0.1.0"
name: base
rules:
  forbidden_paths:
    patterns:
      - "**/.env"
"#,
    );
    let child = write(
        tmp.path(),
        "child.yaml",
        &format!(
            r#"hushspec: "0.1.0"
name: child
extends: "{}"
merge_strategy: merge
rules:
  egress:
    allow:
      - "child.example.com"
    block: []
    default: block
"#,
            base.file_name().unwrap().to_string_lossy()
        ),
    );

    let output = h2h()
        .arg("resolve")
        .arg(child.to_str().unwrap())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let yaml = String::from_utf8(output).unwrap();
    // Core spec 2.3: both resolution instructions are consumed, so what the
    // command prints is what `Resolution.spec` holds -- a document that says
    // what the policy permits and nothing about how it was assembled.
    assert!(
        !yaml.contains("extends:"),
        "extends should be consumed by resolution:\n{yaml}"
    );
    assert!(
        !yaml.contains("merge_strategy:"),
        "merge_strategy should be consumed by resolution:\n{yaml}"
    );
    assert!(yaml.contains("child.example.com"), "{yaml}");
    assert!(
        yaml.contains("**/.env"),
        "rule blocks only the parent defines should survive the merge:\n{yaml}"
    );

    // The printed document must itself be a valid HushSpec document.
    h2h()
        .arg("validate")
        .arg("-")
        .write_stdin(yaml)
        .assert()
        .success();
}

#[test]
fn resolve_json_format_emits_an_object() {
    let output = h2h()
        .arg("resolve")
        .arg("--format")
        .arg("json")
        .arg("rulesets/default.yaml")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(parsed["hushspec"], "0.1.0");
    assert!(parsed["rules"].is_object());
}

#[test]
fn resolve_accepts_builtin_references() {
    h2h()
        .arg("resolve")
        .arg("builtin:strict")
        .assert()
        .success()
        .stdout(predicate::str::contains("hushspec:"));
}

#[test]
fn resolve_missing_file_exits_2() {
    h2h()
        .arg("resolve")
        .arg("no-such-policy.yaml")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("file not found"));
}

#[test]
fn resolve_unresolvable_extends_exits_1() {
    let tmp = TempDir::new().unwrap();
    let policy = write(
        tmp.path(),
        "dangling.yaml",
        "hushspec: \"0.1.0\"\nname: dangling\nextends: \"missing-parent.yaml\"\n",
    );

    h2h()
        .arg("resolve")
        .arg(policy.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("failed to resolve"));
}

#[test]
fn resolve_strict_fails_on_extension_warnings() {
    let tmp = TempDir::new().unwrap();
    let policy = write(
        tmp.path(),
        "posture.yaml",
        r#"hushspec: "0.1.0"
name: posture-warnings
extensions:
  posture:
    initial: standard
    states:
      standard:
        capabilities: [not_a_real_capability]
        budgets:
          not_a_real_budget: 3
    transitions: []
rules:
  egress:
    allow: []
    block: []
    default: block
"#,
    );

    // Without --strict the document still resolves and prints.
    h2h()
        .arg("resolve")
        .arg(policy.to_str().unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains("unknown capability"));

    h2h()
        .arg("resolve")
        .arg("--strict")
        .arg(policy.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("unknown capability"))
        .stderr(predicate::str::contains("strict mode"));
}

// ----------------------------------------------------------------- schema --

#[test]
fn schema_prints_a_schema_by_short_name() {
    let output = h2h()
        .arg("schema")
        .arg("core")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        parsed["$id"],
        "https://hushspec.dev/schemas/hushspec-core.v1.schema.json"
    );
}

#[test]
fn schema_output_matches_the_file_on_disk() {
    for (name, file) in [
        ("core", "hushspec-core.v1.schema.json"),
        ("posture", "hushspec-posture.v1.schema.json"),
        ("origins", "hushspec-origins.v1.schema.json"),
        ("detection", "hushspec-detection.v1.schema.json"),
        ("evaluator-test", "hushspec-evaluator-test.v1.schema.json"),
        ("receipt", "hushspec-receipt.v1.schema.json"),
        ("signature", "hushspec-signature.v1.schema.json"),
        ("keyring", "hushspec-keyring.v1.schema.json"),
    ] {
        let output = h2h()
            .arg("schema")
            .arg(name)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let on_disk = fs::read_to_string(workspace_root().join("schemas").join(file)).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            on_disk,
            "{name} differs from schemas/{file}"
        );
    }
}

#[test]
fn schema_accepts_the_published_file_name() {
    h2h()
        .arg("schema")
        .arg("hushspec-receipt.v1.schema.json")
        .assert()
        .success()
        .stdout(predicate::str::contains("hushspec-receipt.v1.schema.json"));
}

#[test]
fn schema_list_names_every_schema() {
    h2h()
        .arg("schema")
        .arg("--list")
        .assert()
        .success()
        .stdout(predicate::str::contains("core"))
        .stdout(predicate::str::contains("evaluator-test"))
        .stdout(predicate::str::contains("signature"));
}

#[test]
fn schema_list_json_is_machine_readable() {
    let output = h2h()
        .arg("schema")
        .arg("--list")
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let entries = parsed.as_array().expect("list should be a JSON array");
    // Counted from `schemas/` rather than hardcoded: the published set grows,
    // and a stale literal here would fail every PR that adds a schema instead
    // of catching the thing this test is for -- a schema on disk that never
    // made it into the embedded module.
    let published = std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../../schemas"))
        .expect("schemas/ is readable")
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .ends_with(".schema.json")
        })
        .count();
    assert_eq!(
        entries.len(),
        published,
        "h2h schema --list is missing a schema"
    );
    for expected in [
        "core",
        "hash-vector",
        "framework-registry",
        "error-codes",
        "merge-vector",
        "conformance-report",
    ] {
        assert!(
            entries.iter().any(|e| e["name"] == expected),
            "{expected} is missing from h2h schema --list"
        );
    }
}

#[test]
fn schema_unknown_name_exits_2() {
    h2h()
        .arg("schema")
        .arg("not-a-schema")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown schema"));
}

#[test]
fn schema_without_a_name_or_list_is_a_usage_error() {
    h2h().arg("schema").assert().code(2);
}

// ------------------------------------------------------------ completions --

#[test]
fn completions_generate_for_every_supported_shell() {
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let output = h2h()
            .arg("completions")
            .arg(shell)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let script = String::from_utf8(output).unwrap();
        assert!(!script.is_empty(), "{shell} completion script was empty");
        assert!(
            script.contains("h2h"),
            "{shell} completion script does not mention h2h"
        );
        assert!(
            script.contains("resolve"),
            "{shell} completion script is missing the resolve subcommand"
        );
    }
}

#[test]
fn completions_reject_an_unknown_shell() {
    h2h().arg("completions").arg("tcsh").assert().code(2);
}

// ---------------------------------------------------------------- version --

#[test]
fn version_subcommand_reports_build_metadata() {
    h2h()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")))
        .stdout(predicate::str::contains("spec version"))
        .stdout(predicate::str::contains(hushspec::HUSHSPEC_VERSION));
}

#[test]
fn version_json_contains_every_documented_field() {
    let output = h2h()
        .arg("version")
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(parsed["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(parsed["spec_version"], hushspec::HUSHSPEC_VERSION);
    assert!(
        parsed["supported_spec_versions"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
    );
    assert!(parsed["git_sha"].is_string());
    assert!(parsed["target"].is_string());
}

/// Adding a `version` subcommand must not shadow clap's `--version` flag.
#[test]
fn version_flag_still_works() {
    h2h()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

// --------------------------------------------------------- diff --fail-on --

const DENY_POLICY: &str = r#"hushspec: "0.1.0"
name: strictish
rules:
  forbidden_paths:
    patterns:
      - "/etc/passwd"
"#;

const ALLOW_POLICY: &str = r#"hushspec: "0.1.0"
name: looser
rules:
  forbidden_paths:
    patterns: []
"#;

#[test]
fn diff_without_fail_on_still_exits_0() {
    let tmp = TempDir::new().unwrap();
    let old = write(tmp.path(), "old.yaml", DENY_POLICY);
    let new = write(tmp.path(), "new.yaml", ALLOW_POLICY);

    h2h()
        .arg("diff")
        .arg(old.to_str().unwrap())
        .arg(new.to_str().unwrap())
        .assert()
        .success();
}

#[test]
fn diff_fail_on_relaxed_exits_1_for_a_relaxation() {
    let tmp = TempDir::new().unwrap();
    let old = write(tmp.path(), "old.yaml", DENY_POLICY);
    let new = write(tmp.path(), "new.yaml", ALLOW_POLICY);

    h2h()
        .arg("diff")
        .arg(old.to_str().unwrap())
        .arg(new.to_str().unwrap())
        .arg("--fail-on")
        .arg("relaxed")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("--fail-on relaxed"));

    // The same relaxation must not trip --fail-on tightened.
    h2h()
        .arg("diff")
        .arg(old.to_str().unwrap())
        .arg(new.to_str().unwrap())
        .arg("--fail-on")
        .arg("tightened")
        .assert()
        .success();
}

#[test]
fn diff_fail_on_tightened_exits_1_for_a_tightening() {
    let tmp = TempDir::new().unwrap();
    let old = write(tmp.path(), "old.yaml", ALLOW_POLICY);
    let new = write(tmp.path(), "new.yaml", DENY_POLICY);

    h2h()
        .arg("diff")
        .arg(old.to_str().unwrap())
        .arg(new.to_str().unwrap())
        .arg("--fail-on")
        .arg("tightened")
        .assert()
        .code(1);

    h2h()
        .arg("diff")
        .arg(old.to_str().unwrap())
        .arg(new.to_str().unwrap())
        .arg("--fail-on")
        .arg("relaxed")
        .assert()
        .success();
}

#[test]
fn diff_fail_on_any_catches_either_direction() {
    let tmp = TempDir::new().unwrap();
    let old = write(tmp.path(), "old.yaml", DENY_POLICY);
    let new = write(tmp.path(), "new.yaml", ALLOW_POLICY);

    h2h()
        .arg("diff")
        .arg(old.to_str().unwrap())
        .arg(new.to_str().unwrap())
        .arg("--fail-on")
        .arg("any")
        .assert()
        .code(1);
}

#[test]
fn diff_fail_on_is_quiet_when_nothing_changed() {
    let tmp = TempDir::new().unwrap();
    let old = write(tmp.path(), "old.yaml", DENY_POLICY);
    let new = write(tmp.path(), "new.yaml", DENY_POLICY);

    h2h()
        .arg("diff")
        .arg(old.to_str().unwrap())
        .arg(new.to_str().unwrap())
        .arg("--fail-on")
        .arg("any")
        .assert()
        .success();
}

#[test]
fn diff_rejects_an_unknown_fail_on_class() {
    let tmp = TempDir::new().unwrap();
    let old = write(tmp.path(), "old.yaml", DENY_POLICY);
    let new = write(tmp.path(), "new.yaml", ALLOW_POLICY);

    h2h()
        .arg("diff")
        .arg(old.to_str().unwrap())
        .arg(new.to_str().unwrap())
        .arg("--fail-on")
        .arg("sideways")
        .assert()
        .code(2);
}

// ------------------------------------------------------------------ stdin --

#[test]
fn validate_reads_stdin() {
    h2h()
        .arg("validate")
        .arg("-")
        .write_stdin(SIMPLE_POLICY)
        .assert()
        .success()
        .stdout(predicate::str::contains("<stdin>"));
}

#[test]
fn validate_stdin_reports_invalid_documents() {
    h2h()
        .arg("validate")
        .arg("-")
        .write_stdin("name: no-version\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("<stdin>"));
}

#[test]
fn validate_stdin_json_names_the_pseudo_path() {
    let output = h2h()
        .arg("validate")
        .arg("--format")
        .arg("json")
        .arg("-")
        .write_stdin(SIMPLE_POLICY)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(parsed[0]["file"], "<stdin>");
    assert_eq!(parsed[0]["valid"], true);
}

#[test]
fn validate_stdin_strict_resolves_builtin_extends() {
    h2h()
        .arg("validate")
        .arg("--strict")
        .arg("-")
        .write_stdin("hushspec: \"0.1.0\"\nname: child\nextends: \"builtin:default\"\n")
        .assert()
        .success();
}

#[test]
fn lint_reads_stdin() {
    h2h()
        .arg("lint")
        .arg("-")
        .write_stdin(SIMPLE_POLICY)
        .assert()
        .success()
        .stdout(predicate::str::contains("<stdin>"));
}

#[test]
fn lint_fix_refuses_stdin() {
    h2h()
        .arg("lint")
        .arg("-")
        .arg("--fix")
        .write_stdin(SIMPLE_POLICY)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot rewrite stdin"));
}

#[test]
fn lint_dry_run_accepts_stdin() {
    h2h()
        .arg("lint")
        .arg("-")
        .arg("--dry-run")
        .write_stdin(SIMPLE_POLICY)
        .assert()
        .success();
}

#[test]
fn fmt_stdin_writes_the_formatted_document_to_stdout() {
    let output = h2h()
        .arg("fmt")
        .arg("-")
        .write_stdin(SIMPLE_POLICY)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let formatted = String::from_utf8(output).unwrap();
    assert!(
        formatted.starts_with("hushspec:"),
        "stdout should carry only the document:\n{formatted}"
    );
    let a = formatted.find("a-domain.com").unwrap();
    let z = formatted.find("z-domain.com").unwrap();
    assert!(a < z, "entries should be sorted:\n{formatted}");
}

#[test]
fn fmt_stdin_check_reports_without_writing() {
    h2h()
        .arg("fmt")
        .arg("--check")
        .arg("-")
        .write_stdin(SIMPLE_POLICY)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("<stdin> would be reformatted"));
}

// --------------------------------------------------------- fmt + comments --

const COMMENTED_POLICY: &str = r#"hushspec: "0.1.0"
name: audited
rules:
  # --- 45 CFR 164.312(a)(1): Access Control ---
  forbidden_paths:
    patterns:
      - "**/phi/**"
"#;

#[test]
fn fmt_refuses_to_discard_comments() {
    let tmp = TempDir::new().unwrap();
    let policy = write(tmp.path(), "audited.yaml", COMMENTED_POLICY);

    h2h()
        .arg("fmt")
        .arg(policy.to_str().unwrap())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("refusing to reformat"))
        .stderr(predicate::str::contains("1 comment line(s)"))
        .stderr(predicate::str::contains("line 4"));

    assert_eq!(
        fs::read_to_string(&policy).unwrap(),
        COMMENTED_POLICY,
        "the file must be left untouched"
    );
}

#[test]
fn fmt_check_reports_comments_as_a_skip_not_a_failure() {
    let tmp = TempDir::new().unwrap();
    let policy = write(tmp.path(), "audited.yaml", COMMENTED_POLICY);

    h2h()
        .arg("fmt")
        .arg("--check")
        .arg(policy.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("has comments; would not reformat"));
}

#[test]
fn fmt_strip_comments_rewrites_the_document() {
    let tmp = TempDir::new().unwrap();
    let policy = write(tmp.path(), "audited.yaml", COMMENTED_POLICY);

    h2h()
        .arg("fmt")
        .arg("--strip-comments")
        .arg(policy.to_str().unwrap())
        .assert()
        .success();

    let formatted = fs::read_to_string(&policy).unwrap();
    assert!(
        !formatted.contains("45 CFR"),
        "--strip-comments should drop comments:\n{formatted}"
    );
    assert!(formatted.contains("forbidden_paths:"));
}

#[test]
fn fmt_json_reports_comment_metadata() {
    let tmp = TempDir::new().unwrap();
    let policy = write(tmp.path(), "audited.yaml", COMMENTED_POLICY);

    let output = h2h()
        .arg("fmt")
        .arg("--format")
        .arg("json")
        .arg(policy.to_str().unwrap())
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(parsed[0]["has_comments"], true);
    assert_eq!(parsed[0]["skipped"], true);
    assert_eq!(parsed[0]["comment_count"], 1);
    assert_eq!(parsed[0]["first_comment_line"], 4);
    assert_eq!(
        fs::read_to_string(&policy).unwrap(),
        COMMENTED_POLICY,
        "JSON output must not write either"
    );
}

/// A leading yaml-language-server modeline is preserved by the formatter, so
/// it must not trigger the comment refusal on its own.
#[test]
fn fmt_still_formats_a_document_whose_only_comment_is_the_modeline() {
    let tmp = TempDir::new().unwrap();
    let policy = write(
        tmp.path(),
        "modeline.yaml",
        &format!(
            "# yaml-language-server: $schema=https://hushspec.dev/schemas/hushspec-core.v1.schema.json\n{SIMPLE_POLICY}"
        ),
    );

    h2h()
        .arg("fmt")
        .arg(policy.to_str().unwrap())
        .assert()
        .success();

    let formatted = fs::read_to_string(&policy).unwrap();
    assert!(formatted.starts_with("# yaml-language-server:"));
}

/// A `#` inside a quoted scalar is data, not a comment.
#[test]
fn fmt_does_not_mistake_hashes_inside_scalars_for_comments() {
    let tmp = TempDir::new().unwrap();
    let policy = write(
        tmp.path(),
        "hashes.yaml",
        r#"hushspec: "0.1.0"
name: hashes
rules:
  shell_commands:
    forbidden_patterns:
      - "curl .*#fragment"
"#,
    );

    h2h()
        .arg("fmt")
        .arg(policy.to_str().unwrap())
        .assert()
        .success();
}

#[test]
fn fmt_stdin_refuses_comments_too() {
    h2h()
        .arg("fmt")
        .arg("-")
        .write_stdin(COMMENTED_POLICY)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("refusing to reformat"));
}
