//! Corpus-wide guarantees for `h2h lint --fix`:
//!
//! - Neutrality: fixing never changes any probe's decision, verified via
//!   `h2h diff --format json` (a flat JSON array of probe results, each with
//!   a `change_type` of "unchanged" or one of "tightened"/"relaxed"/
//!   "escalated"/"demoted" -- there is no top-level `"changes"` wrapper).
//! - Idempotence: running `--fix` a second time is a byte-for-byte no-op.
//! - The shipped corpus (below) happens to be fully clean today, so its loop
//!   alone never actually exercises a fix -- every `--fix` call in it is a
//!   no-op and the assertions that follow check nothing.
//!   `fix_is_decision_neutral_and_idempotent_when_a_real_fix_is_applied`
//!   covers that gap using a fixture with a genuine fixable duplicate.
use assert_cmd::Command;

#[test]
fn fix_is_decision_neutral_and_idempotent_for_all_shipped_policies() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let dir = tempfile::tempdir().unwrap();
    for entry in glob_policies(root) {
        let name = entry.file_name().unwrap().to_string_lossy().to_string();
        let copy = dir.path().join(&name);
        std::fs::copy(&entry, &copy).unwrap();

        let _ = Command::cargo_bin("h2h")
            .unwrap()
            .args(["lint", copy.to_str().unwrap(), "--fix"])
            .assert(); // exit code may be nonzero if semantic findings remain -- that's fine

        assert_neutral_and_idempotent(&name, &entry, &copy);
    }
}

/// Regression guard for the gap noted in the module docs: reuses the exact
/// duplicate-pattern fixture from `dry_run_never_writes_and_previews_what_fix_would_do`
/// (a policy with a byte-identical repeated `forbidden_paths` entry) so the
/// same corpus-style flow -- fix, then assert diff-neutrality, then assert
/// idempotence -- runs at least once against a policy that actually changes
/// under `--fix`, rather than only against the always-clean shipped corpus.
#[test]
fn fix_is_decision_neutral_and_idempotent_when_a_real_fix_is_applied() {
    let dir = tempfile::tempdir().unwrap();

    let original = dir.path().join("dupe-original.yaml");
    std::fs::write(
        &original,
        "hushspec: \"0.1.0\"\nname: t\nrules:\n  forbidden_paths:\n    patterns:\n      - \"**/.ssh/**\"\n      - \"**/.aws/**\"\n      - \"**/.ssh/**\"\n",
    )
    .unwrap();
    let copy = dir.path().join("dupe-fixed.yaml");
    std::fs::copy(&original, &copy).unwrap();
    let before = std::fs::read(&copy).unwrap();

    let _ = Command::cargo_bin("h2h")
        .unwrap()
        .args(["lint", copy.to_str().unwrap(), "--fix"])
        .assert();
    assert_ne!(
        before,
        std::fs::read(&copy).unwrap(),
        "fixture should actually change under --fix, otherwise this test is as \
         vacuous as the corpus loop it's meant to backstop"
    );

    assert_neutral_and_idempotent("dupe.yaml", &original, &copy);
}

/// `h2h fmt`'s canonical writer preserves a leading yaml-language-server
/// modeline (see `cmd_fmt::split_modeline`/`format_canonical`), but `--fix`
/// writes through `format_spec` directly on an already-mutated in-memory
/// `HushSpec` rather than through `format_canonical` -- so this exercises the
/// separate rejoin wired into `cmd_lint::run` for that path. Uses the same
/// genuine-duplicate fixture as the neutrality test above so the file
/// actually changes under `--fix`, not just a no-op pass.
#[test]
fn fix_preserves_leading_modeline() {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("modeline.yaml");
    let modeline =
        "# yaml-language-server: $schema=https://hushspec.dev/schemas/hushspec-core.v0.schema.json";
    std::fs::write(
        &policy,
        format!(
            "{modeline}\nhushspec: \"0.1.0\"\nname: t\nrules:\n  forbidden_paths:\n    patterns:\n      - \"**/.ssh/**\"\n      - \"**/.aws/**\"\n      - \"**/.ssh/**\"\n"
        ),
    )
    .unwrap();

    let _ = Command::cargo_bin("h2h")
        .unwrap()
        .args(["lint", policy.to_str().unwrap(), "--fix"])
        .assert();

    let fixed = std::fs::read_to_string(&policy).unwrap();
    assert_eq!(
        fixed.matches("**/.ssh/**").count(),
        1,
        "fixture must actually be fixed, otherwise the modeline assertion below is vacuous: {fixed}"
    );
    assert!(
        fixed.starts_with(&format!("{modeline}\n")),
        "modeline must survive --fix rewriting the file:\n{fixed}"
    );
}

/// Shared by both tests above: `fixed` has already been through `--fix` once.
/// Asserts that doing so did not change any probe's decision relative to
/// `original` (per `h2h diff --format json`, a flat array of probes -- no
/// top-level `"changes"` wrapper), then asserts a second `--fix` on `fixed`
/// is a byte-for-byte no-op.
fn assert_neutral_and_idempotent(name: &str, original: &std::path::Path, fixed: &std::path::Path) {
    let diff = Command::cargo_bin("h2h")
        .unwrap()
        .args([
            "diff",
            original.to_str().unwrap(),
            fixed.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&diff.stdout).unwrap();
    let probes = v.as_array().expect("diff --format json is a flat array");
    assert!(
        !probes.is_empty(),
        "{name}: expected diff to probe something"
    );
    let real_changes: Vec<&serde_json::Value> = probes
        .iter()
        .filter(|p| p["change_type"] != "unchanged")
        .collect();
    assert!(
        real_changes.is_empty(),
        "{name} changed {} decision(s): {:#?}",
        real_changes.len(),
        real_changes
    );

    // Idempotence: second --fix is a byte-for-byte no-op.
    let once = std::fs::read(fixed).unwrap();
    let _ = Command::cargo_bin("h2h")
        .unwrap()
        .args(["lint", fixed.to_str().unwrap(), "--fix"])
        .assert();
    assert_eq!(once, std::fs::read(fixed).unwrap(), "{name} not idempotent");
}

#[test]
fn dry_run_never_writes_and_previews_what_fix_would_do() {
    let dir = tempfile::tempdir().unwrap();

    // A file with a real, provably-fixable duplicate.
    let policy = dir.path().join("dupe.yaml");
    std::fs::write(
        &policy,
        "hushspec: \"0.1.0\"\nname: t\nrules:\n  forbidden_paths:\n    patterns:\n      - \"**/.ssh/**\"\n      - \"**/.aws/**\"\n      - \"**/.ssh/**\"\n",
    )
    .unwrap();
    let before = std::fs::read(&policy).unwrap();

    let dry_run = Command::cargo_bin("h2h")
        .unwrap()
        .args(["lint", policy.to_str().unwrap(), "--dry-run"])
        .output()
        .unwrap();

    assert_eq!(
        before,
        std::fs::read(&policy).unwrap(),
        "--dry-run must never write"
    );
    let dry_run_stdout = String::from_utf8(dry_run.stdout).unwrap();
    assert!(
        dry_run_stdout.contains("dupe.yaml"),
        "--dry-run should show a diff header for the file: {dry_run_stdout}"
    );

    // Actually fixing the same file should produce the fixed content that the
    // dry-run diff's "+" side previewed, and nothing else.
    let _ = Command::cargo_bin("h2h")
        .unwrap()
        .args(["lint", policy.to_str().unwrap(), "--fix"])
        .assert();
    let fixed = std::fs::read_to_string(&policy).unwrap();
    assert_ne!(
        String::from_utf8(before).unwrap(),
        fixed,
        "the duplicate fixture should actually change under --fix"
    );
    assert_eq!(
        fixed.matches("**/.ssh/**").count(),
        1,
        "the duplicate pattern should be gone after --fix: {fixed}"
    );
}

#[test]
fn fix_and_dry_run_are_mutually_exclusive() {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("t.yaml");
    std::fs::write(&policy, "hushspec: \"0.1.0\"\nname: t\n").unwrap();

    Command::cargo_bin("h2h")
        .unwrap()
        .args(["lint", policy.to_str().unwrap(), "--fix", "--dry-run"])
        .assert()
        .failure();
}

#[test]
fn never_rewrites_a_file_that_failed_to_parse() {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("broken.yaml");
    std::fs::write(
        &policy,
        "hushspec: \"0.1.0\"\nrules: [this is not a mapping\n",
    )
    .unwrap();
    let before = std::fs::read(&policy).unwrap();

    let _ = Command::cargo_bin("h2h")
        .unwrap()
        .args(["lint", policy.to_str().unwrap(), "--fix"])
        .assert();

    assert_eq!(
        before,
        std::fs::read(&policy).unwrap(),
        "a file that failed to parse must never be rewritten"
    );
}

fn glob_policies(root: &str) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for dir in [
        "rulesets",
        "library/general",
        "library/finance",
        "library/healthcare",
        "library/government",
        "library/education",
        "library/devops",
    ] {
        if let Ok(entries) = std::fs::read_dir(format!("{root}/{dir}")) {
            for e in entries.flatten() {
                if e.path().extension().is_some_and(|x| x == "yaml") {
                    out.push(e.path());
                }
            }
        }
    }
    assert!(out.len() >= 10, "expected the shipped policy corpus");
    out
}
