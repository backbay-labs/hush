use clap::ValueEnum;
use colored::Colorize;
use hushspec::{
    Decision, EvaluationAction, EvaluationResult, HushSpec, PostureResult, evaluate_with_detection,
    validate,
};
use jsonschema::JSONSchema;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The evaluator-fixture schema, vendored into this crate.
///
/// `cargo package` only ships files inside the crate directory, so this cannot
/// `include_str!` the canonical `schemas/` copy at the workspace root the way
/// the testkit (never published) does. `evaluator_schema_matches_workspace_copy`
/// in `tests/resolve_tests.rs` fails if the two ever drift.
const EVALUATOR_TEST_SCHEMA: &str =
    include_str!("../schemas/hushspec-evaluator-test.v0.schema.json");

#[derive(clap::Args)]
pub struct TestArgs {
    /// Policy file to test against (overrides policy embedded in fixtures)
    #[arg(short, long)]
    policy: Option<PathBuf>,

    /// Test fixture files
    #[arg(required_unless_present = "fixtures")]
    tests: Vec<PathBuf>,

    /// Directory of test fixture files
    #[arg(long)]
    fixtures: Option<PathBuf>,

    /// Panic sentinel file to consult before evaluating; if it exists the
    /// process denies all actions (default: .hushspec_panic)
    #[arg(long, value_name = "PATH")]
    sentinel: Option<PathBuf>,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: TestOutputFormat,
}

#[derive(Clone, Copy, ValueEnum)]
enum TestOutputFormat {
    Text,
    Tap,
    Json,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationFixture {
    hushspec_test: String,
    #[allow(dead_code)]
    description: String,
    policy: serde_json::Value,
    cases: Vec<EvaluationCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationCase {
    description: String,
    action: EvaluationAction,
    /// Runtime context for `when` conditions (core spec 3.13); copied onto the
    /// action before evaluation.
    #[serde(default)]
    context: Option<hushspec::RuntimeContext>,
    expect: ExpectedEvaluation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedEvaluation {
    decision: Decision,
    #[serde(default)]
    matched_rule: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    origin_profile: Option<String>,
    #[serde(default)]
    posture: Option<PostureResult>,
}

struct CaseResult {
    description: String,
    passed: bool,
    message: Option<String>,
}

struct FixtureResult {
    file: String,
    cases: Vec<CaseResult>,
}

#[derive(serde::Serialize)]
struct JsonFixtureResult {
    file: String,
    passed: usize,
    failed: usize,
    cases: Vec<JsonCaseResult>,
}

#[derive(serde::Serialize)]
struct JsonCaseResult {
    description: String,
    passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

pub fn run(args: TestArgs) -> i32 {
    // A file-based `h2h panic activate` sentinel must flip the process-global
    // panic latch before evaluation, otherwise the kill switch is a no-op here.
    crate::cmd_panic::check_sentinel(args.sentinel.as_deref());

    let test_files = collect_test_files(&args);

    if test_files.is_empty() {
        eprintln!("{} No test fixture files found", "ERROR".red());
        return 2;
    }

    // Fail closed before a single case runs: a fixture with a typo in `expect`
    // (`matched_rul:`) or an unknown top-level key used to be silently ignored
    // and reported green. A malformed suite is a config error, not a failure.
    let mut malformed = false;
    for file in &test_files {
        if let Err(errors) = validate_fixture_schema(file) {
            malformed = true;
            eprintln!(
                "{} {} does not match the hushspec-evaluator-test schema:",
                "ERROR".red(),
                file.display()
            );
            for error in errors {
                eprintln!("  {error}");
            }
        }
    }
    if malformed {
        return 2;
    }

    let external_policy = args.policy.as_ref().map(|path| {
        // Resolve `extends` here: `--policy` names the document the suite runs
        // against, and an unresolved leaf drops every block its base declares.
        hushspec::resolve_from_path_with_builtins(path).unwrap_or_else(|e| {
            eprintln!(
                "{} Failed to load policy {}: {e}",
                "ERROR".red(),
                path.display()
            );
            std::process::exit(2);
        })
    });

    let mut fixture_results: Vec<FixtureResult> = Vec::new();

    for file in &test_files {
        let result = run_fixture_file(file, external_policy.as_ref());
        fixture_results.push(result);
    }

    let total_passed: usize = fixture_results
        .iter()
        .map(|fr| fr.cases.iter().filter(|c| c.passed).count())
        .sum();
    let total_failed: usize = fixture_results
        .iter()
        .map(|fr| fr.cases.iter().filter(|c| !c.passed).count())
        .sum();

    match args.format {
        TestOutputFormat::Text => print_text(&fixture_results, total_passed, total_failed),
        TestOutputFormat::Tap => print_tap(&fixture_results),
        TestOutputFormat::Json => print_json(&fixture_results),
    }

    if total_failed > 0 { 1 } else { 0 }
}

/// Compiled `hushspec-evaluator-test.v0` schema (compiled once per process).
fn evaluator_schema() -> &'static JSONSchema {
    static SCHEMA: OnceLock<JSONSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let schema_json: serde_json::Value = serde_json::from_str(EVALUATOR_TEST_SCHEMA)
            .expect("evaluator schema should be valid JSON");
        // Formats are asserted deliberately rather than left at draft 2020-12's
        // annotation-only default, matching the testkit's compile options.
        JSONSchema::options()
            .should_validate_formats(true)
            .compile(&schema_json)
            .expect("evaluator schema should compile")
    })
}

/// Validate one fixture file against the evaluator-test schema, reporting each
/// violation with its JSON-pointer path.
///
/// This mirrors what the conformance testkit already does
/// (`hushspec-testkit`'s `validate_evaluator_schema`); without it, `h2h test`
/// accepted anything its structs happened to deserialize and skipped the rest.
fn validate_fixture_schema(path: &Path) -> Result<(), Vec<String>> {
    let content =
        std::fs::read_to_string(path).map_err(|e| vec![format!("failed to read file: {e}")])?;
    let value: serde_json::Value =
        serde_yaml::from_str(&content).map_err(|e| vec![format!("invalid YAML: {e}")])?;

    match evaluator_schema().validate(&value) {
        Ok(()) => Ok(()),
        Err(errors) => Err(errors
            .map(|error| {
                let pointer = error.instance_path.to_string();
                let pointer = if pointer.is_empty() {
                    "/".to_string()
                } else {
                    pointer
                };
                format!("{pointer}: {error}")
            })
            .collect()),
    }
}

fn collect_test_files(args: &TestArgs) -> Vec<PathBuf> {
    let mut files = Vec::new();

    if let Some(dir) = &args.fixtures {
        if dir.is_dir() {
            collect_yaml_files(dir, &mut files);
        } else if dir.is_file() {
            files.push(dir.clone());
        }
    }

    for path in &args.tests {
        if path.is_dir() {
            collect_yaml_files(path, &mut files);
        } else if path.is_file() {
            files.push(path.clone());
        }
    }

    files.sort();
    files.dedup();
    files
}

fn collect_yaml_files(dir: &Path, files: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_yaml_files(&path, files);
            } else if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                // Only include files that look like test fixtures (.test.yaml)
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if name.contains(".test.") {
                    files.push(path);
                }
            }
        }
    }
}

fn run_fixture_file(path: &Path, external_policy: Option<&HushSpec>) -> FixtureResult {
    let file_display = path.display().to_string();

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            return FixtureResult {
                file: file_display,
                cases: vec![CaseResult {
                    description: "(file read)".into(),
                    passed: false,
                    message: Some(format!("failed to read file: {e}")),
                }],
            };
        }
    };

    let raw_value: serde_json::Value = match serde_yaml::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return FixtureResult {
                file: file_display,
                cases: vec![CaseResult {
                    description: "(YAML parse)".into(),
                    passed: false,
                    message: Some(format!("invalid YAML: {e}")),
                }],
            };
        }
    };

    let fixture: EvaluationFixture = match serde_json::from_value(raw_value) {
        Ok(f) => f,
        Err(e) => {
            return FixtureResult {
                file: file_display,
                cases: vec![CaseResult {
                    description: "(fixture parse)".into(),
                    passed: false,
                    message: Some(format!("failed to deserialize fixture: {e}")),
                }],
            };
        }
    };

    if fixture.hushspec_test != "0.1.0" {
        return FixtureResult {
            file: file_display,
            cases: vec![CaseResult {
                description: "(version check)".into(),
                passed: false,
                message: Some(format!(
                    "unsupported hushspec_test version: {}",
                    fixture.hushspec_test
                )),
            }],
        };
    }

    // Use external policy if provided, otherwise parse embedded policy
    let spec = if let Some(ext) = external_policy {
        ext.clone()
    } else {
        let policy_yaml = match serde_yaml::to_string(&fixture.policy) {
            Ok(y) => y,
            Err(e) => {
                return FixtureResult {
                    file: file_display,
                    cases: vec![CaseResult {
                        description: "(policy serialize)".into(),
                        passed: false,
                        message: Some(format!("failed to serialize embedded policy: {e}")),
                    }],
                };
            }
        };

        let parsed = match HushSpec::parse(&policy_yaml) {
            Ok(s) => s,
            Err(e) => {
                return FixtureResult {
                    file: file_display,
                    cases: vec![CaseResult {
                        description: "(policy parse)".into(),
                        passed: false,
                        message: Some(format!("embedded policy failed to parse: {e}")),
                    }],
                };
            }
        };

        // An embedded policy has no file of its own, so its `extends` chain is
        // resolved as if it lived beside the fixture: builtins by name, and
        // relative paths against the fixture's directory. A chain that will not
        // resolve fails the fixture instead of running against the bare leaf.
        if parsed.extends.is_none() {
            parsed
        } else {
            let loader = hushspec::create_composite_loader();
            match hushspec::resolve_with_loader(&parsed, Some(&file_display), &loader) {
                Ok(resolved) => resolved,
                Err(e) => {
                    return FixtureResult {
                        file: file_display,
                        cases: vec![CaseResult {
                            description: "(policy resolve)".into(),
                            passed: false,
                            message: Some(format!("embedded policy failed to resolve: {e}")),
                        }],
                    };
                }
            }
        }
    };

    // Validate parsed policy
    let validation = validate(&spec);
    if !validation.is_valid() {
        let errors: Vec<String> = validation.errors.iter().map(|e| e.to_string()).collect();
        return FixtureResult {
            file: file_display,
            cases: vec![CaseResult {
                description: "(policy validation)".into(),
                passed: false,
                message: Some(format!("policy failed validation: {}", errors.join(", "))),
            }],
        };
    }

    // Run each case
    let mut case_results = Vec::new();
    for case in &fixture.cases {
        let mut action = case.action.clone();
        if action.context.is_none() {
            action.context = case.context.clone();
        }
        let actual = evaluate_with_detection(&spec, &action).evaluation;
        let mismatch = compare_expected(&case.expect, &actual);

        case_results.push(CaseResult {
            description: case.description.clone(),
            passed: mismatch.is_none(),
            message: mismatch,
        });
    }

    FixtureResult {
        file: file_display,
        cases: case_results,
    }
}

fn compare_expected(expected: &ExpectedEvaluation, actual: &EvaluationResult) -> Option<String> {
    if expected.decision != actual.decision {
        return Some(format!(
            "expected {:?}, got {:?}",
            expected.decision, actual.decision
        ));
    }
    if let Some(expected_rule) = &expected.matched_rule
        && actual.matched_rule.as_ref() != Some(expected_rule)
    {
        return Some(format!(
            "expected matched_rule {:?}, got {:?}",
            expected_rule, actual.matched_rule
        ));
    }
    if let Some(expected_reason) = &expected.reason
        && actual.reason.as_ref() != Some(expected_reason)
    {
        return Some(format!(
            "expected reason {:?}, got {:?}",
            expected_reason, actual.reason
        ));
    }
    if let Some(expected_origin) = &expected.origin_profile
        && actual.origin_profile.as_ref() != Some(expected_origin)
    {
        return Some(format!(
            "expected origin_profile {:?}, got {:?}",
            expected_origin, actual.origin_profile
        ));
    }
    if let Some(expected_posture) = &expected.posture
        && actual.posture.as_ref() != Some(expected_posture)
    {
        return Some(format!(
            "expected posture {:?}, got {:?}",
            expected_posture, actual.posture
        ));
    }
    None
}

fn print_text(results: &[FixtureResult], total_passed: usize, total_failed: usize) {
    for fr in results {
        let case_count = fr.cases.len();

        // Shorten the file path for display
        let display_file = fr
            .file
            .rsplit_once("fixtures/")
            .map(|(_, rel)| rel)
            .unwrap_or(&fr.file);

        println!("Running {} cases from {}...", case_count, display_file);

        for case in &fr.cases {
            if case.passed {
                println!("  {} {}", "\u{2713}".green(), case.description);
            } else {
                let msg = case.message.as_deref().unwrap_or("failed");
                println!(
                    "  {} {} {} {}",
                    "\u{2717}".red(),
                    case.description,
                    "\u{2014}".dimmed(),
                    msg.red()
                );
            }
        }
        println!();
    }

    println!();
    if total_failed == 0 {
        println!("{} {} passed, 0 failed", "Results:".bold(), total_passed);
    } else {
        println!(
            "{} {} passed, {} failed",
            "Results:".bold(),
            total_passed,
            total_failed
        );
    }
}

fn print_tap(results: &[FixtureResult]) {
    let total_cases: usize = results.iter().map(|fr| fr.cases.len()).sum();
    println!("TAP version 14");
    println!("1..{total_cases}");

    let mut index = 1;
    for fr in results {
        for case in &fr.cases {
            if case.passed {
                println!("ok {index} - {}", case.description);
            } else {
                println!("not ok {index} - {}", case.description);
                if let Some(msg) = &case.message {
                    println!("  ---");
                    println!("  message: {msg}");
                    println!("  file: {}", fr.file);
                    println!("  ...");
                }
            }
            index += 1;
        }
    }
}

fn print_json(results: &[FixtureResult]) {
    let json_results: Vec<JsonFixtureResult> = results
        .iter()
        .map(|fr| {
            let passed = fr.cases.iter().filter(|c| c.passed).count();
            let failed = fr.cases.len() - passed;
            JsonFixtureResult {
                file: fr.file.clone(),
                passed,
                failed,
                cases: fr
                    .cases
                    .iter()
                    .map(|c| JsonCaseResult {
                        description: c.description.clone(),
                        passed: c.passed,
                        message: c.message.clone(),
                    })
                    .collect(),
            }
        })
        .collect();

    if let Ok(json) = serde_json::to_string_pretty(&json_results) {
        println!("{json}");
    }
}
