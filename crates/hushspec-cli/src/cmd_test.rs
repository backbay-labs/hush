use clap::ValueEnum;
use colored::Colorize;
use hushspec::{
    Decision, EvaluationAction, EvaluationResult, HushSpec, PostureResult, evaluate_with_detection,
    validate,
};
use serde::Deserialize;
use std::path::{Path, PathBuf};

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
struct EvaluationFixture {
    hushspec_test: String,
    #[allow(dead_code)]
    description: String,
    policy: serde_json::Value,
    cases: Vec<EvaluationCase>,
}

#[derive(Debug, Deserialize)]
struct EvaluationCase {
    description: String,
    action: EvaluationAction,
    expect: ExpectedEvaluation,
}

#[derive(Debug, Deserialize)]
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
    crate::cmd_panic::check_default_sentinel();

    let test_files = collect_test_files(&args);

    if test_files.is_empty() {
        eprintln!("{} No test fixture files found", "ERROR".red());
        return 2;
    }

    let external_policy = args.policy.as_ref().map(|path| {
        let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
            eprintln!(
                "{} Failed to read policy {}: {e}",
                "ERROR".red(),
                path.display()
            );
            std::process::exit(2);
        });
        HushSpec::parse(&content).unwrap_or_else(|e| {
            eprintln!(
                "{} Failed to parse policy {}: {e}",
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

        match HushSpec::parse(&policy_yaml) {
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
        let actual = evaluate_with_detection(&spec, &case.action).evaluation;
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
