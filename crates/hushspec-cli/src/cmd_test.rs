use clap::ValueEnum;
use colored::Colorize;
use hushspec::receipt::{RuleOutcome, RuleTraceEntry};
use hushspec::{
    Decision, EvaluationAction, EvaluationResult, HushSpec, PostureResult, Resolution,
    evaluate_with_detection_traced, validate,
};
use jsonschema::JSONSchema;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The evaluator-fixture schema, vendored into this crate.
///
/// `cargo package` only ships files inside the crate directory, so this cannot
/// `include_str!` the canonical `schemas/` copy at the workspace root the way
/// the testkit (never published) does. `evaluator_schema_matches_workspace_copy`
/// in `tests/resolve_tests.rs` fails if the two ever drift.
const EVALUATOR_TEST_SCHEMA: &str =
    include_str!("../schemas/hushspec-evaluator-test.v1.schema.json");

/// Fixture format versions this runner accepts (evaluator-test schema).
const SUPPORTED_TEST_VERSIONS: &[&str] = &["0.1.0", "0.2.0"];

/// Fixed evaluation time for `expect.receipt`: 2026-09-15T12:00:00.000Z.
///
/// The inputs a receipt assertion is evaluated under are the ones
/// `fixtures/receipts/expected/README.md` pins, so a fixture's `expect.receipt`
/// and the expected-receipt vectors describe the same object.
const RECEIPT_CLOCK_MILLIS: u64 = 1_789_473_600_000;

/// Receipt members that are inputs rather than outcomes, and are therefore
/// never compared even when a fixture spells them.
const RECEIPT_IGNORED_MEMBERS: [&str; 3] = ["actor", "timestamp", "receipt_id"];

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

    /// Write the report in `--format` here instead of to stdout; stdout then
    /// carries the human-readable summary
    #[arg(long, value_name = "PATH")]
    report_file: Option<PathBuf>,

    /// Exit non-zero when a declared rule path was never hit by any case
    #[arg(long)]
    fail_on_uncovered: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TestOutputFormat {
    Text,
    Tap,
    Json,
    Junit,
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
    /// The controls this case is evidence for (evaluator-test schema 0.2).
    #[serde(default)]
    controls: Vec<ControlRef>,
    /// Free-form labels (evaluator-test schema 0.2).
    #[serde(default)]
    tags: Vec<String>,
    expect: ExpectedEvaluation,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlRef {
    framework: String,
    control_id: String,
}

impl ControlRef {
    fn label(&self) -> String {
        format!("{}:{}", self.framework, self.control_id)
    }
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
    /// The recorded rule trace (receipt spec 4.3), compared in order and in
    /// full.
    #[serde(default)]
    rule_trace: Option<Vec<RuleTraceExpectation>>,
    /// A partial format 0.2 receipt (see `RECEIPT_IGNORED_MEMBERS`).
    #[serde(default)]
    receipt: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleTraceExpectation {
    rule_block: String,
    outcome: RuleOutcome,
    #[serde(default)]
    rule_path: Option<String>,
}

/// One assertion that did not hold, kept in the three parts a JUnit `<failure>`
/// wants: what was compared, what the fixture asked for, what ran.
struct Mismatch {
    field: String,
    expected: String,
    actual: String,
}

impl Mismatch {
    fn new(field: &str, expected: impl Into<String>, actual: impl Into<String>) -> Self {
        Self {
            field: field.to_string(),
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    fn message(&self) -> String {
        format!(
            "{}: expected {}, got {}",
            self.field, self.expected, self.actual
        )
    }
}

struct CaseResult {
    description: String,
    passed: bool,
    mismatch: Option<Mismatch>,
    controls: Vec<ControlRef>,
    tags: Vec<String>,
}

impl CaseResult {
    fn message(&self) -> Option<String> {
        self.mismatch.as_ref().map(Mismatch::message)
    }
}

struct FixtureResult {
    file: String,
    cases: Vec<CaseResult>,
}

/// Declared-versus-hit rule paths for one policy under test.
#[derive(Default)]
struct Coverage {
    declared: Vec<String>,
    hit: BTreeSet<String>,
}

impl Coverage {
    /// Credit every declared path the evaluator's `matched_rule` or a
    /// `rule_trace` entry's `rule_path` points inside: `rules.egress.allow`
    /// covers `rules.egress`, and `rules.secret_patterns.patterns.ssn` covers
    /// both `rules.secret_patterns` and that named pattern.
    fn record(&mut self, path: &str) {
        for declared in &self.declared {
            if path == declared
                || path.starts_with(&format!("{declared}."))
                || path.starts_with(&format!("{declared}["))
            {
                self.hit.insert(declared.clone());
            }
        }
    }

    fn uncovered(&self) -> Vec<&str> {
        self.declared
            .iter()
            .filter(|path| !self.hit.contains(*path))
            .map(String::as_str)
            .collect()
    }

    fn covered(&self) -> usize {
        self.declared.len() - self.uncovered().len()
    }

    fn percent(&self) -> f64 {
        if self.declared.is_empty() {
            100.0
        } else {
            (self.covered() as f64 / self.declared.len() as f64) * 100.0
        }
    }
}

#[derive(serde::Serialize)]
struct JsonReport {
    passed: usize,
    failed: usize,
    fixtures: Vec<JsonFixtureResult>,
    coverage: JsonCoverage,
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    controls: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
}

#[derive(serde::Serialize)]
struct JsonCoverage {
    declared: usize,
    covered: usize,
    policies: Vec<JsonPolicyCoverage>,
}

#[derive(serde::Serialize)]
struct JsonPolicyCoverage {
    policy: String,
    declared: usize,
    covered: usize,
    uncovered: Vec<String>,
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

    // Resolve `extends` here: `--policy` names the document the suite runs
    // against, and an unresolved leaf drops every block its base declares.
    let external_policy = match args.policy.as_ref() {
        Some(path) => match hushspec::resolve_from_path_with_builtins(path) {
            Ok(policy) => Some(policy),
            Err(e) => {
                eprintln!(
                    "{} Failed to load policy {}: {e}",
                    "ERROR".red(),
                    path.display()
                );
                return 2;
            }
        },
        None => None,
    };
    let external_policy_key = args
        .policy
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_default();

    let mut fixture_results: Vec<FixtureResult> = Vec::new();
    // Coverage is per policy under test: with `--policy` every fixture shares
    // one, otherwise each fixture's embedded document is its own.
    let mut coverage: BTreeMap<String, Coverage> = BTreeMap::new();

    for file in &test_files {
        let key = if external_policy.is_some() {
            external_policy_key.clone()
        } else {
            file.display().to_string()
        };
        let result = run_fixture_file(
            file,
            external_policy.as_ref(),
            coverage.entry(key).or_default(),
        );
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
    let uncovered: usize = coverage.values().map(|c| c.uncovered().len()).sum();

    let report = match args.format {
        TestOutputFormat::Text => render_text(&fixture_results, total_passed, total_failed),
        TestOutputFormat::Tap => render_tap(&fixture_results),
        TestOutputFormat::Json => {
            match render_json(&fixture_results, total_passed, total_failed, &coverage) {
                Ok(json) => json,
                Err(message) => {
                    eprintln!("{} {message}", "ERROR".red());
                    return 2;
                }
            }
        }
        TestOutputFormat::Junit => {
            render_junit(&fixture_results, &coverage, args.fail_on_uncovered)
        }
    };

    match &args.report_file {
        Some(path) => {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty())
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                eprintln!(
                    "{} Failed to create {}: {e}",
                    "ERROR".red(),
                    parent.display()
                );
                return 2;
            }
            if let Err(e) = std::fs::write(path, &report) {
                eprintln!("{} Failed to write {}: {e}", "ERROR".red(), path.display());
                return 2;
            }
            // The report left stdout, so stdout gets the readable summary.
            print!(
                "{}",
                render_text(&fixture_results, total_passed, total_failed)
            );
            println!("Report written to {}", path.display());
            print!("{}", render_coverage_table(&coverage, ""));
        }
        None => {
            print!("{report}");
            // Only the text and TAP reports can carry the table without
            // becoming unparseable; JSON and JUnit already carry the numbers.
            match args.format {
                TestOutputFormat::Text => print!("{}", render_coverage_table(&coverage, "")),
                TestOutputFormat::Tap => print!("{}", render_coverage_table(&coverage, "# ")),
                TestOutputFormat::Json | TestOutputFormat::Junit => {}
            }
        }
    }

    if total_failed > 0 {
        return 1;
    }
    if args.fail_on_uncovered && uncovered > 0 {
        eprintln!(
            "{} {uncovered} declared rule path(s) were never hit",
            "ERROR".red()
        );
        return 1;
    }
    0
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

/// The rule paths a resolved document declares: every rule block it contains,
/// plus every named secret pattern, spelled the way the evaluator spells
/// `matched_rule`.
fn declared_rule_paths(spec: &HushSpec) -> Vec<String> {
    let Ok(document) = serde_json::to_value(spec) else {
        return Vec::new();
    };
    let mut paths = crate::controls::rule_block_paths(&document);
    if let Some(rules) = &spec.rules
        && let Some(secret_patterns) = &rules.secret_patterns
    {
        for pattern in &secret_patterns.patterns {
            paths.push(format!("rules.secret_patterns.patterns.{}", pattern.name));
        }
    }
    paths
}

fn fixture_failure(file: String, description: &str, message: String) -> FixtureResult {
    FixtureResult {
        file,
        cases: vec![CaseResult {
            description: description.to_string(),
            passed: false,
            mismatch: Some(Mismatch::new("fixture", "a runnable suite", message)),
            controls: Vec::new(),
            tags: Vec::new(),
        }],
    }
}

fn run_fixture_file(
    path: &Path,
    external_policy: Option<&HushSpec>,
    coverage: &mut Coverage,
) -> FixtureResult {
    let file_display = path.display().to_string();

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            return fixture_failure(
                file_display,
                "(file read)",
                format!("failed to read file: {e}"),
            );
        }
    };

    let raw_value: serde_json::Value = match serde_yaml::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return fixture_failure(file_display, "(YAML parse)", format!("invalid YAML: {e}"));
        }
    };

    let fixture: EvaluationFixture = match serde_json::from_value(raw_value) {
        Ok(f) => f,
        Err(e) => {
            return fixture_failure(
                file_display,
                "(fixture parse)",
                format!("failed to deserialize fixture: {e}"),
            );
        }
    };

    if !SUPPORTED_TEST_VERSIONS.contains(&fixture.hushspec_test.as_str()) {
        return fixture_failure(
            file_display,
            "(version check)",
            format!(
                "unsupported hushspec_test version: {} (supported: {})",
                fixture.hushspec_test,
                SUPPORTED_TEST_VERSIONS.join(", ")
            ),
        );
    }

    // Use external policy if provided, otherwise parse embedded policy
    let spec = if let Some(ext) = external_policy {
        ext.clone()
    } else {
        let policy_yaml = match serde_yaml::to_string(&fixture.policy) {
            Ok(y) => y,
            Err(e) => {
                return fixture_failure(
                    file_display,
                    "(policy serialize)",
                    format!("failed to serialize embedded policy: {e}"),
                );
            }
        };

        let parsed = match HushSpec::parse(&policy_yaml) {
            Ok(s) => s,
            Err(e) => {
                return fixture_failure(
                    file_display,
                    "(policy parse)",
                    format!("embedded policy failed to parse: {e}"),
                );
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
                    return fixture_failure(
                        file_display,
                        "(policy resolve)",
                        format!("embedded policy failed to resolve: {e}"),
                    );
                }
            }
        }
    };

    // Validate parsed policy
    let validation = validate(&spec);
    if !validation.is_valid() {
        let errors: Vec<String> = validation.errors.iter().map(|e| e.to_string()).collect();
        return fixture_failure(
            file_display,
            "(policy validation)",
            format!("policy failed validation: {}", errors.join(", ")),
        );
    }

    if coverage.declared.is_empty() {
        coverage.declared = declared_rule_paths(&spec);
    }

    // A receipt assertion needs a `Resolution`; the document is already
    // resolved here, so this is a single-link resolution exactly as the
    // expected-receipt vectors describe.
    let resolution = Resolution::from_resolved(&spec, None);

    // Run each case
    let mut case_results = Vec::new();
    for (index, case) in fixture.cases.iter().enumerate() {
        let mut action = case.action.clone();
        if action.context.is_none() {
            action.context = case.context.clone();
        }
        let traced = evaluate_with_detection_traced(&spec, &action, None, &HashMap::new());
        let trace: Vec<RuleTraceEntry> = traced
            .traced
            .trace
            .iter()
            .map(RuleTraceEntry::from)
            .collect();
        let actual = traced.evaluation;

        if let Some(path) = &actual.matched_rule {
            coverage.record(path);
        }
        for entry in &trace {
            if let Some(path) = &entry.rule_path {
                coverage.record(path);
            }
        }

        let mut mismatch = compare_expected(&case.expect, &actual);
        if mismatch.is_none()
            && let Some(expected_trace) = &case.expect.rule_trace
        {
            mismatch = compare_rule_trace(expected_trace, &trace);
        }
        if mismatch.is_none()
            && let Some(expected_receipt) = &case.expect.receipt
        {
            mismatch = match &resolution {
                Ok(resolution) => compare_receipt(
                    expected_receipt,
                    resolution,
                    &action,
                    case.context.as_ref(),
                    index,
                ),
                Err(e) => Some(Mismatch::new(
                    "receipt",
                    "a resolvable policy",
                    e.to_string(),
                )),
            };
        }

        case_results.push(CaseResult {
            description: case.description.clone(),
            passed: mismatch.is_none(),
            mismatch,
            controls: case.controls.clone(),
            tags: case.tags.clone(),
        });
    }

    FixtureResult {
        file: file_display,
        cases: case_results,
    }
}

fn compare_expected(expected: &ExpectedEvaluation, actual: &EvaluationResult) -> Option<Mismatch> {
    if expected.decision != actual.decision {
        return Some(Mismatch::new(
            "decision",
            format!("{:?}", expected.decision),
            format!("{:?}", actual.decision),
        ));
    }
    if let Some(expected_rule) = &expected.matched_rule
        && actual.matched_rule.as_ref() != Some(expected_rule)
    {
        return Some(Mismatch::new(
            "matched_rule",
            format!("{expected_rule:?}"),
            format!("{:?}", actual.matched_rule),
        ));
    }
    if let Some(expected_reason) = &expected.reason
        && actual.reason.as_ref() != Some(expected_reason)
    {
        return Some(Mismatch::new(
            "reason",
            format!("{expected_reason:?}"),
            format!("{:?}", actual.reason),
        ));
    }
    if let Some(expected_origin) = &expected.origin_profile
        && actual.origin_profile.as_ref() != Some(expected_origin)
    {
        return Some(Mismatch::new(
            "origin_profile",
            format!("{expected_origin:?}"),
            format!("{:?}", actual.origin_profile),
        ));
    }
    if let Some(expected_posture) = &expected.posture
        && actual.posture.as_ref() != Some(expected_posture)
    {
        return Some(Mismatch::new(
            "posture",
            format!("{expected_posture:?}"),
            format!("{:?}", actual.posture),
        ));
    }
    None
}

fn render_trace_entry(entry: &RuleTraceEntry) -> String {
    match &entry.rule_path {
        Some(path) => format!("{}:{:?}@{path}", entry.rule_block, entry.outcome),
        None => format!("{}:{:?}", entry.rule_block, entry.outcome),
    }
}

fn render_expected_trace_entry(entry: &RuleTraceExpectation) -> String {
    match &entry.rule_path {
        Some(path) => format!("{}:{:?}@{path}", entry.rule_block, entry.outcome),
        None => format!("{}:{:?}", entry.rule_block, entry.outcome),
    }
}

/// Compare a fixture's `expect.rule_trace` with the recorded trace: in order,
/// in full, and member by member (`rule_path` only where the fixture spells
/// it).
fn compare_rule_trace(
    expected: &[RuleTraceExpectation],
    actual: &[RuleTraceEntry],
) -> Option<Mismatch> {
    let render_expected = || {
        expected
            .iter()
            .map(render_expected_trace_entry)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let render_actual = || {
        actual
            .iter()
            .map(render_trace_entry)
            .collect::<Vec<_>>()
            .join(", ")
    };

    if expected.len() != actual.len() {
        return Some(Mismatch::new(
            "rule_trace",
            format!("{} entries [{}]", expected.len(), render_expected()),
            format!("{} entries [{}]", actual.len(), render_actual()),
        ));
    }

    for (index, (want, got)) in expected.iter().zip(actual).enumerate() {
        let matches = want.rule_block == got.rule_block
            && want.outcome == got.outcome
            && want
                .rule_path
                .as_ref()
                .is_none_or(|path| got.rule_path.as_ref() == Some(path));
        if !matches {
            return Some(Mismatch::new(
                &format!("rule_trace[{index}]"),
                render_expected_trace_entry(want),
                render_trace_entry(got),
            ));
        }
    }
    None
}

/// Build the receipt for one case under the fixed inputs of
/// `fixtures/receipts/expected/README.md` and compare the members the fixture
/// spelled.
fn compare_receipt(
    expected: &serde_json::Value,
    resolution: &Resolution,
    action: &EvaluationAction,
    context: Option<&hushspec::RuntimeContext>,
    case_index: usize,
) -> Option<Mismatch> {
    let config = hushspec::AuditConfig {
        enabled: true,
        include_rule_trace: true,
        // Off: a receipt assertion must not depend on the machine running it.
        record_duration: false,
    };
    let ctx = hushspec::AuditContext {
        actor: Some(hushspec::Actor {
            agent_id: Some("fixture-agent".to_string()),
            session_id: Some("fixture-session".to_string()),
            principal: Some("fixture@hushspec.dev".to_string()),
            runtime: Some("hushspec-conformance/0.2".to_string()),
        }),
        enforcement: None,
        enforcement_mode: hushspec::EnforcementMode::Enforce,
        time_source: hushspec::TimeSource::Trusted,
        clock: chrono::DateTime::from_timestamp_millis(RECEIPT_CLOCK_MILLIS as i64),
        receipt_id: Some(hushspec::deterministic_uuid_v7(
            RECEIPT_CLOCK_MILLIS,
            case_index as u64,
        )),
        context: context.cloned(),
        conditions: HashMap::new(),
    };
    let receipt = hushspec::evaluate_audited(resolution, action, &config, &ctx);
    let Ok(actual) = serde_json::to_value(&receipt) else {
        return Some(Mismatch::new(
            "receipt",
            "a serializable receipt",
            "serialization failed",
        ));
    };

    let Some(expected_members) = expected.as_object() else {
        return Some(Mismatch::new(
            "receipt",
            "an object",
            "expect.receipt is not an object",
        ));
    };
    for (key, want) in expected_members {
        if RECEIPT_IGNORED_MEMBERS.contains(&key.as_str()) {
            continue;
        }
        if let Some(mismatch) = receipt_member_mismatch(key, want, actual.get(key)) {
            return Some(mismatch);
        }
    }
    None
}

/// Render one JSON value the way a receipt mismatch reports it.
fn render_json_value(value: Option<&serde_json::Value>) -> String {
    value.map_or_else(
        || "(absent)".to_string(),
        |value| serde_json::to_string(value).unwrap_or_default(),
    )
}

/// Member-wise comparison: a nested object in the fixture is itself partial,
/// every other value must be equal. Reports the first member that differs, by
/// its dotted path and its own two values.
fn receipt_member_mismatch(
    path: &str,
    expected: &serde_json::Value,
    actual: Option<&serde_json::Value>,
) -> Option<Mismatch> {
    match (expected, actual) {
        (serde_json::Value::Object(want), Some(serde_json::Value::Object(got))) => {
            for (key, value) in want {
                if let Some(inner) =
                    receipt_member_mismatch(&format!("{path}.{key}"), value, got.get(key))
                {
                    return Some(inner);
                }
            }
            None
        }
        (_, Some(got)) if got == expected => None,
        (_, got) => Some(Mismatch::new(
            &format!("receipt.{path}"),
            render_json_value(Some(expected)),
            render_json_value(got),
        )),
    }
}

fn render_text(results: &[FixtureResult], total_passed: usize, total_failed: usize) -> String {
    let mut out = String::new();
    for fr in results {
        let case_count = fr.cases.len();

        // Shorten the file path for display
        let display_file = fr
            .file
            .rsplit_once("fixtures/")
            .map(|(_, rel)| rel)
            .unwrap_or(&fr.file);

        out.push_str(&format!(
            "Running {} cases from {}...\n",
            case_count, display_file
        ));

        for case in &fr.cases {
            if case.passed {
                out.push_str(&format!("  {} {}\n", "\u{2713}".green(), case.description));
            } else {
                let msg = case.message().unwrap_or_else(|| "failed".to_string());
                out.push_str(&format!(
                    "  {} {} {} {}\n",
                    "\u{2717}".red(),
                    case.description,
                    "\u{2014}".dimmed(),
                    msg.red()
                ));
            }
        }
        out.push('\n');
    }

    out.push('\n');
    out.push_str(&format!(
        "{} {} passed, {} failed\n",
        "Results:".bold(),
        total_passed,
        total_failed
    ));
    out
}

/// The rule-coverage table: declared rule paths versus paths any case hit.
///
/// `prefix` lets the TAP report carry the same table as comments.
fn render_coverage_table(coverage: &BTreeMap<String, Coverage>, prefix: &str) -> String {
    if coverage.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    out.push_str(&format!("\n{prefix}{}\n", "Rule coverage:".bold()));

    let mut declared_total = 0;
    let mut covered_total = 0;
    for (policy, entry) in coverage {
        declared_total += entry.declared.len();
        covered_total += entry.covered();
        let display = policy
            .rsplit_once("fixtures/")
            .map(|(_, rel)| rel)
            .unwrap_or(policy);
        let line = format!(
            "{prefix}  {display}: {}/{} ({:.0}%)\n",
            entry.covered(),
            entry.declared.len(),
            entry.percent()
        );
        if entry.uncovered().is_empty() {
            out.push_str(&line);
        } else {
            out.push_str(&line.yellow().to_string());
            for path in entry.uncovered() {
                out.push_str(&format!("{prefix}    uncovered: {path}\n"));
            }
        }
    }

    let percent = if declared_total == 0 {
        100.0
    } else {
        (covered_total as f64 / declared_total as f64) * 100.0
    };
    out.push_str(&format!(
        "{prefix}  {} {covered_total}/{declared_total} ({percent:.0}%)\n",
        "Total:".bold()
    ));
    out
}

fn render_tap(results: &[FixtureResult]) -> String {
    let total_cases: usize = results.iter().map(|fr| fr.cases.len()).sum();
    let mut out = String::new();
    out.push_str("TAP version 14\n");
    out.push_str(&format!("1..{total_cases}\n"));

    let mut index = 1;
    for fr in results {
        for case in &fr.cases {
            if case.passed {
                out.push_str(&format!("ok {index} - {}\n", case.description));
            } else {
                out.push_str(&format!("not ok {index} - {}\n", case.description));
                if let Some(msg) = case.message() {
                    out.push_str("  ---\n");
                    out.push_str(&format!("  message: {msg}\n"));
                    out.push_str(&format!("  file: {}\n", fr.file));
                    out.push_str("  ...\n");
                }
            }
            index += 1;
        }
    }
    out
}

fn render_json(
    results: &[FixtureResult],
    total_passed: usize,
    total_failed: usize,
    coverage: &BTreeMap<String, Coverage>,
) -> Result<String, String> {
    let fixtures: Vec<JsonFixtureResult> = results
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
                        message: c.message(),
                        controls: c.controls.iter().map(ControlRef::label).collect(),
                        tags: c.tags.clone(),
                    })
                    .collect(),
            }
        })
        .collect();

    let policies: Vec<JsonPolicyCoverage> = coverage
        .iter()
        .map(|(policy, entry)| JsonPolicyCoverage {
            policy: policy.clone(),
            declared: entry.declared.len(),
            covered: entry.covered(),
            uncovered: entry.uncovered().iter().map(|p| (*p).to_string()).collect(),
        })
        .collect();

    let report = JsonReport {
        passed: total_passed,
        failed: total_failed,
        coverage: JsonCoverage {
            declared: policies.iter().map(|p| p.declared).sum(),
            covered: policies.iter().map(|p| p.covered).sum(),
            policies,
        },
        fixtures,
    };

    match serde_json::to_string_pretty(&report) {
        Ok(json) => Ok(format!("{json}\n")),
        Err(e) => Err(format!("could not serialize the JSON report: {e}")),
    }
}

/// Escape a string for an XML attribute or text node.
fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // XML 1.0 forbids most control characters outright.
            c if (c < ' ' && c != '\n' && c != '\t' && c != '\r') || c == '\u{7f}' => {
                out.push('\u{fffd}')
            }
            c => out.push(c),
        }
    }
    out
}

/// A JUnit `classname`: the fixture path with separators turned into dots, so
/// report viewers group by suite the way they do for a package.
fn junit_classname(file: &str) -> String {
    // `strip_suffix`, not `trim_end_matches`: the latter strips the suffix
    // repeatedly, so `a.test.yaml.test.yaml` would collapse to `a`.
    let stem = file
        .strip_suffix(".test.yaml")
        .or_else(|| file.strip_suffix(".test.yml"))
        .unwrap_or(file);
    stem.replace(['/', '\\'], ".")
}

fn render_junit(
    results: &[FixtureResult],
    coverage: &BTreeMap<String, Coverage>,
    fail_on_uncovered: bool,
) -> String {
    let total_cases: usize = results.iter().map(|fr| fr.cases.len()).sum();
    let total_failures: usize = results
        .iter()
        .map(|fr| fr.cases.iter().filter(|c| !c.passed).count())
        .sum();
    let uncovered_policies = coverage
        .values()
        .filter(|entry| !entry.uncovered().is_empty())
        .count();
    let coverage_failures = if fail_on_uncovered {
        uncovered_policies
    } else {
        0
    };

    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!(
        "<testsuites name=\"h2h test\" tests=\"{}\" failures=\"{}\">\n",
        total_cases + coverage.len(),
        total_failures + coverage_failures
    ));

    for fr in results {
        let passed = fr.cases.iter().filter(|c| c.passed).count();
        let failures = fr.cases.len() - passed;
        let classname = junit_classname(&fr.file);
        out.push_str(&format!(
            "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\">\n",
            xml_escape(&fr.file),
            fr.cases.len(),
            failures
        ));
        for case in &fr.cases {
            out.push_str(&format!(
                "    <testcase name=\"{}\" classname=\"{}\"",
                xml_escape(&case.description),
                xml_escape(&classname)
            ));
            if case.passed && case.controls.is_empty() && case.tags.is_empty() {
                out.push_str("/>\n");
                continue;
            }
            out.push_str(">\n");
            if !case.controls.is_empty() || !case.tags.is_empty() {
                out.push_str("      <properties>\n");
                for control in &case.controls {
                    out.push_str(&format!(
                        "        <property name=\"control\" value=\"{}\"/>\n",
                        xml_escape(&control.label())
                    ));
                }
                for tag in &case.tags {
                    out.push_str(&format!(
                        "        <property name=\"tag\" value=\"{}\"/>\n",
                        xml_escape(tag)
                    ));
                }
                out.push_str("      </properties>\n");
            }
            if let Some(mismatch) = &case.mismatch {
                out.push_str(&format!(
                    "      <failure message=\"{}\" type=\"assertion\">expected: {}\nactual:   {}</failure>\n",
                    xml_escape(&mismatch.message()),
                    xml_escape(&mismatch.expected),
                    xml_escape(&mismatch.actual)
                ));
            }
            out.push_str("    </testcase>\n");
        }
        out.push_str("  </testsuite>\n");
    }

    // Rule coverage as its own suite, so a report viewer shows an uncovered
    // rule path next to the cases instead of only in the run log.
    out.push_str(&format!(
        "  <testsuite name=\"rule coverage\" tests=\"{}\" failures=\"{coverage_failures}\">\n",
        coverage.len()
    ));
    for (policy, entry) in coverage {
        out.push_str(&format!(
            "    <testcase name=\"{}\" classname=\"rule-coverage\">\n",
            xml_escape(policy)
        ));
        out.push_str("      <properties>\n");
        out.push_str(&format!(
            "        <property name=\"declared\" value=\"{}\"/>\n",
            entry.declared.len()
        ));
        out.push_str(&format!(
            "        <property name=\"covered\" value=\"{}\"/>\n",
            entry.covered()
        ));
        out.push_str("      </properties>\n");
        let uncovered = entry.uncovered();
        if !uncovered.is_empty() {
            let detail = uncovered.join("\n");
            if fail_on_uncovered {
                out.push_str(&format!(
                    "      <failure message=\"{} declared rule path(s) never hit\" type=\"coverage\">{}</failure>\n",
                    uncovered.len(),
                    xml_escape(&detail)
                ));
            } else {
                out.push_str(&format!(
                    "      <system-out>uncovered:\n{}</system-out>\n",
                    xml_escape(&detail)
                ));
            }
        }
        out.push_str("    </testcase>\n");
    }
    out.push_str("  </testsuite>\n");
    out.push_str("</testsuites>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_credits_a_path_inside_a_declared_block() {
        let mut coverage = Coverage {
            declared: vec![
                "rules.egress".to_string(),
                "rules.secret_patterns".to_string(),
                "rules.secret_patterns.patterns.ssn".to_string(),
            ],
            ..Default::default()
        };
        coverage.record("rules.egress.allow");
        coverage.record("rules.secret_patterns.patterns.ssn");
        assert!(
            coverage.uncovered().is_empty(),
            "{:?}",
            coverage.uncovered()
        );
    }

    #[test]
    fn coverage_does_not_credit_a_sibling_with_a_shared_prefix() {
        let mut coverage = Coverage {
            declared: vec![
                "rules.secret_patterns.patterns.dea".to_string(),
                "rules.secret_patterns.patterns.dea_number".to_string(),
            ],
            ..Default::default()
        };
        coverage.record("rules.secret_patterns.patterns.dea_number");
        assert_eq!(
            coverage.uncovered(),
            vec!["rules.secret_patterns.patterns.dea"]
        );
    }

    #[test]
    fn receipt_members_are_compared_partially() {
        let expected = serde_json::json!({"policy": {"content_hash": "sha256:abc"}});
        let actual = serde_json::json!({
            "policy": {"content_hash": "sha256:abc", "spec_version": "0.1.0"}
        });
        assert!(
            receipt_member_mismatch("policy", &expected["policy"], actual.get("policy")).is_none()
        );
    }

    #[test]
    fn a_differing_receipt_member_names_its_path() {
        let expected = serde_json::json!({"content_hash": "sha256:abc"});
        let actual = serde_json::json!({"content_hash": "sha256:def"});
        let mismatch = receipt_member_mismatch("policy", &expected, Some(&actual))
            .expect("the member differs");
        assert_eq!(mismatch.field, "receipt.policy.content_hash");
        assert_eq!(mismatch.expected, "\"sha256:abc\"");
        assert_eq!(mismatch.actual, "\"sha256:def\"");
    }

    #[test]
    fn xml_escaping_covers_the_attribute_delimiters() {
        assert_eq!(
            xml_escape("a<b>&\"c\"'d'"),
            "a&lt;b&gt;&amp;&quot;c&quot;&apos;d&apos;"
        );
    }
}
