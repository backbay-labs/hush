use crate::fixture::{FixtureCategory, TestFixture};
use hushspec::receipt::{RuleOutcome, RuleTraceEntry};
use hushspec::{
    Decision, EvaluationAction, HushSpec, PostureResult, Resolution,
    evaluate_with_detection_traced, merge,
};
use jsonschema::JSONSchema;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

/// Fixture format versions this runner accepts (evaluator-test schema).
const SUPPORTED_TEST_VERSIONS: &[&str] = &["0.1.0", "0.2.0"];

/// Fixed evaluation time for `expect.receipt`: 2026-09-15T12:00:00.000Z, the
/// clock `fixtures/receipts/expected/README.md` pins.
const RECEIPT_CLOCK_MILLIS: u64 = 1_789_473_600_000;

/// Receipt members that are inputs rather than outcomes, never compared.
const RECEIPT_IGNORED_MEMBERS: [&str; 3] = ["actor", "timestamp", "receipt_id"];

#[derive(Debug, Clone)]
pub struct TestResult {
    pub fixture_path: String,
    pub category: FixtureCategory,
    pub passed: bool,
    pub message: String,
}

/// Run conformance tests for all fixtures.
pub fn run_conformance(fixtures: &[TestFixture]) -> Vec<TestResult> {
    let mut results = Vec::new();
    let mut merge_fixtures = Vec::new();

    for fixture in fixtures {
        let result = match fixture.category {
            FixtureCategory::ValidCore
            | FixtureCategory::PostureValid
            | FixtureCategory::OriginsValid
            | FixtureCategory::DetectionValid => test_valid_fixture(fixture),

            FixtureCategory::InvalidCore
            | FixtureCategory::PostureInvalid
            | FixtureCategory::OriginsInvalid
            | FixtureCategory::DetectionInvalid => test_invalid_fixture(fixture),

            FixtureCategory::Evaluation => test_evaluation_fixture(fixture),

            FixtureCategory::Hash => test_hash_fixture(fixture),

            FixtureCategory::Resolve => test_resolve_fixture(fixture),

            FixtureCategory::MergeBase
            | FixtureCategory::MergeChild
            | FixtureCategory::MergeExpected => {
                merge_fixtures.push(fixture.clone());
                continue;
            }
        };
        results.push(result);
    }

    results.extend(test_merge_fixtures(&merge_fixtures));
    results
}

fn test_valid_fixture(fixture: &TestFixture) -> TestResult {
    let path = fixture.path.display().to_string();
    match HushSpec::parse(&fixture.content) {
        Ok(spec) => {
            let validation = hushspec::validate(&spec);
            if validation.is_valid() {
                TestResult {
                    fixture_path: path,
                    category: fixture.category,
                    passed: true,
                    message: "OK".to_string(),
                }
            } else {
                let errors: Vec<String> = validation.errors.iter().map(|e| e.to_string()).collect();
                TestResult {
                    fixture_path: path,
                    category: fixture.category,
                    passed: false,
                    message: format!("Validation failed: {}", errors.join(", ")),
                }
            }
        }
        Err(e) => TestResult {
            fixture_path: path,
            category: fixture.category,
            passed: false,
            message: format!("Parse failed: {e}"),
        },
    }
}

fn test_invalid_fixture(fixture: &TestFixture) -> TestResult {
    let path = fixture.path.display().to_string();
    match HushSpec::parse(&fixture.content) {
        Ok(spec) => {
            let validation = hushspec::validate(&spec);
            if validation.is_valid() {
                TestResult {
                    fixture_path: path,
                    category: fixture.category,
                    passed: false,
                    message: "Expected rejection but document was accepted".to_string(),
                }
            } else {
                TestResult {
                    fixture_path: path,
                    category: fixture.category,
                    passed: true,
                    message: format!("Correctly rejected: {}", validation.errors[0]),
                }
            }
        }
        Err(_) => TestResult {
            fixture_path: path,
            category: fixture.category,
            passed: true,
            message: "Correctly rejected at parse time".to_string(),
        },
    }
}

fn test_evaluation_fixture(fixture: &TestFixture) -> TestResult {
    let path = fixture.path.display().to_string();
    let raw_json: serde_json::Value = match serde_yaml::from_str(&fixture.content) {
        Ok(value) => value,
        Err(e) => {
            return TestResult {
                fixture_path: path,
                category: fixture.category,
                passed: false,
                message: format!("Invalid YAML: {e}"),
            };
        }
    };

    if let Err(message) = validate_evaluator_schema(&raw_json) {
        return TestResult {
            fixture_path: path,
            category: fixture.category,
            passed: false,
            message,
        };
    }

    let doc: EvaluationFixture = match serde_json::from_value(raw_json) {
        Ok(doc) => doc,
        Err(error) => {
            return TestResult {
                fixture_path: path,
                category: fixture.category,
                passed: false,
                message: format!("Failed to deserialize evaluator fixture: {error}"),
            };
        }
    };

    if !SUPPORTED_TEST_VERSIONS.contains(&doc.hushspec_test.as_str()) {
        return TestResult {
            fixture_path: path,
            category: fixture.category,
            passed: false,
            message: format!(
                "Unsupported hushspec_test version in evaluator fixture: {} (supported: {})",
                doc.hushspec_test,
                SUPPORTED_TEST_VERSIONS.join(", ")
            ),
        };
    }

    let policy_yaml = match serde_yaml::to_string(&doc.policy) {
        Ok(yaml) => yaml,
        Err(error) => {
            return TestResult {
                fixture_path: path,
                category: fixture.category,
                passed: false,
                message: format!("Failed to serialize embedded policy: {error}"),
            };
        }
    };
    let parsed = match HushSpec::parse(&policy_yaml) {
        Ok(spec) => spec,
        Err(error) => {
            return TestResult {
                fixture_path: path,
                category: fixture.category,
                passed: false,
                message: format!("Embedded policy failed to parse: {error}"),
            };
        }
    };

    // An embedded policy that extends is resolved before it runs -- the
    // library suites (`fixtures/library/`) are a leaf naming
    // `builtin:library/<vertical>/<name>` -- because a bare leaf would drop
    // every block its base declares and pass for the wrong reason.
    let spec = if parsed.extends.is_none() {
        parsed
    } else {
        let loader = hushspec::create_composite_loader();
        match hushspec::resolve_with_loader(&parsed, Some(&path), &loader) {
            Ok(resolved) => resolved,
            Err(error) => {
                return TestResult {
                    fixture_path: path,
                    category: fixture.category,
                    passed: false,
                    message: format!("Embedded policy failed to resolve: {error}"),
                };
            }
        }
    };

    let validation = hushspec::validate(&spec);
    if !validation.is_valid() {
        let errors: Vec<String> = validation.errors.iter().map(|e| e.to_string()).collect();
        return TestResult {
            fixture_path: path,
            category: fixture.category,
            passed: false,
            message: format!("Embedded policy failed validation: {}", errors.join(", ")),
        };
    }

    let resolution = Resolution::from_resolved(&spec, None);

    for (index, case) in doc.cases.iter().enumerate() {
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

        let mut message = compare_expected(&case.expect, &traced.evaluation);
        if message.is_none()
            && let Some(expected_trace) = &case.expect.rule_trace
        {
            message = compare_rule_trace(expected_trace, &trace);
        }
        if message.is_none()
            && let Some(expected_receipt) = &case.expect.receipt
        {
            message = match &resolution {
                Ok(resolution) => compare_receipt(
                    expected_receipt,
                    resolution,
                    &action,
                    case.context.as_ref(),
                    index,
                ),
                Err(error) => Some(format!("expect.receipt needs a resolvable policy: {error}")),
            };
        }

        if let Some(message) = message {
            return TestResult {
                fixture_path: path,
                category: fixture.category,
                passed: false,
                message: format!("cases[{index}] {}: {message}", case.description),
            };
        }
    }

    TestResult {
        fixture_path: path,
        category: fixture.category,
        passed: true,
        message: format!("OK ({} evaluated cases)", doc.cases.len()),
    }
}

/// Render one recorded trace entry the way a mismatch reports it.
fn render_trace_entry(
    rule_block: &str,
    outcome: RuleOutcome,
    rule_path: Option<&String>,
) -> String {
    match rule_path {
        Some(rule_path) => format!("{rule_block}:{outcome:?}@{rule_path}"),
        None => format!("{rule_block}:{outcome:?}"),
    }
}

/// Compare a fixture's `expect.rule_trace` with the recorded trace (receipt
/// spec 4.3): in order, in full, and member by member -- `rule_path` only
/// where the fixture spells it.
fn compare_rule_trace(
    expected: &[RuleTraceExpectation],
    actual: &[RuleTraceEntry],
) -> Option<String> {
    let rendered_actual: Vec<String> = actual
        .iter()
        .map(|entry| render_trace_entry(&entry.rule_block, entry.outcome, entry.rule_path.as_ref()))
        .collect();

    if expected.len() != actual.len() {
        return Some(format!(
            "expected {} rule_trace entries, got {} [{}]",
            expected.len(),
            actual.len(),
            rendered_actual.join(", ")
        ));
    }

    for (index, (want, got)) in expected.iter().zip(actual).enumerate() {
        let matches = want.rule_block == got.rule_block
            && want.outcome == got.outcome
            && want
                .rule_path
                .as_ref()
                .is_none_or(|rule_path| got.rule_path.as_ref() == Some(rule_path));
        if !matches {
            return Some(format!(
                "rule_trace[{index}]: expected {}, got {}",
                render_trace_entry(&want.rule_block, want.outcome, want.rule_path.as_ref()),
                rendered_actual[index]
            ));
        }
    }
    None
}

/// Build the receipt for one case under the fixed inputs of
/// `fixtures/receipts/expected/README.md` and compare the members the fixture
/// spelled. Nested objects are compared member-wise; everything else exactly.
fn compare_receipt(
    expected: &serde_json::Value,
    resolution: &Resolution,
    action: &EvaluationAction,
    context: Option<&hushspec::RuntimeContext>,
    case_index: usize,
) -> Option<String> {
    let config = hushspec::AuditConfig {
        enabled: true,
        include_rule_trace: true,
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
    let actual = serde_json::to_value(&receipt).ok()?;

    for (key, want) in expected.as_object()? {
        if RECEIPT_IGNORED_MEMBERS.contains(&key.as_str()) {
            continue;
        }
        if let Some(message) = receipt_member_mismatch(key, want, actual.get(key)) {
            return Some(message);
        }
    }
    None
}

fn receipt_member_mismatch(
    path: &str,
    expected: &serde_json::Value,
    actual: Option<&serde_json::Value>,
) -> Option<String> {
    match (expected, actual) {
        (serde_json::Value::Object(want), Some(serde_json::Value::Object(got))) => {
            want.iter().find_map(|(key, value)| {
                receipt_member_mismatch(&format!("{path}.{key}"), value, got.get(key))
            })
        }
        (_, Some(got)) if got == expected => None,
        (_, got) => Some(format!(
            "receipt.{path}: expected {expected}, got {}",
            got.map_or_else(|| "(absent)".to_string(), ToString::to_string)
        )),
    }
}

/// A canonical-form vector (spec/hushspec-canonical.md section 7): a resolved
/// document paired with the exact canonical text and content hash every
/// conformant implementation must produce for it.
///
/// The vector's `policy` is projected as a value tree, which is the path the
/// specification recommends (canonical spec 6) and the only one that can
/// express the absent/empty distinctions of section 3.3.
fn test_hash_fixture(fixture: &TestFixture) -> TestResult {
    let path = fixture.path.display().to_string();
    let fail = |message: String| TestResult {
        fixture_path: path.clone(),
        category: fixture.category,
        passed: false,
        message,
    };

    let vector: HashVector = match serde_yaml::from_str(&fixture.content) {
        Ok(vector) => vector,
        Err(error) => return fail(format!("Invalid canonical-form vector: {error}")),
    };
    if vector.hushspec_hash_vector != HASH_VECTOR_VERSION {
        return fail(format!(
            "Unsupported hushspec_hash_vector version: {}",
            vector.hushspec_hash_vector
        ));
    }

    // A vector's `policy` is already resolved; resolve defensively so a future
    // vector that ships an `extends` chain is canonicalized after resolution
    // rather than hashed as a fragment (canonical spec 2.1).
    let document = if vector.policy.get("extends").is_some() {
        match resolve_vector_policy(&vector.policy) {
            Ok(document) => document,
            Err(message) => return fail(message),
        }
    } else {
        vector.policy.clone()
    };

    let canonical = match hushspec::canonical_json_value(&document) {
        Ok(canonical) => canonical,
        Err(error) => return fail(format!("Canonicalization failed: {error}")),
    };
    if canonical != vector.canonical {
        return fail(format!(
            "Canonical form mismatch: expected {} bytes, got {} bytes",
            vector.canonical.len(),
            canonical.len()
        ));
    }

    let digest = hushspec::canonical::digest(&canonical);
    if digest != vector.content_hash {
        return fail(format!(
            "content_hash mismatch: expected {}, got {digest}",
            vector.content_hash
        ));
    }

    TestResult {
        fixture_path: path,
        category: fixture.category,
        passed: true,
        message: format!("OK ({digest})"),
    }
}

/// A resolution vector (core spec 2.3, receipt spec 4.2): an inline leaf
/// whose `extends` references builtins, expected to resolve to a given
/// content hash and chain, or to be rejected with a given reason.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveVector {
    hushspec_resolve: String,
    #[allow(dead_code)]
    description: String,
    policy: serde_json::Value,
    expect: ResolveExpect,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveExpect {
    #[serde(default)]
    #[allow(dead_code)]
    resolves: Option<bool>,
    #[serde(default)]
    content_hash: Option<String>,
    #[serde(default)]
    chain: Option<Vec<ResolveLink>>,
    #[serde(default)]
    rejects: Option<String>,
}

#[derive(serde::Deserialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
struct ResolveLink {
    source: String,
    content_hash: String,
}

fn resolve_reason(error: &hushspec::ResolveError) -> &'static str {
    use hushspec::ResolveError as E;
    match error {
        E::DigestMismatch { .. } => "digest_mismatch",
        E::InvalidPin { .. } => "invalid_pin",
        E::Cycle { .. } => "cycle",
        E::MaxDepth => "max_depth",
        E::NotFound { .. } => "not_found",
        E::SignatureRequired { .. } => "signature_required",
        _ => "error",
    }
}

fn test_resolve_fixture(fixture: &TestFixture) -> TestResult {
    let path = fixture.path.display().to_string();
    let fail = |message: String| TestResult {
        fixture_path: path.clone(),
        category: fixture.category,
        passed: false,
        message,
    };
    let vector: ResolveVector = match serde_yaml::from_str(&fixture.content) {
        Ok(vector) => vector,
        Err(error) => return fail(format!("Invalid resolve vector: {error}")),
    };
    if vector.hushspec_resolve != "0.1.0" {
        return fail(format!(
            "Unsupported hushspec_resolve version: {}",
            vector.hushspec_resolve
        ));
    }
    let yaml = match serde_yaml::to_string(&vector.policy) {
        Ok(yaml) => yaml,
        Err(error) => return fail(format!("Failed to re-encode the policy: {error}")),
    };
    let spec = match HushSpec::parse(&yaml) {
        Ok(spec) => spec,
        Err(error) => return fail(format!("Policy failed to parse: {error}")),
    };
    let loader = hushspec::create_composite_loader();
    let result =
        hushspec::resolve_with_options(&spec, None, &loader, &hushspec::ResolveOptions::default());
    match (&vector.expect.rejects, result) {
        (Some(expected), Err(error)) if resolve_reason(&error) == expected => TestResult {
            fixture_path: path,
            category: fixture.category,
            passed: true,
            message: format!("Correctly rejected: {expected}"),
        },
        (Some(expected), Err(error)) => fail(format!(
            "Expected rejection {expected}, got {}: {error}",
            resolve_reason(&error)
        )),
        (Some(expected), Ok(_)) => fail(format!("Expected rejection {expected}, but it resolved")),
        (None, Err(error)) => fail(format!("Expected to resolve: {error}")),
        (None, Ok(resolution)) => {
            if let Some(expected) = &vector.expect.content_hash
                && expected != &resolution.content_hash
            {
                return fail(format!(
                    "content_hash mismatch: expected {expected}, got {}",
                    resolution.content_hash
                ));
            }
            if let Some(expected) = &vector.expect.chain {
                let actual: Vec<ResolveLink> = resolution
                    .chain
                    .iter()
                    .map(|link| ResolveLink {
                        source: link.source.clone(),
                        content_hash: link.content_hash.clone(),
                    })
                    .collect();
                if &actual != expected {
                    return fail(format!(
                        "chain mismatch: expected {expected:?}, got {actual:?}"
                    ));
                }
            }
            TestResult {
                fixture_path: path,
                category: fixture.category,
                passed: true,
                message: format!("OK ({} link(s))", resolution.chain.len()),
            }
        }
    }
}

fn resolve_vector_policy(policy: &serde_json::Value) -> Result<serde_json::Value, String> {
    let yaml = serde_yaml::to_string(policy)
        .map_err(|error| format!("Failed to re-encode the policy: {error}"))?;
    let spec = HushSpec::parse(&yaml).map_err(|error| format!("Failed to parse: {error}"))?;
    let resolved = hushspec::resolve_with_loader(&spec, None, &hushspec::create_composite_loader())
        .map_err(|error| format!("Failed to resolve: {error}"))?;
    serde_json::to_value(&resolved)
        .map_err(|error| format!("Failed to re-encode the resolved policy: {error}"))
}

fn test_merge_fixtures(fixtures: &[TestFixture]) -> Vec<TestResult> {
    if fixtures.is_empty() {
        return Vec::new();
    }

    let mut grouped: BTreeMap<String, Vec<TestFixture>> = BTreeMap::new();
    for fixture in fixtures {
        let Some(parent) = fixture.path.parent() else {
            continue;
        };
        grouped
            .entry(parent.display().to_string())
            .or_default()
            .push(fixture.clone());
    }

    let mut results = Vec::new();
    for (group_path, group_fixtures) in grouped {
        let Some(base_fixture) = group_fixtures
            .iter()
            .find(|fixture| fixture.category == FixtureCategory::MergeBase)
        else {
            results.push(TestResult {
                fixture_path: group_path,
                category: FixtureCategory::MergeBase,
                passed: false,
                message: "Missing merge base fixture".to_string(),
            });
            continue;
        };

        let base_spec = match HushSpec::parse(&base_fixture.content) {
            Ok(spec) => spec,
            Err(error) => {
                results.push(TestResult {
                    fixture_path: base_fixture.path.display().to_string(),
                    category: FixtureCategory::MergeBase,
                    passed: false,
                    message: format!("Failed to parse merge base: {error}"),
                });
                continue;
            }
        };

        results.extend(
            group_fixtures
                .iter()
                .filter(|fixture| fixture.category == FixtureCategory::MergeChild)
                .map(|child_fixture| test_merge_case(&base_spec, child_fixture, &group_fixtures)),
        );
    }
    results
}

fn test_merge_case(
    base: &HushSpec,
    child_fixture: &TestFixture,
    fixtures: &[TestFixture],
) -> TestResult {
    let path = child_fixture.path.display().to_string();
    let child_name = child_fixture
        .path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    let expected_name = child_name.replacen("child-", "expected-", 1);

    let Some(expected_fixture) = fixtures.iter().find(|fixture| {
        fixture.category == FixtureCategory::MergeExpected
            && fixture
                .path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or_default()
                == expected_name
    }) else {
        return TestResult {
            fixture_path: path,
            category: FixtureCategory::MergeChild,
            passed: false,
            message: format!("Missing expected fixture: {expected_name}.yaml"),
        };
    };

    let child_spec = match HushSpec::parse(&child_fixture.content) {
        Ok(spec) => spec,
        Err(error) => {
            return TestResult {
                fixture_path: path,
                category: FixtureCategory::MergeChild,
                passed: false,
                message: format!("Failed to parse merge child: {error}"),
            };
        }
    };
    let expected_spec = match HushSpec::parse(&expected_fixture.content) {
        Ok(spec) => spec,
        Err(error) => {
            return TestResult {
                fixture_path: path,
                category: FixtureCategory::MergeChild,
                passed: false,
                message: format!("Failed to parse expected merge fixture: {error}"),
            };
        }
    };

    let merged = merge(base, &child_spec);
    if merged == expected_spec {
        TestResult {
            fixture_path: path,
            category: FixtureCategory::MergeChild,
            passed: true,
            message: format!("OK (matched {expected_name}.yaml)"),
        }
    } else {
        TestResult {
            fixture_path: path,
            category: FixtureCategory::MergeChild,
            passed: false,
            message: format!("Merged result did not match {expected_name}.yaml"),
        }
    }
}

/// Vector format version (`schemas/hushspec-hash-vector.v0.schema.json`).
const HASH_VECTOR_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HashVector {
    hushspec_hash_vector: String,
    #[allow(dead_code)]
    description: String,
    /// Informational: the unresolved document `policy` came from.
    #[serde(default)]
    #[allow(dead_code)]
    source: Option<serde_json::Value>,
    policy: serde_json::Value,
    canonical: String,
    content_hash: String,
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
    /// Runtime context for `when` conditions (core spec 3.13); copied onto the
    /// action before evaluation.
    #[serde(default)]
    context: Option<hushspec::RuntimeContext>,
    /// The controls this case is evidence for (evaluator-test 0.2). Carried by
    /// the fixture for reporting; a conformance verdict does not depend on it.
    #[serde(default)]
    #[allow(dead_code)]
    controls: Vec<serde_json::Value>,
    /// Free-form labels (evaluator-test 0.2).
    #[serde(default)]
    #[allow(dead_code)]
    tags: Vec<String>,
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
    /// The recorded rule trace, asserted in order and in full when present
    /// (evaluator-test 0.2).
    #[serde(default)]
    rule_trace: Option<Vec<RuleTraceExpectation>>,
    /// A partial format 0.2 receipt, asserted member-wise when present
    /// (evaluator-test 0.2).
    #[serde(default)]
    receipt: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RuleTraceExpectation {
    rule_block: String,
    outcome: RuleOutcome,
    #[serde(default)]
    rule_path: Option<String>,
}

/// Validate a value against the evaluator-test fixture schema.
///
/// `pub(crate)` so `emit::build_regression_fixture` can refuse to emit a
/// fixture that would fail this exact check -- the same schema, the same
/// compiled `JSONSchema`, no reimplementation drift between "what the runner
/// accepts" and "what the emitter promises is valid".
pub(crate) fn validate_evaluator_schema(value: &serde_json::Value) -> Result<(), String> {
    match evaluator_schema().validate(value) {
        Ok(()) => Ok(()),
        Err(errors) => {
            let messages: Vec<String> = errors.map(|error| error.to_string()).collect();
            Err(format!(
                "Evaluator fixture did not match schema: {}",
                messages.join(", ")
            ))
        }
    }
}

fn evaluator_schema() -> &'static JSONSchema {
    static SCHEMA: OnceLock<JSONSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let schema_json: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/hushspec-evaluator-test.v0.schema.json"
        ))
        .expect("evaluator schema should be valid JSON");
        // The evaluator fixture schema has no `format` keyword today, but formats
        // are asserted deliberately (rather than left at the draft's default) so
        // that if a `format` keyword is ever added here, it is enforced instead
        // of silently becoming a non-asserting annotation under draft 2020-12.
        JSONSchema::options()
            .should_validate_formats(true)
            .compile(&schema_json)
            .expect("evaluator schema should compile")
    })
}

fn compare_expected(
    expected: &ExpectedEvaluation,
    actual: &hushspec::EvaluationResult,
) -> Option<String> {
    if expected.decision != actual.decision {
        return Some(format!(
            "expected decision {:?}, got {:?}",
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
    if let Some(expected_origin_profile) = &expected.origin_profile
        && actual.origin_profile.as_ref() != Some(expected_origin_profile)
    {
        return Some(format!(
            "expected origin_profile {:?}, got {:?}",
            expected_origin_profile, actual.origin_profile
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
