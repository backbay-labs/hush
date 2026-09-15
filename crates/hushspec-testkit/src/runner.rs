use crate::fixture::{FixtureCategory, TestFixture};
use hushspec::{Decision, EvaluationAction, HushSpec, PostureResult, evaluate_with_detection};
use jsonschema::JSONSchema;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::OnceLock;

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
    let result = |passed: bool, message: String| TestResult {
        fixture_path: path.clone(),
        category: fixture.category,
        passed,
        message,
    };

    // The refusal, as a registered error code plus its diagnostic
    // (spec/registries/error-codes.yaml).
    let refusal: Option<(&str, String)> = match HushSpec::parse(&fixture.content) {
        Err(error) => Some((crate::expect::parse_error_code(), error.to_string())),
        Ok(spec) => {
            let validation = hushspec::validate(&spec);
            validation.errors.first().map(|error| {
                (
                    crate::expect::validation_error_code(error),
                    error.to_string(),
                )
            })
        }
    };

    let Some((code, message)) = refusal else {
        return result(
            false,
            "Expected rejection but document was accepted".to_string(),
        );
    };

    // Every invalid vector names the code its rejection must carry, so a
    // vector cannot pass by being refused for an unrelated reason.
    match crate::expect::load(&fixture.path) {
        Err(error) => result(false, error),
        Ok(None) => result(
            false,
            format!(
                "no {} sidecar: every invalid vector must name the error code it is rejected \
                 with (spec/registries/error-codes.yaml)",
                crate::expect::SIDECAR_SUFFIX
            ),
        ),
        Ok(Some(expected)) => match crate::expect::check(&expected, code, &message) {
            Some(problem) => result(false, problem),
            None => result(true, format!("Correctly rejected [{code}]: {message}")),
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

    if doc.hushspec_test != "0.1.0" {
        return TestResult {
            fixture_path: path,
            category: fixture.category,
            passed: false,
            message: format!(
                "Unsupported hushspec_test version in evaluator fixture: {}",
                doc.hushspec_test
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
    match HushSpec::parse(&policy_yaml) {
        Ok(spec) => {
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

            for (index, case) in doc.cases.iter().enumerate() {
                let mut action = case.action.clone();
                if action.context.is_none() {
                    action.context = case.context.clone();
                }
                let actual = evaluate_with_detection(&spec, &action).evaluation;
                if let Some(message) = compare_expected(&case.expect, &actual) {
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
        Err(error) => TestResult {
            fixture_path: path,
            category: fixture.category,
            passed: false,
            message: format!("Embedded policy failed to parse: {error}"),
        },
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
    let dir = child_fixture
        .path
        .parent()
        .unwrap_or(std::path::Path::new("."));

    // A vector marked as a refusal (an `expect-reject` file, or `reject: true`
    // in the directory's fixture.yaml) has no expected document: the failure
    // is the assertion.
    if crate::merge_vector::child_expects_reject(dir, &child_fixture.path) {
        return match crate::merge_vector::compose(base, &child_fixture.path) {
            Ok(_) => TestResult {
                fixture_path: path,
                category: FixtureCategory::MergeChild,
                passed: false,
                message: "Expected the vector to be refused, but it composed".to_string(),
            },
            Err(error) => TestResult {
                fixture_path: path,
                category: FixtureCategory::MergeChild,
                passed: true,
                message: format!("Correctly refused: {error}"),
            },
        };
    }

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

    // A child that pins its base by digest is resolved rather than merged, so
    // the pin is actually checked; every other child keeps the direct
    // merge(base, child) the corpus has always been checked with.
    let merged = match crate::merge_vector::compose(base, &child_fixture.path) {
        Ok(merged) => merged,
        Err(error) => {
            return TestResult {
                fixture_path: path,
                category: FixtureCategory::MergeChild,
                passed: false,
                message: format!("Failed to compose merge vector: {error}"),
            };
        }
    };
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
        // Embedded via the generated module rather than `include_str!`: the
        // schemas live outside the crate directory and would not survive
        // `cargo package` (see scripts/generate_testkit_schemas.py).
        let schema_json: serde_json::Value = serde_json::from_str(
            crate::generated_schemas::schema_body("evaluator-test")
                .expect("the evaluator-test schema is embedded"),
        )
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
