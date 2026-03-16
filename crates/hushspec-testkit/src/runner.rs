use crate::fixture::{FixtureCategory, TestFixture};
use hushspec::{Decision, EvaluationAction, HushSpec, PostureResult, evaluate, merge};
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
                let actual = evaluate(&spec, &case.action);
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

fn validate_evaluator_schema(value: &serde_json::Value) -> Result<(), String> {
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
        JSONSchema::compile(&schema_json).expect("evaluator schema should compile")
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
