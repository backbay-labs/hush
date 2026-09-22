//! Raw YAML scalar vectors for Levels 1, 3, and 4.
//!
//! The JSON container carries the YAML source spelling.  Each case is passed
//! directly to the public parser; it is never decoded and re-emitted as YAML
//! before parsing, because spelling is the property this corpus exercises.

use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

use crate::report::{Status, VectorResult};

const CATEGORY: &str = "raw-yaml";
const CANONICAL_CATEGORY: &str = "raw-yaml-canonical";
const EVALUATION_CATEGORY: &str = "raw-yaml-evaluation";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawYamlVector {
    id: String,
    yaml: String,
    accept: bool,
    #[serde(default)]
    value_path: Option<Vec<String>>,
    #[serde(default)]
    value: CorpusValue,
    #[serde(default)]
    canonical: Option<String>,
    #[serde(default)]
    decision: Option<String>,
}

/// `Option<Value>` treats both a missing member and JSON `null` as `None`.
/// The corpus needs to assert a literal null, so retain member presence.
#[derive(Debug, Default)]
struct CorpusValue {
    present: bool,
    value: Value,
}

impl<'de> Deserialize<'de> for CorpusValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self {
            present: true,
            value: Value::deserialize(deserializer)?,
        })
    }
}

fn label(path: &Path) -> String {
    crate::manifest::relative_fixture_path(path).unwrap_or_else(|| path.display().to_string())
}

fn result(path: String, category: &str, level: u8, passed: bool, message: String) -> VectorResult {
    VectorResult {
        path,
        category: category.to_string(),
        level: Some(level),
        status: if passed { Status::Pass } else { Status::Fail },
        message: Some(message),
        parser_failure: false,
    }
}

fn parse_failure(path: String, message: String) -> VectorResult {
    let mut outcome = result(path, CATEGORY, 1, false, message);
    outcome.parser_failure = true;
    outcome
}

fn malformed(path: String, detail: impl std::fmt::Display) -> VectorResult {
    parse_failure(path, format!("malformed raw YAML corpus: {detail}"))
}

/// Run `fixtures/core/raw-yaml/scalars.json`.
///
/// A case always yields a Level 1 parse/value result. Its optional decision
/// and canonical/hash assertions yield independent Level 3 and Level 4
/// results, so a failed advanced assertion cannot lower the parser score.
/// A missing or malformed corpus produces a failed Level 1 result, never an
/// empty successful run.
pub fn run_raw_yaml_vectors(fixtures_dir: &Path) -> Vec<VectorResult> {
    let path = fixtures_dir.join("core/raw-yaml/scalars.json");
    let corpus = label(&path);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => return vec![malformed(corpus, error)],
    };
    let cases: Vec<Value> = match serde_json::from_str(&text) {
        Ok(cases) => cases,
        Err(error) => return vec![malformed(corpus, error)],
    };
    if cases.is_empty() {
        return vec![malformed(corpus, "the corpus contains no cases")];
    }

    let mut results = Vec::new();
    for (index, value) in cases.into_iter().enumerate() {
        let vector: RawYamlVector = match serde_json::from_value(value) {
            Ok(vector) => vector,
            Err(error) => {
                results.push(malformed(format!("{corpus}#{index}"), error));
                continue;
            }
        };
        let name = format!("{corpus}#{}", vector.id);
        let value_assertion = vector.value_path.is_some() && vector.value.present;
        if vector.value_path.is_some() != vector.value.present {
            results.push(malformed(
                name,
                "value_path and value must either both be present or both be absent",
            ));
            continue;
        }
        if !vector.accept
            && (value_assertion || vector.canonical.is_some() || vector.decision.is_some())
        {
            results.push(malformed(
                name,
                "a rejected case cannot carry value, canonical, or decision assertions",
            ));
            continue;
        }

        // `yaml` is the exact string from the JSON corpus. Do not normalize,
        // parse, or re-emit it before this call.
        let parsed = hushspec::HushSpec::parse(&vector.yaml);
        match (parsed, vector.accept) {
            (Err(error), true) => {
                results.push(parse_failure(name, format!("expected acceptance: {error}")));
            }
            (Err(error), false) => {
                results.push(result(
                    name,
                    CATEGORY,
                    1,
                    true,
                    format!("correctly rejected: {error}"),
                ));
            }
            (Ok(_), false) => {
                results.push(parse_failure(
                    name,
                    "expected rejection but parsed successfully".to_string(),
                ));
            }
            (Ok(policy), true) => {
                let canonical = match hushspec::canonical_json(&policy) {
                    Ok(canonical) => canonical,
                    Err(error) => {
                        results.push(result(
                            name,
                            CATEGORY,
                            1,
                            false,
                            format!("canonical projection for value assertion: {error}"),
                        ));
                        continue;
                    }
                };

                let value_ok = if let Some(path) = &vector.value_path {
                    let expected = &vector.value.value;
                    match value_at_path(&canonical, path) {
                        Ok(actual) if actual == *expected => true,
                        Ok(actual) => {
                            results.push(result(
                                name.clone(),
                                CATEGORY,
                                1,
                                false,
                                format!(
                                    "value at {}: expected {expected}, got {actual}",
                                    path.join(".")
                                ),
                            ));
                            false
                        }
                        Err(error) => {
                            results.push(result(name.clone(), CATEGORY, 1, false, error));
                            false
                        }
                    }
                } else {
                    true
                };
                if value_ok {
                    results.push(result(
                        name.clone(),
                        CATEGORY,
                        1,
                        true,
                        "parsed and decoded as expected".to_string(),
                    ));
                }

                if let Some(expected) = vector.canonical {
                    let actual_hash = hushspec::content_hash(&policy);
                    let expected_hash = hushspec::canonical::digest(&expected);
                    let passed = canonical == expected
                        && actual_hash.as_deref() == Ok(expected_hash.as_str());
                    let message = if passed {
                        "canonical form and content hash match".to_string()
                    } else {
                        format!(
                            "canonical/hash mismatch: canonical_match={}, expected_hash={expected_hash}, actual_hash={}",
                            canonical == expected,
                            actual_hash.unwrap_or_else(|error| format!("error: {error}")),
                        )
                    };
                    results.push(result(name.clone(), CANONICAL_CATEGORY, 4, passed, message));
                }

                if let Some(expected) = vector.decision {
                    let action = hushspec::EvaluationAction {
                        action_type: "egress".to_string(),
                        target: Some("example.com".to_string()),
                        context: Some(hushspec::RuntimeContext {
                            counters: std::collections::HashMap::from([(
                                "requests".to_string(),
                                9,
                            )]),
                            ..Default::default()
                        }),
                        ..Default::default()
                    };
                    let actual =
                        serde_json::to_value(hushspec::evaluate(&policy, &action).decision)
                            .expect("Decision serializes");
                    let passed = actual == Value::String(expected.clone());
                    results.push(result(
                        name,
                        EVALUATION_CATEGORY,
                        3,
                        passed,
                        if passed {
                            format!("decision {expected} as expected")
                        } else {
                            format!("expected decision {expected}, got {actual}")
                        },
                    ));
                }
            }
        }
    }
    results
}

fn value_at_path(canonical: &str, path: &[String]) -> Result<Value, String> {
    let mut value: Value = serde_json::from_str(canonical)
        .map_err(|error| format!("canonical JSON could not be read back: {error}"))?;
    for key in path {
        value = match &value {
            Value::Object(entries) => entries.get(key).cloned(),
            Value::Array(entries) => key
                .parse::<usize>()
                .ok()
                .and_then(|index| entries.get(index).cloned()),
            _ => None,
        }
        .ok_or_else(|| format!("value_path {} is absent", path.join(".")))?;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
    }

    #[test]
    fn raw_yaml_cases_are_all_scored_and_rejections_are_explicit() {
        let results = run_raw_yaml_vectors(&fixtures_dir());
        let cases: Vec<Value> = serde_json::from_str(
            &std::fs::read_to_string(fixtures_dir().join("core/raw-yaml/scalars.json"))
                .expect("corpus reads"),
        )
        .expect("corpus parses");
        assert_eq!(
            results
                .iter()
                .filter(|result| result.category == CATEGORY)
                .count(),
            cases.len()
        );
        let failures: Vec<String> = results
            .iter()
            .filter(|result| result.status != Status::Pass)
            .map(|result| {
                format!(
                    "{}: {}",
                    result.path,
                    result.message.as_deref().unwrap_or_default()
                )
            })
            .collect();
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert_eq!(
            results
                .iter()
                .filter(|result| result.category == CATEGORY)
                .filter(|result| result
                    .message
                    .as_deref()
                    .is_some_and(|message| message.starts_with("correctly rejected:")))
                .count(),
            cases.iter().filter(|case| case["accept"] == false).count(),
        );
    }

    #[test]
    fn missing_or_malformed_raw_yaml_corpus_fails_level_one() {
        let missing = tempfile::tempdir().expect("tempdir");
        let missing_results = run_raw_yaml_vectors(missing.path());
        assert_eq!(missing_results.len(), 1);
        assert_eq!(missing_results[0].level, Some(1));
        assert_eq!(missing_results[0].status, Status::Fail);
        assert!(missing_results[0].parser_failure);

        let malformed = tempfile::tempdir().expect("tempdir");
        let dir = malformed.path().join("core/raw-yaml");
        std::fs::create_dir_all(&dir).expect("create corpus directory");
        std::fs::write(dir.join("scalars.json"), "not JSON").expect("write malformed corpus");
        let malformed_results = run_raw_yaml_vectors(malformed.path());
        assert_eq!(malformed_results.len(), 1);
        assert_eq!(malformed_results[0].level, Some(1));
        assert_eq!(malformed_results[0].status, Status::Fail);
        assert!(malformed_results[0].parser_failure);
    }

    #[test]
    fn value_path_accepts_decimal_components_for_array_items() {
        let value = value_at_path(
            r#"{"rules":{"egress":{"when":{"not":{"any_of":[{"context":{"custom.value":0.5}}]}}}}}"#,
            &[
                "rules".to_string(),
                "egress".to_string(),
                "when".to_string(),
                "not".to_string(),
                "any_of".to_string(),
                "0".to_string(),
                "context".to_string(),
                "custom.value".to_string(),
            ],
        )
        .expect("array item resolves");
        assert_eq!(value, serde_json::json!(0.5));
    }
}
