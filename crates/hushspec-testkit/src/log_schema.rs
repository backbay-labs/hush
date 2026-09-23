//! Schema-derived log-entry vectors for Level 5.

use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

use crate::report::{Status, VectorResult};

const CATEGORY: &str = "log-schema";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogSchemaVector {
    id: String,
    valid: bool,
    entry: Value,
}

fn label(path: &Path) -> String {
    crate::manifest::relative_fixture_path(path).unwrap_or_else(|| path.display().to_string())
}

fn result(path: String, passed: bool, message: String) -> VectorResult {
    VectorResult {
        path,
        category: CATEGORY.to_string(),
        level: Some(5),
        status: if passed { Status::Pass } else { Status::Fail },
        message: Some(message),
        parser_failure: false,
    }
}

/// Run `fixtures/log/schema-vectors.json` through the public log verifier.
///
/// A missing or malformed corpus is a failed Level 5 result. Invalid cases
/// pass only when the verifier actually refuses their entry.
pub fn run_log_schema_vectors(fixtures_dir: &Path) -> Vec<VectorResult> {
    let path = fixtures_dir.join("log/schema-vectors.json");
    let corpus = label(&path);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            return vec![result(
                corpus,
                false,
                format!("malformed log schema corpus: {error}"),
            )];
        }
    };
    let cases: Vec<Value> = match serde_json::from_str::<Vec<Value>>(&text) {
        Ok(cases) if !cases.is_empty() => cases,
        Ok(_) => {
            return vec![result(
                corpus,
                false,
                "malformed log schema corpus: the corpus contains no cases".to_string(),
            )];
        }
        Err(error) => {
            return vec![result(
                corpus,
                false,
                format!("malformed log schema corpus: {error}"),
            )];
        }
    };

    cases
        .into_iter()
        .enumerate()
        .map(
            |(index, value)| match serde_json::from_value::<LogSchemaVector>(value) {
                Err(error) => result(
                    format!("{corpus}#{index}"),
                    false,
                    format!("malformed log schema corpus: {error}"),
                ),
                Ok(vector) => {
                    let name = format!("{corpus}#{}", vector.id);
                    match hushspec::verify_log(
                        &vector.id,
                        &vector.entry.to_string(),
                        &hushspec::LogVerifyOptions::default(),
                    ) {
                        Ok(_) if vector.valid => result(name, true, "entry verifies".to_string()),
                        Ok(_) => result(
                            name,
                            false,
                            "expected rejection but entry verified".to_string(),
                        ),
                        Err(error) if vector.valid => {
                            result(name, false, format!("expected verification: {error}"))
                        }
                        Err(error) => result(name, true, format!("correctly rejected: {error}")),
                    }
                }
            },
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
    }

    #[test]
    fn log_schema_cases_are_all_scored_and_rejections_are_explicit() {
        let results = run_log_schema_vectors(&fixtures_dir());
        let cases: Vec<Value> = serde_json::from_str(
            &std::fs::read_to_string(fixtures_dir().join("log/schema-vectors.json"))
                .expect("corpus reads"),
        )
        .expect("corpus parses");
        assert_eq!(results.len(), cases.len());
        assert!(results.iter().all(|result| result.status == Status::Pass));
        assert_eq!(
            results
                .iter()
                .filter(|result| result
                    .message
                    .as_deref()
                    .is_some_and(|message| message.starts_with("correctly rejected:")))
                .count(),
            cases.iter().filter(|case| case["valid"] == false).count(),
        );
    }

    #[test]
    fn missing_or_malformed_log_schema_corpus_fails_level_five() {
        let missing = tempfile::tempdir().expect("tempdir");
        let missing_results = run_log_schema_vectors(missing.path());
        assert_eq!(missing_results.len(), 1);
        assert_eq!(missing_results[0].level, Some(5));
        assert_eq!(missing_results[0].status, Status::Fail);

        let malformed = tempfile::tempdir().expect("tempdir");
        let dir = malformed.path().join("log");
        std::fs::create_dir_all(&dir).expect("create corpus directory");
        std::fs::write(dir.join("schema-vectors.json"), "not JSON")
            .expect("write malformed corpus");
        let malformed_results = run_log_schema_vectors(malformed.path());
        assert_eq!(malformed_results.len(), 1);
        assert_eq!(malformed_results[0].level, Some(5));
        assert_eq!(malformed_results[0].status, Status::Fail);
    }
}
