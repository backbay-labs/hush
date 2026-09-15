//! Expected error codes for the `invalid/` vectors.
//!
//! "The document was rejected" is a weak assertion: a vector that tests the
//! YAML profile passes just as well when the engine refuses it for an
//! unrelated reason. Every `fixtures/<module>/invalid/<name>.yaml` therefore
//! has a `<name>.expect.yaml` sidecar naming the registered error code
//! (`spec/registries/error-codes.yaml`) its rejection must carry, and
//! optionally a substring the diagnostic must contain.
//!
//! The Rust reference asserts the code. TypeScript, Python, and Go still only
//! have to reject the vector: their validators do not emit registry codes yet
//! (RFC 09 P6-03), and core spec Section 8 Level 1 requires the code only of
//! implementations that do.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// A `<name>.expect.yaml` sidecar.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedError {
    /// Always `true`: a sidecar describes a refusal and nothing else.
    pub reject: bool,
    /// The registered code (`spec/registries/error-codes.yaml`).
    pub code: String,
    /// Optional literal substring the diagnostic must contain, for the broad
    /// codes where the code alone does not identify the requirement.
    #[serde(default)]
    pub message_contains: Option<String>,
}

/// The sidecar extension. A file with this suffix is metadata, never a vector.
pub const SIDECAR_SUFFIX: &str = ".expect.yaml";

/// Whether a path is an expected-error sidecar rather than a vector.
#[must_use]
pub fn is_sidecar(path: &Path) -> bool {
    path.to_string_lossy().ends_with(SIDECAR_SUFFIX)
}

/// The sidecar path for an `invalid/` vector: `a.yaml` -> `a.expect.yaml`.
#[must_use]
pub fn sidecar_path(vector: &Path) -> PathBuf {
    let text = vector.to_string_lossy().to_string();
    let stem = text
        .strip_suffix(".yaml")
        .or_else(|| text.strip_suffix(".yml"))
        .unwrap_or(&text);
    PathBuf::from(format!("{stem}{SIDECAR_SUFFIX}"))
}

/// Read the sidecar beside an `invalid/` vector.
///
/// `Ok(None)` means there is no sidecar; `Err` means there is one and it is
/// unusable, which is a failure rather than something to skip past.
pub fn load(vector: &Path) -> Result<Option<ExpectedError>, String> {
    let path = sidecar_path(vector);
    if !path.is_file() {
        return Ok(None);
    }
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let expected: ExpectedError = serde_yaml::from_str(&text)
        .map_err(|error| format!("{}: not an expected-error sidecar: {error}", path.display()))?;
    if !expected.reject {
        return Err(format!(
            "{}: `reject` must be true; a sidecar exists only to describe a refusal",
            path.display()
        ));
    }
    Ok(Some(expected))
}

/// The registered code for a refusal by the Rust reference implementation.
///
/// This mirrors, deliberately and in one place, the mapping `h2h validate`
/// prints (`crates/hushspec-cli/src/cmd_validate.rs`): a fixture's expected
/// code is the code a user would see.
#[must_use]
pub fn parse_error_code() -> &'static str {
    // Every HushSpec struct denies unknown fields, so unknown keys, missing
    // fields, type mismatches, bad enum variants and YAML profile violations
    // all surface as one parse refusal.
    "E001"
}

/// The registered code for a validation error.
#[must_use]
pub fn validation_error_code(error: &hushspec::ValidationError) -> &'static str {
    match error {
        hushspec::ValidationError::UnsupportedVersion(_) => "E002",
        hushspec::ValidationError::DuplicatePatternName(_) => "E003",
        hushspec::ValidationError::InvalidRegex { .. } => "E005",
        hushspec::ValidationError::InvalidDate { .. } => "E011",
        hushspec::ValidationError::Custom(_) => "E004",
    }
}

/// Check an actual refusal against a sidecar.
///
/// Returns `None` when the refusal matches, or a diagnostic when it does not.
#[must_use]
pub fn check(expected: &ExpectedError, actual_code: &str, actual_message: &str) -> Option<String> {
    if expected.code != actual_code {
        return Some(format!(
            "expected {} but the document was rejected with {actual_code}: {actual_message}",
            expected.code
        ));
    }
    if let Some(needle) = &expected.message_contains
        && !actual_message.contains(needle.as_str())
    {
        return Some(format!(
            "{actual_code} was reported, but the message does not contain {needle:?}: \
             {actual_message}"
        ));
    }
    None
}

/// The error-code registry (`spec/registries/error-codes.yaml`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub registry_version: String,
    pub codes: Vec<RegisteredCode>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredCode {
    pub code: String,
    pub summary: String,
    pub description: String,
    pub phase: String,
    #[serde(default)]
    pub emitted_by: Vec<String>,
    #[serde(default)]
    pub superseded_by: Option<String>,
}

impl Registry {
    /// Read the registry from a repository root.
    pub fn load(repo_root: &Path) -> Result<Self, String> {
        let path = repo_root.join("spec/registries/error-codes.yaml");
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        serde_yaml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))
    }

    #[must_use]
    pub fn contains(&self, code: &str) -> bool {
        self.codes.iter().any(|entry| entry.code == code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn a_sidecar_sits_beside_its_vector() {
        assert_eq!(
            sidecar_path(Path::new("fixtures/core/invalid/a.yaml")),
            PathBuf::from("fixtures/core/invalid/a.expect.yaml")
        );
        assert!(is_sidecar(Path::new("fixtures/core/invalid/a.expect.yaml")));
        assert!(!is_sidecar(Path::new("fixtures/core/invalid/a.yaml")));
    }

    #[test]
    fn every_invalid_vector_has_a_sidecar_naming_a_registered_code() {
        let root = repo_root();
        let registry = Registry::load(&root).expect("the error-code registry loads");
        let mut checked = 0;
        for module in ["core", "posture", "origins", "detection"] {
            let dir = root.join("fixtures").join(module).join("invalid");
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if is_sidecar(&path) || path.extension().is_none_or(|ext| ext != "yaml") {
                    continue;
                }
                let expected = load(&path)
                    .unwrap_or_else(|error| panic!("{error}"))
                    .unwrap_or_else(|| {
                        panic!(
                            "{} has no {} sidecar; every invalid vector must name the code it is \
                             rejected with",
                            path.display(),
                            SIDECAR_SUFFIX
                        )
                    });
                assert!(
                    registry.contains(&expected.code),
                    "{}: {} is not in spec/registries/error-codes.yaml",
                    path.display(),
                    expected.code
                );
                checked += 1;
            }
        }
        assert!(
            checked >= 28,
            "expected the invalid corpus, found {checked}"
        );
    }

    #[test]
    fn a_mismatched_code_is_reported() {
        let expected = ExpectedError {
            reject: true,
            code: "E001".to_string(),
            message_contains: None,
        };
        assert!(check(&expected, "E001", "anything").is_none());
        assert!(check(&expected, "E004", "anything").is_some());
    }

    #[test]
    fn a_missing_substring_is_reported() {
        let expected = ExpectedError {
            reject: true,
            code: "E001".to_string(),
            message_contains: Some("anchors are not allowed".to_string()),
        };
        assert!(check(&expected, "E001", "line 5: anchors are not allowed").is_none());
        assert!(check(&expected, "E001", "some other refusal").is_some());
    }
}
