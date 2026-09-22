use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A conformance test fixture file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestFixture {
    pub path: PathBuf,
    pub category: FixtureCategory,
    pub content: String,
    /// Set when the file could not be read. A vector nobody opened is never
    /// scored against its category; the runner fails it on this message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FixtureCategory {
    ValidCore,
    InvalidCore,
    MergeBase,
    MergeChild,
    MergeExpected,
    Evaluation,
    /// Canonical-form vector (spec/hushspec-canonical.md section 7).
    Hash,
    /// Resolution vector (core spec 2.3: digest pins and chain provenance).
    Resolve,
    PostureValid,
    PostureInvalid,
    OriginsValid,
    OriginsInvalid,
    DetectionValid,
    DetectionInvalid,
}

/// Discover all fixture files under a fixtures directory.
pub fn discover_fixtures(fixtures_dir: &Path) -> Vec<TestFixture> {
    let mut fixtures = Vec::new();

    let categories = [
        ("core/valid", FixtureCategory::ValidCore),
        ("core/invalid", FixtureCategory::InvalidCore),
        ("core/evaluation", FixtureCategory::Evaluation),
        ("core/hash", FixtureCategory::Hash),
        ("core/resolve", FixtureCategory::Resolve),
        ("core/merge", FixtureCategory::MergeBase), // categorized further below
        ("posture/evaluation", FixtureCategory::Evaluation),
        ("posture/merge", FixtureCategory::MergeBase),
        ("posture/valid", FixtureCategory::PostureValid),
        ("posture/invalid", FixtureCategory::PostureInvalid),
        ("origins/evaluation", FixtureCategory::Evaluation),
        ("origins/merge", FixtureCategory::MergeBase),
        ("origins/valid", FixtureCategory::OriginsValid),
        ("origins/invalid", FixtureCategory::OriginsInvalid),
        ("detection/evaluation", FixtureCategory::Evaluation),
        ("detection/merge", FixtureCategory::MergeBase),
        ("detection/valid", FixtureCategory::DetectionValid),
        ("detection/invalid", FixtureCategory::DetectionInvalid),
    ];

    // The vertical-library suites (`fixtures/library/<vertical>/*.test.yaml`)
    // are evaluator fixtures like any other, one directory deeper.
    let mut categories: Vec<(String, FixtureCategory)> = categories
        .iter()
        .map(|(subdir, category)| ((*subdir).to_string(), *category))
        .collect();
    if let Ok(entries) = std::fs::read_dir(fixtures_dir.join("library")) {
        let mut verticals: Vec<String> = entries
            .flatten()
            .filter(|entry| entry.path().is_dir())
            .map(|entry| format!("library/{}", entry.file_name().to_string_lossy()))
            .collect();
        verticals.sort();
        categories.extend(
            verticals
                .into_iter()
                .map(|subdir| (subdir, FixtureCategory::Evaluation)),
        );
    }

    for (subdir, category) in &categories {
        let dir = fixtures_dir.join(subdir);
        if !dir.exists() {
            continue;
        }

        // Merge vectors nest: a case that needs its own base -- a digest pin
        // names one exact document -- gets a subdirectory rather than
        // colliding with the shared base.yaml. The three SDK runners already
        // walk for those, so this walks too.
        let files = if *category == FixtureCategory::MergeBase {
            crate::manifest::walk(&dir)
        } else {
            let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
                .into_iter()
                .flatten()
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.is_file())
                .collect();
            files.sort();
            files
        };

        for path in files {
            if path.extension().is_none_or(|e| e != "yaml" && e != "yml") {
                continue;
            }
            // Expected-error sidecars describe the vector beside them; they
            // are not vectors themselves.
            if crate::expect::is_sidecar(&path) {
                continue;
            }
            let (content, read_error) = match std::fs::read_to_string(&path) {
                Ok(content) => (content, None),
                Err(error) => (String::new(), Some(error.to_string())),
            };
            let mut cat = *category;

            // Categorize merge fixtures more specifically.
            if *category == FixtureCategory::MergeBase {
                let filename = path.file_stem().unwrap_or_default().to_string_lossy();
                if filename.starts_with("child-") {
                    cat = FixtureCategory::MergeChild;
                } else if filename.starts_with("expected-") {
                    cat = FixtureCategory::MergeExpected;
                }
            }

            fixtures.push(TestFixture {
                path,
                category: cat,
                content,
                read_error,
            });
        }
    }

    fixtures.sort_by(|a, b| a.path.cmp(&b.path));
    fixtures
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixture whose bytes are not UTF-8 cannot be read into a document.
    /// Discovery records the read failure instead of substituting an empty
    /// document, and the runner scores it as a failure rather than letting an
    /// `invalid/` vector pass for a file it never opened.
    #[test]
    fn unreadable_fixture_is_recorded_and_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let invalid_dir = dir.path().join("core/invalid");
        std::fs::create_dir_all(&invalid_dir).expect("create dir");
        std::fs::write(invalid_dir.join("unreadable.yaml"), [0xff, 0xfe, 0xfd])
            .expect("write fixture");

        let fixtures = discover_fixtures(dir.path());
        assert_eq!(fixtures.len(), 1);
        assert!(fixtures[0].read_error.is_some());
        assert!(fixtures[0].content.is_empty());

        let results = crate::runner::run_conformance(&fixtures);
        assert_eq!(results.len(), 1);
        assert!(!results[0].passed, "{}", results[0].message);
        assert!(results[0].message.contains("Failed to read fixture"));
    }
}
