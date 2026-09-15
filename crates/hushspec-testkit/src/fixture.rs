use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A conformance test fixture file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestFixture {
    pub path: PathBuf,
    pub category: FixtureCategory,
    pub content: String,
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
            let content = std::fs::read_to_string(&path).unwrap_or_default();
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
            });
        }
    }

    fixtures.sort_by(|a, b| a.path.cmp(&b.path));
    fixtures
}
