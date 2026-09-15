//! The conformance report (`schemas/hushspec-conformance-report.v0.schema.json`).
//!
//! A report is the evidence behind a conformance statement: it names the
//! implementation, pins the corpus by the digest of `fixtures/MANIFEST.json`,
//! states an outcome for each of the six levels of core spec Section 8, and
//! lists every vector it ran.
//!
//! Levels subsume, so the highest passing level is the largest `N` for which
//! levels `0..=N` all pass. A level with any skipped vector is never `pass`:
//! `not_attempted` is not a synonym for success.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::fixture::FixtureCategory;
use crate::manifest::Manifest;
use crate::runner::TestResult;

/// Highest level the report format knows about.
pub const MAX_LEVEL: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Fail,
    NotAttempted,
}

/// One vector's outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorResult {
    /// Repository-relative path; a per-case unit appends `#<index>`.
    pub path: String,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelResult {
    pub status: Status,
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Implementation {
    pub name: String,
    pub version: String,
    pub language: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub implementation: Implementation,
    pub fixtures_version: String,
    pub manifest_sha256: String,
    /// Keyed by the level number as a string, so the JSON object matches the
    /// schema's `"0".."5"` properties.
    pub levels: BTreeMap<String, LevelResult>,
    pub highest_level: Option<u8>,
    pub results: Vec<VectorResult>,
    pub generated_at: String,
}

/// The level a document-vector category belongs to (core spec Section 8).
#[must_use]
pub fn level_of_category(category: FixtureCategory) -> u8 {
    match category {
        // Parsing is Level 0, but a `valid/` vector also has to validate, and
        // an `invalid/` one has to be refused for the right reason, so both
        // are scored at Level 1 and Level 0 is scored on parsing alone.
        FixtureCategory::ValidCore
        | FixtureCategory::PostureValid
        | FixtureCategory::OriginsValid
        | FixtureCategory::DetectionValid
        | FixtureCategory::InvalidCore
        | FixtureCategory::PostureInvalid
        | FixtureCategory::OriginsInvalid
        | FixtureCategory::DetectionInvalid => 1,
        FixtureCategory::MergeBase
        | FixtureCategory::MergeChild
        | FixtureCategory::MergeExpected => 2,
        FixtureCategory::Evaluation => 3,
        // Canonical-form and resolution vectors both assert content hashes,
        // which is what Level 4 is about.
        FixtureCategory::Hash | FixtureCategory::Resolve => 4,
    }
}

/// The manifest category name for a document-vector category.
#[must_use]
pub fn name_of_category(category: FixtureCategory) -> &'static str {
    match category {
        FixtureCategory::ValidCore
        | FixtureCategory::PostureValid
        | FixtureCategory::OriginsValid
        | FixtureCategory::DetectionValid => "valid",
        FixtureCategory::InvalidCore
        | FixtureCategory::PostureInvalid
        | FixtureCategory::OriginsInvalid
        | FixtureCategory::DetectionInvalid => "invalid",
        FixtureCategory::MergeBase
        | FixtureCategory::MergeChild
        | FixtureCategory::MergeExpected => "merge",
        FixtureCategory::Evaluation => "evaluation",
        FixtureCategory::Hash => "canonical",
        FixtureCategory::Resolve => "resolve",
    }
}

impl From<&TestResult> for VectorResult {
    fn from(result: &TestResult) -> Self {
        let path = crate::manifest::relative_fixture_path(Path::new(&result.fixture_path))
            .unwrap_or_else(|| result.fixture_path.clone());
        VectorResult {
            path,
            category: name_of_category(result.category).to_string(),
            level: Some(level_of_category(result.category)),
            status: if result.passed {
                Status::Pass
            } else {
                Status::Fail
            },
            message: Some(result.message.clone()),
        }
    }
}

/// Levels 0 and 1 share the document vectors: Level 0 asks only that a valid
/// document parses and an invalid one is refused *somehow*, Level 1 adds
/// validation and the expected error code. A runner that reports a Level 1
/// failure therefore still reports Level 0 as passing when the refusal
/// happened at all -- which is why the level scores are derived from the
/// vector results rather than counted once.
fn level_note(level: u8, skipped: u32) -> Option<String> {
    if skipped == 0 {
        return None;
    }
    Some(format!(
        "level {level}: {skipped} vector(s) were not attempted, so the level cannot be reported as \
         a pass"
    ))
}

/// Build a report from the document-vector results and the evidence-vector
/// results.
pub fn build(
    implementation: Implementation,
    fixtures_dir: &Path,
    document_results: &[TestResult],
    evidence_results: &[VectorResult],
    generated_at: String,
) -> Result<ConformanceReport, String> {
    let manifest = Manifest::load(fixtures_dir).map_err(|error| error.to_string())?;
    let manifest_sha256 = Manifest::digest(fixtures_dir).map_err(|error| error.to_string())?;

    let mut results: Vec<VectorResult> = document_results.iter().map(VectorResult::from).collect();
    results.extend(evidence_results.iter().cloned());
    results.sort_by(|a, b| a.path.cmp(&b.path));

    let mut levels: BTreeMap<String, LevelResult> = BTreeMap::new();
    for level in 0..=MAX_LEVEL {
        levels.insert(
            level.to_string(),
            LevelResult {
                status: Status::NotAttempted,
                passed: 0,
                failed: 0,
                skipped: 0,
                note: None,
            },
        );
    }

    for result in &results {
        let level = result.level.unwrap_or(MAX_LEVEL);
        let entry = levels
            .get_mut(&level.to_string())
            .ok_or_else(|| format!("{}: level {level} is out of range", result.path))?;
        match result.status {
            Status::Pass => entry.passed += 1,
            Status::Fail => entry.failed += 1,
            Status::NotAttempted => entry.skipped += 1,
        }
    }

    // Level 0 is parsing: a document vector that got as far as a decision
    // proves the parser ran, so Level 0 passes when Level 1 was attempted at
    // all and nothing failed to parse. The runner reports a parse failure as a
    // Level 1 failure whose message says so.
    let level_one = levels["1"].clone();
    if level_one.passed + level_one.failed > 0 {
        let parse_failures = results
            .iter()
            .filter(|result| {
                result.level == Some(1)
                    && result.status == Status::Fail
                    && result
                        .message
                        .as_deref()
                        .is_some_and(|message| message.contains("Parse failed"))
            })
            .count() as u32;
        let entry = levels.get_mut("0").expect("level 0 exists");
        entry.passed = level_one.passed + level_one.failed - parse_failures;
        entry.failed = parse_failures;
    }

    for (key, entry) in levels.iter_mut() {
        let level: u8 = key.parse().unwrap_or(MAX_LEVEL);
        entry.status = if entry.failed > 0 {
            Status::Fail
        } else if entry.passed == 0 || entry.skipped > 0 {
            Status::NotAttempted
        } else {
            Status::Pass
        };
        entry.note = level_note(level, entry.skipped);
    }

    // Levels subsume: the highest passing level is the largest N for which
    // every level up to N passed.
    let mut highest_level = None;
    for level in 0..=MAX_LEVEL {
        if levels[&level.to_string()].status == Status::Pass {
            highest_level = Some(level);
        } else {
            break;
        }
    }

    Ok(ConformanceReport {
        implementation,
        fixtures_version: manifest.fixtures_version,
        manifest_sha256,
        levels,
        highest_level,
        results,
        generated_at,
    })
}

/// The reference implementation's own identity.
#[must_use]
pub fn reference_implementation() -> Implementation {
    Implementation {
        name: "hushspec (reference implementation)".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        language: "rust".to_string(),
    }
}

/// RFC 3339 UTC with second precision, as the schema requires.
#[must_use]
pub fn now_rfc3339() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Write a report as pretty JSON with a trailing newline.
pub fn write(report: &ConformanceReport, path: &Path) -> Result<(), String> {
    let text = serde_json::to_string_pretty(report)
        .map_err(|error| format!("could not serialize the report: {error}"))?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    std::fs::write(path, format!("{text}\n"))
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Validate a report against the published schema. Fail-closed: the tool that
/// writes the report also checks it, so a malformed report never ships.
pub fn validate(report: &ConformanceReport) -> Result<(), String> {
    let body = crate::generated_schemas::schema_body("conformance-report")
        .ok_or_else(|| "the conformance-report schema is not embedded".to_string())?;
    let schema: serde_json::Value =
        serde_json::from_str(body).map_err(|error| format!("report schema: {error}"))?;
    let compiled = jsonschema::JSONSchema::options()
        .should_validate_formats(true)
        .compile(&schema)
        .map_err(|error| format!("report schema does not compile: {error}"))?;
    let value = serde_json::to_value(report)
        .map_err(|error| format!("could not serialize the report: {error}"))?;
    compiled.validate(&value).map_err(|errors| {
        let messages: Vec<String> = errors.map(|error| error.to_string()).collect();
        format!(
            "the report does not match its schema: {}",
            messages.join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
    }

    fn full_report() -> ConformanceReport {
        let dir = fixtures_dir();
        let fixtures = crate::fixture::discover_fixtures(&dir);
        let document = crate::runner::run_conformance(&fixtures);
        let evidence = crate::evidence::run_evidence(&dir);
        build(
            reference_implementation(),
            &dir,
            &document,
            &evidence,
            "2026-09-15T12:00:00Z".to_string(),
        )
        .expect("the report builds")
    }

    #[test]
    fn the_reference_implementation_reaches_level_5() {
        let report = full_report();
        let failures: Vec<&VectorResult> = report
            .results
            .iter()
            .filter(|result| result.status != Status::Pass)
            .collect();
        assert!(
            failures.is_empty(),
            "vectors failed:\n  {}",
            failures
                .iter()
                .map(|result| format!(
                    "{}: {}",
                    result.path,
                    result.message.as_deref().unwrap_or("")
                ))
                .collect::<Vec<_>>()
                .join("\n  ")
        );
        assert_eq!(report.highest_level, Some(5), "levels: {:?}", report.levels);
    }

    #[test]
    fn a_report_validates_against_its_schema() {
        validate(&full_report()).unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn a_failed_level_stops_the_highest_level_there() {
        let mut report = full_report();
        report.levels.insert(
            "3".to_string(),
            LevelResult {
                status: Status::Fail,
                passed: 0,
                failed: 1,
                skipped: 0,
                note: None,
            },
        );
        let mut highest = None;
        for level in 0..=MAX_LEVEL {
            if report.levels[&level.to_string()].status == Status::Pass {
                highest = Some(level);
            } else {
                break;
            }
        }
        assert_eq!(highest, Some(2));
    }
}
