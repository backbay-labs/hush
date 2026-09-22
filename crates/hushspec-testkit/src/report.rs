//! The conformance report (`schemas/hushspec-conformance-report.v1.schema.json`).
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
    /// True when this result proves the implementation did not meet a parse
    /// acceptance assertion. This is report-internal metadata, deliberately
    /// absent from the published JSON schema.
    #[serde(skip)]
    pub parser_failure: bool,
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
            // The older document runner records only a diagnostic string.
            // New runners carry this classification directly instead.
            parser_failure: !result.passed
                && result.message.contains(crate::runner::PARSE_FAILURE_PREFIX),
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

/// Manifest categories the document-vector pipeline scores one result per
/// file. The evidence categories are driven by their own vector manifests and
/// list their inputs -- keys, signatures, bundles, logs -- beside the vectors
/// that consume them, so they are not comparable file for file.
const SCORED_CATEGORIES: [&str; 9] = [
    "valid",
    "invalid",
    "merge",
    "evaluation",
    "canonical",
    "resolve",
    "library-suite",
    "raw-yaml",
    "log-schema",
];

/// Every scored vector the manifest lists that the run did not report on.
///
/// A corpus is cited by the digest of its manifest, so a level cannot be a
/// pass while a vector that manifest lists went unrun: the report records each
/// one as `not_attempted`, which core spec Section 8 states is never a pass.
fn unattempted(manifest: &Manifest, results: &[VectorResult]) -> Vec<VectorResult> {
    // A vector whose unit is a case inside a file appends `#<case>`, so the
    // file it ran is the part before the separator.
    let ran: std::collections::BTreeSet<&str> = results
        .iter()
        .map(|result| {
            result
                .path
                .split_once('#')
                .map_or(result.path.as_str(), |(path, _)| path)
        })
        .collect();
    let ran_dirs: std::collections::BTreeSet<&str> = ran
        .iter()
        .map(|path| path.rsplit_once('/').map_or("", |(dir, _)| dir))
        .collect();

    manifest
        .files
        .iter()
        .filter(|entry| SCORED_CATEGORIES.contains(&entry.category.as_str()))
        .filter(|entry| !ran.contains(entry.path.as_str()))
        // A merge group reports one result per `child-` vector; the base and
        // the expected document beside it are that case's inputs.
        .filter(|entry| {
            entry.category != "merge"
                || !ran_dirs.contains(entry.path.rsplit_once('/').map_or("", |(dir, _)| dir))
        })
        .map(|entry| VectorResult {
            path: entry.path.clone(),
            category: entry.category.clone(),
            level: Some(entry.level),
            status: Status::NotAttempted,
            message: Some(
                "the manifest lists this vector and the run did not attempt it".to_string(),
            ),
            parser_failure: false,
        })
        .collect()
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
    results.extend(unattempted(&manifest, &results));
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

    // Level 0 is parsing: a vector that met its parse acceptance assertion
    // proves the parser ran. Level 1 additionally covers decoded values and
    // validation. New case runners carry `parser_failure` explicitly, so an
    // advanced assertion cannot accidentally affect Level 0.
    let level_one = levels["1"].clone();
    if level_one.passed + level_one.failed > 0 {
        let parse_failures = results
            .iter()
            .filter(|result| {
                result.level == Some(1) && result.status == Status::Fail && result.parser_failure
            })
            .count() as u32;
        let entry = levels.get_mut("0").expect("level 0 exists");
        entry.passed = level_one.passed + level_one.failed - parse_failures;
        entry.failed = parse_failures;
        // A document vector the run never attempted was never parsed either,
        // so it is unattempted at Level 0 as well.
        entry.skipped += level_one.skipped;
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

    /// A raw corpus case that was required to parse but did not is a parser
    /// failure as well as a Level 1 conformance failure. In contrast, a value
    /// assertion after a successful parse remains a Level 1-only failure.
    #[test]
    fn raw_yaml_acceptance_failure_stops_level_zero_but_value_failure_does_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        let raw_dir = dir.path().join("core/raw-yaml");
        std::fs::create_dir_all(&raw_dir).expect("create raw corpus directory");
        std::fs::write(
            raw_dir.join("scalars.json"),
            r#"[{"id":"must-parse","yaml":"hushspec: [","accept":true}]"#,
        )
        .expect("write mutated raw case");
        std::fs::write(
            dir.path().join("MANIFEST.json"),
            r#"{
  "manifest_version":"0.1",
  "fixtures_version":"1.0.0",
  "generated_at":"2026-09-22T00:00:00Z",
  "files":[{
    "path":"fixtures/core/raw-yaml/scalars.json",
    "sha256":"0000000000000000000000000000000000000000000000000000000000000000",
    "category":"raw-yaml",
    "module":"core",
    "level":1
  }]
}"#,
        )
        .expect("write manifest");

        let parse_results = crate::raw_yaml::run_raw_yaml_vectors(dir.path());
        let parse_report = build(
            reference_implementation(),
            dir.path(),
            &[],
            &parse_results,
            "2026-09-22T00:00:00Z".to_string(),
        )
        .expect("build parse-failure report");
        assert_eq!(parse_report.levels["1"].status, Status::Fail);
        assert_eq!(parse_report.levels["0"].status, Status::Fail);
        assert_eq!(parse_report.highest_level, None);

        std::fs::write(raw_dir.join("scalars.json"), "not JSON")
            .expect("write malformed raw corpus");
        let corpus_results = crate::raw_yaml::run_raw_yaml_vectors(dir.path());
        let corpus_report = build(
            reference_implementation(),
            dir.path(),
            &[],
            &corpus_results,
            "2026-09-22T00:00:00Z".to_string(),
        )
        .expect("build malformed-corpus report");
        assert_eq!(corpus_report.levels["1"].status, Status::Fail);
        assert_eq!(corpus_report.levels["0"].status, Status::Fail);
        assert_eq!(corpus_report.highest_level, None);

        let value_report = build(
            reference_implementation(),
            dir.path(),
            &[],
            &[VectorResult {
                path: "fixtures/core/raw-yaml/scalars.json#value".to_string(),
                category: "raw-yaml".to_string(),
                level: Some(1),
                status: Status::Fail,
                message: Some("value mismatch after parsing".to_string()),
                parser_failure: false,
            }],
            "2026-09-22T00:00:00Z".to_string(),
        )
        .expect("build value-failure report");
        assert_eq!(value_report.levels["0"].status, Status::Pass);
        assert_eq!(value_report.levels["1"].status, Status::Fail);
    }

    /// Every scored vector the manifest lists is reported on, so the corpus a
    /// report cites by digest is the corpus it actually ran.
    #[test]
    fn the_full_report_leaves_no_manifest_vector_unattempted() {
        let report = full_report();
        let skipped: Vec<&str> = report
            .results
            .iter()
            .filter(|result| result.status == Status::NotAttempted)
            .map(|result| result.path.as_str())
            .collect();
        assert!(skipped.is_empty(), "not attempted: {skipped:?}");
    }

    /// Raw YAML scalar spelling and schema-derived log entries are case
    /// vectors, not SDK-only regression tests. The published report must name
    /// each case and score its expected refusal rather than silently omitting
    /// either corpus.
    #[test]
    fn the_reference_report_scores_raw_yaml_and_log_schema_cases() {
        let report = full_report();

        let raw: Vec<&VectorResult> = report
            .results
            .iter()
            .filter(|result| result.category == "raw-yaml")
            .collect();
        let expected_raw: Vec<serde_json::Value> = serde_json::from_str(
            &std::fs::read_to_string(fixtures_dir().join("core/raw-yaml/scalars.json"))
                .expect("raw YAML corpus reads"),
        )
        .expect("raw YAML corpus parses");
        assert_eq!(raw.len(), expected_raw.len());
        assert!(raw.iter().all(|result| result.level == Some(1)));
        assert!(raw.iter().all(|result| result.status == Status::Pass));

        let expected_canonical = expected_raw
            .iter()
            .filter(|vector| vector.get("canonical").is_some())
            .count();
        let canonical = report
            .results
            .iter()
            .filter(|result| result.category == "raw-yaml-canonical")
            .collect::<Vec<_>>();
        assert_eq!(canonical.len(), expected_canonical);
        assert!(canonical.iter().all(|result| result.level == Some(4)));
        assert!(canonical.iter().all(|result| result.status == Status::Pass));

        let expected_evaluation = expected_raw
            .iter()
            .filter(|vector| vector.get("decision").is_some())
            .count();
        let evaluation = report
            .results
            .iter()
            .filter(|result| result.category == "raw-yaml-evaluation")
            .collect::<Vec<_>>();
        assert_eq!(evaluation.len(), expected_evaluation);
        assert!(evaluation.iter().all(|result| result.level == Some(3)));
        assert!(
            evaluation
                .iter()
                .all(|result| result.status == Status::Pass)
        );

        let log_schema: Vec<&VectorResult> = report
            .results
            .iter()
            .filter(|result| result.category == "log-schema")
            .collect();
        let expected_log: Vec<serde_json::Value> = serde_json::from_str(
            &std::fs::read_to_string(fixtures_dir().join("log/schema-vectors.json"))
                .expect("log schema corpus reads"),
        )
        .expect("log schema corpus parses");
        assert_eq!(log_schema.len(), expected_log.len());
        assert!(log_schema.iter().all(|result| result.level == Some(5)));
        assert!(
            log_schema
                .iter()
                .all(|result| result.status == Status::Pass)
        );

        let expected_rejections = expected_log
            .iter()
            .filter(|vector| vector["valid"] == false)
            .count();
        let reported_rejections = log_schema
            .iter()
            .filter(|result| {
                result
                    .message
                    .as_deref()
                    .is_some_and(|message| message.starts_with("correctly rejected:"))
            })
            .count();
        assert_eq!(reported_rejections, expected_rejections);
    }

    /// A vector the discovery pass misses is recorded as `not_attempted`
    /// rather than left out, and the level it belongs to cannot then pass.
    #[test]
    fn a_vector_the_run_missed_is_recorded_as_not_attempted() {
        let manifest = Manifest::load(&fixtures_dir()).expect("manifest loads");
        let listed = manifest
            .files
            .iter()
            .find(|entry| entry.category == "evaluation")
            .expect("an evaluation vector is listed");

        let skipped = unattempted(&manifest, &[]);
        let found = skipped
            .iter()
            .find(|result| result.path == listed.path)
            .expect("the unrun vector is reported");
        assert_eq!(found.status, Status::NotAttempted);
        assert_eq!(found.level, Some(listed.level));

        // The manifest's supporting inputs -- signing keys, bundles, logs --
        // are never scored as vectors of their own.
        assert!(
            !skipped
                .iter()
                .any(|result| result.path.starts_with("fixtures/signing/keys/"))
        );
    }
}
