//! Expected receipts shared by every SDK (receipt spec 8).
//!
//! For every case of every shared evaluation fixture, the Rust SDK produces a
//! receipt under fixed inputs (see `fixtures/receipts/expected/README.md`).
//! TypeScript, Python, and Go must produce the same receipt byte for byte
//! after canonicalization. This test compares the committed files with a
//! fresh generation so the directory cannot drift; set
//! `HUSHSPEC_UPDATE_EXPECTED=1` to regenerate after a deliberate change.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{TimeZone, Utc};
use hushspec::receipt::{
    Actor, AuditConfig, AuditContext, EnforcementMode, TimeSource, deterministic_uuid_v7,
    evaluate_audited,
};
use hushspec::{EvaluationAction, HushSpec, Resolution};

/// Fixed evaluation time for every expected receipt.
const CLOCK_MILLIS: u64 = 1_789_473_600_000; // 2026-09-15T12:00:00.000Z

fn repo_root() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../..")).to_path_buf()
}

#[derive(serde::Deserialize)]
struct Fixture {
    policy: serde_json::Value,
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    action: EvaluationAction,
    #[serde(default)]
    context: Option<hushspec::RuntimeContext>,
}

fn fixed_context(case_index: usize) -> AuditContext {
    AuditContext {
        actor: Some(Actor {
            agent_id: Some("fixture-agent".to_string()),
            session_id: Some("fixture-session".to_string()),
            principal: Some("fixture@hushspec.dev".to_string()),
            runtime: Some("hushspec-conformance/0.2".to_string()),
        }),
        enforcement: None,
        enforcement_mode: EnforcementMode::Enforce,
        time_source: TimeSource::Trusted,
        clock: Some(Utc.with_ymd_and_hms(2026, 9, 15, 12, 0, 0).unwrap()),
        receipt_id: Some(deterministic_uuid_v7(CLOCK_MILLIS, case_index as u64)),
        context: None,
        conditions: Default::default(),
    }
}

fn evaluation_fixtures() -> Vec<PathBuf> {
    let root = repo_root().join("fixtures");
    let mut paths = Vec::new();
    for module in ["core", "posture", "origins", "detection"] {
        let dir = root.join(module).join("evaluation");
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".test.yaml"))
            {
                paths.push(path);
            }
        }
    }
    paths.sort();
    paths
}

/// `fixtures/receipts/expected/<module>/<fixture stem>/<case index>.json`
fn expected_dir(fixture: &Path) -> PathBuf {
    let module = fixture
        .parent()
        .and_then(Path::parent)
        .and_then(|p| p.file_name())
        .unwrap()
        .to_string_lossy()
        .to_string();
    let stem = fixture
        .file_name()
        .unwrap()
        .to_string_lossy()
        .trim_end_matches(".test.yaml")
        .to_string();
    repo_root()
        .join("fixtures/receipts/expected")
        .join(module)
        .join(stem)
}

#[test]
fn expected_receipts_match_the_committed_vectors() {
    let update = update_requested("HUSHSPEC_UPDATE_EXPECTED");
    let config = AuditConfig {
        enabled: true,
        include_rule_trace: true,
        record_duration: false,
    };
    let mut checked = 0;
    let mut mismatches = Vec::new();

    for fixture_path in evaluation_fixtures() {
        let text = fs::read_to_string(&fixture_path).unwrap();
        let fixture: Fixture = serde_yaml::from_str(&text)
            .unwrap_or_else(|e| panic!("{}: {e}", fixture_path.display()));
        let policy_yaml = serde_yaml::to_string(&fixture.policy).unwrap();
        let spec = HushSpec::parse(&policy_yaml)
            .unwrap_or_else(|e| panic!("{}: policy: {e}", fixture_path.display()));
        let resolution = Resolution::from_resolved(&spec, None)
            .unwrap_or_else(|e| panic!("{}: {e}", fixture_path.display()));
        let dir = expected_dir(&fixture_path);

        for (index, case) in fixture.cases.iter().enumerate() {
            let mut action = case.action.clone();
            if action.context.is_none() {
                action.context = case.context.clone();
            }
            let receipt = evaluate_audited(&resolution, &action, &config, &fixed_context(index));
            let rendered = format!("{}\n", serde_json::to_string_pretty(&receipt).unwrap());
            let file = dir.join(format!("{index}.json"));
            if update {
                fs::create_dir_all(&dir).unwrap();
                fs::write(&file, &rendered).unwrap();
            } else {
                match fs::read_to_string(&file) {
                    Ok(existing) if existing == rendered => {}
                    Ok(_) => mismatches.push(format!("{} differs", file.display())),
                    Err(_) => mismatches.push(format!("{} is missing", file.display())),
                }
            }
            checked += 1;
        }
    }

    assert!(checked > 0, "no evaluation fixtures found");
    assert!(
        mismatches.is_empty(),
        "expected receipts drifted (run with HUSHSPEC_UPDATE_EXPECTED=1 after a deliberate change):\n{}",
        mismatches.join("\n")
    );
}

/// Whether the caller asked for the committed vectors to be regenerated.
///
/// Only `1` and `true` count: `is_ok()` would make `VAR=0` regenerate, which
/// silently turns a verifying run into a rubber stamp.
fn update_requested(var: &str) -> bool {
    matches!(std::env::var(var).as_deref(), Ok("1") | Ok("true"))
}
