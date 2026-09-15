//! `h2h report` and the vectors under `fixtures/report/`.
//!
//! The synthetic 24-hour log is generated here, from a fixed clock, fixed
//! actors and two real policies, so the committed vector and the committed
//! expected report are both drift-checked against the code that produces
//! them. Set `HUSHSPEC_UPDATE_REPORT_VECTORS=1` to regenerate both after a
//! deliberate change.
//!
//! Every case in [`cases`] carries the decision it is expected to produce,
//! asserted as the log is written, so the report's decision totals are the
//! sum of a table a human wrote rather than of whatever the evaluator
//! happened to say.

use assert_cmd::Command;
use chrono::{TimeZone, Utc};
use hushspec::log::{ChainedFileSink, PolicyEvent, PolicyEventKind, SdkInfo};
use hushspec::receipt::{
    Actor, AuditConfig, AuditContext, EnforcementMode, EnforcementOutcome, EnforcementSummary,
    TimeSource, deterministic_uuid_v7, evaluate_audited, policy_summary,
};
use hushspec::sink::ReceiptSink;
use hushspec::{Decision, EvaluationAction, HushSpec, Resolution, ResolveOptions};
use predicates::prelude::*;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// 2026-09-15T00:00:00.000Z.
const DAY_START_MILLIS: i64 = 1_789_430_400_000;

/// The policy the receipts are evaluated under, and whose `metadata.controls`
/// the control evidence joins against.
const POLICY: &str = "library/healthcare/hipaa-base.yaml";

fn h2h() -> Command {
    Command::cargo_bin("h2h").unwrap()
}

fn repo_root() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../..")).to_path_buf()
}

fn vectors_dir() -> PathBuf {
    repo_root().join("fixtures/report")
}

fn at(hour: u32, minute: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 15, hour, minute, 0).unwrap()
}

fn millis(hour: u32, minute: u32) -> u64 {
    (DAY_START_MILLIS + i64::from(hour) * 3_600_000 + i64::from(minute) * 60_000) as u64
}

fn actor(index: usize) -> Actor {
    if index == 0 {
        Actor {
            agent_id: Some("clinical-assistant".to_string()),
            session_id: Some("session-alpha".to_string()),
            principal: Some("nurse@hospital.example".to_string()),
            runtime: Some("hushspec-conformance/0.2".to_string()),
        }
    } else {
        Actor {
            agent_id: Some("ops-assistant".to_string()),
            session_id: Some("session-beta".to_string()),
            principal: Some("sre@hospital.example".to_string()),
            runtime: Some("hushspec-conformance/0.2".to_string()),
        }
    }
}

fn config() -> AuditConfig {
    AuditConfig {
        enabled: true,
        include_rule_trace: true,
        record_duration: false,
    }
}

/// A resolution whose chain link names the policy by its repository path
/// rather than by wherever the test checkout happens to live, so the vector
/// is byte-stable on every machine.
fn stable_resolution(source: &str, resolved: &HushSpec, expected_hash: &str) -> Resolution {
    let resolution = Resolution::from_resolved(resolved, Some(source)).unwrap();
    assert_eq!(
        resolution.content_hash, expected_hash,
        "{source}: re-wrapping the resolved document must not change its hash"
    );
    resolution
}

fn hipaa() -> Resolution {
    let path = repo_root().join(POLICY);
    let resolved = hushspec::resolve_path_with_options(&path, &ResolveOptions::default()).unwrap();
    stable_resolution(POLICY, &resolved.spec, &resolved.content_hash)
}

fn builtin_default() -> Resolution {
    let spec = HushSpec::parse(hushspec::load_builtin("default").unwrap()).unwrap();
    Resolution::from_resolved(&spec, Some("builtin:default")).unwrap()
}

fn event(
    kind: PolicyEventKind,
    hour: u32,
    policy: &Resolution,
    previous: Option<&str>,
) -> PolicyEvent {
    PolicyEvent {
        event: kind,
        timestamp: hushspec::format_timestamp(at(hour, 0)),
        policy: policy_summary(policy),
        enforcement_mode: EnforcementMode::Enforce,
        sdk: SdkInfo {
            name: "hushspec-conformance".to_string(),
            version: "0.2".to_string(),
        },
        spec_version: "0.2.0".to_string(),
        previous_content_hash: previous.map(str::to_string),
    }
}

/// One synthetic evaluation: when it happened, who did it, what was
/// attempted, and the decision a reader of the policy expects.
struct Case {
    hour: u32,
    minute: u32,
    actor: usize,
    action: serde_json::Value,
    expect: Decision,
    mode: EnforcementMode,
    /// Overrides the implied disposition (a warn approved by a human).
    enforcement: Option<EnforcementOutcome>,
}

/// The working day under `library/healthcare/hipaa-base.yaml`.
fn cases() -> Vec<Case> {
    let case = |hour, minute, actor, action, expect| Case {
        hour,
        minute,
        actor,
        action,
        expect,
        mode: EnforcementMode::Enforce,
        enforcement: None,
    };
    vec![
        // Routine work the policy allows.
        case(
            1,
            5,
            0,
            serde_json::json!({"type": "tool_call", "target": "read_file"}),
            Decision::Allow,
        ),
        case(
            2,
            15,
            0,
            serde_json::json!({"type": "egress", "target": "fhir.epic.com"}),
            Decision::Allow,
        ),
        case(
            3,
            30,
            0,
            serde_json::json!({"type": "file_read", "target": "/srv/app/README.md"}),
            Decision::Allow,
        ),
        case(
            4,
            0,
            1,
            serde_json::json!({"type": "egress", "target": "registry.npmjs.org"}),
            Decision::Allow,
        ),
        // 45 CFR 164.502: a paste site is explicitly blocked.
        case(
            5,
            20,
            0,
            serde_json::json!({"type": "egress", "target": "paste.ee"}),
            Decision::Deny,
        ),
        // 45 CFR 164.312(e)(1): egress defaults to block.
        case(
            6,
            45,
            1,
            serde_json::json!({"type": "egress", "target": "analytics.example.com"}),
            Decision::Deny,
        ),
        // 45 CFR 164.312(a)(1): a credential store is a forbidden path.
        case(
            7,
            10,
            1,
            serde_json::json!({"type": "file_read", "target": "/home/sre/.ssh/id_rsa"}),
            Decision::Deny,
        ),
        // 45 CFR 164.312(b): the HIPAA audit log is unreachable.
        case(
            8,
            0,
            0,
            serde_json::json!({"type": "file_write", "target": "/var/hipaa-audit/2026-09.log"}),
            Decision::Deny,
        ),
        // 45 CFR 164.514(b)(2): an SSN in written content.
        case(
            9,
            25,
            0,
            serde_json::json!({
                "type": "file_write",
                "target": "/srv/app/intake.txt",
                "content": "intake note -- SSN: 123-45-6789",
            }),
            Decision::Deny,
        ),
        // 45 CFR 164.502: a database dump is a forbidden shell command.
        case(
            10,
            40,
            1,
            serde_json::json!({"type": "shell_command", "target": "pg_dump -h db patients"}),
            Decision::Deny,
        ),
        // Tool allowlist: an unlisted tool is denied by default.
        case(
            11,
            0,
            1,
            serde_json::json!({"type": "tool_call", "target": "shell_exec"}),
            Decision::Deny,
        ),
        // require_confirmation: a warn.
        Case {
            hour: 12,
            minute: 30,
            actor: 0,
            action: serde_json::json!({"type": "tool_call", "target": "file_write"}),
            expect: Decision::Warn,
            mode: EnforcementMode::Enforce,
            enforcement: Some(EnforcementOutcome::Confirmed),
        },
        // The same warn with nobody to confirm it: a block (core spec 6).
        Case {
            hour: 13,
            minute: 15,
            actor: 1,
            action: serde_json::json!({"type": "tool_call", "target": "git_push"}),
            expect: Decision::Warn,
            mode: EnforcementMode::Enforce,
            enforcement: None,
        },
        // Monitor mode: recorded, not enforced.
        Case {
            hour: 14,
            minute: 0,
            actor: 1,
            action: serde_json::json!({"type": "egress", "target": "drive.google.com"}),
            expect: Decision::Deny,
            mode: EnforcementMode::Monitor,
            enforcement: None,
        },
        Case {
            hour: 15,
            minute: 45,
            actor: 0,
            action: serde_json::json!({"type": "file_read", "target": "/srv/ehr/patient-42/chart.json"}),
            expect: Decision::Deny,
            mode: EnforcementMode::Monitor,
            enforcement: None,
        },
        case(
            16,
            10,
            0,
            serde_json::json!({"type": "tool_call", "target": "run_tests"}),
            Decision::Allow,
        ),
    ]
}

/// After the swap, the same runtime enforces the `default` builtin.
fn cases_after_swap() -> Vec<Case> {
    vec![
        Case {
            hour: 19,
            minute: 0,
            actor: 1,
            action: serde_json::json!({"type": "tool_call", "target": "read_file"}),
            expect: Decision::Allow,
            mode: EnforcementMode::Enforce,
            enforcement: None,
        },
        Case {
            hour: 20,
            minute: 30,
            actor: 1,
            action: serde_json::json!({"type": "file_read", "target": "/home/sre/.aws/credentials"}),
            expect: Decision::Deny,
            mode: EnforcementMode::Enforce,
            enforcement: None,
        },
    ]
}

/// Write the 24-hour log and return its text.
fn generate_log(dir: &Path) -> String {
    let path = dir.join("24h.jsonl");
    let hipaa = hipaa();
    let fallback = builtin_default();
    let sink = ChainedFileSink::open(&path).unwrap().with_clock(at(0, 0));

    sink.record_policy_event(&event(PolicyEventKind::Loaded, 0, &hipaa, None))
        .unwrap();

    let mut index = 0u64;
    for (resolution, case) in cases()
        .into_iter()
        .map(|case| (hipaa.clone(), case))
        .chain(std::iter::once((
            fallback.clone(),
            Case {
                hour: 18,
                minute: 0,
                actor: 0,
                action: serde_json::Value::Null,
                expect: Decision::Allow,
                mode: EnforcementMode::Enforce,
                enforcement: None,
            },
        )))
        .chain(
            cases_after_swap()
                .into_iter()
                .map(|case| (fallback.clone(), case)),
        )
    {
        if case.action.is_null() {
            sink.record_policy_event(&event(
                PolicyEventKind::Swapped,
                18,
                &fallback,
                Some(&hipaa.content_hash),
            ))
            .unwrap();
            continue;
        }
        let action: EvaluationAction = serde_json::from_value(case.action.clone()).unwrap();
        let ctx = AuditContext {
            actor: Some(actor(case.actor)),
            enforcement: case.enforcement.map(|outcome| EnforcementSummary {
                mode: case.mode,
                outcome,
            }),
            enforcement_mode: case.mode,
            time_source: TimeSource::Trusted,
            clock: Some(at(case.hour, case.minute)),
            receipt_id: Some(deterministic_uuid_v7(millis(case.hour, case.minute), index)),
            ..AuditContext::default()
        };
        let receipt = evaluate_audited(&resolution, &action, &config(), &ctx);
        assert_eq!(
            receipt.decision,
            case.expect,
            "{:02}:{:02} {}: expected {:?}, the policy decided {:?} ({})",
            case.hour,
            case.minute,
            case.action,
            case.expect,
            receipt.decision,
            receipt.matched_rule.as_deref().unwrap_or("-")
        );
        sink.send(&receipt).unwrap();
        index += 1;
    }

    std::fs::read_to_string(&path).unwrap()
}

/// Regenerate a vector, or report that the committed one drifted.
fn check_vector(name: &str, generated: &str) {
    let path = vectors_dir().join(name);
    if update_requested("HUSHSPEC_UPDATE_REPORT_VECTORS") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, generated).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "fixtures/report/{name} is missing ({error}); regenerate with \
             HUSHSPEC_UPDATE_REPORT_VECTORS=1"
        )
    });
    assert_eq!(
        committed, generated,
        "fixtures/report/{name} drifted; regenerate with HUSHSPEC_UPDATE_REPORT_VECTORS=1"
    );
}

fn report_json(args: &[&str]) -> serde_json::Value {
    let output = h2h()
        .current_dir(repo_root())
        .arg("report")
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).expect("the report is JSON")
}

// ----------------------------------------------------------------- vectors --

#[test]
fn the_synthetic_log_and_its_report_are_current() {
    let dir = TempDir::new().unwrap();
    check_vector("24h.jsonl", &generate_log(dir.path()));

    let output = h2h()
        .current_dir(repo_root())
        .args([
            "report",
            "fixtures/report/24h.jsonl",
            "--policy",
            POLICY,
            "--format",
            "json",
            "--now",
            "2026-09-16T00:00:00Z",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    check_vector(
        "expected-report.json",
        &String::from_utf8(output).expect("the report is UTF-8"),
    );
}

#[test]
fn the_expected_report_validates_against_the_report_schema() {
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("schemas/hushspec-report.v0.schema.json"))
            .unwrap(),
    )
    .unwrap();
    let compiled = jsonschema::JSONSchema::options()
        .should_validate_formats(true)
        .compile(&schema)
        .expect("the report schema compiles");
    let instance: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(vectors_dir().join("expected-report.json")).unwrap(),
    )
    .unwrap();
    if let Err(errors) = compiled.validate(&instance) {
        let messages: Vec<String> = errors.map(|error| error.to_string()).collect();
        panic!("the expected report fails its schema: {messages:?}");
    }
}

// ------------------------------------------------------- hand-computed sums --

#[test]
fn the_totals_match_the_case_table() {
    let report = report_json(&["fixtures/report/24h.jsonl", "--format", "json"]);

    // Hand-computed from `cases()` + `cases_after_swap()`: 6 receipts the
    // policy allows (4 in the day's routine work, 1 tool call at 16:10, 1
    // read_file after the swap), 2 warns (the confirmed file_write and the
    // unconfirmed git_push), 10 denies.
    assert_eq!(report["totals"]["receipts"], 18);
    assert_eq!(report["totals"]["by_decision"]["allow"], 6);
    assert_eq!(report["totals"]["by_decision"]["warn"], 2);
    assert_eq!(report["totals"]["by_decision"]["deny"], 10);
    assert_eq!(
        report["totals"]["by_decision"]["allow"].as_u64().unwrap()
            + report["totals"]["by_decision"]["warn"].as_u64().unwrap()
            + report["totals"]["by_decision"]["deny"].as_u64().unwrap(),
        report["totals"]["receipts"].as_u64().unwrap()
    );

    // Two receipts were recorded in monitor mode, and both of them are denies,
    // so they are the two `would_block`s; one warn was confirmed by a human;
    // the six allows proceeded; the remaining nine are blocked.
    assert_eq!(report["totals"]["by_mode"]["enforce"], 16);
    assert_eq!(report["totals"]["by_mode"]["monitor"], 2);
    assert_eq!(report["totals"]["by_outcome"]["allowed"], 6);
    assert_eq!(report["totals"]["by_outcome"]["confirmed"], 1);
    assert_eq!(report["totals"]["by_outcome"]["would_block"], 2);
    assert_eq!(report["totals"]["by_outcome"]["blocked"], 9);

    // Two policy events: the load at 00:00 and the swap at 18:00.
    assert_eq!(report["totals"]["policy_events"], 2);
    assert_eq!(report["policy_timeline"][0]["event"], "loaded");
    assert_eq!(report["policy_timeline"][1]["event"], "swapped");
    assert_eq!(report["policies"].as_array().unwrap().len(), 2);

    // The chain verified, and both actors are accounted for.
    assert_eq!(report["chain_verified"], true);
    assert_eq!(report["chain"]["entries"], 20);
    assert_eq!(report["actors"].as_array().unwrap().len(), 2);
    assert_eq!(
        report["window"]["first_receipt"],
        "2026-09-15T01:05:00.000Z"
    );
    assert_eq!(report["window"]["last_receipt"], "2026-09-15T20:30:00.000Z");
}

#[test]
fn the_egress_control_row_counts_the_egress_evaluations() {
    let report = report_json(&[
        "fixtures/report/24h.jsonl",
        "--policy",
        POLICY,
        "--format",
        "json",
    ]);
    let controls = &report["controls"];

    // Sixteen of the eighteen receipts were evaluated under the HIPAA policy;
    // the two after the 18:00 swap were not, and cannot evidence its controls.
    assert_eq!(controls["receipts_matching_policy"], 16);

    let hipaa = controls["frameworks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|framework| framework["framework"] == "hipaa-2013")
        .expect("the HIPAA framework is reported");
    assert_eq!(hipaa["registered"], true);

    // 45 CFR 164.312(e)(1) maps to `rules.egress`, which five actions in the
    // table reach (fhir.epic.com, registry.npmjs.org, paste.ee,
    // analytics.example.com, drive.google.com). Three of them are denied.
    let transmission = hipaa["controls"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["control_id"] == "164.312(e)(1)")
        .expect("the transmission-security row is reported");
    assert_eq!(transmission["rule_paths"][0], "rules.egress");
    assert_eq!(transmission["rule_blocks"][0], "egress");
    assert_eq!(transmission["receipts"], 5);
    assert_eq!(transmission["evaluated"], 5);
    assert_eq!(transmission["fired"], 3);
    assert_eq!(transmission["denied"], 3);
    assert_eq!(transmission["last_seen"], "2026-09-15T14:00:00.000Z");

    // 45 CFR 164.502 maps to `rules.egress.block` and `rules.shell_commands`.
    // Only the two receipts whose recorded path is under `rules.egress.block`
    // (paste.ee, drive.google.com) and the one shell command evidence it -- a
    // receipt that merely consulted the egress allowlist does not.
    let minimum_necessary = hipaa["controls"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["control_id"] == "164.502")
        .expect("the minimum-necessary row is reported");
    assert_eq!(minimum_necessary["receipts"], 3);
    assert_eq!(minimum_necessary["denied"], 3);
}

// -------------------------------------------------------------- behaviour --

#[test]
fn a_malformed_line_is_refused_with_its_line_number() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("mixed.jsonl");
    let good = std::fs::read_to_string(vectors_dir().join("24h.jsonl")).unwrap();
    let lines: Vec<&str> = good.lines().collect();
    std::fs::write(
        &log,
        format!("{}\n{{\"nope\": true}}\n{}\n", lines[0], lines[1]),
    )
    .unwrap();

    h2h()
        .arg("report")
        .arg(&log)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("mixed.jsonl:2"))
        .stderr(predicate::str::contains("--lenient"));

    // --lenient skips it and says how many lines it skipped. The chain is
    // broken by the missing line, so reporting also needs --unverified.
    let output = h2h()
        .arg("report")
        .arg(&log)
        .args(["--lenient", "--unverified", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["totals"]["skipped_lines"], 1);
    assert_eq!(report["chain_verified"], false);
}

#[test]
fn a_broken_chain_refuses_to_report_without_unverified() {
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("tampered.jsonl");
    let good = std::fs::read_to_string(vectors_dir().join("24h.jsonl")).unwrap();
    let lines: Vec<&str> = good.lines().collect();
    let tampered = lines[2].replacen("\"allow\"", "\"deny\"", 1);
    std::fs::write(&log, format!("{}\n{}\n{}\n", lines[0], lines[1], tampered)).unwrap();

    h2h()
        .arg("report")
        .arg(&log)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("BROKEN"))
        .stderr(predicate::str::contains("--unverified"));

    let output = h2h()
        .arg("report")
        .arg(&log)
        .args(["--unverified", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["chain_verified"], false);
    assert!(
        report["chain"]["reason"]
            .as_str()
            .unwrap()
            .contains("entry_hash")
    );
}

#[test]
fn a_plain_receipt_jsonl_reports_without_a_chain() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("receipts.jsonl");
    let log = std::fs::read_to_string(vectors_dir().join("24h.jsonl")).unwrap();
    let mut receipts = String::new();
    for line in log.lines() {
        let entry: serde_json::Value = serde_json::from_str(line).unwrap();
        if let Some(receipt) = entry.get("receipt") {
            receipts.push_str(&serde_json::to_string(receipt).unwrap());
            receipts.push('\n');
        }
    }
    std::fs::write(&path, receipts).unwrap();

    let output = h2h()
        .arg("report")
        .arg(&path)
        .args(["--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(report["chain_verified"].is_null(), "no chain to verify");
    assert!(report["chain"].is_null());
    assert_eq!(report["totals"]["receipts"], 18);
    assert_eq!(report["totals"]["policy_events"], 0);
}

#[test]
fn the_window_narrows_the_report() {
    let report = report_json(&[
        "fixtures/report/24h.jsonl",
        "--since",
        "2026-09-15T05:00:00Z",
        "--until",
        "2026-09-15T11:00:00Z",
        "--format",
        "json",
    ]);
    // 05:20, 06:45, 07:10, 08:00, 09:25, 10:40 and 11:00 -- seven denies.
    assert_eq!(report["totals"]["receipts"], 7);
    assert_eq!(report["totals"]["by_decision"]["deny"], 7);
    assert_eq!(report["totals"]["policy_events"], 0);
    assert_eq!(report["window"]["since"], "2026-09-15T05:00:00.000Z");
    assert_eq!(report["window"]["until"], "2026-09-15T11:00:00.000Z");
    // The chain is still verified over the whole file: a window narrows what
    // is counted, never what is checked.
    assert_eq!(report["chain_verified"], true);
    assert_eq!(report["chain"]["entries"], 20);
}

#[test]
fn text_output_names_the_controls_and_the_unmapped_blocks() {
    h2h()
        .current_dir(repo_root())
        .args([
            "report",
            "fixtures/report/24h.jsonl",
            "--policy",
            POLICY,
            "--by",
            "control",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Control evidence"))
        .stdout(predicate::str::contains("hipaa-2013"))
        .stdout(predicate::str::contains("164.312(e)(1)"));
}

#[test]
fn csv_writes_one_file_per_table_and_one_table_to_stdout() {
    let dir = TempDir::new().unwrap();
    h2h()
        .current_dir(repo_root())
        .args([
            "report",
            "fixtures/report/24h.jsonl",
            "--policy",
            POLICY,
            "--format",
            "csv",
            "--out",
        ])
        .arg(dir.path())
        .assert()
        .success();
    for name in [
        "totals.csv",
        "rule_blocks.csv",
        "action_types.csv",
        "policies.csv",
        "policy_timeline.csv",
        "actors.csv",
        "signatures.csv",
        "detections.csv",
        "controls.csv",
        "unmapped_rule_blocks.csv",
    ] {
        assert!(dir.path().join(name).exists(), "{name} was not written");
    }
    let controls = std::fs::read_to_string(dir.path().join("controls.csv")).unwrap();
    assert!(controls.starts_with("framework,control_id,rule_paths,"));
    assert!(controls.contains("hipaa-2013,164.312(e)(1)"));

    let output = h2h()
        .current_dir(repo_root())
        .args([
            "report",
            "fixtures/report/24h.jsonl",
            "--format",
            "csv",
            "--by",
            "decision",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.starts_with("category,key,count\n"));
    assert!(text.contains("decision,deny,10\n"));
}

#[test]
fn oscal_is_gated_and_emits_one_result_with_findings() {
    h2h()
        .current_dir(repo_root())
        .args([
            "report",
            "fixtures/report/24h.jsonl",
            "--policy",
            POLICY,
            "--format",
            "oscal",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--experimental-oscal"));

    let output = h2h()
        .current_dir(repo_root())
        .args([
            "report",
            "fixtures/report/24h.jsonl",
            "--policy",
            POLICY,
            "--format",
            "oscal",
            "--experimental-oscal",
            "--now",
            "2026-09-16T00:00:00Z",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let document: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let results = document["assessment-results"]["results"]
        .as_array()
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(
        document["assessment-results"]["metadata"]["oscal-version"],
        "1.1.2"
    );
    let findings = results[0]["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 6, "one finding per HIPAA control mapping");
    assert!(
        findings
            .iter()
            .any(|finding| finding["target"]["target-id"] == "164.312(e)(1)")
    );
    assert_eq!(results[0]["observations"].as_array().unwrap().len(), 6);
}

#[test]
fn a_block_that_fired_with_no_mapping_is_reported_as_a_gap() {
    let dir = TempDir::new().unwrap();
    let policy = dir.path().join("partial.yaml");
    std::fs::write(
        &policy,
        r#"hushspec: "0.1.0"
name: partial
rules:
  egress:
    allow: ["api.example.com"]
    default: block
  tool_access:
    allow: ["read_file"]
    default: block
metadata:
  controls:
    - framework: soc2-tsc-2017
      control_id: CC6.1
      rule_paths:
        - rules.egress
"#,
    )
    .unwrap();
    let log = dir.path().join("eval.jsonl");

    // `h2h eval --log` is the writer here: the report reads exactly what the
    // evaluation side of the CLI produces, not a hand-written fixture.
    h2h()
        .arg("eval")
        .arg(&policy)
        .args(["--type", "tool_call", "--target", "shell_exec", "--log"])
        .arg(&log)
        .assert()
        .code(1);

    let output = h2h()
        .arg("report")
        .arg(&log)
        .arg("--policy")
        .arg(&policy)
        .args(["--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let controls = &report["controls"];
    assert_eq!(controls["receipts_matching_policy"], 1);
    assert_eq!(
        controls["unmapped_fired_rule_blocks"],
        serde_json::json!(["tool_access"])
    );
    // The mapped control saw nothing: a tool call never reaches egress.
    let row = &controls["frameworks"][0]["controls"][0];
    assert_eq!(row["control_id"], "CC6.1");
    assert_eq!(row["receipts"], 0);
    assert!(row["last_seen"].is_null());
}

/// Whether the caller asked for the committed vectors to be regenerated.
///
/// Only `1` and `true` count: `is_ok()` would make `VAR=0` regenerate, which
/// silently turns a verifying run into a rubber stamp.
fn update_requested(var: &str) -> bool {
    matches!(std::env::var(var).as_deref(), Ok("1") | Ok("true"))
}
