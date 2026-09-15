//! The evidence-chain vectors: conformance Levels 4 (Auditor) and 5 (Attested).
//!
//! Levels 0-3 are about the document -- parse, validate, merge, evaluate --
//! and the fixture runner in [`crate::runner`] covers them. Levels 4 and 5 are
//! about what an engine *emits*: receipts whose content hash and rule trace
//! any implementation can reproduce, and signatures, logs and bundles anyone
//! can verify offline. Those vectors do not look like policies, so they get
//! their own runners here, one per corpus directory, each producing the same
//! [`VectorResult`] the report is built from.
//!
//! Every runner is fail-closed: a vector it cannot read, parse or reach is a
//! failure, never a silent skip. The one thing it may report is
//! `not_attempted`, and only for a whole module it was not built to exercise.

use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeZone, Utc};
use hushspec::receipt::{
    Actor, AuditConfig, AuditContext, DecisionReceipt, EnforcementMode, TimeSource,
    deterministic_uuid_v7, evaluate_audited,
};
use hushspec::{EvaluationAction, HushSpec, Resolution};
use jsonschema::JSONSchema;
use serde::Deserialize;

use crate::report::{Status, VectorResult};

/// Fixed evaluation time of every expected receipt: 2026-09-15T12:00:00.000Z
/// (`fixtures/receipts/expected/README.md`).
const CLOCK_MILLIS: u64 = 1_789_473_600_000;

/// The modules that carry evaluation vectors, and so expected receipts.
const EVALUATION_MODULES: [&str; 4] = ["core", "posture", "origins", "detection"];

fn pass(path: String, category: &str, level: u8, message: String) -> VectorResult {
    VectorResult {
        path,
        category: category.to_string(),
        level: Some(level),
        status: Status::Pass,
        message: Some(message),
    }
}

fn fail(path: String, category: &str, level: u8, message: String) -> VectorResult {
    VectorResult {
        path,
        category: category.to_string(),
        level: Some(level),
        status: Status::Fail,
        message: Some(message),
    }
}

fn label(path: &Path) -> String {
    crate::manifest::relative_fixture_path(path).unwrap_or_else(|| path.display().to_string())
}

fn files_in(dir: &Path, extension: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().is_some_and(|found| found == extension))
        .collect();
    files.sort();
    files
}

fn receipt_schema() -> Result<JSONSchema, String> {
    let body = crate::generated_schemas::schema_body("receipt")
        .ok_or_else(|| "the receipt schema is not embedded".to_string())?;
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|error| format!("receipt schema: {error}"))?;
    JSONSchema::options()
        .should_validate_formats(true)
        .compile(&value)
        .map_err(|error| format!("receipt schema does not compile: {error}"))
}

// --------------------------------------------------------------------------
// Level 4: receipts
// --------------------------------------------------------------------------

/// `fixtures/receipts/valid/` and `fixtures/receipts/invalid/`: receipt spec
/// Section 2 conformance point 4 -- the parser accepts every valid vector and
/// refuses every invalid one, and a valid vector round-trips through the
/// typed model without changing its canonical form (Section 6).
pub fn run_receipt_vectors(fixtures_dir: &Path) -> Vec<VectorResult> {
    let schema = match receipt_schema() {
        Ok(schema) => schema,
        Err(error) => {
            return vec![fail("fixtures/receipts".to_string(), "receipt", 4, error)];
        }
    };
    let mut results = Vec::new();

    for path in files_in(&fixtures_dir.join("receipts/valid"), "json") {
        let name = label(&path);
        let Ok(text) = std::fs::read_to_string(&path) else {
            results.push(fail(name, "receipt", 4, "unreadable".to_string()));
            continue;
        };
        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(error) => {
                results.push(fail(name, "receipt", 4, format!("not JSON: {error}")));
                continue;
            }
        };
        if let Err(errors) = schema.validate(&value) {
            let messages: Vec<String> = errors.map(|error| error.to_string()).collect();
            results.push(fail(
                name,
                "receipt",
                4,
                format!("does not validate: {}", messages.join(", ")),
            ));
            continue;
        }
        let receipt = match DecisionReceipt::parse(&text) {
            Ok(receipt) => receipt,
            Err(error) => {
                results.push(fail(name, "receipt", 4, format!("does not parse: {error}")));
                continue;
            }
        };
        let reserialized = match serde_json::to_value(&receipt) {
            Ok(value) => value,
            Err(error) => {
                results.push(fail(name, "receipt", 4, error.to_string()));
                continue;
            }
        };
        match (
            hushspec::canonical::serialize_jcs(&reserialized),
            hushspec::canonical::serialize_jcs(&value),
        ) {
            (Ok(after), Ok(before)) if after == before => {
                results.push(pass(
                    name,
                    "receipt",
                    4,
                    "accepted and round-trips".to_string(),
                ));
            }
            (Ok(_), Ok(_)) => results.push(fail(
                name,
                "receipt",
                4,
                "the typed model does not round-trip the vector".to_string(),
            )),
            (Err(error), _) | (_, Err(error)) => {
                results.push(fail(name, "receipt", 4, error.to_string()));
            }
        }
    }

    for path in files_in(&fixtures_dir.join("receipts/invalid"), "json") {
        let name = label(&path);
        let Ok(text) = std::fs::read_to_string(&path) else {
            results.push(fail(name, "receipt", 4, "unreadable".to_string()));
            continue;
        };
        let schema_ok = serde_json::from_str::<serde_json::Value>(&text)
            .is_ok_and(|value| schema.validate(&value).is_ok());
        let parse_ok = DecisionReceipt::parse(&text).is_ok();
        if schema_ok && parse_ok {
            results.push(fail(
                name,
                "receipt",
                4,
                "accepted by both the schema and the parser".to_string(),
            ));
        } else {
            results.push(pass(name, "receipt", 4, "correctly rejected".to_string()));
        }
    }

    results
}

#[derive(Deserialize)]
struct ExpectedReceiptFixture {
    policy: serde_json::Value,
    cases: Vec<ExpectedReceiptCase>,
}

#[derive(Deserialize)]
struct ExpectedReceiptCase {
    action: EvaluationAction,
    #[serde(default)]
    context: Option<hushspec::RuntimeContext>,
}

fn expected_receipt_context(case_index: usize) -> AuditContext {
    AuditContext {
        actor: Some(Actor {
            agent_id: Some("fixture-agent".to_string()),
            session_id: Some("fixture-session".to_string()),
            principal: Some("fixture@hushspec.dev".to_string()),
            runtime: Some("hushspec-conformance/0.2".to_string()),
        }),
        enforcement_mode: EnforcementMode::Enforce,
        time_source: TimeSource::Trusted,
        clock: Some(Utc.with_ymd_and_hms(2026, 9, 15, 12, 0, 0).unwrap()),
        receipt_id: Some(deterministic_uuid_v7(CLOCK_MILLIS, case_index as u64)),
        ..AuditContext::default()
    }
}

/// `fixtures/receipts/expected/`: receipt spec Section 2 points 1-3 -- the
/// receipt an engine emits for every shared evaluation case, compared after
/// RFC 8785 canonicalization so formatting does not matter and every field
/// value does. This is what makes the recorded `rule_trace` and the canonical
/// `policy.content_hash` checkable rather than asserted.
pub fn run_expected_receipts(fixtures_dir: &Path) -> Vec<VectorResult> {
    let config = AuditConfig {
        enabled: true,
        include_rule_trace: true,
        record_duration: false,
    };
    let mut results = Vec::new();

    for module in EVALUATION_MODULES {
        let dir = fixtures_dir.join(module).join("evaluation");
        for fixture_path in files_in(&dir, "yaml") {
            let stem = fixture_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .trim_end_matches(".test.yaml")
                .to_string();
            let expected_dir = fixtures_dir
                .join("receipts/expected")
                .join(module)
                .join(&stem);
            let name = label(&fixture_path);

            let text = match std::fs::read_to_string(&fixture_path) {
                Ok(text) => text,
                Err(error) => {
                    results.push(fail(name, "receipt-expected", 4, error.to_string()));
                    continue;
                }
            };
            let fixture: ExpectedReceiptFixture = match serde_yaml::from_str(&text) {
                Ok(fixture) => fixture,
                Err(error) => {
                    results.push(fail(name, "receipt-expected", 4, error.to_string()));
                    continue;
                }
            };
            let resolution = match serde_yaml::to_string(&fixture.policy)
                .map_err(|error| error.to_string())
                .and_then(|yaml| HushSpec::parse(&yaml).map_err(|error| error.to_string()))
                .and_then(|spec| {
                    Resolution::from_resolved(&spec, None).map_err(|error| error.to_string())
                }) {
                Ok(resolution) => resolution,
                Err(error) => {
                    results.push(fail(name, "receipt-expected", 4, error));
                    continue;
                }
            };

            for (index, case) in fixture.cases.iter().enumerate() {
                let case_name = format!("{}#{index}", label(&expected_dir));
                let mut action = case.action.clone();
                if action.context.is_none() {
                    action.context = case.context.clone();
                }
                let receipt = evaluate_audited(
                    &resolution,
                    &action,
                    &config,
                    &expected_receipt_context(index),
                );
                let produced = match serde_json::to_value(&receipt)
                    .map_err(|error| error.to_string())
                    .and_then(|value| {
                        hushspec::canonical::serialize_jcs(&value).map_err(|e| e.to_string())
                    }) {
                    Ok(canonical) => canonical,
                    Err(error) => {
                        results.push(fail(case_name, "receipt-expected", 4, error));
                        continue;
                    }
                };
                let vector_path = expected_dir.join(format!("{index}.json"));
                let committed = match std::fs::read_to_string(&vector_path)
                    .map_err(|error| format!("{}: {error}", label(&vector_path)))
                    .and_then(|text| {
                        serde_json::from_str::<serde_json::Value>(&text)
                            .map_err(|error| error.to_string())
                    })
                    .and_then(|value| {
                        hushspec::canonical::serialize_jcs(&value).map_err(|e| e.to_string())
                    }) {
                    Ok(canonical) => canonical,
                    Err(error) => {
                        results.push(fail(case_name, "receipt-expected", 4, error));
                        continue;
                    }
                };
                if produced == committed {
                    results.push(pass(
                        case_name,
                        "receipt-expected",
                        4,
                        "matches the committed receipt".to_string(),
                    ));
                } else {
                    results.push(fail(
                        case_name,
                        "receipt-expected",
                        4,
                        format!("differs from the committed receipt:\n want: {committed}\n  got: {produced}"),
                    ));
                }
            }
        }
    }

    results
}

// --------------------------------------------------------------------------
// Level 5: signatures, logs, bundles
// --------------------------------------------------------------------------

/// `expect: valid`, or `expect: {invalid: <reason code>}`.
#[derive(Deserialize)]
#[serde(untagged)]
enum Expect {
    Valid(ValidMarker),
    Invalid { invalid: String },
}

#[derive(Deserialize)]
enum ValidMarker {
    #[serde(rename = "valid")]
    Valid,
}

impl Expect {
    fn as_str(&self) -> &str {
        match self {
            Expect::Valid(ValidMarker::Valid) => "valid",
            Expect::Invalid { invalid } => invalid.as_str(),
        }
    }
}

fn instant(value: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|error| format!("{value:?} is not an RFC 3339 timestamp: {error}"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningManifest {
    #[serde(rename = "hushspec_signing_vectors")]
    _version: String,
    #[serde(default, rename = "description")]
    _description: Option<String>,
    defaults: SigningDefaults,
    cases: Vec<SigningCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningDefaults {
    keyring: String,
    now: String,
    max_clock_skew_seconds: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningCase {
    name: String,
    policy: String,
    signature: String,
    keyring: Option<String>,
    now: Option<String>,
    max_clock_skew_seconds: Option<i64>,
    last_seen_version: Option<u64>,
    expect: Expect,
    #[serde(default, rename = "note")]
    _note: Option<String>,
}

/// `fixtures/signing/vectors.yaml`: signing spec Section 2 -- an
/// implementation conforms as a verifier if every case returns its expected
/// outcome, `valid` or an exact reason code from Section 6.4.
pub fn run_signing_vectors(fixtures_dir: &Path) -> Vec<VectorResult> {
    use hushspec::signing::{Envelope, Keyring, VerifyOptions, verify_policy_at};

    let root = fixtures_dir.join("signing");
    let manifest_path = root.join("vectors.yaml");
    let manifest: SigningManifest = match std::fs::read_to_string(&manifest_path)
        .map_err(|error| error.to_string())
        .and_then(|text| serde_yaml::from_str(&text).map_err(|error| error.to_string()))
    {
        Ok(manifest) => manifest,
        Err(error) => return vec![fail(label(&manifest_path), "signing", 5, error)],
    };

    let mut results = Vec::new();
    for case in &manifest.cases {
        let name = format!("{}#{}", label(&manifest_path), case.name);
        let keyring_path = root.join(
            case.keyring
                .as_deref()
                .unwrap_or(&manifest.defaults.keyring),
        );
        let keyring = match Keyring::load(&keyring_path) {
            Ok(keyring) => keyring,
            Err(error) => {
                results.push(fail(name, "signing", 5, format!("keyring: {error}")));
                continue;
            }
        };
        let now = match instant(case.now.as_deref().unwrap_or(&manifest.defaults.now)) {
            Ok(now) => now,
            Err(error) => {
                results.push(fail(name, "signing", 5, error));
                continue;
            }
        };
        let options = VerifyOptions {
            now,
            max_clock_skew_seconds: case
                .max_clock_skew_seconds
                .unwrap_or(manifest.defaults.max_clock_skew_seconds),
            last_seen_version: case.last_seen_version,
        };
        let envelope_text = match std::fs::read_to_string(root.join(&case.signature)) {
            Ok(text) => text,
            Err(error) => {
                results.push(fail(
                    name,
                    "signing",
                    5,
                    format!("{}: {error}", case.signature),
                ));
                continue;
            }
        };
        // A `.sig` that will not even parse is a check-1 failure, reported
        // with the same reason code the verifier would use.
        let outcome = match Envelope::parse(&envelope_text) {
            Ok(envelope) => {
                verify_policy_at(&root.join(&case.policy), &envelope, &keyring, &options)
                    .map(|_| ())
            }
            Err(error) => Err(error),
        };
        let actual = match &outcome {
            Ok(()) => "valid".to_string(),
            Err(error) => error.reason_code().to_string(),
        };
        let expected = case.expect.as_str();
        if actual == expected {
            results.push(pass(name, "signing", 5, format!("{expected} as expected")));
        } else {
            let detail = outcome
                .as_ref()
                .err()
                .map_or_else(String::new, |error| format!(" ({})", error.detail));
            results.push(fail(
                name,
                "signing",
                5,
                format!("expected {expected}, got {actual}{detail}"),
            ));
        }
    }
    results
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleManifest {
    #[serde(rename = "hushspec_bundle_vectors")]
    _version: String,
    #[serde(default, rename = "description")]
    _description: Option<String>,
    defaults: BundleDefaults,
    cases: Vec<BundleCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleDefaults {
    keyring: String,
    now: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleCase {
    name: String,
    bundle: String,
    keyring: Option<String>,
    policy: Option<String>,
    now: Option<String>,
    expect: Expect,
    #[serde(default, rename = "note")]
    _note: Option<String>,
}

/// `fixtures/bundle/vectors.yaml`: bundle spec Section 7 -- a bundle verifier
/// returns `valid` or the exact Section 5.4 reason code for every case.
pub fn run_bundle_vectors(fixtures_dir: &Path) -> Vec<VectorResult> {
    use hushspec::bundle::{DsseEnvelope, VerifyBundleOptions, verify_bundle};
    use hushspec::resolve::{ResolveOptions, resolve_path_with_options};
    use hushspec::signing::Keyring;

    let root = fixtures_dir.join("bundle");
    let manifest_path = root.join("vectors.yaml");
    let manifest: BundleManifest = match std::fs::read_to_string(&manifest_path)
        .map_err(|error| error.to_string())
        .and_then(|text| serde_yaml::from_str(&text).map_err(|error| error.to_string()))
    {
        Ok(manifest) => manifest,
        Err(error) => return vec![fail(label(&manifest_path), "bundle", 5, error)],
    };

    let mut results = Vec::new();
    for case in &manifest.cases {
        let name = format!("{}#{}", label(&manifest_path), case.name);
        let keyring_path = root.join(
            case.keyring
                .as_deref()
                .unwrap_or(&manifest.defaults.keyring),
        );
        let keyring = match Keyring::load(&keyring_path) {
            Ok(keyring) => keyring,
            Err(error) => {
                results.push(fail(name, "bundle", 5, format!("keyring: {error}")));
                continue;
            }
        };
        let now = match instant(case.now.as_deref().unwrap_or(&manifest.defaults.now)) {
            Ok(now) => now,
            Err(error) => {
                results.push(fail(name, "bundle", 5, error));
                continue;
            }
        };
        let options = VerifyBundleOptions { now };
        let text = match std::fs::read_to_string(root.join(&case.bundle)) {
            Ok(text) => text,
            Err(error) => {
                results.push(fail(name, "bundle", 5, format!("{}: {error}", case.bundle)));
                continue;
            }
        };
        // A policy that will not resolve has nothing to compare, which is
        // check 4's own failure and never a panic.
        let resolution = case.policy.as_deref().map(|policy| {
            resolve_path_with_options(root.join(policy), &ResolveOptions::default()).ok()
        });
        let policy_missing = matches!(resolution, Some(None));
        let outcome = match DsseEnvelope::parse(&text) {
            Ok(envelope) => {
                verify_bundle(&envelope, &keyring, resolution.flatten().as_ref(), &options)
                    .map(|_| ())
            }
            Err(error) => Err(error),
        };
        let actual = match (&outcome, policy_missing) {
            (_, true) => "policy_mismatch".to_string(),
            (Ok(()), _) => "valid".to_string(),
            (Err(error), _) => error.reason_code().to_string(),
        };
        let expected = case.expect.as_str();
        if actual == expected {
            results.push(pass(name, "bundle", 5, format!("{expected} as expected")));
        } else {
            let detail = outcome
                .as_ref()
                .err()
                .map_or_else(String::new, |error| format!(" ({})", error.detail));
            results.push(fail(
                name,
                "bundle",
                5,
                format!("expected {expected}, got {actual}{detail}"),
            ));
        }
    }
    results
}

/// `fixtures/log/`: log spec -- every `valid/` chain verifies, every
/// `invalid/` one is refused at the line its file name names.
pub fn run_log_vectors(fixtures_dir: &Path) -> Vec<VectorResult> {
    use hushspec::log::{LogVerifyOptions, verify_log, verify_logs};
    use hushspec::signing::{Keyring, VerifyOptions};

    let root = fixtures_dir.join("log");
    // Fail closed on the keyring: the signed vectors need it to tell a bad
    // signature from a good one, and `.ok()` here would let every one of them
    // pass without a signature ever being checked.
    let keyring = match Keyring::load(&fixtures_dir.join("signing/keys/keyring.json")) {
        Ok(keyring) => Some(keyring),
        Err(error) => {
            return vec![fail(label(&root), "log", 5, format!("keyring: {error}"))];
        }
    };
    let options = || LogVerifyOptions {
        require_signatures: false,
        keyring: keyring.clone(),
        verify: Some(VerifyOptions {
            now: Utc.with_ymd_and_hms(2026, 9, 15, 12, 0, 0).unwrap(),
            max_clock_skew_seconds: 300,
            last_seen_version: None,
        }),
    };

    let mut results = Vec::new();
    let mut rotated: Vec<(String, String)> = Vec::new();

    for path in files_in(&root.join("valid"), "jsonl") {
        let name = label(&path);
        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let Ok(text) = std::fs::read_to_string(&path) else {
            results.push(fail(name, "log", 5, "unreadable".to_string()));
            continue;
        };
        if file_name.starts_with("rotated-") {
            // A rotation is one chain across two files: each verifies alone
            // from its own link, and the pair verifies in order.
            rotated.push((file_name.clone(), text.clone()));
        }
        match verify_log(&file_name, &text, &options()) {
            Ok(_) => results.push(pass(name, "log", 5, "chain verifies".to_string())),
            Err(error) => results.push(fail(name, "log", 5, error.to_string())),
        }
    }

    if rotated.len() >= 2 {
        rotated.sort();
        let pair: Vec<(&str, &str)> = rotated
            .iter()
            .map(|(name, text)| (name.as_str(), text.as_str()))
            .collect();
        let name = "fixtures/log/valid/rotated-*.jsonl".to_string();
        match verify_logs(&pair, &options()) {
            Ok(_) => results.push(pass(
                name,
                "log",
                5,
                "the rotated pair verifies as one chain".to_string(),
            )),
            Err(error) => results.push(fail(name, "log", 5, error.to_string())),
        }
    }

    for path in files_in(&root.join("invalid"), "jsonl") {
        let name = label(&path);
        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let Ok(text) = std::fs::read_to_string(&path) else {
            results.push(fail(name, "log", 5, "unreadable".to_string()));
            continue;
        };
        // The file name ends with the line the chain first breaks at, so a
        // verifier that rejects for the wrong reason does not pass.
        let expected_line: Option<usize> = file_name
            .trim_end_matches(".jsonl")
            .rsplit('-')
            .next()
            .and_then(|tail| tail.parse().ok());
        let Some(expected_line) = expected_line else {
            results.push(fail(
                name,
                "log",
                5,
                "an invalid log vector must name the line it breaks at, as \
                 `<reason>-line-<n>.jsonl`"
                    .to_string(),
            ));
            continue;
        };
        match verify_log(&file_name, &text, &options()) {
            Ok(_) => results.push(fail(name, "log", 5, "accepted a broken chain".to_string())),
            Err(error) if error.line != expected_line => results.push(fail(
                name,
                "log",
                5,
                format!(
                    "break reported at line {} but expected line {expected_line}",
                    error.line
                ),
            )),
            Err(error) => results.push(pass(
                name,
                "log",
                5,
                format!("refused at line {}: {error}", error.line),
            )),
        }
    }

    results
}

/// `fixtures/receipts/signed/`: receipt signing (signing spec Section 8) --
/// the valid envelope verifies, and each invalid one fails for its own
/// reason.
pub fn run_signed_receipt_vectors(fixtures_dir: &Path) -> Vec<VectorResult> {
    use hushspec::signing::{Keyring, SignedReceipt, VerifyOptions, verify_receipt};

    let root = fixtures_dir.join("receipts/signed");
    let keyring = match Keyring::load(&fixtures_dir.join("signing/keys/keyring.json")) {
        Ok(keyring) => keyring,
        Err(error) => {
            return vec![fail(
                label(&root),
                "receipt-signed",
                5,
                format!("keyring: {error}"),
            )];
        }
    };
    let options = VerifyOptions {
        now: Utc.with_ymd_and_hms(2026, 9, 15, 12, 0, 0).unwrap(),
        max_clock_skew_seconds: 300,
        last_seen_version: None,
    };

    let mut results = Vec::new();
    for (subdir, should_verify) in [("valid", true), ("invalid", false)] {
        for path in files_in(&root.join(subdir), "json") {
            let name = label(&path);
            let signed: SignedReceipt = match std::fs::read_to_string(&path)
                .map_err(|error| error.to_string())
                .and_then(|text| serde_json::from_str(&text).map_err(|error| error.to_string()))
            {
                Ok(signed) => signed,
                Err(error) => {
                    // A malformed envelope is a refusal, which is what an
                    // invalid vector wants and a valid one must not be.
                    if should_verify {
                        results.push(fail(name, "receipt-signed", 5, error));
                    } else {
                        results.push(pass(
                            name,
                            "receipt-signed",
                            5,
                            format!("correctly rejected: {error}"),
                        ));
                    }
                    continue;
                }
            };
            match (verify_receipt(&signed, &keyring, &options), should_verify) {
                (Ok(_), true) => results.push(pass(
                    name,
                    "receipt-signed",
                    5,
                    "signature verifies".to_string(),
                )),
                (Ok(_), false) => results.push(fail(
                    name,
                    "receipt-signed",
                    5,
                    "verified a receipt that must be rejected".to_string(),
                )),
                (Err(error), true) => {
                    results.push(fail(name, "receipt-signed", 5, error.to_string()));
                }
                (Err(error), false) => results.push(pass(
                    name,
                    "receipt-signed",
                    5,
                    format!("correctly rejected: {}", error.reason.as_str()),
                )),
            }
        }
    }
    results
}

/// Every Level 4 and Level 5 vector, in corpus order.
pub fn run_evidence(fixtures_dir: &Path) -> Vec<VectorResult> {
    let mut results = Vec::new();
    results.extend(run_receipt_vectors(fixtures_dir));
    results.extend(run_expected_receipts(fixtures_dir));
    results.extend(run_signing_vectors(fixtures_dir));
    results.extend(run_signed_receipt_vectors(fixtures_dir));
    results.extend(run_log_vectors(fixtures_dir));
    results.extend(run_bundle_vectors(fixtures_dir));
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
    }

    fn assert_all_pass(results: &[VectorResult], what: &str) {
        assert!(!results.is_empty(), "{what}: no vectors ran");
        let failures: Vec<String> = results
            .iter()
            .filter(|result| result.status != Status::Pass)
            .map(|result| {
                format!(
                    "{}: {}",
                    result.path,
                    result.message.as_deref().unwrap_or("")
                )
            })
            .collect();
        assert!(failures.is_empty(), "{what}:\n  {}", failures.join("\n  "));
    }

    #[test]
    fn receipt_vectors_pass() {
        assert_all_pass(&run_receipt_vectors(&fixtures_dir()), "receipt vectors");
    }

    #[test]
    fn expected_receipts_pass() {
        assert_all_pass(&run_expected_receipts(&fixtures_dir()), "expected receipts");
    }

    #[test]
    fn signing_vectors_pass() {
        assert_all_pass(&run_signing_vectors(&fixtures_dir()), "signing vectors");
    }

    #[test]
    fn signed_receipt_vectors_pass() {
        assert_all_pass(
            &run_signed_receipt_vectors(&fixtures_dir()),
            "signed receipt vectors",
        );
    }

    #[test]
    fn log_vectors_pass() {
        assert_all_pass(&run_log_vectors(&fixtures_dir()), "log vectors");
    }

    #[test]
    fn bundle_vectors_pass() {
        assert_all_pass(&run_bundle_vectors(&fixtures_dir()), "bundle vectors");
    }
}
