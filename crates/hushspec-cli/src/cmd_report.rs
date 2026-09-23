//! `h2h report`: turn a window of receipts into an evidence report.
//!
//! The input is either a hash-linked log (`spec/hushspec-log.md`) or a plain
//! receipt JSONL; each line is classified on its own, and a file holding any
//! log entry is treated as a log. A log's chain is verified before anything is
//! counted, because a report over a chain that does not verify is not evidence
//! -- it is a summary of whatever the last writer left behind. Reporting on a
//! broken chain therefore takes an explicit `--unverified`, and stamps the
//! document `chain_verified: false`.
//!
//! The aggregation itself is [`hushspec::report`]. What lives here is the
//! reading (auto-detection, the window, fail-closed line handling), the
//! `metadata.controls` join -- which needs the resolved policy and the
//! framework registry, so it belongs to the CLI the way `h2h audit --controls`
//! does -- and the four renderings.

use clap::ValueEnum;
use colored::Colorize;
use hushspec::log::{LogEntry, LogError, LogVerifyOptions, PolicyEvent, verify_log};
use hushspec::report::{
    ChainSummary, ControlsEvidence, Report, ReportOptions, build_report, in_window,
};
use hushspec::signing::SignedReceipt;
use hushspec::{DecisionReceipt, HushSpec, ResolveOptions};
use jsonschema::JSONSchema;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

#[derive(clap::Args)]
pub struct ReportArgs {
    /// Hash-linked logs (`.jsonl`) or plain receipt JSONL files
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// Only count records at or after this RFC 3339 timestamp
    #[arg(long, value_name = "TIMESTAMP")]
    since: Option<String>,

    /// Only count records at or before this RFC 3339 timestamp
    #[arg(long, value_name = "TIMESTAMP")]
    until: Option<String>,

    /// Policy whose `metadata.controls` the report joins the receipts against
    #[arg(long, value_name = "PATH")]
    policy: Option<PathBuf>,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,

    /// Report on one table only (and, for CSV on stdout, which one)
    #[arg(long, value_name = "TABLE")]
    by: Option<By>,

    /// Write here: a directory for `--format csv`, a file for every other
    /// format (default: stdout)
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,

    /// Skip input lines that do not parse instead of refusing to report
    #[arg(long)]
    lenient: bool,

    /// Report even though an input log's hash chain did not verify
    #[arg(long)]
    unverified: bool,

    /// Trusted keyring JSON for entry signatures
    #[arg(long, value_name = "PATH", conflicts_with = "key")]
    keyring: Option<PathBuf>,

    /// A single trusted public key (PEM) for entry signatures
    #[arg(long, value_name = "PATH")]
    key: Option<PathBuf>,

    /// Every log entry must carry a signature that verifies (legacy mode: logs only)
    #[arg(long)]
    require_signatures: bool,

    /// Allowed signer clock skew in seconds
    #[arg(long, default_value_t = 300, value_name = "SECONDS")]
    max_skew: i64,

    /// Stamp the report with this RFC 3339 time instead of the wall clock
    #[arg(long, value_name = "TIMESTAMP")]
    now: Option<String>,

    /// Enable the experimental OSCAL exporter (`--format oscal`)
    #[arg(long)]
    experimental_oscal: bool,

    /// How many `rule_path`s each rule-block row lists
    #[arg(long, default_value_t = 5, value_name = "N")]
    top_paths: usize,

    /// Experimental strict verification profile (offline local artifacts)
    #[arg(long, value_name = "PATH")]
    evidence_profile: Option<PathBuf>,

    /// New verification sidecar file, published last as the completion marker
    #[arg(long, value_name = "PATH")]
    verification_out: Option<PathBuf>,

    /// Strict mode only: maximum bytes in any input file (default 16777216)
    #[arg(long)]
    max_evidence_file_bytes: Option<u64>,

    /// Strict mode only: maximum total input bytes (default 67108864)
    #[arg(long)]
    max_evidence_total_bytes: Option<u64>,

    /// Strict mode only: maximum JSONL line bytes (default 1048576)
    #[arg(long)]
    max_evidence_line_bytes: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Csv,
    /// OSCAL assessment-results skeleton; needs `--experimental-oscal`
    Oscal,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum By {
    Control,
    Rule,
    Decision,
    Policy,
}

impl By {
    fn table(self) -> &'static str {
        match self {
            By::Control => "controls",
            By::Rule => "rule_blocks",
            By::Decision => "totals",
            By::Policy => "policies",
        }
    }
}

/// Everything read from the inputs before aggregation.
#[derive(Default)]
struct Loaded {
    receipts: Vec<DecisionReceipt>,
    events: Vec<PolicyEvent>,
    chain: Option<ChainSummary>,
    skipped: u64,
    /// `file:line: reason` for every line that did not parse.
    malformed: Vec<String>,
}

pub fn run(args: ReportArgs) -> i32 {
    if args.evidence_profile.is_some()
        || args.verification_out.is_some()
        || args.max_evidence_file_bytes.is_some()
        || args.max_evidence_total_bytes.is_some()
        || args.max_evidence_line_bytes.is_some()
    {
        return run_strict(&args);
    }
    if args.format == OutputFormat::Oscal && !args.experimental_oscal {
        eprintln!(
            "{} --format oscal is experimental; pass --experimental-oscal to enable it",
            "error:".red()
        );
        return 2;
    }

    let since = match parse_bound(args.since.as_deref(), "--since") {
        Ok(bound) => bound,
        Err(code) => return code,
    };
    let until = match parse_bound(args.until.as_deref(), "--until") {
        Ok(bound) => bound,
        Err(code) => return code,
    };
    if let (Some(since), Some(until)) = (since, until)
        && since > until
    {
        eprintln!("{} --since is after --until", "error:".red());
        return 2;
    }
    let generated_at = match args.now.as_deref() {
        None => Some(Utc::now()),
        Some(text) => match parse_bound(Some(text), "--now") {
            Ok(value) => value,
            Err(code) => return code,
        },
    };

    // A report's chain check is `h2h log verify`'s, so it reads the same
    // flags and runs the same receipt schema pass. The report's own instant is
    // the verifier's clock, so a report pinned with `--now` verifies the
    // signatures as of the moment it claims to describe.
    let verify_args = crate::verify_opts::VerifyOnLoadArgs {
        require_signature: false,
        keyring: args.keyring.clone(),
        key: args.key.clone(),
        now: args.now.clone(),
        max_skew: args.max_skew,
        last_seen_version: None,
    };
    let resolve_options = match verify_args.to_options() {
        Ok(options) => options,
        Err(code) => return code,
    };
    let log_options = LogVerifyOptions {
        require_signatures: args.require_signatures,
        keyring: resolve_options.keyring,
        verify: resolve_options.verify,
    };
    let receipt_schema = match crate::cmd_log::receipt_schema() {
        Ok(schema) => schema,
        Err(message) => {
            eprintln!("{} {message}", "error:".red());
            return 2;
        }
    };

    let mut loaded = Loaded::default();
    for path in &args.files {
        if let Err(code) = read_file(path, &log_options, &receipt_schema, &mut loaded) {
            return code;
        }
    }
    if !loaded.malformed.is_empty() {
        if args.lenient {
            loaded.skipped = loaded.malformed.len() as u64;
        } else {
            eprintln!(
                "{} {} input line(s) are neither a log entry nor a receipt; \
                 pass --lenient to skip them:",
                "error:".red(),
                loaded.malformed.len()
            );
            for message in &loaded.malformed {
                eprintln!("  {message}");
            }
            return 2;
        }
    }
    if let Some(chain) = &loaded.chain
        && !chain.verified
        && !args.unverified
    {
        eprintln!(
            "{} {}",
            "BROKEN".red().bold(),
            chain
                .reason
                .as_deref()
                .unwrap_or("the log chain did not verify")
        );
        eprintln!(
            "       pass --unverified to report anyway (the report is stamped chain_verified: false)"
        );
        return 1;
    }

    let options = ReportOptions {
        sources: args
            .files
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        since,
        until,
        generated_at,
        chain: loaded.chain.clone(),
        skipped_lines: loaded.skipped,
        top_rule_paths: args.top_paths,
    };
    let mut report = build_report(&loaded.receipts, &loaded.events, &options);

    let in_window_receipts: Vec<&DecisionReceipt> = loaded
        .receipts
        .iter()
        .filter(|receipt| in_window(&receipt.timestamp, since, until))
        .collect();
    match control_evidence(
        args.policy.as_deref(),
        &loaded,
        &in_window_receipts,
        &report,
    ) {
        Ok(controls) => report.controls = controls,
        Err(code) => return code,
    }

    if args.by == Some(By::Control) && report.controls.is_none() {
        eprintln!(
            "{} --by control needs control mappings: pass --policy <file> whose \
             metadata.controls names the controls to report on",
            "error:".red()
        );
        return 2;
    }
    if args.format == OutputFormat::Oscal && report.controls.is_none() {
        eprintln!(
            "{} --format oscal needs control mappings: pass --policy <file>",
            "error:".red()
        );
        return 2;
    }

    emit(&report, &args)
}

// ---------------------------------------------------------------------- input

fn run_strict(args: &ReportArgs) -> i32 {
    match strict_report(args) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("error: {error}");
            error.exit_code()
        }
    }
}

fn strict_report(args: &ReportArgs) -> Result<(), crate::report_evidence::model::EvidenceError> {
    use crate::report_evidence::{self, model::*, output::*, policy, snapshot::*};
    use hushspec::signing::{Keyring, VerifyOptions};
    let config = |message| EvidenceError::new(EvidenceCode::Configuration, message);
    let profile_path = args
        .evidence_profile
        .as_deref()
        .ok_or_else(|| config("strict reporting requires --evidence-profile"))?;
    if args.format != OutputFormat::Json
        || args.lenient
        || args.unverified
        || args.by.is_some()
        || args.max_skew < 0
    {
        return Err(config(
            "strict reporting requires JSON, nonnegative skew, and no --lenient, --unverified or --by",
        ));
    }
    let report_path = args
        .out
        .as_ref()
        .ok_or_else(|| config("strict reporting requires --out"))?;
    let sidecar_path = args
        .verification_out
        .as_ref()
        .ok_or_else(|| config("strict reporting requires --verification-out"))?;
    let key_path = match (&args.keyring, &args.key) {
        (Some(path), None) | (None, Some(path)) => path,
        _ => {
            return Err(config(
                "strict reporting requires exactly one --key or --keyring",
            ));
        }
    };
    let defaults = Limits::default();
    let limits = Limits {
        file_bytes: args.max_evidence_file_bytes.unwrap_or(defaults.file_bytes),
        total_bytes: args
            .max_evidence_total_bytes
            .unwrap_or(defaults.total_bytes),
        line_bytes: args.max_evidence_line_bytes.unwrap_or(defaults.line_bytes),
    };
    limits.validate()?;
    let mut budget = InputBudget::default();
    let profile_input = read_snapshot(profile_path, "profile", &limits, &mut budget)?;
    let profile = parse_profile(&profile_input.bytes)?;
    let key_input = read_snapshot(key_path, "trust input", &limits, &mut budget)?;
    let key_text =
        std::str::from_utf8(&key_input.bytes).map_err(|_| config("trust input is not UTF-8"))?;
    let keys = if args.keyring.is_some() {
        report_evidence::json::parse_json(&key_input.bytes, MAX_DEPTH)?;
        Keyring::parse(key_text)
    } else {
        Keyring::from_public_key_pem(key_text)
    }
    .map_err(|_| config("invalid trust input"))?;
    let timestamp = |text: &str| {
        DateTime::parse_from_rfc3339(text)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|_| config("invalid RFC 3339 timestamp"))
    };
    let since = timestamp(&profile.window.since)?;
    let until = timestamp(&profile.window.until)?;
    for (supplied, expected) in [(&args.since, since), (&args.until, until)] {
        if let Some(supplied) = supplied
            && timestamp(supplied)? != expected
        {
            return Err(config("CLI window must equal the profile window"));
        }
    }
    let clock = VerifyOptions {
        now: args
            .now
            .as_deref()
            .map(timestamp)
            .transpose()?
            .unwrap_or_else(Utc::now),
        max_clock_skew_seconds: args.max_skew,
        last_seen_version: None,
    };
    let inputs = snapshot_profile_inputs(&profile_input.path, &profile, &limits, &mut budget)?;
    let input_paths: Vec<_> = inputs
        .artifacts
        .values()
        .map(|input| input.path.as_path())
        .chain([profile_input.path.as_path(), key_input.path.as_path()])
        .collect();
    reject_input_paths(
        &[report_path.as_path(), sidecar_path.as_path()],
        &input_paths,
    )?;
    let files: Vec<_> = profile
        .streams
        .iter()
        .flat_map(|stream| &stream.files)
        .collect();
    if files.len() != args.files.len() {
        return Err(config("positional files must match profile order"));
    }
    for (supplied, declared) in args.files.iter().zip(&files) {
        if supplied
            .canonicalize()
            .map_err(|_| config("cannot resolve positional source"))?
            != inputs.artifacts[&declared.path].path
        {
            return Err(config("positional files must match profile order"));
        }
    }
    if let Some(selected) = &args.policy {
        let selected = selected
            .canonicalize()
            .map_err(|_| config("cannot resolve selected policy"))?;
        if !profile
            .policies
            .iter()
            .filter_map(|policy| policy.artifact.as_ref())
            .any(|artifact| inputs.artifacts[&artifact.path].path == selected)
        {
            return Err(config("--policy must name a declared policy artifact"));
        }
    }
    let verified = report_evidence::verify_evidence(&profile, &inputs, &keys, &clock, &limits)?;
    let receipts: Vec<_> = verified
        .streams
        .iter()
        .flat_map(|stream| stream.receipts.iter().cloned())
        .collect();
    let events: Vec<_> = verified
        .streams
        .iter()
        .flat_map(|stream| {
            stream
                .entries
                .iter()
                .filter_map(|entry| entry.policy_event.clone())
        })
        .collect();
    let mut chain = ChainSummary {
        verified: true,
        ..Default::default()
    };
    let mut sources = Vec::new();
    for stream in &verified.streams {
        for file in &stream.spec.files {
            let snapshot = &inputs.artifacts[&file.path];
            let mut signers = std::collections::BTreeSet::new();
            let mut records = 0;
            // Parse only authenticated snapshots; never reopen a source path.
            for line in snapshot
                .bytes
                .split(|b| *b == b'\n')
                .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
            {
                let value = report_evidence::json::parse_json(line, MAX_DEPTH)?;
                signers.insert(
                    value["signature"]["key_id"]
                        .as_str()
                        .expect("verified signature key")
                        .to_owned(),
                );
                records += 1;
                if stream.spec.kind == StreamKind::SignedLog {
                    chain.entries += 1;
                    chain.signed_entries += 1;
                    chain.receipts += u64::from(value.get("receipt").is_some());
                    chain.policy_events += u64::from(value.get("policy_event").is_some());
                    chain.last_seq = value["seq"].as_u64().expect("verified sequence");
                    chain.last_entry_hash = value["entry_hash"].as_str().map(str::to_owned);
                }
            }
            if stream.spec.kind == StreamKind::SignedLog {
                chain.files += 1;
            }
            sources.push(SourceResult {
                stream_id: stream.spec.id.clone(),
                path: snapshot.label.clone(),
                sha256: snapshot.sha256.clone(),
                records,
                signer_key_ids: signers.into_iter().collect(),
            });
        }
    }
    let options = ReportOptions {
        sources: files.iter().map(|file| file.path.clone()).collect(),
        since: Some(since),
        until: Some(until),
        generated_at: Some(clock.now),
        chain: (chain.files > 0).then_some(chain),
        top_rule_paths: args.top_paths,
        ..Default::default()
    };
    let mut report = build_report(&receipts, &events, &options);
    if profile.policies.len() == 1 {
        let policies = policy::load_policies(&profile, &inputs, &keys, &clock)?;
        let (hash, policy) = policies.first_key_value().expect("declared policy");
        if let (Some(spec), Some(source)) = (&policy.spec, &policy.source) {
            let window: Vec<_> = receipts
                .iter()
                .filter(|receipt| in_window(&receipt.timestamp, Some(since), Some(until)))
                .collect();
            report.controls = Some(crate::report_controls::build_control_evidence(
                source, spec, hash, &window, &report,
            ));
        }
    }
    let native_value =
        serde_json::to_value(&report).map_err(|_| config("cannot serialize report"))?;
    validate_schema(&native_value, "report")?;
    let native = OutputArtifact {
        path: report_path.clone(),
        bytes: serde_json::to_vec_pretty(&native_value)
            .map_err(|_| config("cannot serialize report"))?,
    };
    let result = VerificationResult { verification_version: "0.1.0".into(), run_id: profile.run_id.clone(), window: profile.window.clone(),
        verified_at: hushspec::receipt::format_timestamp(clock.now), verifier: Verifier { name: "h2h".into(), version: env!("CARGO_PKG_VERSION").into() },
        profile_sha256: profile_input.sha256, keyring_sha256: key_input.sha256, report_sha256: sha256_bytes(&native.bytes), sources, streams: verified.results,
        inventory_sha256: profile.inventory.as_ref().map(|artifact| artifact.sha256.clone()),
        limitations: vec!["Authentication covers supplied records, including outside the selected window; it does not establish action-attempt completeness.".into(),
            "Inventory acquisition and the trusted profile/key inputs are operator assumptions.".into(),
            "Counts describe recorded decisions and enforcement outcomes, not control satisfaction or certification.".into(),
            "This unsigned sidecar requires source reverification or an authenticated packet producer. Presence alone is not assurance.".into(),
            "Native chain fields summarize checked log files; per-stream continuity and policy intervals are in this sidecar.".into()] };
    let sidecar_value =
        serde_json::to_value(&result).map_err(|_| config("cannot serialize verification"))?;
    validate_schema(&sidecar_value, "evidence-verification-experimental")?;
    let sidecar = OutputArtifact {
        path: sidecar_path.clone(),
        bytes: serde_json::to_vec_pretty(&sidecar_value)
            .map_err(|_| config("cannot serialize verification"))?,
    };
    publish_outputs(&[native], &sidecar)
}

fn parse_bound(text: Option<&str>, flag: &str) -> Result<Option<DateTime<Utc>>, i32> {
    let Some(text) = text else {
        return Ok(None);
    };
    match DateTime::parse_from_rfc3339(text) {
        Ok(parsed) => Ok(Some(parsed.with_timezone(&Utc))),
        Err(error) => {
            eprintln!(
                "{} {flag} is not an RFC 3339 timestamp: {error}",
                "error:".red()
            );
            Err(2)
        }
    }
}

/// One classified line.
enum Line {
    Entry(Box<LogEntry>),
    Receipt(Box<DecisionReceipt>),
}

/// Classify a line as a log entry or a receipt. A log entry is tried first:
/// both types reject unknown fields and require a version field of their own,
/// so no line can be read as both.
fn classify(line: &str) -> Result<Line, String> {
    if let Ok(entry) = serde_json::from_str::<LogEntry>(line) {
        return Ok(Line::Entry(Box::new(entry)));
    }
    if let Ok(signed) = serde_json::from_str::<SignedReceipt>(line) {
        return Ok(Line::Receipt(Box::new(signed.receipt)));
    }
    match DecisionReceipt::parse(line) {
        Ok(receipt) => Ok(Line::Receipt(Box::new(receipt))),
        Err(error) => Err(format!("neither a log entry nor a receipt: {error}")),
    }
}

/// A record whose timestamp is not RFC 3339 cannot be placed in a window, so
/// it is malformed rather than silently counted or silently dropped.
fn check_timestamp(timestamp: &str) -> Result<(), String> {
    DateTime::parse_from_rfc3339(timestamp)
        .map(|_| ())
        .map_err(|error| format!("timestamp {timestamp:?} is not RFC 3339: {error}"))
}

/// Line numbers for a diagnostic, listing the first few and counting the rest.
fn line_list(lines: &[usize]) -> String {
    const SHOWN: usize = 5;
    let mut text = lines
        .iter()
        .take(SHOWN)
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    if lines.len() > SHOWN {
        let _ = write!(text, " (and {} more)", lines.len() - SHOWN);
    }
    text
}

/// Validate every receipt entry of `text` against the published receipt schema.
///
/// The chain verifier checks each receipt through the typed model, whose
/// structural checks do not replicate every constraint the JSON Schema states:
/// a line whose receipt is hash-consistent can still carry a document no
/// auditor would accept as evidence.
fn receipts_match_schema(name: &str, text: &str, schema: &JSONSchema) -> Result<(), LogError> {
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<LogEntry>(line) else {
            continue; // already reported by the chain verifier
        };
        let Some(receipt) = &entry.receipt else {
            continue;
        };
        let value = match serde_json::to_value(receipt) {
            Ok(value) => value,
            Err(error) => {
                return Err(LogError {
                    file: name.to_string(),
                    line: index + 1,
                    message: format!("cannot serialize receipt: {error}"),
                });
            }
        };
        if let Err(errors) = schema.validate(&value) {
            let messages: Vec<String> = errors.map(|error| error.to_string()).collect();
            return Err(LogError {
                file: name.to_string(),
                line: index + 1,
                message: format!(
                    "receipt does not validate against the receipt schema: {}",
                    messages.join("; ")
                ),
            });
        }
    }
    Ok(())
}

fn read_file(
    path: &Path,
    options: &LogVerifyOptions,
    receipt_schema: &JSONSchema,
    loaded: &mut Loaded,
) -> Result<(), i32> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("{} cannot read {}: {error}", "error:".red(), path.display());
            return Err(2);
        }
    };
    let name = path.display().to_string();

    let mut classified: Vec<(usize, Line)> = Vec::new();
    let mut entry_lines = 0usize;
    let mut receipt_lines: Vec<usize> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let line_no = index + 1;
        match classify(line) {
            Ok(parsed) => {
                match &parsed {
                    Line::Entry(_) => entry_lines += 1,
                    Line::Receipt(_) => receipt_lines.push(line_no),
                }
                classified.push((line_no, parsed));
            }
            Err(message) => loaded
                .malformed
                .push(format!("{name}:{line_no}: {message}")),
        }
    }

    // Any log entry makes the whole file a log. Verifying only the files that
    // *open* with one would let a plain receipt prepended to a hash-linked log
    // carry the rest of that log past chain verification entirely.
    let is_log = entry_lines > 0;
    if is_log && !receipt_lines.is_empty() {
        eprintln!(
            "{} {name} mixes record types: {entry_lines} log entry line(s) and {} plain \
             receipt line(s) at {}; the file is verified as a log, so its plain receipt \
             lines break the chain",
            "warning:".yellow(),
            receipt_lines.len(),
            line_list(&receipt_lines),
        );
    }

    // A log's chain is verified before its receipts are counted (log spec 8).
    // Each file is verified on its own, which is exactly right for a
    // standalone log and for a rotated continuation (whose `log_started`
    // carries the previous file's hash); checking the link *between* two
    // rotated files is `h2h log verify`'s job, and it takes them in order.
    if is_log {
        let verified = verify_log(&name, &text, options)
            // The chain verifier checks `receipt_version`; the schema pass
            // covers every other member of every receipt entry (log spec 8,
            // step 8), exactly as `h2h log verify` runs it.
            .and_then(|report| {
                receipts_match_schema(&name, &text, receipt_schema).map(|()| report)
            });
        let summary = match verified {
            Ok(report) => ChainSummary {
                verified: true,
                files: 1,
                entries: report.entries as u64,
                receipts: report.receipts as u64,
                policy_events: report.policy_events as u64,
                signed_entries: report.signed as u64,
                last_seq: report.last_seq,
                last_entry_hash: Some(report.last_entry_hash),
                reason: None,
            },
            // A break is not reported from here: a line that does not parse
            // at all is the more specific diagnosis, and `run` reports that
            // first. The refusal to report on a broken chain follows.
            Err(error) => ChainSummary {
                verified: false,
                files: 1,
                reason: Some(error.to_string()),
                ..ChainSummary::default()
            },
        };
        loaded.chain = Some(match loaded.chain.take() {
            None => summary,
            Some(previous) => merge_chain(previous, summary),
        });
    }

    for (line_no, parsed) in classified {
        match parsed {
            Line::Entry(entry) => {
                if let Some(receipt) = entry.receipt {
                    if let Err(message) = check_timestamp(&receipt.timestamp) {
                        loaded
                            .malformed
                            .push(format!("{name}:{line_no}: {message}"));
                    } else {
                        loaded.receipts.push(receipt);
                    }
                }
                if let Some(event) = entry.policy_event {
                    if let Err(message) = check_timestamp(&event.timestamp) {
                        loaded
                            .malformed
                            .push(format!("{name}:{line_no}: {message}"));
                    } else {
                        loaded.events.push(event);
                    }
                }
            }
            Line::Receipt(receipt) => {
                if let Err(message) = check_timestamp(&receipt.timestamp) {
                    loaded
                        .malformed
                        .push(format!("{name}:{line_no}: {message}"));
                } else {
                    loaded.receipts.push(*receipt);
                }
            }
        }
    }
    Ok(())
}

/// Sum two files' chain summaries; a single broken file makes the whole
/// report's chain unverified, and its reason is the one reported.
fn merge_chain(previous: ChainSummary, next: ChainSummary) -> ChainSummary {
    ChainSummary {
        verified: previous.verified && next.verified,
        files: previous.files + next.files,
        entries: previous.entries + next.entries,
        receipts: previous.receipts + next.receipts,
        policy_events: previous.policy_events + next.policy_events,
        signed_entries: previous.signed_entries + next.signed_entries,
        last_seq: next.last_seq,
        last_entry_hash: next.last_entry_hash.or(previous.last_entry_hash),
        reason: previous.reason.or(next.reason),
    }
}

// ------------------------------------------------------------------- controls

/// Resolve the policy the control mappings come from: `--policy` when given,
/// otherwise a source named by a `policy_loaded` / `policy_swapped` event that
/// still resolves from here (a builtin, or a path that exists).
fn control_policy(
    explicit: Option<&Path>,
    loaded: &Loaded,
) -> Result<Option<(String, HushSpec, String)>, i32> {
    if let Some(path) = explicit {
        return match hushspec::resolve_path_with_options(path, &ResolveOptions::default()) {
            Ok(resolution) => Ok(Some((
                path.display().to_string(),
                resolution.spec,
                resolution.content_hash,
            ))),
            Err(error) => {
                eprintln!(
                    "{} failed to resolve {}: {error}",
                    "error:".red(),
                    path.display()
                );
                Err(2)
            }
        };
    }

    // Best effort: the leaf of an `extends_chain` is the document the writer
    // loaded. A source that no longer resolves here is not an error -- the
    // report simply carries no control evidence.
    for event in &loaded.events {
        let Some(chain) = &event.policy.extends_chain else {
            continue;
        };
        let Some(link) = chain.last() else {
            continue;
        };
        let resolved = if link.source.starts_with("builtin:") {
            hushspec::load_builtin(link.source.trim_start_matches("builtin:"))
                .and_then(|text| HushSpec::parse(text).ok())
                .and_then(|spec| {
                    hushspec::Resolution::from_resolved(&spec, Some(&link.source)).ok()
                })
        } else if Path::new(&link.source).exists() {
            hushspec::resolve_path_with_options(&link.source, &ResolveOptions::default()).ok()
        } else {
            None
        };
        if let Some(resolution) = resolved
            && resolution.content_hash == event.policy.content_hash
        {
            return Ok(Some((
                link.source.clone(),
                resolution.spec,
                resolution.content_hash,
            )));
        }
    }
    Ok(None)
}

fn control_evidence(
    explicit: Option<&Path>,
    loaded: &Loaded,
    receipts: &[&DecisionReceipt],
    report: &Report,
) -> Result<Option<ControlsEvidence>, i32> {
    let Some((source, spec, content_hash)) = control_policy(explicit, loaded)? else {
        return Ok(None);
    };
    let evidence = crate::report_controls::build_control_evidence(
        &source,
        &spec,
        &content_hash,
        receipts,
        report,
    );
    let matching = evidence.receipts_matching_policy as usize;
    if matching < receipts.len() && explicit.is_some() {
        eprintln!(
            "{} {} of {} receipt(s) in the window name another policy; control \
             evidence counts only the {} that name {source}",
            "warning:".yellow(),
            receipts.len() - matching,
            receipts.len(),
            matching
        );
    }
    Ok(Some(evidence))
}

// -------------------------------------------------------------------- output

fn emit(report: &Report, args: &ReportArgs) -> i32 {
    match args.format {
        OutputFormat::Text => write_out(args.out.as_deref(), &render_text(report, args.by)),
        OutputFormat::Json => match serde_json::to_string_pretty(report) {
            Ok(mut json) => {
                json.push('\n');
                write_out(args.out.as_deref(), &json)
            }
            Err(error) => {
                eprintln!("{} cannot serialize the report: {error}", "error:".red());
                2
            }
        },
        OutputFormat::Oscal => match serde_json::to_string_pretty(&oscal(report)) {
            Ok(mut json) => {
                json.push('\n');
                write_out(args.out.as_deref(), &json)
            }
            Err(error) => {
                eprintln!("{} cannot serialize the report: {error}", "error:".red());
                2
            }
        },
        OutputFormat::Csv => write_csv(report, args),
    }
}

fn write_out(out: Option<&Path>, text: &str) -> i32 {
    match out {
        None => {
            print!("{text}");
            0
        }
        Some(path) => match std::fs::write(path, text) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!(
                    "{} cannot write {}: {error}",
                    "error:".red(),
                    path.display()
                );
                2
            }
        },
    }
}

// ---------------------------------------------------------------------- text

fn render_text(report: &Report, by: Option<By>) -> String {
    let mut out = String::new();
    let window = format!(
        "{} .. {}",
        report
            .window
            .first_receipt
            .as_deref()
            .or(report.window.since.as_deref())
            .unwrap_or("-"),
        report
            .window
            .last_receipt
            .as_deref()
            .or(report.window.until.as_deref())
            .unwrap_or("-")
    );
    let _ = writeln!(out, "{}  {}", "Window:".bold(), window);
    let _ = writeln!(out, "{}  {}", "Sources:".bold(), report.sources.join(", "));
    match report.chain_verified {
        Some(true) => {
            let _ = writeln!(out, "{}  {}", "Chain:".bold(), "verified".green());
        }
        Some(false) => {
            let _ = writeln!(
                out,
                "{}  {} ({})",
                "Chain:".bold(),
                "NOT VERIFIED".red().bold(),
                report
                    .chain
                    .as_ref()
                    .and_then(|chain| chain.reason.as_deref())
                    .unwrap_or("reported under --unverified")
            );
        }
        None => {}
    }
    if report.totals.skipped_lines > 0 {
        let _ = writeln!(
            out,
            "{}  {} line(s) skipped under --lenient",
            "Skipped:".bold(),
            report.totals.skipped_lines
        );
    }

    if by.is_none() || by == Some(By::Decision) {
        let totals = &report.totals;
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", "Decisions:".bold());
        let _ = writeln!(
            out,
            "  {} receipts: {} allow, {} warn, {} deny",
            totals.receipts,
            totals.by_decision.allow,
            totals.by_decision.warn,
            totals.by_decision.deny
        );
        let _ = writeln!(
            out,
            "  enforcement: {} allowed, {} confirmed, {} blocked, {} would_block \
             ({} enforce, {} monitor)",
            totals.by_outcome.allowed,
            totals.by_outcome.confirmed,
            totals.by_outcome.blocked,
            totals.by_outcome.would_block,
            totals.by_mode.enforce,
            totals.by_mode.monitor
        );
        let _ = writeln!(
            out,
            "  signatures: {} verified, {} unverified, {} not checked",
            report.signatures.verified, report.signatures.unverified, report.signatures.absent
        );
        for reason in &report.signatures.reasons {
            let _ = writeln!(out, "    {} x{}", reason.reason, reason.count);
        }
    }

    if by.is_none() || by == Some(By::Rule) {
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", "Rule blocks:".bold());
        let width = column_width(
            report.rule_blocks.iter().map(|row| row.rule_block.as_str()),
            "RULE BLOCK",
        );
        let _ = writeln!(
            out,
            "  {:<width$}  {:>9}  {:>5}  {:>4}  {:>4}  TOP RULE PATH",
            "RULE BLOCK", "EVALUATED", "FIRED", "DENY", "WARN"
        );
        for row in &report.rule_blocks {
            let top = row
                .top_rule_paths
                .first()
                .map(|path| format!("{} (x{})", path.rule_path, path.count))
                .unwrap_or_default();
            let line = format!(
                "  {:<width$}  {:>9}  {:>5}  {:>4}  {:>4}  {top}",
                row.rule_block, row.evaluated, row.fired, row.deny, row.warn
            );
            let _ = writeln!(out, "{}", line.trim_end());
        }
        if report.rule_blocks.is_empty() {
            let _ = writeln!(out, "  (none)");
        }

        let _ = writeln!(out);
        let _ = writeln!(out, "{}", "Action types:".bold());
        let width = column_width(
            report
                .action_types
                .iter()
                .map(|row| row.action_type.as_str()),
            "ACTION TYPE",
        );
        let _ = writeln!(
            out,
            "  {:<width$}  {:>8}  {:>5}  {:>4}  {:>4}",
            "ACTION TYPE", "RECEIPTS", "ALLOW", "WARN", "DENY"
        );
        for row in &report.action_types {
            let _ = writeln!(
                out,
                "  {:<width$}  {:>8}  {:>5}  {:>4}  {:>4}",
                row.action_type,
                row.receipts,
                row.by_decision.allow,
                row.by_decision.warn,
                row.by_decision.deny
            );
        }
        if report.action_types.is_empty() {
            let _ = writeln!(out, "  (none)");
        }
    }

    if by.is_none() || by == Some(By::Policy) {
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", "Policies in force:".bold());
        for row in &report.policies {
            let _ = writeln!(
                out,
                "  {}  {}  {} receipts  {} .. {}",
                short_hash(&row.content_hash),
                row.name.as_deref().unwrap_or("(unnamed)"),
                row.receipts,
                row.first_seen,
                row.last_seen
            );
        }
        if report.policies.is_empty() {
            let _ = writeln!(out, "  (none)");
        }
        if !report.policy_timeline.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "{}", "Policy timeline:".bold());
            for row in &report.policy_timeline {
                let event = match row.event {
                    hushspec::log::PolicyEventKind::Loaded => "loaded ",
                    hushspec::log::PolicyEventKind::Swapped => "swapped",
                };
                let previous = row
                    .previous_content_hash
                    .as_deref()
                    .map(|hash| format!(" (was {})", short_hash(hash)))
                    .unwrap_or_default();
                let _ = writeln!(
                    out,
                    "  {}  {event}  {}  {}{previous}",
                    row.timestamp,
                    short_hash(&row.content_hash),
                    row.name.as_deref().unwrap_or("(unnamed)")
                );
            }
        }

        let _ = writeln!(out);
        let _ = writeln!(out, "{}", "Actors:".bold());
        for row in &report.actors {
            let _ = writeln!(
                out,
                "  {} / {} / {}  {} receipts, {} denied",
                row.agent_id.as_deref().unwrap_or("-"),
                row.session_id.as_deref().unwrap_or("-"),
                row.principal.as_deref().unwrap_or("-"),
                row.receipts,
                row.by_decision.deny
            );
        }
        if report.actors.is_empty() {
            let _ = writeln!(out, "  (none)");
        }
    }

    if (by.is_none() || by == Some(By::Rule)) && !report.detections.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", "Detections:".bold());
        for row in &report.detections {
            let _ = writeln!(
                out,
                "  {}  {} evaluated, {} matched (critical {}, high {}, suspicious {})",
                row.detector_id,
                row.evaluated,
                row.matched,
                row.by_level.critical,
                row.by_level.high,
                row.by_level.suspicious
            );
        }
    }

    if let Some(controls) = &report.controls
        && (by.is_none() || by == Some(By::Control))
    {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "{}  {} ({} receipt(s) evaluated under it)",
            "Control evidence:".bold(),
            controls.policy_source,
            controls.receipts_matching_policy
        );
        for framework in &controls.frameworks {
            let _ = writeln!(out);
            let mark = if framework.registered {
                ""
            } else {
                " \u{26a0}"
            };
            let _ = writeln!(out, "  {}{mark}", framework.framework.bold());
            let width = column_width(
                framework.controls.iter().map(|row| row.control_id.as_str()),
                "CONTROL",
            );
            let _ = writeln!(
                out,
                "    {:<width$}  {:>9}  {:>5}  {:>6}  LAST SEEN",
                "CONTROL", "EVALUATED", "FIRED", "DENIED"
            );
            for row in &framework.controls {
                let _ = writeln!(
                    out,
                    "    {:<width$}  {:>9}  {:>5}  {:>6}  {}",
                    row.control_id,
                    row.evaluated,
                    row.fired,
                    row.denied,
                    row.last_seen.as_deref().unwrap_or("-")
                );
            }
        }
        if !controls.unmapped_fired_rule_blocks.is_empty() {
            let _ = writeln!(out);
            for block in &controls.unmapped_fired_rule_blocks {
                let _ = writeln!(
                    out,
                    "  {} {block} fired with no control mapping",
                    "\u{2717}".red()
                );
            }
        }
    }
    out
}

/// Padded columns are written without color: a `ColoredString` pads to the
/// width of its escape sequences, not of its visible text.
fn column_width<'a>(values: impl Iterator<Item = &'a str>, heading: &str) -> usize {
    values
        .map(|value| value.chars().count())
        .max()
        .unwrap_or(0)
        .max(heading.len())
}

/// The first 12 characters of a digest, for the text report's fixed columns.
///
/// Receipts are parsed before their `content_hash` is format-checked, so the
/// digest may be any string: truncate by character, never by byte.
fn short_hash(hash: &str) -> String {
    let hex = hash.strip_prefix("sha256:").unwrap_or(hash);
    let head: String = hex.chars().take(12).collect();
    format!("sha256:{head}")
}

// ----------------------------------------------------------------------- csv

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn csv_row(fields: &[String]) -> String {
    let cells: Vec<String> = fields.iter().map(|field| csv_field(field)).collect();
    format!("{}\n", cells.join(","))
}

fn table(report: &Report, name: &str) -> String {
    let mut out = String::new();
    match name {
        "totals" => {
            out.push_str(&csv_row(&s(&["category", "key", "count"])));
            let t = &report.totals;
            for (key, count) in [
                ("allow", t.by_decision.allow),
                ("warn", t.by_decision.warn),
                ("deny", t.by_decision.deny),
            ] {
                out.push_str(&csv_row(&s(&["decision", key, &count.to_string()])));
            }
            for (key, count) in [
                ("enforce", t.by_mode.enforce),
                ("monitor", t.by_mode.monitor),
            ] {
                out.push_str(&csv_row(&s(&["mode", key, &count.to_string()])));
            }
            for (key, count) in [
                ("allowed", t.by_outcome.allowed),
                ("confirmed", t.by_outcome.confirmed),
                ("blocked", t.by_outcome.blocked),
                ("would_block", t.by_outcome.would_block),
            ] {
                out.push_str(&csv_row(&s(&["outcome", key, &count.to_string()])));
            }
            for (key, count) in [
                ("receipts", t.receipts),
                ("policy_events", t.policy_events),
                ("skipped_lines", t.skipped_lines),
            ] {
                out.push_str(&csv_row(&s(&["total", key, &count.to_string()])));
            }
        }
        "rule_blocks" => {
            out.push_str(&csv_row(&s(&[
                "rule_block",
                "receipts",
                "evaluated",
                "skipped",
                "fired",
                "warn",
                "deny",
                "top_rule_paths",
            ])));
            for row in &report.rule_blocks {
                let paths: Vec<String> = row
                    .top_rule_paths
                    .iter()
                    .map(|path| format!("{}={}", path.rule_path, path.count))
                    .collect();
                out.push_str(&csv_row(&s(&[
                    &row.rule_block,
                    &row.receipts.to_string(),
                    &row.evaluated.to_string(),
                    &row.skipped.to_string(),
                    &row.fired.to_string(),
                    &row.warn.to_string(),
                    &row.deny.to_string(),
                    &paths.join(" "),
                ])));
            }
        }
        "action_types" => {
            out.push_str(&csv_row(&s(&[
                "action_type",
                "receipts",
                "allow",
                "warn",
                "deny",
                "allowed",
                "confirmed",
                "blocked",
                "would_block",
            ])));
            for row in &report.action_types {
                out.push_str(&csv_row(&s(&[
                    &row.action_type,
                    &row.receipts.to_string(),
                    &row.by_decision.allow.to_string(),
                    &row.by_decision.warn.to_string(),
                    &row.by_decision.deny.to_string(),
                    &row.by_outcome.allowed.to_string(),
                    &row.by_outcome.confirmed.to_string(),
                    &row.by_outcome.blocked.to_string(),
                    &row.by_outcome.would_block.to_string(),
                ])));
            }
        }
        "policies" => {
            out.push_str(&csv_row(&s(&[
                "content_hash",
                "name",
                "version",
                "spec_version",
                "receipts",
                "first_seen",
                "last_seen",
                "allow",
                "warn",
                "deny",
            ])));
            for row in &report.policies {
                out.push_str(&csv_row(&s(&[
                    &row.content_hash,
                    row.name.as_deref().unwrap_or(""),
                    &row.version.map(|v| v.to_string()).unwrap_or_default(),
                    &row.spec_version,
                    &row.receipts.to_string(),
                    &row.first_seen,
                    &row.last_seen,
                    &row.by_decision.allow.to_string(),
                    &row.by_decision.warn.to_string(),
                    &row.by_decision.deny.to_string(),
                ])));
            }
        }
        "policy_timeline" => {
            out.push_str(&csv_row(&s(&[
                "timestamp",
                "event",
                "content_hash",
                "name",
                "previous_content_hash",
                "enforcement_mode",
                "sdk",
            ])));
            for row in &report.policy_timeline {
                let event = match row.event {
                    hushspec::log::PolicyEventKind::Loaded => "loaded",
                    hushspec::log::PolicyEventKind::Swapped => "swapped",
                };
                let mode = match row.enforcement_mode {
                    hushspec::EnforcementMode::Enforce => "enforce",
                    hushspec::EnforcementMode::Monitor => "monitor",
                };
                out.push_str(&csv_row(&s(&[
                    &row.timestamp,
                    event,
                    &row.content_hash,
                    row.name.as_deref().unwrap_or(""),
                    row.previous_content_hash.as_deref().unwrap_or(""),
                    mode,
                    &row.sdk,
                ])));
            }
        }
        "actors" => {
            out.push_str(&csv_row(&s(&[
                "agent_id",
                "session_id",
                "principal",
                "receipts",
                "allow",
                "warn",
                "deny",
                "blocked",
                "would_block",
            ])));
            for row in &report.actors {
                out.push_str(&csv_row(&s(&[
                    row.agent_id.as_deref().unwrap_or(""),
                    row.session_id.as_deref().unwrap_or(""),
                    row.principal.as_deref().unwrap_or(""),
                    &row.receipts.to_string(),
                    &row.by_decision.allow.to_string(),
                    &row.by_decision.warn.to_string(),
                    &row.by_decision.deny.to_string(),
                    &row.by_outcome.blocked.to_string(),
                    &row.by_outcome.would_block.to_string(),
                ])));
            }
        }
        "signatures" => {
            out.push_str(&csv_row(&s(&["status", "reason", "count"])));
            out.push_str(&csv_row(&s(&[
                "verified",
                "",
                &report.signatures.verified.to_string(),
            ])));
            out.push_str(&csv_row(&s(&[
                "absent",
                "",
                &report.signatures.absent.to_string(),
            ])));
            for reason in &report.signatures.reasons {
                out.push_str(&csv_row(&s(&[
                    "unverified",
                    &reason.reason,
                    &reason.count.to_string(),
                ])));
            }
        }
        "detections" => {
            out.push_str(&csv_row(&s(&[
                "detector_id",
                "category",
                "evaluated",
                "matched",
                "none",
                "low",
                "suspicious",
                "high",
                "critical",
            ])));
            for row in &report.detections {
                let category = serde_json::to_value(&row.category)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_string))
                    .unwrap_or_default();
                out.push_str(&csv_row(&s(&[
                    &row.detector_id,
                    &category,
                    &row.evaluated.to_string(),
                    &row.matched.to_string(),
                    &row.by_level.none.to_string(),
                    &row.by_level.low.to_string(),
                    &row.by_level.suspicious.to_string(),
                    &row.by_level.high.to_string(),
                    &row.by_level.critical.to_string(),
                ])));
            }
        }
        "controls" => {
            out.push_str(&csv_row(&s(&[
                "framework",
                "control_id",
                "rule_paths",
                "rule_blocks",
                "receipts",
                "evaluated",
                "fired",
                "denied",
                "last_seen",
            ])));
            for framework in report
                .controls
                .iter()
                .flat_map(|controls| &controls.frameworks)
            {
                for row in &framework.controls {
                    out.push_str(&csv_row(&s(&[
                        &framework.framework,
                        &row.control_id,
                        &row.rule_paths.join(" "),
                        &row.rule_blocks.join(" "),
                        &row.receipts.to_string(),
                        &row.evaluated.to_string(),
                        &row.fired.to_string(),
                        &row.denied.to_string(),
                        row.last_seen.as_deref().unwrap_or(""),
                    ])));
                }
            }
        }
        "unmapped_rule_blocks" => {
            out.push_str(&csv_row(&s(&["rule_block", "fired"])));
            for block in report
                .controls
                .iter()
                .flat_map(|controls| &controls.unmapped_fired_rule_blocks)
            {
                let fired = report
                    .rule_blocks
                    .iter()
                    .find(|row| row.rule_block == *block)
                    .map(|row| row.fired)
                    .unwrap_or(0);
                out.push_str(&csv_row(&s(&[block, &fired.to_string()])));
            }
        }
        _ => {}
    }
    out
}

/// `["a", "b"]` as owned fields; keeps the table writers readable.
fn s(fields: &[&str]) -> Vec<String> {
    fields.iter().map(|field| (*field).to_string()).collect()
}

const CSV_TABLES: &[&str] = &[
    "totals",
    "rule_blocks",
    "action_types",
    "policies",
    "policy_timeline",
    "actors",
    "signatures",
    "detections",
];

fn write_csv(report: &Report, args: &ReportArgs) -> i32 {
    let Some(dir) = args.out.as_deref() else {
        // One flattened table on stdout: the one --by names (rule blocks by
        // default, the table an operator wants most often).
        let name = args.by.map_or("rule_blocks", By::table);
        print!("{}", table(report, name));
        return 0;
    };
    if let Err(error) = std::fs::create_dir_all(dir) {
        eprintln!(
            "{} cannot create {}: {error}",
            "error:".red(),
            dir.display()
        );
        return 2;
    }
    let mut names: Vec<&str> = CSV_TABLES.to_vec();
    if report.controls.is_some() {
        names.push("controls");
        names.push("unmapped_rule_blocks");
    }
    let written = names.len();
    for name in names {
        let path = dir.join(format!("{name}.csv"));
        if let Err(error) = std::fs::write(&path, table(report, name)) {
            eprintln!(
                "{} cannot write {}: {error}",
                "error:".red(),
                path.display()
            );
            return 2;
        }
    }
    println!("wrote {written} table(s) to {}", dir.display());
    0
}

// --------------------------------------------------------------------- oscal

/// A UUID derived from `key`, so an exported document is byte-stable for the
/// same report. OSCAL wants UUIDs; it does not want fresh ones on every run.
fn stable_uuid(key: &str) -> String {
    let digest = hushspec::canonical::digest(key);
    let hex: String = digest
        .trim_start_matches("sha256:")
        .chars()
        .take(32)
        .collect();
    let version = format!("4{}", &hex[13..16]);
    let variant = format!(
        "{:x}{}",
        (u8::from_str_radix(&hex[16..17], 16).unwrap_or(0) & 0x3) | 0x8,
        &hex[17..20]
    );
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        version,
        variant,
        &hex[20..32]
    )
}

/// A minimal OSCAL 1.1.2 assessment-results document: one result whose
/// findings are the per-control rows and whose observations hold the counts.
///
/// Experimental. It is deliberately the smallest document an OSCAL consumer
/// will accept: there is no assessment plan to import, no system security
/// plan, and no subject inventory, because HushSpec receipts describe a tool
/// boundary rather than an assessed system.
fn oscal(report: &Report) -> serde_json::Value {
    let controls = report.controls.as_ref();
    // A report over a log whose hash chain did not verify is not evidence that
    // anything happened, so no control is satisfied from it and the document
    // carries the chain's status where a consumer cannot miss it.
    let chain_verified = report.chain_verified;
    let chain_broken = chain_verified == Some(false);
    let chain_reason = report
        .chain
        .as_ref()
        .and_then(|chain| chain.reason.clone())
        .unwrap_or_else(|| "the log chain did not verify".to_string());
    let chain_props = serde_json::json!([{
        "name": "chain-verified",
        "ns": "https://hushspec.org/ns/oscal",
        "value": match chain_verified {
            Some(true) => "true",
            Some(false) => "false",
            None => "not-applicable",
        },
    }]);
    let chain_remarks = if chain_broken {
        Some(format!(
            "The hash-linked log chain did not verify ({chain_reason}); no control is reported \
             satisfied from this window."
        ))
    } else {
        None
    };
    let start = report
        .window
        .first_receipt
        .clone()
        .or_else(|| report.window.since.clone())
        .or_else(|| report.generated_at.clone())
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_string());
    let end = report
        .window
        .last_receipt
        .clone()
        .or_else(|| report.window.until.clone())
        .unwrap_or_else(|| start.clone());

    let mut observations = Vec::new();
    let mut findings = Vec::new();
    let mut selected = Vec::new();
    for framework in controls.iter().flat_map(|controls| &controls.frameworks) {
        for row in &framework.controls {
            let id = format!("{}/{}", framework.framework, row.control_id);
            selected.push(serde_json::json!({ "control-id": row.control_id }));
            observations.push(serde_json::json!({
                "uuid": stable_uuid(&format!("observation:{id}")),
                "title": format!("{id}: recorded evaluations"),
                "description": format!(
                    "{} receipt(s) consulted {}; {} evaluation(s), {} fired, {} denied.",
                    row.receipts,
                    row.rule_paths.join(", "),
                    row.evaluated,
                    row.fired,
                    row.denied
                ),
                "methods": ["TEST"],
                "collected": row.last_seen.clone().unwrap_or_else(|| end.clone()),
            }));
            let mut finding = serde_json::json!({
                "uuid": stable_uuid(&format!("finding:{id}")),
                "title": id.as_str(),
                "description": format!(
                    "HushSpec rule paths {} were exercised {} time(s) in this window.",
                    row.rule_paths.join(", "),
                    row.evaluated
                ),
                "props": chain_props.clone(),
                "target": {
                    "type": "objective-id",
                    "target-id": row.control_id,
                    "status": {
                        "state": if row.evaluated > 0 && !chain_broken {
                            "satisfied"
                        } else {
                            "not-satisfied"
                        },
                    },
                },
                "related-observations": [
                    { "observation-uuid": stable_uuid(&format!("observation:{id}")) },
                ],
            });
            if let (Some(remarks), Some(object)) = (&chain_remarks, finding.as_object_mut()) {
                object.insert(
                    "remarks".to_string(),
                    serde_json::Value::String(remarks.clone()),
                );
            }
            findings.push(finding);
        }
    }

    let mut metadata = serde_json::json!({
        "title": "HushSpec control evidence",
        "last-modified": report.generated_at.clone().unwrap_or_else(|| end.clone()),
        "version": report.report_version,
        "oscal-version": "1.1.2",
        "props": chain_props.clone(),
    });
    if let (Some(remarks), Some(object)) = (&chain_remarks, metadata.as_object_mut()) {
        object.insert(
            "remarks".to_string(),
            serde_json::Value::String(remarks.clone()),
        );
    }

    serde_json::json!({
        "assessment-results": {
            "uuid": stable_uuid(&format!("assessment:{}:{start}:{end}", report.sources.join(","))),
            "metadata": metadata,
            "import-ap": { "href": "#" },
            "results": [{
                "uuid": stable_uuid(&format!("result:{start}:{end}")),
                "title": "HushSpec receipt window",
                "description": format!(
                    "{} receipt(s) from {}; {} allow, {} warn, {} deny.",
                    report.totals.receipts,
                    report.sources.join(", "),
                    report.totals.by_decision.allow,
                    report.totals.by_decision.warn,
                    report.totals.by_decision.deny
                ),
                "props": chain_props,
                "start": start,
                "end": end,
                "reviewed-controls": {
                    "control-selections": [{ "include-controls": selected }],
                },
                "observations": observations,
                "findings": findings,
            }],
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report_controls::mapping_covers;
    use hushspec::RuleTraceEntry;
    use hushspec::receipt::RuleOutcome;

    fn entry(block: &str, rule_path: Option<&str>) -> RuleTraceEntry {
        RuleTraceEntry {
            rule_block: block.to_string(),
            rule_path: rule_path.map(str::to_string),
            outcome: RuleOutcome::Deny,
            evaluated: true,
            reason: None,
        }
    }

    fn policy() -> serde_json::Value {
        serde_json::json!({
            "rules": {
                "egress": { "allow": ["api.example.com"], "block": [], "default": "block" },
                "tool_access": { "allow": ["read_file"], "default": "block" },
                "forbidden_paths": { "patterns": ["/etc/**"] }
            }
        })
    }

    #[test]
    fn a_block_mapping_covers_every_entry_of_that_block() {
        let doc = policy();
        let egress = entry("egress", Some("rules.egress.allow"));
        assert!(mapping_covers(&doc, "rules", &egress));
        assert!(mapping_covers(&doc, "rules.egress", &egress));
        assert!(!mapping_covers(&doc, "rules.tool_access", &egress));
        // A block mapping that names no block of this policy evidences nothing.
        assert!(!mapping_covers(&doc, "rules.nope", &egress));
    }

    #[test]
    fn a_deep_mapping_needs_the_recorded_path_under_it() {
        let doc = policy();
        let blocked = entry("egress", Some("rules.egress.block"));
        let allowed = entry("egress", Some("rules.egress.allow"));
        assert!(mapping_covers(&doc, "rules.egress.block", &blocked));
        assert!(!mapping_covers(&doc, "rules.egress.block", &allowed));
        // A block that recorded no path evidences nothing deeper than itself.
        assert!(!mapping_covers(
            &doc,
            "rules.egress.block",
            &entry("egress", None)
        ));
        // Segment boundaries: `rules.egress.blocklist` is not under `.block`.
        assert!(!mapping_covers(
            &doc,
            "rules.egress.block",
            &entry("egress", Some("rules.egress.blocklist"))
        ));
        assert!(mapping_covers(
            &doc,
            "rules.forbidden_paths.patterns",
            &entry("forbidden_paths", Some("rules.forbidden_paths.patterns"))
        ));
    }

    #[test]
    fn stable_uuids_are_stable_and_well_formed() {
        let id = stable_uuid("finding:hipaa-2013/164.312(e)(1)");
        assert_eq!(id, stable_uuid("finding:hipaa-2013/164.312(e)(1)"));
        assert_ne!(id, stable_uuid("finding:other"));
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(
            parts.iter().map(|part| part.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(parts[2].starts_with('4'));
        assert!(["8", "9", "a", "b"].contains(&&parts[3][0..1]));
    }

    #[test]
    fn csv_fields_are_quoted_when_they_must_be() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }
}
