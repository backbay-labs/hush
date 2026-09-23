//! `h2h log verify`: check a hash-linked receipt log (spec/hushspec-log.md).

use clap::{Subcommand, ValueEnum};
use colored::Colorize;
use hushspec::log::{LogEntry, LogError, LogVerifyOptions, LogVerifyReport, verify_log_files};
use jsonschema::JSONSchema;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct LogArgs {
    #[command(subcommand)]
    command: LogCommand,
}

#[derive(Subcommand)]
enum LogCommand {
    /// Check sequence continuity, hash links, receipt validity, and entry
    /// signatures; report the first break by file and line
    Verify(LogVerifyArgs),
}

#[derive(clap::Args)]
pub struct LogVerifyArgs {
    /// Log files in rotation order, oldest first
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// Trusted keyring JSON for entry signatures
    #[arg(long, value_name = "PATH", conflicts_with = "key")]
    keyring: Option<PathBuf>,

    /// A single trusted public key (PEM) for entry signatures
    #[arg(long, value_name = "PATH")]
    key: Option<PathBuf>,

    /// Every entry must carry a signature that verifies
    #[arg(long)]
    require_signatures: bool,

    /// Verifier clock as an RFC 3339 timestamp (defaults to now)
    #[arg(long, value_name = "TIMESTAMP")]
    now: Option<String>,

    /// Allowed signer clock skew in seconds
    #[arg(long, default_value_t = 300, value_name = "SECONDS")]
    max_skew: i64,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(serde::Serialize)]
struct Failure<'a> {
    ok: bool,
    file: &'a str,
    line: usize,
    message: &'a str,
}

#[derive(serde::Serialize)]
struct Success<'a> {
    ok: bool,
    #[serde(flatten)]
    report: &'a LogVerifyReport,
}

pub fn run(args: LogArgs) -> i32 {
    match args.command {
        LogCommand::Verify(args) => verify(args),
    }
}

/// Compile the embedded receipt schema once.
pub(crate) fn receipt_schema() -> Result<JSONSchema, String> {
    let body = crate::generated_schemas::schema_body("receipt")
        .ok_or_else(|| "embedded receipt schema is missing".to_string())?;
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("embedded receipt schema: {e}"))?;
    JSONSchema::options()
        .should_validate_formats(true)
        .compile(&value)
        .map_err(|e| format!("embedded receipt schema does not compile: {e}"))
}

fn verify(args: LogVerifyArgs) -> i32 {
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
    let options = LogVerifyOptions {
        require_signatures: args.require_signatures,
        keyring: resolve_options.keyring,
        verify: resolve_options.verify,
    };

    let report = match verify_log_files(&args.files, &options) {
        Ok(report) => report,
        Err(error) => {
            report_failure(&error, args.format);
            return 1;
        }
    };

    // The chain verifier checks receipt_version; the schema check here
    // covers every other field of every receipt entry (log spec 8, step 8).
    let schema = match receipt_schema() {
        Ok(schema) => schema,
        Err(message) => {
            eprintln!("{} {message}", "error:".red());
            return 2;
        }
    };
    for path in &args.files {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) => {
                eprintln!("{} cannot read {}: {e}", "error:".red(), path.display());
                return 2;
            }
        };
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(entry) = serde_json::from_str::<LogEntry>(line) else {
                continue; // already reported by the chain verifier
            };
            if let Some(receipt) = &entry.receipt {
                let value = serde_json::to_value(receipt).unwrap_or_default();
                if let Err(errors) = schema.validate(&value) {
                    let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
                    let error = LogError {
                        file: path.display().to_string(),
                        line: index + 1,
                        message: format!(
                            "receipt does not validate against the receipt schema: {}",
                            messages.join("; ")
                        ),
                    };
                    report_failure(&error, args.format);
                    return 1;
                }
            }
        }
    }

    match args.format {
        OutputFormat::Text => {
            println!(
                "{} {} file(s), {} entries ({} receipts, {} policy events), {} signed, {} verified; head seq {} {}",
                "OK".green().bold(),
                report.files,
                report.entries,
                report.receipts,
                report.policy_events,
                report.signed,
                report.verified_signatures,
                report.last_seq,
                report.last_entry_hash
            );
        }
        OutputFormat::Json => {
            let success = Success {
                ok: true,
                report: &report,
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&success).unwrap_or_default()
            );
        }
    }
    0
}

fn report_failure(error: &LogError, format: OutputFormat) {
    match format {
        OutputFormat::Text => {
            eprintln!("{} {error}", "BROKEN".red().bold());
        }
        OutputFormat::Json => {
            let failure = Failure {
                ok: false,
                file: &error.file,
                line: error.line,
                message: &error.message,
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&failure).unwrap_or_default()
            );
        }
    }
}
