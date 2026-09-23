//! `h2h receipts verify`: check decision receipts against the receipt
//! schema, the policy they name, and their signatures (receipt spec 6).

use clap::{Subcommand, ValueEnum};
use colored::Colorize;
use hushspec::log::LogEntry;
use hushspec::signing::{Envelope, SignedReceipt, verify_receipt};
use hushspec::{
    AuditConfig, AuditContext, DecisionReceipt, EvaluationAction, PostureContext, Resolution,
    ResolveOptions, evaluate_audited,
};
use std::path::{Path, PathBuf};

#[derive(clap::Args)]
pub struct ReceiptsArgs {
    #[command(subcommand)]
    command: ReceiptsCommand,
}

#[derive(Subcommand)]
enum ReceiptsCommand {
    /// Validate receipts, check they name the given policy, re-derive the
    /// decision where the action can be replayed, and verify signatures
    Verify(ReceiptsVerifyArgs),
}

#[derive(clap::Args)]
pub struct ReceiptsVerifyArgs {
    /// Receipt files: .jsonl logs (receipt entries), JSON receipts, or signed
    /// receipts ({receipt, signature})
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// The policy every receipt must name (by canonical content hash); when
    /// the receipt carries no content, the decision is re-derived against it
    #[arg(long, value_name = "PATH")]
    policy: Option<PathBuf>,

    /// Trusted keyring JSON for receipt signatures
    #[arg(long, value_name = "PATH", conflicts_with = "key")]
    keyring: Option<PathBuf>,

    /// A single trusted public key (PEM) for receipt signatures
    #[arg(long, value_name = "PATH")]
    key: Option<PathBuf>,

    /// Every receipt must carry a signature that verifies
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
struct Outcome {
    source: String,
    receipt_id: String,
    ok: bool,
    checks: Vec<Check>,
}

#[derive(serde::Serialize)]
struct Check {
    name: &'static str,
    ok: bool,
    detail: String,
}

pub fn run(args: ReceiptsArgs) -> i32 {
    match args.command {
        ReceiptsCommand::Verify(args) => verify(args),
    }
}

struct Item {
    source: String,
    receipt: DecisionReceipt,
    signature: Option<Envelope>,
}

/// Read receipts from a log, a receipt file, or a signed-receipt file.
fn load_items(path: &Path) -> Result<Vec<Item>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let name = path.display().to_string();
    if path.extension().is_some_and(|e| e == "jsonl") {
        let mut items = Vec::new();
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let label = format!("{name}:{}", index + 1);
            if let Ok(entry) = serde_json::from_str::<LogEntry>(line) {
                if let Some(receipt) = entry.receipt {
                    items.push(Item {
                        source: label,
                        receipt,
                        signature: None,
                    });
                }
                continue;
            }
            items.push(parse_item(line, label)?);
        }
        return Ok(items);
    }
    Ok(vec![parse_item(&text, name)?])
}

fn parse_item(text: &str, source: String) -> Result<Item, String> {
    if let Ok(signed) = serde_json::from_str::<SignedReceipt>(text) {
        return Ok(Item {
            source,
            receipt: signed.receipt,
            signature: Some(signed.signature),
        });
    }
    let receipt = DecisionReceipt::parse(text)
        .map_err(|e| format!("{source}: not a receipt or signed receipt: {e}"))?;
    Ok(Item {
        source,
        receipt,
        signature: None,
    })
}

fn verify(args: ReceiptsVerifyArgs) -> i32 {
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
    let keyring = resolve_options.keyring;
    let verify_options = resolve_options.verify.unwrap_or_default();

    let resolution: Option<Resolution> = match &args.policy {
        Some(path) => match hushspec::resolve_path_with_options(path, &ResolveOptions::default()) {
            Ok(resolution) => Some(resolution),
            Err(e) => {
                eprintln!(
                    "{} failed to resolve {}: {e}",
                    "error:".red(),
                    path.display()
                );
                return 2;
            }
        },
        None => None,
    };

    let schema = match crate::cmd_log::receipt_schema() {
        Ok(schema) => schema,
        Err(message) => {
            eprintln!("{} {message}", "error:".red());
            return 2;
        }
    };

    let mut items = Vec::new();
    for path in &args.files {
        match load_items(path) {
            Ok(loaded) => items.extend(loaded),
            Err(message) => {
                eprintln!("{} {message}", "error:".red());
                return 2;
            }
        }
    }

    let mut outcomes = Vec::new();
    let mut all_ok = true;
    for item in &items {
        let mut checks = Vec::new();

        let value = serde_json::to_value(&item.receipt).unwrap_or_default();
        match schema.validate(&value) {
            Ok(()) => checks.push(Check {
                name: "schema",
                ok: true,
                detail: "validates against the receipt schema".to_string(),
            }),
            Err(errors) => {
                let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
                checks.push(Check {
                    name: "schema",
                    ok: false,
                    detail: messages.join("; "),
                });
            }
        }

        if let Some(resolution) = &resolution {
            let matches = item.receipt.policy.content_hash == resolution.content_hash;
            checks.push(Check {
                name: "policy",
                ok: matches,
                detail: if matches {
                    "receipt names the given policy".to_string()
                } else {
                    format!(
                        "receipt names {} but the policy hashes to {}",
                        item.receipt.policy.content_hash, resolution.content_hash
                    )
                },
            });
            if matches {
                checks.push(rederive(resolution, &item.receipt));
            }
        }

        match (&item.signature, &keyring) {
            (Some(signature), Some(keyring)) => {
                let signed = SignedReceipt {
                    receipt: item.receipt.clone(),
                    signature: signature.clone(),
                };
                match verify_receipt(&signed, keyring, &verify_options) {
                    Ok(verified) => checks.push(Check {
                        name: "signature",
                        ok: true,
                        detail: format!("verified with {}", verified.key_id),
                    }),
                    Err(error) => checks.push(Check {
                        name: "signature",
                        ok: false,
                        detail: error.to_string(),
                    }),
                }
            }
            (Some(_), None) => checks.push(Check {
                name: "signature",
                ok: !args.require_signatures,
                detail: "present but not verified (no keyring)".to_string(),
            }),
            (None, _) => checks.push(Check {
                name: "signature",
                ok: !args.require_signatures,
                detail: "unsigned".to_string(),
            }),
        }

        let ok = checks.iter().all(|check| check.ok);
        all_ok &= ok;
        outcomes.push(Outcome {
            source: item.source.clone(),
            receipt_id: item.receipt.receipt_id.clone(),
            ok,
            checks,
        });
    }

    match args.format {
        OutputFormat::Text => {
            for outcome in &outcomes {
                let label = if outcome.ok {
                    "OK".green().bold()
                } else {
                    "FAIL".red().bold()
                };
                println!("{label} {} ({})", outcome.receipt_id, outcome.source);
                for check in &outcome.checks {
                    let mark = if check.ok { "+" } else { "-" };
                    println!("  {mark} {:<10} {}", check.name, check.detail);
                }
            }
            println!(
                "{} of {} receipt(s) verified",
                outcomes.iter().filter(|o| o.ok).count(),
                outcomes.len()
            );
        }
        OutputFormat::Json => match serde_json::to_string_pretty(&outcomes) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("error: cannot serialize the report: {error}");
                return 2;
            }
        },
    }
    if all_ok { 0 } else { 1 }
}

/// Replay the receipt's action against the policy when the receipt carries
/// enough of it: no content (content is never stored) and an action type
/// whose inputs the summary captures.
fn rederive(resolution: &Resolution, receipt: &DecisionReceipt) -> Check {
    if receipt.action.content_hash.is_some() {
        return Check {
            name: "decision",
            ok: true,
            detail: "not re-derived: the action carried content, which receipts never store"
                .to_string(),
        };
    }
    if matches!(
        receipt.action.action_type.as_str(),
        "browser_action" | "code_exec"
    ) {
        return Check {
            name: "decision",
            ok: true,
            detail: "not re-derived: the summary does not capture this action type's inputs"
                .to_string(),
        };
    }
    // A recorded `origin` or `context` that will not deserialize cannot be
    // replayed: dropping it would re-derive a different action and report the
    // answer as if the recorded one had been checked.
    let origin = match receipt.action.origin.clone() {
        Some(value) => match serde_json::from_value(value) {
            Ok(origin) => Some(origin),
            Err(error) => {
                return Check {
                    name: "decision",
                    ok: false,
                    detail: format!("action.origin does not deserialize: {error}"),
                };
            }
        },
        None => None,
    };
    let context = match receipt.action.context.clone() {
        Some(value) => match serde_json::from_value(value) {
            Ok(context) => Some(context),
            Err(error) => {
                return Check {
                    name: "decision",
                    ok: false,
                    detail: format!("action.context does not deserialize: {error}"),
                };
            }
        },
        None => None,
    };
    let action = EvaluationAction {
        action_type: receipt.action.action_type.clone(),
        target: receipt.action.target.clone(),
        content: None,
        origin,
        // `receipt.posture.current` is the state the evaluation ran under
        // (receipt spec 4.8), so the replay runs under it too; without it a
        // policy with a posture extension re-derives from the initial state.
        posture: receipt.posture.as_ref().map(|posture| PostureContext {
            current: Some(posture.current.clone()),
            signal: None,
        }),
        args_size: receipt.action.args_size.map(|size| size as usize),
        url: None,
        network: None,
        timeout_ms: None,
        context,
    };
    let replay = evaluate_audited(
        resolution,
        &action,
        &AuditConfig {
            enabled: false,
            include_rule_trace: false,
            record_duration: false,
        },
        &AuditContext::default(),
    );
    let same = replay.decision == receipt.decision && replay.matched_rule == receipt.matched_rule;
    Check {
        name: "decision",
        ok: same,
        detail: if same {
            format!("re-derived {:?}", receipt.decision).to_lowercase()
        } else {
            format!(
                "receipt says {:?} ({}), replay says {:?} ({})",
                receipt.decision,
                receipt.matched_rule.as_deref().unwrap_or("-"),
                replay.decision,
                replay.matched_rule.as_deref().unwrap_or("-")
            )
        },
    }
}
