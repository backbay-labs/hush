//! `h2h verify` -- check a detached 0.2 signature (signing spec 6).
//!
//! Runs the ten ordered checks and prints the reason code of the first that
//! fails. The code is the contract: it is what a receipt's
//! `policy.signature.reason` carries, so it is printed verbatim rather than
//! wrapped in prose.

use clap::ValueEnum;
use colored::Colorize;
use hushspec::signing::{Envelope, Keyring, LegacySignature, Verified, VerifyError, VerifyOptions};
use std::path::{Path, PathBuf};

#[derive(clap::Args)]
pub struct VerifyArgs {
    /// Policy file to verify
    #[arg(required = true)]
    policy: PathBuf,

    /// Detached .sig file (defaults to <POLICY>.sig, then <POLICY stem>.sig)
    #[arg(short, long, value_name = "PATH")]
    sig: Option<PathBuf>,

    /// PEM SPKI public key, accepted as a one-key keyring
    #[arg(short, long, conflicts_with = "keyring", value_name = "PATH")]
    key: Option<PathBuf>,

    /// Trusted keyring JSON (hushspec-keyring.v1.schema.json)
    #[arg(long, value_name = "PATH")]
    keyring: Option<PathBuf>,

    /// Verifier clock, RFC 3339 (defaults to now)
    #[arg(long, value_name = "TIMESTAMP")]
    now: Option<String>,

    /// Allowed clock skew for signed_at, in seconds
    #[arg(long, default_value_t = 300, value_name = "SECONDS")]
    max_skew: i64,

    /// The last policy_version accepted for this policy name (rollback protection)
    #[arg(long, value_name = "N")]
    last_seen_version: Option<u64>,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

pub fn run(args: VerifyArgs) -> i32 {
    if !args.policy.exists() {
        eprintln!(
            "{} Policy file not found: {}",
            "ERROR".red(),
            args.policy.display()
        );
        return 2;
    }

    let Some(sig_path) = args
        .sig
        .clone()
        .or_else(|| hushspec::signing::detached_signature_path(&args.policy))
    else {
        eprintln!(
            "{} No signature file for {}: looked for {} and {}",
            "ERROR".red(),
            args.policy.display(),
            hushspec::signing::default_signature_path(&args.policy).display(),
            args.policy.with_extension("sig").display()
        );
        return 2;
    };
    if !sig_path.exists() {
        eprintln!(
            "{} Signature file not found: {}",
            "ERROR".red(),
            sig_path.display()
        );
        return 2;
    }

    let keyring = match load_keyring(args.key.as_deref(), args.keyring.as_deref()) {
        Ok(keyring) => keyring,
        Err(code) => return code,
    };

    let now = match args.now.as_deref().map(parse_now).transpose() {
        Ok(now) => now.unwrap_or_else(chrono::Utc::now),
        Err(message) => {
            eprintln!("{} {message}", "ERROR".red());
            return 2;
        }
    };

    let envelope_text = match std::fs::read_to_string(&sig_path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!(
                "{} Failed to read {}: {e}",
                "ERROR".red(),
                sig_path.display()
            );
            return 2;
        }
    };

    let envelope = match Envelope::parse(&envelope_text) {
        Ok(envelope) => envelope,
        Err(error) => {
            // A 0.1 signature is not corrupt, it is superseded. Say so.
            if let Some(legacy) = LegacySignature::detect(&envelope_text) {
                report_legacy(&sig_path, &legacy, args.format);
            } else {
                report_failure(&error, args.format);
            }
            return 1;
        }
    };

    let options = VerifyOptions {
        now,
        max_clock_skew_seconds: args.max_skew,
        last_seen_version: args.last_seen_version,
    };

    match hushspec::signing::verify_policy_at(&args.policy, &envelope, &keyring, &options) {
        Ok(verified) => {
            report_success(&verified, args.format);
            0
        }
        Err(error) => {
            report_failure(&error, args.format);
            1
        }
    }
}

/// Exit code for a keyring that would not load.
///
/// The split follows the CLI's convention: 2 for input the tool could not
/// read, 1 for input it read and rejected. It is decided from the error, not
/// from a `path.exists()` stat racing the failed open.
pub(crate) fn keyring_exit_code(error: &hushspec::signing::SigningError) -> i32 {
    match error {
        hushspec::signing::SigningError::Io(_) => 2,
        _ => 1,
    }
}

fn load_keyring(key: Option<&Path>, keyring: Option<&Path>) -> Result<Keyring, i32> {
    match (key, keyring) {
        (_, Some(path)) => Keyring::load(path).map_err(|e| {
            eprintln!(
                "{} Failed to load the keyring {}: {e}",
                "ERROR".red(),
                path.display()
            );
            keyring_exit_code(&e)
        }),
        (Some(path), None) => {
            let text = std::fs::read_to_string(path).map_err(|e| {
                eprintln!(
                    "{} Failed to read the public key {}: {e}",
                    "ERROR".red(),
                    path.display()
                );
                2
            })?;
            Keyring::from_public_key_pem(&text).map_err(|e| {
                eprintln!(
                    "{} Invalid public key {}: {e}",
                    "ERROR".red(),
                    path.display()
                );
                1
            })
        }
        (None, None) => {
            eprintln!(
                "{} Nothing to trust: pass --keyring <ring.json> or --key <pub.pem>.",
                "ERROR".red()
            );
            Err(2)
        }
    }
}

fn parse_now(value: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|instant| instant.with_timezone(&chrono::Utc))
        .map_err(|e| format!("--now {value:?} is not an RFC 3339 timestamp: {e}"))
}

fn report_success(verified: &Verified, format: OutputFormat) {
    if format == OutputFormat::Json {
        let report = serde_json::json!({
            "valid": true,
            "key_id": verified.key_id,
            "signed_at": verified.signed_at,
            "expires_at": verified.expires_at,
            "content_hash": verified.content_hash,
            "policy_name": verified.policy_name,
            "policy_version": verified.policy_version,
            "signer": verified.signer,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
        return;
    }

    println!("{} Signature is valid", "\u{2713}".green());
    println!("  {} {}", "Key ID:".dimmed(), verified.key_id);
    println!("  {} {}", "Signed at:".dimmed(), verified.signed_at);
    if let Some(expires_at) = &verified.expires_at {
        println!("  {} {expires_at}", "Expires at:".dimmed());
    }
    println!("  {} {}", "Content hash:".dimmed(), verified.content_hash);
    if let Some(name) = &verified.policy_name {
        println!("  {} {name}", "Policy name:".dimmed());
    }
    if let Some(version) = verified.policy_version {
        println!("  {} {version}", "Policy version:".dimmed());
    }
    if let Some(signer) = &verified.signer {
        println!("  {} {signer}", "Signer:".dimmed());
    }
}

fn report_failure(error: &VerifyError, format: OutputFormat) {
    if format == OutputFormat::Json {
        let report = serde_json::json!({
            "valid": false,
            "reason": error.reason_code(),
            "detail": error.detail,
        });
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
        return;
    }

    eprintln!(
        "{} Signature verification failed: {}",
        "\u{2717}".red(),
        error.reason_code().bold()
    );
    eprintln!("  {}", error.detail);
}

fn report_legacy(path: &Path, legacy: &LegacySignature, format: OutputFormat) {
    let detail = format!(
        "{} is a format {} signature over the policy's raw bytes. Format 0.2 signs the \
         canonical hash of the resolved policy, so the two cannot be compared: re-sign the \
         policy with `h2h sign` (convert the 0.1 key with `h2h keygen --convert`).",
        path.display(),
        legacy.format_version
    );

    if format == OutputFormat::Json {
        let report = serde_json::json!({
            "valid": false,
            "reason": "unsupported_format_version",
            "detail": detail,
            "legacy_format_version": legacy.format_version,
        });
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
        return;
    }

    eprintln!(
        "{} Signature verification failed: {}",
        "\u{2717}".red(),
        "unsupported_format_version".bold()
    );
    eprintln!("  {detail}");
}
