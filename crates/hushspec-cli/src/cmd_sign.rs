//! `h2h sign` -- produce a detached 0.2 signature envelope (signing spec 4).
//!
//! The signature covers the content hash of the **resolved** policy, so the
//! policy's `extends` chain is resolved and validated before anything is
//! signed: a signer that cannot resolve the chain must refuse to sign
//! (signing spec 3). The `metadata.lifecycle_state` gate (core spec 2.5) runs
//! first, because a signature is a durable attestation that this document was
//! approved.

use colored::Colorize;
use hushspec::signing::{Envelope, SignOptions, SigningError};
use std::path::{Path, PathBuf};

#[derive(clap::Args)]
pub struct SignArgs {
    /// Policy file to sign
    #[arg(required = true)]
    policy: PathBuf,

    /// PEM PKCS#8 Ed25519 private key (see `h2h keygen`)
    #[arg(short, long)]
    key: PathBuf,

    /// Expiry, as a duration from now: 30d, 12h, 90m, 3600s
    #[arg(long, value_name = "DURATION")]
    expires_in: Option<String>,

    /// Override the policy_version claim (defaults to metadata.policy_version)
    #[arg(long, value_name = "N")]
    policy_version: Option<u64>,

    /// Human-readable signer identity (e.g. an email address)
    #[arg(long)]
    signer: Option<String>,

    /// Output path for the .sig file (defaults to <POLICY>.sig)
    #[arg(short, long, alias = "output", value_name = "PATH")]
    out: Option<PathBuf>,

    /// Sign a policy whose lifecycle_state is not approved or deployed
    /// (development only -- the signature then attests an unreviewed policy)
    #[arg(long)]
    allow_unapproved: bool,
}

pub fn run(args: SignArgs) -> i32 {
    if !args.policy.exists() {
        eprintln!(
            "{} Policy file not found: {}",
            "ERROR".red(),
            args.policy.display()
        );
        return 2;
    }

    if !args.allow_unapproved && !lifecycle_gate_passes(&args.policy) {
        return 1;
    }

    // One clock reading for both claims, so `expires_in 30d` is exactly 30
    // days after the `signed_at` the envelope carries.
    let signed_at = chrono::Utc::now();
    let expires_at = match args.expires_in.as_deref().map(parse_duration).transpose() {
        Ok(offset) => offset.map(|offset| signed_at + offset),
        Err(message) => {
            eprintln!("{} {message}", "ERROR".red());
            return 2;
        }
    };

    let signing_key = match hushspec::signing::load_private_key(&args.key) {
        Ok(key) => key,
        Err(e) => {
            eprintln!(
                "{} Invalid private key {}: {e}",
                "ERROR".red(),
                args.key.display()
            );
            return 1;
        }
    };

    // Resolve, validate and hash exactly the way the verifier will.
    let resolved = match hushspec::signing::load_resolved(&args.policy) {
        Ok(resolved) => resolved,
        Err(e) => {
            eprintln!(
                "{} Refusing to sign {}: {}",
                "ERROR".red(),
                args.policy.display(),
                describe(&e)
            );
            return 1;
        }
    };

    let envelope = match hushspec::signing::sign_resolved(
        &resolved,
        &signing_key,
        &SignOptions {
            signed_at: Some(signed_at),
            expires_at,
            policy_version: args.policy_version,
            policy_name: None,
            signer: args.signer.clone(),
        },
    ) {
        Ok(envelope) => envelope,
        Err(e) => {
            eprintln!("{} Failed to sign: {e}", "ERROR".red());
            return 1;
        }
    };

    let out = args
        .out
        .unwrap_or_else(|| hushspec::signing::default_signature_path(&args.policy));

    if let Err(e) = envelope.save(&out) {
        eprintln!("{} Failed to write the signature file: {e}", "ERROR".red());
        return 1;
    }

    report(&envelope, &out);
    0
}

fn report(envelope: &Envelope, out: &Path) {
    println!("  {} {}", "Signed".green().bold(), out.display());
    println!("  {} {}", "Key ID:".dimmed(), envelope.key_id);
    println!("  {} {}", "Content hash:".dimmed(), envelope.content_hash);
    println!("  {} {}", "Signed at:".dimmed(), envelope.signed_at);
    if let Some(expires_at) = &envelope.expires_at {
        println!("  {} {expires_at}", "Expires at:".dimmed());
    }
    if let Some(version) = envelope.policy_version {
        println!("  {} {version}", "Policy version:".dimmed());
    }
    if let Some(signer) = &envelope.signer {
        println!("  {} {signer}", "Signer:".dimmed());
    }
}

fn describe(error: &SigningError) -> String {
    match error {
        SigningError::Resolve(cause) => {
            format!(
                "its extends chain does not resolve ({cause}); a signer that cannot resolve the chain must not sign"
            )
        }
        other => other.to_string(),
    }
}

/// `30d`, `12h`, `90m`, `3600s` -- the duration grammar the core schema uses.
fn parse_duration(value: &str) -> Result<chrono::Duration, String> {
    let invalid =
        || format!("--expires-in {value:?} is not a duration; use <number><s|m|h|d>, e.g. 30d");
    let (digits, unit) = value.split_at(value.len().checked_sub(1).ok_or_else(invalid)?);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let amount: i64 = digits.parse().map_err(|_| invalid())?;
    let seconds = match unit {
        "s" => amount,
        "m" => amount.checked_mul(60).ok_or_else(invalid)?,
        "h" => amount.checked_mul(3600).ok_or_else(invalid)?,
        "d" => amount.checked_mul(86_400).ok_or_else(invalid)?,
        _ => return Err(invalid()),
    };
    if seconds == 0 {
        return Err(format!(
            "--expires-in {value:?} is zero; an already-expired signature verifies nowhere"
        ));
    }
    chrono::Duration::try_seconds(seconds).ok_or_else(invalid)
}

/// A signature is a durable attestation that this exact policy was approved, so
/// only a policy that says it *was* approved may be signed. Anything else -- a
/// draft, a policy still in review, one that is deprecated or archived, or one
/// with no `metadata.lifecycle_state` at all -- is refused unless the caller
/// passes `--allow-unapproved`. Fail-closed: a policy that will not parse is
/// refused too, because its lifecycle state cannot be established.
fn lifecycle_gate_passes(path: &Path) -> bool {
    use hushspec::governance::LifecycleState;

    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!(
                "{} Failed to read policy file {}: {e}",
                "ERROR".red(),
                path.display()
            );
            return false;
        }
    };

    let spec = match hushspec::HushSpec::parse(&text) {
        Ok(spec) => spec,
        Err(e) => {
            eprintln!(
                "{} Refusing to sign an unparseable policy: {e}",
                "ERROR".red()
            );
            return false;
        }
    };

    let state = spec
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.lifecycle_state);

    match state {
        Some(LifecycleState::Approved | LifecycleState::Deployed) => true,
        other => {
            let label = other
                .and_then(|state| {
                    serde_json::to_value(state)
                        .ok()
                        .and_then(|v| v.as_str().map(|s| format!("'{s}'")))
                })
                .unwrap_or_else(|| "not set".to_string());
            eprintln!(
                "{} Refusing to sign {}: metadata.lifecycle_state is {label}, expected 'approved' or 'deployed'.",
                "ERROR".red(),
                "an unapproved policy".bold()
            );
            eprintln!("  Pass --allow-unapproved to sign it anyway (development only).");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_duration;

    #[test]
    fn durations_parse_or_explain_themselves() {
        assert_eq!(parse_duration("30d").unwrap().num_days(), 30);
        assert_eq!(parse_duration("12h").unwrap().num_hours(), 12);
        assert_eq!(parse_duration("90m").unwrap().num_minutes(), 90);
        assert_eq!(parse_duration("45s").unwrap().num_seconds(), 45);

        for bad in ["", "d", "30", "30w", "-1d", "1.5d", "0d"] {
            assert!(parse_duration(bad).is_err(), "{bad:?} should not parse");
        }
    }
}
