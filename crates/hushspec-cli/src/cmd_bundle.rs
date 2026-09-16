//! `h2h bundle` -- policy bundle attestation (spec/hushspec-bundle.md).
//!
//! `create` resolves a policy with the verify-on-load options the evidence
//! chain already uses, wraps the resolution in an in-toto statement, and
//! signs it into a DSSE envelope. `verify` runs the four ordered checks of
//! bundle spec 5.2 and prints the reason code of the first that fails --
//! the code is the contract, so it is printed verbatim rather than wrapped
//! in prose. `inspect` reads a bundle without trusting it.

use clap::{Subcommand, ValueEnum};
use colored::Colorize;
use hushspec::bundle::{
    BundleOptions, BundleVerified, BundleVerifyError, DsseEnvelope, Statement, VerifyBundleOptions,
    build_statement, sign_statement, unsigned_envelope, verify_bundle,
};
use hushspec::signing::Keyring;
use std::path::{Path, PathBuf};

#[derive(clap::Args)]
pub struct BundleArgs {
    #[command(subcommand)]
    command: BundleCommand,
}

#[derive(Subcommand)]
enum BundleCommand {
    /// Resolve a policy and attest it as a signed DSSE / in-toto bundle
    Create(CreateArgs),
    /// Check a bundle's signatures, subject digest, and (optionally) the
    /// policy it claims to be about
    Verify(VerifyArgs),
    /// Print a bundle's predicate summary without verifying it
    Inspect(InspectArgs),
}

#[derive(clap::Args)]
pub struct CreateArgs {
    /// Policy file to bundle, or a builtin reference (e.g. "builtin:default")
    #[arg(required = true)]
    policy: String,

    /// PEM PKCS#8 Ed25519 private key that signs the bundle (see `h2h keygen`)
    #[arg(short, long, value_name = "PATH")]
    key: Option<PathBuf>,

    /// Trusted keyring JSON used to verify the policy's own signature on load
    #[arg(long, value_name = "PATH")]
    keyring: Option<PathBuf>,

    /// Refuse to bundle unless every non-builtin document in the extends
    /// chain carries a verifying signature or a matching #sha256: pin
    #[arg(long)]
    require_signature: bool,

    /// Allowed signer clock skew in seconds when verifying on load
    #[arg(long, default_value_t = 300, value_name = "SECONDS")]
    max_skew: i64,

    /// Output path for the bundle (defaults to <POLICY>.bundle.json)
    #[arg(short, long, alias = "output", value_name = "PATH")]
    out: Option<PathBuf>,

    /// Pin predicate.created_at instead of using the clock, for reproducible
    /// bundles (RFC 3339, e.g. 2026-09-15T12:00:00.000Z)
    #[arg(long, value_name = "TIMESTAMP")]
    created_at: Option<String>,

    /// Override the subject name (defaults to the policy's name)
    #[arg(long, value_name = "NAME")]
    subject_name: Option<String>,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,
}

#[derive(clap::Args)]
pub struct VerifyArgs {
    /// Bundle file to verify
    #[arg(required = true)]
    bundle: PathBuf,

    /// PEM SPKI public key, accepted as a one-key keyring
    #[arg(short, long, conflicts_with = "keyring", value_name = "PATH")]
    key: Option<PathBuf>,

    /// Trusted keyring JSON (hushspec-keyring.v1.schema.json)
    #[arg(long, value_name = "PATH")]
    keyring: Option<PathBuf>,

    /// Re-resolve this policy and assert the bundle attests it (check 4)
    #[arg(long, value_name = "PATH")]
    policy: Option<String>,

    /// Verifier clock, RFC 3339 (defaults to now). A bundle has no expiry;
    /// this only stamps the report.
    #[arg(long, value_name = "TIMESTAMP")]
    now: Option<String>,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,
}

#[derive(clap::Args)]
pub struct InspectArgs {
    /// Bundle file to read
    #[arg(required = true)]
    bundle: PathBuf,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

pub fn run(args: BundleArgs) -> i32 {
    match args.command {
        BundleCommand::Create(args) => create(args),
        BundleCommand::Verify(args) => verify(args),
        BundleCommand::Inspect(args) => inspect(args),
    }
}

fn create(args: CreateArgs) -> i32 {
    // The verify-on-load flags `eval`, `explain`, and `resolve` share, minus
    // `--key`: on `create` that names the *private* key the bundle is signed
    // with, so the policy's own trust anchor is always `--keyring`.
    let verify_args = crate::verify_opts::VerifyOnLoadArgs {
        require_signature: args.require_signature,
        keyring: args.keyring.clone(),
        key: None,
        now: None,
        max_skew: args.max_skew,
        last_seen_version: None,
    };
    let resolve_options = match verify_args.to_options() {
        Ok(options) => options,
        Err(code) => return code,
    };

    let created_at = match args.created_at.as_deref().map(parse_timestamp).transpose() {
        Ok(created_at) => created_at,
        Err(message) => {
            eprintln!("{} {message}", "error:".red());
            return 2;
        }
    };

    let signing_key = match args.key.as_deref() {
        Some(path) => match hushspec::signing::load_private_key(path) {
            Ok(key) => Some(key),
            Err(e) => {
                eprintln!(
                    "{} invalid private key {}: {e}",
                    "error:".red(),
                    path.display()
                );
                return 1;
            }
        },
        None => None,
    };

    let resolution = match crate::cmd_resolve::load_with(&args.policy, &resolve_options) {
        Ok(resolution) => resolution,
        Err(crate::cmd_resolve::LoadError::NotFound(message)) => {
            eprintln!("{} {message}", "error:".red());
            return 2;
        }
        Err(crate::cmd_resolve::LoadError::Failed(message)) => {
            eprintln!("{} {message}", "error:".red());
            return 1;
        }
    };

    // A bundle that attests a document no engine would accept is worse than
    // no bundle: validate the merged result before attesting it.
    let validation = hushspec::validate(&resolution.spec);
    if !validation.is_valid() {
        for error in &validation.errors {
            eprintln!("{} {error}", "error:".red());
        }
        eprintln!(
            "{} refusing to bundle {}: the resolved policy is not valid",
            "error:".red(),
            args.policy
        );
        return 1;
    }

    let options = BundleOptions {
        created_at,
        tool: "h2h".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        subject_name: args.subject_name.clone(),
        base_dir: std::env::current_dir().ok(),
    };

    let statement = match build_statement(&resolution, &options) {
        Ok(statement) => statement,
        Err(e) => {
            eprintln!("{} failed to build the statement: {e}", "error:".red());
            return 1;
        }
    };

    let envelope = match signing_key.as_ref() {
        Some(key) => sign_statement(&statement, key),
        None => unsigned_envelope(&statement),
    };
    let envelope = match envelope {
        Ok(envelope) => envelope,
        Err(e) => {
            eprintln!("{} failed to build the bundle: {e}", "error:".red());
            return 1;
        }
    };

    let out = args
        .out
        .unwrap_or_else(|| default_bundle_path(&args.policy));
    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        eprintln!(
            "{} failed to create {}: {e}",
            "error:".red(),
            parent.display()
        );
        return 1;
    }
    if let Err(e) = envelope.save(&out) {
        eprintln!("{} failed to write {}: {e}", "error:".red(), out.display());
        return 1;
    }

    if envelope.signatures.is_empty() {
        eprintln!(
            "{} {} is unsigned: an unsigned bundle carries the evidence but attests nothing, and \
             `h2h bundle verify` rejects it. Pass --key <key.pem> to sign it.",
            "warning:".yellow(),
            out.display()
        );
    }

    report_create(&statement, &envelope, &out, args.format);
    0
}

fn default_bundle_path(policy: &str) -> PathBuf {
    let name = match policy.strip_prefix("builtin:") {
        Some(builtin) => builtin.to_string(),
        None => Path::new(policy)
            .file_name()
            .map_or_else(|| policy.to_string(), |name| name.to_string_lossy().into()),
    };
    PathBuf::from(format!("{name}.bundle.json"))
}

fn report_create(statement: &Statement, envelope: &DsseEnvelope, out: &Path, format: OutputFormat) {
    let predicate = &statement.predicate;
    if format == OutputFormat::Json {
        let report = serde_json::json!({
            "bundle": out.display().to_string(),
            "subject": statement.subject[0].name,
            "content_hash": predicate.policy.content_hash,
            "chain": predicate.chain.iter().map(|link| &link.source).collect::<Vec<_>>(),
            "created_at": predicate.created_at,
            "signed": !envelope.signatures.is_empty(),
            "key_ids": envelope.signatures.iter().map(|s| &s.keyid).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
        return;
    }

    println!("  {} {}", "Bundled".green().bold(), out.display());
    println!("  {} {}", "Subject:".dimmed(), statement.subject[0].name);
    println!(
        "  {} {}",
        "Content hash:".dimmed(),
        predicate.policy.content_hash
    );
    println!("  {} {}", "Created at:".dimmed(), predicate.created_at);
    println!(
        "  {} {}",
        "Chain:".dimmed(),
        predicate
            .chain
            .iter()
            .map(|link| link.source.as_str())
            .collect::<Vec<_>>()
            .join(" -> ")
    );
    for signature in &envelope.signatures {
        println!("  {} {}", "Signed by:".dimmed(), signature.keyid);
    }
}

fn verify(args: VerifyArgs) -> i32 {
    if !args.bundle.exists() {
        eprintln!(
            "{} bundle file not found: {}",
            "error:".red(),
            args.bundle.display()
        );
        return 2;
    }

    let keyring = match load_keyring(args.key.as_deref(), args.keyring.as_deref()) {
        Ok(keyring) => keyring,
        Err(code) => return code,
    };

    let now = match args.now.as_deref().map(parse_timestamp).transpose() {
        Ok(now) => now.unwrap_or_else(chrono::Utc::now),
        Err(message) => {
            eprintln!("{} {message}", "error:".red());
            return 2;
        }
    };

    let text = match std::fs::read_to_string(&args.bundle) {
        Ok(text) => text,
        Err(e) => {
            eprintln!(
                "{} failed to read {}: {e}",
                "error:".red(),
                args.bundle.display()
            );
            return 2;
        }
    };

    let envelope = match DsseEnvelope::parse(&text) {
        Ok(envelope) => envelope,
        Err(error) => {
            report_failure(&error, args.format);
            return 1;
        }
    };

    // Check 4's input: the caller's own resolution of the policy file. A
    // policy that will not resolve -- because it is absent, or because the
    // chain will not merge -- is a `policy_mismatch` (bundle spec 5.2): there
    // is nothing to compare the bundle against.
    let resolution = match args.policy.as_deref() {
        Some(reference) => {
            match crate::cmd_resolve::load_with(reference, &hushspec::ResolveOptions::default()) {
                Ok(resolution) => Some(resolution),
                Err(
                    crate::cmd_resolve::LoadError::NotFound(message)
                    | crate::cmd_resolve::LoadError::Failed(message),
                ) => {
                    report_failure(
                        &BundleVerifyError {
                            reason: hushspec::bundle::BundleReason::PolicyMismatch,
                            detail: message,
                        },
                        args.format,
                    );
                    return 1;
                }
            }
        }
        None => None,
    };

    let options = VerifyBundleOptions { now };
    match verify_bundle(&envelope, &keyring, resolution.as_ref(), &options) {
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

fn load_keyring(key: Option<&Path>, keyring: Option<&Path>) -> Result<Keyring, i32> {
    match (key, keyring) {
        (_, Some(path)) => Keyring::load(path).map_err(|e| {
            eprintln!(
                "{} failed to load the keyring {}: {e}",
                "error:".red(),
                path.display()
            );
            crate::cmd_verify::keyring_exit_code(&e)
        }),
        (Some(path), None) => {
            let text = std::fs::read_to_string(path).map_err(|e| {
                eprintln!(
                    "{} failed to read the public key {}: {e}",
                    "error:".red(),
                    path.display()
                );
                2
            })?;
            Keyring::from_public_key_pem(&text).map_err(|e| {
                eprintln!(
                    "{} invalid public key {}: {e}",
                    "error:".red(),
                    path.display()
                );
                1
            })
        }
        (None, None) => {
            eprintln!(
                "{} nothing to trust: pass --keyring <ring.json> or --key <pub.pem>.",
                "error:".red()
            );
            Err(2)
        }
    }
}

fn report_success(verified: &BundleVerified, format: OutputFormat) {
    if format == OutputFormat::Json {
        let report = serde_json::json!({
            "valid": true,
            "key_ids": verified.key_ids,
            "subject": verified.subject_name,
            "content_hash": verified.content_hash,
            "policy_name": verified.policy_name,
            "policy_version": verified.policy_version,
            "created_at": verified.created_at,
            "chain_length": verified.chain_length,
            "policy_checked": verified.policy_checked,
            "verified_at": verified.verified_at,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
        return;
    }

    println!("{} Bundle is valid", "\u{2713}".green());
    println!("  {} {}", "Subject:".dimmed(), verified.subject_name);
    println!("  {} {}", "Content hash:".dimmed(), verified.content_hash);
    println!("  {} {}", "Created at:".dimmed(), verified.created_at);
    println!("  {} {}", "Chain:".dimmed(), verified.chain_length);
    for key_id in &verified.key_ids {
        println!("  {} {key_id}", "Signed by:".dimmed());
    }
    if verified.policy_checked {
        println!(
            "  {} the policy re-resolves to the attested document",
            "Policy:".dimmed()
        );
    }
}

fn report_failure(error: &BundleVerifyError, format: OutputFormat) {
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
        "{} Bundle verification failed: {}",
        "\u{2717}".red(),
        error.reason_code().bold()
    );
    eprintln!("  {}", error.detail);
}

fn inspect(args: InspectArgs) -> i32 {
    let text = match std::fs::read_to_string(&args.bundle) {
        Ok(text) => text,
        Err(e) => {
            eprintln!(
                "{} failed to read {}: {e}",
                "error:".red(),
                args.bundle.display()
            );
            return 2;
        }
    };

    let envelope = match DsseEnvelope::parse(&text) {
        Ok(envelope) => envelope,
        Err(error) => {
            report_failure(&error, args.format);
            return 1;
        }
    };
    let statement = match envelope.statement() {
        Ok(statement) => statement,
        Err(error) => {
            report_failure(&error, args.format);
            return 1;
        }
    };
    let predicate = &statement.predicate;

    if args.format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&statement).unwrap_or_default()
        );
        return 0;
    }

    println!("{} {}", "Bundle".bold(), args.bundle.display());
    println!("  {} {}", "Predicate:".dimmed(), statement.predicate_type);
    println!(
        "  {} {}",
        "Bundle version:".dimmed(),
        predicate.bundle_version
    );
    println!("  {} {}", "Subject:".dimmed(), statement.subject[0].name);
    println!(
        "  {} {}",
        "Content hash:".dimmed(),
        predicate.policy.content_hash
    );
    println!(
        "  {} {}",
        "Spec version:".dimmed(),
        predicate.policy.spec_version
    );
    if let Some(name) = &predicate.policy.name {
        println!("  {} {name}", "Policy name:".dimmed());
    }
    if let Some(version) = predicate.policy.policy_version {
        println!("  {} {version}", "Policy version:".dimmed());
    }
    println!(
        "  {} {} {}",
        "Resolver:".dimmed(),
        predicate.resolver.tool,
        predicate.resolver.version
    );
    println!("  {} {}", "Created at:".dimmed(), predicate.created_at);
    println!("  {}", "Chain:".dimmed());
    for link in &predicate.chain {
        let status = match &link.signature {
            Some(status) if status.verified => " [signature verified]".to_string(),
            Some(status) => format!(
                " [signature {}]",
                status.reason.as_deref().unwrap_or("unverified")
            ),
            None => String::new(),
        };
        println!("    {} {}{status}", link.source, link.content_hash.dimmed());
    }
    match &predicate.signature_verification {
        Some(status) if status.verified => println!(
            "  {} verified{}",
            "Policy signature:".dimmed(),
            status
                .key_id
                .as_deref()
                .map(|id| format!(" by {id}"))
                .unwrap_or_default()
        ),
        Some(status) => println!(
            "  {} not verified ({})",
            "Policy signature:".dimmed(),
            status.reason.as_deref().unwrap_or("unverified")
        ),
        None => println!(
            "  {} not checked at bundling time",
            "Policy signature:".dimmed()
        ),
    }
    if envelope.signatures.is_empty() {
        println!("  {} unsigned", "Signatures:".dimmed());
    } else {
        for signature in &envelope.signatures {
            println!("  {} {}", "Signed by:".dimmed(), signature.keyid);
        }
    }
    0
}

fn parse_timestamp(value: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|instant| instant.with_timezone(&chrono::Utc))
        .map_err(|e| format!("{value:?} is not an RFC 3339 timestamp: {e}"))
}

#[cfg(test)]
mod tests {
    use super::default_bundle_path;
    use std::path::PathBuf;

    #[test]
    fn the_default_output_sits_next_to_the_working_directory_not_the_policy() {
        assert_eq!(
            default_bundle_path("library/healthcare/hipaa-base.yaml"),
            PathBuf::from("hipaa-base.yaml.bundle.json")
        );
        // A builtin reference is not a path; the prefix is dropped rather
        // than left as a colon in a file name.
        assert_eq!(
            default_bundle_path("builtin:default"),
            PathBuf::from("default.bundle.json")
        );
    }
}
