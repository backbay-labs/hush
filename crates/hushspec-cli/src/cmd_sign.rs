use colored::Colorize;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct SignArgs {
    /// Policy file to sign
    #[arg(required = true)]
    policy: PathBuf,

    /// Path to the Ed25519 private key file
    #[arg(short, long)]
    key: PathBuf,

    /// Key identifier (defaults to a truncated hash of the public key)
    #[arg(long)]
    key_id: Option<String>,

    /// Human-readable signer identity (e.g. email)
    #[arg(long)]
    signer: Option<String>,

    /// Output path for the .sig file (defaults to <POLICY>.sig)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Sign a policy whose lifecycle_state is not approved or deployed
    /// (development only -- the signature then attests an unreviewed policy)
    #[arg(long)]
    allow_unapproved: bool,
}

pub fn run(args: SignArgs) -> i32 {
    // Read the policy file (raw bytes for signing)
    let content = match std::fs::read(&args.policy) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} Failed to read policy file {}: {e}",
                "ERROR".red(),
                args.policy.display()
            );
            return 1;
        }
    };

    if !args.allow_unapproved && !lifecycle_gate_passes(&content) {
        return 1;
    }

    // Read the private key
    let key_content = match std::fs::read_to_string(&args.key) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} Failed to read key file {}: {e}",
                "ERROR".red(),
                args.key.display()
            );
            return 1;
        }
    };

    let signing_key = match hushspec::signing::parse_private_key_pem(&key_content) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{} Invalid private key: {e}", "ERROR".red());
            return 1;
        }
    };

    // Derive key_id from public key if not provided
    let key_id = args.key_id.unwrap_or_else(|| {
        let vk = signing_key.verifying_key();
        let encoded = hushspec::signing::encode_verifying_key(&vk);
        // Use first 16 chars of the base64-encoded public key as identifier
        format!("ed25519:{}", &encoded[..16])
    });

    let signature =
        hushspec::signing::sign_policy(&content, &signing_key, &key_id, args.signer.as_deref());

    // Determine output path
    let output_path = args.output.unwrap_or_else(|| {
        let mut p = args.policy.clone().into_os_string();
        p.push(".sig");
        PathBuf::from(p)
    });

    match hushspec::signing::save_signature(&signature, &output_path) {
        Ok(()) => {
            println!(
                "  {} {} (key: {})",
                "Signed".green().bold(),
                output_path.display(),
                key_id,
            );
            println!("  {} {}", "Hash".dimmed(), signature.content_hash,);
            0
        }
        Err(e) => {
            eprintln!("{} Failed to write signature file: {e}", "ERROR".red());
            1
        }
    }
}

/// A signature is a durable attestation that this exact policy was approved, so
/// only a policy that says it *was* approved may be signed. Anything else -- a
/// draft, a policy still in review, one that is deprecated or archived, or one
/// with no `metadata.lifecycle_state` at all -- is refused unless the caller
/// passes `--allow-unapproved`. Fail-closed: a policy that will not parse is
/// refused too, because its lifecycle state cannot be established.
fn lifecycle_gate_passes(content: &[u8]) -> bool {
    use hushspec::governance::LifecycleState;

    let Ok(text) = std::str::from_utf8(content) else {
        eprintln!("{} Policy file is not valid UTF-8", "ERROR".red());
        return false;
    };

    let spec = match hushspec::HushSpec::parse(text) {
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
