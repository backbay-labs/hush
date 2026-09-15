//! Verify-on-load flags shared by `eval`, `explain`, and `resolve`
//! (signing spec 6.5).

use colored::Colorize;
use hushspec::ResolveOptions;
use hushspec::signing::{Keyring, VerifyOptions};
use std::path::{Path, PathBuf};

#[derive(clap::Args, Clone, Debug, Default)]
pub struct VerifyOnLoadArgs {
    /// Require every non-builtin document in the extends chain to carry a
    /// verifying detached signature or a matching #sha256: pin
    #[arg(long)]
    pub require_signature: bool,

    /// Trusted keyring JSON used to verify policy signatures on load
    #[arg(long, value_name = "PATH", conflicts_with = "key")]
    pub keyring: Option<PathBuf>,

    /// A single trusted public key (PEM) used to verify policy signatures on load
    #[arg(long, value_name = "PATH")]
    pub key: Option<PathBuf>,

    /// Verifier clock as an RFC 3339 timestamp (defaults to now)
    #[arg(long, value_name = "TIMESTAMP")]
    pub now: Option<String>,

    /// Allowed signer clock skew in seconds
    #[arg(long, default_value_t = 300, value_name = "SECONDS")]
    pub max_skew: i64,

    /// The last policy_version accepted for this policy (rollback protection)
    #[arg(long, value_name = "N")]
    pub last_seen_version: Option<u64>,
}

impl VerifyOnLoadArgs {
    /// Build resolver options, printing a usage error and returning exit
    /// code 2 when a key, keyring, or timestamp cannot be read.
    pub fn to_options(&self) -> Result<ResolveOptions, i32> {
        let mut options = ResolveOptions {
            require_signature: self.require_signature,
            ..ResolveOptions::default()
        };
        options.keyring = match (&self.keyring, &self.key) {
            (Some(path), _) => Some(load_keyring(path)?),
            (None, Some(path)) => Some(load_single_key(path)?),
            (None, None) => None,
        };
        let now = match self.now.as_deref() {
            Some(text) => chrono::DateTime::parse_from_rfc3339(text)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .map_err(|e| {
                    eprintln!("{} invalid --now {text:?}: {e}", "error:".red());
                    2
                })?,
            None => chrono::Utc::now(),
        };
        options.verify = Some(VerifyOptions {
            now,
            max_clock_skew_seconds: self.max_skew,
            last_seen_version: self.last_seen_version,
        });
        if self.require_signature && options.keyring.is_none() {
            eprintln!(
                "{} --require-signature without --keyring or --key: only #sha256: pins can satisfy it",
                "note:".yellow()
            );
        }
        Ok(options)
    }
}

fn load_keyring(path: &Path) -> Result<Keyring, i32> {
    Keyring::load(path).map_err(|e| {
        eprintln!(
            "{} failed to load keyring {}: {e}",
            "error:".red(),
            path.display()
        );
        2
    })
}

fn load_single_key(path: &Path) -> Result<Keyring, i32> {
    let pem = std::fs::read_to_string(path).map_err(|e| {
        eprintln!(
            "{} failed to read key {}: {e}",
            "error:".red(),
            path.display()
        );
        2
    })?;
    Keyring::from_public_key_pem(&pem).map_err(|e| {
        eprintln!(
            "{} invalid public key {}: {e}",
            "error:".red(),
            path.display()
        );
        2
    })
}
