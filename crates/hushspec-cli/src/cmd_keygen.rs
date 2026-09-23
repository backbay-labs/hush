//! `h2h keygen` -- Ed25519 keys for policy signing (signing spec 5).
//!
//! Writes standard PEM: PKCS#8 for the private key, SubjectPublicKeyInfo for
//! the public one, which is what `openssl genpkey -algorithm ed25519` and
//! `openssl pkey -pubout` produce and what every mainstream crypto library
//! reads. `--convert` upgrades the bespoke 32-byte key files HushSpec 0.1
//! wrote, which are not valid 0.2 key material.

use colored::Colorize;
use hushspec::signing::{SigningKey, VerifyingKey};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(clap::Args)]
pub struct KeygenArgs {
    /// Directory to write key files to (defaults to the current directory)
    #[arg(long, default_value = ".")]
    output_dir: PathBuf,

    /// Base name for the key files: writes <NAME>.key.pem and <NAME>.pub.pem
    #[arg(long, default_value = "h2h")]
    name: String,

    /// Convert a HushSpec 0.1 key file to PEM instead of generating a new key
    #[arg(long, value_name = "OLD_KEY")]
    convert: Option<PathBuf>,

    /// Overwrite existing key files
    #[arg(long)]
    force: bool,
}

pub fn run(args: KeygenArgs) -> i32 {
    if !args.output_dir.exists()
        && let Err(e) = std::fs::create_dir_all(&args.output_dir)
    {
        eprintln!("{} Failed to create output directory: {e}", "ERROR".red());
        return 1;
    }

    let private_path = args.output_dir.join(format!("{}.key.pem", args.name));
    let public_path = args.output_dir.join(format!("{}.pub.pem", args.name));

    if !args.force {
        for path in [&private_path, &public_path] {
            if path.exists() {
                eprintln!(
                    "{} {} already exists. Pass --force to overwrite it.",
                    "ERROR".red(),
                    path.display()
                );
                return 1;
            }
        }
    }

    let (signing_key, verifying_key, converted) = match &args.convert {
        Some(old) => match convert(old) {
            Ok(pair) => (pair.0, pair.1, true),
            Err(code) => return code,
        },
        None => {
            let (signing_key, verifying_key) = hushspec::signing::generate_keypair();
            (signing_key, verifying_key, false)
        }
    };

    let private_pem = match hushspec::signing::private_key_pem(&signing_key) {
        Ok(pem) => pem,
        Err(e) => {
            eprintln!("{} Failed to encode the private key: {e}", "ERROR".red());
            return 1;
        }
    };
    let public_pem = match hushspec::signing::public_key_pem(&verifying_key) {
        Ok(pem) => pem,
        Err(e) => {
            eprintln!("{} Failed to encode the public key: {e}", "ERROR".red());
            return 1;
        }
    };
    let key_id = match hushspec::signing::key_id(&verifying_key) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("{} Failed to compute the key id: {e}", "ERROR".red());
            return 1;
        }
    };

    if let Err(e) = write_private_key(&private_path, &private_pem) {
        eprintln!("{} Failed to write the private key: {e}", "ERROR".red());
        return 1;
    }
    if let Err(e) = std::fs::write(&public_path, &public_pem) {
        eprintln!("{} Failed to write the public key: {e}", "ERROR".red());
        return 1;
    }

    let verb = if converted { "Converted" } else { "Created" };
    println!(
        "  {} {} (PKCS#8 private key -- keep secret!)",
        verb.green().bold(),
        private_path.display(),
    );
    println!(
        "  {} {} (SPKI public key -- share freely)",
        verb.green().bold(),
        public_path.display(),
    );
    println!("  {} {key_id}", "Key ID:".dimmed());

    if converted {
        println!();
        println!(
            "{} the 0.1 key is unchanged, but every signature it made is format 0.1 and",
            "Note:".bold()
        );
        println!("  must be re-made with `h2h sign`: 0.2 signs the policy's canonical hash,");
        println!("  not its bytes.");
    }

    println!();
    println!("{}", "Next steps:".bold());
    println!(
        "  1. Sign a policy:   {}",
        format!("h2h sign policy.yaml --key {}", private_path.display()).dimmed()
    );
    println!(
        "  2. Verify it:       {}",
        format!("h2h verify policy.yaml --key {}", public_path.display()).dimmed()
    );

    0
}

/// Read a HushSpec 0.1 key file and recover the same Ed25519 key.
///
/// The file may be either half of a 0.1 pair: a private key yields the pair,
/// a public key yields a public-only conversion (and the private half has to
/// be converted from its own file).
fn convert(path: &Path) -> Result<(SigningKey, VerifyingKey), i32> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("{} Failed to read {}: {e}", "ERROR".red(), path.display());
            return Err(2);
        }
    };

    match hushspec::signing::convert_legacy_private_key(&content) {
        Ok(signing_key) => {
            let verifying_key = signing_key.verifying_key();
            Ok((signing_key, verifying_key))
        }
        Err(private_error) => {
            if hushspec::signing::convert_legacy_public_key(&content).is_ok() {
                eprintln!(
                    "{} {} is a HushSpec 0.1 *public* key. Convert the private key file \
                     instead; the public key is derived from it.",
                    "ERROR".red(),
                    path.display()
                );
            } else {
                eprintln!(
                    "{} {} is not a HushSpec 0.1 private key: {private_error}",
                    "ERROR".red(),
                    path.display()
                );
            }
            Err(1)
        }
    }
}

fn write_private_key(path: &Path, contents: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}
