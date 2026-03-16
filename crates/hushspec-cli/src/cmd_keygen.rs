use colored::Colorize;
use std::io::Write;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct KeygenArgs {
    /// Directory to write key files to (defaults to current directory)
    #[arg(long, default_value = ".")]
    output_dir: PathBuf,
}

pub fn run(args: KeygenArgs) -> i32 {
    if !args.output_dir.exists()
        && let Err(e) = std::fs::create_dir_all(&args.output_dir)
    {
        eprintln!("{} Failed to create output directory: {e}", "ERROR".red());
        return 1;
    }

    let private_key_path = args.output_dir.join("hushspec.key");
    let public_key_path = args.output_dir.join("hushspec.pub");

    // Check if files already exist
    if private_key_path.exists() {
        eprintln!(
            "{} {} already exists. Remove it first to generate a new keypair.",
            "ERROR".red(),
            private_key_path.display()
        );
        return 1;
    }
    if public_key_path.exists() {
        eprintln!(
            "{} {} already exists. Remove it first to generate a new keypair.",
            "ERROR".red(),
            public_key_path.display()
        );
        return 1;
    }

    // Generate keypair
    let (signing_key, verifying_key) = hushspec::signing::generate_keypair();

    let private_pem = hushspec::signing::format_private_key_pem(&signing_key);
    if let Err(e) = write_private_key(&private_key_path, &private_pem) {
        eprintln!("{} Failed to write private key: {e}", "ERROR".red());
        return 1;
    }

    // Write public key
    let public_pem = hushspec::signing::format_public_key_pem(&verifying_key);
    if let Err(e) = std::fs::write(&public_key_path, &public_pem) {
        eprintln!("{} Failed to write public key: {e}", "ERROR".red());
        return 1;
    }

    println!(
        "  {} {} (private key -- keep secret!)",
        "Created".green().bold(),
        private_key_path.display(),
    );
    println!(
        "  {} {} (public key -- share freely)",
        "Created".green().bold(),
        public_key_path.display(),
    );

    let key_id = {
        let encoded = hushspec::signing::encode_verifying_key(&verifying_key);
        format!("ed25519:{}", &encoded[..16])
    };
    println!("  {} {}", "Key ID:".dimmed(), key_id);

    println!();
    println!("{}", "Next steps:".bold());
    println!(
        "  1. Sign a policy:   {}",
        format!(
            "hushspec sign policy.yaml --key {}",
            private_key_path.display()
        )
        .dimmed()
    );
    println!(
        "  2. Verify it:       {}",
        format!(
            "hushspec verify policy.yaml --key {}",
            public_key_path.display()
        )
        .dimmed()
    );

    0
}

fn write_private_key(path: &PathBuf, contents: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

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
