use clap::{Args, Subcommand};
use std::path::PathBuf;

pub(crate) const DEFAULT_SENTINEL: &str = ".hushspec_panic";

/// Consult the default panic sentinel file, flipping the process-global panic
/// latch if it is present. Evaluating subcommands (`eval`, `test`, `diff`) call
/// this before evaluation so a file-based `h2h panic activate` actually takes
/// effect for them rather than being a no-op.
pub(crate) fn check_default_sentinel() {
    hushspec::panic::check_panic_sentinel(DEFAULT_SENTINEL);
}

#[derive(Args)]
pub struct PanicArgs {
    #[command(subcommand)]
    pub action: PanicAction,
}

#[derive(Subcommand)]
pub enum PanicAction {
    /// Activate panic mode by creating the sentinel file
    Activate {
        /// Path to the sentinel file (default: .hushspec_panic in current directory)
        #[arg(long)]
        sentinel: Option<PathBuf>,
    },
    /// Deactivate panic mode by removing the sentinel file
    Deactivate {
        /// Path to the sentinel file (default: .hushspec_panic in current directory)
        #[arg(long)]
        sentinel: Option<PathBuf>,
    },
    /// Check the current panic mode status
    Status {
        /// Path to the sentinel file (default: .hushspec_panic in current directory)
        #[arg(long)]
        sentinel: Option<PathBuf>,
    },
}

pub fn run(args: PanicArgs) -> i32 {
    match args.action {
        PanicAction::Activate { sentinel } => {
            let path = sentinel.unwrap_or_else(|| PathBuf::from(DEFAULT_SENTINEL));
            match std::fs::write(&path, "") {
                Ok(()) => {
                    println!(
                        "Panic mode ACTIVATED. Sentinel file created: {}",
                        path.display()
                    );
                    println!("All evaluate() calls will now return deny.");
                    0
                }
                Err(e) => {
                    eprintln!("Failed to create sentinel file {}: {}", path.display(), e);
                    1
                }
            }
        }
        PanicAction::Deactivate { sentinel } => {
            let path = sentinel.unwrap_or_else(|| PathBuf::from(DEFAULT_SENTINEL));
            if !path.exists() {
                println!("Panic mode already inactive (sentinel file not found).");
                return 0;
            }
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    println!(
                        "Panic mode DEACTIVATED. Sentinel file removed: {}",
                        path.display()
                    );
                    0
                }
                Err(e) => {
                    eprintln!("Failed to remove sentinel file {}: {}", path.display(), e);
                    1
                }
            }
        }
        PanicAction::Status { sentinel } => {
            let path = sentinel.unwrap_or_else(|| PathBuf::from(DEFAULT_SENTINEL));
            if path.exists() {
                println!("ACTIVE  Sentinel file exists: {}", path.display());
                1
            } else {
                println!("INACTIVE  No sentinel file at: {}", path.display());
                0
            }
        }
    }
}
