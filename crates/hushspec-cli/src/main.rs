mod cmd_audit;
mod cmd_diff;
mod cmd_fmt;
mod cmd_init;
mod cmd_keygen;
mod cmd_lint;
mod cmd_panic;
mod cmd_sign;
mod cmd_test;
mod cmd_validate;
mod cmd_verify;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "h2h",
    about = "hush to hush — because your agent's permissions shouldn't be shouted about",
    version,
    propagate_version = true,
    after_help = "psst... keep it down out there"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display governance metadata and run advisory checks
    Audit(cmd_audit::AuditArgs),
    /// Validate policy files against the HushSpec schema
    Validate(cmd_validate::ValidateArgs),
    /// Run evaluation test suites against policies
    Test(cmd_test::TestArgs),
    /// Scaffold a new policy project
    Init(cmd_init::InitArgs),
    /// Run static analysis checks on policy files
    Lint(cmd_lint::LintArgs),
    /// Compare two policies and show effective decision changes
    Diff(cmd_diff::DiffArgs),
    /// Format policy files canonically
    Fmt(cmd_fmt::FmtArgs),
    /// Manage emergency panic mode (deny-all kill switch)
    Panic(cmd_panic::PanicArgs),
    /// Sign a policy file with an Ed25519 key
    Sign(cmd_sign::SignArgs),
    /// Verify a policy file's detached signature
    Verify(cmd_verify::VerifyArgs),
    /// Generate a new Ed25519 keypair for policy signing
    Keygen(cmd_keygen::KeygenArgs),
}

fn main() {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Commands::Audit(args) => cmd_audit::run(args),
        Commands::Validate(args) => cmd_validate::run(args),
        Commands::Test(args) => cmd_test::run(args),
        Commands::Init(args) => cmd_init::run(args),
        Commands::Lint(args) => cmd_lint::run(args),
        Commands::Diff(args) => cmd_diff::run(args),
        Commands::Fmt(args) => cmd_fmt::run(args),
        Commands::Panic(args) => cmd_panic::run(args),
        Commands::Sign(args) => cmd_sign::run(args),
        Commands::Verify(args) => cmd_verify::run(args),
        Commands::Keygen(args) => cmd_keygen::run(args),
    };

    std::process::exit(exit_code);
}
