mod cmd_audit;
mod cmd_completions;
mod cmd_diff;
mod cmd_eval;
mod cmd_fmt;
mod cmd_init;
mod cmd_keygen;
mod cmd_lint;
mod cmd_panic;
mod cmd_resolve;
mod cmd_schema;
mod cmd_sign;
mod cmd_test;
mod cmd_validate;
mod cmd_verify;
mod cmd_version;
mod generated_schemas;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "h2h",
    about = "hush to hush — because your agent's permissions shouldn't be shouted about",
    version,
    propagate_version = true,
    after_help = "psst... keep it down out there"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display governance metadata and run advisory checks
    Audit(cmd_audit::AuditArgs),
    /// Validate policy files against the HushSpec schema
    Validate(cmd_validate::ValidateArgs),
    /// Print a policy with its extends chain fully resolved and merged
    Resolve(cmd_resolve::ResolveArgs),
    /// Run evaluation test suites against policies
    Test(cmd_test::TestArgs),
    /// Evaluate a single action against a policy
    Eval(cmd_eval::EvalArgs),
    /// Explain a single-action decision with a rule-by-rule trace
    Explain(cmd_eval::EvalArgs),
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
    /// Print a published HushSpec JSON Schema
    Schema(cmd_schema::SchemaArgs),
    /// Generate a shell completion script
    Completions(cmd_completions::CompletionsArgs),
    /// Print CLI, build, and spec version information
    Version(cmd_version::VersionArgs),
}

fn main() {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Commands::Audit(args) => cmd_audit::run(args),
        Commands::Validate(args) => cmd_validate::run(args),
        Commands::Resolve(args) => cmd_resolve::run(args),
        Commands::Test(args) => cmd_test::run(args),
        Commands::Eval(args) => cmd_eval::run(args),
        Commands::Explain(args) => cmd_eval::run_explain(args),
        Commands::Init(args) => cmd_init::run(args),
        Commands::Lint(args) => cmd_lint::run(args),
        Commands::Diff(args) => cmd_diff::run(args),
        Commands::Fmt(args) => cmd_fmt::run(args),
        Commands::Panic(args) => cmd_panic::run(args),
        Commands::Sign(args) => cmd_sign::run(args),
        Commands::Verify(args) => cmd_verify::run(args),
        Commands::Keygen(args) => cmd_keygen::run(args),
        Commands::Schema(args) => cmd_schema::run(args),
        Commands::Completions(args) => cmd_completions::run(args),
        Commands::Version(args) => cmd_version::run(args),
    };

    std::process::exit(exit_code);
}
