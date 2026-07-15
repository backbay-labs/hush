use clap::Parser;
use hushspec_testkit::diff::{DifftestConfig, run_difftest};
use hushspec_testkit::r#gen::{random_seed, seed_from_string};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "hushspec-difftest",
    about = "Differential cross-SDK fuzz runner for HushSpec evaluators"
)]
struct Cli {
    /// Seed for deterministic generation (default: OS-random, always printed)
    #[arg(long, conflicts_with = "seed_from_string")]
    seed: Option<u64>,

    /// Derive the seed by hashing a string (e.g. "$GITHUB_SHA")
    #[arg(long)]
    seed_from_string: Option<String>,

    /// Policies per chunk
    #[arg(long, default_value_t = 250)]
    groups: usize,

    /// Actions per policy
    #[arg(long, default_value_t = 4)]
    actions_per_group: usize,

    /// Number of chunks (seed + chunk index each)
    #[arg(long, default_value_t = 1)]
    chunks: usize,

    /// Stop starting new chunks after this many seconds
    #[arg(long)]
    max_seconds: Option<u64>,

    /// SDKs to compare against the Rust oracle (repeatable; default: all three)
    #[arg(long = "sdk", value_parser = ["typescript", "python", "go"])]
    sdks: Vec<String>,

    /// Minimize each divergence before reporting
    #[arg(long)]
    minimize: bool,

    /// Emit minimized divergences as evaluator fixtures into this directory
    #[arg(long)]
    emit_fixtures: Option<PathBuf>,

    /// Write a JSON report here
    #[arg(long)]
    report: Option<PathBuf>,

    /// Directory for reproducible bundle artifacts
    #[arg(long, default_value = "target/difftest")]
    bundles_dir: PathBuf,

    /// Compare everything except reason strings
    #[arg(long)]
    ignore_reason: bool,

    /// Replay an existing bundle instead of generating
    #[arg(long)]
    bundle: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    let seed = match (cli.seed, &cli.seed_from_string) {
        (Some(seed), _) => seed,
        (None, Some(text)) => seed_from_string(text),
        (None, None) => random_seed(),
    };
    let sdks = if cli.sdks.is_empty() {
        vec![
            "typescript".to_string(),
            "python".to_string(),
            "go".to_string(),
        ]
    } else {
        cli.sdks.clone()
    };
    println!("hushspec-difftest seed: {seed}");

    let config = DifftestConfig {
        seed,
        groups_per_chunk: cli.groups,
        actions_per_group: cli.actions_per_group,
        chunks: cli.chunks,
        max_seconds: cli.max_seconds,
        sdks,
        minimize: cli.minimize,
        emit_fixtures_dir: cli.emit_fixtures,
        report_path: cli.report,
        bundles_dir: cli.bundles_dir,
        ignore_reason: cli.ignore_reason,
        repo_root: repo_root(),
        bundle_path: cli.bundle,
        harness_override: None,
    };

    match run_difftest(&config) {
        Ok(outcome) => {
            println!(
                "{} cases across {} chunk(s); {} divergence(s)",
                outcome.cases_run,
                outcome.chunks_run,
                outcome.divergences.len()
            );
            for divergence in &outcome.divergences {
                println!(
                    "  DIVERGE [{}] {} ({:?})",
                    divergence.sdk, divergence.case_key, divergence.kind
                );
            }
            for fixture in &outcome.fixtures {
                println!("  fixture candidate: {}", fixture.display());
            }
            if outcome.divergences.is_empty() {
                std::process::exit(0);
            }
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("ERROR: {error}");
            std::process::exit(2);
        }
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root resolves")
}
