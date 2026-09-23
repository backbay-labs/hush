use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "hushspec-testkit", about = "HushSpec conformance test runner")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to the fixtures directory
    #[arg(short, long, default_value = "fixtures")]
    fixtures: PathBuf,

    /// Output format
    #[arg(short, long, default_value = "text")]
    output: OutputFormat,

    /// Also write a conformance report
    /// (schemas/hushspec-conformance-report.v1.schema.json) to this path
    #[arg(long, value_name = "FILE")]
    report: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Package the published conformance bundle: prose, schemas, vectors and
    /// the manifest that pins them, reproducibly
    Bundle(BundleArgs),
    /// Run a digest-bound external engine against the captured corpus (Linux)
    External(ExternalArgs),
}

#[derive(clap::Args)]
struct ExternalArgs {
    #[arg(long, value_name = "PROFILE")]
    engine: PathBuf,
    #[arg(long, default_value = "fixtures", value_name = "DIR")]
    fixtures: PathBuf,
    #[arg(long, value_name = "NEW_DIR")]
    out: PathBuf,
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(0..=3))]
    level: u8,
    #[arg(long, default_value_t = 2000)]
    timeout_ms: u64,
    /// Total engine-dispatch time budget, excluding snapshot and publication
    #[arg(long, default_value_t = 300000)]
    total_timeout_ms: u64,
    #[arg(long, default_value_t = 1048576)]
    stdout_bytes: usize,
    #[arg(long, default_value_t = 262144)]
    stderr_bytes: usize,
    #[arg(long, default_value_t = 67108864)]
    total_output_bytes: usize,
    /// Combined retained request and serialized input bytes
    #[arg(long, default_value_t = 67108864)]
    total_request_bytes: usize,
    #[arg(long)]
    source_sha: Option<String>,
    #[arg(long)]
    ci_run: Option<String>,
    #[arg(long)]
    ci_attempt: Option<String>,
}

fn run_external_command(args: &ExternalArgs) -> i32 {
    use hushspec_testkit::external::{
        model::{BuildContext, ProcessLimits},
        run::{ExternalOptions, run_external},
    };
    let options = ExternalOptions {
        profile: args.engine.clone(),
        fixtures: args.fixtures.clone(),
        output: args.out.clone(),
        level: args.level,
        limits: ProcessLimits {
            timeout_ms: args.timeout_ms,
            total_timeout_ms: args.total_timeout_ms,
            stdout_bytes: args.stdout_bytes,
            stderr_bytes: args.stderr_bytes,
            total_output_bytes: args.total_output_bytes,
            total_request_bytes: args.total_request_bytes,
        },
        context: BuildContext {
            source_sha: args.source_sha.clone(),
            ci_run: args.ci_run.clone(),
            ci_attempt: args.ci_attempt.clone(),
        },
    };
    match run_external(options) {
        Ok(outcome) => {
            println!(
                "external conformance {}: {}",
                if outcome.qualified {
                    "qualified"
                } else {
                    "not qualified"
                },
                outcome.report_path.display()
            );
            i32::from(!outcome.qualified)
        }
        Err(error) => {
            eprintln!("ERROR external conformance: {error}");
            2
        }
    }
}

#[derive(clap::Args)]
struct BundleArgs {
    /// Repository root to package from
    #[arg(long, default_value = ".", value_name = "DIR")]
    root: PathBuf,

    /// Where to write the archive
    /// (default: hushspec-conformance-<fixtures version>.tar.gz)
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() {
    let cli = Cli::parse();

    if let Some(Command::Bundle(args)) = &cli.command {
        std::process::exit(run_bundle(args));
    }
    if let Some(Command::External(args)) = &cli.command {
        std::process::exit(run_external_command(args));
    }

    if !cli.fixtures.exists() {
        eprintln!(
            "{} Fixtures directory not found: {}",
            "ERROR".red(),
            cli.fixtures.display()
        );
        std::process::exit(1);
    }

    let fixtures = hushspec_testkit::fixture::discover_fixtures(&cli.fixtures);
    if fixtures.is_empty() {
        // Exiting 0 here would make a conformance job pointed at the wrong
        // path green having verified nothing.
        eprintln!(
            "{} No fixtures found in {}",
            "ERROR".red(),
            cli.fixtures.display()
        );
        std::process::exit(1);
    }

    let results = hushspec_testkit::runner::run_conformance(&fixtures);

    match cli.output {
        OutputFormat::Text => print_text_results(&results),
        OutputFormat::Json => print_json_results(&results),
    }

    let failed = results.iter().filter(|r| !r.passed).count();
    let passed = results.iter().filter(|r| r.passed).count();

    // Report mode also runs the JSON case corpora the default document walk
    // cannot discover: raw YAML cases score Levels 1, 3, and 4, while the
    // evidence-chain and schema-derived log cases score Levels 4 and 5. The
    // default run stays the document corpus it has always been.
    let mut report_failed = 0;
    if cli.report.is_some() {
        match write_report(&cli, &results) {
            Ok((path, highest, failures)) => {
                report_failed = failures;
                println!();
                println!(
                    "{} conformance report written to {}",
                    "REPORT".cyan().bold(),
                    path.display()
                );
                match highest {
                    Some(level) => println!("  highest fully passing level: {level}"),
                    None => println!("  highest fully passing level: none"),
                }
            }
            Err(error) => {
                eprintln!("{} {error}", "ERROR".red());
                std::process::exit(1);
            }
        }
    }

    println!();
    if failed == 0 && report_failed == 0 {
        println!("{} {} passed, 0 failed", "PASS".green().bold(), passed);
    } else {
        println!(
            "{} {} passed, {} failed",
            "FAIL".red().bold(),
            passed,
            failed + report_failed
        );
        std::process::exit(1);
    }
}

fn run_bundle(args: &BundleArgs) -> i32 {
    match hushspec_testkit::conformance_bundle::write(&args.root, args.out.as_deref()) {
        Ok((path, digest)) => {
            println!("{} {}", "BUNDLE".green().bold(), path.display());
            println!("  sha256: {digest}");
            0
        }
        Err(error) => {
            eprintln!("{} {error}", "ERROR".red());
            1
        }
    }
}

/// Run the evidence vectors, build the report, validate it against the
/// published schema, and write it. Returns the path, the highest fully
/// passing level, and how many evidence vectors failed.
fn write_report(
    cli: &Cli,
    document_results: &[hushspec_testkit::runner::TestResult],
) -> Result<(PathBuf, Option<u8>, usize), String> {
    use hushspec_testkit::report;

    let path = cli.report.as_ref().expect("checked by the caller").clone();
    let evidence = hushspec_testkit::evidence::run_evidence(&cli.fixtures);
    let failures = evidence
        .iter()
        .filter(|result| result.status != report::Status::Pass)
        .count();

    let implementation = report::reference_implementation();

    let built = report::build(
        implementation,
        &cli.fixtures,
        document_results,
        &evidence,
        report::now_rfc3339(),
    )?;
    report::validate(&built)?;
    report::write(&built, &path)?;

    for result in &evidence {
        if result.status != report::Status::Pass {
            eprintln!(
                "  {} {} — {}",
                "FAIL".red(),
                result.path,
                result.message.as_deref().unwrap_or("")
            );
        }
    }

    Ok((path, built.highest_level, failures))
}

fn print_text_results(results: &[hushspec_testkit::runner::TestResult]) {
    for result in results {
        let status = if result.passed {
            "PASS".green()
        } else {
            "FAIL".red()
        };
        let path = result
            .fixture_path
            .rsplit_once("fixtures/")
            .map(|(_, rel)| rel)
            .unwrap_or(&result.fixture_path);
        println!("  {} {} — {}", status, path, result.message);
    }
}

fn print_json_results(results: &[hushspec_testkit::runner::TestResult]) {
    // Serialize results as JSON array
    let json_results: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            serde_json::json!({
                "path": r.fixture_path,
                "category": format!("{:?}", r.category),
                "passed": r.passed,
                "message": r.message,
            })
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&json_results).unwrap_or_default()
    );
}
