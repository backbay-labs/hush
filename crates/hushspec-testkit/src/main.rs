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
    /// (schemas/hushspec-conformance-report.v0.schema.json) to this path
    #[arg(long, value_name = "FILE")]
    report: Option<PathBuf>,

    /// Name recorded in the report's `implementation` block
    #[arg(long, value_name = "NAME", requires = "report")]
    implementation: Option<String>,

    /// Version recorded in the report's `implementation` block
    #[arg(long, value_name = "VERSION", requires = "report")]
    implementation_version: Option<String>,

    /// Language recorded in the report's `implementation` block
    #[arg(long, value_name = "LANGUAGE", requires = "report")]
    implementation_language: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Package the published conformance bundle: prose, schemas, vectors and
    /// the manifest that pins them, reproducibly
    Bundle(BundleArgs),
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
        eprintln!(
            "{} No fixtures found in {}",
            "WARN".yellow(),
            cli.fixtures.display()
        );
        std::process::exit(0);
    }

    let results = hushspec_testkit::runner::run_conformance(&fixtures);

    match cli.output {
        OutputFormat::Text => print_text_results(&results),
        OutputFormat::Json => print_json_results(&results),
    }

    let failed = results.iter().filter(|r| !r.passed).count();
    let passed = results.iter().filter(|r| r.passed).count();

    // The evidence-chain vectors (Levels 4 and 5) are only run when a report
    // is asked for: they are what the report scores those levels on, and the
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

    let default = report::reference_implementation();
    let implementation = report::Implementation {
        name: cli.implementation.clone().unwrap_or(default.name),
        version: cli
            .implementation_version
            .clone()
            .unwrap_or(default.version),
        language: cli
            .implementation_language
            .clone()
            .unwrap_or(default.language),
    };

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
