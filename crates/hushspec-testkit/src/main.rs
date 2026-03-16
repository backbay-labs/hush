use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "hushspec-testkit", about = "HushSpec conformance test runner")]
struct Cli {
    /// Path to the fixtures directory
    #[arg(short, long, default_value = "fixtures")]
    fixtures: PathBuf,

    /// Output format
    #[arg(short, long, default_value = "text")]
    output: OutputFormat,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() {
    let cli = Cli::parse();

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

    println!();
    if failed == 0 {
        println!("{} {} passed, 0 failed", "PASS".green().bold(), passed);
    } else {
        println!(
            "{} {} passed, {} failed",
            "FAIL".red().bold(),
            passed,
            failed
        );
        std::process::exit(1);
    }
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
