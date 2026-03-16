use clap::ValueEnum;
use colored::Colorize;
use hushspec::{HushSpec, resolve_from_path_with_builtins, validate};
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct ValidateArgs {
    /// Policy YAML files to validate
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,

    /// Also check that extends references resolve
    #[arg(long)]
    strict: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

/// A single file's validation result for JSON output.
#[derive(serde::Serialize)]
struct FileResult {
    file: String,
    valid: bool,
    errors: Vec<ErrorEntry>,
    warnings: Vec<String>,
}

#[derive(serde::Serialize)]
struct ErrorEntry {
    code: String,
    message: String,
}

pub fn run(args: ValidateArgs) -> i32 {
    let mut any_not_found = false;
    let mut any_invalid = false;
    let mut results: Vec<FileResult> = Vec::new();

    for path in &args.files {
        if !path.exists() {
            any_not_found = true;
            let result = FileResult {
                file: path.display().to_string(),
                valid: false,
                errors: vec![ErrorEntry {
                    code: "E000".into(),
                    message: format!("file not found: {}", path.display()),
                }],
                warnings: Vec::new(),
            };
            match args.format {
                OutputFormat::Text => {
                    eprintln!("{} {}", "\u{2717}".red(), path.display());
                    eprintln!(
                        "  {}",
                        format!("error[E000]: file not found: {}", path.display()).red()
                    );
                }
                OutputFormat::Json => {}
            }
            results.push(result);
            continue;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                any_invalid = true;
                let result = FileResult {
                    file: path.display().to_string(),
                    valid: false,
                    errors: vec![ErrorEntry {
                        code: "E000".into(),
                        message: format!("failed to read file: {e}"),
                    }],
                    warnings: Vec::new(),
                };
                match args.format {
                    OutputFormat::Text => {
                        eprintln!("{} {}", "\u{2717}".red(), path.display());
                        eprintln!(
                            "  {}",
                            format!("error[E000]: failed to read file: {e}").red()
                        );
                    }
                    OutputFormat::Json => {}
                }
                results.push(result);
                continue;
            }
        };

        let (valid, errors, warnings) = validate_content(&content, path, args.strict);

        if !valid {
            any_invalid = true;
        }

        match args.format {
            OutputFormat::Text => {
                if valid {
                    println!("{} {}", "\u{2713}".green(), path.display());
                    for w in &warnings {
                        println!("  {}", format!("warn: {w}").yellow());
                    }
                } else {
                    println!("{} {}", "\u{2717}".red(), path.display());
                    for err in &errors {
                        println!(
                            "  {}",
                            format!("error[{}]: {}", err.code, err.message).red()
                        );
                    }
                    for w in &warnings {
                        println!("  {}", format!("warn: {w}").yellow());
                    }
                }
            }
            OutputFormat::Json => {}
        }

        results.push(FileResult {
            file: path.display().to_string(),
            valid,
            errors,
            warnings,
        });
    }

    if matches!(args.format, OutputFormat::Json)
        && let Ok(json) = serde_json::to_string_pretty(&results)
    {
        println!("{json}");
    }

    if any_not_found {
        2
    } else if any_invalid {
        1
    } else {
        0
    }
}

fn validate_content(
    content: &str,
    path: &std::path::Path,
    strict: bool,
) -> (bool, Vec<ErrorEntry>, Vec<String>) {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Layer 1: YAML parse
    let spec = match HushSpec::parse(content) {
        Ok(s) => s,
        Err(e) => {
            errors.push(ErrorEntry {
                code: "E001".into(),
                message: format!("YAML parse error: {e}"),
            });
            return (false, errors, warnings);
        }
    };

    // Layer 2: structural validation
    let validation = validate(&spec);
    for err in &validation.errors {
        errors.push(ErrorEntry {
            code: error_code(err),
            message: err.to_string(),
        });
    }
    for w in &validation.warnings {
        warnings.push(w.clone());
    }

    // Layer 3: strict extends resolution
    if strict
        && let Err(error) = resolve_from_path_with_builtins(path)
    {
        errors.push(ErrorEntry {
            code: "E010".into(),
            message: format!("extends resolution failed: {error}"),
        });
    }

    (errors.is_empty(), errors, warnings)
}

fn error_code(err: &hushspec::ValidationError) -> String {
    match err {
        hushspec::ValidationError::UnsupportedVersion(_) => "E002".into(),
        hushspec::ValidationError::DuplicatePatternName(_) => "E003".into(),
        hushspec::ValidationError::InvalidRegex { .. } => "E005".into(),
        hushspec::ValidationError::Custom(_) => "E004".into(),
    }
}
