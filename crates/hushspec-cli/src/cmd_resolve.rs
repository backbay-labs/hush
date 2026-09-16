use clap::ValueEnum;
use colored::Colorize;
use hushspec::{HushSpec, validate};
use std::path::Path;

#[derive(clap::Args)]
pub struct ResolveArgs {
    /// Policy YAML file, or a builtin reference (e.g. "builtin:default")
    #[arg(required = true)]
    policy: String,

    /// Output format
    #[arg(short, long, default_value = "yaml")]
    format: ResolveOutputFormat,

    /// Treat validation warnings (unknown extension keys, unreachable posture
    /// states, ...) on the resolved document as failures
    #[arg(long)]
    strict: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum ResolveOutputFormat {
    Yaml,
    Json,
}

pub fn run(args: ResolveArgs) -> i32 {
    let resolved = match load(&args.policy) {
        Ok(spec) => spec,
        Err(LoadError::NotFound(msg)) => {
            eprintln!("{} {msg}", "error".red());
            return 2;
        }
        Err(LoadError::Failed(msg)) => {
            eprintln!("{} {msg}", "error".red());
            return 1;
        }
    };

    // Validate the *resolved* document: a merge can produce a document neither
    // side had (a duplicate pattern name across layers, say), and emitting it
    // as if it were fine would be fail-open.
    let validation = validate(&resolved);
    if !validation.is_valid() {
        for err in &validation.errors {
            eprintln!("{} {err}", "error".red());
        }
        return 1;
    }

    for warning in &validation.warnings {
        eprintln!("{} {warning}", "warn".yellow());
    }

    if args.strict && !validation.warnings.is_empty() {
        eprintln!(
            "{} {} warning(s) in strict mode",
            "error".red(),
            validation.warnings.len()
        );
        return 1;
    }

    let rendered = match args.format {
        ResolveOutputFormat::Yaml => resolved.to_yaml().map_err(|e| e.to_string()),
        ResolveOutputFormat::Json => {
            serde_json::to_string_pretty(&resolved).map_err(|e| e.to_string())
        }
    };

    match rendered {
        Ok(text) => {
            print!("{}", crate::cmd_fmt::normalize_trailing_newline(&text));
            0
        }
        Err(e) => {
            eprintln!("{} failed to serialize resolved policy: {e}", "error".red());
            1
        }
    }
}

enum LoadError {
    /// The policy reference names a file that does not exist (exit 2).
    NotFound(String),
    /// Parsing or extends resolution failed (exit 1).
    Failed(String),
}

/// Resolve a policy from a builtin reference or a filesystem path, consuming
/// the whole `extends` chain.
fn load(reference: &str) -> Result<HushSpec, LoadError> {
    if let Some(yaml) = hushspec::load_builtin(reference) {
        let unresolved = HushSpec::parse(yaml).map_err(|e| {
            LoadError::Failed(format!("failed to parse builtin '{reference}': {e}"))
        })?;
        let source = if reference.starts_with("builtin:") {
            reference.to_string()
        } else {
            format!("builtin:{reference}")
        };
        let loader = hushspec::create_composite_loader();
        return hushspec::resolve_with_loader(&unresolved, Some(&source), &loader)
            .map_err(|e| LoadError::Failed(format!("failed to resolve '{reference}': {e}")));
    }

    let path = Path::new(reference);
    if !path.exists() {
        return Err(LoadError::NotFound(format!("file not found: {reference}")));
    }

    hushspec::resolve_from_path_with_builtins(path)
        .map_err(|e| LoadError::Failed(format!("failed to resolve {reference}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::{LoadError, load};

    #[test]
    fn missing_file_is_not_found() {
        match load("definitely-not-a-policy.yaml") {
            Err(LoadError::NotFound(_)) => {}
            _ => panic!("expected NotFound"),
        }
    }

    #[test]
    fn builtin_reference_resolves() {
        let spec = match load("builtin:default") {
            Ok(spec) => spec,
            Err(_) => panic!("builtin:default should resolve"),
        };
        assert!(spec.rules.is_some());
        // extends is consumed by resolution.
        assert!(spec.extends.is_none());
    }
}
