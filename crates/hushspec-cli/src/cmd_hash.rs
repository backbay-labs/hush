//! `h2h hash` -- the portable identity of a policy (canonical spec 5).
//!
//! Prints the content hash of the *resolved* document, or the canonical JSON
//! text it is computed over. Two parties holding the same policy get the same
//! digest in every SDK; a policy whose base changed gets a different one, even
//! if its own file is untouched.

use clap::ValueEnum;
use colored::Colorize;
use hushspec::{HushSpec, validate};

#[derive(clap::Args)]
pub struct HashArgs {
    /// Policy YAML file, a builtin reference (e.g. "builtin:default"), or "-"
    /// to read the document from stdin
    #[arg(required = true)]
    policy: String,

    /// Output format
    #[arg(short, long, default_value = "digest")]
    format: HashOutputFormat,

    /// Treat validation warnings on the resolved document as failures
    #[arg(long)]
    strict: bool,

    /// Hash the document on its own, with `extends` and `merge_strategy`
    /// stripped and no resolution: the value a `#sha256:` digest pin names
    /// and a receipt records for a chain link (core spec 2.3)
    #[arg(long)]
    own: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum HashOutputFormat {
    /// The `sha256:<hex>` content hash (canonical spec 5)
    Digest,
    /// The RFC 8785 canonical JSON text the hash covers (canonical spec 4)
    Canonical,
}

pub fn run(args: HashArgs) -> i32 {
    let text = match read_document(&args.policy) {
        Ok(text) => text,
        Err(Failure::NotFound(message)) => {
            eprintln!("{} {message}", "error".red());
            return 2;
        }
        Err(Failure::Failed(message)) => {
            eprintln!("{} {message}", "error".red());
            return 1;
        }
    };

    let spec = match HushSpec::parse(&text) {
        Ok(spec) => spec,
        Err(error) => {
            eprintln!("{} failed to parse {}: {error}", "error".red(), args.policy);
            return 1;
        }
    };

    if args.own {
        return match hushspec::own_content_hash(&spec, &args.policy) {
            Ok(digest) => {
                println!("{digest}");
                0
            }
            Err(error) => {
                eprintln!("{} {}", "error".red(), error);
                1
            }
        };
    }

    // Only resolved documents have a canonical form (canonical spec 2.1).
    // A document that declares `extends` goes through the same resolution
    // `h2h resolve` performs, so its identity is the policy that is enforced.
    let canonical = if spec.extends.is_some() {
        // A document read from stdin has no path to resolve relative
        // references against, so it goes straight to the composite loader,
        // which serves `builtin:` from the SDK's own embedded rulesets.
        let resolved = if crate::input::is_stdin(std::path::Path::new(&args.policy)) {
            match hushspec::resolve_with_loader(&spec, None, &hushspec::create_composite_loader()) {
                Ok(resolved) => resolved,
                Err(error) => {
                    eprintln!("{} failed to resolve stdin: {error}", "error".red());
                    return 1;
                }
            }
        } else {
            match crate::cmd_resolve::load(&args.policy) {
                Ok(resolved) => resolved,
                Err(crate::cmd_resolve::LoadError::NotFound(message)) => {
                    eprintln!("{} {message}", "error".red());
                    return 2;
                }
                Err(crate::cmd_resolve::LoadError::Failed(message)) => {
                    eprintln!("{} {message}", "error".red());
                    return 1;
                }
            }
        };
        if let Some(code) = report_validation(&resolved, args.strict) {
            return code;
        }
        hushspec::canonical_json(&resolved)
    } else {
        if let Some(code) = report_validation(&spec, args.strict) {
            return code;
        }
        // Already resolved: canonicalize the document as written, which is
        // the path canonical spec 6 recommends and the one the normative
        // vectors pin.
        match serde_yaml::from_str::<serde_json::Value>(&text) {
            Ok(document) => hushspec::canonical_json_value(&document),
            Err(error) => {
                eprintln!("{} failed to read {}: {error}", "error".red(), args.policy);
                return 1;
            }
        }
    };

    let canonical = match canonical {
        Ok(canonical) => canonical,
        Err(error) => {
            eprintln!(
                "{} {} has no canonical form: {error}",
                "error".red(),
                args.policy
            );
            return 1;
        }
    };

    match args.format {
        HashOutputFormat::Digest => println!("{}", hushspec::canonical::digest(&canonical)),
        HashOutputFormat::Canonical => println!("{canonical}"),
    }
    0
}

/// Canonicalizing an invalid document would produce an identity no conformant
/// engine would ever enforce (canonical spec 2.3), so validation comes first.
fn report_validation(spec: &HushSpec, strict: bool) -> Option<i32> {
    let validation = validate(spec);
    if !validation.is_valid() {
        for error in &validation.errors {
            eprintln!("{} {error}", "error".red());
        }
        return Some(1);
    }
    for warning in &validation.warnings {
        eprintln!("{} {warning}", "warn".yellow());
    }
    if strict && !validation.warnings.is_empty() {
        eprintln!(
            "{} {} warning(s) in strict mode",
            "error".red(),
            validation.warnings.len()
        );
        return Some(1);
    }
    None
}

enum Failure {
    /// The reference names a file that does not exist (exit 2).
    NotFound(String),
    /// Reading failed (exit 1).
    Failed(String),
}

/// The document text behind a policy reference: stdin, a builtin body, or a
/// file. Kept separate from `cmd_resolve::load` so an already-resolved
/// document can be canonicalized exactly as written.
fn read_document(reference: &str) -> Result<String, Failure> {
    let path = std::path::Path::new(reference);
    if crate::input::is_stdin(path) {
        return crate::input::read_policy(path).map_err(|error| match error {
            crate::input::ReadError::NotFound => {
                Failure::NotFound(format!("file not found: {reference}"))
            }
            crate::input::ReadError::Io(message) => Failure::Failed(message),
        });
    }
    if let Some(body) = hushspec::load_builtin(reference) {
        return Ok(body.to_string());
    }
    if !path.exists() {
        return Err(Failure::NotFound(format!("file not found: {reference}")));
    }
    std::fs::read_to_string(path)
        .map_err(|error| Failure::Failed(format!("failed to read {reference}: {error}")))
}
