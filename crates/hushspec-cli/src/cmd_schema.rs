use clap::ValueEnum;
use colored::Colorize;

use crate::generated_schemas::{SCHEMA_FILE_NAMES, SCHEMA_NAMES, schema_body};

#[derive(clap::Args)]
pub struct SchemaArgs {
    /// Schema to print: a short name (core, posture, ...) or a published file
    /// name (hushspec-core.v1.schema.json)
    #[arg(required_unless_present = "list")]
    name: Option<String>,

    /// List the available schema names instead of printing one
    #[arg(long, conflicts_with = "name")]
    list: bool,

    /// Output format for --list (the schema body itself is always JSON)
    #[arg(short, long, default_value = "text")]
    format: SchemaOutputFormat,
}

#[derive(Clone, Copy, ValueEnum)]
enum SchemaOutputFormat {
    Text,
    Json,
}

#[derive(serde::Serialize)]
struct SchemaEntry {
    name: &'static str,
    file: &'static str,
    id: String,
}

pub fn run(args: SchemaArgs) -> i32 {
    if args.list {
        print_list(args.format);
        return 0;
    }

    // clap's `required_unless_present` guarantees a name here.
    let Some(name) = args.name.as_deref() else {
        eprintln!("{} no schema name given (try --list)", "error".red());
        return 2;
    };

    match schema_body(name) {
        Some(body) => {
            // Schema files are stored with a trailing newline; print exactly
            // one so `h2h schema core > core.json` round-trips byte for byte.
            print!("{}", ensure_trailing_newline(body));
            0
        }
        None => {
            eprintln!(
                "{} unknown schema '{name}' (known: {})",
                "error".red(),
                SCHEMA_NAMES.join(", ")
            );
            2
        }
    }
}

fn print_list(format: SchemaOutputFormat) {
    let entries: Vec<SchemaEntry> = SCHEMA_FILE_NAMES
        .iter()
        .map(|(name, file)| SchemaEntry {
            name,
            file,
            id: format!("https://hushspec.dev/schemas/{file}"),
        })
        .collect();

    match format {
        SchemaOutputFormat::Json => {
            if let Ok(json) = serde_json::to_string_pretty(&entries) {
                println!("{json}");
            }
        }
        SchemaOutputFormat::Text => {
            // The column is as wide as the longest name, so no name runs into
            // the file name beside it. Padding is applied to the plain name --
            // a ColoredString pads to the width of its escape sequences, not
            // its visible text.
            let width = entries
                .iter()
                .map(|entry| entry.name.chars().count())
                .max()
                .unwrap_or(0);
            for entry in &entries {
                println!("{:<width$} {}", entry.name, entry.file);
            }
        }
    }
}

fn ensure_trailing_newline(body: &str) -> String {
    if body.ends_with('\n') {
        body.to_string()
    } else {
        format!("{body}\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_schema_has_a_body_and_file_name() {
        assert_eq!(SCHEMA_NAMES.len(), SCHEMA_FILE_NAMES.len());
        for (name, file) in SCHEMA_FILE_NAMES {
            let body = schema_body(name).unwrap_or_else(|| panic!("{name} has no body"));
            let parsed: serde_json::Value =
                serde_json::from_str(body).unwrap_or_else(|e| panic!("{name} is not JSON: {e}"));
            assert_eq!(
                parsed["$id"].as_str(),
                Some(format!("https://hushspec.dev/schemas/{file}").as_str()),
                "{name} $id does not match its file name"
            );
        }
    }

    #[test]
    fn schema_body_accepts_published_file_names() {
        assert_eq!(
            schema_body("hushspec-core.v1.schema.json"),
            schema_body("core")
        );
    }

    #[test]
    fn schema_body_rejects_unknown_names() {
        assert!(schema_body("nope").is_none());
        assert!(schema_body("").is_none());
    }

    /// The committed generated module must match `schemas/` on disk; CI also
    /// enforces this with `scripts/generate_cli_schemas.py --check`.
    #[test]
    fn generated_schemas_match_the_schemas_directory() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../schemas");
        let mut seen = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let file = path.file_name().unwrap().to_string_lossy().to_string();
            if !file.ends_with(".schema.json") {
                continue;
            }
            let on_disk = std::fs::read_to_string(&path).unwrap();
            assert_eq!(
                schema_body(&file),
                Some(on_disk.as_str()),
                "{file} is stale in generated_schemas.rs -- rerun scripts/generate_cli_schemas.py"
            );
            seen += 1;
        }
        assert_eq!(seen, SCHEMA_NAMES.len(), "schema count drifted");
    }
}
