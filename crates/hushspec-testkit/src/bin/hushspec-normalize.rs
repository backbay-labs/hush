use hushspec::{HushSpec, canonical_json};
use std::path::PathBuf;

fn main() {
    let Some(path) = std::env::args().nth(1).map(PathBuf::from) else {
        eprintln!("usage: hushspec-normalize <path>");
        std::process::exit(2);
    };

    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) => {
            eprintln!("failed to read {}: {error}", path.display());
            std::process::exit(1);
        }
    };

    let mut spec = match HushSpec::parse(&content) {
        Ok(spec) => spec,
        Err(error) => {
            eprintln!("failed to parse {}: {error}", path.display());
            std::process::exit(1);
        }
    };

    // The document's own canonical form: `extends` and `merge_strategy` are
    // resolution instructions, not policy (canonical spec 3), so a document
    // that still declares them canonicalizes without them, as a digest pin
    // and `h2h hash --own` do.
    spec.extends = None;
    spec.merge_strategy = None;
    match canonical_json(&spec) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("failed to canonicalize {}: {error}", path.display());
            std::process::exit(1);
        }
    }
}
