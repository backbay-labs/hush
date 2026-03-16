use hushspec::HushSpec;
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

    let spec = match HushSpec::parse(&content) {
        Ok(spec) => spec,
        Err(error) => {
            eprintln!("failed to parse {}: {error}", path.display());
            std::process::exit(1);
        }
    };

    match serde_json::to_string(&spec) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("failed to serialize {}: {error}", path.display());
            std::process::exit(1);
        }
    }
}
