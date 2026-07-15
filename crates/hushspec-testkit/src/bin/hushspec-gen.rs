use clap::Parser;
use hushspec_testkit::r#gen::{GenConfig, generate_bundle, random_seed};

#[derive(Parser)]
#[command(
    name = "hushspec-gen",
    about = "Generate a portable HushSpec differential case bundle (JSON)"
)]
struct Cli {
    /// Seed for deterministic generation (default: OS-random, printed to stderr)
    #[arg(long)]
    seed: Option<u64>,

    /// Number of policies in the bundle
    #[arg(long, default_value_t = 250)]
    groups: usize,

    /// Actions generated per policy
    #[arg(long, default_value_t = 4)]
    actions_per_group: usize,

    /// Output path, or "-" for stdout
    #[arg(long, default_value = "-")]
    out: String,
}

fn main() {
    let cli = Cli::parse();
    let seed = cli.seed.unwrap_or_else(random_seed);
    eprintln!("hushspec-gen seed: {seed}");

    let bundle = generate_bundle(
        seed,
        &GenConfig {
            groups: cli.groups,
            actions_per_group: cli.actions_per_group,
        },
    );
    let json = bundle.to_json().expect("bundle serializes");

    if cli.out == "-" {
        println!("{json}");
    } else if let Err(error) = std::fs::write(&cli.out, format!("{json}\n")) {
        eprintln!("error: failed to write {}: {error}", cli.out);
        std::process::exit(2);
    } else {
        eprintln!("wrote {} cases to {}", bundle.case_count(), cli.out);
    }
}
