use clap::ValueEnum;
use colored::Colorize;

#[derive(clap::Args)]
pub struct VersionArgs {
    /// Output format
    #[arg(short, long, default_value = "text")]
    format: VersionOutputFormat,
}

#[derive(Clone, Copy, ValueEnum)]
enum VersionOutputFormat {
    Text,
    Json,
}

#[derive(serde::Serialize)]
struct VersionInfo {
    /// `h2h` CLI crate version.
    version: &'static str,
    /// Short git SHA of the build, or "unknown" outside a git checkout.
    git_sha: &'static str,
    /// HushSpec version this build writes by default.
    spec_version: &'static str,
    /// Every HushSpec document version this build accepts.
    supported_spec_versions: &'static [&'static str],
    /// Rust target triple the binary was built for.
    target: &'static str,
}

const UNKNOWN: &str = "unknown";

fn info() -> VersionInfo {
    VersionInfo {
        version: env!("CARGO_PKG_VERSION"),
        // build.rs sets H2H_GIT_SHA when git metadata is available; a source
        // tarball build has none, so fall back rather than failing.
        git_sha: option_env!("H2H_GIT_SHA").unwrap_or(UNKNOWN),
        spec_version: hushspec::HUSHSPEC_VERSION,
        supported_spec_versions: hushspec::version::HUSHSPEC_SUPPORTED_VERSIONS,
        target: option_env!("H2H_BUILD_TARGET").unwrap_or(UNKNOWN),
    }
}

pub fn run(args: VersionArgs) -> i32 {
    let info = info();

    match args.format {
        VersionOutputFormat::Json => match serde_json::to_string_pretty(&info) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("{} failed to serialize version info: {e}", "error".red());
                return 1;
            }
        },
        VersionOutputFormat::Text => {
            println!("{} {}", "h2h".bold(), info.version);
            println!("  {} {}", "git sha:".dimmed(), info.git_sha);
            println!("  {} {}", "spec version:".dimmed(), info.spec_version);
            println!(
                "  {} {}",
                "supported spec versions:".dimmed(),
                info.supported_spec_versions.join(", ")
            );
            println!("  {} {}", "target:".dimmed(), info.target);
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::info;

    #[test]
    fn version_info_is_populated() {
        let info = info();
        assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(info.spec_version, hushspec::HUSHSPEC_VERSION);
        assert!(
            info.supported_spec_versions
                .contains(&hushspec::HUSHSPEC_VERSION)
        );
    }
}
