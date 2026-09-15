use clap::CommandFactory;
use clap_complete::Shell;

#[derive(clap::Args)]
pub struct CompletionsArgs {
    /// Shell to generate a completion script for
    #[arg(required = true, value_name = "SHELL")]
    shell: Shell,
}

pub fn run(args: CompletionsArgs) -> i32 {
    let mut command = crate::Cli::command();
    let name = command.get_name().to_string();
    clap_complete::generate(args.shell, &mut command, name, &mut std::io::stdout());
    0
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;
    use clap_complete::Shell;

    #[test]
    fn every_shell_generates_a_non_empty_script() {
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Elvish,
        ] {
            let mut command = crate::Cli::command();
            let mut buf: Vec<u8> = Vec::new();
            clap_complete::generate(shell, &mut command, "h2h", &mut buf);
            let script = String::from_utf8(buf).expect("completion script should be UTF-8");
            assert!(!script.is_empty(), "{shell} produced an empty script");
            assert!(
                script.contains("h2h"),
                "{shell} script does not mention the binary name"
            );
        }
    }
}
