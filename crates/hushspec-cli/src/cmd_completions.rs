use clap::CommandFactory;
use clap_complete::Shell;
use colored::Colorize;
use std::io::Write;

#[derive(clap::Args)]
pub struct CompletionsArgs {
    /// Shell to generate a completion script for
    #[arg(required = true, value_name = "SHELL")]
    shell: Shell,
}

pub fn run(args: CompletionsArgs) -> i32 {
    let mut command = crate::Cli::command();
    let name = command.get_name().to_string();

    // Render into a buffer rather than straight to stdout: completion scripts
    // are big enough to outrun a pipe buffer, and writing directly would panic
    // inside clap_complete on the broken pipe from `h2h completions zsh | head`.
    let mut script: Vec<u8> = Vec::new();
    clap_complete::generate(args.shell, &mut command, name, &mut script);

    let mut stdout = std::io::stdout();
    match stdout.write_all(&script).and_then(|()| stdout.flush()) {
        Ok(()) => 0,
        // A closed downstream pipe is the reader's choice, not an error.
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => 0,
        Err(e) => {
            eprintln!("{} failed to write completion script: {e}", "error".red());
            1
        }
    }
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
