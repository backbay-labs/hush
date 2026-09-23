//! Shared policy-input handling for commands that accept `-` (stdin).
//!
//! `validate`, `lint` and `fmt` all take a list of policy paths; treating `-`
//! as stdin lets them sit in a pipeline (`cat policy.yaml | h2h validate -`)
//! without a temp file. Reading is centralized here so every command reports
//! the same pseudo-path and the same not-found/IO split.

use std::io::Read;
use std::path::Path;

/// The path argument that means "read stdin".
pub(crate) const STDIN_ARG: &str = "-";

/// How stdin is named in diagnostics and machine-readable output.
pub(crate) const STDIN_DISPLAY: &str = "<stdin>";

#[derive(Debug)]
pub(crate) enum ReadError {
    /// The path does not exist (callers map this to exit code 2).
    NotFound,
    /// The file (or stdin) could not be read or was not valid UTF-8.
    Io(String),
}

/// True when this path argument means stdin.
pub(crate) fn is_stdin(path: &Path) -> bool {
    path.as_os_str() == STDIN_ARG
}

/// Display name for a policy path: `<stdin>` for `-`, the path otherwise.
pub(crate) fn display(path: &Path) -> String {
    if is_stdin(path) {
        STDIN_DISPLAY.to_string()
    } else {
        path.display().to_string()
    }
}

/// Read a policy document from `path`, or from stdin when it is `-`.
pub(crate) fn read_policy(path: &Path) -> Result<String, ReadError> {
    if is_stdin(path) {
        let mut buf = String::new();
        return std::io::stdin()
            .read_to_string(&mut buf)
            .map(|_| buf)
            .map_err(|e| ReadError::Io(format!("failed to read stdin: {e}")));
    }

    if !path.exists() {
        return Err(ReadError::NotFound);
    }

    std::fs::read_to_string(path)
        .map_err(|e| ReadError::Io(format!("failed to read {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn dash_is_stdin_but_other_paths_are_not() {
        assert!(is_stdin(&PathBuf::from("-")));
        assert!(!is_stdin(&PathBuf::from("./-")));
        assert!(!is_stdin(&PathBuf::from("policy.yaml")));
    }

    #[test]
    fn display_renames_stdin_only() {
        assert_eq!(display(&PathBuf::from("-")), "<stdin>");
        assert_eq!(display(&PathBuf::from("a/b.yaml")), "a/b.yaml");
    }

    #[test]
    fn missing_file_is_not_found() {
        let err = read_policy(&PathBuf::from("no-such-policy-file.yaml")).unwrap_err();
        assert!(matches!(err, ReadError::NotFound));
    }
}
