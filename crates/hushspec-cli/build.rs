//! Build script for the `h2h` binary.
//!
//! Records the build's git SHA and target triple so `h2h version` can report
//! provenance. Both are best-effort: a source tarball (`cargo package`) has no
//! git metadata, and the binary must still build and run there, so a missing
//! SHA is reported as "unknown" at runtime rather than failing the build.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=H2H_GIT_SHA");

    // The target triple is always available to build scripts.
    if let Ok(target) = std::env::var("TARGET") {
        println!("cargo:rustc-env=H2H_BUILD_TARGET={target}");
    }

    if let Some(sha) = git_sha() {
        println!("cargo:rustc-env=H2H_GIT_SHA={sha}");
    }
}

/// Resolve the short git SHA: an externally supplied `H2H_GIT_SHA` wins (CI
/// release builds set it), otherwise ask git, otherwise give up quietly.
fn git_sha() -> Option<String> {
    if let Ok(sha) = std::env::var("H2H_GIT_SHA") {
        let sha = sha.trim().to_string();
        if !sha.is_empty() {
            return Some(sha);
        }
    }

    // Rebuild when HEAD moves, but only if this really is a git checkout.
    // `.git` is a directory in a normal clone and a file in a worktree.
    if let Some(head) = git_head_path() {
        println!("cargo:rerun-if-changed={}", head.display());
    }

    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let sha = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if sha.is_empty() { None } else { Some(sha) }
}

fn git_head_path() -> Option<std::path::PathBuf> {
    let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let git = dir.join(".git");
        if git.is_dir() {
            let head = git.join("HEAD");
            return head.exists().then_some(head);
        }
        if git.is_file() {
            // Worktree: `.git` points at the real git dir. Not worth parsing;
            // the file itself changes rarely, so skip the rerun hint.
            return None;
        }
        if !dir.pop() {
            return None;
        }
    }
}
