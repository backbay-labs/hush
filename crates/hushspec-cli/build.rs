//! Build script for the `h2h` binary.
//!
//! Records the build's git SHA and target triple so `h2h version` can report
//! provenance. Both are best-effort: a source tarball (`cargo package`) has no
//! git metadata, and the binary must still build and run there, so a missing
//! SHA is reported as "unknown" at runtime rather than failing the build.

use std::path::{Path, PathBuf};
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

/// Resolve the git SHA: an externally supplied `H2H_GIT_SHA` wins, otherwise
/// ask git for the short SHA, otherwise give up quietly.
fn git_sha() -> Option<String> {
    if let Ok(sha) = std::env::var("H2H_GIT_SHA") {
        let sha = sha.trim().to_string();
        if !sha.is_empty() {
            return Some(sha);
        }
    }

    watch_head();

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

/// Ask Cargo to rerun this script whenever the commit under HEAD changes.
///
/// `HEAD` on its own is not enough. A checkout that stays on one branch keeps
/// the same `ref: refs/heads/<branch>` line as commits land, so watching only
/// `HEAD` freezes the reported SHA at whatever it was when the script last
/// ran. What moves is the branch's own ref file, or `packed-refs` when the
/// branch tip is packed. A detached HEAD holds the commit id itself, so there
/// `HEAD` is the whole story.
///
/// Every step is best-effort and silent: a checkout with no git metadata must
/// still build.
fn watch_head() {
    let Some(git_dir) = git_dir() else {
        return;
    };
    let head = git_dir.join("HEAD");
    let Ok(contents) = std::fs::read_to_string(&head) else {
        return;
    };
    watch(&head);

    let Some(reference) = contents.trim().strip_prefix("ref:") else {
        return;
    };
    let reference = reference.trim();
    if reference.is_empty() {
        return;
    }

    // A per-worktree ref lives in that worktree's git directory; a branch lives
    // in the shared one, loose or packed.
    let common_dir = common_dir(&git_dir);
    watch(&git_dir.join(reference));
    watch(&common_dir.join(reference));
    watch(&common_dir.join("packed-refs"));
    // Updating a packed branch can create a loose ref without changing HEAD
    // or packed-refs. Watch the ref tree so that creation invalidates the build.
    watch(&common_dir.join("refs"));
}

/// Watch a path that may not exist: a path Cargo cannot stat counts as
/// changed, which would rerun this script on every build.
fn watch(path: &Path) {
    if path.exists() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

/// The git directory for this checkout: `.git` itself in a normal clone, and
/// the directory named by the `gitdir:` line when `.git` is the file a linked
/// worktree carries.
fn git_dir() -> Option<PathBuf> {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let git = dir.join(".git");
        if git.is_dir() {
            return Some(git);
        }
        if git.is_file() {
            let contents = std::fs::read_to_string(&git).ok()?;
            let target = PathBuf::from(contents.trim().strip_prefix("gitdir:")?.trim());
            return Some(absolute(&dir, target));
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// The directory holding `refs/` and `packed-refs`. A linked worktree's git
/// directory names the shared one in its `commondir` file; everywhere else the
/// git directory is its own common directory.
fn common_dir(git_dir: &Path) -> PathBuf {
    match std::fs::read_to_string(git_dir.join("commondir")) {
        Ok(contents) => absolute(git_dir, PathBuf::from(contents.trim())),
        Err(_) => git_dir.to_path_buf(),
    }
}

/// Resolve `path` against `base` when it is relative, tidying the result when
/// the filesystem allows it.
fn absolute(base: &Path, path: PathBuf) -> PathBuf {
    let joined = if path.is_absolute() {
        path
    } else {
        base.join(path)
    };
    std::fs::canonicalize(&joined).unwrap_or(joined)
}
