//! Capture bounded regular-file bytes once, then work only from those bytes.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};

use super::{json, model::MIB};
use crate::manifest::{MANIFEST_FILE, MANIFEST_VERSION, Manifest, digest_bytes};

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub label: String,
    pub bytes: Vec<u8>,
    pub sha256: String,
    identity: (u64, u64),
}

impl Snapshot {
    pub(crate) fn identity(&self) -> (u64, u64) {
        self.identity
    }
}

#[derive(Debug)]
pub struct CorpusSnapshot {
    pub manifest: Manifest,
    pub manifest_snapshot: Snapshot,
    pub files: BTreeMap<String, Snapshot>,
}

#[derive(Clone, Copy)]
pub struct CorpusLimits {
    pub file_bytes: usize,
    pub total_bytes: usize,
    pub entries: usize,
}
impl Default for CorpusLimits {
    fn default() -> Self {
        Self {
            file_bytes: 16 * MIB,
            total_bytes: 64 * MIB,
            entries: 4096,
        }
    }
}

pub fn valid_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// Every pathname component is opened relative to the preceding directory fd.
// This prevents a directory replacement from inserting a symlink after checks.
#[cfg(target_os = "linux")]
fn open_regular(path: &Path) -> Result<File, String> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    let mut dir = File::open("/").map_err(|e| e.to_string())?;
    let components: Vec<_> = absolute
        .components()
        .filter(|c| !matches!(c, Component::RootDir | Component::CurDir))
        .collect();
    if components.is_empty() {
        return Err("not a regular file".into());
    }
    for (index, part) in components.iter().enumerate() {
        let name = CString::new(part.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | if index + 1 < components.len() {
                libc::O_DIRECTORY
            } else {
                0
            };
        // SAFETY: directory fd and NUL-terminated name are live; success owns a new fd.
        let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(format!(
                "{}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: successful openat returned a unique owned fd.
        dir = unsafe { File::from_raw_fd(fd) };
    }
    Ok(dir)
}

#[cfg(not(target_os = "linux"))]
fn open_regular(_path: &Path) -> Result<File, String> {
    Err("external conformance snapshots currently require Linux".into())
}

fn capture(mut file: File, label: &str, limit: usize) -> Result<Snapshot, String> {
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(format!("{label}: not a bounded regular file"));
    }
    #[cfg(unix)]
    let identity = {
        use std::os::unix::fs::MetadataExt;
        (metadata.dev(), metadata.ino())
    };
    #[cfg(not(unix))]
    let identity = (0, 0);
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err(format!("{label}: file size limit exceeded"));
    }
    let sha256 = digest_bytes(&bytes);
    Ok(Snapshot {
        label: label.into(),
        bytes,
        sha256,
        identity,
    })
}

pub fn snapshot_file(path: &Path, label: &str, limit: usize) -> Result<Snapshot, String> {
    capture(open_regular(path)?, label, limit)
}

pub fn snapshot_controller() -> Result<Snapshot, String> {
    #[cfg(target_os = "linux")]
    {
        capture(
            File::open("/proc/self/exe").map_err(|e| e.to_string())?,
            "controller",
            256 * MIB,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("external conformance currently requires Linux".into())
    }
}

fn fixture_relative(label: &str) -> Result<&str, String> {
    let relative = label
        .strip_prefix("fixtures/")
        .ok_or_else(|| format!("invalid fixture path {label}"))?;
    if relative.is_empty()
        || relative.contains('\\')
        || relative
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err(format!("invalid fixture path {label}"));
    }
    Ok(relative)
}

fn inventory(
    root: &Path,
    relative: &Path,
    found: &mut BTreeSet<String>,
    visited: &mut usize,
) -> Result<(), String> {
    *visited += 1;
    if *visited > 8192 || relative.components().count() > 64 {
        return Err("corpus tree limit exceeded".into());
    }
    let path = root.join(relative);
    if std::fs::symlink_metadata(&path)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_symlink()
    {
        return Err(format!("symlink input {}", path.display()));
    }
    for entry in std::fs::read_dir(path).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let child = relative.join(entry.file_name());
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        if kind.is_dir() {
            inventory(root, &child, found, visited)?;
        } else if kind.is_file() {
            let label = child.to_str().ok_or("non UTF-8 fixture path")?;
            if label != MANIFEST_FILE {
                found.insert(format!("fixtures/{label}"));
            }
            *visited += 1;
            if *visited > 8192 {
                return Err("corpus tree limit exceeded".into());
            }
        } else {
            return Err(format!("nonregular corpus input {}", child.display()));
        }
    }
    Ok(())
}

pub fn snapshot_corpus(root: &Path) -> Result<CorpusSnapshot, String> {
    snapshot_corpus_with_limits(root, CorpusLimits::default())
}

pub fn snapshot_corpus_with_limits(
    root: &Path,
    limits: CorpusLimits,
) -> Result<CorpusSnapshot, String> {
    let manifest_snapshot =
        snapshot_file(&root.join(MANIFEST_FILE), "fixtures/MANIFEST.json", 8 * MIB)?;
    let manifest: Manifest = serde_json::from_value(json::parse_json(&manifest_snapshot.bytes)?)
        .map_err(|e| e.to_string())?;
    if manifest.manifest_version != MANIFEST_VERSION
        || manifest.files.is_empty()
        || manifest.files.len() > limits.entries
    {
        return Err("unsupported, empty or oversized fixture manifest".into());
    }
    let mut files = BTreeMap::new();
    let mut identities = BTreeSet::from([manifest_snapshot.identity]);
    let mut total = 0usize;
    for entry in &manifest.files {
        let relative = fixture_relative(&entry.path)?;
        if relative == MANIFEST_FILE
            || files.contains_key(&entry.path)
            || !valid_digest(&entry.sha256)
            || entry.level > 5
        {
            return Err(format!(
                "invalid or duplicate manifest entry {}",
                entry.path
            ));
        }
        if !matches!(
            entry.category.as_str(),
            "bundle"
                | "canonical"
                | "doc"
                | "evaluation"
                | "expect"
                | "integration"
                | "invalid"
                | "library-suite"
                | "log"
                | "log-schema"
                | "merge"
                | "raw-yaml"
                | "receipt"
                | "receipt-expected"
                | "receipt-signed"
                | "report"
                | "resolve"
                | "signing"
                | "valid"
        ) {
            return Err(format!("unknown corpus category {}", entry.category));
        }
        let snapshot = snapshot_file(&root.join(relative), &entry.path, limits.file_bytes)?;
        total = total
            .checked_add(snapshot.bytes.len())
            .ok_or("corpus byte count overflow")?;
        if total > limits.total_bytes {
            return Err("corpus total size limit exceeded".into());
        }
        if snapshot.sha256 != entry.sha256 {
            return Err(format!("fixture digest mismatch {}", entry.path));
        }
        if !identities.insert(snapshot.identity) {
            return Err(format!("physical input alias {}", entry.path));
        }
        files.insert(entry.path.clone(), snapshot);
    }
    let mut found = BTreeSet::new();
    inventory(root, Path::new(""), &mut found, &mut 0)?;
    if found != files.keys().cloned().collect() {
        return Err("unlisted or missing corpus files".into());
    }
    Ok(CorpusSnapshot {
        manifest,
        manifest_snapshot,
        files,
    })
}

/// Supported-image check, not a sandbox or a claim about program honesty.
pub fn validate_engine_image(bytes: &[u8]) -> Result<(), String> {
    let reject =
        || "engine must be a static ELF executable without PT_INTERP/PT_DYNAMIC".to_string();
    if bytes.get(..4) != Some(b"\x7fELF") || bytes.get(6) != Some(&1) {
        return Err(reject());
    }
    let little = match bytes.get(5) {
        Some(1) => true,
        Some(2) => false,
        _ => return Err(reject()),
    };
    let word = |offset: usize, len: usize| -> Result<u64, String> {
        let slice = bytes
            .get(offset..offset.checked_add(len).ok_or_else(reject)?)
            .ok_or_else(reject)?;
        let mut result = 0u64;
        if little {
            for (i, b) in slice.iter().enumerate() {
                result |= u64::from(*b) << (8 * i);
            }
        } else {
            for b in slice {
                result = (result << 8) | u64::from(*b);
            }
        }
        Ok(result)
    };
    if !matches!(word(16, 2)?, 2 | 3) {
        return Err(reject());
    }
    let (offset, stride, count, min) = match bytes.get(4) {
        Some(1) => (word(28, 4)?, word(42, 2)?, word(44, 2)?, 32),
        Some(2) => (word(32, 8)?, word(54, 2)?, word(56, 2)?, 56),
        _ => return Err(reject()),
    };
    if stride < min || count == 0 || count > 4096 {
        return Err(reject());
    }
    for index in 0..count {
        let pos = offset
            .checked_add(index.checked_mul(stride).ok_or_else(reject)?)
            .ok_or_else(reject)?;
        let end = pos.checked_add(stride).ok_or_else(reject)?;
        if end > bytes.len() as u64 || matches!(word(pos as usize, 4)?, 2 | 3) {
            return Err(reject());
        }
    }
    Ok(())
}
