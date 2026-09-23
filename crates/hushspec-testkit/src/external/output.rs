//! Private staging and exclusive atomic publication of complete packets.
use super::{model::Artifact, snapshot::snapshot_file};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

pub struct Packet {
    pub root: PathBuf,
    artifacts: BTreeMap<String, Artifact>,
}
impl Packet {
    pub fn new(root: PathBuf) -> Result<Self, String> {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&root).map_err(|e| e.to_string())?;
        Ok(Self {
            root,
            artifacts: BTreeMap::new(),
        })
    }
    pub fn put(&mut self, path: &str, bytes: &[u8]) -> Result<Artifact, String> {
        if path.is_empty()
            || !Path::new(path)
                .components()
                .all(|c| matches!(c, Component::Normal(_)))
            || path.contains('\\')
        {
            return Err("invalid packet artifact path".into());
        }
        let destination = self.root.join(path);
        std::fs::create_dir_all(destination.parent().ok_or("missing artifact parent")?)
            .map_err(|e| e.to_string())?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&destination).map_err(|e| e.to_string())?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        let artifact = Artifact {
            path: path.into(),
            sha256: crate::manifest::digest_bytes(bytes),
            bytes: bytes.len(),
        };
        self.artifacts.insert(path.into(), artifact.clone());
        Ok(artifact)
    }
    pub fn verify(&self) -> Result<(), String> {
        for artifact in self.artifacts.values() {
            let snapshot = snapshot_file(
                &self.root.join(&artifact.path),
                &artifact.path,
                artifact.bytes,
            )?;
            if snapshot.bytes.len() != artifact.bytes || snapshot.sha256 != artifact.sha256 {
                return Err(format!("staged artifact changed: {}", artifact.path));
            }
        }
        Ok(())
    }
    pub fn publish(self, out: &Path) -> Result<(), String> {
        sync_directories(&self.root)?;
        let directory = File::open(&self.root).map_err(|e| e.to_string())?;
        rename_exclusive(&self.root, out)?;
        let parent = out.parent().ok_or("missing output parent")?;
        if let Err(error) = File::open(parent).and_then(|f| f.sync_all()) {
            // Revoke completion through the still-owned directory inode, not a
            // possibly replaced output pathname, before attempting rollback.
            #[cfg(target_os = "linux")]
            {
                use std::os::fd::AsRawFd;
                use std::os::unix::fs::MetadataExt;
                // SAFETY: live owned directory fd and fixed NUL-terminated name.
                unsafe {
                    libc::unlinkat(directory.as_raw_fd(), c"execution.json".as_ptr(), 0);
                }
                if let (Ok(ours), Ok(current)) =
                    (directory.metadata(), std::fs::symlink_metadata(out))
                    && ours.dev() == current.dev()
                    && ours.ino() == current.ino()
                {
                    let _ = rename_exclusive(out, &self.root);
                }
            }
            return Err(format!("output directory sync failed: {error}"));
        }
        Ok(())
    }
}

fn sync_directories(path: &Path) -> Result<(), String> {
    for entry in std::fs::read_dir(path).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            sync_directories(&entry.path())?;
        }
    }
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}

#[cfg(target_os = "linux")]
fn rename_exclusive(from: &Path, to: &Path) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let from = CString::new(from.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let to = CString::new(to.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    // SAFETY: both path strings are live. RENAME_NOREPLACE never replaces an
    // existing destination, including empty directories or dangling symlinks.
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } < 0
    {
        return Err(format!(
            "exclusive packet publication failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn rename_exclusive(_from: &Path, _to: &Path) -> Result<(), String> {
    Err("external publication currently requires Linux".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn publication_failure_does_not_overwrite_or_leave_a_completion_marker() {
        let dir = tempfile::tempdir().unwrap();
        let mut packet = Packet::new(dir.path().join("staged")).unwrap();
        packet.put("inputs/one", b"one").unwrap();
        assert!(packet.put("inputs/one/child", b"failure").is_err());
        assert!(!packet.root.join("execution.json").exists());
        let out = dir.path().join("existing");
        std::fs::create_dir(&out).unwrap();
        std::fs::write(out.join("sentinel"), b"keep").unwrap();
        packet.put("execution.json", b"{}").unwrap();
        assert!(packet.publish(&out).is_err());
        assert_eq!(std::fs::read(out.join("sentinel")).unwrap(), b"keep");
        assert!(!out.join("execution.json").exists());
    }
}
