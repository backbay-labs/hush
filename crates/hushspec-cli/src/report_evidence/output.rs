use super::model::{EvidenceCode, EvidenceError};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

pub(crate) struct OutputArtifact {
    pub(crate) path: PathBuf,
    pub(crate) bytes: Vec<u8>,
}

fn io_error(_: std::io::Error) -> EvidenceError {
    EvidenceError::new(EvidenceCode::Io, "cannot stage or publish output")
}

fn targets(artifacts: &[&OutputArtifact]) -> Result<(PathBuf, Vec<PathBuf>), EvidenceError> {
    let mut directory = None;
    let mut seen = BTreeSet::new();
    let mut paths = Vec::new();
    for artifact in artifacts {
        let conflict = || {
            EvidenceError::new(
                EvidenceCode::OutputConflict,
                "outputs require distinct new files in one existing directory",
            )
        };
        let parent = artifact
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = parent.canonicalize().map_err(|_| conflict())?;
        if !parent.is_dir() || directory.as_ref().is_some_and(|dir| *dir != parent) {
            return Err(conflict());
        }
        let name = artifact.path.file_name().ok_or_else(conflict)?;
        let path = parent.join(name);
        match path.symlink_metadata() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(conflict()),
        }
        if !seen.insert(path.clone()) {
            return Err(conflict());
        }
        directory = Some(parent);
        paths.push(path);
    }
    Ok((directory.expect("completion artifact required"), paths))
}

pub(crate) fn publish_outputs(
    data: &[OutputArtifact],
    completion: &OutputArtifact,
) -> Result<(), EvidenceError> {
    publish_with(data, completion, || Ok(()))
}

pub(crate) fn reject_input_paths(outputs: &[&Path], inputs: &[&Path]) -> Result<(), EvidenceError> {
    for path in outputs {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = parent.canonicalize().map_err(|_| {
            EvidenceError::new(EvidenceCode::OutputConflict, "output parent must exist")
        })?;
        let name = path.file_name().ok_or_else(|| {
            EvidenceError::new(EvidenceCode::OutputConflict, "output requires a filename")
        })?;
        if inputs.iter().any(|input| **input == parent.join(name)) {
            return Err(EvidenceError::new(
                EvidenceCode::OutputConflict,
                "output aliases an input snapshot",
            ));
        }
    }
    Ok(())
}

fn publish_with(
    data: &[OutputArtifact],
    completion: &OutputArtifact,
    before_completion: impl FnOnce() -> Result<(), EvidenceError>,
) -> Result<(), EvidenceError> {
    let artifacts: Vec<_> = data.iter().chain(std::iter::once(completion)).collect();
    let (directory, paths) = targets(&artifacts)?;
    let mut staged = Vec::new();
    for artifact in artifacts {
        let mut file = tempfile::NamedTempFile::new_in(&directory).map_err(io_error)?;
        file.write_all(&artifact.bytes).map_err(io_error)?;
        file.as_file().sync_all().map_err(io_error)?;
        staged.push(file);
    }
    let completion_file = staged.pop().expect("completion is staged last");
    let mut published: Vec<(PathBuf, same_file::Handle)> = Vec::new();
    let result = (|| {
        for (file, path) in staged.into_iter().zip(&paths) {
            // Capture identity before publishing so rollback never removes a replacement.
            let identity =
                same_file::Handle::from_file(file.reopen().map_err(io_error)?).map_err(io_error)?;
            file.persist_noclobber(path)
                .map_err(|error| publication_error(error.error))?;
            published.push((path.clone(), identity));
        }
        #[cfg(unix)]
        std::fs::File::open(&directory)
            .and_then(|file| file.sync_all())
            .map_err(io_error)?;
        before_completion()?;
        completion_file
            .persist_noclobber(paths.last().expect("completion path"))
            .map_err(|error| publication_error(error.error))?;
        // No fallible operation after the completion marker becomes visible.
        Ok(())
    })();
    if result.is_err() {
        for (path, identity) in published {
            if same_file::Handle::from_path(&path).is_ok_and(|current| current == identity) {
                let _ = std::fs::remove_file(path);
            }
        }
    }
    result
}

fn publication_error(error: std::io::Error) -> EvidenceError {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        EvidenceError::new(
            EvidenceCode::OutputConflict,
            "output appeared during publication",
        )
    } else {
        io_error(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removed_input_path_cannot_be_reused_as_an_output() {
        let dir = tempfile::tempdir().unwrap();
        let captured = dir.path().join("input.json");
        assert_eq!(
            reject_input_paths(&[&captured], &[&captured])
                .unwrap_err()
                .code,
            EvidenceCode::OutputConflict
        );
    }

    #[test]
    fn preexisting_second_target_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let first = OutputArtifact {
            path: dir.path().join("report.json"),
            bytes: b"new report".to_vec(),
        };
        let completion = OutputArtifact {
            path: dir.path().join("verification.json"),
            bytes: b"new sidecar".to_vec(),
        };
        std::fs::write(&completion.path, b"existing").unwrap();
        assert_eq!(
            publish_outputs(&[first], &completion).unwrap_err().code,
            EvidenceCode::OutputConflict
        );
        assert_eq!(std::fs::read(&completion.path).unwrap(), b"existing");
        assert!(!dir.path().join("report.json").exists());
    }

    #[test]
    fn recoverable_failure_removes_only_outputs_owned_by_this_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let data = OutputArtifact {
            path: dir.path().join("report.json"),
            bytes: b"report".to_vec(),
        };
        let completion = OutputArtifact {
            path: dir.path().join("verification.json"),
            bytes: b"sidecar".to_vec(),
        };
        std::fs::write(dir.path().join("unrelated"), b"keep").unwrap();
        let result = publish_with(&[data], &completion, || {
            Err(EvidenceError::new(
                EvidenceCode::Io,
                "injected sync failure",
            ))
        });
        assert_eq!(result.unwrap_err().code, EvidenceCode::Io);
        assert!(!dir.path().join("report.json").exists());
        assert!(!completion.path.exists());
        assert_eq!(
            std::fs::read(dir.path().join("unrelated")).unwrap(),
            b"keep"
        );
    }
}
