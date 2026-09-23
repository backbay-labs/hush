use super::model::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub(crate) struct Snapshot {
    pub(crate) path: PathBuf,
    pub(crate) label: String,
    pub(crate) sha256: String,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SnapshotSet {
    pub(crate) artifacts: BTreeMap<String, Snapshot>,
}

#[derive(Debug, Default)]
pub(crate) struct InputBudget {
    pub(crate) bytes: u64,
    pub(crate) artifacts: usize,
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub(crate) fn resolve_local(root: &Path, label: &str) -> Result<PathBuf, EvidenceError> {
    local_path(label)?;
    let root = root
        .canonicalize()
        .map_err(|_| EvidenceError::new(EvidenceCode::Io, "cannot resolve input directory"))?;
    let path = root.join(label).canonicalize().map_err(|_| {
        EvidenceError::new(EvidenceCode::Io, "cannot resolve declared artifact").at(label, None)
    })?;
    if !path.starts_with(&root) {
        return Err(EvidenceError::new(
            EvidenceCode::Configuration,
            "artifact escapes its manifest directory",
        )
        .at(label, None));
    }
    Ok(path)
}

pub(crate) fn read_snapshot(
    path: &Path,
    label: &str,
    limits: &Limits,
    budget: &mut InputBudget,
) -> Result<Snapshot, EvidenceError> {
    snapshot_with_handle(path, label, limits, budget).map(|(snapshot, _handle)| snapshot)
}

fn snapshot_with_handle(
    path: &Path,
    label: &str,
    limits: &Limits,
    budget: &mut InputBudget,
) -> Result<(Snapshot, same_file::Handle), EvidenceError> {
    limits.validate()?;
    let fail = |code, message| EvidenceError::new(code, message).at(label, None);
    if budget.artifacts >= MAX_ARTIFACTS {
        return Err(fail(
            EvidenceCode::LimitExceeded,
            "artifact count exceeds operator limit",
        ));
    }
    let path = path
        .canonicalize()
        .map_err(|_| fail(EvidenceCode::Io, "cannot resolve input"))?;
    // Check before open as well: opening a FIFO can otherwise block indefinitely.
    if !path
        .metadata()
        .map_err(|_| fail(EvidenceCode::Io, "cannot inspect input"))?
        .is_file()
    {
        return Err(fail(
            EvidenceCode::Configuration,
            "input is not a regular file",
        ));
    }
    let mut file = File::open(&path).map_err(|_| fail(EvidenceCode::Io, "cannot open input"))?;
    if !file
        .metadata()
        .map_err(|_| fail(EvidenceCode::Io, "cannot inspect opened input"))?
        .is_file()
    {
        return Err(fail(
            EvidenceCode::Configuration,
            "opened input is not a regular file",
        ));
    }
    let remaining = limits
        .total_bytes
        .checked_sub(budget.bytes)
        .ok_or_else(|| {
            fail(
                EvidenceCode::LimitExceeded,
                "total input byte limit exceeded",
            )
        })?;
    let bound = limits.file_bytes.min(remaining);
    let mut bytes = Vec::new();
    (&mut file)
        .take(bound + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| fail(EvidenceCode::Io, "cannot read input"))?;
    if bytes.len() as u64 > bound {
        return Err(fail(
            EvidenceCode::LimitExceeded,
            "file or total input byte limit exceeded",
        ));
    }
    let handle = same_file::Handle::from_file(file)
        .map_err(|_| fail(EvidenceCode::Io, "cannot identify opened input"))?;
    budget.bytes = budget
        .bytes
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| fail(EvidenceCode::LimitExceeded, "input byte count overflow"))?;
    budget.artifacts += 1;
    Ok((
        Snapshot {
            path,
            label: label.into(),
            sha256: sha256_bytes(&bytes),
            bytes,
        },
        handle,
    ))
}

pub(crate) fn snapshot_profile_inputs(
    profile_path: &Path,
    profile: &EvidenceProfile,
    limits: &Limits,
    budget: &mut InputBudget,
) -> Result<SnapshotSet, EvidenceError> {
    let profile_path = profile_path
        .canonicalize()
        .map_err(|_| EvidenceError::new(EvidenceCode::Io, "cannot resolve profile"))?;
    let root = profile_path.parent().ok_or_else(|| {
        EvidenceError::new(
            EvidenceCode::Configuration,
            "profile needs a parent directory",
        )
    })?;
    let mut inputs = SnapshotSet::default();
    let mut identities = HashSet::new();
    for artifact in profile.artifacts() {
        let path = resolve_local(root, &artifact.path)?;
        let (snapshot, identity) = snapshot_with_handle(&path, &artifact.path, limits, budget)?;
        if !identities.insert(identity) || inputs.artifacts.contains_key(&artifact.path) {
            return Err(EvidenceError::new(
                EvidenceCode::Configuration,
                "duplicate physical input or path",
            )
            .at(&artifact.path, None));
        }
        if snapshot.sha256 != artifact.sha256 {
            return Err(EvidenceError::new(
                EvidenceCode::InputDigestMismatch,
                "input byte digest does not match profile",
            )
            .at(&artifact.path, None));
        }
        inputs.artifacts.insert(artifact.path.clone(), snapshot);
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report_evidence::test_support::*;
    use crate::report_evidence::verify::verify_stream;

    #[test]
    fn byte_digest_does_not_normalize_whitespace() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_ne!(sha256_bytes(b"abc"), sha256_bytes(b"abc\n"));
    }

    #[test]
    fn refuses_nonregular_inputs_and_exhausted_artifact_budget() {
        let (dir, profile, _, _, _) = signed_fixture();
        assert_eq!(
            read_snapshot(
                dir.path(),
                "directory",
                &Limits::default(),
                &mut InputBudget::default()
            )
            .unwrap_err()
            .code,
            EvidenceCode::Configuration
        );
        let mut budget = InputBudget {
            bytes: 0,
            artifacts: MAX_ARTIFACTS,
        };
        assert_eq!(
            snapshot_profile_inputs(
                &dir.path().join("profile.json"),
                &profile,
                &Limits::default(),
                &mut budget
            )
            .unwrap_err()
            .code,
            EvidenceCode::LimitExceeded
        );
    }

    #[test]
    fn snapshots_do_not_reopen_replaced_paths() {
        let (dir, profile, inputs, keys, clock) = signed_fixture();
        std::fs::rename(
            dir.path().join("evidence.jsonl"),
            dir.path().join("old.jsonl"),
        )
        .unwrap();
        std::fs::write(dir.path().join("evidence.jsonl"), b"tampered replacement").unwrap();
        assert_eq!(
            verify_stream(
                &profile.streams[0],
                &inputs,
                &keys,
                &clock,
                &Limits::default()
            )
            .unwrap()
            .signatures_verified,
            1
        );
        assert_eq!(
            snapshot_profile_inputs(
                &dir.path().join("profile.json"),
                &profile,
                &Limits::default(),
                &mut InputBudget::default()
            )
            .unwrap_err()
            .code,
            EvidenceCode::InputDigestMismatch
        );
    }

    #[test]
    fn enforces_file_and_shared_total_limits_without_truncation() {
        let (dir, profile, inputs, _, _) = signed_fixture();
        let size = inputs.artifacts["evidence.jsonl"].bytes.len() as u64;
        let path = dir.path().join("profile.json");
        let mut limits = Limits {
            file_bytes: size,
            total_bytes: size,
            line_bytes: 1,
        };
        assert!(
            snapshot_profile_inputs(&path, &profile, &limits, &mut InputBudget::default()).is_ok()
        );
        limits.file_bytes -= 1;
        assert_eq!(
            snapshot_profile_inputs(&path, &profile, &limits, &mut InputBudget::default())
                .unwrap_err()
                .code,
            EvidenceCode::LimitExceeded
        );
        limits.file_bytes = size;
        let mut budget = InputBudget {
            bytes: 1,
            artifacts: 1,
        };
        assert_eq!(
            snapshot_profile_inputs(&path, &profile, &limits, &mut budget)
                .unwrap_err()
                .code,
            EvidenceCode::LimitExceeded
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_escape_and_physical_aliases() {
        use std::os::unix::fs::symlink;
        let (dir, mut profile, _, _, _) = signed_fixture();
        let path = dir.path().join("profile.json");
        let escaped = tempfile::tempdir().unwrap();
        std::fs::copy(
            dir.path().join("evidence.jsonl"),
            escaped.path().join("outside.jsonl"),
        )
        .unwrap();
        symlink(
            escaped.path().join("outside.jsonl"),
            dir.path().join("escape.jsonl"),
        )
        .unwrap();
        profile.streams[0].files[0].path = "escape.jsonl".into();
        assert_eq!(
            snapshot_profile_inputs(
                &path,
                &profile,
                &Limits::default(),
                &mut InputBudget::default()
            )
            .unwrap_err()
            .code,
            EvidenceCode::Configuration
        );
        profile.streams[0].files[0].path = "evidence.jsonl".into();
        symlink(
            dir.path().join("evidence.jsonl"),
            dir.path().join("alias.jsonl"),
        )
        .unwrap();
        let mut alias = profile.streams[0].files[0].clone();
        alias.path = "alias.jsonl".into();
        profile.streams[0].files.push(alias);
        assert_eq!(
            snapshot_profile_inputs(
                &path,
                &profile,
                &Limits::default(),
                &mut InputBudget::default()
            )
            .unwrap_err()
            .code,
            EvidenceCode::Configuration
        );
        std::fs::hard_link(
            dir.path().join("evidence.jsonl"),
            dir.path().join("hard.jsonl"),
        )
        .unwrap();
        profile.streams[0].files[1].path = "hard.jsonl".into();
        assert_eq!(
            snapshot_profile_inputs(
                &path,
                &profile,
                &Limits::default(),
                &mut InputBudget::default()
            )
            .unwrap_err()
            .code,
            EvidenceCode::Configuration
        );
    }
}
