use super::model::*;
use super::snapshot::*;
use hushspec::signing::{Keyring, VerifyOptions};
use std::path::PathBuf;

pub(crate) fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub(crate) fn signed_fixture() -> (
    tempfile::TempDir,
    EvidenceProfile,
    SnapshotSet,
    Keyring,
    VerifyOptions,
) {
    let dir = tempfile::tempdir().unwrap();
    let signed: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root().join("fixtures/receipts/signed/valid/allow-egress.signed.json"))
            .unwrap(),
    )
    .unwrap();
    let bytes = format!("{signed}\n").into_bytes();
    std::fs::write(dir.path().join("evidence.jsonl"), &bytes).unwrap();
    let mut profile = parse_profile(
        &std::fs::read(root().join("fixtures/assurance/profile-shape.json")).unwrap(),
    )
    .unwrap();
    profile.streams[0].files[0].sha256 = sha256_bytes(&bytes);
    let path = dir.path().join("profile.json");
    std::fs::write(&path, serde_json::to_vec(&profile).unwrap()).unwrap();
    let inputs = snapshot_profile_inputs(
        &path,
        &profile,
        &Limits::default(),
        &mut InputBudget::default(),
    )
    .unwrap();
    let keys = Keyring::load(&root().join("fixtures/signing/keys/keyring.json")).unwrap();
    let clock = VerifyOptions {
        now: "2026-09-15T12:00:00Z".parse().unwrap(),
        ..VerifyOptions::default()
    };
    (dir, profile, inputs, keys, clock)
}

pub(crate) fn replace_source(
    profile: &mut EvidenceProfile,
    inputs: &mut SnapshotSet,
    bytes: Vec<u8>,
) {
    let source = inputs.artifacts.get_mut("evidence.jsonl").unwrap();
    source.bytes = bytes;
    source.sha256 = sha256_bytes(&source.bytes);
    profile.streams[0].files[0].sha256 = source.sha256.clone();
}
