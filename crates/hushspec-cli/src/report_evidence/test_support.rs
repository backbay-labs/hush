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

pub(crate) fn signed_log_fixture(
    rotated: bool,
) -> (
    tempfile::TempDir,
    EvidenceProfile,
    SnapshotSet,
    Keyring,
    VerifyOptions,
) {
    use hushspec::log::{ChainedFileSink, PolicyEvent};
    use hushspec::receipt::EnforcementMode;
    use hushspec::sink::ReceiptSink;
    let (dir, mut profile, inputs, keys, clock) = signed_fixture();
    let signed: hushspec::signing::SignedReceipt =
        serde_json::from_slice(&inputs.artifacts["evidence.jsonl"].bytes).unwrap();
    let sink = ChainedFileSink::open(dir.path().join("events-1.jsonl"))
        .unwrap()
        .with_clock(clock.now)
        .with_signer(
            hushspec::signing::load_private_key(
                &root().join("fixtures/signing/keys/test-signing.key.pem"),
            )
            .unwrap(),
        );
    let mut event = PolicyEvent::loaded(signed.receipt.policy.clone(), EnforcementMode::Enforce);
    event.timestamp = "2026-09-15T08:00:00.000Z".into();
    sink.record_policy_event(&event).unwrap();
    sink.send(&signed.receipt).unwrap();
    let mut names = vec!["events-1.jsonl"];
    if rotated {
        sink.rotate(dir.path().join("events-2.jsonl")).unwrap();
        let mut receipt = signed.receipt.clone();
        receipt.receipt_id = "01994b7e-2c1a-7c3e-8f4a-0123456789ac".into();
        sink.send(&receipt).unwrap();
        names.push("events-2.jsonl");
    }
    profile.streams[0].kind = StreamKind::SignedLog;
    profile.streams[0].files = names
        .iter()
        .map(|name| ArtifactRef {
            path: (*name).into(),
            sha256: sha256_bytes(&std::fs::read(dir.path().join(name)).unwrap()),
        })
        .collect();
    let inputs = snapshot_profile_inputs(
        &dir.path().join("profile.json"),
        &profile,
        &Limits::default(),
        &mut InputBudget::default(),
    )
    .unwrap();
    (dir, profile, inputs, keys, clock)
}

pub(crate) fn sign_entry_document(document: &mut serde_json::Value) {
    document.as_object_mut().unwrap().remove("entry_hash");
    document.as_object_mut().unwrap().remove("signature");
    let hash = hushspec::canonical::digest(&hushspec::canonical::serialize_jcs(document).unwrap());
    let key = hushspec::signing::load_private_key(
        &root().join("fixtures/signing/keys/test-signing.key.pem"),
    )
    .unwrap();
    let signature = hushspec::signing::sign_content_hash(
        &hash,
        &key,
        &hushspec::signing::SignOptions {
            signed_at: Some("2026-09-15T12:00:00Z".parse().unwrap()),
            ..Default::default()
        },
    )
    .unwrap();
    document["entry_hash"] = hash.into();
    document["signature"] = serde_json::to_value(signature).unwrap();
}

pub(crate) fn log_documents(inputs: &SnapshotSet, path: &str) -> Vec<serde_json::Value> {
    std::str::from_utf8(&inputs.artifacts[path].bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

pub(crate) fn replace_log(
    profile: &mut EvidenceProfile,
    inputs: &mut SnapshotSet,
    path: &str,
    documents: &mut [serde_json::Value],
) {
    let mut previous = hushspec::log::GENESIS_HASH.to_string();
    for (index, document) in documents.iter_mut().enumerate() {
        document["seq"] = (index + 1).into();
        document["prev_hash"] = previous.into();
        sign_entry_document(document);
        previous = document["entry_hash"].as_str().unwrap().into();
    }
    let source = inputs.artifacts.get_mut(path).unwrap();
    source.bytes = documents
        .iter()
        .map(|d| format!("{d}\n"))
        .collect::<String>()
        .into_bytes();
    source.sha256 = sha256_bytes(&source.bytes);
    for stream in &mut profile.streams {
        for file in &mut stream.files {
            if file.path == path {
                file.sha256.clone_from(&source.sha256);
            }
        }
    }
}
