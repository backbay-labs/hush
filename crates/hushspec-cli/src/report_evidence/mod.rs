pub(crate) mod json;
pub(crate) mod model;
pub(crate) mod output;
pub(crate) mod policy;
pub(crate) mod snapshot;
#[cfg(test)]
pub(crate) mod test_support;
pub(crate) mod verify;

use hushspec::signing::{Keyring, VerifyOptions};
use model::*;
use snapshot::SnapshotSet;
use std::collections::BTreeSet;
use verify::VerifiedStream;

#[derive(Debug)]
pub(crate) struct VerifiedEvidence {
    pub(crate) streams: Vec<VerifiedStream>,
    pub(crate) results: Vec<StreamResult>,
}

pub(crate) fn verify_evidence(
    profile: &EvidenceProfile,
    inputs: &SnapshotSet,
    keys: &Keyring,
    clock: &VerifyOptions,
    limits: &Limits,
) -> Result<VerifiedEvidence, EvidenceError> {
    limits.validate()?;
    profile.validate()?;
    if profile.streams.is_empty() || profile.streams.len() > MAX_STREAMS {
        return Err(EvidenceError::new(
            EvidenceCode::Configuration,
            "profile requires between 1 and 64 streams",
        ));
    }
    let inventory = policy::load_inventory(profile, inputs)?;
    let mut count = 0usize;
    let mut file_hashes = BTreeSet::new();
    for stream in &profile.streams {
        for file in &stream.files {
            if !file_hashes.insert(&file.sha256) {
                return Err(EvidenceError::new(
                    EvidenceCode::Configuration,
                    "the same source bytes are declared more than once",
                ));
            }
            let snapshot = inputs.artifacts.get(&file.path).ok_or_else(|| {
                EvidenceError::new(EvidenceCode::Configuration, "missing source snapshot")
            })?;
            count += snapshot
                .bytes
                .split(|b| *b == b'\n')
                .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
                .count();
            if count > MAX_RECORDS {
                return Err(EvidenceError::new(
                    EvidenceCode::LimitExceeded,
                    "all streams together exceed the record limit",
                ));
            }
        }
    }
    let mut evidence = VerifiedEvidence {
        streams: Vec::new(),
        results: Vec::new(),
    };
    let mut receipt_ids = BTreeSet::new();
    for spec in &profile.streams {
        let stream = verify::verify_stream(spec, inputs, keys, clock, limits)?;
        for receipt in &stream.receipts {
            if !receipt_ids.insert(receipt.receipt_id.clone()) {
                return Err(EvidenceError::new(
                    EvidenceCode::DuplicateReceipt,
                    "receipt ID occurs across multiple streams",
                ));
            }
        }
        let result =
            policy::qualify_stream(&stream, profile, inventory.as_ref(), inputs, keys, clock)?;
        evidence.streams.push(stream);
        evidence.results.push(result);
    }
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn independent_streams_have_separate_heads_and_no_shared_receipt_ids() {
        let (_dir, mut profile, mut inputs, keys, clock) = signed_log_fixture(false);
        let mut second = inputs.artifacts["events-1.jsonl"].clone();
        second.label = "other.jsonl".into();
        let mut declaration = profile.streams[0].clone();
        declaration.id = "agent-2".into();
        declaration.files[0].path = second.label.clone();
        profile.streams.push(declaration);
        inputs.artifacts.insert(second.label.clone(), second);
        let mut documents = log_documents(&inputs, "other.jsonl");
        documents[1]["receipt"]["receipt_id"] = "01994b7e-2c1a-7c3e-8f4a-0123456789ad".into();
        replace_log(&mut profile, &mut inputs, "other.jsonl", &mut documents);
        let verified =
            verify_evidence(&profile, &inputs, &keys, &clock, &Limits::default()).unwrap();
        assert_eq!(verified.results.len(), 2);
        assert_ne!(
            verified.results[0].last.as_ref().unwrap().file_sha256,
            verified.results[1].last.as_ref().unwrap().file_sha256
        );
        documents[1]["receipt"]["receipt_id"] = "01994b7e-2c1a-7c3e-8f4a-0123456789ab".into();
        documents[1]["receipt"]["timestamp"] = "2026-09-15T08:30:01.123Z".into();
        replace_log(&mut profile, &mut inputs, "other.jsonl", &mut documents);
        assert_eq!(
            verify_evidence(&profile, &inputs, &keys, &clock, &Limits::default())
                .unwrap_err()
                .code,
            EvidenceCode::DuplicateReceipt
        );
    }

    #[test]
    fn required_inventory_cannot_be_silently_omitted() {
        let (_dir, mut profile, inputs, keys, clock) = signed_fixture();
        profile.requirements.boundary_inventory = true;
        assert_eq!(
            verify_evidence(&profile, &inputs, &keys, &clock, &Limits::default())
                .unwrap_err()
                .code,
            EvidenceCode::BoundaryMismatch
        );
    }
}
