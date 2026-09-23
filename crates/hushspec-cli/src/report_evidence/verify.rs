use super::json::parse_json;
use super::model::*;
use super::snapshot::{SnapshotSet, sha256_bytes};
use hushspec::signing::{Keyring, SignedReceipt, VerifyOptions, verify_receipt};
use std::collections::BTreeSet;

#[derive(Debug)]
pub(crate) struct VerifiedStream {
    pub(crate) spec: StreamSpec,
    pub(crate) entries: Vec<hushspec::log::LogEntry>,
    pub(crate) receipts: Vec<hushspec::DecisionReceipt>,
    pub(crate) positions: Vec<Position>,
    pub(crate) signatures_verified: u64,
}

pub(crate) fn verify_stream(
    stream: &StreamSpec,
    inputs: &SnapshotSet,
    keys: &Keyring,
    clock: &VerifyOptions,
    limits: &Limits,
) -> Result<VerifiedStream, EvidenceError> {
    limits.validate()?;
    let receipt_schema = crate::cmd_log::receipt_schema().map_err(|_| {
        EvidenceError::new(EvidenceCode::Configuration, "cannot compile receipt schema")
    })?;
    let signature_schema = schema_validator("signature")?;
    let log_schema = schema_validator("log-entry")?;
    let mut verified = VerifiedStream {
        spec: stream.clone(),
        entries: Vec::new(),
        receipts: Vec::new(),
        positions: Vec::new(),
        signatures_verified: 0,
    };
    let mut ids = BTreeSet::new();
    for artifact in &stream.files {
        let source = inputs.artifacts.get(&artifact.path).ok_or_else(|| {
            EvidenceError::new(
                EvidenceCode::Configuration,
                "declared source was not snapshotted",
            )
            .at(&artifact.path, None)
        })?;
        if sha256_bytes(&source.bytes) != artifact.sha256 || source.sha256 != artifact.sha256 {
            return Err(EvidenceError::new(
                EvidenceCode::InputDigestMismatch,
                "snapshot digest does not match profile",
            )
            .at(&artifact.path, None));
        }
        let mut file_records = 0;
        for (index, line) in source.bytes.split(|byte| *byte == b'\n').enumerate() {
            let line_no = index + 1;
            let fail =
                |code, message| EvidenceError::new(code, message).at(&artifact.path, Some(line_no));
            if line.len() as u64 > limits.line_bytes {
                return Err(fail(
                    EvidenceCode::LimitExceeded,
                    "JSONL line byte limit exceeded",
                ));
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            if verified.receipts.len().max(verified.entries.len()) >= MAX_RECORDS {
                return Err(fail(
                    EvidenceCode::LimitExceeded,
                    "record count limit exceeded",
                ));
            }
            let value = parse_json(line, MAX_DEPTH)
                .map_err(|error| error.at(&artifact.path, Some(line_no)))?;
            if stream.kind == StreamKind::SignedLog {
                if !log_schema.is_valid(&value)
                    || value
                        .get("receipt")
                        .is_some_and(|receipt| !receipt_schema.is_valid(receipt))
                {
                    return Err(fail(
                        EvidenceCode::Malformed,
                        "log entry or embedded receipt does not match its schema",
                    ));
                }
                let entry: hushspec::log::LogEntry = serde_json::from_value(value)
                    .map_err(|_| fail(EvidenceCode::Malformed, "invalid log entry"))?;
                let signature = entry.signature.as_ref().ok_or_else(|| {
                    fail(
                        EvidenceCode::SignatureInvalid,
                        "every log entry requires a signature",
                    )
                })?;
                if !stream.allowed_signer_key_ids.contains(&signature.key_id) {
                    return Err(fail(
                        EvidenceCode::UnauthorizedKey,
                        "entry signer is not authorized for this stream",
                    ));
                }
                if let Some(receipt) = &entry.receipt {
                    verified.receipts.push(receipt.clone());
                    verified.positions.push(Position {
                        file_sha256: source.sha256.clone(),
                        line: line_no,
                        seq: Some(entry.seq),
                    });
                }
                verified.entries.push(entry);
                file_records += 1;
                continue;
            }
            let receipt = value.get("receipt").ok_or_else(|| {
                fail(
                    EvidenceCode::Malformed,
                    "expected a signed receipt envelope",
                )
            })?;
            let signature = value.get("signature").ok_or_else(|| {
                fail(
                    EvidenceCode::Malformed,
                    "expected a signed receipt envelope",
                )
            })?;
            if !receipt_schema.is_valid(receipt) || !signature_schema.is_valid(signature) {
                return Err(fail(
                    EvidenceCode::Malformed,
                    "receipt or signature does not match its schema",
                ));
            }
            let signed: SignedReceipt = serde_json::from_value(value)
                .map_err(|_| fail(EvidenceCode::Malformed, "invalid signed receipt envelope"))?;
            if !stream
                .allowed_signer_key_ids
                .contains(&signed.signature.key_id)
            {
                return Err(fail(
                    EvidenceCode::UnauthorizedKey,
                    "signer is not authorized for this stream",
                ));
            }
            verify_receipt(&signed, keys, clock).map_err(|_| {
                fail(
                    EvidenceCode::SignatureInvalid,
                    "receipt signature verification failed",
                )
            })?;
            if !ids.insert(signed.receipt.receipt_id.clone()) {
                return Err(fail(
                    EvidenceCode::DuplicateReceipt,
                    "receipt ID occurs more than once",
                ));
            }
            verified.receipts.push(signed.receipt);
            verified.positions.push(Position {
                file_sha256: source.sha256.clone(),
                line: line_no,
                seq: None,
            });
            verified.signatures_verified += 1;
            file_records += 1;
        }
        if file_records == 0 {
            return Err(EvidenceError::new(
                EvidenceCode::Malformed,
                "declared source contains no records",
            )
            .at(&artifact.path, None));
        }
    }
    if verified.receipts.is_empty() && verified.entries.is_empty() {
        return Err(EvidenceError::new(
            EvidenceCode::Malformed,
            "declared stream contains no records",
        ));
    }
    if stream.kind == StreamKind::SignedLog {
        let texts = stream
            .files
            .iter()
            .map(|artifact| {
                let text =
                    std::str::from_utf8(&inputs.artifacts[&artifact.path].bytes).map_err(|_| {
                        EvidenceError::new(EvidenceCode::Malformed, "log is not UTF-8")
                            .at(&artifact.path, None)
                    })?;
                Ok((artifact.path.as_str(), text))
            })
            .collect::<Result<Vec<_>, EvidenceError>>()?;
        let report = hushspec::log::verify_logs(
            &texts,
            &hushspec::log::LogVerifyOptions {
                require_signatures: true,
                keyring: Some(keys.clone()),
                verify: Some(clock.clone()),
            },
        )
        .map_err(|error| {
            let code = if error.message.starts_with("signature:")
                || error.message.starts_with("signature.content_hash")
            {
                EvidenceCode::SignatureInvalid
            } else {
                EvidenceCode::ChainInvalid
            };
            EvidenceError::new(code, "ordered signed log verification failed")
                .at(error.file, Some(error.line))
        })?;
        verified.signatures_verified = report.verified_signatures as u64;
        for receipt in &verified.receipts {
            if !ids.insert(receipt.receipt_id.clone()) {
                return Err(EvidenceError::new(
                    EvidenceCode::DuplicateReceipt,
                    "receipt ID occurs more than once in stream",
                ));
            }
        }
    }
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report_evidence::test_support::*;
    use serde_json::json;

    #[test]
    fn valid_signed_receipt_preserves_its_original_record() {
        let (_dir, profile, inputs, keys, clock) = signed_fixture();
        let verified = verify_stream(
            &profile.streams[0],
            &inputs,
            &keys,
            &clock,
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(verified.signatures_verified, 1);
        assert_eq!(verified.receipts.len(), 1);
        assert_eq!(
            verified.receipts[0].action.target.as_deref(),
            Some("api.example.com")
        );
        assert_eq!(verified.positions[0].line, 1);
        assert!(verified.entries.is_empty());
    }

    #[test]
    fn tampered_envelope_cannot_be_counted() {
        let (_dir, mut profile, mut inputs, keys, clock) = signed_fixture();
        let mut value: serde_json::Value =
            serde_json::from_slice(&inputs.artifacts["evidence.jsonl"].bytes).unwrap();
        value["receipt"]["action"]["target"] = "evil.example".into();
        replace_source(&mut profile, &mut inputs, format!("{value}\n").into_bytes());
        assert_eq!(
            verify_stream(
                &profile.streams[0],
                &inputs,
                &keys,
                &clock,
                &Limits::default()
            )
            .unwrap_err()
            .code,
            EvidenceCode::SignatureInvalid
        );
    }

    #[test]
    fn refuses_unsigned_mixed_ambiguous_and_repeated_records() {
        let (_dir, initial_profile, initial_inputs, keys, clock) = signed_fixture();
        let value: serde_json::Value =
            serde_json::from_slice(&initial_inputs.artifacts["evidence.jsonl"].bytes).unwrap();
        let mut altered = value.clone();
        altered["signature"]["signature"] = json!("A".repeat(86));
        let mut outside = value.clone();
        outside["receipt"]["timestamp"] = json!("2026-09-17T00:00:00.000Z");
        outside["receipt"]["receipt_id"] = json!("01994b7e-2c1a-7c3e-8f4a-0123456789ac");
        for (bytes, code) in [
            (
                format!("{}\n", value["receipt"]).into_bytes(),
                EvidenceCode::Malformed,
            ),
            (
                format!("{altered}\n").into_bytes(),
                EvidenceCode::SignatureInvalid,
            ),
            (
                format!("{value}\n{outside}\n").into_bytes(),
                EvidenceCode::SignatureInvalid,
            ),
            (
                format!("{value}\n{{\"log_version\":\"0.1\"}}\n").into_bytes(),
                EvidenceCode::Malformed,
            ),
            (
                format!("{value}\n{value}\n").into_bytes(),
                EvidenceCode::DuplicateReceipt,
            ),
            (b"  \r\n\n".to_vec(), EvidenceCode::Malformed),
            (b"\xff".to_vec(), EvidenceCode::Malformed),
            (
                format!("{{\"receipt\":null,{}", &value.to_string()[1..]).into_bytes(),
                EvidenceCode::Malformed,
            ),
        ] {
            let mut profile = initial_profile.clone();
            let mut inputs = initial_inputs.clone();
            replace_source(&mut profile, &mut inputs, bytes);
            assert_eq!(
                verify_stream(
                    &profile.streams[0],
                    &inputs,
                    &keys,
                    &clock,
                    &Limits::default()
                )
                .unwrap_err()
                .code,
                code
            );
        }
    }

    #[test]
    fn trust_requires_both_the_stream_role_and_a_current_key() {
        let (_dir, mut profile, inputs, keys, clock) = signed_fixture();
        profile.streams[0].allowed_signer_key_ids = vec![format!("sha256:{}", "f".repeat(64))];
        assert_eq!(
            verify_stream(
                &profile.streams[0],
                &inputs,
                &keys,
                &clock,
                &Limits::default()
            )
            .unwrap_err()
            .code,
            EvidenceCode::UnauthorizedKey
        );
        let (_dir, profile, inputs, _, clock) = signed_fixture();
        for name in ["keyring-revoked.json", "keyring-retired.json"] {
            let keys = Keyring::load(&root().join("fixtures/signing/keys").join(name)).unwrap();
            assert_eq!(
                verify_stream(
                    &profile.streams[0],
                    &inputs,
                    &keys,
                    &clock,
                    &Limits::default()
                )
                .unwrap_err()
                .code,
                EvidenceCode::SignatureInvalid
            );
        }
        let keys = Keyring::from_public_key_pem(
            &std::fs::read_to_string(root().join("fixtures/signing/keys/test-untrusted.pub.pem"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_stream(
                &profile.streams[0],
                &inputs,
                &keys,
                &clock,
                &Limits::default()
            )
            .unwrap_err()
            .code,
            EvidenceCode::SignatureInvalid
        );
    }

    #[test]
    fn line_limit_applies_even_to_blank_lines() {
        let (_dir, mut profile, mut inputs, keys, clock) = signed_fixture();
        replace_source(&mut profile, &mut inputs, b"     \n".to_vec());
        let limits = Limits {
            line_bytes: 4,
            ..Limits::default()
        };
        assert_eq!(
            verify_stream(&profile.streams[0], &inputs, &keys, &clock, &limits)
                .unwrap_err()
                .code,
            EvidenceCode::LimitExceeded
        );
    }

    #[test]
    fn signed_rotations_require_the_declared_order() {
        let (_dir, profile, inputs, keys, clock) = signed_log_fixture(true);
        let verified = verify_stream(
            &profile.streams[0],
            &inputs,
            &keys,
            &clock,
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(verified.entries.len(), 4);
        assert_eq!(verified.signatures_verified, 4);
        assert_eq!(verified.receipts.len(), 2);
        assert_eq!(verified.positions[1].seq, Some(2));
        assert_eq!(
            verified.positions[1].file_sha256,
            profile.streams[0].files[1].sha256
        );
        let mut reversed = profile.streams[0].clone();
        reversed.files.reverse();
        assert_eq!(
            verify_stream(&reversed, &inputs, &keys, &clock, &Limits::default())
                .unwrap_err()
                .code,
            EvidenceCode::ChainInvalid
        );
        let mut duplicate = profile.streams[0].clone();
        duplicate.files.push(duplicate.files[1].clone());
        assert_eq!(
            verify_stream(&duplicate, &inputs, &keys, &clock, &Limits::default())
                .unwrap_err()
                .code,
            EvidenceCode::ChainInvalid
        );
    }

    #[test]
    fn unrelated_signed_logs_are_not_one_continuation() {
        let (_dir, mut profile, mut inputs, keys, clock) = signed_log_fixture(false);
        let mut second = inputs.artifacts["events-1.jsonl"].clone();
        second.label = "unrelated.jsonl".into();
        profile.streams[0].files.push(ArtifactRef {
            path: second.label.clone(),
            sha256: second.sha256.clone(),
        });
        inputs.artifacts.insert(second.label.clone(), second);
        assert_eq!(
            verify_stream(
                &profile.streams[0],
                &inputs,
                &keys,
                &clock,
                &Limits::default()
            )
            .unwrap_err()
            .code,
            EvidenceCode::ChainInvalid
        );
    }

    #[test]
    fn a_missing_middle_rotation_breaks_the_chain() {
        use crate::report_evidence::snapshot::InputBudget;
        use crate::report_evidence::snapshot::read_snapshot;
        use hushspec::log::ChainedFileSink;
        let (dir, mut profile, mut inputs, keys, clock) = signed_log_fixture(true);
        let sink = ChainedFileSink::open(dir.path().join("events-2.jsonl"))
            .unwrap()
            .with_clock(clock.now)
            .with_signer(
                hushspec::signing::load_private_key(
                    &root().join("fixtures/signing/keys/test-signing.key.pem"),
                )
                .unwrap(),
            );
        sink.rotate(dir.path().join("events-3.jsonl")).unwrap();
        let third = read_snapshot(
            &dir.path().join("events-3.jsonl"),
            "events-3.jsonl",
            &Limits::default(),
            &mut InputBudget::default(),
        )
        .unwrap();
        profile.streams[0].files.push(ArtifactRef {
            path: third.label.clone(),
            sha256: third.sha256.clone(),
        });
        inputs.artifacts.insert(third.label.clone(), third);
        assert!(
            verify_stream(
                &profile.streams[0],
                &inputs,
                &keys,
                &clock,
                &Limits::default()
            )
            .is_ok()
        );
        profile.streams[0].files.remove(1);
        assert_eq!(
            verify_stream(
                &profile.streams[0],
                &inputs,
                &keys,
                &clock,
                &Limits::default()
            )
            .unwrap_err()
            .code,
            EvidenceCode::ChainInvalid
        );
    }

    #[test]
    fn every_log_entry_requires_an_authorized_signature() {
        let (_dir, mut profile, mut inputs, keys, clock) = signed_log_fixture(false);
        profile.streams[0].allowed_signer_key_ids = vec![format!("sha256:{}", "f".repeat(64))];
        assert_eq!(
            verify_stream(
                &profile.streams[0],
                &inputs,
                &keys,
                &clock,
                &Limits::default()
            )
            .unwrap_err()
            .code,
            EvidenceCode::UnauthorizedKey
        );
        let (_dir, original, _, _, _) = signed_fixture();
        profile.streams[0].allowed_signer_key_ids =
            original.streams[0].allowed_signer_key_ids.clone();
        let mut documents = log_documents(&inputs, "events-1.jsonl");
        documents[0].as_object_mut().unwrap().remove("signature");
        let bytes = documents
            .iter()
            .map(|d| format!("{d}\n"))
            .collect::<String>()
            .into_bytes();
        let source = inputs.artifacts.get_mut("events-1.jsonl").unwrap();
        source.sha256 = sha256_bytes(&bytes);
        source.bytes = bytes;
        profile.streams[0].files[0]
            .sha256
            .clone_from(&source.sha256);
        assert_eq!(
            verify_stream(
                &profile.streams[0],
                &inputs,
                &keys,
                &clock,
                &Limits::default()
            )
            .unwrap_err()
            .code,
            EvidenceCode::SignatureInvalid
        );
    }
}
