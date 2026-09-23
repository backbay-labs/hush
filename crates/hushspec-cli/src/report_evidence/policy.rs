use super::model::*;
use super::snapshot::{Snapshot, SnapshotSet, sha256_bytes};
use super::verify::VerifiedStream;
use hushspec::signing::{Envelope, Keyring, VerifyOptions, verify_policy};
use hushspec::{DecisionReceipt, HushSpec};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub(crate) struct PolicyEvidence {
    pub(crate) spec: Option<HushSpec>,
    pub(crate) source: Option<String>,
    pub(crate) origin_verified: bool,
    pub(crate) origin_basis: Vec<String>,
}

fn artifact<'a>(
    inputs: &'a SnapshotSet,
    reference: &ArtifactRef,
) -> Result<&'a Snapshot, EvidenceError> {
    let source = inputs.artifacts.get(&reference.path).ok_or_else(|| {
        EvidenceError::new(EvidenceCode::Configuration, "missing declared snapshot")
            .at(&reference.path, None)
    })?;
    if source.sha256 != reference.sha256 || sha256_bytes(&source.bytes) != reference.sha256 {
        return Err(EvidenceError::new(
            EvidenceCode::InputDigestMismatch,
            "snapshot does not match declared byte digest",
        )
        .at(&reference.path, None));
    }
    Ok(source)
}

pub(crate) fn load_policies(
    profile: &EvidenceProfile,
    inputs: &SnapshotSet,
    keys: &Keyring,
    clock: &VerifyOptions,
) -> Result<BTreeMap<String, PolicyEvidence>, EvidenceError> {
    let mut policies = BTreeMap::new();
    for declaration in &profile.policies {
        let mut evidence = PolicyEvidence {
            spec: None,
            source: None,
            origin_verified: false,
            origin_basis: Vec::new(),
        };
        if let Some(reference) = &declaration.artifact {
            let source = artifact(inputs, reference)?;
            let text = std::str::from_utf8(&source.bytes).map_err(|_| {
                EvidenceError::new(EvidenceCode::Malformed, "policy is not UTF-8")
                    .at(&reference.path, None)
            })?;
            let spec = HushSpec::parse(text).map_err(|_| {
                EvidenceError::new(EvidenceCode::Malformed, "invalid policy document")
                    .at(&reference.path, None)
            })?;
            if spec.extends.is_some() || !hushspec::validate(&spec).is_valid() {
                return Err(EvidenceError::new(
                    EvidenceCode::PolicyMismatch,
                    "policy must be valid and already resolved without extends",
                )
                .at(&reference.path, None));
            }
            let hash = hushspec::canonical::content_hash(&spec).map_err(|_| {
                EvidenceError::new(EvidenceCode::PolicyMismatch, "cannot canonicalize policy")
            })?;
            if hash != declaration.content_hash {
                return Err(EvidenceError::new(
                    EvidenceCode::PolicyMismatch,
                    "policy canonical identity does not match declaration",
                )
                .at(&reference.path, None));
            }
            evidence.spec = Some(spec);
            evidence.source = Some(reference.path.clone());
            evidence.origin_basis.push(format!(
                "{}: resolved artifact {} ({})",
                declaration.content_hash, reference.path, reference.sha256
            ));
        }
        if let Some(reference) = &declaration.signature {
            let source = artifact(inputs, reference)?;
            let envelope: Envelope = parse_document(&source.bytes, "signature")?;
            if !declaration
                .allowed_signer_key_ids
                .contains(&envelope.key_id)
            {
                return Err(EvidenceError::new(
                    EvidenceCode::UnauthorizedKey,
                    "policy signer is not authorized for this policy",
                )
                .at(&reference.path, None));
            }
            let spec = evidence.spec.as_ref().ok_or_else(|| {
                EvidenceError::new(
                    EvidenceCode::PolicyMismatch,
                    "a policy signature requires its resolved artifact",
                )
            })?;
            verify_policy(&envelope, spec, keys, clock).map_err(|_| {
                EvidenceError::new(
                    EvidenceCode::SignatureInvalid,
                    "policy origin signature verification failed",
                )
                .at(&reference.path, None)
            })?;
            evidence.origin_verified = true;
            evidence.origin_basis.push(format!(
                "{}: signature {} ({}), verified signer {}",
                declaration.content_hash, reference.path, reference.sha256, envelope.key_id
            ));
        }
        if !evidence.origin_verified {
            evidence.origin_basis.push(format!(
                "{}: independent policy origin not established",
                declaration.content_hash
            ));
        }
        if profile.requirements.policy_signatures && !evidence.origin_verified {
            return Err(EvidenceError::new(
                EvidenceCode::SignatureInvalid,
                "required policy origin signature is absent",
            ));
        }
        policies.insert(declaration.content_hash.clone(), evidence);
    }
    Ok(policies)
}

pub(crate) fn load_inventory(
    profile: &EvidenceProfile,
    inputs: &SnapshotSet,
) -> Result<Option<BoundaryInventory>, EvidenceError> {
    match &profile.inventory {
        Some(reference) => {
            let inventory: BoundaryInventory = parse_document(
                &artifact(inputs, reference)?.bytes,
                "evidence-inventory-experimental",
            )?;
            validate_inventory(profile, &inventory)?;
            Ok(Some(inventory))
        }
        None if profile.requirements.boundary_inventory => Err(EvidenceError::new(
            EvidenceCode::BoundaryMismatch,
            "required trusted inventory is absent",
        )),
        None => Ok(None),
    }
}

fn validate_inventory(
    profile: &EvidenceProfile,
    inventory: &BoundaryInventory,
) -> Result<(), EvidenceError> {
    let fail = || {
        EvidenceError::new(
            EvidenceCode::BoundaryMismatch,
            "inventory does not match the declared run, window, streams and ordered files",
        )
    };
    if inventory.run_id != profile.run_id
        || inventory.window != profile.window
        || inventory.streams.len() != profile.streams.len()
    {
        return Err(fail());
    }
    let mut seen = BTreeSet::new();
    for expected in &profile.streams {
        let matched = inventory
            .streams
            .iter()
            .find(|s| s.id == expected.id)
            .ok_or_else(fail)?;
        if !seen.insert(&matched.id)
            || matched.file_sha256s
                != expected
                    .files
                    .iter()
                    .map(|f| f.sha256.clone())
                    .collect::<Vec<_>>()
            || (expected.kind == StreamKind::SignedLog) != matched.log.is_some()
        {
            return Err(fail());
        }
    }
    Ok(())
}

pub(crate) fn entry_positions(stream: &VerifiedStream, inputs: &SnapshotSet) -> Vec<Position> {
    let mut entries = stream.entries.iter();
    let mut positions = Vec::new();
    for file in &stream.spec.files {
        for (index, line) in inputs.artifacts[&file.path]
            .bytes
            .split(|b| *b == b'\n')
            .enumerate()
        {
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            if let Some(entry) = entries.next() {
                positions.push(Position {
                    file_sha256: file.sha256.clone(),
                    line: index + 1,
                    seq: Some(entry.seq),
                });
            }
        }
    }
    positions
}

fn property(status: PropertyStatus, scope: &str, basis: &str) -> PropertyResult {
    PropertyResult {
        status,
        scope: scope.into(),
        basis: vec![basis.into()],
    }
}

pub(crate) fn qualify_stream(
    stream: &VerifiedStream,
    profile: &EvidenceProfile,
    inventory: Option<&BoundaryInventory>,
    inputs: &SnapshotSet,
    keys: &Keyring,
    clock: &VerifyOptions,
) -> Result<StreamResult, EvidenceError> {
    use PropertyStatus::{NotApplicable, NotEstablished, Verified};
    use hushspec::log::PolicyEventKind;
    if profile.requirements.boundary_inventory && inventory.is_none() {
        return Err(EvidenceError::new(
            EvidenceCode::BoundaryMismatch,
            "required trusted inventory is absent",
        ));
    }
    let mut boundary = None;
    if let Some(inventory) = inventory {
        validate_inventory(profile, inventory)?;
        boundary = inventory
            .streams
            .iter()
            .find(|s| s.id == stream.spec.id)
            .and_then(|s| s.log.as_ref());
    }
    let positions = if stream.spec.kind == StreamKind::SignedLog {
        entry_positions(stream, inputs)
    } else {
        stream.positions.clone()
    };
    if let Some(boundary) = boundary {
        let first = stream.entries.first().ok_or_else(|| {
            EvidenceError::new(EvidenceCode::BoundaryMismatch, "anchored log is empty")
        })?;
        let last = stream.entries.last().expect("nonempty log");
        if first.prev_hash != boundary.start_prev_hash
            || last.seq != boundary.end_seq
            || last.entry_hash != boundary.end_entry_hash
            || positions.last().map(|p| &p.file_sha256) != Some(&boundary.end_file_sha256)
        {
            return Err(EvidenceError::new(
                EvidenceCode::BoundaryMismatch,
                "log endpoints do not match trusted inventory",
            ));
        }
    }
    let policies = load_policies(profile, inputs, keys, clock)?;
    let allowed = |hash: &str| {
        stream.spec.allowed_policy_hashes.iter().any(|h| h == hash) && policies.contains_key(hash)
    };
    let mismatch = || {
        EvidenceError::new(
            EvidenceCode::PolicyMismatch,
            "receipt or policy event does not match the authorized policy state",
        )
    };
    let mut state = boundary.and_then(|b| b.initial_policy_hash.clone());
    if state.as_deref().is_some_and(|hash| !allowed(hash)) {
        return Err(mismatch());
    }
    let since = profile
        .window
        .since
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|_| EvidenceError::new(EvidenceCode::Configuration, "invalid window"))?;
    let until = profile
        .window
        .until
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|_| EvidenceError::new(EvidenceCode::Configuration, "invalid window"))?;
    let mut intervals: Vec<(PolicyInterval, Vec<DecisionReceipt>)> = Vec::new();
    let mut open = |hash: &str, position: &Position| {
        intervals.push((
            PolicyInterval {
                policy_content_hash: hash.into(),
                first: position.clone(),
                last: position.clone(),
                receipts: 0,
                controls: None,
            },
            Vec::new(),
        ));
    };
    if let Some(hash) = &state {
        open(hash, positions.first().ok_or_else(mismatch)?);
    }
    // Each item contains either a signed log event/receipt or a standalone receipt.
    let records: Vec<_> = if stream.spec.kind == StreamKind::SignedLog {
        stream
            .entries
            .iter()
            .map(|entry| (entry.policy_event.as_ref(), entry.receipt.as_ref()))
            .collect()
    } else {
        stream
            .receipts
            .iter()
            .map(|receipt| (None, Some(receipt)))
            .collect()
    };
    for ((event, receipt), position) in records.into_iter().zip(&positions) {
        if let Some(event) = event {
            let hash = &event.policy.content_hash;
            if !allowed(hash) {
                return Err(mismatch());
            }
            match event.event {
                PolicyEventKind::Loaded if state.is_none() => {}
                PolicyEventKind::Swapped
                    if state.is_some()
                        && event.previous_content_hash.as_ref() == state.as_ref() => {}
                _ => return Err(mismatch()),
            }
            state = Some(hash.clone());
            intervals.push((
                PolicyInterval {
                    policy_content_hash: hash.clone(),
                    first: position.clone(),
                    last: position.clone(),
                    receipts: 0,
                    controls: None,
                },
                Vec::new(),
            ));
        }
        if let Some(receipt) = receipt {
            let hash = &receipt.policy.content_hash;
            if !allowed(hash) {
                return Err(mismatch());
            }
            if stream.spec.kind == StreamKind::SignedReceipts && state.as_ref() != Some(hash) {
                state = Some(hash.clone());
                intervals.push((
                    PolicyInterval {
                        policy_content_hash: hash.clone(),
                        first: position.clone(),
                        last: position.clone(),
                        receipts: 0,
                        controls: None,
                    },
                    Vec::new(),
                ));
            }
            if state.as_ref() != Some(hash) {
                return Err(mismatch());
            }
            if hushspec::report::in_window(&receipt.timestamp, Some(since), Some(until)) {
                intervals
                    .last_mut()
                    .ok_or_else(mismatch)?
                    .1
                    .push(receipt.clone());
            }
        }
        if let Some((interval, _)) = intervals.last_mut() {
            interval.last = position.clone();
        }
    }
    for (interval, receipts) in &mut intervals {
        interval.receipts = receipts.len() as u64;
        let policy = &policies[&interval.policy_content_hash];
        if let (Some(spec), Some(source)) = (&policy.spec, &policy.source) {
            let report = hushspec::report::build_report(receipts, &[], &Default::default());
            interval.controls = Some(crate::report_controls::build_control_evidence(
                source,
                spec,
                &interval.policy_content_hash,
                &receipts.iter().collect::<Vec<_>>(),
                &report,
            ));
        }
    }
    let log = stream.spec.kind == StreamKind::SignedLog;
    Ok(StreamResult {
        id: stream.spec.id.clone(),
        kind: stream.spec.kind,
        authenticity: property(
            Verified,
            "every supplied record",
            "signatures verified against operator-authorized stream keys",
        ),
        continuity: property(
            if log { Verified } else { NotApplicable },
            "supplied stream endpoints",
            if log {
                "ordered entries and rotation links verified; missing prefix or tail is not excluded"
            } else {
                "standalone receipts have no chain or transition history"
            },
        ),
        completeness: match inventory {
            Some(inventory) => property(
                Verified,
                "declared inventory only, not all action attempts",
                &format!(
                    "operator asserts independent acquisition from {}; exact stream/file inventory and log endpoints match",
                    inventory.acquired_from
                ),
            ),
            None => property(
                NotEstablished,
                "declared run/window",
                "no independent inventory or expected endpoints supplied",
            ),
        },
        policy_binding: property(
            Verified,
            "receipt policy identities",
            if boundary.is_some_and(|b| b.initial_policy_hash.is_some()) {
                "initial state is asserted by matching trusted inventory; signed transitions checked in entry order"
            } else if log {
                "signed policy events establish state in entry order"
            } else {
                "authorized hashes only; no transition history established"
            },
        ),
        policy_origin: PropertyResult {
            status: if stream.spec.allowed_policy_hashes.iter().all(|hash| {
                policies
                    .get(hash)
                    .is_some_and(|policy| policy.origin_verified)
            }) {
                Verified
            } else {
                NotEstablished
            },
            scope: "authorized policies; runtime receipt claims do not establish origin".into(),
            basis: stream
                .spec
                .allowed_policy_hashes
                .iter()
                .filter_map(|hash| policies.get(hash))
                .flat_map(|policy| policy.origin_basis.clone())
                .collect(),
        },
        signatures_verified: stream.signatures_verified,
        first: positions.first().cloned(),
        last: positions.last().cloned(),
        intervals: intervals
            .into_iter()
            .map(|(interval, _)| interval)
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report_evidence::{test_support::*, verify::verify_stream};
    use serde_json::json;

    #[test]
    fn policy_origin_checks_even_an_optional_supplied_signature() {
        let (dir, mut profile, mut inputs, keys, clock) = signed_fixture();
        let bytes = std::fs::read(root().join("fixtures/signing/policies/basic.yaml")).unwrap();
        let signature = std::fs::read(root().join("fixtures/signing/policies/basic.sig")).unwrap();
        let hash = "sha256:386fb3d6955b04d671dd2777c6417bf322489c9e820572993923d5f9e1fa563a";
        profile.policies[0].content_hash = hash.into();
        profile.streams[0].allowed_policy_hashes = vec![hash.into()];
        for (path, data) in [("policy.yaml", bytes), ("policy.sig", signature)] {
            inputs.artifacts.insert(
                path.into(),
                crate::report_evidence::snapshot::Snapshot {
                    path: dir.path().join(path),
                    label: path.into(),
                    sha256: crate::report_evidence::snapshot::sha256_bytes(&data),
                    bytes: data,
                },
            );
        }
        profile.policies[0].artifact = Some(ArtifactRef {
            path: "policy.yaml".into(),
            sha256: inputs.artifacts["policy.yaml"].sha256.clone(),
        });
        profile.policies[0].signature = Some(ArtifactRef {
            path: "policy.sig".into(),
            sha256: inputs.artifacts["policy.sig"].sha256.clone(),
        });
        profile.policies[0].allowed_signer_key_ids =
            profile.streams[0].allowed_signer_key_ids.clone();
        let policies = load_policies(&profile, &inputs, &keys, &clock).unwrap();
        assert!(policies[hash].origin_verified);
        assert!(
            policies[hash]
                .origin_basis
                .iter()
                .any(|basis| basis.contains("policy.sig")
                    && basis.contains(
                        "sha256:1187bb3ca0fd60b25cb90390812fb3a90823466b499e9c29effcc9f3c4ce6142"
                    ))
        );
        profile.policies[0].allowed_signer_key_ids = vec![format!("sha256:{}", "f".repeat(64))];
        assert_eq!(
            load_policies(&profile, &inputs, &keys, &clock)
                .unwrap_err()
                .code,
            EvidenceCode::UnauthorizedKey
        );
        profile.policies[0].allowed_signer_key_ids =
            profile.streams[0].allowed_signer_key_ids.clone();
        let source = inputs.artifacts.get_mut("policy.sig").unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&source.bytes).unwrap();
        value["signature"] = json!("A".repeat(86));
        source.bytes = serde_json::to_vec(&value).unwrap();
        source.sha256 = crate::report_evidence::snapshot::sha256_bytes(&source.bytes);
        profile.policies[0]
            .signature
            .as_mut()
            .unwrap()
            .sha256
            .clone_from(&source.sha256);
        assert_eq!(
            load_policies(&profile, &inputs, &keys, &clock)
                .unwrap_err()
                .code,
            EvidenceCode::SignatureInvalid
        );
        profile.policies[0].signature = None;
        assert!(!load_policies(&profile, &inputs, &keys, &clock).unwrap()[hash].origin_verified);
        profile.requirements.policy_signatures = true;
        assert_eq!(
            load_policies(&profile, &inputs, &keys, &clock)
                .unwrap_err()
                .code,
            EvidenceCode::SignatureInvalid
        );
    }

    fn inventory_for(profile: &EvidenceProfile, inputs: &SnapshotSet) -> BoundaryInventory {
        let documents = log_documents(inputs, "events-1.jsonl");
        let first = documents.first().unwrap();
        let last = documents.last().unwrap();
        BoundaryInventory {
            inventory_version: "0.1.0".into(),
            run_id: profile.run_id.clone(),
            window: profile.window.clone(),
            acquired_from: "independent test checkpoint".into(),
            streams: vec![InventoryStream {
                id: "agent-1".into(),
                file_sha256s: profile.streams[0]
                    .files
                    .iter()
                    .map(|f| f.sha256.clone())
                    .collect(),
                log: Some(LogBoundary {
                    start_prev_hash: first["prev_hash"].as_str().unwrap().into(),
                    initial_policy_hash: None,
                    end_file_sha256: profile.streams[0].files[0].sha256.clone(),
                    end_seq: last["seq"].as_u64().unwrap(),
                    end_entry_hash: last["entry_hash"].as_str().unwrap().into(),
                }),
            }],
        }
    }

    #[test]
    fn inventory_snapshot_is_authenticated_and_detects_an_omitted_stream() {
        let (dir, mut profile, mut inputs, keys, clock) = signed_log_fixture(false);
        let mut inventory = inventory_for(&profile, &inputs);
        for case in ["valid", "missing-stream", "schema", "digest"] {
            if case == "missing-stream" {
                let mut omitted = inventory.streams[0].clone();
                omitted.id = "independently-recorded-agent-2".into();
                inventory.streams.push(omitted);
            } else {
                inventory.streams.truncate(1);
            }
            let mut value = serde_json::to_value(&inventory).unwrap();
            if case == "schema" {
                value["unexpected"] = json!(true);
            }
            let bytes = serde_json::to_vec(&value).unwrap();
            let digest = sha256_bytes(&bytes);
            profile.inventory = Some(ArtifactRef {
                path: "inventory.json".into(),
                sha256: if case == "digest" {
                    format!("sha256:{}", "0".repeat(64))
                } else {
                    digest.clone()
                },
            });
            inputs.artifacts.insert(
                "inventory.json".into(),
                Snapshot {
                    path: dir.path().join("inventory.json"),
                    label: "inventory.json".into(),
                    sha256: digest,
                    bytes,
                },
            );
            let result = crate::report_evidence::verify_evidence(
                &profile,
                &inputs,
                &keys,
                &clock,
                &Limits::default(),
            );
            match case {
                "valid" => assert_eq!(
                    result.unwrap().results[0].completeness.status,
                    PropertyStatus::Verified
                ),
                "missing-stream" => {
                    assert_eq!(result.unwrap_err().code, EvidenceCode::BoundaryMismatch)
                }
                "schema" => assert_eq!(result.unwrap_err().code, EvidenceCode::Malformed),
                _ => assert_eq!(result.unwrap_err().code, EvidenceCode::InputDigestMismatch),
            }
        }
    }

    #[test]
    fn policy_bytes_must_be_resolved_and_match_canonical_identity() {
        let (dir, mut profile, mut inputs, keys, clock) = signed_fixture();
        for text in [
            "hushspec: '1.0.0'\nextends: builtin:default\n",
            "hushspec: '1.0.0'\nname: another-policy\n",
        ] {
            let bytes = text.as_bytes().to_vec();
            let digest = sha256_bytes(&bytes);
            profile.policies[0].artifact = Some(ArtifactRef {
                path: "policy.yaml".into(),
                sha256: digest.clone(),
            });
            inputs.artifacts.insert(
                "policy.yaml".into(),
                Snapshot {
                    path: dir.path().join("policy.yaml"),
                    label: "policy.yaml".into(),
                    sha256: digest,
                    bytes,
                },
            );
            assert_eq!(
                load_policies(&profile, &inputs, &keys, &clock)
                    .unwrap_err()
                    .code,
                EvidenceCode::PolicyMismatch
            );
        }
    }

    #[test]
    fn signed_continuity_does_not_claim_unanchored_completeness() {
        let (_dir, profile, inputs, keys, clock) = signed_log_fixture(true);
        let stream = verify_stream(
            &profile.streams[0],
            &inputs,
            &keys,
            &clock,
            &Limits::default(),
        )
        .unwrap();
        let result = qualify_stream(&stream, &profile, None, &inputs, &keys, &clock).unwrap();
        assert_eq!(result.authenticity.status, PropertyStatus::Verified);
        assert_eq!(result.continuity.status, PropertyStatus::Verified);
        assert_eq!(result.completeness.status, PropertyStatus::NotEstablished);
        assert_eq!(result.policy_origin.status, PropertyStatus::NotEstablished);
        assert_eq!(result.intervals.len(), 1);
        assert_eq!(result.intervals[0].receipts, 2);
    }

    #[test]
    fn a_midstream_prefix_requires_trusted_initial_policy_state() {
        let (_dir, mut profile, inputs, keys, clock) = signed_log_fixture(true);
        let mut original_inventory = inventory_for(&profile, &inputs);
        let documents = log_documents(&inputs, "events-2.jsonl");
        let last = documents.last().unwrap();
        let original_end = original_inventory.streams[0].log.as_mut().unwrap();
        original_end.end_file_sha256 = profile.streams[0].files[1].sha256.clone();
        original_end.end_seq = last["seq"].as_u64().unwrap();
        original_end.end_entry_hash = last["entry_hash"].as_str().unwrap().into();
        profile.streams[0].files.remove(0);
        let stream = verify_stream(
            &profile.streams[0],
            &inputs,
            &keys,
            &clock,
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(
            qualify_stream(&stream, &profile, None, &inputs, &keys, &clock)
                .unwrap_err()
                .code,
            EvidenceCode::PolicyMismatch
        );
        assert_eq!(
            qualify_stream(
                &stream,
                &profile,
                Some(&original_inventory),
                &inputs,
                &keys,
                &clock
            )
            .unwrap_err()
            .code,
            EvidenceCode::BoundaryMismatch
        );
        let mut scoped = original_inventory;
        scoped.streams[0].file_sha256s.remove(0);
        let boundary = scoped.streams[0].log.as_mut().unwrap();
        boundary.start_prev_hash = documents[0]["prev_hash"].as_str().unwrap().into();
        boundary.initial_policy_hash = Some(profile.policies[0].content_hash.clone());
        let qualified =
            qualify_stream(&stream, &profile, Some(&scoped), &inputs, &keys, &clock).unwrap();
        assert_eq!(qualified.completeness.status, PropertyStatus::Verified);
        assert!(
            qualified
                .policy_binding
                .basis
                .iter()
                .any(|basis| basis.contains("inventory"))
        );
    }

    #[test]
    fn same_hash_swaps_open_a_new_interval_without_resetting_history() {
        let (_dir, mut profile, mut inputs, keys, clock) = signed_log_fixture(false);
        let mut documents = log_documents(&inputs, "events-1.jsonl");
        let mut swapped = documents[0].clone();
        swapped["entry_type"] = json!("policy_swapped");
        swapped["policy_event"]["event"] = json!("swapped");
        swapped["policy_event"]["previous_content_hash"] = json!(profile.policies[0].content_hash);
        documents.push(swapped);
        let mut receipt = documents[1].clone();
        receipt["receipt"]["receipt_id"] = json!("01994b7e-2c1a-7c3e-8f4a-0123456789ad");
        documents.push(receipt);
        replace_log(&mut profile, &mut inputs, "events-1.jsonl", &mut documents);
        let stream = verify_stream(
            &profile.streams[0],
            &inputs,
            &keys,
            &clock,
            &Limits::default(),
        )
        .unwrap();
        let qualified = qualify_stream(&stream, &profile, None, &inputs, &keys, &clock).unwrap();
        assert_eq!(qualified.intervals.len(), 2);
        assert_eq!(qualified.intervals[0].receipts, 1);
        assert_eq!(qualified.intervals[1].receipts, 1);
        assert_eq!(qualified.intervals[0].last.seq, Some(2));
        assert_eq!(qualified.intervals[1].first.seq, Some(3));
    }

    #[test]
    fn control_mappings_never_cross_policy_intervals() {
        use crate::report_evidence::snapshot::{Snapshot, sha256_bytes};
        let (dir, mut profile, mut inputs, keys, clock) = signed_log_fixture(false);
        let original = log_documents(&inputs, "events-1.jsonl");
        let mut documents = Vec::new();
        profile.policies.clear();
        profile.streams[0].allowed_policy_hashes.clear();
        let mut previous = None;
        for (index, rule_path) in ["rules.egress", "rules.tool_access"].iter().enumerate() {
            let name = format!("policy-{index}");
            let text = format!(
                "hushspec: '1.0.0'\nname: {name}\nrules:\n  egress:\n    allow: [api.example.com]\n  tool_access:\n    default: block\nmetadata:\n  controls:\n    - framework: pilot\n      control_id: control-{index}\n      rule_paths: [{rule_path}]\n"
            );
            let spec = HushSpec::parse(&text).unwrap();
            let hash = hushspec::canonical::content_hash(&spec).unwrap();
            let path = format!("{name}.yaml");
            let bytes = text.into_bytes();
            let digest = sha256_bytes(&bytes);
            inputs.artifacts.insert(
                path.clone(),
                Snapshot {
                    path: dir.path().join(&path),
                    label: path.clone(),
                    sha256: digest.clone(),
                    bytes,
                },
            );
            profile.policies.push(PolicySpec {
                content_hash: hash.clone(),
                artifact: Some(ArtifactRef {
                    path,
                    sha256: digest,
                }),
                signature: None,
                allowed_signer_key_ids: Vec::new(),
            });
            profile.streams[0].allowed_policy_hashes.push(hash.clone());
            let mut event = original[0].clone();
            event["policy_event"]["policy"]["content_hash"] = json!(hash);
            event["policy_event"]["policy"]["name"] = json!(name);
            event["policy_event"]["policy"]["spec_version"] = json!("1.0.0");
            if let Some(previous) = previous {
                event["entry_type"] = json!("policy_swapped");
                event["policy_event"]["event"] = json!("swapped");
                event["policy_event"]["previous_content_hash"] = json!(previous);
            }
            let mut receipt = original[1].clone();
            receipt["receipt"]["policy"] = event["policy_event"]["policy"].clone();
            receipt["receipt"]["receipt_id"] =
                json!(format!("01994b7e-2c1a-7c3e-8f4a-0123456789a{index}"));
            documents.extend([event, receipt]);
            previous = Some(hash);
        }
        replace_log(&mut profile, &mut inputs, "events-1.jsonl", &mut documents);
        let stream = verify_stream(
            &profile.streams[0],
            &inputs,
            &keys,
            &clock,
            &Limits::default(),
        )
        .unwrap();
        let qualified = qualify_stream(&stream, &profile, None, &inputs, &keys, &clock).unwrap();
        assert_eq!(qualified.intervals.len(), 2);
        for (index, interval) in qualified.intervals.iter().enumerate() {
            let controls = interval.controls.as_ref().unwrap();
            assert_eq!(controls.receipts_matching_policy, 1);
            assert_eq!(
                controls.policy_content_hash,
                profile.policies[index].content_hash
            );
            assert_eq!(
                controls.frameworks[0].controls[0].control_id,
                format!("control-{index}")
            );
        }
        assert_eq!(
            qualified.intervals[0].controls.as_ref().unwrap().frameworks[0].controls[0].receipts,
            1
        );
        assert_eq!(
            qualified.intervals[1].controls.as_ref().unwrap().frameworks[0].controls[0].receipts,
            0
        );
    }

    #[test]
    fn signed_but_invalid_policy_order_is_refused() {
        let (_dir, initial_profile, initial_inputs, keys, clock) = signed_log_fixture(false);
        let original = log_documents(&initial_inputs, "events-1.jsonl");
        let other = format!("sha256:{}", "a".repeat(64));
        for case in [
            "receipt-before-load",
            "wrong-receipt-hash",
            "wrong-predecessor",
            "undeclared-new-policy",
            "repeated-load",
        ] {
            let mut profile = initial_profile.clone();
            let mut inputs = initial_inputs.clone();
            let mut documents = original.clone();
            match case {
                "receipt-before-load" => documents.swap(0, 1),
                "wrong-receipt-hash" => {
                    documents[1]["receipt"]["policy"]["content_hash"] = json!(other)
                }
                "repeated-load" => documents.push(documents[0].clone()),
                _ => {
                    let mut swapped = documents[0].clone();
                    swapped["entry_type"] = json!("policy_swapped");
                    swapped["policy_event"]["event"] = json!("swapped");
                    swapped["policy_event"]["previous_content_hash"] =
                        json!(if case == "wrong-predecessor" {
                            &other
                        } else {
                            &profile.policies[0].content_hash
                        });
                    if case == "undeclared-new-policy" {
                        swapped["policy_event"]["policy"]["content_hash"] = json!(other);
                    }
                    documents.push(swapped);
                }
            }
            replace_log(&mut profile, &mut inputs, "events-1.jsonl", &mut documents);
            let stream = verify_stream(
                &profile.streams[0],
                &inputs,
                &keys,
                &clock,
                &Limits::default(),
            )
            .unwrap();
            assert_eq!(
                qualify_stream(&stream, &profile, None, &inputs, &keys, &clock)
                    .unwrap_err()
                    .code,
                EvidenceCode::PolicyMismatch,
                "{case}"
            );
        }
    }

    #[test]
    fn inventory_verifies_only_matching_scope_and_endpoints() {
        let (_dir, profile, inputs, keys, clock) = signed_log_fixture(false);
        let stream = verify_stream(
            &profile.streams[0],
            &inputs,
            &keys,
            &clock,
            &Limits::default(),
        )
        .unwrap();
        let inventory = inventory_for(&profile, &inputs);
        assert_eq!(
            qualify_stream(&stream, &profile, Some(&inventory), &inputs, &keys, &clock)
                .unwrap()
                .completeness
                .status,
            PropertyStatus::Verified
        );
        for case in ["run", "window", "stream", "file", "prefix", "tail"] {
            let mut invalid = inventory.clone();
            match case {
                "run" => invalid.run_id = "another-run".into(),
                "window" => invalid.window.until = "2026-09-17T00:00:00.000Z".into(),
                "stream" => invalid.streams[0].id = "unlisted-stream".into(),
                "file" => invalid.streams[0].file_sha256s[0] = format!("sha256:{}", "a".repeat(64)),
                "prefix" => {
                    invalid.streams[0].log.as_mut().unwrap().start_prev_hash =
                        format!("sha256:{}", "a".repeat(64))
                }
                "tail" => invalid.streams[0].log.as_mut().unwrap().end_seq += 1,
                _ => unreachable!(),
            }
            assert_eq!(
                qualify_stream(&stream, &profile, Some(&invalid), &inputs, &keys, &clock)
                    .unwrap_err()
                    .code,
                EvidenceCode::BoundaryMismatch,
                "{case}"
            );
        }
        let mut truncated_profile = profile.clone();
        let mut truncated_inputs = inputs.clone();
        let mut documents = log_documents(&inputs, "events-1.jsonl");
        documents.pop();
        replace_log(
            &mut truncated_profile,
            &mut truncated_inputs,
            "events-1.jsonl",
            &mut documents,
        );
        let truncated = verify_stream(
            &truncated_profile.streams[0],
            &truncated_inputs,
            &keys,
            &clock,
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(
            qualify_stream(
                &truncated,
                &truncated_profile,
                None,
                &truncated_inputs,
                &keys,
                &clock
            )
            .unwrap()
            .continuity
            .status,
            PropertyStatus::Verified
        );
        assert_eq!(
            qualify_stream(
                &truncated,
                &truncated_profile,
                Some(&inventory),
                &truncated_inputs,
                &keys,
                &clock
            )
            .unwrap_err()
            .code,
            EvidenceCode::BoundaryMismatch
        );
    }
}
