//! The normative signing vectors (signing spec 9, `fixtures/signing/`).
//!
//! An implementation conforms as a verifier if, for every case in
//! `vectors.yaml`, it returns the expected outcome: `valid`, or invalid with
//! the expected reason code of signing spec 6.4. This runner is the Rust
//! side of that conformance statement; the TypeScript, Python, and Go ports
//! walk the same manifest.

#![cfg(feature = "signing")]

use chrono::{DateTime, Utc};
use hushspec::signing::{
    Envelope, Keyring, ReasonCode, SignOptions, VerifyOptions, generate_keypair, load_resolved,
    sign_resolved, verify_content_hash, verify_policy_at,
};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

// --------------------------------------------------------------------------
// The manifest
// --------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    #[serde(rename = "hushspec_signing_vectors")]
    _version: String,
    #[serde(default, rename = "description")]
    _description: Option<String>,
    defaults: Defaults,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Defaults {
    keyring: String,
    now: String,
    max_clock_skew_seconds: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    policy: String,
    signature: String,
    keyring: Option<String>,
    now: Option<String>,
    max_clock_skew_seconds: Option<i64>,
    last_seen_version: Option<u64>,
    expect: Expect,
    #[serde(default, rename = "note")]
    _note: Option<String>,
}

/// `expect: valid`, or `expect: {invalid: <reason code>}`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Expect {
    Valid(ValidMarker),
    Invalid { invalid: String },
}

#[derive(Debug, Deserialize)]
enum ValidMarker {
    #[serde(rename = "valid")]
    Valid,
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/signing")
        .canonicalize()
        .expect("fixtures/signing is readable")
}

fn schemas() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas")
        .canonicalize()
        .expect("schemas/ is readable")
}

fn manifest() -> Manifest {
    let raw = std::fs::read_to_string(fixtures().join("vectors.yaml")).expect("vectors.yaml");
    serde_yaml::from_str(&raw).expect("vectors.yaml parses")
}

fn instant(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .unwrap_or_else(|error| panic!("{value:?} is not a timestamp: {error}"))
        .with_timezone(&Utc)
}

// --------------------------------------------------------------------------
// The conformance run
// --------------------------------------------------------------------------

#[test]
fn every_vector_returns_its_expected_outcome() {
    let root = fixtures();
    let manifest = manifest();
    let mut failures: Vec<String> = Vec::new();

    for case in &manifest.cases {
        let keyring_path = root.join(
            case.keyring
                .as_deref()
                .unwrap_or(&manifest.defaults.keyring),
        );
        let keyring = match Keyring::load(&keyring_path) {
            Ok(keyring) => keyring,
            Err(error) => {
                failures.push(format!("{}: keyring did not load: {error}", case.name));
                continue;
            }
        };

        let options = VerifyOptions {
            now: instant(case.now.as_deref().unwrap_or(&manifest.defaults.now)),
            max_clock_skew_seconds: case
                .max_clock_skew_seconds
                .unwrap_or(manifest.defaults.max_clock_skew_seconds),
            last_seen_version: case.last_seen_version,
        };

        let envelope_text =
            std::fs::read_to_string(root.join(&case.signature)).unwrap_or_else(|error| {
                panic!("{}: {} is unreadable: {error}", case.name, case.signature)
            });

        // A `.sig` that will not even parse is a check-1 failure, reported
        // with the same reason code the verifier would use.
        let outcome = match Envelope::parse(&envelope_text) {
            Ok(envelope) => {
                verify_policy_at(&root.join(&case.policy), &envelope, &keyring, &options)
                    .map(|_| ())
            }
            Err(error) => Err(error),
        };

        let actual = match &outcome {
            Ok(()) => "valid".to_string(),
            Err(error) => error.reason_code().to_string(),
        };
        let expected = match &case.expect {
            Expect::Valid(ValidMarker::Valid) => "valid".to_string(),
            Expect::Invalid { invalid } => invalid.clone(),
        };

        if actual != expected {
            let detail = outcome
                .as_ref()
                .err()
                .map_or_else(String::new, |error| format!(" ({})", error.detail));
            failures.push(format!(
                "{}: expected {expected}, got {actual}{detail}",
                case.name
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "signing vectors failed:\n  {}",
        failures.join("\n  ")
    );
    assert_eq!(
        manifest.cases.len(),
        17,
        "signing spec 9 publishes 17 vectors"
    );
}

/// Every reason code a vector names is one this implementation can produce,
/// so a typo in the manifest cannot pass as a new code.
#[test]
fn every_expected_reason_code_is_in_the_closed_set() {
    let known: BTreeSet<&str> = ReasonCode::ALL.iter().map(ReasonCode::as_str).collect();
    for case in manifest().cases {
        if let Expect::Invalid { invalid } = case.expect {
            assert!(
                known.contains(invalid.as_str()),
                "{}: {invalid} is not a signing spec 6.4 reason code",
                case.name
            );
        }
    }
}

/// The vectors between them exercise every check that can fail in the
/// fixtures' reach; losing one would silently shrink the suite.
#[test]
fn the_vectors_cover_the_reason_codes_they_advertise() {
    let covered: BTreeSet<String> = manifest()
        .cases
        .into_iter()
        .filter_map(|case| match case.expect {
            Expect::Invalid { invalid } => Some(invalid),
            Expect::Valid(_) => None,
        })
        .collect();

    for code in [
        ReasonCode::UnsupportedFormatVersion,
        ReasonCode::UnsupportedAlgorithm,
        ReasonCode::UnknownKeyId,
        ReasonCode::KeyRevoked,
        ReasonCode::KeyRetired,
        ReasonCode::SignedAtInFuture,
        ReasonCode::Expired,
        ReasonCode::SignatureMismatch,
        ReasonCode::ContentHashMismatch,
        ReasonCode::PolicyVersionRollback,
    ] {
        assert!(
            covered.contains(code.as_str()),
            "no vector expects {}",
            code.as_str()
        );
    }
}

/// The `extends-chain-resolved-before-hashing` vector is the one that pins
/// signing spec 3: the envelope covers the merged document, not the child's
/// own file. `extends-child.resolved.json` is what that merge produces.
#[test]
fn the_extends_vector_hashes_the_resolved_document() {
    let root = fixtures();
    let resolved = load_resolved(&root.join("policies/extends-child.yaml"))
        .expect("the child resolves through builtin:default");

    let published: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("policies/extends-child.resolved.json"))
            .expect("the resolved document is published"),
    )
    .expect("it is JSON");

    assert_eq!(
        resolved.content_hash,
        hushspec::content_hash_value(&published).expect("the published document has a hash"),
        "the resolved child must hash to the published resolved document"
    );

    let envelope = Envelope::parse(
        &std::fs::read_to_string(root.join("policies/extends-child.sig")).expect("the envelope"),
    )
    .expect("the envelope parses");
    assert_eq!(envelope.content_hash, resolved.content_hash);

    // The child's own unresolved file hashes to something else entirely.
    let child: serde_json::Value = serde_yaml::from_str(
        &std::fs::read_to_string(root.join("policies/extends-child.yaml")).unwrap(),
    )
    .unwrap();
    assert!(
        hushspec::content_hash_value(&child).is_err(),
        "an unresolved document has no canonical form"
    );
}

// --------------------------------------------------------------------------
// Signing
// --------------------------------------------------------------------------

const APPROVED_POLICY: &str = r#"hushspec: "0.2.0"
name: round-trip
metadata:
  policy_version: 7
  author: security@example.com
rules:
  egress:
    allow:
      - api.example.com
    default: block
"#;

fn write_policy(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("the policy is writable");
    path
}

fn envelope_schema() -> jsonschema::JSONSchema {
    let raw = std::fs::read_to_string(schemas().join("hushspec-signature.v1.schema.json"))
        .expect("the signature schema is published");
    let document: serde_json::Value = serde_json::from_str(&raw).expect("it is JSON");
    jsonschema::JSONSchema::options()
        .should_validate_formats(true)
        .compile(&document)
        .expect("it compiles")
}

fn assert_matches_schema(envelope: &Envelope) {
    let schema = envelope_schema();
    let instance = serde_json::to_value(envelope).expect("an envelope is JSON");
    if let Err(errors) = schema.validate(&instance) {
        let messages: Vec<String> = errors.map(|error| error.to_string()).collect();
        panic!("the envelope does not match the published schema: {messages:?}");
    }
}

#[test]
fn a_freshly_signed_policy_verifies() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let policy = write_policy(dir.path(), "policy.yaml", APPROVED_POLICY);
    let resolved = load_resolved(&policy).expect("the policy resolves");

    let (signing_key, verifying_key) = generate_keypair();
    let envelope = sign_resolved(
        &resolved,
        &signing_key,
        &SignOptions {
            signer: Some("security@example.com".to_string()),
            ..SignOptions::default()
        },
    )
    .expect("signing succeeds");

    assert_matches_schema(&envelope);
    assert_eq!(envelope.format_version, "0.2");
    assert_eq!(envelope.algorithm, "ed25519");
    assert_eq!(envelope.content_hash, resolved.content_hash);
    // Claims copied from the policy (signing spec 4.2 step 2).
    assert_eq!(envelope.policy_name.as_deref(), Some("round-trip"));
    assert_eq!(envelope.policy_version, Some(7));
    assert_eq!(
        envelope.key_id,
        hushspec::signing::key_id(&verifying_key).unwrap()
    );

    let keyring = Keyring::from_verifying_keys([verifying_key]).expect("a one-key keyring");
    let verified = verify_policy_at(&policy, &envelope, &keyring, &VerifyOptions::default())
        .expect("the fresh signature verifies");
    assert_eq!(verified.content_hash, resolved.content_hash);
    assert_eq!(verified.policy_version, Some(7));

    // The `.sig` file round-trips through disk unchanged.
    let sig_path = hushspec::signing::default_signature_path(&policy);
    envelope.save(&sig_path).expect("the envelope is writable");
    assert_eq!(
        Envelope::load(&sig_path).expect("it reads back"),
        envelope.clone()
    );
    assert_eq!(
        hushspec::signing::detached_signature_path(&policy),
        Some(sig_path)
    );
}

#[test]
fn reformatting_a_signed_policy_keeps_its_signature_valid() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let policy = write_policy(dir.path(), "policy.yaml", APPROVED_POLICY);
    let resolved = load_resolved(&policy).expect("the policy resolves");

    let (signing_key, verifying_key) = generate_keypair();
    let envelope =
        sign_resolved(&resolved, &signing_key, &SignOptions::default()).expect("signing succeeds");
    let keyring = Keyring::from_verifying_keys([verifying_key]).expect("a one-key keyring");

    // Same meaning, different bytes: quoting, key order and a comment.
    write_policy(
        dir.path(),
        "policy.yaml",
        "# reordered\nrules:\n  egress:\n    default: block\n    allow: [\"api.example.com\"]\nmetadata:\n  author: \"security@example.com\"\n  policy_version: 7\nname: \"round-trip\"\nhushspec: \"0.2.0\"\n",
    );

    verify_policy_at(&policy, &envelope, &keyring, &VerifyOptions::default())
        .expect("a reformatted policy still verifies");
}

#[test]
fn signing_the_same_inputs_twice_produces_identical_bytes() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let policy = write_policy(dir.path(), "policy.yaml", APPROVED_POLICY);
    let resolved = load_resolved(&policy).expect("the policy resolves");

    let (signing_key, _) = generate_keypair();
    let options = SignOptions {
        signed_at: Some(instant("2026-09-15T09:00:00.000Z")),
        expires_at: Some(instant("2026-12-15T09:00:00.000Z")),
        signer: Some("security@example.com".to_string()),
        ..SignOptions::default()
    };

    let first = sign_resolved(&resolved, &signing_key, &options).expect("signing succeeds");
    let second = sign_resolved(&resolved, &signing_key, &options).expect("signing succeeds");

    // Ed25519 is deterministic and the signing input is canonical, so the
    // whole envelope -- signature included -- is reproducible byte for byte.
    assert_eq!(first, second);
    assert_eq!(first.to_json().unwrap(), second.to_json().unwrap());
    assert_eq!(
        first.signing_input().unwrap(),
        second.signing_input().unwrap()
    );
    assert_matches_schema(&first);
}

#[test]
fn editing_any_claim_invalidates_the_envelope() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let policy = write_policy(dir.path(), "policy.yaml", APPROVED_POLICY);
    let resolved = load_resolved(&policy).expect("the policy resolves");

    let (signing_key, verifying_key) = generate_keypair();
    let envelope = sign_resolved(
        &resolved,
        &signing_key,
        &SignOptions {
            signer: Some("security@example.com".to_string()),
            ..SignOptions::default()
        },
    )
    .expect("signing succeeds");
    let keyring = Keyring::from_verifying_keys([verifying_key]).expect("a one-key keyring");

    let mut edited = envelope.clone();
    edited.signer = Some("attacker@example.com".to_string());
    let error = verify_policy_at(&policy, &edited, &keyring, &VerifyOptions::default())
        .expect_err("an edited claim is not signed");
    assert_eq!(error.reason, ReasonCode::SignatureMismatch);
}

#[test]
fn an_unresolved_document_cannot_be_signed() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let policy = write_policy(
        dir.path(),
        "child.yaml",
        "hushspec: \"0.2.0\"\nname: child\nextends: builtin:default\nrules:\n  egress:\n    default: block\n",
    );
    let unresolved = hushspec::HushSpec::parse(&std::fs::read_to_string(&policy).unwrap()).unwrap();
    let (signing_key, _) = generate_keypair();

    // A signer that cannot resolve the chain MUST refuse to sign
    // (signing spec 3).
    assert!(
        hushspec::signing::sign_policy(&unresolved, &signing_key, &SignOptions::default()).is_err(),
        "a document that still declares extends has no content hash"
    );

    // Resolving first is what a signer does, and that does succeed.
    let resolved = load_resolved(&policy).expect("the chain resolves");
    sign_resolved(&resolved, &signing_key, &SignOptions::default()).expect("the merged doc signs");
}

#[test]
fn a_policy_that_does_not_resolve_is_a_content_hash_mismatch() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let policy = write_policy(dir.path(), "policy.yaml", APPROVED_POLICY);
    let resolved = load_resolved(&policy).expect("the policy resolves");

    let (signing_key, verifying_key) = generate_keypair();
    let envelope =
        sign_resolved(&resolved, &signing_key, &SignOptions::default()).expect("signing succeeds");
    let keyring = Keyring::from_verifying_keys([verifying_key]).expect("a one-key keyring");

    write_policy(dir.path(), "policy.yaml", "hushspec: \"0.2.0\"\nbogus: 1\n");
    let error = verify_policy_at(&policy, &envelope, &keyring, &VerifyOptions::default())
        .expect_err("an unparseable policy has no hash to compare");
    assert_eq!(error.reason, ReasonCode::ContentHashMismatch);

    // Check 9 runs after checks 1-8, so a forged envelope over an
    // unparseable policy is still reported as the forgery it is.
    let (other_key, _) = generate_keypair();
    let forged = sign_resolved(&resolved, &other_key, &SignOptions::default()).unwrap();
    let error = verify_policy_at(&policy, &forged, &keyring, &VerifyOptions::default())
        .expect_err("the forged key is not trusted");
    assert_eq!(error.reason, ReasonCode::UnknownKeyId);
}

#[test]
fn rollback_protection_compares_only_the_numbers() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let policy = write_policy(dir.path(), "policy.yaml", APPROVED_POLICY);
    let resolved = load_resolved(&policy).expect("the policy resolves");

    let (signing_key, verifying_key) = generate_keypair();
    let keyring = Keyring::from_verifying_keys([verifying_key]).expect("a one-key keyring");
    let envelope =
        sign_resolved(&resolved, &signing_key, &SignOptions::default()).expect("signing succeeds");
    assert_eq!(envelope.policy_version, Some(7));

    for (last_seen, expected) in [
        (Some(6), true),
        (Some(7), true),
        (Some(8), false),
        (None, true),
    ] {
        let options = VerifyOptions {
            last_seen_version: last_seen,
            ..VerifyOptions::default()
        };
        let outcome =
            verify_content_hash(&envelope, Some(&resolved.content_hash), &keyring, &options);
        assert_eq!(
            outcome.is_ok(),
            expected,
            "last_seen_version {last_seen:?} should {} an envelope at version 7",
            if expected { "accept" } else { "reject" }
        );
        if !expected {
            assert_eq!(
                outcome.unwrap_err().reason,
                ReasonCode::PolicyVersionRollback
            );
        }
    }
}
