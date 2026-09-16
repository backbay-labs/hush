//! The normative policy-bundle vectors (bundle spec 7, `fixtures/bundle/`).
//!
//! An implementation conforms as a bundle verifier if, for every case in
//! `vectors.yaml`, it returns the expected outcome: `valid`, or invalid with
//! the expected reason code of bundle spec 5.4.

#![cfg(feature = "signing")]

use hushspec::bundle::{
    BundleOptions, BundleReason, DsseEnvelope, VerifyBundleOptions, build_statement,
    sign_statement, unsigned_envelope, verify_bundle,
};
use hushspec::resolve::{Resolution, ResolveError, ResolveOptions, resolve_path_with_options};
use hushspec::signing::{Keyring, generate_keypair};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

// --------------------------------------------------------------------------
// The manifest
// --------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    #[serde(rename = "hushspec_bundle_vectors")]
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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    bundle: String,
    keyring: Option<String>,
    policy: Option<String>,
    now: Option<String>,
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
        .join("../../fixtures/bundle")
        .canonicalize()
        .expect("fixtures/bundle is readable")
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

fn instant(value: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(value)
        .unwrap_or_else(|error| panic!("{value:?} is not a timestamp: {error}"))
        .with_timezone(&chrono::Utc)
}

/// Resolve a policy the way `h2h bundle verify --policy` does.
fn resolve(path: &Path) -> Result<Resolution, ResolveError> {
    resolve_path_with_options(path, &ResolveOptions::default())
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

        let options = VerifyBundleOptions {
            now: instant(case.now.as_deref().unwrap_or(&manifest.defaults.now)),
        };

        let text = std::fs::read_to_string(root.join(&case.bundle)).unwrap_or_else(|error| {
            panic!("{}: {} is unreadable: {error}", case.name, case.bundle)
        });

        // Check 4's input. A case that names a policy names one the suite can
        // resolve: an unresolvable one would report `policy_mismatch` whatever
        // the bundle said, so the case would pass without testing anything.
        let resolution = match case.policy.as_deref() {
            None => None,
            Some(policy) => match resolve(&root.join(policy)) {
                Ok(resolution) => Some(resolution),
                Err(error) => {
                    failures.push(format!("{}: {policy} did not resolve: {error}", case.name));
                    continue;
                }
            },
        };

        let outcome = match DsseEnvelope::parse(&text) {
            Ok(envelope) => {
                verify_bundle(&envelope, &keyring, resolution.as_ref(), &options).map(|_| ())
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
        "bundle vectors failed:\n  {}",
        failures.join("\n  ")
    );
    assert_eq!(
        manifest.cases.len(),
        10,
        "bundle spec 7 publishes 10 vectors"
    );
}

/// Every reason code a vector names is one this implementation can produce,
/// so a typo in the manifest cannot pass as a new code.
#[test]
fn every_expected_reason_code_is_in_the_closed_set() {
    let known: BTreeSet<&str> = BundleReason::ALL.iter().map(BundleReason::as_str).collect();
    for case in manifest().cases {
        if let Expect::Invalid { invalid } = case.expect {
            assert!(
                known.contains(invalid.as_str()),
                "{}: {invalid} is not a bundle spec 5.4 reason code",
                case.name
            );
        }
    }
}

/// Between them the vectors exercise every check that can fail; losing one
/// would silently shrink the suite.
#[test]
fn the_vectors_cover_every_reason_code() {
    let covered: BTreeSet<String> = manifest()
        .cases
        .into_iter()
        .filter_map(|case| match case.expect {
            Expect::Invalid { invalid } => Some(invalid),
            Expect::Valid(_) => None,
        })
        .collect();

    for reason in BundleReason::ALL {
        assert!(
            covered.contains(reason.as_str()),
            "no vector expects {}",
            reason.as_str()
        );
    }
}

// --------------------------------------------------------------------------
// The published schema
// --------------------------------------------------------------------------

fn bundle_schema() -> serde_json::Value {
    let raw = std::fs::read_to_string(schemas().join("hushspec-bundle.v1.schema.json"))
        .expect("the bundle schema is published");
    serde_json::from_str(&raw).expect("it is JSON")
}

fn compile(schema: &serde_json::Value) -> jsonschema::JSONSchema {
    jsonschema::JSONSchema::options()
        .should_validate_formats(true)
        .compile(schema)
        .expect("the schema compiles")
}

/// `#/$defs/Statement` as a schema in its own right: the definitions come
/// along so its internal `#/$defs/...` refs still resolve.
fn statement_schema() -> jsonschema::JSONSchema {
    let document = bundle_schema();
    let mut statement_document = document["$defs"]["Statement"].clone();
    statement_document["$schema"] = document["$schema"].clone();
    statement_document["$defs"] = document["$defs"].clone();
    compile(&statement_document)
}

/// Every vector -- valid or not -- is a well-formed DSSE envelope, and every
/// vector whose statement is meant to be readable validates against
/// `#/$defs/Statement`.
#[test]
fn every_vector_validates_against_the_published_schema() {
    let envelope_schema = compile(&bundle_schema());
    let statement_schema = statement_schema();

    let root = fixtures();
    for case in manifest().cases {
        let path = root.join(&case.bundle);
        let raw = std::fs::read_to_string(&path).expect("the bundle is readable");
        let instance: serde_json::Value = serde_json::from_str(&raw).expect("it is JSON");
        if let Err(errors) = envelope_schema.validate(&instance) {
            let messages: Vec<String> = errors.map(|error| error.to_string()).collect();
            panic!(
                "{}: envelope does not match the schema: {messages:?}",
                case.name
            );
        }

        // The malformed vector is malformed *as a statement*: it is the one
        // case whose payload deliberately fails this.
        let payload = instance["payload"].as_str().expect("payload is a string");
        let bytes = base64_decode(payload);
        let statement: serde_json::Value =
            serde_json::from_slice(&bytes).expect("the payload is JSON");
        let outcome = statement_schema.validate(&statement);
        let expected_valid = case.name != "malformed-predicate-type";
        assert_eq!(
            outcome.is_ok(),
            expected_valid,
            "{}: statement schema validation should {}",
            case.name,
            if expected_valid { "pass" } else { "fail" }
        );
    }
}

/// Standard base64 with padding, without pulling the `base64` crate into the
/// test's own dependency set.
fn base64_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes().filter(|byte| *byte != b'=') {
        let value = ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .unwrap_or_else(|| panic!("{byte:?} is not base64")) as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    out
}

// --------------------------------------------------------------------------
// Bundling
// --------------------------------------------------------------------------

fn hipaa_base() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../library/healthcare/hipaa-base.yaml")
        .canonicalize()
        .expect("the library policy is readable")
}

/// A 0.x policy that declares `name: ""`, which the frozen 0.x format admits.
fn empty_name_policy() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/core/valid/empty-name-0-2.yaml")
        .canonicalize()
        .expect("the fixture is readable")
}

/// The `created_at` the bundle vectors pin, reused so these bundles are
/// byte-reproducible too.
const PINNED_CREATED_AT: &str = "2026-09-15T12:00:00.000Z";

/// An empty name is a name the bundle schema will not accept: both
/// `subject[0].name` and `predicate.policy.name` need a character. The subject
/// falls through to the leaf file name and the policy claim is left out
/// altogether.
#[test]
fn a_policy_with_an_empty_name_bundles_under_its_file_name() {
    let resolution = resolve(&empty_name_policy()).expect("the fixture resolves");
    let statement = build_statement(
        &resolution,
        &BundleOptions {
            created_at: Some(instant(PINNED_CREATED_AT)),
            ..BundleOptions::default()
        },
    )
    .expect("the statement builds");

    assert_eq!(statement.subject[0].name, "empty-name-0-2.yaml");
    assert_eq!(statement.predicate.policy.name, None);

    // Absent, not present and empty: read off the payload bytes rather than
    // the typed statement, because it is the serialized form the schema and
    // every other verifier see.
    let payload: serde_json::Value =
        serde_json::from_slice(&statement.to_canonical_bytes().expect("canonical bytes"))
            .expect("the payload is JSON");
    assert!(
        !payload["predicate"]["policy"]
            .as_object()
            .expect("policy is an object")
            .contains_key("name")
    );
    if let Err(errors) = statement_schema().validate(&payload) {
        let messages: Vec<String> = errors.map(|error| error.to_string()).collect();
        panic!("the statement does not match the schema: {messages:?}");
    }

    let (signing_key, verifying_key) = generate_keypair();
    let envelope = sign_statement(&statement, &signing_key).expect("it signs");
    let keyring = Keyring::from_verifying_keys([verifying_key]).expect("a one-key keyring");
    let verified = verify_bundle(
        &envelope,
        &keyring,
        Some(&resolution),
        &VerifyBundleOptions {
            now: instant(PINNED_CREATED_AT),
        },
    )
    .expect("the bundle verifies");
    assert_eq!(verified.subject_name, "empty-name-0-2.yaml");
    assert_eq!(verified.policy_name, None);
    assert!(verified.policy_checked);
}

/// An override is a choice the caller makes, and an empty string is not one:
/// it falls through to the policy's own name rather than producing a subject
/// the schema rejects.
#[test]
fn an_empty_subject_name_override_falls_through_to_the_policy_name() {
    let resolution = resolve(&hipaa_base()).expect("the library policy resolves");
    let statement = build_statement(
        &resolution,
        &BundleOptions {
            created_at: Some(instant(PINNED_CREATED_AT)),
            subject_name: Some(String::new()),
            ..BundleOptions::default()
        },
    )
    .expect("the statement builds");

    assert_eq!(statement.subject[0].name, "hipaa-base");
}

#[test]
fn a_freshly_built_bundle_verifies() {
    let resolution = resolve(&hipaa_base()).expect("the library policy resolves");
    let (signing_key, verifying_key) = generate_keypair();

    let statement =
        build_statement(&resolution, &BundleOptions::default()).expect("the statement builds");
    let envelope = sign_statement(&statement, &signing_key).expect("it signs");

    // The subject digest is the content hash without its prefix.
    assert_eq!(
        statement.subject[0].digest.sha256,
        resolution.content_hash.trim_start_matches("sha256:")
    );
    assert_eq!(
        statement.predicate.policy.content_hash,
        resolution.content_hash
    );
    assert_eq!(statement.predicate.chain.len(), resolution.chain.len());

    let keyring = Keyring::from_verifying_keys([verifying_key]).expect("a one-key keyring");
    let verified = verify_bundle(
        &envelope,
        &keyring,
        Some(&resolution),
        &VerifyBundleOptions::default(),
    )
    .expect("the fresh bundle verifies");
    assert_eq!(verified.content_hash, resolution.content_hash);
    assert!(verified.policy_checked);
    assert_eq!(verified.key_ids.len(), 1);

    // The bundle round-trips through disk unchanged.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("policy.bundle.json");
    envelope.save(&path).expect("the bundle is writable");
    assert_eq!(DsseEnvelope::load(&path).expect("it reads back"), envelope);
}

/// Retirement is graceful (bundle spec 5.2 check 2): a bundle produced while
/// the key was current keeps verifying after it is retired, and one produced
/// at or after `not_after` does not.
#[test]
fn a_retired_key_still_attests_the_bundles_it_signed_while_current() {
    let resolution = resolve(&hipaa_base()).expect("the library policy resolves");
    let (signing_key, verifying_key) = generate_keypair();
    let statement = build_statement(
        &resolution,
        &BundleOptions {
            created_at: Some(instant(PINNED_CREATED_AT)),
            ..BundleOptions::default()
        },
    )
    .expect("the statement builds");
    let envelope = sign_statement(&statement, &signing_key).expect("it signs");

    let mut keyring = Keyring::from_verifying_keys([verifying_key]).expect("a one-key keyring");
    keyring.keys[0].not_after = Some("2026-09-16T00:00:00.000Z".to_string());
    verify_bundle(&envelope, &keyring, None, &VerifyBundleOptions::default())
        .expect("a bundle dated before not_after still verifies");

    keyring.keys[0].not_after = Some(PINNED_CREATED_AT.to_string());
    let error = verify_bundle(&envelope, &keyring, None, &VerifyBundleOptions::default())
        .expect_err("a bundle dated at not_after does not");
    assert_eq!(error.reason, BundleReason::KeyRetired);

    keyring.keys[0].not_after = None;
    keyring.keys[0].revoked = true;
    let error = verify_bundle(&envelope, &keyring, None, &VerifyBundleOptions::default())
        .expect_err("a revoked key attests nothing");
    assert_eq!(error.reason, BundleReason::KeyRevoked);
}

#[test]
fn bundling_the_same_inputs_twice_produces_identical_bytes() {
    let resolution = resolve(&hipaa_base()).expect("the library policy resolves");
    let (signing_key, _) = generate_keypair();
    let options = BundleOptions {
        created_at: Some(instant(PINNED_CREATED_AT)),
        ..BundleOptions::default()
    };

    let first = sign_statement(
        &build_statement(&resolution, &options).unwrap(),
        &signing_key,
    )
    .unwrap();
    let second = sign_statement(
        &build_statement(&resolution, &options).unwrap(),
        &signing_key,
    )
    .unwrap();

    // JCS payloads and deterministic Ed25519: byte for byte reproducible.
    assert_eq!(first, second);
    assert_eq!(first.to_json().unwrap(), second.to_json().unwrap());
}

#[test]
fn an_unsigned_bundle_is_readable_but_never_valid() {
    let resolution = resolve(&hipaa_base()).expect("the library policy resolves");
    let statement =
        build_statement(&resolution, &BundleOptions::default()).expect("the statement builds");
    let envelope = unsigned_envelope(&statement).expect("an unsigned envelope");

    // The statement is fully readable...
    assert_eq!(
        envelope
            .statement()
            .expect("it decodes")
            .predicate
            .policy
            .content_hash,
        resolution.content_hash
    );

    // ...and still not evidence.
    let (_, verifying_key) = generate_keypair();
    let keyring = Keyring::from_verifying_keys([verifying_key]).unwrap();
    let error = verify_bundle(&envelope, &keyring, None, &VerifyBundleOptions::default())
        .expect_err("an unsigned bundle does not verify");
    assert_eq!(error.reason, BundleReason::DsseSignatureMismatch);
}

/// A signature over the statement's canonical bytes rather than over the PAE
/// must not verify: the PAE is what binds the payload type to the payload.
#[test]
fn a_signature_that_skips_the_pae_does_not_verify() {
    use ed25519_dalek::Signer;

    let resolution = resolve(&hipaa_base()).expect("the library policy resolves");
    let statement =
        build_statement(&resolution, &BundleOptions::default()).expect("the statement builds");
    let payload = statement.to_canonical_bytes().expect("canonical bytes");

    let (signing_key, verifying_key) = generate_keypair();
    let mut envelope = unsigned_envelope(&statement).expect("an unsigned envelope");
    envelope.signatures.push(hushspec::bundle::DsseSignature {
        keyid: hushspec::signing::key_id(&verifying_key).unwrap(),
        sig: base64_encode(&signing_key.sign(&payload).to_bytes()),
    });

    let keyring = Keyring::from_verifying_keys([verifying_key]).unwrap();
    let error = verify_bundle(&envelope, &keyring, None, &VerifyBundleOptions::default())
        .expect_err("a signature over the bare payload is not a DSSE signature");
    assert_eq!(error.reason, BundleReason::DsseSignatureMismatch);
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let triple = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(ALPHABET[((triple >> (18 - index * 6)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
