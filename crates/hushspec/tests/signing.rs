//! The public surface of `hushspec::signing` (format 0.2).
//!
//! The normative conformance run lives in `signing_vectors.rs`; this suite
//! covers the API around it -- key material, the keyring loader, envelope
//! I/O, the ordered checks that the published vectors cannot reach, and the
//! 0.1 readers that let tooling explain an old signature instead of choking
//! on it.

#![cfg(feature = "signing")]

use chrono::{DateTime, Duration, Utc};
use hushspec::signing::{
    ALGORITHM, Envelope, FORMAT_VERSION, KEYRING_VERSION, Keyring, LEGACY_FORMAT_VERSION,
    LegacySignature, ReasonCode, SignOptions, TrustedKey, VerifyOptions,
    convert_legacy_private_key, convert_legacy_public_key, generate_keypair, key_id, load_resolved,
    parse_private_key_pem, parse_public_key_pem, private_key_pem, public_key_pem,
    sign_content_hash, sign_policy, sign_resolved, verify_content_hash, verify_policy,
};
use std::path::{Path, PathBuf};

const FIXTURE_KEY: &str = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGTPdfz6EVZtaJOI5QCAuV95QpjiCTsQwnJ3dZSakPlk
-----END PRIVATE KEY-----
";

const POLICY: &str = r#"hushspec: "0.2.0"
name: api-suite
metadata:
  policy_version: 2
rules:
  egress:
    allow:
      - api.example.com
    default: block
"#;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/signing")
        .canonicalize()
        .expect("fixtures/signing is readable")
}

fn instant(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("a timestamp")
        .with_timezone(&Utc)
}

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

// --------------------------------------------------------------------- keys

#[test]
fn generate_keypair_produces_a_matched_distinct_pair() {
    let (first, verifying) = generate_keypair();
    assert_eq!(first.verifying_key().to_bytes(), verifying.to_bytes());

    let (second, _) = generate_keypair();
    assert_ne!(first.to_bytes(), second.to_bytes());
}

#[test]
fn keys_round_trip_through_pem() {
    let (signing, verifying) = generate_keypair();

    let private = private_key_pem(&signing).unwrap();
    let public = public_key_pem(&verifying).unwrap();
    assert!(private.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(private.ends_with("-----END PRIVATE KEY-----\n"));
    assert!(public.starts_with("-----BEGIN PUBLIC KEY-----"));

    assert_eq!(
        parse_private_key_pem(&private).unwrap().to_bytes(),
        signing.to_bytes()
    );
    assert_eq!(
        parse_public_key_pem(&public).unwrap().to_bytes(),
        verifying.to_bytes()
    );
}

#[test]
fn the_published_fixture_keys_load_and_name_themselves() {
    let root = fixtures();
    let signing = parse_private_key_pem(
        &std::fs::read_to_string(root.join("keys/test-signing.key.pem")).unwrap(),
    )
    .expect("the published private key loads despite its DO-NOT-USE header");
    let verifying = parse_public_key_pem(
        &std::fs::read_to_string(root.join("keys/test-signing.pub.pem")).unwrap(),
    )
    .expect("the published public key loads");

    assert_eq!(signing.verifying_key().to_bytes(), verifying.to_bytes());
    assert_eq!(
        key_id(&verifying).unwrap(),
        "sha256:1187bb3ca0fd60b25cb90390812fb3a90823466b499e9c29effcc9f3c4ce6142"
    );

    let untrusted = parse_public_key_pem(
        &std::fs::read_to_string(root.join("keys/test-untrusted.pub.pem")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        key_id(&untrusted).unwrap(),
        "sha256:2b570037138bf0b0f6694d04ae3cd3b53e47c4af3b05e449fed87e023b172d23"
    );
}

#[test]
fn a_bespoke_zero_one_key_file_is_rejected_with_a_pointer_to_the_converter() {
    let error = parse_private_key_pem("-----BEGIN HUSHSPEC PRIVATE KEY-----\nAAAA\n")
        .unwrap_err()
        .to_string();
    assert!(error.contains("--convert"), "{error}");
}

// ------------------------------------------------------------------ keyring

#[test]
fn the_published_keyrings_load() {
    let root = fixtures();
    for (file, revoked, retired) in [
        ("keys/keyring.json", false, false),
        ("keys/keyring-revoked.json", true, false),
        ("keys/keyring-retired.json", false, true),
    ] {
        let keyring = Keyring::load(&root.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(keyring.keyring_version, KEYRING_VERSION);
        assert_eq!(keyring.keys.len(), 1);
        let entry = &keyring.keys[0];
        assert_eq!(entry.algorithm, ALGORITHM);
        assert_eq!(entry.revoked, revoked);
        assert_eq!(entry.not_after.is_some(), retired);
        assert_eq!(
            key_id(&entry.verifying_key().unwrap()).unwrap(),
            entry.key_id
        );
    }
}

#[test]
fn a_keyring_with_an_unusable_entry_does_not_load_at_all() {
    let (_, verifying) = generate_keypair();
    let good = TrustedKey::from_verifying_key(&verifying, Some("good".into())).unwrap();

    let mut keyring = Keyring::from_verifying_keys([verifying]).unwrap();
    keyring.keys.push(TrustedKey {
        public_key: "-----BEGIN PUBLIC KEY-----\nnot base64\n-----END PUBLIC KEY-----\n"
            .to_string(),
        ..good.clone()
    });

    let json = serde_json::to_string(&keyring).unwrap();
    let error = Keyring::parse(&json).unwrap_err().to_string();
    assert!(error.contains("unusable"), "{error}");
}

#[test]
fn a_keyring_rejects_a_wrong_version_an_empty_list_and_a_foreign_algorithm() {
    let (_, verifying) = generate_keypair();
    let entry = TrustedKey::from_verifying_key(&verifying, None).unwrap();

    let wrong_version = Keyring {
        keyring_version: "0.1".to_string(),
        keys: vec![entry.clone()],
    };
    assert!(Keyring::parse(&serde_json::to_string(&wrong_version).unwrap()).is_err());

    let empty = Keyring {
        keyring_version: KEYRING_VERSION.to_string(),
        keys: vec![],
    };
    assert!(Keyring::parse(&serde_json::to_string(&empty).unwrap()).is_err());

    let foreign = Keyring {
        keyring_version: KEYRING_VERSION.to_string(),
        keys: vec![TrustedKey {
            algorithm: "rsa-pss".to_string(),
            ..entry
        }],
    };
    assert!(Keyring::parse(&serde_json::to_string(&foreign).unwrap()).is_err());
}

#[test]
fn key_selection_is_by_exact_id_with_no_fallback() {
    let (signing, verifying) = generate_keypair();
    let (_, other) = generate_keypair();

    let envelope = sign_content_hash(&digest('a'), &signing, &SignOptions::default()).unwrap();
    // A keyring holding a *different* key, even a single one, must not be
    // tried: selection is by exact key_id.
    let keyring = Keyring::from_verifying_keys([other]).unwrap();
    let error = verify_content_hash(
        &envelope,
        Some(&digest('a')),
        &keyring,
        &VerifyOptions::default(),
    )
    .unwrap_err();
    assert_eq!(error.reason, ReasonCode::UnknownKeyId);

    let keyring = Keyring::from_verifying_keys([verifying]).unwrap();
    assert!(
        verify_content_hash(
            &envelope,
            Some(&digest('a')),
            &keyring,
            &VerifyOptions::default()
        )
        .is_ok()
    );
}

// ----------------------------------------------------------------- envelope

#[test]
fn an_envelope_round_trips_through_its_sig_file() {
    let dir = tempfile::tempdir().unwrap();
    let (signing, _) = generate_keypair();
    let envelope = sign_content_hash(
        &digest('b'),
        &signing,
        &SignOptions {
            signer: Some("ci@example.com".to_string()),
            policy_name: Some("p".to_string()),
            policy_version: Some(3),
            expires_at: Some(instant("2027-01-01T00:00:00.000Z")),
            signed_at: Some(instant("2026-09-15T09:00:00.000Z")),
        },
    )
    .unwrap();

    let path = dir.path().join("policy.yaml.sig");
    envelope.save(&path).unwrap();
    assert!(
        std::fs::read_to_string(&path).unwrap().ends_with("}\n"),
        "a .sig file is pretty-printed with a trailing newline"
    );
    assert_eq!(Envelope::load(&path).unwrap(), envelope);
    assert_eq!(envelope.format_version, FORMAT_VERSION);
    assert_eq!(envelope.algorithm, ALGORITHM);
}

#[test]
fn an_envelope_with_an_unknown_member_is_malformed() {
    let (signing, _) = generate_keypair();
    let envelope = sign_content_hash(&digest('c'), &signing, &SignOptions::default()).unwrap();
    let mut json: serde_json::Value = serde_json::to_value(&envelope).unwrap();
    json["nonce"] = serde_json::Value::from(1);

    let error = Envelope::parse(&json.to_string()).unwrap_err();
    assert_eq!(error.reason, ReasonCode::MalformedEnvelope);
}

#[test]
fn an_envelope_with_a_coarse_timestamp_is_malformed() {
    let (signing, _) = generate_keypair();
    let envelope = sign_content_hash(&digest('d'), &signing, &SignOptions::default()).unwrap();
    let mut json: serde_json::Value = serde_json::to_value(&envelope).unwrap();
    json["signed_at"] = serde_json::Value::from("2026-09-15T09:00:00Z");

    let error = Envelope::parse(&json.to_string()).unwrap_err();
    assert_eq!(error.reason, ReasonCode::MalformedEnvelope);
    assert!(error.detail.contains("millisecond"), "{}", error.detail);
}

/// Checks 2 and 3 own `format_version` and `algorithm`, so an envelope that
/// names another version or algorithm must *parse* and then be rejected with
/// the code that says which one it named -- not lumped in with a corrupt file.
#[test]
fn a_foreign_version_or_algorithm_parses_and_then_fails_its_own_check() {
    let (signing, verifying) = generate_keypair();
    let keyring = Keyring::from_verifying_keys([verifying]).unwrap();
    let envelope = sign_content_hash(&digest('e'), &signing, &SignOptions::default()).unwrap();

    for (member, value, expected) in [
        (
            "format_version",
            "0.3",
            ReasonCode::UnsupportedFormatVersion,
        ),
        ("algorithm", "rsa-pss", ReasonCode::UnsupportedAlgorithm),
    ] {
        let mut json: serde_json::Value = serde_json::to_value(&envelope).unwrap();
        json[member] = serde_json::Value::from(value);
        let parsed = Envelope::parse(&json.to_string())
            .unwrap_or_else(|e| panic!("{member} = {value} should parse, got {e}"));
        let error = verify_content_hash(
            &parsed,
            Some(&digest('e')),
            &keyring,
            &VerifyOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.reason, expected);
    }
}

/// `sign_policy` and `verify_policy` are the typed pair the SDK ports mirror:
/// both take the resolved document and derive the hash themselves.
#[test]
fn the_typed_pair_signs_and_verifies_a_resolved_document() {
    let resolved = hushspec::HushSpec::parse(POLICY).unwrap();
    let (signing, verifying) = generate_keypair();

    let envelope = sign_policy(&resolved, &signing, &SignOptions::default()).unwrap();
    assert_eq!(envelope.policy_name.as_deref(), Some("api-suite"));
    assert_eq!(envelope.policy_version, Some(2));

    let keyring = Keyring::from_verifying_keys([verifying]).unwrap();
    let verified =
        verify_policy(&envelope, &resolved, &keyring, &VerifyOptions::default()).unwrap();
    assert_eq!(verified.content_hash, envelope.content_hash);

    // A different document is a content mismatch, not a signature failure:
    // the envelope is genuine, it just covers something else.
    let other = hushspec::HushSpec::parse(
        "hushspec: \"0.2.0\"\nname: elsewhere\nrules:\n  egress:\n    default: block\n",
    )
    .unwrap();
    assert_eq!(
        verify_policy(&envelope, &other, &keyring, &VerifyOptions::default())
            .unwrap_err()
            .reason,
        ReasonCode::ContentHashMismatch
    );

    // An unresolved document has no hash at all, and fails the same check.
    let unresolved = hushspec::HushSpec::parse(
        "hushspec: \"0.2.0\"\nname: child\nextends: builtin:default\nrules:\n  egress:\n    default: block\n",
    )
    .unwrap();
    assert_eq!(
        verify_policy(&envelope, &unresolved, &keyring, &VerifyOptions::default())
            .unwrap_err()
            .reason,
        ReasonCode::ContentHashMismatch
    );
}

// ------------------------------------------------------------ ordered checks

#[test]
fn revocation_beats_retirement_beats_expiry() {
    let (signing, verifying) = generate_keypair();
    let signed_at = instant("2026-09-15T09:00:00.000Z");
    let envelope = sign_content_hash(
        &digest('f'),
        &signing,
        &SignOptions {
            signed_at: Some(signed_at),
            expires_at: Some(instant("2026-09-15T10:00:00.000Z")),
            ..SignOptions::default()
        },
    )
    .unwrap();

    let options = VerifyOptions {
        now: instant("2026-09-15T12:00:00.000Z"),
        ..VerifyOptions::default()
    };
    let base = Keyring::from_verifying_keys([verifying]).unwrap();

    // Expiry alone (checks 5 and 6 pass).
    let error = verify_content_hash(&envelope, Some(&digest('f')), &base, &options).unwrap_err();
    assert_eq!(error.reason, ReasonCode::Expired);

    // Retirement (check 6) is reported before expiry (check 7).
    let mut retired = base.clone();
    retired.keys[0].not_after = Some("2026-09-15T00:00:00.000Z".to_string());
    let error = verify_content_hash(&envelope, Some(&digest('f')), &retired, &options).unwrap_err();
    assert_eq!(error.reason, ReasonCode::KeyRetired);

    // Revocation (check 5) is reported before retirement.
    let mut revoked = retired.clone();
    revoked.keys[0].revoked = true;
    let error = verify_content_hash(&envelope, Some(&digest('f')), &revoked, &options).unwrap_err();
    assert_eq!(error.reason, ReasonCode::KeyRevoked);
}

#[test]
fn retirement_keeps_signatures_made_before_it() {
    let (signing, verifying) = generate_keypair();
    let mut keyring = Keyring::from_verifying_keys([verifying]).unwrap();
    keyring.keys[0].not_after = Some("2026-09-15T00:00:00.000Z".to_string());

    let earlier = sign_content_hash(
        &digest('1'),
        &signing,
        &SignOptions {
            signed_at: Some(instant("2026-09-14T23:59:59.999Z")),
            ..SignOptions::default()
        },
    )
    .unwrap();
    let options = VerifyOptions {
        now: instant("2026-09-15T12:00:00.000Z"),
        ..VerifyOptions::default()
    };
    assert!(verify_content_hash(&earlier, Some(&digest('1')), &keyring, &options).is_ok());

    // At the instant itself the key is already retired.
    let at_the_boundary = sign_content_hash(
        &digest('1'),
        &signing,
        &SignOptions {
            signed_at: Some(instant("2026-09-15T00:00:00.000Z")),
            ..SignOptions::default()
        },
    )
    .unwrap();
    assert_eq!(
        verify_content_hash(&at_the_boundary, Some(&digest('1')), &keyring, &options)
            .unwrap_err()
            .reason,
        ReasonCode::KeyRetired
    );
}

#[test]
fn clock_skew_is_an_allowance_not_a_freshness_window() {
    let (signing, verifying) = generate_keypair();
    let keyring = Keyring::from_verifying_keys([verifying]).unwrap();
    let now = instant("2026-09-15T12:00:00.000Z");

    // Four minutes ahead: inside the 300s default.
    let ahead = sign_content_hash(
        &digest('2'),
        &signing,
        &SignOptions {
            signed_at: Some(now + Duration::seconds(240)),
            ..SignOptions::default()
        },
    )
    .unwrap();
    let options = VerifyOptions {
        now,
        ..VerifyOptions::default()
    };
    assert!(verify_content_hash(&ahead, Some(&digest('2')), &keyring, &options).is_ok());

    // The same envelope under a tightened skew.
    let strict = VerifyOptions {
        now,
        max_clock_skew_seconds: 60,
        last_seen_version: None,
    };
    assert_eq!(
        verify_content_hash(&ahead, Some(&digest('2')), &keyring, &strict)
            .unwrap_err()
            .reason,
        ReasonCode::SignedAtInFuture
    );

    // Two years old, never expired: still valid. `signed_at` is not freshness.
    let old = sign_content_hash(
        &digest('2'),
        &signing,
        &SignOptions {
            signed_at: Some(now - Duration::days(730)),
            ..SignOptions::default()
        },
    )
    .unwrap();
    assert!(verify_content_hash(&old, Some(&digest('2')), &keyring, &options).is_ok());
}

#[test]
fn the_content_check_runs_after_the_signature_check() {
    let (signing, verifying) = generate_keypair();
    let keyring = Keyring::from_verifying_keys([verifying]).unwrap();
    let mut envelope = sign_content_hash(&digest('3'), &signing, &SignOptions::default()).unwrap();

    // A corrupt signature is check 8, reported before the content mismatch
    // that a forged content_hash would also produce.
    envelope.signature.replace_range(0..1, "A");
    let error = verify_content_hash(
        &envelope,
        Some(&digest('4')),
        &keyring,
        &VerifyOptions::default(),
    )
    .unwrap_err();
    assert_eq!(error.reason, ReasonCode::SignatureMismatch);
}

// ---------------------------------------------------------- the whole cycle

#[test]
fn a_policy_signed_from_disk_verifies_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policy.yaml");
    std::fs::write(&policy, POLICY).unwrap();

    let signing = parse_private_key_pem(FIXTURE_KEY).unwrap();
    let resolved = load_resolved(&policy).unwrap();
    let envelope = sign_resolved(
        &resolved,
        &signing,
        &SignOptions {
            signed_at: Some(instant("2026-09-15T09:00:00.000Z")),
            ..SignOptions::default()
        },
    )
    .unwrap();

    assert_eq!(envelope.policy_name.as_deref(), Some("api-suite"));
    assert_eq!(envelope.policy_version, Some(2));
    assert_eq!(
        envelope.key_id,
        key_id(&signing.verifying_key()).unwrap(),
        "the envelope names the key that signed it"
    );

    let keyring =
        Keyring::from_public_key_pem(&public_key_pem(&signing.verifying_key()).unwrap()).unwrap();
    let verified = hushspec::signing::verify_policy_at(
        &policy,
        &envelope,
        &keyring,
        &VerifyOptions {
            now: instant("2026-09-15T12:00:00.000Z"),
            ..VerifyOptions::default()
        },
    )
    .expect("the signature verifies");
    assert_eq!(verified.content_hash, resolved.content_hash);
    assert_eq!(verified.policy_name.as_deref(), Some("api-suite"));
}

// ------------------------------------------------------- format 0.1 readers

#[test]
fn a_zero_one_envelope_is_recognized_rather_than_mistaken_for_corruption() {
    let legacy = r#"{
      "format_version": "0.1.0",
      "algorithm": "ed25519",
      "content_hash": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
      "signature": "Zm9vYmFy",
      "signed_at": "2025-01-15T00:00:00Z",
      "key_id": "ed25519:abcdef0123456789",
      "signer": "security@example.com"
    }"#;

    // It is not a 0.2 envelope...
    assert_eq!(
        Envelope::parse(legacy).unwrap_err().reason,
        ReasonCode::MalformedEnvelope
    );
    // ...but tooling can still say what it is.
    let parsed = LegacySignature::detect(legacy).expect("a 0.1 signature is recognizable");
    assert_eq!(parsed.format_version, LEGACY_FORMAT_VERSION);
    assert_eq!(parsed.key_id, "ed25519:abcdef0123456789");
    assert!(
        !parsed.content_hash.starts_with("sha256:"),
        "0.1 hashed raw bytes into bare hex"
    );

    // A 0.2 envelope is not mistaken for a 0.1 one.
    let (signing, _) = generate_keypair();
    let current = sign_content_hash(&digest('5'), &signing, &SignOptions::default()).unwrap();
    assert!(LegacySignature::detect(&current.to_json().unwrap()).is_none());
}

#[test]
fn a_converted_zero_one_key_signs_and_verifies_as_pem() {
    let (original, original_public) = generate_keypair();
    let legacy_private = format!(
        "-----BEGIN HUSHSPEC PRIVATE KEY-----\n{}\n-----END HUSHSPEC PRIVATE KEY-----\n",
        base64_standard(&original.to_bytes())
    );
    let legacy_public = format!(
        "-----BEGIN HUSHSPEC PUBLIC KEY-----\n{}\n-----END HUSHSPEC PUBLIC KEY-----\n",
        base64_standard(&original_public.to_bytes())
    );

    let converted = convert_legacy_private_key(&legacy_private).unwrap();
    let converted_public = convert_legacy_public_key(&legacy_public).unwrap();
    assert_eq!(converted.to_bytes(), original.to_bytes());

    // The converted key writes as standard PEM and keeps its identity.
    let pem = private_key_pem(&converted).unwrap();
    let reloaded = parse_private_key_pem(&pem).unwrap();
    assert_eq!(
        key_id(&reloaded.verifying_key()).unwrap(),
        key_id(&converted_public).unwrap()
    );

    let envelope = sign_content_hash(&digest('6'), &reloaded, &SignOptions::default()).unwrap();
    let keyring = Keyring::from_verifying_keys([converted_public]).unwrap();
    assert!(
        verify_content_hash(
            &envelope,
            Some(&digest('6')),
            &keyring,
            &VerifyOptions::default()
        )
        .is_ok()
    );
}

fn base64_standard(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
