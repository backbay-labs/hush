#![cfg(feature = "signing")]

//! Receipt signing (RFC 09 P2-06): a 0.2 envelope over the receipt hash,
//! and the vectors under `fixtures/receipts/signed/` (regenerate with
//! `HUSHSPEC_UPDATE_SIGNED_RECEIPTS=1`).

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{TimeZone, Utc};
use hushspec::receipt::DecisionReceipt;
use hushspec::signing::{
    Keyring, ReasonCode, SignOptions, SignedReceipt, VerifyOptions, load_private_key, sign_receipt,
    verify_receipt,
};

fn repo_root() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../..")).to_path_buf()
}

fn signed_dir() -> PathBuf {
    repo_root().join("fixtures/receipts/signed")
}

fn test_key() -> hushspec::signing::SigningKey {
    load_private_key(&repo_root().join("fixtures/signing/keys/test-signing.key.pem")).unwrap()
}

fn keyring() -> Keyring {
    Keyring::load(&repo_root().join("fixtures/signing/keys/keyring.json")).unwrap()
}

fn verify_options() -> VerifyOptions {
    VerifyOptions {
        now: Utc.with_ymd_and_hms(2026, 9, 15, 12, 0, 0).unwrap(),
        max_clock_skew_seconds: 300,
        last_seen_version: None,
    }
}

fn sign_options() -> SignOptions {
    SignOptions {
        signed_at: Some(Utc.with_ymd_and_hms(2026, 9, 15, 12, 0, 0).unwrap()),
        signer: Some("fixtures".to_string()),
        ..SignOptions::default()
    }
}

/// The receipt every signed vector is built from.
fn source_receipt() -> DecisionReceipt {
    let path = repo_root().join("fixtures/receipts/valid/allow-egress.json");
    DecisionReceipt::parse(&fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn sign_then_verify_round_trips_and_covers_every_field() {
    let receipt = source_receipt();
    let signed = sign_receipt(&receipt, &test_key(), &sign_options()).unwrap();
    assert_eq!(
        signed.signature.content_hash,
        receipt.receipt_hash().unwrap()
    );
    let verified = verify_receipt(&signed, &keyring(), &verify_options()).unwrap();
    assert_eq!(verified.content_hash, signed.signature.content_hash);

    let mut tampered = signed.clone();
    tampered.receipt.decision = hushspec::Decision::Allow;
    tampered.receipt.reason = Some("edited after signing".to_string());
    let error = verify_receipt(&tampered, &keyring(), &verify_options()).unwrap_err();
    assert_eq!(error.reason, ReasonCode::ContentHashMismatch);

    // Serialization is stable: the wire form re-parses and still verifies.
    let json = serde_json::to_string_pretty(&signed).unwrap();
    let reparsed: SignedReceipt = serde_json::from_str(&json).unwrap();
    verify_receipt(&reparsed, &keyring(), &verify_options()).unwrap();
}

#[test]
fn signing_is_deterministic() {
    let receipt = source_receipt();
    let a = sign_receipt(&receipt, &test_key(), &sign_options()).unwrap();
    let b = sign_receipt(&receipt, &test_key(), &sign_options()).unwrap();
    assert_eq!(a, b);
}

#[test]
fn signed_receipt_vectors_are_current_and_behave() {
    let update = std::env::var("HUSHSPEC_UPDATE_SIGNED_RECEIPTS").is_ok();
    let receipt = source_receipt();
    let signed = sign_receipt(&receipt, &test_key(), &sign_options()).unwrap();

    let mut tampered = signed.clone();
    tampered.receipt.decision = hushspec::Decision::Deny;

    let untrusted_key =
        load_private_key(&repo_root().join("fixtures/signing/keys/test-untrusted.key.pem"))
            .unwrap();
    let untrusted = sign_receipt(&receipt, &untrusted_key, &sign_options()).unwrap();

    let generated = [
        ("valid/allow-egress.signed.json", &signed),
        ("invalid/tampered-after-signing.signed.json", &tampered),
        ("invalid/untrusted-key.signed.json", &untrusted),
    ];
    if update {
        for (name, value) in generated {
            let path = signed_dir().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(
                &path,
                format!("{}\n", serde_json::to_string_pretty(value).unwrap()),
            )
            .unwrap();
        }
    }
    for (name, value) in generated {
        let path = signed_dir().join(name);
        let text = fs::read_to_string(&path).unwrap_or_else(|_| panic!("{name} is missing"));
        assert_eq!(
            text,
            format!("{}\n", serde_json::to_string_pretty(value).unwrap()),
            "{name} drifted (run with HUSHSPEC_UPDATE_SIGNED_RECEIPTS=1 after a deliberate change)"
        );
    }

    let read = |name: &str| -> SignedReceipt {
        serde_json::from_str(&fs::read_to_string(signed_dir().join(name)).unwrap()).unwrap()
    };
    verify_receipt(
        &read("valid/allow-egress.signed.json"),
        &keyring(),
        &verify_options(),
    )
    .expect("the valid vector verifies");
    assert_eq!(
        verify_receipt(
            &read("invalid/tampered-after-signing.signed.json"),
            &keyring(),
            &verify_options()
        )
        .unwrap_err()
        .reason,
        ReasonCode::ContentHashMismatch
    );
    assert_eq!(
        verify_receipt(
            &read("invalid/untrusted-key.signed.json"),
            &keyring(),
            &verify_options()
        )
        .unwrap_err()
        .reason,
        ReasonCode::UnknownKeyId
    );
}
