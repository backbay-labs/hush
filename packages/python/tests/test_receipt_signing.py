"""Receipt signing (receipt spec section 6): a 0.2 envelope over the receipt
hash, and the vectors under ``fixtures/receipts/signed/``.

The signature sits *outside* the receipt, so a receipt's own hash is the same
whether or not it was ever signed -- the value a log links and a signature
covers are one and the same.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hushspec.evaluate import Decision
from hushspec.receipt import parse_receipt, receipt_hash, receipt_to_dict
from hushspec.signing import (
    MalformedEnvelope,
    SignedReceipt,
    SigningUnavailable,
    load_keyring,
    sign_receipt,
    verify_receipt,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SIGNED = REPO_ROOT / "fixtures" / "receipts" / "signed"
KEYS = REPO_ROOT / "fixtures" / "signing" / "keys"

NOW = "2026-09-15T12:00:00.000Z"


def _key() -> str:
    return (KEYS / "test-signing.key.pem").read_text()


def _keyring():
    return load_keyring((KEYS / "keyring.json").read_text())


def _source_receipt():
    return parse_receipt(
        (REPO_ROOT / "fixtures" / "receipts" / "valid" / "allow-egress.json").read_text()
    )


def _signed(name: str) -> SignedReceipt:
    return SignedReceipt.from_dict(json.loads((SIGNED / name).read_text()))


class TestSignAndVerify:
    def test_round_trips_and_covers_every_field(self) -> None:
        receipt = _source_receipt()
        signed = sign_receipt(receipt, _key(), signed_at=NOW, signer="fixtures")
        assert signed.signature.content_hash == receipt_hash(receipt)

        result = verify_receipt(signed, keyring=_keyring(), now=NOW)
        assert result.valid and result.reason is None

        # Editing the receipt after signing breaks the claim.
        tampered = SignedReceipt(
            receipt=parse_receipt(
                dict(receipt_to_dict(receipt), reason="edited after signing")
            ),
            signature=signed.signature,
        )
        failure = verify_receipt(tampered, keyring=_keyring(), now=NOW)
        assert failure.valid is False
        assert failure.reason == "content_hash_mismatch"

    def test_signing_is_deterministic(self) -> None:
        receipt = _source_receipt()
        first = sign_receipt(receipt, _key(), signed_at=NOW, signer="fixtures")
        second = sign_receipt(receipt, _key(), signed_at=NOW, signer="fixtures")
        assert first.signature == second.signature

    def test_the_wire_form_reparses_and_still_verifies(self) -> None:
        signed = sign_receipt(_source_receipt(), _key(), signed_at=NOW, signer="fixtures")
        reparsed = SignedReceipt.from_dict(json.loads(signed.to_json()))
        assert verify_receipt(reparsed, keyring=_keyring(), now=NOW).valid

    def test_a_malformed_wrapper_is_rejected(self) -> None:
        signed = sign_receipt(_source_receipt(), _key(), signed_at=NOW)
        with pytest.raises(MalformedEnvelope):
            SignedReceipt.from_dict({"receipt": signed.to_dict()["receipt"]})
        with pytest.raises(MalformedEnvelope):
            SignedReceipt.from_dict(dict(signed.to_dict(), extra=1))


class TestVectors:
    def test_the_vector_directories_are_populated(self) -> None:
        assert sorted(p.name for p in (SIGNED / "valid").glob("*.json")) == [
            "allow-egress.signed.json"
        ]
        assert len(list((SIGNED / "invalid").glob("*.json"))) == 2

    def test_the_valid_vector_is_what_this_sdk_produces(self) -> None:
        signed = sign_receipt(_source_receipt(), _key(), signed_at=NOW, signer="fixtures")
        expected = json.loads((SIGNED / "valid" / "allow-egress.signed.json").read_text())
        assert json.loads(signed.to_json()) == expected

    def test_the_valid_vector_verifies(self) -> None:
        result = verify_receipt(
            _signed("valid/allow-egress.signed.json"), keyring=_keyring(), now=NOW
        )
        assert result.valid, result.reason

    def test_a_receipt_tampered_after_signing_is_rejected(self) -> None:
        signed = _signed("invalid/tampered-after-signing.signed.json")
        assert signed.receipt.decision == Decision.DENY
        result = verify_receipt(signed, keyring=_keyring(), now=NOW)
        assert result.valid is False
        assert result.reason == "content_hash_mismatch"

    def test_an_untrusted_key_is_rejected(self) -> None:
        result = verify_receipt(
            _signed("invalid/untrusted-key.signed.json"), keyring=_keyring(), now=NOW
        )
        assert result.valid is False
        assert result.reason == "unknown_key_id"

    def test_verify_accepts_the_raw_json_object(self) -> None:
        raw = json.loads((SIGNED / "valid" / "allow-egress.signed.json").read_text())
        assert verify_receipt(raw, keyring=_keyring(), now=NOW).valid


def test_signing_needs_the_cryptography_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    # Receipt signing fails closed exactly as policy signing does: a missing
    # backend is never readable as "verified".
    import hushspec.signing as signing

    def unavailable():
        raise SigningUnavailable("no backend")

    monkeypatch.setattr(signing, "_ed25519", unavailable)
    monkeypatch.setattr(signing, "_load_private_key", lambda _pem: unavailable())
    with pytest.raises(SigningUnavailable):
        sign_receipt(_source_receipt(), _key(), signed_at=NOW)
    with pytest.raises(SigningUnavailable):
        verify_receipt(_signed("valid/allow-egress.signed.json"), keyring=_keyring())
