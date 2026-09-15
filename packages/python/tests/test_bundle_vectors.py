"""Normative policy-bundle vectors (spec/hushspec-bundle.md section 7).

Every case in ``fixtures/bundle/vectors.yaml`` pairs a DSSE bundle, a keyring,
a verifier clock and optionally a policy with the outcome a conformant verifier
MUST return: ``valid``, or invalid with an exact reason code from spec section
5.4. Every SDK runs the same directory; a divergence here is a conformance
failure, not a test-fixture problem.

Beyond the vectors this file covers the PAE encoding byte-for-byte, the shape
checks of check 1, and the behaviour of the module without the optional
``cryptography`` extra.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
import yaml

from hushspec.bundle import (
    BUNDLE_REASON_CODES,
    BUNDLE_VERSION,
    PAYLOAD_TYPE,
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    BundleError,
    DsseEnvelope,
    pae,
    parse_bundle,
    verify_bundle,
)
from hushspec.parse import CoreSafeLoader, parse_or_raise
from hushspec.resolve import create_composite_loader, resolve_with_options_or_raise
from hushspec.signing import SigningError

REPO_ROOT = Path(__file__).resolve().parents[3]
VECTOR_DIR = REPO_ROOT / "fixtures" / "bundle"
VECTOR_FILE = VECTOR_DIR / "vectors.yaml"
VECTOR_VERSION = "0.1.0"
BUNDLE_SCHEMA = REPO_ROOT / "schemas" / "hushspec-bundle.v0.schema.json"

pytest.importorskip(
    "cryptography",
    reason="bundle verification needs the optional `signing` extra: "
    "pip install hushspec[signing]",
)


def _load_manifest() -> dict[str, Any]:
    manifest = yaml.load(VECTOR_FILE.read_text(encoding="utf-8"), Loader=CoreSafeLoader)
    assert isinstance(manifest, dict), "vectors.yaml must be a mapping"
    assert manifest.get("hushspec_bundle_vectors") == VECTOR_VERSION, (
        f"{VECTOR_FILE} declares "
        f"{manifest.get('hushspec_bundle_vectors')!r}, this runner reads "
        f"{VECTOR_VERSION!r}"
    )
    return manifest


MANIFEST = _load_manifest()
DEFAULTS: dict[str, Any] = MANIFEST.get("defaults") or {}
CASES: list[dict[str, Any]] = list(MANIFEST["cases"])


def _case_setting(case: dict[str, Any], key: str) -> Any:
    """A case's value for *key*, falling back to the manifest defaults."""
    return case[key] if key in case else DEFAULTS.get(key)


def _expected(case: dict[str, Any]) -> tuple[bool, str | None]:
    expect = case["expect"]
    if expect == "valid":
        return True, None
    assert isinstance(expect, dict) and "invalid" in expect, (
        f"{case['name']}: `expect` must be 'valid' or {{invalid: <reason>}}"
    )
    return False, expect["invalid"]


def _resolved(path: Path):
    """The policy at *path*, resolved through the composite loader."""
    return resolve_with_options_or_raise(
        parse_or_raise(path.read_text(encoding="utf-8")),
        source=str(path),
        loader=create_composite_loader(),
    )


# ---- The manifest itself ---- #


def test_vector_manifest_is_populated() -> None:
    assert len(CASES) == 8, "spec section 7 lists eight bundle vectors"
    names = [case["name"] for case in CASES]
    assert len(set(names)) == len(names), "vector names must be unique"


def test_every_expected_reason_is_a_spec_reason_code() -> None:
    for case in CASES:
        _valid, reason = _expected(case)
        if reason is not None:
            assert reason in BUNDLE_REASON_CODES, (
                f"{case['name']}: {reason!r} is not a spec section 5.4 reason code"
            )


def test_the_vectors_cover_every_reason_code() -> None:
    covered = {reason for case in CASES for reason in [_expected(case)[1]] if reason}
    assert covered == set(BUNDLE_REASON_CODES), (
        f"uncovered reason codes: {sorted(set(BUNDLE_REASON_CODES) - covered)}"
    )


# ---- The vectors ---- #


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_bundle_vector(case: dict[str, Any]) -> None:
    bundle = json.loads((VECTOR_DIR / case["bundle"]).read_text(encoding="utf-8"))
    keyring = json.loads(
        (VECTOR_DIR / _case_setting(case, "keyring")).read_text(encoding="utf-8")
    )
    policy_path = _case_setting(case, "policy")
    policy = _resolved(VECTOR_DIR / policy_path) if policy_path else None

    result = verify_bundle(
        bundle,
        keyring=keyring,
        now=_case_setting(case, "now"),
        policy=policy,
    )

    expected_valid, expected_reason = _expected(case)
    if expected_valid:
        assert result.valid, (
            f"{case['name']}: expected valid, got {result.reason}: {result.detail}"
        )
        assert result.reason is None
        assert result.policy_checked is (policy is not None)
    else:
        assert not result.valid, f"{case['name']}: expected {expected_reason}, got valid"
        assert result.reason == expected_reason, (
            f"{case['name']}: expected {expected_reason}, "
            f"got {result.reason}: {result.detail}"
        )
        assert result.detail
    assert bool(result) is result.valid


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_every_vector_bundle_matches_the_published_schema(case: dict[str, Any]) -> None:
    """Every bundle is a schema-valid envelope, including the invalid ones.

    The refusals are about content -- a bad signature, an unknown predicate
    version -- not about a document the schema would reject outright.
    """
    bundle = json.loads((VECTOR_DIR / case["bundle"]).read_text(encoding="utf-8"))
    schema = json.loads(BUNDLE_SCHEMA.read_text(encoding="utf-8"))
    try:
        import jsonschema
    except ImportError:  # pragma: no cover - jsonschema is a dev-only extra
        assert set(schema["required"]) <= set(bundle)
        assert bundle["payloadType"] == PAYLOAD_TYPE
        assert isinstance(bundle["signatures"], list)
        return
    jsonschema.validate(bundle, schema)


def test_the_valid_bundle_reports_its_attested_identity() -> None:
    bundle = json.loads(
        (VECTOR_DIR / "bundles" / "valid.bundle.json").read_text(encoding="utf-8")
    )
    keyring = json.loads(
        (VECTOR_DIR / DEFAULTS["keyring"]).read_text(encoding="utf-8")
    )
    result = verify_bundle(bundle, keyring=keyring, now=DEFAULTS["now"])

    assert result.valid
    assert result.subject_name == "hipaa-base"
    assert result.policy_name == "hipaa-base"
    assert result.content_hash and result.content_hash.startswith("sha256:")
    assert result.created_at == "2026-09-15T12:00:00.000Z"
    assert result.chain_length == 2
    assert result.policy_checked is False
    assert result.verified_at == DEFAULTS["now"]
    assert len(result.key_ids) == 1


# ---- Pre-Authentication Encoding (spec section 3.1) ---- #


class TestPae:
    def test_the_dsse_reference_vector(self) -> None:
        assert (
            pae("http://example.com/HelloWorld", b"hello world")
            == b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        )

    def test_an_empty_payload_still_carries_its_length(self) -> None:
        assert pae("a", b"") == b"DSSEv1 1 a 0 "

    def test_lengths_are_byte_counts_not_character_counts(self) -> None:
        assert pae("t", "é".encode("utf-8")) == b"DSSEv1 1 t 2 \xc3\xa9"

    def test_the_hushspec_prefix_is_fixed(self) -> None:
        assert pae(PAYLOAD_TYPE, b"{}").startswith(
            b"DSSEv1 28 application/vnd.in-toto+json 2 "
        )

    def test_an_envelope_paes_its_decoded_payload(self) -> None:
        envelope = DsseEnvelope(
            payload_type=PAYLOAD_TYPE,
            payload=base64.b64encode(b"{}").decode("ascii"),
        )
        assert envelope.pae() == pae(PAYLOAD_TYPE, b"{}")


# ---- Check 1: shape ---- #


def _valid_statement() -> dict[str, Any]:
    bundle = json.loads(
        (VECTOR_DIR / "bundles" / "valid.bundle.json").read_text(encoding="utf-8")
    )
    return json.loads(base64.b64decode(bundle["payload"]))


def _envelope_for(statement: dict[str, Any]) -> dict[str, Any]:
    payload = base64.b64encode(
        json.dumps(statement, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    return {"payloadType": PAYLOAD_TYPE, "payload": payload, "signatures": []}


class TestParseBundle:
    def test_accepts_a_vector_bundle(self) -> None:
        text = (VECTOR_DIR / "bundles" / "valid.bundle.json").read_text(
            encoding="utf-8"
        )
        envelope = parse_bundle(text)
        assert envelope.payload_type == PAYLOAD_TYPE
        assert len(envelope.signatures) == 1
        assert parse_bundle(envelope) is envelope
        assert parse_bundle(text.encode("utf-8")).payload == envelope.payload

    def test_round_trips_through_to_dict(self) -> None:
        raw = json.loads(
            (VECTOR_DIR / "bundles" / "valid.bundle.json").read_text(encoding="utf-8")
        )
        assert parse_bundle(raw).to_dict() == raw

    @pytest.mark.parametrize(
        ("mutate", "fragment"),
        [
            (lambda b: b.pop("signatures"), "must be an array"),
            (lambda b: b.pop("payload"), "missing field"),
            (lambda b: b.update(payloadType="application/json"), "payloadType"),
            (lambda b: b.update(payload=""), "must not be empty"),
            (lambda b: b.update(signatures={}), "must be an array"),
            (lambda b: b.update(extra=1), "unknown field"),
            (lambda b: b["signatures"].append({"keyid": "x", "sig": "y"}), "keyid"),
        ],
    )
    def test_rejects_a_malformed_envelope(self, mutate, fragment) -> None:
        bundle = json.loads(
            (VECTOR_DIR / "bundles" / "valid.bundle.json").read_text(encoding="utf-8")
        )
        mutate(bundle)
        with pytest.raises(BundleError, match=fragment) as caught:
            parse_bundle(bundle)
        assert caught.value.reason == "malformed_bundle"

    def test_rejects_text_that_is_not_json(self) -> None:
        with pytest.raises(BundleError, match="not valid JSON"):
            parse_bundle("not json")

    def test_rejects_a_payload_that_is_not_base64(self) -> None:
        with pytest.raises(BundleError, match="not valid base64"):
            parse_bundle(
                {"payloadType": PAYLOAD_TYPE, "payload": "!!!!", "signatures": []}
            ).payload_bytes()


class TestStatementShape:
    """Check 1 beyond the envelope: every refusal is ``malformed_bundle``."""

    @pytest.mark.parametrize(
        ("mutate", "fragment"),
        [
            (lambda s: s.update(_type="https://in-toto.io/Statement/v0.1"), "_type"),
            (lambda s: s.update(subject=[]), "exactly one subject"),
            (
                lambda s: s.update(subject=[s["subject"][0], s["subject"][0]]),
                "exactly one subject",
            ),
            (lambda s: s["subject"][0].update(name=""), "must not be empty"),
            (
                lambda s: s["subject"][0]["digest"].update(sha256="ABC"),
                "64 lowercase hex",
            ),
            (
                lambda s: s["subject"][0]["digest"].update(sha512="0" * 128),
                "unknown field",
            ),
            (lambda s: s["predicate"].update(bundle_version="0.2"), "bundle_version"),
            (lambda s: s["predicate"].update(chain=[]), "at least one link"),
            (lambda s: s["predicate"].update(resolved=[]), "must be an object"),
            (lambda s: s["predicate"]["resolver"].update(tool=""), "must not be empty"),
            (
                lambda s: s["predicate"].update(created_at="2026-09-15T12:00:00Z"),
                "millisecond precision",
            ),
            (
                lambda s: s["predicate"].update(created_at="2026-13-15T12:00:00.000Z"),
                "not a real instant",
            ),
            (
                lambda s: s["predicate"]["policy"].update(content_hash="sha256:zz"),
                "content_hash",
            ),
            (
                lambda s: s["predicate"]["policy"].update(policy_version="4"),
                "non-negative integer",
            ),
            (
                lambda s: s["predicate"]["chain"][0].update(content_hash="nope"),
                "content_hash",
            ),
            (lambda s: s["predicate"]["chain"][0].update(source=""), "must not be empty"),
            (lambda s: s["predicate"].update(surprise=1), "unknown field"),
        ],
    )
    def test_rejects(self, mutate, fragment) -> None:
        statement = _valid_statement()
        mutate(statement)
        with pytest.raises(BundleError, match=fragment) as caught:
            parse_bundle(_envelope_for(statement)).statement()
        assert caught.value.reason == "malformed_bundle"

    def test_accepts_the_vector_statement(self) -> None:
        statement = parse_bundle(_envelope_for(_valid_statement())).statement()
        assert statement.statement_type == STATEMENT_TYPE
        assert statement.predicate_type == PREDICATE_TYPE
        assert statement.predicate.bundle_version == BUNDLE_VERSION
        assert len(statement.subject) == 1

    def test_rejects_a_payload_that_is_not_an_object(self) -> None:
        envelope = {
            "payloadType": PAYLOAD_TYPE,
            "payload": base64.b64encode(b"[]").decode("ascii"),
            "signatures": [],
        }
        with pytest.raises(BundleError, match="must be a JSON object"):
            parse_bundle(envelope).statement()


# ---- Trust inputs ---- #


class TestTrustInputs:
    def test_a_bare_public_key_is_a_one_key_keyring(self) -> None:
        bundle = json.loads(
            (VECTOR_DIR / "bundles" / "valid.bundle.json").read_text(encoding="utf-8")
        )
        pem = (
            REPO_ROOT / "fixtures" / "signing" / "keys" / "test-signing.pub.pem"
        ).read_text(encoding="utf-8")
        assert verify_bundle(bundle, public_key_pem=pem, now=DEFAULTS["now"]).valid

    @pytest.mark.parametrize(
        "kwargs",
        [{}, {"keyring": {"keyring_version": "0.2", "keys": []}, "public_key_pem": "x"}],
    )
    def test_exactly_one_trust_input_is_required(self, kwargs) -> None:
        with pytest.raises(SigningError, match="exactly one"):
            verify_bundle({}, **kwargs)

    def test_now_defaults_to_the_current_time(self) -> None:
        bundle = json.loads(
            (VECTOR_DIR / "bundles" / "valid.bundle.json").read_text(encoding="utf-8")
        )
        keyring = json.loads(
            (VECTOR_DIR / DEFAULTS["keyring"]).read_text(encoding="utf-8")
        )
        result = verify_bundle(bundle, keyring=keyring)
        assert result.valid
        assert result.verified_at and result.verified_at.endswith("Z")


# ---- The optional crypto backend ---- #


_WITHOUT_CRYPTOGRAPHY = textwrap.dedent(
    """
    import sys

    class Blocker:
        def find_module(self, name, path=None):
            return self if name.split(".")[0] == "cryptography" else None

        def find_spec(self, name, path=None, target=None):
            if name.split(".")[0] == "cryptography":
                raise ImportError("blocked")
            return None

    sys.meta_path.insert(0, Blocker())
    for name in [n for n in sys.modules if n.split(".")[0] == "cryptography"]:
        del sys.modules[name]

    from hushspec.bundle import verify_bundle
    from hushspec.signing import SigningUnavailable

    try:
        verify_bundle({}, public_key_pem="x")
    except SigningUnavailable as exc:
        assert "hushspec[signing]" in str(exc), str(exc)
        print("OK")
    else:
        raise AssertionError("verify_bundle returned a result with no Ed25519 backend")
    """
)


def test_verification_without_cryptography_raises_rather_than_answering() -> None:
    """"Could not check" must never be readable as "this bundle is good"."""
    completed = subprocess.run(
        [sys.executable, "-c", _WITHOUT_CRYPTOGRAPHY],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT / "packages" / "python"),
    )
    assert completed.returncode == 0, completed.stderr
    assert "OK" in completed.stdout
