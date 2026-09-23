"""Normative policy-signing vectors (spec/hushspec-signing.md section 9).

Every case in ``fixtures/signing/vectors.yaml`` pairs a policy, a detached
envelope, a keyring and a verifier clock with the outcome a conformant verifier
MUST return: ``valid``, or invalid with an exact reason code from spec section
6.4. All four SDKs run the same directory; a divergence here is a conformance
failure, not a test-fixture problem.

Beyond the vectors this file covers the signer half -- sign, verify, round
trip, determinism -- and checks that produced envelopes validate against
``schemas/hushspec-signature.v1.schema.json``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from hushspec import content_hash
from hushspec.parse import CoreSafeLoader
from hushspec.resolve import create_builtin_loader, resolve
from hushspec.schema import HushSpec
from hushspec.signing import (
    ENVELOPE_FORMAT_VERSION,
    REASON_CODES,
    SIGNATURE_ALGORITHM,
    Envelope,
    Keyring,
    KeyringError,
    MalformedEnvelope,
    SigningError,
    TrustedKey,
    format_timestamp,
    key_id_from_public_key,
    load_keyring,
    parse_envelope,
    public_key_from_private_key,
    sign_policy,
    signing_input,
    verify_policy,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
VECTOR_DIR = REPO_ROOT / "fixtures" / "signing"
VECTOR_FILE = VECTOR_DIR / "vectors.yaml"
VECTOR_VERSION = "0.1.0"

SIGNING_KEY = VECTOR_DIR / "keys" / "test-signing.key.pem"
SIGNING_PUB = VECTOR_DIR / "keys" / "test-signing.pub.pem"
UNTRUSTED_KEY = VECTOR_DIR / "keys" / "test-untrusted.key.pem"
DEFAULT_KEYRING = VECTOR_DIR / "keys" / "keyring.json"

pytest.importorskip(
    "cryptography",
    reason="policy signing needs the optional `signing` extra: pip install hushspec[signing]",
)


def _signature_schema() -> dict[str, Any]:
    """The published signature schema for this envelope format version.

    A schema that has moved or whose ``format_version`` has drifted is a
    failure, not a skip: keeping the envelopes this SDK writes in step with
    the published schema is what these tests are for.
    """
    path = REPO_ROOT / "schemas" / "hushspec-signature.v1.schema.json"
    assert path.is_file(), f"{path} is missing"
    schema = json.loads(path.read_text(encoding="utf-8"))
    declared = schema.get("properties", {}).get("format_version", {}).get("const")
    assert declared == ENVELOPE_FORMAT_VERSION, (
        f"{path} declares format_version {declared!r}, "
        f"this SDK writes {ENVELOPE_FORMAT_VERSION!r}"
    )
    return schema


def _load_manifest() -> dict[str, Any]:
    manifest = yaml.load(VECTOR_FILE.read_text(encoding="utf-8"), Loader=CoreSafeLoader)
    assert isinstance(manifest, dict), "vectors.yaml must be a mapping"
    assert manifest.get("hushspec_signing_vectors") == VECTOR_VERSION, (
        f"vectors.yaml is not a hushspec_signing_vectors {VECTOR_VERSION} file"
    )
    return manifest


MANIFEST = _load_manifest()
DEFAULTS: dict[str, Any] = MANIFEST.get("defaults") or {}
CASES: list[dict[str, Any]] = list(MANIFEST["cases"])


def _resolved_policy(relative: str) -> Any:
    """Load a vector policy and resolve its ``extends`` chain.

    The raw mapping is canonicalized, not the typed model, because the absent/
    empty distinction of the canonical spec section 3.3 survives only in the
    raw form. A policy that extends is resolved through the embedded builtins,
    which is the whole point of the ``extends-chain-resolved-before-hashing``
    case: the signature covers the merged document, not the file on disk.
    """
    path = VECTOR_DIR / relative
    raw = yaml.load(path.read_text(encoding="utf-8"), Loader=CoreSafeLoader)
    assert isinstance(raw, dict), f"{relative}: policy must be a mapping"
    if raw.get("extends") is None:
        return raw
    ok, resolved = resolve(HushSpec.from_dict(raw), loader=create_builtin_loader())
    assert ok, f"{relative}: could not resolve `extends`: {resolved}"
    return resolved


def _case_setting(case: dict[str, Any], key: str) -> Any:
    return case.get(key, DEFAULTS.get(key))


def _expected(case: dict[str, Any]) -> tuple[bool, str | None]:
    expect = case["expect"]
    if expect == "valid":
        return True, None
    assert isinstance(expect, dict) and "invalid" in expect, (
        f"{case['name']}: `expect` must be 'valid' or {{invalid: <reason>}}"
    )
    return False, expect["invalid"]


def test_vector_manifest_is_populated() -> None:
    assert len(CASES) == 18, f"expected the 18 normative signing vectors, found {len(CASES)}"
    names = [case["name"] for case in CASES]
    assert len(set(names)) == len(names), "vector names must be unique"


def test_every_expected_reason_is_a_spec_reason_code() -> None:
    for case in CASES:
        valid, reason = _expected(case)
        if not valid:
            assert reason in REASON_CODES, (
                f"{case['name']}: {reason!r} is not a spec section 6.4 reason code"
            )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_signing_vector(case: dict[str, Any]) -> None:
    policy = _resolved_policy(case["policy"])
    envelope = json.loads((VECTOR_DIR / case["signature"]).read_text(encoding="utf-8"))
    keyring = load_keyring(
        json.loads((VECTOR_DIR / _case_setting(case, "keyring")).read_text(encoding="utf-8"))
    )

    result = verify_policy(
        policy,
        envelope,
        keyring=keyring,
        now=_case_setting(case, "now"),
        max_clock_skew_seconds=_case_setting(case, "max_clock_skew_seconds") or 300,
        last_seen_version=case.get("last_seen_version"),
    )

    expected_valid, expected_reason = _expected(case)
    if expected_valid:
        assert result.valid, (
            f"{case['name']}: expected valid, got {result.reason}: {result.detail}"
        )
        assert result.reason is None
    else:
        assert not result.valid, f"{case['name']}: expected {expected_reason}, got valid"
        assert result.reason == expected_reason, (
            f"{case['name']}: expected {expected_reason}, got {result.reason}: {result.detail}"
        )
    assert bool(result) is result.valid


#: Vectors whose envelope is deliberately not a well-formed 0.2 envelope,
#: mapped to the reason parsing it must carry. ``bad-algorithm`` and
#: ``bad-format-version`` pin values the schema closes with ``const``, which is
#: exactly why spec section 6.2 gives each its own check rather than folding it
#: into check 1; ``impossible-signed-at-date`` and ``leap-second-signed-at``
#: fail check 1 itself.
_UNPARSEABLE_VECTORS = {
    "bad-algorithm": "unsupported_algorithm",
    "bad-format-version": "unsupported_format_version",
    "impossible-signed-at-date": "malformed_envelope",
    "leap-second-signed-at": "malformed_envelope",
}


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_vector_envelopes_match_the_signature_schema(case: dict[str, Any]) -> None:
    """Every other negative vector is a structurally well-formed 0.2 envelope."""
    envelope = json.loads((VECTOR_DIR / case["signature"]).read_text(encoding="utf-8"))
    expected_reason = _UNPARSEABLE_VECTORS.get(case["name"])
    if expected_reason is not None:
        with pytest.raises(MalformedEnvelope) as caught:
            parse_envelope(envelope)
        assert caught.value.reason == expected_reason
        return
    _assert_matches_signature_schema(envelope)
    parsed = parse_envelope(envelope)
    assert parsed.to_dict() == envelope


# --------------------------------------------------------------------------- #
# Schema conformance of produced envelopes
# --------------------------------------------------------------------------- #


def _assert_matches_signature_schema(envelope: dict[str, Any]) -> None:
    """Validate against the published schema, or fall back to a structural check.

    ``jsonschema`` is a dev-only dependency; when it is absent the structural
    pass below still enforces the members and patterns the schema declares, so
    the assertion never silently becomes a no-op.
    """
    schema = _signature_schema()
    try:
        import jsonschema
    except ImportError:
        _assert_structurally_valid(envelope, schema)
        return
    jsonschema.validate(envelope, schema)


def _assert_structurally_valid(envelope: dict[str, Any], schema: dict[str, Any]) -> None:
    import re

    properties = schema["properties"]
    assert set(envelope) <= set(properties), (
        f"unknown envelope member(s): {sorted(set(envelope) - set(properties))}"
    )
    for required in schema["required"]:
        assert required in envelope, f"missing required member `{required}`"
    for key, value in envelope.items():
        rule = properties[key]
        if rule.get("type") == "integer":
            assert isinstance(value, int) and not isinstance(value, bool)
            if "minimum" in rule:
                assert value >= rule["minimum"]
            continue
        assert isinstance(value, str), f"`{key}` must be a string"
        if "const" in rule:
            assert value == rule["const"], f"`{key}` must be {rule['const']!r}"
        if "pattern" in rule:
            assert re.match(rule["pattern"], value), f"`{key}` does not match its pattern"
        if "minLength" in rule:
            assert len(value) >= rule["minLength"]


# --------------------------------------------------------------------------- #
# Signing
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def signing_key() -> str:
    return SIGNING_KEY.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def generated_key() -> str:
    """A freshly generated PKCS#8 Ed25519 key, so the round trip owns its key."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    key = ed25519.Ed25519PrivateKey.generate()
    return key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode("ascii")


@pytest.fixture(scope="module")
def basic_policy() -> Any:
    return _resolved_policy("policies/basic.yaml")


def test_sign_then_verify_round_trip(generated_key: str, basic_policy: Any) -> None:
    envelope = sign_policy(basic_policy, generated_key, signer="tests@hushspec.dev")
    keyring = Keyring.from_public_key(public_key_from_private_key(generated_key))

    result = verify_policy(basic_policy, envelope, keyring=keyring)
    assert result.valid, f"{result.reason}: {result.detail}"
    assert result.key_id == envelope.key_id

    # The claims the spec asks a signer to copy from the policy (section 4.2).
    assert envelope.content_hash == content_hash(basic_policy)
    assert envelope.policy_name == "signed-basic"
    assert envelope.policy_version == 4
    assert envelope.format_version == ENVELOPE_FORMAT_VERSION
    assert envelope.algorithm == SIGNATURE_ALGORITHM
    assert len(envelope.signature) == 86 and "=" not in envelope.signature


def test_round_trip_through_the_sig_file_json(generated_key: str, basic_policy: Any) -> None:
    envelope = sign_policy(basic_policy, generated_key)
    reparsed = parse_envelope(json.loads(envelope.to_json()))
    assert reparsed == envelope
    assert verify_policy(
        basic_policy,
        reparsed,
        public_key_pem=public_key_from_private_key(generated_key),
    ).valid


def test_produced_envelope_matches_the_signature_schema(
    generated_key: str, basic_policy: Any
) -> None:
    envelope = sign_policy(
        basic_policy,
        generated_key,
        signed_at="2026-09-15T09:00:00.000Z",
        expires_at="2027-09-15T09:00:00.000Z",
        signer="security@example.com",
    )
    _assert_matches_signature_schema(envelope.to_dict())


def test_signing_is_deterministic(generated_key: str, basic_policy: Any) -> None:
    """Ed25519 is deterministic, so the same claims give byte-identical output."""
    first = sign_policy(basic_policy, generated_key, signed_at="2026-09-15T09:00:00.000Z")
    second = sign_policy(basic_policy, generated_key, signed_at="2026-09-15T09:00:00.000Z")
    assert first == second
    assert first.to_json() == second.to_json()


def test_signing_reproduces_the_published_basic_vector(
    signing_key: str, basic_policy: Any
) -> None:
    """The signer half of the `basic` vector, byte for byte.

    The published test key is deterministic, so a conformant signer given the
    same claims MUST reproduce the exact signature in ``policies/basic.sig``.
    """
    published = json.loads((VECTOR_DIR / "policies" / "basic.sig").read_text(encoding="utf-8"))
    envelope = sign_policy(
        basic_policy,
        signing_key,
        signed_at=published["signed_at"],
        signer=published["signer"],
    )
    assert envelope.to_dict() == published


def test_signing_input_is_the_canonical_claims(signing_key: str, basic_policy: Any) -> None:
    envelope = sign_policy(
        basic_policy, signing_key, signed_at="2026-09-15T09:00:00.000Z"
    )
    payload = signing_input(envelope.claims()).decode("utf-8")
    assert "signature" not in payload
    assert payload.startswith('{"algorithm":"ed25519","content_hash":"sha256:')
    # RFC 8785: keys in UTF-16 code-unit order, no whitespace.
    assert " " not in payload.replace('"signer":"', "").split('"signer"')[0]
    assert json.loads(payload) == envelope.claims()


def test_sign_refuses_an_unresolved_policy(signing_key: str) -> None:
    """Spec section 3: a signer that cannot resolve the chain MUST refuse to sign."""
    from hushspec.canonical import CanonicalError

    unresolved = yaml.load(
        (VECTOR_DIR / "policies" / "extends-child.yaml").read_text(encoding="utf-8"),
        Loader=CoreSafeLoader,
    )
    with pytest.raises(CanonicalError):
        sign_policy(unresolved, signing_key)


def test_signer_and_expiry_are_optional(generated_key: str, basic_policy: Any) -> None:
    envelope = sign_policy(basic_policy, generated_key)
    assert envelope.signer is None
    assert envelope.expires_at is None
    assert "signer" not in envelope.to_dict()
    assert "expires_at" not in envelope.to_dict()


def test_explicit_claims_override_the_policy(generated_key: str, basic_policy: Any) -> None:
    envelope = sign_policy(
        basic_policy, generated_key, policy_version=9, policy_name="renamed"
    )
    assert envelope.policy_version == 9
    assert envelope.policy_name == "renamed"


# --------------------------------------------------------------------------- #
# Verification behaviour beyond the vectors
# --------------------------------------------------------------------------- #


def test_editing_any_claim_breaks_the_signature(generated_key: str, basic_policy: Any) -> None:
    """Spec section 4.1: every member is inside the signing input."""
    envelope = sign_policy(basic_policy, generated_key, signer="security@example.com")
    public_key = public_key_from_private_key(generated_key)
    for member, value in (
        ("signer", "attacker@example.com"),
        ("signed_at", "2026-01-01T00:00:00.000Z"),
        ("policy_name", "something-else"),
        ("policy_version", 99),
    ):
        edited = envelope.to_dict()
        edited[member] = value
        result = verify_policy(basic_policy, edited, public_key_pem=public_key)
        assert result.reason == "signature_mismatch", f"editing {member} should break the seal"


def test_clock_skew_window(generated_key: str, basic_policy: Any) -> None:
    envelope = sign_policy(basic_policy, generated_key, signed_at="2026-09-15T12:00:00.000Z")
    public_key = public_key_from_private_key(generated_key)

    # 200s in the past relative to signed_at, inside the default 300s allowance.
    inside = verify_policy(
        basic_policy, envelope, public_key_pem=public_key, now="2026-09-15T11:56:40.000Z"
    )
    assert inside.valid

    outside = verify_policy(
        basic_policy,
        envelope,
        public_key_pem=public_key,
        now="2026-09-15T11:56:40.000Z",
        max_clock_skew_seconds=0,
    )
    assert outside.reason == "signed_at_in_future"


def test_expiry_boundary_is_inclusive(generated_key: str, basic_policy: Any) -> None:
    """Spec section 4: the signature is invalid *at* or after ``expires_at``."""
    envelope = sign_policy(
        basic_policy,
        generated_key,
        signed_at="2026-09-15T09:00:00.000Z",
        expires_at="2026-09-15T10:00:00.000Z",
    )
    public_key = public_key_from_private_key(generated_key)
    assert verify_policy(
        basic_policy, envelope, public_key_pem=public_key, now="2026-09-15T09:59:59.999Z"
    ).valid
    assert (
        verify_policy(
            basic_policy, envelope, public_key_pem=public_key, now="2026-09-15T10:00:00.000Z"
        ).reason
        == "expired"
    )


def test_retirement_boundary_is_inclusive(generated_key: str, basic_policy: Any) -> None:
    """Spec section 5.3: signatures dated before ``not_after`` remain valid."""
    public_key = public_key_from_private_key(generated_key)
    ring = Keyring(
        keys=(
            TrustedKey(
                key_id=key_id_from_public_key(public_key),
                algorithm=SIGNATURE_ALGORITHM,
                public_key=public_key,
                not_after="2026-09-15T00:00:00.000Z",
            ),
        )
    )
    before = sign_policy(basic_policy, generated_key, signed_at="2026-09-14T23:59:59.999Z")
    assert verify_policy(
        basic_policy, before, keyring=ring, now="2026-09-15T12:00:00.000Z"
    ).valid
    at = sign_policy(basic_policy, generated_key, signed_at="2026-09-15T00:00:00.000Z")
    assert (
        verify_policy(basic_policy, at, keyring=ring, now="2026-09-15T12:00:00.000Z").reason
        == "key_retired"
    )


def test_rollback_requires_both_sides(generated_key: str, basic_policy: Any) -> None:
    """Check 10 applies only when the verifier and the envelope both have a version."""
    public_key = public_key_from_private_key(generated_key)
    versioned = sign_policy(basic_policy, generated_key, policy_version=3)
    assert (
        verify_policy(
            basic_policy, versioned, public_key_pem=public_key, last_seen_version=4
        ).reason
        == "policy_version_rollback"
    )
    assert verify_policy(
        basic_policy, versioned, public_key_pem=public_key, last_seen_version=3
    ).valid
    # An envelope with no version cannot be rolled back by this check.
    unversioned = parse_envelope(
        {k: v for k, v in versioned.to_dict().items() if k != "policy_version"}
    )
    assert (
        verify_policy(
            basic_policy, unversioned, public_key_pem=public_key, last_seen_version=4
        ).reason
        == "signature_mismatch"  # removing a signed claim breaks the seal first
    )


def test_verify_needs_exactly_one_trust_input(basic_policy: Any) -> None:
    """Neither trust input and both of them are distinct refusals."""
    envelope = json.loads((VECTOR_DIR / "policies" / "basic.sig").read_text(encoding="utf-8"))
    with pytest.raises(SigningError, match="keyring|public key|trust"):
        verify_policy(basic_policy, envelope)
    with pytest.raises(SigningError, match="both|one of|not both"):
        verify_policy(
            basic_policy,
            envelope,
            keyring=load_keyring(json.loads(DEFAULT_KEYRING.read_text())),
            public_key_pem=SIGNING_PUB.read_text(),
        )


def test_wrong_key_in_a_one_key_keyring_is_unknown_key_id(basic_policy: Any) -> None:
    """Spec section 5.3: a verifier never falls back to another key."""
    envelope = json.loads((VECTOR_DIR / "policies" / "basic.sig").read_text(encoding="utf-8"))
    untrusted_pub = public_key_from_private_key(UNTRUSTED_KEY.read_text(encoding="utf-8"))
    result = verify_policy(basic_policy, envelope, public_key_pem=untrusted_pub)
    assert result.reason == "unknown_key_id"


@pytest.mark.parametrize(
    "mutation,expected",
    [
        ({"signature": "not-base64url!"}, "malformed_envelope"),
        ({"key_id": "deadbeef"}, "malformed_envelope"),
        ({"content_hash": "sha256:NOTHEX"}, "malformed_envelope"),
        ({"signed_at": "2026-09-15T09:00:00Z"}, "malformed_envelope"),
        ({"signed_at": "2026-13-45T09:00:00.000Z"}, "malformed_envelope"),
        ({"policy_version": -1}, "malformed_envelope"),
        ({"policy_version": True}, "malformed_envelope"),
        ({"unexpected": "field"}, "malformed_envelope"),
        ({"format_version": "0.3"}, "unsupported_format_version"),
        ({"algorithm": "ed448"}, "unsupported_algorithm"),
    ],
)
def test_malformed_envelopes_fail_closed(
    basic_policy: Any, mutation: dict[str, Any], expected: str
) -> None:
    envelope = json.loads((VECTOR_DIR / "policies" / "basic.sig").read_text(encoding="utf-8"))
    envelope.update(mutation)
    keyring = load_keyring(json.loads(DEFAULT_KEYRING.read_text(encoding="utf-8")))
    result = verify_policy(
        basic_policy, envelope, keyring=keyring, now="2026-09-15T12:00:00.000Z"
    )
    assert result.reason == expected

    with pytest.raises(MalformedEnvelope) as caught:
        parse_envelope(envelope)
    assert caught.value.reason == expected


@pytest.mark.parametrize("dropped", ["format_version", "algorithm", "key_id", "signature"])
def test_missing_required_members_fail_closed(basic_policy: Any, dropped: str) -> None:
    envelope = json.loads((VECTOR_DIR / "policies" / "basic.sig").read_text(encoding="utf-8"))
    del envelope[dropped]
    result = verify_policy(
        basic_policy,
        envelope,
        public_key_pem=SIGNING_PUB.read_text(encoding="utf-8"),
        now="2026-09-15T12:00:00.000Z",
    )
    assert result.reason == "malformed_envelope"


def test_unresolvable_policy_is_a_content_hash_mismatch(basic_policy: Any) -> None:
    """Spec section 6.2 check 9: no hash to compare is a mismatch, not a crash."""
    unresolved = yaml.load(
        (VECTOR_DIR / "policies" / "extends-child.yaml").read_text(encoding="utf-8"),
        Loader=CoreSafeLoader,
    )
    envelope = json.loads(
        (VECTOR_DIR / "policies" / "extends-child.sig").read_text(encoding="utf-8")
    )
    result = verify_policy(
        unresolved,
        envelope,
        keyring=load_keyring(json.loads(DEFAULT_KEYRING.read_text(encoding="utf-8"))),
        now="2026-09-15T12:00:00.000Z",
    )
    assert result.reason == "content_hash_mismatch"


# --------------------------------------------------------------------------- #
# Keyrings
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name", ["keyring.json", "keyring-retired.json", "keyring-revoked.json"]
)
def test_published_keyrings_load(name: str) -> None:
    ring = load_keyring(json.loads((VECTOR_DIR / "keys" / name).read_text(encoding="utf-8")))
    assert len(ring.keys) == 1
    entry = ring.keys[0]
    assert entry.key_id == key_id_from_public_key(entry.public_key)
    assert ring.find(entry.key_id) is entry
    assert ring.find("sha256:" + "0" * 64) is None


def test_keyring_rejects_a_key_id_that_does_not_match_its_key() -> None:
    """Spec section 5.2: verifiers MUST NOT trust a declared id that differs."""
    ring = json.loads(DEFAULT_KEYRING.read_text(encoding="utf-8"))
    ring["keys"][0]["key_id"] = "sha256:" + "a" * 64
    with pytest.raises(KeyringError, match="does not match"):
        load_keyring(ring)


@pytest.mark.parametrize(
    "mutation",
    [
        {"keyring_version": "0.1"},
        {"keys": []},
        {"keys": "not-an-array"},
        {"unexpected": True},
    ],
)
def test_malformed_keyrings_are_rejected(mutation: dict[str, Any]) -> None:
    ring = json.loads(DEFAULT_KEYRING.read_text(encoding="utf-8"))
    ring.update(mutation)
    with pytest.raises(KeyringError):
        load_keyring(ring)


def test_keyring_rejects_a_non_ed25519_entry() -> None:
    ring = json.loads(DEFAULT_KEYRING.read_text(encoding="utf-8"))
    ring["keys"][0]["algorithm"] = "rsa-pss"
    with pytest.raises(KeyringError, match="unsupported algorithm"):
        load_keyring(ring)


def test_keyring_accepts_json_text_and_a_bare_public_key() -> None:
    from_text = load_keyring(DEFAULT_KEYRING.read_text(encoding="utf-8"))
    assert len(from_text.keys) == 1

    # A public key file, header comments and all, as a one-key keyring.
    from_pem = load_keyring(SIGNING_PUB.read_text(encoding="utf-8"))
    assert from_pem.keys[0].key_id == from_text.keys[0].key_id
    assert from_pem.keyring_version == from_text.keyring_version
    # The comment header is dropped; the armored block is kept verbatim.
    assert from_pem.keys[0].public_key.startswith("-----BEGIN PUBLIC KEY-----\n")
    assert "DO NOT USE" not in from_pem.keys[0].public_key


def test_keyring_round_trips_through_its_dict_form() -> None:
    ring = load_keyring(json.loads((VECTOR_DIR / "keys" / "keyring-retired.json").read_text()))
    assert load_keyring(ring.to_dict()) == ring


# --------------------------------------------------------------------------- #
# Key identifiers
# --------------------------------------------------------------------------- #


def test_key_id_matches_the_published_value() -> None:
    """Spec section 5.2 over the published test key, with and without its header."""
    published = json.loads(DEFAULT_KEYRING.read_text(encoding="utf-8"))["keys"][0]["key_id"]
    assert key_id_from_public_key(SIGNING_PUB.read_text(encoding="utf-8")) == published
    assert key_id_from_public_key(published_pem := _armor_only(SIGNING_PUB)) == published
    assert published_pem.startswith("-----BEGIN PUBLIC KEY-----")


def _armor_only(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    start = text.index("-----BEGIN PUBLIC KEY-----")
    return text[start:]


def test_key_id_derives_from_the_private_key_too() -> None:
    derived = public_key_from_private_key(SIGNING_KEY.read_text(encoding="utf-8"))
    assert key_id_from_public_key(derived) == key_id_from_public_key(
        SIGNING_PUB.read_text(encoding="utf-8")
    )


@pytest.mark.parametrize(
    "bad",
    [
        "not a pem at all",
        "-----BEGIN PUBLIC KEY-----\nnot base64!!\n-----END PUBLIC KEY-----\n",
        # A valid PEM block that is too short to be an Ed25519 SPKI.
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2Vw\n-----END PUBLIC KEY-----\n",
    ],
)
def test_key_id_rejects_non_ed25519_material(bad: str) -> None:
    with pytest.raises(SigningError):
        key_id_from_public_key(bad)


# --------------------------------------------------------------------------- #
# Timestamps
# --------------------------------------------------------------------------- #


def test_timestamps_are_millisecond_utc() -> None:
    from datetime import datetime, timedelta, timezone

    assert (
        format_timestamp(datetime(2026, 9, 15, 9, 0, 0, 123456, tzinfo=timezone.utc))
        == "2026-09-15T09:00:00.123Z"
    )
    # Sub-millisecond precision truncates rather than rounding up.
    assert (
        format_timestamp(datetime(2026, 9, 15, 9, 0, 0, 999999, tzinfo=timezone.utc))
        == "2026-09-15T09:00:00.999Z"
    )
    # A non-UTC offset is converted, not stamped with the wrong Z.
    other = datetime(2026, 9, 15, 11, 0, 0, tzinfo=timezone(timedelta(hours=2)))
    assert format_timestamp(other) == "2026-09-15T09:00:00.000Z"


def test_envelope_datetime_arguments_are_normalized(
    generated_key: str, basic_policy: Any
) -> None:
    from datetime import datetime, timezone

    envelope = sign_policy(
        basic_policy,
        generated_key,
        signed_at=datetime(2026, 9, 15, 9, 0, 0, tzinfo=timezone.utc),
        expires_at=datetime(2027, 9, 15, 9, 0, 0, tzinfo=timezone.utc),
    )
    assert envelope.signed_at == "2026-09-15T09:00:00.000Z"
    assert envelope.expires_at == "2027-09-15T09:00:00.000Z"
    assert isinstance(envelope, Envelope)


# --------------------------------------------------------------------------- #
# The optional crypto backend
# --------------------------------------------------------------------------- #


_WITHOUT_CRYPTOGRAPHY = '''
import sys


class _Blocker:
    """Make `cryptography` unimportable, as it is on a bare `pip install hushspec`."""

    def find_spec(self, name, path=None, target=None):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("no cryptography (simulated)")
        return None


for _name in [n for n in sys.modules if n == "cryptography" or n.startswith("cryptography.")]:
    del sys.modules[_name]
sys.meta_path.insert(0, _Blocker())

# Importing the package and the module must still work: the crypto import is
# lazy, so a policy can be parsed and hashed without a signing backend.
import hushspec
from hushspec.signing import (
    SigningUnavailable,
    key_id_from_public_key,
    load_keyring,
    parse_envelope,
    sign_policy,
    verify_policy,
)

PUB = open({pub!r}).read()
ENVELOPE = open({sig!r}).read()
KEYRING = open({keyring!r}).read()
POLICY = {{"hushspec": "0.2.0", "name": "signed-basic"}}

# The stdlib-only surface keeps working.
assert key_id_from_public_key(PUB).startswith("sha256:")
assert len(load_keyring(KEYRING).keys) == 1
assert parse_envelope(ENVELOPE).algorithm == "ed25519"
assert hushspec.content_hash(POLICY).startswith("sha256:")

# The signature operations refuse loudly instead of guessing.
for call in (
    lambda: sign_policy(POLICY, "-----BEGIN PRIVATE KEY-----\\nx\\n-----END PRIVATE KEY-----\\n"),
    lambda: verify_policy(POLICY, ENVELOPE, keyring=KEYRING),
):
    try:
        call()
    except SigningUnavailable as exc:
        assert "hushspec[signing]" in str(exc), exc
    else:
        raise AssertionError("expected SigningUnavailable")

print("ok")
'''


def test_without_cryptography_it_fails_closed() -> None:
    """Without the ``signing`` extra, nothing reports an unverified signature as good.

    Run in a subprocess because the import has to fail at first use, and this
    process has already imported ``cryptography``.
    """
    import subprocess
    import sys

    script = _WITHOUT_CRYPTOGRAPHY.format(
        pub=str(SIGNING_PUB),
        sig=str(VECTOR_DIR / "policies" / "basic.sig"),
        keyring=str(DEFAULT_KEYRING),
    )
    done = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, f"stdout={done.stdout}\nstderr={done.stderr}"
    assert done.stdout.strip().endswith("ok")
