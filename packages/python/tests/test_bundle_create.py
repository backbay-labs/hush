"""Bundle creation (``spec/hushspec-bundle.md`` section 4).

The contract a bundler has to meet is reproducibility: "two bundlers given the
same resolution, the same ``created_at``, and the same resolver therefore
produce byte-identical payloads and -- Ed25519 being deterministic --
byte-identical bundles" (spec section 4). The normative vector
``fixtures/bundle/bundles/valid.bundle.json`` was produced by the reference
CLI, so rebuilding it here from the same policy, key and ``created_at`` puts
that claim under test across two independent implementations.
"""

from __future__ import annotations

import base64
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from hushspec.bundle import (
    BUNDLE_VERSION,
    PAYLOAD_TYPE,
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    REASON_DSSE_SIGNATURE_MISMATCH,
    DsseEnvelope,
    build_statement,
    bundle_to_json,
    create_bundle,
    parse_bundle,
    statement_bytes,
    statement_to_dict,
    verify_bundle,
)
from hushspec.canonical import CanonicalError, canonical_json_value, digest
from hushspec.log import SDK_NAME, _sdk_version
from hushspec.parse import parse_or_raise
from hushspec.resolve import create_composite_loader, resolve_with_options_or_raise

pytest.importorskip(
    "cryptography",
    reason="signing a bundle needs the optional `signing` extra: "
    'pip install "hushspec[signing]"',
)

REPO_ROOT = Path(__file__).resolve().parents[3]
KEYS = REPO_ROOT / "fixtures" / "signing" / "keys"
BUNDLES = REPO_ROOT / "fixtures" / "bundle" / "bundles"

#: The policy every bundle vector attests (``fixtures/bundle/README.md``).
VECTOR_POLICY = REPO_ROOT / "library" / "healthcare" / "hipaa-base.yaml"

#: The ``created_at`` the vectors pin so the bundles are byte-reproducible.
VECTOR_CREATED_AT = "2026-09-15T12:00:00.000Z"


def read_key(name: str) -> str:
    """A published test key, minus the DO-NOT-USE header above its PEM block."""
    text = (KEYS / name).read_text(encoding="utf-8")
    return text[text.index("-----BEGIN") :]


def read_vector(name: str) -> DsseEnvelope:
    return parse_bundle((BUNDLES / name).read_text(encoding="utf-8"))


def vector_resolver() -> dict[str, str]:
    """The reference CLI's resolver, read back from the vector it produced."""
    payload = json.loads(base64.b64decode(read_vector("valid.bundle.json").payload))
    return dict(payload["predicate"]["resolver"])


def vector_resolution():
    spec = parse_or_raise(VECTOR_POLICY.read_text(encoding="utf-8"))
    return resolve_with_options_or_raise(
        spec, source=str(VECTOR_POLICY), loader=create_composite_loader()
    )


def keyring():
    from hushspec.signing import load_keyring

    return load_keyring((KEYS / "keyring.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# Reproducing the normative vectors
# --------------------------------------------------------------------------- #


def test_reproduces_the_signed_vector_byte_for_byte() -> None:
    expected = read_vector("valid.bundle.json")
    built = create_bundle(
        vector_resolution(),
        private_key_pem=read_key("test-signing.key.pem"),
        created_at=VECTOR_CREATED_AT,
        base_dir=REPO_ROOT,
        **vector_resolver(),
    )

    # Equal payloads mean the two bundlers agree on every member of the
    # statement, not merely on its meaning.
    assert built.payload == expected.payload
    assert built.payload_type == expected.payload_type
    assert built.signatures == expected.signatures
    assert bundle_to_json(built) == (BUNDLES / "valid.bundle.json").read_text(
        encoding="utf-8"
    )


def test_reproduces_the_unsigned_vector() -> None:
    expected = read_vector("unsigned.bundle.json")
    built = create_bundle(
        vector_resolution(),
        created_at=VECTOR_CREATED_AT,
        base_dir=REPO_ROOT,
        **vector_resolver(),
    )
    assert built.signatures == ()
    assert built.payload == expected.payload


def test_reproduces_the_untrusted_key_vector() -> None:
    expected = read_vector("wrong-key.bundle.json")
    built = create_bundle(
        vector_resolution(),
        private_key_pem=read_key("test-untrusted.key.pem"),
        created_at=VECTOR_CREATED_AT,
        base_dir=REPO_ROOT,
        **vector_resolver(),
    )
    assert built == expected


def test_is_deterministic() -> None:
    options = {
        "private_key_pem": read_key("test-signing.key.pem"),
        "created_at": VECTOR_CREATED_AT,
        "base_dir": REPO_ROOT,
    }
    assert create_bundle(vector_resolution(), **options) == create_bundle(
        vector_resolution(), **options
    )


# --------------------------------------------------------------------------- #
# Round trip
# --------------------------------------------------------------------------- #


def test_a_created_bundle_verifies() -> None:
    resolution = vector_resolution()
    bundle = create_bundle(
        resolution,
        private_key_pem=read_key("test-signing.key.pem"),
        created_at=VECTOR_CREATED_AT,
        base_dir=REPO_ROOT,
    )
    result = verify_bundle(
        bundle_to_json(bundle),
        keyring=keyring(),
        now=VECTOR_CREATED_AT,
        policy=resolution,
    )
    assert result.valid, result.detail
    assert result.content_hash == resolution.content_hash
    assert result.policy_checked


def test_an_unsigned_bundle_is_refused_at_verification() -> None:
    # Spec section 3: an unsigned bundle is well formed and is not evidence.
    bundle = create_bundle(vector_resolution(), created_at=VECTOR_CREATED_AT)
    result = verify_bundle(bundle_to_json(bundle), keyring=keyring(), now=VECTOR_CREATED_AT)
    assert not result.valid
    assert result.reason == REASON_DSSE_SIGNATURE_MISMATCH


# --------------------------------------------------------------------------- #
# The statement (spec section 4)
# --------------------------------------------------------------------------- #


def test_names_the_constants_of_sections_3_and_4() -> None:
    statement = build_statement(vector_resolution(), created_at=VECTOR_CREATED_AT)
    assert statement.statement_type == STATEMENT_TYPE
    assert statement.predicate_type == PREDICATE_TYPE
    assert statement.predicate.bundle_version == BUNDLE_VERSION
    assert len(statement.subject) == 1


def test_the_subject_digest_is_the_digest_of_predicate_resolved() -> None:
    statement = build_statement(vector_resolution(), created_at=VECTOR_CREATED_AT)
    recomputed = digest(canonical_json_value(statement.predicate.resolved))
    assert statement.predicate.policy.content_hash == recomputed
    assert statement.subject[0].digest.sha256 == recomputed[len("sha256:") :]


def test_the_chain_is_root_first_with_each_hop_hashed_on_its_own() -> None:
    resolution = vector_resolution()
    statement = build_statement(
        resolution, created_at=VECTOR_CREATED_AT, base_dir=REPO_ROOT
    )
    assert [link.source for link in statement.predicate.chain] == [
        "builtin:strict",
        "library/healthcare/hipaa-base.yaml",
    ]
    assert [link.content_hash for link in statement.predicate.chain] == [
        link.content_hash for link in resolution.chain
    ]


def test_a_source_outside_base_dir_is_left_alone() -> None:
    resolution = vector_resolution()
    statement = build_statement(
        resolution, created_at=VECTOR_CREATED_AT, base_dir=REPO_ROOT / "crates"
    )
    # `builtin:strict` is portable already; the leaf is not beneath `crates/`.
    assert statement.predicate.chain[0].source == "builtin:strict"
    assert statement.predicate.chain[1].source == resolution.chain[1].source


def test_signature_verification_is_omitted_when_none_was_attempted() -> None:
    statement = build_statement(vector_resolution(), created_at=VECTOR_CREATED_AT)
    # Recording ``verified: false`` would assert a check that never ran
    # (spec section 4.5).
    assert statement.predicate.signature_verification is None
    assert "signature_verification" not in statement_to_dict(statement)["predicate"]


def test_the_subject_name_falls_back_to_the_leaf_file_name() -> None:
    resolution = vector_resolution()
    unnamed = replace(resolution, spec=replace(resolution.spec, name=None))
    statement = build_statement(
        unnamed, created_at=VECTOR_CREATED_AT, base_dir=REPO_ROOT
    )
    assert statement.subject[0].name == "hipaa-base.yaml"
    assert statement.predicate.policy.name is None


def test_an_explicit_subject_name_wins() -> None:
    statement = build_statement(
        vector_resolution(),
        created_at=VECTOR_CREATED_AT,
        subject_name="release-2026-09",
    )
    assert statement.subject[0].name == "release-2026-09"


def test_created_at_is_written_with_millisecond_precision() -> None:
    statement = build_statement(
        vector_resolution(),
        created_at=datetime(2026, 9, 15, 12, 0, 0, 500_000, tzinfo=timezone.utc),
    )
    assert statement.predicate.created_at == "2026-09-15T12:00:00.500Z"


def test_the_resolver_defaults_to_this_sdk() -> None:
    statement = build_statement(vector_resolution(), created_at=VECTOR_CREATED_AT)
    assert statement.predicate.resolver.tool == SDK_NAME
    assert statement.predicate.resolver.version == _sdk_version()


def test_statement_bytes_is_what_the_payload_carries() -> None:
    resolution = vector_resolution()
    statement = build_statement(
        resolution, created_at=VECTOR_CREATED_AT, base_dir=REPO_ROOT
    )
    bundle = create_bundle(
        resolution, created_at=VECTOR_CREATED_AT, base_dir=REPO_ROOT
    )
    assert base64.b64encode(statement_bytes(statement)).decode() == bundle.payload
    assert bundle.payload_type == PAYLOAD_TYPE


def test_an_unresolved_document_has_no_bundle() -> None:
    spec = parse_or_raise(VECTOR_POLICY.read_text(encoding="utf-8"))
    with pytest.raises(CanonicalError):
        build_statement(spec)
