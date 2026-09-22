"""Verification on load and digest pinning (signing spec section 6.5).

A policy is only as trustworthy as the chain it was merged from, so resolution
can be asked to prove every hop: by digest pin (the reference names the exact
content hash it expects) or by detached signature (an envelope next to the
document, verified against a trusted keyring). This file covers both, the
evidence they leave in :class:`~hushspec.resolve.Resolution`, and what
:class:`~hushspec.middleware.HushGuard` does when the proof fails.

The keys are the published, test-only keypairs under ``fixtures/signing/keys/``;
the policies are written fresh into ``tmp_path`` and signed here, so the
envelopes always cover exactly the documents under test.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from hushspec.canonical import content_hash
from hushspec.evaluate import Decision
from hushspec.middleware import (
    POLICY_SIGNATURE_RULE,
    EnforcementConfig,
    HushGuard,
    HushSpecDenied,
)
from hushspec.parse import parse_or_raise
from hushspec.resolve import (
    INLINE_SOURCE,
    REASON_MISSING_SIGNATURE,
    REASON_NO_KEYRING,
    PolicyVerificationError,
    ResolveOptions,
    VerifyOptions,
    create_composite_loader,
    default_signature_locator,
    resolve,
    resolve_file,
    resolve_with_options,
    resolve_with_options_or_raise,
)
from hushspec.signing import sign_policy
from hushspec.sinks import CallbackSink

REPO_ROOT = Path(__file__).resolve().parents[3]
KEY_DIR = REPO_ROOT / "fixtures" / "signing" / "keys"

pytest.importorskip(
    "cryptography",
    reason="verify-on-load needs the optional `signing` extra: pip install hushspec[signing]",
)

SIGNING_KEY = (KEY_DIR / "test-signing.key.pem").read_text()
SIGNING_PUB = (KEY_DIR / "test-signing.pub.pem").read_text()
UNTRUSTED_KEY = (KEY_DIR / "test-untrusted.key.pem").read_text()

BASE = """
hushspec: "0.1.0"
name: base
rules:
  tool_access:
    allow: [read_file]
    default: block
"""

MID = """
hushspec: "0.1.0"
name: mid
extends: "builtin:strict"
rules:
  egress:
    allow: ["api.example.com"]
    default: block
"""

LEAF_OF_MID = """
hushspec: "0.1.0"
name: leaf
extends: "mid.yaml"
rules:
  egress:
    allow: ["api.example.com", "cdn.example.com"]
    default: block
"""

LEAF_OF_BASE = """
hushspec: "0.1.0"
name: leaf
extends: "base.yaml"
rules:
  egress:
    allow: ["api.example.com"]
    default: block
"""

STANDALONE = """
hushspec: "0.1.0"
name: standalone
rules:
  egress:
    allow: ["api.example.com"]
    default: block
"""


def write(directory: Path, name: str, text: str) -> Path:
    path = directory / name
    path.write_text(text)
    return path


def sign_file(path: Path, key_pem: str = SIGNING_KEY, *, sig_path: Path | None = None, **kwargs):
    """Sign the *resolved* policy at ``path`` and write its detached envelope.

    Signing spec section 3: the envelope covers the content hash of the
    resolved document, so the chain has to be merged before it is signed --
    exactly what the verifier will hash when it loads the same leaf.
    """
    ok, resolved = resolve_file(path)
    assert ok, resolved
    envelope = sign_policy(resolved, key_pem, **kwargs)
    (sig_path or Path(f"{path}.sig")).write_text(envelope.to_json())
    return envelope


def keyring_options(**kwargs) -> ResolveOptions:
    return ResolveOptions(keyring=SIGNING_PUB, **kwargs)


#: The receipt/envelope timestamp spelling: milliseconds, `Z`.
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

# --------------------------------------------------------------------------- #
# Chain construction (receipt spec section 4.2)
# --------------------------------------------------------------------------- #


def test_chain_is_root_first_over_a_builtin_plus_file_chain(tmp_path: Path) -> None:
    write(tmp_path, "mid.yaml", MID)
    leaf = write(tmp_path, "leaf.yaml", LEAF_OF_MID)

    resolution = resolve_with_options_or_raise(
        parse_or_raise(leaf.read_text()),
        source=str(leaf),
        loader=create_composite_loader(),
    )

    assert [link.source for link in resolution.chain] == [
        "builtin:strict",
        str(tmp_path / "mid.yaml"),
        str(leaf),
    ]
    assert resolution.spec.extends is None
    # The resolved document's own hash, not any hop's.
    assert resolution.content_hash == content_hash(resolution.spec)
    assert resolution.content_hash != resolution.chain[-1].content_hash
    # Nothing was verified: no keyring, no requirement.
    assert resolution.signature is None
    assert all(link.signature is None for link in resolution.chain)


def test_each_link_hashes_its_own_document_with_extends_stripped(tmp_path: Path) -> None:
    write(tmp_path, "base.yaml", BASE)
    leaf = write(tmp_path, "leaf.yaml", LEAF_OF_BASE)

    resolution = resolve_with_options_or_raise(
        parse_or_raise(leaf.read_text()),
        source=str(leaf),
        loader=create_composite_loader(),
    )

    root, leaf_link = resolution.chain
    # The base has no `extends`, so its link hash is simply its content hash.
    assert root.content_hash == content_hash(parse_or_raise(BASE))
    # The leaf's is the leaf alone -- `extends` stripped, base *not* merged in.
    stripped = parse_or_raise(LEAF_OF_BASE)
    stripped.extends = None
    assert leaf_link.content_hash == content_hash(stripped)


def test_a_policy_without_extends_has_a_one_link_chain_and_no_receipt_chain() -> None:
    resolution = resolve_with_options_or_raise(parse_or_raise(STANDALONE))

    assert len(resolution.chain) == 1
    assert resolution.chain[0].source == INLINE_SOURCE
    assert resolution.chain[0].content_hash == resolution.content_hash
    # Receipt spec section 4.2: `extends_chain` is absent when there was none.
    assert resolution.extends_chain == []


def test_resolve_stays_a_thin_wrapper() -> None:
    ok, spec = resolve(parse_or_raise(MID))
    assert ok
    assert spec.extends is None
    assert spec.rules is not None and spec.rules.tool_access is not None


# --------------------------------------------------------------------------- #
# Digest pinning
# --------------------------------------------------------------------------- #


def pin_leaf(tmp_path: Path, digest: str, *, base_name: str = "base.yaml") -> Path:
    return write(
        tmp_path,
        "leaf.yaml",
        LEAF_OF_BASE.replace(
            f'extends: "{base_name}"', f'extends: "{base_name}#{digest}"'
        ),
    )


def base_digest(text: str = BASE) -> str:
    return content_hash(parse_or_raise(text))


def test_a_matching_digest_pin_resolves(tmp_path: Path) -> None:
    write(tmp_path, "base.yaml", BASE)
    leaf = pin_leaf(tmp_path, base_digest())

    resolution = resolve_with_options_or_raise(
        parse_or_raise(leaf.read_text()),
        source=str(leaf),
        loader=create_composite_loader(),
    )

    assert resolution.chain[0].content_hash == base_digest()
    assert resolution.spec.rules.tool_access is not None  # merged from the base


def test_a_digest_pin_mismatch_is_fatal_without_require_signature(tmp_path: Path) -> None:
    write(tmp_path, "base.yaml", BASE)
    stale = "sha256:" + "0" * 64
    leaf = pin_leaf(tmp_path, stale)

    with pytest.raises(PolicyVerificationError) as caught:
        resolve_with_options_or_raise(
            parse_or_raise(leaf.read_text()),
            source=str(leaf),
            loader=create_composite_loader(),
        )

    assert caught.value.reason == "digest_mismatch"
    assert caught.value.source == str(tmp_path / "base.yaml")
    assert caught.value.status.verified is False
    assert stale in str(caught.value)


def test_a_digest_pin_is_enforced_by_plain_resolve_too(tmp_path: Path) -> None:
    write(tmp_path, "base.yaml", BASE)
    leaf = pin_leaf(tmp_path, "sha256:" + "1" * 64)

    ok, message = resolve(
        parse_or_raise(leaf.read_text()),
        source=str(leaf),
        loader=create_composite_loader(),
    )

    assert not ok
    assert "digest pin mismatch" in message


def test_a_pin_that_no_longer_matches_an_edited_base_is_caught(tmp_path: Path) -> None:
    base = write(tmp_path, "base.yaml", BASE)
    leaf = pin_leaf(tmp_path, base_digest())
    base.write_text(BASE.replace("read_file", "write_file"))

    with pytest.raises(PolicyVerificationError) as caught:
        resolve_with_options_or_raise(
            parse_or_raise(leaf.read_text()),
            source=str(leaf),
            loader=create_composite_loader(),
        )
    assert caught.value.reason == "digest_mismatch"


def test_a_malformed_digest_pin_is_rejected_not_ignored(tmp_path: Path) -> None:
    write(tmp_path, "base.yaml", BASE)
    for bad in ("sha256:abc", "sha256:" + "A" * 64, "sha256:"):
        leaf = pin_leaf(tmp_path, bad)
        with pytest.raises(PolicyVerificationError) as caught:
            resolve_with_options_or_raise(
                parse_or_raise(leaf.read_text()),
                source=str(leaf),
                loader=create_composite_loader(),
            )
        assert caught.value.reason == "invalid_pin", bad
        assert caught.value.code == "invalid_pin", bad


def test_a_pin_on_a_middle_hop_is_checked(tmp_path: Path) -> None:
    write(tmp_path, "mid.yaml", MID)
    leaf = write(tmp_path, "leaf.yaml", LEAF_OF_MID)
    unpinned = resolve_with_options_or_raise(
        parse_or_raise(leaf.read_text()),
        source=str(leaf),
        loader=create_composite_loader(),
    )
    mid_digest = unpinned.chain[1].content_hash

    pinned = write(
        tmp_path,
        "leaf.yaml",
        LEAF_OF_MID.replace('extends: "mid.yaml"', f'extends: "mid.yaml#{mid_digest}"'),
    )
    resolution = resolve_with_options_or_raise(
        parse_or_raise(pinned.read_text()),
        source=str(pinned),
        loader=create_composite_loader(),
    )
    assert resolution.chain[1].content_hash == mid_digest

    # The mid hop's hash covers the mid document alone: merging `builtin:strict`
    # into it must not change what the pin names.
    assert mid_digest != resolution.content_hash


# --------------------------------------------------------------------------- #
# require_signature
# --------------------------------------------------------------------------- #


def test_require_signature_admits_a_signed_leaf_over_a_builtin_base(tmp_path: Path) -> None:
    leaf = write(tmp_path, "leaf.yaml", MID)  # extends builtin:strict
    envelope = sign_file(leaf)

    resolution = resolve_with_options_or_raise(
        parse_or_raise(leaf.read_text()),
        source=str(leaf),
        loader=create_composite_loader(),
        options=keyring_options(require_signature=True),
    )

    assert resolution.signature is not None
    assert resolution.signature.verified is True
    assert resolution.signature.key_id == envelope.key_id
    assert resolution.signature.reason is None
    # `verified_at` is the verifier's clock -- when the ten checks ran -- not
    # the signer's `signed_at` (receipt spec 4.2).
    assert TIMESTAMP_RE.match(resolution.signature.verified_at)
    # A builtin hop is embedded in the engine: no separate verification.
    assert resolution.chain[0].source == "builtin:strict"
    assert resolution.chain[0].signature is None
    assert resolution.chain[-1].signature is resolution.signature


def test_require_signature_refuses_an_unsigned_leaf(tmp_path: Path) -> None:
    leaf = write(tmp_path, "leaf.yaml", STANDALONE)

    with pytest.raises(PolicyVerificationError) as caught:
        resolve_with_options_or_raise(
            parse_or_raise(leaf.read_text()),
            source=str(leaf),
            loader=create_composite_loader(),
            options=keyring_options(require_signature=True),
        )

    assert caught.value.reason == "missing_signature"
    assert caught.value.source == str(leaf)
    assert caught.value.status.verified is False


def test_require_signature_refuses_an_unsigned_base(tmp_path: Path) -> None:
    write(tmp_path, "base.yaml", BASE)
    leaf = write(tmp_path, "leaf.yaml", LEAF_OF_BASE)
    sign_file(leaf)

    with pytest.raises(PolicyVerificationError) as caught:
        resolve_with_options_or_raise(
            parse_or_raise(leaf.read_text()),
            source=str(leaf),
            loader=create_composite_loader(),
            options=keyring_options(require_signature=True),
        )

    # The base is reached first, so it is the hop that fails.
    assert caught.value.source == str(tmp_path / "base.yaml")
    assert caught.value.reason == "missing_signature"


def test_a_matching_pin_satisfies_require_signature_for_that_hop(tmp_path: Path) -> None:
    write(tmp_path, "base.yaml", BASE)
    leaf = pin_leaf(tmp_path, base_digest())
    sign_file(leaf)

    resolution = resolve_with_options_or_raise(
        parse_or_raise(leaf.read_text()),
        source=str(leaf),
        loader=create_composite_loader(),
        options=keyring_options(require_signature=True),
    )

    # The base was checked and had no envelope, which the link records: a pin
    # satisfies the requirement without turning into a signature.
    assert resolution.chain[0].signature.verified is False
    assert resolution.chain[0].signature.reason == "missing_signature"
    assert resolution.signature.verified is True


def test_require_signature_refuses_a_signature_from_an_untrusted_key(tmp_path: Path) -> None:
    leaf = write(tmp_path, "leaf.yaml", STANDALONE)
    sign_file(leaf, UNTRUSTED_KEY)

    with pytest.raises(PolicyVerificationError) as caught:
        resolve_with_options_or_raise(
            parse_or_raise(leaf.read_text()),
            source=str(leaf),
            loader=create_composite_loader(),
            options=keyring_options(require_signature=True),
        )
    assert caught.value.reason == "unknown_key_id"


def test_require_signature_refuses_a_policy_edited_after_signing(tmp_path: Path) -> None:
    leaf = write(tmp_path, "leaf.yaml", STANDALONE)
    sign_file(leaf)
    leaf.write_text(STANDALONE.replace("api.example.com", "evil.example.com"))

    with pytest.raises(PolicyVerificationError) as caught:
        resolve_with_options_or_raise(
            parse_or_raise(leaf.read_text()),
            source=str(leaf),
            loader=create_composite_loader(),
            options=keyring_options(require_signature=True),
        )
    assert caught.value.reason == "content_hash_mismatch"


def test_require_signature_honours_the_verifier_clock_and_rollback_inputs(
    tmp_path: Path,
) -> None:
    leaf = write(tmp_path, "leaf.yaml", STANDALONE)
    sign_file(leaf, signed_at="2026-01-01T00:00:00.000Z", policy_version=3)

    ok, resolution = resolve_with_options(
        parse_or_raise(leaf.read_text()),
        source=str(leaf),
        loader=create_composite_loader(),
        options=keyring_options(
            require_signature=True, verify=VerifyOptions(now="2026-06-01T00:00:00.000Z")
        ),
    )
    assert ok and resolution.signature.verified

    # A verifier that has already seen version 4 rejects this version 3 envelope.
    ok, message = resolve_with_options(
        parse_or_raise(leaf.read_text()),
        source=str(leaf),
        loader=create_composite_loader(),
        options=keyring_options(
            require_signature=True,
            verify=VerifyOptions(now="2026-06-01T00:00:00.000Z", last_seen_version=4),
        ),
    )
    assert not ok
    assert "policy_version_rollback" in message

    # ...and a signature dated after the verifier's clock is refused.
    ok, message = resolve_with_options(
        parse_or_raise(leaf.read_text()),
        source=str(leaf),
        loader=create_composite_loader(),
        options=keyring_options(
            require_signature=True, verify=VerifyOptions(now="2025-01-01T00:00:00.000Z")
        ),
    )
    assert not ok
    assert "signed_at_in_future" in message


def test_require_signature_without_a_keyring_refuses_every_unpinned_hop() -> None:
    # Signing spec 6.5: a hop with no envelope at all records
    # `missing_signature`, and one whose envelope cannot be checked against
    # anything records `no_keyring`. Both refuse; neither is silently admitted.
    with pytest.raises(PolicyVerificationError) as unsigned:
        resolve_with_options_or_raise(
            parse_or_raise(STANDALONE),
            options=ResolveOptions(require_signature=True),
        )
    assert unsigned.value.code == REASON_MISSING_SIGNATURE

    envelope = sign_policy(parse_or_raise(STANDALONE), SIGNING_KEY).to_json().encode()
    with pytest.raises(PolicyVerificationError) as unkeyed:
        resolve_with_options_or_raise(
            parse_or_raise(STANDALONE),
            options=ResolveOptions(
                require_signature=True, signature_locator=lambda _source: envelope
            ),
        )
    assert unkeyed.value.code == REASON_NO_KEYRING
    assert unkeyed.value.status.verified is False


def test_an_in_memory_policy_cannot_satisfy_require_signature_by_default() -> None:
    ok, message = resolve_with_options(
        parse_or_raise(STANDALONE), options=keyring_options(require_signature=True)
    )
    assert not ok
    assert INLINE_SOURCE in message and "missing_signature" in message


def test_a_caller_supplied_locator_can_admit_an_in_memory_policy(tmp_path: Path) -> None:
    envelope = sign_policy(parse_or_raise(STANDALONE), SIGNING_KEY)
    seen: list[str] = []

    def locator(source: str) -> bytes:
        seen.append(source)
        return envelope.to_json().encode("utf-8")

    resolution = resolve_with_options_or_raise(
        parse_or_raise(STANDALONE),
        options=keyring_options(require_signature=True, signature_locator=locator),
    )

    assert seen == [INLINE_SOURCE]
    assert resolution.signature.verified is True


# --------------------------------------------------------------------------- #
# Opportunistic verification
# --------------------------------------------------------------------------- #


def test_opportunistic_verification_is_recorded(tmp_path: Path) -> None:
    leaf = write(tmp_path, "leaf.yaml", STANDALONE)
    envelope = sign_file(leaf)

    resolution = resolve_with_options_or_raise(
        parse_or_raise(leaf.read_text()),
        source=str(leaf),
        loader=create_composite_loader(),
        options=keyring_options(),
    )

    assert resolution.signature.verified is True
    assert resolution.signature.key_id == envelope.key_id


def test_opportunistic_verification_records_a_failure_without_blocking(
    tmp_path: Path,
) -> None:
    leaf = write(tmp_path, "leaf.yaml", STANDALONE)
    sign_file(leaf, UNTRUSTED_KEY)

    resolution = resolve_with_options_or_raise(
        parse_or_raise(leaf.read_text()),
        source=str(leaf),
        loader=create_composite_loader(),
        options=keyring_options(),
    )

    assert resolution.signature.verified is False
    assert resolution.signature.reason == "unknown_key_id"
    assert resolution.spec.rules.egress is not None  # the policy still loaded


def test_a_malformed_envelope_is_recorded_not_raised(tmp_path: Path) -> None:
    leaf = write(tmp_path, "leaf.yaml", STANDALONE)
    Path(f"{leaf}.sig").write_text("{not json")

    resolution = resolve_with_options_or_raise(
        parse_or_raise(leaf.read_text()),
        source=str(leaf),
        loader=create_composite_loader(),
        options=keyring_options(),
    )
    assert resolution.signature.reason == "malformed_envelope"


def test_without_a_keyring_no_signature_is_even_looked_for(tmp_path: Path) -> None:
    leaf = write(tmp_path, "leaf.yaml", STANDALONE)
    sign_file(leaf)

    resolution = resolve_with_options_or_raise(
        parse_or_raise(leaf.read_text()),
        source=str(leaf),
        loader=create_composite_loader(),
        options=ResolveOptions(),
    )
    assert resolution.signature is None


# --------------------------------------------------------------------------- #
# The default locator (signing spec section 7.1)
# --------------------------------------------------------------------------- #


def test_locator_prefers_the_full_name_over_the_stem(tmp_path: Path) -> None:
    leaf = write(tmp_path, "leaf.yaml", STANDALONE)
    Path(f"{leaf}.sig").write_text('{"preferred": true}')
    (tmp_path / "leaf.sig").write_text('{"preferred": false}')

    assert json.loads(default_signature_locator(str(leaf)))["preferred"] is True


def test_locator_falls_back_to_the_stem_for_0_1_layouts(tmp_path: Path) -> None:
    leaf = write(tmp_path, "leaf.yaml", STANDALONE)
    stem = tmp_path / "leaf.sig"
    sign_file(leaf, sig_path=stem)
    assert not Path(f"{leaf}.sig").exists()

    assert default_signature_locator(str(leaf)) == stem.read_bytes()
    resolution = resolve_with_options_or_raise(
        parse_or_raise(leaf.read_text()),
        source=str(leaf),
        loader=create_composite_loader(),
        options=keyring_options(require_signature=True),
    )
    assert resolution.signature.verified is True


def test_locator_returns_none_for_sources_it_cannot_serve(tmp_path: Path) -> None:
    assert default_signature_locator("builtin:strict") is None
    assert default_signature_locator("https://example.com/policy.yaml") is None
    assert default_signature_locator(INLINE_SOURCE) is None
    assert default_signature_locator(str(tmp_path / "missing.yaml")) is None


# --------------------------------------------------------------------------- #
# HushGuard
# --------------------------------------------------------------------------- #


def test_guard_keeps_the_resolution_for_a_verified_policy(tmp_path: Path) -> None:
    write(tmp_path, "mid.yaml", MID)
    leaf = write(tmp_path, "leaf.yaml", LEAF_OF_MID)
    sign_file(leaf)
    sign_file(tmp_path / "mid.yaml")

    guard = HushGuard.from_file(
        str(leaf), require_signature=True, trusted_keys=[SIGNING_PUB]
    )

    assert guard.refusal is None
    assert guard.resolution is not None
    assert [link.source for link in guard.resolution.chain] == [
        "builtin:strict",
        str(tmp_path / "mid.yaml"),
        str(leaf),
    ]
    assert guard.resolution.signature.verified is True
    assert guard.resolution.chain[1].signature.verified is True
    assert guard.check(HushGuard.map_egress("api.example.com")) is True


def test_guard_records_the_chain_even_without_verification(tmp_path: Path) -> None:
    write(tmp_path, "base.yaml", BASE)
    leaf = write(tmp_path, "leaf.yaml", LEAF_OF_BASE)

    guard = HushGuard.from_file(str(leaf))

    assert guard.resolution.content_hash.startswith("sha256:")
    assert len(guard.resolution.chain) == 2
    assert guard.resolution.signature is None


def test_guard_refuses_every_action_when_the_signature_is_missing(tmp_path: Path) -> None:
    leaf = write(tmp_path, "leaf.yaml", STANDALONE)

    guard = HushGuard.from_file(
        str(leaf), require_signature=True, trusted_keys=[SIGNING_PUB]
    )

    assert guard.refusal is not None
    assert guard.refusal.reason == "missing_signature"
    assert guard.resolution is None

    action = HushGuard.map_egress("api.example.com")  # the policy allows this
    result = guard.evaluate(action)
    assert result.decision == Decision.DENY
    assert result.matched_rule == POLICY_SIGNATURE_RULE
    assert "missing_signature" in result.reason
    assert guard.check(action) is False
    with pytest.raises(HushSpecDenied):
        guard.enforce(action)


def test_guard_refusal_carries_the_verification_reason(tmp_path: Path) -> None:
    leaf = write(tmp_path, "leaf.yaml", STANDALONE)
    sign_file(leaf, UNTRUSTED_KEY)

    guard = HushGuard.from_file(
        str(leaf), require_signature=True, trusted_keys=[SIGNING_PUB]
    )

    assert guard.refusal.reason == "unknown_key_id"
    assert "unknown_key_id" in guard.evaluate(HushGuard.map_egress("api.example.com")).reason


def test_a_refusal_cannot_be_downgraded_to_monitor(tmp_path: Path) -> None:
    leaf = write(tmp_path, "leaf.yaml", STANDALONE)
    receipts: list = []
    guard = HushGuard.from_file(
        str(leaf),
        require_signature=True,
        trusted_keys=[SIGNING_PUB],
        enforcement=EnforcementConfig(mode="monitor"),
        sink=CallbackSink(receipts.append),
    )

    outcome = guard.gate(HushGuard.map_egress("api.example.com"))

    assert outcome.proceed is False
    assert outcome.enforcement.mode == "enforce"
    assert outcome.enforcement.outcome == "blocked"
    assert receipts
    refused = receipts[-1]
    assert refused.matched_rule == POLICY_SIGNATURE_RULE
    assert refused.rule_trace == []
    assert refused.policy.name == "standalone"
    # The refused document's own content hash, so an auditor can join the
    # receipt to the load it is about; `signature.verified` is what says the
    # document was never proven.
    assert refused.policy.content_hash == content_hash(parse_or_raise(STANDALONE))
    assert refused.policy.signature.verified is False
    assert refused.policy.signature.reason == "missing_signature"
    assert refused.enforcement.outcome == "blocked"


def test_guard_refuses_an_unverifiable_base(tmp_path: Path) -> None:
    write(tmp_path, "base.yaml", BASE)
    leaf = write(tmp_path, "leaf.yaml", LEAF_OF_BASE)
    sign_file(leaf)

    guard = HushGuard.from_file(
        str(leaf), require_signature=True, trusted_keys=[SIGNING_PUB]
    )
    assert guard.refusal is not None
    assert guard.check(HushGuard.map_egress("api.example.com")) is False


def test_guard_admits_a_pinned_base_with_a_signed_leaf(tmp_path: Path) -> None:
    write(tmp_path, "base.yaml", BASE)
    leaf = pin_leaf(tmp_path, base_digest())
    sign_file(leaf)

    guard = HushGuard.from_file(
        str(leaf), require_signature=True, trusted_keys=[SIGNING_PUB]
    )

    assert guard.refusal is None
    # The base really was merged in: `tool_access` comes only from it.
    assert guard.check(HushGuard.map_tool_call("read_file")) is True
    assert guard.check(HushGuard.map_tool_call("shell_exec")) is False


def test_from_yaml_refuses_under_require_signature_because_it_has_no_source() -> None:
    guard = HushGuard.from_yaml(
        STANDALONE, require_signature=True, trusted_keys=[SIGNING_PUB]
    )
    assert guard.refusal.reason == "missing_signature"


def test_swap_policy_keeps_the_last_good_policy_when_verification_fails(
    tmp_path: Path,
) -> None:
    leaf = write(tmp_path, "leaf.yaml", STANDALONE)
    sign_file(leaf)
    guard = HushGuard.from_file(
        str(leaf), require_signature=True, trusted_keys=[SIGNING_PUB]
    )
    assert guard.refusal is None
    good_hash = guard.resolution.content_hash

    with pytest.raises(PolicyVerificationError):
        guard.swap_policy(parse_or_raise(STANDALONE.replace("standalone", "swapped")))

    assert guard.refusal is None
    assert guard.resolution.content_hash == good_hash
    assert guard.check(HushGuard.map_egress("api.example.com")) is True


def test_a_verified_swap_clears_a_refusal(tmp_path: Path) -> None:
    leaf = write(tmp_path, "leaf.yaml", STANDALONE)
    guard = HushGuard.from_file(
        str(leaf), require_signature=True, trusted_keys=[SIGNING_PUB]
    )
    assert guard.refusal is not None

    sign_file(leaf)
    guard.swap_policy(parse_or_raise(leaf.read_text()))

    assert guard.refusal is None
    assert guard.resolution.signature.verified is True
    assert guard.check(HushGuard.map_egress("api.example.com")) is True


def test_guard_rejects_both_keyring_and_trusted_keys() -> None:
    with pytest.raises(ValueError, match="not both"):
        HushGuard.from_yaml(
            STANDALONE, keyring=SIGNING_PUB, trusted_keys=[SIGNING_PUB]
        )


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

from hushspec.parse import parse_or_raise
from hushspec.resolve import ResolveOptions, resolve_with_options, resolve_with_options_or_raise
from hushspec.signing import SigningUnavailable

POLICY = parse_or_raise(open({policy!r}).read())
PUB = open({pub!r}).read()

# Resolution that asks for no proof still works without a crypto backend.
ok, resolution = resolve_with_options(POLICY, options=ResolveOptions())
assert ok and resolution.content_hash.startswith("sha256:"), resolution

# Requiring one fails closed, loudly, and identically through both entry points.
for call in (
    lambda: resolve_with_options_or_raise(
        POLICY, options=ResolveOptions(require_signature=True, keyring=PUB)
    ),
    lambda: resolve_with_options(
        POLICY, options=ResolveOptions(require_signature=True, keyring=PUB)
    ),
):
    try:
        call()
    except SigningUnavailable as exc:
        assert "hushspec[signing]" in str(exc), exc
    else:
        raise AssertionError("expected SigningUnavailable")

print("ok")
'''


def test_require_signature_without_cryptography_fails_closed(tmp_path: Path) -> None:
    """A missing backend must never read as "no signature needed".

    Run in a subprocess because the import has to fail at first use, and this
    process has already imported ``cryptography``.
    """
    import subprocess
    import sys

    policy = write(tmp_path, "leaf.yaml", STANDALONE)
    script = _WITHOUT_CRYPTOGRAPHY.format(
        policy=str(policy), pub=str(KEY_DIR / "test-signing.pub.pem")
    )
    done = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, f"stdout={done.stdout}\nstderr={done.stderr}"
    assert done.stdout.strip().endswith("ok")
