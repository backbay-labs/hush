"""Policy bundle verification (``spec/hushspec-bundle.md``, format 0.1).

A bundle is a DSSE envelope whose payload is an in-toto Statement v1 attesting
to one resolved policy: the canonical projection it resolved to, the content
hash that names it, and every hop of the ``extends`` chain that produced it.
Verifying one answers "was this exact resolved policy attested by a key I
trust", which is the question an auditor asks of a receipt's policy identity
long after the files have moved on.

The four checks of spec section 5.2, in order, stopping at the first failure:

1. **Shape** -- the envelope and the statement it carries are well formed and
   name the constants this build knows (:data:`REASON_MALFORMED_BUNDLE`).
2. **Signature** -- some signature verifies as Ed25519 over the PAE, under a
   key the keyring holds whose id is *recomputed* from the public key
   (:data:`REASON_UNKNOWN_KEY_ID`, :data:`REASON_DSSE_SIGNATURE_MISMATCH`).
3. **Subject** -- ``predicate.resolved`` canonicalizes to the content hash the
   predicate declares, and to the subject digest
   (:data:`REASON_SUBJECT_DIGEST_MISMATCH`).
4. **Policy** -- optionally, a policy re-resolved here produces the same
   canonical form and the same chain hashes
   (:data:`REASON_POLICY_MISMATCH`).

Check 2 precedes check 3 deliberately: an edit in transit breaks the signature
first, so a ``subject_digest_mismatch`` means a correctly signed but internally
inconsistent statement -- a bundler bug -- rather than tampering.

Ed25519 is not in the standard library, so verification needs the optional
``cryptography`` dependency, exactly as policy signing does::

    pip install "hushspec[signing]"

Without it :func:`verify_bundle` raises :class:`~hushspec.signing.SigningUnavailable`
before any check can look like a verdict. :func:`parse_bundle` is pure standard
library.

This module verifies; it does not create. And a verified bundle is *not* a
policy: nothing here loads ``predicate.resolved`` and enforces it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from hushspec.canonical import (
    HASH_PREFIX,
    CanonicalError,
    canonical_json_value,
    content_hash,
)
from hushspec.signing import (
    MalformedEnvelope,
    SigningError,
    _ed25519,
    _parse_timestamp,
    _verify_raw,
    format_timestamp,
    key_id_from_public_key,
    load_keyring,
)

__all__ = [
    "BUNDLE_VERSION",
    "BUNDLE_REASON_CODES",
    "PAYLOAD_TYPE",
    "PREDICATE_TYPE",
    "STATEMENT_TYPE",
    "REASON_DSSE_SIGNATURE_MISMATCH",
    "REASON_MALFORMED_BUNDLE",
    "REASON_POLICY_MISMATCH",
    "REASON_SUBJECT_DIGEST_MISMATCH",
    "REASON_UNKNOWN_KEY_ID",
    "BundleError",
    "DsseEnvelope",
    "DsseSignature",
    "BundleVerifyResult",
    "parse_bundle",
    "pae",
    "verify_bundle",
]

#: The predicate version this build knows.
BUNDLE_VERSION = "0.1"

#: The only DSSE payload type a HushSpec bundle carries.
PAYLOAD_TYPE = "application/vnd.in-toto+json"

#: in-toto Statement v1.
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

#: The policy-bundle predicate this build knows.
PREDICATE_TYPE = "https://hushspec.dev/attestation/policy-bundle/v0.1"

_PAE_PREFIX = b"DSSEv1"

# -- reason codes (spec section 5.4) --------------------------------------- #

REASON_MALFORMED_BUNDLE = "malformed_bundle"
REASON_DSSE_SIGNATURE_MISMATCH = "dsse_signature_mismatch"
REASON_UNKNOWN_KEY_ID = "unknown_key_id"
REASON_SUBJECT_DIGEST_MISMATCH = "subject_digest_mismatch"
REASON_POLICY_MISMATCH = "policy_mismatch"

#: Every reason a bundle can be refused, in check order. The set is closed: a
#: verifier never invents a code.
BUNDLE_REASON_CODES: tuple[str, ...] = (
    REASON_MALFORMED_BUNDLE,
    REASON_DSSE_SIGNATURE_MISMATCH,
    REASON_UNKNOWN_KEY_ID,
    REASON_SUBJECT_DIGEST_MISMATCH,
    REASON_POLICY_MISMATCH,
)


class BundleError(ValueError):
    """A bundle document is not a usable DSSE envelope.

    Carries the spec section 5.4 ``reason`` code the corresponding check in
    :func:`verify_bundle` would report, so the two entry points agree.
    """

    def __init__(self, message: str, reason: str = REASON_MALFORMED_BUNDLE) -> None:
        super().__init__(message)
        self.reason = reason


# --------------------------------------------------------------------------- #
# The wire types (spec sections 3 and 4)
# --------------------------------------------------------------------------- #


_SIGNATURE_KEYS = frozenset(("keyid", "sig"))
_ENVELOPE_KEYS = frozenset(("payloadType", "payload", "signatures"))


@dataclass(frozen=True)
class DsseSignature:
    """One DSSE signature: a declared key id and a base64 signature."""

    keyid: str
    sig: str


@dataclass(frozen=True)
class DsseEnvelope:
    """A parsed DSSE envelope (spec section 3).

    The statement is *not* decoded here: an envelope with an undecodable
    payload is still an envelope, and decoding it is check 1's job.
    """

    payload_type: str
    payload: str
    signatures: tuple[DsseSignature, ...] = ()

    def payload_bytes(self) -> bytes:
        """The decoded statement bytes (standard base64, with padding)."""
        try:
            return base64.b64decode(self.payload, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise BundleError(f"payload is not valid base64: {exc}") from exc

    def pae(self) -> bytes:
        """The DSSE Pre-Authentication Encoding this envelope's signatures cover."""
        return pae(self.payload_type, self.payload_bytes())

    def statement(self) -> "Statement":
        """Decode and shape-check the statement (check 1)."""
        raw = self.payload_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BundleError(f"payload is not valid UTF-8: {exc}") from exc
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise BundleError(f"payload is not valid JSON: {exc}") from exc
        return _parse_statement(value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "payloadType": self.payload_type,
            "payload": self.payload,
            "signatures": [
                {"keyid": signature.keyid, "sig": signature.sig}
                for signature in self.signatures
            ],
        }


@dataclass(frozen=True)
class SubjectDigest:
    sha256: str


@dataclass(frozen=True)
class Subject:
    name: str
    digest: SubjectDigest


@dataclass(frozen=True)
class Resolver:
    tool: str
    version: str


@dataclass(frozen=True)
class PolicyIdentity:
    content_hash: str
    spec_version: str
    name: str | None = None
    policy_version: int | None = None


@dataclass(frozen=True)
class BundleChainLink:
    """One hop of the attested ``extends`` chain (spec section 4.4).

    ``source`` is a provenance label, never an identity: spec section 5.3
    compares chains by ``content_hash`` alone.
    """

    source: str
    content_hash: str
    signature: dict[str, Any] | None = None


@dataclass(frozen=True)
class PolicyBundlePredicate:
    bundle_version: str
    policy: PolicyIdentity
    chain: tuple[BundleChainLink, ...]
    resolved: dict[str, Any]
    resolver: Resolver
    created_at: str
    signature_verification: dict[str, Any] | None = None


@dataclass(frozen=True)
class Statement:
    """The in-toto Statement v1 a bundle's payload carries (spec section 4)."""

    statement_type: str
    subject: tuple[Subject, ...]
    predicate_type: str
    predicate: PolicyBundlePredicate


# --------------------------------------------------------------------------- #
# Pre-Authentication Encoding (spec section 3.1)
# --------------------------------------------------------------------------- #


def pae(payload_type: str, payload: bytes) -> bytes:
    """``DSSEv1 SP LEN(t) SP t SP LEN(b) SP b``.

    Lengths are **byte** counts in ASCII decimal with no leading zeros, and
    nothing follows the payload. For a HushSpec bundle the prefix is always
    ``DSSEv1 28 application/vnd.in-toto+json <len> ``.
    """
    encoded_type = payload_type.encode("utf-8")
    header = b" ".join(
        (
            _PAE_PREFIX,
            str(len(encoded_type)).encode("ascii"),
            encoded_type,
            str(len(payload)).encode("ascii"),
        )
    )
    return header + b" " + payload


# --------------------------------------------------------------------------- #
# Parsing (check 1)
# --------------------------------------------------------------------------- #


def parse_bundle(obj: Any) -> DsseEnvelope:
    """Parse a bundle document into a :class:`DsseEnvelope`.

    ``obj`` is a parsed mapping, JSON text or bytes, or an existing envelope.
    Unknown members anywhere are rejected, as is a ``payloadType`` other than
    :data:`PAYLOAD_TYPE`. Raises :class:`BundleError` carrying
    ``malformed_bundle``.
    """
    if isinstance(obj, DsseEnvelope):
        return obj
    if isinstance(obj, (bytes, bytearray)):
        # Strictly: repairing invalid UTF-8 into U+FFFD would silently change
        # the bytes a signature covers, so a bundle that is not UTF-8 is
        # refused rather than mended.
        try:
            obj = bytes(obj).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BundleError(f"bundle is not valid UTF-8: {exc}") from exc
    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except json.JSONDecodeError as exc:
            raise BundleError(f"bundle is not valid JSON: {exc}") from exc
    if not isinstance(obj, Mapping):
        raise BundleError("bundle must be a JSON object")

    _reject_unknown(obj, _ENVELOPE_KEYS, "bundle")
    payload_type = _required_str(obj, "payloadType", "bundle")
    if payload_type != PAYLOAD_TYPE:
        raise BundleError(
            f"payloadType must be {PAYLOAD_TYPE!r}, got {payload_type!r}"
        )
    payload = _required_str(obj, "payload", "bundle")
    if not payload:
        raise BundleError("bundle.payload must not be empty")

    raw_signatures = obj.get("signatures")
    if not _is_array(raw_signatures):
        raise BundleError("bundle.signatures must be an array")
    signatures = []
    for index, entry in enumerate(raw_signatures):
        label = f"bundle.signatures[{index}]"
        if not isinstance(entry, Mapping):
            raise BundleError(f"{label} must be an object")
        _reject_unknown(entry, _SIGNATURE_KEYS, label)
        keyid = _required_str(entry, "keyid", label)
        if not _is_content_hash(keyid):
            raise BundleError(f"{label}.keyid must be sha256:<64 hex>, got {keyid!r}")
        signatures.append(
            DsseSignature(keyid=keyid, sig=_required_str(entry, "sig", label))
        )

    return DsseEnvelope(
        payload_type=payload_type,
        payload=payload,
        signatures=tuple(signatures),
    )


_STATEMENT_KEYS = frozenset(("_type", "subject", "predicateType", "predicate"))
_SUBJECT_KEYS = frozenset(("name", "digest"))
_PREDICATE_KEYS = frozenset(
    (
        "bundle_version",
        "policy",
        "chain",
        "resolved",
        "resolver",
        "created_at",
        "signature_verification",
    )
)
_POLICY_KEYS = frozenset(("content_hash", "spec_version", "name", "policy_version"))
_CHAIN_LINK_KEYS = frozenset(("source", "content_hash", "signature"))
_RESOLVER_KEYS = frozenset(("tool", "version"))


def _parse_statement(value: Any) -> Statement:
    """Every refusal here is check 1: ``malformed_bundle``."""
    if not isinstance(value, Mapping):
        raise BundleError("statement must be a JSON object")
    _reject_unknown(value, _STATEMENT_KEYS, "statement")

    statement_type = _required_str(value, "_type", "statement")
    if statement_type != STATEMENT_TYPE:
        raise BundleError(
            f"statement._type must be {STATEMENT_TYPE!r}, got {statement_type!r}"
        )
    predicate_type = _required_str(value, "predicateType", "statement")
    if predicate_type != PREDICATE_TYPE:
        # Closed by default: a predicate version this build does not know is
        # refused even when the signature over it is good.
        raise BundleError(
            f"statement.predicateType must be {PREDICATE_TYPE!r}, got {predicate_type!r}"
        )

    raw_subject = value.get("subject")
    if not _is_array(raw_subject) or len(raw_subject) != 1:
        raise BundleError("statement.subject must carry exactly one subject")
    subject = _parse_subject(raw_subject[0])

    return Statement(
        statement_type=statement_type,
        subject=(subject,),
        predicate_type=predicate_type,
        predicate=_parse_predicate(value.get("predicate")),
    )


def _parse_subject(value: Any) -> Subject:
    if not isinstance(value, Mapping):
        raise BundleError("statement.subject[0] must be an object")
    _reject_unknown(value, _SUBJECT_KEYS, "statement.subject[0]")
    name = _required_str(value, "name", "statement.subject[0]")
    if not name:
        raise BundleError("statement.subject[0].name must not be empty")
    digest = value.get("digest")
    if not isinstance(digest, Mapping):
        raise BundleError("statement.subject[0].digest must be an object")
    # The digest carries exactly `sha256`, so a bundle cannot name the policy
    # by an algorithm the verifier does not check.
    _reject_unknown(digest, frozenset(("sha256",)), "statement.subject[0].digest")
    sha256 = _required_str(digest, "sha256", "statement.subject[0].digest")
    if not _is_hex_digest(sha256):
        raise BundleError(
            f"statement.subject[0].digest.sha256 must be 64 lowercase hex digits, "
            f"got {sha256!r}"
        )
    return Subject(name=name, digest=SubjectDigest(sha256=sha256))


def _parse_predicate(value: Any) -> PolicyBundlePredicate:
    if not isinstance(value, Mapping):
        raise BundleError("statement.predicate must be an object")
    _reject_unknown(value, _PREDICATE_KEYS, "predicate")

    bundle_version = _required_str(value, "bundle_version", "predicate")
    if bundle_version != BUNDLE_VERSION:
        raise BundleError(
            f"predicate.bundle_version must be {BUNDLE_VERSION!r}, got {bundle_version!r}"
        )

    policy = _parse_policy_identity(value.get("policy"))

    raw_chain = value.get("chain")
    if not _is_array(raw_chain) or not raw_chain:
        raise BundleError("predicate.chain must carry at least one link")
    chain = tuple(
        _parse_chain_link(link, index) for index, link in enumerate(raw_chain)
    )

    resolved = value.get("resolved")
    if not isinstance(resolved, Mapping):
        raise BundleError("predicate.resolved must be an object")

    resolver = value.get("resolver")
    if not isinstance(resolver, Mapping):
        raise BundleError("predicate.resolver must be an object")
    _reject_unknown(resolver, _RESOLVER_KEYS, "predicate.resolver")
    tool = _required_str(resolver, "tool", "predicate.resolver")
    version = _required_str(resolver, "version", "predicate.resolver")
    if not tool or not version:
        raise BundleError("predicate.resolver.tool and .version must not be empty")

    created_at = _required_str(value, "created_at", "predicate")
    try:
        _parse_timestamp(created_at, "predicate.created_at")
    except MalformedEnvelope as exc:
        raise BundleError(str(exc)) from exc

    signature_verification = value.get("signature_verification")
    if signature_verification is not None and not isinstance(
        signature_verification, Mapping
    ):
        raise BundleError("predicate.signature_verification must be an object")

    return PolicyBundlePredicate(
        bundle_version=bundle_version,
        policy=policy,
        chain=chain,
        resolved=dict(resolved),
        resolver=Resolver(tool=tool, version=version),
        created_at=created_at,
        signature_verification=(
            dict(signature_verification)
            if signature_verification is not None
            else None
        ),
    )


def _parse_policy_identity(value: Any) -> PolicyIdentity:
    if not isinstance(value, Mapping):
        raise BundleError("predicate.policy must be an object")
    _reject_unknown(value, _POLICY_KEYS, "predicate.policy")
    hash_value = _required_str(value, "content_hash", "predicate.policy")
    if not _is_content_hash(hash_value):
        raise BundleError(
            f"predicate.policy.content_hash must be sha256:<64 hex>, got {hash_value!r}"
        )
    spec_version = _required_str(value, "spec_version", "predicate.policy")
    if not spec_version:
        raise BundleError("predicate.policy.spec_version must not be empty")

    name = value.get("name")
    if name is not None and (not isinstance(name, str) or not name):
        raise BundleError("predicate.policy.name must be a non-empty string")

    policy_version = value.get("policy_version")
    if policy_version is not None and (
        isinstance(policy_version, bool)
        or not isinstance(policy_version, int)
        or policy_version < 0
    ):
        # An integer, never a string: a version compared as text orders wrong.
        raise BundleError(
            "predicate.policy.policy_version must be a non-negative integer"
        )

    return PolicyIdentity(
        content_hash=hash_value,
        spec_version=spec_version,
        name=name,
        policy_version=policy_version,
    )


def _parse_chain_link(value: Any, index: int) -> BundleChainLink:
    label = f"predicate.chain[{index}]"
    if not isinstance(value, Mapping):
        raise BundleError(f"{label} must be an object")
    _reject_unknown(value, _CHAIN_LINK_KEYS, label)
    source = _required_str(value, "source", label)
    if not source:
        raise BundleError(f"{label}.source must not be empty")
    hash_value = _required_str(value, "content_hash", label)
    if not _is_content_hash(hash_value):
        raise BundleError(
            f"{label}.content_hash must be sha256:<64 hex>, got {hash_value!r}"
        )
    signature = value.get("signature")
    if signature is not None and not isinstance(signature, Mapping):
        raise BundleError(f"{label}.signature must be an object")
    return BundleChainLink(
        source=source,
        content_hash=hash_value,
        signature=dict(signature) if signature is not None else None,
    )


# --------------------------------------------------------------------------- #
# The result
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class BundleVerifyResult:
    """The outcome of :func:`verify_bundle`.

    ``reason`` is ``None`` when ``valid`` is true and otherwise one of
    :data:`BUNDLE_REASON_CODES`, spelled exactly as spec section 5.4 spells it.
    ``detail`` is free text for humans and is never part of the contract.
    """

    valid: bool
    reason: str | None = None
    detail: str | None = None
    #: Every key whose signature verified (check 2).
    key_ids: tuple[str, ...] = ()
    subject_name: str | None = None
    #: The attested content hash, ``sha256:``-prefixed.
    content_hash: str | None = None
    policy_name: str | None = None
    policy_version: int | None = None
    created_at: str | None = None
    chain_length: int = 0
    #: Whether check 4 ran, i.e. a policy was supplied to compare against.
    policy_checked: bool = False
    verified_at: str | None = None

    def __bool__(self) -> bool:
        return self.valid

    @classmethod
    def fail(cls, reason: str, detail: str) -> "BundleVerifyResult":
        assert (
            reason in BUNDLE_REASON_CODES
        ), f"{reason!r} is not a spec section 5.4 reason code"
        return cls(valid=False, reason=reason, detail=detail)


# --------------------------------------------------------------------------- #
# Verification (spec section 5.2)
# --------------------------------------------------------------------------- #


def verify_bundle(
    bundle: Any,
    *,
    keyring: Any = None,
    public_key_pem: str | None = None,
    now: datetime | str | None = None,
    policy: Any = None,
) -> BundleVerifyResult:
    """Run the four ordered checks of spec section 5.2 over a bundle.

    ``bundle`` is a parsed mapping, JSON text or bytes, or a
    :class:`DsseEnvelope`. Trust comes from ``keyring`` (a
    :class:`~hushspec.signing.Keyring`, a parsed keyring mapping, or JSON text)
    or from ``public_key_pem`` as a one-key keyring; exactly one is required.

    ``policy`` enables check 4: pass a :class:`~hushspec.resolve.Resolution`
    (or a resolved ``HushSpec``, which is taken as a one-link chain) and the
    bundle's canonical form and chain hashes are compared against it. Chains
    are compared by content hash, in order, never by ``source``.

    Raises :class:`~hushspec.signing.SigningUnavailable` when the
    ``cryptography`` extra is not installed: a caller must never be able to
    read "could not check" as valid.
    """
    # Fail loudly before any check can look like a verdict.
    _ed25519()

    if (keyring is None) == (public_key_pem is None):
        raise SigningError(
            "exactly one of `keyring` or `public_key_pem` is required to verify a bundle"
        )
    trusted = load_keyring(keyring if keyring is not None else public_key_pem)
    verified_at = format_timestamp(
        _coerce_now(now) if now is not None else datetime.now(timezone.utc)
    )

    # -- check 1: shape ---------------------------------------------------- #
    try:
        envelope = parse_bundle(bundle)
        statement = envelope.statement()
        pae_bytes = envelope.pae()
    except BundleError as exc:
        return BundleVerifyResult.fail(exc.reason, str(exc))

    predicate = statement.predicate

    # -- check 2: DSSE signature ------------------------------------------- #
    signature_failure = _check_signatures(envelope, trusted, pae_bytes)
    if isinstance(signature_failure, BundleVerifyResult):
        return signature_failure
    key_ids = signature_failure

    # -- check 3: subject digest ------------------------------------------- #
    try:
        canonical = canonical_json_value(predicate.resolved)
    except CanonicalError as exc:
        return BundleVerifyResult.fail(
            REASON_SUBJECT_DIGEST_MISMATCH,
            f"predicate.resolved has no canonical form: {exc}",
        )
    recomputed = _digest(canonical)
    if recomputed != predicate.policy.content_hash:
        return BundleVerifyResult.fail(
            REASON_SUBJECT_DIGEST_MISMATCH,
            f"predicate.resolved hashes to {recomputed}, but predicate.policy"
            f".content_hash declares {predicate.policy.content_hash}",
        )
    declared = statement.subject[0].digest.sha256
    expected = recomputed[len(HASH_PREFIX):]
    if declared != expected:
        return BundleVerifyResult.fail(
            REASON_SUBJECT_DIGEST_MISMATCH,
            f"subject digest is {declared}, but predicate.resolved hashes to {expected}",
        )

    # -- check 4: the policy, when one was supplied ------------------------ #
    if policy is not None:
        mismatch = _compare_policy(predicate, policy)
        if mismatch is not None:
            return mismatch

    return BundleVerifyResult(
        valid=True,
        key_ids=tuple(key_ids),
        subject_name=statement.subject[0].name,
        content_hash=predicate.policy.content_hash,
        policy_name=predicate.policy.name,
        policy_version=predicate.policy.policy_version,
        created_at=predicate.created_at,
        chain_length=len(predicate.chain),
        policy_checked=policy is not None,
        verified_at=verified_at,
    )


def _check_signatures(
    envelope: DsseEnvelope, trusted: Any, pae_bytes: bytes
) -> "list[str] | BundleVerifyResult":
    """Check 2: the keys that verified, or the failure to report.

    A signature entry counts only when the keyring holds its ``keyid`` *and*
    the id recomputed from that key's public bytes matches what the bundle
    declared -- a verifier must not trust the id a bundle names itself.
    """
    key_ids: list[str] = []
    named_a_trusted_key = False
    mismatch_detail = ""

    for signature in envelope.signatures:
        entry = trusted.find(signature.keyid)
        if entry is None:
            continue
        try:
            if key_id_from_public_key(entry.public_key) != signature.keyid:
                continue
        except SigningError:
            continue
        named_a_trusted_key = True
        try:
            raw = base64.b64decode(signature.sig, validate=True)
        except (binascii.Error, ValueError):
            mismatch_detail = f"signature by {signature.keyid} is not valid base64"
            continue
        if len(raw) != 64:
            mismatch_detail = (
                f"signature by {signature.keyid} is {len(raw)} bytes, not 64"
            )
            continue
        if _verify_raw(entry.public_key, raw, pae_bytes):
            key_ids.append(signature.keyid)
        else:
            mismatch_detail = f"Ed25519 verification failed for {signature.keyid}"

    if key_ids:
        return key_ids
    if named_a_trusted_key:
        return BundleVerifyResult.fail(
            REASON_DSSE_SIGNATURE_MISMATCH,
            mismatch_detail or "no signature verified under a trusted key",
        )
    if not envelope.signatures:
        return BundleVerifyResult.fail(
            REASON_DSSE_SIGNATURE_MISMATCH,
            "the bundle is unsigned; an unsigned bundle is not evidence",
        )
    return BundleVerifyResult.fail(
        REASON_UNKNOWN_KEY_ID,
        f"none of the {len(envelope.signatures)} signature(s) names a key in the "
        f"keyring ({len(trusted.keys)} trusted)",
    )


def _compare_policy(
    predicate: PolicyBundlePredicate, policy: Any
) -> BundleVerifyResult | None:
    """Check 4: the bundle describes the policy in hand, or it does not.

    Compared through canonical forms rather than JSON values -- a round trip
    can turn ``10.0`` into ``10``, which RFC 8785 serializes identically but
    value equality does not. Chain ``source`` is a provenance label and is
    never compared; a difference in chain *length* is a mismatch even when the
    resolved documents agree.
    """
    spec, chain = _policy_parts(policy)
    try:
        actual = content_hash(spec)
    except CanonicalError as exc:
        return BundleVerifyResult.fail(
            REASON_POLICY_MISMATCH, f"the policy has no canonical form: {exc}"
        )
    if actual != predicate.policy.content_hash:
        return BundleVerifyResult.fail(
            REASON_POLICY_MISMATCH,
            f"the policy resolves to {actual}, but the bundle attests "
            f"{predicate.policy.content_hash}",
        )
    if len(chain) != len(predicate.chain):
        return BundleVerifyResult.fail(
            REASON_POLICY_MISMATCH,
            f"the policy resolves through {len(chain)} link(s), but the bundle "
            f"attests {len(predicate.chain)}",
        )
    for index, (mine, bundled) in enumerate(zip(chain, predicate.chain)):
        if mine.content_hash != bundled.content_hash:
            return BundleVerifyResult.fail(
                REASON_POLICY_MISMATCH,
                f"chain link {index} resolves to {mine.content_hash}, but the "
                f"bundle attests {bundled.content_hash}",
            )
    return None


def _policy_parts(policy: Any) -> tuple[Any, Sequence[Any]]:
    """``(resolved spec, chain)`` from a Resolution or a bare resolved spec."""
    spec = getattr(policy, "spec", None)
    if spec is None:
        # A bare resolved document: one link, its own hash, no chain to walk.
        return policy, ()
    chain = getattr(policy, "chain", None) or ()
    return spec, chain


# --------------------------------------------------------------------------- #
# Small shared helpers
# --------------------------------------------------------------------------- #


def _digest(canonical: str) -> str:
    """``sha256:`` + 64 lowercase hex over the canonical UTF-8 bytes."""
    return HASH_PREFIX + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _coerce_now(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        return value
    try:
        return _parse_timestamp(value, "now")
    except MalformedEnvelope as exc:
        raise SigningError(str(exc)) from exc


def _is_array(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes))


def _is_hex_digest(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _is_content_hash(value: str) -> bool:
    return value.startswith(HASH_PREFIX) and _is_hex_digest(value[len(HASH_PREFIX):])


def _reject_unknown(obj: Mapping[Any, Any], allowed: frozenset[str], label: str) -> None:
    for key in obj:
        if not isinstance(key, str) or key not in allowed:
            raise BundleError(f"unknown field at {label}: {key!r}")


def _required_str(obj: Mapping[str, Any], key: str, label: str) -> str:
    if key not in obj:
        raise BundleError(f"{label} is missing field {key!r}")
    value = obj[key]
    if not isinstance(value, str):
        raise BundleError(f"{label}.{key} must be a string")
    return value
