"""Policy signing and verification (``spec/hushspec-signing.md``, format 0.2).

A signed policy lets an enforcement point prove that the controls it applied
are the controls an authorized party approved. Format 0.2 signs the **content
hash of the resolved policy** (``hushspec.canonical.content_hash``), not the
bytes of the file, so a reformatted YAML still verifies and a changed base
policy in an ``extends`` chain does not.

The three pieces:

* :class:`Envelope` (spec section 4) -- the detached JSON object stored as
  ``<policy>.yaml.sig``. Every member except ``signature`` is a signed claim;
  the signing input is the RFC 8785 canonical form of the envelope with
  ``signature`` absent.
* :class:`Keyring` (spec section 5.3) -- the public keys a verifier trusts,
  each selected by exact ``key_id``, with graceful retirement (``not_after``)
  and hard revocation (``revoked``).
* :func:`verify_policy` (spec section 6.2) -- the ten ordered checks, stopping
  at the first failure and reporting its reason code verbatim.

Everything here is fail-closed. An unknown ``format_version`` or ``algorithm``,
an unknown key, a malformed envelope, or a policy that cannot be canonicalized
all produce a failure; none of them produce ``valid``.

Ed25519 is not in the standard library, so the signature operations need the
optional ``cryptography`` dependency::

    pip install "hushspec[signing]"

Without it :func:`sign_policy` and :func:`verify_policy` raise
:class:`SigningUnavailable` rather than returning an unverified result. The
rest of the module -- :func:`load_keyring`, :func:`key_id_from_public_key`,
:func:`parse_envelope`, :func:`signing_input` -- is pure standard library,
because a key id is a SHA-256 over DER bytes and needs no curve arithmetic.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any

from hushspec.canonical import CanonicalError, canonical_json_value, content_hash

__all__ = [
    "Envelope",
    "MalformedEnvelope",
    "Keyring",
    "KeyringError",
    "SigningError",
    "SigningUnavailable",
    "TrustedKey",
    "VerifyResult",
    "ENVELOPE_FORMAT_VERSION",
    "KEYRING_VERSION",
    "REASON_CODES",
    "SIGNATURE_ALGORITHM",
    "format_timestamp",
    "key_id_from_public_key",
    "load_keyring",
    "parse_envelope",
    "public_key_from_private_key",
    "sign_policy",
    "signing_input",
    "verify_policy",
]

#: The only envelope format this implementation accepts (spec section 4).
ENVELOPE_FORMAT_VERSION = "0.2"

#: The only signature algorithm defined in 0.2: RFC 8032 pure Ed25519.
SIGNATURE_ALGORITHM = "ed25519"

#: The only keyring document version (spec section 5.3).
KEYRING_VERSION = "0.2"

#: Default clock skew allowance for ``signed_at`` (spec section 6.3).
DEFAULT_MAX_CLOCK_SKEW_SECONDS = 300

#: The closed reason-code set of spec section 6.4, in check order. A verifier
#: never reports anything outside this set.
REASON_CODES = (
    "malformed_envelope",
    "unsupported_format_version",
    "unsupported_algorithm",
    "unknown_key_id",
    "key_revoked",
    "key_retired",
    "signed_at_in_future",
    "expired",
    "signature_mismatch",
    "content_hash_mismatch",
    "policy_version_rollback",
)

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIMESTAMP_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$")
_SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")

#: The fixed DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410): a
#: 44-byte structure whose last 32 bytes are the raw public key. Checking it
#: keeps a key id from being computed over some other algorithm's key.
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_ED25519_SPKI_LEN = len(_ED25519_SPKI_PREFIX) + 32

_ENVELOPE_REQUIRED = ("format_version", "algorithm", "key_id", "signed_at", "content_hash",
                      "signature")
_ENVELOPE_OPTIONAL = ("expires_at", "policy_version", "policy_name", "signer")
_ENVELOPE_KEYS = frozenset(_ENVELOPE_REQUIRED + _ENVELOPE_OPTIONAL)

_TRUSTED_KEY_REQUIRED = ("key_id", "algorithm", "public_key")
_TRUSTED_KEY_KEYS = frozenset(_TRUSTED_KEY_REQUIRED + ("name", "not_after", "revoked"))


class SigningError(ValueError):
    """A signing or verification input could not be used."""


class SigningUnavailable(SigningError):
    """Ed25519 is unavailable: the optional ``cryptography`` extra is missing.

    Raised instead of returning a result, so a caller can never mistake "we
    could not check this signature" for "this signature is good".
    """


class MalformedEnvelope(SigningError):
    """An envelope object is not a usable 0.2 envelope.

    Carries the spec section 6.4 ``reason`` code that the corresponding check
    in :func:`verify_policy` would report, so the two entry points agree:
    ``malformed_envelope`` (check 1), ``unsupported_format_version`` (check 2),
    or ``unsupported_algorithm`` (check 3).
    """

    def __init__(self, message: str, reason: str = "malformed_envelope") -> None:
        super().__init__(message)
        self.reason = reason


class KeyringError(SigningError):
    """A keyring document is malformed or an entry's ``key_id`` does not match."""


# --------------------------------------------------------------------------- #
# Timestamps (spec section 4: RFC 3339 UTC, millisecond precision, Z suffix)
# --------------------------------------------------------------------------- #


def format_timestamp(moment: datetime) -> str:
    """Render ``moment`` as the envelope timestamp format.

    Naive datetimes are read as UTC; aware ones are converted. Microseconds are
    truncated (not rounded) to milliseconds, so the rendered instant is never
    later than the one it describes -- rounding up could push a ``signed_at``
    past a ``not_after`` boundary it was actually before.
    """
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    moment = moment.astimezone(timezone.utc)
    millis = moment.microsecond // 1000
    return f"{moment:%Y-%m-%dT%H:%M:%S}.{millis:03d}Z"


def _parse_timestamp(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP_RE.match(value):
        raise MalformedEnvelope(
            f"{label} must be RFC 3339 UTC with millisecond precision and a Z suffix, "
            f"got {value!r}"
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:  # e.g. 2026-13-40T...: pattern matches, date does not exist
        raise MalformedEnvelope(f"{label} is not a real instant: {value!r} ({exc})") from exc
    return parsed.replace(tzinfo=timezone.utc)


def _coerce_moment(value: datetime | str | None, label: str) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return _parse_timestamp(format_timestamp(value), label)
    return _parse_timestamp(value, label)


# --------------------------------------------------------------------------- #
# Keys (spec section 5)
# --------------------------------------------------------------------------- #


def _pem_body(pem: str, label: str) -> bytes:
    """Return the DER bytes of a PEM block, tolerating surrounding comments.

    The published test keys under ``fixtures/signing/keys/`` carry a
    DO-NOT-USE header above the armor, and PEM readers are expected to ignore
    anything outside the ``-----BEGIN/END-----`` lines (RFC 7468 section 5.2).
    """
    if not isinstance(pem, str):
        raise SigningError(f"{label} must be a PEM string, got {type(pem).__name__}")
    begin = f"-----BEGIN {label}-----"
    end = f"-----END {label}-----"
    start = pem.find(begin)
    stop = pem.find(end, start + len(begin)) if start >= 0 else -1
    if start < 0 or stop < 0:
        raise SigningError(f"not a PEM {label} block")
    encoded = "".join(pem[start + len(begin):stop].split())
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SigningError(f"{label} body is not valid base64: {exc}") from exc


def key_id_from_public_key(public_key_pem: str) -> str:
    """Return ``sha256:`` + hex SHA-256 of the SPKI DER (spec section 5.2).

    Deriving the id from the SubjectPublicKeyInfo rather than the raw 32 key
    bytes binds it to the algorithm as well as the key, so an id can never be
    reinterpreted under a different scheme. The DER is checked against the
    fixed Ed25519 SPKI shape first: a key id over some other algorithm's key
    would be a well-formed-looking value that no verifier could ever use.
    """
    der = _pem_body(public_key_pem, "PUBLIC KEY")
    if len(der) != _ED25519_SPKI_LEN or not der.startswith(_ED25519_SPKI_PREFIX):
        raise SigningError(
            "public key is not an Ed25519 SubjectPublicKeyInfo "
            f"(expected {_ED25519_SPKI_LEN} DER bytes with the RFC 8410 prefix, "
            f"got {len(der)})"
        )
    return "sha256:" + hashlib.sha256(der).hexdigest()


def _raw_public_key(public_key_pem: str) -> bytes:
    """Return the 32 raw key bytes of an Ed25519 SPKI PEM."""
    der = _pem_body(public_key_pem, "PUBLIC KEY")
    if len(der) != _ED25519_SPKI_LEN or not der.startswith(_ED25519_SPKI_PREFIX):
        raise SigningError("public key is not an Ed25519 SubjectPublicKeyInfo")
    return der[len(_ED25519_SPKI_PREFIX):]


@dataclass(frozen=True)
class TrustedKey:
    """One entry of a keyring (spec section 5.3).

    ``key_id`` is always the value recomputed from ``public_key``:
    :func:`load_keyring` rejects an entry whose declared id differs, so nothing
    downstream has to wonder which of the two it is holding.
    """

    key_id: str
    algorithm: str
    public_key: str
    name: str | None = None
    not_after: str | None = None
    revoked: bool = False

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key": self.public_key,
        }
        if self.name is not None:
            out["name"] = self.name
        if self.not_after is not None:
            out["not_after"] = self.not_after
        if self.revoked:
            out["revoked"] = True
        return out


@dataclass(frozen=True)
class Keyring:
    """The set of public keys a verifier trusts (spec section 5.3)."""

    keys: tuple[TrustedKey, ...] = ()
    keyring_version: str = KEYRING_VERSION

    def find(self, key_id: str) -> TrustedKey | None:
        """Return the entry with exactly this ``key_id``, or ``None``.

        Selection is by exact match only. A verifier MUST NOT try other keys
        when the named one is absent (spec section 5.3), so there is
        deliberately no "try them all" helper here.
        """
        for entry in self.keys:
            if entry.key_id == key_id:
                return entry
        return None

    @classmethod
    def from_public_key(cls, public_key_pem: str, *, name: str | None = None) -> "Keyring":
        """Build a one-key keyring from a bare SPKI PEM (spec section 5.3, last line)."""
        return cls(
            keys=(
                TrustedKey(
                    key_id=key_id_from_public_key(public_key_pem),
                    algorithm=SIGNATURE_ALGORITHM,
                    public_key=_normalize_public_key_pem(public_key_pem),
                    name=name,
                ),
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "keyring_version": self.keyring_version,
            "keys": [entry.to_dict() for entry in self.keys],
        }


def _normalize_public_key_pem(pem: str) -> str:
    """Re-emit just the armored block, dropping any comment header around it."""
    der = _pem_body(pem, "PUBLIC KEY")
    body = base64.b64encode(der).decode("ascii")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"


def load_keyring(obj: Any) -> Keyring:
    """Load and validate a keyring (spec section 5.3).

    ``obj`` is a parsed keyring mapping, a JSON string, a PEM public key (taken
    as a one-key keyring), or an existing :class:`Keyring`.

    Every entry's ``key_id`` is recomputed from its ``public_key`` and an entry
    whose declared id differs is rejected outright: a keyring that can name a
    key one thing and carry another is a keyring where ``key_id`` selection
    means nothing.
    """
    if isinstance(obj, Keyring):
        return obj
    if isinstance(obj, (bytes, bytearray)):
        obj = obj.decode("utf-8")
    if isinstance(obj, str):
        text = obj.strip()
        # A keyring document is a JSON object and a public key file is PEM, so
        # the leading character tells them apart. Sniffing for the PEM armor
        # instead would misread a keyring, whose `public_key` members contain
        # that armor as escaped JSON string content.
        if not text.startswith("{") and "-----BEGIN PUBLIC KEY-----" in text:
            return Keyring.from_public_key(text)
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise KeyringError(f"keyring is not valid JSON: {exc}") from exc
    if not isinstance(obj, Mapping):
        raise KeyringError(f"keyring must be a JSON object, got {type(obj).__name__}")

    unknown = sorted(set(obj) - {"keyring_version", "keys"})
    if unknown:
        raise KeyringError(f"unknown keyring field(s): {', '.join(unknown)}")
    version = obj.get("keyring_version")
    if version != KEYRING_VERSION:
        raise KeyringError(
            f"unsupported keyring_version {version!r} (this implementation reads "
            f"{KEYRING_VERSION!r} only)"
        )
    raw_keys = obj.get("keys")
    if not isinstance(raw_keys, Sequence) or isinstance(raw_keys, (str, bytes)):
        raise KeyringError("keyring `keys` must be an array")
    if not raw_keys:
        raise KeyringError("keyring `keys` must not be empty")

    entries: list[TrustedKey] = []
    for index, raw in enumerate(raw_keys):
        entries.append(_load_trusted_key(raw, index))
    return Keyring(keys=tuple(entries), keyring_version=KEYRING_VERSION)


def _load_trusted_key(raw: Any, index: int) -> TrustedKey:
    where = f"keys[{index}]"
    if not isinstance(raw, Mapping):
        raise KeyringError(f"{where} must be an object")
    unknown = sorted(set(raw) - _TRUSTED_KEY_KEYS)
    if unknown:
        raise KeyringError(f"{where}: unknown field(s): {', '.join(unknown)}")
    for required in _TRUSTED_KEY_REQUIRED:
        if required not in raw:
            raise KeyringError(f"{where}: missing required field `{required}`")

    algorithm = raw["algorithm"]
    if algorithm != SIGNATURE_ALGORITHM:
        raise KeyringError(
            f"{where}: unsupported algorithm {algorithm!r} (only {SIGNATURE_ALGORITHM!r} "
            "is defined in 0.2)"
        )
    declared = raw["key_id"]
    if not isinstance(declared, str) or not _HASH_RE.match(declared):
        raise KeyringError(f"{where}: key_id must match sha256:<64 lowercase hex>")
    public_key = raw["public_key"]
    try:
        recomputed = key_id_from_public_key(public_key)
    except SigningError as exc:
        raise KeyringError(f"{where}: {exc}") from exc
    if recomputed != declared:
        raise KeyringError(
            f"{where}: declared key_id {declared} does not match the id recomputed from "
            f"public_key ({recomputed}); the entry is untrustworthy"
        )

    name = raw.get("name")
    if name is not None and not isinstance(name, str):
        raise KeyringError(f"{where}: name must be a string")
    not_after = raw.get("not_after")
    if not_after is not None:
        if not isinstance(not_after, str) or not _TIMESTAMP_RE.match(not_after):
            raise KeyringError(
                f"{where}: not_after must be RFC 3339 UTC with millisecond precision"
            )
        try:
            _parse_timestamp(not_after, f"{where}.not_after")
        except MalformedEnvelope as exc:
            raise KeyringError(f"{where}: {exc}") from exc
    revoked = raw.get("revoked", False)
    if not isinstance(revoked, bool):
        raise KeyringError(f"{where}: revoked must be a boolean")

    return TrustedKey(
        key_id=declared,
        algorithm=SIGNATURE_ALGORITHM,
        public_key=public_key,
        name=name,
        not_after=not_after,
        revoked=revoked,
    )


# --------------------------------------------------------------------------- #
# The envelope (spec section 4)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Envelope:
    """A detached policy signature (spec section 4).

    Every member except :attr:`signature` is a signed claim, so editing any of
    them after signing invalidates the envelope.
    """

    key_id: str
    signed_at: str
    content_hash: str
    signature: str
    format_version: str = ENVELOPE_FORMAT_VERSION
    algorithm: str = SIGNATURE_ALGORITHM
    expires_at: str | None = None
    policy_version: int | None = None
    policy_name: str | None = None
    signer: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the envelope as the JSON object written to ``<policy>.yaml.sig``."""
        out = self.claims()
        out["signature"] = self.signature
        return out

    def claims(self) -> dict[str, Any]:
        """Return the signed members: the envelope without ``signature``."""
        out: dict[str, Any] = {
            "format_version": self.format_version,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "signed_at": self.signed_at,
            "content_hash": self.content_hash,
        }
        if self.expires_at is not None:
            out["expires_at"] = self.expires_at
        if self.policy_version is not None:
            out["policy_version"] = self.policy_version
        if self.policy_name is not None:
            out["policy_name"] = self.policy_name
        if self.signer is not None:
            out["signer"] = self.signer
        return out

    def to_json(self, *, indent: int | None = 2) -> str:
        """Render the ``.sig`` file text. Key order is presentational only."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False) + "\n"

    def signing_input(self) -> bytes:
        """Return the exact bytes the signature covers (spec section 4.1)."""
        return signing_input(self.claims())


def signing_input(claims: Mapping[str, Any]) -> bytes:
    """Return the signing input for a set of envelope claims (spec section 4.1).

    The RFC 8785 canonical form, UTF-8, of the envelope object with the
    ``signature`` member absent. No projection applies: envelopes have no
    schema defaults to materialize.
    """
    payload = {key: value for key, value in claims.items() if key != "signature"}
    try:
        return canonical_json_value(payload).encode("utf-8")
    except CanonicalError as exc:
        raise MalformedEnvelope(f"envelope has no canonical form: {exc}") from exc


def parse_envelope(obj: Any) -> Envelope:
    """Parse and structurally validate an envelope object, fail-closed.

    ``obj`` is a parsed JSON mapping, a JSON string, or an existing
    :class:`Envelope`. Unknown members, missing required members, malformed
    values, an unrecognized ``format_version`` and an unrecognized
    ``algorithm`` all raise :class:`MalformedEnvelope`, whose ``reason``
    attribute carries the spec section 6.4 code.

    Note that ``format_version`` and ``algorithm`` are validated *after* the
    structural pass, not as part of it: the schema pins both with ``const``,
    but spec section 6.2 gives each its own check and its own reason code, and
    the vectors ``bad-format-version`` and ``bad-algorithm`` expect those codes
    rather than ``malformed_envelope``. So the structural pass treats them as
    plain non-empty strings and :func:`_check_format` / :func:`_check_algorithm`
    decide the value.
    """
    envelope = _parse_envelope_shape(obj)
    _check_format(envelope)
    _check_algorithm(envelope)
    return envelope


def _parse_envelope_shape(obj: Any) -> Envelope:
    """Check 1 of spec section 6.2: the envelope validates against the schema."""
    if isinstance(obj, Envelope):
        # Round-trip rather than trusting it: a hand-built Envelope has not been
        # through check 1, and `verify_policy` accepts whatever a caller hands it.
        obj = obj.to_dict()
    if isinstance(obj, (bytes, bytearray)):
        obj = obj.decode("utf-8")
    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except json.JSONDecodeError as exc:
            raise MalformedEnvelope(f"envelope is not valid JSON: {exc}") from exc
    if not isinstance(obj, Mapping):
        raise MalformedEnvelope(f"envelope must be a JSON object, got {type(obj).__name__}")

    unknown = sorted(set(obj) - _ENVELOPE_KEYS)
    if unknown:
        raise MalformedEnvelope(f"unknown envelope field(s): {', '.join(unknown)}")
    for required in _ENVELOPE_REQUIRED:
        if required not in obj:
            raise MalformedEnvelope(f"missing required envelope field `{required}`")

    format_version = obj["format_version"]
    if not isinstance(format_version, str) or not format_version:
        raise MalformedEnvelope("format_version must be a non-empty string")
    algorithm = obj["algorithm"]
    if not isinstance(algorithm, str) or not algorithm:
        raise MalformedEnvelope("algorithm must be a non-empty string")

    key_id = obj["key_id"]
    if not isinstance(key_id, str) or not _HASH_RE.match(key_id):
        raise MalformedEnvelope("key_id must match sha256:<64 lowercase hex>")
    hash_value = obj["content_hash"]
    if not isinstance(hash_value, str) or not _HASH_RE.match(hash_value):
        raise MalformedEnvelope("content_hash must match sha256:<64 lowercase hex>")
    signature = obj["signature"]
    if not isinstance(signature, str) or not _SIGNATURE_RE.match(signature):
        raise MalformedEnvelope(
            "signature must be 86 base64url characters without padding (a 64-byte Ed25519 "
            "signature)"
        )

    signed_at = obj["signed_at"]
    _parse_timestamp(signed_at, "signed_at")
    expires_at = obj.get("expires_at")
    if expires_at is not None:
        _parse_timestamp(expires_at, "expires_at")

    policy_version = obj.get("policy_version")
    if policy_version is not None:
        # `True` is an `int` in Python and would sail through a naive check.
        if isinstance(policy_version, bool) or not isinstance(policy_version, int):
            raise MalformedEnvelope("policy_version must be an integer")
        if policy_version < 0:
            raise MalformedEnvelope("policy_version must not be negative")
    policy_name = obj.get("policy_name")
    if policy_name is not None and (not isinstance(policy_name, str) or not policy_name):
        raise MalformedEnvelope("policy_name must be a non-empty string")
    signer = obj.get("signer")
    if signer is not None and (not isinstance(signer, str) or not signer):
        raise MalformedEnvelope("signer must be a non-empty string")

    return Envelope(
        format_version=format_version,
        algorithm=algorithm,
        key_id=key_id,
        signed_at=signed_at,
        content_hash=hash_value,
        signature=signature,
        expires_at=expires_at,
        policy_version=policy_version,
        policy_name=policy_name,
        signer=signer,
    )


def _check_format(envelope: Envelope) -> None:
    """Check 2 of spec section 6.2. A verifier never negotiates a version down."""
    if envelope.format_version != ENVELOPE_FORMAT_VERSION:
        raise MalformedEnvelope(
            f"unsupported envelope format_version {envelope.format_version!r} "
            f"(this implementation reads {ENVELOPE_FORMAT_VERSION!r} only)",
            reason="unsupported_format_version",
        )


def _check_algorithm(envelope: Envelope) -> None:
    """Check 3 of spec section 6.2."""
    if envelope.algorithm != SIGNATURE_ALGORITHM:
        raise MalformedEnvelope(
            f"unsupported signature algorithm {envelope.algorithm!r} "
            f"(only {SIGNATURE_ALGORITHM!r} is defined in 0.2)",
            reason="unsupported_algorithm",
        )


def _b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


# --------------------------------------------------------------------------- #
# Ed25519 backend (optional `cryptography` extra)
# --------------------------------------------------------------------------- #


def _ed25519():
    """Import the Ed25519 primitives lazily, or explain that they are missing."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise SigningUnavailable(
            "Ed25519 is not available: the standard library has no Ed25519, so policy "
            "signing and verification need the optional `cryptography` dependency. "
            'Install it with: pip install "hushspec[signing]"'
        ) from exc
    return ed25519


def _load_private_key(private_key_pem: str | bytes):
    ed25519 = _ed25519()
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode("utf-8")
    try:
        key = load_pem_private_key(private_key_pem, password=None)
    except Exception as exc:
        raise SigningError(f"could not read the PKCS#8 private key: {exc}") from exc
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise SigningError(
            f"private key is {type(key).__name__}, not Ed25519; format 0.2 defines "
            "Ed25519 only"
        )
    return key


def public_key_from_private_key(private_key_pem: str | bytes) -> str:
    """Return the SPKI PEM of the public half of a PKCS#8 Ed25519 private key."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = _load_private_key(private_key_pem)
    return key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def _verify_raw(public_key_pem: str, signature: bytes, payload: bytes) -> bool:
    ed25519 = _ed25519()
    try:
        key = ed25519.Ed25519PublicKey.from_public_bytes(_raw_public_key(public_key_pem))
    except SigningError:
        raise
    except Exception as exc:
        raise SigningError(f"could not read the public key: {exc}") from exc
    try:
        key.verify(signature, payload)
    except Exception:
        # `InvalidSignature` and anything else the backend raises are the same
        # answer here: this signature does not verify.
        return False
    return True


# --------------------------------------------------------------------------- #
# Signing (spec section 4.2)
# --------------------------------------------------------------------------- #


def sign_policy(
    resolved_spec: Any,
    private_key_pem: str | bytes,
    *,
    signed_at: datetime | str | None = None,
    expires_at: datetime | str | None = None,
    policy_version: int | None = None,
    policy_name: str | None = None,
    signer: str | None = None,
) -> Envelope:
    """Sign a **resolved** policy, returning the detached envelope.

    ``resolved_spec`` is a resolved document -- a raw mapping (preferred) or a
    parsed :class:`~hushspec.schema.HushSpec`. It must already be resolved:
    spec section 3 requires a signer to resolve and validate exactly as the
    verifier will, and :func:`~hushspec.canonical.content_hash` refuses a
    document that still carries ``extends``.

    ``policy_version`` and ``policy_name`` default to the document's
    ``metadata.policy_version`` and ``name`` when it has them, which is what
    spec section 4.2 asks signers to do; pass a value to override. ``signed_at``
    defaults to now.

    Raises :class:`SigningUnavailable` when the ``cryptography`` extra is not
    installed, and :class:`~hushspec.canonical.CanonicalError` when the
    document has no canonical form.
    """
    key = _load_private_key(private_key_pem)
    digest = content_hash(resolved_spec)

    document = _as_mapping(resolved_spec)
    if policy_version is None:
        metadata = document.get("metadata") if document is not None else None
        if isinstance(metadata, Mapping):
            candidate = metadata.get("policy_version")
            if isinstance(candidate, int) and not isinstance(candidate, bool):
                policy_version = candidate
    if policy_name is None and document is not None:
        candidate = document.get("name")
        if isinstance(candidate, str) and candidate:
            policy_name = candidate

    moment = _coerce_moment(signed_at, "signed_at") or datetime.now(timezone.utc)
    expiry = _coerce_moment(expires_at, "expires_at")

    envelope = Envelope(
        key_id=key_id_from_public_key(public_key_from_private_key(private_key_pem)),
        signed_at=format_timestamp(moment),
        content_hash=digest,
        signature="",
        expires_at=format_timestamp(expiry) if expiry is not None else None,
        policy_version=policy_version,
        policy_name=policy_name,
        signer=signer,
    )
    raw = key.sign(signing_input(envelope.claims()))
    return _replace_signature(envelope, _b64url_nopad(raw))


def _replace_signature(envelope: Envelope, signature: str) -> Envelope:
    return replace(envelope, signature=signature)


def _as_mapping(spec: Any) -> Mapping[str, Any] | None:
    """Return ``spec`` as a mapping when it can be one, for claim defaults."""
    if isinstance(spec, Mapping):
        return spec
    to_dict = getattr(spec, "to_dict", None)
    if callable(to_dict):
        result = to_dict()
        if isinstance(result, Mapping):
            return result
    return None


# --------------------------------------------------------------------------- #
# Verification (spec section 6)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class VerifyResult:
    """The outcome of :func:`verify_policy`.

    ``reason`` is ``None`` when ``valid`` is true and otherwise one of
    :data:`REASON_CODES`, spelled exactly as spec section 6.4 spells it --
    it is the value that goes into a receipt's ``policy.signature.reason``.
    ``detail`` is free text for humans and is never part of the contract.
    """

    valid: bool
    reason: str | None = None
    detail: str | None = None
    key_id: str | None = None
    policy_version: int | None = None

    def __bool__(self) -> bool:
        return self.valid

    @classmethod
    def ok(cls, envelope: Envelope) -> "VerifyResult":
        return cls(
            valid=True,
            key_id=envelope.key_id,
            policy_version=envelope.policy_version,
        )

    @classmethod
    def fail(
        cls, reason: str, detail: str, *, envelope: Envelope | None = None
    ) -> "VerifyResult":
        assert reason in REASON_CODES, f"{reason!r} is not a spec section 6.4 reason code"
        return cls(
            valid=False,
            reason=reason,
            detail=detail,
            key_id=envelope.key_id if envelope is not None else None,
            policy_version=envelope.policy_version if envelope is not None else None,
        )


def verify_policy(
    resolved_spec: Any,
    envelope: Any,
    *,
    keyring: Any = None,
    public_key_pem: str | None = None,
    now: datetime | str | None = None,
    max_clock_skew_seconds: int = DEFAULT_MAX_CLOCK_SKEW_SECONDS,
    last_seen_version: int | None = None,
) -> VerifyResult:
    """Run the ten ordered checks of spec section 6.2 over a resolved policy.

    Checks stop at the first failure and the result carries that check's reason
    code. ``resolved_spec`` must be the resolved, in-memory document that will
    actually be evaluated -- spec section 10 ("time of check, time of use")
    requires the verified document and the enforced document to be the same
    object, not the same file re-read afterwards.

    Trust comes from ``keyring`` (a :class:`Keyring`, a parsed keyring mapping,
    or JSON text) or from ``public_key_pem`` as a one-key keyring; exactly one
    is required. ``now`` defaults to the current time, ``last_seen_version`` is
    the verifier's recorded ``policy_version`` for this policy name and enables
    check 10 when supplied.

    Raises :class:`SigningUnavailable` when the ``cryptography`` extra is not
    installed: a caller must never be able to read "could not check" as valid.
    """
    _ed25519()  # fail loudly before any check can look like a verdict

    if keyring is None and public_key_pem is None:
        raise SigningError(
            "verify_policy needs a keyring or a public_key_pem; there is no default trust"
        )
    if keyring is not None and public_key_pem is not None:
        raise SigningError("pass either keyring or public_key_pem, not both")
    try:
        ring = load_keyring(keyring) if keyring is not None else Keyring.from_public_key(
            public_key_pem  # type: ignore[arg-type]
        )
    except SigningError as exc:
        # A keyring we cannot load is not a verdict about the signature; it is a
        # misconfigured verifier, and silently reporting `unknown_key_id` would
        # hide that.
        raise KeyringError(str(exc)) from exc

    moment = _coerce_moment(now, "now") or datetime.now(timezone.utc)
    if max_clock_skew_seconds < 0:
        raise SigningError("max_clock_skew_seconds must not be negative")

    # Checks 1-3: shape, format version, algorithm.
    try:
        parsed = parse_envelope(envelope)
    except MalformedEnvelope as exc:
        return VerifyResult(valid=False, reason=exc.reason, detail=str(exc))

    # Check 4: key lookup by exact id. `load_keyring` already recomputed every
    # entry's id from its public key, so a hit is a key we trust by its bits.
    entry = ring.find(parsed.key_id)
    if entry is None:
        return VerifyResult.fail(
            "unknown_key_id",
            f"no trusted key with key_id {parsed.key_id}",
            envelope=parsed,
        )

    # Check 5: revocation beats everything about the key.
    if entry.revoked:
        return VerifyResult.fail(
            "key_revoked", f"key {entry.key_id} is revoked", envelope=parsed
        )

    signed_at = _parse_timestamp(parsed.signed_at, "signed_at")

    # Check 6: retirement, which only rejects signatures made at or after it.
    if entry.not_after is not None:
        not_after = _parse_timestamp(entry.not_after, "not_after")
        if signed_at >= not_after:
            return VerifyResult.fail(
                "key_retired",
                f"key {entry.key_id} was retired at {entry.not_after}, "
                f"signature is dated {parsed.signed_at}",
                envelope=parsed,
            )

    # Check 7: clock. `signed_at` is never used for freshness (spec 6.3).
    if signed_at > moment + timedelta(seconds=max_clock_skew_seconds):
        return VerifyResult.fail(
            "signed_at_in_future",
            f"signed_at {parsed.signed_at} is more than {max_clock_skew_seconds}s after "
            f"{format_timestamp(moment)}",
            envelope=parsed,
        )
    if parsed.expires_at is not None:
        expires_at = _parse_timestamp(parsed.expires_at, "expires_at")
        if moment >= expires_at:
            return VerifyResult.fail(
                "expired",
                f"signature expired at {parsed.expires_at}",
                envelope=parsed,
            )

    # Check 8: the signature over the canonical claims.
    try:
        payload = signing_input(parsed.claims())
        raw_signature = _b64url_decode(parsed.signature)
    except (MalformedEnvelope, binascii.Error, ValueError) as exc:
        return VerifyResult.fail("malformed_envelope", str(exc), envelope=parsed)
    if len(raw_signature) != 64 or not _verify_raw(entry.public_key, raw_signature, payload):
        return VerifyResult.fail(
            "signature_mismatch",
            f"Ed25519 verification failed for key {entry.key_id}",
            envelope=parsed,
        )

    # Check 9: the claim the signature actually makes. A document that cannot be
    # canonicalized has no hash to compare, which the spec calls a mismatch.
    try:
        actual = content_hash(resolved_spec)
    except CanonicalError as exc:
        return VerifyResult.fail(
            "content_hash_mismatch",
            f"the policy has no content hash: {exc}",
            envelope=parsed,
        )
    if actual != parsed.content_hash:
        return VerifyResult.fail(
            "content_hash_mismatch",
            f"policy hashes to {actual}, envelope signs {parsed.content_hash}",
            envelope=parsed,
        )

    # Check 10: rollback, only when the verifier holds a last-seen version and
    # the envelope carries one.
    if last_seen_version is not None and parsed.policy_version is not None:
        if parsed.policy_version < last_seen_version:
            return VerifyResult.fail(
                "policy_version_rollback",
                f"envelope policy_version {parsed.policy_version} is older than the "
                f"last seen {last_seen_version}",
                envelope=parsed,
            )

    return VerifyResult.ok(parsed)
