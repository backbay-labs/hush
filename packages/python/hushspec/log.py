"""Hash-linked receipt log (``spec/hushspec-log.md``, format 0.1).

A log is a JSON Lines file of :class:`LogEntry` records. Each entry carries a
sequence number, the hash of the previous entry, its own hash over its
canonical form, and optionally an Ed25519 signature over that hash. A verifier
can therefore detect a line that was edited, deleted, inserted, or reordered
without any other source of truth.

Entries wrap a :class:`~hushspec.receipt.DecisionReceipt` or a
:class:`PolicyEvent` (which policy was loaded or swapped in, with its
provenance) so the log proves not only what was decided but what was in force
when.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    BinaryIO,
    Iterable,
    Iterator,
    NamedTuple,
    Optional,
    Sequence,
    Union,
)

from hushspec.canonical import canonical_json_value
from hushspec.receipt import (
    RECEIPT_VERSION,
    DecisionReceipt,
    PolicySummary,
    ReceiptError,
    digest,
    format_timestamp,
    parse_receipt,
    policy_summary_to_dict,
    receipt_to_dict,
)
from hushspec.version import HUSHSPEC_VERSION

try:  # POSIX advisory locking; absent on Windows.
    import fcntl
except ImportError:  # pragma: no cover - platform dependent
    fcntl = None  # type: ignore[assignment]

__all__ = [
    "LOG_VERSION",
    "GENESIS_HASH",
    "REASON_UNSIGNED",
    "SDK_NAME",
    "EntryType",
    "PolicyEventKind",
    "SdkInfo",
    "PolicyEvent",
    "LogStarted",
    "LogSignature",
    "LogEntry",
    "LogError",
    "LogVerifyOptions",
    "LogVerifyReport",
    "ChainedFileSink",
    "compute_entry_hash",
    "policy_event_to_dict",
    "verify_log",
    "verify_logs",
    "verify_log_files",
]

#: The log-entry format this module writes and verifies.
LOG_VERSION = "0.1"

#: ``prev_hash`` of the first entry of a log that continues nothing.
GENESIS_HASH = "sha256:" + "0" * 64

#: Reported by :func:`verify_log` for an unsigned entry when signatures are
#: required (log spec section 7), besides the signing spec's reason codes.
REASON_UNSIGNED = "entry_unsigned"

#: The ``sdk.name`` this SDK writes into a policy event.
SDK_NAME = "hushspec-python"

#: How long an append waits for another writer's lock before failing.
LOCK_TIMEOUT_SECONDS = 5.0

#: How long to wait between attempts while another writer holds the lock.
_LOCK_POLL_SECONDS = 0.005


def _sdk_version() -> str:
    try:
        from importlib.metadata import version

        return version("hushspec")
    except Exception:  # pragma: no cover - source checkouts without metadata
        return "0.0.0"


# --------------------------------------------------------------------------- #
# Wire types
# --------------------------------------------------------------------------- #


class EntryType(str, Enum):
    """What an entry wraps. Exactly the payload it names is present."""

    RECEIPT = "receipt"
    POLICY_LOADED = "policy_loaded"
    POLICY_SWAPPED = "policy_swapped"
    LOG_STARTED = "log_started"


class PolicyEventKind(str, Enum):
    LOADED = "loaded"
    SWAPPED = "swapped"


@dataclass
class SdkInfo:
    """The SDK that wrote an entry."""

    name: str = SDK_NAME
    version: str = field(default_factory=_sdk_version)

    @classmethod
    def this_sdk(cls) -> "SdkInfo":
        return cls(name=SDK_NAME, version=_sdk_version())


@dataclass
class PolicyEvent:
    """A policy-in-effect record (log spec section 6).

    What was enforced from this moment on, with the same identity a receipt
    carries, so a reader can map every receipt to the exact policy in force by
    walking back to the nearest policy event.
    """

    policy: PolicySummary
    event: str = PolicyEventKind.LOADED.value
    #: RFC 3339 UTC, millisecond precision.
    timestamp: str = ""
    enforcement_mode: str = "enforce"
    sdk: SdkInfo = field(default_factory=SdkInfo.this_sdk)
    #: The HushSpec version the engine implements.
    spec_version: str = HUSHSPEC_VERSION
    #: For ``swapped``: the content hash of the policy that was replaced.
    previous_content_hash: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = format_timestamp(datetime.now(timezone.utc))

    @classmethod
    def loaded(
        cls,
        policy: PolicySummary,
        enforcement_mode: str = "enforce",
        *,
        timestamp: Optional[str] = None,
        sdk: Optional[SdkInfo] = None,
    ) -> "PolicyEvent":
        """A ``loaded`` event for *policy*, stamped now unless given a time."""
        return cls(
            policy=policy,
            event=PolicyEventKind.LOADED.value,
            timestamp=timestamp or "",
            enforcement_mode=_value(enforcement_mode),
            sdk=sdk or SdkInfo.this_sdk(),
        )

    @classmethod
    def swapped(
        cls,
        policy: PolicySummary,
        enforcement_mode: str = "enforce",
        previous_content_hash: Optional[str] = None,
        *,
        timestamp: Optional[str] = None,
        sdk: Optional[SdkInfo] = None,
    ) -> "PolicyEvent":
        """A ``swapped`` event: *policy* replaces the one named by the hash."""
        return cls(
            policy=policy,
            event=PolicyEventKind.SWAPPED.value,
            timestamp=timestamp or "",
            enforcement_mode=_value(enforcement_mode),
            sdk=sdk or SdkInfo.this_sdk(),
            previous_content_hash=previous_content_hash,
        )


@dataclass
class LogStarted:
    """The first entry of a rotated log file: where the chain came from."""

    timestamp: str
    previous_file: Optional[str] = None
    #: The last ``entry_hash`` of the previous file; equals this entry's
    #: ``prev_hash``.
    previous_entry_hash: Optional[str] = None


@dataclass
class LogSignature:
    """An entry signature: the 0.2 signature envelope (signing spec section 4)
    whose ``content_hash`` is the entry's ``entry_hash``."""

    key_id: str
    signed_at: str
    content_hash: str
    signature: str
    format_version: str = "0.2"
    algorithm: str = "ed25519"
    expires_at: Optional[str] = None
    policy_version: Optional[int] = None
    policy_name: Optional[str] = None
    signer: Optional[str] = None

    @classmethod
    def from_envelope(cls, envelope: Any) -> "LogSignature":
        """Carry a signing envelope into a log entry.

        An entry signature is exactly an envelope, so the members are copied
        by name and the two field sets have to match: a member added to one
        and not the other would otherwise vanish on the way into the log.
        """
        members = {member.name for member in fields(cls)}
        supplied = {member.name for member in fields(envelope)}
        if members != supplied:
            raise SinkError(
                "a log entry signature and a signing envelope carry the same "
                f"members; these differ by {sorted(members ^ supplied)}"
            )
        return cls(**{name: getattr(envelope, name) for name in members})


@dataclass
class LogEntry:
    """One line of a log."""

    seq: int
    #: ``entry_hash`` of the previous entry, or :data:`GENESIS_HASH`.
    prev_hash: str
    entry_type: str
    log_version: str = LOG_VERSION
    receipt: Optional[DecisionReceipt] = None
    policy_event: Optional[PolicyEvent] = None
    log_started: Optional[LogStarted] = None
    #: ``sha256:`` over the canonical form of this entry without ``entry_hash``
    #: and ``signature``.
    entry_hash: str = ""
    signature: Optional[LogSignature] = None

    def to_dict(self) -> dict[str, Any]:
        """The entry as the JSON object one line of the log holds."""
        data: dict[str, Any] = {
            "log_version": self.log_version,
            "seq": self.seq,
            "prev_hash": self.prev_hash,
            "entry_type": _value(self.entry_type),
        }
        if self.receipt is not None:
            data["receipt"] = (
                dict(self.receipt)
                if isinstance(self.receipt, dict)
                else receipt_to_dict(self.receipt)
            )
        if self.policy_event is not None:
            data["policy_event"] = policy_event_to_dict(self.policy_event)
        if self.log_started is not None:
            data["log_started"] = _plain(self.log_started)
        if self.entry_hash:
            data["entry_hash"] = self.entry_hash
        if self.signature is not None:
            data["signature"] = _plain(self.signature)
        return data

    def compute_entry_hash(self) -> str:
        """Recompute the hash this entry should carry."""
        return compute_entry_hash(self.to_dict())

    def payload_matches_type(self) -> bool:
        """Whether exactly the payload named by ``entry_type`` is present."""
        return _payload_matches_type(self.to_dict())


def policy_event_to_dict(event: PolicyEvent) -> dict[str, Any]:
    """The JSON object a log entry's ``policy_event`` member carries.

    The one spelling of a policy event: a log entry embeds it, and a telemetry
    sink exports exactly these bytes, so both say the same thing about the same
    load.
    """
    return _plain(event)


def compute_entry_hash(entry: dict[str, Any]) -> str:
    """``sha256:`` over the RFC 8785 canonical form of *entry* with
    ``entry_hash`` and ``signature`` removed (log spec section 4).

    Takes the raw JSON object rather than a typed entry, so verification hashes
    exactly the bytes the file holds and never a re-serialization of them.
    """
    payload = {
        key: value
        for key, value in entry.items()
        if key not in ("entry_hash", "signature")
    }
    return digest(canonical_json_value(payload))


def _payload_matches_type(entry: dict[str, Any]) -> bool:
    has_receipt = entry.get("receipt") is not None
    has_event = entry.get("policy_event") is not None
    has_started = entry.get("log_started") is not None
    entry_type = entry.get("entry_type")
    if entry_type == EntryType.RECEIPT.value:
        return has_receipt and not has_event and not has_started
    if entry_type == EntryType.LOG_STARTED.value:
        return has_started and not has_receipt and not has_event
    if entry_type in (
        EntryType.POLICY_LOADED.value,
        EntryType.POLICY_SWAPPED.value,
    ):
        if has_receipt or has_started or not has_event:
            return False
        kind = entry["policy_event"].get("event")
        return kind == (
            PolicyEventKind.LOADED.value
            if entry_type == EntryType.POLICY_LOADED.value
            else PolicyEventKind.SWAPPED.value
        )
    return False


_ENTRY_KEYS = frozenset(
    (
        "log_version",
        "seq",
        "prev_hash",
        "entry_type",
        "receipt",
        "policy_event",
        "log_started",
        "entry_hash",
        "signature",
    )
)

_POLICY_EVENT_KEYS = frozenset(
    (
        "event",
        "timestamp",
        "policy",
        "enforcement_mode",
        "sdk",
        "spec_version",
        "previous_content_hash",
    )
)

_POLICY_SUMMARY_KEYS = frozenset(
    ("name", "version", "spec_version", "content_hash", "extends_chain", "signature")
)

_CHAIN_LINK_KEYS = frozenset(("source", "content_hash"))

_SIGNATURE_STATUS_KEYS = frozenset(("verified", "key_id", "verified_at", "reason"))

_SDK_KEYS = frozenset(("name", "version"))

_LOG_STARTED_KEYS = frozenset(("timestamp", "previous_file", "previous_entry_hash"))

_ENTRY_SIGNATURE_KEYS = frozenset(
    (
        "format_version",
        "algorithm",
        "key_id",
        "signed_at",
        "expires_at",
        "policy_version",
        "policy_name",
        "content_hash",
        "signer",
        "signature",
    )
)


def _unknown_key(value: Any, allowed: frozenset[str]) -> Optional[str]:
    """The first unknown member of *value*, or ``None``.

    Unknown fields are a break (log spec section 8, step 1): a verifier that
    ignored them would not be hashing what it read.
    """
    if not isinstance(value, dict):
        return None
    unknown = sorted(set(value) - allowed)
    return unknown[0] if unknown else None


def _unknown_policy_event_key(event: Any) -> Optional[str]:
    """The first unknown member anywhere inside a ``policy_event``.

    The log-entry schema closes every object it defines, not only the ones the
    entry names directly, so the check reaches the policy identity and the SDK
    record too.
    """
    unknown = _unknown_key(event, _POLICY_EVENT_KEYS)
    if unknown is not None or not isinstance(event, dict):
        return unknown
    unknown = _unknown_policy_summary_key(event.get("policy"))
    if unknown is not None:
        return unknown
    return _unknown_key(event.get("sdk"), _SDK_KEYS)


def _log_entry_problem(entry: Any) -> Optional[str]:
    """Why *entry* is not a log entry, or ``None``.

    The entry-level strictness of log spec section 8, step 1: an unknown member
    anywhere the log-entry schema closes an object, a payload member that is
    not a JSON object, and a ``policy_event`` or ``log_started`` that departs
    from the shape the schema gives it. An append runs it over the file's last
    line, so the tail this SDK is willing to continue is exactly the tail a
    verifier is willing to read.
    """
    if not isinstance(entry, dict):
        return "expected a JSON object"
    for member in ("receipt", "policy_event", "log_started", "signature"):
        value = entry.get(member)
        if value is not None and not isinstance(value, dict):
            return f"{member} is not a JSON object"
    unknown = (
        _unknown_key(entry, _ENTRY_KEYS)
        or _unknown_policy_event_key(entry.get("policy_event"))
        or _unknown_key(entry.get("log_started"), _LOG_STARTED_KEYS)
        or _unknown_key(entry.get("signature"), _ENTRY_SIGNATURE_KEYS)
    )
    if unknown is not None:
        return f"unknown field {unknown!r}"
    return _payload_problem(entry)


class _Member(NamedTuple):
    """One member of a log payload object, as the log-entry schema declares it.

    ``kind`` is the JSON type the schema gives the member, where ``index`` is a
    non-negative integer (``PolicySummary.version``); ``values`` is the closed
    enum the value must fall in, when the schema gives it one.
    """

    name: str
    kind: str
    required: bool
    values: tuple[str, ...] = ()


# ``$defs.LogStarted`` of the log-entry schema.
_LOG_STARTED_MEMBERS = (
    _Member("timestamp", "string", True),
    _Member("previous_file", "string", False),
    _Member("previous_entry_hash", "string", False),
)

# ``$defs.PolicyEvent`` of the log-entry schema.
_POLICY_EVENT_MEMBERS = (
    _Member("event", "string", True, ("loaded", "swapped")),
    _Member("timestamp", "string", True),
    _Member("policy", "object", True),
    _Member("enforcement_mode", "string", True, ("enforce", "monitor")),
    _Member("sdk", "object", True),
    _Member("spec_version", "string", True),
    _Member("previous_content_hash", "string", False),
)

# ``$defs.PolicyEvent.sdk`` of the log-entry schema.
_SDK_MEMBERS = (
    _Member("name", "string", True),
    _Member("version", "string", True),
)

# ``$defs.PolicySummary`` of the log-entry schema.
_POLICY_SUMMARY_MEMBERS = (
    _Member("name", "string", False),
    _Member("version", "index", False),
    _Member("spec_version", "string", True),
    _Member("content_hash", "string", True),
    _Member("extends_chain", "array", False),
    _Member("signature", "object", False),
)

# ``$defs.PolicySummary.extends_chain`` items.
_CHAIN_LINK_MEMBERS = (
    _Member("source", "string", True),
    _Member("content_hash", "string", True),
)

# ``$defs.PolicySummary.signature``.
_SIGNATURE_STATUS_MEMBERS = (
    _Member("verified", "boolean", True),
    _Member("key_id", "string", False),
    _Member("verified_at", "string", False),
    _Member("reason", "string", False),
)


def _member_problem(
    container: dict[str, Any], members: tuple[_Member, ...], path: str
) -> Optional[str]:
    """The first way *container* departs from *members*, or ``None``.

    Optional means absent; no declared member admits an explicit ``null``.
    """
    for member in members:
        where = f"{path}.{member.name}"
        if member.name not in container:
            if member.required:
                return f"{where} is missing"
            continue
        value = container[member.name]
        if value is None:
            return f"{where} must not be null"
        if member.kind == "string":
            if not isinstance(value, str):
                return f"{where} is not a string"
            if member.values and value not in member.values:
                return f"{where} is not one of {', '.join(member.values)}"
        elif member.kind == "boolean":
            if not isinstance(value, bool):
                return f"{where} is not a boolean"
        elif member.kind == "index":
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                return f"{where} is not a non-negative integer"
        elif member.kind == "object":
            if not isinstance(value, dict):
                return f"{where} is not a JSON object"
        elif member.kind == "array":
            if not isinstance(value, list):
                return f"{where} is not an array"
    return None


def _payload_problem(entry: dict[str, Any]) -> Optional[str]:
    """Why the payloads *entry* carries are not the ones the schema describes.

    Log spec section 8, step 1: an entry counts as parsed only once every
    payload it carries validates against
    ``schemas/hushspec-log-entry.v1.schema.json``. The entry hash covers
    whatever JSON the line held, so a hash-consistent line can still carry a
    payload missing a member an auditor reads.
    """
    scalar_problem = _log_scalar_problem(entry)
    if scalar_problem is not None:
        return scalar_problem
    if entry.get("signature") is not None:
        problem = _member_problem(entry["signature"], (
            _Member("format_version", "string", True, ("0.2",)),
            _Member("algorithm", "string", True, ("ed25519",)),
            *(_Member(name, "string", True) for name in ("key_id", "signed_at", "content_hash", "signature")),
            *(_Member(name, "string", False) for name in ("expires_at", "policy_name", "signer")),
            _Member("policy_version", "index", False),
        ), "signature")
        if problem is not None:
            return problem
    started = entry.get("log_started")
    if isinstance(started, dict):
        problem = _member_problem(started, _LOG_STARTED_MEMBERS, "log_started")
        if problem is not None:
            return problem
    event = entry.get("policy_event")
    if not isinstance(event, dict):
        return None
    problem = _member_problem(event, _POLICY_EVENT_MEMBERS, "policy_event")
    if problem is not None:
        return problem
    problem = _member_problem(event["sdk"], _SDK_MEMBERS, "policy_event.sdk")
    if problem is not None:
        return problem
    return _policy_summary_problem(event["policy"], "policy_event.policy")


def _log_scalar_problem(value: Any, path: str = "") -> Optional[str]:
    """Log-schema scalars over the original document; receipts validate separately."""
    if value is None:
        return f"{path} must not be null"
    if isinstance(value, dict):
        for key, child in value.items():
            if not path and key == "receipt" and child is not None:
                continue
            problem = _log_scalar_problem(child, f"{path}.{key}" if path else key)
            if problem is not None:
                return problem
    elif isinstance(value, list):
        for index, child in enumerate(value):
            problem = _log_scalar_problem(child, f"{path}[{index}]")
            if problem is not None:
                return problem
    elif isinstance(value, str):
        key = path.rsplit(".", 1)[-1]
        valid = True
        if key in ("prev_hash", "entry_hash", "content_hash", "previous_content_hash", "previous_entry_hash", "key_id"):
            valid = re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
        elif key in ("timestamp", "signed_at", "expires_at", "verified_at"):
            valid = re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z", value) is not None
            if valid:
                try:
                    datetime.fromisoformat(value[:-1] + "+00:00")
                except ValueError:
                    valid = False
        elif key == "spec_version":
            valid = re.fullmatch(r"(0|1)\.[0-9]+\.[0-9]+", value) is not None
        elif path == "signature.signature":
            valid = re.fullmatch(r"[A-Za-z0-9_-]{86}", value) is not None
        elif key in ("source", "previous_file", "policy_name", "signer") or path.startswith("policy_event.sdk."):
            valid = bool(value)
        if not valid:
            return f"{path} does not satisfy the log-entry schema"
    return None


def _policy_summary_problem(policy: dict[str, Any], path: str) -> Optional[str]:
    """Why a policy identity is not a ``PolicySummary``, or ``None``."""
    problem = _member_problem(policy, _POLICY_SUMMARY_MEMBERS, path)
    if problem is not None:
        return problem
    chain = policy.get("extends_chain")
    if isinstance(chain, list):
        for index, link in enumerate(chain):
            where = f"{path}.extends_chain[{index}]"
            if not isinstance(link, dict):
                return f"{where} is not a JSON object"
            problem = _member_problem(link, _CHAIN_LINK_MEMBERS, where)
            if problem is not None:
                return problem
    signature = policy.get("signature")
    if not isinstance(signature, dict):
        return None
    return _member_problem(
        signature, _SIGNATURE_STATUS_MEMBERS, f"{path}.signature"
    )


def _unknown_policy_summary_key(policy: Any) -> Optional[str]:
    """The first unknown member of a policy summary or of its own objects."""
    unknown = _unknown_key(policy, _POLICY_SUMMARY_KEYS)
    if unknown is not None or not isinstance(policy, dict):
        return unknown
    chain = policy.get("extends_chain")
    if isinstance(chain, list):
        for link in chain:
            unknown = _unknown_key(link, _CHAIN_LINK_KEYS)
            if unknown is not None:
                return unknown
    return _unknown_key(policy.get("signature"), _SIGNATURE_STATUS_KEYS)


# --------------------------------------------------------------------------- #
# The chained sink
# --------------------------------------------------------------------------- #


class SinkError(RuntimeError):
    """A hash-linked log could not be continued or written consistently."""


class ChainedFileSink:
    """Appends hash-linked entries to a JSON Lines file, fsyncing each one.

    Opening an existing file continues its chain from the last entry. Appends
    are serialized in-process by a lock and across processes by the
    ``<path>.lock`` sentinel every SDK takes, under which an exclusive
    ``flock`` is held too where the platform has one (log spec section 4).
    Every line is flushed and ``os.fsync``'d before the entry is reported as
    written (log spec section 3). The chain head -- ``seq`` and ``prev_hash``
    -- is re-read from the file while that lock is held, so a second sink or
    process writing the same log extends the chain instead of forking it.
    Rotation (:meth:`rotate`) carries the chain into the new file through a
    ``log_started`` entry.

    It satisfies :class:`~hushspec.sinks.ReceiptSink`, so a guard can write its
    receipts straight into a log.
    """

    def __init__(self, path: Union[str, Path]) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._clock: Optional[datetime] = None
        self._signer: Optional[Union[str, bytes]] = None
        self._signer_options: dict[str, Any] = {}
        last = _last_entry(self._path)
        if last is None:
            self._seq, self._prev_hash = 0, GENESIS_HASH
        else:
            self._seq = last["seq"]
            self._prev_hash = last["entry_hash"]

    @classmethod
    def open(cls, path: Union[str, Path]) -> "ChainedFileSink":
        """Open (or create) the log at *path* and continue its chain."""
        return cls(path)

    def with_clock(self, clock: datetime) -> "ChainedFileSink":
        """Use a fixed instant for ``log_started`` timestamps and signatures."""
        self._clock = clock
        return self

    def with_signer(
        self, private_key_pem: Union[str, bytes], **options: Any
    ) -> "ChainedFileSink":
        """Sign every entry with *private_key_pem* (log spec section 7).

        The envelope is produced over ``entry_hash`` exactly as a policy
        signature is produced over a policy hash. Raises
        :class:`~hushspec.signing.SigningUnavailable` at append time without
        the ``cryptography`` extra.
        """
        self._signer = private_key_pem
        self._signer_options = dict(options)
        return self

    @property
    def path(self) -> Path:
        """The file currently being written."""
        return self._path

    def head(self) -> tuple[int, str]:
        """The last sequence number and entry hash written (or the genesis
        values for an empty log)."""
        with self._lock:
            return self._seq, self._prev_hash

    def _now(self) -> datetime:
        return self._clock or datetime.now(timezone.utc)

    def append(
        self,
        payload: Union[DecisionReceipt, PolicyEvent, LogStarted],
    ) -> LogEntry:
        """Append one entry, returning it with its hash and signature filled in.

        The chain head is re-read from the file under the write lock, so an
        entry continues what the file holds rather than what this sink last
        wrote. A tail that cannot be parsed raises :class:`SinkError`:
        continuing past it would leave a second, unlinked chain in the file.
        """
        with self._lock:
            entry = self._append_to(self._path, self._seq, self._prev_hash, payload)
            self._seq, self._prev_hash = entry.seq, entry.entry_hash
            return entry

    def _append_to(
        self,
        path: Path,
        cached_seq: int,
        cached_prev_hash: str,
        payload: Union[DecisionReceipt, PolicyEvent, LogStarted],
    ) -> LogEntry:
        """Write one entry to *path*, continuing from *cached_seq* and
        *cached_prev_hash* when the file holds no entry of its own, and return
        it without touching the chain head.

        The caller commits the head, so an append that fails leaves the sink
        describing the file it was describing before.
        """
        if isinstance(payload, DecisionReceipt):
            entry_type = EntryType.RECEIPT.value
        elif isinstance(payload, PolicyEvent):
            entry_type = (
                EntryType.POLICY_SWAPPED.value
                if _value(payload.event) == PolicyEventKind.SWAPPED.value
                else EntryType.POLICY_LOADED.value
            )
        elif isinstance(payload, LogStarted):
            entry_type = EntryType.LOG_STARTED.value
        else:
            raise SinkError(f"cannot append {type(payload).__name__} to a log")

        with _locked_for_append(path) as handle:
            # A missing or empty file means a fresh log, or a rotation whose
            # ``log_started`` entry is about to seed the new file; both
            # continue from the head this sink carries.
            head = _last_entry_of(handle, path)
            if head is None:
                seq, prev_hash = cached_seq, cached_prev_hash
            else:
                seq, prev_hash = head["seq"], head["entry_hash"]

            entry = LogEntry(
                seq=seq + 1,
                prev_hash=prev_hash,
                entry_type=entry_type,
                receipt=payload if isinstance(payload, DecisionReceipt) else None,
                policy_event=payload if isinstance(payload, PolicyEvent) else None,
                log_started=payload if isinstance(payload, LogStarted) else None,
            )
            entry.entry_hash = compute_entry_hash(entry.to_dict())
            # Signing belongs under the lock too: the signature covers
            # ``entry_hash``, which depends on the ``prev_hash`` just read.
            if self._signer is not None:
                from hushspec.signing import sign_content_hash

                options = dict(self._signer_options)
                options.setdefault("signed_at", self._now())
                envelope = sign_content_hash(
                    entry.entry_hash, self._signer, **options
                )
                entry.signature = LogSignature.from_envelope(envelope)

            line = json.dumps(entry.to_dict(), separators=(",", ":")) + "\n"
            _write_line(handle, path, line)
            return entry

    def send(self, receipt: DecisionReceipt) -> None:
        """:class:`~hushspec.sinks.ReceiptSink` entry point."""
        self.append(receipt)

    def record_policy_event(self, event: PolicyEvent) -> LogEntry:
        """Record a policy-in-effect event (log spec section 6)."""
        return self.append(event)

    def rotate(self, new_path: Union[str, Path]) -> LogEntry:
        """Start writing to *new_path*, whose first entry is a ``log_started``
        record naming the file this chain continues from and its last hash.

        Sequence numbers restart at 1 in the new file; ``prev_hash`` carries
        over. The new file must not already exist.

        The switch is committed only once that entry is on disk. A rotation
        that cannot write it leaves the sink on the old file, still linked and
        still verifiable, rather than on a new one whose first receipt would
        continue nothing.
        """
        new_path = Path(new_path)
        if new_path.exists():
            raise SinkError(f"cannot rotate into existing file {new_path}")
        # The switch and the ``log_started`` entry happen under one lock: a
        # concurrent send must not slip a receipt into the new file ahead of
        # the record that links it to the old one (log spec section 5).
        with self._lock:
            # Only the file name: logs are moved between hosts, and a path
            # would leak the writer's layout for no verification benefit.
            previous_file = self._path.name or str(self._path)

            def link(previous_hash: str) -> LogEntry:
                return self._append_to(
                    new_path,
                    0,
                    previous_hash,
                    LogStarted(
                        timestamp=format_timestamp(self._now()),
                        previous_file=previous_file,
                        # Always recorded, the genesis value included (log spec
                        # section 5): a verifier given both files compares it
                        # against the previous file's last hash, and an omitted
                        # member is not that hash.
                        previous_entry_hash=previous_hash,
                    ),
                )

            # The link names the old file's last hash as it is on disk, not as
            # this sink last saw it: another writer sharing the file may have
            # appended since. The old file stays locked until the new file's
            # first entry is written, so nothing can extend it past the link.
            if self._path.exists():
                with _locked_for_append(self._path) as handle:
                    head = _last_entry_of(handle, self._path)
                    entry = link(self._prev_hash if head is None else head["entry_hash"])
            else:
                entry = link(self._prev_hash)
            self._path = new_path
            self._seq, self._prev_hash = entry.seq, entry.entry_hash
            return entry


@contextmanager
def _locked_for_append(path: Path) -> Iterator[BinaryIO]:
    """Open *path* for reading and appending under an exclusive lock.

    The lock covers reading the chain head as well as writing, so two writers
    cannot build entries from the same predecessor (log spec section 4). The
    file is opened for append, so the write is atomic against other appenders
    on POSIX.
    """
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    with _sentinel_lock(path):
        try:
            handle = open(path, "a+b")
        except OSError as exc:
            raise SinkError(f"cannot append to {path}: {exc}") from exc
        try:
            with _advisory_lock(handle, path):
                yield handle
        finally:
            handle.close()


@contextmanager
def _sentinel_lock(path: Path) -> Iterator[None]:
    """Hold ``<path>.lock``, created atomically with ``O_EXCL``.

    This is the lock every SDK takes, so writers in different languages
    exclude each other (log spec section 4). A lock this SDK cannot acquire
    within :data:`LOCK_TIMEOUT_SECONDS` is an error, never something to
    bypass: two writers appending to one file interleave chains and corrupt
    both.
    """
    lock_path = path.with_name(path.name + ".lock")
    deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
    while True:
        try:
            descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            break
        except FileExistsError:
            if time.monotonic() > deadline:
                raise SinkError(f"timed out waiting for {lock_path}") from None
            time.sleep(_LOCK_POLL_SECONDS)
        except OSError as exc:
            raise SinkError(f"cannot lock {path}: {exc}") from exc
    try:
        yield
    finally:
        os.close(descriptor)
        try:
            os.unlink(lock_path)
        except OSError:  # pragma: no cover - another writer already reclaimed it
            pass


@contextmanager
def _advisory_lock(handle: BinaryIO, path: Path) -> Iterator[None]:
    """Hold an exclusive ``flock`` on the log file itself, under the sentinel.

    The kernel releases it even if the writer dies, so it also excludes a
    writer that takes only the advisory lock. Platforms without ``fcntl`` rely
    on the sentinel alone rather than appending with no exclusion at all.
    """
    if fcntl is None:  # pragma: no cover - platform dependent
        yield
        return
    deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
    while True:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if time.monotonic() > deadline:
                raise SinkError(f"timed out waiting for a lock on {path}") from None
            time.sleep(_LOCK_POLL_SECONDS)
        except OSError as exc:
            raise SinkError(f"cannot lock {path}: {exc}") from exc
    try:
        yield
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _write_line(handle: BinaryIO, path: Path, line: str) -> None:
    """Write one whole line and flush it to durable storage (log spec 3)."""
    try:
        handle.write(line.encode("utf-8"))
        handle.flush()
        os.fsync(handle.fileno())
    except OSError as exc:
        raise SinkError(f"cannot append to {path}: {exc}") from exc


#: How much of the tail to read at a time when looking for the last line.
_TAIL_CHUNK_BYTES = 8 * 1024


def _last_entry(path: Path) -> Optional[dict[str, Any]]:
    """The last non-empty line of *path* as a parsed entry, or ``None``."""
    try:
        handle = open(path, "rb")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SinkError(f"cannot read {path}: {exc}") from exc
    with handle:
        return _last_entry_of(handle, path)


def _last_entry_of(handle: BinaryIO, path: Path) -> Optional[dict[str, Any]]:
    """The last non-empty line of the open *handle* as a parsed entry."""
    last = _last_line_of(handle)
    if last is None:
        return None
    try:
        entry = json.loads(last)
    except ValueError as exc:
        raise SinkError(f"last line of {path} is not a log entry: {exc}") from exc
    problem = _log_entry_problem(entry)
    if problem is not None:
        raise SinkError(f"last line of {path} is not a log entry: {problem}")
    if "seq" not in entry or "entry_hash" not in entry:
        raise SinkError(f"last line of {path} is not a log entry")
    seq, entry_hash = entry["seq"], entry["entry_hash"]
    # Coercing here would seed the chain from a malformed tail: `int("x")`
    # raises the wrong exception type, and `str(5)` would quietly make "5" the
    # next entry's prev_hash, breaking the chain for every later verifier.
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise SinkError(f"last line of {path} has a non-integer seq {seq!r}")
    if not isinstance(entry_hash, str):
        raise SinkError(
            f"last line of {path} has a non-string entry_hash {entry_hash!r}"
        )
    return entry


def _last_line_of(handle: BinaryIO) -> Optional[str]:
    """The last non-empty line, read by seeking back from the end.

    Every append reads the head this way, so the cost has to be the size of one
    entry rather than the size of the log.
    """
    end = handle.seek(0, os.SEEK_END)
    tail = b""
    while end > 0:
        start = max(0, end - _TAIL_CHUNK_BYTES)
        handle.seek(start)
        tail = handle.read(end - start) + tail
        end = start
        line = _last_line_in(tail, at_start=end == 0)
        if line is not None:
            return line
    return None


def _last_line_in(buffer: bytes, *, at_start: bool) -> Optional[str]:
    """The last non-empty line inside *buffer*, or ``None`` when it may still
    begin earlier in the file.

    *at_start* says *buffer* reaches the file's first byte, so a line with no
    newline before it is already complete.
    """
    trimmed = buffer.rstrip()
    if not trimmed:
        return None
    newline = trimmed.rfind(b"\n")
    if newline < 0 and not at_start:
        return None
    return trimmed[newline + 1 :].decode("utf-8")


# --------------------------------------------------------------------------- #
# Verification (log spec section 8)
# --------------------------------------------------------------------------- #


@dataclass
class LogVerifyOptions:
    """What a verifier trusts and demands."""

    #: Every entry must carry a signature that verifies.
    require_signatures: bool = False
    #: Keys to verify entry signatures against. When absent, signed entries are
    #: counted but not verified (an error under ``require_signatures``).
    keyring: Any = None
    #: Verifier clock and rollback inputs
    #: (:class:`~hushspec.resolve.VerifyOptions`).
    verify: Any = None


@dataclass
class LogVerifyReport:
    """Summary of a verified log."""

    files: int = 0
    entries: int = 0
    receipts: int = 0
    policy_events: int = 0
    signed: int = 0
    verified_signatures: int = 0
    last_seq: int = 0
    last_entry_hash: str = GENESIS_HASH


class LogError(ValueError):
    """Why a log did not verify. :attr:`file` and :attr:`line` locate the first
    break; ``line`` is 0 for a whole-file problem."""

    def __init__(self, file: str, line: int, message: str) -> None:
        super().__init__(f"{file}:{line}: {message}")
        self.file = file
        self.line = line
        self.message = message


def verify_log(
    name: str, text: str, options: Optional[LogVerifyOptions] = None
) -> LogVerifyReport:
    """Verify one log file's text, raising :class:`LogError` at the first break."""
    return verify_logs([(name, text)], options)


def verify_logs(
    files: Sequence[tuple[str, str]], options: Optional[LogVerifyOptions] = None
) -> LogVerifyReport:
    """Verify a sequence of rotated log files in order.

    Each file after the first must start with a ``log_started`` entry whose
    ``previous_entry_hash`` is the previous file's last hash. Raises
    :class:`LogError` naming the first line that breaks the chain.
    """
    options = options or LogVerifyOptions()
    report = LogVerifyReport()
    carried_hash: Optional[str] = None

    for index, (name, text) in enumerate(files):
        report.files += 1
        expected_seq = 1
        prev_hash = carried_hash or GENESIS_HASH
        any_entry = False

        for line_index, line in enumerate(text.split("\n")):
            line_no = line_index + 1
            if not line.strip():
                continue

            def fail(message: str) -> LogError:
                return LogError(name, line_no, message)

            try:
                entry = json.loads(line)
            except ValueError as exc:
                raise fail(f"not a log entry: {exc}") from exc
            if not isinstance(entry, dict):
                raise fail("not a log entry: expected a JSON object")
            unknown = _unknown_key(entry, _ENTRY_KEYS)
            if unknown is not None:
                raise fail(f"unknown field {unknown!r} in log entry")
            if entry.get("log_version") != LOG_VERSION:
                raise fail(
                    f"unsupported log_version {entry.get('log_version')!r}, "
                    f"expected {LOG_VERSION!r}"
                )
            # An entry's hash covers whatever JSON the line held, so a
            # hash-consistent line can still carry a member of the wrong shape.
            # Check the shapes before reading into them: a malformed log is a
            # verification failure, never an exception out of the verifier.
            for member in ("receipt", "policy_event", "log_started", "signature"):
                value = entry.get(member)
                if value is not None and not isinstance(value, dict):
                    raise fail(f"{member} is not a JSON object")
            nested = (
                _unknown_policy_event_key(entry.get("policy_event"))
                or _unknown_key(entry.get("log_started"), _LOG_STARTED_KEYS)
                or _unknown_key(entry.get("signature"), _ENTRY_SIGNATURE_KEYS)
            )
            if nested is not None:
                raise fail(f"unknown field {nested!r} in log entry")
            seq = entry.get("seq")
            if not isinstance(seq, int) or isinstance(seq, bool):
                raise fail(f"seq {seq!r} is not an integer")
            if seq != expected_seq:
                raise fail(
                    f"sequence gap: expected seq {expected_seq}, found {seq}"
                )
            if not _payload_matches_type(entry):
                raise fail(
                    f"payload does not match entry_type {entry.get('entry_type')!r}"
                )
            # A payload the entry carries has to be the payload the log-entry
            # schema describes, not merely a JSON object with no unknown
            # members: the entry hash covers whatever the line held, so a
            # hash-consistent line can still carry a policy event missing the
            # SDK that wrote it.
            malformed = _payload_problem(entry)
            if malformed is not None:
                raise fail(f"not a log entry: {malformed}")
            started = entry.get("log_started")
            if expected_seq == 1 and index > 0:
                if started is None:
                    raise fail("a continued file must start with a log_started entry")
                if started.get("previous_entry_hash") != carried_hash:
                    raise fail(
                        "log_started.previous_entry_hash does not match the previous "
                        "file's last hash"
                    )
            if (
                expected_seq == 1
                and index == 0
                and started is not None
                and started.get("previous_entry_hash") is not None
            ):
                # The first file of a set may itself continue an earlier file
                # the verifier was not given; its prev_hash must then be that
                # file's last hash. It cannot vouch for what came before.
                prev_hash = started["previous_entry_hash"]
            if entry.get("prev_hash") != prev_hash:
                raise fail(
                    f"prev_hash {entry.get('prev_hash')} does not link to the previous "
                    f"entry {prev_hash}"
                )
            recomputed = compute_entry_hash(entry)
            if recomputed != entry.get("entry_hash"):
                raise fail(
                    f"entry_hash {entry.get('entry_hash')} does not match the entry's "
                    f"canonical form ({recomputed})"
                )
            receipt = entry.get("receipt")
            if receipt is not None:
                if receipt.get("receipt_version") != RECEIPT_VERSION:
                    raise fail(
                        f"receipt_version {receipt.get('receipt_version')!r} is not "
                        f"{RECEIPT_VERSION!r}"
                    )
                # The entry hash covers whatever JSON the line held, so a
                # hash-consistent line can still carry something that is not a
                # receipt. Log spec section 8, step 8 requires the payload to
                # validate.
                try:
                    parse_receipt(receipt)
                except ReceiptError as exc:
                    raise fail(
                        f"receipt does not validate against the 0.2 receipt "
                        f"schema: {exc}"
                    ) from exc
                report.receipts += 1
            if entry.get("policy_event") is not None:
                report.policy_events += 1

            signature = entry.get("signature")
            if signature is None:
                if options.require_signatures:
                    raise fail(f"{REASON_UNSIGNED}: signatures are required")
            else:
                report.signed += 1
                if signature.get("content_hash") != entry.get("entry_hash"):
                    raise fail(
                        "signature.content_hash does not name this entry's entry_hash"
                    )
                if options.keyring is not None:
                    result = _verify_entry_signature(
                        signature, entry["entry_hash"], options
                    )
                    if not result.valid:
                        raise fail(f"signature: {result.reason} ({result.detail})")
                    report.verified_signatures += 1
                elif options.require_signatures:
                    raise fail("no_keyring: cannot verify a required signature")

            prev_hash = entry["entry_hash"]
            expected_seq += 1
            any_entry = True
            report.entries += 1
            report.last_seq = entry["seq"]
            report.last_entry_hash = entry["entry_hash"]

        if not any_entry and index > 0:
            raise LogError(name, 0, "continued file is empty")
        carried_hash = prev_hash

    return report


def verify_log_files(
    paths: Iterable[Union[str, Path]], options: Optional[LogVerifyOptions] = None
) -> LogVerifyReport:
    """Verify the log files at *paths*, in order.

    Raises :class:`LogError` with ``line: 0`` for a file that cannot be read,
    otherwise as :func:`verify_logs`.
    """
    texts: list[tuple[str, str]] = []
    for path in paths:
        path = Path(path)
        try:
            texts.append((str(path), path.read_text(encoding="utf-8")))
        except OSError as exc:
            raise LogError(str(path), 0, f"cannot read: {exc}") from exc
    return verify_logs(texts, options)


def _verify_entry_signature(
    signature: dict[str, Any], entry_hash: str, options: LogVerifyOptions
) -> Any:
    from hushspec.signing import verify_content_hash

    verify = options.verify
    kwargs: dict[str, Any] = {}
    if verify is not None:
        if getattr(verify, "now", None) is not None:
            kwargs["now"] = verify.now
        if getattr(verify, "max_clock_skew_seconds", None) is not None:
            kwargs["max_clock_skew_seconds"] = verify.max_clock_skew_seconds
        if getattr(verify, "last_seen_version", None) is not None:
            kwargs["last_seen_version"] = verify.last_seen_version
    return verify_content_hash(
        signature, entry_hash, keyring=options.keyring, **kwargs
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _value(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


def _plain(value: Any) -> Any:
    """Dataclasses and enums to JSON-ready values, dropping ``None`` members."""
    from dataclasses import fields as dataclass_fields
    from dataclasses import is_dataclass

    if isinstance(value, Enum):
        return value.value
    if isinstance(value, PolicySummary):
        # One spelling per fact: a policy event's `policy` member is byte for
        # byte the object a receipt carries.
        return policy_summary_to_dict(value)
    if is_dataclass(value) and not isinstance(value, type):
        return {
            f.name: _plain(getattr(value, f.name))
            for f in dataclass_fields(value)
            if getattr(value, f.name) is not None
        }
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items() if item is not None}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value
