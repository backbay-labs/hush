"""Decision receipts, format 0.2 (``spec/hushspec-receipt.md``).

A receipt is the unit of evidence: which resolved policy was in force (by
canonical content hash), who acted, what was attempted (never the content
itself), what the policy decided and why, which rule blocks and detectors
actually ran, and what the enforcement point did with the decision.

Receipts are built from a :class:`~hushspec.resolve.Resolution` so that the
policy identity, ``extends_chain``, and signature status come from the load
step and cost nothing per evaluation. The rule trace is the evaluator's own
recording (:func:`~hushspec.evaluate.evaluate_traced`); nothing here is
reconstructed from the decision afterwards.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Union

from hushspec.canonical import canonical_json_value, content_hash, digest

# Re-exported: a receipt timestamp and an envelope timestamp are the same
# format (receipt spec section 4.1, signing spec section 4), so there is one
# renderer for both.
from hushspec.signing import format_timestamp
from hushspec.conditions import Condition, RuntimeContext
from hushspec.detection import DetectorEvaluation, DetectorLevel
from hushspec.evaluate import (
    UNKNOWN_ACTION_TYPE_RULE,
    Decision,
    EvaluationAction,
    PostureResult,
)

# Re-exported: the rule trace is produced by the evaluator itself, so its
# types live there.
from hushspec.evaluate import RuleEvaluation, RuleOutcome  # noqa: F401
from hushspec.resolve import ChainLink, Resolution, SignatureStatus
from hushspec.schema import HushSpec

__all__ = [
    "RECEIPT_VERSION",
    "UNKNOWN_ACTION_TYPE_BLOCK",
    "ORIGIN_PROFILE_BLOCK",
    "POLICY_UNVERIFIED_RULE",
    "TimeSource",
    "Actor",
    "ReceiptChainLink",
    "PolicySummary",
    "ActionSummary",
    "RuleTraceEntry",
    "EnforcementMode",
    "EnforcementOutcome",
    "EnforcementSummary",
    "DecisionReceipt",
    "DetectorEvaluation",
    "DetectorLevel",
    "AuditConfig",
    "AuditContext",
    "compact_object",
    "canonical_json",
    "receipt_hash",
    "receipt_to_dict",
    "policy_summary_to_dict",
    "parse_receipt",
    "format_timestamp",
    "deterministic_uuid_v7",
    "evaluate_audited",
    "evaluate_audited_spec",
    "policy_summary",
    "unverified_policy_receipt",
    "compute_policy_hash",
    "RuleEvaluation",
    "RuleOutcome",
]

#: The receipt format this module writes and accepts.
RECEIPT_VERSION = "0.2"

#: The ``rule_block`` id a receipt uses for the unknown-action-type stage.
UNKNOWN_ACTION_TYPE_BLOCK = "unknown_action_type"
#: The ``rule_block`` id a receipt uses for the origins engine stage.
ORIGIN_PROFILE_BLOCK = "origin_profile"

#: ``matched_rule`` of a receipt for an action refused because the policy did
#: not verify (receipt spec 4.5).
POLICY_UNVERIFIED_RULE = "__hushspec_policy_unverified__"

# --------------------------------------------------------------------------- #
# Wire types
# --------------------------------------------------------------------------- #


class TimeSource(str, Enum):
    """How much to trust ``timestamp`` (receipt spec 3.3)."""

    SYSTEM = "system"
    MONOTONIC_ADJUSTED = "monotonic_adjusted"
    TRUSTED = "trusted"
    UNKNOWN = "unknown"


@dataclass
class Actor:
    """Who the action was evaluated for (receipt spec 4.1)."""

    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    principal: Optional[str] = None
    runtime: Optional[str] = None

    def is_empty(self) -> bool:
        """True when no field is set (such an actor is omitted from receipts)."""
        return not any(
            (self.agent_id, self.session_id, self.principal, self.runtime)
        )


@dataclass
class ReceiptChainLink:
    """One link of ``policy.extends_chain`` (receipt spec 4.2)."""

    source: str
    content_hash: str

    @classmethod
    def from_chain_link(cls, link: ChainLink) -> "ReceiptChainLink":
        return cls(source=link.source, content_hash=link.content_hash)


@dataclass
class PolicySummary:
    """Identity of the resolved policy (receipt spec 4.2)."""

    #: The policy's ``hushspec`` field.
    spec_version: str
    #: Canonical content hash of the resolved policy (``sha256:`` + hex).
    content_hash: str
    name: Optional[str] = None
    #: ``metadata.policy_version``, when present. An integer, never a string.
    version: Optional[int] = None
    extends_chain: Optional[list[ReceiptChainLink]] = None
    signature: Optional[SignatureStatus] = None


@dataclass
class ActionSummary:
    """The evaluated action, minus its content (receipt spec 4.4)."""

    type: str
    target: Optional[str] = None
    #: ``sha256:`` over the UTF-8 bytes of the content, when content was given.
    content_hash: Optional[str] = None
    content_size: Optional[int] = None
    args_size: Optional[int] = None
    #: The origin descriptor as supplied, compacted (see :func:`compact_object`).
    origin: Optional[dict[str, Any]] = None
    #: The runtime context as supplied, compacted.
    context: Optional[dict[str, Any]] = None


@dataclass
class RuleTraceEntry:
    """One rule block's or engine stage's contribution (receipt spec 4.3)."""

    rule_block: str
    outcome: RuleOutcome
    evaluated: bool
    rule_path: Optional[str] = None
    reason: Optional[str] = None

    @classmethod
    def from_rule_evaluation(cls, entry: RuleEvaluation) -> "RuleTraceEntry":
        """Map the evaluator's recorded entry to the receipt spelling.

        The evaluator records the unknown-action stage under ``default`` with
        the reserved ``__unknown_action_type__`` rule, and the origins guard
        under ``origins``; receipts use the closed ids ``unknown_action_type``
        and ``origin_profile`` for those stages (receipt spec 4.3, item 5).
        """
        block = entry.rule_block
        if block == "default" and entry.matched_rule == UNKNOWN_ACTION_TYPE_RULE:
            block = UNKNOWN_ACTION_TYPE_BLOCK
        elif block == "origins":
            block = ORIGIN_PROFILE_BLOCK
        return cls(
            rule_block=block,
            outcome=entry.outcome,
            evaluated=entry.evaluated,
            rule_path=entry.matched_rule,
            reason=entry.reason,
        )


class EnforcementMode(str, Enum):
    ENFORCE = "enforce"
    MONITOR = "monitor"


class EnforcementOutcome(str, Enum):
    ALLOWED = "allowed"
    CONFIRMED = "confirmed"
    BLOCKED = "blocked"
    WOULD_BLOCK = "would_block"


@dataclass
class EnforcementSummary:
    """What the enforcement point did with the decision (receipt spec 4.7).

    :attr:`DecisionReceipt.decision` is always the evaluated policy decision;
    this records how the runtime applied it. Required in 0.2.
    """

    mode: str = EnforcementMode.ENFORCE.value      # 'enforce' | 'monitor'
    outcome: str = EnforcementOutcome.ALLOWED.value

    @classmethod
    def implied(
        cls, decision: Decision, mode: str = EnforcementMode.ENFORCE.value
    ) -> "EnforcementSummary":
        """The disposition implied by a decision with no enforcement point.

        An allow proceeds; a warn with no confirmation channel is a deny
        (core spec 6); under monitor mode a warn or deny proceeds and is
        recorded as ``would_block``.
        """
        mode_value = mode.value if isinstance(mode, Enum) else str(mode)
        if decision == Decision.ALLOW:
            outcome = EnforcementOutcome.ALLOWED.value
        elif mode_value == EnforcementMode.MONITOR.value:
            outcome = EnforcementOutcome.WOULD_BLOCK.value
        else:
            outcome = EnforcementOutcome.BLOCKED.value
        return cls(mode=mode_value, outcome=outcome)


@dataclass
class DecisionReceipt:
    """A decision receipt, format 0.2.

    Field order is fixed across the SDKs so the JSON Lines a sink writes read
    the same everywhere; the *hash* is order-independent (RFC 8785 sorts keys).
    """

    receipt_id: str
    #: RFC 3339 UTC, exactly millisecond precision, ``Z`` suffix.
    timestamp: str
    policy: PolicySummary
    action: ActionSummary
    decision: Decision
    rule_trace: list[RuleTraceEntry]
    enforcement: EnforcementSummary
    receipt_version: str = RECEIPT_VERSION
    time_source: str = TimeSource.SYSTEM.value
    actor: Optional[Actor] = None
    matched_rule: Optional[str] = None
    reason: Optional[str] = None
    #: Present when the detection pipeline ran, even if empty.
    detection_trace: Optional[list[DetectorEvaluation]] = None
    origin_profile: Optional[str] = None
    posture: Optional[PostureResult] = None
    duration_us: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        """The receipt as the JSON object a sink writes."""
        return receipt_to_dict(self)

    def canonical_json(self) -> str:
        """The receipt's canonical form: RFC 8785, no projection (spec 6)."""
        return canonical_json(self)

    def receipt_hash(self) -> str:
        """``sha256:`` over the canonical form (spec 6)."""
        return receipt_hash(self)


# The declaration order above is constructor order (required fields first);
# the *wire* order is the receipt spec's documentation order.
_RECEIPT_FIELD_ORDER = (
    "receipt_version",
    "receipt_id",
    "timestamp",
    "time_source",
    "actor",
    "policy",
    "action",
    "decision",
    "matched_rule",
    "reason",
    "rule_trace",
    "detection_trace",
    "enforcement",
    "origin_profile",
    "posture",
    "duration_us",
)

_POLICY_FIELD_ORDER = (
    "name",
    "version",
    "spec_version",
    "content_hash",
    "extends_chain",
    "signature",
)

_SIGNATURE_FIELD_ORDER = ("verified", "key_id", "verified_at", "reason")

_ACTION_FIELD_ORDER = (
    "type",
    "target",
    "content_hash",
    "content_size",
    "args_size",
    "origin",
    "context",
)

_TRACE_FIELD_ORDER = ("rule_block", "rule_path", "outcome", "evaluated", "reason")

_DETECTOR_FIELD_ORDER = ("detector_id", "category", "score", "level", "matched")


class ReceiptError(ValueError):
    """A receipt could not be read."""


# --------------------------------------------------------------------------- #
# Serialization
# --------------------------------------------------------------------------- #


def _plain(value: Any) -> Any:
    """Convert enums and dataclasses to JSON-ready values, dropping ``None``."""
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {
            f.name: _plain(getattr(value, f.name))
            for f in fields(value)
            if getattr(value, f.name) is not None
        }
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items() if item is not None}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _ordered(data: dict[str, Any], order: tuple[str, ...]) -> dict[str, Any]:
    out = {key: data[key] for key in order if key in data}
    # Anything not named by `order` (never, for the types here) keeps its place
    # at the end rather than being silently dropped.
    out.update({key: value for key, value in data.items() if key not in out})
    return out


def _policy_dict(data: dict[str, Any]) -> dict[str, Any]:
    policy = _ordered(data, _POLICY_FIELD_ORDER)
    if isinstance(policy.get("signature"), dict):
        signature = dict(policy["signature"])
        signature.setdefault("verified", False)
        policy["signature"] = _ordered(signature, _SIGNATURE_FIELD_ORDER)
    return policy


def policy_summary_to_dict(policy: PolicySummary) -> dict[str, Any]:
    """The JSON object a receipt's ``policy`` member and a log's
    ``policy_event.policy`` member both carry -- one spelling per fact."""
    return _policy_dict(_plain(policy))


def receipt_to_dict(receipt: DecisionReceipt) -> dict[str, Any]:
    """Convert a receipt to the JSON object sinks, logs, and hashing use.

    Absent optional fields are omitted rather than serialized as ``null``
    (receipt spec: "no nulls anywhere; absent means absent"), enums become
    their string values, and members appear in the spec's documentation order.
    Key order is presentational only -- the receipt hash canonicalizes first.
    """
    data = _plain(receipt)
    if "policy" in data:
        data["policy"] = _policy_dict(data["policy"])
    if "action" in data:
        data["action"] = _ordered(data["action"], _ACTION_FIELD_ORDER)
    if "rule_trace" in data:
        data["rule_trace"] = [
            _ordered(entry, _TRACE_FIELD_ORDER) for entry in data["rule_trace"]
        ]
    if "detection_trace" in data:
        data["detection_trace"] = [
            _ordered(entry, _DETECTOR_FIELD_ORDER) for entry in data["detection_trace"]
        ]
    return _ordered(data, _RECEIPT_FIELD_ORDER)


def canonical_json(receipt: Union[DecisionReceipt, dict[str, Any]]) -> str:
    """The RFC 8785 canonical form of a receipt (receipt spec section 6).

    No projection step applies: receipts have no schema defaults to materialize
    and no resolution fields to strip, and every optional field is either
    present or absent.
    """
    value = receipt if isinstance(receipt, dict) else receipt_to_dict(receipt)
    return canonical_json_value(value)


def receipt_hash(receipt: Union[DecisionReceipt, dict[str, Any]]) -> str:
    """``sha256:`` over the canonical form: the value a log links and a
    receipt signature covers (receipt spec section 6)."""
    return digest(canonical_json(receipt))


def parse_receipt(data: Union[str, bytes, dict[str, Any]]) -> DecisionReceipt:
    """Parse a receipt object, rejecting anything that is not a 0.2 receipt.

    Unknown members are rejected the way every other HushSpec parser rejects
    them: a receipt with a field this format does not define is not a 0.2
    receipt (receipt spec section 3). Required members, member types and the
    closed enums are checked too, so a consumer -- a log verifier above all --
    never counts an arbitrary JSON object as evidence.
    """
    import json

    if isinstance(data, (str, bytes)):
        try:
            data = json.loads(data)
        except ValueError as exc:
            raise ReceiptError(f"receipt is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ReceiptError("receipt must be a JSON object")
    version = data.get("receipt_version")
    if version != RECEIPT_VERSION:
        raise ReceiptError(
            f"unsupported receipt_version {version!r}, expected {RECEIPT_VERSION!r}"
        )
    _validate_receipt_shape(data)
    return _receipt_from_dict(data)


# --------------------------------------------------------------------------- #
# Structural validation (receipt spec section 2, item 4)
# --------------------------------------------------------------------------- #

#: ``$.timestamp``: RFC 3339 UTC with exactly three fractional digits.
_TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
)

_ACTOR_KEYS = ("agent_id", "session_id", "principal", "runtime")
_POLICY_KEYS = (
    "name",
    "version",
    "spec_version",
    "content_hash",
    "extends_chain",
    "signature",
)
_CHAIN_LINK_KEYS = ("source", "content_hash")
_SIGNATURE_STATUS_KEYS = ("verified", "key_id", "verified_at", "reason")
_ACTION_KEYS = (
    "type",
    "target",
    "content_hash",
    "content_size",
    "args_size",
    "origin",
    "context",
)
_RULE_TRACE_KEYS = ("rule_block", "rule_path", "outcome", "evaluated", "reason")
_DETECTION_TRACE_KEYS = ("detector_id", "category", "score", "level", "matched")
_ENFORCEMENT_KEYS = ("mode", "outcome")
_POSTURE_KEYS = ("current", "next")

_TIME_SOURCES = ("system", "monotonic_adjusted", "trusted", "unknown")
_DECISIONS = ("allow", "warn", "deny")
_RULE_OUTCOMES = ("allow", "warn", "deny", "skip")
_ENFORCEMENT_MODES = ("enforce", "monitor")
_ENFORCEMENT_OUTCOMES = ("allowed", "confirmed", "blocked", "would_block")
_DETECTION_CATEGORIES = (
    "prompt_injection",
    "jailbreak",
    "data_exfiltration",
    "threat_intel",
)
_DETECTOR_LEVELS = ("none", "low", "suspicious", "high", "critical")


def _require_object(value: Any, label: str, allowed: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReceiptError(f"{label} must be a JSON object")
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise ReceiptError(f"unknown field {unknown[0]!r} in {label}")
    return value


def _require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReceiptError(f"{label} must be an array")
    return value


def _require_members(obj: dict[str, Any], label: str, keys: tuple[str, ...]) -> None:
    for key in keys:
        if obj.get(key) is None:
            raise ReceiptError(f"{label} is missing {key!r}")


def _require_str(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ReceiptError(f"{label} must be a string")
    return value


def _optional_str(value: Any, label: str) -> None:
    if value is not None:
        _require_str(value, label)


def _require_bool(value: Any, label: str) -> None:
    if not isinstance(value, bool):
        raise ReceiptError(f"{label} must be a boolean")


def _optional_size(value: Any, label: str) -> None:
    if value is None:
        return
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ReceiptError(f"{label} must be a non-negative integer")


def _require_enum(value: Any, label: str, allowed: tuple[str, ...]) -> None:
    text = _require_str(value, label)
    if text not in allowed:
        raise ReceiptError(f"{label} {text!r} is outside the closed enum")


def _require_timestamp(value: Any, label: str) -> None:
    text = _require_str(value, label)
    if _TIMESTAMP_PATTERN.match(text):
        try:
            datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ")
            return
        except ValueError:
            pass
    raise ReceiptError(
        f"{label} {text!r} is not an RFC 3339 UTC instant with millisecond precision"
    )


def _validate_receipt_shape(receipt: dict[str, Any]) -> None:
    _require_members(
        receipt,
        "receipt",
        (
            "receipt_id",
            "timestamp",
            "time_source",
            "policy",
            "action",
            "decision",
            "rule_trace",
            "enforcement",
        ),
    )
    _require_str(receipt["receipt_id"], "receipt_id")
    _require_timestamp(receipt["timestamp"], "timestamp")
    _require_enum(receipt["time_source"], "time_source", _TIME_SOURCES)
    _require_enum(receipt["decision"], "decision", _DECISIONS)
    _optional_str(receipt.get("matched_rule"), "matched_rule")
    _optional_str(receipt.get("reason"), "reason")
    _optional_str(receipt.get("origin_profile"), "origin_profile")
    _optional_size(receipt.get("duration_us"), "duration_us")

    if receipt.get("actor") is not None:
        actor = _require_object(receipt["actor"], "actor", _ACTOR_KEYS)
        for key in _ACTOR_KEYS:
            _optional_str(actor.get(key), f"actor.{key}")

    _validate_policy(_require_object(receipt["policy"], "policy", _POLICY_KEYS))
    _validate_action(_require_object(receipt["action"], "action", _ACTION_KEYS))
    _validate_rule_trace(_require_list(receipt["rule_trace"], "rule_trace"))
    if receipt.get("detection_trace") is not None:
        _validate_detection_trace(
            _require_list(receipt["detection_trace"], "detection_trace")
        )

    enforcement = _require_object(
        receipt["enforcement"], "enforcement", _ENFORCEMENT_KEYS
    )
    _require_members(enforcement, "enforcement", _ENFORCEMENT_KEYS)
    _require_enum(enforcement["mode"], "enforcement.mode", _ENFORCEMENT_MODES)
    _require_enum(
        enforcement["outcome"], "enforcement.outcome", _ENFORCEMENT_OUTCOMES
    )

    if receipt.get("posture") is not None:
        posture = _require_object(receipt["posture"], "posture", _POSTURE_KEYS)
        _require_members(posture, "posture", _POSTURE_KEYS)
        _require_str(posture["current"], "posture.current")
        _require_str(posture["next"], "posture.next")


def _validate_policy(policy: dict[str, Any]) -> None:
    _require_members(policy, "policy", ("spec_version", "content_hash"))
    _require_str(policy["spec_version"], "policy.spec_version")
    _require_str(policy["content_hash"], "policy.content_hash")
    _optional_str(policy.get("name"), "policy.name")
    _optional_size(policy.get("version"), "policy.version")

    if policy.get("extends_chain") is not None:
        chain = _require_list(policy["extends_chain"], "policy.extends_chain")
        for index, raw in enumerate(chain):
            label = f"policy.extends_chain[{index}]"
            link = _require_object(raw, label, _CHAIN_LINK_KEYS)
            _require_members(link, label, _CHAIN_LINK_KEYS)
            _require_str(link["source"], f"{label}.source")
            _require_str(link["content_hash"], f"{label}.content_hash")

    if policy.get("signature") is not None:
        status = _require_object(
            policy["signature"], "policy.signature", _SIGNATURE_STATUS_KEYS
        )
        if "verified" not in status:
            raise ReceiptError("policy.signature is missing 'verified'")
        _require_bool(status["verified"], "policy.signature.verified")
        _optional_str(status.get("key_id"), "policy.signature.key_id")
        _optional_str(status.get("reason"), "policy.signature.reason")
        if status.get("verified_at") is not None:
            _require_timestamp(status["verified_at"], "policy.signature.verified_at")


def _validate_action(action: dict[str, Any]) -> None:
    _require_members(action, "action", ("type",))
    _require_str(action["type"], "action.type")
    _optional_str(action.get("target"), "action.target")
    _optional_str(action.get("content_hash"), "action.content_hash")
    _optional_size(action.get("content_size"), "action.content_size")
    _optional_size(action.get("args_size"), "action.args_size")
    # `origin` and `context` are the descriptors the caller supplied, carried
    # verbatim (receipt spec section 4.4); any JSON value is in range.


def _validate_rule_trace(entries: list[Any]) -> None:
    for index, raw in enumerate(entries):
        label = f"rule_trace[{index}]"
        entry = _require_object(raw, label, _RULE_TRACE_KEYS)
        if "evaluated" not in entry:
            raise ReceiptError(f"{label} is missing 'evaluated'")
        _require_members(entry, label, ("rule_block", "outcome"))
        _require_str(entry["rule_block"], f"{label}.rule_block")
        _optional_str(entry.get("rule_path"), f"{label}.rule_path")
        _require_enum(entry["outcome"], f"{label}.outcome", _RULE_OUTCOMES)
        _require_bool(entry["evaluated"], f"{label}.evaluated")
        _optional_str(entry.get("reason"), f"{label}.reason")


def _validate_detection_trace(entries: list[Any]) -> None:
    for index, raw in enumerate(entries):
        label = f"detection_trace[{index}]"
        entry = _require_object(raw, label, _DETECTION_TRACE_KEYS)
        if "matched" not in entry:
            raise ReceiptError(f"{label} is missing 'matched'")
        _require_members(entry, label, ("detector_id", "category", "score", "level"))
        _require_str(entry["detector_id"], f"{label}.detector_id")
        _require_enum(entry["category"], f"{label}.category", _DETECTION_CATEGORIES)
        score = entry["score"]
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise ReceiptError(f"{label}.score must be a number in [0, 1]")
        if not 0 <= score <= 1:
            raise ReceiptError(f"{label}.score must be a number in [0, 1]")
        _require_enum(entry["level"], f"{label}.level", _DETECTOR_LEVELS)
        _require_bool(entry["matched"], f"{label}.matched")


def _typed(
    raw: Any, cls: Any, *, label: str, rename: Optional[dict[str, str]] = None
) -> Any:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ReceiptError(f"{label} must be an object")
    rename = rename or {}
    names = {f.name for f in fields(cls)}
    kwargs: dict[str, Any] = {}
    for key, value in raw.items():
        target = rename.get(key, key)
        if target not in names:
            raise ReceiptError(f"unknown field {key!r} in {label}")
        kwargs[target] = value
    try:
        return cls(**kwargs)
    except TypeError as exc:
        raise ReceiptError(f"{label}: {exc}") from exc


def _receipt_from_dict(data: dict[str, Any]) -> DecisionReceipt:
    known = {f.name for f in fields(DecisionReceipt)}
    unknown = sorted(set(data) - known)
    if unknown:
        raise ReceiptError(f"unknown field {unknown[0]!r} in receipt")
    policy = _typed(data.get("policy"), PolicySummary, label="policy")
    if policy is None:
        raise ReceiptError("receipt is missing 'policy'")
    if isinstance(policy.signature, dict):
        policy.signature = _typed(
            policy.signature, SignatureStatus, label="policy.signature"
        )
    if policy.extends_chain is not None:
        policy.extends_chain = [
            _typed(link, ReceiptChainLink, label="policy.extends_chain")
            for link in policy.extends_chain
        ]
    action = _typed(data.get("action"), ActionSummary, label="action")
    if action is None:
        raise ReceiptError("receipt is missing 'action'")
    enforcement = _typed(
        data.get("enforcement"), EnforcementSummary, label="enforcement"
    )
    if enforcement is None:
        raise ReceiptError("receipt is missing 'enforcement'")
    trace = [
        _typed(entry, RuleTraceEntry, label="rule_trace")
        for entry in data.get("rule_trace", [])
    ]
    for entry in trace:
        try:
            entry.outcome = RuleOutcome(entry.outcome)
        except ValueError as exc:
            raise ReceiptError(f"rule_trace.outcome: {exc}") from exc
    detection = data.get("detection_trace")
    if detection is not None:
        detection = [
            _typed(entry, DetectorEvaluation, label="detection_trace")
            for entry in detection
        ]
    posture = _typed(data.get("posture"), PostureResult, label="posture")
    for required in ("receipt_id", "timestamp", "time_source", "decision"):
        if required not in data:
            raise ReceiptError(f"receipt is missing {required!r}")
    try:
        decision = Decision(data["decision"])
    except ValueError as exc:
        raise ReceiptError(f"receipt.decision: {exc}") from exc
    return DecisionReceipt(
        receipt_version=data["receipt_version"],
        receipt_id=data["receipt_id"],
        timestamp=data["timestamp"],
        time_source=data["time_source"],
        actor=_typed(data.get("actor"), Actor, label="actor"),
        policy=policy,
        action=action,
        decision=decision,
        matched_rule=data.get("matched_rule"),
        reason=data.get("reason"),
        rule_trace=trace,
        detection_trace=detection,
        enforcement=enforcement,
        origin_profile=data.get("origin_profile"),
        posture=posture,
        duration_us=data.get("duration_us"),
    )


def compact_object(value: Any) -> dict[str, Any]:
    """Serialize a supplied descriptor "verbatim" (receipt spec 4.4).

    In the one form every typed model can reproduce: its JSON object with
    top-level members that are absent, ``null``, ``{}``, or ``[]`` removed.
    SDKs differ in which empty members they materialize; the document the
    caller supplied did not have them.
    """
    data = _plain(value)
    if not isinstance(data, dict):
        return {}
    return {
        key: member
        for key, member in data.items()
        if member is not None
        and not (isinstance(member, (dict, list, tuple)) and len(member) == 0)
    }


# --------------------------------------------------------------------------- #
# Building receipts
# --------------------------------------------------------------------------- #


@dataclass
class AuditConfig:
    """What to record.

    ``enabled=False`` skips timing and the trace; the decision and the policy
    identity are always correct, because identity comes from the
    :class:`~hushspec.resolve.Resolution` and costs nothing.
    """

    enabled: bool = True
    include_rule_trace: bool = True
    #: Record ``duration_us``. Off for conformance vectors, whose bytes must
    #: not depend on the machine that produced them.
    record_duration: bool = True
    #: Legacy: a 0.2 receipt never carries content, only its hash and size
    #: (receipt spec 4.4), so this no longer affects a receipt. It still gates
    #: whether a guard's observer events embed action content.
    redact_content: bool = True


@dataclass
class AuditContext:
    """Everything about the evaluation that is not the policy or the action:
    who is acting, what the enforcement point does, and the clock.

    ``clock`` and ``receipt_id`` exist so tests and conformance vectors can be
    deterministic; production callers leave them ``None``.
    """

    actor: Optional[Actor] = None
    #: The enforcement point's disposition. ``None`` records the disposition
    #: implied by the decision under :attr:`enforcement_mode`.
    enforcement: Optional[EnforcementSummary] = None
    enforcement_mode: str = EnforcementMode.ENFORCE.value
    time_source: str = TimeSource.SYSTEM.value
    #: Fixed evaluation time (defaults to now).
    clock: Optional[datetime] = None
    #: Fixed receipt id (defaults to a fresh UUID v7).
    receipt_id: Optional[str] = None
    #: Explicit runtime context; replaces ``action.context`` when set.
    context: Optional[RuntimeContext] = None
    #: Out-of-band conditions keyed by rule-block name.
    conditions: dict[str, Condition] = field(default_factory=dict)


def deterministic_uuid_v7(unix_millis: int, seed: int) -> str:
    """A UUID v7 whose random bits come from *seed* instead of an RNG.

    So a conformance vector can name the receipt id it expects: the 48-bit
    timestamp is ``unix_millis``, ``rand_a`` (12 bits) is ``seed & 0xfff``,
    ``rand_b`` (62 bits) is ``seed >> 12``, the version nibble is 7 and the
    variant is ``10``.
    """
    raw = bytearray(16)
    ms = unix_millis & 0x0000_FFFF_FFFF_FFFF
    raw[0:6] = ms.to_bytes(6, "big")
    rand_a = seed & 0x0FFF
    raw[6] = 0x70 | (rand_a >> 8)
    raw[7] = rand_a & 0xFF
    rand_b = (seed >> 12) & 0x3FFF_FFFF_FFFF_FFFF
    tail = rand_b.to_bytes(8, "big")
    raw[8] = 0x80 | (tail[0] & 0x3F)
    raw[9:16] = tail[1:]
    return str(uuid.UUID(bytes=bytes(raw)))


def _as_resolution(policy: Union[Resolution, HushSpec]) -> Resolution:
    """Accept a resolution or, for callers written against 0.1, a resolved spec."""
    if isinstance(policy, Resolution):
        return policy
    return Resolution.from_resolved(policy)


def evaluate_audited(
    resolution: Union[Resolution, HushSpec],
    action: EvaluationAction,
    config: Optional[AuditConfig] = None,
    context: Optional[AuditContext] = None,
) -> DecisionReceipt:
    """Evaluate *action* against a resolved policy and record the receipt.

    Routes through the detection pipeline when the policy has a ``detection:``
    extension, so the receipt's decision is the one an enforcement point acts
    on and ``detection_trace`` is present whenever detection ran.

    *resolution* is a :class:`~hushspec.resolve.Resolution`; a bare resolved
    :class:`~hushspec.schema.HushSpec` is accepted and wrapped (its chain is
    then the single ``memory`` link), which is what 0.1 callers passed.
    """
    from hushspec.compiled import compiled_for_spec

    resolution = _as_resolution(resolution)
    return audited_from_compiled(
        compiled_for_spec(resolution.spec), resolution, action, config, context
    )


def audited_from_compiled(
    compiled: Any,
    resolution: Resolution,
    action: EvaluationAction,
    config: Optional[AuditConfig] = None,
    context: Optional[AuditContext] = None,
) -> DecisionReceipt:
    """:func:`evaluate_audited` against an already-compiled policy.

    *resolution* is the policy identity the receipt records; *compiled* is the
    :class:`~hushspec.compiled.CompiledPolicy` that decides the action. A
    caller holding both (a guard, a long-lived enforcement point) skips the
    compile and the hash on every evaluation.
    """
    config = config or AuditConfig()
    ctx = context or AuditContext()

    keep_trace = config.enabled and config.include_rule_trace
    timed = config.enabled and config.record_duration
    # A trace nobody keeps is not recorded. A timed evaluation records one
    # regardless, so ``duration_us`` always covers the same work.
    record_trace = keep_trace or timed

    start_ns = time.perf_counter_ns() if timed else None
    detected = compiled.run_with_detection(
        action, ctx.context, ctx.conditions, record_trace=record_trace
    )
    duration_us = (
        (time.perf_counter_ns() - start_ns) // 1000 if start_ns is not None else None
    )
    result = detected.evaluation

    rule_trace = (
        _build_trace(detected.traced.trace, result.origin_profile) if keep_trace else []
    )

    now = ctx.clock or datetime.now(timezone.utc)
    receipt_id = ctx.receipt_id or _uuid7_now()
    enforcement = ctx.enforcement or EnforcementSummary.implied(
        result.decision, ctx.enforcement_mode
    )
    actor = ctx.actor if (ctx.actor is not None and not ctx.actor.is_empty()) else None

    return DecisionReceipt(
        receipt_version=RECEIPT_VERSION,
        receipt_id=receipt_id,
        timestamp=format_timestamp(now),
        time_source=_value(ctx.time_source),
        actor=actor,
        policy=policy_summary(resolution),
        action=action_summary(action),
        decision=result.decision,
        matched_rule=result.matched_rule,
        reason=result.reason,
        rule_trace=rule_trace,
        detection_trace=detected.detector_trace,
        enforcement=enforcement,
        origin_profile=result.origin_profile,
        posture=result.posture,
        duration_us=duration_us,
    )


def evaluate_audited_spec(
    spec: HushSpec,
    action: EvaluationAction,
    config: Optional[AuditConfig] = None,
    context: Optional[AuditContext] = None,
) -> DecisionReceipt:
    """:func:`evaluate_audited` for a document that is already resolved and has
    no provenance to record.

    The content hash is computed on every call; hold a
    :class:`~hushspec.resolve.Resolution` instead when evaluating repeatedly.
    Raises :class:`~hushspec.canonical.CanonicalError` when the document still
    declares ``extends`` or otherwise has no canonical form.
    """
    return evaluate_audited(Resolution.from_resolved(spec), action, config, context)


def unverified_policy_receipt(
    policy: PolicySummary,
    action: EvaluationAction,
    context: Optional[AuditContext] = None,
) -> DecisionReceipt:
    """The receipt an enforcement point that requires signatures emits when the
    policy did not verify (signing spec 6.5).

    A deny with an empty trace, ``policy.signature.verified: false``, and the
    reason the verifier gave.
    """
    ctx = context or AuditContext()
    now = ctx.clock or datetime.now(timezone.utc)
    reason = (
        policy.signature.reason
        if policy.signature is not None and policy.signature.reason
        else "unverified"
    )
    enforcement = ctx.enforcement or EnforcementSummary.implied(
        Decision.DENY, ctx.enforcement_mode
    )
    actor = ctx.actor if (ctx.actor is not None and not ctx.actor.is_empty()) else None
    return DecisionReceipt(
        receipt_version=RECEIPT_VERSION,
        receipt_id=ctx.receipt_id or _uuid7_now(),
        timestamp=format_timestamp(now),
        time_source=_value(ctx.time_source),
        actor=actor,
        policy=policy,
        action=action_summary(action),
        decision=Decision.DENY,
        matched_rule=POLICY_UNVERIFIED_RULE,
        reason=f"policy signature did not verify: {reason}",
        rule_trace=[],
        detection_trace=None,
        enforcement=enforcement,
        origin_profile=None,
        posture=None,
        duration_us=None,
    )


def policy_summary(resolution: Union[Resolution, HushSpec]) -> PolicySummary:
    """The policy identity a receipt carries, taken from the resolution."""
    resolution = _as_resolution(resolution)
    spec = resolution.spec
    version = None
    if spec.metadata is not None:
        version = getattr(spec.metadata, "policy_version", None)
    return PolicySummary(
        name=spec.name,
        version=version,
        spec_version=spec.hushspec,
        content_hash=resolution.content_hash,
        extends_chain=(
            [ReceiptChainLink.from_chain_link(link) for link in resolution.chain]
            if resolution.had_extends()
            else None
        ),
        signature=resolution.signature,
    )


def action_summary(action: EvaluationAction) -> ActionSummary:
    """The action as a receipt records it: never the content, only its hash."""
    content = action.content
    return ActionSummary(
        type=action.type,
        target=action.target,
        content_hash=digest(content) if content is not None else None,
        content_size=len(content.encode("utf-8")) if content is not None else None,
        args_size=action.args_size,
        origin=compact_object(action.origin) if action.origin is not None else None,
        context=compact_object(action.context) if action.context is not None else None,
    )


def _build_trace(
    trace: list[RuleEvaluation], origin_profile: Optional[str]
) -> list[RuleTraceEntry]:
    """Convert the evaluator's recorded trace to receipt entries, adding the
    origins stage when a profile was selected (receipt spec 4.3, item 5).

    The selected profile is a recorded fact of the same evaluation (the
    evaluator returns it alongside the decision); it is placed first because
    the origins guard runs before the posture guard and every rule block.
    """
    entries = [RuleTraceEntry.from_rule_evaluation(entry) for entry in trace]
    if origin_profile is not None and not any(
        entry.rule_block == ORIGIN_PROFILE_BLOCK for entry in entries
    ):
        entries.insert(
            0,
            RuleTraceEntry(
                rule_block=ORIGIN_PROFILE_BLOCK,
                rule_path=f"extensions.origins.profiles.{origin_profile}",
                outcome=RuleOutcome.ALLOW,
                evaluated=True,
                reason="origin profile selected",
            ),
        )
    return entries


def _value(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


def _uuid7_now() -> str:
    """A fresh UUIDv7 with 74 random bits of entropy."""
    import secrets

    millis = int(time.time() * 1000)
    return deterministic_uuid_v7(millis, secrets.randbits(74))


def compute_policy_hash(spec: HushSpec) -> str:
    """Canonical content hash of the *resolved* policy -- ``sha256:<64 hex>``.

    Hashing an unresolved leaf would make the receipt's ``content_hash``
    identify a document that is not what was enforced (every block inherited
    from the base is missing from it), so an ``extends`` still present here is
    resolved against the embedded builtins first and, if that is impossible,
    rejected rather than hashed. Guards resolve on load, so this is a backstop
    for direct callers.

    This is the canonical hash of ``spec/hushspec-canonical.md`` section 5 --
    RFC 8785 over the canonical projection, wire form ``sha256:<hex>``,
    identical in every SDK. (Receipt format 0.1 used a bare 64-hex digest over
    each SDK's own JSON serialization; the two are not comparable.)
    """
    if spec.extends is not None:
        from hushspec.resolve import create_builtin_loader, resolve

        ok, resolved = resolve(spec, loader=create_builtin_loader())
        if not ok:
            raise ValueError(
                f"cannot hash an unresolved policy (extends: {spec.extends}): {resolved}"
            )
        assert isinstance(resolved, HushSpec)
        spec = resolved
    return content_hash(spec)
