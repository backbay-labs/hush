from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from hushspec.evaluate import (
    Decision,
    EvaluationAction,
    PostureResult,
    evaluate_traced,
)

# Re-exported: the rule trace is produced by the evaluator itself, so its types
# live there (mirroring the Rust crate's `pub use crate::evaluate::{...}`).
from hushspec.evaluate import RuleEvaluation, RuleOutcome  # noqa: F401
from hushspec.schema import HushSpec
from hushspec.version import HUSHSPEC_VERSION





@dataclass
class ActionSummary:
    type: str
    target: Optional[str] = None
    content_redacted: bool = False


@dataclass
class PolicySummary:
    version: str
    content_hash: str
    name: Optional[str] = None


@dataclass
class AuditConfig:
    enabled: bool = True
    include_rule_trace: bool = True
    redact_content: bool = True


@dataclass
class EnforcementSummary:
    """How the runtime applied a decision.

    DecisionReceipt.decision is always the evaluated policy decision;
    this records what the enforcement point did with it.
    """

    mode: str      # 'enforce' | 'monitor'
    outcome: str   # 'allowed' | 'confirmed' | 'blocked' | 'would_block'


@dataclass
class DecisionReceipt:
    receipt_id: str
    timestamp: str
    hushspec_version: str
    action: ActionSummary
    decision: Decision
    rule_trace: list[RuleEvaluation]
    policy: PolicySummary
    evaluation_duration_us: int
    matched_rule: Optional[str] = None
    reason: Optional[str] = None
    origin_profile: Optional[str] = None
    posture: Optional[PostureResult] = None
    enforcement: Optional[EnforcementSummary] = None





def evaluate_audited(
    spec: HushSpec,
    action: EvaluationAction,
    config: AuditConfig,
) -> DecisionReceipt:
    start_ns = time.perf_counter_ns() if config.enabled else 0
    traced = evaluate_traced(spec, action)
    result = traced.result

    duration_us = (
        (time.perf_counter_ns() - start_ns) // 1000 if config.enabled else 0
    )

    # The evaluator records its own trace, so the receipt reflects exactly the
    # blocks that ran under Section 6.1 aggregation -- never a reconstruction.
    rule_trace: list[RuleEvaluation] = (
        traced.trace if config.enabled and config.include_rule_trace else []
    )

    if config.enabled:
        policy = _build_policy_summary(spec)
    else:
        policy = PolicySummary(
            name=spec.name,
            version=spec.hushspec,
            content_hash="",
        )

    action_summary = ActionSummary(
        type=action.type,
        target=action.target,
        content_redacted=config.redact_content and action.content is not None,
    )

    return DecisionReceipt(
        receipt_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        hushspec_version=HUSHSPEC_VERSION,
        action=action_summary,
        decision=result.decision,
        matched_rule=result.matched_rule,
        reason=result.reason,
        rule_trace=rule_trace,
        policy=policy,
        origin_profile=result.origin_profile,
        posture=result.posture,
        evaluation_duration_us=duration_us,
    )


def _drop_none(value: Any) -> Any:
    """Recursively remove dict keys whose value is exactly ``None``.

    Rust/Go/TS serialize ``Option``/optional fields with a skip-if-absent
    annotation, so a receipt's optional fields (``matched_rule``, ``reason``,
    ``origin_profile``, ``posture``, ``enforcement``, ``policy.name``, the
    same fields nested inside each ``rule_trace`` entry, etc.) are omitted
    entirely rather than serialized as an explicit JSON ``null``. Python's
    ``dataclasses.asdict`` has no such notion, so without this pass every
    ``Optional[...] = None`` field would round-trip as ``"key": null``,
    diverging from the other three SDKs. Only ``None`` is dropped --
    falsy-but-present values (``False``, ``0``, ``""``, ``[]``) are left
    untouched, matching ``skip_serializing_if = "Option::is_none"`` (never
    "is falsy").
    """
    if isinstance(value, dict):
        return {key: _drop_none(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_drop_none(item) for item in value]
    return value


def receipt_to_dict(receipt: DecisionReceipt) -> dict:
    """Convert a receipt to a JSON-ready ``dict`` for sinks and observers.

    This is the single place receipts get flattened for serialization, so
    that ``FileReceiptSink``, ``StderrReceiptSink``, and the observer's
    ``JsonLineObserver`` all emit byte-consistent JSON. Two fields get a
    special-cased pop for their "nothing to report" value in addition to the
    general ``None``-dropping pass below, mirroring the other three HushSpec
    SDKs (Rust/Go skip-serialize the same way):

    - ``policy.content_hash`` is omitted when empty -- the zero-overhead
      disabled-audit fast path never computes a hash, and an empty string
      would violate the receipt schema's ``^[0-9a-f]{64}$`` pattern.
    - ``action.content_redacted`` is omitted when ``False``.

    Every other optional field that is ``None`` (``matched_rule``, ``reason``,
    ``origin_profile``, ``posture``, ``enforcement``, nested ``rule_trace``
    entries' ``matched_rule``/``reason``, etc.) is dropped recursively so
    Python never emits an explicit JSON ``null`` where Rust/Go/TS would omit
    the key entirely.
    """
    data = asdict(receipt)
    policy = data.get("policy")
    if isinstance(policy, dict) and not policy.get("content_hash"):
        policy.pop("content_hash", None)
    action = data.get("action")
    if isinstance(action, dict) and not action.get("content_redacted"):
        action.pop("content_redacted", None)
    return _drop_none(data)


def compute_policy_hash(spec: HushSpec) -> str:
    """Hash of the *resolved* policy -- the document evaluation runs against.

    Hashing an unresolved leaf would make the receipt's ``content_hash``
    identify a document that is not what was enforced (every block inherited
    from the base is missing from it), so an ``extends`` still present here is
    resolved against the embedded builtins first and, if that is impossible,
    rejected rather than hashed. Guards resolve on load, so this is a backstop
    for direct callers.
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
    spec_dict = spec.to_dict()
    json_str = json.dumps(spec_dict, separators=(",", ":"), sort_keys=False)
    return hashlib.sha256(json_str.encode("utf-8")).hexdigest()





def _build_policy_summary(spec: HushSpec) -> PolicySummary:
    return PolicySummary(
        name=spec.name,
        version=spec.hushspec,
        content_hash=compute_policy_hash(spec),
    )
