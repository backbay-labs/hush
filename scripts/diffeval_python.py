#!/usr/bin/env python3
"""Evaluate a HushSpec differential case bundle with the Python SDK."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packages" / "python"))

from hushspec import content_hash, parse, validate  # noqa: E402
from hushspec.conditions import RuntimeContext  # noqa: E402
from hushspec.evaluate import (  # noqa: E402
    Decision,
    EvaluationAction,
    OriginContext,
    PostureContext,
    evaluate_traced,
)
from hushspec.receipt import (  # noqa: E402
    RECEIPT_VERSION,
    ActionSummary,
    Actor,
    AuditConfig,
    AuditContext,
    DecisionReceipt,
    EnforcementSummary,
    deterministic_uuid_v7,
    evaluate_audited_spec,
    format_timestamp,
    policy_summary,
    receipt_hash,
    receipt_to_dict,
)
from hushspec.resolve import Resolution, resolve  # noqa: E402

#: The audited inputs every SDK replays so the receipts they record for a case
#: are byte-identical (``fixtures/receipts/expected/README.md``). A bundle
#: written before the ``audit`` block existed replays these same defaults.
DEFAULT_AUDIT = {
    "clock": "2026-09-15T12:00:00.000Z",
    "time_source": "trusted",
    "enforcement_mode": "enforce",
    "actor": {
        "agent_id": "fixture-agent",
        "session_id": "fixture-session",
        "principal": "fixture@hushspec.dev",
        "runtime": "hushspec-conformance/0.2",
    },
    "index_base": 0,
    "emit_receipts": False,
}

#: Record the trace but never the duration: a receipt's bytes must not depend
#: on the machine that produced them.
AUDIT_CONFIG = AuditConfig(enabled=True, include_rule_trace=True, record_duration=False)


def build_action(data: dict) -> EvaluationAction:
    origin = None
    if "origin" in data:
        raw = data["origin"]
        origin = OriginContext(
            provider=raw.get("provider"),
            tenant_id=raw.get("tenant_id"),
            space_id=raw.get("space_id"),
            space_type=raw.get("space_type"),
            visibility=raw.get("visibility"),
            external_participants=raw.get("external_participants"),
            tags=raw.get("tags", []),
            sensitivity=raw.get("sensitivity"),
            actor_role=raw.get("actor_role"),
        )
    posture = None
    if "posture" in data:
        raw = data["posture"]
        posture = PostureContext(current=raw.get("current"), signal=raw.get("signal"))
    context = None
    if "context" in data and data["context"] is not None:
        context = RuntimeContext.from_dict(data["context"])
    return EvaluationAction(
        type=data["type"],
        target=data.get("target"),
        content=data.get("content"),
        origin=origin,
        posture=posture,
        args_size=data.get("args_size"),
        url=data.get("url"),
        network=data.get("network"),
        timeout_ms=data.get("timeout_ms"),
        context=context,
    )


def trace_to_list(trace) -> list[dict]:
    out: list[dict] = []
    for entry in trace:
        normalized = {
            "rule_block": entry.rule_block,
            "outcome": entry.outcome.value,
            "evaluated": entry.evaluated,
        }
        if entry.matched_rule is not None:
            normalized["matched_rule"] = entry.matched_rule
        if entry.reason is not None:
            normalized["reason"] = entry.reason
        out.append(normalized)
    return out


def result_to_dict(receipt: DecisionReceipt, trace, emit_receipt: bool) -> dict:
    """The verdict, read back out of the receipt that recorded it.

    Taking the decision from the receipt rather than from a second evaluation
    makes a receipt that disagrees with its own decision impossible by
    construction. ``trace`` is the base evaluator's own recording, which is a
    different spelling from the receipt's (engine-stage ids, ``rule_path``).
    """
    out = {"decision": _value(receipt.decision)}
    if receipt.matched_rule is not None:
        out["matched_rule"] = receipt.matched_rule
    if receipt.reason is not None:
        out["reason"] = receipt.reason
    if receipt.origin_profile is not None:
        out["origin_profile"] = receipt.origin_profile
    if receipt.posture is not None:
        out["posture"] = {"current": receipt.posture.current, "next": receipt.posture.next}
    rule_trace = trace_to_list(trace)
    if rule_trace:
        out["rule_trace"] = rule_trace
    out["receipt_hash"] = receipt_hash(receipt)
    if emit_receipt:
        out["receipt"] = receipt_to_dict(receipt)
    return out


def _value(value):
    return value.value if hasattr(value, "value") else value


def audit_context(audit: dict, clock: datetime, clock_millis: int, position: int) -> AuditContext:
    """The audit context of the case at *position* in the bundle."""
    return AuditContext(
        actor=Actor(**audit["actor"]),
        enforcement_mode=audit["enforcement_mode"],
        time_source=audit["time_source"],
        clock=clock,
        receipt_id=deterministic_uuid_v7(clock_millis, audit["index_base"] + position),
    )


def policy_identity_hash(spec, audit: dict, clock: datetime) -> str:
    """The group-level ``receipt_hash``.

    A receipt carrying this policy's summary and nothing else that varies:
    fixed id, the bundle's clock, a reserved action, a deny with an empty
    trace. Hashed with this SDK's own receipt canonicalizer, so a disagreement
    means the policy identity our receipts would record -- name, version,
    spec_version, content_hash, extends_chain, signature -- differs from the
    bundle's expected value, independently of any one action.
    """
    return receipt_hash(
        DecisionReceipt(
            receipt_version=RECEIPT_VERSION,
            receipt_id="00000000-0000-7000-8000-000000000000",
            timestamp=format_timestamp(clock),
            time_source=audit["time_source"],
            policy=policy_summary(Resolution.from_resolved(spec)),
            action=ActionSummary(type="__hushspec_policy_identity__"),
            decision=Decision.DENY,
            rule_trace=[],
            enforcement=EnforcementSummary.implied(Decision.DENY, audit["enforcement_mode"]),
        )
    )


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: diffeval_python.py <bundle.json>", file=sys.stderr)
        return 2

    bundle = json.loads(Path(sys.argv[1]).read_text())
    if bundle.get("hushspec_diff") != "0.1.0":
        print(
            f"unsupported hushspec_diff version: {bundle.get('hushspec_diff')}",
            file=sys.stderr,
        )
        return 2

    audit = {**DEFAULT_AUDIT, **(bundle.get("audit") or {})}
    try:
        clock = datetime.fromisoformat(str(audit["clock"]).replace("Z", "+00:00"))
        clock_millis = int(clock.astimezone(timezone.utc).timestamp() * 1000)
    except (TypeError, ValueError) as error:
        # Fail closed: a clock we cannot read has no reproducible receipts, and
        # falling back to "now" would make this harness disagree with every
        # other one while still looking like it answered.
        print(f"unreadable audit.clock {audit['clock']!r}: {error}", file=sys.stderr)
        return 2

    results: dict[str, dict] = {}
    # Group id -> canonical content hash of the resolved policy the actions in
    # that group were evaluated against (spec/hushspec-canonical.md section 5).
    # Every SDK must report the same value; a group whose policy was rejected
    # has no resolved document and so no entry.
    #
    # This hashes the *parsed model*, not the raw tree, because that is the only
    # form a resolved `extends` chain exists in. Both reach the same projection:
    # the one presence-significant property canonical spec section 3.3 keeps,
    # `OriginProfile.match`, is an optional mapping in every SDK's model.
    hashes: dict[str, str] = {}
    # Group id -> hash of the policy-identity receipt (see policy_identity_hash).
    identities: dict[str, str] = {}
    # Position of the next case in the bundle, counting every action of every
    # group in order (rejected policies included). `index_base + position`
    # seeds that case's receipt id in every SDK, so the counter advances even
    # when there is no receipt to record.
    position = 0
    for group in bundle["groups"]:
        spec = None
        rejection = None
        ok, parsed = parse(yaml.safe_dump(group["policy"], sort_keys=False))
        if not ok:
            rejection = {"status": "rejected", "phase": "parse", "message": str(parsed)}
        else:
            # parse -> resolve -> validate -> evaluate, the order every SDK applies.
            # The generator only emits `builtin:` references, which the default
            # composite loader serves from the SDK's embedded rulesets.
            if parsed.extends is not None:
                resolved_ok, resolved = resolve(parsed)
                if not resolved_ok:
                    rejection = {
                        "status": "rejected",
                        "phase": "resolve",
                        "message": str(resolved),
                    }
                else:
                    parsed = resolved
            if rejection is None:
                validation = validate(parsed)
                if not validation.is_valid:
                    rejection = {
                        "status": "rejected",
                        "phase": "validate",
                        "message": str(validation.errors[0]),
                    }
                else:
                    spec = parsed
                    try:
                        hashes[group["id"]] = content_hash(spec)
                    except Exception as error:  # noqa: BLE001 - reported as a divergence
                        hashes[group["id"]] = f"error: {error}"
                    try:
                        identities[group["id"]] = policy_identity_hash(spec, audit, clock)
                    except Exception as error:  # noqa: BLE001 - reported as a divergence
                        identities[group["id"]] = f"error: {error}"

        for case in group["actions"]:
            key = f"{group['id']}/{case['id']}"
            case_index = position
            position += 1
            if rejection is not None:
                results[key] = rejection
                continue
            try:
                action = build_action(case["action"])
                # The audited path is the one an enforcement point runs: it
                # routes through the detection pipeline and records the
                # evidence, so the verdict reported here is read back out of
                # the receipt. The base evaluator's trace comes from an
                # explicit evaluate_traced call over the same inputs;
                # detection never re-runs the rule blocks, so the two agree by
                # construction.
                traced = evaluate_traced(spec, action, None, {})
                receipt = evaluate_audited_spec(
                    spec,
                    action,
                    AUDIT_CONFIG,
                    audit_context(audit, clock, clock_millis, case_index),
                )
                results[key] = {
                    "status": "ok",
                    "result": result_to_dict(receipt, traced.trace, audit["emit_receipts"]),
                }
            except Exception as error:  # noqa: BLE001 - report per-case, never crash
                results[key] = {"status": "error", "message": str(error)}

    # Difftest contract: per-group data lives under "groups"; a rejected policy
    # reports neither hash.
    def _sha(value) -> object:
        return value if isinstance(value, str) and value.startswith("sha256:") else None

    groups = {
        gid: {"content_hash": _sha(hashes.get(gid)), "receipt_hash": _sha(identities.get(gid))}
        for gid in {**hashes, **identities}
    }
    print(json.dumps({"sdk": "python", "results": results, "groups": groups}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
