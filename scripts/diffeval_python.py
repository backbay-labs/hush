#!/usr/bin/env python3
"""Evaluate a HushSpec differential case bundle with the Python SDK."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packages" / "python"))

from hushspec import content_hash, parse, validate  # noqa: E402
from hushspec.conditions import RuntimeContext  # noqa: E402
from hushspec.detection import evaluate_with_detection  # noqa: E402
from hushspec.evaluate import (  # noqa: E402
    EvaluationAction,
    OriginContext,
    PostureContext,
    evaluate_traced,
)
from hushspec.resolve import resolve  # noqa: E402


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


def result_to_dict(result, trace) -> dict:
    out = {"decision": result.decision.value}
    if result.matched_rule is not None:
        out["matched_rule"] = result.matched_rule
    if result.reason is not None:
        out["reason"] = result.reason
    if result.origin_profile is not None:
        out["origin_profile"] = result.origin_profile
    if result.posture is not None:
        out["posture"] = {"current": result.posture.current, "next": result.posture.next}
    rule_trace = trace_to_list(trace)
    if rule_trace:
        out["rule_trace"] = rule_trace
    return out


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

    results: dict[str, dict] = {}
    # Group id -> canonical content hash of the resolved policy the actions in
    # that group were evaluated against (spec/hushspec-canonical.md section 5).
    # Every SDK must report the same value; a group whose policy was rejected
    # has no resolved document and so no entry.
    #
    # This hashes the *parsed model*, not the raw tree, because that is the only
    # form a resolved `extends` chain exists in. The typed model cannot express
    # the absent/empty distinction canonical spec section 3.3 preserves for
    # origins overlay fields, so the four SDKs agree here only as long as their
    # models are lossy in the same way -- which is exactly what this comparison
    # is for.
    hashes: dict[str, str] = {}
    for group in bundle["groups"]:
        spec = None
        rejection = None
        ok, parsed = parse(yaml.safe_dump(group["policy"], sort_keys=False))
        if not ok:
            rejection = {"status": "rejected", "phase": "parse", "message": str(parsed)}
        else:
            # parse -> resolve -> validate -> evaluate, the same order the Rust
            # oracle uses. The generator only emits `builtin:` references, which
            # the default composite loader serves from the SDK's embedded rulesets.
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

        for case in group["actions"]:
            key = f"{group['id']}/{case['id']}"
            if rejection is not None:
                results[key] = rejection
                continue
            try:
                action = build_action(case["action"])
                # Detection-aware result plus the base evaluator's trace:
                # detection never re-runs the rule blocks, so the traced
                # evaluation's trace is the trace behind the final verdict.
                traced = evaluate_traced(spec, action, None, {})
                result = evaluate_with_detection(spec, action).evaluation
                results[key] = {
                    "status": "ok",
                    "result": result_to_dict(result, traced.trace),
                }
            except Exception as error:  # noqa: BLE001 - report per-case, never crash
                results[key] = {"status": "error", "message": str(error)}

    print(json.dumps({"sdk": "python", "results": results, "content_hash": hashes}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
