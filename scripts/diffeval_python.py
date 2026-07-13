#!/usr/bin/env python3
"""Evaluate a HushSpec differential case bundle with the Python SDK."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packages" / "python"))

from hushspec import parse, validate  # noqa: E402
from hushspec.evaluate import (  # noqa: E402
    EvaluationAction,
    OriginContext,
    PostureContext,
    evaluate,
)


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
    return EvaluationAction(
        type=data["type"],
        target=data.get("target"),
        content=data.get("content"),
        origin=origin,
        posture=posture,
        args_size=data.get("args_size"),
    )


def result_to_dict(result) -> dict:
    out = {"decision": result.decision.value}
    if result.matched_rule is not None:
        out["matched_rule"] = result.matched_rule
    if result.reason is not None:
        out["reason"] = result.reason
    if result.origin_profile is not None:
        out["origin_profile"] = result.origin_profile
    if result.posture is not None:
        out["posture"] = {"current": result.posture.current, "next": result.posture.next}
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
    for group in bundle["groups"]:
        spec = None
        rejection = None
        ok, parsed = parse(yaml.safe_dump(group["policy"], sort_keys=False))
        if not ok:
            rejection = {"status": "rejected", "phase": "parse", "message": str(parsed)}
        else:
            validation = validate(parsed)
            if not validation.is_valid:
                rejection = {
                    "status": "rejected",
                    "phase": "validate",
                    "message": str(validation.errors[0]),
                }
            else:
                spec = parsed

        for case in group["actions"]:
            key = f"{group['id']}/{case['id']}"
            if rejection is not None:
                results[key] = rejection
                continue
            try:
                result = evaluate(spec, build_action(case["action"]))
                results[key] = {"status": "ok", "result": result_to_dict(result)}
            except Exception as error:  # noqa: BLE001 - report per-case, never crash
                results[key] = {"status": "error", "message": str(error)}

    print(json.dumps({"sdk": "python", "results": results}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
