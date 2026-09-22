"""Shared source-byte vectors: never decode and re-emit the policy before parse."""
import hashlib
import json
from pathlib import Path

import pytest

from hushspec import parse, canonical_json, content_hash, evaluate, EvaluationAction
from hushspec.conditions import RuntimeContext

VECTORS = json.loads((Path(__file__).resolve().parents[3] / "fixtures/core/raw-yaml/scalars.json").read_text())


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["id"])
def test_raw_yaml(vector):
    ok, policy = parse(vector["yaml"])
    assert ok == vector["accept"], str(policy)
    if not ok:
        return
    canonical = canonical_json(policy)
    value = json.loads(canonical)
    for key in vector["value_path"]:
        value = value[int(key)] if isinstance(value, list) else value[key]
    assert value == vector["value"]
    assert type(value) is type(vector["value"]) or (type(value) in (int, float) and type(vector["value"]) in (int, float))
    if "canonical" in vector:
        assert canonical == vector["canonical"]
        assert content_hash(policy) == "sha256:" + hashlib.sha256(vector["canonical"].encode()).hexdigest()
    if "decision" in vector:
        result = evaluate(policy, EvaluationAction(type="egress", target="example.com", context=RuntimeContext(counters={"requests": 9})))
        assert result.decision.value == vector["decision"]
