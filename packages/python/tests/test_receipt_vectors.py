"""Normative receipt vectors (``spec/hushspec-receipt.md``, format 0.2).

Three directories, three obligations:

* ``fixtures/receipts/expected/`` -- for every case of every shared evaluation
  fixture, the receipt this SDK produces must equal the committed one byte for
  byte *after canonicalization* (RFC 8785), under the fixed inputs of
  ``fixtures/receipts/expected/README.md``. This is the port's real conformance
  gate: it pins the rule trace, the engine-stage ids, the detection trace, the
  action summary, and the policy content hash all at once.
* ``fixtures/receipts/valid/`` -- must parse and validate against the schema.
* ``fixtures/receipts/invalid/`` -- must be rejected by the schema.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from hushspec.canonical import canonical_json_value
from hushspec.conditions import RuntimeContext
from hushspec.evaluate import EvaluationAction, OriginContext, PostureContext
from hushspec.parse import CoreSafeLoader, parse_or_raise
from hushspec.receipt import (
    Actor,
    AuditConfig,
    AuditContext,
    TimeSource,
    canonical_json,
    deterministic_uuid_v7,
    evaluate_audited,
    parse_receipt,
    receipt_hash,
    receipt_to_dict,
)
from hushspec.resolve import Resolution

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURES = REPO_ROOT / "fixtures"
EXPECTED_ROOT = FIXTURES / "receipts" / "expected"
SCHEMA_PATH = REPO_ROOT / "schemas" / "hushspec-receipt.v0.schema.json"

#: The fixed evaluation time of every expected receipt: 2026-09-15T12:00:00Z.
CLOCK_MILLIS = 1_789_473_600_000
CLOCK = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)

EVALUATION_MODULES = ("core", "posture", "origins", "detection")


def _action(data: dict, context: dict | None) -> EvaluationAction:
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
    runtime_context = None
    if data.get("context") is not None:
        runtime_context = RuntimeContext.from_dict(data["context"])
    elif context is not None:
        # The case's context applies to the action when the action has none.
        runtime_context = RuntimeContext.from_dict(context)
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
        context=runtime_context,
    )


def _fixed_context(case_index: int) -> AuditContext:
    return AuditContext(
        actor=Actor(
            agent_id="fixture-agent",
            session_id="fixture-session",
            principal="fixture@hushspec.dev",
            runtime="hushspec-conformance/0.2",
        ),
        enforcement=None,
        enforcement_mode="enforce",
        time_source=TimeSource.TRUSTED.value,
        clock=CLOCK,
        receipt_id=deterministic_uuid_v7(CLOCK_MILLIS, case_index),
    )


def _fixed_config() -> AuditConfig:
    # `record_duration` is off: the bytes of a vector must not depend on the
    # machine that produced them.
    return AuditConfig(enabled=True, include_rule_trace=True, record_duration=False)


def _evaluation_fixtures() -> list[Path]:
    paths: list[Path] = []
    for module in EVALUATION_MODULES:
        directory = FIXTURES / module / "evaluation"
        if directory.exists():
            paths.extend(sorted(directory.glob("*.test.yaml")))
    return paths


def _cases() -> list[tuple[Path, int]]:
    out: list[tuple[Path, int]] = []
    for path in _evaluation_fixtures():
        document = yaml.load(path.read_text(), Loader=CoreSafeLoader)
        out.extend((path, index) for index in range(len(document.get("cases", []))))
    return out


EXPECTED_CASES = _cases()


def _expected_path(fixture: Path, index: int) -> Path:
    module = fixture.parent.parent.name
    stem = fixture.name[: -len(".test.yaml")]
    return EXPECTED_ROOT / module / stem / f"{index}.json"


def test_there_are_expected_receipts_to_check() -> None:
    assert EXPECTED_CASES, "no shared evaluation fixtures found"
    assert len(list(EXPECTED_ROOT.rglob("*.json"))) == len(EXPECTED_CASES)


@pytest.mark.parametrize(
    "fixture,index",
    EXPECTED_CASES,
    ids=[f"{p.parent.parent.name}/{p.name[:-len('.test.yaml')]}/{i}" for p, i in EXPECTED_CASES],
)
def test_expected_receipt_matches_byte_for_byte(fixture: Path, index: int) -> None:
    document = yaml.load(fixture.read_text(), Loader=CoreSafeLoader)
    spec = parse_or_raise(yaml.safe_dump(document["policy"]))
    # The fixture's policy is treated as already resolved: one link, `memory`,
    # so there is no `extends_chain` to record.
    resolution = Resolution.from_resolved(spec)
    case = document["cases"][index]
    action = _action(case["action"], case.get("context"))

    receipt = evaluate_audited(resolution, action, _fixed_config(), _fixed_context(index))

    expected_file = _expected_path(fixture, index)
    expected = canonical_json_value(json.loads(expected_file.read_text()))
    assert canonical_json(receipt) == expected, (
        f"{expected_file.relative_to(REPO_ROOT)} does not match this SDK's receipt"
    )


@pytest.mark.parametrize(
    ("fixture", "index"),
    EXPECTED_CASES,
    ids=[f"{fixture.stem}-{index}" for fixture, index in EXPECTED_CASES],
)
def test_an_expected_receipt_round_trips_through_the_parser(
    fixture: Path, index: int
) -> None:
    # Parsing a receipt and re-serializing it in canonical form yields the same
    # bytes, and the hash is unchanged by the trip (receipt spec section 6).
    path = _expected_path(fixture, index)
    text = path.read_text()
    receipt = parse_receipt(text)
    assert canonical_json(receipt) == canonical_json_value(json.loads(text))
    assert receipt_hash(receipt) == receipt_hash(parse_receipt(receipt_to_dict(receipt)))


# --------------------------------------------------------------------------- #
# valid/ and invalid/
# --------------------------------------------------------------------------- #


def _validator():
    jsonschema = pytest.importorskip("jsonschema")
    return jsonschema.Draft202012Validator(json.loads(SCHEMA_PATH.read_text()))


VALID = sorted((FIXTURES / "receipts" / "valid").glob("*.json"))
INVALID = sorted((FIXTURES / "receipts" / "invalid").glob("*.json"))


def test_the_vector_directories_are_populated() -> None:
    assert len(VALID) >= 12
    assert len(INVALID) >= 12


@pytest.mark.parametrize("path", VALID, ids=[p.stem for p in VALID])
def test_valid_vector_is_accepted(path: Path) -> None:
    document = json.loads(path.read_text())
    _validator().validate(document)
    receipt = parse_receipt(document)
    assert receipt.receipt_version == "0.2"
    # Parsing must be lossless: the canonical form is unchanged.
    assert canonical_json(receipt) == canonical_json_value(document)


@pytest.mark.parametrize("path", INVALID, ids=[p.stem for p in INVALID])
def test_invalid_vector_is_rejected(path: Path) -> None:
    document = json.loads(path.read_text())
    assert not _validator().is_valid(document), f"{path.name} validated but must not"
