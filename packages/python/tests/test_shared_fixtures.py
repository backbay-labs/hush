from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from hushspec import merge, parse, validate
from hushspec.detection import evaluate_with_detection
from hushspec.evaluate import EvaluationAction, OriginContext, PostureContext


REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURES_ROOT = REPO_ROOT / "fixtures"

VALID_DIRS = [
    "core/valid",
    "posture/valid",
    "origins/valid",
    "detection/valid",
]

INVALID_DIRS = [
    "core/invalid",
    "posture/invalid",
    "origins/invalid",
    "detection/invalid",
]

EVALUATION_DIRS = [
    "core/evaluation",
    "posture/evaluation",
    "origins/evaluation",
    "detection/evaluation",
]

MERGE_DIRS = [
    "core/merge",
    "posture/merge",
    "origins/merge",
    "detection/merge",
]


def iter_yaml_files(subdir: str) -> list[Path]:
    directory = FIXTURES_ROOT / subdir
    if not directory.exists():
        return []
    return sorted(
        [
            path
            for path in directory.iterdir()
            if path.suffix in {".yaml", ".yml"} and path.is_file()
        ]
    )


class TestSharedFixtures:
    def test_valid_documents(self):
        for subdir in VALID_DIRS:
            for fixture_path in iter_yaml_files(subdir):
                ok, result = parse(fixture_path.read_text())
                assert ok, f"{fixture_path}: {result}"
                validation = validate(result)
                assert validation.is_valid, f"{fixture_path}: {validation.errors}"

    def test_invalid_documents(self):
        for subdir in INVALID_DIRS:
            for fixture_path in iter_yaml_files(subdir):
                ok, result = parse(fixture_path.read_text())
                if ok:
                    validation = validate(result)
                    assert (
                        not validation.is_valid
                    ), f"{fixture_path}: expected rejection"

    def test_merge_fixtures(self):
        for subdir in MERGE_DIRS:
            base_path = FIXTURES_ROOT / subdir / "base.yaml"
            if not base_path.exists():
                continue
            base = parse_or_fail(base_path)

            for child_path in iter_yaml_files(subdir):
                if not child_path.stem.startswith("child-"):
                    continue
                expected_path = child_path.with_name(
                    child_path.name.replace("child-", "expected-", 1)
                )
                expected = parse_or_fail(expected_path)
                merged = merge(base, parse_or_fail(child_path))
                assert (
                    merged.to_dict() == expected.to_dict()
                ), f"{child_path}: merged output differed from {expected_path.name}"

    def test_evaluator_fixtures(self):
        for subdir in EVALUATION_DIRS:
            for fixture_path in iter_yaml_files(subdir):
                raw = yaml.safe_load(fixture_path.read_text())
                assert raw["hushspec_test"] == "0.1.0"
                assert raw["description"].strip()
                assert raw["cases"]

                for index, case in enumerate(raw["cases"]):
                    assert case["description"].strip(), f"{fixture_path}: case {index}"
                    assert case["expect"]["decision"] in {"allow", "warn", "deny"}
                    assert isinstance(case["action"], dict)
                    assert isinstance(case["action"].get("type"), str)

                policy_yaml = yaml.safe_dump(raw["policy"], sort_keys=False)
                ok, spec = parse(policy_yaml)
                assert ok, f"{fixture_path}: {spec}"
                validation = validate(spec)
                assert validation.is_valid, f"{fixture_path}: {validation.errors}"

                # Actually run each case through the reference evaluator --
                # not just check fixture *shape* -- via
                # evaluate_with_detection(spec, action).evaluation rather
                # than bare evaluate(). evaluate_with_detection() is an
                # exact no-op when the policy has no extensions.detection
                # block (true of every core/posture/origins fixture), so
                # this is equivalent to evaluate() for all of them and only
                # exercises detection for fixtures/detection/evaluation/.
                for index, case in enumerate(raw["cases"]):
                    action = _action_from_case(case["action"])
                    actual = evaluate_with_detection(spec, action).evaluation
                    expect = case["expect"]
                    label = (
                        f"{fixture_path}: cases[{index}] {case['description']!r}"
                    )

                    assert actual.decision.value == expect["decision"], label
                    if "matched_rule" in expect:
                        assert actual.matched_rule == expect["matched_rule"], label
                    if "reason" in expect:
                        assert actual.reason == expect["reason"], label
                    if "origin_profile" in expect:
                        assert actual.origin_profile == expect["origin_profile"], label
                    if "posture" in expect:
                        assert actual.posture is not None, label
                        assert actual.posture.current == expect["posture"]["current"], label
                        assert actual.posture.next == expect["posture"]["next"], label


def parse_or_fail(path: Path):
    ok, result = parse(path.read_text())
    assert ok, f"{path}: {result}"
    return result


def _action_from_case(raw: dict[str, Any]) -> EvaluationAction:
    """Build an EvaluationAction from a fixture case's raw ``action`` mapping.

    Field names are shared verbatim with schemas/hushspec-evaluator-test.v0
    .schema.json's Action/Origin/PostureInput $defs, so this is a direct
    keyword-argument passthrough per sub-object.
    """
    origin = OriginContext(**raw["origin"]) if raw.get("origin") is not None else None
    posture = PostureContext(**raw["posture"]) if raw.get("posture") is not None else None
    return EvaluationAction(
        type=raw["type"],
        target=raw.get("target"),
        content=raw.get("content"),
        args_size=raw.get("args_size"),
        origin=origin,
        posture=posture,
    )
