from __future__ import annotations

from pathlib import Path

import yaml

from hushspec import merge, parse, validate


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
                ok, result = parse(policy_yaml)
                assert ok, f"{fixture_path}: {result}"
                validation = validate(result)
                assert validation.is_valid, f"{fixture_path}: {validation.errors}"


def parse_or_fail(path: Path):
    ok, result = parse(path.read_text())
    assert ok, f"{path}: {result}"
    return result
