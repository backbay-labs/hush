from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml

from hushspec import merge, parse, validate
from hushspec.conditions import RuntimeContext
from hushspec.detection import evaluate_with_detection
from hushspec.evaluate import EvaluationAction, OriginContext, PostureContext
from hushspec.parse import CoreSafeLoader
from hushspec.receipt import (
    Actor,
    AuditConfig,
    AuditContext,
    TimeSource,
    deterministic_uuid_v7,
    evaluate_audited,
    receipt_to_dict,
)
from hushspec.resolve import (
    DIGEST_PIN_MARKER,
    Resolution,
    create_composite_loader,
    resolve,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURES_ROOT = REPO_ROOT / "fixtures"

# Fixture format versions this runner accepts (evaluator-test schema).
SUPPORTED_TEST_VERSIONS = {"0.1.0", "0.2.0"}

# The fixed inputs an ``expect.receipt`` assertion is evaluated under, pinned
# by fixtures/receipts/expected/README.md -- the same ones the expected-receipt
# vectors use, so a fixture's ``expect.receipt`` and those files describe one
# object.
RECEIPT_CLOCK_MILLIS = 1_789_473_600_000

# Receipt members that are inputs rather than outcomes, never compared.
RECEIPT_IGNORED_MEMBERS = {"actor", "timestamp", "receipt_id"}

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
    return iter_yaml_files_in(FIXTURES_ROOT / subdir)


def iter_yaml_files_in(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    return sorted(
        [
            path
            for path in directory.iterdir()
            if path.suffix in {".yaml", ".yml"} and path.is_file()
        ]
    )


def iter_fixture_dirs(subdir: str) -> list[Path]:
    """The fixture directory and any per-case subdirectory under it.

    Merge vectors have historically been flat (`base.yaml` + `child-*.yaml` +
    `expected-*.yaml` in one directory). A vector that needs its own base -- a
    digest pin names one exact document, so a pin-mismatch case cannot share a
    base with a pin-match case -- gets its own subdirectory with its own
    `base.yaml`, and this picks those up too.
    """
    root = FIXTURES_ROOT / subdir
    if not root.exists():
        return []
    return [root] + sorted(path for path in root.iterdir() if path.is_dir())


def fixture_pins_its_base(child_path: Path) -> bool:
    """Whether a merge fixture's child pins its base by digest."""
    extends = (parse_raw_or_fail(child_path) or {}).get("extends")
    return isinstance(extends, str) and DIGEST_PIN_MARKER in extends


def expects_rejection(child_path: Path) -> bool:
    """Whether a merge fixture is expected to be rejected rather than merged.

    Two conventions are honoured, so a digest-pin vector lands correctly under
    whichever one its fixture uses:

    * a marker file -- `child-x.yaml.expect-reject`, `child-x.expect-reject`,
      or a directory-wide `expect-reject`;
    * `reject: true` in a `fixture.yaml`, either beside the child
      (`child-x.fixture.yaml`) or for the directory, where a per-child mapping
      keyed by the child's file name or stem is also read.
    """
    for marker in (
        child_path.parent / f"{child_path.name}.expect-reject",
        child_path.parent / f"{child_path.stem}.expect-reject",
        child_path.parent / "expect-reject",
    ):
        if marker.exists():
            return True

    names = {child_path.name, child_path.stem}
    for meta_path in (
        child_path.parent / f"{child_path.stem}.fixture.yaml",
        child_path.parent / "fixture.yaml",
    ):
        if not meta_path.is_file():
            continue
        meta = yaml.load(meta_path.read_text(), Loader=CoreSafeLoader)
        if isinstance(meta, dict) and _declares_rejection(meta, names):
            return True
    return False


def _declares_rejection(meta: dict[str, Any], names: set[str]) -> bool:
    if meta.get("reject") is True:
        return True
    for key in ("cases", "children", "fixtures", "merge"):
        section = meta.get(key)
        if isinstance(section, dict):
            for name in names:
                entry = section.get(name)
                if entry is True:
                    return True
                if isinstance(entry, dict) and entry.get("reject") is True:
                    return True
        elif isinstance(section, list):
            for entry in section:
                if not isinstance(entry, dict) or entry.get("reject") is not True:
                    continue
                if names & {entry.get("child"), entry.get("name"), entry.get("file")}:
                    return True
    return False


class TestSharedFixtures:
    def test_valid_documents(self):
        checked = 0
        for subdir in VALID_DIRS:
            for fixture_path in iter_yaml_files(subdir):
                ok, result = parse(fixture_path.read_text())
                assert ok, f"{fixture_path}: {result}"
                validation = validate(result)
                assert validation.is_valid, f"{fixture_path}: {validation.errors}"
                checked += 1
        # A renamed or missing directory yields no files, and a loop over
        # nothing passes: count, so that shows up as a failure.
        assert checked > 0, "no valid vectors were found"

    def test_invalid_documents(self):
        """Every `invalid/` vector is refused, for the reason its sidecar names.

        `<name>.expect.yaml` pins the error-code-registry `code` a conformant
        implementation MUST report (core spec 8, Level 1) and, where the
        wording is load-bearing, a `message_contains` fragment. Asserting the
        code turns "the document was rejected" into "rejected for this
        reason", which is the property that makes the vectors portable: two
        SDKs that refuse the same file for different reasons have not agreed.
        """
        checked = 0
        for subdir in INVALID_DIRS:
            for fixture_path in iter_yaml_files(subdir):
                if fixture_path.name.endswith(".expect.yaml"):
                    continue
                code, message = _reject(fixture_path)
                assert code is not None, f"{fixture_path}: expected rejection"

                expected = _expected_rejection(fixture_path)
                assert expected is not None, (
                    f"{fixture_path}: no {fixture_path.stem}.expect.yaml sidecar"
                )
                assert expected.get("reject") is True, (
                    f"{fixture_path}: sidecar does not declare `reject: true`"
                )
                assert code == expected["code"], (
                    f"{fixture_path}: expected {expected['code']}, got {code}: {message}"
                )
                fragment = expected.get("message_contains")
                if fragment is not None:
                    assert fragment in message, (
                        f"{fixture_path}: expected the message to contain "
                        f"{fragment!r}, got {message!r}"
                    )
                checked += 1
        assert checked > 0, "no invalid vectors were found"

    def test_merge_fixtures(self):
        checked = 0
        for subdir in MERGE_DIRS:
            for directory in iter_fixture_dirs(subdir):
                base_path = directory / "base.yaml"
                if not base_path.exists():
                    continue
                base = parse_or_fail(base_path)

                for child_path in iter_yaml_files_in(directory):
                    if not child_path.stem.startswith("child-"):
                        continue
                    self._run_merge_fixture(base, child_path)
                    checked += 1
        assert checked > 0, "no merge vectors were found"

    def _run_merge_fixture(self, base, child_path: Path) -> None:
        """Merge (or resolve) one `child-*.yaml` and compare with its expectation.

        A child that pins its base by digest (`extends: "base.yaml#sha256:..."`)
        goes through the resolver instead of a bare `merge()`, because the pin
        is only checked while resolving; the merged document that comes out is
        the same one `merge()` would produce for a matching pin.

        A fixture marked as expected-to-reject (see `expects_rejection`) must
        fail instead, and needs no `expected-*.yaml`.
        """
        expect_reject = expects_rejection(child_path)
        pinned = fixture_pins_its_base(child_path)

        if pinned:
            ok, result = resolve(
                parse_or_fail(child_path),
                source=str(child_path),
                loader=create_composite_loader(),
            )
        else:
            ok, result = True, merge(base, parse_or_fail(child_path))

        if expect_reject:
            assert not ok, f"{child_path}: expected rejection, got a merged document"
            return
        assert ok, f"{child_path}: {result}"

        expected_path = child_path.with_name(
            child_path.name.replace("child-", "expected-", 1)
        )
        if pinned and not expected_path.is_file():
            return  # a pin-only fixture: the outcome is the assertion
        expected = parse_or_fail(expected_path)
        assert (
            result.to_dict() == expected.to_dict()
        ), f"{child_path}: merged output differed from {expected_path.name}"

    def test_evaluator_fixtures(self):
        checked = 0
        for subdir in EVALUATION_DIRS:
            for fixture_path in iter_yaml_files(subdir):
                checked += 1
                # YAML 1.2 Core (the HushSpec profile): `on:`/`yes:` stay
                # strings, so the policy survives the re-dump below.
                raw = yaml.load(fixture_path.read_text(), Loader=CoreSafeLoader)
                assert raw["hushspec_test"] in SUPPORTED_TEST_VERSIONS
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
                    action = _action_from_case(case["action"], case.get("context"))
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

                    # `rule_trace` and `receipt` are asserted through the
                    # audited path, because a receipt is where both are
                    # published (receipt spec 4.3).
                    if "rule_trace" in expect or "receipt" in expect:
                        receipt = _fixed_receipt(
                            spec, action, case.get("context"), index
                        )
                        if "rule_trace" in expect:
                            _assert_rule_trace(
                                expect["rule_trace"], receipt["rule_trace"], label
                            )
                        if "receipt" in expect:
                            _assert_receipt_members(expect["receipt"], receipt, label)
        assert checked > 0, "no evaluator vectors were found"


def _fixed_receipt(
    spec, action: EvaluationAction, context: dict[str, Any] | None, case_index: int
) -> dict[str, Any]:
    """The format 0.2 receipt for one case under the pinned fixed inputs."""
    # The fixture's policy is already resolved here: one link, no chain.
    resolution = Resolution.from_resolved(spec)
    config = AuditConfig(
        enabled=True,
        include_rule_trace=True,
        # Off: an assertion must not depend on the machine running it.
        record_duration=False,
    )
    ctx = AuditContext(
        actor=Actor(
            agent_id="fixture-agent",
            session_id="fixture-session",
            principal="fixture@hushspec.dev",
            runtime="hushspec-conformance/0.2",
        ),
        enforcement=None,
        enforcement_mode="enforce",
        time_source=TimeSource.TRUSTED.value,
        clock=datetime.fromtimestamp(RECEIPT_CLOCK_MILLIS / 1000, tz=timezone.utc),
        receipt_id=deterministic_uuid_v7(RECEIPT_CLOCK_MILLIS, case_index),
        context=RuntimeContext.from_dict(context) if context is not None else None,
    )
    return receipt_to_dict(evaluate_audited(resolution, action, config, ctx))


def _render_trace_entry(entry: dict[str, Any]) -> str:
    """``rule_block:outcome[@rule_path]``, the spelling a mismatch reports."""
    rule_path = entry.get("rule_path")
    rendered = f"{entry['rule_block']}:{entry['outcome']}"
    return f"{rendered}@{rule_path}" if rule_path is not None else rendered


def _assert_rule_trace(
    expected: list[dict[str, Any]], actual: list[dict[str, Any]], label: str
) -> None:
    """In order, in full, and member-wise -- ``rule_path`` only where spelled."""
    rendered = ", ".join(_render_trace_entry(entry) for entry in actual)
    assert len(expected) == len(actual), (
        f"{label}: expected {len(expected)} rule_trace entries, "
        f"got {len(actual)} [{rendered}]"
    )
    for index, (want, got) in enumerate(zip(expected, actual)):
        assert want["rule_block"] == got["rule_block"], f"{label}: rule_trace[{index}]"
        assert want["outcome"] == got["outcome"], f"{label}: rule_trace[{index}]"
        if "rule_path" in want:
            assert want["rule_path"] == got.get("rule_path"), (
                f"{label}: rule_trace[{index}].rule_path"
            )


def _assert_receipt_members(
    expected: dict[str, Any], actual: dict[str, Any], label: str, path: str = ""
) -> None:
    """Nested objects are compared member-wise; everything else exactly."""
    for key, want in expected.items():
        if path == "" and key in RECEIPT_IGNORED_MEMBERS:
            continue
        at = key if path == "" else f"{path}.{key}"
        got = actual.get(key) if isinstance(actual, dict) else None
        if isinstance(want, dict):
            assert isinstance(got, dict), f"{label}: receipt.{at} is not an object"
            _assert_receipt_members(want, got, label, at)
            continue
        assert got == want, f"{label}: receipt.{at}: expected {want!r}, got {got!r}"


def _reject(fixture_path: Path) -> tuple[str | None, str]:
    """``(registry code, message)`` for a refused document, ``(None, "")`` otherwise.

    Parsing and validating are one refusal from a caller's point of view: some
    checks refuse at parse time and others at validate time, and which side of
    that line a given check falls on is an implementation detail the registry
    code deliberately abstracts over.
    """
    ok, result = parse(fixture_path.read_text())
    if not ok:
        return getattr(result, "code", None), str(result)
    validation = validate(result)
    if not validation.is_valid:
        return validation.errors[0].code, str(validation.errors[0])
    return None, ""


def _expected_rejection(fixture_path: Path) -> dict[str, Any] | None:
    """The `<name>.expect.yaml` sidecar beside an `invalid/` vector."""
    sidecar = fixture_path.with_suffix(".expect.yaml")
    if not sidecar.is_file():
        return None
    loaded = yaml.load(sidecar.read_text(), Loader=CoreSafeLoader)
    return loaded if isinstance(loaded, dict) else None


def parse_or_fail(path: Path):
    ok, result = parse(path.read_text())
    assert ok, f"{path}: {result}"
    return result


def parse_raw_or_fail(path: Path) -> dict[str, Any] | None:
    """The document as a plain mapping -- for fields the typed model normalizes."""
    raw = yaml.load(path.read_text(), Loader=CoreSafeLoader)
    return raw if isinstance(raw, dict) else None


class TestMergeFixtureConventions:
    """The runner's handling of digest-pinned and expected-to-reject vectors.

    These build the same shapes in a temp directory, so the runner is covered
    independently of which vectors ``fixtures/`` happens to carry, and a vector
    written in either marker convention is known to be honoured.
    """

    MERGE_BASE = 'hushspec: "0.1.0"\nname: base\nrules:\n  egress:\n    allow: ["a.com"]\n    default: block\n'
    MERGE_CHILD = 'hushspec: "0.1.0"\nname: child\nextends: "base.yaml#{pin}"\nrules:\n  egress:\n    allow: ["b.com"]\n    default: block\n'

    def _fixture(self, tmp_path: Path, pin: str) -> tuple[Any, Path]:
        base_path = tmp_path / "base.yaml"
        base_path.write_text(self.MERGE_BASE)
        child_path = tmp_path / "child-pinned.yaml"
        child_path.write_text(self.MERGE_CHILD.format(pin=pin))
        return parse_or_fail(base_path), child_path

    def _good_pin(self, tmp_path: Path) -> str:
        from hushspec import content_hash

        return content_hash(parse_or_fail(tmp_path / "base.yaml"))

    def test_a_matching_pin_resolves_and_matches_the_expected_document(self, tmp_path):
        base, child_path = self._fixture(tmp_path, "sha256:" + "0" * 64)
        child_path.write_text(self.MERGE_CHILD.format(pin=self._good_pin(tmp_path)))
        expected = merge(base, parse_or_fail(child_path))
        (tmp_path / "expected-pinned.yaml").write_text(
            yaml.safe_dump(expected.to_dict(), sort_keys=False)
        )

        TestSharedFixtures()._run_merge_fixture(base, child_path)

    def test_a_pin_only_vector_needs_no_expected_document(self, tmp_path):
        base, child_path = self._fixture(tmp_path, "sha256:" + "0" * 64)
        child_path.write_text(self.MERGE_CHILD.format(pin=self._good_pin(tmp_path)))

        TestSharedFixtures()._run_merge_fixture(base, child_path)

    def test_a_pin_mismatch_fails_unless_it_is_marked(self, tmp_path):
        base, child_path = self._fixture(tmp_path, "sha256:" + "0" * 64)

        with pytest.raises(AssertionError, match="expected rejection|digest pin"):
            TestSharedFixtures()._run_merge_fixture(base, child_path)

    @pytest.mark.parametrize(
        "marker",
        ["child-pinned.yaml.expect-reject", "child-pinned.expect-reject", "expect-reject"],
    )
    def test_a_marker_file_makes_a_pin_mismatch_the_expected_outcome(self, tmp_path, marker):
        base, child_path = self._fixture(tmp_path, "sha256:" + "0" * 64)
        (tmp_path / marker).write_text("")

        assert expects_rejection(child_path)
        TestSharedFixtures()._run_merge_fixture(base, child_path)

    @pytest.mark.parametrize(
        "meta",
        [
            {"reject": True},
            {"cases": {"child-pinned.yaml": {"reject": True}}},
            {"children": {"child-pinned": True}},
            {"fixtures": [{"child": "child-pinned.yaml", "reject": True}]},
        ],
    )
    def test_a_fixture_yaml_reject_flag_is_honoured(self, tmp_path, meta):
        base, child_path = self._fixture(tmp_path, "sha256:" + "0" * 64)
        (tmp_path / "fixture.yaml").write_text(yaml.safe_dump(meta))

        assert expects_rejection(child_path)
        TestSharedFixtures()._run_merge_fixture(base, child_path)

    def test_a_reject_flag_for_another_child_does_not_apply(self, tmp_path):
        base, child_path = self._fixture(tmp_path, "sha256:" + "0" * 64)
        (tmp_path / "fixture.yaml").write_text(
            yaml.safe_dump({"cases": {"child-other.yaml": {"reject": True}}})
        )

        assert not expects_rejection(child_path)
        # The mismatching pin, not some other assertion inside the runner.
        with pytest.raises(AssertionError, match="expected rejection|digest pin"):
            TestSharedFixtures()._run_merge_fixture(base, child_path)

    def test_a_vector_marked_reject_that_resolves_is_a_failure(self, tmp_path):
        base, child_path = self._fixture(tmp_path, "sha256:" + "0" * 64)
        child_path.write_text(self.MERGE_CHILD.format(pin=self._good_pin(tmp_path)))
        (tmp_path / "expect-reject").write_text("")

        with pytest.raises(AssertionError, match="expected rejection"):
            TestSharedFixtures()._run_merge_fixture(base, child_path)

    def test_unpinned_vectors_still_merge_without_resolving(self, tmp_path):
        base_path = tmp_path / "base.yaml"
        base_path.write_text(self.MERGE_BASE)
        base = parse_or_fail(base_path)
        # `extends: base` is not a loadable reference (the historical fixtures
        # use it as a label), so this would fail if the runner resolved it.
        child_path = tmp_path / "child-plain.yaml"
        child_path.write_text(
            'hushspec: "0.1.0"\nname: child\nextends: "base"\nrules:\n'
            '  egress:\n    allow: ["b.com"]\n    default: block\n'
        )
        assert not fixture_pins_its_base(child_path)
        (tmp_path / "expected-plain.yaml").write_text(
            yaml.safe_dump(merge(base, parse_or_fail(child_path)).to_dict(), sort_keys=False)
        )

        TestSharedFixtures()._run_merge_fixture(base, child_path)

    def test_per_case_subdirectories_are_discovered(self, tmp_path, monkeypatch):
        root = tmp_path / "core" / "merge"
        (root / "digest-pin").mkdir(parents=True)
        monkeypatch.setitem(globals(), "FIXTURES_ROOT", tmp_path)

        found = iter_fixture_dirs("core/merge")
        assert found == [root, root / "digest-pin"]


def _action_from_case(
    raw: dict[str, Any], context: dict[str, Any] | None = None
) -> EvaluationAction:
    """Build an EvaluationAction from a fixture case's raw ``action`` mapping.

    Field names are shared verbatim with schemas/hushspec-evaluator-test.v0
    .schema.json's Action/Origin/PostureInput/RuntimeContext $defs, so this is
    a direct keyword-argument passthrough per sub-object. The case-level
    ``context`` (core spec 3.13) rides on the action, in
    ``EvaluationAction.context``.
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
        url=raw.get("url"),
        network=raw.get("network"),
        timeout_ms=raw.get("timeout_ms"),
        context=RuntimeContext.from_dict(context) if context is not None else None,
    )
