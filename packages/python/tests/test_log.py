"""Hash-linked receipt log (``spec/hushspec-log.md``, format 0.1).

The chained sink, rotation, signing, verification, and the normative vectors
under ``fixtures/log/``: every file in ``valid/`` must verify, every file in
``invalid/`` must be rejected at the line its name ends with.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from hushspec.builtins import load_builtin
from hushspec.evaluate import EvaluationAction
from hushspec.log import (
    GENESIS_HASH,
    LOG_VERSION,
    SDK_NAME,
    ChainedFileSink,
    EntryType,
    LogError,
    LogVerifyOptions,
    PolicyEvent,
    SdkInfo,
    SinkError,
    compute_entry_hash,
    verify_log,
    verify_log_files,
    verify_logs,
)
from hushspec.receipt import (
    Actor,
    AuditConfig,
    AuditContext,
    TimeSource,
    deterministic_uuid_v7,
    evaluate_audited,
    policy_summary,
)
from hushspec.resolve import Resolution, VerifyOptions
from hushspec.signing import load_keyring

REPO_ROOT = Path(__file__).resolve().parents[3]
VECTORS = REPO_ROOT / "fixtures" / "log"
KEYS = REPO_ROOT / "fixtures" / "signing" / "keys"

CLOCK_MILLIS = 1_789_473_600_000
CLOCK = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)


def _keyring():
    return load_keyring((KEYS / "keyring.json").read_text())


def _signed_options() -> LogVerifyOptions:
    return LogVerifyOptions(
        require_signatures=False,
        keyring=_keyring(),
        verify=VerifyOptions(now=CLOCK, max_clock_skew_seconds=300),
    )


def _resolution() -> Resolution:
    return Resolution.from_resolved(load_builtin("default"), "builtin:default")


def _actions() -> list[EvaluationAction]:
    return [
        EvaluationAction(type="tool_call", target="read_file"),
        EvaluationAction(type="egress", target="api.github.com"),
        EvaluationAction(type="file_read", target="/home/me/.ssh/id_rsa"),
    ]


def _context(index: int) -> AuditContext:
    return AuditContext(
        actor=Actor(
            agent_id="fixture-agent",
            session_id="fixture-session",
            principal="fixture@hushspec.dev",
            runtime="hushspec-conformance/0.2",
        ),
        time_source=TimeSource.TRUSTED.value,
        clock=CLOCK,
        receipt_id=deterministic_uuid_v7(CLOCK_MILLIS, index),
    )


def _config() -> AuditConfig:
    return AuditConfig(enabled=True, include_rule_trace=True, record_duration=False)


def _write_basic(path: Path, *, signed: bool = False) -> ChainedFileSink:
    """A `policy_loaded` entry followed by three receipts, as the vectors are."""
    resolution = _resolution()
    sink = ChainedFileSink.open(path).with_clock(CLOCK)
    if signed:
        sink = sink.with_signer((KEYS / "test-signing.key.pem").read_text())
    sink.record_policy_event(
        PolicyEvent.loaded(
            policy_summary(resolution),
            "enforce",
            timestamp="2026-09-15T12:00:00.000Z",
            sdk=SdkInfo(name="hushspec-conformance", version="0.2"),
        )
    )
    for index, action in enumerate(_actions()):
        sink.send(evaluate_audited(resolution, action, _config(), _context(index)))
    return sink


# --------------------------------------------------------------------------- #
# Behaviour
# --------------------------------------------------------------------------- #


class TestChainedFileSink:
    def test_entries_link_and_verify(self, tmp_path: Path) -> None:
        path = tmp_path / "log.jsonl"
        sink = _write_basic(path)
        assert sink.head()[0] == 4

        entries = [json.loads(line) for line in path.read_text().splitlines()]
        assert len(entries) == 4
        assert entries[0]["seq"] == 1
        assert entries[0]["prev_hash"] == GENESIS_HASH
        assert entries[0]["entry_type"] == EntryType.POLICY_LOADED.value
        for before, after in zip(entries, entries[1:]):
            assert after["prev_hash"] == before["entry_hash"]
            assert after["seq"] == before["seq"] + 1
        for entry in entries:
            assert compute_entry_hash(entry) == entry["entry_hash"]
            assert entry["log_version"] == LOG_VERSION

        report = verify_log("log.jsonl", path.read_text())
        assert (report.entries, report.receipts, report.policy_events) == (4, 3, 1)
        assert report.last_entry_hash == entries[3]["entry_hash"]

    def test_reopening_continues_the_chain(self, tmp_path: Path) -> None:
        path = tmp_path / "log.jsonl"
        head = _write_basic(path).head()
        reopened = ChainedFileSink.open(path)
        assert reopened.head() == head
        reopened.send(
            evaluate_audited(_resolution(), _actions()[0], _config(), _context(9))
        )
        assert verify_log("log.jsonl", path.read_text()).entries == 5

    def test_two_sinks_on_one_file_extend_one_chain(self, tmp_path: Path) -> None:
        path = tmp_path / "log.jsonl"
        resolution = _resolution()
        first = ChainedFileSink.open(path).with_clock(CLOCK)
        second = ChainedFileSink.open(path).with_clock(CLOCK)

        first.record_policy_event(
            PolicyEvent.loaded(
                policy_summary(resolution),
                "enforce",
                timestamp="2026-09-15T12:00:00.000Z",
                sdk=SdkInfo(name="hushspec-conformance", version="0.2"),
            )
        )
        for index, action in enumerate(_actions()):
            sink = second if index % 2 == 0 else first
            sink.send(evaluate_audited(resolution, action, _config(), _context(index)))

        entries = [json.loads(line) for line in path.read_text().splitlines()]
        assert [entry["seq"] for entry in entries] == [1, 2, 3, 4]
        report = verify_log("log.jsonl", path.read_text())
        assert report.entries == 4
        assert report.last_seq == 4
        assert second.head() == (4, entries[3]["entry_hash"])

    def test_rotation_carries_the_chain_into_the_next_file(self, tmp_path: Path) -> None:
        first, second = tmp_path / "log-1.jsonl", tmp_path / "log-2.jsonl"
        sink = _write_basic(first)
        last_hash = sink.head()[1]

        started = sink.rotate(second)
        assert started.seq == 1
        assert started.prev_hash == last_hash
        assert started.log_started.previous_entry_hash == last_hash
        assert started.log_started.previous_file == "log-1.jsonl"
        sink.send(evaluate_audited(_resolution(), _actions()[1], _config(), _context(7)))

        report = verify_log_files([first, second])
        assert (report.files, report.entries) == (2, 6)

        # The second file alone verifies from its log_started link; it just
        # cannot vouch for what came before.
        assert verify_log("log-2", second.read_text()).entries == 2

        # Given out of order, the link breaks on the first line.
        with pytest.raises(LogError) as caught:
            verify_log_files([second, first])
        assert caught.value.line == 1

    def test_rotation_links_the_last_entry_on_disk(self, tmp_path: Path) -> None:
        first, second = tmp_path / "log-1.jsonl", tmp_path / "log-2.jsonl"
        resolution = _resolution()
        rotating = ChainedFileSink.open(first).with_clock(CLOCK)
        other = ChainedFileSink.open(first).with_clock(CLOCK)
        rotating.record_policy_event(
            PolicyEvent.loaded(
                policy_summary(resolution),
                "enforce",
                timestamp="2026-09-15T12:00:00.000Z",
                sdk=SdkInfo(name="hushspec-conformance", version="0.2"),
            )
        )
        # The other writer extends the file after this sink last wrote to it.
        other.send(evaluate_audited(resolution, _actions()[0], _config(), _context(1)))
        on_disk = other.head()[1]
        assert rotating.head()[1] != on_disk

        started = rotating.rotate(second)
        assert started.prev_hash == on_disk
        assert started.log_started.previous_entry_hash == on_disk
        assert verify_log_files([first, second]).entries == 3

    def test_a_chain_rotated_at_genesis_verifies(self, tmp_path: Path) -> None:
        """A writer that rotates before writing anything carries the genesis
        hash into the new file. The link is recorded all the same, so a
        verifier given both files sees one chain."""
        first, second = tmp_path / "log-1.jsonl", tmp_path / "log-2.jsonl"
        first.write_text("")
        sink = ChainedFileSink.open(first).with_clock(CLOCK)

        started = sink.rotate(second)
        assert started.prev_hash == GENESIS_HASH
        assert started.log_started.previous_entry_hash == GENESIS_HASH
        sink.send(evaluate_audited(_resolution(), _actions()[0], _config(), _context(0)))

        report = verify_log_files([first, second])
        assert (report.files, report.entries) == (2, 2)

    def test_an_unknown_field_inside_a_policy_event_is_a_break(
        self, tmp_path: Path
    ) -> None:
        """The log-entry schema closes every object it defines, not only the
        ones the entry names directly."""
        path = tmp_path / "log.jsonl"
        _write_basic(path)
        first = json.loads(path.read_text().splitlines()[0])
        first["policy_event"]["policy"]["rogue"] = 1
        with pytest.raises(LogError) as caught:
            verify_log("log.jsonl", json.dumps(first))
        assert "rogue" in caught.value.message

    def test_a_rotation_that_cannot_be_written_keeps_the_old_file(
        self, tmp_path: Path
    ) -> None:
        """The sink may move to the new file only once the ``log_started``
        entry that links it is on disk, or the next receipt becomes line 1 of a
        file that continues nothing."""
        first = tmp_path / "log-1.jsonl"
        sink = _write_basic(first)
        head = sink.head()

        # A regular file where the new log's directory would be: neither the
        # file nor its lock can be created there.
        blocker = tmp_path / "not-a-directory"
        blocker.write_text("")
        with pytest.raises(SinkError):
            sink.rotate(blocker / "log-2.jsonl")

        assert sink.path == first
        assert sink.head() == head

        # The old file is still current, so the next receipt continues it.
        sink.send(evaluate_audited(_resolution(), _actions()[0], _config(), _context(9)))
        assert verify_log_files([first]).entries == 5

    def test_a_log_is_created_together_with_its_parent_directory(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "logs" / "audit.jsonl"
        sink = ChainedFileSink.open(path).with_clock(CLOCK)
        sink.send(evaluate_audited(_resolution(), _actions()[0], _config(), _context(0)))
        assert verify_log_files([path]).entries == 1

    def test_rotating_into_an_existing_file_is_refused(self, tmp_path: Path) -> None:
        first, second = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
        sink = _write_basic(first)
        second.write_text("")
        with pytest.raises(SinkError, match="cannot rotate into existing file"):
            sink.rotate(second)

    def test_signed_entries_verify_with_the_keyring_and_fail_without(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "log.jsonl"
        _write_basic(path, signed=True)
        text = path.read_text()

        options = LogVerifyOptions(
            require_signatures=True,
            keyring=_keyring(),
            verify=VerifyOptions(now=CLOCK, max_clock_skew_seconds=300),
        )
        report = verify_log("log.jsonl", text, options)
        assert report.signed == 4
        assert report.verified_signatures == 4

        with pytest.raises(LogError) as caught:
            verify_log(
                "log.jsonl", text, LogVerifyOptions(require_signatures=True)
            )
        assert "no_keyring" in caught.value.message

        revoked = LogVerifyOptions(
            require_signatures=True,
            keyring=load_keyring((KEYS / "keyring-revoked.json").read_text()),
            verify=VerifyOptions(now=CLOCK, max_clock_skew_seconds=300),
        )
        with pytest.raises(LogError) as caught:
            verify_log("log.jsonl", text, revoked)
        assert caught.value.line == 1
        assert "signature" in caught.value.message

    def test_unsigned_entries_fail_when_signatures_are_required(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "log.jsonl"
        _write_basic(path)
        options = LogVerifyOptions(require_signatures=True, keyring=_keyring())
        with pytest.raises(LogError) as caught:
            verify_log("log.jsonl", path.read_text(), options)
        assert caught.value.line == 1
        assert "entry_unsigned" in caught.value.message

    def test_this_sdk_names_itself_in_a_policy_event(self, tmp_path: Path) -> None:
        path = tmp_path / "log.jsonl"
        sink = ChainedFileSink.open(path).with_clock(CLOCK)
        entry = sink.record_policy_event(
            PolicyEvent.loaded(policy_summary(_resolution()), "monitor")
        )
        assert entry.policy_event.sdk.name == SDK_NAME == "hushspec-python"
        written = json.loads(path.read_text().splitlines()[0])
        assert written["policy_event"]["enforcement_mode"] == "monitor"
        assert written["policy_event"]["sdk"]["name"] == "hushspec-python"
        assert verify_log("log.jsonl", path.read_text()).policy_events == 1

    def test_a_swap_names_the_policy_it_replaced(self, tmp_path: Path) -> None:
        path = tmp_path / "log.jsonl"
        sink = ChainedFileSink.open(path).with_clock(CLOCK)
        previous = "sha256:" + "11" * 32
        entry = sink.record_policy_event(
            PolicyEvent.swapped(policy_summary(_resolution()), "enforce", previous)
        )
        assert entry.entry_type == EntryType.POLICY_SWAPPED.value
        assert entry.policy_event.previous_content_hash == previous
        assert verify_log("log.jsonl", path.read_text()).policy_events == 1


class TestTampering:
    def _lines(self, tmp_path: Path) -> list[str]:
        path = tmp_path / "log.jsonl"
        _write_basic(path)
        return path.read_text().splitlines()

    def test_an_edited_line_is_caught_at_that_line(self, tmp_path: Path) -> None:
        lines = self._lines(tmp_path)
        edited = lines[2].replace('"allow"', '"deny"', 1)
        text = "\n".join([lines[0], lines[1], edited, lines[3]])
        with pytest.raises(LogError) as caught:
            verify_log("t", text)
        assert caught.value.line == 3
        assert "entry_hash" in caught.value.message

    def test_a_deleted_line_is_caught(self, tmp_path: Path) -> None:
        lines = self._lines(tmp_path)
        with pytest.raises(LogError) as caught:
            verify_log("t", "\n".join([lines[0], lines[2], lines[3]]))
        assert caught.value.line == 2
        assert "sequence gap" in caught.value.message

    def test_reordering_is_caught(self, tmp_path: Path) -> None:
        lines = self._lines(tmp_path)
        with pytest.raises(LogError) as caught:
            verify_log("t", "\n".join([lines[0], lines[2], lines[1], lines[3]]))
        assert caught.value.line == 2

    def test_truncation_is_not_detectable_from_the_file_alone(
        self, tmp_path: Path
    ) -> None:
        # Log spec section 9: detecting truncation needs an external anchor.
        lines = self._lines(tmp_path)
        assert verify_log("t", "\n".join(lines[:2])).entries == 2

    def test_payload_must_match_entry_type(self, tmp_path: Path) -> None:
        lines = self._lines(tmp_path)
        entry = json.loads(lines[0])
        entry["entry_type"] = "receipt"
        with pytest.raises(LogError) as caught:
            verify_log("t", json.dumps(entry))
        assert "payload" in caught.value.message

    def test_an_unknown_field_is_a_break(self, tmp_path: Path) -> None:
        lines = self._lines(tmp_path)
        entry = json.loads(lines[0])
        entry["extra"] = 1
        with pytest.raises(LogError) as caught:
            verify_log("t", json.dumps(entry))
        assert "unknown field" in caught.value.message

    def test_an_unknown_log_version_is_rejected(self, tmp_path: Path) -> None:
        lines = self._lines(tmp_path)
        entry = json.loads(lines[0])
        entry["log_version"] = "0.2"
        with pytest.raises(LogError) as caught:
            verify_log("t", json.dumps(entry))
        assert "log_version" in caught.value.message


# --------------------------------------------------------------------------- #
# Vectors
# --------------------------------------------------------------------------- #

VALID_VECTORS = sorted((VECTORS / "valid").glob("*.jsonl"))
INVALID_VECTORS = sorted((VECTORS / "invalid").glob("*.jsonl"))


def test_the_vector_directories_are_populated() -> None:
    assert len(VALID_VECTORS) >= 4
    assert len(INVALID_VECTORS) >= 5


@pytest.mark.parametrize(
    "path", [p for p in VALID_VECTORS if not p.name.startswith("rotated-")],
    ids=lambda p: p.stem,
)
def test_valid_vector_verifies(path: Path) -> None:
    report = verify_log(path.name, path.read_text(), _signed_options())
    # A verifier that walked nothing would also not raise.
    assert report.entries > 0
    assert report.files == 1
    assert report.last_entry_hash


def test_the_rotated_pair_verifies_in_order() -> None:
    first = (VECTORS / "valid" / "rotated-1.jsonl").read_text()
    second = (VECTORS / "valid" / "rotated-2.jsonl").read_text()
    report = verify_logs([("rotated-1", first), ("rotated-2", second)])
    assert report.files == 2
    # And the later file alone verifies from its log_started link.
    assert verify_log("rotated-2", second).entries >= 1


@pytest.mark.parametrize("path", INVALID_VECTORS, ids=lambda p: p.stem)
def test_invalid_vector_is_rejected_at_the_named_line(path: Path) -> None:
    # The file name ends with the line a verifier must identify as the break.
    expected_line = int(path.stem.rsplit("-", 1)[-1])
    with pytest.raises(LogError) as caught:
        verify_log(path.name, path.read_text(), _signed_options())
    assert caught.value.line == expected_line, caught.value.message


class TestMalformedEntriesAreRejectedNotRaised:
    """An entry's hash covers whatever JSON the line held.

    A line can therefore be hash-consistent and still carry a member of the
    wrong shape. Every such line must come back as a :class:`LogError` naming
    it, never as an exception out of the verifier.
    """

    def _rewritten(self, tmp_path: Path, mutate) -> str:
        path = tmp_path / "log.jsonl"
        _write_basic(path)
        lines = [line for line in path.read_text().split("\n") if line.strip()]
        entry = json.loads(lines[-1])
        mutate(entry)
        # Re-hash so the line passes the chain and hash checks and reaches the
        # payload reads this is about.
        entry.pop("entry_hash", None)
        entry["entry_hash"] = compute_entry_hash(entry)
        lines[-1] = json.dumps(entry)
        return "\n".join(lines) + "\n"

    @pytest.mark.parametrize(
        "member", ["receipt", "policy_event", "log_started", "signature"]
    )
    def test_a_non_object_payload_member_is_a_log_error(
        self, tmp_path: Path, member: str
    ) -> None:
        def mutate(entry):
            entry[member] = "not-an-object"

        text = self._rewritten(tmp_path, mutate)
        with pytest.raises(LogError, match=f"{member} is not a JSON object"):
            verify_log("log.jsonl", text)

    def test_a_boolean_seq_is_not_an_integer(self, tmp_path: Path) -> None:
        # `True == 1` in Python, so a bare equality check would accept this.
        def mutate(entry):
            entry["seq"] = True

        text = self._rewritten(tmp_path, mutate)
        with pytest.raises(LogError, match="is not an integer"):
            verify_log("log.jsonl", text)

    def test_a_tail_with_an_unknown_member_is_refused(self, tmp_path: Path) -> None:
        """Rust and Go parse the tail strictly before continuing it; a line this
        SDK extended but a verifier refuses would leave an unreadable log."""
        path = tmp_path / "log.jsonl"
        _write_basic(path)
        lines = [line for line in path.read_text().split("\n") if line.strip()]
        last = json.loads(lines[-1])
        for mutation in (
            {"rogue": 1},
            {"log_started": {"timestamp": "2026-09-15T12:00:00.000Z", "rogue": 1}},
            {"receipt": "not an object"},
        ):
            lines[-1] = json.dumps({**last, **mutation})
            path.write_text("\n".join(lines) + "\n")
            with pytest.raises(SinkError, match="is not a log entry"):
                ChainedFileSink.open(path)

    def test_a_malformed_tail_is_refused_rather_than_coerced(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "log.jsonl"
        _write_basic(path)
        lines = [line for line in path.read_text().split("\n") if line.strip()]
        entry = json.loads(lines[-1])
        entry["entry_hash"] = 5
        lines[-1] = json.dumps(entry)
        path.write_text("\n".join(lines) + "\n")
        # str(5) would seed the next entry's prev_hash with "5" and fork the
        # chain for every later verifier.
        with pytest.raises(SinkError, match="non-string entry_hash"):
            ChainedFileSink.open(path)
