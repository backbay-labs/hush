"""What a guard leaves behind: 0.2 receipts, an actor, and the
policy-in-effect records a hash-linked log needs (log spec section 6).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hushspec.evaluate import Decision, EvaluationAction
from hushspec.log import ChainedFileSink, EntryType, verify_log
from hushspec.middleware import (
    EnforcementConfig,
    HushGuard,
)
from hushspec.canonical import content_hash
from hushspec.parse import parse_or_raise
from hushspec.receipt import POLICY_UNVERIFIED_RULE, Actor, TimeSource
from hushspec.resolve import (
    ChainLink,
    PolicyVerificationError,
    Resolution,
    SignatureStatus,
)
from hushspec.sinks import CallbackSink

POLICY = """
hushspec: "0.1.0"
name: guard-evidence
metadata:
  policy_version: 7
rules:
  tool_access:
    block: ["dangerous_tool"]
    default: allow
"""

OTHER_POLICY = """
hushspec: "0.1.0"
name: guard-evidence-v2
rules:
  tool_access:
    block: ["dangerous_tool", "deploy"]
    default: allow
"""


def _receipts() -> tuple[list, CallbackSink]:
    collected: list = []
    return collected, CallbackSink(collected.append)


class TestReceiptShape:
    def test_a_guard_emits_a_0_2_receipt(self) -> None:
        collected, sink = _receipts()
        guard = HushGuard.from_yaml(POLICY, sink=sink)
        guard.gate(EvaluationAction(type="tool_call", target="dangerous_tool"))

        receipt = collected[-1]
        assert receipt.receipt_version == "0.2"
        assert receipt.policy.content_hash == guard.resolution.content_hash
        assert receipt.policy.spec_version == "0.1.0"
        assert receipt.policy.version == 7
        assert receipt.decision == Decision.DENY
        assert receipt.enforcement.mode == "enforce"
        assert receipt.enforcement.outcome == "blocked"
        assert receipt.rule_trace

    def test_the_actor_option_reaches_every_receipt(self) -> None:
        collected, sink = _receipts()
        actor = Actor(
            agent_id="deploy-bot-3",
            session_id="run-1",
            principal="alice@example.com",
            runtime="hushspec-python/0.2",
        )
        guard = HushGuard.from_yaml(POLICY, sink=sink, actor=actor)
        guard.gate(EvaluationAction(type="tool_call", target="anything"))
        assert collected[-1].actor == actor

    def test_the_time_source_option_reaches_every_receipt(self) -> None:
        collected, sink = _receipts()
        guard = HushGuard.from_yaml(
            POLICY, sink=sink, time_source=TimeSource.MONOTONIC_ADJUSTED
        )
        guard.gate(EvaluationAction(type="tool_call", target="anything"))
        assert collected[-1].time_source == "monotonic_adjusted"

    def test_the_default_time_source_is_system(self) -> None:
        collected, sink = _receipts()
        HushGuard.from_yaml(POLICY, sink=sink).gate(
            EvaluationAction(type="tool_call", target="anything")
        )
        assert collected[-1].time_source == "system"

    def test_a_time_source_outside_the_enum_is_refused(self) -> None:
        # Receipt spec 3.3 closes the enum, so an unknown value is refused when
        # the guard is built rather than written into receipts.
        with pytest.raises(ValueError, match="invalid time_source"):
            HushGuard.from_yaml(POLICY, time_source="approximate")

    def test_no_actor_means_no_actor_member(self) -> None:
        collected, sink = _receipts()
        HushGuard.from_yaml(POLICY, sink=sink).gate(
            EvaluationAction(type="tool_call", target="anything")
        )
        assert collected[-1].actor is None

    def test_a_confirmed_warn_is_recorded_as_confirmed(self) -> None:
        collected, sink = _receipts()
        warn_policy = POLICY.replace(
            'block: ["dangerous_tool"]', 'require_confirmation: ["risky"]'
        )
        guard = HushGuard.from_yaml(warn_policy, sink=sink, on_warn=lambda _r, _a: True)
        outcome = guard.gate(EvaluationAction(type="tool_call", target="risky"))
        assert outcome.proceed is True
        assert collected[-1].enforcement.outcome == "confirmed"


class TestPolicyEvents:
    def test_a_load_and_a_swap_are_recorded_in_the_log(self, tmp_path: Path) -> None:
        path = tmp_path / "log.jsonl"
        sink = ChainedFileSink.open(path)
        guard = HushGuard(parse_or_raise(POLICY), sink=sink)
        first_hash = guard.resolution.content_hash

        guard.gate(EvaluationAction(type="tool_call", target="anything"))
        guard.swap_policy(parse_or_raise(OTHER_POLICY))
        guard.gate(EvaluationAction(type="tool_call", target="deploy"))

        entries = [json.loads(line) for line in path.read_text().splitlines()]
        assert [entry["entry_type"] for entry in entries] == [
            EntryType.POLICY_LOADED.value,
            EntryType.RECEIPT.value,
            EntryType.POLICY_SWAPPED.value,
            EntryType.RECEIPT.value,
        ]
        assert entries[0]["policy_event"]["policy"]["content_hash"] == first_hash
        assert entries[0]["policy_event"]["sdk"]["name"] == "hushspec-python"
        swapped = entries[2]["policy_event"]
        assert swapped["previous_content_hash"] == first_hash
        assert swapped["policy"]["content_hash"] == guard.resolution.content_hash
        # Every receipt maps to the nearest preceding policy event.
        assert entries[1]["receipt"]["policy"]["content_hash"] == first_hash
        assert entries[3]["receipt"]["policy"]["content_hash"] != first_hash

        report = verify_log("log.jsonl", path.read_text())
        assert (report.entries, report.receipts, report.policy_events) == (4, 2, 2)

    def test_the_enforcement_mode_in_force_is_recorded(self, tmp_path: Path) -> None:
        path = tmp_path / "log.jsonl"
        HushGuard(
            parse_or_raise(POLICY),
            sink=ChainedFileSink.open(path),
            enforcement=EnforcementConfig(mode="monitor"),
        )
        entry = json.loads(path.read_text().splitlines()[0])
        assert entry["policy_event"]["enforcement_mode"] == "monitor"

    def test_a_sink_that_raises_does_not_break_the_load(self) -> None:
        from hushspec.sinks import ReceiptSink

        class Exploding(ReceiptSink):
            def send(self, receipt):
                raise RuntimeError("sink down")

            def record_policy_event(self, event):
                raise RuntimeError("sink down")

        guard = HushGuard.from_yaml(POLICY, sink=Exploding())
        assert guard.check(EvaluationAction(type="tool_call", target="anything")) is True

    def test_a_plain_receipt_sink_sees_no_policy_event(self) -> None:
        collected, sink = _receipts()
        HushGuard.from_yaml(POLICY, sink=sink)
        assert collected == []


class TestRefusedPolicy:
    def test_a_refused_load_emits_an_unverified_policy_receipt(
        self, tmp_path: Path
    ) -> None:
        # Signing spec 6.5: a runtime that requires signatures denies and
        # records the refusal rather than evaluating an unproven document.
        leaf = tmp_path / "leaf.yaml"
        leaf.write_text(POLICY)
        public_key = (
            Path(__file__).resolve().parents[3]
            / "fixtures/signing/keys/test-signing.pub.pem"
        ).read_text()
        collected, sink = _receipts()
        guard = HushGuard.from_file(
            str(leaf), require_signature=True, trusted_keys=[public_key], sink=sink
        )
        assert guard.refusal is not None

        outcome = guard.gate(EvaluationAction(type="tool_call", target="anything"))
        assert outcome.proceed is False

        receipt = collected[-1]
        assert receipt.receipt_version == "0.2"
        assert receipt.decision == Decision.DENY
        assert receipt.matched_rule == POLICY_UNVERIFIED_RULE
        assert receipt.rule_trace == []
        # The refused document's own hash, so an auditor can see which load
        # was refused; `signature.verified` is what says it was not proven.
        assert receipt.policy.content_hash == content_hash(parse_or_raise(POLICY))
        assert receipt.policy.signature.verified is False
        assert receipt.enforcement.outcome == "blocked"

    def test_a_refused_guard_records_no_policy_event(self, tmp_path: Path) -> None:
        # It loaded no policy, so there is none to declare in force.
        leaf = tmp_path / "leaf.yaml"
        leaf.write_text(POLICY)
        public_key = (
            Path(__file__).resolve().parents[3]
            / "fixtures/signing/keys/test-signing.pub.pem"
        ).read_text()
        path = tmp_path / "log.jsonl"
        HushGuard.from_file(
            str(leaf),
            require_signature=True,
            trusted_keys=[public_key],
            sink=ChainedFileSink.open(path),
        )
        assert not path.exists() or path.read_text() == ""


class TestAdoptedChain:
    """A resolution produced elsewhere is held to this guard's requirement.

    Signing spec 6.5 asks every non-``builtin:`` hop to prove itself, so a
    guard that adopts a provider's resolution re-checks the whole chain: a
    signed leaf on an unsigned base is not a proven policy.
    """

    @staticmethod
    def _chain(*links: ChainLink) -> Resolution:
        spec = parse_or_raise(POLICY)
        return Resolution(
            spec=spec,
            content_hash=content_hash(spec),
            chain=list(links),
            signature=links[-1].signature,
        )

    def test_a_signed_leaf_on_an_unsigned_base_is_refused(self) -> None:
        resolution = self._chain(
            ChainLink(source="base.yaml", content_hash="sha256:" + "0" * 64),
            ChainLink(
                source="leaf.yaml",
                content_hash="sha256:" + "1" * 64,
                signature=SignatureStatus(verified=True, key_id="sha256:" + "a" * 64),
            ),
        )
        guard = HushGuard(resolution, require_signature=True)

        assert guard.refusal is not None
        assert guard.refusal.verified is False
        assert guard.refusal.reason == "missing_signature"
        outcome = guard.gate(EvaluationAction(type="tool_call", target="anything"))
        assert outcome.proceed is False
        assert outcome.result.matched_rule == POLICY_UNVERIFIED_RULE

    def test_a_fully_signed_chain_is_adopted(self) -> None:
        signed = SignatureStatus(verified=True, key_id="sha256:" + "a" * 64)
        resolution = self._chain(
            ChainLink(
                source="base.yaml",
                content_hash="sha256:" + "0" * 64,
                signature=signed,
            ),
            ChainLink(
                source="leaf.yaml",
                content_hash="sha256:" + "1" * 64,
                signature=signed,
            ),
        )
        guard = HushGuard(resolution, require_signature=True)

        assert guard.refusal is None

    def test_a_builtin_base_signs_nothing(self) -> None:
        resolution = self._chain(
            ChainLink(source="builtin:default", content_hash="sha256:" + "0" * 64),
            ChainLink(
                source="leaf.yaml",
                content_hash="sha256:" + "1" * 64,
                signature=SignatureStatus(verified=True, key_id="sha256:" + "a" * 64),
            ),
        )
        guard = HushGuard(resolution, require_signature=True)

        assert guard.refusal is None

    def test_a_pinned_base_proves_itself(self) -> None:
        signed = SignatureStatus(verified=True, key_id="sha256:" + "a" * 64)
        resolution = self._chain(
            ChainLink(
                source="base.yaml",
                content_hash="sha256:" + "0" * 64,
                pinned=True,
            ),
            ChainLink(
                source="leaf.yaml",
                content_hash="sha256:" + "1" * 64,
                signature=signed,
            ),
        )
        guard = HushGuard(resolution, require_signature=True)

        assert guard.refusal is None
        outcome = guard.gate(EvaluationAction(type="tool_call", target="anything"))
        assert outcome.proceed is True

    def test_a_verified_swap_leaves_the_refused_state(self) -> None:
        signed = SignatureStatus(verified=True, key_id="sha256:" + "a" * 64)
        guard = HushGuard(
            self._chain(ChainLink(source="leaf.yaml", content_hash="sha256:" + "1" * 64)),
            require_signature=True,
        )
        assert guard.refusal is not None
        refused = guard.gate(EvaluationAction(type="tool_call", target="anything"))
        assert refused.proceed is False
        assert refused.result.matched_rule == POLICY_UNVERIFIED_RULE

        guard.swap_resolution(
            self._chain(
                ChainLink(
                    source="leaf.yaml",
                    content_hash="sha256:" + "1" * 64,
                    signature=signed,
                )
            )
        )

        assert guard.refusal is None
        assert guard.gate(EvaluationAction(type="tool_call", target="anything")).proceed is True

    def test_a_swap_refuses_an_unproven_base(self) -> None:
        signed = SignatureStatus(verified=True, key_id="sha256:" + "a" * 64)
        guard = HushGuard(
            self._chain(
                ChainLink(
                    source="leaf.yaml",
                    content_hash="sha256:" + "1" * 64,
                    signature=signed,
                )
            ),
            require_signature=True,
        )
        assert guard.refusal is None

        with pytest.raises(PolicyVerificationError):
            guard.swap_resolution(
                self._chain(
                    ChainLink(source="base.yaml", content_hash="sha256:" + "0" * 64),
                    ChainLink(
                        source="leaf.yaml",
                        content_hash="sha256:" + "1" * 64,
                        signature=signed,
                    ),
                )
            )
