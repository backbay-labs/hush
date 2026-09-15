from __future__ import annotations

import json

import pytest

from hushspec.evaluate import Decision
from hushspec.log import PolicyEvent
from hushspec.receipt import (
    ActionSummary,
    DecisionReceipt,
    EnforcementSummary,
    PolicySummary,
    RuleOutcome,
    RuleTraceEntry,
)
from hushspec.sinks import (
    CallbackSink,
    FileReceiptSink,
    FilteredSink,
    MultiSink,
    NullSink,
    ReceiptSink,
    StderrReceiptSink,
)



# Helpers



def _policy_summary() -> PolicySummary:
    return PolicySummary(
        name="test-policy",
        spec_version="0.1.0",
        content_hash="sha256:" + "ab" * 32,
    )


def _make_receipt(decision: Decision = Decision.ALLOW) -> DecisionReceipt:
    return DecisionReceipt(
        receipt_id="01994b7e-2c1a-7c3e-8f4a-0123456789ab",
        timestamp="2026-03-15T00:00:00.000Z",
        time_source="system",
        action=ActionSummary(type="tool_call", target="test_tool"),
        decision=decision,
        matched_rule="rules.tool_access.allow",
        reason="tool is explicitly allowed",
        rule_trace=[
            RuleTraceEntry(
                rule_block="tool_access",
                outcome=RuleOutcome.ALLOW,
                rule_path="rules.tool_access.allow",
                reason="tool is explicitly allowed",
                evaluated=True,
            ),
        ],
        policy=_policy_summary(),
        enforcement=EnforcementSummary("enforce", "allowed"),
        duration_us=42,
    )



# FileReceiptSink



class TestFileReceiptSink:
    def test_writes_json_lines(self, tmp_path):
        path = str(tmp_path / "receipts.jsonl")
        sink = FileReceiptSink(path)

        sink.send(_make_receipt(Decision.ALLOW))
        sink.send(_make_receipt(Decision.DENY))

        with open(path, "r") as f:
            lines = f.read().strip().split("\n")

        assert len(lines) == 2

        parsed1 = json.loads(lines[0])
        assert parsed1["receipt_id"] == "01994b7e-2c1a-7c3e-8f4a-0123456789ab"
        assert parsed1["receipt_version"] == "0.2"
        assert parsed1["enforcement"] == {"mode": "enforce", "outcome": "allowed"}

        parsed2 = json.loads(lines[1])
        assert parsed2["decision"] == "deny"

    def test_appends_not_overwrites(self, tmp_path):
        path = str(tmp_path / "receipts.jsonl")
        sink = FileReceiptSink(path)

        sink.send(_make_receipt())
        sink.send(_make_receipt())
        sink.send(_make_receipt())

        with open(path, "r") as f:
            lines = f.read().strip().split("\n")

        assert len(lines) == 3



# StderrReceiptSink



class TestStderrReceiptSink:
    def test_does_not_crash(self):
        sink = StderrReceiptSink()
        # Should not raise.
        sink.send(_make_receipt(Decision.ALLOW))
        sink.send(_make_receipt(Decision.DENY))



# FilteredSink



class TestFilteredSink:
    def test_deny_only_forwards_deny(self):
        collected: list[Decision] = []
        inner = CallbackSink(lambda r: collected.append(r.decision))
        filtered = FilteredSink.deny_only(inner)

        filtered.send(_make_receipt(Decision.ALLOW))
        filtered.send(_make_receipt(Decision.WARN))
        filtered.send(_make_receipt(Decision.DENY))
        filtered.send(_make_receipt(Decision.ALLOW))
        filtered.send(_make_receipt(Decision.DENY))

        assert len(collected) == 2
        assert collected[0] == Decision.DENY
        assert collected[1] == Decision.DENY

    def test_filters_by_custom_decisions(self):
        collected: list[Decision] = []
        inner = CallbackSink(lambda r: collected.append(r.decision))
        filtered = FilteredSink(inner, ["allow", "warn"])

        filtered.send(_make_receipt(Decision.ALLOW))
        filtered.send(_make_receipt(Decision.DENY))
        filtered.send(_make_receipt(Decision.WARN))

        assert len(collected) == 2
        assert collected[0] == Decision.ALLOW
        assert collected[1] == Decision.WARN



# MultiSink



class TestMultiSink:
    def test_sends_to_all_sinks(self):
        count1 = [0]
        count2 = [0]

        def inc1(_r):
            count1[0] += 1

        def inc2(_r):
            count2[0] += 1

        multi = MultiSink([CallbackSink(inc1), CallbackSink(inc2)])
        multi.send(_make_receipt())
        multi.send(_make_receipt())

        assert count1[0] == 2
        assert count2[0] == 2

    def test_continues_after_error(self):
        count = [0]

        def failing(_r):
            raise RuntimeError("test error")

        def counting(_r):
            count[0] += 1

        multi = MultiSink([CallbackSink(failing), CallbackSink(counting)])
        # Should not raise even though first sink fails.
        multi.send(_make_receipt())
        assert count[0] == 1



# CallbackSink



class TestCallbackSink:
    def test_invokes_callback(self):
        received: list[DecisionReceipt] = []
        sink = CallbackSink(lambda r: received.append(r))

        sink.send(_make_receipt(Decision.ALLOW))
        sink.send(_make_receipt(Decision.DENY))

        assert len(received) == 2
        assert received[0].decision == Decision.ALLOW
        assert received[1].decision == Decision.DENY



# NullSink



class TestNullSink:
    def test_does_not_crash(self):
        sink = NullSink()
        # Should not raise.
        sink.send(_make_receipt(Decision.ALLOW))
        sink.send(_make_receipt(Decision.DENY))
        sink.send(_make_receipt(Decision.WARN))



# ReceiptSink.record_policy_event



class TestPolicyEvents:
    def test_plain_sinks_ignore_a_policy_event(self):
        # Log spec section 6: only a hash-linked log writes the record; every
        # other sink carries receipts and must not break on one.
        received: list[DecisionReceipt] = []
        sink = CallbackSink(lambda r: received.append(r))
        sink.record_policy_event(PolicyEvent.loaded(_policy_summary()))
        NullSink().record_policy_event(PolicyEvent.loaded(_policy_summary()))
        assert received == []

    def test_multi_and_filtered_sinks_forward_it(self):
        seen: list[PolicyEvent] = []

        class Recording(ReceiptSink):
            def send(self, receipt):
                pass

            def record_policy_event(self, event):
                seen.append(event)

        event = PolicyEvent.loaded(_policy_summary())
        MultiSink([Recording(), Recording()]).record_policy_event(event)
        # A decision filter is about decisions; a policy event is not one, and
        # a log that drops it cannot map its receipts back to a policy at all.
        FilteredSink.deny_only(Recording()).record_policy_event(event)
        assert len(seen) == 3


class TestFilteredSinkConstruction:
    def test_a_predicate_is_refused_rather_than_silently_matching_nothing(self):
        # A callable is not a collection of decision names: accepting one would
        # make the sink drop every receipt without saying so.
        with pytest.raises(TypeError, match="collection of decision names"):
            FilteredSink(NullSink(), lambda receipt: True)

    def test_a_bare_string_is_refused(self):
        with pytest.raises(TypeError, match="collection of decision names"):
            FilteredSink(NullSink(), "deny")

    def test_any_collection_of_names_is_accepted(self):
        sink = FilteredSink(NullSink(), ("deny", "warn"))
        assert sink._decisions == frozenset({"deny", "warn"})


class TestMultiSinkFailureReporting:
    class _Exploding(ReceiptSink):
        def send(self, receipt):
            raise RuntimeError("sink is down")

    def test_a_failing_sink_is_counted_and_reported(self):
        seen = []
        multi = MultiSink(
            [self._Exploding(), NullSink()],
            on_error=lambda sink, exc: seen.append((type(sink).__name__, str(exc))),
        )
        multi.send(_make_receipt())
        assert multi.dropped == 1
        assert seen == [("_Exploding", "sink is down")]

    def test_a_failing_sink_does_not_stop_the_others(self):
        recorded = []
        multi = MultiSink([self._Exploding(), CallbackSink(recorded.append)])
        multi.send(_make_receipt())
        assert len(recorded) == 1
        assert multi.dropped == 1

    def test_a_broken_handler_is_not_fatal(self):
        def explode(sink, exc):
            raise RuntimeError("handler is down too")

        multi = MultiSink([self._Exploding()], on_error=explode)
        multi.send(_make_receipt())
        assert multi.dropped == 1
