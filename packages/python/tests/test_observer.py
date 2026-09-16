import io
import json

from hushspec.evaluate import Decision, EvaluationAction
from hushspec.middleware import HushGuard
from hushspec.observer import (
    ConsoleObserver,
    EvaluationObserver,
    JsonLineObserver,
    MetricsCollector,
    ObservableEvaluator,
)
from hushspec.parse import parse_or_raise
from hushspec.schema import HushSpec
from hushspec.sinks import MultiSink, ReceiptSink



# Helpers



def minimal_spec() -> HushSpec:
    return parse_or_raise(
        'hushspec: "0.1.0"\nname: test-policy\n'
    )


def spec_with_tool_access() -> HushSpec:
    return parse_or_raise(
        """
hushspec: "0.1.0"
name: tool-policy
rules:
  tool_access:
    allow: ["read_file", "write_file"]
    block: ["dangerous_tool"]
    default: block
"""
    )


class EventCollector(EvaluationObserver):
    def __init__(self):
        self.events = []

    def on_event(self, event):
        self.events.append(event)


class FailingSink(ReceiptSink):
    """Refuses everything it is handed, and says so."""

    def send(self, receipt):
        raise OSError("no space left on device")

    def record_policy_event(self, event):
        raise OSError("no space left on device")



# ObservableEvaluator



class TestObservableEvaluator:
    def test_emits_evaluation_completed_events(self):
        evaluator = ObservableEvaluator()
        observer = EventCollector()
        evaluator.add_observer(observer)

        spec = minimal_spec()
        action = EvaluationAction(type="tool_call", target="test")
        result = evaluator.evaluate(spec, action)

        assert result.decision == Decision.ALLOW
        assert len(observer.events) == 1
        event = observer.events[0]
        assert event["type"] == "evaluation.completed"
        assert event["action"] is action
        assert event["result"] is result
        assert isinstance(event["duration_us"], int)
        assert "T" in event["timestamp"]

    def test_emits_correct_decision_for_denied_tool(self):
        evaluator = ObservableEvaluator()
        observer = EventCollector()
        evaluator.add_observer(observer)

        spec = spec_with_tool_access()
        action = EvaluationAction(type="tool_call", target="dangerous_tool")
        result = evaluator.evaluate(spec, action)

        assert result.decision == Decision.DENY
        event = observer.events[0]
        assert event["result"].decision == Decision.DENY

    def test_emits_policy_loaded_event(self):
        evaluator = ObservableEvaluator()
        observer = EventCollector()
        evaluator.add_observer(observer)

        evaluator.notify_policy_loaded("test-policy", "abc123")

        assert len(observer.events) == 1
        event = observer.events[0]
        assert event["type"] == "policy.loaded"
        assert event["policy_name"] == "test-policy"
        assert event["content_hash"] == "abc123"

    def test_emits_policy_load_failed_event(self):
        evaluator = ObservableEvaluator()
        observer = EventCollector()
        evaluator.add_observer(observer)

        evaluator.notify_policy_load_failed("file not found", "/path/to/missing.yaml")

        assert len(observer.events) == 1
        event = observer.events[0]
        assert event["type"] == "policy.load_failed"
        assert event["error"] == "file not found"
        assert event["source"] == "/path/to/missing.yaml"

    def test_emits_policy_reloaded_event(self):
        evaluator = ObservableEvaluator()
        observer = EventCollector()
        evaluator.add_observer(observer)

        evaluator.notify_policy_reloaded("new-policy", "newhash", "oldhash")

        assert len(observer.events) == 1
        event = observer.events[0]
        assert event["type"] == "policy.reloaded"
        assert event["policy_name"] == "new-policy"
        assert event["content_hash"] == "newhash"
        assert event["previous_hash"] == "oldhash"

    def test_observer_errors_do_not_crash_evaluator(self):
        evaluator = ObservableEvaluator()

        class CrashingObserver(EvaluationObserver):
            def on_event(self, event):
                raise RuntimeError("observer crash")

        safe_observer = EventCollector()
        evaluator.add_observer(CrashingObserver())
        evaluator.add_observer(safe_observer)

        spec = minimal_spec()
        action = EvaluationAction(type="tool_call", target="test")
        result = evaluator.evaluate(spec, action)

        assert result.decision == Decision.ALLOW
        assert len(safe_observer.events) == 1

    def test_remove_observer_stops_notifications(self):
        evaluator = ObservableEvaluator()
        observer = EventCollector()
        evaluator.add_observer(observer)

        spec = minimal_spec()
        evaluator.evaluate(spec, EvaluationAction(type="tool_call", target="test"))
        assert len(observer.events) == 1

        evaluator.remove_observer(observer)
        evaluator.evaluate(spec, EvaluationAction(type="tool_call", target="test"))
        assert len(observer.events) == 1  # no new event



# MetricsCollector



class TestMetricsCollector:
    def test_tracks_counts_by_decision_type(self):
        evaluator = ObservableEvaluator()
        metrics = MetricsCollector()
        evaluator.add_observer(metrics)

        spec_allow = minimal_spec()
        spec_deny = spec_with_tool_access()

        evaluator.evaluate(spec_allow, EvaluationAction(type="tool_call", target="test"))
        evaluator.evaluate(spec_allow, EvaluationAction(type="tool_call", target="test"))
        evaluator.evaluate(spec_deny, EvaluationAction(type="tool_call", target="dangerous_tool"))

        assert metrics.get_count("evaluate.allow") == 2
        assert metrics.get_count("evaluate.deny") == 1
        assert metrics.get_count("evaluation.completed") == 3
        assert metrics.get_total_evaluations() == 3

    def test_computes_average_duration(self):
        metrics = MetricsCollector()
        metrics.on_event({
            "type": "evaluation.completed",
            "timestamp": "2026-01-01T00:00:00Z",
            "action": {"type": "tool_call"},
            "result": {"decision": "allow"},
            "duration_us": 100,
        })
        metrics.on_event({
            "type": "evaluation.completed",
            "timestamp": "2026-01-01T00:00:00Z",
            "action": {"type": "tool_call"},
            "result": {"decision": "allow"},
            "duration_us": 200,
        })

        assert metrics.get_average_duration_us() == 150.0

    def test_computes_p99_duration(self):
        metrics = MetricsCollector()
        for i in range(1, 101):
            metrics.on_event({
                "type": "evaluation.completed",
                "timestamp": "2026-01-01T00:00:00Z",
                "action": {"type": "tool_call"},
                "result": {"decision": "allow"},
                "duration_us": i,
            })

        assert metrics.get_p99_duration_us() == 100

    def test_returns_zero_for_empty_metrics(self):
        metrics = MetricsCollector()
        assert metrics.get_average_duration_us() == 0.0
        assert metrics.get_p99_duration_us() == 0.0
        assert metrics.get_total_evaluations() == 0
        assert metrics.get_count("nonexistent") == 0

    def test_to_prometheus_outputs_valid_format(self):
        evaluator = ObservableEvaluator()
        metrics = MetricsCollector()
        evaluator.add_observer(metrics)

        evaluator.evaluate(minimal_spec(), EvaluationAction(type="tool_call", target="test"))
        evaluator.evaluate(
            spec_with_tool_access(),
            EvaluationAction(type="tool_call", target="dangerous_tool"),
        )

        output = metrics.to_prometheus()
        assert "hushspec_evaluate_allow_total 1" in output
        assert "hushspec_evaluate_deny_total 1" in output
        assert "hushspec_evaluation_completed_total 2" in output
        assert "hushspec_evaluate_duration_us_avg" in output
        assert "hushspec_evaluate_duration_us_p99" in output

    def test_reset_clears_all_data(self):
        evaluator = ObservableEvaluator()
        metrics = MetricsCollector()
        evaluator.add_observer(metrics)

        evaluator.evaluate(minimal_spec(), EvaluationAction(type="tool_call", target="test"))
        assert metrics.get_total_evaluations() == 1

        metrics.reset()
        assert metrics.get_total_evaluations() == 0
        assert metrics.get_count("evaluate.allow") == 0
        assert metrics.to_prometheus() == ""



# JsonLineObserver



class TestJsonLineObserver:
    def test_writes_json_lines_to_stream(self):
        stream = io.StringIO()
        evaluator = ObservableEvaluator()
        json_observer = JsonLineObserver(stream)
        evaluator.add_observer(json_observer)

        evaluator.evaluate(minimal_spec(), EvaluationAction(type="tool_call", target="test"))

        output = stream.getvalue()
        lines = [l for l in output.strip().split("\n") if l]
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["type"] == "evaluation.completed"



# ConsoleObserver



class TestConsoleObserver:
    def test_deny_only_filters_non_deny_events(self, capsys):
        observer = ConsoleObserver(level="deny_only")
        evaluator = ObservableEvaluator()
        evaluator.add_observer(observer)

        # allow event -- should be filtered
        evaluator.evaluate(minimal_spec(), EvaluationAction(type="tool_call", target="test"))
        captured = capsys.readouterr()
        assert captured.err == ""

        # deny event -- should be logged
        evaluator.evaluate(
            spec_with_tool_access(),
            EvaluationAction(type="tool_call", target="dangerous_tool"),
        )
        captured = capsys.readouterr()
        assert "[hushspec]" in captured.err

    def test_all_level_logs_all_events(self, capsys):
        observer = ConsoleObserver(level="all")
        evaluator = ObservableEvaluator()
        evaluator.add_observer(observer)

        evaluator.evaluate(minimal_spec(), EvaluationAction(type="tool_call", target="test"))
        captured = capsys.readouterr()
        assert "[hushspec]" in captured.err

    def test_logs_policy_lifecycle_events(self, capsys):
        observer = ConsoleObserver(level="deny_only")
        evaluator = ObservableEvaluator()
        evaluator.add_observer(observer)

        evaluator.notify_policy_loaded("test", "hash")
        captured = capsys.readouterr()
        assert "[hushspec]" in captured.err



# HushGuard observer integration



ALLOW_POLICY = """
hushspec: "0.1.0"
name: allow-all
rules:
  tool_access:
    default: allow
"""

DENY_POLICY = """
hushspec: "0.1.0"
name: deny-tools
rules:
  tool_access:
    block: ["dangerous_tool"]
    default: block
"""


class TestHushGuardObserverIntegration:
    def test_emits_evaluation_events_when_observer_set(self):
        observer = EventCollector()
        guard = HushGuard.from_yaml(ALLOW_POLICY, observer=observer)

        assert any(e["type"] == "policy.loaded" for e in observer.events)

        guard.check(EvaluationAction(type="tool_call", target="test"))
        assert any(e["type"] == "evaluation.completed" for e in observer.events)

    def test_emits_policy_reloaded_on_swap_policy(self):
        observer = EventCollector()
        guard = HushGuard.from_yaml(ALLOW_POLICY, observer=observer)

        new_policy = parse_or_raise(DENY_POLICY)
        guard.swap_policy(new_policy)

        reload_events = [e for e in observer.events if e["type"] == "policy.reloaded"]
        assert len(reload_events) == 1
        re = reload_events[0]
        assert re["policy_name"] == "deny-tools"
        assert re["previous_hash"] is not None
        assert re["content_hash"] is not None
        assert re["content_hash"] != re["previous_hash"]

    def test_guard_without_observer_works_normally(self):
        guard = HushGuard.from_yaml(ALLOW_POLICY)
        assert guard.check(EvaluationAction(type="tool_call", target="test")) is True

    def test_a_sink_that_refuses_a_receipt_leaves_the_decision_and_raises_sink_error(self):
        observer = EventCollector()
        guard = HushGuard.from_yaml(DENY_POLICY, observer=observer, sink=FailingSink())
        observer.events.clear()

        assert guard.check(EvaluationAction(type="tool_call", target="dangerous_tool")) is False
        assert guard.check(EvaluationAction(type="tool_call", target="anything")) is False

        errors = [e for e in observer.events if e["type"] == "sink.error"]
        assert len(errors) == 2
        assert errors[0]["error"] == "no space left on device"
        assert errors[0]["source"] == "FailingSink"
        assert errors[0]["timestamp"].endswith("Z")

    def test_a_sink_that_refuses_the_policy_event_raises_sink_error(self):
        observer = EventCollector()
        HushGuard.from_yaml(ALLOW_POLICY, observer=observer, sink=FailingSink())

        errors = [e for e in observer.events if e["type"] == "sink.error"]
        assert len(errors) == 1
        assert errors[0]["error"] == "no space left on device"
        assert errors[0]["source"] == "FailingSink"

    def test_a_sink_that_refuses_behind_a_multi_sink_names_the_child(self):
        recorded: list[object] = []

        class Recording(ReceiptSink):
            def send(self, receipt):
                recorded.append(receipt)

        observer = EventCollector()
        guard = HushGuard.from_yaml(
            DENY_POLICY,
            observer=observer,
            sink=MultiSink([FailingSink(), Recording()]),
        )
        observer.events.clear()

        assert guard.check(EvaluationAction(type="tool_call", target="dangerous_tool")) is False
        assert len(recorded) == 1

        errors = [e for e in observer.events if e["type"] == "sink.error"]
        assert len(errors) == 1
        assert errors[0]["error"] == "sink FailingSink: no space left on device"
        assert errors[0]["source"] == "MultiSink"



# Module-level exports



class TestExports:
    def test_the_top_level_names_are_the_observer_module_s_own(self):
        import hushspec
        from hushspec import observer as observer_module

        for name in (
            "EvaluationObserver",
            "ObservableEvaluator",
            "JsonLineObserver",
            "ConsoleObserver",
            "MetricsCollector",
        ):
            assert name in hushspec.__all__
            assert getattr(hushspec, name) is getattr(observer_module, name)
