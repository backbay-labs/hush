import dataclasses
import json

from hushspec.evaluate import Decision, EvaluationAction, EvaluationResult
from hushspec.observer import EvaluationObserver, ObservableEvaluator
from hushspec.parse import parse_or_raise

POLICY = """
hushspec: "0.1.0"
name: enforcement-fixture
rules:
  tool_access:
    block: ["dangerous_tool"]
    default: allow
"""


def test_evaluate_audited_never_sets_enforcement():
    from hushspec.receipt import AuditConfig, evaluate_audited

    spec = parse_or_raise(POLICY)
    action = EvaluationAction(type="tool_call", target="dangerous_tool")
    receipt = evaluate_audited(spec, action, AuditConfig())
    assert receipt.decision == Decision.DENY
    assert receipt.enforcement is None


def test_enforcement_summary_serializes_on_receipt():
    from hushspec.receipt import AuditConfig, EnforcementSummary, evaluate_audited

    spec = parse_or_raise(POLICY)
    action = EvaluationAction(type="tool_call", target="dangerous_tool")
    receipt = evaluate_audited(spec, action, AuditConfig())
    receipt.enforcement = EnforcementSummary(mode="monitor", outcome="would_block")

    payload = json.loads(json.dumps(dataclasses.asdict(receipt), default=str))
    assert payload["enforcement"] == {"mode": "monitor", "outcome": "would_block"}
    assert payload["decision"] == "deny"


def test_notify_evaluation_completed_emits_tagged_event():
    from hushspec.receipt import EnforcementSummary

    events = []

    class Capture(EvaluationObserver):
        def on_event(self, event):
            events.append(event)

    evaluator = ObservableEvaluator()
    evaluator.add_observer(Capture())
    action = EvaluationAction(type="tool_call", target="dangerous_tool")
    result = EvaluationResult(decision=Decision.DENY, matched_rule="rules.tool_access.block")
    summary = EnforcementSummary(mode="monitor", outcome="would_block")

    evaluator.notify_evaluation_completed(action, result, 42, enforcement=summary)

    assert len(events) == 1
    assert events[0]["type"] == "evaluation.completed"
    assert events[0]["duration_us"] == 42
    assert events[0]["enforcement"] is summary
    assert "receipt" not in events[0]
