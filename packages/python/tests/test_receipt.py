from __future__ import annotations

import re

from hushspec import (
    Decision,
    EvaluationAction,
    evaluate,
    HUSHSPEC_VERSION,
)
from hushspec.receipt import (
    AuditConfig,
    DecisionReceipt,
    evaluate_audited,
    compute_policy_hash,
)
from hushspec.generated_models import (
    EgressRule,
    HushSpec,
    Rules,
    ShellCommandsRule,
    ToolAccessRule,
    DefaultAction,
)

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _minimal_spec() -> HushSpec:
    return HushSpec(hushspec="0.1.0", name="test-policy")


def _spec_with_tool_access() -> HushSpec:
    return HushSpec(
        hushspec="0.1.0",
        name="tool-policy",
        rules=Rules(
            tool_access=ToolAccessRule(
                allow=["read_file", "write_file"],
                block=["dangerous_tool"],
                default=DefaultAction.BLOCK,
            ),
        ),
    )


def _enabled_config() -> AuditConfig:
    return AuditConfig(enabled=True, include_rule_trace=True, redact_content=True)


def _disabled_config() -> AuditConfig:
    return AuditConfig(enabled=False, include_rule_trace=False, redact_content=True)


class TestEvaluateAudited:
    def test_returns_correct_decision_matching_evaluate(self):
        spec = _spec_with_tool_access()
        action = EvaluationAction(type="tool_call", target="read_file")
        receipt = evaluate_audited(spec, action, _enabled_config())
        result = evaluate(spec, action)
        assert receipt.decision == result.decision
        assert receipt.decision == Decision.ALLOW

    def test_returns_deny_for_blocked_tool(self):
        spec = _spec_with_tool_access()
        action = EvaluationAction(type="tool_call", target="dangerous_tool")
        receipt = evaluate_audited(spec, action, _enabled_config())
        result = evaluate(spec, action)
        assert receipt.decision == result.decision
        assert receipt.decision == Decision.DENY
        assert receipt.matched_rule == result.matched_rule

    def test_has_valid_uuid(self):
        spec = _minimal_spec()
        action = EvaluationAction(type="tool_call", target="test")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert UUID_RE.match(receipt.receipt_id)

    def test_has_valid_iso_timestamp(self):
        spec = _minimal_spec()
        action = EvaluationAction(type="tool_call", target="test")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert ISO_RE.match(receipt.timestamp)
        assert receipt.timestamp.endswith("Z")

    def test_sets_hushspec_version(self):
        spec = _minimal_spec()
        action = EvaluationAction(type="tool_call", target="test")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert receipt.hushspec_version == HUSHSPEC_VERSION

    def test_populates_rule_trace_when_enabled(self):
        spec = _spec_with_tool_access()
        action = EvaluationAction(type="tool_call", target="read_file")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert len(receipt.rule_trace) > 0
        assert receipt.rule_trace[0].rule_block == "tool_access"
        assert receipt.rule_trace[0].evaluated is True

    def test_returns_empty_trace_when_disabled(self):
        spec = _spec_with_tool_access()
        action = EvaluationAction(type="tool_call", target="read_file")
        receipt = evaluate_audited(spec, action, _disabled_config())
        assert receipt.rule_trace == []
        assert receipt.evaluation_duration_us == 0

    def test_returns_empty_policy_hash_when_disabled(self):
        spec = _spec_with_tool_access()
        action = EvaluationAction(type="tool_call", target="read_file")
        receipt = evaluate_audited(spec, action, _disabled_config())
        assert receipt.policy.content_hash == ""

    def test_content_redacted_when_content_present(self):
        spec = HushSpec(
            hushspec="0.1.0",
            rules=Rules(
                shell_commands=ShellCommandsRule(
                    enabled=True, forbidden_patterns=[]
                )
            ),
        )
        action = EvaluationAction(
            type="shell_command", target="echo hello", content="some content"
        )
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert receipt.action.content_redacted is True

    def test_content_not_redacted_when_no_content(self):
        spec = _minimal_spec()
        action = EvaluationAction(type="tool_call", target="test")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert receipt.action.content_redacted is False

    def test_non_negative_duration_when_enabled(self):
        spec = _spec_with_tool_access()
        action = EvaluationAction(type="tool_call", target="read_file")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert receipt.evaluation_duration_us >= 0

    def test_generates_unique_receipt_ids(self):
        spec = _minimal_spec()
        action = EvaluationAction(type="tool_call", target="test")
        r1 = evaluate_audited(spec, action, _enabled_config())
        r2 = evaluate_audited(spec, action, _enabled_config())
        assert r1.receipt_id != r2.receipt_id

    def test_includes_action_type_and_target(self):
        spec = _minimal_spec()
        action = EvaluationAction(type="egress", target="api.example.com")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert receipt.action.type == "egress"
        assert receipt.action.target == "api.example.com"

    def test_populates_policy_name(self):
        spec = _minimal_spec()
        action = EvaluationAction(type="tool_call", target="test")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert receipt.policy.name == "test-policy"
        assert receipt.policy.version == "0.1.0"


class TestComputePolicyHash:
    def test_produces_valid_sha256(self):
        spec = _minimal_spec()
        h = compute_policy_hash(spec)
        assert SHA256_RE.match(h)

    def test_is_deterministic(self):
        spec = _minimal_spec()
        h1 = compute_policy_hash(spec)
        h2 = compute_policy_hash(spec)
        assert h1 == h2

    def test_differs_for_different_specs(self):
        spec1 = _minimal_spec()
        spec2 = HushSpec(hushspec="0.1.0", name="different-policy")
        assert compute_policy_hash(spec1) != compute_policy_hash(spec2)


class TestRuleTraceActionTypes:
    def test_traces_egress_rule(self):
        spec = HushSpec(
            hushspec="0.1.0",
            rules=Rules(
                egress=EgressRule(
                    allow=["api.example.com"],
                    default=DefaultAction.BLOCK,
                )
            ),
        )
        action = EvaluationAction(type="egress", target="api.example.com")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert receipt.decision == Decision.ALLOW
        egress_trace = [t for t in receipt.rule_trace if t.rule_block == "egress"]
        assert len(egress_trace) == 1
        assert egress_trace[0].evaluated is True
        assert egress_trace[0].outcome == "allow"

    def test_traces_shell_commands_rule(self):
        spec = HushSpec(
            hushspec="0.1.0",
            rules=Rules(
                shell_commands=ShellCommandsRule(
                    enabled=True, forbidden_patterns=[r"rm\s+-rf"]
                )
            ),
        )
        action = EvaluationAction(type="shell_command", target="ls -la")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert receipt.decision == Decision.ALLOW
        shell_trace = [
            t for t in receipt.rule_trace if t.rule_block == "shell_commands"
        ]
        assert len(shell_trace) == 1
        assert shell_trace[0].evaluated is True
        assert shell_trace[0].outcome == "allow"

    def test_traces_skip_for_unconfigured_tool_access(self):
        spec = HushSpec(hushspec="0.1.0")
        action = EvaluationAction(type="tool_call", target="test")
        receipt = evaluate_audited(spec, action, _enabled_config())
        tool_trace = [
            t for t in receipt.rule_trace if t.rule_block == "tool_access"
        ]
        assert len(tool_trace) == 1
        assert tool_trace[0].evaluated is False
        assert tool_trace[0].outcome == "skip"

    def test_handles_unknown_action_type(self):
        spec = HushSpec(hushspec="0.1.0")
        action = EvaluationAction(type="unknown_action", target="test")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert receipt.decision == Decision.ALLOW
        default_trace = [
            t for t in receipt.rule_trace if t.rule_block == "default"
        ]
        assert len(default_trace) == 1
        assert default_trace[0].evaluated is True
