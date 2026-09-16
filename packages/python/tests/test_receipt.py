from __future__ import annotations

import re
from datetime import datetime, timezone

import pytest

from hushspec import (
    Decision,
    EvaluationAction,
    evaluate,
)
from hushspec.canonical import content_hash
from hushspec.receipt import (
    RECEIPT_VERSION,
    ReceiptError,
    Actor,
    AuditConfig,
    AuditContext,
    DecisionReceipt,
    EnforcementSummary,
    TimeSource,
    canonical_json,
    compute_policy_hash,
    deterministic_uuid_v7,
    evaluate_audited,
    evaluate_audited_spec,
    format_timestamp,
    parse_receipt,
    receipt_hash,
    receipt_to_dict,
)
from hushspec.generated_models import (
    EgressRule,
    HushSpec,
    RemoteDesktopChannelsRule,
    Rules,
    SecretPattern,
    SecretPatternsRule,
    Severity,
    ShellCommandsRule,
    ToolAccessRule,
    DefaultAction,
)
from hushspec.resolve import Resolution

UUID_V7_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
CONTENT_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


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
    return AuditConfig(enabled=True, include_rule_trace=True)


def _disabled_config() -> AuditConfig:
    return AuditConfig(enabled=False, include_rule_trace=False)


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

    def test_has_valid_uuid_v7(self):
        # Receipt spec 3.2: v7 so receipts sort by creation time lexically.
        spec = _minimal_spec()
        action = EvaluationAction(type="tool_call", target="test")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert UUID_V7_RE.match(receipt.receipt_id)

    def test_timestamp_has_exactly_millisecond_precision(self):
        # Receipt spec 3.3: one canonical spelling per instant.
        spec = _minimal_spec()
        action = EvaluationAction(type="tool_call", target="test")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert TIMESTAMP_RE.match(receipt.timestamp)

    def test_sets_receipt_version_and_time_source(self):
        spec = _minimal_spec()
        action = EvaluationAction(type="tool_call", target="test")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert receipt.receipt_version == RECEIPT_VERSION == "0.2"
        # The default is `system`; an engine never claims `trusted` unasked.
        assert receipt.time_source == TimeSource.SYSTEM.value

    def test_enforcement_is_always_present(self):
        # Receipt spec 4.7: required in 0.2, never null. With no enforcement
        # point the disposition is the one the decision implies.
        spec = _spec_with_tool_access()
        allowed = evaluate_audited(
            _spec_with_tool_access(),
            EvaluationAction(type="tool_call", target="read_file"),
            _enabled_config(),
        )
        assert allowed.enforcement == EnforcementSummary("enforce", "allowed")
        denied = evaluate_audited(
            spec,
            EvaluationAction(type="tool_call", target="dangerous_tool"),
            _enabled_config(),
        )
        assert denied.enforcement == EnforcementSummary("enforce", "blocked")

    def test_monitor_mode_records_would_block(self):
        receipt = evaluate_audited(
            _spec_with_tool_access(),
            EvaluationAction(type="tool_call", target="dangerous_tool"),
            _enabled_config(),
            AuditContext(enforcement_mode="monitor"),
        )
        assert receipt.enforcement == EnforcementSummary("monitor", "would_block")

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
        assert receipt.duration_us is None

    def test_policy_identity_is_correct_even_when_audit_is_disabled(self):
        # It comes from the resolution, so it costs nothing per evaluation.
        spec = _spec_with_tool_access()
        action = EvaluationAction(type="tool_call", target="read_file")
        receipt = evaluate_audited(spec, action, _disabled_config())
        assert receipt.policy.content_hash == content_hash(spec)

    def test_content_is_recorded_as_hash_and_size_never_content(self):
        # Receipt spec 4.2/4.4: never the content, and `content_size` is bytes.
        spec = HushSpec(
            hushspec="0.1.0",
            rules=Rules(
                shell_commands=ShellCommandsRule(enabled=True, forbidden_patterns=[])
            ),
        )
        action = EvaluationAction(
            type="shell_command", target="echo hello", content="sekret é"
        )
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert CONTENT_HASH_RE.match(receipt.action.content_hash)
        assert receipt.action.content_size == len("sekret é".encode("utf-8"))
        assert "sekret" not in canonical_json(receipt)

    def test_no_content_hash_when_no_content(self):
        spec = _minimal_spec()
        action = EvaluationAction(type="tool_call", target="test")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert receipt.action.content_hash is None
        assert receipt.action.content_size is None

    def test_duration_is_recorded_only_when_asked(self):
        spec = _spec_with_tool_access()
        action = EvaluationAction(type="tool_call", target="read_file")
        assert isinstance(
            evaluate_audited(spec, action, _enabled_config()).duration_us, int
        )
        off = AuditConfig(enabled=True, include_rule_trace=True, record_duration=False)
        assert evaluate_audited(spec, action, off).duration_us is None

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

    def test_target_is_the_string_as_supplied_not_normalized(self):
        # Receipt spec 4.4: an auditor sees what the agent asked for.
        spec = HushSpec(
            hushspec="0.1.0",
            rules=Rules(egress=EgressRule(allow=["api.example.com"], default=DefaultAction.BLOCK)),
        )
        action = EvaluationAction(type="egress", target="API.EXAMPLE.COM:443")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert receipt.decision == Decision.ALLOW
        assert receipt.action.target == "API.EXAMPLE.COM:443"

    def test_populates_policy_identity(self):
        spec = _minimal_spec()
        action = EvaluationAction(type="tool_call", target="test")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert receipt.policy.name == "test-policy"
        # 0.1 put the `hushspec` field in `policy.version`; 0.2 splits them.
        assert receipt.policy.spec_version == "0.1.0"
        assert receipt.policy.version is None

    def test_actor_is_recorded_and_an_empty_one_is_omitted(self):
        spec = _minimal_spec()
        action = EvaluationAction(type="tool_call", target="test")
        actor = Actor(agent_id="bot", session_id="run-1")
        with_actor = evaluate_audited(
            spec, action, _enabled_config(), AuditContext(actor=actor)
        )
        assert with_actor.actor == actor
        empty = evaluate_audited(
            spec, action, _enabled_config(), AuditContext(actor=Actor())
        )
        assert empty.actor is None

    def test_extends_chain_only_when_there_was_an_extends(self):
        spec = _minimal_spec()
        receipt = evaluate_audited(
            Resolution.from_resolved(spec),
            EvaluationAction(type="tool_call", target="test"),
            _enabled_config(),
        )
        assert receipt.policy.extends_chain is None

    def test_evaluate_audited_spec_wraps_a_resolved_document(self):
        spec = _spec_with_tool_access()
        action = EvaluationAction(type="tool_call", target="read_file")
        receipt = evaluate_audited_spec(spec, action, _enabled_config())
        assert receipt.policy.content_hash == content_hash(spec)


class TestDeterminism:
    def test_fixed_clock_and_id_make_a_receipt_reproducible(self):
        spec = _spec_with_tool_access()
        action = EvaluationAction(type="tool_call", target="read_file")
        ctx = AuditContext(
            clock=datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc),
            receipt_id=deterministic_uuid_v7(1_789_473_600_000, 3),
            time_source=TimeSource.TRUSTED.value,
        )
        config = AuditConfig(
            enabled=True, include_rule_trace=True, record_duration=False
        )
        first = evaluate_audited(spec, action, config, ctx)
        second = evaluate_audited(spec, action, config, ctx)
        assert receipt_hash(first) == receipt_hash(second)
        assert first.timestamp == "2026-09-15T12:00:00.000Z"

    def test_deterministic_uuid_v7_has_version_and_variant_bits(self):
        value = deterministic_uuid_v7(1_757_930_400_123, 42)
        assert UUID_V7_RE.match(value)
        assert value == deterministic_uuid_v7(1_757_930_400_123, 42)
        assert value != deterministic_uuid_v7(1_757_930_400_123, 43)

    def test_format_timestamp_truncates_to_milliseconds(self):
        moment = datetime(2026, 9, 15, 8, 30, 0, 123_999, tzinfo=timezone.utc)
        assert format_timestamp(moment) == "2026-09-15T08:30:00.123Z"

    def test_receipt_hash_is_sha256_over_the_canonical_form(self):
        spec = _minimal_spec()
        receipt = evaluate_audited(
            spec, EvaluationAction(type="tool_call", target="x"), _enabled_config()
        )
        assert CONTENT_HASH_RE.match(receipt_hash(receipt))
        # RFC 8785 sorts keys, so the hash does not depend on member order.
        assert canonical_json(receipt).startswith('{"action":')


class TestComputePolicyHash:
    def test_produces_the_canonical_content_hash(self):
        spec = _minimal_spec()
        assert compute_policy_hash(spec) == content_hash(spec)
        assert CONTENT_HASH_RE.match(compute_policy_hash(spec))

    def test_is_deterministic(self):
        # Two independently built equal specs, not one object twice: hashing
        # the same object would also pass with an identity-keyed cache.
        assert compute_policy_hash(_minimal_spec()) == compute_policy_hash(
            _minimal_spec()
        )

    def test_differs_for_different_specs(self):
        spec1 = _minimal_spec()
        spec2 = HushSpec(hushspec="0.1.0", name="different-policy")
        assert compute_policy_hash(spec1) != compute_policy_hash(spec2)


def _assert_no_null_values(value, path: str = "$") -> None:
    """Recursively assert no dict key in *value* holds ``None``.

    Receipt spec 7: "no nulls anywhere; absent means absent".
    """
    if isinstance(value, dict):
        for key, item in value.items():
            assert item is not None, f"{path}.{key} is null; expected the key to be omitted"
            _assert_no_null_values(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_no_null_values(item, f"{path}[{index}]")


class TestReceiptToDict:
    def test_allow_receipt_has_no_null_keys(self):
        # A minimal spec with no rules, no posture extension, and no origin
        # produces an ALLOW decision where matched_rule, reason, origin_profile
        # and posture are all None -- and the tool_access rule_trace entry also
        # carries a None rule_path. An absent value is an omitted key, never an
        # explicit null (receipt spec section 3).
        spec = _minimal_spec()
        action = EvaluationAction(type="tool_call", target="anything")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert receipt.decision == Decision.ALLOW
        assert receipt.matched_rule is None
        assert receipt.posture is None

        data = receipt_to_dict(receipt)
        _assert_no_null_values(data)

        assert "matched_rule" not in data
        assert "reason" not in data
        assert "origin_profile" not in data
        assert "posture" not in data
        # `enforcement` is required in 0.2 and therefore always present.
        assert data["enforcement"] == {"mode": "enforce", "outcome": "allowed"}
        assert "rule_path" not in data["rule_trace"][0]
        assert data["rule_trace"][0]["reason"] == "no tool_access rule configured"
        assert data["policy"]["name"] == "test-policy"

    def test_receipt_with_unset_policy_name_omits_it(self):
        spec = HushSpec(hushspec="0.1.0")  # no `name` set
        action = EvaluationAction(type="tool_call", target="anything")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert receipt.policy.name is None

        data = receipt_to_dict(receipt)
        _assert_no_null_values(data)
        assert "name" not in data["policy"]

    def test_falsy_but_present_values_are_kept(self):
        spec = _minimal_spec()
        action = EvaluationAction(type="tool_call", target="anything")
        receipt = evaluate_audited(spec, action, _enabled_config())
        data = receipt_to_dict(receipt)
        assert data["rule_trace"][0]["evaluated"] is False

    def test_round_trips_through_parse_receipt(self):
        spec = _spec_with_tool_access()
        receipt = evaluate_audited(
            spec,
            EvaluationAction(type="tool_call", target="dangerous_tool", content="x"),
            _enabled_config(),
        )
        reparsed = parse_receipt(receipt_to_dict(receipt))
        assert receipt_hash(reparsed) == receipt_hash(receipt)
        assert reparsed.decision == Decision.DENY

    def test_parse_rejects_another_version_and_unknown_fields(self):
        import pytest

        from hushspec.receipt import ReceiptError

        spec = _minimal_spec()
        data = receipt_to_dict(
            evaluate_audited(
                spec, EvaluationAction(type="tool_call", target="x"), _enabled_config()
            )
        )
        old = dict(data, receipt_version="0.1")
        with pytest.raises(ReceiptError):
            parse_receipt(old)
        with pytest.raises(ReceiptError):
            parse_receipt(dict(data, hushspec_version="0.2.0"))


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
        assert tool_trace[0].reason == "no tool_access rule configured"

    def test_a_configured_secret_scan_without_content_says_so(self):
        # Core spec 5: a tool_call is scanned only when it carries content.
        # The skip reason has to separate "the policy configures no scan" from
        # "the policy configures one and the action gave it nothing to read" --
        # a reader of the receipt cannot otherwise tell the two apart.
        rule = SecretPatternsRule(
            patterns=[
                SecretPattern(
                    name="aws_key",
                    pattern="AKIA[0-9A-Z]{16}",
                    severity=Severity.CRITICAL,
                )
            ]
        )
        spec = HushSpec(hushspec="1.0.0", rules=Rules(secret_patterns=rule))
        action = EvaluationAction(type="tool_call", target="test")
        receipt = evaluate_audited(spec, action, _enabled_config())
        scan = [t for t in receipt.rule_trace if t.rule_block == "secret_patterns"]
        assert len(scan) == 1
        assert scan[0].evaluated is False
        assert scan[0].outcome == "skip"
        assert scan[0].reason == "content not supplied; secret_patterns not consulted"

        # Absent from the document, the same block reads as unconfigured.
        bare = HushSpec(hushspec="1.0.0")
        bare_scan = [
            t
            for t in evaluate_audited(bare, action, _enabled_config()).rule_trace
            if t.rule_block == "secret_patterns"
        ]
        assert bare_scan[0].reason == "no secret_patterns rule configured"

    def test_a_computer_use_target_that_is_not_a_channel_says_so(self):
        # Core spec 3.9: remote_desktop_channels decides only the four
        # `remote.*` channel targets; any other computer_use target leaves the
        # configured block unconsulted rather than unconfigured.
        spec = HushSpec(
            hushspec="1.0.0",
            rules=Rules(
                remote_desktop_channels=RemoteDesktopChannelsRule(
                    enabled=True, clipboard=True
                )
            ),
        )
        action = EvaluationAction(type="computer_use", target="screenshot")
        receipt = evaluate_audited(spec, action, _enabled_config())
        channels = [
            t for t in receipt.rule_trace if t.rule_block == "remote_desktop_channels"
        ]
        assert len(channels) == 1
        assert channels[0].evaluated is False
        assert channels[0].outcome == "skip"
        assert channels[0].reason == (
            "target is not a remote desktop channel; "
            "remote_desktop_channels not consulted"
        )

        # A target that *is* a channel reaches the rule.
        on_channel = evaluate_audited(
            spec,
            EvaluationAction(type="computer_use", target="remote.clipboard"),
            _enabled_config(),
        )
        decided = [
            t for t in on_channel.rule_trace if t.rule_block == "remote_desktop_channels"
        ]
        assert decided[0].evaluated is True

        bare = HushSpec(hushspec="1.0.0")
        bare_channels = [
            t
            for t in evaluate_audited(bare, action, _enabled_config()).rule_trace
            if t.rule_block == "remote_desktop_channels"
        ]
        assert bare_channels[0].reason == "no remote_desktop_channels rule configured"

    def test_handles_unknown_action_type(self):
        # Core spec 5: an action type unknown to the specification denies, and
        # the recorded trace carries the sentinel rule. Receipt spec 4.3 item 5
        # spells the engine stage `unknown_action_type`, not `default`.
        spec = HushSpec(hushspec="0.1.0")
        action = EvaluationAction(type="unknown_action", target="test")
        receipt = evaluate_audited(spec, action, _enabled_config())
        assert receipt.decision == Decision.DENY
        assert receipt.matched_rule == "__unknown_action_type__"
        stage = [
            t for t in receipt.rule_trace if t.rule_block == "unknown_action_type"
        ]
        assert len(stage) == 1
        assert stage[0].evaluated is True
        assert stage[0].outcome == "deny"
        assert not [t for t in receipt.rule_trace if t.rule_block == "default"]


class TestDecisionReceiptMethods:
    def test_methods_mirror_the_module_functions(self):
        spec = _minimal_spec()
        receipt: DecisionReceipt = evaluate_audited(
            spec, EvaluationAction(type="tool_call", target="x"), _enabled_config()
        )
        assert receipt.to_dict() == receipt_to_dict(receipt)
        assert receipt.canonical_json() == canonical_json(receipt)
        assert receipt.receipt_hash() == receipt_hash(receipt)


class TestParseReceiptRefusals:
    """Every refusal is a :class:`ReceiptError`, whatever the input looks like."""

    def _receipt(self, **overrides):
        body = {
            "receipt_version": RECEIPT_VERSION,
            "receipt_id": "01994b7e-2c1a-7c3e-8f4a-0123456789ab",
            "timestamp": "2026-03-15T00:00:00.000Z",
            "time_source": "system",
            "policy": {
                "name": "p",
                "spec_version": "0.2.0",
                "content_hash": "sha256:" + "ab" * 32,
            },
            "action": {"type": "tool_call", "target": "t"},
            "decision": "allow",
            "enforcement": {"mode": "enforce", "outcome": "allowed"},
            "rule_trace": [],
        }
        body.update(overrides)
        return body

    def test_the_baseline_parses(self):
        assert parse_receipt(self._receipt()).decision.value == "allow"

    @pytest.mark.parametrize(
        "member", ["receipt_id", "timestamp", "time_source", "decision"]
    )
    def test_a_missing_required_member_is_a_receipt_error(self, member):
        body = self._receipt()
        del body[member]
        with pytest.raises(ReceiptError, match=f"missing {member!r}"):
            parse_receipt(body)

    def test_an_unknown_decision_is_a_receipt_error(self):
        with pytest.raises(ReceiptError, match="decision .* closed enum"):
            parse_receipt(self._receipt(decision="bogus"))

    def test_an_unknown_rule_trace_outcome_is_a_receipt_error(self):
        body = self._receipt(
            rule_trace=[
                {"rule_block": "egress", "outcome": "nope", "evaluated": True}
            ]
        )
        with pytest.raises(ReceiptError, match=r"rule_trace\[0\].outcome"):
            parse_receipt(body)
