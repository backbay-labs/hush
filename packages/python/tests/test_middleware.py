import pytest

from hushspec import HushGuard, HushSpecDenied
from hushspec.evaluate import Decision, EvaluationAction, EvaluationResult
from hushspec.middleware import HushGuard as HushGuardDirect
from hushspec.adapters.langchain import hush_tool
from hushspec.middleware import EnforcementConfig, matches_rule_path_prefix
from hushspec.observer import EvaluationObserver
from hushspec.parse import parse_or_raise


# Shared policies


ALLOW_ALL_POLICY = """
hushspec: "0.1.0"
name: allow-all
rules:
  tool_access:
    allow: ["*"]
    default: allow
  egress:
    allow: ["*"]
    default: allow
"""

DENY_SHELL_POLICY = """
hushspec: "0.1.0"
name: deny-shell
rules:
  shell_commands:
    forbidden_patterns:
      - "rm -rf"
  tool_access:
    block: ["dangerous_tool"]
    require_confirmation: ["risky_tool"]
    allow: ["safe_tool"]
    default: block
  egress:
    allow: ["api.example.com"]
    default: block
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
"""



# HushGuard core



class TestHushGuardFromYaml:
    def test_creates_guard_from_valid_yaml(self):
        guard = HushGuard.from_yaml(ALLOW_ALL_POLICY)
        assert isinstance(guard, HushGuard)

    def test_raises_on_invalid_yaml(self):
        with pytest.raises(ValueError):
            HushGuard.from_yaml("not: valid: yaml: {")


class TestHushGuardCheck:
    def test_returns_true_for_allowed_actions(self):
        guard = HushGuard.from_yaml(ALLOW_ALL_POLICY)
        action = EvaluationAction(type="tool_call", target="any_tool")
        assert guard.check(action) is True

    def test_returns_false_for_denied_actions(self):
        guard = HushGuard.from_yaml(DENY_SHELL_POLICY)
        action = EvaluationAction(type="tool_call", target="dangerous_tool")
        assert guard.check(action) is False

    def test_returns_false_for_denied_file_reads(self):
        guard = HushGuard.from_yaml(DENY_SHELL_POLICY)
        action = EvaluationAction(type="file_read", target="/home/user/.ssh/id_rsa")
        assert guard.check(action) is False

    def test_returns_false_for_denied_egress(self):
        guard = HushGuard.from_yaml(DENY_SHELL_POLICY)
        action = EvaluationAction(type="egress", target="evil.com")
        assert guard.check(action) is False

    def test_returns_true_for_allowed_egress(self):
        guard = HushGuard.from_yaml(DENY_SHELL_POLICY)
        action = EvaluationAction(type="egress", target="api.example.com")
        assert guard.check(action) is True


class TestHushGuardEnforce:
    def test_does_not_raise_for_allowed_actions(self):
        guard = HushGuard.from_yaml(ALLOW_ALL_POLICY)
        action = EvaluationAction(type="tool_call", target="any_tool")
        guard.enforce(action)  # should not raise

    def test_raises_hushspec_denied_for_denied_actions(self):
        guard = HushGuard.from_yaml(DENY_SHELL_POLICY)
        action = EvaluationAction(type="tool_call", target="dangerous_tool")
        with pytest.raises(HushSpecDenied) as exc_info:
            guard.enforce(action)
        assert exc_info.value.result.decision == Decision.DENY

    def test_raises_hushspec_denied_for_denied_shell_commands(self):
        guard = HushGuard.from_yaml(DENY_SHELL_POLICY)
        action = EvaluationAction(type="shell_command", target="rm -rf /")
        with pytest.raises(HushSpecDenied):
            guard.enforce(action)


class TestHushGuardWarnHandler:
    def test_calls_on_warn_and_allows_when_handler_returns_true(self):
        warn_called = False

        def on_warn(result: EvaluationResult, action: EvaluationAction) -> bool:
            nonlocal warn_called
            warn_called = True
            return True

        guard = HushGuard.from_yaml(DENY_SHELL_POLICY, on_warn=on_warn)
        action = EvaluationAction(type="tool_call", target="risky_tool")
        assert guard.check(action) is True
        assert warn_called is True

    def test_calls_on_warn_and_denies_when_handler_returns_false(self):
        guard = HushGuard.from_yaml(DENY_SHELL_POLICY, on_warn=lambda r, a: False)
        action = EvaluationAction(type="tool_call", target="risky_tool")
        assert guard.check(action) is False

    def test_default_on_warn_denies_fail_closed(self):
        guard = HushGuard.from_yaml(DENY_SHELL_POLICY)
        action = EvaluationAction(type="tool_call", target="risky_tool")
        assert guard.check(action) is False

    def test_enforce_raises_when_on_warn_returns_false(self):
        guard = HushGuard.from_yaml(DENY_SHELL_POLICY, on_warn=lambda r, a: False)
        action = EvaluationAction(type="tool_call", target="risky_tool")
        with pytest.raises(HushSpecDenied):
            guard.enforce(action)

    def test_enforce_passes_when_on_warn_returns_true(self):
        guard = HushGuard.from_yaml(DENY_SHELL_POLICY, on_warn=lambda r, a: True)
        action = EvaluationAction(type="tool_call", target="risky_tool")
        guard.enforce(action)  # should not raise


class TestHushGuardSwapPolicy:
    def test_changes_active_policy(self):
        guard = HushGuard.from_yaml(DENY_SHELL_POLICY)
        action = EvaluationAction(type="tool_call", target="dangerous_tool")
        assert guard.check(action) is False

        new_policy = parse_or_raise(ALLOW_ALL_POLICY)
        guard.swap_policy(new_policy)
        assert guard.check(action) is True


class TestHushGuardActionMappers:
    def test_map_tool_call_creates_correct_action(self):
        action = HushGuard.map_tool_call("my_tool", {"key": "value"})
        assert action.type == "tool_call"
        assert action.target == "my_tool"
        assert action.args_size is not None
        assert action.args_size > 0

    def test_map_tool_call_without_args_has_none_args_size(self):
        action = HushGuard.map_tool_call("my_tool")
        assert action.args_size is None

    def test_map_file_read_creates_correct_action(self):
        action = HushGuard.map_file_read("/etc/passwd")
        assert action.type == "file_read"
        assert action.target == "/etc/passwd"

    def test_map_file_write_creates_correct_action(self):
        action = HushGuard.map_file_write("/tmp/test.txt", "content")
        assert action.type == "file_write"
        assert action.target == "/tmp/test.txt"
        assert action.content == "content"

    def test_map_egress_creates_correct_action(self):
        action = HushGuard.map_egress("api.example.com")
        assert action.type == "egress"
        assert action.target == "api.example.com"

    def test_map_shell_command_creates_correct_action(self):
        action = HushGuard.map_shell_command("ls -la")
        assert action.type == "shell_command"
        assert action.target == "ls -la"



# LangChain adapter



class TestLangChainAdapter:
    def test_hush_tool_allows_permitted_tool(self):
        guard = HushGuard.from_yaml(ALLOW_ALL_POLICY)

        @hush_tool(guard, tool_name="safe_tool")
        def my_tool(query: str) -> str:
            return f"result: {query}"

        result = my_tool("test")
        assert result == "result: test"

    def test_hush_tool_blocks_denied_tool(self):
        guard = HushGuard.from_yaml(DENY_SHELL_POLICY)

        @hush_tool(guard, tool_name="dangerous_tool")
        def my_tool(query: str) -> str:
            return f"result: {query}"

        with pytest.raises(HushSpecDenied):
            my_tool("test")

    def test_hush_tool_uses_function_name_when_tool_name_omitted(self):
        guard = HushGuard.from_yaml(DENY_SHELL_POLICY)

        @hush_tool(guard)
        def safe_tool(query: str) -> str:
            return f"result: {query}"

        result = safe_tool("test")
        assert result == "result: test"

    def test_hush_tool_preserves_function_metadata(self):
        guard = HushGuard.from_yaml(ALLOW_ALL_POLICY)

        @hush_tool(guard)
        def documented_tool() -> str:
            """This tool has docs."""
            return "ok"

        assert documented_tool.__name__ == "documented_tool"
        assert documented_tool.__doc__ == "This tool has docs."



# Module-level export



class TestExports:
    def test_hushguard_importable_from_top_level(self):
        from hushspec import HushGuard as HG, HushSpecDenied as HSD

        assert HG is HushGuardDirect
        assert HSD is HushSpecDenied


# Enforcement mode: config validation and prefix matching


class _NoopObserver(EvaluationObserver):
    def on_event(self, event):
        pass


class TestMatchesRulePathPrefix:
    def test_matches_exact_keys_and_segment_boundaries_only(self):
        assert matches_rule_path_prefix("rules.tool_access", "rules.tool_access") is True
        assert matches_rule_path_prefix("rules.tool_access.block", "rules.tool_access") is True
        assert (
            matches_rule_path_prefix(
                "rules.shell_commands.forbidden_patterns[0]",
                "rules.shell_commands.forbidden_patterns",
            )
            is True
        )
        assert matches_rule_path_prefix("rules.tool_access_x", "rules.tool_access") is False
        assert matches_rule_path_prefix("rules.egress.block", "rules.egres") is False


class TestEnforcementConfigValidation:
    def test_rejects_monitor_mode_without_observer_or_sink(self):
        with pytest.raises(ValueError, match="monitor mode requires an observer or a receipt sink"):
            HushGuard.from_yaml(ALLOW_ALL_POLICY, enforcement=EnforcementConfig(mode="monitor"))

    def test_rejects_unknown_rule_names_in_override_keys(self):
        with pytest.raises(ValueError, match="unknown rule in enforcement override 'rules.egres'"):
            HushGuard.from_yaml(
                ALLOW_ALL_POLICY,
                observer=_NoopObserver(),
                enforcement=EnforcementConfig(
                    mode="monitor", overrides={"rules.egres": "enforce"}
                ),
            )

    def test_rejects_override_keys_outside_rules_and_extensions(self):
        with pytest.raises(ValueError, match="must start with 'rules.' or 'extensions.'"):
            HushGuard.from_yaml(
                ALLOW_ALL_POLICY,
                observer=_NoopObserver(),
                enforcement=EnforcementConfig(overrides={"tool_access": "monitor"}),
            )

    def test_rejects_invalid_mode_values(self):
        with pytest.raises(ValueError, match="invalid enforcement mode: 'audit'"):
            HushGuard.from_yaml(ALLOW_ALL_POLICY, enforcement=EnforcementConfig(mode="audit"))

    def test_accepts_valid_monitor_config_with_observer(self):
        guard = HushGuard.from_yaml(
            ALLOW_ALL_POLICY,
            observer=_NoopObserver(),
            enforcement=EnforcementConfig(
                mode="monitor",
                overrides={"rules.egress": "enforce", "extensions.posture": "monitor"},
            ),
        )
        assert isinstance(guard, HushGuard)
