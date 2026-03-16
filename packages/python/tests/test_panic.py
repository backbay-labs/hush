import os
import tempfile

import pytest

from hushspec import (
    Decision,
    EvaluationAction,
    HushSpec,
    activate_panic,
    check_panic_sentinel,
    deactivate_panic,
    evaluate,
    is_panic_active,
    panic_policy,
)


@pytest.fixture(autouse=True)
def _reset_panic():
    deactivate_panic()
    yield
    deactivate_panic()


class TestPanicActivation:
    def test_is_panic_active_default(self):
        assert not is_panic_active()

    def test_activate_panic(self):
        activate_panic()
        assert is_panic_active()

    def test_deactivate_panic(self):
        activate_panic()
        assert is_panic_active()
        deactivate_panic()
        assert not is_panic_active()


class TestPanicEvaluate:
    def test_all_action_types_denied(self):
        activate_panic()
        spec = HushSpec(hushspec="0.1.0")
        action_types = [
            "tool_call",
            "egress",
            "file_read",
            "file_write",
            "patch_apply",
            "shell_command",
            "computer_use",
            "unknown_action",
        ]

        for action_type in action_types:
            action = EvaluationAction(type=action_type, target="anything")
            result = evaluate(spec, action)
            assert result.decision == Decision.DENY, (
                f"expected deny for {action_type}"
            )
            assert result.matched_rule == "__hushspec_panic__"
            assert result.reason == "emergency panic mode is active"

    def test_deactivate_restores_normal(self):
        spec = HushSpec(hushspec="0.1.0")
        action = EvaluationAction(type="tool_call", target="some_tool")

        # Normal mode -- allow (no rules)
        result = evaluate(spec, action)
        assert result.decision == Decision.ALLOW

        # Activate panic -- deny
        activate_panic()
        result = evaluate(spec, action)
        assert result.decision == Decision.DENY

        # Deactivate -- allow again
        deactivate_panic()
        result = evaluate(spec, action)
        assert result.decision == Decision.ALLOW


class TestPanicPolicy:
    def test_panic_policy_parses(self):
        spec = panic_policy()
        assert spec.name == "__hushspec_panic__"
        assert spec.hushspec == "0.1.0"
        assert spec.rules is not None

    def test_panic_policy_does_not_depend_on_cwd(self):
        original = os.getcwd()
        tmpdir = tempfile.mkdtemp(prefix="hushspec-panic-")
        try:
            os.chdir(tmpdir)
            spec = panic_policy()
            assert spec.name == "__hushspec_panic__"
        finally:
            os.chdir(original)
            os.rmdir(tmpdir)

    def test_panic_policy_denies_file_reads(self):
        spec = panic_policy()
        result = evaluate(spec, EvaluationAction(type="file_read", target="/etc/passwd"))
        assert result.decision == Decision.DENY

    def test_panic_policy_denies_egress(self):
        spec = panic_policy()
        result = evaluate(spec, EvaluationAction(type="egress", target="example.com"))
        assert result.decision == Decision.DENY

    def test_panic_policy_denies_tool_calls(self):
        spec = panic_policy()
        result = evaluate(spec, EvaluationAction(type="tool_call", target="any_tool"))
        assert result.decision == Decision.DENY


class TestPanicSentinel:
    def test_sentinel_file_activates_panic(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            sentinel = f.name
        try:
            assert check_panic_sentinel(sentinel)
            assert is_panic_active()
        finally:
            os.unlink(sentinel)

    def test_sentinel_file_missing_does_not_activate(self):
        sentinel = os.path.join(tempfile.gettempdir(), "nonexistent_hushspec_panic")
        if os.path.exists(sentinel):
            os.unlink(sentinel)

        assert not check_panic_sentinel(sentinel)
        assert not is_panic_active()
