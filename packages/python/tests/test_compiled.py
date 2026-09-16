"""Compiled policies: same decisions, paid for once (hushspec.compiled)."""

from __future__ import annotations

from pathlib import Path

import pytest

from hushspec import (
    CompiledPolicy,
    CompileError,
    Decision,
    EvaluationAction,
    HushGuard,
    HushSpec,
    Rules,
    SecretPattern,
    SecretPatternsRule,
    Severity,
    ShellCommandsRule,
    compile_policy,
    content_hash,
    evaluate,
    evaluate_traced,
    parse_or_raise,
)
from hushspec.compiled import compiled_for_spec
from hushspec.detection import evaluate_with_detection
from hushspec.resolve import Resolution

REPO_ROOT = Path(__file__).resolve().parents[3]

ACTIONS = [
    EvaluationAction(type="file_read", target="/home/u/project/main.py"),
    EvaluationAction(type="file_read", target="/home/u/.ssh/id_rsa"),
    EvaluationAction(
        type="file_write", target="/home/u/app.env", content="AKIAIOSFODNN7EXAMPLE"
    ),
    EvaluationAction(type="egress", target="https://api.openai.com/v1"),
    EvaluationAction(type="egress", target="evil.example.com"),
    EvaluationAction(type="tool_call", target="shell_exec", args_size=12),
    EvaluationAction(type="tool_call", target="git_push", args_size=12),
    EvaluationAction(type="shell_command", target="rm -rf /"),
    EvaluationAction(type="shell_command", target="ls -la"),
    EvaluationAction(type="not_a_real_action", target="x"),
]


def _default_policy() -> HushSpec:
    return parse_or_raise((REPO_ROOT / "rulesets" / "default.yaml").read_text())


def _invalid_pattern_policy() -> HushSpec:
    """A hand-built document the validator would have rejected.

    ``parse`` refuses both of these patterns, so the only way one reaches the
    evaluator is a document built in code -- which is exactly the case the
    fail-closed compile has to cover.
    """
    return HushSpec(
        hushspec="0.2.0",
        name="hand-built",
        rules=Rules(
            secret_patterns=SecretPatternsRule(
                patterns=[
                    SecretPattern(
                        name="lookahead",
                        pattern="(?=secret)x",
                        severity=Severity.CRITICAL,
                    )
                ]
            ),
            shell_commands=ShellCommandsRule(forbidden_patterns=["(a+)+b"]),
        ),
    )


class TestParity:
    def test_compiled_matches_the_free_function(self):
        spec = _default_policy()
        compiled = compile_policy(spec)
        for action in ACTIONS:
            assert compiled.evaluate(action) == evaluate(spec, action)

    def test_compiled_trace_matches_the_free_function(self):
        spec = _default_policy()
        compiled = compile_policy(spec)
        for action in ACTIONS:
            assert compiled.evaluate_traced(action) == evaluate_traced(spec, action)

    def test_compiled_detection_matches_the_free_function(self):
        spec = _default_policy()
        compiled = compile_policy(spec)
        for action in ACTIONS:
            assert (
                compiled.evaluate_with_detection(action).evaluation
                == evaluate_with_detection(spec, action).evaluation
            )


class TestFailClosed:
    def test_strict_compile_raises_on_a_pattern_outside_the_profile(self):
        with pytest.raises(CompileError) as excinfo:
            compile_policy(_invalid_pattern_policy())
        assert (
            excinfo.value.rule_path
            == "rules.secret_patterns.patterns.lookahead.pattern"
        )

    def test_lenient_compile_records_every_offending_pattern(self):
        compiled = compile_policy(_invalid_pattern_policy(), strict=False)
        assert [error.rule_path for error in compiled.errors] == [
            "rules.secret_patterns.patterns.lookahead.pattern",
            "rules.shell_commands.forbidden_patterns[0]",
        ]

    def test_an_unusable_pattern_denies_rather_than_raising(self):
        spec = _invalid_pattern_policy()
        result = evaluate(
            spec, EvaluationAction(type="file_write", target="/tmp/x", content="hello")
        )
        assert result.decision == Decision.DENY
        assert result.matched_rule == "rules.secret_patterns.patterns.lookahead.pattern"
        assert "is invalid" in (result.reason or "")

        shell = evaluate(spec, EvaluationAction(type="shell_command", target="ls"))
        assert shell.decision == Decision.DENY
        assert shell.matched_rule == "rules.shell_commands.forbidden_patterns[0]"


class TestIdentity:
    def test_content_hash_is_the_documents_own(self):
        spec = _default_policy()
        compiled = compile_policy(spec)
        assert compiled.content_hash == content_hash(spec)
        # Cached: the second read is the same string object, not a rehash.
        assert compiled.content_hash is compiled.content_hash

    def test_compiling_a_resolution_keeps_its_provenance(self):
        spec = _default_policy()
        resolution = Resolution.from_resolved(spec, source="rulesets/default.yaml")
        compiled = compile_policy(resolution)
        assert compiled.resolution is resolution
        assert compiled.content_hash == resolution.content_hash

    def test_the_source_document_is_kept_for_receipts(self):
        spec = _default_policy()
        assert compile_policy(spec).spec is spec


class TestCache:
    def test_the_free_functions_reuse_one_compiled_policy(self):
        spec = _default_policy()
        evaluate(spec, ACTIONS[0])
        first = compiled_for_spec(spec)
        evaluate(spec, ACTIONS[1])
        assert compiled_for_spec(spec) is first

    def test_distinct_documents_get_distinct_compiled_policies(self):
        assert compiled_for_spec(_default_policy()) is not compiled_for_spec(
            _default_policy()
        )


class TestGuard:
    def test_guard_exposes_the_policy_it_compiled(self):
        guard = HushGuard(_default_policy())
        assert isinstance(guard.compiled, CompiledPolicy)
        assert guard.compiled.spec is guard.resolution.spec

    def test_guard_recompiles_on_swap(self):
        guard = HushGuard(_default_policy())
        before = guard.compiled
        guard.swap_policy(parse_or_raise('hushspec: "0.2.0"\nname: empty\n'))
        assert guard.compiled is not before
        assert guard.compiled.spec.name == "empty"

    def test_guard_decisions_are_the_compiled_ones(self):
        guard = HushGuard(_default_policy())
        for action in ACTIONS:
            assert guard.evaluate(action) == guard.compiled.evaluate_with_detection(
                action
            ).evaluation
