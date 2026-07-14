from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from hushspec import parse
from hushspec.evaluate import (
    Decision,
    EvaluationAction,
    OriginContext,
    PostureContext,
    evaluate,
    glob_matches,
)

FIXTURES_ROOT = Path(__file__).parent.parent.parent.parent / "fixtures"

EVALUATION_DIRS = ["core/evaluation", "posture/evaluation", "origins/evaluation"]


def _build_origin(data: dict) -> OriginContext:
    return OriginContext(
        provider=data.get("provider"),
        tenant_id=data.get("tenant_id"),
        space_id=data.get("space_id"),
        space_type=data.get("space_type"),
        visibility=data.get("visibility"),
        external_participants=data.get("external_participants"),
        tags=data.get("tags", []),
        sensitivity=data.get("sensitivity"),
        actor_role=data.get("actor_role"),
    )


def _build_posture(data: dict) -> PostureContext:
    return PostureContext(
        current=data.get("current"),
        signal=data.get("signal"),
    )


def _build_action(data: dict) -> EvaluationAction:
    origin = _build_origin(data["origin"]) if "origin" in data else None
    posture = _build_posture(data["posture"]) if "posture" in data else None
    return EvaluationAction(
        type=data["type"],
        target=data.get("target"),
        content=data.get("content"),
        origin=origin,
        posture=posture,
        args_size=data.get("args_size"),
    )


def _collect_evaluation_cases():
    cases = []
    for eval_dir in EVALUATION_DIRS:
        dir_path = FIXTURES_ROOT / eval_dir
        if not dir_path.exists():
            continue
        for yaml_file in sorted(dir_path.glob("*.yaml")):
            with open(yaml_file) as f:
                fixture = yaml.safe_load(f)
            for case in fixture["cases"]:
                test_id = (
                    f"{yaml_file.relative_to(FIXTURES_ROOT)}::{case['description']}"
                )
                cases.append(
                    pytest.param(
                        fixture["policy"],
                        case,
                        id=test_id,
                    )
                )
    return cases


@pytest.mark.parametrize("policy,case", _collect_evaluation_cases())
def test_evaluation(policy: dict, case: dict):
    ok, spec_or_err = parse(yaml.dump(policy))
    assert ok, f"Failed to parse policy: {spec_or_err}"
    spec = spec_or_err

    action = _build_action(case["action"])
    result = evaluate(spec, action)

    expected = case["expect"]
    assert result.decision.value == expected["decision"], (
        f"{case['description']}: expected decision={expected['decision']}, "
        f"got {result.decision.value}"
    )

    if "matched_rule" in expected:
        assert result.matched_rule == expected["matched_rule"], (
            f"{case['description']}: expected matched_rule={expected['matched_rule']}, "
            f"got {result.matched_rule}"
        )

    if "origin_profile" in expected:
        assert result.origin_profile == expected["origin_profile"], (
            f"{case['description']}: expected origin_profile={expected['origin_profile']}, "
            f"got {result.origin_profile}"
        )

    if "posture" in expected:
        assert result.posture is not None, (
            f"{case['description']}: expected posture but got None"
        )
        assert result.posture.current == expected["posture"]["current"], (
            f"{case['description']}: expected posture.current={expected['posture']['current']}, "
            f"got {result.posture.current}"
        )
        assert result.posture.next == expected["posture"]["next"], (
            f"{case['description']}: expected posture.next={expected['posture']['next']}, "
            f"got {result.posture.next}"
        )


def test_origin_profile_tool_access_still_respects_base_blocklist():
    ok, spec_or_err = parse(
        """\
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: ["*"]
    block: ["dangerous_tool"]
    require_confirmation: []
    default: allow
extensions:
  origins:
    default_behavior: deny
    profiles:
      - id: slack
        match:
          provider: slack
        tool_access:
          enabled: true
          allow: ["*"]
          block: []
          require_confirmation: []
          default: allow
"""
    )
    assert ok, spec_or_err
    spec = spec_or_err

    result = evaluate(
        spec,
        EvaluationAction(
            type="tool_call",
            target="dangerous_tool",
            origin=OriginContext(provider="slack"),
        ),
    )

    assert result.decision == Decision.DENY
    assert result.matched_rule == "rules.tool_access.block"
    assert result.origin_profile == "slack"


def test_origin_profile_egress_cannot_bypass_base_default_block():
    ok, spec_or_err = parse(
        """\
hushspec: "0.1.0"
rules:
  egress:
    enabled: true
    allow: ["api.safe.example.com"]
    block: []
    default: block
extensions:
  origins:
    default_behavior: deny
    profiles:
      - id: slack
        match:
          provider: slack
        egress:
          enabled: true
          allow: []
          block: []
          default: allow
"""
    )
    assert ok, spec_or_err
    spec = spec_or_err

    result = evaluate(
        spec,
        EvaluationAction(
            type="egress",
            target="evil.example.com",
            origin=OriginContext(provider="slack"),
        ),
    )

    assert result.decision == Decision.DENY
    assert result.matched_rule == "extensions.origins.profiles.slack.egress.default"
    assert result.origin_profile == "slack"


def test_forbidden_path_exception_still_respects_path_allowlist():
    ok, spec_or_err = parse(
        """\
hushspec: "0.1.0"
rules:
  forbidden_paths:
    enabled: true
    patterns: ["**/*.key"]
    exceptions: ["/workspace/allowed.key"]
  path_allowlist:
    enabled: true
    write: ["/workspace/reports/**"]
"""
    )
    assert ok, spec_or_err
    spec = spec_or_err

    result = evaluate(
        spec,
        EvaluationAction(type="file_write", target="/workspace/allowed.key"),
    )

    assert result.decision == Decision.DENY
    assert result.matched_rule == "rules.path_allowlist"


def test_input_inject_denies_unlisted_type():
    ok, spec_or_err = parse(
        """\
hushspec: "0.1.0"
rules:
  input_injection:
    enabled: true
    allowed_types: [keyboard]
"""
    )
    assert ok, spec_or_err
    spec = spec_or_err

    result = evaluate(spec, EvaluationAction(type="input_inject", target="mouse"))

    assert result.decision == Decision.DENY
    assert result.matched_rule == "rules.input_injection.allowed_types"


def test_computer_use_respects_remote_desktop_channel_blocks():
    ok, spec_or_err = parse(
        """\
hushspec: "0.1.0"
rules:
  computer_use:
    enabled: true
    mode: observe
    allowed_actions: [remote.clipboard]
  remote_desktop_channels:
    enabled: true
    clipboard: false
    file_transfer: false
    audio: true
    drive_mapping: false
"""
    )
    assert ok, spec_or_err
    spec = spec_or_err

    result = evaluate(
        spec,
        EvaluationAction(type="computer_use", target="remote.clipboard"),
    )

    assert result.decision == Decision.DENY
    assert result.matched_rule == "rules.remote_desktop_channels.clipboard"


# glob_matches end-of-text anchoring
#
# Python's `re.search(r'...$', target)` treats `$` as "end of string OR just
# before a trailing \n", so a glob like "internal.corp" used to wrongly match
# "internal.corp\n". The translator now anchors with \Z (true end-of-string,
# no newline exception) instead of `$`, matching Rust `regex` / Go RE2 / JS
# non-multiline `$` end-of-text semantics.


def test_glob_does_not_match_target_with_trailing_newline():
    assert glob_matches("internal.corp", "internal.corp\n") is False
    assert glob_matches("internal.corp", "internal.corp") is True


def test_glob_star_does_not_match_trailing_newline():
    assert glob_matches("*.internal.corp", "api.internal.corp\n") is False
    assert glob_matches("*.internal.corp", "api.internal.corp") is True


def test_glob_ascii_patterns_unchanged():
    assert glob_matches("*.example.com", "api.example.com") is True
    assert glob_matches("*.example.com", "example.com") is False
    assert glob_matches("*.example.com", "api.example.com.evil.net") is False
    assert glob_matches("**/secrets/**", "a/b/secrets/c") is True
    assert glob_matches("**/x", "x") is True
    assert glob_matches("**/x", "a/b/x") is True
    assert glob_matches("a?b", "acb") is True
    assert glob_matches("a?b", "ab") is False
    assert glob_matches("literal$", "literal$") is True
    assert glob_matches("literal$", "literal") is False
