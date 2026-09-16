from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from hushspec import parse, parse_or_raise
from hushspec.conditions import RuntimeContext
from hushspec.parse import CoreSafeLoader
from hushspec.evaluate import (
    Decision,
    EvaluationAction,
    OriginContext,
    PostureContext,
    evaluate,
    glob_matches,
    host_pattern_matches,
    normalize_host,
    normalize_path,
    patch_stats,
    path_glob_matches,
    punycode_encode,
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


def _build_action(data: dict, context: dict | None = None) -> EvaluationAction:
    origin = _build_origin(data["origin"]) if "origin" in data else None
    posture = _build_posture(data["posture"]) if "posture" in data else None
    return EvaluationAction(
        type=data["type"],
        target=data.get("target"),
        content=data.get("content"),
        origin=origin,
        posture=posture,
        args_size=data.get("args_size"),
        url=data.get("url"),
        network=data.get("network"),
        timeout_ms=data.get("timeout_ms"),
        context=RuntimeContext.from_dict(context) if context is not None else None,
    )


def _collect_evaluation_cases():
    cases = []
    for eval_dir in EVALUATION_DIRS:
        dir_path = FIXTURES_ROOT / eval_dir
        if not dir_path.exists():
            continue
        for yaml_file in sorted(dir_path.glob("*.yaml")):
            with open(yaml_file) as f:
                # The HushSpec YAML profile is YAML 1.2 Core: `on`/`yes` are
                # plain strings, not booleans, so a fixture's `on:` transition
                # trigger must survive the load -> re-dump round trip below.
                fixture = yaml.load(f, Loader=CoreSafeLoader)
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

    action = _build_action(case["action"], case.get("context"))
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
          allow: []
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

    # D12: the effective default is the stricter of base and overlay, and the
    # reported path is the object whose `default` determined it -- the base.
    assert result.decision == Decision.DENY
    assert result.matched_rule == "rules.egress.default"
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


# patch_stats line-splitting parity
#
# `str.splitlines()` also breaks on \r, \v, \f, and the Unicode NEL/LS/PS
# separators, but Rust's `.lines()` and the TS/Go SDKs split only on \n. A
# bare \r with no \n used to be treated as its own line boundary here,
# double-counting additions/deletions relative to the other three SDKs.


def test_patch_stats_splits_only_on_newline_not_carriage_return():
    stats = patch_stats("+a\r+b")
    assert stats.additions == 1
    assert stats.deletions == 0


def test_patch_stats_counts_additions_and_deletions_with_real_newlines():
    # Regression guard: ordinary \n-delimited patch content (the common
    # case) must still count correctly after switching from splitlines() to
    # split("\n"), including skipping the +++/--- file headers.
    content = "--- a\n+++ b\n+line one\n+line two\n-old line\n context line\n"
    stats = patch_stats(content)
    assert stats.additions == 2
    assert stats.deletions == 1


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


# D5/D6: host and path normalization (core spec 3.14). These mirror the unit
# tests of the Rust reference (crates/hushspec/src/evaluate.rs) case for case,
# so a divergence surfaces here rather than only in the differential fuzzer.


class TestNormalizePath:
    def test_collapses_dot_and_dot_dot_segments(self):
        assert normalize_path("/proj/../.env") == "/.env"
        assert normalize_path("/a/../../b") == "/b"
        assert normalize_path("./a/./b") == "a/b"
        assert normalize_path("../a") == "../a"

    def test_unifies_separators_and_strips_trailing_slash(self):
        assert normalize_path("C:\\proj\\..\\.env") == "C:/.env"
        assert normalize_path("//data//x//") == "/data/x"
        assert normalize_path("/") == "/"

    def test_normalizes_to_nfc(self):
        assert normalize_path("/data/cafe\u0301/x") == "/data/caf\u00e9/x"


class TestPathGlobs:
    def test_leading_globstar_matches_zero_or_more_segments(self):
        assert path_glob_matches("**/.env", ".env") is True
        assert path_glob_matches("**/.env", "a/.env") is True
        assert path_glob_matches("**/.env", "/home/u/.env") is True
        assert path_glob_matches("/proj/**/secret.txt", "/proj/secret.txt") is True

    def test_trailing_globstar_requires_at_least_one_character(self):
        assert path_glob_matches("/home/**", "/home/x/y") is True
        assert path_glob_matches("/home/**", "/home") is False

    def test_single_wildcards_never_cross_a_separator(self):
        assert path_glob_matches("/tmp/*.log", "/tmp/a.log") is True
        assert path_glob_matches("/tmp/*.log", "/tmp/sub/a.log") is False
        assert path_glob_matches("/a?b", "/axb") is True
        assert path_glob_matches("/a?b", "/a/b") is False

    def test_brackets_and_braces_are_literal(self):
        assert path_glob_matches("/logs/[old]/**", "/logs/[old]/a") is True
        assert path_glob_matches("/logs/[old]/**", "/logs/o/a") is False


class TestNormalizeHost:
    def test_strips_scheme_userinfo_port_path_and_trailing_dot(self):
        assert normalize_host("API.EXAMPLE.COM:443") == "api.example.com"
        assert (
            normalize_host("https://user:pw@api.example.com:8443/v1?x=1#f")
            == "api.example.com"
        )
        assert normalize_host("api.example.com.") == "api.example.com"

    def test_keeps_bracketed_ipv6_literals(self):
        assert normalize_host("[::1]:8080") == "[::1]"

    def test_encodes_non_ascii_labels_as_idna_a_labels(self):
        assert normalize_host("B\u00dcCHER.example") == "xn--bcher-kva.example"

    def test_returns_none_for_syntactically_invalid_hosts(self):
        assert normalize_host("") is None
        assert normalize_host("a..b") is None
        assert normalize_host("bad host") is None


class TestHostPatterns:
    def test_single_star_is_exactly_one_label(self):
        assert host_pattern_matches("*.example.com", "api.example.com") is True
        assert host_pattern_matches("*.example.com", "a.b.example.com") is False
        assert host_pattern_matches("*.example.com", "example.com") is False
        assert host_pattern_matches("api-*.example.com", "api-1.example.com") is True

    def test_double_star_is_one_or_more_labels(self):
        assert host_pattern_matches("**.example.com", "a.b.example.com") is True
        assert host_pattern_matches("**.example.com", "example.com") is False

    def test_patterns_are_idna_normalized(self):
        assert (
            host_pattern_matches("b\u00fccher.example", "xn--bcher-kva.example") is True
        )

    def test_ip_literals_match_only_exactly(self):
        assert host_pattern_matches("10.0.*.*", "10.0.0.1") is False
        assert host_pattern_matches("10.0.0.1", "10.0.0.1") is True
        assert host_pattern_matches("[::1]", "[::1]") is True


class TestPunycode:
    def test_matches_rfc_3492_examples(self):
        assert punycode_encode("b\u00fccher") == "bcher-kva"
        assert punycode_encode("m\u00fcnchen") == "mnchen-3ya"

    def test_agrees_with_the_standard_library_codec(self):
        for label in ("b\u00fccher", "m\u00fcnchen", "\u4f8b\u3048", "caf\u00e9"):
            assert punycode_encode(label) == label.encode("punycode").decode("ascii")


class TestUnknownActionTypes:
    def test_unknown_action_type_denies(self):
        spec = parse_or_raise(
            'hushspec: "0.2.0"\nrules:\n  tool_access:\n    default: allow\n'
        )
        result = evaluate(spec, EvaluationAction(type="teleport", target="anywhere"))
        assert result.decision == Decision.DENY
        assert result.matched_rule == "__unknown_action_type__"

    def test_custom_action_without_posture_denies(self):
        spec = parse_or_raise(
            'hushspec: "0.2.0"\nrules:\n  tool_access:\n    default: allow\n'
        )
        result = evaluate(spec, EvaluationAction(type="custom", target="anything"))
        assert result.decision == Decision.DENY
        assert result.matched_rule == "__unknown_action_type__"
