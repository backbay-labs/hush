import time

import pytest

from hushspec import (
    DefaultAction,
    DetectionExtension,
    EvaluationAction,
    Extensions,
    GovernanceMetadata,
    HushSpec,
    PatchIntegrityRule,
    PostureExtension,
    PostureState,
    PostureTransition,
    Rules,
    ThreatIntelDetection,
    TransitionTrigger,
    content_hash,
    evaluate,
    is_supported,
    merge,
    parse,
    parse_or_raise,
    validate,
)


class TestParseMinimal:
    def test_parse_minimal_valid(self):
        yaml = """
hushspec: "0.1.0"
name: test
"""
        ok, spec = parse(yaml)
        assert ok is True
        assert isinstance(spec, HushSpec)
        assert spec.hushspec == "0.1.0"
        assert spec.name == "test"
        result = validate(spec)
        assert result.is_valid

    def test_parse_or_raise_valid(self):
        yaml = """
hushspec: "0.1.0"
name: test
"""
        spec = parse_or_raise(yaml)
        assert spec.hushspec == "0.1.0"

    def test_parse_or_raise_invalid(self):
        yaml = """
hushspec: "0.1.0"
unknown_field: true
"""
        with pytest.raises(ValueError, match="unknown field `unknown_field`"):
            parse_or_raise(yaml)


class TestParseWithRules:
    def test_parse_with_rules(self):
        yaml = """
hushspec: "0.1.0"
name: test-rules
rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
    exceptions:
      - "**/.ssh/config"
  egress:
    allow:
      - "api.openai.com"
    default: block
  tool_access:
    block:
      - shell_exec
    default: allow
"""
        ok, spec = parse(yaml)
        assert ok is True
        assert isinstance(spec, HushSpec)
        rules = spec.rules
        assert rules is not None

        fp = rules.forbidden_paths
        assert fp is not None
        assert len(fp.patterns) == 2
        assert len(fp.exceptions) == 1

        eg = rules.egress
        assert eg is not None
        assert len(eg.allow) == 1
        assert eg.default == DefaultAction.BLOCK

        ta = rules.tool_access
        assert ta is not None
        assert ta.block == ["shell_exec"]
        assert ta.default == DefaultAction.ALLOW


class TestRejectUnknownFields:
    def test_reject_unknown_top_level(self):
        yaml = """
hushspec: "0.1.0"
name: test
unknown_field: true
"""
        ok, err = parse(yaml)
        assert ok is False
        assert isinstance(err, str)
        assert "unknown field `unknown_field`" in err

    def test_reject_unknown_rule(self):
        yaml = """
hushspec: "0.1.0"
rules:
  nonexistent_rule:
    enabled: true
"""
        ok, err = parse(yaml)
        assert ok is False
        assert isinstance(err, str)
        assert "unknown field `nonexistent_rule` at rules" in err

    def test_reject_unknown_extension(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  nonexistent_extension:
    enabled: true
"""
        ok, err = parse(yaml)
        assert ok is False
        assert isinstance(err, str)
        assert "unknown field `nonexistent_extension` at extensions" in err

    def test_reject_unknown_nested_field(self):
        yaml = """
hushspec: "0.1.0"
rules:
  egress:
    default: block
    extra_field: true
"""
        ok, err = parse(yaml)
        assert ok is False
        assert isinstance(err, str)
        assert "unknown field `extra_field` at rules.egress" in err

    def test_reject_invalid_bool_type(self):
        yaml = """
hushspec: "0.1.0"
rules:
  egress:
    enabled: "yes"
    default: block
"""
        ok, err = parse(yaml)
        assert ok is False
        assert isinstance(err, str)
        assert "rules.egress.enabled: invalid type, expected a boolean" in err

    def test_missing_hushspec_version(self):
        yaml = """
name: test
"""
        ok, err = parse(yaml)
        assert ok is False
        assert isinstance(err, str)
        assert "hushspec" in err

    def test_non_string_hushspec_version(self):
        yaml = """
hushspec: 42
"""
        ok, err = parse(yaml)
        assert ok is False
        assert isinstance(err, str)
        assert "hushspec" in err

    def test_not_a_mapping(self):
        yaml = "- item1\n- item2\n"
        ok, err = parse(yaml)
        assert ok is False
        assert isinstance(err, str)
        assert "mapping" in err

    def test_invalid_yaml(self):
        yaml = "{{{{invalid yaml"
        ok, err = parse(yaml)
        assert ok is False
        assert isinstance(err, str)
        assert "YAML parse error" in err


class TestValidate:
    def test_validate_unsupported_version(self):
        yaml = """
hushspec: "99.0.0"
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid
        assert any("unsupported" in str(e) for e in result.errors)

    def test_parse_rejects_duplicate_secret_pattern_names(self):
        yaml = """
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: aws_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: aws_key
        pattern: "ASIA[0-9A-Z]{16}"
        severity: critical
"""
        ok, err = parse(yaml)
        assert ok is False
        assert isinstance(err, str)
        assert "duplicate secret pattern name" in err

    def test_parse_rejects_invalid_regex_pattern(self):
        yaml = """
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: bad
        pattern: "["
        severity: critical
"""
        ok, err = parse(yaml)
        assert ok is False
        assert isinstance(err, str)
        assert "valid regular expression" in err

    def test_parse_rejects_invalid_detection_top_k(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      top_k: 0
"""
        ok, err = parse(yaml)
        assert ok is False
        assert isinstance(err, str)
        assert "top_k must be >= 1" in err

    def test_validate_no_rules_warning(self):
        yaml = """
hushspec: "0.1.0"
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert result.is_valid
        assert any("no rules" in w for w in result.warnings)

    def test_validate_empty_rules_warning(self):
        yaml = """
hushspec: "0.1.0"
rules: {}
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert result.is_valid
        assert any("no rules configured" in w for w in result.warnings)

    def test_validate_max_args_size_zero(self):
        yaml = """
hushspec: "0.1.0"
rules:
  tool_access:
    max_args_size: 0
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "max_args_size must be >= 1" in err

    def test_validate_imbalance_ratio_zero(self):
        yaml = """
hushspec: "0.1.0"
rules:
  patch_integrity:
    max_imbalance_ratio: 0
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "max_imbalance_ratio must be > 0" in err

    def test_validate_imbalance_ratio_nan_rejected(self):
        # YAML `.nan` passes every `<= 0` / `> 0` bounds check (NaN
        # comparisons are always false), so a bounds check alone would admit
        # it and then make `require_balance` fail open (`ratio > NaN` is also
        # always false). An explicit isfinite check is what rejects it.
        yaml = """
hushspec: "0.1.0"
rules:
  patch_integrity:
    max_imbalance_ratio: .nan
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "max_imbalance_ratio" in err
        assert "finite" in err

    def test_validate_imbalance_ratio_infinity_rejected(self):
        # +Infinity passes for a different reason than NaN: the field has no
        # upper bound (only `min_exclusive=0`) and `Infinity <= 0` is False,
        # so only the isfinite check refuses it.
        yaml = """
hushspec: "0.1.0"
rules:
  patch_integrity:
    max_imbalance_ratio: .inf
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "max_imbalance_ratio" in err
        assert "finite" in err

    def test_validate_similarity_threshold_nan_rejected(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      similarity_threshold: .nan
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "similarity_threshold" in err
        assert "finite" in err

    def test_validate_direct_rejects_nan_imbalance_ratio(self):
        # Exercises validate.py's own isfinite check directly, independent of
        # raw_validate.py's pre-check in parse() -- e.g. a HushSpec built
        # programmatically rather than parsed from YAML.
        spec = HushSpec(
            hushspec="0.1.0",
            rules=Rules(
                patch_integrity=PatchIntegrityRule(max_imbalance_ratio=float("nan"))
            ),
        )
        result = validate(spec)
        assert not result.is_valid
        assert any("finite" in str(e) for e in result.errors)

    def test_validate_direct_rejects_infinite_similarity_threshold(self):
        spec = HushSpec(
            hushspec="0.1.0",
            extensions=Extensions(
                detection=DetectionExtension(
                    threat_intel=ThreatIntelDetection(similarity_threshold=float("inf"))
                )
            ),
        )
        result = validate(spec)
        assert not result.is_valid
        assert any("finite" in str(e) for e in result.errors)


class TestMerge:
    def test_merge_replace_uses_child(self):
        base = parse_or_raise("""
hushspec: "0.1.0"
name: base
rules:
  egress:
    allow: ["a.com"]
    default: block
""")
        child = parse_or_raise("""
hushspec: "0.1.0"
name: child
extends: base
merge_strategy: replace
rules:
  tool_access:
    block: ["shell_exec"]
    default: allow
""")
        merged = merge(base, child)
        assert merged.name == "child"
        assert merged.extends is None
        assert merged.rules is not None
        assert merged.rules.egress is None
        assert merged.rules.tool_access is not None

    def test_merge_shallow_child_overrides_rule(self):
        base = parse_or_raise("""
hushspec: "0.1.0"
rules:
  egress:
    allow: ["a.com"]
    default: block
  forbidden_paths:
    patterns: ["**/.ssh/**"]
""")
        child = parse_or_raise("""
hushspec: "0.1.0"
extends: base
merge_strategy: merge
rules:
  egress:
    allow: ["b.com"]
    default: allow
""")
        merged = merge(base, child)
        assert merged.extends is None
        rules = merged.rules
        assert rules is not None
        # egress replaced by child
        assert rules.egress is not None
        assert rules.egress.allow == ["b.com"]
        # forbidden_paths preserved from base
        assert rules.forbidden_paths is not None

    def test_merge_deep_child_overrides_rule(self):
        base = parse_or_raise("""
hushspec: "0.1.0"
rules:
  egress:
    allow: ["a.com"]
    default: block
  forbidden_paths:
    patterns: ["**/.ssh/**"]
""")
        child = parse_or_raise("""
hushspec: "0.1.0"
extends: base
rules:
  egress:
    allow: ["b.com"]
    default: allow
""")
        merged = merge(base, child)
        assert merged.extends is None
        rules = merged.rules
        assert rules is not None
        # deep_merge is default: child egress overrides base egress
        assert rules.egress is not None
        assert rules.egress.allow == ["b.com"]
        # forbidden_paths preserved from base
        assert rules.forbidden_paths is not None

    def test_merge_name_fallback(self):
        base = parse_or_raise("""
hushspec: "0.1.0"
name: base-name
""")
        child = parse_or_raise("""
hushspec: "0.1.0"
""")
        merged = merge(base, child)
        # Child has no name, falls back to base
        assert merged.name == "base-name"

    def test_merge_metadata_child_over_parent(self):
        # Metadata merges child-over-parent like every other field
        # (core spec 2.3).
        base = parse_or_raise("""
hushspec: "0.1.0"
name: base
metadata:
  author: a
""")
        child = parse_or_raise("""
hushspec: "0.1.0"
name: child
extends: base
metadata:
  author: b
""")
        merged = merge(base, child)
        assert merged.metadata is not None
        assert merged.metadata.author == "b"

    def test_merge_metadata_parent_preserved_when_child_absent(self):
        base = parse_or_raise("""
hushspec: "0.1.0"
name: base
metadata:
  author: a
""")
        child = parse_or_raise("""
hushspec: "0.1.0"
name: child
extends: base
""")
        merged = merge(base, child)
        assert merged.metadata is not None
        assert merged.metadata.author == "a"

    def test_merge_metadata_is_deep_copied(self):
        # Mutating the merged metadata must not bleed into the source specs.
        base = HushSpec(hushspec="0.1.0", metadata=GovernanceMetadata(author="a"))
        child = HushSpec(hushspec="0.1.0")
        merged = merge(base, child)
        assert merged.metadata is not None
        merged.metadata.author = "mutated"
        assert base.metadata.author == "a"


class TestRoundtrip:
    def test_roundtrip_yaml(self):
        import yaml

        yaml_str = """
hushspec: "0.1.0"
name: roundtrip
rules:
  egress:
    allow:
      - "*.openai.com"
    default: block
"""
        spec = parse_or_raise(yaml_str)
        out = yaml.dump(spec.to_dict(), default_flow_style=False)
        spec2 = parse_or_raise(out)
        assert spec.hushspec == spec2.hushspec
        assert spec.name == spec2.name
        assert spec.rules is not None
        assert spec2.rules is not None
        assert spec.rules.egress is not None
        assert spec2.rules.egress is not None
        assert spec.rules.egress.allow == spec2.rules.egress.allow
        assert spec.rules.egress.default == spec2.rules.egress.default



# browser_automation / code_execution raw validation
#
# Both rule blocks get the same pre-decode treatment as every other block:
# wrong-typed fields, out-of-range bounds and unsafe regex in
# extra_credential_patterns are refused by parse()'s pre-check rather than
# reaching the dataclass unchecked via from_dict().


class TestBrowserAutomationValidation:
    def test_rejects_wrong_typed_enabled(self):
        yaml = """
hushspec: "0.1.0"
rules:
  browser_automation:
    enabled: "yes"
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "rules.browser_automation.enabled: invalid type, expected a boolean" in err

    def test_rejects_unknown_field(self):
        yaml = """
hushspec: "0.1.0"
rules:
  browser_automation:
    enabled: true
    bogus_field: true
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "unknown field `bogus_field` at rules.browser_automation" in err

    def test_rejects_non_array_allowed_domains(self):
        yaml = """
hushspec: "0.1.0"
rules:
  browser_automation:
    allowed_domains: "example.com"
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "rules.browser_automation.allowed_domains: invalid type, expected an array" in err

    def test_rejects_unsafe_regex_in_extra_credential_patterns(self):
        yaml = """
hushspec: "0.1.0"
rules:
  browser_automation:
    enabled: true
    extra_credential_patterns:
      - "(a+)+"
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "RE2" in err

    def test_accepts_valid_browser_automation_rule(self):
        yaml = """
hushspec: "0.1.0"
rules:
  browser_automation:
    enabled: true
    allowed_domains: ["example.com"]
    blocked_domains: []
    allowed_verbs: ["click", "type"]
    credential_detection: true
    extra_credential_patterns:
      - "sk-[A-Za-z0-9]{20,}"
"""
        ok, spec = parse(yaml)
        assert ok is True
        assert isinstance(spec, HushSpec)
        assert spec.rules is not None
        assert spec.rules.browser_automation is not None
        assert spec.rules.browser_automation.allowed_domains == ["example.com"]


class TestCodeExecutionValidation:
    def test_rejects_wrong_typed_enabled(self):
        yaml = """
hushspec: "0.1.0"
rules:
  code_execution:
    enabled: "yes"
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "rules.code_execution.enabled: invalid type, expected a boolean" in err

    def test_rejects_unknown_field(self):
        yaml = """
hushspec: "0.1.0"
rules:
  code_execution:
    enabled: true
    bogus_field: true
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "unknown field `bogus_field` at rules.code_execution" in err

    def test_rejects_zero_max_scan_bytes(self):
        yaml = """
hushspec: "0.1.0"
rules:
  code_execution:
    enabled: true
    max_scan_bytes: 0
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "rules.code_execution.max_scan_bytes must be >= 1" in err

    def test_rejects_negative_max_execution_time_ms(self):
        yaml = """
hushspec: "0.1.0"
rules:
  code_execution:
    enabled: true
    max_execution_time_ms: -1
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "rules.code_execution.max_execution_time_ms must be >= 0" in err

    def test_accepts_valid_code_execution_rule(self):
        yaml = """
hushspec: "0.1.0"
rules:
  code_execution:
    enabled: true
    language_allowlist: ["python"]
    module_denylist: ["os", "subprocess"]
    network_access: false
    max_execution_time_ms: 5000
    max_scan_bytes: 65536
"""
        ok, spec = parse(yaml)
        assert ok is True
        assert isinstance(spec, HushSpec)
        assert spec.rules is not None
        assert spec.rules.code_execution is not None
        assert spec.rules.code_execution.module_denylist == ["os", "subprocess"]



# A posture transition duration is ASCII digits only.
#
# Python's `\d` is Unicode-aware, so `^\d+[smhd]$` would accept a fullwidth or
# Arabic-indic digit run (e.g. "４s", "٤s") as a well-formed duration. The
# pattern spells the digit class `[0-9]`, so only ASCII digits are accepted.


class TestDurationAsciiOnly:
    def test_rejects_fullwidth_digit_duration_via_parse(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  posture:
    initial: normal
    states:
      normal: {}
    transitions:
      - from: normal
        to: normal
        on: timeout
        after: "４s"
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "must match" in err

    def test_rejects_arabic_indic_digit_duration_via_parse(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  posture:
    initial: normal
    states:
      normal: {}
    transitions:
      - from: normal
        to: normal
        on: timeout
        after: "٤s"
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "must match" in err

    def test_accepts_ascii_digit_duration_via_parse(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  posture:
    initial: normal
    states:
      normal: {}
    transitions:
      - from: normal
        to: normal
        on: timeout
        after: "4s"
"""
        ok, spec = parse(yaml)
        assert ok is True

    def test_rejects_fullwidth_digit_duration_via_validate_direct(self):
        # Exercises validate.py's own _DURATION_PATTERN directly, independent
        # of raw_validate.py's pre-check in parse() -- e.g. a HushSpec built
        # programmatically rather than parsed from YAML.
        spec = HushSpec(
            hushspec="0.1.0",
            extensions=Extensions(
                posture=PostureExtension(
                    initial="normal",
                    states={"normal": PostureState()},
                    transitions=[
                        PostureTransition(
                            from_state="normal",
                            to="normal",
                            on=TransitionTrigger.TIMEOUT,
                            after="４s",
                        ),
                    ],
                )
            ),
        )
        result = validate(spec)
        assert not result.is_valid
        assert any("must match" in str(e) for e in result.errors)


# YAML loader robustness
#
# PyYAML's `safe_load` is more permissive than the HushSpec YAML profile
# (core spec 2.4) in three ways a fail-closed parser must not tolerate: it
# silently accepts duplicate mapping keys (last-wins), has no alias/anchor
# expansion cap (a "billion laughs" bomb would blow up the post-parse tree
# walks), and lets deeply nested flow YAML surface an uncaught RecursionError
# instead of a clean parse error. `parse()` closes all three.


class TestYamlRobustness:
    def test_rejects_duplicate_top_level_keys(self):
        # PyYAML would keep the last value; the profile rejects duplicates.
        ok, err = parse('hushspec: "0.1.0"\nname: a\nname: b\n')
        assert ok is False
        assert isinstance(err, str)
        assert "duplicate entry with key" in err

    def test_rejects_duplicate_nested_keys(self):
        yaml = """
hushspec: "0.1.0"
rules:
  egress:
    default: block
    default: allow
"""
        ok, err = parse(yaml)
        assert ok is False
        assert isinstance(err, str)
        assert "duplicate entry with key" in err

    def test_anchor_bomb_fails_fast(self):
        # A nested-anchor bomb: tiny source text whose alias-expanded size is
        # astronomically large. It must be rejected quickly (via the alias
        # expansion cap), not hang while the post-parse passes walk the
        # expanded structure.
        lines = ["a: &a [x,x,x,x,x,x,x,x,x]"]
        prev = "a"
        for name in "bcdefghij":
            fan = ",".join([f"*{prev}"] * 9)
            lines.append(f"{name}: &{name} [{fan}]")
            prev = name
        bomb = "\n".join(lines) + "\n"

        start = time.monotonic()
        ok, err = parse(bomb)
        elapsed = time.monotonic() - start

        assert ok is False
        assert isinstance(err, str)
        # Generous bound purely as a hang detector -- the cap rejects in ~ms.
        assert elapsed < 5.0, f"anchor bomb took {elapsed:.2f}s (expected fast rejection)"

    def test_deeply_nested_flow_returns_error_not_traceback(self):
        # 10000-deep flow sequence overflows the interpreter stack during
        # compose; PyYAML raises a bare RecursionError (not a YAMLError), which
        # must be caught so parse() returns (False, msg) rather than crashing.
        deep = "[" * 10000 + "]" * 10000
        ok, err = parse(deep)
        assert ok is False
        assert isinstance(err, str)

    def test_anchors_are_rejected_by_the_yaml_profile(self):
        # Core spec 2.4: anchors are outside the HushSpec YAML profile, even
        # in a small non-malicious document, so every SDK rejects them.
        yaml = """
hushspec: "0.1.0"
name: anchored
rules:
  egress:
    allow: &domains
      - api.example.com
    block: []
    default: block
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "anchors are not allowed" in err


class TestYamlProfile:
    """Core spec 2.4: the accepted YAML dialect."""

    def test_rejects_aliases(self):
        ok, err = parse(
            'hushspec: "0.2.0"\n'
            "rules:\n"
            "  forbidden_paths:\n"
            "    patterns: &secrets\n"
            '      - "**/.env"\n'
            "    exceptions: *secrets\n"
        )
        assert ok is False
        assert "are not allowed (YAML profile)" in err

    def test_rejects_merge_keys(self):
        ok, err = parse(
            'hushspec: "0.2.0"\n'
            "rules:\n"
            "  egress:\n"
            "    <<: {default: block}\n"
        )
        assert ok is False
        assert "merge keys are not allowed" in err

    def test_rejects_multi_document_streams(self):
        ok, err = parse(
            'hushspec: "0.2.0"\nname: first\n---\nhushspec: "0.2.0"\nname: second\n'
        )
        assert ok is False
        assert "multi-document streams are not allowed" in err

    def test_accepts_a_leading_directive_end_marker(self):
        ok, spec = parse('---\nhushspec: "0.2.0"\nname: only\n')
        assert ok is True
        assert spec.name == "only"

    def test_rejects_yaml_1_1_booleans(self):
        for literal in ("yes", "no", "on", "off"):
            ok, err = parse(
                f'hushspec: "0.2.0"\nrules:\n  egress:\n    enabled: {literal}\n'
                "    default: block\n"
            )
            assert ok is False, literal
            assert "expected a boolean" in err, literal

    def test_still_accepts_core_booleans(self):
        for literal, expected in (("true", True), ("false", False), ("True", True)):
            ok, spec = parse(
                f'hushspec: "0.2.0"\nrules:\n  egress:\n    enabled: {literal}\n'
                "    default: block\n"
            )
            assert ok is True, literal
            assert spec.rules.egress.enabled is expected, literal

    def test_a_bare_on_key_stays_a_string(self):
        # `on:` is the posture transition trigger field; under YAML 1.1 PyYAML
        # would turn it into the boolean key True.
        ok, spec = parse(
            'hushspec: "0.2.0"\n'
            "extensions:\n"
            "  posture:\n"
            "    initial: standard\n"
            "    states:\n"
            "      standard:\n"
            "        capabilities: [tool_call]\n"
            "      locked:\n"
            "        capabilities: []\n"
            "    transitions:\n"
            "      - from: standard\n"
            "        to: locked\n"
            "        on: user_denial\n"
        )
        assert ok is True
        assert spec.extensions.posture.transitions[0].on.value == "user_denial"

    def test_rejects_tab_indentation(self):
        ok, err = parse('hushspec: "0.2.0"\nrules:\n\tegress:\n\t\tdefault: block\n')
        assert ok is False
        assert "YAML parse error" in err

    def test_rejects_documents_over_the_size_cap(self):
        oversized = 'hushspec: "0.2.0"\nname: "' + "x" * (1024 * 1024) + '"\n'
        ok, err = parse(oversized)
        assert ok is False
        assert "maximum size" in err

    def test_rejects_nesting_past_the_depth_cap(self):
        body = 'hushspec: "0.2.0"\nrules:\n  shell_commands:\n    when:\n'
        indent = 6
        for _ in range(40):
            body += " " * indent + "not:\n"
            indent += 2
        body += " " * indent + "context: {a: 1}\n"
        ok, err = parse(body)
        assert ok is False
        assert "maximum depth" in err


class TestVersionAcceptance:
    """Core spec 2.2: an engine supporting minor X.Y accepts every X.Y.Z."""

    def test_accepts_every_patch_of_a_supported_minor(self):
        for version in ("0.1.0", "0.1.1", "0.1.99", "0.2.0", "0.2.7", "1.0.0", "1.0.3"):
            assert is_supported(version) is True, version
            ok, spec = parse(f'hushspec: "{version}"\nname: v\n')
            assert ok is True, version
            assert validate(spec).is_valid, version

    def test_rejects_unsupported_or_malformed_versions(self):
        for version in ("0.3.0", "1.7.0", "2.0.0", "0.1", "0.1.0.0", "0.1.x", "+0.1.0", ""):
            assert is_supported(version) is False, version

    def test_a_one_point_zero_document_is_evaluated_as_a_zero_point_two_one(self):
        # Core spec 10.2: 1.0 freezes the 0.2 semantics without changing them,
        # so one document declared under either version validates alike and
        # reaches the same decision by the same rule.
        def document(version: str) -> str:
            return f"""
hushspec: "{version}"
name: version-equivalence
rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
  egress:
    allow:
      - api.example.com
    default: block
  tool_access:
    block:
      - shell_exec
    default: allow
"""

        zero = parse_or_raise(document("0.2.0"))
        one = parse_or_raise(document("1.0.0"))
        assert validate(zero).is_valid
        assert validate(one).is_valid

        actions = [
            ("file_read", "/home/agent/.ssh/id_ed25519"),
            ("egress", "api.example.com"),
            ("egress", "blocked.example.net"),
            ("tool_call", "shell_exec"),
        ]
        for action_type, target in actions:
            action = EvaluationAction(type=action_type, target=target)
            under_zero = evaluate(zero, action)
            under_one = evaluate(one, action)
            assert under_one.decision == under_zero.decision, (action_type, target)
            assert under_one.matched_rule == under_zero.matched_rule, (
                action_type,
                target,
            )
            assert under_one.reason == under_zero.reason, (action_type, target)

        denied = evaluate(
            one, EvaluationAction(type="file_read", target="/home/agent/.ssh/id_rsa")
        )
        assert denied.decision == "deny"
        assert denied.matched_rule == "rules.forbidden_paths.patterns"

        # The `hushspec` field is part of the canonical form, so the two
        # hashes differ; what must not differ is the decisions they hash.
        assert content_hash(zero) != content_hash(one)

    def test_unsupported_version_names_the_supported_minors(self):
        spec = parse_or_raise('hushspec: "0.9.0"\nname: v\n')
        result = validate(spec)
        assert not result.is_valid
        message = str(result.errors[0])
        assert message.startswith("unsupported hushspec version: 0.9.0")
        assert "0.1, 0.2, 1.0" in message
        assert result.errors[0].kind == "unsupported_version"
        # And the registry code the shared `invalid/` sidecars pin.
        assert result.errors[0].code == "E002"
