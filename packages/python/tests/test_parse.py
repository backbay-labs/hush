import time

from hushspec import (
    DefaultAction,
    DetectionExtension,
    Extensions,
    GovernanceMetadata,
    HushSpec,
    MergeStrategy,
    PatchIntegrityRule,
    PostureExtension,
    PostureState,
    PostureTransition,
    Rules,
    ThreatIntelDetection,
    TransitionTrigger,
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
        try:
            parse_or_raise(yaml)
            assert False, "Expected ValueError"
        except ValueError as e:
            assert "unknown top-level field" in str(e)


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
        assert "unknown top-level field" in err

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
        assert "unknown rule" in err

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
        assert "unknown extension" in err

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
        assert "unknown field at rules.egress" in err

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
        assert "rules.egress.enabled must be a boolean" in err

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
        # YAML `.nan` fails every `<= 0` / `> 0` bounds check (NaN comparisons
        # are always false), so without an explicit isfinite check this used
        # to pass validation and then make `require_balance` fail OPEN
        # (`ratio > NaN` is also always false).
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
        # +Infinity is a distinct silent-pass bug from NaN: this field has no
        # upper bound (only `min_exclusive=0`), and `Infinity <= 0` is False,
        # so +Infinity used to slip through validation entirely.
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
        # S1: metadata must merge child-over-parent like every other field
        # (it was previously dropped from the merged result entirely).
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



# Phase-gated guards: browser_automation / code_execution raw validation
#
# raw_validate.py previously had no validator for these two rule blocks (only
# RULE_KEYS listed them as known top-level keys), so malformed content --
# wrong-typed fields, out-of-range bounds, unsafe regex in
# extra_credential_patterns -- sailed through parse()'s pre-check and landed
# untype-checked in the dataclass via from_dict(). These mirror the checks
# already applied to every other rule block.


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
        assert "rules.browser_automation.enabled must be a boolean" in err

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
        assert "unknown field at rules.browser_automation" in err

    def test_rejects_non_array_allowed_domains(self):
        yaml = """
hushspec: "0.1.0"
rules:
  browser_automation:
    allowed_domains: "example.com"
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "rules.browser_automation.allowed_domains must be an array" in err

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
        assert "rules.code_execution.enabled must be a boolean" in err

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
        assert "unknown field at rules.code_execution" in err

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



# D11: posture transition duration must be ASCII-digit only
#
# `^\d+[smhd]$` used Python's Unicode-aware \d, so a fullwidth or
# Arabic-indic digit run (e.g. "４s", "٤s") was wrongly accepted as a valid
# duration -- TS (JS \d is ASCII-only) and Go (RE2 \d is ASCII-only by
# default) already rejected these. [0-9] makes Python agree.


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


# YAML loader robustness (parity with the Rust/TS/Go SDKs)
#
# PyYAML's `safe_load` is more permissive than the YAML parsers behind the
# other three SDKs in three ways that a fail-closed parser must not tolerate:
# it silently accepts duplicate mapping keys (last-wins), has no alias/anchor
# expansion cap (a "billion laughs" bomb blows up our post-parse tree walks),
# and lets deeply nested flow YAML surface an uncaught RecursionError instead
# of a clean parse error. `parse()` now hardens all three.


class TestYamlRobustness:
    def test_rejects_duplicate_top_level_keys(self):
        # PyYAML would keep the last value; Rust/TS/Go reject duplicates.
        ok, err = parse('hushspec: "0.1.0"\nname: a\nname: b\n')
        assert ok is False
        assert isinstance(err, str)
        assert "duplicate key" in err

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
        assert "duplicate key" in err

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

    def test_legitimate_anchors_still_resolve(self):
        # A small, non-malicious anchor/alias document must still parse fine.
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
        ok, spec = parse(yaml)
        assert ok is True
        assert isinstance(spec, HushSpec)
        assert spec.rules is not None
        assert spec.rules.egress is not None
        assert spec.rules.egress.allow == ["api.example.com"]
