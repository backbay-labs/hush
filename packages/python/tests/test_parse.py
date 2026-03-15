"""Tests for parse, validate, and merge — mirrors the Rust/TS test cases."""

from hushspec import (
    DefaultAction,
    HushSpec,
    MergeStrategy,
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

    def test_validate_duplicate_secret_pattern_names(self):
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
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid
        assert any("duplicate" in str(e) for e in result.errors)

    def test_validate_invalid_regex_pattern(self):
        yaml = """
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: bad
        pattern: "["
        severity: critical
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid
        assert any("regular expression" in str(e) for e in result.errors)

    def test_validate_invalid_detection_top_k(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      top_k: 0
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid

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
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid

    def test_validate_imbalance_ratio_zero(self):
        yaml = """
hushspec: "0.1.0"
rules:
  patch_integrity:
    max_imbalance_ratio: 0
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid


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
merge_strategy: replace
rules:
  tool_access:
    block: ["shell_exec"]
    default: allow
""")
        merged = merge(base, child)
        assert merged.name == "child"
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
merge_strategy: merge
rules:
  egress:
    allow: ["b.com"]
    default: allow
""")
        merged = merge(base, child)
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
rules:
  egress:
    allow: ["b.com"]
    default: allow
""")
        merged = merge(base, child)
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
