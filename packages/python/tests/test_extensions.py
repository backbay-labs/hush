"""Tests for posture, origins, detection parsing and validation.

Mirrors the Rust/TS extension test cases.
"""

from hushspec import (
    HushSpec,
    OriginDefaultBehavior,
    merge,
    parse_or_raise,
    validate,
)


class TestPosture:
    def test_parse_posture_extension(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  posture:
    initial: standard
    states:
      restricted:
        description: Minimal access
        capabilities: [file_access]
        budgets: {}
      standard:
        capabilities: [file_access, file_write, egress]
        budgets:
          file_writes: 50
          egress_calls: 20
      elevated:
        capabilities: [file_access, file_write, egress, shell, tool_call, patch]
        budgets:
          file_writes: 200
    transitions:
      - from: restricted
        to: standard
        on: user_approval
      - from: standard
        to: elevated
        on: user_approval
      - from: "*"
        to: restricted
        on: critical_violation
      - from: elevated
        to: standard
        on: timeout
        after: "1h"
      - from: standard
        to: restricted
        on: budget_exhausted
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert result.is_valid, f"errors: {result.errors}"

        ext = spec.extensions
        assert ext is not None
        posture = ext.posture
        assert posture is not None
        assert posture.initial == "standard"
        assert len(posture.states) == 3
        assert len(posture.transitions) == 5

    def test_validate_posture_invalid_initial(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  posture:
    initial: nonexistent
    states:
      valid:
        capabilities: []
    transitions: []
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid

    def test_validate_posture_timeout_requires_after(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  posture:
    initial: a
    states:
      a:
        capabilities: []
      b:
        capabilities: []
    transitions:
      - from: a
        to: b
        on: timeout
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid

    def test_validate_posture_negative_budget(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  posture:
    initial: a
    states:
      a:
        capabilities: []
        budgets:
          tool_calls: -5
    transitions: []
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid

    def test_validate_posture_empty_states(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  posture:
    initial: a
    states: {}
    transitions: []
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid

    def test_validate_posture_transition_to_wildcard(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  posture:
    initial: a
    states:
      a:
        capabilities: []
    transitions:
      - from: a
        to: "*"
        on: user_approval
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid

    def test_validate_posture_transition_from_undefined(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  posture:
    initial: a
    states:
      a:
        capabilities: []
      b:
        capabilities: []
    transitions:
      - from: nonexistent
        to: b
        on: user_approval
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid

    def test_validate_posture_unknown_capability_warning(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  posture:
    initial: a
    states:
      a:
        capabilities: [file_access, unknown_cap]
    transitions: []
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert result.is_valid
        assert any("unknown capability" in w for w in result.warnings)


class TestOrigins:
    def test_parse_origins_extension(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  posture:
    initial: elevated
    states:
      elevated:
        capabilities: [tool_call]
    transitions: []
  origins:
    default_behavior: deny
    profiles:
      - id: incident-room
        match:
          provider: slack
          tags: [incident]
        posture: elevated
        tool_access:
          allow: ["*"]
          default: allow
        budgets:
          tool_calls: 200
        explanation: Incident response channel
      - id: external-chat
        match:
          visibility: external_shared
        data:
          redact_before_send: true
          block_sensitive_outputs: true
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert result.is_valid, f"errors: {result.errors}"

        ext = spec.extensions
        assert ext is not None
        origins = ext.origins
        assert origins is not None
        assert len(origins.profiles) == 2
        assert origins.profiles[0].id == "incident-room"

    def test_validate_origins_duplicate_ids(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  origins:
    profiles:
      - id: dup
        match:
          provider: slack
      - id: dup
        match:
          provider: teams
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid

    def test_validate_origins_posture_without_extension(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  origins:
    profiles:
      - id: test
        posture: elevated
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid

    def test_validate_origins_posture_undefined_state(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  posture:
    initial: a
    states:
      a:
        capabilities: []
    transitions: []
  origins:
    profiles:
      - id: test
        posture: nonexistent
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid


class TestDetection:
    def test_parse_detection_extension(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      enabled: true
      warn_at_or_above: suspicious
      block_at_or_above: high
    jailbreak:
      enabled: true
      block_threshold: 40
      warn_threshold: 15
    threat_intel:
      enabled: true
      pattern_db: "builtin:s2bench-v1"
      similarity_threshold: 0.85
      top_k: 5
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert result.is_valid, f"errors: {result.errors}"

    def test_validate_detection_threshold_warning(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  detection:
    jailbreak:
      block_threshold: 10
      warn_threshold: 50
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert result.is_valid  # warning, not error
        assert len(result.warnings) > 0

    def test_validate_detection_similarity_out_of_range(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      similarity_threshold: 1.5
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid

    def test_validate_detection_prompt_injection_threshold_warning(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      warn_at_or_above: high
      block_at_or_above: suspicious
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert result.is_valid  # warning, not error
        assert any("block_at_or_above" in w for w in result.warnings)

    def test_validate_jailbreak_threshold_over_100(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  detection:
    jailbreak:
      block_threshold: 101
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid

    def test_validate_jailbreak_max_input_bytes_zero(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  detection:
    jailbreak:
      max_input_bytes: 0
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid

    def test_validate_prompt_injection_max_scan_bytes_zero(self):
        yaml = """
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      max_scan_bytes: 0
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert not result.is_valid

    def test_validate_threat_intel_top_k_zero(self):
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


class TestMergeExtensions:
    def test_merge_extensions_posture(self):
        base = parse_or_raise("""
hushspec: "0.1.0"
extensions:
  posture:
    initial: a
    states:
      a:
        capabilities: [file_access]
    transitions: []
""")
        child = parse_or_raise("""
hushspec: "0.1.0"
extensions:
  posture:
    initial: b
    states:
      b:
        capabilities: [egress]
    transitions: []
""")
        merged = merge(base, child)
        posture = merged.extensions.posture
        assert posture is not None
        assert posture.initial == "b"
        assert "a" in posture.states
        assert "b" in posture.states

    def test_merge_extensions_origins_by_id(self):
        base = parse_or_raise("""
hushspec: "0.1.0"
extensions:
  origins:
    default_behavior: deny
    profiles:
      - id: existing
        match:
          provider: slack
        explanation: base profile
""")
        child = parse_or_raise("""
hushspec: "0.1.0"
extensions:
  origins:
    profiles:
      - id: existing
        match:
          provider: teams
        explanation: overridden
      - id: new-profile
        match:
          provider: github
""")
        merged = merge(base, child)
        origins = merged.extensions.origins
        assert origins is not None
        assert len(origins.profiles) == 2
        assert origins.default_behavior == OriginDefaultBehavior.DENY
        # existing overridden
        existing = next(p for p in origins.profiles if p.id == "existing")
        assert existing.explanation == "overridden"
        # new appended
        assert any(p.id == "new-profile" for p in origins.profiles)

    def test_merge_strategy_replaces_extension_block(self):
        base = parse_or_raise("""
hushspec: "0.1.0"
extensions:
  origins:
    default_behavior: minimal_profile
    profiles:
      - id: base
        explanation: base profile
""")
        child = parse_or_raise("""
hushspec: "0.1.0"
merge_strategy: merge
extensions:
  origins:
    profiles:
      - id: child
        explanation: child profile
""")
        merged = merge(base, child)
        origins = merged.extensions.origins
        assert origins is not None
        # merge strategy: child origins block replaces base origins block
        assert origins.default_behavior is None
        assert len(origins.profiles) == 1
        assert origins.profiles[0].id == "child"

    def test_deep_merge_detection_preserves_base_fields(self):
        base = parse_or_raise("""
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      enabled: true
    jailbreak:
      warn_threshold: 20
""")
        child = parse_or_raise("""
hushspec: "0.1.0"
extensions:
  detection:
    jailbreak:
      block_threshold: 90
""")
        merged = merge(base, child)
        detection = merged.extensions.detection
        assert detection is not None
        # prompt_injection preserved from base
        assert detection.prompt_injection is not None
        assert detection.prompt_injection.enabled is True
        # jailbreak: child block_threshold, base warn_threshold
        assert detection.jailbreak is not None
        assert detection.jailbreak.block_threshold == 90
        assert detection.jailbreak.warn_threshold == 20

    def test_parse_full_document_with_rules_and_extensions(self):
        yaml = """
hushspec: "0.1.0"
name: full-featured
rules:
  egress:
    allow: ["api.openai.com"]
    default: block
  tool_access:
    block: ["shell_exec"]
    default: allow
extensions:
  posture:
    initial: standard
    states:
      standard:
        capabilities: [file_access, egress]
      restricted:
        capabilities: [file_access]
    transitions:
      - from: "*"
        to: restricted
        on: critical_violation
  detection:
    prompt_injection:
      enabled: true
      block_at_or_above: high
"""
        spec = parse_or_raise(yaml)
        result = validate(spec)
        assert result.is_valid, f"errors: {result.errors}"
        assert spec.rules is not None
        assert spec.extensions is not None
