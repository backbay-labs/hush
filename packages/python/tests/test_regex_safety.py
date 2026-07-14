from pathlib import Path

from hushspec import is_safe_regex, parse, parse_or_raise, validate



# is_safe_regex unit tests



class TestIsSafeRegex:
    def test_accepts_simple_character_class(self):
        assert is_safe_regex("AKIA[0-9A-Z]{16}") is True

    def test_accepts_case_insensitive_flag(self):
        assert is_safe_regex("(?i)disable[\\s_\\-]?(security|auth)") is True

    def test_accepts_dot_star_with_literal(self):
        assert is_safe_regex("curl.*\\|.*bash") is True

    def test_accepts_non_capturing_group(self):
        assert is_safe_regex("(?:key|token)\\s*[:=]\\s*[A-Za-z0-9]{32,}") is True

    def test_accepts_named_group(self):
        assert is_safe_regex("(?P<name>[a-z]+)") is True

    def test_accepts_anchors_and_word_boundaries(self):
        assert is_safe_regex("^\\bfoo\\b$") is True

    def test_rejects_backreference_1(self):
        assert is_safe_regex("(a)\\1") is False

    def test_rejects_backreference_2(self):
        assert is_safe_regex("(a)(b)\\2") is False

    def test_rejects_named_backreference_k(self):
        assert is_safe_regex("(?P<word>\\w+)\\k<word>") is False

    def test_rejects_positive_lookahead(self):
        assert is_safe_regex("foo(?=bar)") is False

    def test_rejects_negative_lookahead(self):
        assert is_safe_regex("foo(?!bar)") is False

    def test_rejects_positive_lookbehind(self):
        assert is_safe_regex("(?<=password:)\\s*\\S+") is False

    def test_rejects_negative_lookbehind(self):
        assert is_safe_regex("(?<!\\d)\\d{3}") is False

    def test_rejects_atomic_group(self):
        assert is_safe_regex("(?>abc)") is False

    def test_rejects_possessive_star(self):
        assert is_safe_regex("a*+") is False

    def test_rejects_possessive_plus(self):
        assert is_safe_regex("a++") is False

    def test_rejects_possessive_question(self):
        assert is_safe_regex("a?+") is False

    def test_rejects_conditional_pattern(self):
        assert is_safe_regex("(?(1)yes|no)") is False

    def test_rejects_named_backreference_P_equals(self):
        assert is_safe_regex("(?P<word>\\w+)(?P=word)") is False

    def test_rejects_subroutine_call(self):
        assert is_safe_regex("\\g<name>") is False

    # Possessive braces, \Z/\z anchors, and empty character classes.
    #
    # Plain possessive quantifiers (*+, ++, ?+) were already rejected above.
    # Python's `re` (3.11+) actually *compiles* `a{2,}+` as a real possessive
    # quantifier rather than erroring like JS/Go do at compile time, so the
    # brace form needs the same explicit rejection. \Z/\z anchor semantics
    # differ across engines (and JS treats them as literal letters), and
    # empty classes [] / [^] are accepted by JS but not the other three
    # SDKs -- all must be rejected identically everywhere.

    def test_rejects_possessive_brace_exact(self):
        assert is_safe_regex("a{2}+") is False

    def test_rejects_possessive_brace_unbounded(self):
        assert is_safe_regex("a{2,}+") is False

    def test_rejects_possessive_brace_range(self):
        assert is_safe_regex("a{2,5}+") is False

    def test_accepts_bounded_brace_quantifier_without_possessive_marker(self):
        # Regression guard: a plain (non-possessive) brace quantifier must
        # still be accepted.
        assert is_safe_regex("a{2,5}") is True
        assert is_safe_regex("AKIA[0-9A-Z]{16}") is True

    def test_rejects_end_anchor_Z(self):
        assert is_safe_regex("foo\\Z") is False

    def test_rejects_end_anchor_z(self):
        assert is_safe_regex("foo\\z") is False

    def test_rejects_empty_character_class(self):
        assert is_safe_regex("[]") is False

    def test_rejects_empty_negated_character_class(self):
        assert is_safe_regex("[^]") is False



# Nested-quantifier (catastrophic backtracking / ReDoS) heuristic



class TestNestedQuantifierHeuristic:
    REJECT = ["(a+)+", "(a*)*", "(a+)*", "([0-9]+)*", r"(\d+)+", "(a+)+$"]
    ACCEPT = [
        "(abc)+",
        "a+",
        r"\d{3}-\d{2}-\d{4}",
        "(?:foo|bar)+",
        "(a{1,3}){1,3}",
        "sk-(proj-)?[A-Za-z0-9_-]{20,}",
        "(AKIA|ASIA)[0-9A-Z]{16}",
        "github_pat_[0-9a-zA-Z_]{50,}",
    ]

    def test_rejects_nested_unbounded_quantifiers(self):
        for pattern in self.REJECT:
            assert is_safe_regex(pattern) is False, f"{pattern!r} should be rejected"

    def test_accepts_safe_quantifier_shapes(self):
        for pattern in self.ACCEPT:
            assert is_safe_regex(pattern) is True, f"{pattern!r} should be accepted"



# Regex validation in parse/validate pipeline



class TestRegexSafetyInValidation:
    def test_accepts_valid_re2_pattern(self):
        yaml = """
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: aws_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
"""
        ok, spec = parse(yaml)
        assert ok is True

    def test_rejects_invalid_regex_syntax(self):
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
        assert "valid regular expression" in err

    def test_rejects_backreference_in_secret_patterns(self):
        yaml = """
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: backref
        pattern: "(a)\\\\1"
        severity: critical
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "RE2" in err

    def test_rejects_lookahead_in_shell_commands(self):
        yaml = """
hushspec: "0.1.0"
rules:
  shell_commands:
    forbidden_patterns:
      - "(?=foo)bar"
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "RE2" in err

    def test_rejects_possessive_brace_in_shell_commands(self):
        yaml = """
hushspec: "0.1.0"
rules:
  shell_commands:
    forbidden_patterns:
      - "a{2,}+"
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "RE2" in err

    def test_rejects_end_anchor_in_secret_patterns(self):
        yaml = """
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: bad
        pattern: "foo\\\\Z"
        severity: critical
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "RE2" in err

    def test_rejects_empty_character_class_in_patch_integrity(self):
        yaml = """
hushspec: "0.1.0"
rules:
  patch_integrity:
    max_imbalance_ratio: 10.0
    forbidden_patterns:
      - "[]"
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "valid regular expression" in err

    def test_rejects_lookbehind_in_patch_integrity(self):
        yaml = """
hushspec: "0.1.0"
rules:
  patch_integrity:
    max_imbalance_ratio: 10.0
    forbidden_patterns:
      - "(?<=password:)\\\\s*\\\\S+"
"""
        ok, err = parse(yaml)
        assert ok is False
        assert "RE2" in err

    def test_accepts_all_valid_regex_fields(self):
        yaml = """
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: aws_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: private_key
        pattern: "-----BEGIN\\\\s+(RSA\\\\s+)?PRIVATE\\\\s+KEY-----"
        severity: critical
  shell_commands:
    forbidden_patterns:
      - "(?i)rm\\\\s+-rf\\\\s+/"
      - "curl.*\\\\|.*bash"
  patch_integrity:
    max_imbalance_ratio: 10.0
    forbidden_patterns:
      - "(?i)disable[\\\\s_\\\\-]?(security|auth|ssl|tls)"
      - "(?i)chmod\\\\s+777"
"""
        ok, spec = parse(yaml)
        assert ok is True



# Built-in rulesets must pass regex validation



class TestBuiltInRulesets:
    RULESETS_DIR = Path(__file__).parent.parent.parent.parent / "rulesets"
    RULESET_FILES = [
        "default.yaml",
        "strict.yaml",
        "permissive.yaml",
        "ai-agent.yaml",
        "cicd.yaml",
        "remote-desktop.yaml",
    ]

    def test_all_rulesets_have_valid_patterns(self):
        for filename in self.RULESET_FILES:
            path = self.RULESETS_DIR / filename
            yaml_content = path.read_text()
            ok, result = parse(yaml_content)
            assert ok is True, f"{filename} failed to parse: {result}"
            spec = result
            validation = validate(spec)
            assert validation.is_valid, (
                f"{filename} failed validation: "
                + "; ".join(str(e) for e in validation.errors)
            )
