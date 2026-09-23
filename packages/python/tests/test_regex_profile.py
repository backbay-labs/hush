"""HushSpec regex profile (``compile_profile_regex``) unit tests.

The profile is normative, so these cases are shared across the SDKs: the same
pattern must produce the same answer in every one of them.
"""

from __future__ import annotations

import pytest

from hushspec.regex_profile import compile_profile_regex


def matches(pattern: str, haystack: str) -> bool:
    return compile_profile_regex(pattern).search(haystack) is not None


def rejects(pattern: str) -> str:
    with pytest.raises(ValueError) as excinfo:
        compile_profile_regex(pattern)
    return str(excinfo.value)


class TestRegexProfile:
    def test_digit_shorthand_is_ascii_only(self):
        assert matches(r"key\d{3}", "key123")
        # Arabic-Indic digits are digits to Python's Unicode \d, but not to the
        # profile.
        assert not matches(r"key\d{3}", "key١٢٣")

    def test_word_shorthand_is_ascii_only(self):
        assert matches(r"\w+", "abc_123")
        assert not matches(r"^\w$", "é")

    def test_dollar_is_end_of_text_only(self):
        assert matches("token$", "token")
        # Python's bare `$` also matches before a trailing newline; the profile
        # rewrites it to \Z.
        assert not matches("token$", "token\n")
        assert matches("(?m)token$", "token\nmore")
        # Only "\n" breaks a line: JavaScript's `m` flag would also break at
        # "\r", U+2028 and U+2029, so the TypeScript SDK spells (?m) out.
        assert not matches("(?m)token$", "token\rmore")
        assert matches("(?m)^more", "token\nmore")
        assert not matches("(?m)^more", "token\rmore")

    def test_word_boundary_is_ascii(self):
        assert matches(r"\bfoo", "éfoo")
        assert matches(r"\bfoo\b", "éfoo")
        assert not matches(r"\bfoo\b", "foobar")
        assert matches(r"\Bfoo", "barfoo")

    def test_dot_excludes_only_newline(self):
        assert matches("a.b", "a\rb")
        assert not matches("a.b", "a\nb")
        assert matches("(?s)a.b", "a\nb")
        # `.` consumes one code point, astral included.
        assert matches("^a.b$", "a\U0001F600b")

    def test_space_shorthand_is_ascii_and_includes_vertical_tab(self):
        assert matches(r"a\sb", "ab")
        assert matches(r"a\sb", "a b")
        assert matches(r"a\sb", "a	b")
        assert not matches(r"a\sb", "a b")
        assert not matches(r"a\Sb", "a b")
        assert matches(r"a\Sb", "axb")

    def test_inline_flags_only_leading(self):
        compile_profile_regex("(?i)foobar")
        compile_profile_regex("(?is)foobar")
        compile_profile_regex("(?i)(?m)foobar")
        assert "leading group" in rejects("foo(?i)bar")
        assert "leading group" in rejects("(?i:foo)")
        assert "leading group" in rejects("foo(?-i)bar")
        assert "leading group" in rejects("(?i)foo(?s)bar")

    def test_escaped_backslash_is_not_a_shorthand(self):
        assert compile_profile_regex(r"\\d").pattern == r"\\d"
        assert matches(r"\\d", "\\d")
        assert not matches(r"\\d", "5")

    def test_shorthands_inside_character_classes_are_expanded(self):
        assert compile_profile_regex(r"[\d_]").pattern == "[0-9_]"
        assert compile_profile_regex(r"[\w-]").pattern == "[0-9A-Za-z_-]"
        assert compile_profile_regex(r"[\s]").pattern == r"[\t\n\v\f\r ]"
        assert matches(r"[\d_]+", "_1")
        assert not matches(r"^[\d_]+$", "١")

    def test_escaped_bracket_stays_literal(self):
        assert matches(r"[\]]", "]")
        assert matches(r"a\[b", "a[b")
        assert compile_profile_regex(r"[\]]").pattern == r"[\]]"

    def test_negated_shorthands_and_boundaries_rejected_in_classes(self):
        assert "character class" in rejects(r"[\D]")
        assert "character class" in rejects(r"[\W]")
        assert "character class" in rejects(r"[a\S]")
        assert "character class" in rejects(r"[\b]")
        assert "character class" in rejects(r"[\B]")

    def test_non_portable_escapes_are_rejected(self):
        assert "\\Q" in rejects(r"\Qa.b\E")
        assert "anchor with" in rejects(r"\Afoo")
        # \Z / \z are caught by the shared portability pre-check.
        assert "end-anchors" in rejects(r"foo\Z")
        assert "end-anchors" in rejects(r"foo\z")
        assert "Unicode property" in rejects(r"\p{L}")
        assert "Unicode property" in rejects(r"\P{L}")
        assert "profile escape" in rejects("\\u00a0")
        assert "profile escape" in rejects(r"\a")
        assert "profile escape" in rejects(r"\0")
        assert "two hex digits" in rejects(r"a\x{41}")
        assert "trailing backslash" in rejects("foo\\")
        assert "non-ASCII" in rejects("\\é")

    def test_supported_escapes_survive(self):
        assert matches(r"a\x41b", "aAb")
        assert matches(r"a\tb", "a	b")
        assert matches(r"a\vb", "ab")
        assert matches(r"a\.b", "a.b")
        assert not matches(r"a\.b", "axb")
        assert matches(r"a\-b", "a-b")

    def test_empty_character_classes_are_rejected(self):
        assert "empty character class" in rejects("[]")
        assert "empty character class" in rejects("[^]")

    def test_javascript_named_group_spelling_is_rewritten(self):
        assert compile_profile_regex("(?<year>[0-9]{4})").pattern == "(?P<year>[0-9]{4})"
        assert matches("(?<year>[0-9]{4})", "in 2026")
        assert matches("(?P<year>[0-9]{4})", "in 2026")

    def test_library_patterns_still_compile_and_match(self):
        assert matches(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b", "ssn 123-45-6789.")
        assert matches("(AKIA|ASIA)[0-9A-Z]{16}", "AKIA1234567890ABCDEF")
        assert matches(
            r"(?i)\b(mrn|medical[ \t\n\r\f_-]?record)[ \t\n\r\f]*:?[ \t\n\r\f]*[A-Z0-9]{6,15}\b",
            "MRN: AB12345",
        )

    def test_re2_unsafe_patterns_are_rejected(self):
        assert "nested unbounded quantifier" in rejects("(a+)+")
        assert "group form" in rejects("(?=foo)bar")
        assert "profile escape" in rejects(r"(foo)\1")
        assert "possessive" in rejects("a*+")

    def test_group_names_are_ascii_identifiers(self):
        assert "named group's name" in rejects("(?<1st>x)")
        assert "named group's name" in rejects("(?<année>x)")
        assert "named group's name" in rejects("(?<year x)")

    def test_non_profile_group_openers_are_rejected(self):
        for pattern in (
            "a(?#comment)b",
            "a(?=b)",
            "a(?!b)",
            "(?<=a)b",
            "(?<!a)b",
            "(?>a)",
            "(?(1)a|b)",
            "(?R)",
            "(?1)",
            "(?P<a>x)(?P=a)",
        ):
            assert "group form" in rejects(pattern), pattern
        assert matches("(?:ab)+", "abab")

    def test_posix_bracket_expressions_are_rejected(self):
        assert "unescaped [" in rejects("[[:alpha:]]")
        assert "unescaped [" in rejects("[a[b]")
        assert matches(r"[a\[]", "[")

    def test_open_lower_bound_quantifier_is_rejected(self):
        assert "{,n} quantifier" in rejects("a{,3}")
        assert matches("a{0,3}b", "aab")

    def test_over_long_patterns_are_rejected(self):
        assert "2048 bytes" in rejects("a" * 2049)
        assert matches("a" * 2048, "a" * 2048)

    def test_class_ranges_stay_inside_the_bmp(self):
        assert "Basic Multilingual Plane" in rejects("[\U0001f600-\U0001f64f]")
        assert matches("^[\U0001f600a]$", "\U0001f600")
        assert matches("^[\U0001f600a]$", "a")
        assert not matches("^[^\U0001f600]$", "\U0001f600")
        assert matches("^[^\U0001f600]$", "a")

    def test_case_insensitive_folds_ascii_letters_only(self):
        assert matches("(?i)stra", "STRA")
        assert matches("(?i)stra", "Stra")
        # U+017F (long s) and U+212A (Kelvin sign) simple-case-fold to ASCII
        # under the full Unicode table; the profile folds ASCII only.
        assert not matches("(?i)s", "ſ")
        assert not matches("(?i)k", "K")

    def test_case_insensitive_folds_class_members_and_ranges(self):
        assert matches("(?i)^[a-f]$", "C")
        assert not matches("(?i)^[a-f]$", "G")
        assert matches("(?i)^[sq]$", "S")
        assert not matches("(?i)^[sq]$", "ſ")
        assert not matches("(?i)^[^s]$", "S")
        assert matches("(?i)^[^s]$", "ſ")
        assert matches(r"(?i)\x41", "a")
        assert matches(r"(?i)\x61", "A")
        assert compile_profile_regex("(?i)[0-9]").pattern == "[0-9]"
        assert compile_profile_regex("(?i)(?P<ab>c)").pattern == "(?P<ab>[cC])"
