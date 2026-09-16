"""The HushSpec regex profile.

The one regex dialect every HushSpec engine must implement, so a user-authored
pattern in ``secret_patterns``, ``patch_integrity.forbidden_patterns``, or
``shell_commands.forbidden_patterns`` produces the *same* decision in Rust,
TypeScript, Python, and Go.

The four SDK engines (Rust ``regex``, JavaScript ``RegExp``, Python ``re``, Go
RE2) agree on syntax but disagree on semantics, so the profile is reached by
*translating* the author's pattern into an equivalent pattern in each host
dialect before compiling it. The same translation runs in ``validate`` and in
``evaluate``, so the two can never disagree about what a pattern means.

Profile (normative summary; every SDK implements the same one):

1. Syntax is RE2-class -- lookaround, backreferences, possessive quantifiers,
   atomic/conditional/recursive groups and nested unbounded quantifiers are
   rejected (``is_safe_regex``). The group forms are ``(...)``, ``(?:...)``
   and the named pair ``(?<name>...)`` / ``(?P<name>...)``, whose names are
   ASCII letters, digits and underscores not starting with a digit; any other
   ``(?...)`` opener is rejected.
2. Inline flags only as a leading group: ``(?i)``, ``(?s)``, ``(?m)``,
   ``(?is)`` at the very start (one or more consecutive groups). A flag group
   anywhere else -- including the scoped form ``(?i:...)`` and negations like
   ``(?-i)`` -- is an error.
3. ``\\d \\w \\s \\b`` and their negations are ASCII-only: ``\\d`` = ``[0-9]``,
   ``\\w`` = ``[0-9A-Za-z_]``, ``\\s`` = ``[\\t\\n\\v\\f\\r ]`` (includes the
   vertical tab, excludes NBSP and the Unicode space separators), and
   ``\\b``/``\\B`` are boundaries under that ASCII ``\\w`` -- which is what
   ``re.ASCII`` gives. They are translated, not rejected, including
   inside character classes (``[\\d_]`` -> ``[0-9_]``). The negated shorthands
   ``\\D \\W \\S`` and the boundaries ``\\b \\B`` are rejected *inside* a
   class, where they cannot be expressed as members.
4. ``.`` matches any scalar value except ``\\n``; with a leading ``(?s)`` it
   matches everything. Python's ``.`` already behaves this way.
5. ``$`` matches only at end of text unless a leading ``(?m)`` is present.
   Python's ``$`` also matches just before a trailing newline, so an unescaped
   ``$`` outside a character class is rewritten to ``\\Z`` when ``(?m)`` is
   absent. ``^`` is unchanged.
6. ``(?i)`` folds ASCII letters only. Each ASCII letter is expanded into a
   two-member class (``s`` -> ``[sS]``) and no case-insensitive flag reaches
   ``re``, so the profile answers the same way as an engine whose own ``(?i)``
   would apply the full Unicode case-folding table.
7. Unanchored search semantics.
8. Compile failure at evaluation time denies, carrying the offending rule path
   (see ``evaluate.py``).

A character class is a set of scalar values: an unescaped ``[`` inside one is
rejected (so POSIX bracket expressions are not mistaken for a class of their
own), and a range endpoint outside the Basic Multilingual Plane is rejected
because the SDKs cannot express such a range alike. A pattern is limited to
2048 UTF-8 bytes (core spec 3.14.3).

Escapes are restricted to the intersection the four engines agree on:
``\\n \\r \\t \\f \\v``, ``\\xHH``, ``\\d \\D \\w \\W \\s \\S \\b \\B``, and any
escaped ASCII punctuation. ``\\A``, ``\\Z``, ``\\z``, ``\\Q``, ``\\E``,
``\\p{...}``, ``\\P{...}``, ``\\uXXXX``, ``\\0``, ``\\a`` and every other
alphanumeric escape are rejected: each is unsupported by at least one engine,
or -- worse -- silently reinterpreted by JavaScript as the bare letter.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Optional, Pattern

__all__ = ["compile_profile_regex", "NESTED_QUANTIFIER_MESSAGE"]

#: Character-class body for ASCII ``\d``.
_DIGIT_BODY = "0-9"
#: Character-class body for ASCII ``\w``.
_WORD_BODY = "0-9A-Za-z_"
#: Character-class body for ASCII ``\s`` -- includes ``\v``, excludes NBSP.
_SPACE_BODY = r"\t\n\v\f\r "

#: Size limit of a policy-authored pattern, in UTF-8 bytes (core spec 3.14.3).
_MAX_PATTERN_BYTES = 2048

#: Shared rejection message for nested unbounded quantifiers. Kept identical to
#: the message the other three SDKs report.
NESTED_QUANTIFIER_MESSAGE = (
    "pattern contains a nested unbounded quantifier (e.g. (a+)+) "
    "that can cause catastrophic backtracking (ReDoS)"
)

#: Shared rejection message for an over-long pattern.
_PATTERN_TOO_LONG_MESSAGE = (
    "pattern exceeds the HushSpec regex profile limit of 2048 bytes"
)

#: Shared rejection message for group openers outside the profile.
_GROUP_FORM_MESSAGE = (
    "this group form is not portable across the HushSpec SDK regex engines; "
    "the profile allows (?:...), the named forms (?<name>...) and "
    "(?P<name>...), and a leading inline flag group such as (?i)"
)

#: Shared rejection message for a malformed or non-portable group name.
_GROUP_NAME_MESSAGE = (
    "a named group's name must be ASCII letters, digits and underscores, must "
    "not start with a digit, and must be closed by >"
)

#: Shared rejection message for an unescaped ``[`` inside a character class.
_NESTED_CLASS_MESSAGE = (
    "an unescaped [ inside a character class is not portable across the "
    "HushSpec SDK regex engines (Rust and Go read [[:alpha:]] as a POSIX "
    "class, JavaScript and Python as a literal [); escape it as \\["
)

#: Shared rejection message for a class range reaching outside the BMP.
_ASTRAL_RANGE_MESSAGE = (
    "a character-class range with an endpoint outside the Basic Multilingual "
    "Plane is not portable across the HushSpec SDK regex engines"
)

#: Shared rejection message for an empty character class.
_EMPTY_CLASS_MESSAGE = (
    "empty character classes [] and [^] are not portable across the HushSpec "
    "SDK regex engines"
)

#: Characters that may appear in an inline flag group; used only to detect one.
_INLINE_FLAG_CHARS = frozenset("imsxuUaLn-")

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


@lru_cache(maxsize=4096)
def compile_profile_regex(pattern: str) -> Pattern[str]:
    """Compile ``pattern`` under the HushSpec regex profile.

    Memoized on the pattern text: translation and compilation are pure, a
    compiled pattern is immutable, and the same pattern recurs across rule
    blocks, across documents that share a base, and between ``validate`` and
    ``evaluate``. A rejection raises every time (exceptions are not cached).

    This is the only way policy-authored regexes are compiled in this SDK: both
    ``validate`` and ``evaluate`` route through it, so validation and evaluation
    can never disagree. Raises :class:`ValueError` for any pattern outside the
    profile -- the evaluator turns that into a deny.
    """
    if len(pattern.encode("utf-8")) > _MAX_PATTERN_BYTES:
        raise ValueError(_PATTERN_TOO_LONG_MESSAGE)

    # Local import: hushspec.validate imports this module at module level, so
    # the dependency has to run the other way at call time. These are the shared
    # portability pre-check and the ReDoS heuristic; running them here, not only
    # in ``validate``, keeps the evaluator fail-closed for a hand-built,
    # never-validated HushSpec. The rest of the RE2 subset -- lookaround,
    # backreferences, atomic and recursive groups -- is refused by the
    # translation below, which reports which construct was refused.
    from hushspec.validate import _disallowed_regex_feature, _has_nested_quantifier

    feature = _disallowed_regex_feature(pattern)
    if feature is not None:
        raise ValueError(feature)
    if _has_nested_quantifier(pattern):
        raise ValueError(NESTED_QUANTIFIER_MESSAGE)

    flags, body_start = _split_leading_flags(pattern)
    source = _translate(
        pattern[body_start:],
        multi_line="m" in flags,
        case_insensitive="i" in flags,
    )

    # ``re.IGNORECASE`` is deliberately absent: the profile folds ASCII letters
    # only, which ``_translate`` has already done by expanding each one into a
    # two-member class.
    re_flags = re.ASCII
    if "s" in flags:
        re_flags |= re.DOTALL
    if "m" in flags:
        re_flags |= re.MULTILINE

    try:
        return re.compile(source, re_flags)
    except (re.error, Warning) as exc:
        # ``re.compile`` reports some shapes (a nested set, a set difference)
        # as a ``FutureWarning`` rather than an error, which is raised here
        # when warnings are configured as errors. Either way the pattern is
        # refused rather than escaping as an uncaught exception.
        raise ValueError(str(exc)) from exc


def _split_leading_flags(pattern: str) -> tuple[str, int]:
    """Consume the leading run of ``(?flags)`` groups.

    Returns the accumulated flag letters and the index at which the pattern body
    starts. Only ``i``, ``s`` and ``m`` are recognized; anything else leaves the
    group in place, where :func:`_translate` rejects it as a non-leading inline
    flag group.
    """
    flags = ""
    index = 0
    n = len(pattern)
    while index + 2 < n and pattern[index] == "(" and pattern[index + 1] == "?":
        cursor = index + 2
        start = cursor
        while cursor < n and pattern[cursor] in "ism":
            cursor += 1
        if cursor == start or cursor >= n or pattern[cursor] != ")":
            break
        for flag in pattern[start:cursor]:
            if flag not in flags:
                flags += flag
        index = cursor + 1
    return flags, index


def _inline_flag_group_error(pattern: str, index: int) -> str | None:
    """Reject ``(?flags)`` / ``(?flags:...)`` groups outside the leading run."""
    if index + 1 >= len(pattern) or pattern[index + 1] != "?":
        return None
    cursor = index + 2
    start = cursor
    while cursor < len(pattern) and pattern[cursor] in _INLINE_FLAG_CHARS:
        cursor += 1
    if cursor == start:
        return None
    if cursor < len(pattern) and pattern[cursor] in (")", ":"):
        return (
            "inline flags are only allowed as a leading group such as (?i), (?s), "
            "(?m) or (?is); a flag group elsewhere in the pattern is not portable "
            "across the HushSpec SDK regex engines"
        )
    return None


def _escape_length(pattern: str, index: int) -> int:
    """Chars consumed by the escape sequence starting at ``index``."""
    return 4 if index + 1 < len(pattern) and pattern[index + 1] == "x" else 2


def _ascii_case_counterpart(char: str) -> Optional[str]:
    """The other ASCII case of *char*, or ``None`` when it is not a letter."""
    if "a" <= char <= "z":
        return char.upper()
    if "A" <= char <= "Z":
        return char.lower()
    return None


def _folded_class_range(low: str, high: str) -> str:
    """The class-body ranges that fold ``low``-``high`` to its other ASCII case.

    A range is emitted for the part of ``low``-``high`` inside ``a-z`` and for
    the part inside ``A-Z``, so ``[a-f]`` under ``(?i)`` becomes ``[a-fA-F]``
    and a range over digits is left alone.
    """
    out = ""
    lower_start, lower_end = max(low, "a"), min(high, "z")
    if lower_start <= lower_end:
        out += f"{lower_start.upper()}-{lower_end.upper()}"
    upper_start, upper_end = max(low, "A"), min(high, "Z")
    if upper_start <= upper_end:
        out += f"{upper_start.lower()}-{upper_end.lower()}"
    return out


def _translate_escape(
    escaped: str, in_class: bool, fold: bool, pattern: str, index: int
) -> str:
    """Translate one escape sequence into Python ``re`` source.

    ``fold`` asks for the profile's ASCII case folding, which applies only
    outside a character class -- :func:`_translate_character_class` folds its
    own members.
    """
    if escaped in ("d", "w", "s"):
        body = _DIGIT_BODY if escaped == "d" else _WORD_BODY if escaped == "w" else _SPACE_BODY
        return body if in_class else f"[{body}]"
    if escaped in ("D", "W", "S"):
        if in_class:
            raise ValueError(
                f"\\{escaped} is not portable inside a character class; a negated "
                "shorthand cannot be expressed as a class member"
            )
        body = _DIGIT_BODY if escaped == "D" else _WORD_BODY if escaped == "W" else _SPACE_BODY
        return f"[^{body}]"
    if escaped in ("b", "B"):
        if in_class:
            raise ValueError(
                f"\\{escaped} is not portable inside a character class (JavaScript and "
                "Python read it as a backspace; Rust and Go reject it)"
            )
        # re.ASCII pins Python's word boundary to the profile's ASCII \w.
        return f"\\{escaped}"
    if escaped in ("A", "Z", "z"):
        raise ValueError(
            f"\\{escaped} is not portable across the HushSpec SDK regex engines "
            "(JavaScript reads it as a literal letter); anchor with ^ and $"
        )
    if escaped in ("Q", "E"):
        raise ValueError(
            "\\Q ... \\E literal spans are not portable across the HushSpec SDK regex "
            "engines; escape the literal characters individually"
        )
    if escaped in ("p", "P"):
        raise ValueError(
            f"Unicode property escapes (\\{escaped}) are not portable across the "
            "HushSpec SDK regex engines; spell the character class out"
        )
    if escaped == "x":
        hi = pattern[index + 2] if index + 2 < len(pattern) else ""
        lo = pattern[index + 3] if index + 3 < len(pattern) else ""
        if hi not in _HEX_DIGITS or lo not in _HEX_DIGITS:
            raise ValueError(
                "\\x must be followed by exactly two hex digits (\\x41); the braced "
                "form \\x{...} is not portable across the HushSpec SDK regex engines"
            )
        if fold:
            other = _ascii_case_counterpart(chr(int(hi + lo, 16)))
            if other is not None:
                return f"[\\x{hi}{lo}{other}]"
        return f"\\x{hi}{lo}"
    if escaped in ("n", "r", "t", "f", "v"):
        return f"\\{escaped}"
    if escaped.isascii() and (escaped.isalnum() or escaped == "_"):
        raise ValueError(f"\\{escaped} is not a HushSpec regex profile escape")
    if escaped.isascii():
        return f"\\{escaped}"
    raise ValueError(
        f"escaping the non-ASCII character '{escaped}' is not portable across the "
        "HushSpec SDK regex engines"
    )


def _escape_literal_value(pattern: str, index: int) -> Optional[str]:
    """The scalar value an escape sequence stands for.

    ``None`` when it stands for a set of them. Only reached for escapes
    :func:`_translate_escape` accepted.
    """
    escaped = pattern[index + 1]
    if escaped in ("d", "w", "s"):
        return None
    if escaped == "x":
        return chr(int(pattern[index + 2 : index + 4], 16))
    return {"n": "\n", "r": "\r", "t": "\t", "f": "\f", "v": "\v"}.get(escaped, escaped)


def _read_class_atom(pattern: str, index: int) -> tuple[str, Optional[str], int]:
    """Read the class member starting at ``pattern[index]``.

    Returns its translated source, the scalar value it stands for (``None`` for
    a multi-member shorthand such as ``\\d``), and the number of chars it spans.
    """
    char = pattern[index]
    if char == "\\":
        if index + 1 >= len(pattern):
            raise ValueError("pattern ends with a trailing backslash")
        source = _translate_escape(pattern[index + 1], True, False, pattern, index)
        return source, _escape_literal_value(pattern, index), _escape_length(pattern, index)
    if char == "[":
        raise ValueError(_NESTED_CLASS_MESSAGE)
    return char, char, 1


def _translate_character_class(
    pattern: str, start: int, case_insensitive: bool
) -> tuple[str, int]:
    """Translate the character class starting at ``pattern[start]``.

    Returns its Python ``re`` source and the index just past its closing ``]``.
    Members are read one at a time so that an unescaped ``[`` can be refused, a
    range can be checked for a non-BMP endpoint, and -- under ``(?i)`` -- both
    the members and the ranges can be folded to their other ASCII case.
    """
    n = len(pattern)
    index = start + 1
    negated = index < n and pattern[index] == "^"
    if negated:
        index += 1
    # `[]` / `[^]` read as an empty class (a compile error) in Rust, Python and
    # Go but as "match nothing"/"match anything" in JavaScript, so they are
    # never portable.
    if index >= n or pattern[index] == "]":
        raise ValueError(_EMPTY_CLASS_MESSAGE)

    body: list[str] = []
    while index < n and pattern[index] != "]":
        source, value, length = _read_class_atom(pattern, index)
        after = index + length
        # A `-` is a range only between two single members and never just
        # before the closing `]`, where it is a literal hyphen.
        if (
            value is not None
            and after < n
            and pattern[after] == "-"
            and after + 1 < n
            and pattern[after + 1] != "]"
        ):
            high_source, high_value, high_length = _read_class_atom(pattern, after + 1)
            if high_value is not None:
                if ord(value) > 0xFFFF or ord(high_value) > 0xFFFF:
                    raise ValueError(_ASTRAL_RANGE_MESSAGE)
                body.append(f"{source}-{high_source}")
                if case_insensitive:
                    body.append(_folded_class_range(value, high_value))
                index = after + 1 + high_length
                continue
        body.append(source)
        if case_insensitive and value is not None:
            other = _ascii_case_counterpart(value)
            if other is not None:
                body.append(other)
        index = after

    prefix = "^" if negated else ""
    if index >= n:
        # Unterminated: hand it to `re`, whose own diagnostic names the class.
        return f"[{prefix}{''.join(body)}", index
    return f"[{prefix}{''.join(body)}]", index + 1


def _translate_group(pattern: str, start: int, out: list[str]) -> int:
    """Translate the group opener starting at ``pattern[start]``.

    Returns the index just past it. ``(``, ``(?:`` and the two named spellings
    are the profile's only group forms; ``(?=``, ``(?!``, ``(?>``, ``(?#``,
    ``(?(``, ``(?R)`` and ``(?P=name)`` are rejected here rather than left to a
    host engine that may accept them.
    """
    n = len(pattern)
    if start + 1 >= n or pattern[start + 1] != "?":
        out.append("(")
        return start + 1
    error = _inline_flag_group_error(pattern, start)
    if error is not None:
        raise ValueError(error)
    if start + 2 >= n:
        raise ValueError(_GROUP_FORM_MESSAGE)
    marker = pattern[start + 2]
    if marker == ":":
        out.append("(?:")
        return start + 3
    # `(?<name>...)` is accepted by Rust, Go and JavaScript but is a syntax
    # error in Python, which spells named groups `(?P<name>...)`.
    if marker == "<" and pattern[start + 3 : start + 4] not in ("=", "!"):
        return _translate_group_name(pattern, start + 3, out)
    if marker == "P" and pattern[start + 3 : start + 4] == "<":
        return _translate_group_name(pattern, start + 4, out)
    raise ValueError(_GROUP_FORM_MESSAGE)


def _translate_group_name(pattern: str, start: int, out: list[str]) -> int:
    """Copy the group name that starts at ``start`` and ends at ``>``.

    Returns the index just past the ``>``. The name is never case-folded: it is
    an identifier, not subject text.
    """
    cursor = pattern.find(">", start)
    if cursor < 0:
        raise ValueError(_GROUP_NAME_MESSAGE)
    name = pattern[start:cursor]
    if not _is_group_name(name):
        raise ValueError(_GROUP_NAME_MESSAGE)
    out.append(f"(?P<{name}>")
    return cursor + 1


def _is_group_name(name: str) -> bool:
    """``[A-Za-z_][0-9A-Za-z_]*``: the names every SDK engine accepts alike."""
    if not name or not (name[0] == "_" or name[0].isascii() and name[0].isalpha()):
        return False
    return all(char == "_" or (char.isascii() and char.isalnum()) for char in name)


def _translate(pattern: str, multi_line: bool, case_insensitive: bool) -> str:
    """Walk the pattern body, translating profile constructs into ``re`` source.

    ``multi_line`` carries a leading ``(?m)``: without it, an unescaped ``$``
    outside a character class becomes ``\\Z``, because Python's ``$`` otherwise
    also matches just before a trailing newline (the other three engines anchor
    at end of text). ``case_insensitive`` carries a leading ``(?i)``, compiled
    here by expanding every ASCII letter into a two-member class, because
    ``re.IGNORECASE`` would otherwise be the engine's own definition of case.
    """
    n = len(pattern)
    out: list[str] = []
    index = 0

    while index < n:
        char = pattern[index]

        if char == "\\":
            if index + 1 >= n:
                raise ValueError("pattern ends with a trailing backslash")
            out.append(
                _translate_escape(
                    pattern[index + 1], False, case_insensitive, pattern, index
                )
            )
            index += _escape_length(pattern, index)
            continue

        if char == "[":
            source, index = _translate_character_class(pattern, index, case_insensitive)
            out.append(source)
            continue

        if char == "(":
            index = _translate_group(pattern, index, out)
            continue

        if char == "$" and not multi_line:
            out.append(r"\Z")
            index += 1
            continue

        other = _ascii_case_counterpart(char) if case_insensitive else None
        out.append(f"[{char}{other}]" if other is not None else char)
        index += 1

    return "".join(out)
