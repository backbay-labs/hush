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
   rejected (``is_safe_regex``).
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
4. ``.`` matches any character except ``\\n``; with a leading ``(?s)`` it
   matches everything. Python's ``.`` already behaves this way.
5. ``$`` matches only at end of text unless a leading ``(?m)`` is present.
   Python's ``$`` also matches just before a trailing newline, so an unescaped
   ``$`` outside a character class is rewritten to ``\\Z`` when ``(?m)`` is
   absent. ``^`` is unchanged.
6. Unanchored search semantics.
7. Compile failure at evaluation time denies, carrying the offending rule path
   (see ``evaluate.py``).

Escapes are restricted to the intersection the four engines agree on:
``\\n \\r \\t \\f \\v``, ``\\xHH``, ``\\d \\D \\w \\W \\s \\S \\b \\B``, and any
escaped ASCII punctuation. ``\\A``, ``\\Z``, ``\\z``, ``\\Q``, ``\\E``,
``\\p{...}``, ``\\P{...}``, ``\\uXXXX``, ``\\0``, ``\\a`` and every other
alphanumeric escape are rejected: each is unsupported by at least one engine,
or -- worse -- silently reinterpreted by JavaScript as the bare letter.

Known residual divergence: under a leading ``(?i)``, Rust and Go case-fold with
the full Unicode table while JavaScript (no ``u`` flag) and Python (``re.ASCII``)
fold only ASCII.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Pattern

__all__ = ["compile_profile_regex", "NESTED_QUANTIFIER_MESSAGE"]

#: Character-class body for ASCII ``\d``.
_DIGIT_BODY = "0-9"
#: Character-class body for ASCII ``\w``.
_WORD_BODY = "0-9A-Za-z_"
#: Character-class body for ASCII ``\s`` -- includes ``\v``, excludes NBSP.
_SPACE_BODY = r"\t\n\v\f\r "

#: Shared rejection message for nested unbounded quantifiers. Kept identical to
#: the message the other three SDKs report.
NESTED_QUANTIFIER_MESSAGE = (
    "pattern contains a nested unbounded quantifier (e.g. (a+)+) "
    "that can cause catastrophic backtracking (ReDoS)"
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
    # Local import: hushspec.validate imports this module at module level, so
    # the dependency has to run the other way at call time. These are the shared
    # RE2 portability pre-check and the ReDoS heuristic (the two halves of
    # ``is_safe_regex``); running them here, not only in ``validate``, keeps the
    # evaluator fail-closed for a hand-built, never-validated HushSpec.
    from hushspec.validate import (
        _RE2_DISALLOWED,
        _disallowed_regex_feature,
        _has_nested_quantifier,
    )

    if _disallowed_regex_feature(pattern) is not None or _RE2_DISALLOWED.search(pattern):
        raise ValueError("pattern uses features not in the RE2 subset")
    if _has_nested_quantifier(pattern):
        raise ValueError(NESTED_QUANTIFIER_MESSAGE)

    flags, body_start = _split_leading_flags(pattern)
    source = _translate(pattern[body_start:], multi_line="m" in flags)

    re_flags = re.ASCII
    if "i" in flags:
        re_flags |= re.IGNORECASE
    if "s" in flags:
        re_flags |= re.DOTALL
    if "m" in flags:
        re_flags |= re.MULTILINE

    try:
        return re.compile(source, re_flags)
    except re.error as exc:  # pragma: no cover - defensive
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


def _translate_escape(escaped: str, in_class: bool, pattern: str, index: int) -> str:
    """Translate one escape sequence into Python ``re`` source."""
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


def _translate(pattern: str, multi_line: bool) -> str:
    """Walk the pattern body, translating profile constructs into ``re`` source.

    ``multi_line`` carries a leading ``(?m)``: without it, an unescaped ``$``
    outside a character class becomes ``\\Z``, because Python's ``$`` otherwise
    also matches just before a trailing newline (the other three engines anchor
    at end of text).
    """
    n = len(pattern)
    out: list[str] = []
    in_class = False
    index = 0

    while index < n:
        char = pattern[index]

        if char == "\\":
            if index + 1 >= n:
                raise ValueError("pattern ends with a trailing backslash")
            out.append(_translate_escape(pattern[index + 1], in_class, pattern, index))
            index += _escape_length(pattern, index)
            continue

        if in_class:
            if char == "]":
                in_class = False
            out.append(char)
            index += 1
            continue

        if char == "[":
            # `[]` / `[^]` read as an empty class (a compile error) in Rust,
            # Python and Go but as "match nothing"/"match anything" in
            # JavaScript, so they are never portable.
            cursor = index + 1
            if cursor < n and pattern[cursor] == "^":
                cursor += 1
            if cursor >= n or pattern[cursor] == "]":
                raise ValueError(
                    "empty character classes [] and [^] are not portable across the "
                    "HushSpec SDK regex engines"
                )
            in_class = True
            out.append("[")
            index += 1
            continue

        if char == "(":
            error = _inline_flag_group_error(pattern, index)
            if error is not None:
                raise ValueError(error)
            # `(?<name>...)` is accepted by Rust, Go and JavaScript but is a
            # syntax error in Python, which spells named groups `(?P<name>...)`.
            if (
                pattern[index + 1 : index + 3] == "?<"
                and index + 3 < n
                and pattern[index + 3] not in ("=", "!")
            ):
                out.append("(?P<")
                index += 3
                continue
            out.append("(")
            index += 1
            continue

        if char == "$" and not multi_line:
            out.append(r"\Z")
            index += 1
            continue

        out.append(char)
        index += 1

    return "".join(out)
