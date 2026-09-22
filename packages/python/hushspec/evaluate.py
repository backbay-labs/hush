"""Reference evaluator for HushSpec 0.2 (core spec Sections 3, 5, and 6).

Evaluation of one action is:

1. extension guards (panic, origins ``default_behavior``, posture capability),
2. every applicable rule block for the action type -- present, ``enabled``,
   and with a satisfied ``when`` condition -- evaluated in the order of the
   Section 5 table, never short-circuiting on an allow,
3. aggregation: deny beats warn beats allow; ``matched_rule``/``reason`` come
   from the first block in evaluation order whose decision equals the
   aggregate and which named a rule.

Unknown action types deny (``__unknown_action_type__``). Hosts and paths are
normalized as specified in Section 3.14 before any pattern is consulted.

The engine itself lives in :mod:`hushspec.compiled`: a policy's patterns,
conditions and per-action-type plans are compiled once into a
:class:`~hushspec.compiled.CompiledPolicy`, and the functions here are thin
wrappers that compile on first use and reuse the result. Callers that hold a
policy for more than one action should hold the compiled form directly
(:func:`hushspec.compiled.compile_policy`).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from enum import Enum
from typing import Optional

from hushspec.canonical import CanonicalError, canonical_json_value
from hushspec.conditions import Condition, RuntimeContext
from hushspec.extensions import (
    OriginMatch,
    OriginProfile,
    TransitionTrigger,
)
from hushspec.rules import DefaultAction
from hushspec.schema import HushSpec

#: ``matched_rule`` reported when the action type is unknown to the specification.
UNKNOWN_ACTION_TYPE_RULE = "__unknown_action_type__"
#: ``matched_rule`` reported when the emergency panic protocol is active.
PANIC_RULE = "__hushspec_panic__"


class Decision(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    DENY = "deny"


class RuleOutcome(str, Enum):
    """Outcome of consulting one rule block (or extension guard).

    ``SKIP`` means the block was applicable but not evaluated (absent,
    disabled, condition false, or short-circuited by a guard deny).
    """

    ALLOW = "allow"
    WARN = "warn"
    DENY = "deny"
    SKIP = "skip"


@dataclass
class OriginContext:
    provider: Optional[str] = None
    tenant_id: Optional[str] = None
    space_id: Optional[str] = None
    space_type: Optional[str] = None
    visibility: Optional[str] = None
    external_participants: Optional[bool] = None
    tags: list[str] = field(default_factory=list)
    sensitivity: Optional[str] = None
    actor_role: Optional[str] = None


@dataclass
class PostureContext:
    current: Optional[str] = None
    signal: Optional[str] = None


def args_size_of(arguments: object) -> Optional[int]:
    """``args_size`` for a tool call whose arguments are a JSON value.

    Core spec 3.7 fixes the unit: the length in bytes of the UTF-8 encoding of
    the arguments serialized as JSON in the canonical form of the Canonical
    Form specification, section 4 (RFC 8785). Neither a character count nor a
    count of escaped characters is that number: a one-key object holding one
    two-byte character is 9 characters, 10 bytes, and 15 bytes once
    ``json.dumps`` has escaped that character. So the measurement runs through
    the canonicalizer rather than through ``len(json.dumps(...))``.

    ``None`` when the arguments have no canonical JSON form. A size that
    cannot be measured is left unreported rather than guessed at, because
    ``max_args_size`` denies on the number it is given.
    """
    try:
        return len(canonical_json_value(arguments).encode("utf-8"))
    except (CanonicalError, TypeError, ValueError):
        return None


@dataclass
class EvaluationAction:
    type: str
    target: Optional[str] = None
    content: Optional[str] = None
    origin: Optional[OriginContext] = None
    posture: Optional[PostureContext] = None
    args_size: Optional[int] = None
    url: Optional[str] = None
    """``browser_action``: navigation destination (core spec 3.11)."""
    network: Optional[bool] = None
    """``code_exec``: whether the call requests network access (core spec 3.12)."""
    timeout_ms: Optional[int] = None
    """``code_exec``: requested execution time in milliseconds (core spec 3.12)."""
    context: Optional[RuntimeContext] = None
    """Runtime context consulted by ``when`` conditions (core spec 3.13)."""


@dataclass
class PostureResult:
    current: str
    next: str


@dataclass
class EvaluationResult:
    decision: Decision
    matched_rule: Optional[str] = None
    reason: Optional[str] = None
    origin_profile: Optional[str] = None
    posture: Optional[PostureResult] = None


@dataclass
class RuleEvaluation:
    """One recorded rule-block consultation, in evaluation order."""

    rule_block: str
    outcome: RuleOutcome
    evaluated: bool
    matched_rule: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class TracedEvaluation:
    """An evaluation result together with its recorded rule trace."""

    result: EvaluationResult
    trace: list[RuleEvaluation]


@dataclass
class _PatchStats:
    additions: int
    deletions: int


#: Rule blocks applicable to each reference action type, in evaluation order
#: (core spec Section 5). An action type absent from this table is unknown to
#: the specification.
_APPLICABLE_BLOCKS: dict[str, tuple[str, ...]] = {
    "file_read": ("forbidden_paths", "path_allowlist"),
    "file_write": ("forbidden_paths", "path_allowlist", "secret_patterns"),
    "patch_apply": (
        "forbidden_paths",
        "path_allowlist",
        "patch_integrity",
        "secret_patterns",
    ),
    "shell_command": ("shell_commands",),
    "egress": ("egress", "secret_patterns"),
    "tool_call": ("tool_access", "secret_patterns"),
    "computer_use": ("computer_use", "remote_desktop_channels"),
    "input_inject": ("input_injection",),
    "browser_action": ("browser_automation",),
    "code_exec": ("code_execution",),
    "custom": (),
}


def applicable_blocks(action_type: str) -> Optional[tuple[str, ...]]:
    return _APPLICABLE_BLOCKS.get(action_type)


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


_compiled_for_spec = None


def compiled_policy(spec: HushSpec):
    """The cached :class:`~hushspec.compiled.CompiledPolicy` for *spec*.

    Imported lazily: :mod:`hushspec.compiled` is built on top of this module.
    """
    global _compiled_for_spec
    if _compiled_for_spec is None:
        from hushspec.compiled import compiled_for_spec

        _compiled_for_spec = compiled_for_spec
    return _compiled_for_spec(spec)


def evaluate(spec: HushSpec, action: EvaluationAction) -> EvaluationResult:
    """Evaluate *action* against a resolved document.

    ``when`` conditions are evaluated against ``action.context`` (an empty
    context and the engine clock when absent).

    *spec* is compiled on first use and the compiled policy is reused for
    later calls with the same document.
    """
    return compiled_policy(spec).evaluate(action)


def evaluate_traced(
    spec: HushSpec,
    action: EvaluationAction,
    context: Optional[RuntimeContext] = None,
    conditions: Optional[dict[str, Condition]] = None,
) -> TracedEvaluation:
    """Full evaluation with the recorded rule trace (used by receipts)."""
    return compiled_policy(spec).evaluate_traced(action, context, conditions)


# ---------------------------------------------------------------------------
# Rule-block helpers
#
# The rule blocks themselves are compiled per policy in hushspec.compiled;
# what stays here is the matching vocabulary they are defined in terms of.
# ---------------------------------------------------------------------------


#: Built-in credential detectors consulted by ``browser_automation`` when
#: ``credential_detection`` is true (core spec 3.11). Documents needing
#: portable detection list their own patterns in ``extra_credential_patterns``.
BUILTIN_CREDENTIAL_PATTERNS: tuple[tuple[str, str], ...] = (
    ("aws_access_key", "(AKIA|ASIA)[0-9A-Z]{16}"),
    ("github_token", "gh[opsur]_[A-Za-z0-9]{36}"),
    ("github_fine_grained_pat", "github_pat_[0-9a-zA-Z_]{50,}"),
    ("openai_key", "sk-[A-Za-z0-9_-]{20,}"),
    ("slack_token", "xox[baprs]-[0-9A-Za-z-]{10,}"),
    (
        "private_key",
        "-----BEGIN[ \\t]+(RSA[ \\t]+|EC[ \\t]+|OPENSSH[ \\t]+)?PRIVATE[ \\t]+KEY-----",
    ),
    (
        "jwt",
        "eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}",
    ),
)


def tool_list_contains(entries: list[str], tool: str) -> bool:
    """Tool names are exact, case-sensitive strings after NFC normalization
    (core spec 3.7); no glob or regex metacharacters."""
    normalized = unicodedata.normalize("NFC", tool)
    return any(unicodedata.normalize("NFC", entry) == normalized for entry in entries)


def _default_rule_path(
    base_present: bool,
    base_default: DefaultAction,
    overlay_default: Optional[DefaultAction],
    effective: DefaultAction,
    base_path: str,
    prefix: Optional[str],
) -> str:
    """Path reported for a ``default`` decision: the object whose ``default``
    field determined the effective value."""
    if prefix is None:
        return base_path
    overlay_path = f"{prefix}.default"
    if effective == DefaultAction.BLOCK:
        if base_present and base_default == DefaultAction.BLOCK:
            return base_path
        return overlay_path
    if base_present or overlay_default is None:
        return base_path
    return overlay_path


def _scan_prefix(content: str, max_scan_bytes: Optional[int]) -> str:
    """The leading ``max_scan_bytes`` UTF-8 bytes of *content*, backed off to
    the nearest character boundary so the prefix stays valid UTF-8."""
    if max_scan_bytes is None:
        return content
    encoded = content.encode("utf-8")
    if max_scan_bytes >= len(encoded):
        return content
    end = max_scan_bytes
    while end > 0 and (encoded[end] & 0xC0) == 0x80:
        end -= 1
    return encoded[:end].decode("utf-8", errors="ignore")


def _is_word_char(ch: str) -> bool:
    return ch.isascii() and (ch.isalnum() or ch == "_")


def contains_word(text: str, word: str) -> bool:
    """Whether *word* occurs in *text* bounded by non-``[A-Za-z0-9_]``
    characters or the text boundaries (core spec 3.12 step 4)."""
    if not word:
        return False
    start = 0
    while True:
        at = text.find(word, start)
        if at < 0:
            return False
        end = at + len(word)
        before_ok = at == 0 or not _is_word_char(text[at - 1])
        after_ok = end == len(text) or not _is_word_char(text[end])
        if before_ok and after_ok:
            return True
        start = at + 1
        if start >= len(text):
            return False


# ---------------------------------------------------------------------------
# Posture and origins
# ---------------------------------------------------------------------------


_REQUIRED_CAPABILITIES: dict[str, str] = {
    "file_read": "file_access",
    "file_write": "file_write",
    "patch_apply": "patch",
    "shell_command": "shell",
    "tool_call": "tool_call",
    "egress": "egress",
    "custom": "custom",
}


def required_capability(action_type: str) -> Optional[str]:
    """Capability the posture guard requires per action type (posture 3.3)."""
    return _REQUIRED_CAPABILITIES.get(action_type)


_TRIGGER_NAMES: dict[TransitionTrigger, str] = {
    TransitionTrigger.USER_APPROVAL: "user_approval",
    TransitionTrigger.USER_DENIAL: "user_denial",
    TransitionTrigger.CRITICAL_VIOLATION: "critical_violation",
    TransitionTrigger.ANY_VIOLATION: "any_violation",
    TransitionTrigger.TIMEOUT: "timeout",
    TransitionTrigger.BUDGET_EXHAUSTED: "budget_exhausted",
    TransitionTrigger.PATTERN_MATCH: "pattern_match",
}


def _trigger_name(trigger: TransitionTrigger) -> str:
    return _TRIGGER_NAMES.get(trigger, "")


def resolve_posture(
    spec: HushSpec,
    matched_profile: Optional[OriginProfile],
    posture: Optional[PostureContext],
) -> Optional[PostureResult]:
    """Posture state in force for this action, and the state it transitions to."""
    return compiled_policy(spec).resolve_posture(matched_profile, posture)


def _match_origin(rules: OriginMatch, origin: OriginContext) -> Optional[int]:
    """Number of ``match`` fields satisfied by *origin*, or ``None`` when any
    present field is not satisfied. ``tags`` counts as one field."""
    count = 0
    pairs = (
        (rules.provider, origin.provider),
        (rules.tenant_id, origin.tenant_id),
        (rules.space_id, origin.space_id),
        (rules.space_type, origin.space_type),
        (rules.visibility, origin.visibility),
        (rules.sensitivity, origin.sensitivity),
        (rules.actor_role, origin.actor_role),
    )
    for expected, actual in pairs:
        if expected is None:
            continue
        if actual != expected:
            return None
        count += 1

    if rules.external_participants is not None:
        if origin.external_participants != rules.external_participants:
            return None
        count += 1

    if rules.tags:
        if not all(tag in origin.tags for tag in rules.tags):
            return None
        count += 1

    return count


def select_origin_profile(
    spec: HushSpec, origin: Optional[OriginContext]
) -> Optional[OriginProfile]:
    """Origin profile selection (origins spec Section 3): candidates are
    profiles with a ``match`` object every present field of which is satisfied;
    a ``space_id`` match wins outright, then the greatest matched-field count,
    then document order."""
    return compiled_policy(spec).select_origin_profile(origin)


# ---------------------------------------------------------------------------
# Path globs (core spec 3.14.1)
# ---------------------------------------------------------------------------


def normalize_path(target: str) -> str:
    """Normalize a filesystem path for matching: NFC, ``\\`` to ``/``,
    collapsed separators, lexical ``.``/``..`` resolution, no trailing ``/``."""
    unified = unicodedata.normalize("NFC", target).replace("\\", "/")
    absolute = unified.startswith("/")
    segments: list[str] = []
    for segment in unified.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments and segments[-1] != "..":
                segments.pop()
            elif absolute:
                pass
            else:
                segments.append("..")
            continue
        segments.append(segment)
    joined = "/".join(segments)
    return f"/{joined}" if absolute else joined


@lru_cache(maxsize=4096)
def _path_glob_regex(pattern: str) -> Optional[re.Pattern[str]]:
    """Compile a path glob (core spec 3.14.1) into an anchored regex.

    Memoized: the same glob recurs across a policy's rule blocks and across
    documents that share a base, and a compiled pattern is immutable.
    """
    chars = list(unicodedata.normalize("NFC", pattern))
    parts: list[str] = ["^"]
    literal: list[str] = []

    def flush() -> None:
        if literal:
            # re.escape() escapes character by character, so escaping a run is
            # the same string as escaping each of its characters in turn.
            parts.append(re.escape("".join(literal)))
            literal.clear()

    index = 0
    length = len(chars)
    while index < length:
        ch = chars[index]
        if ch == "*" and index + 1 < length and chars[index + 1] == "*":
            at_segment_start = index == 0 or chars[index - 1] == "/"
            flush()
            if (
                at_segment_start
                and index + 2 < length
                and chars[index + 2] == "/"
            ):
                # `**/`: zero or more complete leading segments.
                parts.append("(?:[^/]*/)*")
                index += 3
            else:
                parts.append(".*")
                index += 2
            continue
        if ch == "*":
            flush()
            parts.append("[^/]*")
        elif ch == "?":
            flush()
            parts.append("[^/]")
        else:
            literal.append(ch)
        index += 1
    flush()
    regex = "".join(parts)
    # \Z (not $): Python's `$` also matches just before a trailing "\n", so a
    # glob like "internal.corp" would wrongly match "internal.corp\n". \Z is a
    # true end-of-text anchor with no newline exception, which is the
    # end-of-text semantic the glob grammar calls for.
    regex += r"\Z"
    try:
        return re.compile(regex)
    except re.error:
        return None


def path_glob_matches(pattern: str, path: str) -> bool:
    """Whether *path* (already normalized) matches the path glob *pattern*.

    One-shot: the glob is compiled for this call. A policy's own globs are
    compiled once by :mod:`hushspec.compiled` instead.
    """
    compiled = _path_glob_regex(pattern)
    return compiled is not None and compiled.search(path) is not None


def glob_matches(pattern: str, target: str) -> bool:
    """Match a raw path target against a path glob, normalizing it first.

    Kept for callers outside the evaluator (lint, diff); prefer
    :func:`path_glob_matches` with an already-normalized path.
    """
    return path_glob_matches(pattern, normalize_path(target))


# ---------------------------------------------------------------------------
# Host patterns (core spec 3.14.2)
# ---------------------------------------------------------------------------

_HOST_CHARS = re.compile(r"\A[0-9A-Za-z._-]+\Z")
_ASCII_DIGITS = re.compile(r"\A[0-9]+\Z")
_IPV6_INNER = re.compile(r"\A[0-9A-Fa-f:.]+\Z")


def normalize_host(target: str) -> Optional[str]:
    """Reduce an egress target (host, ``host:port``, or URL) to a normalized
    host. Returns ``None`` when the target cannot be reduced to a
    syntactically valid host, in which case it matches nothing."""
    if not isinstance(target, str):
        return None
    target = target.strip()
    scheme = target.find("://")
    authority = target[scheme + 3 :] if scheme >= 0 else target
    # A backslash ends the authority exactly as a slash does (core spec
    # 3.14.2), the way a browser reads a special-scheme URL.
    end = len(authority)
    for ch in ("/", "\\", "?", "#"):
        found = authority.find(ch)
        if found >= 0:
            end = min(end, found)
    authority = authority[:end]
    at = authority.rfind("@")
    if at >= 0:
        authority = authority[at + 1 :]
    if not authority:
        return None

    if authority.startswith("["):
        rest = authority[1:]
        close = rest.find("]")
        if close < 0:
            return None
        inner = rest[:close]
        if not inner or _IPV6_INNER.match(inner) is None:
            return None
        return f"[{inner.lower()}]"

    host = authority
    colon = host.rfind(":")
    if colon >= 0:
        port = host[colon + 1 :]
        if port and _ASCII_DIGITS.match(port) is not None:
            host = host[:colon]
    if ":" in host:
        return None
    if host.endswith("."):
        host = host[:-1]
    if not host:
        return None

    labels: list[str] = []
    for label in host.split("."):
        if not label:
            return None
        normalized_label = _normalize_host_label(label)
        if normalized_label is None:
            return None
        labels.append(normalized_label)
    normalized = ".".join(labels)
    if _HOST_CHARS.match(normalized) is None:
        return None
    return normalized


def _normalize_host_label(label: str) -> Optional[str]:
    """Normalize one host label: ASCII lowercase, or the IDNA A-label
    (punycode) of the NFC-normalized, lowercased label when it is not ASCII."""
    if label.isascii():
        return label.lower()
    folded = unicodedata.normalize("NFC", label.lower())
    if folded.isascii():
        return folded
    encoded = punycode_encode(folded)
    if encoded is None:
        return None
    return f"xn--{encoded}"


def _normalize_host_pattern(pattern: str) -> str:
    """Normalize a host pattern (steps 5-7 of core spec 3.14.2), keeping ``*``."""
    pattern = pattern.strip()
    if pattern.endswith("."):
        pattern = pattern[:-1]
    if pattern.startswith("["):
        return pattern.lower()
    labels = []
    for label in pattern.split("."):
        if label.isascii():
            labels.append(label.lower())
        else:
            normalized = _normalize_host_label(label)
            labels.append(normalized if normalized is not None else label.lower())
    return ".".join(labels)


def _is_ipv4_literal(host: str) -> bool:
    octets = host.split(".")
    if len(octets) != 4:
        return False
    for octet in octets:
        if not octet or len(octet) > 3 or _ASCII_DIGITS.match(octet) is None:
            return False
        if int(octet) > 255:
            return False
    return True


def _is_ip_literal(host: str) -> bool:
    return host.startswith("[") or _is_ipv4_literal(host)


@lru_cache(maxsize=4096)
def _host_pattern_regex(pattern: str) -> Optional[re.Pattern[str]]:
    """Compile an already-normalized host pattern (core spec 3.14.2) into an
    anchored regex: ``*`` is one or more non-dot characters, ``**`` one or more
    characters including dots, everything else literal."""
    regex = "^"
    chars = list(pattern)
    index = 0
    length = len(chars)
    while index < length:
        if chars[index] == "*":
            if index + 1 < length and chars[index + 1] == "*":
                regex += ".+"
                index += 2
            else:
                regex += "[^.]+"
                index += 1
            continue
        regex += re.escape(chars[index])
        index += 1
    regex += r"\Z"
    try:
        return re.compile(regex)
    except re.error:
        return None


def host_pattern_matches(pattern: str, host: str) -> bool:
    """Whether a normalized *host* matches a host pattern (core spec 3.14.2).

    IP literals match only exactly. One-shot: the pattern is normalized and
    compiled for this call; a policy's own host patterns are prepared once by
    :mod:`hushspec.compiled` instead.
    """
    pattern = _normalize_host_pattern(pattern)
    if _is_ip_literal(host):
        return pattern == host
    compiled = _host_pattern_regex(pattern)
    return compiled is not None and compiled.search(host) is not None


_PUNYCODE_BASE = 36
_PUNYCODE_TMIN = 1
_PUNYCODE_TMAX = 26
_PUNYCODE_SKEW = 38
_PUNYCODE_DAMP = 700
_PUNYCODE_INITIAL_BIAS = 72
_PUNYCODE_INITIAL_N = 128
_U32_MAX = 0xFFFFFFFF


def _punycode_adapt(delta: int, num_points: int, first_time: bool) -> int:
    delta = delta // _PUNYCODE_DAMP if first_time else delta // 2
    delta += delta // num_points
    k = 0
    while delta > ((_PUNYCODE_BASE - _PUNYCODE_TMIN) * _PUNYCODE_TMAX) // 2:
        delta //= _PUNYCODE_BASE - _PUNYCODE_TMIN
        k += _PUNYCODE_BASE
    return k + (((_PUNYCODE_BASE - _PUNYCODE_TMIN + 1) * delta) // (delta + _PUNYCODE_SKEW))


def _punycode_digit(value: int) -> str:
    if value < 26:
        return chr(ord("a") + value)
    return chr(ord("0") + value - 26)


def punycode_encode(text: str) -> Optional[str]:
    """RFC 3492 punycode encoding of one label (without the ``xn--`` prefix)."""
    code_points = [ord(ch) for ch in text]
    output = [chr(cp) for cp in code_points if cp < 128]
    basic_count = len(output)
    handled = basic_count
    if basic_count > 0:
        output.append("-")

    n = _PUNYCODE_INITIAL_N
    delta = 0
    bias = _PUNYCODE_INITIAL_BIAS
    while handled < len(code_points):
        candidates = [cp for cp in code_points if cp >= n]
        if not candidates:
            return None
        m = min(candidates)
        delta += (m - n) * (handled + 1)
        if delta > _U32_MAX:
            return None
        n = m
        for cp in code_points:
            if cp < n:
                delta += 1
                if delta > _U32_MAX:
                    return None
            if cp == n:
                q = delta
                k = _PUNYCODE_BASE
                while True:
                    if k <= bias:
                        t = _PUNYCODE_TMIN
                    elif k >= bias + _PUNYCODE_TMAX:
                        t = _PUNYCODE_TMAX
                    else:
                        t = k - bias
                    if q < t:
                        break
                    output.append(_punycode_digit(t + (q - t) % (_PUNYCODE_BASE - t)))
                    q = (q - t) // (_PUNYCODE_BASE - t)
                    k += _PUNYCODE_BASE
                output.append(_punycode_digit(q))
                bias = _punycode_adapt(delta, handled + 1, handled == basic_count)
                delta = 0
                handled += 1
        delta += 1
        n += 1
        if delta > _U32_MAX or n > _U32_MAX:
            return None
    return "".join(output)


# ---------------------------------------------------------------------------
# Patch statistics
# ---------------------------------------------------------------------------


def patch_stats(content: str) -> _PatchStats:
    additions = 0
    deletions = 0
    # A patch line boundary is "\n" and nothing else. `str.splitlines()`
    # also splits on \r, \v, \f and the Unicode NEL/LS/PS separators, so a
    # bare \r inside patch content would start a line here and double-count
    # additions and deletions.
    for line in content.split("\n"):
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            additions += 1
        elif line.startswith("-"):
            deletions += 1
    return _PatchStats(additions=additions, deletions=deletions)


def imbalance_ratio(additions: int, deletions: int) -> float:
    if additions == 0 and deletions == 0:
        return 0.0
    if additions == 0:
        return float(deletions)
    if deletions == 0:
        return float(additions)
    larger = float(max(additions, deletions))
    smaller = float(min(additions, deletions))
    return larger / smaller


# ---------------------------------------------------------------------------
# Panic protocol
# ---------------------------------------------------------------------------


_panic_active = False


def activate_panic() -> None:
    global _panic_active
    _panic_active = True


def deactivate_panic() -> None:
    global _panic_active
    _panic_active = False


def is_panic_active() -> bool:
    return _panic_active


def panic_policy() -> HushSpec:
    from hushspec.builtins import PANIC_POLICY_YAML
    from hushspec.parse import parse_or_raise

    return parse_or_raise(PANIC_POLICY_YAML)


def check_panic_sentinel(path: str) -> bool:
    """Activate panic mode if the sentinel file at *path* exists.

    This is a kill switch, so it **fails closed**: if the file's existence
    cannot be determined (a permission error, a path component that is not a
    directory, or any other I/O error from ``os.stat``), the sentinel is
    treated as present and panic mode is activated. Only a definitive "not
    found" (``FileNotFoundError``) counts as absent, the reading every SDK
    applies. (``os.path.isfile`` is unusable here: it silently returns
    ``False`` on any stat error, which would let the kill switch fail open.)
    """
    import os

    try:
        os.stat(path)
        present = True
    except FileNotFoundError:
        present = False
    except OSError:
        # Could not prove the sentinel is absent (e.g. PermissionError);
        # treat it as present so the kill switch never fails open.
        present = True

    if present:
        activate_panic()
    return present
