"""Canonical form and content hash for HushSpec documents.

Implements ``spec/hushspec-canonical.md``:

* **Projection** (spec section 3) -- walk a *resolved* document alongside the
  published JSON Schemas, materializing every schema default inside objects
  that are present, dropping the resolution-only fields, and normalizing empty
  containers that carry no meaning.
* **Serialization** (spec section 4) -- RFC 8785 (JSON Canonicalization Scheme):
  keys ordered by UTF-16 code units, minimal string escaping, ECMAScript
  ``Number::toString`` number formatting, no whitespace.
* **Content hash** (spec section 5) -- ``sha256:`` followed by 64 lowercase hex
  digits of the SHA-256 of the canonical UTF-8 bytes.

Two conformant implementations MUST produce byte-identical output for the same
resolved document; the vectors under ``fixtures/core/hash/`` are normative and
``tests/test_canonical_vectors.py`` runs all of them against this module.

Only the standard library is used here -- no schema files are read at runtime,
so the projection rules are embedded below (``_CORE_ROOT`` and
``_EXTENSION_ROOTS``) and kept honest against ``schemas/`` by
``tests/test_canonical_schema_sync.py``.

Prefer canonicalizing the *raw* parsed mapping (spec section 6): the typed
``HushSpec`` model cannot represent the difference between an absent and an
explicitly-empty origins overlay field, which section 3.3 makes significant.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from typing import Any

from hushspec.generated_contract import (
    BRIDGE_POLICY_KEYS,
    BRIDGE_TARGET_KEYS,
    BROWSER_AUTOMATION_KEYS,
    CHANGELOG_ENTRY_KEYS,
    CODE_EXECUTION_KEYS,
    COMPUTER_USE_KEYS,
    CONDITION_KEYS,
    CONTROL_MAPPING_KEYS,
    DETECTION_KEYS,
    EGRESS_KEYS,
    EXTENSION_KEYS,
    FORBIDDEN_PATH_KEYS,
    GOVERNANCE_METADATA_KEYS,
    INPUT_INJECTION_KEYS,
    JAILBREAK_KEYS,
    ORIGIN_BUDGET_KEYS,
    ORIGIN_DATA_KEYS,
    ORIGIN_EGRESS_OVERLAY_KEYS,
    ORIGIN_MATCH_KEYS,
    ORIGIN_PROFILE_KEYS,
    ORIGIN_TOOL_ACCESS_OVERLAY_KEYS,
    ORIGINS_KEYS,
    PATCH_INTEGRITY_KEYS,
    PATH_ALLOWLIST_KEYS,
    POSTURE_KEYS,
    POSTURE_STATE_KEYS,
    POSTURE_TRANSITION_KEYS,
    PROMPT_INJECTION_HEURISTICS_KEYS,
    PROMPT_INJECTION_KEYS,
    RATE_CONDITION_KEYS,
    REMOTE_DESKTOP_KEYS,
    RULE_KEYS,
    SECRET_PATTERN_KEYS,
    SECRET_PATTERNS_KEYS,
    SHELL_COMMAND_KEYS,
    THREAT_INTEL_KEYS,
    TIME_WINDOW_KEYS,
    TOOL_ACCESS_KEYS,
    TOP_LEVEL_KEYS,
)

__all__ = [
    "CanonicalError",
    "canonical_json",
    "canonical_json_value",
    "content_hash",
    "digest",
    "is_content_hash",
]

#: Self-describing prefix of a content hash (spec section 5).
HASH_PREFIX = "sha256:"

#: Integers outside the IEEE 754 safe range have no faithful canonical form
#: (spec section 4.3); refuse rather than round.
SAFE_INTEGER_MAX = 2**53 - 1

#: Consumed by resolution, never part of a resolved document (spec section 3.1).
_RESOLUTION_FIELDS = ("extends", "merge_strategy")

#: Reserved for an inline signature; a signature must never cover itself
#: (spec section 3.1, signing spec section 7).
_INLINE_SIGNATURE_FIELD = "signature"


class CanonicalError(ValueError):
    """The document cannot be canonicalized."""


# --------------------------------------------------------------------------- #
# Projection schema (spec/hushspec-canonical.md section 3)
# --------------------------------------------------------------------------- #


class _Obj:
    """A schema object: a fixed key set, defaults, and typed children.

    ``keys`` comes from ``generated_contract`` (regenerated from ``schemas/``),
    so an unknown key is always a hard error. ``defaults`` holds only the
    properties that declare a schema ``default``; ``required`` and
    ``preserve_empty`` mark the properties that survive section 3.3's
    empty-container omission.
    """

    __slots__ = ("keys", "defaults", "required", "preserve_empty", "children")

    def __init__(
        self,
        keys: frozenset[str],
        *,
        defaults: dict[str, Any] | None = None,
        required: tuple[str, ...] = (),
        preserve_empty: tuple[str, ...] = (),
    ) -> None:
        self.keys = keys
        self.defaults: dict[str, Any] = defaults or {}
        self.required = frozenset(required)
        self.preserve_empty = frozenset(preserve_empty)
        #: property name -> child node; properties absent here are leaves or
        #: free-form values and pass through untouched.
        self.children: dict[str, _Node] = {}

    def project(self, value: Any, path: str) -> Any:
        if not isinstance(value, Mapping):
            # Type errors belong to validation (spec section 2.3); pass through.
            return _plain(value)
        for key in value:
            if key not in self.keys:
                raise CanonicalError(f"unknown field {path}.{key}")
        out: dict[str, Any] = {}
        for key, raw in value.items():
            child = self.children.get(key)
            projected = child.project(raw, f"{path}.{key}") if child else _plain(raw)
            if (
                key not in self.defaults
                and key not in self.required
                and key not in self.preserve_empty
                and _is_empty_container(projected)
            ):
                continue
            out[key] = projected
        for key, default in self.defaults.items():
            if key not in value:
                out[key] = copy.deepcopy(default)
        return out


class _ArrayOf:
    """A schema array whose items are objects."""

    __slots__ = ("item",)

    def __init__(self, item: _Obj) -> None:
        self.item = item

    def project(self, value: Any, path: str) -> Any:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            return _plain(value)
        return [self.item.project(item, f"{path}[{i}]") for i, item in enumerate(value)]


class _MapOf:
    """A schema map (``additionalProperties`` as a schema, e.g. posture ``states``).

    Every key is kept exactly as written; only the values are projected.
    """

    __slots__ = ("value",)

    def __init__(self, value: _Obj) -> None:
        self.value = value

    def project(self, value: Any, path: str) -> Any:
        if not isinstance(value, Mapping):
            return _plain(value)
        return {key: self.value.project(item, f"{path}.{key}") for key, item in value.items()}


_Node = _Obj | _ArrayOf | _MapOf


def _is_empty_container(value: Any) -> bool:
    return isinstance(value, (list, dict)) and len(value) == 0


def _plain(value: Any) -> Any:
    """Normalize a pass-through value to plain JSON containers.

    Free-form values (``when.context``, posture ``budgets``) are kept exactly as
    written, but a caller may hand us a ``Mapping``/``Sequence`` that is not a
    ``dict``/``list``; ``_is_empty_container`` and the serializer both key off
    the concrete types.
    """
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [_plain(item) for item in value]
    return value


# -- core schema (schemas/hushspec-core.v0.schema.json) --------------------- #

_CONDITION = _Obj(CONDITION_KEYS)
_TIME_WINDOW = _Obj(TIME_WINDOW_KEYS, defaults={"timezone": "UTC"}, required=("start", "end"))
_RATE_CONDITION = _Obj(
    RATE_CONDITION_KEYS, required=("counter", "threshold", "comparison")
)
_CONDITION.children = {
    "time_window": _TIME_WINDOW,
    "all_of": _ArrayOf(_CONDITION),
    "any_of": _ArrayOf(_CONDITION),
    "not": _CONDITION,
    "rate": _RATE_CONDITION,
}

_SECRET_PATTERN = _Obj(SECRET_PATTERN_KEYS, required=("name", "pattern", "severity"))
_CONTROL_MAPPING = _Obj(CONTROL_MAPPING_KEYS, required=("framework", "control_id", "rule_paths"))
_GOVERNANCE_METADATA = _Obj(GOVERNANCE_METADATA_KEYS)
_CHANGELOG_ENTRY = _Obj(CHANGELOG_ENTRY_KEYS, required=("version", "date", "summary"))
_GOVERNANCE_METADATA.children = {
    "controls": _ArrayOf(_CONTROL_MAPPING),
    "changelog": _ArrayOf(_CHANGELOG_ENTRY),
}


def _rule(keys: frozenset[str], defaults: dict[str, Any]) -> _Obj:
    node = _Obj(keys, defaults=defaults)
    node.children = {"when": _CONDITION}
    return node


_RULES = _Obj(RULE_KEYS)
_RULES.children = {
    "forbidden_paths": _rule(
        FORBIDDEN_PATH_KEYS, {"enabled": True, "patterns": [], "exceptions": []}
    ),
    "path_allowlist": _rule(
        PATH_ALLOWLIST_KEYS, {"enabled": False, "read": [], "write": [], "patch": []}
    ),
    "egress": _rule(
        EGRESS_KEYS, {"enabled": True, "allow": [], "block": [], "default": "block"}
    ),
    "secret_patterns": _rule(
        SECRET_PATTERNS_KEYS, {"enabled": True, "patterns": [], "skip_paths": []}
    ),
    "patch_integrity": _rule(
        PATCH_INTEGRITY_KEYS,
        {
            "enabled": True,
            "max_additions": 1000,
            "max_deletions": 500,
            "forbidden_patterns": [],
            "require_balance": False,
            "max_imbalance_ratio": 10.0,
        },
    ),
    "shell_commands": _rule(SHELL_COMMAND_KEYS, {"enabled": True, "forbidden_patterns": []}),
    "tool_access": _rule(
        TOOL_ACCESS_KEYS,
        {
            "enabled": True,
            "allow": [],
            "block": [],
            "require_confirmation": [],
            "default": "allow",
        },
    ),
    "computer_use": _rule(
        COMPUTER_USE_KEYS, {"enabled": False, "mode": "guardrail", "allowed_actions": []}
    ),
    "remote_desktop_channels": _rule(
        REMOTE_DESKTOP_KEYS,
        {
            "enabled": False,
            "clipboard": False,
            "file_transfer": False,
            "audio": True,
            "drive_mapping": False,
        },
    ),
    "input_injection": _rule(
        INPUT_INJECTION_KEYS,
        {"enabled": False, "allowed_types": [], "require_postcondition_probe": False},
    ),
    "browser_automation": _rule(
        BROWSER_AUTOMATION_KEYS,
        {
            "enabled": False,
            "allowed_domains": [],
            "blocked_domains": [],
            "allowed_verbs": [],
            "credential_detection": True,
            "extra_credential_patterns": [],
        },
    ),
    "code_execution": _rule(
        CODE_EXECUTION_KEYS,
        {
            "enabled": False,
            "language_allowlist": [],
            "module_denylist": [],
            "network_access": False,
        },
    ),
}
_RULES.children["secret_patterns"].children["patterns"] = _ArrayOf(_SECRET_PATTERN)

# `merge_strategy` has a schema default but is stripped, never materialized
# (spec section 3.1), so it is deliberately absent from `defaults` here.
_CORE_ROOT = _Obj(TOP_LEVEL_KEYS, required=("hushspec",))
_CORE_ROOT.children = {
    "rules": _RULES,
    "metadata": _GOVERNANCE_METADATA,
}

# -- posture extension (schemas/hushspec-posture.v0.schema.json) ------------ #

_POSTURE_STATE = _Obj(POSTURE_STATE_KEYS)
_POSTURE_TRANSITION = _Obj(POSTURE_TRANSITION_KEYS, required=("from", "to", "on"))
_POSTURE_ROOT = _Obj(POSTURE_KEYS, required=("initial", "states", "transitions"))
_POSTURE_ROOT.children = {
    "states": _MapOf(_POSTURE_STATE),
    "transitions": _ArrayOf(_POSTURE_TRANSITION),
}

# -- origins extension (schemas/hushspec-origins.v0.schema.json) ------------ #
#
# `match` is the one presence-significant field of spec section 3.3: `match: {}`
# is the explicit default profile, where an absent `match` never matches. The
# overlay lists are not presence-significant -- an absent overlay list inherits
# the base block and an empty one contributes nothing, which evaluate the same
# (origins spec section 4) -- so an empty one is omitted like any other
# no-default empty container.

_ORIGIN_MATCH = _Obj(ORIGIN_MATCH_KEYS)
_ORIGIN_TOOL_ACCESS = _Obj(ORIGIN_TOOL_ACCESS_OVERLAY_KEYS)
_ORIGIN_EGRESS = _Obj(ORIGIN_EGRESS_OVERLAY_KEYS)
_ORIGIN_DATA = _Obj(
    ORIGIN_DATA_KEYS,
    defaults={
        "allow_external_sharing": False,
        "redact_before_send": False,
        "block_sensitive_outputs": False,
    },
)
_ORIGIN_BUDGETS = _Obj(ORIGIN_BUDGET_KEYS)
_BRIDGE_TARGET = _Obj(BRIDGE_TARGET_KEYS)
_BRIDGE_POLICY = _Obj(
    BRIDGE_POLICY_KEYS, defaults={"allow_cross_origin": False, "require_approval": False}
)
_BRIDGE_POLICY.children = {"allowed_targets": _ArrayOf(_BRIDGE_TARGET)}

_ORIGIN_PROFILE = _Obj(ORIGIN_PROFILE_KEYS, required=("id",), preserve_empty=("match",))
_ORIGIN_PROFILE.children = {
    "match": _ORIGIN_MATCH,
    "tool_access": _ORIGIN_TOOL_ACCESS,
    "egress": _ORIGIN_EGRESS,
    "data": _ORIGIN_DATA,
    "budgets": _ORIGIN_BUDGETS,
    "bridge": _BRIDGE_POLICY,
}

_ORIGINS_ROOT = _Obj(ORIGINS_KEYS, defaults={"default_behavior": "deny"})
_ORIGINS_ROOT.children = {"profiles": _ArrayOf(_ORIGIN_PROFILE)}

# -- detection extension (schemas/hushspec-detection.v0.schema.json) -------- #

_PROMPT_INJECTION = _Obj(
    PROMPT_INJECTION_KEYS,
    defaults={
        "enabled": True,
        "warn_at_or_above": "suspicious",
        "block_at_or_above": "high",
        "max_scan_bytes": 200000,
    },
)
_PROMPT_INJECTION.children = {
    "heuristics": _Obj(
        PROMPT_INJECTION_HEURISTICS_KEYS,
        defaults={"enabled": True, "min_score": 0},
    ),
}

_DETECTION_ROOT = _Obj(DETECTION_KEYS)
_DETECTION_ROOT.children = {
    "prompt_injection": _PROMPT_INJECTION,
    "jailbreak": _Obj(
        JAILBREAK_KEYS,
        defaults={
            "enabled": True,
            "block_threshold": 80,
            "warn_threshold": 50,
            "max_input_bytes": 200000,
        },
    ),
    "threat_intel": _Obj(
        THREAT_INTEL_KEYS,
        defaults={"enabled": False, "similarity_threshold": 0.7, "top_k": 5},
    ),
}

_EXTENSION_ROOTS: dict[str, _Obj] = {
    "posture": _POSTURE_ROOT,
    "origins": _ORIGINS_ROOT,
    "detection": _DETECTION_ROOT,
}


def project(spec: Any) -> dict[str, Any]:
    """Return the canonical projection (spec section 3) of a resolved document."""
    document = _as_document(spec)
    doc = dict(document)

    if doc.get("extends") is not None:
        raise CanonicalError(
            f"cannot canonicalize an unresolved document (extends: {doc['extends']!r}); "
            "resolve the extends chain first (spec section 2.1)"
        )
    for field in _RESOLUTION_FIELDS:
        doc.pop(field, None)

    metadata = doc.get("metadata")
    if isinstance(metadata, Mapping) and _INLINE_SIGNATURE_FIELD in metadata:
        doc["metadata"] = {
            key: value
            for key, value in metadata.items()
            if key != _INLINE_SIGNATURE_FIELD
        }

    extensions = doc.pop("extensions", None)
    out = _CORE_ROOT.project(doc, "$")

    if extensions is not None:
        if not isinstance(extensions, Mapping):
            raise CanonicalError("$.extensions must be a mapping")
        projected: dict[str, Any] = {}
        for name, block in extensions.items():
            if name not in EXTENSION_KEYS:
                raise CanonicalError(f"unknown extension {name!r}")
            node = _EXTENSION_ROOTS[name]
            value = node.project(block, f"$.extensions.{name}")
            if _is_empty_container(value):
                continue
            projected[name] = value
        if projected:
            out["extensions"] = projected
    return out


def _as_document(spec: Any) -> Mapping[str, Any]:
    """Accept a raw resolved mapping or a parsed ``HushSpec``.

    A raw mapping is the form spec section 6 recommends, but both reach the same
    projection: the one presence-significant property (``OriginProfile.match``)
    is an optional mapping in the typed model, so the two agree.
    """
    if isinstance(spec, Mapping):
        return spec
    to_dict = getattr(spec, "to_dict", None)
    if callable(to_dict):
        result = to_dict()
        if isinstance(result, Mapping):
            return result
    raise CanonicalError(
        f"expected a resolved HushSpec document or mapping, got {type(spec).__name__}"
    )


# --------------------------------------------------------------------------- #
# RFC 8785 serialization (spec/hushspec-canonical.md section 4)
# --------------------------------------------------------------------------- #


def _utf16_sort_key(key: str) -> bytes:
    """Sort key ordering strings by UTF-16 code unit (RFC 8785 section 3.2.3).

    Python compares strings by code point, which differs above the BMP: an
    astral character encodes to a high surrogate (U+D800..U+DBFF) that sorts
    *below* BMP characters from U+E000 up. Big-endian UTF-16 bytes compare
    exactly as the code-unit sequence does, because every unit is two aligned
    bytes. ``surrogatepass`` keeps lone surrogates from raising here; the
    encoder rejects them when the bytes are produced.
    """
    return key.encode("utf-16-be", "surrogatepass")


def _jcs_string(value: str) -> str:
    """Serialize a JSON string per RFC 8785 section 3.2.2.2.

    ``json.dumps(..., ensure_ascii=False)`` already emits exactly the JCS escape
    set -- ``\\"``, ``\\\\``, the short escapes for U+0008/U+0009/U+000A/U+000C/
    U+000D, and lowercase ``\\u00xx`` for the remaining C0 controls -- and
    escapes nothing else, so U+007F, U+00A0, U+2028/U+2029 and astral characters
    stay literal as the spec requires.
    """
    return json.dumps(value, ensure_ascii=False)


def _es6_number(value: float) -> str:
    """Format a non-integral double as ECMAScript ``Number::toString`` does.

    ``repr`` gives the shortest decimal that round-trips, which is the digit
    string ES6 asks for, but the two disagree on how those digits are laid out.
    Python switches to exponent notation at 1e16 where ES6 holds positional
    notation out to 1e21 (``repr(1e20) == '1e+20'``, ES6 gives
    ``100000000000000000000``), and Python pads the exponent to two digits
    (``repr(1e-7) == '1e-07'``, ES6 gives ``1e-7``). The layout below is the
    ES6 rule applied to ``repr``'s digits.
    """
    if math.isnan(value) or math.isinf(value):
        raise CanonicalError("NaN and Infinity are not representable in JSON")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    digits, exponent = _shortest_digits(abs(value))
    k = len(digits)
    n = exponent + k  # value == 0.<digits> x 10**n
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        exp = n - 1
        mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mantissa}e{'+' if exp >= 0 else '-'}{abs(exp)}"
    return sign + body


def _shortest_digits(value: float) -> tuple[str, int]:
    """Return ``(digits, exponent)`` with ``value == 0.<digits> * 10**(exponent+len)``.

    Trailing zeros are stripped so the digit string is the shortest round-trip
    significand, as ECMAScript's algorithm requires.
    """
    text = repr(value)
    mantissa, _, exp_text = text.partition("e")
    exponent = int(exp_text) if exp_text else 0
    whole, _, fraction = mantissa.partition(".")
    digits = whole + fraction
    exponent -= len(fraction)
    # `exponent` counts from the least significant digit, so dropping leading
    # zeros leaves it untouched; dropping trailing zeros raises it by one each.
    digits = digits.lstrip("0") or "0"
    while len(digits) > 1 and digits.endswith("0"):
        digits = digits[:-1]
        exponent += 1
    return digits, exponent


def _jcs(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > SAFE_INTEGER_MAX:
            raise CanonicalError(f"integer {value} exceeds the safe range (2^53-1)")
        return str(value)
    if isinstance(value, float):
        if value.is_integer() and abs(value) <= SAFE_INTEGER_MAX:
            return str(int(value))
        return _es6_number(value)
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalError(f"object key {key!r} is not a string")
        members = (
            _jcs_string(key) + ":" + _jcs(value[key])
            for key in sorted(value, key=_utf16_sort_key)
        )
        return "{" + ",".join(members) + "}"
    raise CanonicalError(f"unsupported value type {type(value).__name__}")


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def canonical_json(spec: Any) -> str:
    """Return the canonical JSON text of a **resolved** HushSpec document.

    ``spec`` is either the raw parsed mapping (preferred; see the module
    docstring) or a parsed :class:`~hushspec.schema.HushSpec`. Raises
    :class:`CanonicalError` if ``extends`` is still set, if an unknown field or
    extension is present, or if a value has no canonical JSON form.
    """
    return _jcs(project(spec))


def canonical_json_value(value: Any) -> str:
    """Return the RFC 8785 canonical JSON text of an arbitrary JSON value.

    This is the serializer of spec section 4 on its own, with no HushSpec
    projection (spec section 3) applied. It exists for the objects the
    companion specifications canonicalize that are *not* policy documents --
    today the signature envelope of ``spec/hushspec-signing.md`` section 4.1,
    which has no schema defaults to materialize. Pass a policy through
    :func:`canonical_json` instead; it projects first.
    """
    return _jcs(_plain(value))


def digest(canonical: str) -> str:
    """``sha256:`` + 64 lowercase hex over the UTF-8 bytes of *canonical*.

    The one place a content hash is computed: a receipt hash, a log entry
    hash, a bundle subject digest and a policy hash are all this function over
    different canonical text.
    """
    return HASH_PREFIX + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def is_content_hash(value: Any) -> bool:
    """Whether *value* is a wire content hash: ``sha256:`` + 64 lowercase hex.

    The spelling is normative (spec section 5), so an upper-case or
    wrong-length digest is not one.
    """
    if not isinstance(value, str) or not value.startswith(HASH_PREFIX):
        return False
    hex_part = value[len(HASH_PREFIX):]
    return len(hex_part) == 64 and all(c in "0123456789abcdef" for c in hex_part)


def content_hash(spec: Any) -> str:
    """Return ``sha256:<64 lowercase hex>`` over the canonical form (spec section 5).

    The prefix is part of the wire value everywhere a content hash appears, so a
    verifier can reject an algorithm it does not implement instead of guessing.
    """
    return digest(canonical_json(spec))
