"""Document parsing under the HushSpec YAML profile (core spec 2.4).

The profile is YAML 1.2 **Core** schema, exactly one document per stream, no
duplicate mapping keys, no anchors, aliases, or merge keys, no tab
indentation, and bounded size, nesting depth, and node count.

PyYAML implements YAML 1.1, whose boolean resolver also accepts
``yes/no/on/off/y/n``; the loader below installs Core-schema resolvers so those
tokens stay plain strings and are rejected wherever a boolean is required.
"""

from __future__ import annotations

import collections.abc
import math
import re

import yaml

from hushspec.error_codes import ERROR_PARSE, ErrorMessage, code_of
from hushspec.raw_validate import unsafe_integer, validate_raw_document
from hushspec.schema import HushSpec

#: Maximum accepted document size in bytes (core spec 2.4, RECOMMENDED default).
MAX_DOCUMENT_BYTES = 1024 * 1024
#: Maximum accepted nesting depth (core spec 2.4, RECOMMENDED default).
MAX_DOCUMENT_DEPTH = 32
#: Maximum accepted node count (core spec 2.4, RECOMMENDED default).
MAX_NODE_COUNT = 100_000

#: YAML 1.2 Core schema boolean forms. YAML 1.1's `yes`/`no`/`on`/`off` are
#: deliberately absent -- under the profile they are plain strings.
_CORE_BOOL = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$")
_CORE_INT = re.compile(r"^(?:[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)$")
_CORE_FLOAT = re.compile(
    r"^(?:[-+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]+)?"
    r"|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$"
)
_CORE_NULL = re.compile(r"^(?:~|null|Null|NULL|)$")


class _ProfileError(yaml.YAMLError):
    """Raised when a document violates the HushSpec YAML profile."""


class _StrictSafeLoader(yaml.SafeLoader):
    """A ``SafeLoader`` restricted to the HushSpec YAML profile.

    * Anchors, aliases, and merge keys are rejected at compose time (the other
      three SDKs reject them, and they are also the shape an alias bomb takes).
    * Duplicate mapping keys are rejected (PyYAML otherwise silently keeps the
      last value).
    * Booleans follow the YAML 1.2 Core schema (see ``_CORE_BOOL``).
    """

    # -- anchors and aliases (compose phase) --------------------------------
    def compose_node(self, parent, index):
        if self.check_event(yaml.events.AliasEvent):
            event = self.peek_event()
            raise _ProfileError(
                f"line {event.start_mark.line + 1}: aliases are not allowed "
                "(YAML profile)"
            )
        event = self.peek_event()
        if isinstance(event, yaml.events.ScalarEvent) and event.tag == "!":
            # YAML's non-specific scalar tag means string, irrespective of
            # the plain spelling. PyYAML otherwise applies implicit resolution.
            event.tag = "tag:yaml.org,2002:str"
        if getattr(event, "anchor", None) is not None:
            raise _ProfileError(
                f"line {event.start_mark.line + 1}: anchors are not allowed "
                "(YAML profile)"
            )
        return super().compose_node(parent, index)

    # -- merge keys and duplicate keys (construct phase) --------------------
    def flatten_mapping(self, node):
        for key_node, _value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise _ProfileError(
                    f"line {key_node.start_mark.line + 1}: merge keys are not "
                    "allowed (YAML profile)"
                )
        return super().flatten_mapping(node)

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, yaml.MappingNode):
            raise yaml.constructor.ConstructorError(
                None,
                None,
                f"expected a mapping node, but found {node.id}",
                node.start_mark,
            )
        self.flatten_mapping(node)
        mapping: dict = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, collections.abc.Hashable):
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found unhashable key",
                    key_node.start_mark,
                )
            if key in mapping:
                raise _ProfileError(
                    f"line {key_node.start_mark.line + 1}: duplicate entry with "
                    f"key {key!r} (YAML profile)"
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _construct_core_int(loader, node):
    text = loader.construct_scalar(node)
    if not _CORE_INT.fullmatch(text):
        raise _ProfileError(f"invalid YAML 1.2 Core integer: {text!r}")
    # Bound before int() so huge literals cannot hit Python's digit limit.
    digits = text.lstrip("+-").lstrip("0") or "0"
    base = 10
    if text.startswith(("0o", "0x")):
        base = 8 if text[1] == "o" else 16
        digits = text[2:].lstrip("0") or "0"
    if len(digits) > 1000:
        raise _ProfileError("integer exceeds the safe range (2^53-1)")
    return int(digits, base) * (-1 if text.startswith("-") else 1)


def _construct_core_float(loader, node):
    text = loader.construct_scalar(node)
    if not _CORE_FLOAT.fullmatch(text):
        raise _ProfileError(f"invalid YAML 1.2 Core float: {text!r}")
    special = text.lstrip("+-").lower()
    value = float(text.replace(".", "", 1)) if special in (".inf", ".nan") else float(text)
    return value


def _construct_core_bool(loader, node):
    text = loader.construct_scalar(node)
    if not _CORE_BOOL.fullmatch(text):
        raise _ProfileError(f"invalid YAML 1.2 Core boolean: {text!r}")
    return text.lower() == "true"


def _construct_core_null(loader, node):
    text = loader.construct_scalar(node)
    if not _CORE_NULL.fullmatch(text):
        raise _ProfileError(f"invalid YAML 1.2 Core null: {text!r}")
    return None


# Replace every YAML 1.1 resolver, including timestamps, sexagesimal numbers,
# binary and underscore-bearing integers. Keep merge detection for the profile.
_StrictSafeLoader.yaml_implicit_resolvers = {}
for _tag, _pattern, _first in (
    ("bool", _CORE_BOOL, "tTfF"),
    ("int", _CORE_INT, "-+0123456789"),
    ("float", _CORE_FLOAT, "-+0123456789."),
    ("null", _CORE_NULL, ["~", "n", "N", ""]),
    ("merge", re.compile(r"^(?:<<)$"), "<"),
):
    _StrictSafeLoader.add_implicit_resolver(f"tag:yaml.org,2002:{_tag}", _pattern, _first)
_StrictSafeLoader.add_constructor("tag:yaml.org,2002:int", _construct_core_int)
_StrictSafeLoader.add_constructor("tag:yaml.org,2002:float", _construct_core_float)
_StrictSafeLoader.add_constructor("tag:yaml.org,2002:bool", _construct_core_bool)
_StrictSafeLoader.add_constructor("tag:yaml.org,2002:null", _construct_core_null)
_StrictSafeLoader.yaml_constructors = {
    tag: constructor for tag, constructor in _StrictSafeLoader.yaml_constructors.items()
    if tag is None or tag in {f"tag:yaml.org,2002:{kind}" for kind in ("str", "int", "float", "bool", "null", "seq", "map")}
}

#: Public alias: the YAML 1.2 Core, profile-enforcing loader. Exposed so tools
#: that read HushSpec-adjacent YAML (evaluator fixtures, bundles) resolve
#: scalars the same way the parser does.
CoreSafeLoader = _StrictSafeLoader


def _measure(value, depth: int) -> tuple[int, int]:
    """Return ``(max_depth, node_count)`` for a parsed document.

    Both are quantities core spec 2.4 bounds. Mapping keys count as nodes and
    nest one level, so a deeply nested key is measured like a value.
    """
    if isinstance(value, list):
        max_depth, nodes = depth, 1
        for item in value:
            item_depth, item_nodes = _measure(item, depth + 1)
            max_depth = max(max_depth, item_depth)
            nodes += item_nodes
        return max_depth, nodes
    if isinstance(value, dict):
        max_depth, nodes = depth, 1
        for key, item in value.items():
            key_depth, key_nodes = _measure(key, depth + 1)
            item_depth, item_nodes = _measure(item, depth + 1)
            max_depth = max(max_depth, key_depth, item_depth)
            nodes += key_nodes + item_nodes
        return max_depth, nodes
    return depth, 1


def _nonfinite_number(value, path: str = "$") -> str | None:
    if isinstance(value, float) and not math.isfinite(value):
        return f"{path}: non-finite numbers are not allowed"
    entries = value.items() if isinstance(value, dict) else enumerate(value) if isinstance(value, list) else ()
    for key, child in entries:
        found = _nonfinite_number(child, f"{path}.{key}")
        if found:
            return found
    return None


def _normalize_policy_integers(value, path: tuple[str, ...] = ()):
    """Keep free-form context and number fields as doubles, normalize integers.

    The two number-typed properties are the ratio and similarity threshold;
    all other numeric policy properties are integers. Unknown fields are still
    refused by validate_raw_document after this scalar pass.
    """
    if path[-1:] == ("context",) and isinstance(value, dict):
        return value
    if isinstance(value, dict):
        return {key: _normalize_policy_integers(child, (*path, str(key))) for key, child in value.items()}
    if isinstance(value, list):
        return [_normalize_policy_integers(child, (*path, str(index))) for index, child in enumerate(value)]
    if isinstance(value, float) and path[-2:] not in (
        ("patch_integrity", "max_imbalance_ratio"),
        ("threat_intel", "similarity_threshold"),
    ):
        if abs(value) > 2**53 - 1:
            raise _ProfileError(f"{'.'.join(path)}: integer field exceeds the safe range (2^53-1)")
        if value.is_integer():
            return int(value)
    return value


def parse(yaml_str: str) -> tuple[bool, HushSpec | str]:
    """Returns ``(True, spec)`` on success or ``(False, error_message)`` on failure.

    The failure value is an :class:`~hushspec.error_codes.ErrorMessage`: a
    ``str`` carrying the registry ``code`` of the refusal
    (``spec/registries/error-codes.yaml``), so a caller can branch on the
    reason rather than on the wording.
    """
    if len(yaml_str.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        return False, _refused(
            "YAML parse error: document exceeds the maximum size of "
            f"{MAX_DOCUMENT_BYTES} bytes"
        )

    try:
        doc = yaml.load(yaml_str, Loader=_StrictSafeLoader)
    except yaml.composer.ComposerError as e:
        # PyYAML reports a second document as a compose-time surprise; the
        # profile refuses multi-document streams outright (core spec 2.4), and
        # the shared vectors read the diagnostic for that phrase.
        if "single document" in str(e):
            return False, _refused(
                "YAML parse error: multi-document streams are not allowed "
                "(YAML profile)"
            )
        return False, _refused(f"YAML parse error: {e}")
    except yaml.YAMLError as e:
        return False, _refused(f"YAML parse error: {e}")
    except RecursionError:
        # Deeply nested flow YAML overflows the interpreter stack during
        # compose; PyYAML lets that surface as an uncaught RecursionError
        # rather than a YAMLError, so catch it explicitly and fail closed.
        return False, _refused("YAML parse error: document nesting is too deep")

    if not isinstance(doc, dict):
        return False, _refused("HushSpec document must be a YAML mapping")

    # Canonical spec 4.3 bounds integer syntax by the IEEE 754 safe range, and
    # the decoded document is the last place integer syntax is still telling
    # itself apart from float syntax.
    unsafe = unsafe_integer(doc)
    if unsafe is not None:
        return False, _refused(f"YAML parse error: {unsafe}")

    nonfinite = _nonfinite_number(doc)
    if nonfinite is not None:
        return False, _refused(f"YAML parse error: {nonfinite}")

    try:
        doc = _normalize_policy_integers(doc)
    except _ProfileError as error:
        return False, _refused(f"YAML parse error: {error}")

    depth, nodes = _measure(doc, 1)
    if depth > MAX_DOCUMENT_DEPTH:
        return False, _refused(
            "YAML parse error: document nesting exceeds the maximum depth of "
            f"{MAX_DOCUMENT_DEPTH}"
        )
    if nodes > MAX_NODE_COUNT:
        return False, _refused(
            "YAML parse error: document exceeds the maximum node count of "
            f"{MAX_NODE_COUNT}"
        )

    errors = validate_raw_document(doc)
    if errors:
        return False, _refused(errors[0], code_of(errors[0]))

    return True, HushSpec.from_dict(doc)


def _refused(message: str, code: str = ERROR_PARSE) -> ErrorMessage:
    return ErrorMessage(message, code)


def parse_or_raise(yaml_str: str) -> HushSpec:
    ok, result = parse(yaml_str)
    if not ok:
        error = ValueError(result)
        # The code rides on the exception too, so a caller that only ever uses
        # the raising form can still read the reason off it.
        error.code = code_of(result)  # type: ignore[attr-defined]
        raise error
    return result  # type: ignore[return-value]
