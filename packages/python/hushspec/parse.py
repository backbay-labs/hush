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
import re

import yaml

from hushspec.error_codes import ERROR_PARSE, ErrorMessage, code_of
from hushspec.raw_validate import validate_raw_document
from hushspec.schema import HushSpec

#: Maximum accepted document size in bytes (core spec 2.4, RECOMMENDED default).
MAX_DOCUMENT_BYTES = 1024 * 1024
#: Maximum accepted nesting depth (core spec 2.4, RECOMMENDED default).
MAX_NESTING_DEPTH = 32
#: Maximum accepted node count (core spec 2.4, RECOMMENDED default).
MAX_NODE_COUNT = 100_000

#: YAML 1.2 Core schema boolean forms. YAML 1.1's `yes`/`no`/`on`/`off` are
#: deliberately absent -- under the profile they are plain strings.
_CORE_BOOL = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$")


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


def _install_core_bool_resolver(loader: type[yaml.SafeLoader]) -> None:
    """Narrow the implicit boolean resolver to the YAML 1.2 Core forms.

    ``yaml_implicit_resolvers`` is a first-character index; PyYAML registers
    the 1.1 boolean pattern under ``y n Y N t f T F o O`` (plus the empty
    key). Rebuilding the table drops ``yes``/``no``/``on``/``off`` -- they
    resolve as plain strings, so ``enabled: yes`` fails the boolean check in
    ``raw_validate`` instead of silently meaning ``true``.
    """
    bool_tag = "tag:yaml.org,2002:bool"
    resolvers: dict[str, list] = {}
    for first_char, entries in yaml.SafeLoader.yaml_implicit_resolvers.items():
        kept = [(tag, regex) for tag, regex in entries if tag != bool_tag]
        resolvers[first_char] = kept
    for first_char in "tTfF":
        resolvers.setdefault(first_char, [])
        resolvers[first_char] = [(bool_tag, _CORE_BOOL)] + resolvers[first_char]
    loader.yaml_implicit_resolvers = {
        key: list(value) for key, value in resolvers.items() if value
    }


_install_core_bool_resolver(_StrictSafeLoader)

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

    depth, nodes = _measure(doc, 1)
    if depth > MAX_NESTING_DEPTH:
        return False, _refused(
            "YAML parse error: document nesting exceeds the maximum depth of "
            f"{MAX_NESTING_DEPTH}"
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
