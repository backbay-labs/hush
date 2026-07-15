from __future__ import annotations

import collections.abc

import yaml

from hushspec.raw_validate import validate_raw_document
from hushspec.schema import HushSpec

# Upper bound on the alias-expanded node count of a single document. PyYAML
# shares anchor nodes, so a "billion laughs" bomb composes only a handful of
# nodes -- but our post-parse passes (_normalize_yaml_mapping_keys,
# validate_raw_document) walk that shared DAG as a *tree*, so an
# exponentially-expanding document would hang there. Capping the alias-expanded
# size at compose time rejects such bombs before they reach those passes. 100k
# is far above any realistic policy (shipped policies are a few hundred nodes).
_MAX_EXPANDED_NODES = 100_000


class _NodeLimitError(yaml.YAMLError):
    """Raised when a document's alias-expanded node count exceeds the cap."""


class _StrictSafeLoader(yaml.SafeLoader):
    """A ``SafeLoader`` hardened to match the Rust/TS/Go SDKs.

    * Duplicate mapping keys are rejected (PyYAML otherwise silently keeps the
      last value; the other three SDKs reject duplicates).
    * Alias expansion is bounded so an anchor/alias bomb fails fast instead of
      hanging in the post-parse tree walks.
    """

    def __init__(self, stream) -> None:
        super().__init__(stream)
        # id(node) -> alias-expanded node count, memoized so shared anchor
        # nodes are sized once.
        self._expanded_sizes: dict[int, int] = {}

    # -- alias-expansion cap (compose phase) --------------------------------
    def compose_node(self, parent, index):
        node = super().compose_node(parent, index)
        if self._expanded_size(node) > _MAX_EXPANDED_NODES:
            raise _NodeLimitError(
                "YAML alias expansion exceeds the maximum of "
                f"{_MAX_EXPANDED_NODES} nodes"
            )
        return node

    def _expanded_size(self, node) -> int:
        key = id(node)
        cached = self._expanded_sizes.get(key)
        if cached is not None:
            return cached
        # Children are composed before their container, so their sizes are
        # already memoized here. An aliased child resolves to the same node
        # object, so it contributes its target's expanded size -- which is
        # what makes a bomb's size grow exponentially and trip the cap within
        # a few levels.
        if isinstance(node, yaml.SequenceNode):
            size = 1
            for child in node.value:
                size += self._expanded_sizes.get(id(child), 1)
        elif isinstance(node, yaml.MappingNode):
            size = 1
            for key_node, value_node in node.value:
                size += self._expanded_sizes.get(id(key_node), 1)
                size += self._expanded_sizes.get(id(value_node), 1)
        else:
            size = 1
        self._expanded_sizes[key] = size
        return size

    # -- duplicate-key rejection (construct phase) --------------------------
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
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def parse(yaml_str: str) -> tuple[bool, HushSpec | str]:
    """Returns ``(True, spec)`` on success or ``(False, error_message)`` on failure."""
    try:
        doc = yaml.load(yaml_str, Loader=_StrictSafeLoader)
    except yaml.YAMLError as e:
        return False, f"YAML parse error: {e}"
    except RecursionError:
        # Deeply nested flow YAML overflows the interpreter stack during
        # compose; PyYAML lets that surface as an uncaught RecursionError
        # rather than a YAMLError, so catch it explicitly and fail closed.
        return False, "YAML parse error: document nesting is too deep"

    if not isinstance(doc, dict):
        return False, "HushSpec document must be a YAML mapping"

    doc = _normalize_yaml_mapping_keys(doc)
    errors = validate_raw_document(doc)
    if errors:
        return False, errors[0]

    return True, HushSpec.from_dict(doc)


def parse_or_raise(yaml_str: str) -> HushSpec:
    ok, result = parse(yaml_str)
    if not ok:
        raise ValueError(result)
    return result  # type: ignore[return-value]


def _normalize_yaml_mapping_keys(value):
    """Normalize PyYAML's YAML 1.1 bool-key coercions (notably bare ``on:``)."""
    if isinstance(value, dict):
        normalized = {}
        for key, item in value.items():
            normalized_key = "on" if key is True and "on" not in value else key
            normalized[normalized_key] = _normalize_yaml_mapping_keys(item)
        return normalized
    if isinstance(value, list):
        return [_normalize_yaml_mapping_keys(item) for item in value]
    return value
