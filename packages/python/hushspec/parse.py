"""Parse YAML strings into typed HushSpec documents."""

from __future__ import annotations

import yaml

from hushspec.raw_validate import validate_raw_document
from hushspec.schema import HushSpec


def parse(yaml_str: str) -> tuple[bool, HushSpec | str]:
    """Parse YAML into HushSpec.

    Returns ``(True, spec)`` on success or ``(False, error_message)`` on failure.
    """
    try:
        doc = yaml.safe_load(yaml_str)
    except yaml.YAMLError as e:
        return False, f"YAML parse error: {e}"

    if not isinstance(doc, dict):
        return False, "HushSpec document must be a YAML mapping"

    doc = _normalize_yaml_mapping_keys(doc)
    errors = validate_raw_document(doc)
    if errors:
        return False, errors[0]

    spec = _dict_to_hushspec(doc)
    return True, spec


def parse_or_raise(yaml_str: str) -> HushSpec:
    """Parse YAML into HushSpec, raising ``ValueError`` on failure."""
    ok, result = parse(yaml_str)
    if not ok:
        raise ValueError(result)
    return result  # type: ignore[return-value]


def _dict_to_hushspec(doc: dict) -> HushSpec:
    """Convert a raw dict (from YAML) into a typed ``HushSpec`` dataclass."""
    return HushSpec.from_dict(doc)


def _normalize_yaml_mapping_keys(value):
    """Normalize PyYAML's YAML 1.1 bool-key coercions (notably bare `on:`)."""
    if isinstance(value, dict):
        normalized = {}
        for key, item in value.items():
            normalized_key = "on" if key is True and "on" not in value else key
            normalized[normalized_key] = _normalize_yaml_mapping_keys(item)
        return normalized
    if isinstance(value, list):
        return [_normalize_yaml_mapping_keys(item) for item in value]
    return value
