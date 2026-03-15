"""Parse YAML strings into typed HushSpec documents."""

from __future__ import annotations

import yaml

from hushspec.schema import HushSpec

KNOWN_TOP_LEVEL_KEYS = frozenset(
    {"hushspec", "name", "description", "extends", "merge_strategy", "rules", "extensions"}
)
KNOWN_RULE_KEYS = frozenset(
    {
        "forbidden_paths",
        "path_allowlist",
        "egress",
        "secret_patterns",
        "patch_integrity",
        "shell_commands",
        "tool_access",
        "computer_use",
        "remote_desktop_channels",
        "input_injection",
    }
)
KNOWN_EXTENSION_KEYS = frozenset({"posture", "origins", "detection"})


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

    # Check unknown top-level fields
    for key in doc:
        if key not in KNOWN_TOP_LEVEL_KEYS:
            return False, f"unknown top-level field: {key}"

    if "hushspec" not in doc or not isinstance(doc["hushspec"], str):
        return False, 'missing or invalid "hushspec" version field'

    # Check unknown rule keys
    if "rules" in doc and isinstance(doc["rules"], dict):
        for key in doc["rules"]:
            if key not in KNOWN_RULE_KEYS:
                return False, f"unknown rule: {key}"

    # Check unknown extension keys
    if "extensions" in doc and isinstance(doc["extensions"], dict):
        for key in doc["extensions"]:
            if key not in KNOWN_EXTENSION_KEYS:
                return False, f"unknown extension: {key}"

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
