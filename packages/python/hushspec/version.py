"""HushSpec specification version support.

Version acceptance follows core spec 2.2 (D14): an engine that supports a
minor version ``X.Y`` accepts every ``X.Y.Z`` document, because patch versions
carry only clarifications and errata. This engine implements the 0.2.0
semantics and also accepts 0.1.x documents (evaluated under 0.2 semantics).
"""

from __future__ import annotations

from typing import Optional

#: The HushSpec version this engine writes by default.
HUSHSPEC_VERSION = "0.2.0"

#: Minor versions this engine accepts, as ``X.Y`` strings, in order.
HUSHSPEC_SUPPORTED_MINORS: tuple[str, ...] = ("0.1", "0.2")

#: Representative full versions for each supported minor (display only; use
#: :func:`is_supported` for acceptance, which accepts every patch level).
HUSHSPEC_SUPPORTED_VERSIONS: tuple[str, ...] = ("0.1.0", "0.2.0")

#: Backwards-compatible alias for the representative full versions.
SUPPORTED_VERSIONS = frozenset(HUSHSPEC_SUPPORTED_VERSIONS)


def _is_digits(part: str) -> bool:
    return len(part) > 0 and all("0" <= ch <= "9" for ch in part)


def supported_minor(version: str) -> Optional[str]:
    """The ``X.Y`` minor of a well-formed, supported version string."""
    if not isinstance(version, str):
        return None
    parts = version.split(".")
    if len(parts) != 3:
        return None
    major, minor, patch = parts
    if not _is_digits(major) or not _is_digits(minor) or not _is_digits(patch):
        return None
    for supported in HUSHSPEC_SUPPORTED_MINORS:
        if supported.split(".", 1) == [major, minor]:
            return supported
    return None


def is_supported(version: str) -> bool:
    """Whether *version* is a well-formed ``X.Y.Z`` of a supported minor."""
    return supported_minor(version) is not None
