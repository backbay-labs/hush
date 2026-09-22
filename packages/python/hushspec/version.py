"""HushSpec specification version support.

Version acceptance follows core spec 2.2: an engine that supports a
minor version ``X.Y`` accepts every ``X.Y.Z`` document, because patch versions
carry only clarifications and errata. This engine implements the 1.0.0
semantics, which are identical to 0.2.0, and also accepts 0.1.x and 0.2.x
documents (core spec 10).
"""

from __future__ import annotations

from typing import Optional

#: The HushSpec version this engine writes by default.
HUSHSPEC_VERSION = "1.0.0"

#: Minor versions this engine accepts, as ``X.Y`` strings, in order.
HUSHSPEC_SUPPORTED_MINORS: tuple[str, ...] = ("0.1", "0.2", "1.0")

#: Representative full versions for each supported minor (display only; use
#: :func:`is_supported` for acceptance, which accepts every patch level).
HUSHSPEC_SUPPORTED_VERSIONS: tuple[str, ...] = ("0.1.0", "0.2.0", "1.0.0")

#: Backwards-compatible alias for the representative full versions.
SUPPORTED_VERSIONS = frozenset(HUSHSPEC_SUPPORTED_VERSIONS)

#: Unprefixed alias for :data:`HUSHSPEC_SUPPORTED_MINORS`, so the constant can
#: be reached under the same short name in every SDK.
SUPPORTED_MINORS: tuple[str, ...] = HUSHSPEC_SUPPORTED_MINORS


def _is_digits(part: str) -> bool:
    return len(part) > 0 and all("0" <= ch <= "9" for ch in part)


def major_version(version: str) -> Optional[int]:
    """The MAJOR component of a well-formed ``X.Y.Z`` version string.

    The document format is versioned by its major component: the 1.0 format
    differs from 0.x only in the constraints it places on a document (core spec
    10), so a constraint introduced with 1.0 is gated on this rather than on
    the minor an engine happens to support. Returns ``None`` when *version* is
    not a well-formed ``X.Y.Z`` string, or when its major does not fit an
    unsigned 32-bit integer, the bound every SDK applies; a digit string that
    long is never converted at all.
    """
    if not isinstance(version, str):
        return None
    parts = version.split(".")
    if len(parts) != 3:
        return None
    if not all(_is_digits(part) for part in parts):
        return None
    if len(parts[0]) > 10:
        return None
    major = int(parts[0])
    return major if major <= 0xFFFF_FFFF else None


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
