"""HushSpec version constants."""

HUSHSPEC_VERSION = "0.1.0"
SUPPORTED_VERSIONS = frozenset(["0.1.0"])


def is_supported(version: str) -> bool:
    """Returns True if the given version string is supported."""
    return version in SUPPORTED_VERSIONS
