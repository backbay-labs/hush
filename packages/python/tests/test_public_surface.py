"""The names ``import hushspec`` is expected to carry.

Isomorphism across the SDKs is partly a naming property: a reader who knows
the Rust reference should find the same concept under the same name here, and
a snippet in the docs should not need a different import per language. These
are the names the cross-SDK parity checklist pins, plus the invariant that
``__all__`` never advertises something the package does not actually export.
"""

from __future__ import annotations

import pytest

import hushspec

#: Names every SDK exposes, checked here so a rename or a dropped re-export
#: fails loudly rather than only showing up in another language's port.
ISOMORPHIC_NAMES = [
    # parsing, validation, merging, resolution
    "parse",
    "parse_or_raise",
    "validate",
    "merge",
    "resolve",
    "resolve_file",
    # evaluation
    "evaluate",
    "evaluate_traced",
    "compile_policy",
    "evaluate_with_detection",
    "evaluate_with_context",
    "default_detector_registry",
    # identity and evidence
    "content_hash",
    "canonical_json",
    "evaluate_audited",
    "receipt_hash",
    "sign_policy",
    "verify_policy",
    "sign_receipt",
    "verify_receipt",
    "verify_log",
    "verify_bundle",
    "parse_bundle",
    # enforcement and delivery
    "HushGuard",
    "ReceiptSink",
    "FileReceiptSink",
    "StderrReceiptSink",
    "OtlpReceiptSink",
    "PolicyWatcher",
    # constants
    "HUSHSPEC_VERSION",
    "SUPPORTED_MINORS",
    "ERROR_CODES",
    "BUNDLE_REASON_CODES",
    "REASON_CODES",
]


@pytest.mark.parametrize("name", ISOMORPHIC_NAMES)
def test_the_package_exports_the_isomorphic_name(name: str) -> None:
    assert hasattr(hushspec, name), f"hushspec does not export {name}"
    assert name in hushspec.__all__, f"{name} is not listed in __all__"


def test_all_is_honest() -> None:
    missing = [name for name in hushspec.__all__ if not hasattr(hushspec, name)]
    assert missing == [], f"__all__ advertises names the package lacks: {missing}"


def test_all_has_no_duplicates() -> None:
    seen: set[str] = set()
    duplicates = sorted({n for n in hushspec.__all__ if n in seen or seen.add(n)})
    assert duplicates == [], f"__all__ lists these twice: {duplicates}"


def test_the_version_constants_agree() -> None:
    assert hushspec.__version__ == hushspec.HUSHSPEC_VERSION
    assert hushspec.SUPPORTED_MINORS is hushspec.HUSHSPEC_SUPPORTED_MINORS
    assert hushspec.HUSHSPEC_VERSION.startswith(hushspec.SUPPORTED_MINORS[-1] + ".")
