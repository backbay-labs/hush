"""Normative canonical-form vectors (spec/hushspec-canonical.md section 7).

Every file under ``fixtures/core/hash/`` pairs a resolved HushSpec document
with the exact canonical JSON text and content hash a conformant SDK MUST
produce. All four SDKs run the same directory; a divergence here is a
conformance failure, not a test-fixture problem.
"""

from __future__ import annotations

import difflib
from pathlib import Path
from typing import Any

import pytest
import yaml

from hushspec import canonical_json, content_hash
from hushspec.parse import CoreSafeLoader
from hushspec.resolve import create_builtin_loader, resolve
from hushspec.schema import HushSpec

REPO_ROOT = Path(__file__).resolve().parents[3]
VECTOR_DIR = REPO_ROOT / "fixtures" / "core" / "hash"
VECTOR_VERSION = "0.1.0"

VECTOR_FILES = sorted(VECTOR_DIR.glob("*.yaml"))


def _load_vector(path: Path) -> dict[str, Any]:
    # The vectors quote every key and the posture extension uses `on` as a
    # mapping key, so they must be read with the YAML 1.2 Core loader the
    # parser uses -- bare PyYAML would turn `on` into True.
    vector = yaml.load(path.read_text(encoding="utf-8"), Loader=CoreSafeLoader)
    assert isinstance(vector, dict), f"{path.name}: vector must be a mapping"
    assert vector.get("hushspec_hash_vector") == VECTOR_VERSION, (
        f"{path.name}: not a hushspec_hash_vector {VECTOR_VERSION} file"
    )
    return vector


def _resolved_policy(path: Path, policy: Any) -> Any:
    """Vectors carry an already-resolved ``policy``; resolve anyway if one does not.

    ``extends-resolved.yaml`` keeps the unresolved document in the
    informational ``source`` field and the resolved one in ``policy``. Should a
    future vector put an ``extends`` in ``policy``, resolve it against the
    embedded builtins the same way ``h2h resolve`` would -- canonicalizing a
    fragment is a conformance failure (spec section 2.1).
    """
    if not isinstance(policy, dict) or policy.get("extends") is None:
        return policy
    ok, resolved = resolve(HushSpec.from_dict(policy), loader=create_builtin_loader())
    assert ok, f"{path.name}: could not resolve `policy`: {resolved}"
    assert isinstance(resolved, HushSpec)
    return resolved


def _diff(expected: str, actual: str) -> str:
    matcher = difflib.SequenceMatcher(None, expected, actual)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        window = 40
        return (
            f"first difference at offset {i1} ({tag}):\n"
            f"  expected ...{expected[max(0, i1 - window):i2 + window]!r}...\n"
            f"  actual   ...{actual[max(0, j1 - window):j2 + window]!r}..."
        )
    return "strings are equal"


def test_vector_directory_is_populated() -> None:
    assert len(VECTOR_FILES) == 13, (
        f"expected the 13 normative vectors in {VECTOR_DIR}, found {len(VECTOR_FILES)}"
    )


@pytest.mark.parametrize("path", VECTOR_FILES, ids=lambda path: path.stem)
def test_canonical_vector(path: Path) -> None:
    vector = _load_vector(path)
    policy = _resolved_policy(path, vector["policy"])

    actual = canonical_json(policy)
    expected = vector["canonical"]
    assert actual == expected, f"{path.name}: canonical JSON mismatch\n{_diff(expected, actual)}"

    assert content_hash(policy) == vector["content_hash"], (
        f"{path.name}: content_hash mismatch"
    )


@pytest.mark.parametrize("path", VECTOR_FILES, ids=lambda path: path.stem)
def test_content_hash_wire_form(path: Path) -> None:
    digest = content_hash(_resolved_policy(path, _load_vector(path)["policy"]))
    prefix, _, hexdigest = digest.partition(":")
    assert prefix == "sha256"
    assert len(hexdigest) == 64
    assert hexdigest == hexdigest.lower()
    assert all(char in "0123456789abcdef" for char in hexdigest)
