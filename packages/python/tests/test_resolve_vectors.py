"""Resolution vectors (core spec 2.3, receipt spec 4.2), ``fixtures/core/resolve/``.

Each vector is an inline leaf document whose ``extends`` references only
builtins, so every SDK resolves it with its embedded rulesets and no
filesystem. The expectation is either the resolved content hash plus the chain
links (root first, the leaf recorded as ``memory``), or a rejection reason.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from hushspec.parse import CoreSafeLoader, parse_or_raise
from hushspec.resolve import (
    MEMORY_SOURCE,
    ResolveRejected,
    Resolution,
    create_composite_loader,
    resolve_with_options_or_raise,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
VECTORS = sorted((REPO_ROOT / "fixtures" / "core" / "resolve").glob("*.yaml"))


def test_the_vector_directory_is_populated() -> None:
    assert len(VECTORS) >= 7


@pytest.mark.parametrize("path", VECTORS, ids=[p.stem for p in VECTORS])
def test_resolve_vector(path: Path) -> None:
    vector = yaml.load(path.read_text(), Loader=CoreSafeLoader)
    assert vector["hushspec_resolve"] == "0.1.0", "unsupported vector version"
    spec = parse_or_raise(yaml.safe_dump(vector["policy"]))
    expect = vector["expect"]

    if expect.get("rejects") is not None:
        with pytest.raises(ResolveRejected) as caught:
            resolve_with_options_or_raise(spec, loader=create_composite_loader())
        assert caught.value.code == expect["rejects"], str(caught.value)
        return

    resolution = resolve_with_options_or_raise(spec, loader=create_composite_loader())
    assert resolution.content_hash == expect["content_hash"]
    assert [
        {"source": link.source, "content_hash": link.content_hash}
        for link in resolution.chain
    ] == expect["chain"]


def test_an_in_memory_leaf_is_recorded_as_memory() -> None:
    # The spelling is normative: the vectors pin it, and it is what a receipt's
    # `extends_chain` shows for a policy the runtime had in hand.
    resolution = Resolution.from_resolved(parse_or_raise('hushspec: "0.1.0"\n'))
    assert MEMORY_SOURCE == "memory"
    assert resolution.chain[0].source == MEMORY_SOURCE
    assert resolution.had_extends() is False
