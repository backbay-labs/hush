"""Resolve ``extends`` chains for parsed HushSpec documents."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from hushspec.merge import merge
from hushspec.parse import parse
from hushspec.schema import HushSpec


@dataclass
class LoadedSpec:
    source: str
    spec: HushSpec


Resolver = Callable[[str, str | None], LoadedSpec]


def resolve(
    spec: HushSpec,
    *,
    source: str | None = None,
    loader: Resolver | None = None,
) -> tuple[bool, HushSpec | str]:
    """Resolve ``extends`` recursively using the supplied loader or the filesystem."""
    stack = [source] if source is not None else []
    return _resolve_inner(spec, source, loader or _load_from_filesystem, stack)


def resolve_or_raise(
    spec: HushSpec,
    *,
    source: str | None = None,
    loader: Resolver | None = None,
) -> HushSpec:
    ok, result = resolve(spec, source=source, loader=loader)
    if not ok:
        raise ValueError(result)
    return result


def resolve_file(path: str | Path) -> tuple[bool, HushSpec | str]:
    """Load and resolve a HushSpec document from disk."""
    source = str(Path(path).resolve())
    try:
        content = Path(source).read_text()
    except OSError as exc:
        return False, f"failed to read HushSpec at {source}: {exc}"
    ok, parsed = parse(content)
    if not ok:
        return False, f"failed to parse HushSpec at {source}: {parsed}"
    return resolve(parsed, source=source, loader=_load_from_filesystem)


def _resolve_inner(
    spec: HushSpec,
    source: str | None,
    loader: Resolver,
    stack: list[str],
) -> tuple[bool, HushSpec | str]:
    if spec.extends is None:
        return True, spec

    try:
        loaded = loader(spec.extends, source)
    except Exception as exc:  # pragma: no cover - exercised through public API
        return False, str(exc)

    if loaded.source in stack:
        cycle = stack[stack.index(loaded.source) :] + [loaded.source]
        return False, f"circular extends detected: {' -> '.join(cycle)}"

    stack.append(loaded.source)
    ok, parent = _resolve_inner(loaded.spec, loaded.source, loader, stack)
    stack.pop()
    if not ok:
        return False, parent

    return True, merge(parent, spec)


def _load_from_filesystem(reference: str, source: str | None) -> LoadedSpec:
    path = Path(reference)
    if not path.is_absolute():
        path = Path(source).parent / path if source is not None else path.resolve()
    canonical = path.resolve()
    content = canonical.read_text()
    ok, parsed = parse(content)
    if not ok:
        raise ValueError(f"failed to parse HushSpec at {canonical}: {parsed}")
    return LoadedSpec(source=str(canonical), spec=parsed)
