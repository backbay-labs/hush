from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from hushspec.builtins import load_builtin
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
    stack = [source] if source is not None else []
    return _resolve_inner(spec, source, loader or _create_composite_loader(), stack)


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
    source = str(Path(path).resolve())
    try:
        content = Path(source).read_text()
    except OSError as exc:
        return False, f"failed to read HushSpec at {source}: {exc}"
    ok, parsed = parse(content)
    if not ok:
        return False, f"failed to parse HushSpec at {source}: {parsed}"
    return resolve(parsed, source=source, loader=_create_composite_loader())


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


def _create_composite_loader() -> Resolver:
    """Loader that serves `builtin:<name>` references from the embedded
    rulesets and everything else from the filesystem (mirrors the Rust/TS
    resolvers). A bare name with no path separators or dots is tried as a
    builtin before falling back to the filesystem.

    `http://`/`https://` references are rejected outright, mirroring Rust's
    (non-`http`-feature) `create_composite_loader` and TS's synchronous
    `createCompositeLoader`: this loader has no HTTP client, so silently
    handing a URL to the filesystem loader would fail with a confusing
    "no such file or directory" error instead of a clear one.
    """

    def _loader(reference: str, source: str | None) -> LoadedSpec:
        if reference.startswith("builtin:"):
            spec = load_builtin(reference)
            if spec is None:
                raise ValueError(f"unknown builtin ruleset '{reference}'")
            return LoadedSpec(source=reference, spec=spec)

        if reference.startswith("http://") or reference.startswith("https://"):
            raise ValueError(
                "HTTP-based policy loading is not supported by the default "
                f"loader; provide a custom `loader` for '{reference}'"
            )

        if "/" not in reference and "\\" not in reference and "." not in reference:
            spec = load_builtin(reference)
            if spec is not None:
                return LoadedSpec(source=f"builtin:{reference}", spec=spec)

        return _load_from_filesystem(reference, source)

    return _loader


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
