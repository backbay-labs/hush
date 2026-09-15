#!/usr/bin/env python3
"""Reference canonicalizer for HushSpec documents.

Implements spec/hushspec-canonical.md: the canonical *projection* of a
resolved HushSpec document (schema defaults materialized, resolution-only
fields removed) followed by RFC 8785 (JCS) serialization and a SHA-256
content digest.

This script is the reference that generates the vectors under
fixtures/core/hash/. SDK implementations must reproduce its output
byte-for-byte for every vector.

Usage:
    canonical_json.py POLICY            # print canonical JSON and digest
    canonical_json.py --check DIR|FILE  # verify hash vectors
    canonical_json.py --fill DIR|FILE   # (maintainers) rewrite the canonical /
                                        # content_hash lines of vector files

Only the standard library is used for projection, serialization and hashing.
YAML input is decoded with PyYAML when it is installed; JSON input needs
nothing extra. The script canonicalizes *resolved* documents only: it does
not resolve `extends` (use `h2h resolve --format json` for that).

Known limits of this reference:
  * It trusts that the input is a valid HushSpec document. Unknown keys are
    reported as errors, but no other validation is performed.
  * YAML is decoded by PyYAML's SafeLoader (YAML 1.1 scalars). Documents
    that follow the HushSpec YAML profile (core spec 2.4) decode identically
    under YAML 1.1 and 1.2; documents that rely on `yes`/`no` booleans do
    not, and are rejected by conformant parsers anyway.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import sys
from decimal import Decimal
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = REPO_ROOT / "schemas"

CORE_SCHEMA = "hushspec-core.v0.schema.json"
EXTENSION_SCHEMAS = {
    "posture": "hushspec-posture.v0.schema.json",
    "origins": "hushspec-origins.v0.schema.json",
    "detection": "hushspec-detection.v0.schema.json",
}

# Fields consumed by resolution; never part of a resolved document.
RESOLUTION_FIELDS = ("extends", "merge_strategy")
# Reserved for an inline signature (spec/hushspec-signing.md section 7).
# Excluded from the canonical form so a signature never covers itself.
INLINE_SIGNATURE_FIELD = "signature"

# Fields whose *presence* changes meaning even when the value is empty
# (spec/hushspec-canonical.md section 3.3). Keyed by (schema file, $defs
# name, property). Everything else that is an empty container with no schema
# default is equivalent to absence and is omitted from the canonical form --
# the origins profile overlay lists included, because an absent overlay list
# and an empty one evaluate identically (origins spec section 4).
PRESERVE_EMPTY = {
    ("hushspec-origins.v0.schema.json", "OriginProfile", "match"),
}

SAFE_INTEGER_MAX = 2**53 - 1
HASH_PREFIX = "sha256:"

# JCS short escapes for the control characters that have them (RFC 8785 3.2.2.2).
_SHORT_ESCAPES = {
    chr(0x08): "\\b",
    chr(0x09): "\\t",
    chr(0x0A): "\\n",
    chr(0x0C): "\\f",
    chr(0x0D): "\\r",
    '"': '\\"',
    "\\": "\\\\",
}


class CanonicalError(ValueError):
    """The document cannot be canonicalized."""


# --------------------------------------------------------------------------- #
# Schema helpers
# --------------------------------------------------------------------------- #

_schema_cache: dict[str, dict] = {}


def load_schema(name: str) -> dict:
    if name not in _schema_cache:
        with open(SCHEMAS_DIR / name, encoding="utf-8") as fh:
            _schema_cache[name] = json.load(fh)
    return _schema_cache[name]


def resolve_ref(root: dict, node: dict) -> tuple[dict, str | None]:
    """Follow a local `#/$defs/...` reference, if any.

    Returns the target schema and the `$defs` name it was reached through
    (None for inline schemas).
    """
    ref = node.get("$ref")
    if ref is None:
        return node, None
    if not ref.startswith("#/$defs/"):
        raise CanonicalError(f"unsupported $ref {ref!r}")
    name = ref[len("#/$defs/"):]
    target = root["$defs"][name]
    resolved, inner = resolve_ref(root, target)
    return resolved, inner or name


# --------------------------------------------------------------------------- #
# Projection (spec/hushspec-canonical.md section 3)
# --------------------------------------------------------------------------- #


def _is_empty_container(value: object) -> bool:
    return isinstance(value, (list, dict)) and len(value) == 0


def _project_object(
    value: dict,
    schema: dict,
    root: dict,
    root_name: str,
    def_name: str | None,
    path: str,
    skip_defaults: tuple[str, ...] = (),
) -> dict:
    props: dict = schema.get("properties", {})
    required = set(schema.get("required", []))
    out: dict = {}
    for key in value:
        if key not in props:
            raise CanonicalError(f"unknown field {path}.{key}")
    for key, sub in props.items():
        if key in value:
            projected = _project_node(value[key], sub, root, root_name, f"{path}.{key}")
            # Section 3.3: a present-but-empty container for a field that has
            # no schema default and is not presence-significant is equivalent
            # to absence and is omitted.
            if (
                "default" not in sub
                and key not in required
                and _is_empty_container(projected)
                and (root_name, def_name, key) not in PRESERVE_EMPTY
            ):
                continue
            out[key] = projected
        elif "default" in sub and key not in skip_defaults:
            out[key] = copy.deepcopy(sub["default"])
    return out


def _project_node(value: object, schema: dict, root: dict, root_name: str, path: str) -> object:
    schema, def_name = resolve_ref(root, schema)
    if isinstance(value, dict) and "properties" in schema:
        return _project_object(value, schema, root, root_name, def_name, path)
    if isinstance(value, list) and schema.get("type") == "array":
        items = schema.get("items")
        if isinstance(items, dict):
            return [
                _project_node(item, items, root, root_name, f"{path}[{i}]")
                for i, item in enumerate(value)
            ]
        return list(value)
    if isinstance(value, dict) and isinstance(schema.get("additionalProperties"), dict):
        # Map-typed object (e.g. posture `states`): project every entry.
        sub = schema["additionalProperties"]
        return {k: _project_node(v, sub, root, root_name, f"{path}.{k}") for k, v in value.items()}
    # Scalars and free-form objects (e.g. `when.context`) pass through unchanged.
    return value


def project(document: dict) -> dict:
    """Return the canonical projection of a resolved HushSpec document."""
    if not isinstance(document, dict):
        raise CanonicalError("document must be a mapping")
    doc = copy.deepcopy(document)
    for field in RESOLUTION_FIELDS:
        doc.pop(field, None)
    meta = doc.get("metadata")
    if isinstance(meta, dict):
        meta.pop(INLINE_SIGNATURE_FIELD, None)

    core = load_schema(CORE_SCHEMA)
    extensions = doc.pop("extensions", None)
    out = _project_object(doc, core, core, CORE_SCHEMA, None, "$", skip_defaults=RESOLUTION_FIELDS)

    if isinstance(extensions, dict):
        projected_ext: dict = {}
        for name, block in extensions.items():
            if name not in EXTENSION_SCHEMAS:
                raise CanonicalError(f"unknown extension {name!r}")
            ext_root = load_schema(EXTENSION_SCHEMAS[name])
            projected_block = _project_node(
                block, ext_root, ext_root, EXTENSION_SCHEMAS[name], f"$.extensions.{name}"
            )
            if _is_empty_container(projected_block):
                continue
            projected_ext[name] = projected_block
        if projected_ext:
            out["extensions"] = projected_ext
    return out


# --------------------------------------------------------------------------- #
# RFC 8785 serialization (spec/hushspec-canonical.md section 4)
# --------------------------------------------------------------------------- #


def _utf16_key(key: str) -> bytes:
    return key.encode("utf-16-be")


def jcs_string(value: str) -> str:
    out = ['"']
    for ch in value:
        short = _SHORT_ESCAPES.get(ch)
        if short is not None:
            out.append(short)
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def es6_number(value: float) -> str:
    """Format a float exactly as ECMAScript Number::toString does."""
    if math.isnan(value) or math.isinf(value):
        raise CanonicalError("NaN and Infinity are not representable in JSON")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    dec = Decimal(repr(abs(value)))  # repr() is the shortest round-trip form
    tup = dec.as_tuple()
    digits = list(tup.digits)
    exponent = int(tup.exponent)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1
    k = len(digits)
    n = exponent + k  # value == 0.d1..dk x 10**n
    ds = "".join(str(d) for d in digits)
    if k <= n <= 21:
        body = ds + "0" * (n - k)
    elif 0 < n <= 21:
        body = ds[:n] + "." + ds[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + ds
    else:
        exp = n - 1
        exp_str = ("+" if exp >= 0 else "-") + str(abs(exp))
        body = (ds if k == 1 else ds[0] + "." + ds[1:]) + "e" + exp_str
    return sign + body


def jcs(value: object) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > SAFE_INTEGER_MAX:
            raise CanonicalError(f"integer {value} exceeds the safe range (2^53-1)")
        return str(value)
    if isinstance(value, float):
        if value.is_integer() and abs(value) <= SAFE_INTEGER_MAX:
            return str(int(value)) if value != 0 else "0"
        return es6_number(value)
    if isinstance(value, str):
        return jcs_string(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalError(f"object key {key!r} is not a string")
        parts = [
            jcs_string(key) + ":" + jcs(value[key]) for key in sorted(value, key=_utf16_key)
        ]
        return "{" + ",".join(parts) + "}"
    raise CanonicalError(f"unsupported value type {type(value).__name__}")


def content_hash(canonical: str) -> str:
    return HASH_PREFIX + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def canonicalize(document: dict) -> tuple[str, str]:
    """Return (canonical JSON, content hash) for a resolved document."""
    canonical = jcs(project(document))
    return canonical, content_hash(canonical)


# --------------------------------------------------------------------------- #
# Input handling
# --------------------------------------------------------------------------- #


_yaml_loader = None


def _yaml12_loader():
    """PyYAML SafeLoader with YAML 1.2 Core booleans.

    PyYAML implements YAML 1.1, where bare `yes`, `no`, `on`, and `off` are
    booleans. The HushSpec YAML profile (core spec 2.4) is YAML 1.2 Core, in
    which only true/false (any capitalization of the whole word) are booleans;
    the posture extension even uses `on` as a mapping key. This loader swaps
    the boolean resolver so both agree.
    """
    global _yaml_loader
    if _yaml_loader is not None:
        return _yaml_loader
    import re

    import yaml  # type: ignore[import-not-found]

    class Loader(yaml.SafeLoader):
        pass

    bool_tag = "tag:yaml.org,2002:bool"
    Loader.yaml_implicit_resolvers = {
        first: [(tag, rx) for tag, rx in resolvers if tag != bool_tag]
        for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }
    Loader.add_implicit_resolver(
        bool_tag, re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
    )
    _yaml_loader = Loader
    return Loader


def load_document(path: Path) -> object:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(
            "PyYAML is required to read YAML input; pass a .json document instead"
        ) from exc
    return yaml.load(text, Loader=_yaml12_loader())


# --------------------------------------------------------------------------- #
# Vectors (fixtures/core/hash)
# --------------------------------------------------------------------------- #

VECTOR_VERSION = "0.1.0"


def iter_vector_files(target: Path):
    if target.is_dir():
        yield from sorted(p for p in target.glob("*.yaml"))
    else:
        yield target


def check_vector(path: Path) -> list[str]:
    vector = load_document(path)
    if not isinstance(vector, dict) or vector.get("hushspec_hash_vector") != VECTOR_VERSION:
        return [f"{path}: not a hushspec_hash_vector {VECTOR_VERSION} file"]
    try:
        canonical, digest = canonicalize(vector["policy"])
    except (CanonicalError, KeyError) as exc:
        return [f"{path}: {exc}"]
    errors: list[str] = []
    if canonical != vector.get("canonical"):
        errors.append(
            f"{path}: canonical JSON mismatch; expected {vector.get('canonical')!r}, actual {canonical!r}"
        )
    if digest != vector.get("content_hash"):
        errors.append(
            f"{path}: content_hash mismatch; expected {vector.get('content_hash')}, actual {digest}"
        )
    return errors


def _yaml_double_quoted(value: str) -> str:
    """A YAML double-quoted scalar for `value`.

    JSON string syntax is a subset of YAML double-quoted syntax, so json.dumps
    does most of the work; characters YAML forbids even inside quotes (DEL and
    the C1 controls other than NEL) are additionally written as \\uXXXX.
    """
    text = json.dumps(value, ensure_ascii=False)
    return "".join(
        "\\u%04x" % ord(ch)
        if (0x7F <= ord(ch) <= 0x9F and ord(ch) != 0x85) or ord(ch) in (0xFFFE, 0xFFFF)
        else ch
        for ch in text
    )


def fill_vector(path: Path) -> None:
    """Rewrite the `canonical:` and `content_hash:` lines of a vector file."""
    vector = load_document(path)
    canonical, digest = canonicalize(vector["policy"])
    out = []
    for line in path.read_text(encoding="utf-8").split("\n"):
        if line.startswith("canonical:"):
            out.append("canonical: " + _yaml_double_quoted(canonical))
        elif line.startswith("content_hash:"):
            out.append(f'content_hash: "{digest}"')
        else:
            out.append(line)
    path.write_text("\n".join(out), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "target",
        type=Path,
        help="resolved policy (YAML/JSON), or a vector file/dir with --check/--fill",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="verify hash vectors")
    mode.add_argument(
        "--fill", action="store_true", help="rewrite vector expectations (maintainers only)"
    )
    parser.add_argument("--hash-only", action="store_true", help="print only the digest")
    args = parser.parse_args(argv)

    if args.check:
        errors: list[str] = []
        count = 0
        for path in iter_vector_files(args.target):
            count += 1
            errors.extend(check_vector(path))
        for err in errors:
            print(err, file=sys.stderr)
        if errors:
            print(f"{len(errors)} hash vector failure(s)")
            return 1
        print(f"{count}/{count} hash vectors OK")
        return 0

    if args.fill:
        for path in iter_vector_files(args.target):
            fill_vector(path)
            print(f"filled {path}")
        return 0

    document = load_document(args.target)
    try:
        canonical, digest = canonicalize(document)  # type: ignore[arg-type]
    except CanonicalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not args.hash_only:
        print(canonical)
    print(digest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
