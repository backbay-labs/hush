"""Unit tests for the canonical projection and RFC 8785 serializer.

The normative vectors live in ``test_canonical_vectors.py``. These cover the
rules the 13 vectors cannot pin down on their own: ES6 exponent formatting,
UTF-16 key order where it actually differs from code-point order, and the
errors that keep an unresolved or unknown-field document from being hashed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import hushspec.canonical as canonical
from hushspec import CanonicalError, canonical_json, content_hash
from hushspec.canonical import _ArrayOf, _MapOf, _Obj
from hushspec.schema import HushSpec

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMAS_DIR = REPO_ROOT / "schemas"


def _hash_of(policy: dict) -> str:
    return content_hash(policy)


def _numbers(**patch_integrity: Any) -> str:
    """Canonical text of a document whose only numbers are the given ones."""
    return canonical_json(
        {"hushspec": "0.1.0", "rules": {"patch_integrity": patch_integrity}}
    )


# --------------------------------------------------------------------------- #
# Section 4.3 -- ECMAScript Number::toString
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (10.0, "10"),
        (-0.0, "0"),
        (0.0, "0"),
        (0.35, "0.35"),
        (1e16, "10000000000000000"),
        (1e20, "100000000000000000000"),
        # ES6 switches to exponent notation at 1e21 and below 1e-6; Python's
        # repr switches at different thresholds and pads the exponent ("1e+21"
        # is a coincidence, "1e-07" is not).
        (1e21, "1e+21"),
        (1.5e22, "1.5e+22"),
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (2.5e-8, "2.5e-8"),
        (-1e-7, "-1e-7"),
        (0.000001234, "0.000001234"),
    ],
)
def test_es6_number_formatting(value: float, expected: str) -> None:
    text = _numbers(max_imbalance_ratio=value)
    assert f'"max_imbalance_ratio":{expected},' in text, text


def test_integer_and_whole_float_are_indistinguishable() -> None:
    assert _hash_of(
        {"hushspec": "0.1.0", "rules": {"patch_integrity": {"max_additions": 10}}}
    ) == _hash_of(
        {"hushspec": "0.1.0", "rules": {"patch_integrity": {"max_additions": 10.0}}}
    )


def test_unsafe_integer_is_refused() -> None:
    with pytest.raises(CanonicalError, match="safe range"):
        _numbers(max_additions=2**53)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nan_and_infinity_are_refused(value: float) -> None:
    with pytest.raises(CanonicalError, match="not representable"):
        _numbers(max_imbalance_ratio=value)


# --------------------------------------------------------------------------- #
# Section 4.1 -- UTF-16 key order
# --------------------------------------------------------------------------- #


def test_keys_sort_by_utf16_code_unit_not_code_point() -> None:
    # U+FFFD is one UTF-16 unit (FFFD); U+1F600 is the pair D83D DE00. By code
    # point U+FFFD comes first; by UTF-16 code unit the astral character does,
    # because D83D < FFFD. Only the free-form `when.context` map can carry
    # arbitrary keys, so the discrimination happens there.
    text = canonical_json(
        {
            "hushspec": "0.1.0",
            "rules": {"egress": {"when": {"context": {"\ufffd": 1, "\U0001f600": 2}}}},
        }
    )
    assert '"context":{"\U0001f600":2,"\ufffd":1}' in text, text
    assert sorted(["\ufffd", "\U0001f600"]) == ["\ufffd", "\U0001f600"], (
        "Python's default string order is code-point order"
    )


# --------------------------------------------------------------------------- #
# Section 4.2 -- string escaping
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ('quote"', '"quote\\""'),
        ("back\\slash", '"back\\\\slash"'),
        ("\b\t\n\f\r", '"\\b\\t\\n\\f\\r"'),
        ("\x00\x01\x1f", '"\\u0000\\u0001\\u001f"'),
        ("\x7f", '"\x7f"'),  # DEL is not escaped
        ("\u00a0", '"\u00a0"'),  # NBSP is not escaped
        ("\u2028\u2029", '"\u2028\u2029"'),  # line/paragraph separators stay literal
        ("\U0001f600", '"\U0001f600"'),  # astral characters stay literal
        ("a/b", '"a/b"'),  # solidus is never escaped
    ],
)
def test_jcs_string_escaping(value: str, expected: str) -> None:
    text = canonical_json({"hushspec": "0.1.0", "name": value})
    assert f'"name":{expected}' in text, text


def test_canonical_form_is_utf8_with_no_bom_or_newline() -> None:
    text = canonical_json({"hushspec": "0.1.0", "name": "é"})
    assert not text.endswith("\n")
    assert text.encode("utf-8")[:3] != b"\xef\xbb\xbf"
    assert json.loads(text)["name"] == "é"


# --------------------------------------------------------------------------- #
# Section 3 -- projection
# --------------------------------------------------------------------------- #


def test_unresolved_document_is_refused() -> None:
    with pytest.raises(CanonicalError, match="unresolved"):
        canonical_json({"hushspec": "0.1.0", "extends": "builtin:default"})


def test_merge_strategy_is_never_emitted() -> None:
    assert canonical_json({"hushspec": "0.1.0", "merge_strategy": "replace"}) == (
        '{"hushspec":"0.1.0"}'
    )


def test_inline_signature_is_stripped() -> None:
    with_signature = {
        "hushspec": "0.1.0",
        "metadata": {"author": "a@example.com", "signature": {"key_id": "k", "sig": "s"}},
    }
    without = {"hushspec": "0.1.0", "metadata": {"author": "a@example.com"}}
    assert canonical_json(with_signature) == canonical_json(without)


def test_unknown_field_is_refused() -> None:
    with pytest.raises(CanonicalError, match=r"unknown field \$\.rules\.egress\.nope"):
        canonical_json({"hushspec": "0.1.0", "rules": {"egress": {"nope": 1}}})


def test_unknown_extension_is_refused() -> None:
    with pytest.raises(CanonicalError, match="unknown extension"):
        canonical_json({"hushspec": "0.1.0", "extensions": {"nope": {}}})


def test_absent_rule_block_is_not_invented() -> None:
    assert canonical_json({"hushspec": "0.1.0", "rules": {}}) == '{"hushspec":"0.1.0"}'


def test_origins_overlay_empties_are_presence_significant() -> None:
    written_empty = {
        "hushspec": "0.1.0",
        "extensions": {
            "origins": {"profiles": [{"id": "p", "match": {}, "egress": {"allow": []}}]}
        },
    }
    absent = {
        "hushspec": "0.1.0",
        "extensions": {"origins": {"profiles": [{"id": "p", "match": {}, "egress": {}}]}},
    }
    assert '"egress":{"allow":[]}' in canonical_json(written_empty)
    assert canonical_json(written_empty) != canonical_json(absent)


def test_parsed_model_and_raw_mapping_agree() -> None:
    raw = {
        "hushspec": "0.1.0",
        "name": "typed",
        "rules": {"egress": {"allow": ["api.example.com"]}},
    }
    assert content_hash(HushSpec.from_dict(raw)) == content_hash(raw)


def test_non_document_input_is_refused() -> None:
    with pytest.raises(CanonicalError, match="expected a resolved HushSpec"):
        canonical_json("hushspec: 0.1.0")


# --------------------------------------------------------------------------- #
# The embedded projection schema must stay in step with schemas/
# --------------------------------------------------------------------------- #


def _resolve_ref(root: dict, node: dict) -> dict:
    ref = node.get("$ref")
    if ref is None:
        return node
    assert ref.startswith("#/$defs/"), f"unsupported $ref {ref}"
    return _resolve_ref(root, root["$defs"][ref[len("#/$defs/") :]])


def _assert_in_step(schema: dict, root: dict, node: _Obj, label: str, seen: set) -> None:
    marker = (id(schema), id(node))
    if marker in seen:
        return
    seen.add(marker)

    props: dict = schema["properties"]
    assert set(props) == set(node.keys), f"{label}: key set drifted from the schema"
    declared = {key: sub["default"] for key, sub in props.items() if "default" in sub}
    # `merge_strategy` is the one schema default that is deliberately never
    # materialized (spec section 3.1).
    declared.pop("merge_strategy", None)
    assert declared == node.defaults, f"{label}: defaults drifted from the schema"
    assert set(schema.get("required", [])) == node.required, (
        f"{label}: required list drifted from the schema"
    )

    for key, sub in props.items():
        if label == "_CORE_ROOT" and key == "extensions":
            # Each extension block is projected against the root of its own
            # schema document, not against the core schema's opaque stand-in
            # (spec section 3.4); checked separately below.
            continue
        target = _resolve_ref(root, sub)
        child = node.children.get(key)
        items = _resolve_ref(root, target.get("items", {})) if target.get("items") else {}
        extra = target.get("additionalProperties")
        extra = _resolve_ref(root, extra) if isinstance(extra, dict) else None

        if "properties" in target:
            assert isinstance(child, _Obj), f"{label}.{key}: expected an object child"
            _assert_in_step(target, root, child, f"{label}.{key}", seen)
        elif "properties" in items:
            assert isinstance(child, _ArrayOf), f"{label}.{key}: expected an array child"
            _assert_in_step(items, root, child.item, f"{label}.{key}[]", seen)
        elif extra is not None and "properties" in extra:
            assert isinstance(child, _MapOf), f"{label}.{key}: expected a map child"
            _assert_in_step(extra, root, child.value, f"{label}.{key}{{}}", seen)
        else:
            assert child is None, f"{label}.{key}: unexpected child node"


@pytest.mark.parametrize(
    ("schema_name", "node_name"),
    [
        ("hushspec-core.v0.schema.json", "_CORE_ROOT"),
        ("hushspec-posture.v0.schema.json", "_POSTURE_ROOT"),
        ("hushspec-origins.v0.schema.json", "_ORIGINS_ROOT"),
        ("hushspec-detection.v0.schema.json", "_DETECTION_ROOT"),
    ],
)
def test_projection_schema_matches_published_schema(schema_name: str, node_name: str) -> None:
    """Fail loudly when ``schemas/`` gains a field the projection does not know.

    ``canonical.py`` embeds the projection rules so the installed package needs
    no schema files at runtime; this is the guard that keeps the embedded copy
    honest. Skipped outside a source checkout.
    """
    schema_path = SCHEMAS_DIR / schema_name
    if not schema_path.is_file():
        pytest.skip(f"{schema_path} is not available outside the repository")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    _assert_in_step(schema, schema, getattr(canonical, node_name), node_name, set())

    if node_name == "_CORE_ROOT":
        extensions = _resolve_ref(schema, schema["properties"]["extensions"])
        assert set(extensions["properties"]) == set(canonical._EXTENSION_ROOTS), (
            "the set of extension blocks drifted from the core schema"
        )
