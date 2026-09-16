"""The published JSON Schemas, checked against the shared policy vectors.

The schemas are the machine-readable half of the specification: an editor, a
CI job, or a SchemaStore consumer validates a policy with them and never sees
the SDKs at all. So they have to agree with the vectors on which documents are
HushSpec documents -- including inside `extensions`, where the core schema
composes each companion schema by `$ref` so that an unknown key is a rejection
rather than an annotation (core spec 2.1 and 9.5).
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
import yaml

from hushspec.parse import CoreSafeLoader

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMAS_ROOT = REPO_ROOT / "schemas"
FIXTURES_ROOT = REPO_ROOT / "fixtures"

FAMILIES = ("core", "posture", "origins", "detection")

#: (extensions key, embedded ``$defs`` name, published file name).
EMBEDDED_EXTENSIONS = (
    ("posture", "PostureExtension", "hushspec-posture.v1.schema.json"),
    ("origins", "OriginsExtension", "hushspec-origins.v1.schema.json"),
    ("detection", "DetectionExtension", "hushspec-detection.v1.schema.json"),
)

#: Vectors the YAML profile refuses before there is a document to validate.
#: Anchors and aliases, merge keys, duplicate keys and multi-document streams
#: are properties of the YAML *text* (core spec 2.4); a JSON Schema only ever
#: sees the loaded document, so this module makes no claim about them.
PROFILE_ONLY_VECTORS = frozenset(
    {
        "yaml-alias.yaml",
        "yaml-duplicate-key.yaml",
        "yaml-merge-key.yaml",
        "yaml-multi-doc.yaml",
    }
)

#: Vectors whose refusal no JSON Schema can express: referential integrity
#: between two members of a document, uniqueness by a field of a list entry, a
#: lookup in the IANA time zone database, the HushSpec regex profile, a
#: recursion depth bound, and which minor versions *this* engine implements --
#: the schema states the shape of a version (core spec 2.2, appendix A), while
#: acceptance is a property of the engine reading it (core spec 10.3). The
#: SDKs check them after parsing. They are asserted to *pass* below, so a
#: schema change that does become able to express one fails this module until
#: the name is removed.
BEYOND_SCHEMA_VECTORS = frozenset(
    {
        "bad-initial.yaml",
        "duplicate-ids.yaml",
        "duplicate-pattern-names.yaml",
        "regex-mid-pattern-flag.yaml",
        "version-unsupported-minor.yaml",
        "when-bad-timezone.yaml",
        "when-too-deep.yaml",
    }
)


def load_schema(file_name: str) -> dict:
    return json.loads((SCHEMAS_ROOT / file_name).read_text())


def core_validator() -> jsonschema.protocols.Validator:
    schema = load_schema("hushspec-core.v1.schema.json")
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema, format_checker=cls.FORMAT_CHECKER)


def policy_vectors(kind: str) -> list[Path]:
    paths: list[Path] = []
    for family in FAMILIES:
        directory = FIXTURES_ROOT / family / kind
        paths.extend(
            sorted(
                path
                for path in directory.iterdir()
                if path.suffix == ".yaml" and not path.name.endswith(".expect.yaml")
            )
        )
    return paths


def load_document(path: Path) -> object:
    return yaml.load(path.read_text(), Loader=CoreSafeLoader)


def test_core_schema_embeds_the_companion_schemas_verbatim():
    """The composition resolves offline, from copies that have not drifted.

    The core schema is a compound schema document: each ``extensions`` key
    references its companion schema by that schema's own ``$id``, and the
    companion documents are carried verbatim in ``$defs`` so the references
    resolve with no network access.
    """
    core = load_schema("hushspec-core.v1.schema.json")
    extensions = core["$defs"]["Extensions"]

    for key, def_name, file_name in EMBEDDED_EXTENSIONS:
        published = load_schema(file_name)
        expected_id = f"https://hushspec.dev/schemas/{file_name}"

        assert extensions["properties"][key]["$ref"] == expected_id
        assert extensions["properties"][key]["unevaluatedProperties"] is False
        assert published["$id"] == expected_id
        assert core["$defs"][def_name] == published, (
            f"$defs/{def_name} has drifted from schemas/{file_name}; "
            "copy the published file back over it"
        )

    assert set(extensions["properties"]) == {key for key, _, _ in EMBEDDED_EXTENSIONS}


@pytest.mark.parametrize(
    "path", policy_vectors("valid"), ids=lambda path: f"{path.parent.parent.name}/{path.name}"
)
def test_valid_vectors_satisfy_the_core_schema(path: Path):
    errors = list(core_validator().iter_errors(load_document(path)))
    assert not errors, [error.message for error in errors]


@pytest.mark.parametrize(
    "path", policy_vectors("invalid"), ids=lambda path: f"{path.parent.parent.name}/{path.name}"
)
def test_invalid_vectors_are_refused_by_the_core_schema(path: Path):
    if path.name in PROFILE_ONLY_VECTORS:
        pytest.skip("refused by the YAML profile, before a document exists")

    valid = core_validator().is_valid(load_document(path))
    if path.name in BEYOND_SCHEMA_VECTORS:
        assert valid, (
            f"{path.name} is listed as beyond JSON Schema but the schema now "
            "refuses it; drop it from BEYOND_SCHEMA_VECTORS"
        )
    else:
        assert not valid, f"{path.name} must be refused by the schema"


def test_listed_vector_names_are_still_published():
    names = {path.name for path in policy_vectors("invalid")}
    assert PROFILE_ONLY_VECTORS <= names
    assert BEYOND_SCHEMA_VECTORS <= names


@pytest.mark.parametrize("key", [key for key, _, _ in EMBEDDED_EXTENSIONS])
def test_unknown_key_inside_an_extension_block_is_refused(key: str):
    document = {"hushspec": "0.1.0", "extensions": {key: {"bogus": 1}}}
    assert not core_validator().is_valid(document)
