#!/usr/bin/env python3
"""Generate hash-consistent log schema mutations using JSON Schema as oracle.

No SDK validator or hash helper supplies the expected result. The seeds contain
only ASCII and small integers, whose sorted compact JSON is also their JCS form.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/hushspec-log-entry.v1.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
assert "date-time" in VALIDATOR.format_checker.checkers, "install jsonschema[format]"
HASH = "sha256:" + "0" * 64
STAMP = "2026-09-15T12:00:00.000Z"


def resolve(schema):
    return SCHEMA["$defs"][schema["$ref"].split("/")[-1]] if "$ref" in schema else schema


def sample(schema):
    schema = resolve(schema)
    if "const" in schema:
        return schema["const"]
    if "enum" in schema:
        return schema["enum"][0]
    if schema.get("format") == "date-time":
        return STAMP
    if "pattern" in schema:
        pattern = schema["pattern"]
        return HASH if "sha256" in pattern else "A" * 86 if "86" in pattern else "1.0.0"
    kind = schema.get("type")
    if kind == "object":
        return {key: sample(value) for key, value in schema.get("properties", {}).items()}
    if kind == "array":
        return [sample(schema["items"])]
    return {"string": "value", "integer": schema.get("minimum", 0), "boolean": True}[kind]


def mutations(value, schema, path=()):
    schema = resolve(schema)
    yield path, None, "null"
    yield path, [] if schema["type"] != "array" else {}, "wrong-type"
    if "enum" in schema or "const" in schema or "pattern" in schema:
        yield path, "invalid", "value"
    if schema.get("format") == "date-time":
        for suffix, stamp in [("calendar", "2026-02-30T00:00:00.000Z"),
                              ("precision", "2026-09-15T12:00:00Z"),
                              ("timezone", "2026-09-15T12:00:00.000+00:00"),
                              ("suffix", STAMP + "x")]:
            yield path, stamp, suffix
    if "minLength" in schema:
        yield path, "", "empty"
    if "minimum" in schema:
        yield path, schema["minimum"] - 1, "minimum"
        yield path, 0.5, "fraction"
        yield path, True, "boolean"
    if schema["type"] == "object":
        if schema.get("additionalProperties") is False:
            yield path + ("unknown",), True, "unknown"
        for key in schema.get("required", []):
            yield path + (key,), None, "missing"
        for key, child in schema.get("properties", {}).items():
            if key in value:
                yield from mutations(value[key], child, path + (key,))
    elif schema["type"] == "array":
        for index, item in enumerate(value):
            yield from mutations(item, schema["items"], path + (index,))


def seal(entry):
    unsigned = {k: v for k, v in entry.items() if k not in ("entry_hash", "signature")}
    entry["entry_hash"] = "sha256:" + hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    signature = entry.get("signature")
    if isinstance(signature, dict) and signature.get("content_hash") == HASH:
        signature["content_hash"] = entry["entry_hash"]


def generate():
    cases = []
    receipt = json.loads((ROOT / "fixtures/log/valid/basic.jsonl").read_text().splitlines()[1])["receipt"]
    for family in ("policy_loaded", "policy_swapped", "log_started", "receipt"):
        seed = sample(SCHEMA)
        for payload in ("policy_event", "log_started", "receipt"):
            del seed[payload]
        seed["entry_type"] = family
        if family.startswith("policy_"):
            seed["policy_event"] = sample(SCHEMA["$defs"]["PolicyEvent"])
            seed["policy_event"]["event"] = "loaded" if family == "policy_loaded" else "swapped"
        elif family == "log_started":
            seed["log_started"] = sample(SCHEMA["$defs"]["LogStarted"])
        else:
            seed["receipt"] = receipt
        for path, value, constraint in [((), seed, "valid"), *mutations(seed, SCHEMA)]:
            # The entry hash itself cannot be malformed AND correctly recomputed.
            # Receipt internals have their own schema and conformance vectors.
            if not path and constraint != "valid" or path[:1] == ("entry_hash",):
                continue
            entry = copy.deepcopy(seed)
            if path:
                parent = entry
                for part in path[:-1]:
                    parent = parent[part]
                if constraint == "missing":
                    del parent[path[-1]]
                else:
                    parent[path[-1]] = value
            seal(entry)
            valid = VALIDATOR.is_valid(entry)
            assert valid == (constraint == "valid"), (family, path, constraint)
            cases.append({"id": family + ":" + ".".join(map(str, path)) + ":" + constraint,
                          "valid": valid, "entry": entry})
    return "[\n" + ",\n".join(json.dumps(case, separators=(",", ":"), ensure_ascii=True) for case in cases) + "\n]\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    destination = ROOT / "fixtures/log/schema-vectors.json"
    output = generate()
    if args.check:
        assert destination.read_text() == output, "regenerate log schema vectors"
    else:
        destination.write_text(output)
