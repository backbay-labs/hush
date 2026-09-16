#!/usr/bin/env python3
"""Build the machine-readable index of the published JSON Schemas.

Every schema declares an `$id` under `https://hushspec.dev/schemas/`, and the
docs deployment serves the directory at exactly those URLs. A consumer that
arrives at the host with no prior knowledge -- an editor extension, a catalog
crawler, someone reading the site -- needs one document that says what is
served and under which identifier, so `index.json` is published alongside the
schemas themselves.

The index is a deployment artifact, not a checked-in source: it is built from
`schemas/` at deploy time, so it can never name a schema the site is not also
serving.

Usage:
    python3 scripts/build_schema_index.py --out docs/book/schemas/index.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = ROOT / "schemas"

#: The host the schemas' own `$id` fields declare.
HOST = "https://hushspec.dev/schemas/"


def build() -> dict:
    entries = []
    for path in sorted(SCHEMAS_DIR.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        identifier = document.get("$id")
        expected = f"{HOST}{path.name}"
        if identifier != expected:
            raise SystemExit(
                f"{path.name} declares $id {identifier!r}, but it is served at "
                f"{expected!r}; the index would point at a URL nothing answers"
            )
        entry = {
            "file": path.name,
            "$id": identifier,
            "title": document.get("title", path.stem),
        }
        description = document.get("description")
        if description:
            entry["description"] = description
        entries.append(entry)

    if not entries:
        raise SystemExit(f"no schemas found in {SCHEMAS_DIR}")

    index = {
        "$comment": (
            "The JSON Schemas published at this host, each served at the $id "
            "its own document declares. Built from the schemas/ directory of "
            "github.com/backbay-labs/hush at deploy time."
        ),
        "host": HOST,
        "schemas": entries,
    }
    commit = os.environ.get("HUSHSPEC_COMMIT")
    if commit:
        index["commit"] = commit
    return index


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        required=True,
        help="path to write the index to; parent directories are created",
    )
    args = parser.parse_args(argv)

    index = build()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(index['schemas'])} schemas)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
