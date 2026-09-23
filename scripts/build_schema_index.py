#!/usr/bin/env python3
"""Build the machine-readable index of the published JSON Schemas.

Current schemas declare an `$id` under `https://hushspec.org/schemas/`.
Frozen v0 schemas retain their original identifiers and are mirrored there.
A consumer that arrives with no prior knowledge -- an editor extension, a catalog
crawler, someone reading the site -- needs one document that says what is
served and under which identifier, so `index.json` is published alongside the
schemas themselves.

The index is built from the source directory. Website exports require clean,
committed inputs and include byte digests and the source commit.

Usage:
    python3 scripts/build_schema_index.py --out docs/book/schemas/index.json
    python3 scripts/build_schema_index.py --site-root ../hush-ui/public
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = ROOT / "schemas"

#: Retrieval host; only the current lineage also declares this host in its ID.
HOST = "https://hushspec.org/schemas/"
LEGACY_HOST = "https://hushspec.dev/schemas/"


def build(commit: str | None = None, sources: dict[Path, bytes] | None = None) -> dict:
    entries = []
    for path in sorted(SCHEMAS_DIR.glob("*.json")):
        if path.name == "frozen-v0.json":
            continue
        raw = sources[path] if sources is not None else path.read_bytes()
        document = json.loads(raw)
        identifier = document.get("$id")
        identifier_host = HOST if path.name.endswith(".v1.schema.json") else LEGACY_HOST
        expected = f"{identifier_host}{path.name}"
        if identifier != expected:
            raise SystemExit(
                f"{path.name} declares $id {identifier!r}, expected {expected!r}"
            )
        entry = {
            "file": path.name,
            "$id": identifier,
            "url": f"{HOST}{path.name}",
            "sha256": hashlib.sha256(raw).hexdigest(),
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
            "Schema retrieval URLs and byte digests. V1 is served at its $id; "
            "v0 retains its legacy $id and is mirrored at url. Built from "
            "github.com/backbay-labs/hush; commit identifies the source."
        ),
        "host": HOST,
        "schemas": entries,
        "registries": [
            {"file": path.name, "url": f"https://hushspec.org/registries/{path.name}",
             "sha256": hashlib.sha256(sources[path] if sources is not None else path.read_bytes()).hexdigest()}
            for path in sorted((ROOT / "spec/registries").glob("*.yaml"))
        ],
    }
    commit = commit or os.environ.get("HUSHSPEC_COMMIT")
    if commit:
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise SystemExit("source commit must be a full Git SHA")
        index["commit"] = commit
    return index


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument(
        "--out",
        help="path to write the index to; parent directories are created",
    )
    output.add_argument("--site-root", help="export committed schemas and registries to a static site's public directory")
    args = parser.parse_args(argv)

    if args.site_root:
        changed = subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=all", "--", "schemas",
             "spec/registries", "scripts/build_schema_index.py"], cwd=ROOT, text=True,
        )
        if changed:
            raise SystemExit("refusing to export uncommitted schema publication inputs")
        tracked = set(subprocess.check_output(
            ["git", "ls-files", "--", "schemas", "spec/registries"], cwd=ROOT, text=True,
        ).splitlines())
        for path in [*SCHEMAS_DIR.glob("*.json"), *(ROOT / "spec/registries").glob("*.yaml")]:
            if path.is_symlink() or path.relative_to(ROOT).as_posix() not in tracked:
                raise SystemExit("refusing to export uncommitted or symlinked schema publication inputs")
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        # A clean checkout may have line-ending or filter conversions. Publish
        # the pinned Git blobs, not those transformed working-tree bytes.
        sources = {
            path: subprocess.check_output(
                ["git", "show", f"{commit}:{path.relative_to(ROOT).as_posix()}"], cwd=ROOT,
            )
            for path in [*SCHEMAS_DIR.glob("*.json"), *(ROOT / "spec/registries").glob("*.yaml")]
        }
        index = build(commit, sources)
        site = Path(args.site_root)
        for category, source in (("schemas", SCHEMAS_DIR), ("registries", ROOT / "spec/registries")):
            destination = site / category
            destination.mkdir(parents=True, exist_ok=True)
            for entry in index[category]:
                (destination / entry["file"]).write_bytes(sources[source / entry["file"]])
        out = site / "schemas/index.json"
    else:
        index = build()
        out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(index['schemas'])} schemas)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
