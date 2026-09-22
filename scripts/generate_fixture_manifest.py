#!/usr/bin/env python3
"""Generate `fixtures/MANIFEST.json`, the conformance corpus inventory.

The manifest is what makes a conformance run citable: it pins the exact bytes
of every vector a third-party implementation was tested against, so a report
(`schemas/hushspec-conformance-report.v1.schema.json`) can name the corpus by
`manifest_sha256` instead of "the fixtures directory, some time in September".

Every file under `fixtures/` is listed, except the manifest itself.

Each entry carries:

* `path`     -- repository-relative, POSIX separators, sorted
* `sha256`   -- lowercase hex digest of the file's exact bytes
* `category` -- what kind of vector it is (see CATEGORY_RULES)
* `module`   -- the spec module it belongs to (`core`, `posture`, ...)
* `level`    -- the conformance level (core spec 8) at which the vector
                becomes REQUIRED

Usage:
    python3 scripts/generate_fixture_manifest.py           # write
    python3 scripts/generate_fixture_manifest.py --check   # verify (CI)
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
MANIFEST = FIXTURES / "MANIFEST.json"
CORE_SPEC = ROOT / "spec" / "hushspec-core.md"

MANIFEST_VERSION = "0.1"

#: The manifest cannot list its own digest.
EXCLUDED_PATHS = ("fixtures/MANIFEST.json",)

#: The spec modules that carry document vectors: core plus the three
#: extension modules (core spec 9).
MODULES = "core|posture|origins|detection"

#: (regex over the repo-relative path, category, level). First match wins, so
#: the more specific patterns come first.
CATEGORY_RULES: list[tuple[re.Pattern[str], str, int]] = [
    (re.compile(r"^fixtures/(?:[^/]+/)*README\.md$"), "doc", 0),
    # Expected-error sidecars sit beside the invalid vector they describe.
    (re.compile(rf"^fixtures/(?:{MODULES})/invalid/.+\.expect\.yaml$"), "expect", 1),
    (re.compile(rf"^fixtures/(?:{MODULES})/valid/"), "valid", 1),
    (re.compile(rf"^fixtures/(?:{MODULES})/invalid/"), "invalid", 1),
    (re.compile(rf"^fixtures/(?:{MODULES})/merge/"), "merge", 2),
    # Resolution vectors assert the resolved content hash and the chain's
    # per-hop hashes, which is canonical-form territory: Level 4, not the
    # Level 2 ability to merge an extends chain at all.
    (re.compile(r"^fixtures/core/resolve/"), "resolve", 4),
    # Control-tagged suites for the vertical policy library:
    # evaluation vectors whose policy is a library builtin.
    (re.compile(r"^fixtures/library/.+\.test\.yaml$"), "library-suite", 3),
    (re.compile(rf"^fixtures/(?:{MODULES})/evaluation/"), "evaluation", 3),
    (re.compile(r"^fixtures/core/hash/"), "canonical", 4),
    # The raw source-string corpus exercises parser/value decoding. Its
    # optional evaluator and canonical assertions are reported separately by
    # the testkit at Levels 3 and 4.
    (re.compile(r"^fixtures/core/raw-yaml/"), "raw-yaml", 1),
    (re.compile(r"^fixtures/receipts/expected/"), "receipt-expected", 4),
    (re.compile(r"^fixtures/receipts/signed/"), "receipt-signed", 5),
    (re.compile(r"^fixtures/receipts/"), "receipt", 4),
    (re.compile(r"^fixtures/log/schema-vectors\.json$"), "log-schema", 5),
    (re.compile(r"^fixtures/log/"), "log", 5),
    (re.compile(r"^fixtures/signing/"), "signing", 5),
    (re.compile(r"^fixtures/bundle/"), "bundle", 5),
    # Framework action mapping is supplemental SDK integration evidence, not
    # a core-engine conformance requirement. It is inventoried but unscored.
    (re.compile(r"^fixtures/adapters/"), "integration", 0),
    # Evidence-report vectors: a synthetic log and the report
    # h2h report must produce from it; Level 4 material (receipts, canonical hashes).
    (re.compile(r"^fixtures/report/"), "report", 4),
]


def fixtures_version() -> str:
    """The spec version the corpus tracks, read from the core specification."""
    for line in CORE_SPEC.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\*\*Version:\*\*\s*(\d+\.\d+\.\d+)", line)
        if match:
            return match.group(1)
    raise SystemExit(f"cannot read a **Version:** line from {CORE_SPEC}")


def classify(relative: str) -> tuple[str, int]:
    for pattern, category, level in CATEGORY_RULES:
        if pattern.match(relative):
            return category, level
    raise SystemExit(
        f"{relative} matches no category rule; add one to "
        "scripts/generate_fixture_manifest.py so every fixture is classified"
    )


def module_of(relative: str) -> str:
    return relative.split("/")[1]


def iter_files() -> list[Path]:
    """Every file under fixtures/ that git tracks or would track.

    The index plus untracked files no ignore rule covers, so a build product
    or scratch file left in the tree cannot be hashed into the manifest.
    """
    result = subprocess.run(
        [
            "git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others",
            "--exclude-standard", "--", FIXTURES.relative_to(ROOT).as_posix(),
        ],
        check=True,
        capture_output=True,
    )
    kept = []
    for relative in sorted(set(result.stdout.decode("utf-8").split("\0"))):
        if not relative or relative in EXCLUDED_PATHS:
            continue
        path = ROOT / relative
        if path.is_file():
            kept.append(path)
    return kept


def build(generated_at: str) -> dict:
    entries = []
    for path in iter_files():
        relative = path.relative_to(ROOT).as_posix()
        category, level = classify(relative)
        entries.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "category": category,
                "module": module_of(relative),
                "level": level,
            }
        )
    return {
        "manifest_version": MANIFEST_VERSION,
        "fixtures_version": fixtures_version(),
        "generated_at": generated_at,
        "files": entries,
    }


def render(manifest: dict) -> str:
    return json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"


def without_timestamp(manifest: dict) -> dict:
    return {key: value for key, value in manifest.items() if key != "generated_at"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if fixtures/MANIFEST.json does not match the fixtures tree",
    )
    args = parser.parse_args()

    current: dict | None = None
    if MANIFEST.exists():
        current = json.loads(MANIFEST.read_text(encoding="utf-8"))

    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    fresh = build(now)

    if args.check:
        if current is None:
            print(f"{MANIFEST.relative_to(ROOT)} is missing", file=sys.stderr)
            return 1
        # `generated_at` is deliberately not compared: it records when the
        # manifest was written, not what it covers, and comparing it would
        # make every run fail.
        if without_timestamp(current) != without_timestamp(fresh):
            print(
                f"{MANIFEST.relative_to(ROOT)} is out of date -- rerun "
                "scripts/generate_fixture_manifest.py",
                file=sys.stderr,
            )
            _report_drift(current, fresh)
            return 1
        # The manifest is cited by its sha256, so its bytes are the artifact:
        # matching content is not enough if the formatting has drifted.
        expected = render({**fresh, "generated_at": current.get("generated_at", now)})
        if MANIFEST.read_text(encoding="utf-8") != expected:
            print(
                f"{MANIFEST.relative_to(ROOT)} is not canonically formatted -- rerun "
                "scripts/generate_fixture_manifest.py",
                file=sys.stderr,
            )
            return 1
        return 0

    # Keep the recorded timestamp when nothing else changed, so regenerating
    # after an unrelated edit does not produce a diff.
    if current is not None and without_timestamp(current) == without_timestamp(fresh):
        fresh["generated_at"] = current.get("generated_at", now)

    MANIFEST.write_text(render(fresh), encoding="utf-8", newline="\n")
    return 0


def _report_drift(current: dict, fresh: dict) -> None:
    before = {entry["path"]: entry for entry in current.get("files", [])}
    after = {entry["path"]: entry for entry in fresh["files"]}
    for path in sorted(set(after) - set(before)):
        print(f"  + {path}", file=sys.stderr)
    for path in sorted(set(before) - set(after)):
        print(f"  - {path}", file=sys.stderr)
    for path in sorted(set(before) & set(after)):
        if before[path] != after[path]:
            print(f"  ~ {path}", file=sys.stderr)
    for key in ("manifest_version", "fixtures_version"):
        if current.get(key) != fresh.get(key):
            print(
                f"  ~ {key}: {current.get(key)!r} -> {fresh.get(key)!r}",
                file=sys.stderr,
            )


if __name__ == "__main__":
    raise SystemExit(main())
