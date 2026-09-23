#!/usr/bin/env python3
"""Parse a HushSpec file with the Python SDK and print its own canonical form."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packages" / "python"))

from hushspec import canonical_json, parse_or_raise  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: normalize_python.py <path>", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    spec = parse_or_raise(path.read_text())
    # The document's own canonical form: ``extends`` and ``merge_strategy`` are
    # resolution instructions, not policy (canonical spec 3).
    print(canonical_json(replace(spec, extends=None, merge_strategy=None)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
