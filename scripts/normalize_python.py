#!/usr/bin/env python3
"""Parse a HushSpec file with the Python SDK and emit normalized JSON."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packages" / "python"))

from hushspec import parse_or_raise  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: normalize_python.py <path>", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    spec = parse_or_raise(path.read_text())
    print(json.dumps(spec.to_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
