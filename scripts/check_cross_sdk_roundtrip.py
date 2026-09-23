#!/usr/bin/env python3
"""Compare the canonical form of the shared corpus across Rust, TypeScript, Python and Go.

Each SDK parses every document and prints its own canonical form (canonical
spec 3); the four strings must be byte-identical. Nothing is projected through
a model on this side, so a key one SDK emits and another omits is a divergence.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


SDKS = {
    "rust": ["cargo", "run", "-q", "-p", "hushspec-testkit", "--bin", "hushspec-normalize", "--"],
    "typescript": ["node", str(ROOT / "scripts" / "normalize_ts.mjs")],
    "python": ["python3", str(ROOT / "scripts" / "normalize_python.py")],
    "go": ["go", "run", "./cmd/hushspec-normalize"],
}


def main() -> int:
    corpus = collect_corpus()
    checked = 0

    for path in corpus:
        baseline = None
        for sdk in SDKS:
            normalized = run_sdk(sdk, path)
            if baseline is None:
                baseline = normalized
            elif normalized != baseline:
                raise SystemExit(
                    f"{path.relative_to(ROOT)} produced different normalized output in {sdk}"
                )

        with tempfile.TemporaryDirectory(prefix="hushspec-roundtrip-") as tmpdir:
            roundtrip_path = Path(tmpdir) / path.name
            # JSON is a YAML 1.2 document with every string quoted, so the
            # round trip cannot depend on how a YAML 1.1 dumper spells a scalar
            # such as "-08", which the SDKs' YAML 1.2 parsers read as a number.
            roundtrip_path.write_text(baseline + "\n")
            for sdk in SDKS:
                normalized = run_sdk(sdk, roundtrip_path)
                if normalized != baseline:
                    raise SystemExit(
                        f"{path.relative_to(ROOT)} failed roundtrip equivalence in {sdk}"
                    )

        checked += 1

    print(f"cross-sdk roundtrip OK ({checked} documents, {len(SDKS)} SDKs)")
    return 0


def collect_corpus() -> list[Path]:
    corpus: list[Path] = []
    for subdir in [
        ROOT / "fixtures" / "core" / "valid",
        ROOT / "fixtures" / "posture" / "valid",
        ROOT / "fixtures" / "origins" / "valid",
        ROOT / "fixtures" / "detection" / "valid",
        ROOT / "fixtures" / "core" / "merge",
        ROOT / "fixtures" / "posture" / "merge",
        ROOT / "fixtures" / "origins" / "merge",
        ROOT / "fixtures" / "detection" / "merge",
    ]:
        if not subdir.exists():
            raise SystemExit(f"missing corpus directory {subdir.relative_to(ROOT)}")
        for path in sorted(subdir.glob("*.yaml")):
            if path.name.startswith("child-") or path.name == "base.yaml":
                continue
            corpus.append(path)
    if not corpus:
        raise SystemExit("the cross-SDK corpus is empty; nothing was compared")
    return corpus


def run_sdk(name: str, path: Path) -> str:
    cmd = SDKS[name] + [str(path)]
    kwargs = {
        "cwd": ROOT,
        "capture_output": True,
        "text": True,
        "check": True,
    }
    if name == "go":
        kwargs["cwd"] = ROOT / "packages" / "go"
    result = subprocess.run(cmd, **kwargs)
    return result.stdout.strip()


if __name__ == "__main__":
    raise SystemExit(main())
