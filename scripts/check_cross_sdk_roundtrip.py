#!/usr/bin/env python3
"""Compare normalized HushSpec outputs across Rust, TypeScript, Python, and Go."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packages" / "python"))

from hushspec import HushSpec  # noqa: E402


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
            normalized = canonicalize(run_sdk(sdk, path))
            if baseline is None:
                baseline = normalized
            elif normalized != baseline:
                raise SystemExit(
                    f"{path.relative_to(ROOT)} produced different normalized output in {sdk}"
                )

        with tempfile.TemporaryDirectory(prefix="hushspec-roundtrip-") as tmpdir:
            roundtrip_path = Path(tmpdir) / path.name
            roundtrip_path.write_text(yaml.safe_dump(baseline, sort_keys=False))
            for sdk in SDKS:
                normalized = canonicalize(run_sdk(sdk, roundtrip_path))
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
            continue
        for path in sorted(subdir.glob("*.yaml")):
            if path.name.startswith("child-") or path.name == "base.yaml":
                continue
            corpus.append(path)
    return corpus


def run_sdk(name: str, path: Path) -> dict:
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
    return json.loads(result.stdout)


def canonicalize(raw: dict) -> dict:
    return HushSpec.from_dict(raw).to_dict()


if __name__ == "__main__":
    raise SystemExit(main())
