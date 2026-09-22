"""Pieces the code generators under `scripts/` share.

Every SDK embeds the same built-in policies, and every generated Rust source is
committed as rustfmt output, so the list of built-ins and the rustfmt call live
here rather than in each generator.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RULESETS_DIR = ROOT / "rulesets"
LIBRARY_DIR = ROOT / "library"

#: The `rulesets/` presets, in the order every SDK lists them.
BUILTIN_NAMES = [
    "default",
    "strict",
    "permissive",
    "ai-agent",
    "cicd",
    "remote-desktop",
]

#: Embedded alongside the built-ins but not a built-in name: `extends:
#: builtin:panic` does not resolve; the panic policy is reachable only through
#: the emergency kill switch (core spec 6.2).
PANIC_NAME = "panic"


def library_names() -> list[str]:
    """Every vertical-library policy, as `library/<vertical>/<name>`.

    The library ships as built-ins alongside `rulesets/` so that
    `extends: "builtin:library/healthcare/hipaa-base"` resolves with no file
    system, in every SDK. Discovered rather than listed, so adding a policy to
    `library/` is one commit; the `library/` prefix keeps the existing
    `rulesets/` names unchanged.
    """
    return sorted(
        f"library/{path.parent.name}/{path.stem}"
        for path in LIBRARY_DIR.glob("*/*.yaml")
    )


def all_builtin_names() -> list[str]:
    """`rulesets/` first, then the library."""
    return BUILTIN_NAMES + library_names()


def builtin_yaml(name: str) -> str:
    """The canonical YAML for a built-in name, or for `PANIC_NAME`."""
    if name.startswith("library/"):
        return (ROOT / f"{name}.yaml").read_text()
    return (RULESETS_DIR / f"{name}.yaml").read_text()


def rustfmt(content: str) -> str:
    """`content` formatted by rustfmt, the form every generated Rust file is
    committed in.

    Generating without rustfmt would write a file that `cargo fmt` immediately
    reformats and the generator's `--check` then reports as out of date, so a
    missing binary or a formatting failure ends the run with the reason.
    """
    binary = shutil.which("rustfmt")
    if binary is None:
        raise SystemExit(
            "rustfmt is not on PATH; install it with `rustup component add rustfmt`"
        )
    result = subprocess.run(
        [binary, "--emit", "stdout", "--edition", "2024"],
        input=content,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"rustfmt failed (exit {result.returncode}):\n{result.stderr.strip()}"
        )
    return result.stdout
