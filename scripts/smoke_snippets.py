#!/usr/bin/env python3
"""Execute marked README and guide snippets directly from markdown."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MARKDOWN_FILES = [
    ROOT / "README.md",
    ROOT / "docs" / "src" / "guides" / "getting-started.md",
]
POLICY_YAML = 'hushspec: "0.1.0"\nname: smoke-test\n'


@dataclass
class Snippet:
    id: str
    language: str
    code: str
    source: Path


def main() -> int:
    snippets = extract_snippets()
    for snippet_id in [
        "readme-rust",
        "readme-typescript",
        "readme-python",
        "readme-go",
        "guide-rust-parse",
        "guide-typescript-parse",
        "guide-rust-validate",
        "guide-typescript-validate",
    ]:
        snippet = snippets[snippet_id]
        print(f"[smoke] {snippet.id} ({snippet.language})")
        run_snippet(snippet)
    return 0


def extract_snippets() -> dict[str, Snippet]:
    pattern = re.compile(
        r"<!--\s*smoke:\s*([a-z0-9-]+)\s*-->\s*```([^\n]+)\n(.*?)```",
        re.DOTALL,
    )
    snippets: dict[str, Snippet] = {}

    for markdown_file in MARKDOWN_FILES:
        content = markdown_file.read_text()
        for match in pattern.finditer(content):
            snippet_id, language, code = match.groups()
            snippets[snippet_id] = Snippet(
                id=snippet_id,
                language=language.strip().split()[0],
                code=code.strip("\n"),
                source=markdown_file,
            )
    return snippets


def run_snippet(snippet: Snippet) -> None:
    if snippet.language == "rust":
        run_rust(snippet)
        return
    if snippet.language == "typescript":
        run_typescript(snippet)
        return
    if snippet.language == "python":
        run_python(snippet)
        return
    if snippet.language == "go":
        run_go(snippet)
        return
    raise ValueError(f"Unsupported snippet language: {snippet.language}")


def run_rust(snippet: Snippet) -> None:
    with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
        workdir = Path(temp_dir)
        (workdir / "src").mkdir()
        (workdir / "Cargo.toml").write_text(
            textwrap.dedent(
                f"""
                [package]
                name = "smoke-snippet"
                version = "0.1.0"
                edition = "2021"

                [dependencies]
                hushspec = {{ path = "{ROOT / 'crates' / 'hushspec'}" }}

                [workspace]
                """
            ).strip()
            + "\n"
        )
        (workdir / "src" / "main.rs").write_text(
            "fn main() -> Result<(), Box<dyn std::error::Error>> {\n"
            + indent(snippet.code)
            + "\n    Ok(())\n}\n"
        )
        maybe_write_policy_file(workdir, snippet)
        run(["cargo", "run", "--quiet"], cwd=workdir)


def run_typescript(snippet: Snippet) -> None:
    with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
        workdir = Path(temp_dir)
        maybe_write_policy_file(workdir, snippet)
        (workdir / "snippet.mjs").write_text(snippet.code + "\n")
        run(["node", "snippet.mjs"], cwd=workdir)


def run_python(snippet: Snippet) -> None:
    with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
        workdir = Path(temp_dir)
        maybe_write_policy_file(workdir, snippet)
        (workdir / "snippet.py").write_text(snippet.code + "\n")
        run(
            [sys.executable, "snippet.py"],
            cwd=workdir,
            extra_env={"PYTHONPATH": str(ROOT / "packages" / "python")},
        )


def run_go(snippet: Snippet) -> None:
    with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
        workdir = Path(temp_dir)
        maybe_write_policy_file(workdir, snippet)
        imports, body = split_go_imports(snippet.code)
        (workdir / "go.mod").write_text(
            textwrap.dedent(
                f"""
                module smoke-snippet

                go 1.22

                require github.com/backbay-labs/hush/packages/go v0.0.0

                replace github.com/backbay-labs/hush/packages/go => {ROOT / 'packages' / 'go'}
                """
            ).strip()
            + "\n"
        )
        (workdir / "main.go").write_text(
            "package main\n\n"
            + imports
            + "\n\nfunc main() {\n"
            + indent(body)
            + "\n}\n"
        )
        run(["go", "mod", "tidy"], cwd=workdir)
        run(["go", "run", "."], cwd=workdir)


def split_go_imports(code: str) -> tuple[str, str]:
    stripped = code.lstrip()
    if not stripped.startswith("import"):
        return "", code

    lines = code.splitlines()
    import_lines: list[str] = []
    body_lines: list[str] = []
    collecting_imports = True
    block_depth = 0
    for line in lines:
        if collecting_imports:
            import_lines.append(line)
            block_depth += line.count("(")
            block_depth -= line.count(")")
            if line.startswith("import ") and "(" not in line:
                collecting_imports = False
            elif block_depth == 0 and line.strip() == ")":
                collecting_imports = False
        else:
            body_lines.append(line)

    if body_lines and body_lines[0].strip() == "":
        body_lines = body_lines[1:]
    return "\n".join(import_lines), "\n".join(body_lines)


def maybe_write_policy_file(workdir: Path, snippet: Snippet) -> None:
    if snippet.id.startswith("guide-"):
        (workdir / "policy.yaml").write_text(POLICY_YAML)


def indent(code: str) -> str:
    return "\n".join(f"    {line}" if line else "" for line in code.splitlines())


def run(command: list[str], cwd: Path, extra_env: dict[str, str] | None = None) -> None:
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    subprocess.run(command, cwd=cwd, env=env, check=True)


if __name__ == "__main__":
    raise SystemExit(main())
