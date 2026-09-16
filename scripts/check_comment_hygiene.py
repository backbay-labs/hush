#!/usr/bin/env python3
"""Fail the build when source text cites how the repo was written.

Comments, docstrings and fixture descriptions are read by people who only ever
see the published repository. They have no planning document to resolve `D12`
or `RFC 09 P3-03` against, no roster to tell them which "other agent" owned a
port, and no reason to care which implementation a behavior was mirrored from.
Such references are noise at best and misleading at worst -- a reader cannot
tell whether "staged in Wave 4" describes today's behavior or last month's.

The rule is simple: describe the behavior and cite the normative section.

    D7 (core 3.14.3): explicit ASCII classes behave identically
    ->  Explicit ASCII classes behave identically in every engine
        (core spec 3.14.3)

PATTERNS below is the enforced list. Anything it matches in a scanned file is
reported as `path:line: pattern: text` and fails the run. Genuine exceptions go
in scripts/comment-hygiene-allow.txt, one `path:pattern` per line, so every
exemption is visible in one place rather than buried in a regex.

Usage:
    python3 scripts/check_comment_hygiene.py           # check (the default)
    python3 scripts/check_comment_hygiene.py --check   # same thing, explicit
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST = ROOT / "scripts" / "comment-hygiene-allow.txt"

#: Everything the check reads. Directories are scanned recursively; the loose
#: files are the top-level text that ships with a release.
SCAN_ROOTS = (
    ".github",
    "crates",
    "packages",
    "scripts",
    "fixtures",
    "library",
    "rulesets",
    "spec",
    "docs/src",
    "README.md",
    "CHANGELOG.md",
    "action.yml",
    "Dockerfile",
)

#: Planning prose lives here on purpose; it is not published as reference text.
EXCLUDED_PREFIXES = ("docs/plans/",)

#: Machine-written sources are rewritten wholesale by their generator, so a hit
#: in one has to be fixed in the generator, not the output.
EXCLUDED_BASENAME_PREFIXES = ("generated_",)

#: Lockfiles and vendored third-party schemas are not ours to edit. The
#: allowlist is a list of pattern sources by construction, so scanning it would
#: flag the file for every exemption anyone records in it.
EXCLUDED_PATHS = (
    "Cargo.lock",
    "package-lock.json",
    "packages/go/go.sum",
    "crates/hushspec-cli/schemas/sarif-2.1.0.schema.json",
    "scripts/comment-hygiene-allow.txt",
)
EXCLUDED_SUFFIXES = (".lock", ".sum")

#: (regex source, case-sensitive). The source string is what the report prints
#: and what an allowlist entry names, so it is also the stable identifier for
#: each rule -- edit one and its allowlist entries must be updated too.
#:
#: `P3-03` stays case-sensitive: lowercased, `p3-03` collides with ordinary
#: identifiers and version strings. Everything else is prose, where case
#: carries no signal.
PATTERNS: tuple[tuple[str, bool], ...] = (
    # Planning-document identifiers. The trailing boundary on the RFC rule is
    # what keeps it off real IETF citations: the receipt spec cites RFC 9562
    # for UUIDv7, and that is not a planning reference.
    (r"RFC[- ]0?9\b", False),
    (r"\bP[0-6]-[0-9]{2}\b", True),
    (r"\bwave[- ][0-6]\b", False),
    (r"\(D[12]?[0-9]\)", True),
    (r"\bD[12]?[0-9]\b", False),
    # How the work was divided up.
    (r"another agent", False),
    (r"other agents?", False),
    (r"port agents?", False),
    (r"the brief", False),
    (r"as instructed", False),
    (r"this task", False),
    (r"work package", False),
    (r"the fork", False),
    (r"concurrent(ly)? (agent|edit)", False),
    (r"\bsubagents?\b", False),
    # Review-thread vocabulary and task markers. Source text describes what
    # the code does, not the conversation that produced it; a task marker is a
    # note to a future editor that belongs in an issue.
    (r"\bCodex\b", True),
    (r"review (comment|finding|thread)s?", False),
    (r"\bFinding [A-F0-9]\b", True),
    (r"\b(FIXME|HACK)\b", True),
    # One implementation described as the source of truth for another. Every
    # SDK implements the same specification; none of them defines it.
    (r"Rust reference", False),
    (r"the oracle", False),
    (r"matching Rust", False),
    (r"mirror(s|ing)? Rust", False),
    # Authoring-tool attribution. The bare word `Claude` cannot be the rule:
    # HushSpec ships a Claude/Anthropic tool-use adapter, so
    # `mapClaudeToolToAction` and the Claude Code hook are product surface that
    # the docs have to name. The forms below only ever arrive from a commit
    # trailer or a generated footer leaking into source text.
    (r"Co-Authored", False),
    (r"Claude-Session", False),
    (r"Generated with \[?Claude", False),
    (r"claude\.(ai|com)/(code|claude-code)", False),
)


def compiled() -> list[tuple[str, re.Pattern[str]]]:
    return [
        (source, re.compile(source, 0 if sensitive else re.IGNORECASE))
        for source, sensitive in PATTERNS
    ]


def tracked_files() -> list[str]:
    """Every tracked path under SCAN_ROOTS, repo-relative with / separators."""
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z", "--", *SCAN_ROOTS],
        check=True,
        capture_output=True,
    )
    return sorted(
        path for path in result.stdout.decode("utf-8").split("\0") if path
    )


def is_scanned(relative: str) -> bool:
    if relative.startswith(EXCLUDED_PREFIXES):
        return False
    if relative in EXCLUDED_PATHS or relative.endswith(EXCLUDED_SUFFIXES):
        return False
    return not relative.rsplit("/", 1)[-1].startswith(EXCLUDED_BASENAME_PREFIXES)


def read_text(path: Path) -> list[str] | None:
    """The file's lines, or None when it is binary or not valid UTF-8."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return None


def load_allowlist() -> tuple[set[tuple[str, str]], list[str]]:
    """Parse `path:pattern` exemptions. `*` exempts a path from every rule."""
    if not ALLOWLIST.exists():
        return set(), []
    entries: set[tuple[str, str]] = set()
    errors: list[str] = []
    known = {source for source, _ in PATTERNS}
    for number, raw in enumerate(ALLOWLIST.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        path, separator, pattern = line.partition(":")
        if not separator or not path or not pattern:
            errors.append(
                f"{ALLOWLIST.relative_to(ROOT)}:{number}: expected `path:pattern`, got {raw!r}"
            )
            continue
        if pattern != "*" and pattern not in known:
            errors.append(
                f"{ALLOWLIST.relative_to(ROOT)}:{number}: {pattern!r} is not one of "
                "the patterns in scripts/check_comment_hygiene.py"
            )
            continue
        entries.add((path, pattern))
    return entries, errors


def scan() -> tuple[list[tuple[str, int, str, str]], set[tuple[str, str]]]:
    """Return every (path, line number, pattern, text) hit and the rules used."""
    rules = compiled()
    hits: list[tuple[str, int, str, str]] = []
    used: set[tuple[str, str]] = set()
    for relative in tracked_files():
        if not is_scanned(relative):
            continue
        lines = read_text(ROOT / relative)
        if lines is None:
            continue
        for number, text in enumerate(lines, 1):
            for source, pattern in rules:
                if pattern.search(text):
                    hits.append((relative, number, source, text.strip()))
                    used.add((relative, source))
    return hits, used


def summarize(hits: list[tuple[str, int, str, str]]) -> None:
    counts: dict[str, int] = {}
    for relative, _, _, _ in hits:
        counts[relative.split("/")[0]] = counts.get(relative.split("/")[0], 0) + 1
    for key in sorted(counts):
        print(f"  {key}: {counts[key]}", file=sys.stderr)
    print(f"  total: {len(hits)}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="report planning references and fail if any are found (the default)",
    )
    parser.parse_args()

    allowed, errors = load_allowlist()
    for error in errors:
        print(error, file=sys.stderr)

    hits, used = scan()
    reported = [
        hit
        for hit in hits
        if (hit[0], hit[2]) not in allowed and (hit[0], "*") not in allowed
    ]
    for relative, number, source, text in reported:
        print(f"{relative}:{number}: {source}: {text}")

    matched_paths = {path for path, _ in used}
    stale = sorted(
        (path, pattern)
        for path, pattern in allowed
        if (path not in matched_paths if pattern == "*" else (path, pattern) not in used)
    )
    for path, pattern in stale:
        errors.append(
            f"{ALLOWLIST.relative_to(ROOT)}: {path}:{pattern} no longer matches "
            "anything -- delete the entry"
        )
        print(errors[-1], file=sys.stderr)

    if reported:
        print(
            f"{len(reported)} planning reference(s) in published text:",
            file=sys.stderr,
        )
        summarize(reported)
        print(
            "Describe the behavior and cite the normative section instead; see "
            "scripts/check_comment_hygiene.py for the rule and the allowlist.",
            file=sys.stderr,
        )
    return 1 if reported or errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
