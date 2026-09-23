"""Check the real CLI build script after Git moves a branch without source edits."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


BUILD_SCRIPT = Path(__file__).resolve().parents[1] / "crates/hushspec-cli/build.rs"


class BuildProvenanceTests(unittest.TestCase):
    def check_branch_move(self, *, packed: bool, linked: bool):
        with tempfile.TemporaryDirectory(prefix="hush-build-provenance-") as temp:
            root = Path(temp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "src").mkdir()
            (repo / "Cargo.toml").write_text(
                '[package]\nname="provenance-probe"\nversion="0.0.0"\nedition="2024"\n'
            )
            (repo / "src/main.rs").write_text(
                'fn main() { println!("{}", env!("H2H_GIT_SHA")); }\n'
            )
            shutil.copyfile(BUILD_SCRIPT, repo / "build.rs")
            env = {**os.environ, "CARGO_TARGET_DIR": str(root / "target")}
            env.pop("H2H_GIT_SHA", None)

            def run(*args, cwd=repo):
                return subprocess.run(
                    args, cwd=cwd, env=env, check=True, text=True, capture_output=True
                ).stdout.strip()

            def commit(cwd):
                run("git", "-c", "user.name=Provenance Test",
                    "-c", "user.email=provenance-test@example.invalid",
                    "commit", "--allow-empty", "-qm", "fixture", cwd=cwd)

            run("git", "init", "-q", "-b", "main")
            run("git", "add", ".")
            commit(repo)
            checkout = repo
            if linked:
                checkout = root / "linked"
                run("git", "worktree", "add", "-q", "-b", "linked", str(checkout))
            if packed:
                run("git", "pack-refs", "--all", "--prune")
            old = run("git", "rev-parse", "--short", "HEAD", cwd=checkout)
            self.assertEqual(run("cargo", "run", "--offline", "--quiet", cwd=checkout), old)
            commit(checkout)
            new = run("git", "rev-parse", "--short", "HEAD", cwd=checkout)
            self.assertNotEqual(new, old)
            self.assertEqual(run("cargo", "run", "--offline", "--quiet", cwd=checkout), new)

    def test_loose_branch_move_refreshes_embedded_sha(self):
        self.check_branch_move(packed=False, linked=False)

    def test_packed_branch_move_refreshes_embedded_sha(self):
        self.check_branch_move(packed=True, linked=False)

    def test_linked_packed_branch_move_refreshes_embedded_sha(self):
        self.check_branch_move(packed=True, linked=True)


if __name__ == "__main__":
    unittest.main()
