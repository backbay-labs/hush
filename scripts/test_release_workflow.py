"""Exercise release candidate selection and version checks without publishing."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.load(
    (ROOT / ".github/workflows/release.yml").read_text(), Loader=yaml.BaseLoader
)
STEPS = WORKFLOW["jobs"]["candidate"]["steps"]


class PythonPublishSelectionTests(unittest.TestCase):
    def test_authentication_selection_fails_closed_without_leaking_credentials(self):
        workflow = yaml.load(
            (ROOT / ".github/workflows/publish.yml").read_text(), Loader=yaml.BaseLoader
        )
        selector = next((step for step in workflow["jobs"]["pypi"]["steps"]
                         if step.get("id") == "authentication"), None)
        self.assertIsNotNone(selector, "Python publication needs an explicit authentication selector")
        cases = [
            ("trusted", "false", "", "trusted"),
            ("token", "false", "fixture-not-a-credential", "token"),
            ("token", "false", "", None),
            ("trusted", "true", "", "dry-run"),
            ("token", "true", "", "dry-run"),
            ("unknown", "false", "fixture-not-a-credential", None),
            ("trusted", "invalid", "", None),
        ]
        for method, dry_run, credential, expected in cases:
            with self.subTest(method=method, dry_run=dry_run, expected=expected), tempfile.TemporaryDirectory() as temp:
                output = Path(temp) / "output"
                result = subprocess.run(
                    ["bash", "-e", "-o", "pipefail", "-c", selector["run"]],
                    env={**os.environ, "PYPI_AUTH": method, "DRY_RUN": dry_run,
                         "PYPI_TOKEN": credential, "GITHUB_OUTPUT": str(output)},
                    capture_output=True, text=True, check=False,
                )
                if expected is None:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(output.read_text(), f"method={expected}\n")
                if credential:
                    self.assertNotIn(credential, result.stdout + result.stderr)


class ReleaseCandidateTests(unittest.TestCase):
    def build_step(self, name, *, root, target, cross, extra_env=None):
        step = next(s for s in WORKFLOW["jobs"]["build"]["steps"] if s.get("name") == name)
        replacements = {
            "${{ matrix.target }}": target,
            "${{ matrix.cross }}": cross,
            "${{ runner.os }}": "Linux",
            "${{ needs.candidate.outputs.sha }}": "a" * 40,
        }

        def render(value):
            for expression, replacement in replacements.items():
                value = value.replace(expression, replacement)
            return value

        return subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", render(step["run"])],
            cwd=root,
            env={**os.environ, "TAG": "v1.0.0", **(extra_env or {}),
                 **{key: render(value) for key, value in step.get("env", {}).items()}},
            capture_output=True, text=True, check=False,
        )

    def test_cross_invocation_requests_candidate_sha_passthrough(self):
        # Observe the real workflow's cross invocation contract; this does not
        # substitute for building and executing the hosted ARM64 artifact.
        with tempfile.TemporaryDirectory(prefix="hush-release-cross-") as temp:
            root = Path(temp)
            cross = root / "cross"
            cross.write_text(
                f"#!{sys.executable}\nimport json, os, sys\n"
                "print(json.dumps({'sha': os.getenv('H2H_GIT_SHA'), "
                "'passthrough': os.getenv('CROSS_BUILD_ENV_PASSTHROUGH'), 'args': sys.argv[1:]}))\n"
            )
            cross.chmod(0o755)
            result = self.build_step("Build", root=root, target="aarch64-unknown-linux-gnu", cross="true",
                                     extra_env={"PATH": str(root) + os.pathsep + os.environ["PATH"],
                                                "CROSS_BUILD_ENV_PASSTHROUGH": ""})
            self.assertEqual(result.returncode, 0, result.stderr)
            observed = json.loads(result.stdout)
            self.assertEqual(observed["sha"], "a" * 40)
            self.assertIn("H2H_GIT_SHA", (observed["passthrough"] or "").split())
            self.assertEqual(observed["args"], ["build", "-p", "hushspec-cli", "--release", "--locked",
                                                 "--target", "aarch64-unknown-linux-gnu"])

    def test_native_smoke_rejects_wrong_candidate_version_or_target(self):
        target = "x86_64-unknown-linux-gnu"
        for changed in (None, "git_sha", "version", "target"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory(prefix="hush-release-smoke-") as temp:
                root = Path(temp)
                binary = root / "target" / target / "release/h2h"
                binary.parent.mkdir(parents=True)
                version = {"git_sha": "a" * 40, "version": "1.0.0", "target": target}
                if changed:
                    version[changed] = "wrong"
                binary.write_text(f"#!{sys.executable}\nimport sys\nif sys.argv[1] == 'version': print({json.dumps(version)!r})\n")
                binary.chmod(0o755)
                result = self.build_step("Smoke-test executable", root=root, target=target, cross="false")
                if changed is None:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0, "wrong artifact identity was accepted")

    def test_arm_smoke_runs_built_executable_without_cross_toolchain_output(self):
        target = "aarch64-unknown-linux-gnu"
        for valid in (True, False):
            with self.subTest(valid=valid), tempfile.TemporaryDirectory(prefix="hush-release-cross-smoke-") as temp:
                root = Path(temp)
                version = {"git_sha": "a" * 40 if valid else "wrong", "version": "1.0.0", "target": target}
                cross = root / "cross"
                # rustup prints this status even with --quiet. Cross 0.2.5
                # also fails to recognize toolchain list's (active, default).
                cross.write_text(
                    f"#!{sys.executable}\nimport sys\n"
                    "print('\\n  stable-x86_64-unknown-linux-gnu unchanged\\n')\n"
                    f"if 'version' in sys.argv: print({json.dumps(version)!r})\n"
                )
                cross.chmod(0o755)
                binary = root / "target" / target / "release/h2h"
                binary.parent.mkdir(parents=True)
                binary.write_text(f"#!{sys.executable}\nimport sys\nif sys.argv[1] == 'version': print({json.dumps(version)!r})\n")
                binary.chmod(0o755)
                docker = root / "docker"
                docker.write_text(
                    f"#!{sys.executable}\nimport pathlib, subprocess, sys\n"
                    "args = sys.argv[1:]\n"
                    "assert args[:3] == ['run', '--rm', '--network=none']\n"
                    "assert args[3:5] == ['--volume', str(pathlib.Path.cwd()) + ':/work:ro']\n"
                    "assert args[5:7] == ['--workdir', '/work']\n"
                    "assert args[7:10] == ['ghcr.io/cross-rs/aarch64-unknown-linux-gnu:0.2.5', '/linux-runner', 'aarch64']\n"
                    f"assert args[10] == 'target/{target}/release/h2h'\n"
                    "sys.exit(subprocess.run(args[10:]).returncode)\n"
                )
                docker.chmod(0o755)
                result = self.build_step("Smoke-test executable", root=root, target=target, cross="true",
                                         extra_env={"PATH": str(root) + os.pathsep + os.environ["PATH"]})
                if valid:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads((root / "cli-version.json").read_text()), version)
                else:
                    self.assertNotEqual(result.returncode, 0, "wrong artifact identity was accepted")

    def run_selection(self, *, dry_run: str, candidate: str, tag: str = "v1.0.0"):
        with tempfile.TemporaryDirectory(prefix="hush-release-selection-") as temp:
            output = Path(temp) / "output"
            result = subprocess.run(
                ["bash", "-e", "-o", "pipefail", "-c", STEPS[0]["run"]],
                env={
                    **os.environ,
                    "TAG": tag,
                    "DRY_RUN": dry_run,
                    "CANDIDATE_REF": candidate,
                    "GITHUB_OUTPUT": str(output),
                },
                capture_output=True,
                text=True,
                check=False,
            )
            return result, output.read_text() if output.exists() else ""

    def test_rehearsal_selects_exact_commit_without_a_tag(self):
        result, output = self.run_selection(dry_run="true", candidate="a" * 40)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, "checkout_ref=" + "a" * 40 + "\n")

    def test_rehearsal_rejects_missing_or_mutable_ref(self):
        for candidate in ("", "main", "feature/candidate", "a" * 39, "g" * 40):
            with self.subTest(candidate=candidate):
                result, output = self.run_selection(dry_run="true", candidate=candidate)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, "")

    def test_publication_selects_the_tag_only(self):
        result, output = self.run_selection(dry_run="false", candidate="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, "checkout_ref=refs/tags/v1.0.0\n")

    def test_publication_refuses_a_candidate_override(self):
        result, output = self.run_selection(dry_run="false", candidate="a" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output, "")

    def test_invalid_mode_or_tag_never_selects_a_candidate(self):
        for dry_run, tag in (("", "v1.0.0"), ("yes", "v1.0.0"), ("true", "main")):
            with self.subTest(dry_run=dry_run, tag=tag):
                result, output = self.run_selection(
                    dry_run=dry_run, candidate="a" * 40, tag=tag
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, "")

    def test_mismatched_package_version_refuses_candidate(self):
        pin = next(step for step in STEPS if step.get("id") == "candidate")
        for changed in (None, "Cargo.toml", "packages/hushspec/package.json", "packages/python/pyproject.toml"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory(prefix="hush-release-pin-") as temp:
                root = Path(temp)
                versions = {name: "1.0.0" for name in (
                    "Cargo.toml", "packages/hushspec/package.json", "packages/python/pyproject.toml"
                )}
                if changed is not None:
                    versions[changed] = "0.1.1"
                for name, version in versions.items():
                    target = root / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(
                        json.dumps({"version": version}) if name.endswith(".json") else
                        f'[{"workspace.package" if name == "Cargo.toml" else "project"}]\nversion = "{version}"\n'
                    )
                subprocess.run(["git", "init", "-q", str(root)], check=True)
                subprocess.run(["git", "-C", str(root), "add", "."], check=True)
                subprocess.run([
                    "git", "-C", str(root), "-c", "user.name=Release Test",
                    "-c", "user.email=release-test@example.invalid", "commit", "-qm", "fixture"
                ], check=True)
                result = subprocess.run(
                    ["bash", "-e", "-o", "pipefail", "-c", pin["run"]],
                    cwd=root,
                    env={**os.environ, "TAG": "v1.0.0", "DRY_RUN": "false", "GITHUB_OUTPUT": str(root / "output")},
                    capture_output=True, text=True, check=False,
                )
                if changed is None:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertRegex((root / "output").read_text(), r"^sha=[0-9a-f]{40}\n$")
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("does not match tag version", result.stderr)
                    self.assertFalse((root / "output").exists())


if __name__ == "__main__":
    unittest.main()
