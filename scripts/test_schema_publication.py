"""Exercise schema-site exports using committed source and real schema bytes."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SchemaPublicationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hush-schema-site-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "source"
        self.root.mkdir()
        self.site = Path(temp.name) / "site"
        for directory in ("schemas", "spec/registries"):
            shutil.copytree(ROOT / directory, self.root / directory)
        (self.root / "scripts").mkdir()
        shutil.copyfile(ROOT / "scripts/build_schema_index.py", self.root / "scripts/build_schema_index.py")
        self.git("init", "-q")
        self.commit()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], text=True).strip()

    def commit(self):
        self.git("add", ".")
        self.git("-c", "user.name=Schema Test", "-c", "user.email=schema@example.invalid",
                 "commit", "-qm", "fixture")

    def export(self):
        import sys
        return subprocess.run(
            [sys.executable, str(self.root / "scripts/build_schema_index.py"),
             "--site-root", str(self.site)], capture_output=True, text=True,
            env={**os.environ, "HUSHSPEC_COMMIT": "not-the-source-commit"},
        )

    def test_export_pins_source_and_preserves_schema_and_registry_bytes(self):
        result = self.export()
        self.assertEqual(result.returncode, 0, result.stderr)
        index = json.loads((self.site / "schemas/index.json").read_text())
        self.assertEqual(index["commit"], self.git("rev-parse", "HEAD"))
        self.assertEqual(index["host"], "https://hushspec.org/schemas/")
        self.assertEqual(len(index["schemas"]), len(list((self.root / "schemas").glob("*.schema.json"))))
        for entry in index["schemas"]:
            source = (self.root / "schemas" / entry["file"]).read_bytes()
            self.assertEqual((self.site / "schemas" / entry["file"]).read_bytes(), source)
            self.assertEqual(entry["sha256"], hashlib.sha256(source).hexdigest())
            self.assertEqual(entry["url"], "https://hushspec.org/schemas/" + entry["file"])
            host = "hushspec.org" if ".v1." in entry["file"] else "hushspec.dev"
            self.assertEqual(entry["$id"], f"https://{host}/schemas/{entry['file']}")
        self.assertEqual(len(index["registries"]), len(list((self.root / "spec/registries").glob("*.yaml"))))
        for entry in index["registries"]:
            source = (self.root / "spec/registries" / entry["file"]).read_bytes()
            self.assertEqual((self.site / "registries" / entry["file"]).read_bytes(), source)
            self.assertEqual(entry["sha256"], hashlib.sha256(source).hexdigest())
            self.assertEqual(entry["url"], "https://hushspec.org/registries/" + entry["file"])

    def test_export_rejects_dirty_sources_before_writing(self):
        for relative in ("schemas/hushspec-core.v1.schema.json", "spec/registries/frameworks.yaml"):
            with self.subTest(relative=relative):
                path = self.root / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                result = self.export()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("uncommitted", result.stderr)
                self.assertFalse(self.site.exists())
                path.write_bytes(original)

    def test_export_uses_committed_bytes_from_a_clean_crlf_checkout(self):
        clone = self.root.parent / "crlf-source"
        subprocess.run(
            ["git", "clone", "-q", "-c", "core.autocrlf=true", str(self.root), str(clone)],
            check=True,
        )
        self.root = clone
        self.assertEqual(self.git("status", "--porcelain"), "")
        frozen = self.root / "schemas/hushspec-core.v0.schema.json"
        self.assertIn(b"\r\n", frozen.read_bytes())
        result = self.export()
        self.assertEqual(result.returncode, 0, result.stderr)
        index = json.loads((self.site / "schemas/index.json").read_text())
        self.assertEqual(index["commit"], self.git("rev-parse", "HEAD"))
        for category, source in (("schemas", "schemas"), ("registries", "spec/registries")):
            for entry in index[category]:
                with self.subTest(file=entry["file"]):
                    committed = subprocess.check_output([
                        "git", "-C", str(self.root), "show",
                        f"{index['commit']}:{source}/{entry['file']}",
                    ])
                    self.assertEqual((self.site / category / entry["file"]).read_bytes(), committed)
                    self.assertEqual(entry["sha256"], hashlib.sha256(committed).hexdigest())

    def test_export_rejects_wrong_schema_hosts(self):
        for name in ("hushspec-core.v1.schema.json", "hushspec-core.v0.schema.json"):
            with self.subTest(name=name):
                path = self.root / "schemas" / name
                original = path.read_text()
                document = json.loads(original)
                document["$id"] = "https://unowned.example/schemas/" + name
                path.write_text(json.dumps(document))
                self.commit()
                result = self.export()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("declares $id", result.stderr)
                self.assertFalse(self.site.exists())
                path.write_text(original)
                self.commit()

    def test_export_rejects_ignored_schema_not_in_the_commit(self):
        (self.root / ".gitignore").write_text("schemas/hushspec-extra.v1.schema.json\n")
        self.commit()
        (self.root / "schemas/hushspec-extra.v1.schema.json").write_text(json.dumps({
            "$id": "https://hushspec.org/schemas/hushspec-extra.v1.schema.json", "type": "object",
        }))
        result = self.export()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("uncommitted", result.stderr)
        self.assertFalse(self.site.exists())


if __name__ == "__main__":
    unittest.main()
