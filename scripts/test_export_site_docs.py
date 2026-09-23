"""Export security and reproducibility against real Git trees, not mocked Git."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from export_site_docs import export


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'
        self.site = Path(self.temp.name) / 'site'
        self.root.mkdir()
        (self.site / 'content').mkdir(parents=True)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Docs Test')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'core.autocrlf', 'true')
        (self.root / 'docs/src').mkdir(parents=True)
        (self.root / 'spec').mkdir()
        self.source = self.root / 'docs/src/intro.md'
        self.source.write_bytes(b'# Original\r\n\r\nText.\r\n')
        (self.root / 'spec/hushspec-core.md').write_text('# Frozen\n')
        self.commit()
        self.release = self.git('rev-parse', 'HEAD').strip()
        self.source.write_bytes(b'# Updated\r\n\r\nText.\r\n')
        self.commit()
        self.docs = self.git('rev-parse', 'HEAD').strip()
        self.pages = [{'route':'/docs', 'sourcePath':'docs/src/intro.md'},
                      {'route':'/docs/specification/core', 'sourcePath':'spec/hushspec-core.md'}]
        self.config()

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, stderr=subprocess.DEVNULL, text=True)

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')

    def config(self):
        (self.site / 'content/docs.config.json').write_text(json.dumps({'pages':self.pages}))

    def run_export(self):
        return export(self.root, self.site, self.release, self.docs)

    def test_clean_crlf_exports_git_blobs_and_separate_commits(self):
        first = self.run_export()
        self.assertEqual(first['releaseCommit'], self.release)
        self.assertEqual(first['docsCommit'], self.docs)
        for item in first['files']:
            raw = (self.site / 'content/upstream' / item['path']).read_bytes()
            self.assertNotIn(b'\r', raw)
            self.assertEqual(item['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(self.run_export(), first)

    def test_dirty_source_refused_before_any_write(self):
        self.source.write_text('# Uncommitted\n')
        with self.assertRaisesRegex(ValueError, 'uncommitted'):
            self.run_export()
        self.assertFalse((self.site / 'content/upstream').exists())

    def test_missing_source_refused(self):
        self.pages[0]['sourcePath'] = 'docs/src/missing.md'
        self.config()
        with self.assertRaisesRegex(ValueError, 'missing'):
            self.run_export()

    def test_symlink_source_refused(self):
        self.source.unlink()
        self.source.symlink_to('../../spec/hushspec-core.md')
        self.commit()
        self.docs = self.git('rev-parse', 'HEAD').strip()
        with self.assertRaisesRegex(ValueError, 'regular'):
            self.run_export()

    def test_traversal_refused(self):
        self.pages[0]['sourcePath'] = '../outside.md'
        self.config()
        with self.assertRaisesRegex(ValueError, 'source path'):
            self.run_export()

    def test_duplicate_route_refused(self):
        self.pages.append(self.pages[0])
        self.config()
        with self.assertRaisesRegex(ValueError, 'duplicate route'):
            self.run_export()

    def test_destination_symlink_refused(self):
        outside = Path(self.temp.name) / 'outside'
        outside.mkdir()
        (self.site / 'content/upstream').symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.run_export()
        self.assertEqual(list(outside.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
