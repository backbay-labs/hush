"""Fail closed on code-block drift and unclassified examples."""
import unittest
from docs_blocks import blocks, check_inventory, sources


class Blocks(unittest.TestCase):
    def test_downloaded_readmes_are_inventoried(self):
        self.assertTrue(any(str(path).endswith('docs/examples/evidence/README.md') for path in sources()))
    def test_indented_fences_keep_exact_code(self):
        found = blocks('intro\n\n   ```python\n   print("ok")\n   ```\n')
        self.assertEqual(found[0]['code'], 'print("ok")\n')

    def test_long_fence_can_contain_short_fences(self):
        self.assertEqual(len(blocks('````md\n```py\nx\n```\n````\n')), 1)

    def test_nested_blockquote_fences_are_not_lost(self):
        self.assertEqual(blocks('> ```python\n> print(1)\n> ```\n'),
                         [{'language':'python', 'code':'print(1)\n'}])

    def test_unknown_or_changed_block_fails(self):
        block = {'id': 'guide.md:1', 'code': 'print(1)\n', 'language': 'python'}
        with self.assertRaisesRegex(ValueError, 'unclassified'):
            check_inventory([block], {})
        with self.assertRaisesRegex(ValueError, 'changed'):
            check_inventory([block], {'guide.md:1': {'sha256': 'wrong', 'kind': 'fragment', 'reason': 'excerpt'}})

    def test_runnable_requires_runner(self):
        import hashlib
        block = {'id': 'guide.md:1', 'code': 'x\n', 'language': 'python'}
        entry = {'sha256': hashlib.sha256(b'x\n').hexdigest(), 'kind': 'runnable'}
        with self.assertRaisesRegex(ValueError, 'runner'):
            check_inventory([block], {'guide.md:1': entry})


if __name__ == '__main__':
    unittest.main()
