"""Curated prose follows the approved v1 style; frozen specs are not rewritten."""
from pathlib import Path
import unittest

class Style(unittest.TestCase):
    def test_curated_prose_has_no_em_dashes(self):
        root=Path(__file__).resolve().parent.parent/'docs/src'
        failures=[str(path.relative_to(root)) for path in root.rglob('*.md') if '\u2014' in path.read_text()]
        self.assertEqual(failures,[])

if __name__=='__main__':
    unittest.main()
