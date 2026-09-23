#!/usr/bin/env python3
"""Validate complete curated Markdown policy examples with the release CLI.

Partial snippets remain fragments; normative grammar/negative fixtures are not
silently relabeled runnable. Multi-file inheritance is assembled by filename.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import yaml
from docs_blocks import blocks

ROOT = Path(__file__).resolve().parent.parent
H2H = os.environ.get('H2H', str(ROOT / 'target/release/h2h'))

def complete_policies(markdown):
    policies=[]
    for index, block in enumerate(blocks(markdown)):
        if block['language'] not in ('yaml','yml'):
            continue
        doc=yaml.safe_load(block['code'])
        if isinstance(doc,dict) and 'hushspec' in doc:
            policies.append((index,block['code'],doc))
    return policies


class DocumentationPolicies(unittest.TestCase):
    def test_nested_policy_is_not_lost(self):
        from test_docs_policies import complete_policies
        self.assertEqual(len(complete_policies('> ```yaml\n> hushspec: "1.0.0"\n> name: nested\n> ```\n')),1)
    def test_complete_curated_policies(self):
        total = 0
        for source in [ROOT / 'README.md', *sorted((ROOT / 'docs/src').rglob('*.md'))]:
            policies = complete_policies(source.read_text())
            with tempfile.TemporaryDirectory(prefix='hush-doc-policy-') as directory:
                for index, raw, doc in policies:
                    match = re.match(r'# ([a-z-]+\.yaml)\n', raw)
                    filename = match[1] if match else f'example-{index}.yaml'
                    (Path(directory) / filename).write_text(raw)
                for index, raw, doc in policies:
                    match = re.match(r'# ([a-z-]+\.yaml)\n', raw)
                    filename = match[1] if match else f'example-{index}.yaml'
                    with self.subTest(source=str(source.relative_to(ROOT)), block=index):
                        result = subprocess.run([H2H, 'validate', '--strict', '--format', 'json', filename], cwd=directory, capture_output=True, text=True)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        total += 1
        self.assertGreater(total, 5, 'empty documentation test inventory')
        print(f'Validated {total} complete curated policy blocks')


if __name__ == '__main__':
    unittest.main()
