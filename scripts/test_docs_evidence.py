"""Execute the public evidence recipe and assert specific refusal categories."""
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from docs_blocks import blocks
import shutil

ROOT = Path(__file__).resolve().parent.parent
H2H = os.environ.get('H2H', str(ROOT/'target/release/h2h'))


class EvidenceDocs(unittest.TestCase):
    def test_downloaded_readme_commands(self):
        with tempfile.TemporaryDirectory(prefix='hush-doc-evidence-readme-') as directory:
            work=Path(directory)
            for source in ['docs/examples/evidence/verify.py','docs/examples/quickstart/policy.yaml']:
                shutil.copyfile(ROOT/source,work/Path(source).name)
            (work/'h2h').symlink_to(Path(H2H).resolve())
            (work/'python3').symlink_to(Path(sys.executable).resolve())
            commands=blocks((ROOT/'docs/examples/evidence/README.md').read_text())
            self.assertEqual(len(commands),1)
            result=subprocess.run(['sh','-eu','-c',commands[0]['code']],cwd=work,
                env={**os.environ,'PATH':directory+os.pathsep+os.environ['PATH']},capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual(json.loads(result.stdout)['wrong_key'],'unknown_key_id')
    def test_monitor_tamper_and_oscal_commands_are_copied_from_guide(self):
        guide = (ROOT/'docs/src/guides/evidence-verification.md').read_text()
        blocks = re.findall(r'<!-- docs-run: (evidence-[a-z]+) -->\s*```bash\n(.*?)```', guide, re.S)
        self.assertEqual([b[0] for b in blocks], ['evidence-monitor','evidence-tamper','evidence-oscal'])
        with tempfile.TemporaryDirectory(prefix='hush-doc-evidence-') as directory:
            executable = Path(directory)/'h2h'
            executable.symlink_to(Path(H2H).resolve())
            result = subprocess.run(['sh','-eu','-c','\n'.join(b[1] for b in blocks)], cwd=ROOT,
                                    env={**os.environ, 'PATH':directory+os.pathsep+os.environ['PATH'], 'TMPDIR':directory},
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertIn('completeness not established', result.stdout)

    def test_annotated_receipt_matches_schema_and_live_evaluation(self):
        import jsonschema
        receipt = json.loads((ROOT/'docs/examples/evidence/receipt.json').read_text())
        schema = json.loads((ROOT/'schemas/hushspec-receipt.v1.schema.json').read_text())
        jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(receipt)
        result = subprocess.run([H2H, 'eval', str(ROOT/'docs/examples/quickstart/policy.yaml'),
                                 '--type', 'file_read', '--target', '/workspace/.env', '--format', 'receipt'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        current = json.loads(result.stdout)
        for key in ['receipt_version','policy','action','decision','matched_rule','reason','rule_trace','enforcement']:
            self.assertEqual(receipt[key], current[key], key)

    def test_negative_verification_categories(self):
        result = subprocess.run([sys.executable, str(ROOT/'docs/examples/evidence/verify.py'),
                                 '--h2h', H2H, '--policy', str(ROOT/'docs/examples/quickstart/policy.yaml')],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        report = json.loads(result.stdout)
        for key, expected in {
            'tampered_policy': 'content_hash_mismatch', 'wrong_key': 'unknown_key_id',
            'expired': 'expired', 'tampered_signature': 'signature_mismatch',
            'broken_log': 'prev_hash mismatch', 'invalid_bundle': 'dsse_signature_mismatch',
            'truncated_log': 'valid-prefix-not-completeness',
        }.items():
            self.assertEqual(report[key], expected)


if __name__ == '__main__':
    unittest.main()
