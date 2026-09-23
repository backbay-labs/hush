#!/usr/bin/env python3
"""The quickstart is an executable contract against the selected release CLI."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import unittest
import yaml

ROOT = Path(__file__).resolve().parent.parent
H2H = os.environ.get('H2H', str(ROOT / 'target/release/h2h'))
EXAMPLES = ROOT / 'docs/examples/quickstart'


class Quickstart(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hush-quickstart-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        for name in ('policy.yaml', 'policy.test.yaml'):
            shutil.copyfile(EXAMPLES / name, self.work / name)

    def cli(self, *args):
        return subprocess.run([H2H, *args], cwd=self.work, capture_output=True, text=True)

    def test_release_decisions_and_exit_codes(self):
        self.assertEqual(yaml.safe_load((self.work/'policy.yaml').read_text()), yaml.safe_load((self.work/'policy.test.yaml').read_text())['policy'])
        first_policy=(ROOT/'docs/src/guides/first-policy.md').read_text()
        code=re.search(r'```yaml\n(.*?)```', first_policy, re.S)[1]
        self.assertEqual(code,(self.work/'policy.yaml').read_text(), 'copied policy bytes drifted')
        self.assertEqual(self.cli('validate', '--strict', 'policy.yaml').returncode, 0)
        for kind, target, code, decision in [('file_read','/workspace/src/main.ts',0,'allow'),
                ('file_read','/workspace/.env',1,'deny'), ('tool_call','search',0,'allow'),
                ('tool_call','deploy',1,'deny'), ('tool_call','write_file',4,'warn')]:
            with self.subTest(kind=kind,target=target):
                result=self.cli('eval','policy.yaml','--type',kind,'--target',target,'--format','json')
                self.assertEqual(result.returncode,code,result.stdout+result.stderr)
                self.assertEqual(json.loads(result.stdout)['decision'],decision)
        result=self.cli('test','--policy','policy.yaml','policy.test.yaml')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_unconfirmed_warning_is_recorded_blocked(self):
        result=self.cli('eval','policy.yaml','--type','tool_call','--target','write_file','--format','receipt')
        self.assertEqual(result.returncode,4,result.stdout+result.stderr)
        receipt=json.loads(result.stdout)
        self.assertEqual(receipt['decision'],'warn')
        self.assertEqual(receipt['enforcement']['outcome'],'blocked')

    def test_copied_commands(self):
        text=(ROOT/'docs/src/guides/getting-started.md').read_text()
        blocks=re.findall(r'<!-- docs-run: quickstart -->\s*```sh\n(.*?)```',text,re.S)
        self.assertTrue(blocks, 'No runnable quickstart commands')
        (self.work/'bin').mkdir()
        (self.work/'bin/h2h').symlink_to(Path(H2H).resolve())
        started=time.monotonic()
        for block in blocks:
            result=subprocess.run(['sh','-c',block],cwd=self.work,env={**os.environ,'PATH':str(self.work/'bin')+os.pathsep+os.environ['PATH']},capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        print(f'Copied CLI walkthrough: {time.monotonic()-started:.2f}s (installation and human reading excluded)')


if __name__ == '__main__':
    unittest.main()
