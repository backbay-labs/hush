"""A self-contained evidence lab. Ephemeral keys are never production trust.

Requires Python 3.10+ and h2h 1.0.0. All generated files, including private keys,
live in an owned temporary directory and are removed on normal exit.
"""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--h2h', default='h2h')
    parser.add_argument('--policy', type=Path, required=True)
    args = parser.parse_args()
    executable = shutil.which(args.h2h)
    if not executable:
        raise SystemExit('Install h2h or supply --h2h /absolute/path/to/h2h')
    policy_bytes = args.policy.read_bytes()
    outcomes = {}
    with tempfile.TemporaryDirectory(prefix='hush-evidence-lab-') as directory:
        root = Path(directory)
        def run(*arguments, expected=0, json_output=False):
            completed = subprocess.run([executable, *arguments], cwd=root, capture_output=True, text=True)
            if completed.returncode != expected:
                raise AssertionError(f'{arguments}: exit {completed.returncode}, expected {expected}\n{completed.stdout}{completed.stderr}')
            # Policy/bundle refusal JSON uses stderr; log refusal JSON uses stdout.
            return json.loads(completed.stdout or completed.stderr) if json_output else completed.stdout

        (root/'policy.yaml').write_bytes(policy_bytes)
        run('keygen', '--name', 'lab')
        run('keygen', '--name', 'wrong')
        run('sign', 'policy.yaml', '--key', 'lab.key.pem', '--expires-in', '1h', '--allow-unapproved')
        verify = ['verify', 'policy.yaml', '--key', 'lab.pub.pem', '--format', 'json']
        assert run(*verify, json_output=True)['valid'] is True
        outcomes['valid_policy'] = True

        result = run('verify', 'policy.yaml', '--key', 'wrong.pub.pem', '--format', 'json', expected=1, json_output=True)
        outcomes['wrong_key'] = result['reason']
        later = (datetime.now(timezone.utc)+timedelta(hours=2)).isoformat()
        outcomes['expired'] = run(*verify, '--now', later, expected=1, json_output=True)['reason']

        changed = policy_bytes.replace(b'coding-agent-quickstart', b'changed-policy')
        assert changed != policy_bytes, 'Use the downloaded quickstart policy for this lab'
        (root/'policy.yaml').write_bytes(changed)
        outcomes['tampered_policy'] = run(*verify, expected=1, json_output=True)['reason']
        (root/'policy.yaml').write_bytes(policy_bytes)
        signature = (root/'policy.yaml.sig').read_bytes()
        envelope = json.loads(signature)
        signature_bytes = bytearray(base64.urlsafe_b64decode(envelope['signature']+'=='))
        signature_bytes[0] ^= 1
        envelope['signature'] = base64.urlsafe_b64encode(signature_bytes).decode().rstrip('=')
        (root/'policy.yaml.sig').write_text(json.dumps(envelope))
        outcomes['tampered_signature'] = run(*verify, expected=1, json_output=True)['reason']
        (root/'policy.yaml.sig').write_bytes(signature)

        receipt = run('eval', 'policy.yaml', '--type', 'file_read', '--target', '/workspace/.env',
                      '--format', 'receipt', '--log', 'events.jsonl', '--log-key', 'lab.key.pem',
                      expected=1, json_output=True)
        assert receipt['decision'] == 'deny' and receipt['enforcement']['outcome'] == 'blocked'
        (root/'receipt.json').write_text(json.dumps(receipt))
        run('receipts', 'verify', 'receipt.json', '--policy', 'policy.yaml')
        log_verify = ['log', 'verify', 'events.jsonl', '--key', 'lab.pub.pem', '--require-signatures', '--format', 'json']
        assert run(*log_verify, json_output=True)['ok'] is True
        lines = (root/'events.jsonl').read_text().splitlines()
        assert len(lines) == 2  # policy_loaded, then receipt
        second = json.loads(lines[1])
        second['prev_hash'] = 'sha256:' + '0'*64
        (root/'events.jsonl').write_text(lines[0]+'\n'+json.dumps(second)+'\n')
        broken = run(*log_verify, expected=1, json_output=True)
        assert broken['line'] == 2 and 'prev_hash' in broken['message']
        outcomes['broken_log'] = 'prev_hash mismatch'
        (root/'events.jsonl').write_text(lines[0]+'\n')
        assert run(*log_verify, json_output=True)['ok'] is True
        outcomes['truncated_log'] = 'valid-prefix-not-completeness'

        run('bundle', 'create', 'policy.yaml', '--key', 'lab.key.pem', '--out', 'policy.bundle.json')
        bundle_verify = ['bundle', 'verify', 'policy.bundle.json', '--key', 'lab.pub.pem', '--policy', 'policy.yaml', '--format', 'json']
        assert run(*bundle_verify, json_output=True)['valid'] is True
        bundle = json.loads((root/'policy.bundle.json').read_text())
        payload = json.loads(base64.b64decode(bundle['payload']))
        payload['predicate']['resolved']['name'] = 'changed-policy'
        bundle['payload'] = base64.b64encode(json.dumps(payload).encode()).decode()
        (root/'policy.bundle.json').write_text(json.dumps(bundle))
        outcomes['invalid_bundle'] = run(*bundle_verify, expected=1, json_output=True)['reason']
    print(json.dumps(outcomes, indent=2))


if __name__ == '__main__':
    main()
