"""Capture every release help surface and fail on documentation drift.

--refresh replaces only the generated appendix. Exit semantics are reviewed
against command implementations; they are not inferred from help text.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT/'docs/src/reference/cli.md'
MARKER = '<!-- generated-cli-reference -->'
EXITS = {
    'audit': '0: report produced; 1: unreadable/invalid policy or strict governance failure. Usage errors: 2.',
    'bundle': 'Select create, verify or inspect; their exit contracts follow below. Missing/invalid subcommand: 2.',
    'bundle create': '0: bundle created; 1: policy resolution/validation/trust refusal; 2: unusable input or output.',
    'bundle verify': '0: valid; 1: verification refused with a reason code on stderr; 2: unusable input or trust configuration.',
    'bundle inspect': '0: decoded; 1: bundle cannot be decoded. Inspection does not verify trust. Usage errors: 2.',
    'validate': '0: valid; 1: invalid; 2: input could not be read or invalid usage.',
    'resolve': '0: resolved; 1: resolution/validation/trust failure or strict warning; 2: missing input or invalid usage.',
    'test': '0: all cases passed; 1: failed cases or no runnable cases; 2: input/configuration failure.',
    'eval': '0: allow; 1: deny or policy refusal; 4: warn; 2: input/usage failure. No tool is executed.',
    'explain': '0: allow; 1: deny or policy refusal; 4: warn; 2: input/usage failure. No tool is executed.',
    'init': '0: scaffold created; 1: refusal or filesystem failure; 2: invalid usage.',
    'lint': '0: no blocking findings; 1: errors or warnings with --fail-on-warnings; 2: input/usage failure.',
    'diff': '0: no selected --fail-on class; 1: selected change class found; 2: input/usage failure.',
    'fmt': '0: formatted or already canonical; 1: --check needs changes or rewrite refused; 2: read/parse/write/usage failure.',
    'hash': '0: digest/canonical output; 1: parse/resolve/validation/canonicalization failure; 2: input/usage failure.',
    'panic': 'Select activate, deactivate or status. This manages a sentinel file, not another process latch. Usage errors: 2.',
    'panic activate': '0: sentinel created; 1: write failed; 2: invalid usage.',
    'panic deactivate': '0: sentinel removed or already absent; 1: removal failed; 2: invalid usage. Running SDK latches require explicit reset.',
    'panic status': '0: absence proven; 1: present or absence cannot be proven; 2: invalid usage.',
    'sign': '0: signed; 1: approval/key/policy/signing/output failure; 2: missing policy, invalid duration or usage.',
    'verify': '0: valid; 1: invalid signature with reason/detail JSON on stderr; 2: unusable inputs or usage.',
    'keygen': '0: keys written; 1: key conversion, existing-file refusal or I/O failure; 2: invalid usage.',
    'schema': '0: schema/list printed; 2: unknown name or input/serialization/usage failure.',
    'completions': '0: completion script printed; 2: invalid shell or usage.',
    'version': '0: version printed; 1: serialization failure; 2: invalid usage.',
    'log': 'Select verify; missing/invalid subcommand: 2.',
    'log verify': '0: supplied chain verifies; 1: first break reported by file/line; 2: unusable trust configuration or usage. A prefix is not completeness.',
    'receipts': 'Select verify; missing/invalid subcommand: 2.',
    'receipts verify': '0: supplied receipts pass requested checks; 1: receipt/policy/signature refusal; 2: input/configuration/usage failure.',
    'report': '0: output produced; 1: chain/integrity/authentication/required-boundary failure; 2: input/configuration/limits/output/usage failure. Strict mode publishes no success packet on refusal.',
}


def commands(help_text):
    match = re.search(r'^Commands:\n(.*?)(?:\n\n|\Z)', help_text, re.M|re.S)
    if not match:
        return []
    return [m[1] for m in re.finditer(r'^  ([a-z-]+)\s', match[1], re.M) if m[1] != 'help']


def capture(binary):
    env = {**os.environ, 'NO_COLOR':'1', 'TERM':'dumb', 'COLUMNS':'100'}
    def help_for(parts):
        body = subprocess.check_output([binary, *parts, '--help'], env=env, text=True)
        # Clap indents some blank lines. Normalize only trailing whitespace
        # so the captured reference passes the repository whitespace gate.
        return '\n'.join(line.rstrip() for line in body.splitlines())+'\n'
    root = help_for([])
    tops = commands(root)
    if len(tops) != 22:
        raise ValueError(f'expected 22 v1 commands, found {tops}')
    found = {}
    def collect(parts):
        body = help_for(parts)
        found[' '.join(parts)] = body
        for child in commands(body):
            collect([*parts, child])
    for top in tops:
        collect([top])
    if set(found) != set(EXITS):
        raise ValueError('new or missing command needs an exit-contract review')
    return found


def validate_coverage(markdown, help_text):
    for command, body in help_text.items():
        expected = f'<!-- cli-help: {command} -->\n```text\n{body}```'
        if expected not in markdown:
            raise ValueError(f'help coverage differs: h2h {command}')
        exit_line = f'<!-- cli-exit: {command} -->\n{EXITS[command]}'
        if exit_line not in markdown:
            raise ValueError(f'exit contract missing or changed: h2h {command}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--h2h', default=os.environ.get('H2H', str(ROOT/'target/release/h2h')))
    parser.add_argument('--refresh', action='store_true')
    args = parser.parse_args()
    version = json.loads(subprocess.check_output([args.h2h,'version','--format','json'], text=True))
    if version['version'] != '1.0.0' or version['spec_version'] != '1.0.0':
        raise ValueError('capture requires the v1 CLI')
    help_text = capture(args.h2h)
    markdown = PAGE.read_text()
    if args.refresh:
        appendix = MARKER+'\n\n## Complete v1 option reference\n\n'
        appendix += 'Captured from `h2h 1.0.0`. These blocks list every public command and option.\nExit notes are checked against the release implementation, not inferred from help.\n\n'
        for command, body in help_text.items():
            appendix += f'### `h2h {command}` options\n\n<!-- cli-exit: {command} -->\n{EXITS[command]}\n\n<!-- cli-help: {command} -->\n```text\n{body}```\n\n'
        markdown = markdown.split(MARKER)[0].rstrip()+'\n\n'+appendix.rstrip()+'\n'
        PAGE.write_text(markdown)
        directory = ROOT/'docs/examples/cli'
        directory.mkdir(parents=True, exist_ok=True)
        (directory/'help.json').write_text(json.dumps({'version':version['version'], 'releaseCommit':'e771ec647b7f26a0a09ff852886eb8a91093bc58', 'commands':help_text, 'exits':EXITS}, indent=2)+'\n')
    validate_coverage(markdown, help_text)
    print(f'{len(help_text)} release help surfaces and exit contracts match; CLI {version["version"]}; source {version["git_sha"]}')


if __name__ == '__main__':
    main()
