"""Inventory fenced examples. Every source edit requires classification review.

This lexer handles the fenced blocks used by this book, including indented
list fences and fences containing shorter fences. The website's Markdown AST
checker independently compares its parsed code-block inventory at export time.
"""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = ROOT / 'docs/examples/blocks.json'
KINDS = {'runnable', 'fragment', 'operator-command', 'expected-output', 'negative', 'normative'}


def blocks(markdown):
    result = []
    opened = None
    code = []
    for line in markdown.splitlines(keepends=True):
        if opened is None:
            match = re.match(r'^( *)(`{3,}|~{3,})([^\n]*)\n?$', line)
            if match:
                indent, fence, info = match.groups()
                opened = (len(indent), fence, info.strip().split()[0] if info.strip() else '')
        else:
            indent, fence, language = opened
            if re.match(r'^ *' + re.escape(fence[0]) + '{' + str(len(fence)) + r',}\s*$', line):
                result.append({'language': language, 'code': ''.join(code)})
                opened, code = None, []
            else:
                removed = min(indent, len(line) - len(line.lstrip(' ')))
                code.append(line[removed:])
    if opened:
        raise ValueError('unclosed documentation fence')
    return result


def sources():
    return [ROOT / 'README.md', *sorted((ROOT / 'docs/src').rglob('*.md')), *sorted((ROOT / 'spec').glob('*.md'))]


def all_blocks():
    result = []
    for source in sources():
        for index, block in enumerate(blocks(source.read_text()), 1):
            result.append({'id': f'{source.relative_to(ROOT)}:{index}', **block})
    return result


def check_inventory(found, inventory):
    seen = set()
    for block in found:
        key = block['id']
        if key in seen:
            raise ValueError(f'duplicate block ID: {key}')
        seen.add(key)
        entry = inventory.get(key)
        if not entry:
            raise ValueError(f'unclassified documentation block: {key}')
        if entry['sha256'] != hashlib.sha256(block['code'].encode()).hexdigest():
            raise ValueError(f'changed documentation block: {key}; review classification')
        if entry.get('kind') not in KINDS:
            raise ValueError(f'unknown classification: {key}')
        if entry['kind'] == 'runnable':
            if not entry.get('runner'):
                raise ValueError(f'runnable block needs a runner: {key}')
            if not (ROOT / entry['runner']).is_file():
                raise ValueError(f'missing runner: {key}')
        elif not entry.get('reason'):
            raise ValueError(f'non-runnable block needs a reason: {key}')
    if set(inventory) != seen:
        raise ValueError(f'stale documentation blocks: {sorted(set(inventory) - seen)}')


def check():
    found = all_blocks()
    check_inventory(found, json.loads(INVENTORY.read_text()))
    print(f'{len(found)} documentation blocks classified; no drift')


if __name__ == '__main__':
    check()
