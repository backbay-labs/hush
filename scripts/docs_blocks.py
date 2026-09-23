"""Inventory fenced examples. Every source edit requires classification review.

Use the CommonMark parser for nested lists/quotes and fences. The website's
Markdown AST checker independently compares the code-block inventory at export.
"""
import hashlib
import json
from pathlib import Path
from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = ROOT / 'docs/examples/blocks.json'
KINDS = {'runnable', 'fragment', 'operator-command', 'expected-output', 'negative', 'normative'}


def blocks(markdown):
    return [{'language':token.info.strip().split()[0] if token.info.strip() else '',
             'code':token.content}
            for token in MarkdownIt('commonmark').parse(markdown) if token.type=='fence']


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
