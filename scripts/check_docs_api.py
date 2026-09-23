#!/usr/bin/env python3
"""Pin easy-to-misread SDK contracts to source signatures and guide tables."""
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parent.parent


def check():
    table=(ROOT/'docs/src/reference/sdk-api.md').read_text()
    assertions=[
        ('packages/hushspec/src/middleware.ts', r'check\(action: EvaluationAction\): boolean', '`check` -> boolean'),
        ('packages/python/hushspec/middleware.py', r'def check\(self, action: EvaluationAction\) -> bool', '`check` -> bool'),
        ('packages/hushspec/src/middleware.ts', r'gate\(action: EvaluationAction\): GateOutcome', '`gate` -> `GateOutcome`'),
        ('packages/python/hushspec/middleware.py', r'def gate\(self, action: EvaluationAction\) -> GateOutcome', '`gate` -> `GateOutcome`'),
        ('packages/go/hushspec/guard.go', r'func \(g \*Guard\) Check\(ctx context.Context, action \*EvaluationAction\) \(GuardDecision, error\)', '`Check` -> `(GuardDecision, error)`'),
        ('packages/python/hushspec/provider.py', r'class HttpProvider:', '`HttpProvider`'),
        ('packages/go/hushspec/provider.go', r'func NewHTTPProvider\(', '`NewHTTPProvider`'),
        ('packages/go/hushspec/compiled.go', r'func CompilePolicy\(spec \*HushSpec\)', '`CompilePolicy` (takes `resolution.Spec`)'),
    ]
    for file, signature, text in assertions:
        assert re.search(signature,(ROOT/file).read_text()), f'source contract changed: {file}: {signature}'
        assert text in table, f'documentation contract missing: {text}'
    seen=set()
    for path in (ROOT/'docs/src').rglob('*.md'):
        for match in re.finditer(r'<!-- docs-file: ([a-z0-9-]+) ([a-z0-9/_.-]+) -->\s*```[^\n]+\n(.*?)```',path.read_text(),re.S):
            name, source, code=match.groups()
            assert name not in seen, f'duplicate runnable example ID: {name}'
            seen.add(name)
            assert code==(ROOT/source).read_text(), f'copied executable drift: {path}: {name}'
    assert len(seen)>=5, 'missing executable programs'
    print(f'{len(assertions)} source-checked API contracts')


if __name__=='__main__':
    check()
