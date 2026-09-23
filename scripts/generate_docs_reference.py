#!/usr/bin/env python3
"""Generate reader inventories from the release registries and schema files."""
import json
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / 'docs/src/reference'


def generate():
    errors = yaml.safe_load((ROOT / 'spec/registries/error-codes.yaml').read_text())['codes']
    text = '# Error reference\n\nUse the code and the failing field, not only the exit status. `E004` means a\nconstraint violation; `E005` means a pattern is outside the portable regex profile.\n\n```sh\nh2h validate --format json policy.yaml\n```\n\n## Registered errors\n\nGenerated from the [error registry](../../../spec/registries/error-codes.yaml).\nA parser that reports registry codes must use their registered meaning.\n\n| Code | Summary | Phase | Meaning |\n| --- | --- | --- | --- |\n'
    for e in errors:
        text += f"| `{e['code']}` | {e['summary']} | {e.get('phase', '')} | {e['description'].strip().replace(chr(10), ' ').replace('|', '&#124;')} |\n"
    text += '\n## Next diagnostic\n\nFor syntax/type failures, reduce to the smallest invalid field; do not strip\nunknown security fields to make a policy load. For resolution or signing\nfailures, retain the last known-good policy and inspect the load reason. See\n[troubleshooting](../guides/troubleshooting.md) and [signing](../signing-spec.md).\n'
    (OUT / 'errors.md').write_text(text)
    text = '# Registries\n\nRegistries define portable vocabulary, not permission to extend a closed object.\nAn unknown action is denied; an unknown document field is rejected. Capability\nextensions are separately described by the posture specification.\n\n## Published inventory\n\n| Registry | Download | Role |\n| --- | --- | --- |\n'
    for p in sorted((ROOT / 'spec/registries').glob('*.yaml')):
        data = yaml.safe_load(p.read_text())
        values = data.get('entries', data.get('codes', []))
        role = 'Closed portable vocabulary' if data.get('status') == 'closed' else 'Registered identifiers and compatibility rules'
        text += f'| [{p.stem}](../../../spec/registries/{p.name}) | [YAML](https://hushspec.org/registries/{p.name}) | {role} |\n'
        if values and isinstance(values, list):
            pass
    text += '\n## Version and ownership\n\nA registry can retain its original registry version while shipping in HushSpec\nv1. Read the registry header for its extension policy. Do not infer that an\narbitrary capability, detector or framework is supported merely because a\nstring fits its identifier grammar. [Conformance](conformance.md) is a separate\nclaim about behavior against a named corpus.\n'
    (OUT / 'registries.md').write_text(text)
    target = OUT / 'json-schema.md'
    existing = target.read_text().split('\n<!-- generated-schema-inventory -->')[0].rstrip()
    rows = '\n\n<!-- generated-schema-inventory -->\n## Complete Published Schema Inventory\n\nGenerated from release schema identities. Frozen v0 IDs retain `hushspec.dev`;\nretrieval mirrors are served on `hushspec.org`. The [JSON index](https://hushspec.org/schemas/index.json) carries every byte digest.\n\n| Schema | Declared identity |\n| --- | --- |\n'
    for p in sorted((ROOT / 'schemas').glob('hushspec-*.schema.json')):
        data = json.loads(p.read_text())
        rows += f"| [{p.name}](https://hushspec.org/schemas/{p.name}) | `{data['$id']}` |\n"
    target.write_text(existing+rows)


if __name__ == '__main__':
    generate()
