# Decision receipt vectors

Normative vectors for [`spec/hushspec-receipt.md`](../../spec/hushspec-receipt.md), format 0.2.

- `valid/*.json` MUST be accepted by a conformant receipt parser and validate against the 0.2
  schema (`schemas/hushspec-receipt.v1.schema.json`).
- `invalid/*.json` MUST be rejected. Each file name says which rule it breaks; section 8 of the
  spec lists them.

Validate with any JSON Schema 2020-12 validator, for example:

```bash
python3 -c "
import json, glob, jsonschema
s = json.load(open('schemas/hushspec-receipt.v1.schema.json'))
v = jsonschema.Draft202012Validator(s)
for f in glob.glob('fixtures/receipts/valid/*.json'): v.validate(json.load(open(f)))
for f in glob.glob('fixtures/receipts/invalid/*.json'): assert not v.is_valid(json.load(open(f))), f
print('ok')"
```

The `content_hash` values inside the vectors are real canonical hashes (`rulesets/default.yaml`
and the minimal document) or clearly synthetic repeated-byte digests; receipts are validated
structurally here, not re-derived from an evaluation.

The Rust test `crates/hushspec/tests/receipt.rs` walks both directories. `expected/` holds the
receipt each SDK must produce for every shared evaluation fixture case under the fixed inputs
described in `expected/README.md`.
