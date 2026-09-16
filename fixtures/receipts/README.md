# Decision receipt vectors

Normative vectors for [`spec/hushspec-receipt.md`](../../spec/hushspec-receipt.md), format 0.2.

- `valid/*.json` MUST be accepted by a conformant receipt parser and validate against the 0.2
  schema (`schemas/staged/0.2.0/hushspec-receipt.v0.schema.json` until RFC 09 P2-04 promotes it
  to `schemas/`).
- `invalid/*.json` MUST be rejected. Each file name says which rule it breaks; section 8 of the
  spec lists them.

Validate with any JSON Schema 2020-12 validator, for example:

```bash
python3 -c "
import json, glob, jsonschema
s = json.load(open('schemas/staged/0.2.0/hushspec-receipt.v0.schema.json'))
v = jsonschema.Draft202012Validator(s)
for f in glob.glob('fixtures/receipts/valid/*.json'): v.validate(json.load(open(f)))
for f in glob.glob('fixtures/receipts/invalid/*.json'): assert not v.is_valid(json.load(open(f))), f
print('ok')"
```

The `content_hash` values inside the vectors are real canonical hashes (`rulesets/default.yaml`
and the minimal document) or clearly synthetic repeated-byte digests; receipts are validated
structurally here, not re-derived from an evaluation.

No SDK runner walks this directory until P2-04, which also brings the SDKs' receipt output to
format 0.2.
