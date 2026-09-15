# Canonical form vectors

Normative test vectors for [`spec/hushspec-canonical.md`](../../../spec/hushspec-canonical.md).
Each file conforms to [`schemas/hushspec-hash-vector.v0.schema.json`](../../../schemas/hushspec-hash-vector.v0.schema.json)
and pairs a **resolved** HushSpec document (`policy`) with the exact canonical JSON text
(`canonical`) and content hash (`content_hash`) a conformant implementation MUST produce.

The reference implementation that generated these files is
[`scripts/canonical_json.py`](../../../scripts/canonical_json.py). Verify the directory with:

```bash
python3 scripts/canonical_json.py --check fixtures/core/hash
```

Regenerate expectations after a deliberate spec change with `--fill` on the same path, and
say why in the commit message: every SDK must be updated in the same change.

## Status

No SDK test runner walks this directory yet. RFC 09 Wave 4 (P2-02) adds a hash-vector
runner to the Rust testkit and to the TypeScript, Python, and Go shared-fixture suites, and a
differential-test assertion that all four SDKs compute the same `content_hash` for every
generated policy.

## Vectors

| File | Spec section | Exercises |
|---|---|---|
| `minimal.yaml` | 3.1, 4 | Nothing to materialize at the top level. |
| `all-rule-blocks-defaults.yaml` | 3.2 | Every rule block present and empty: full default materialization. |
| `defaults-partial.yaml` | 3.2 | Defaults fill only absent fields; absent blocks are not invented. |
| `numbers.yaml` | 4.3 | Whole floats print as integers, fractions keep the shortest form. |
| `strings-escapes.yaml` | 4.2 | Every escape class; non-ASCII, U+2028, astral, DEL, NBSP are literal. |
| `key-order-utf16.yaml` | 4.1 | UTF-16 code-unit key order, including a surrogate-pair key. |
| `empty-containers.yaml` | 3.3 | Empty no-default containers are omitted. |
| `metadata-governance.yaml` | 3.1 | `metadata` is covered by the hash. |
| `when-conditions.yaml` | 3.2, 3.3 | `when` projection; `timezone` default; nested conditions. |
| `extension-posture.yaml` | 3.4 | Schema maps; required-but-empty arrays are kept. |
| `extension-origins.yaml` | 3.3, 3.4 | Presence-significant `match: {}` and overlay empties are preserved. |
| `extension-detection.yaml` | 3.4 | Detector defaults. |
| `extends-resolved.yaml` | 2.1 | Canonicalized after resolution; `source` is the unresolved child. |
