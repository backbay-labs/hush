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

Hash-vector runners (RFC 09 P2-02), one per SDK:

- Rust: `cargo test -p hushspec --test canonical_vectors`, plus the testkit's `hash`
  category (`cargo run -p hushspec-testkit --bin hushspec-testkit -- --fixtures fixtures`).
- TypeScript, Python, Go: their shared-fixture suites.

`hushspec-difftest` additionally compares the `content_hash` all four SDKs report for
every generated policy; `--ignore-content-hash` opts out of that comparison.

## Canonicalize from the document tree, not from typed structs

Project the vector's `policy` as a generic tree of maps, arrays and scalars, the way
[canonical spec section 6](../../../spec/hushspec-canonical.md) recommends. Two vectors
cannot be reproduced any other way:

- `extension-origins.yaml` writes `tool_access: {allow: []}` and `egress: {block: []}`,
  which section 3.3 marks presence-significant. Every SDK models those overlay lists as a
  plain list, so parsing collapses "written empty" into "absent" and the projection can no
  longer tell them apart.
- `extension-posture.yaml` uses posture triggers (`secret_detected`, `operator_reset`)
  outside the `PostureTransition.on` enum, so a typed parse rejects it outright.

Those same two policies are *not* valid HushSpec documents, and section 2.3 says only valid
documents have a canonical form. The reference canonicalizer performs no validation (a
documented limit of `scripts/canonical_json.py`), which is why it produced them. A tool that
validates first -- `h2h hash`, for instance -- therefore rejects both, by design. Fixing the
two vectors means regenerating them with `--fill` and updating all four SDKs in the same
change.

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
