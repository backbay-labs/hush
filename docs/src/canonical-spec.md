# Canonical Form

The full normative specification is at [`spec/hushspec-canonical.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-canonical.md).

Every resolved HushSpec policy has exactly one canonical form and one content hash, the same in every SDK:

1. **Projection.** Start from the resolved document (no `extends`, no `merge_strategy`). Inside every object that is present, materialize the JSON Schema defaults of absent fields. Omit empty containers for fields that have no default and where emptiness means the same as absence (an origins profile's `match: {}` is the one field where presence matters and is preserved).
2. **Serialization.** RFC 8785 (JCS): keys sorted by UTF-16 code units, no whitespace, ECMAScript number formatting (`10.0` becomes `10`), JCS string escapes.
3. **Hash.** `sha256:` followed by the lowercase hex SHA-256 of the UTF-8 canonical bytes.

The content hash is how receipts and signatures identify a policy. Reformatting a YAML file does not change it; changing a base policy in the `extends` chain does.

## Resolve before identifying

A file digest answers “which bytes did I download?” A canonical content hash
answers “which resolved policy did I evaluate?” Keep both when distributing a
policy: the first protects a particular artifact, while the second binds
portable evaluation and evidence. A digest pin on one inheritance hop is not
the same as the final resolved policy hash.

The hash includes the canonical document, including its metadata. It does not
identify a runtime binary, an authenticated user, the current filesystem or a
complete execution history. Pair it with those separately recorded identities
when making a claim about an agent run.

## Compute and compare

Computing it:

```bash
h2h hash policy.yaml                      # sha256:<64 hex>
h2h hash policy.yaml --format canonical   # the RFC 8785 text the digest covers
```

```rust
use hushspec::{canonical_json, content_hash};
// Both take a *resolved* document and refuse one that still declares `extends`.
let digest = content_hash(&resolved)?;
```

Reference implementation and vectors:

```bash
python3 scripts/canonical_json.py rulesets/default.yaml     # canonical JSON and digest
python3 scripts/canonical_json.py --check fixtures/core/hash # verify the normative vectors
```

Continue with [decision receipts](receipt-spec.md) to see where this identity
appears, or run the [evidence lab](signing-spec.md#run-the-evidence-lab).
