# Expected receipts

For every case of every shared evaluation fixture (`fixtures/*/evaluation/*.test.yaml`),
`<module>/<fixture stem>/<case index>.json` is the format 0.2 receipt a conformant SDK MUST
produce under the fixed inputs below. TypeScript, Python, and Go compare their own output with
these files byte for byte **after canonicalization** (RFC 8785), so pretty-printing and key
order in the files do not matter; every field value does.

Generated and drift-checked by `crates/hushspec/tests/receipt_expected.rs` (regenerate with
`HUSHSPEC_UPDATE_EXPECTED=1 cargo test -p hushspec --test receipt_expected` after a deliberate
change, and say why in the commit).

## Fixed inputs

| Input | Value |
|---|---|
| Policy | the fixture's inline `policy`, treated as already resolved (single-link resolution, so no `extends_chain`); `policy.content_hash` is its canonical content hash |
| Evaluation time | `2026-09-15T12:00:00.000Z` |
| `time_source` | `trusted` |
| `receipt_id` | UUID v7 whose 48-bit timestamp is the evaluation time in milliseconds (`1789473600000`) and whose 74 random bits are derived from the **0-based case index** exactly as `hushspec::deterministic_uuid_v7(1789473600000, index)` does: `rand_a` (12 bits) = `index & 0xfff`, `rand_b` (62 bits) = `index >> 12`, version nibble 7, variant `10` |
| `actor` | `agent_id: fixture-agent`, `session_id: fixture-session`, `principal: fixture@hushspec.dev`, `runtime: hushspec-conformance/0.2` |
| Enforcement | no enforcement point: `mode: enforce`, `outcome` implied by the decision (`allow` → `allowed`, `warn` and `deny` → `blocked`) |
| `duration_us` | omitted |
| Runtime context | the case's `context`, applied to the action when the action has none |
| Detection | the pipeline runs whenever the policy has a `detection:` extension; `detection_trace` is then present (possibly empty) |

## What the files pin

- `rule_trace`: every applicable block in evaluation order, engine stages first, with the
  closed `rule_block` ids of the receipt schema and `rule_path` where a rule produced the
  outcome.
- `action.origin` and `action.context`: the supplied descriptors as JSON objects with top-level
  members that are absent, `null`, `{}`, or `[]` removed (receipt spec 4.4, "verbatim", in the
  one form every typed model can reproduce).
- `action.content_hash` / `content_size` instead of content.
- `detection_trace` entries: `detector_id` (`<name>@1`), category, normalized score, level
  (`none` for 0, `low` below 0.25, then `suspicious` / `high` / `critical` at the 0.25 / 0.5 /
  0.75 floors), and `matched`.
