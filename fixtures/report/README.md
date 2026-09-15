# Evidence report vectors

Vectors for `h2h report` (RFC 09 P3-01) and
[`schemas/hushspec-report.v0.schema.json`](../../schemas/hushspec-report.v0.schema.json).

- `24h.jsonl` is a synthetic working day: a hash-linked log
  ([log spec](../../spec/hushspec-log.md)) of 20 entries -- a `policy_loaded`
  record at 00:00, 16 receipts evaluated under
  [`library/healthcare/hipaa-base.yaml`](../../library/healthcare/hipaa-base.yaml)
  between 01:05 and 16:10, a `policy_swapped` record at 18:00, and 2 receipts
  under `builtin:default` after it. Two actors
  (`clinical-assistant`/`session-alpha` and `ops-assistant`/`session-beta`),
  two receipts recorded in monitor mode, and one warn confirmed by a human.
- `expected-report.json` is the document
  `h2h report fixtures/report/24h.jsonl --policy library/healthcare/hipaa-base.yaml
  --format json --now 2026-09-16T00:00:00Z` must produce, byte for byte.

Both files are generated and drift-checked by
`crates/hushspec-cli/tests/report_tests.rs`
(`HUSHSPEC_UPDATE_REPORT_VECTORS=1` regenerates them after a deliberate
change). Every case in that test's table carries the decision a reader of the
policy expects, asserted as the log is written, so the report's totals are the
sum of a table a human wrote: **6 allow, 2 warn, 10 deny**, dispositioned as 6
`allowed`, 1 `confirmed`, 9 `blocked`, 2 `would_block`.

The log is byte-stable on every machine: fixed receipt ids
(`deterministic_uuid_v7`), fixed clocks, no `duration_us`, and policies wrapped
with `Resolution::from_resolved` so a chain link names
`library/healthcare/hipaa-base.yaml` rather than the checkout's absolute path.
