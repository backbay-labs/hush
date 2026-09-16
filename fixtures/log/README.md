# Receipt log vectors

Normative vectors for [`spec/hushspec-log.md`](../../spec/hushspec-log.md), log-entry format 0.1.

- `valid/*.jsonl` MUST verify. `basic.jsonl` is a `policy_loaded` entry followed by three receipts;
  `signed.jsonl` is the same chain with every entry signed by the test key in
  `fixtures/signing/keys/`; `rotated-1.jsonl` and `rotated-2.jsonl` are one chain across a rotation
  and verify together in that order (`rotated-2.jsonl` also verifies alone from its `log_started` link).
- `invalid/*.jsonl` MUST be rejected, and a verifier MUST identify the line the file name ends with as
  the first break (`tampered-line-3`, `deleted-line-2`, `reordered-line-2`, `bad-prev-hash-line-2`,
  `bad-signature-line-4`). The signature vector needs the keyring; the others break without one.

Every entry was produced under the fixed inputs of `fixtures/receipts/expected/README.md` (clock
`2026-09-15T12:00:00.000Z`, deterministic receipt ids, the `default` builtin as the policy) so the
files are byte-stable. Generated and drift-checked by `crates/hushspec/tests/log_chain.rs`
(`HUSHSPEC_UPDATE_LOG_VECTORS=1` regenerates them).
