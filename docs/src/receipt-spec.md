# Decision Receipts

The full normative specification is at [`spec/hushspec-receipt.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-receipt.md). The format 0.2 schema is [`schemas/hushspec-receipt.v1.schema.json`](https://github.com/backbay-labs/hush/blob/main/schemas/hushspec-receipt.v1.schema.json); every SDK emits it, and `fixtures/receipts/expected/` holds the receipts every SDK must reproduce.

A receipt is the unit of compliance evidence: one JSON object per evaluation that records

- **which policy** was in force, by canonical content hash, with the `extends` chain and the signature verification outcome;
- **who** acted (`actor`: agent, session, principal, runtime);
- **what** was attempted (`action`: type and target, plus a hash and size of any content, never the content itself);
- **what was decided and why** (`decision`, `matched_rule`, `reason`);
- **which controls ran**, recorded during evaluation (`rule_trace`, `detection_trace`);
- **what the runtime did** with the decision (`enforcement`: enforce or monitor, allowed, confirmed, blocked, would_block);
- **when**, at millisecond precision, with a `time_source` that says how much to trust the clock.

Receipts have a canonical form and a hash of their own, so a log can chain them and a signer can sign them.

Vectors: `fixtures/receipts/valid/` must be accepted, `fixtures/receipts/invalid/` must be rejected.
