# Decision Receipts

The full normative specification is at [`spec/hushspec-receipt.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-receipt.md). The format 0.2 schema is [`schemas/hushspec-receipt.v1.schema.json`](https://github.com/backbay-labs/hush/blob/main/schemas/hushspec-receipt.v1.schema.json); every SDK emits it, and `fixtures/receipts/expected/` holds the receipts every SDK must reproduce.

A receipt is a record of one evaluation, not proof that every side effect was
intercepted. It records

- **which policy** was in force, by canonical content hash, with the `extends` chain and the signature verification outcome;
- **who** acted (`actor`: agent, session, principal, runtime);
- **what** was attempted (`action`: type and target, plus a hash and size of any content, never the content itself);
- **what was decided and why** (`decision`, `matched_rule`, `reason`);
- **which controls ran**, recorded during evaluation (`rule_trace`, `detection_trace`);
- **what disposition the producer reports** (`enforcement`: enforce or monitor, allowed, confirmed, blocked, would_block);
- **when**, at millisecond precision, with a `time_source` that says how much to trust the clock.

Receipts have a canonical form and a hash of their own, so a log can chain them and a signer can sign them.

Vectors: `fixtures/receipts/valid/` must be accepted, `fixtures/receipts/invalid/` must be rejected.

## Read a receipt without overclaiming

| Field | What to inspect | What it does not prove |
|---|---|---|
| `policy.content_hash` | Compare with your expected resolved policy hash | That the signer was authorized to choose that policy |
| `policy.signature` | Recorded load-time verification result, if present | Fresh verification under your current trust roots |
| `actor` | Host-supplied agent, session, principal and runtime descriptors | Authentication merely because a string is present |
| `action` | Mapped action and target; content hash/size where applicable | Every effect of an opaque tool or the original content |
| `rule_trace` | Evaluated and skipped rule blocks in recorded order | A later reconstruction of the actual execution |
| `enforcement.outcome` | `blocked`, `allowed`, `confirmed` or `would_block` | Successful completion of an allowed side effect |
| `timestamp`, `time_source` | The producer's clock and its declared trust | An independent trusted timestamp |

`warn` is the policy decision; confirmation is an enforcement disposition.
Without a confirmation handler, a guard blocks a warning. In monitor mode,
`would_block` records observation while allowing progress. See
[runtime integration](guides/runtime-integration.md) for the caller contract.

## Verify and retain

Use `h2h receipts verify receipt.json --policy policy.yaml` for schema, policy
association and replayable decisions. Add `--keyring` and
`--require-signatures` when your inputs are signed receipt envelopes. A
signature on a surrounding log entry is a different artifact; verify that with
`h2h log verify`. Content-dependent decisions cannot be reconstructed from a
content digest alone.

Retain source bytes, policy artifacts and independently distributed trust
inputs. A receipt hash detects changes only when the expected hash is trusted;
an untrusted hash shipped beside the receipt adds no authentication.

## A real-schema example

The example below was emitted by `h2h 1.0.0` for the
[quickstart policy](https://hushspec.org/docs-examples/quickstart/policy.yaml). It is synthetic test
evidence, not a production event. Its timestamp and duration describe that
sample invocation; tests validate its schema and recheck the policy, action,
decision, trace and enforcement fields against a fresh evaluation.

The CLI evaluates an action description; it does not open `/workspace/.env`.
Here `blocked` is the disposition associated with that denied evaluation.
An integrating runtime must still branch before its actual file operation.

Download the [complete receipt](https://hushspec.org/docs-examples/evidence/receipt.json).

<!-- docs-file: evidence-receipt docs/examples/evidence/receipt.json -->
```json
{
  "receipt_version": "0.2",
  "receipt_id": "01a0d04d-88de-7550-af3c-5b12e1791d93",
  "timestamp": "2026-09-23T22:05:37.374Z",
  "time_source": "system",
  "actor": {
    "runtime": "h2h/1.0.0"
  },
  "policy": {
    "name": "coding-agent-quickstart",
    "spec_version": "1.0.0",
    "content_hash": "sha256:f07d08f7594f1cc97dbf0ae224260a2581eec45797edc83d7dd9439ff46cfedf"
  },
  "action": {
    "type": "file_read",
    "target": "/workspace/.env"
  },
  "decision": "deny",
  "matched_rule": "rules.forbidden_paths.patterns",
  "reason": "path matched a forbidden pattern",
  "rule_trace": [
    {
      "rule_block": "forbidden_paths",
      "rule_path": "rules.forbidden_paths.patterns",
      "outcome": "deny",
      "evaluated": true,
      "reason": "path matched a forbidden pattern"
    },
    {
      "rule_block": "path_allowlist",
      "outcome": "skip",
      "evaluated": false,
      "reason": "no path_allowlist rule configured"
    }
  ],
  "enforcement": {
    "mode": "enforce",
    "outcome": "blocked"
  },
  "duration_us": 10
}
```
