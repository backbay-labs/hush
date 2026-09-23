# Receipt Log

The full normative specification is at [`spec/hushspec-log.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-log.md); the entry schema is [`schemas/hushspec-log-entry.v1.schema.json`](https://github.com/backbay-labs/hush/blob/main/schemas/hushspec-log-entry.v1.schema.json).

A receipt proves one evaluation. A log proves a sequence of them: it is a JSON Lines file whose entries each carry a sequence number, the previous entry's hash, and their own hash over their canonical form, so a verifier can detect an edited, deleted, inserted, or reordered line from the file alone. Entries wrap either a format 0.2 decision receipt or a **policy-in-effect record** (`policy_loaded`, `policy_swapped`) that names the policy by canonical content hash, its `extends` chain, and its signature status, so every receipt can be tied to exactly the policy that was enforced when it was written.

Writers flush every line, may sign every entry with the same Ed25519 envelope used for policies (the envelope's `content_hash` is the entry hash), and rotate files with a `log_started` entry that carries the chain across.

```bash
h2h eval policy.yaml --type egress --target api.github.com --log receipts.jsonl --log-key signing.key.pem
h2h log verify receipts.jsonl --keyring keyring.json --require-signatures
h2h receipts verify receipts.jsonl --policy policy.yaml
```

Vectors: `fixtures/log/valid/` must verify; each file under `fixtures/log/invalid/` breaks at the line its name ends with.
