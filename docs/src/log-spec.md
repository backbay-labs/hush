# Receipt Log

The full normative specification is at [`spec/hushspec-log.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-log.md); the entry schema is [`schemas/hushspec-log-entry.v1.schema.json`](https://github.com/backbay-labs/hush/blob/main/schemas/hushspec-log-entry.v1.schema.json).

A log orders supplied evaluation records. Each JSON Lines entry carries a
sequence number, its predecessor's hash and its own canonical hash. An interior
edit, removal or reordering breaks continuity unless the following chain is
rewritten. Trusted signatures or an independently retained head are needed to
detect a wholesale rewrite; even signed entries alone cannot reveal a missing
tail. A valid prefix is not a complete history.

Entries wrap either a format 0.2 receipt or a **policy-in-effect record**
(`policy_loaded`, `policy_swapped`) naming the policy hash, inheritance chain and
signature status. These establish the producer's recorded policy order, not
independent proof that it mediated every real effect.

Writers flush every line, may sign every entry with the same Ed25519 envelope used for policies (the envelope's `content_hash` is the entry hash), and rotate files with a `log_started` entry that carries the chain across.

```bash
h2h eval policy.yaml --type egress --target api.github.com --log receipts.jsonl --log-key signing.key.pem
h2h log verify receipts.jsonl --keyring keyring.json --require-signatures
h2h receipts verify receipts.jsonl --policy policy.yaml
```

Vectors: `fixtures/log/valid/` must verify; each file under `fixtures/log/invalid/` breaks at the line its name ends with.

## Checks, reloads and rotation

Ordinary guards serialize policy adoption with in-flight checks, including
confirmation and sink recording. A check finishes recording under the old
policy before the swap event and later receipts. Reload can therefore wait;
it is not guaranteed to be nonblocking. Confirmation handlers and custom sinks
must not re-enter or wait on the same guard. Observers run after recording and
may re-enter. See [safe hot reload](guides/hot-reload.md).

Supply rotated files to `h2h log verify` in oldest-first order. The verifier
checks links between files as well as within them and reports the first failing
file and line. Preserve the complete rotation set and any independently trusted
start/end checkpoints; collecting only the newest file does not establish a
run's boundaries.

## Delivery is a separate guarantee

Ordinary guard sinks are best-effort: a write/export failure is reported as
`sink.error` and does not reverse the decision. An allowed decision with a sink
failure is not a durable authorization record. Monitor delivery failures, queue
drops and disk health, and document your application's response.

If dispatch must wait for a durable aggregate permit, evaluate the bounded
[trusted-invocation pilot](reference/trusted-invocation.md). Its journal,
checkpoint and terminal rules are experimental and distinct from this stable
log format. Never manufacture a terminal record to make an incomplete run pass.

See [reporting](guides/reporting.md) for the difference between aggregation and
authenticated, independently bounded evidence.
