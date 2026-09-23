# Troubleshooting

Start with the exact CLI/SDK version, policy source revision and diagnostic.
Do not paste private keys, raw tool arguments or sensitive receipt context
into an issue. Preserve failing evidence before attempting repair.

## YAML or version is rejected

Run `h2h validate --format json policy.yaml`. `E001` includes malformed YAML,
unknown fields and unsupported YAML constructs; `E002` means an unsupported
specification version. Quote `hushspec: "1.0.0"`; remove duplicate keys and
aliases rather than relying on a permissive YAML parser. `E004` names a schema
constraint, not a request to silently coerce the value. Compare the
[error reference](../reference/errors.md) and the release schema.

## Inheritance loads the wrong policy or fails

Run `h2h validate --strict policy.yaml`, then `h2h resolve policy.yaml` and
`h2h hash policy.yaml`. `E010` covers resolution failures such as a missing
base, cycle or depth limit. Check the relative path from the referring file,
the `builtin:` prefix and any `#sha256:` pin. Review the resolved result; a
successful leaf parse says nothing about a missing base.

## An allowed-looking call is denied

Use `h2h explain policy.yaml --type file_read --target /workspace/example.txt`
with the exact mapped action. Inspect all applicable blocks: an allow from one
rule does not override another block's deny. Missing runtime context leaves an
unevaluable condition active. Unknown actions deny. Check lexical pattern
grammar and the host's trusted action mapping before widening the policy.

## A warning does not execute

`warn` requires a real confirmation channel. Without one, a guard blocks it;
the CLI reports the warning with exit 4 but does not execute the described tool.
Inspect `enforcement.outcome` and verify that the host branches before dispatch.
Do not replace the condition with `decision != deny`.

## Signature or key verification fails

Run `h2h verify policy.yaml --keyring keyring.json --format json`. Failure JSON
is on stderr and contains `reason`/`detail`. `unknown_key_id` means the signer
is not in the selected trust set; `content_hash_mismatch` means the resolved
policy differs; `signature_mismatch` means signed claims/signature disagree.
`expired`, `key_retired`, `key_revoked` and `policy_version_rollback` require
trust or rollout investigation, not disabling checks. See [signing](../signing-spec.md).

## Reload appears stuck or keeps an older policy

First run `h2h validate --strict candidate.yaml` and `h2h verify candidate.yaml
--keyring keyring.json` when signatures are required. Then inspect provider
errors, the active hash and any in-flight confirmation/sink. Reload waits for
checks to finish; callbacks must not re-enter or wait on the same guard.
A rejected ordinary reload deliberately preserves the last good policy.
See [hot reload](hot-reload.md) for lifecycle and shutdown rules.

## HTTPS or DNS loading fails

Check the configured hostname allowlist, provider diagnostic, certificate,
timeout and response size. Resolve redirects at the publication source; loaders
do not follow them. Reserved/private resolved addresses are rejected by the
bounded loader even when the hostname text looks public. Validate an
independently downloaded local candidate with `h2h validate --strict candidate.yaml`
to separate policy syntax from transport failure. Do not weaken the live loader
or fetch a model-supplied URL as a troubleshooting shortcut.

## A log or evidence packet is incomplete

Run `h2h log verify oldest.jsonl newest.jsonl --keyring keyring.json
--require-signatures` in the actual rotation order. A break reports file and
line. A valid prefix without trusted endpoints is not complete; strict evidence
without an independent inventory reports `not-established`.

For the invocation pilot, verify the packet with its independently retained
trust file. A missing terminal leaves the effect unknown: reconcile independent
server/file observations, retain the incomplete packet, and start a new stream
under operator control. Never append a guessed success or retry a possibly
completed effect merely to obtain a green verifier result.

## Reporting fails without output

Strict evidence diagnostics distinguish integrity failures (exit 1) from
configuration, bounds and I/O failures (exit 2). Use a new output filename in an
existing operator-controlled directory. Preserve input bytes and inspect the
diagnostic's artifact/line; do not use `--lenient` or `--unverified` as a strict
verification fallback. See [evidence verification](evidence-verification.md).
