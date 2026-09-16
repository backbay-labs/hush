# hushspec

Agentic compliance as code: a portable, open specification for declaring, enforcing, and proving the security controls an AI agent operates under.

`hushspec` is the Python SDK for the [HushSpec](https://github.com/backbay-labs/hush) open policy format. Parse, validate, evaluate, and enforce security rules for AI agent runtimes.

## Installation

```bash
pip install hushspec
```

Requires Python 3.10+.

## Quick Start

```python
from hushspec import Decision, EvaluationAction, evaluate, parse_or_raise, validate

policy = parse_or_raise("""
hushspec: "0.1.0"
name: my-policy
rules:
  egress:
    allow: ["api.github.com"]
    block: []
    default: block
""")

# Validate
result = validate(policy)
assert result.is_valid

# Evaluate an action
outcome = evaluate(policy, EvaluationAction(type="egress", target="api.github.com"))
assert outcome.decision == Decision.ALLOW
```

## HushGuard Middleware

`HushGuard` wraps policy loading and evaluation behind a simple interface.

```python
from hushspec import Decision, EvaluationAction, HushGuard

guard = HushGuard.from_file("./policy.yaml")

# May the action proceed? `check` answers yes or no ...
if not guard.check(EvaluationAction(type="tool_call", target="bash")):
    print("Blocked")

# ... `gate` answers with the decision and what an enforcement point did
outcome = guard.gate(HushGuard.map_tool_call("bash"))
if outcome.result.decision == Decision.DENY:
    print(f"Blocked: {outcome.result.reason}")

# Or enforce (raises HushSpecDenied on deny)
guard.enforce(HushGuard.map_egress("api.openai.com"))
```

`HushGuard.map_egress`, `map_tool_call`, `map_file_read`, `map_file_write` and
`map_shell_command` build the action for the common cases.

### Shadow / monitor mode

Roll out a policy without blocking anything: monitor mode evaluates every
action, records what *would* have been denied, and never raises. Escalate
individual rules to `enforce` as confidence grows.

```python
from hushspec import EnforcementConfig, FileReceiptSink, HushGuard
from hushspec.evaluate import EvaluationAction

guard = HushGuard.from_file(
    "./policy.yaml",
    enforcement=EnforcementConfig(
        mode="monitor",
        overrides={"rules.secret_patterns": "enforce"},  # already trusted: block for real
    ),
    sink=FileReceiptSink("./receipts.jsonl"),  # required: monitor must be observable
)

outcome = guard.gate(EvaluationAction(type="shell_command", target="rm -rf /"))
# outcome.proceed              -> True (monitor never blocks)
# outcome.result.decision      -> Decision.DENY (the evaluated decision)
# outcome.enforcement.outcome  -> "would_block"
```

Receipts written by the sink carry `enforcement` (mode + outcome) alongside
the evaluated `decision`. Panic mode always blocks, even under monitor.

### Verify on load

A guard can refuse to enforce a policy it cannot prove. With
`require_signature`, every hop of the `extends` chain that is not a `builtin:`
ruleset must carry either a detached signature that verifies against the
trusted keys (`<policy>.yaml.sig`, see `h2h sign`) or a digest pin naming its
exact content hash.

```python
guard = HushGuard.from_file(
    "./policy.yaml",
    require_signature=True,
    trusted_keys=[open("release.pub.pem").read()],
)

guard.resolution.signature.verified   # True
guard.resolution.chain                # root first, leaf last, one hash per hop
```

If verification fails the guard does not raise -- it *refuses*: every
evaluation denies with `matched_rule` `__hushspec_policy_unverified__` and
`guard.refusal.reason` carries the reason code (`missing_signature`,
`unknown_key_id`, `content_hash_mismatch`, ...). Without `require_signature` a
keyring still buys opportunistic verification, recorded in
`guard.resolution.signature` and never blocking the load.

Pin a base by digest to get integrity without keys at all:

```yaml
extends: "./base.yaml#sha256:9f2c...<64 hex>"
```

A pin that no longer matches is always fatal, signatures configured or not.
`resolve_with_options()` exposes the same machinery without a guard.

### Policy providers and hot reload

A `PolicyProvider` is where a guard's policy comes from: `load()` returns a
`Resolution` -- the resolved document *and* the evidence gathered resolving it
-- so the chain hashes and signature outcome the provider proved are what every
receipt carries. `FileProvider` reads a file and resolves it against its own
directory, applying the `ResolveOptions` it was built with (including
`require_signature`) to **every** reload.

```python
from hushspec import FileProvider, HushGuard, ResolveOptions

provider = FileProvider("./policy.yaml", ResolveOptions(require_signature=True,
                                                        keyring=ring))
guard = HushGuard.from_provider(provider, watch=True, interval_s=1.0,
                                on_error=log.warning)
...
guard.watcher.stop()
```

`PolicyWatcher` stats the file each tick and reloads only when its bytes
actually change; `PolicyPoller` reloads on a fixed interval from any provider
(`CallbackProvider` wraps a callable for sources that are not files). Both run
on a daemon thread, work as context managers, and expose `check_once()` to
drive a tick by hand. Ticks are serialized, so a manual one and the loop's own
never interleave; `stop()` reports whether the thread actually finished.

Reload fails **safe**: a document that cannot be read, parsed, resolved,
verified, or compiled leaves the policy already in force untouched and is
reported through `on_error`, then retried on the next tick. Pass
`panic_sentinel=".hushspec_panic"` to consult the kill switch on every tick
(`h2h panic activate` writes that file).

### Agent adapters

`hushspec.adapters` maps a runtime's tool calls onto actions a policy can
evaluate, so built-in tools are checked against the rules that actually protect
the machine rather than as opaque tool calls:

```python
from hushspec.adapters import create_secure_tool_handler, map_claude_tool_to_action

action = map_claude_tool_to_action(block)   # a Claude `tool_use` content block
# bash -> shell_command, text editor -> file_read / file_write (with content),
# computer -> computer_use, web_fetch -> egress on the host, mcp__s__t -> tool_call

run_tool = create_secure_tool_handler(guard, my_handler)   # raises HushSpecDenied
```

Adapters for OpenAI (`map_openai_tool_call`), MCP (`map_mcp_tool_call`),
LangChain (`hush_tool`) and CrewAI (`secure_tool`) ship alongside it. None of
them import their SDK: blocks and calls are read structurally.

## Features

### Evaluation

```python
from hushspec import EvaluationAction, evaluate, parse_or_raise

spec = parse_or_raise(policy_yaml)
result = evaluate(spec, EvaluationAction(type="egress", target="evil.example.com"))
# result.decision: Decision.ALLOW | Decision.WARN | Decision.DENY
# result.matched_rule: "rules.egress.default"
```

### Compiled policies

`evaluate()` compiles the document on first use and reuses the result, so a
repeated call costs no compilation. A long-lived enforcement point should hold
the compiled policy itself:

```python
from hushspec import compile_policy, parse_or_raise

compiled = compile_policy(parse_or_raise(policy_yaml))
result = compiled.evaluate(action)
```

`compile_policy()` prepares everything that does not depend on the action --
every regex, path glob and host matcher, the `when` conditions, the
per-action-type rule-block plan, the origin overlays, and the detectors a
`detection:` block enables -- and keeps the source document for receipts and
hashing (`compiled.spec`, `compiled.content_hash`). It accepts a `Resolution`
as well as a `HushSpec`, and carries that provenance into
`compiled.evaluate_audited(action)`.

It is strict by default: a pattern outside the [regex profile](../../spec/)
raises `CompileError` naming the rule path, rather than waiting for the first
action that reaches it. `compile_policy(spec, strict=False)` keeps the
evaluator's deferred behaviour instead -- the offending pattern is recorded in
`compiled.errors` and denies the actions that reach it.

`HushGuard` compiles once at construction and on every `swap_policy()`;
`guard.compiled` is the policy it is enforcing.

`packages/python/bench/evaluate.py` measures it.

### Audit Trail

```python
from hushspec import AuditConfig, Resolution, evaluate_audited, parse_or_raise

resolution = Resolution.from_resolved(spec)
receipt = evaluate_audited(resolution, action, AuditConfig())
# receipt.decision, receipt.rule_trace, receipt.policy.content_hash
```

### Detection Pipeline

Content detection is spec-driven: add a `detection:` block under `extensions:` in
the policy (`prompt_injection` and/or `jailbreak`) and `evaluate_with_detection`
folds the built-in regex detectors' verdict into the evaluation automatically.
It's an exact no-op for policies without a `detection:` extension.

```python
from hushspec import evaluate_with_detection

result = evaluate_with_detection(spec, action)
# result.evaluation: the final EvaluationResult (matched_rule == "detection"
#   when content flagged by a detector escalated the decision)
# result.detections: the DetectionResult produced by each detector that ran
# result.detection_decision: None | "warn" | "deny"
```

### Receipt Sinks

Route decision receipts to files, stderr, or custom callbacks.

```python
from hushspec import FileReceiptSink, FilteredSink, MultiSink, StderrReceiptSink

sink = MultiSink(
    [
        FileReceiptSink("/var/log/hushspec-receipts.jsonl"),
        FilteredSink.deny_only(StderrReceiptSink()),
    ],
    on_error=lambda sink, exc: log.warning("receipt sink %r failed: %s", sink, exc),
)
```

`FilteredSink(inner, ["deny", "warn"])` passes on the decisions you name;
`deny_only` is the common case. A sink that raises never breaks enforcement:
`MultiSink` counts the loss in `sink.dropped` and reports it through
`on_error`.

### OTLP export

`OtlpReceiptSink` ships receipts and policy events to any OpenTelemetry
collector as OTLP/HTTP log records (`POST <endpoint>/v1/logs`), using only the
standard library. The body of each record is the entry's *canonical* JSON --
the exact bytes its hash covers -- so evidence stays verifiable after the trip,
and the facts a dashboard filters on are lifted into attributes.

```python
from hushspec import HushGuard, OtlpReceiptSink

sink = OtlpReceiptSink(
    "http://localhost:4318",
    headers={"x-api-key": "..."},
    service_name="checkout-agent",
)
guard = HushGuard.from_file("policy.yaml", sink=sink)
...
sink.close()      # flushes what is queued
```

| Field | Value |
|---|---|
| `timeUnixNano` | The receipt's or event's own `timestamp` |
| `observedTimeUnixNano` | When the sink took the entry |
| `severityText` / `severityNumber` | `INFO`/9 allow, `WARN`/13 warn, `ERROR`/17 deny (`INFO`/9 for policy events) |
| `body.stringValue` | canonical JSON of the receipt or policy event |
| attributes | `hushspec.entry_type` (`receipt`/`policy_loaded`/`policy_swapped`), `hushspec.receipt_version`, `hushspec.decision`, `hushspec.action_type`, `hushspec.matched_rule`, `hushspec.policy.content_hash`, `hushspec.receipt_hash`, `hushspec.enforcement.mode`, `hushspec.enforcement.outcome` |
| resource | `service.name`, `hushspec.sdk`, `hushspec.sdk.version`, `hushspec.spec_version` |

Export runs on a daemon thread: `send()` never blocks on I/O, batches are
retried with backoff on network errors and `5xx`, and when the bounded queue
(`max_queue`) fills, records are dropped, counted in `sink.dropped`, and
reported through `on_error` -- telemetry is never allowed to stall enforcement.
The same mapping ships in all four SDKs.

### Evidence chain

A receipt proves one evaluation; a hash-linked log proves a sequence of them.
`ChainedFileSink` writes format 0.2 receipts as JSON Lines, each entry carrying
the previous entry's hash, so an auditor can see that nothing was edited,
deleted, inserted, or reordered. A guard also records which policy came into
force, and when it was swapped, so every receipt maps back to the exact
document that produced it.

```python
from hushspec import ChainedFileSink, HushGuard, verify_log_files
from hushspec.receipt import Actor

sink = ChainedFileSink.open("/var/log/hushspec.jsonl")
guard = HushGuard.from_file(
    "policy.yaml",
    sink=sink,
    actor=Actor(agent_id="deploy-bot-3", session_id="run-42"),
)
guard.check(HushGuard.map_egress("api.example.com"))

report = verify_log_files(["/var/log/hushspec.jsonl"])
# report.entries / .receipts / .policy_events / .last_entry_hash
```

Hold a signing key and every entry is signed too (`sink.with_signer(pem)`);
`verify_log_files(..., LogVerifyOptions(require_signatures=True, keyring=ring))`
then checks each one and reports the first break by line. Rotate with
`sink.rotate("next.jsonl")`, which carries the chain across files.

A receipt can also be signed on its own -- the envelope covers the receipt hash,
so the receipt's own identity is the same whether or not it was ever signed:

```python
from hushspec.signing import sign_receipt, verify_receipt

signed = sign_receipt(receipt, private_key_pem)
result = verify_receipt(signed, keyring=keyring)   # result.valid, result.reason
```

Both need the `signing` extra (`pip install "hushspec[signing]"`); without it
they raise `SigningUnavailable` rather than returning an unchecked answer.

### Panic Mode

```python
from hushspec import activate_panic, deactivate_panic, is_panic_active

activate_panic()
# All evaluate() calls now return deny
deactivate_panic()
```

## CLI

`h2h` -- validate, lint, test, diff, format, sign and more -- is a separate
distribution, not a console script of this package. See the
[repository](https://github.com/backbay-labs/hush) for the install options.

```bash
h2h validate policy.yaml
h2h lint policy.yaml
```

## License

Apache-2.0
