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
from hushspec import parse_or_raise, validate, evaluate

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
decision = evaluate(policy, {"type": "egress", "target": "api.github.com"})
assert decision.decision == "allow"
```

## HushGuard Middleware

`HushGuard` wraps policy loading and evaluation behind a simple interface.

```python
from hushspec import HushGuard

guard = HushGuard.from_file("./policy.yaml")

# Check without raising
result = guard.check({"type": "tool_call", "target": "bash"})
if result.decision == "deny":
    print(f"Blocked: {result.reason}")

# Or enforce (raises HushSpecDenied on deny)
guard.enforce({"type": "egress", "target": "api.openai.com"})
```

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
evaluation denies with `matched_rule` `__hushspec_policy_signature__` and
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

## Features

### Evaluation

```python
from hushspec import parse_or_raise, evaluate

spec = parse_or_raise(policy_yaml)
result = evaluate(spec, {"type": "egress", "target": "evil.example.com"})
# result.decision: "allow" | "warn" | "deny"
# result.matched_rule: "rules.egress.default"
```

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
from hushspec import FileReceiptSink, FilteredSink, MultiSink

sink = MultiSink([
    FileReceiptSink("/var/log/hushspec-receipts.jsonl"),
    FilteredSink(stderr_sink, lambda r: r.decision == "deny"),
])
```

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

The `h2h` CLI tool provides validate, lint, test, diff, format, sign, and more:

```bash
cargo install hushspec-cli
h2h validate policy.yaml
h2h lint policy.yaml
```

## License

Apache-2.0
