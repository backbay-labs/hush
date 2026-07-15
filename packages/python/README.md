# hushspec

Portable specification types for AI agent security rules.

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
from hushspec import parse_or_raise, evaluate_audited

receipt = evaluate_audited(spec, action, {
    "enabled": True,
    "include_rule_trace": True,
    "redact_content": False,
})
# receipt.decision, receipt.rule_evaluations, receipt.policy_summary
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
