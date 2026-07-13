# @hushspec/core

Portable specification types for AI agent security rules.

`@hushspec/core` is the TypeScript SDK for the [HushSpec](https://github.com/backbay-labs/hush) open policy format. Parse, validate, evaluate, and enforce security rules for AI agent runtimes.

## Installation

```bash
npm install @hushspec/core
```

## Quick Start

```typescript
import { parseOrThrow, validate, evaluate } from '@hushspec/core';

const policy = parseOrThrow(`
hushspec: "0.1.0"
name: my-policy
rules:
  egress:
    allow: ["api.github.com"]
    block: []
    default: block
`);

// Validate
const result = validate(policy);
console.log(result.valid); // true

// Evaluate an action
const decision = evaluate(policy, { type: 'egress', target: 'api.github.com' });
console.log(decision.decision); // 'allow'
```

## HushGuard Middleware

`HushGuard` wraps policy loading and evaluation behind a simple interface for application code.

```typescript
import { HushGuard } from '@hushspec/core';

const guard = HushGuard.fromFile('./policy.yaml');

// Check without throwing
const result = guard.check({ type: 'tool_call', target: 'bash' });
if (result.decision === 'deny') {
  console.log('Blocked:', result.reason);
}

// Or enforce (throws HushSpecDenied on deny)
guard.enforce({ type: 'egress', target: 'api.openai.com' });
```

### Shadow / monitor mode

Roll out a policy without blocking anything: monitor mode evaluates every
action, records what *would* have been denied, and never throws. Escalate
individual rules to `enforce` as confidence grows.

```ts
import { HushGuard, FileReceiptSink } from '@hushspec/core';

const guard = HushGuard.fromFile('./policy.yaml', {
  enforcement: {
    mode: 'monitor',
    overrides: { 'rules.secret_patterns': 'enforce' }, // already trusted: block for real
  },
  sink: new FileReceiptSink('./receipts.jsonl'), // required: monitor must be observable
});

const outcome = guard.gate({ type: 'shell_command', target: 'rm -rf /' });
// outcome.proceed        -> true (monitor never blocks)
// outcome.result.decision -> 'deny' (the evaluated decision)
// outcome.enforcement    -> { mode: 'monitor', outcome: 'would_block' }
```

Receipts written by the sink carry `enforcement: { mode, outcome }` alongside
the evaluated `decision`. Panic mode always blocks, even under monitor.

## Features

### Evaluation

```typescript
import { parseOrThrow, evaluate } from '@hushspec/core';

const spec = parseOrThrow(policyYaml);
const result = evaluate(spec, { type: 'egress', target: 'evil.example.com' });
// result.decision: 'allow' | 'warn' | 'deny'
// result.matched_rule: 'rules.egress.default'
```

### Audit Trail

```typescript
import { parseOrThrow, evaluateAudited } from '@hushspec/core';

const receipt = evaluateAudited(spec, action, {
  enabled: true,
  include_rule_trace: true,
  redact_content: false,
});
// receipt.decision, receipt.rule_evaluations, receipt.policy_summary
```

### Detection Pipeline

Plug prompt injection, jailbreak, and exfiltration checks into the evaluation flow.

```typescript
import { evaluateWithDetection, DetectorRegistry } from '@hushspec/core';

const registry = DetectorRegistry.withDefaults();
const result = evaluateWithDetection(spec, action, registry, {
  enabled: true,
  prompt_injection_threshold: 0.5,
});
```

### Framework Adapters

Prebuilt adapters for Claude, OpenAI, and MCP tool calls.

```typescript
import { HushGuard, mapClaudeToolToAction } from '@hushspec/core';

const guard = HushGuard.fromFile('./policy.yaml');
const action = mapClaudeToolToAction(toolUseBlock);
guard.enforce(action);
```

### Hot Reload

```typescript
import { PolicyWatcher, HushGuard } from '@hushspec/core';

const guard = HushGuard.fromFile('./policy.yaml');
const watcher = new PolicyWatcher('./policy.yaml', {
  onChange: (newSpec) => guard.swapPolicy(newSpec),
});
watcher.start();
```

### Observability

```typescript
import { ObservableEvaluator, JsonLineObserver, MetricsCollector } from '@hushspec/core';

const evaluator = new ObservableEvaluator();
evaluator.addObserver(new JsonLineObserver(process.stderr));
evaluator.addObserver(new MetricsCollector());
```

### Panic Mode

```typescript
import { activatePanic, deactivatePanic, isPanicActive } from '@hushspec/core';

activatePanic();
// All evaluate() calls now return deny
deactivatePanic();
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
