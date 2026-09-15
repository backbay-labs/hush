# @hushspec/core

Agentic compliance as code: a portable, open specification for declaring, enforcing, and proving the security controls an AI agent operates under.

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
import { parseOrThrow, resolveWithOptions, evaluateAudited } from '@hushspec/core';

const resolution = resolveWithOptions(parseOrThrow(policyYaml));
const receipt = evaluateAudited(resolution, action, {
  enabled: true,
  includeRuleTrace: true,
  recordDuration: true,
});
// receipt.decision, receipt.rule_trace, receipt.policy.content_hash
```

## Evidence chain

A decision receipt proves one evaluation; a hash-linked log proves a sequence
of them. Together with receipt signing they are what an auditor is handed.

**Receipts** ([format 0.2](../../spec/hushspec-receipt.md)) record which
resolved policy was in force (by canonical content hash), who acted, what was
attempted, what the policy decided and why, which rule blocks and detectors
actually ran, and what the enforcement point did. A receipt never carries
action content -- only its `sha256:` hash and byte size -- so a receipt log is
safe to hand over. `receiptHash()` is `sha256:` over the receipt's RFC 8785
canonical form; it is what a log links and a signature covers.

**The log** ([format 0.1](../../spec/hushspec-log.md)) is JSON Lines. Each
entry names the previous entry's hash and carries its own, so an edited,
deleted, inserted or reordered line is detectable from the file alone.
`ChainedFileSink` is a `ReceiptSink`, so a guard writes one by construction,
and it also records `policy_loaded` / `policy_swapped` events -- a reader maps
every receipt to the policy in force by walking back to the nearest one.

```typescript
import { ChainedFileSink, HushGuard, verifyLogFiles } from '@hushspec/core';

const sink = ChainedFileSink.open('./audit.jsonl');
const guard = HushGuard.fromFile('./policy.yaml', {
  sink,
  actor: { agent_id: 'deploy-bot', session_id: run.id, principal: user.email },
});

guard.enforce({ type: 'egress', target: 'api.github.com' });

const report = verifyLogFiles(['./audit.jsonl']);
if (!report.ok) {
  // report.break names the file, 1-based line, and what failed there.
  throw new Error(`${report.break.file}:${report.break.line}: ${report.break.message}`);
}
```

**Signing.** Give the sink a key and every entry carries an Ed25519 envelope
over its `entry_hash`; pass a keyring to the verifier and every one is
checked. A single receipt can also be signed on its own:

```typescript
import { signReceipt, verifyReceipt, loadKeyring } from '@hushspec/core';

const signed = signReceipt(receipt, privateKeyPem, { signer: 'audit@example.com' });
const outcome = verifyReceipt(signed, { keyring: loadKeyring(keyringJson) });
// outcome.ok, or outcome.reason: 'content_hash_mismatch' when the receipt was edited
```

Rotation carries the chain forward: `sink.rotate('./audit-2.jsonl')` writes a
`log_started` entry naming the previous file's last hash, and
`verifyLogFiles([...])` checks the files in order. Truncation is not
detectable from a file alone (log spec section 9) -- publish `sink.head()`
periodically as an external anchor.

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
