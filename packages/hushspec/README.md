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
# yaml-language-server: $schema=https://hushspec.dev/schemas/hushspec-core.v1.schema.json
hushspec: "1.0.0"
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

// May this action proceed? (boolean, never throws)
if (!guard.check({ type: 'tool_call', target: 'bash' })) {
  console.log('Blocked');
}

// The decision and the disposition behind it
const { result, proceed } = guard.gate({ type: 'tool_call', target: 'bash' });
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

### Compiled policies

`evaluate()` compiles the document on first use and caches the compilation
against the document object, so nothing changes for a caller that holds one
policy. Compile explicitly to own that step -- and to learn about a pattern
outside the [regex profile](../../spec/hushspec-core.md) before an action
does, rather than as a fail-closed deny at evaluation time:

```typescript
import { compilePolicy, CompileError, parseOrThrow } from '@hushspec/core';

const compiled = compilePolicy(parseOrThrow(policyYaml)); // throws CompileError
compiled.evaluate({ type: 'egress', target: 'evil.example.com' });
compiled.evaluateTraced(action);
compiled.evaluateWithDetection(action);
compiled.evaluateAudited(action); // a receipt, against compiled.resolution
compiled.contentHash; // canonical `sha256:...`, computed once
```

Every regex, path glob, host pattern, tool list, `when` condition and severity
table is built once at compile time, so an evaluation is matching and nothing
else. `HushGuard` compiles at construction and on `swapPolicy()`, and exposes
the result as `guard.compiled`. `npm run bench` (in `packages/hushspec`)
measures the difference on `rulesets/default.yaml`.

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
if (report.break) {
  // The first break: the file, the 1-based line, and what failed there.
  const { file, line, message } = report.break;
  throw new Error(`${file}:${line}: ${message}`);
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

### Policy bundles

A receipt says what one decision was; a bundle says which policy was in force
when it was made. `createBundle` attests a *resolved* policy -- the document
after `extends` has been followed -- as a DSSE envelope carrying an in-toto
statement: the content hash, the chain it was resolved from, and the resolver
that did it.

```typescript
import {
  createBundle,
  bundleToJson,
  verifyBundle,
  parseOrThrow,
  resolveWithOptions,
  createCompositeLoader,
} from '@hushspec/core';

// `createBundle` takes a Resolution -- the resolved document plus the chain
// it came from -- not a bare policy.
const resolution = resolveWithOptions(parseOrThrow(readFileSync('./policy.yaml', 'utf8')), {
  source: './policy.yaml',
  loader: createCompositeLoader(),
});

const bundle = createBundle(resolution, { privateKeyPem });

writeFileSync('./policy.bundle.json', bundleToJson(bundle));

const outcome = verifyBundle(bundle, { keyring, policy: resolution });
// outcome.ok, or outcome.reason: 'content_hash_mismatch' when the bundle
// attests a different policy than the one passed in
```

Creation is reproducible: two bundlers given the same resolution, the same
`createdAt`, and the same resolver produce byte-identical bundles, Ed25519
being deterministic. That is what pins this SDK against the reference CLI's
published vectors. Omit `privateKeyPem` for an unsigned bundle -- useful for
inspecting a statement, though `verifyBundle` refuses one.

`resolver.tool` defaults to this SDK rather than to `BUNDLE_RESOLVER_TOOL`
(`'h2h'`, the reference CLI), so a bundle always names what actually produced
it; pass `tool` and `version` to override.

### OTLP export

`OtlpReceiptSink` is a `ReceiptSink` that exports receipts and
`policy_loaded` / `policy_swapped` events to an OpenTelemetry collector as
OTLP/HTTP **logs** in JSON encoding (`POST <endpoint>/v1/logs`). It uses
`node:http` / `node:https` directly, so the SDK takes no OpenTelemetry
dependency and an application that already runs the OTel SDK is unaffected.

```typescript
import { HushGuard, OtlpReceiptSink } from '@hushspec/core';

const sink = new OtlpReceiptSink({
  endpoint: 'http://localhost:4318',
  headers: { authorization: `Bearer ${process.env.OTEL_TOKEN}` },
  serviceName: 'deploy-bot',
  batchSize: 64,
  flushIntervalMs: 5_000,
  maxQueue: 2_048,
  onError: err => console.error('[hushspec] receipt export failed', err),
});

const guard = HushGuard.fromFile('./policy.yaml', { sink });
guard.enforce({ type: 'egress', target: 'api.github.com' });

await sink.close(); // flushes the backlog, then refuses further entries
```

One `logRecord` per entry, with the wire mapping every HushSpec SDK emits:

| OTLP field | Value |
|---|---|
| `timeUnixNano` | The receipt's or event's own `timestamp` |
| `observedTimeUnixNano` | When the sink took the entry |
| `severityText` / `severityNumber` | `INFO`/9 for `allow`, `WARN`/13 for `warn`, `ERROR`/17 for `deny`; a policy event is `INFO`/9 |
| `body.stringValue` | The entry's RFC 8785 canonical JSON -- byte for byte the form its hash covers |
| attributes | `hushspec.entry_type` (`receipt`, `policy_loaded`, `policy_swapped`), `hushspec.receipt_version`, `hushspec.decision`, `hushspec.action_type`, `hushspec.matched_rule`, `hushspec.policy.content_hash`, `hushspec.receipt_hash`, `hushspec.enforcement.mode`, `hushspec.enforcement.outcome` |
| resource attributes | `service.name` (default `hushspec`), `hushspec.sdk`, `hushspec.sdk.version`, `hushspec.spec_version` |

`send()` never blocks and never throws: entries go onto a bounded queue and
leave on a background chain, batched by size or by timer, retried with
exponential backoff on a network failure and on 429, 502, 503 and 504. Every
other status is final. A full queue drops the incoming entry, counts it
(`sink.dropped`) and reports it through `onError` --
latency is never paid for in the evaluation path, and a lost receipt is never
silent. Pair it with `MultiSink` and a `ChainedFileSink` when the collector is
a convenience and the file is the evidence.

### Detection Pipeline

Prompt injection, jailbreak and exfiltration checks run as part of evaluation
whenever the policy carries a `detection:` extension. The extension configures
them; there is nothing to wire up in code.

```yaml
extensions:
  detection:
    prompt_injection:
      warn_at_or_above: suspicious
      block_at_or_above: high
    jailbreak:
      warn_threshold: 50
      block_threshold: 80
```

```typescript
import { evaluateWithDetection } from '@hushspec/core';

const { evaluation, detections, detectionDecision } = evaluateWithDetection(spec, action);
// evaluation.decision  -> the decision to act on, detection folded in
// detections           -> each detector's score and matched patterns
// detectionDecision    -> what detection alone contributed, if anything
```

Detection can escalate an allow or a warn but never weakens a policy deny.
`HushGuard`'s `evaluate()`, `check()`, `gate()` and `enforce()` all route
through the same pipeline, and a receipt records what ran in
`detection_trace`. Register a custom `Detector` with `DetectorRegistry` to
score input outside the built-in set.

### Framework Adapters

Adapters map a framework's tool call onto an `EvaluationAction` so a policy
sees file, shell and egress actions rather than an opaque tool name. All of
them are structurally typed -- no adapter imports the framework it adapts, so
none of them is a dependency.

| Framework | Mapping | Enforcement |
|---|---|---|
| Anthropic | `mapClaudeToolToAction(name, input)` | `createSecureToolHandler(guard)` |
| OpenAI | `mapOpenAIToolCall(name, args)` | `createOpenAIGuard(guard)` |
| MCP | `mapMCPToolCall(name, args)` | `createMCPGuard(guard)` |
| Vercel AI SDK | `mapVercelToolCall(toolCall)` | `createVercelGuard(guard).wrapTools(tools)` |
| LangChain.js | `mapLangChainToolCall(name, input)` | `wrapLangChainTool(tool, guard)`, `createLangChainCallbackHandler(guard)` |

```typescript
import { HushGuard, mapClaudeToolToAction } from '@hushspec/core';

const guard = HushGuard.fromFile('./policy.yaml');
guard.enforce(mapClaudeToolToAction(block.name, block.input));
```

**Vercel AI SDK.** `wrapTools` returns the tool set with each tool's `execute`
gated: the guard runs before the tool body, a denial throws `HushSpecDenied`
so the model sees a tool error instead of a side effect, and a warn is put to
the guard's `onWarn` handler. Tools without an `execute` (provider-executed)
are returned untouched. Both the AI SDK 4 (`args`) and 5 (`input`) tool-call
shapes are accepted.

```typescript
import { HushGuard, createVercelGuard } from '@hushspec/core';
import { generateText } from 'ai';

const { wrapTools } = createVercelGuard(HushGuard.fromFile('./policy.yaml'));

await generateText({ model, prompt, tools: wrapTools({ readFile, writeFile, bash }) });
```

**LangChain.js.** Wrap one tool -- the result is a proxy, so the tool keeps its
prototype, its fields and its `instanceof`, and `invoke`, `call` and a
`DynamicTool`'s `func` are all gated -- or hand an agent executor the callback
handler, which gates every tool it starts from `handleToolStart`.

```typescript
import { HushGuard, wrapLangChainTool, createLangChainCallbackHandler } from '@hushspec/core';

const guard = HushGuard.fromFile('./policy.yaml');

const tools = [readFileTool, bashTool].map(tool => wrapLangChainTool(tool, guard));

await executor.invoke({ input }, { callbacks: [createLangChainCallbackHandler(guard)] });
```

Recognized tool names (`readFile`, `write_file`, `bash`, `fetch`, ...) map onto
`file_read`, `file_write`, `shell_command` and `egress`; anything else is a
`tool_call` against the tool's own name, with `args_size` recorded so a receipt
carries the payload's size and not the payload. The adapters guess only where
the mapping is unambiguous: a wrong action type would consult the wrong rule
block.

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
