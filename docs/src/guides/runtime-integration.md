# Runtime Integration

A policy document only becomes a control when something asks it before acting.
This guide is about that something: the **enforcement point** at an agent
runtime's tool boundary.

The shape is the same in every SDK:

1. Load a policy and compile it once.
2. Wrap it in a **guard** that knows the enforcement mode, the confirmation
   channel for `warn`, where receipts go, and who is acting.
3. Call the guard before every tool call, file access, egress or shell command.
4. Let the guard follow the policy file so a change takes effect without a
   restart.

This page covers the Rust SDK. The TypeScript and Python SDKs expose the same
concepts under the same names (`HushGuard`, observers, providers, an OTLP
sink); where a spelling differs, it is noted.

## The guard

`HushGuard` is the enforcement point. It holds a compiled policy and adds
everything a bare `CompiledPolicy` deliberately does not know about.

```rust
use hushspec::{EvaluationAction, HushGuard, Policy};

let guard = HushGuard::from_policy(Policy::from_path("policy.yaml")?)?;

let action = EvaluationAction {
    action_type: "egress".to_string(),
    target: Some("api.example.com".to_string()),
    ..Default::default()
};

let decision = guard.check(&action);
if !decision.allowed() {
    // Refuse the tool call. `decision.receipt` is the evidence that it
    // happened and why.
}
```

`check()` returns a `GuardDecision`:

| Field | Meaning |
|---|---|
| `result` | The policy's decision: `allow`, `warn` or `deny`, with `matched_rule` and `reason` |
| `receipt` | The decision receipt (receipt spec 0.2), unless auditing is switched off |
| `enforced` | `true` exactly when the action was **stopped** |
| `enforcement` | Mode and disposition, as the receipt records them |
| `duration_us` | Wall time of the evaluation |

`allowed()` is the complement of `enforced`, and is what a call site branches
on. Two convenience wrappers exist for the common shapes:

```rust
if guard.allows(&action) { /* ... */ }         // just the go/no-go
guard.enforce(&action)?;                        // `Denied` error on refusal
```

`evaluate()` scores an action without enforcing anything -- the receipt still
reaches the sink, stamped with the disposition the decision *implies*. Use it
to shadow a policy the runtime is not yet acting on.

A guard is `Send + Sync` and takes `&self` everywhere, so share one `Arc`
across an agent's worker threads. The policy lives behind an `RwLock<Arc<..>>`:
an evaluation takes the read lock only long enough to clone one `Arc`, and a
hot swap never blocks an in-flight decision.

## Configuring the guard

```rust
use hushspec::{Actor, AuditConfig, EnforcementMode, HushGuard, Policy, StderrObserver, TimeSource};
use std::sync::Arc;

let guard = HushGuard::builder()
    .actor(Actor {
        agent_id: Some("code-assistant".to_string()),
        session_id: Some(session_id.clone()),
        principal: Some("alice@example.com".to_string()),
        runtime: Some("my-agent/1.4".to_string()),
    })
    .time_source(TimeSource::System)
    .sink(Box::new(sink))
    .observer(Arc::new(StderrObserver::deny_only()))
    .enforcement_mode(EnforcementMode::Enforce)
    .enforcement_override("rules.secret_patterns", EnforcementMode::Monitor)
    .on_warn(|result, action| ask_the_operator(result, action))
    .audit(AuditConfig::default())
    .build_from_policy(Policy::from_path("policy.yaml")?)?;
```

The builder also accepts an already-resolved policy
(`build_from_resolution`), an already-compiled one (`build_from_compiled`), or
one with a tenant-scoped kill switch (`build_from_resolution_with`).

### `warn` needs a confirmation channel

A `warn` decision means "ask a human". Without an `on_warn` handler a guard has
nobody to ask, so the action is **denied** (core spec 6). There is no
"warn means proceed" default in any SDK.

A handler that returns `true` records the outcome as `confirmed` -- distinct
from `allowed` in the receipt, so an auditor can tell a policy allow from a
human override.

### Enforcement modes

`EnforcementMode::Monitor` records what the policy *would* have done and lets
the action through; the receipt's `enforcement.outcome` is `would_block`. It is
how a new policy gets rolled out without breaking a running agent.

Monitor mode is only accepted when a sink or an observer is configured. A
shadow decision nobody records is indistinguishable from having no policy at
all, so the guard refuses to build.

Per-rule-path overrides let one block run in shadow while the rest enforces:

```rust
.enforcement_override("rules.secret_patterns", EnforcementMode::Monitor)
```

An override key is a rule path prefix and the **longest** match wins. A prefix
only matches at a segment boundary, so `rules.egress` covers
`rules.egress.default` but not `rules.egress_extra`. Keys must start with
`rules.` or `extensions.` and name a real block -- a typo is a build error, not
a silently inert override.

Two things always enforce, whatever the mode says:

- **Panic mode.** A kill switch monitor mode could wave through would not be a
  kill switch.
- **A refused policy.** See below.

### A policy that will not verify

Under `require_signature`, a policy whose chain does not verify does not make
the guard fail to build. It makes the guard **refuse**: it holds the identity of
what it was handed, and every action is denied with
`matched_rule: __hushspec_policy_unverified__` and an unverified-policy receipt
recording `policy.signature.verified: false` and the verifier's reason (signing
spec 6.5).

That is deliberate. A guard that never came into existence emits nothing --
no receipt, no observer event, no record that an agent tried to act under an
unverified policy. Refusing keeps the attempt on the record.

```rust
let guard = HushGuard::from_policy(
    Policy::from_path("policy.yaml")?.verify(keyring),
)?;
assert!(guard.refused());
let (document, status) = guard.refusal().expect("what would not verify");
```

Every other load failure -- a base that will not load, a chain that will not
merge, a document that will not validate -- is still an error: there is no
document to refuse against.

## Observers

Receipts are the *evidence* channel: durable, hash-linked, specified.
Observers are the *telemetry* channel: best-effort, structured, cheap. A guard
drives both from the same evaluation.

```rust
pub trait EvaluationObserver: Send + Sync {
    fn on_policy_loaded(&self, event: &PolicyLoadedEvent) {}
    fn on_evaluation(&self, event: &EvaluationCompletedEvent) {}
    fn on_error(&self, event: &ErrorEvent) {}
}
```

Every method has a no-op default, so an observer implements only what it cares
about. Batteries included:

| Observer | What it does |
|---|---|
| `JsonLineObserver` | One JSON object per line to any `Write` (the SDKs' shared event shape) |
| `StderrObserver` | A human line per event; `deny_only()` for just the refusals |
| `MetricsCollector` | Counters and a latency histogram, rendered as Prometheus text |
| `WebhookObserver` | POSTs each event to an HTTP endpoint off-thread (`http` feature) |

An action's `content` is stripped before it reaches an observer, exactly as a
receipt records only its hash and size (receipt spec 4.4); the event's
`content_redacted` flag records that it happened. Observers run inline on the
evaluation thread, so do fallible or slow work off-thread.

A receipt sink that refuses a receipt or a policy event never changes a
decision and never reaches the caller -- a full disk is no reason to let an
action through, nor to stop one -- but it is never silent either: every SDK
reports it here as a `sink.error` event carrying the failure and the name of
the sink that refused.

`ObservableEvaluator` is the fan-out, usable on its own when you want telemetry
without enforcement.

### Metrics

`MetricsCollector::render_prometheus()` emits the series the observability
spec names, so an existing dashboard or recording rule works unchanged:

```
hushspec_evaluate_total{decision="deny",action_type="egress"} 89
hushspec_evaluate_duration_us_bucket{action_type="tool_call",le="100"} 9050
hushspec_evaluate_duration_us_sum{action_type="tool_call"} 182340
hushspec_evaluate_duration_us_count{action_type="tool_call"} 9091
hushspec_rule_match_total{rule_block="forbidden_paths",decision="deny"} 45
hushspec_policy_load_total{status="success"} 3
```

`snapshot()` returns the same counters as data, for a handler that renders its
own format.

## Policy providers and hot reload

A `PolicyProvider` answers "what is the policy right now?" -- and answers it
with a fully resolved, verified `Resolution`, never a bare document. That
matters: a leaf policy whose `extends` chain has not been merged silently drops
every rule its base declares.

| Provider | Source |
|---|---|
| `FileProvider` | A file; relative `extends` resolve against its directory, and its detached signature is looked for next to it |
| `HttpProvider` | HTTPS, through the SDK's own loader: HTTPS-only, SSRF protection, a size cap, and ETag revalidation with a cache directory (`http` feature) |

Two drivers reload on an interval and hand each new resolution to a callback --
typically the guard:

```rust
use hushspec::{HushGuard, PolicyWatcher};
use std::{sync::Arc, time::Duration};

let guard = Arc::new(HushGuard::from_path("policy.yaml")?);

let watch = PolicyWatcher::new("policy.yaml")
    .every(Duration::from_secs(2))
    .swapping_into(guard.clone())
    .on_error(|error| eprintln!("policy reload failed: {error}"))
    .start()?;
```

`PolicyWatcher` stats the file each tick and reloads only when its mtime or
size moved, so an unchanged policy costs one `stat`. `PolicyPoller` does the
same for any provider, delivering only when the resolved `content_hash`
actually changed:

```rust
use hushspec::{HttpProvider, PolicyPoller};

let handle = PolicyPoller::new(Arc::new(
    HttpProvider::new("https://policies.example.com/agents/default.yaml")
        .with_cache_dir("/var/cache/hushspec"),
))
.every(Duration::from_secs(60))
.swapping_into(guard.clone())
.start()?;
```

The initial load is synchronous and its failure is returned -- a driver that
never had a policy has nothing to keep. After that, **a reload that will not
load, resolve, verify, validate or compile is an error, not a policy**: the
previous resolution stays in force, the error goes to `on_error`, and the
driver keeps ticking. An unverified file must never become the policy in effect
just because it arrived second.

The returned `PolicyHandle` reports `current()`, `generation()`, `errors()` and
`last_error()`. Dropping it stops the thread and joins it.

### Panic sentinel

Both drivers can check a sentinel file on the same tick as the reload and arm
the guard's kill switch when it appears:

```rust
let watch = PolicyWatcher::new("policy.yaml")
    .every(Duration::from_secs(2))
    .swapping_into(guard.clone())
    .panic_sentinel(".hushspec_panic", guard.panic_state().clone())
    .start()?;
```

Checking fails closed: an I/O error that cannot prove the file absent arms the
latch. `h2h panic` writes the same sentinel.

## Exporting to OpenTelemetry

`OtlpSink` is a receipt sink that batches entries onto a background thread and
POSTs them to a collector as OTLP/HTTP JSON at `<endpoint>/v1/logs`
(`otlp` feature, which implies `http`).

```rust
use hushspec::{ChainedFileSink, HushGuard, MultiSink, OtlpConfig, OtlpSink, Policy};

let sink = MultiSink::new(vec![
    Box::new(ChainedFileSink::open("receipts.log.jsonl")?),
    Box::new(OtlpSink::with_config(
        OtlpConfig::new("http://localhost:4318")
            .with_service_name("agent-gateway")
            .with_header("x-api-key", api_key),
    )?),
]);

let guard = HushGuard::builder()
    .sink(Box::new(sink))
    .build_from_policy(Policy::from_path("policy.yaml")?)?;
```

Evidence and telemetry are different jobs. Fan out through a `MultiSink` so a
collector outage never costs an audit entry: OTLP export is best-effort, the
hash-linked log is not.

### Wire mapping

Normative for every HushSpec SDK -- the four ports emit the same records, so
one collector pipeline works whichever SDK wrote them. One `logRecord` per
entry, in a single `resourceLogs` → `scopeLogs` envelope per request.

| Log record field | Value |
|---|---|
| `timeUnixNano` | The receipt's (or policy event's) `timestamp`, in nanoseconds since the epoch, as a decimal string |
| `observedTimeUnixNano` | When the batch was assembled |
| `severityText` / `severityNumber` | `INFO`/9 for `allow`, `WARN`/13 for `warn`, `ERROR`/17 for `deny`; a policy event is `INFO` |
| `body.stringValue` | The canonical JSON (RFC 8785) of the receipt, or of the policy event |

Log record attributes -- absent members are omitted, never sent as null:

| Attribute | Value |
|---|---|
| `hushspec.entry_type` | `receipt`, `policy_loaded` or `policy_swapped` |
| `hushspec.receipt_version` | `receipt.receipt_version` (receipts only) |
| `hushspec.decision` | `allow` / `warn` / `deny` (receipts only) |
| `hushspec.action_type` | `receipt.action.type` (receipts only) |
| `hushspec.matched_rule` | `receipt.matched_rule` (receipts only, when set) |
| `hushspec.policy.content_hash` | `policy.content_hash` |
| `hushspec.receipt_hash` | `sha256:` over the receipt's canonical form (receipts only) |
| `hushspec.enforcement.mode` | `enforce` / `monitor` |
| `hushspec.enforcement.outcome` | `allowed` / `confirmed` / `blocked` / `would_block` (receipts only) |

Resource attributes:

| Attribute | Value |
|---|---|
| `service.name` | Configurable, default `hushspec` |
| `hushspec.sdk` | `hushspec-rust` (each SDK reports its own) |
| `hushspec.sdk.version` | The SDK's version |
| `hushspec.spec_version` | The HushSpec version the engine implements |

Because the body is the receipt's canonical form byte for byte, a downstream
consumer can recompute `receipt_hash` from the log record and check it against
the attribute.

### Delivery

- **Bounded queue.** When the collector is slower than the agent, the newest
  entry is dropped rather than blocking the evaluation that produced it. Every
  drop increments `OtlpSink::dropped()`, returns an error from `send()`, and --
  with `with_observer()` -- raises a `sink.error` observer event.
- **Retries.** A `5xx` or a transport error is retried with exponential
  backoff. A `4xx` is not: the collector rejected the payload, and resending
  the same bytes will not help.
- **Flush.** The worker exports when the batch fills or the flush interval
  elapses. `flush()` blocks until the queue is exported, and dropping the sink
  flushes and joins the worker -- so a process exiting right after a denial
  still exports the receipt for it.

## Adapters

The Rust SDK ships no framework adapters, by design. `HushGuard::check` **is**
the integration point, and a Rust host calls it from whatever tool-dispatch
function it already has. The TypeScript, Python and Go SDKs ship adapters
(Anthropic, OpenAI, MCP) because their ecosystems have a dominant client
worth adapting to.

## A complete program

`crates/hushspec/examples/guarded_agent.rs` wires all of the above together --
guard, confirmation channel, monitored rule block, hash-linked log, OTLP
export, metrics and hot reload -- and runs a handful of tool calls through it:

```bash
cargo run --example guarded_agent --features otlp
```

```text
ALLOW   egress       api.example.com          Enforce/Allowed     rules.egress.allow
BLOCK   egress       exfil.evil.test          Enforce/Blocked     rules.egress.default
BLOCK   file_read    /home/agent/.ssh/id_rsa  Enforce/Blocked     rules.forbidden_paths.patterns
BLOCK   tool_call    rm_rf                    Enforce/Blocked     rules.tool_access.block
ALLOW   tool_call    deploy                   Enforce/Confirmed   rules.tool_access.require_confirmation
ALLOW   file_write   /home/agent/.config      Monitor/WouldBlock  rules.secret_patterns.patterns.aws_access_key
```
