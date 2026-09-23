# hushspec

Agentic compliance as code: a portable, open specification for declaring, enforcing, and proving the security controls an AI agent operates under.

`hushspec` is the reference implementation, in Rust, of the [HushSpec](https://github.com/backbay-labs/hush) open policy format. It provides parsing, validation, evaluation, resolution, detection, signing, and audit trail capabilities for HushSpec policy documents.

## Installation

```toml
[dependencies]
hushspec = "1.0"
```

Optional features:

```toml
# Ed25519 policy signing and verification
hushspec = { version = "1.0", features = ["signing"] }

# HTTPS-based extends resolution, remote policy providers, webhook observer
hushspec = { version = "1.0", features = ["http"] }

# OTLP/HTTP export of receipts and policy events (implies `http`)
hushspec = { version = "1.0", features = ["otlp"] }
```

## Quick Start

```rust
use hushspec::{HushSpec, validate, evaluate, EvaluationAction};

// Parse a policy
let yaml = r#"
hushspec: "0.1.0"
name: my-policy
rules:
  egress:
    allow: ["api.github.com"]
    block: []
    default: block
"#;
let spec = HushSpec::parse(yaml)?;

// Validate
let result = validate(&spec);
assert!(result.is_valid());

// Evaluate an action
let action = EvaluationAction {
    action_type: "egress".into(),
    target: Some("api.github.com".into()),
    ..Default::default()
};
let decision = evaluate(&spec, &action);
assert_eq!(decision.decision, hushspec::Decision::Allow);
```

## Guarding an agent

`HushGuard` is the enforcement point: one object an agent runtime asks before
it acts. It adds what a bare compiled policy has no business knowing about --
an enforcement mode, a confirmation channel for `warn`, receipt sinks,
observers, the acting principal, and a policy that can be hot-swapped under
live traffic.

```rust
use hushspec::{Actor, EnforcementMode, EvaluationAction, HushGuard, MetricsCollector, Policy};
use std::sync::Arc;

let metrics = Arc::new(MetricsCollector::new());

let guard = HushGuard::builder()
    .actor(Actor { agent_id: Some("agent-1".into()), ..Actor::default() })
    .observer(metrics.clone())
    // Shadow one rule block while it is rolled out; enforce everything else.
    .enforcement_override("rules.secret_patterns", EnforcementMode::Monitor)
    // Without a confirmation channel a `warn` denies (core spec 6).
    .on_warn(|_result, _action| ask_the_operator())
    .build_from_policy(Policy::from_path("policy.yaml")?)?;

let action = EvaluationAction {
    action_type: "egress".into(),
    target: Some("api.example.com".into()),
    ..Default::default()
};

let decision = guard.check(&action);
if decision.allowed() {
    // proceed; `decision.receipt` is the evidence
}

println!("{}", metrics.render_prometheus());
# fn ask_the_operator() -> bool { false }
# Ok::<(), Box<dyn std::error::Error>>(())
```

A guard is `Send + Sync` and takes `&self` everywhere -- share one `Arc` across
worker threads. `PolicyWatcher` and `PolicyPoller` follow a file or any
`PolicyProvider` and swap the guard's policy atomically, keeping the last good
one when a reload will not resolve, validate or compile.

```rust,no_run
use hushspec::{HushGuard, PolicyWatcher};
use std::{sync::Arc, time::Duration};

let guard = Arc::new(HushGuard::from_path("policy.yaml")?);
let _watch = PolicyWatcher::new("policy.yaml")
    .every(Duration::from_secs(2))
    .swapping_into(guard.clone())
    .start()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

A runnable end-to-end program -- guard, hash-linked log, OTLP export, metrics
and hot reload -- lives in `examples/guarded_agent.rs`:

```bash
cargo run --example guarded_agent --features otlp
```

See the [runtime integration guide](https://github.com/backbay-labs/hush/blob/main/docs/src/guides/runtime-integration.md)
for the full walkthrough.

## Core API

| Module | Purpose |
|--------|---------|
| `schema` | Parse and serialize HushSpec YAML/JSON documents |
| `validate` | Structural validation with typed errors and warnings |
| `evaluate` | Evaluate actions against policies (allow/warn/deny) |
| `resolve` | Resolve `extends` chains from filesystem, HTTP, or builtins |
| `merge` | Merge child policies into base policies |
| `conditions` | Conditional rule evaluation (time windows, runtime context) |
| `detection` | Prompt injection, jailbreak, and exfiltration detection |
| `receipt` | Structured audit trail with decision receipts |
| `sink` | Receipt sinks (file, stderr, callback, filtered, multi) |
| `guard` | `HushGuard`: enforcement mode, `warn` confirmation, hot reload |
| `observer` | Evaluation telemetry: JSON Lines, stderr, Prometheus metrics, webhook |
| `provider` | Policy sources (`FileProvider`, `HttpProvider`) plus watcher and poller |
| `otlp` | OTLP/HTTP export of receipts and policy events (feature-gated) |
| `panic` | Emergency deny-all kill switch |
| `signing` | Ed25519 policy signing and verification (feature-gated) |
| `governance` | Governance metadata validation |

## Fail-Closed Design

HushSpec follows a fail-closed philosophy:

- Unknown YAML/JSON fields are rejected at parse time (`deny_unknown_fields`)
- Invalid documents produce typed `ValidationError` values
- Ambiguous or unrecognized rules result in `Deny`
- All regex patterns are validated at parse time

## CLI

The `h2h` CLI tool is available as a separate crate:

```bash
cargo install hushspec-cli
```

See [`hushspec-cli`](https://crates.io/crates/hushspec-cli) for details.

## License

Apache-2.0
