# Rust SDK

Use the Rust SDK at a runtime boundary you own. This guide needs Rust 1.88 or newer
and the [quickstart policy](https://hushspec.org/docs-examples/quickstart/policy.yaml).

Rust returns `Result` for fallible operations. `HushGuard::check` returns a `GuardDecision`; branch on `allowed()`, or use `enforce` and handle `Denied` before dispatch.

## Install and run the complete example

Create an empty directory. Download these files, preserving the listed relative
paths, and place `policy.yaml` at the top of that directory:

- [Cargo.toml](https://hushspec.org/docs-examples/sdks/rust/Cargo.toml)
- [src/main.rs](https://hushspec.org/docs-examples/sdks/rust/src/main.rs)
- [src/trust.rs](https://hushspec.org/docs-examples/sdks/rust/src/trust.rs)

The example enables `features = ["signing"]`. Basic parsing and evaluation do not need that feature. HTTPS providers require `http`; OTLP requires `otlp`.

```sh
cargo run -- policy.yaml
```

Expected output: `PASS: deny=0 dispatches; unconfirmed warn=0; confirmed warn=1; invalid policy refused`.
All effects are in a fresh temporary directory. No model API or credentials are
required, and the program cleans up its own synthetic output.

## Enforce before the effect

The example parses and validates the policy, resolves it, and compiles it once.
It then attaches a consistent actor and callback receipt sink to the guard.
The synthetic handler creates one file only after enforcement permits dispatch.

<!-- docs-file: sdk-rust-dispatch docs/examples/sdks/rust/src/main.rs -->
```rust
use hushspec::{
    Actor, CallbackSink, CompiledPolicy, Decision, EvaluationAction, HushGuard, HushSpec, Policy,
    resolve_from_path, validate,
};
use std::{
    fs,
    io::Write,
    sync::{Arc, Mutex},
};
mod trust;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "policy.yaml".into());
    let document = HushSpec::parse(&fs::read_to_string(&policy_path)?)?;
    assert!(validate(&document).is_valid());
    let resolved = resolve_from_path(&policy_path)?;
    let compiled = CompiledPolicy::compile(&resolved)?;
    trust::check_trust(&policy_path, &resolved)?;
    let action = |target: &str| EvaluationAction {
        action_type: "tool_call".into(),
        target: Some(target.into()),
        ..Default::default()
    };
    assert_eq!(
        compiled.evaluate(&action("search")).decision,
        Decision::Allow
    );
    let receipts = Arc::new(Mutex::new(Vec::new()));
    let builder = || {
        let recorded = Arc::clone(&receipts);
        HushGuard::builder()
            .actor(Actor {
                agent_id: Some("docs-agent".into()),
                session_id: Some("docs-session".into()),
                principal: Some("docs-user".into()),
                runtime: Some("docs/1.0.0".into()),
            })
            .sink(Box::new(CallbackSink::new(move |receipt| {
                recorded.lock().unwrap().push(receipt.clone());
                Ok(())
            })))
    };
    let guard = builder().build_from_policy(Policy::from_path(&policy_path)?)?;
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("effect.txt");
    let dispatches = std::cell::Cell::new(0);
    let dispatch = |guard: &HushGuard, tool: &str| -> Result<bool, std::io::Error> {
        if !guard.check(&action(tool)).allowed() {
            return Ok(false);
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)?;
        file.write_all(b"confirmed once\n")?;
        dispatches.set(dispatches.get() + 1);
        Ok(true)
    };
    assert!(!dispatch(&guard, "deploy")?);
    assert!(!dispatch(&guard, "write_file")?);
    assert_eq!(dispatches.get(), 0);
    assert!(!output.exists());
    let confirmed = builder()
        .on_warn(|_, _| true)
        .build_from_policy(Policy::from_path(&policy_path)?)?;
    assert!(dispatch(&confirmed, "write_file")?);
    assert_eq!(dispatches.get(), 1);
    assert_eq!(fs::read_to_string(output)?, "confirmed once\n");
    let receipts = receipts.lock().unwrap();
    let last = receipts.last().unwrap();
    assert_eq!(
        last.enforcement.outcome,
        hushspec::EnforcementOutcome::Confirmed
    );
    assert_eq!(
        last.actor.as_ref().unwrap().agent_id.as_deref(),
        Some("docs-agent")
    );
    assert!(HushSpec::parse("hushspec: \"1.0.0\"\nunknown_rule: true\n").is_err());
    println!(
        "PASS: deny=0 dispatches; unconfirmed warn=0; confirmed warn=1; invalid policy refused"
    );
    Ok(())
}
```

The `on_warn` / `onWarn` callback in this demonstration approves one synthetic
test action. A real integration must obtain approval from an authenticated
channel and bind it to the pending action. Do not replace approval with
unconditional `true` in a production agent.

## Signing and keyrings

The companion `src/trust.rs` program is called by the main example. It
creates an ephemeral test key, signs the resolved document, verifies with an
explicit keyring, and rejects a different keyring. It prints no private key and
does not persist one. Production signing identities belong to the operator.

Signing and verification must refer to the same resolved policy used for
evaluation. See [signing](../../signing-spec.md), [bundles](../../bundle-spec.md),
and the [exact signing APIs](../../reference/sdk-api.md#signing-keyrings-receipt-signing).
A successful signature proves authenticity relative to your trust roots, not
that a tool obeyed the policy.

## Providers and reload

`FileProvider::load()` returns a `Resolution`; constructing a provider does not start a watcher. Use `PolicyWatcher` or `PolicyPoller` to follow changes. Share an `Arc<HushGuard>` across threads when needed. The ordinary guard waits through in-flight checks and receipt delivery before committing a reload.

Initial policy-load errors cannot fall back to a nonexistent policy. Ordinary
guard reload preserves the last good policy on a rejected update and reports
the error. It is not nonblocking: reload can wait for confirmation and receipt
delivery. See [hot reload](../hot-reload.md) for ordering and the distinct
experimental coordinator refusal contract.

## Receipts and failure handling

The callback sink makes receipt contents visible to the test. It is not durable
storage. Configure a chained file sink or another reviewed delivery path for
operational evidence, and handle `sink.error` through an observer.
A failed ordinary sink does not change the decision; if dispatch must require a
durable permit, use the separately bounded [experimental invocation workflow](../../reference/trusted-invocation.md).

Receipts record actor fields, policy hash, decision, trace and enforcement outcome.
They do not carry raw action content. The `confirmed` outcome distinguishes an
approved warning from a plain allow.

## API map and next steps

The [SDK API contract](../../reference/sdk-api.md) covers parse/validate,
resolve/merge, compile/evaluate, actors, receipts, sinks, signing, keyrings,
providers, panic mode and error conventions. For mapping effects, read
[MCP](../integrations/mcp.md) and [runtime integration](../runtime-integration.md).
Use [conformance](../../reference/conformance.md) to understand what a test
corpus establishes; this example is an integration regression, not an
independent conformance certificate.
