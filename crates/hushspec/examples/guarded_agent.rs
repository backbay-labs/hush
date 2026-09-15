//! An agent tool boundary, end to end.
//!
//! ```text
//! cargo run --example guarded_agent --features otlp
//! ```
//!
//! Wires up what a real enforcement point needs and then runs a handful of
//! tool calls through it:
//!
//! - [`Policy`] loads, resolves and compiles a document
//! - [`HushGuard`] enforces it, with a confirmation channel for `warn`, an
//!   [`Actor`], and one rule block in monitor mode
//! - a [`MultiSink`] fans every receipt into a hash-linked
//!   [`ChainedFileSink`] (the evidence) *and* an [`OtlpSink`] (the telemetry)
//! - a [`MetricsCollector`] and a [`StderrObserver`] watch the decision stream
//! - a [`PolicyWatcher`] follows the policy file, so editing it swaps the
//!   guard's policy without a restart
//!
//! Point it at a collector with `OTEL_EXPORTER_OTLP_ENDPOINT`; the default is
//! `http://localhost:4318`. Nothing here needs the collector to be up -- the
//! OTLP sink is best-effort by design, and the run is unaffected if the export
//! fails.
//!
//! Adapters for specific agent frameworks are deliberately out of scope for
//! the Rust SDK: `HushGuard::check` *is* the integration point, and a Rust
//! host calls it from whatever tool-dispatch function it already has. The
//! TypeScript, Python and Go SDKs ship framework adapters because their
//! ecosystems have a dominant client to adapt to.

use std::sync::Arc;
use std::time::Duration;

use hushspec::{
    Actor, ChainedFileSink, EnforcementMode, EvaluationAction, HushGuard, MetricsCollector,
    MultiSink, OtlpConfig, OtlpSink, PanicState, Policy, PolicyWatcher, StderrObserver,
};

const POLICY: &str = r#"hushspec: "0.2.0"
name: guarded-agent
description: What this example's agent may do.
rules:
  egress:
    allow: ["api.example.com", "*.githubusercontent.com"]
    default: block
  forbidden_paths:
    patterns: ["**/.ssh/**", "**/.env"]
  tool_access:
    # Tool names are matched exactly, not as globs: an allowlist is the
    # complete set of tools this agent may call.
    allow: ["search_docs", "read_file", "write_file", "deploy"]
    block: ["rm_rf"]
    require_confirmation: ["deploy"]
  secret_patterns:
    patterns:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workdir = std::env::temp_dir().join("hushspec-guarded-agent");
    std::fs::create_dir_all(&workdir)?;
    let policy_path = workdir.join("policy.yaml");
    std::fs::write(&policy_path, POLICY)?;
    let log_path = workdir.join("receipts.log.jsonl");

    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:4318".to_string());

    // Evidence and telemetry are different jobs. The hash-linked log is the
    // record an auditor reads; OTLP is what a dashboard reads. Fanning out
    // means a collector outage never costs an audit entry.
    let metrics = Arc::new(MetricsCollector::new());
    let sink = MultiSink::new(vec![
        Box::new(ChainedFileSink::open(&log_path)?),
        Box::new(
            OtlpSink::with_config(
                OtlpConfig::new(&endpoint)
                    .with_service_name("guarded-agent")
                    .with_batch_size(8)
                    .with_flush_interval(Duration::from_secs(1)),
            )?
            .with_observer(metrics.clone()),
        ),
    ]);

    let guard = Arc::new(
        HushGuard::builder()
            .actor(Actor {
                agent_id: Some("demo-agent".to_string()),
                session_id: Some("session-1".to_string()),
                runtime: Some("guarded_agent example".to_string()),
                ..Actor::default()
            })
            .sink(Box::new(sink))
            .observer(metrics.clone())
            .observer(Arc::new(StderrObserver::deny_only()))
            // Roll out a new rule block in shadow first: record what it would
            // have done, enforce everything else.
            .enforcement_override("rules.secret_patterns", EnforcementMode::Monitor)
            // The confirmation channel a `warn` needs. Without one, a warn
            // denies (core spec D16) -- so this is what turns
            // `require_confirmation` into an actual prompt.
            .on_warn(|result, action| {
                println!(
                    "  ? approval requested for {} {} ({})",
                    action.action_type,
                    action.target.as_deref().unwrap_or("-"),
                    result.matched_rule.as_deref().unwrap_or("-")
                );
                // A real runtime asks a human here. This one always says yes.
                true
            })
            .build_from_policy(
                Policy::from_path(&policy_path)?.with_panic_state(PanicState::new()),
            )?,
    );

    // Follow the file: editing the policy swaps it in without a restart, and a
    // document that will not compile leaves the last good one in force.
    let _watch = PolicyWatcher::new(&policy_path)
        .every(Duration::from_secs(2))
        .swapping_into(guard.clone())
        .on_error(|error| eprintln!("  ! policy reload failed: {error}"))
        .start()?;

    println!("policy  {}", guard.content_hash());
    println!("log     {}", log_path.display());
    println!("otlp    {endpoint}/v1/logs\n");

    for action in actions() {
        let decision = guard.check(&action);
        println!(
            "{:<7} {:<12} {:<28} {:?}/{:?}  {}",
            if decision.allowed() { "ALLOW" } else { "BLOCK" },
            action.action_type,
            action.target.as_deref().unwrap_or("-"),
            decision.enforcement.mode,
            decision.enforcement.outcome,
            decision.result.matched_rule.as_deref().unwrap_or("-"),
        );
    }

    println!("\n{}", metrics.render_prometheus());
    println!(
        "verify the log with:  h2h log verify {}",
        log_path.display()
    );
    Ok(())
}

fn actions() -> Vec<EvaluationAction> {
    let action = |action_type: &str, target: &str| EvaluationAction {
        action_type: action_type.to_string(),
        target: Some(target.to_string()),
        ..Default::default()
    };
    vec![
        action("egress", "api.example.com"),
        action("egress", "exfil.evil.test"),
        action("file_read", "/home/agent/project/src/main.rs"),
        action("file_read", "/home/agent/.ssh/id_rsa"),
        action("tool_call", "search_docs"),
        action("tool_call", "rm_rf"),
        // Not on the allowlist at all.
        action("tool_call", "spawn_shell"),
        // `require_confirmation` -> warn -> the on_warn handler above.
        action("tool_call", "deploy"),
        // Caught by `secret_patterns`, which this guard only monitors: the
        // receipt says `would_block` and the action goes through.
        EvaluationAction {
            action_type: "file_write".to_string(),
            target: Some("/home/agent/project/.config".to_string()),
            content: Some("key = AKIAIOSFODNN7EXAMPLE".to_string()),
            ..Default::default()
        },
    ]
}
