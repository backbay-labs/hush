use criterion::{Criterion, criterion_group, criterion_main};
use hushspec::{
    AuditConfig, AuditContext, CompiledPolicy, EvaluationAction, HushSpec, Resolution, evaluate,
    evaluate_audited,
};
use std::hint::black_box;

/// The embedded `default` ruleset (generated from rulesets/default.yaml by
/// scripts/generate_rust_builtins.py).
fn default_policy() -> &'static str {
    hushspec::load_builtin("default").expect("default ruleset is embedded")
}

fn default_spec() -> HushSpec {
    HushSpec::parse(default_policy()).expect("default ruleset parses")
}

fn minimal_spec() -> HushSpec {
    HushSpec::parse("hushspec: \"0.1.0\"\n").expect("minimal policy parses")
}

fn compiled(spec: &HushSpec) -> CompiledPolicy {
    CompiledPolicy::compile(spec).expect("policy compiles")
}

fn action(json: serde_json::Value) -> EvaluationAction {
    serde_json::from_value(json).expect("action deserializes")
}

/// The compile-on-the-fly wrappers: what a caller pays per action when it hands
/// `evaluate` a `&HushSpec` instead of holding a `CompiledPolicy`.
fn bench_evaluate_uncompiled(c: &mut Criterion) {
    let minimal = minimal_spec();
    let spec = default_spec();
    let tool = action(serde_json::json!({"type": "tool_call", "target": "read_file"}));
    let file = action(serde_json::json!({"type": "file_read", "target": "/workspace/src/main.rs"}));
    let shell = action(serde_json::json!({"type": "shell_command", "target": "ls -la"}));

    c.bench_function("evaluate/minimal/tool_call", |b| {
        b.iter(|| evaluate(black_box(&minimal), black_box(&tool)))
    });
    c.bench_function("evaluate/default/tool_call", |b| {
        b.iter(|| evaluate(black_box(&spec), black_box(&tool)))
    });
    c.bench_function("evaluate/default/file_read", |b| {
        b.iter(|| evaluate(black_box(&spec), black_box(&file)))
    });
    c.bench_function("evaluate/default/shell_command", |b| {
        b.iter(|| evaluate(black_box(&spec), black_box(&shell)))
    });
}

/// The same actions against a policy whose patterns were compiled once.
fn bench_evaluate_compiled(c: &mut Criterion) {
    let minimal = compiled(&minimal_spec());
    let policy = compiled(&default_spec());
    let tool = action(serde_json::json!({"type": "tool_call", "target": "read_file"}));
    let file = action(serde_json::json!({"type": "file_read", "target": "/workspace/src/main.rs"}));
    let shell = action(serde_json::json!({"type": "shell_command", "target": "ls -la"}));
    let egress = action(serde_json::json!({"type": "egress", "target": "api.example.com"}));

    c.bench_function("compiled/evaluate/minimal/tool_call", |b| {
        b.iter(|| black_box(&minimal).evaluate(black_box(&tool)))
    });
    c.bench_function("compiled/evaluate/default/tool_call", |b| {
        b.iter(|| black_box(&policy).evaluate(black_box(&tool)))
    });
    c.bench_function("compiled/evaluate/default/file_read", |b| {
        b.iter(|| black_box(&policy).evaluate(black_box(&file)))
    });
    c.bench_function("compiled/evaluate/default/shell_command", |b| {
        b.iter(|| black_box(&policy).evaluate(black_box(&shell)))
    });
    c.bench_function("compiled/evaluate/default/egress", |b| {
        b.iter(|| black_box(&policy).evaluate(black_box(&egress)))
    });
}

/// What compiling itself costs, so the one-off price of `CompiledPolicy` is
/// visible next to the per-action price it removes.
fn bench_compile(c: &mut Criterion) {
    let spec = default_spec();
    c.bench_function("compile/default", |b| {
        b.iter(|| CompiledPolicy::compile(black_box(&spec)).expect("compiles"))
    });
}

fn bench_audited(c: &mut Criterion) {
    let spec = default_spec();
    let policy = compiled(&spec);
    let tool = action(serde_json::json!({"type": "tool_call", "target": "read_file"}));
    let enabled = AuditConfig::default();
    let disabled = AuditConfig {
        enabled: false,
        include_rule_trace: false,
        record_duration: false,
    };
    let resolution = Resolution::from_resolved(&spec, None).expect("resolved");
    let ctx = AuditContext::default();

    c.bench_function("evaluate_audited/enabled/default/tool_call", |b| {
        b.iter(|| {
            evaluate_audited(
                black_box(&resolution),
                black_box(&tool),
                black_box(&enabled),
                black_box(&ctx),
            )
        })
    });
    c.bench_function("evaluate_audited/disabled/default/tool_call", |b| {
        b.iter(|| {
            evaluate_audited(
                black_box(&resolution),
                black_box(&tool),
                black_box(&disabled),
                black_box(&ctx),
            )
        })
    });
    c.bench_function("compiled/evaluate_audited/enabled/default/tool_call", |b| {
        b.iter(|| {
            black_box(&policy)
                .evaluate_audited(black_box(&tool), black_box(&enabled), black_box(&ctx))
                .expect("receipt")
        })
    });
    c.bench_function(
        "compiled/evaluate_audited/disabled/default/tool_call",
        |b| {
            b.iter(|| {
                black_box(&policy)
                    .evaluate_audited(black_box(&tool), black_box(&disabled), black_box(&ctx))
                    .expect("receipt")
            })
        },
    );
}

/// Content hashing. Not part of the audited evaluation path -- the receipt
/// budget in `tests/bench_thresholds.rs` excludes it -- so it is measured on
/// its own rather than inside `bench_audited`.
fn bench_hashing(c: &mut Criterion) {
    let spec = default_spec();
    c.bench_function("policy_hash/default", |b| {
        b.iter(|| hushspec::content_hash(black_box(&spec)))
    });
}

/// Detection: the built-in registry is built once per process, so the cost
/// here should be the detector scan, not 13 regex compilations.
fn bench_detection(c: &mut Criterion) {
    let yaml = r#"
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      enabled: true
    jailbreak:
      enabled: true
"#;
    let spec = HushSpec::parse(yaml).expect("detection policy parses");
    let policy = compiled(&spec);
    let clean = action(serde_json::json!({
        "type": "tool_call",
        "target": "read_file",
        "content": "please summarize the attached report for the team"
    }));

    c.bench_function("evaluate_with_detection/clean", |b| {
        b.iter(|| hushspec::evaluate_with_detection(black_box(&spec), black_box(&clean)))
    });
    c.bench_function("compiled/evaluate_with_detection/clean", |b| {
        b.iter(|| black_box(&policy).evaluate_with_detection(black_box(&clean)))
    });
}

/// The uncompiled glob helper `h2h lint` still uses, kept for reference.
fn bench_glob(c: &mut Criterion) {
    c.bench_function("glob_matches/hit", |b| {
        b.iter(|| {
            hushspec::evaluate::glob_matches(
                black_box("**/.ssh/**"),
                black_box("/home/user/.ssh/id_rsa"),
            )
        })
    });
    c.bench_function("glob_matches/miss", |b| {
        b.iter(|| {
            hushspec::evaluate::glob_matches(
                black_box("**/.ssh/**"),
                black_box("/workspace/src/main.rs"),
            )
        })
    });
}

criterion_group!(
    benches,
    bench_evaluate_uncompiled,
    bench_evaluate_compiled,
    bench_compile,
    bench_audited,
    bench_hashing,
    bench_detection,
    bench_glob
);
criterion_main!(benches);
