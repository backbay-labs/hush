use criterion::{Criterion, criterion_group, criterion_main};
use hushspec::{
    AuditConfig, AuditContext, EvaluationAction, HushSpec, Resolution, evaluate, evaluate_audited,
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

fn action(json: serde_json::Value) -> EvaluationAction {
    serde_json::from_value(json).expect("action deserializes")
}

fn bench_evaluate(c: &mut Criterion) {
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

fn bench_audited(c: &mut Criterion) {
    let spec = default_spec();
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
    c.bench_function("policy_hash/default", |b| {
        b.iter(|| hushspec::content_hash(black_box(&spec)))
    });
}

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

criterion_group!(benches, bench_evaluate, bench_audited, bench_glob);
criterion_main!(benches);
