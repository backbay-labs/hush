//! Release-mode benchmark gate for roadmap risk R10:
//! "evaluate_audited() with enabled: false must have zero overhead;
//!  receipt generation target is <10us".
//!
//! Ignored by default (cargo test --workspace stays fast); CI runs:
//!   cargo test -p hushspec --release --test bench_thresholds -- --ignored --nocapture

use hushspec::{AuditConfig, EvaluationAction, HushSpec, evaluate, evaluate_audited};
use std::time::Instant;

const DEFAULT_POLICY: &str = include_str!("../../../rulesets/default.yaml");
const BATCHES: usize = 60;
const ITERS_PER_BATCH: usize = 2_000;

fn budget_us(var: &str, default_us: f64) -> f64 {
    std::env::var(var)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default_us)
}

/// Median per-iteration microseconds over BATCHES batches (warmup included).
fn median_iteration_us(mut f: impl FnMut()) -> f64 {
    for _ in 0..ITERS_PER_BATCH {
        f();
    }
    let mut samples: Vec<f64> = (0..BATCHES)
        .map(|_| {
            let start = Instant::now();
            for _ in 0..ITERS_PER_BATCH {
                f();
            }
            start.elapsed().as_secs_f64() * 1e6 / ITERS_PER_BATCH as f64
        })
        .collect();
    samples.sort_by(|left, right| left.partial_cmp(right).expect("finite timings"));
    samples[BATCHES / 2]
}

#[test]
#[ignore = "release-mode benchmark gate; run explicitly in the CI bench-thresholds job"]
fn receipt_overhead_within_budget() {
    if cfg!(debug_assertions) {
        panic!("bench_thresholds must run with --release (debug timings are meaningless)");
    }

    let spec = HushSpec::parse(DEFAULT_POLICY).expect("default ruleset parses");
    let action: EvaluationAction = serde_json::from_value(serde_json::json!({
        "type": "tool_call",
        "target": "read_file"
    }))
    .expect("action deserializes");
    let enabled = AuditConfig::default();
    let disabled = AuditConfig {
        enabled: false,
        include_rule_trace: false,
        redact_content: true,
    };

    let t_eval = median_iteration_us(|| {
        std::hint::black_box(evaluate(&spec, &action));
    });
    let t_disabled = median_iteration_us(|| {
        std::hint::black_box(evaluate_audited(&spec, &action, &disabled));
    });
    let t_enabled = median_iteration_us(|| {
        std::hint::black_box(evaluate_audited(&spec, &action, &enabled));
    });

    let disabled_overhead = (t_disabled - t_eval).max(0.0);
    let enabled_overhead = (t_enabled - t_eval).max(0.0);
    let disabled_budget = budget_us("HUSHSPEC_BENCH_BUDGET_DISABLED_US", 2.0);
    let enabled_budget = budget_us("HUSHSPEC_BENCH_BUDGET_ENABLED_US", 10.0);

    println!("evaluate:                 {t_eval:.3} us/iter");
    println!(
        "evaluate_audited (off):   {t_disabled:.3} us/iter (overhead {disabled_overhead:.3} us, budget {disabled_budget} us)"
    );
    println!(
        "evaluate_audited (on):    {t_enabled:.3} us/iter (overhead {enabled_overhead:.3} us, budget {enabled_budget} us)"
    );

    assert!(
        disabled_overhead < disabled_budget,
        "disabled-audit overhead {disabled_overhead:.3}us exceeds budget {disabled_budget}us (roadmap R10: zero overhead when disabled)"
    );
    assert!(
        enabled_overhead < enabled_budget,
        "receipt overhead {enabled_overhead:.3}us exceeds budget {enabled_budget}us (roadmap R10: <10us receipt generation)"
    );
}
