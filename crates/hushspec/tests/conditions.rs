//! Integration tests for the conditional rules system.

use hushspec::{
    Condition, EvaluationAction, HushSpec, RuntimeContext, TimeWindowCondition, evaluate,
    evaluate_with_context,
};
use std::collections::HashMap;

fn make_spec_with_egress_block() -> HushSpec {
    let yaml = r#"
hushspec: "0.1.0"
name: "conditional-test"
rules:
  egress:
    enabled: true
    allow: ["api.openai.com"]
    default: block
"#;
    HushSpec::parse(yaml).expect("valid spec")
}

fn make_spec_with_tool_access() -> HushSpec {
    let yaml = r#"
hushspec: "0.1.0"
name: "conditional-tool-test"
rules:
  tool_access:
    enabled: true
    allow: ["deploy"]
    block: ["danger_tool"]
    default: block
"#;
    HushSpec::parse(yaml).expect("valid spec")
}

#[test]
fn evaluate_with_context_passes_when_condition_met() {
    let spec = make_spec_with_egress_block();
    let action = EvaluationAction {
        action_type: "egress".into(),
        target: Some("api.openai.com".into()),
        ..Default::default()
    };

    let ctx = RuntimeContext {
        environment: Some("production".into()),
        ..Default::default()
    };

    let mut conditions = HashMap::new();
    conditions.insert(
        "egress".to_string(),
        Condition {
            context: Some(HashMap::from([(
                "environment".to_string(),
                serde_json::Value::String("production".to_string()),
            )])),
            ..Default::default()
        },
    );

    let result = evaluate_with_context(&spec, &action, &ctx, &conditions);
    assert_eq!(result.decision, hushspec::Decision::Allow);
    assert!(
        result
            .matched_rule
            .as_deref()
            .unwrap_or("")
            .contains("allow")
    );
}

#[test]
fn evaluate_with_context_skips_rule_when_condition_fails() {
    let spec = make_spec_with_egress_block();
    let action = EvaluationAction {
        action_type: "egress".into(),
        target: Some("evil.example.com".into()),
        ..Default::default()
    };

    // Context says "staging", condition requires "production"
    let ctx = RuntimeContext {
        environment: Some("staging".into()),
        ..Default::default()
    };

    let mut conditions = HashMap::new();
    conditions.insert(
        "egress".to_string(),
        Condition {
            context: Some(HashMap::from([(
                "environment".to_string(),
                serde_json::Value::String("production".to_string()),
            )])),
            ..Default::default()
        },
    );

    // Since egress rule is disabled by condition, the domain is allowed
    // (no rule covers it).
    let result = evaluate_with_context(&spec, &action, &ctx, &conditions);
    assert_eq!(result.decision, hushspec::Decision::Allow);
}

#[test]
fn evaluate_with_context_enforces_rule_when_condition_met() {
    let spec = make_spec_with_egress_block();
    let action = EvaluationAction {
        action_type: "egress".into(),
        target: Some("evil.example.com".into()),
        ..Default::default()
    };

    // Context matches condition -- rule should be active and deny
    let ctx = RuntimeContext {
        environment: Some("production".into()),
        ..Default::default()
    };

    let mut conditions = HashMap::new();
    conditions.insert(
        "egress".to_string(),
        Condition {
            context: Some(HashMap::from([(
                "environment".to_string(),
                serde_json::Value::String("production".to_string()),
            )])),
            ..Default::default()
        },
    );

    let result = evaluate_with_context(&spec, &action, &ctx, &conditions);
    assert_eq!(result.decision, hushspec::Decision::Deny);
}

#[test]
fn evaluate_with_context_no_conditions_behaves_like_evaluate() {
    let spec = make_spec_with_egress_block();
    let action = EvaluationAction {
        action_type: "egress".into(),
        target: Some("evil.example.com".into()),
        ..Default::default()
    };

    let ctx = RuntimeContext::default();
    let conditions = HashMap::new();

    let result_conditional = evaluate_with_context(&spec, &action, &ctx, &conditions);
    let result_plain = evaluate(&spec, &action);

    // The whole result, not just the decision: an empty condition map must not
    // change the matched rule or the reason either.
    assert_eq!(result_conditional, result_plain);
}

/// A `time_window` gates the whole `tool_access` block: inside the window the
/// block runs and its `block` list denies, outside it the block is inactive
/// and nothing covers the action.
#[test]
fn time_window_condition_gates_the_tool_access_block() {
    let spec = make_spec_with_tool_access();

    let action = EvaluationAction {
        action_type: "tool_call".into(),
        target: Some("danger_tool".into()),
        ..Default::default()
    };

    // Condition: only during business hours
    let mut conditions = HashMap::new();
    conditions.insert(
        "tool_access".to_string(),
        Condition {
            time_window: Some(TimeWindowCondition {
                start: "09:00".to_string(),
                end: "17:00".to_string(),
                timezone: Some("UTC".to_string()),
                days: vec![],
            }),
            ..Default::default()
        },
    );

    // 10:00 UTC -- inside business hours, so the block is active and denies.
    let ctx_inside = RuntimeContext {
        current_time: Some("2026-01-14T10:00:00Z".to_string()),
        ..Default::default()
    };
    let result = evaluate_with_context(&spec, &action, &ctx_inside, &conditions);
    assert_eq!(result.decision, hushspec::Decision::Deny);

    // 20:00 UTC -- outside business hours, so the block is inactive and no
    // rule covers the action.
    let ctx_outside = RuntimeContext {
        current_time: Some("2026-01-14T20:00:00Z".to_string()),
        ..Default::default()
    };
    let result = evaluate_with_context(&spec, &action, &ctx_outside, &conditions);
    assert_eq!(result.decision, hushspec::Decision::Allow);
    assert_eq!(result.matched_rule, None);
}

/// A `when` whose context predicate is unsatisfiable disables its rule block
/// (core spec 3.13), so no rule covers the action and it is allowed. The
/// block is gated off, not evaluated and passed.
#[test]
fn unsatisfiable_context_condition_disables_the_rule_block() {
    let spec = make_spec_with_egress_block();
    let action = EvaluationAction {
        action_type: "egress".into(),
        target: Some("api.openai.com".into()),
        ..Default::default()
    };

    // Condition requires environment=production, but context is empty
    let ctx = RuntimeContext::default();
    let mut conditions = HashMap::new();
    conditions.insert(
        "egress".to_string(),
        Condition {
            context: Some(HashMap::from([(
                "environment".to_string(),
                serde_json::Value::String("production".to_string()),
            )])),
            ..Default::default()
        },
    );

    let result = evaluate_with_context(&spec, &action, &ctx, &conditions);
    assert_eq!(result.decision, hushspec::Decision::Allow);
    assert_eq!(
        result.matched_rule, None,
        "a gated-off block must match nothing, not match and allow"
    );
}

#[test]
fn evaluate_with_context_compound_condition() {
    let spec = make_spec_with_egress_block();
    let action = EvaluationAction {
        action_type: "egress".into(),
        target: Some("evil.example.com".into()),
        ..Default::default()
    };

    let mut conditions = HashMap::new();
    conditions.insert(
        "egress".to_string(),
        Condition {
            all_of: Some(vec![
                Condition {
                    context: Some(HashMap::from([(
                        "environment".to_string(),
                        serde_json::Value::String("production".to_string()),
                    )])),
                    ..Default::default()
                },
                Condition {
                    context: Some(HashMap::from([(
                        "user.role".to_string(),
                        serde_json::Value::String("admin".to_string()),
                    )])),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        },
    );

    // Both conditions met
    let mut ctx = RuntimeContext {
        environment: Some("production".into()),
        ..Default::default()
    };
    ctx.user.insert(
        "role".to_string(),
        serde_json::Value::String("admin".to_string()),
    );
    let result = evaluate_with_context(&spec, &action, &ctx, &conditions);
    assert_eq!(result.decision, hushspec::Decision::Deny);

    // Only environment matches, not role -- condition fails, rule disabled
    let ctx_partial = RuntimeContext {
        environment: Some("production".into()),
        ..Default::default()
    };
    let result = evaluate_with_context(&spec, &action, &ctx_partial, &conditions);
    assert_eq!(result.decision, hushspec::Decision::Allow);
}
