//! Property-based round-trip tests for `crates/hushspec`.
//!
//! CLAUDE.md lists "property testing with proptest for serialization
//! round-trip and schema validation code" as a repo-wide convention, but
//! prior to this file the only proptest usage in the workspace lived in
//! `crates/hushspec-testkit/src/gen.rs`. This file exercises the same idea
//! directly against the core crate's own public API.
//!
//! Deliberately does NOT depend on `hushspec-testkit`: that crate depends on
//! `hushspec`, so depending on it back here would be a cycle. Strategies
//! below are simpler than testkit's generator -- no `extensions.posture` /
//! `extensions.origins` -- focused on `rules.*` block fidelity, `Condition`
//! composition, `DecisionReceipt` shape, and the `merge` algorithm.

use std::collections::HashMap;

use hushspec::schema::MergeStrategy;
use hushspec::{
    AuditConfig, AuditContext, BrowserAutomationRule, CodeExecutionRule, ComputerUseMode,
    ComputerUseRule, Condition, DecisionReceipt, DefaultAction, EgressRule, EvaluationAction,
    ForbiddenPathsRule, HushSpec, InputInjectionRule, PatchIntegrityRule, PathAllowlistRule,
    RemoteDesktopChannelsRule, Rules, RuntimeContext, SecretPattern, SecretPatternsRule, Severity,
    ShellCommandsRule, TimeWindowCondition, ToolAccessRule, evaluate_audited_spec,
    evaluate_condition, merge, validate,
};
use proptest::prelude::*;
use proptest::string::string_regex;

// =====================================================================
// Primitive strategies
// =====================================================================

fn ident_strategy() -> impl Strategy<Value = String> {
    string_regex("[a-z][a-z0-9_]{2,10}").expect("valid generator regex")
}

/// Glob patterns drawn from a small, fixed alphabet plus a couple of
/// ident-parameterized shapes -- mirrors the shapes accepted by
/// `forbidden_paths` / `path_allowlist` / `secret_patterns.skip_paths`.
fn glob_pattern_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("**/.ssh/**".to_string()),
        Just("**/.env".to_string()),
        Just("/etc/passwd".to_string()),
        Just("/root/**".to_string()),
        ident_strategy().prop_map(|name| format!("**/{name}/**")),
        ident_strategy().prop_map(|name| format!("src/*.{name}")),
        ident_strategy().prop_map(|name| format!("/workspace/{name}")),
    ]
}

fn domain_strategy() -> impl Strategy<Value = String> {
    string_regex("[a-z]{3,8}\\.(com|dev|internal)").expect("valid generator regex")
}

/// Regexes from a safe subset: no `\d \w \s`, no lookaround/backreferences,
/// no inline flags -- guaranteed to compile under the `regex` crate's RE2
/// semantics and pass `validate_regex`.
fn safe_regex_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        string_regex("[a-z]{2,6}").expect("valid generator regex"),
        string_regex("[0-9]{2,4}").expect("valid generator regex"),
        (
            string_regex("[a-z]{2,6}").expect("valid generator regex"),
            string_regex("[0-9]{2,4}").expect("valid generator regex"),
        )
            .prop_map(|(left, right)| format!("{left}-{right}")),
    ]
}

fn default_action_strategy() -> impl Strategy<Value = DefaultAction> {
    prop_oneof![Just(DefaultAction::Allow), Just(DefaultAction::Block)]
}

fn severity_strategy() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Critical),
        Just(Severity::Error),
        Just(Severity::Warn),
    ]
}

fn computer_use_mode_strategy() -> impl Strategy<Value = ComputerUseMode> {
    prop_oneof![
        Just(ComputerUseMode::Observe),
        Just(ComputerUseMode::Guardrail),
        Just(ComputerUseMode::FailClosed),
    ]
}

// =====================================================================
// Rule-block strategies
// =====================================================================

fn forbidden_paths_strategy() -> impl Strategy<Value = ForbiddenPathsRule> {
    (
        any::<bool>(),
        prop::collection::vec(glob_pattern_strategy(), 0..5),
        prop::collection::vec(glob_pattern_strategy(), 0..3),
    )
        .prop_map(|(enabled, patterns, exceptions)| ForbiddenPathsRule {
            enabled,
            when: None,
            patterns,
            exceptions,
        })
}

fn path_allowlist_strategy() -> impl Strategy<Value = PathAllowlistRule> {
    (
        any::<bool>(),
        prop::collection::vec(glob_pattern_strategy(), 0..4),
        prop::collection::vec(glob_pattern_strategy(), 0..4),
        prop::collection::vec(glob_pattern_strategy(), 0..3),
    )
        .prop_map(|(enabled, read, write, patch)| PathAllowlistRule {
            enabled,
            when: None,
            read,
            write,
            patch,
        })
}

fn egress_strategy() -> impl Strategy<Value = EgressRule> {
    (
        any::<bool>(),
        prop::collection::vec(domain_strategy(), 0..4),
        prop::collection::vec(domain_strategy(), 0..4),
        default_action_strategy(),
    )
        .prop_map(|(enabled, allow, block, default)| EgressRule {
            enabled,
            when: None,
            allow,
            block,
            default,
        })
}

fn secret_patterns_strategy() -> impl Strategy<Value = SecretPatternsRule> {
    let pattern = (ident_strategy(), safe_regex_strategy(), severity_strategy()).prop_map(
        |(name, pattern, severity)| SecretPattern {
            name,
            pattern,
            severity,
            description: None,
        },
    );
    (
        any::<bool>(),
        prop::collection::vec(pattern, 0..4),
        prop::collection::vec(glob_pattern_strategy(), 0..3),
    )
        .prop_map(|(enabled, mut patterns, skip_paths)| {
            // `validate()` rejects duplicate secret pattern names; suffix by
            // index to keep the unique-name invariant true by construction.
            for (index, entry) in patterns.iter_mut().enumerate() {
                entry.name = format!("{}_{index}", entry.name);
            }
            SecretPatternsRule {
                enabled,
                when: None,
                patterns,
                skip_paths,
            }
        })
}

fn patch_integrity_strategy() -> impl Strategy<Value = PatchIntegrityRule> {
    (
        any::<bool>(),
        0usize..2000,
        0usize..1000,
        prop::collection::vec(safe_regex_strategy(), 0..3),
        any::<bool>(),
        1u32..40,
    )
        .prop_map(
            |(
                enabled,
                max_additions,
                max_deletions,
                forbidden_patterns,
                require_balance,
                quarters,
            )| {
                PatchIntegrityRule {
                    enabled,
                    when: None,
                    max_additions,
                    max_deletions,
                    forbidden_patterns,
                    require_balance,
                    // Positive by construction (quarters >= 1) and exact in
                    // both YAML and JSON float formatting.
                    max_imbalance_ratio: f64::from(quarters) * 0.25,
                }
            },
        )
}

fn shell_commands_strategy() -> impl Strategy<Value = ShellCommandsRule> {
    (
        any::<bool>(),
        prop::collection::vec(safe_regex_strategy(), 0..4),
    )
        .prop_map(|(enabled, forbidden_patterns)| ShellCommandsRule {
            enabled,
            when: None,
            forbidden_patterns,
        })
}

fn tool_access_strategy() -> impl Strategy<Value = ToolAccessRule> {
    (
        any::<bool>(),
        prop::collection::vec(ident_strategy(), 0..4),
        prop::collection::vec(ident_strategy(), 0..4),
        prop::collection::vec(ident_strategy(), 0..3),
        default_action_strategy(),
        // `validate()` rejects `Some(0)`; non-zero when present.
        prop::option::of(1usize..4096),
    )
        .prop_map(
            |(enabled, allow, block, require_confirmation, default, max_args_size)| {
                ToolAccessRule {
                    enabled,
                    when: None,
                    allow,
                    block,
                    require_confirmation,
                    default,
                    max_args_size,
                }
            },
        )
}

fn computer_use_strategy() -> impl Strategy<Value = ComputerUseRule> {
    (
        any::<bool>(),
        computer_use_mode_strategy(),
        prop::collection::vec(ident_strategy(), 0..4),
    )
        .prop_map(|(enabled, mode, allowed_actions)| ComputerUseRule {
            enabled,
            when: None,
            mode,
            allowed_actions,
        })
}

fn remote_desktop_strategy() -> impl Strategy<Value = RemoteDesktopChannelsRule> {
    (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(enabled, clipboard, file_transfer, audio, drive_mapping)| RemoteDesktopChannelsRule {
                enabled,
                when: None,
                clipboard,
                file_transfer,
                audio,
                drive_mapping,
            },
        )
}

fn input_injection_strategy() -> impl Strategy<Value = InputInjectionRule> {
    (
        any::<bool>(),
        prop::collection::vec(ident_strategy(), 0..3),
        any::<bool>(),
    )
        .prop_map(
            |(enabled, allowed_types, require_postcondition_probe)| InputInjectionRule {
                enabled,
                when: None,
                allowed_types,
                require_postcondition_probe,
            },
        )
}

fn browser_automation_strategy() -> impl Strategy<Value = BrowserAutomationRule> {
    (
        any::<bool>(),
        prop::collection::vec(domain_strategy(), 0..3),
        prop::collection::vec(domain_strategy(), 0..3),
        prop::collection::vec(ident_strategy(), 0..3),
        any::<bool>(),
        prop::collection::vec(safe_regex_strategy(), 0..2),
    )
        .prop_map(
            |(
                enabled,
                allowed_domains,
                blocked_domains,
                allowed_verbs,
                credential_detection,
                extra_credential_patterns,
            )| BrowserAutomationRule {
                enabled,
                when: None,
                allowed_domains,
                blocked_domains,
                allowed_verbs,
                credential_detection,
                extra_credential_patterns,
            },
        )
}

fn code_execution_strategy() -> impl Strategy<Value = CodeExecutionRule> {
    (
        any::<bool>(),
        prop::collection::vec(ident_strategy(), 0..3),
        prop::collection::vec(ident_strategy(), 0..3),
        any::<bool>(),
        prop::option::of(1usize..600_000),
        prop::option::of(1usize..1_000_000),
    )
        .prop_map(
            |(
                enabled,
                language_allowlist,
                module_denylist,
                network_access,
                max_execution_time_ms,
                max_scan_bytes,
            )| CodeExecutionRule {
                enabled,
                when: None,
                language_allowlist,
                module_denylist,
                network_access,
                max_execution_time_ms,
                max_scan_bytes,
            },
        )
}

fn rules_strategy() -> impl Strategy<Value = Rules> {
    let group_a = (
        prop::option::of(forbidden_paths_strategy()),
        prop::option::of(path_allowlist_strategy()),
        prop::option::of(egress_strategy()),
        prop::option::of(secret_patterns_strategy()),
        prop::option::of(patch_integrity_strategy()),
        prop::option::of(shell_commands_strategy()),
    );
    let group_b = (
        prop::option::of(tool_access_strategy()),
        prop::option::of(computer_use_strategy()),
        prop::option::of(remote_desktop_strategy()),
        prop::option::of(input_injection_strategy()),
        prop::option::of(browser_automation_strategy()),
        prop::option::of(code_execution_strategy()),
    );
    (group_a, group_b).prop_map(
        |(
            (
                forbidden_paths,
                path_allowlist,
                egress,
                secret_patterns,
                patch_integrity,
                shell_commands,
            ),
            (
                tool_access,
                computer_use,
                remote_desktop_channels,
                input_injection,
                browser_automation,
                code_execution,
            ),
        )| Rules {
            forbidden_paths,
            path_allowlist,
            egress,
            secret_patterns,
            patch_integrity,
            shell_commands,
            tool_access,
            computer_use,
            remote_desktop_channels,
            input_injection,
            browser_automation,
            code_execution,
        },
    )
}

/// A structurally valid `HushSpec`: no `extensions` (posture/origins are out
/// of scope for this generator), a fixed accepted `hushspec` version, and a
/// `rules` block built entirely from the strategies above.
fn policy_strategy() -> impl Strategy<Value = HushSpec> {
    (
        prop::option::of(ident_strategy()),
        prop::option::of(rules_strategy()),
    )
        .prop_map(|(name, rules)| HushSpec {
            hushspec: "0.1.0".to_string(),
            name,
            description: None,
            extends: None,
            merge_strategy: None,
            rules,
            extensions: None,
            metadata: None,
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// `serde_yaml` serialize -> `HushSpec::parse` (the YAML path in
    /// `schema.rs`) -> equal to the original value.
    #[test]
    fn hushspec_yaml_round_trip(spec in policy_strategy()) {
        let yaml = spec.to_yaml().expect("generated policy serializes to YAML");
        let parsed = HushSpec::parse(&yaml)
            .unwrap_or_else(|error| panic!("generated policy must re-parse from YAML: {error}\n{yaml}"));
        prop_assert_eq!(parsed, spec);
    }

    /// `serde_json` serialize -> parse via the JSON path -> equal to the
    /// original value. `schema.rs` and `lib.rs` expose only `HushSpec::parse`
    /// (YAML) as a named entry point; there is no `HushSpec::from_json` or
    /// similar in this crate, so "the JSON path" is `serde_json`'s generic
    /// `Deserialize` impl directly -- `HushSpec`'s derive is format-agnostic.
    #[test]
    fn hushspec_json_round_trip(spec in policy_strategy()) {
        let json = serde_json::to_string(&spec).expect("generated policy serializes to JSON");
        let parsed: HushSpec = serde_json::from_str(&json)
            .unwrap_or_else(|error| panic!("generated policy must re-parse from JSON: {error}\n{json}"));
        prop_assert_eq!(parsed, spec);
    }

    /// Every policy this generator produces must be accepted by `validate()`
    /// with zero errors (governance/rule-coverage warnings are fine).
    #[test]
    fn hushspec_generated_policy_validates(spec in policy_strategy()) {
        let result = validate(&spec);
        prop_assert!(
            result.is_valid(),
            "generated policy failed validation: {:?}",
            result.errors
        );
    }
}

// =====================================================================
// Condition strategies
// =====================================================================

fn hhmm_strategy() -> impl Strategy<Value = String> {
    (0u8..24, 0u8..60).prop_map(|(hour, minute)| format!("{hour:02}:{minute:02}"))
}

const TIMEZONES: &[&str] = &[
    "UTC",
    "America/New_York",
    "Asia/Kolkata",
    "Europe/London",
    "Australia/Sydney",
];

const DAYS: &[&str] = &["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

fn time_window_strategy() -> impl Strategy<Value = TimeWindowCondition> {
    (
        hhmm_strategy(),
        hhmm_strategy(),
        prop::option::of(prop::sample::select(TIMEZONES)),
        prop::collection::vec(prop::sample::select(DAYS), 0..7),
    )
        .prop_map(|(start, end, timezone, days)| TimeWindowCondition {
            start,
            end,
            timezone: timezone.map(str::to_string),
            days: days.into_iter().map(str::to_string).collect(),
        })
}

/// Nested `all_of` / `any_of` / `not` up to depth 4.
fn condition_strategy() -> impl Strategy<Value = Condition> {
    let leaf = prop_oneof![
        time_window_strategy().prop_map(|time_window| Condition {
            time_window: Some(time_window),
            ..Default::default()
        }),
        Just(Condition::default()),
    ];
    leaf.prop_recursive(4, 16, 3, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..3).prop_map(|all_of| Condition {
                all_of: Some(all_of),
                ..Default::default()
            }),
            prop::collection::vec(inner.clone(), 0..3).prop_map(|any_of| Condition {
                any_of: Some(any_of),
                ..Default::default()
            }),
            inner.prop_map(|c| Condition {
                not: Some(Box::new(c)),
                ..Default::default()
            }),
        ]
    })
}

fn runtime_context_strategy() -> impl Strategy<Value = RuntimeContext> {
    const ENVIRONMENTS: &[&str] = &["production", "staging", "development"];
    const ROLES: &[&str] = &["admin", "viewer", "sre"];
    // Fixed timestamps rather than `None` (which would fall back to the
    // system clock): determinism must hold for a *given* context, and using
    // the real clock could -- in principle, at a minute boundary -- make two
    // back-to-back `evaluate_condition` calls disagree for reasons that have
    // nothing to do with the function itself.
    const TIMES: &[&str] = &[
        "2026-01-14T10:30:00Z",
        "2026-01-14T23:00:00Z",
        "2026-01-17T03:00:00Z",
        "2026-07-01T13:30:00Z",
    ];

    (
        prop::option::of(prop::sample::select(ENVIRONMENTS)),
        prop::option::of(prop::sample::select(ROLES)),
        prop::sample::select(TIMES),
    )
        .prop_map(|(environment, role, current_time)| {
            let mut user = HashMap::new();
            if let Some(role) = role {
                user.insert(
                    "role".to_string(),
                    serde_json::Value::String(role.to_string()),
                );
            }
            RuntimeContext {
                user,
                environment: environment.map(str::to_string),
                current_time: Some(current_time.to_string()),
                ..Default::default()
            }
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn condition_json_round_trip(condition in condition_strategy()) {
        let json = serde_json::to_string(&condition).expect("condition serializes to JSON");
        let parsed: Condition = serde_json::from_str(&json)
            .unwrap_or_else(|error| panic!("condition must re-parse from JSON: {error}\n{json}"));
        prop_assert_eq!(parsed, condition);
    }

    /// Same condition + same context evaluated twice must always agree.
    #[test]
    fn condition_evaluation_is_deterministic(
        condition in condition_strategy(),
        context in runtime_context_strategy(),
    ) {
        let first = evaluate_condition(&condition, &context);
        let second = evaluate_condition(&condition, &context);
        prop_assert_eq!(first, second);
    }
}

// =====================================================================
// DecisionReceipt strategies
// =====================================================================

fn action_type_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("tool_call".to_string()),
        Just("egress".to_string()),
        Just("file_read".to_string()),
        Just("file_write".to_string()),
        Just("patch_apply".to_string()),
        Just("shell_command".to_string()),
        Just("computer_use".to_string()),
        Just("unknown_action".to_string()),
    ]
}

fn action_strategy() -> impl Strategy<Value = EvaluationAction> {
    (
        action_type_strategy(),
        prop::option::of(prop_oneof![
            ident_strategy(),
            glob_pattern_strategy(),
            domain_strategy(),
        ]),
        prop::option::of(string_regex("[ -~]{0,80}").expect("valid generator regex")),
        prop::option::of(0usize..8192),
    )
        .prop_map(
            |(action_type, target, content, args_size)| EvaluationAction {
                url: None,
                network: None,
                timeout_ms: None,
                context: None,
                action_type,
                target,
                content,
                origin: None,
                posture: None,
                args_size,
            },
        )
}

/// The compiled receipt schema, built once for the whole file: compiling it
/// per proptest case dominated the runtime of `decision_receipt_matches_schema`.
static RECEIPT_SCHEMA: std::sync::LazyLock<jsonschema::JSONSchema> =
    std::sync::LazyLock::new(compile_receipt_schema);

/// Compiles `schemas/hushspec-receipt.v0.schema.json`. `tests/receipt.rs` has
/// its own copy: integration test files are separate compilation units.
fn compile_receipt_schema() -> jsonschema::JSONSchema {
    let schema_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../schemas/hushspec-receipt.v0.schema.json"
    );
    let schema_text = std::fs::read_to_string(schema_path)
        .unwrap_or_else(|e| panic!("failed to read {schema_path}: {e}"));
    let schema: serde_json::Value = serde_json::from_str(&schema_text).unwrap();
    jsonschema::JSONSchema::options()
        .should_validate_formats(true)
        .compile(&schema)
        .unwrap_or_else(|e| panic!("receipt schema failed to compile: {e}"))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn decision_receipt_json_round_trip(spec in policy_strategy(), action in action_strategy()) {
        let receipt = evaluate_audited_spec(&spec, &action, &AuditConfig::default(), &AuditContext::default())
            .expect("generated policies are resolved");
        let json = serde_json::to_string(&receipt).expect("receipt serializes to JSON");
        let parsed = DecisionReceipt::parse(&json)
            .unwrap_or_else(|error| panic!("receipt must re-parse from JSON: {error}\n{json}"));
        prop_assert_eq!(parsed.clone(), receipt.clone());
        // Canonical form is stable: re-serializing the parsed receipt hashes the same.
        prop_assert_eq!(parsed.receipt_hash().unwrap(), receipt.receipt_hash().unwrap());
    }

    #[test]
    fn decision_receipt_matches_schema(spec in policy_strategy(), action in action_strategy()) {
        let receipt = evaluate_audited_spec(&spec, &action, &AuditConfig::default(), &AuditContext::default())
            .expect("generated policies are resolved");
        let value = serde_json::to_value(&receipt).expect("receipt serializes to JSON value");
        if let Err(errors) = RECEIPT_SCHEMA.validate(&value) {
            let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
            prop_assert!(false, "receipt failed schema validation: {messages:?}\n{value:#}");
        }
    }
}

// =====================================================================
// Merge strategies
// =====================================================================

fn replace_pair_strategy() -> impl Strategy<Value = (HushSpec, HushSpec)> {
    (
        prop::option::of(ident_strategy()),
        rules_strategy(),
        ident_strategy(),
        prop::option::of(ident_strategy()),
        rules_strategy(),
    )
        .prop_map(
            |(base_name, base_rules, extends_ref, child_name, child_rules)| {
                let base = HushSpec {
                    hushspec: "0.1.0".to_string(),
                    name: base_name,
                    description: None,
                    extends: None,
                    merge_strategy: None,
                    rules: Some(base_rules),
                    extensions: None,
                    metadata: None,
                };
                let child = HushSpec {
                    hushspec: "0.1.0".to_string(),
                    name: child_name,
                    description: None,
                    extends: Some(extends_ref),
                    merge_strategy: Some(MergeStrategy::Replace),
                    rules: Some(child_rules),
                    extensions: None,
                    metadata: None,
                };
                (base, child)
            },
        )
}

fn deep_merge_pair_strategy() -> impl Strategy<Value = (HushSpec, HushSpec)> {
    (
        prop::option::of(ident_strategy()),
        rules_strategy(),
        ident_strategy(),
        prop::option::of(ident_strategy()),
        rules_strategy(),
    )
        .prop_map(
            |(base_name, base_rules, extends_ref, child_name, child_rules)| {
                let base = HushSpec {
                    hushspec: "0.1.0".to_string(),
                    name: base_name,
                    description: None,
                    extends: None,
                    merge_strategy: None,
                    rules: Some(base_rules),
                    extensions: None,
                    metadata: None,
                };
                let child = HushSpec {
                    hushspec: "0.1.0".to_string(),
                    name: child_name,
                    description: None,
                    extends: Some(extends_ref),
                    merge_strategy: Some(MergeStrategy::DeepMerge),
                    rules: Some(child_rules),
                    extensions: None,
                    metadata: None,
                };
                (base, child)
            },
        )
}

/// Asserts `merged.$field` equals `child.$field` when the child sets it, and
/// falls back to `base.$field` (preserved) when the child leaves it unset.
macro_rules! assert_block_preserved_or_overridden {
    ($base:expr, $child:expr, $merged:expr, $field:ident) => {
        match &$child.$field {
            Some(_) => prop_assert_eq!(&$merged.$field, &$child.$field),
            None => prop_assert_eq!(&$merged.$field, &$base.$field),
        }
    };
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// `merge` with `replace` equals the child document, minus the two
    /// resolution instructions `merge` always consumes so the result is a
    /// self-contained resolved document (core spec 2.3).
    #[test]
    fn merge_replace_equals_child_minus_resolution_fields((base, child) in replace_pair_strategy()) {
        let merged = merge(&base, &child);
        let mut expected = child.clone();
        expected.extends = None;
        expected.merge_strategy = None;
        prop_assert_eq!(merged, expected);
    }

    /// `deep_merge` (the default strategy) preserves every base rule block
    /// the child leaves unset, and lets the child override every block it
    /// does set -- field by field, not merge-or-nothing at the `rules` level.
    #[test]
    fn deep_merge_preserves_base_blocks_absent_in_child((base, child) in deep_merge_pair_strategy()) {
        let merged = merge(&base, &child);
        let base_rules = base.rules.as_ref().expect("generator always sets base.rules");
        let child_rules = child.rules.as_ref().expect("generator always sets child.rules");
        let merged_rules = merged.rules.as_ref().expect("deep merge always yields rules");

        assert_block_preserved_or_overridden!(base_rules, child_rules, merged_rules, forbidden_paths);
        assert_block_preserved_or_overridden!(base_rules, child_rules, merged_rules, path_allowlist);
        assert_block_preserved_or_overridden!(base_rules, child_rules, merged_rules, egress);
        assert_block_preserved_or_overridden!(base_rules, child_rules, merged_rules, secret_patterns);
        assert_block_preserved_or_overridden!(base_rules, child_rules, merged_rules, patch_integrity);
        assert_block_preserved_or_overridden!(base_rules, child_rules, merged_rules, shell_commands);
        assert_block_preserved_or_overridden!(base_rules, child_rules, merged_rules, tool_access);
        assert_block_preserved_or_overridden!(base_rules, child_rules, merged_rules, computer_use);
        assert_block_preserved_or_overridden!(base_rules, child_rules, merged_rules, remote_desktop_channels);
        assert_block_preserved_or_overridden!(base_rules, child_rules, merged_rules, input_injection);
        assert_block_preserved_or_overridden!(base_rules, child_rules, merged_rules, browser_automation);
        assert_block_preserved_or_overridden!(base_rules, child_rules, merged_rules, code_execution);

        // Core spec 2.3: the child names `deep_merge`, and the resolved
        // document that comes back says nothing about how it was assembled.
        prop_assert!(merged.extends.is_none());
        prop_assert!(merged.merge_strategy.is_none());
    }
}
