use crate::bundle::{BUNDLE_FORMAT_VERSION, CaseAction, CaseBundle, CaseGroup};
use hushspec::extensions::{
    Extensions, OriginMatch, OriginProfile, OriginsExtension, PostureExtension, PostureState,
    PostureTransition, TransitionTrigger,
};
use hushspec::{
    ComputerUseMode, ComputerUseRule, DefaultAction, EgressRule, EvaluationAction,
    ForbiddenPathsRule, HushSpec, InputInjectionRule, OriginContext, PatchIntegrityRule,
    PathAllowlistRule, PostureContext, RemoteDesktopChannelsRule, Rules, SecretPattern,
    SecretPatternsRule, Severity, ShellCommandsRule, ToolAccessRule,
};
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::string::string_regex;
use proptest::test_runner::{Config as ProptestConfig, RngAlgorithm, TestRng, TestRunner};

const MAX_RESAMPLE_ATTEMPTS: usize = 100;
const POSTURE_STATE_POOL: &[&str] = &["baseline", "elevated", "lockdown"];
const CAPABILITY_POOL: &[&str] = &[
    "file_access",
    "file_write",
    "patch",
    "shell",
    "tool_call",
    "egress",
];
const PROVIDERS: &[&str] = &["slack", "github", "teams", "jira"];
const SPACE_TYPES: &[&str] = &[
    "channel",
    "group",
    "dm",
    "thread",
    "issue",
    "ticket",
    "pull_request",
    "email_thread",
];
const VISIBILITIES: &[&str] = &["private", "internal", "public", "external_shared"];

pub struct GenConfig {
    pub groups: usize,
    pub actions_per_group: usize,
}

/// Deterministic for a given (seed, config) within one dependency snapshot.
/// Every emitted policy passes `hushspec::validate`.
pub fn generate_bundle(seed: u64, config: &GenConfig) -> CaseBundle {
    let mut runner = seeded_runner(seed);
    let mut groups = Vec::with_capacity(config.groups);
    for group_index in 0..config.groups {
        let spec = sample_valid_policy(&mut runner, seed, group_index);
        let harvest = harvest_targets(&spec);
        let mut actions = Vec::with_capacity(config.actions_per_group);
        for action_index in 0..config.actions_per_group {
            let action = sample(&mut runner, action_strategy(&harvest));
            actions.push(CaseAction {
                id: format!("a{:04}", action_index + 1),
                action: serde_json::to_value(&action).expect("actions serialize"),
            });
        }
        groups.push(CaseGroup {
            id: format!("g{:04}", group_index + 1),
            policy: serde_json::to_value(&spec).expect("policies serialize"),
            actions,
        });
    }
    CaseBundle {
        hushspec_diff: BUNDLE_FORMAT_VERSION.to_string(),
        seed,
        generated_by: format!("hushspec-gen {}", env!("CARGO_PKG_VERSION")),
        groups,
    }
}

/// Random u64 from the OS-keyed sip hasher (no extra dependency).
pub fn random_seed() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish()
}

/// Stable, toolchain-independent seed derivation (e.g. from a commit SHA).
pub fn seed_from_string(text: &str) -> u64 {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(text.as_bytes());
    u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("sha256 yields at least 8 bytes"),
    )
}

fn seeded_runner(seed: u64) -> TestRunner {
    let mut bytes = [0u8; 32];
    for (index, chunk) in bytes.chunks_mut(8).enumerate() {
        chunk.copy_from_slice(&seed.wrapping_add(index as u64).to_le_bytes());
    }
    TestRunner::new_with_rng(
        ProptestConfig::default(),
        TestRng::from_seed(RngAlgorithm::ChaCha, &bytes),
    )
}

fn sample<S: Strategy>(runner: &mut TestRunner, strategy: S) -> S::Value {
    strategy
        .new_tree(runner)
        .expect("strategy produces a value")
        .current()
}

fn sample_valid_policy(runner: &mut TestRunner, seed: u64, group_index: usize) -> HushSpec {
    for _ in 0..MAX_RESAMPLE_ATTEMPTS {
        let spec = sample(runner, policy_strategy());
        if hushspec::validate(&spec).is_valid() {
            return spec;
        }
    }
    panic!(
        "generator bug: no valid policy after {MAX_RESAMPLE_ATTEMPTS} attempts (seed {seed}, group {group_index})"
    );
}

// ---------- primitive strategies ----------

fn ident_strategy() -> impl Strategy<Value = String> {
    string_regex("[a-z][a-z0-9_]{0,11}").expect("valid generator regex")
}

fn domain_strategy() -> impl Strategy<Value = String> {
    string_regex("[a-z]{3,10}\\.(com|dev|internal)").expect("valid generator regex")
}

fn path_strategy() -> impl Strategy<Value = String> {
    string_regex("(/[a-z0-9_.]{1,10}){1,4}").expect("valid generator regex")
}

fn glob_pattern_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("**/.ssh/**".to_string()),
        Just("/etc/passwd".to_string()),
        path_strategy(),
        ident_strategy().prop_map(|name| format!("**/{name}/**")),
        ident_strategy().prop_map(|name| format!("src/*.{name}")),
        ident_strategy().prop_map(|name| format!("{name}/?.txt")),
    ]
}

/// Regexes guaranteed to compile and behave identically in Rust `regex`,
/// JS `RegExp`, Python `re`, and Go `regexp`: no `\d`/`\w`/`\s`, no
/// lookaround, no backreferences, no flags.
fn safe_regex_strategy() -> impl Strategy<Value = String> {
    let literal = || string_regex("[a-z]{2,8}").expect("valid generator regex");
    prop_oneof![
        literal(),
        literal().prop_map(|text| format!("^{text}")),
        literal().prop_map(|text| format!("{text}[0-9]{{2,4}}")),
        (literal(), literal()).prop_map(|(left, right)| format!("({left}|{right})")),
        literal().prop_map(|text| format!("{text}-[a-z0-9]{{4,16}}")),
    ]
}

fn default_action_strategy() -> impl Strategy<Value = DefaultAction> {
    prop_oneof![Just(DefaultAction::Allow), Just(DefaultAction::Block)]
}

// ---------- rule-block strategies ----------

fn forbidden_paths_strategy() -> impl Strategy<Value = ForbiddenPathsRule> {
    (
        any::<bool>(),
        prop::collection::vec(glob_pattern_strategy(), 0..5),
        prop::collection::vec(glob_pattern_strategy(), 0..3),
    )
        .prop_map(|(enabled, patterns, exceptions)| ForbiddenPathsRule {
            enabled,
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
            allow,
            block,
            default,
        })
}

fn secret_patterns_strategy() -> impl Strategy<Value = SecretPatternsRule> {
    let pattern = (
        ident_strategy(),
        safe_regex_strategy(),
        prop_oneof![
            Just(Severity::Critical),
            Just(Severity::Error),
            Just(Severity::Warn)
        ],
    )
        .prop_map(|(name, pattern, severity)| SecretPattern {
            name,
            pattern,
            severity,
            description: None,
        });
    (
        any::<bool>(),
        prop::collection::vec(pattern, 0..4),
        prop::collection::vec(glob_pattern_strategy(), 0..3),
    )
        .prop_map(|(enabled, mut patterns, skip_paths)| {
            // Duplicate names fail validation; suffix by index to keep them unique.
            for (index, entry) in patterns.iter_mut().enumerate() {
                entry.name = format!("{}_{index}", entry.name);
            }
            SecretPatternsRule {
                enabled,
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
        1u32..32,
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
                    max_additions,
                    max_deletions,
                    forbidden_patterns,
                    require_balance,
                    // Exact-in-JSON floats avoid cross-language formatting noise.
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
        prop::option::of(1usize..4096),
    )
        .prop_map(
            |(enabled, allow, block, require_confirmation, default, max_args_size)| {
                ToolAccessRule {
                    enabled,
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
        prop_oneof![
            Just(ComputerUseMode::Observe),
            Just(ComputerUseMode::Guardrail),
            Just(ComputerUseMode::FailClosed),
        ],
        prop::collection::vec(ident_strategy(), 0..4),
    )
        .prop_map(|(enabled, mode, allowed_actions)| ComputerUseRule {
            enabled,
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
                allowed_types,
                require_postcondition_probe,
            },
        )
}

fn rules_strategy() -> impl Strategy<Value = Rules> {
    (
        prop::option::of(forbidden_paths_strategy()),
        prop::option::of(path_allowlist_strategy()),
        prop::option::of(egress_strategy()),
        prop::option::of(secret_patterns_strategy()),
        prop::option::of(patch_integrity_strategy()),
        prop::option::of(shell_commands_strategy()),
        prop::option::of(tool_access_strategy()),
        prop::option::of(computer_use_strategy()),
        prop::option::of(remote_desktop_strategy()),
        prop::option::of(input_injection_strategy()),
    )
        .prop_map(
            |(
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
                // Phase-gated blocks: no evaluation semantics yet.
                browser_automation: None,
                code_execution: None,
            },
        )
}

// ---------- extension strategies ----------

fn trigger_strategy() -> impl Strategy<Value = TransitionTrigger> {
    prop_oneof![
        Just(TransitionTrigger::UserApproval),
        Just(TransitionTrigger::UserDenial),
        Just(TransitionTrigger::CriticalViolation),
        Just(TransitionTrigger::AnyViolation),
        Just(TransitionTrigger::Timeout),
        Just(TransitionTrigger::BudgetExhausted),
        Just(TransitionTrigger::PatternMatch),
    ]
}

fn posture_state_strategy() -> impl Strategy<Value = PostureState> {
    prop::collection::btree_set(
        prop::sample::select(CAPABILITY_POOL),
        0..=CAPABILITY_POOL.len(),
    )
    .prop_map(|capabilities| PostureState {
        description: None,
        capabilities: capabilities.into_iter().map(str::to_string).collect(),
        budgets: std::collections::BTreeMap::new(),
    })
}

fn posture_strategy() -> impl Strategy<Value = PostureExtension> {
    (
        1usize..=POSTURE_STATE_POOL.len(),
        prop::collection::vec(posture_state_strategy(), POSTURE_STATE_POOL.len()),
        prop::collection::vec((0usize..4, 0usize..3, trigger_strategy()), 0..3),
    )
        .prop_map(|(state_count, state_bodies, transition_seeds)| {
            let names: Vec<String> = POSTURE_STATE_POOL
                .iter()
                .take(state_count)
                .map(|name| (*name).to_string())
                .collect();
            let states: std::collections::BTreeMap<String, PostureState> = names
                .iter()
                .cloned()
                .zip(state_bodies.into_iter().take(state_count))
                .collect();
            let transitions = transition_seeds
                .into_iter()
                .map(|(from_seed, to_seed, on)| PostureTransition {
                    // from_seed >= state_count selects the wildcard.
                    from: if from_seed >= state_count {
                        "*".to_string()
                    } else {
                        names[from_seed].clone()
                    },
                    to: names[to_seed % state_count].clone(),
                    // Timeout triggers require a duration (validate_posture).
                    after: (on == TransitionTrigger::Timeout).then(|| "30s".to_string()),
                    on,
                })
                .collect();
            PostureExtension {
                initial: names[0].clone(),
                states,
                transitions,
            }
        })
}

fn origin_match_strategy() -> impl Strategy<Value = OriginMatch> {
    (
        prop::option::of(prop::sample::select(PROVIDERS)),
        prop::option::of(prop::sample::select(SPACE_TYPES)),
        prop::option::of(prop::sample::select(VISIBILITIES)),
        prop::option::of(any::<bool>()),
        prop::collection::vec(ident_strategy(), 0..3),
    )
        .prop_map(
            |(provider, space_type, visibility, external_participants, tags)| OriginMatch {
                provider: provider.map(str::to_string),
                tenant_id: None,
                space_id: None,
                space_type: space_type.map(str::to_string),
                visibility: visibility.map(str::to_string),
                external_participants,
                tags,
                sensitivity: None,
                actor_role: None,
            },
        )
}

fn origins_strategy() -> impl Strategy<Value = OriginsExtension> {
    let profile = (
        origin_match_strategy(),
        prop::option::of(tool_access_strategy()),
        prop::option::of(egress_strategy()),
    )
        .prop_map(|(match_rules, tool_access, egress)| OriginProfile {
            id: String::new(), // unique ids assigned below
            match_rules: Some(match_rules),
            posture: None,
            tool_access,
            egress,
            data: None,
            budgets: None,
            bridge: None,
            explanation: None,
        });
    prop::collection::vec(profile, 1..=3).prop_map(|mut profiles| {
        for (index, profile) in profiles.iter_mut().enumerate() {
            profile.id = format!("profile_{index}");
        }
        OriginsExtension {
            default_behavior: None,
            profiles,
        }
    })
}

fn policy_strategy() -> impl Strategy<Value = HushSpec> {
    (
        prop::option::of(ident_strategy()),
        prop::option::of(rules_strategy()),
        prop::option::weighted(0.35, posture_strategy()),
        prop::option::weighted(0.35, origins_strategy()),
    )
        .prop_map(|(name, rules, posture, origins)| {
            let extensions = if posture.is_none() && origins.is_none() {
                None
            } else {
                Some(Extensions {
                    posture,
                    origins,
                    detection: None,
                })
            };
            HushSpec {
                hushspec: "0.1.0".to_string(),
                name,
                description: None,
                extends: None,
                merge_strategy: None,
                rules,
                extensions,
                metadata: None,
            }
        })
}

// ---------- policy-aware action strategies ----------

struct TargetHarvest {
    targets: Vec<String>,
    secret_regexes: Vec<String>,
    posture_states: Vec<String>,
    has_origins: bool,
}

fn harvest_targets(spec: &HushSpec) -> TargetHarvest {
    let mut targets: Vec<String> = vec![
        "read_file".to_string(),
        "api.example.com".to_string(),
        "/workspace/src/main.rs".to_string(),
        "remote.clipboard".to_string(),
        "remote.file_transfer".to_string(),
        "remote.audio".to_string(),
        "remote.drive_mapping".to_string(),
    ];
    let mut secret_regexes = Vec::new();
    if let Some(rules) = &spec.rules {
        if let Some(rule) = &rules.forbidden_paths {
            targets.extend(rule.patterns.iter().map(|p| instantiate_glob(p)));
            targets.extend(rule.exceptions.iter().map(|p| instantiate_glob(p)));
        }
        if let Some(rule) = &rules.path_allowlist {
            targets.extend(rule.read.iter().map(|p| instantiate_glob(p)));
            targets.extend(rule.write.iter().map(|p| instantiate_glob(p)));
            targets.extend(rule.patch.iter().map(|p| instantiate_glob(p)));
        }
        if let Some(rule) = &rules.egress {
            targets.extend(rule.allow.iter().cloned());
            targets.extend(rule.block.iter().cloned());
        }
        if let Some(rule) = &rules.tool_access {
            targets.extend(rule.allow.iter().cloned());
            targets.extend(rule.block.iter().cloned());
            targets.extend(rule.require_confirmation.iter().cloned());
        }
        if let Some(rule) = &rules.computer_use {
            targets.extend(rule.allowed_actions.iter().cloned());
        }
        if let Some(rule) = &rules.input_injection {
            targets.extend(rule.allowed_types.iter().cloned());
        }
        if let Some(rule) = &rules.secret_patterns {
            secret_regexes.extend(rule.patterns.iter().map(|p| p.pattern.clone()));
        }
    }
    let posture_states = spec
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.posture.as_ref())
        .map(|posture| posture.states.keys().cloned().collect())
        .unwrap_or_default();
    TargetHarvest {
        targets,
        secret_regexes,
        posture_states,
        has_origins: spec
            .extensions
            .as_ref()
            .is_some_and(|extensions| extensions.origins.is_some()),
    }
}

/// Deterministic glob instantiation: "**/x/**" -> "a/b/x/a/b" etc.
fn instantiate_glob(pattern: &str) -> String {
    pattern
        .replace("**", "a/b")
        .replace('*', "x")
        .replace('?', "q")
}

fn action_strategy(harvest: &TargetHarvest) -> impl Strategy<Value = EvaluationAction> {
    let action_type = prop_oneof![
        4 => Just("tool_call".to_string()),
        4 => Just("egress".to_string()),
        4 => Just("file_read".to_string()),
        4 => Just("file_write".to_string()),
        3 => Just("patch_apply".to_string()),
        3 => Just("shell_command".to_string()),
        3 => Just("computer_use".to_string()),
        2 => Just("input_inject".to_string()),
        1 => Just("unknown_action".to_string()),
    ];
    (
        action_type,
        target_strategy(harvest),
        content_strategy(harvest),
        origin_context_strategy(harvest),
        posture_context_strategy(harvest),
        prop::option::of(0usize..8192),
    )
        .prop_map(
            |(action_type, target, content, origin, posture, args_size)| EvaluationAction {
                action_type,
                target,
                content,
                origin,
                posture,
                args_size,
            },
        )
}

fn target_strategy(harvest: &TargetHarvest) -> impl Strategy<Value = Option<String>> {
    let harvested = prop::sample::select(harvest.targets.clone());
    prop_oneof![
        4 => harvested.clone().prop_map(Some),
        2 => harvested.prop_map(|target| Some(format!("{target}_x"))),
        3 => path_strategy().prop_map(Some),
        1 => Just(None),
    ]
}

fn content_strategy(harvest: &TargetHarvest) -> BoxedStrategy<Option<String>> {
    let mut options: Vec<BoxedStrategy<Option<String>>> = vec![
        Just(None).boxed(),
        string_regex("[ -~]{0,200}")
            .expect("valid generator regex")
            .prop_map(Some)
            .boxed(),
        diff_content_strategy().prop_map(Some).boxed(),
    ];
    // Strings that MATCH the policy's own secret patterns (exercises deny paths).
    for pattern in harvest.secret_regexes.iter().take(2) {
        if let Ok(matching) = string_regex(pattern) {
            options.push(matching.prop_map(Some).boxed());
        }
    }
    proptest::strategy::Union::new(options).boxed()
}

fn diff_content_strategy() -> impl Strategy<Value = String> {
    (0usize..40, 0usize..40).prop_map(|(additions, deletions)| {
        let mut out = String::from("--- a/file\n+++ b/file\n");
        for index in 0..additions {
            out.push_str(&format!("+line {index}\n"));
        }
        for index in 0..deletions {
            out.push_str(&format!("-line {index}\n"));
        }
        out
    })
}

fn origin_context_strategy(harvest: &TargetHarvest) -> BoxedStrategy<Option<OriginContext>> {
    let context = (
        prop::option::of(prop::sample::select(PROVIDERS)),
        prop::option::of(prop::sample::select(SPACE_TYPES)),
        prop::option::of(prop::sample::select(VISIBILITIES)),
        prop::option::of(any::<bool>()),
        prop::collection::vec(ident_strategy(), 0..3),
    )
        .prop_map(
            |(provider, space_type, visibility, external_participants, tags)| OriginContext {
                provider: provider.map(str::to_string),
                tenant_id: None,
                space_id: None,
                space_type: space_type.map(str::to_string),
                visibility: visibility.map(str::to_string),
                external_participants,
                tags,
                sensitivity: None,
                actor_role: None,
            },
        );
    let with_origin_weight: u32 = if harvest.has_origins { 7 } else { 2 };
    prop_oneof![
        with_origin_weight => context.prop_map(Some),
        3 => Just(None),
    ]
    .boxed()
}

fn posture_context_strategy(harvest: &TargetHarvest) -> BoxedStrategy<Option<PostureContext>> {
    if harvest.posture_states.is_empty() {
        return Just(None).boxed();
    }
    let states = harvest.posture_states.clone();
    let signals: Vec<&'static str> = vec![
        "none",
        "user_approval",
        "critical_violation",
        "budget_exhausted",
    ];
    (
        prop::option::of(prop::sample::select(states)),
        prop::option::of(prop::sample::select(signals)),
    )
        .prop_map(|(current, signal)| {
            Some(PostureContext {
                current,
                signal: signal.map(str::to_string),
            })
        })
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_produces_identical_bundles() {
        let config = GenConfig {
            groups: 10,
            actions_per_group: 3,
        };
        assert_eq!(generate_bundle(42, &config), generate_bundle(42, &config));
    }

    #[test]
    fn different_seeds_produce_different_bundles() {
        let config = GenConfig {
            groups: 10,
            actions_per_group: 3,
        };
        assert_ne!(generate_bundle(42, &config), generate_bundle(43, &config));
    }

    #[test]
    fn bundle_shape_matches_config() {
        let bundle = generate_bundle(
            7,
            &GenConfig {
                groups: 5,
                actions_per_group: 2,
            },
        );
        assert_eq!(bundle.hushspec_diff, BUNDLE_FORMAT_VERSION);
        assert_eq!(bundle.seed, 7);
        assert_eq!(bundle.groups.len(), 5);
        assert_eq!(bundle.case_count(), 10);
        assert_eq!(bundle.groups[0].id, "g0001");
        assert_eq!(bundle.groups[0].actions[0].id, "a0001");
    }

    #[test]
    fn every_generated_policy_is_rust_valid() {
        let bundle = generate_bundle(
            11,
            &GenConfig {
                groups: 25,
                actions_per_group: 1,
            },
        );
        for group in &bundle.groups {
            let yaml = serde_yaml::to_string(&group.policy).expect("policy re-encodes");
            let spec = HushSpec::parse(&yaml).unwrap_or_else(|error| {
                panic!("{}: generated policy must parse: {error}", group.id)
            });
            assert!(
                hushspec::validate(&spec).is_valid(),
                "{}: generated policy must validate",
                group.id
            );
        }
    }

    #[test]
    fn every_generated_action_deserializes() {
        let bundle = generate_bundle(
            11,
            &GenConfig {
                groups: 25,
                actions_per_group: 2,
            },
        );
        for group in &bundle.groups {
            for case in &group.actions {
                let action: EvaluationAction = serde_json::from_value(case.action.clone())
                    .unwrap_or_else(|error| panic!("{}/{}: {error}", group.id, case.id));
                assert!(!action.action_type.is_empty());
            }
        }
    }

    #[test]
    fn seed_from_string_is_deterministic() {
        assert_eq!(seed_from_string("abc"), seed_from_string("abc"));
        assert_ne!(seed_from_string("abc"), seed_from_string("abd"));
    }
}
