use crate::bundle::{AuditSpec, BUNDLE_FORMAT_VERSION, CaseAction, CaseBundle, CaseGroup};
use crate::diff::{CaseEvaluator, CompareOptions, DiffError, DivergenceKind, compare_reports};
use serde_json::Value;

pub struct MinimizeConfig {
    pub max_rounds: usize,
}

impl Default for MinimizeConfig {
    fn default() -> Self {
        Self { max_rounds: 40 }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MinimizedCase {
    pub policy: Value,
    pub action: Value,
    pub sdk: String,
    pub kind: DivergenceKind,
    pub rounds: usize,
}

/// Greedy structural shrinking: each round batches all single-step
/// reductions into ONE bundle (one subprocess call for the failing SDK),
/// keeps the first still-diverging candidate, and repeats to fixpoint.
/// Candidates that Rust would reject are discarded so every probe stays
/// Rust-valid.
pub fn minimize_case(
    policy: &Value,
    action: &Value,
    oracle: &mut dyn CaseEvaluator,
    failing: &mut dyn CaseEvaluator,
    options: &CompareOptions,
    config: &MinimizeConfig,
) -> Result<MinimizedCase, DiffError> {
    let mut current_policy = policy.clone();
    let mut current_action = action.clone();
    let Some(mut kind) =
        case_divergence(&current_policy, &current_action, oracle, failing, options)?
    else {
        return Err(DiffError::Config(
            "case does not diverge; nothing to minimize".to_string(),
        ));
    };

    let mut rounds = 0;
    while rounds < config.max_rounds {
        rounds += 1;
        let candidates: Vec<(Value, Value)> = shrink_candidates(&current_policy, &current_action)
            .into_iter()
            .filter(|(candidate_policy, _)| rust_accepts(candidate_policy))
            .collect();
        if candidates.is_empty() {
            break;
        }

        let bundle = candidates_bundle(&candidates);
        let oracle_report = oracle.evaluate_bundle(&bundle)?;
        let failing_report = failing.evaluate_bundle(&bundle)?;
        let divergences = compare_reports(&oracle_report, &failing_report, options);

        // Phantom divergences are harness-fabricated case keys that were
        // never part of the bundle this round evaluated. The reference always
        // answers exactly the candidate keys `candidates_bundle` generated
        // (one per entry in `candidates`), so a key it never produced isn't
        // a shrinkable candidate at all: `candidate_index` applied to an
        // arbitrary phantom key can parse to an out-of-range index (or,
        // worse, a coincidentally in-range index for an unrelated
        // candidate never shown to diverge). Skip phantoms when picking the
        // shrink target -- only a real (non-phantom) divergence is
        // guaranteed by `compare_reports`'s contract to map back to a
        // candidate that actually diverged.
        let Some(first) = divergences
            .iter()
            .find(|divergence| divergence.kind != DivergenceKind::PhantomCase)
        else {
            break; // no real (non-phantom) divergence this round: fixpoint
        };
        let index = candidate_index(&first.case_key)
            .ok_or_else(|| DiffError::Config(format!("bad candidate key {}", first.case_key)))?;
        let Some((next_policy, next_action)) = candidates.get(index).cloned() else {
            return Err(DiffError::Config(format!(
                "candidate key {} out of range ({} candidates this round)",
                first.case_key,
                candidates.len()
            )));
        };
        kind = first.kind;
        current_policy = next_policy;
        current_action = next_action;
    }

    Ok(MinimizedCase {
        policy: current_policy,
        action: current_action,
        sdk: failing.sdk_name().to_string(),
        kind,
        rounds,
    })
}

fn case_divergence(
    policy: &Value,
    action: &Value,
    oracle: &mut dyn CaseEvaluator,
    failing: &mut dyn CaseEvaluator,
    options: &CompareOptions,
) -> Result<Option<DivergenceKind>, DiffError> {
    let bundle = CaseBundle::single_case(policy.clone(), action.clone());
    let oracle_report = oracle.evaluate_bundle(&bundle)?;
    let failing_report = failing.evaluate_bundle(&bundle)?;
    Ok(compare_reports(&oracle_report, &failing_report, options)
        .first()
        .map(|divergence| divergence.kind))
}

fn candidates_bundle(candidates: &[(Value, Value)]) -> CaseBundle {
    CaseBundle {
        hushspec_diff: BUNDLE_FORMAT_VERSION.to_string(),
        seed: 0,
        generated_by: "hushspec-minimize".to_string(),
        // The shrink probes carry the default audit inputs, and so does the
        // single-case bundle `case_divergence` starts from: both sides of every
        // probe replay the same clock, actor and receipt ids, so a receipt
        // divergence stays reproducible all the way down to the minimized case.
        audit: AuditSpec::default(),
        groups: candidates
            .iter()
            .enumerate()
            .map(|(index, (policy, action))| CaseGroup {
                id: format!("g{:04}", index + 1),
                policy: policy.clone(),
                actions: vec![CaseAction {
                    id: "a0001".to_string(),
                    action: action.clone(),
                }],
            })
            .collect(),
    }
}

fn candidate_index(case_key: &str) -> Option<usize> {
    let group = case_key.split('/').next()?;
    let number: usize = group.strip_prefix('g')?.parse().ok()?;
    number.checked_sub(1)
}

/// Whether the reference would evaluate this candidate rather than reject it.
/// Applies `diff::parse_policy`'s exact sequence -- parse, resolve `extends`,
/// validate -- so a candidate that survives here is one the reference can
/// actually answer for, and shrinking never wanders into a bundle where every
/// SDK merely agrees on "rejected".
fn rust_accepts(policy: &Value) -> bool {
    let Ok(yaml) = serde_yaml::to_string(policy) else {
        return false;
    };
    let Ok(spec) = hushspec::HushSpec::parse(&yaml) else {
        return false;
    };
    let spec = if spec.extends.is_some() {
        match crate::diff::resolve_builtin_extends(&spec) {
            Ok(resolved) => resolved,
            Err(_) => return false,
        }
    } else {
        spec
    };
    hushspec::validate(&spec).is_valid()
}

/// All single-step reductions of (policy, action).
fn shrink_candidates(policy: &Value, action: &Value) -> Vec<(Value, Value)> {
    let mut candidates = Vec::new();

    if let Value::Object(map) = policy {
        // Drop each top-level key except the required version marker.
        for key in map.keys() {
            if key == "hushspec" {
                continue;
            }
            let mut smaller = map.clone();
            smaller.remove(key);
            candidates.push((Value::Object(smaller), action.clone()));
        }
        // Drop each rule block / extension individually.
        for section in ["rules", "extensions"] {
            if let Some(Value::Object(section_map)) = map.get(section) {
                for block in section_map.keys() {
                    let mut smaller = map.clone();
                    let mut section_smaller = section_map.clone();
                    section_smaller.remove(block);
                    if section_smaller.is_empty() {
                        smaller.remove(section);
                    } else {
                        smaller.insert(section.to_string(), Value::Object(section_smaller));
                    }
                    candidates.push((Value::Object(smaller), action.clone()));
                }

                // Drop each field *within* a block. Without this, a block's
                // `when` condition (and the 0.2.0 sub-fields of
                // browser_automation / code_execution) can only be removed by
                // deleting the whole block, so a repro that needs the block
                // keeps its entire condition tree no matter how irrelevant.
                for (block, body) in section_map {
                    let Value::Object(body_map) = body else {
                        continue;
                    };
                    for field in body_map.keys() {
                        let mut body_smaller = body_map.clone();
                        body_smaller.remove(field);
                        let mut section_smaller = section_map.clone();
                        section_smaller.insert(block.clone(), Value::Object(body_smaller));
                        let mut smaller = map.clone();
                        smaller.insert(section.to_string(), Value::Object(section_smaller));
                        candidates.push((Value::Object(smaller), action.clone()));
                    }
                }
            }
        }
    }

    // Array reductions and string halving anywhere inside the policy.
    for (path, value) in collect_paths(policy) {
        match value {
            Value::Array(items) if !items.is_empty() => {
                let mut variants: Vec<Vec<Value>> = vec![Vec::new()];
                if items.len() > 1 {
                    variants.push(items[..items.len() / 2].to_vec());
                    variants.push(items[items.len() / 2..].to_vec());
                    variants.push(items[1..].to_vec());
                }
                for variant in variants {
                    let mut candidate = policy.clone();
                    set_path(&mut candidate, &path, Value::Array(variant));
                    candidates.push((candidate, action.clone()));
                }
            }
            Value::String(text) if text.chars().count() > 8 => {
                let half: String = text.chars().take(text.chars().count() / 2).collect();
                let mut candidate = policy.clone();
                set_path(&mut candidate, &path, Value::String(half));
                candidates.push((candidate, action.clone()));
            }
            _ => {}
        }
    }

    // Action reductions: drop optional keys, halve strings. "type" is kept,
    // and so is `context` whenever the policy has a `time_window` condition:
    // without `context.current_time` such a condition reads the wall clock,
    // which would make both the shrink probes and any emitted fixture
    // time-dependent.
    let needs_pinned_clock = policy.to_string().contains("\"time_window\"");
    if let Value::Object(map) = action {
        for key in map.keys() {
            if key == "type" || (key == "context" && needs_pinned_clock) {
                continue;
            }
            let mut smaller = map.clone();
            smaller.remove(key);
            candidates.push((policy.clone(), Value::Object(smaller)));
        }
        for field in ["target", "content", "url"] {
            if let Some(Value::String(text)) = map.get(field)
                && text.chars().count() > 8
            {
                let half: String = text.chars().take(text.chars().count() / 2).collect();
                let mut smaller = map.clone();
                smaller.insert(field.to_string(), Value::String(half));
                candidates.push((policy.clone(), Value::Object(smaller)));
            }
        }
        // Drop each field of the runtime context individually, keeping
        // `current_time` -- dropping that would let a `time_window` condition
        // read the wall clock and make the repro nondeterministic.
        if let Some(Value::Object(context)) = map.get("context") {
            for key in context.keys() {
                if key == "current_time" {
                    continue;
                }
                let mut context_smaller = context.clone();
                context_smaller.remove(key);
                let mut smaller = map.clone();
                smaller.insert("context".to_string(), Value::Object(context_smaller));
                candidates.push((policy.clone(), Value::Object(smaller)));
            }
        }
    }

    candidates
}

type JsonPath = Vec<String>;

fn collect_paths(value: &Value) -> Vec<(JsonPath, Value)> {
    let mut out = Vec::new();
    let mut path = Vec::new();
    walk(value, &mut path, &mut out);
    out
}

fn walk(value: &Value, path: &mut JsonPath, out: &mut Vec<(JsonPath, Value)>) {
    if !path.is_empty() {
        out.push((path.clone(), value.clone()));
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                path.push(key.clone());
                walk(child, path, out);
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                path.push(index.to_string());
                walk(child, path, out);
                path.pop();
            }
        }
        _ => {}
    }
}

fn set_path(root: &mut Value, path: &[String], new_value: Value) {
    let mut cursor = root;
    for segment in &path[..path.len() - 1] {
        cursor = match cursor {
            Value::Object(map) => map.get_mut(segment).expect("path segment exists"),
            Value::Array(items) => {
                let index: usize = segment.parse().expect("numeric path segment");
                &mut items[index]
            }
            _ => unreachable!("paths only traverse containers"),
        };
    }
    let last = path.last().expect("non-empty path");
    match cursor {
        Value::Object(map) => {
            map.insert(last.clone(), new_value);
        }
        Value::Array(items) => {
            let index: usize = last.parse().expect("numeric path segment");
            items[index] = new_value;
        }
        _ => unreachable!("paths only traverse containers"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::{CaseVerdict, NormalizedResult, SdkReport};
    use std::collections::BTreeMap;

    /// Stub SDK: decision flips to deny iff the policy still contains
    /// rules.shell_commands (the "relevant" structure).
    struct StubEvaluator {
        sdk: &'static str,
        diverge_on_marker: bool,
    }

    impl CaseEvaluator for StubEvaluator {
        fn sdk_name(&self) -> &str {
            self.sdk
        }

        fn evaluate_bundle(&mut self, bundle: &CaseBundle) -> Result<SdkReport, DiffError> {
            let mut results = BTreeMap::new();
            for group in &bundle.groups {
                let marker = group
                    .policy
                    .get("rules")
                    .and_then(|rules| rules.get("shell_commands"))
                    .is_some();
                for case in &group.actions {
                    let decision = if self.diverge_on_marker && marker {
                        "deny"
                    } else {
                        "allow"
                    };
                    results.insert(
                        format!("{}/{}", group.id, case.id),
                        CaseVerdict::Ok {
                            result: NormalizedResult {
                                decision: decision.to_string(),
                                matched_rule: None,
                                reason: None,
                                origin_profile: None,
                                posture: None,
                                rule_trace: Vec::new(),
                                receipt_hash: None,
                                receipt: None,
                            },
                        },
                    );
                }
            }
            Ok(SdkReport {
                sdk: self.sdk.to_string(),
                results,
                groups: std::collections::BTreeMap::new(),
            })
        }
    }

    #[test]
    fn minimizer_strips_irrelevant_structure() {
        let policy = serde_json::json!({
            "hushspec": "0.1.0",
            "name": "big_policy",
            "description": "lots of irrelevant stuff to strip away",
            "rules": {
                "shell_commands": { "forbidden_patterns": ["rm"] },
                "tool_access": { "allow": ["read_file", "search"], "block": ["shell_exec"] },
                "forbidden_paths": { "patterns": ["**/.ssh/**", "/etc/passwd"] }
            }
        });
        let action = serde_json::json!({
            "type": "shell_command",
            "target": "ls -la",
            "content": "completely irrelevant content"
        });

        let mut oracle = StubEvaluator {
            sdk: "rust",
            diverge_on_marker: false,
        };
        let mut failing = StubEvaluator {
            sdk: "stub",
            diverge_on_marker: true,
        };

        let minimized = minimize_case(
            &policy,
            &action,
            &mut oracle,
            &mut failing,
            &CompareOptions::default(),
            &MinimizeConfig::default(),
        )
        .expect("minimizes");

        let rules = minimized.policy.get("rules").expect("rules survive");
        assert!(
            rules.get("shell_commands").is_some(),
            "relevant block must survive"
        );
        assert!(
            rules.get("tool_access").is_none(),
            "irrelevant block must be stripped"
        );
        assert!(
            rules.get("forbidden_paths").is_none(),
            "irrelevant block must be stripped"
        );
        assert!(minimized.policy.get("name").is_none());
        assert!(minimized.policy.get("description").is_none());
        assert_eq!(minimized.kind, DivergenceKind::Decision);
        assert_eq!(minimized.sdk, "stub");
        assert!(minimized.rounds >= 1);
    }

    /// A receipt-only divergence must shrink like any other: the probes the
    /// minimizer builds carry the same audit inputs on both sides, so the
    /// receipts it compares along the way are the receipts the run compared.
    ///
    /// The stub agrees on every field the pre-receipt fuzzer looked at and
    /// disagrees only on the recorded evidence, exactly as an SDK with a
    /// receipt bug would.
    #[test]
    fn minimizer_shrinks_a_receipt_only_divergence() {
        struct ReceiptStub {
            sdk: &'static str,
            tamper: bool,
        }

        impl CaseEvaluator for ReceiptStub {
            fn sdk_name(&self) -> &str {
                self.sdk
            }

            fn evaluate_bundle(&mut self, bundle: &CaseBundle) -> Result<SdkReport, DiffError> {
                let mut report = crate::diff::InProcessEvaluator.evaluate_bundle(bundle)?;
                report.sdk = self.sdk.to_string();
                if !self.tamper {
                    return Ok(report);
                }
                // Only policies that still carry the marker record a wrong
                // receipt, so shrinking has something to home in on.
                let tampered: std::collections::BTreeSet<String> = bundle
                    .groups
                    .iter()
                    .filter(|group| group.policy.pointer("/rules/shell_commands").is_some())
                    .flat_map(|group| {
                        group
                            .actions
                            .iter()
                            .map(move |case| format!("{}/{}", group.id, case.id))
                    })
                    .collect();
                for (key, verdict) in &mut report.results {
                    if let CaseVerdict::Ok { result } = verdict
                        && tampered.contains(key)
                    {
                        result.receipt_hash = Some(format!("sha256:{}", "0".repeat(64)));
                    }
                }
                Ok(report)
            }
        }

        let policy = serde_json::json!({
            "hushspec": "0.2.0",
            "name": "big_policy",
            "description": "lots of irrelevant stuff to strip away",
            "rules": {
                "shell_commands": { "forbidden_patterns": ["rm"] },
                "tool_access": { "allow": ["read_file", "search"], "block": ["shell_exec"] },
                "forbidden_paths": { "patterns": ["**/.ssh/**", "/etc/passwd"] }
            }
        });
        let action = serde_json::json!({"type": "shell_command", "target": "ls -la"});

        let mut oracle = ReceiptStub {
            sdk: "rust",
            tamper: false,
        };
        let mut failing = ReceiptStub {
            sdk: "go",
            tamper: true,
        };
        let minimized = minimize_case(
            &policy,
            &action,
            &mut oracle,
            &mut failing,
            &CompareOptions::default(),
            &MinimizeConfig::default(),
        )
        .expect("minimizes");

        assert_eq!(minimized.kind, DivergenceKind::Receipt);
        assert!(
            minimized.policy.pointer("/rules/shell_commands").is_some(),
            "the block the receipt bug needs must survive: {}",
            minimized.policy
        );
        assert!(
            minimized.policy.get("description").is_none(),
            "irrelevant structure must still be stripped: {}",
            minimized.policy
        );
    }

    #[test]
    fn minimizer_refuses_non_diverging_cases() {
        let policy = serde_json::json!({"hushspec": "0.1.0"});
        let action = serde_json::json!({"type": "tool_call"});
        let mut oracle = StubEvaluator {
            sdk: "rust",
            diverge_on_marker: false,
        };
        let mut failing = StubEvaluator {
            sdk: "stub",
            diverge_on_marker: false,
        };
        let result = minimize_case(
            &policy,
            &action,
            &mut oracle,
            &mut failing,
            &CompareOptions::default(),
            &MinimizeConfig::default(),
        );
        assert!(matches!(result, Err(DiffError::Config(_))));
    }

    /// Always answers "allow" for every real case in whatever bundle it's
    /// given, regardless of content -- deliberately dumb so it can stand in
    /// as an oracle that a byzantine `failing` counterpart trivially agrees
    /// with on every real key.
    struct AlwaysAllowEvaluator {
        sdk: &'static str,
    }

    impl CaseEvaluator for AlwaysAllowEvaluator {
        fn sdk_name(&self) -> &str {
            self.sdk
        }

        fn evaluate_bundle(&mut self, bundle: &CaseBundle) -> Result<SdkReport, DiffError> {
            let mut results = BTreeMap::new();
            for group in &bundle.groups {
                for case in &group.actions {
                    results.insert(
                        format!("{}/{}", group.id, case.id),
                        CaseVerdict::Ok {
                            result: NormalizedResult {
                                decision: "allow".to_string(),
                                matched_rule: None,
                                reason: None,
                                origin_profile: None,
                                posture: None,
                                rule_trace: Vec::new(),
                                receipt_hash: None,
                                receipt: None,
                            },
                        },
                    );
                }
            }
            Ok(SdkReport {
                sdk: self.sdk.to_string(),
                results,
                groups: std::collections::BTreeMap::new(),
            })
        }
    }

    /// Byzantine harness stub: answers every real case in the bundle exactly
    /// like `AlwaysAllowEvaluator` (so there is never an ordinary verdict
    /// disagreement), but also fabricates an extra case key -- "g9999/a9999"
    /// -- that no bundle in this test ever actually contains. Regression
    /// stub for the minimizer's shrink-loop guard: `candidate_index` applied
    /// to this key parses to a huge-but-valid `usize`, which must not be
    /// used to index the (much smaller) `candidates` vec.
    struct PhantomInventingEvaluator {
        sdk: &'static str,
    }

    impl CaseEvaluator for PhantomInventingEvaluator {
        fn sdk_name(&self) -> &str {
            self.sdk
        }

        fn evaluate_bundle(&mut self, bundle: &CaseBundle) -> Result<SdkReport, DiffError> {
            let mut results = BTreeMap::new();
            for group in &bundle.groups {
                for case in &group.actions {
                    results.insert(
                        format!("{}/{}", group.id, case.id),
                        CaseVerdict::Ok {
                            result: NormalizedResult {
                                decision: "allow".to_string(),
                                matched_rule: None,
                                reason: None,
                                origin_profile: None,
                                posture: None,
                                rule_trace: Vec::new(),
                                receipt_hash: None,
                                receipt: None,
                            },
                        },
                    );
                }
            }
            results.insert(
                "g9999/a9999".to_string(),
                CaseVerdict::Ok {
                    result: NormalizedResult {
                        decision: "deny".to_string(),
                        matched_rule: None,
                        reason: None,
                        origin_profile: None,
                        posture: None,
                        rule_trace: Vec::new(),
                        receipt_hash: None,
                        receipt: None,
                    },
                },
            );
            Ok(SdkReport {
                sdk: self.sdk.to_string(),
                results,
                groups: std::collections::BTreeMap::new(),
            })
        }
    }

    /// A harness that fabricates an out-of-range case key must never crash
    /// the minimizer. When every real key agrees with the reference, the only
    /// divergence left each round is the phantom "g9999/a9999" key; selecting
    /// the candidate by parsing that group number yields index 9998 against a
    /// candidates vector holding a handful of entries. The minimizer must
    /// discard the key instead of indexing with it.
    #[test]
    fn minimizer_survives_a_phantom_case_key_without_panicking() {
        let policy = serde_json::json!({
            "hushspec": "0.1.0",
            "name": "phantom_test_policy",
            "rules": {
                "tool_access": { "allow": ["read_file"] }
            }
        });
        let action = serde_json::json!({
            "type": "tool_call",
            "target": "read_file"
        });

        let mut oracle = AlwaysAllowEvaluator { sdk: "rust" };
        let mut failing = PhantomInventingEvaluator { sdk: "byzantine" };

        let result = minimize_case(
            &policy,
            &action,
            &mut oracle,
            &mut failing,
            &CompareOptions::default(),
            &MinimizeConfig::default(),
        );
        match result {
            Ok(minimized) => assert_eq!(minimized.kind, DivergenceKind::PhantomCase),
            Err(DiffError::Config(_)) => {}
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }
}
