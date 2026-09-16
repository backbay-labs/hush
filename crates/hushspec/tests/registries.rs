//! The registries under `spec/registries/` are normative lists. Each one
//! validates against its published schema, and the closed ones are checked
//! against the code and schemas they describe so that the two cannot drift.
//!
//! Drift is checked in both directions and reported as such: an id the
//! registry carries but the implementation does not have is a different bug
//! from an id the implementation emits but nobody registered, and a
//! maintainer who edits a registry without touching the code should be told
//! which of the two happened rather than handed two sets to diff by eye.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::PathBuf;

use hushspec::evaluate::{PANIC_RULE, UNKNOWN_ACTION_TYPE_RULE, evaluate_traced};
use hushspec::{
    AuditConfig, AuditContext, CompiledPolicy, Condition, DetectionCategory, DetectorRegistry,
    EvaluationAction, HushSpec, OriginContext, POLICY_UNVERIFIED_RULE, PanicState, RateComparison,
    RateCondition, TimeWindowCondition, evaluate, evaluate_audited_spec,
};
use jsonschema::{Draft, JSONSchema};
use serde_json::Value;

/// Every registry under `spec/registries/`, with the schema that governs it.
/// The error-code and framework registries predate the
/// `hushspec-registry-<name>` file-name convention, which is why the schema
/// is named here rather than derived from the registry name.
const REGISTRIES: [(&str, &str); 9] = [
    (
        "action-types",
        "hushspec-registry-action-types.v0.schema.json",
    ),
    (
        "capabilities",
        "hushspec-registry-capabilities.v0.schema.json",
    ),
    (
        "condition-types",
        "hushspec-registry-condition-types.v0.schema.json",
    ),
    ("detectors", "hushspec-registry-detectors.v0.schema.json"),
    ("error-codes", "hushspec-error-codes.v1.schema.json"),
    ("frameworks", "hushspec-framework-registry.v1.schema.json"),
    (
        "media-types",
        "hushspec-registry-media-types.v0.schema.json",
    ),
    (
        "rule-blocks",
        "hushspec-registry-rule-blocks.v0.schema.json",
    ),
    ("rule-paths", "hushspec-registry-rule-paths.v0.schema.json"),
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn load_yaml(rel: &str) -> Value {
    serde_yaml::from_str(&read(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn load_json(rel: &str) -> Value {
    serde_json::from_str(&read(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn registry(name: &str) -> Value {
    load_yaml(&format!("spec/registries/{name}.yaml"))
}

fn compile(schema: &Value, what: &str) -> JSONSchema {
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(schema)
        .unwrap_or_else(|e| panic!("{what}: schema does not compile: {e}"))
}

fn assert_valid(name: &str, schema_file: &str) {
    let compiled = compile(&load_json(&format!("schemas/{schema_file}")), name);
    let document = registry(name);
    if let Err(errors) = compiled.validate(&document) {
        let messages: Vec<String> = errors
            .map(|e| format!("{} at {}", e, e.instance_path))
            .collect();
        panic!("spec/registries/{name}.yaml fails schemas/{schema_file}: {messages:?}");
    }
}

fn ids(document: &Value, list: &str) -> BTreeSet<String> {
    document[list]
        .as_array()
        .unwrap_or_else(|| panic!("registry has no `{list}` list"))
        .iter()
        .map(|entry| {
            entry["id"]
                .as_str()
                .expect("entry id is a string")
                .to_string()
        })
        .collect()
}

fn keys(schema: &Value, def: &str) -> BTreeSet<String> {
    schema["$defs"][def]["properties"]
        .as_object()
        .unwrap_or_else(|| panic!("$defs.{def}.properties missing"))
        .keys()
        .cloned()
        .collect()
}

fn set(values: impl IntoIterator<Item = impl Into<String>>) -> BTreeSet<String> {
    values.into_iter().map(Into::into).collect()
}

/// Compare a registry's ids with what the implementation has, naming both
/// halves of any difference: a registry entry nothing implements, and an
/// implemented id nobody registered.
fn assert_no_drift(
    registry_file: &str,
    registered: &BTreeSet<String>,
    what: &str,
    has: &BTreeSet<String>,
) {
    let missing: Vec<&str> = registered.difference(has).map(String::as_str).collect();
    let extra: Vec<&str> = has.difference(registered).map(String::as_str).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "spec/registries/{registry_file}.yaml has drifted from {what}\n  \
         registered, but {what} does not have it: {missing:?}\n  \
         in {what}, but not registered: {extra:?}",
    );
}

#[test]
fn every_registry_validates_against_its_schema() {
    for (name, schema_file) in REGISTRIES {
        assert_valid(name, schema_file);
    }
}

/// A registry schema published without an entry in the table above would be
/// served to consumers with nothing ever validating a document against it,
/// and the omission would look exactly like a passing suite.
#[test]
fn every_published_registry_schema_is_in_the_table() {
    const PREFIX: &str = "hushspec-registry-";

    let published: BTreeSet<String> = fs::read_dir(root().join("schemas"))
        .expect("schemas/ is readable")
        .filter_map(|entry| {
            let name = entry.ok()?.file_name().to_string_lossy().into_owned();
            name.starts_with(PREFIX).then_some(name)
        })
        .collect();
    let tabled: BTreeSet<String> = REGISTRIES
        .iter()
        .map(|(_, schema_file)| (*schema_file).to_string())
        .filter(|schema_file| schema_file.starts_with(PREFIX))
        .collect();
    assert_eq!(
        published, tabled,
        "schemas/ publishes registry schemas the REGISTRIES table does not name; \
         add the registry so its document is validated too"
    );
}

/// A new registry file is only normative once something checks it, so the
/// table above must list every registry the directory holds.
#[test]
fn every_registry_file_is_in_the_table() {
    let on_disk: BTreeSet<String> = fs::read_dir(root().join("spec/registries"))
        .expect("spec/registries is readable")
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
        .map(|path| {
            path.file_stem()
                .expect("a file name")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let tabled = set(REGISTRIES.map(|(name, _)| name));
    assert_eq!(
        on_disk, tabled,
        "spec/registries/ and the REGISTRIES table disagree; \
         every registry needs the schema that governs it named here"
    );
}

#[test]
fn rule_blocks_match_the_core_schema() {
    let core = load_json("schemas/hushspec-core.v1.schema.json");
    assert_no_drift(
        "rule-blocks",
        &ids(&registry("rule-blocks"), "entries"),
        "the core schema's $defs/Rules",
        &keys(&core, "Rules"),
    );
}

#[test]
fn condition_types_match_the_core_schema() {
    let core = load_json("schemas/hushspec-core.v1.schema.json");
    assert_no_drift(
        "condition-types",
        &ids(&registry("condition-types"), "entries"),
        "the core schema's $defs/Condition",
        &keys(&core, "Condition"),
    );
}

/// The registry is the closed list of members a `when` object may carry (core
/// spec 3.13), and `Condition` is what the parser accepts -- it is
/// `deny_unknown_fields`, so its fields are exactly the accepted keys.
///
/// The struct literal below is deliberate: it names every member, so adding a
/// field to `Condition` stops this test compiling until the new member is
/// registered here too.
#[test]
fn condition_types_match_the_condition_type() {
    let every_member = Condition {
        time_window: Some(TimeWindowCondition {
            start: "09:00".to_string(),
            end: "17:00".to_string(),
            timezone: None,
            days: Vec::new(),
        }),
        context: Some(HashMap::new()),
        all_of: Some(Vec::new()),
        any_of: Some(Vec::new()),
        not: Some(Box::new(Condition::default())),
        capability: Some("egress".to_string()),
        rate: Some(RateCondition {
            counter: "tool_calls".to_string(),
            threshold: 1,
            comparison: RateComparison::Gte,
        }),
    };
    let serialized = serde_json::to_value(&every_member).expect("a condition serializes");
    let members: BTreeSet<String> = serialized
        .as_object()
        .expect("a condition is an object")
        .keys()
        .cloned()
        .collect();
    assert_no_drift(
        "condition-types",
        &ids(&registry("condition-types"), "entries"),
        "the `Condition` type",
        &members,
    );
}

#[test]
fn rule_paths_match_the_receipt_schema() {
    let receipt = load_json("schemas/hushspec-receipt.v1.schema.json");
    let trace_ids: BTreeSet<String> =
        receipt["$defs"]["RuleEvaluation"]["properties"]["rule_block"]["enum"]
            .as_array()
            .expect("rule_block enum")
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

    let document = registry("rule-paths");
    let entries = document["entries"].as_array().unwrap();
    let registered: BTreeSet<String> = entries
        .iter()
        .filter(|e| matches!(e["kind"].as_str(), Some("rule_block" | "engine_stage")))
        .map(|e| e["id"].as_str().unwrap().to_string())
        .collect();
    assert_no_drift(
        "rule-paths",
        &registered,
        "the receipt schema's rule_block enum",
        &trace_ids,
    );

    let reserved: BTreeSet<String> = entries
        .iter()
        .flat_map(|e| {
            let mut names = Vec::new();
            if let Some(m) = e["matched_rule"].as_str() {
                names.push(m.to_string());
            }
            if e["kind"].as_str() == Some("reserved_matched_rule") {
                names.push(e["id"].as_str().unwrap().to_string());
            }
            names
        })
        .collect();
    // Read off the constants the engine emits, so renaming one in the code
    // fails here rather than quietly leaving the registry describing a value
    // no receipt carries any more.
    assert_no_drift(
        "rule-paths",
        &reserved,
        "the reserved `matched_rule` constants",
        &set([
            PANIC_RULE,
            UNKNOWN_ACTION_TYPE_RULE,
            POLICY_UNVERIFIED_RULE,
            "detection",
        ]),
    );
}

/// The registered `rule_block` ids are what a receipt's trace may carry
/// (receipt spec 4.3), so every one of them must be reachable and the
/// evaluator must emit nothing else.
///
/// `default` is the one registered id no receipt here carries: receipt spec
/// 4.3 item 5 makes it optional ("reserved for engines that record an
/// explicit default-allow entry"), and this engine records no such entry --
/// the stage it does record for an action no block decided is
/// `unknown_action_type`.
#[test]
fn rule_paths_are_what_the_evaluator_emits() {
    let document = registry("rule-paths");
    let registered: BTreeSet<String> = document["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| matches!(e["kind"].as_str(), Some("rule_block" | "engine_stage")))
        .map(|e| e["id"].as_str().unwrap().to_string())
        .collect();

    let mut emitted = BTreeSet::new();
    for (policy, action) in trace_scenarios() {
        let spec = HushSpec::parse(&policy).expect("scenario policy parses");
        let receipt = evaluate_audited_spec(
            &spec,
            &action,
            &AuditConfig::default(),
            &AuditContext::default(),
        )
        .expect("the scenario policy is resolved");
        emitted.extend(receipt.rule_trace.iter().map(|e| e.rule_block.clone()));
    }
    emitted.extend(panic_stage_blocks());

    let unreachable: Vec<&str> = registered
        .difference(&emitted)
        .map(String::as_str)
        .collect();
    assert_eq!(
        unreachable,
        vec!["default"],
        "every registered rule-path id but the optional `default` stage \
         (receipt spec 4.3 item 5) must appear in some receipt trace"
    );
    let unregistered: Vec<&str> = emitted
        .difference(&registered)
        .map(String::as_str)
        .collect();
    assert!(
        unregistered.is_empty(),
        "the evaluator emits rule_block ids that spec/registries/rule-paths.yaml \
         does not register: {unregistered:?}"
    );
}

/// Policies and actions that between them drive every rule block and every
/// engine stage the evaluator can record, panic excepted (that one needs its
/// own latch, see [`panic_stage_blocks`]).
fn trace_scenarios() -> Vec<(String, EvaluationAction)> {
    let all_blocks = ALL_BLOCKS_POLICY.to_string();
    let mut scenarios: Vec<(String, EvaluationAction)> = [
        "file_read",
        "file_write",
        "patch_apply",
        "shell_command",
        "egress",
        "tool_call",
        "computer_use",
        "input_inject",
        "browser_action",
        "code_exec",
    ]
    .into_iter()
    .map(|action_type| (all_blocks.clone(), action_of(action_type)))
    .collect();

    // `unknown_action_type`: a type outside core spec 5.
    scenarios.push((all_blocks.clone(), action_of("not_a_registered_type")));
    // `origin_profile`: a profile that matches, and one that does not.
    let origins = ORIGINS_POLICY.to_string();
    let with_origin = |provider: &str| EvaluationAction {
        origin: Some(OriginContext {
            provider: Some(provider.to_string()),
            ..Default::default()
        }),
        ..action_of("file_read")
    };
    scenarios.push((origins.clone(), with_origin("slack")));
    scenarios.push((origins, with_origin("nowhere")));
    // `posture_capability`: a state granting nothing.
    scenarios.push((LOCKED_POSTURE_POLICY.to_string(), action_of("file_read")));
    scenarios
}

/// The `panic` stage, driven through a latch of this policy's own so that
/// arming it cannot reach any other test in this binary.
fn panic_stage_blocks() -> BTreeSet<String> {
    let spec = HushSpec::parse(ALL_BLOCKS_POLICY).expect("the policy parses");
    let policy = CompiledPolicy::compile(&spec)
        .expect("the policy compiles")
        .with_panic_state(PanicState::new());
    policy.panic_state().activate();
    let receipt = policy
        .evaluate_audited(
            &action_of("file_read"),
            &AuditConfig::default(),
            &AuditContext::default(),
        )
        .expect("the policy is resolved");
    receipt
        .rule_trace
        .iter()
        .map(|entry| entry.rule_block.clone())
        .collect()
}

fn action_of(action_type: &str) -> EvaluationAction {
    EvaluationAction {
        action_type: action_type.to_string(),
        target: Some("/tmp/example".into()),
        ..Default::default()
    }
}

#[test]
fn action_types_match_the_evaluator() {
    let spec = HushSpec::parse("hushspec: \"0.2.0\"\n").expect("minimal document");
    let registered = ids(&registry("action-types"), "entries");

    for action_type in &registered {
        let result = evaluate(&spec, &action_of(action_type));
        if action_type == "custom" {
            assert_eq!(
                result.decision,
                hushspec::Decision::Deny,
                "custom without posture must deny"
            );
        } else {
            assert_ne!(
                result.matched_rule.as_deref(),
                Some(UNKNOWN_ACTION_TYPE_RULE),
                "{action_type} is registered but the evaluator does not know it"
            );
        }
    }

    let unknown = EvaluationAction {
        action_type: "not_a_registered_type".into(),
        target: Some("x".into()),
        ..Default::default()
    };
    assert_eq!(
        evaluate(&spec, &unknown).matched_rule.as_deref(),
        Some(UNKNOWN_ACTION_TYPE_RULE)
    );
}

/// Each action type's `rule_blocks` list is the dispatch table (core spec 5),
/// order included: the evaluator records one trace entry per applicable block
/// in evaluation order whether or not the document declares the block
/// (receipt spec 4.3 items 1-2), so the trace is the dispatch table for that
/// action type.
///
/// Both a document that declares nothing and one that declares every block
/// are checked, and the action carries content, because the registry's note
/// on `egress` and `tool_call` is that `secret_patterns` applies only to an
/// action that carries some -- a block that ran and a block that was skipped
/// as absent must both leave their entry.
#[test]
fn action_types_dispatch_to_the_rule_blocks_they_register() {
    let blocks = ids(&registry("rule-blocks"), "entries");

    for (shape, policy) in [
        ("a document declaring nothing", "hushspec: \"0.2.0\"\n"),
        ("a document declaring every block", ALL_BLOCKS_POLICY),
    ] {
        let spec = HushSpec::parse(policy).expect("the policy parses");
        for entry in registry("action-types")["entries"].as_array().unwrap() {
            let action_type = entry["id"].as_str().unwrap();
            let registered: Vec<&str> = entry["rule_blocks"]
                .as_array()
                .unwrap_or_else(|| panic!("{action_type} registers no rule_blocks list"))
                .iter()
                .map(|value| value.as_str().expect("a rule block name"))
                .collect();

            let action = EvaluationAction {
                content: Some("hello".to_string()),
                ..action_of(action_type)
            };
            let traced = evaluate_traced(&spec, &action, None, &HashMap::new());
            let dispatched: Vec<&str> = traced
                .trace
                .iter()
                .map(|entry| entry.rule_block.as_str())
                .filter(|block| blocks.contains(*block))
                .collect();

            assert_eq!(
                registered, dispatched,
                "{action_type} against {shape}: \
                 spec/registries/action-types.yaml lists {registered:?}, \
                 the evaluator consults {dispatched:?}"
            );
        }
    }
}

/// The evaluator-test schema accepts any string for an action's `type`, so
/// that a vector can assert the fail-closed deny for an unknown one; the
/// reference types it names in prose are the registry's, and a vector author
/// reading the schema must not be handed a stale list.
#[test]
fn action_types_match_the_evaluator_test_schema() {
    let schema = load_json("schemas/hushspec-evaluator-test.v1.schema.json");
    let description = schema["$defs"]["Action"]["properties"]["type"]["description"]
        .as_str()
        .expect("the action type is documented");
    let listed = description
        .split_once("reference types are ")
        .map(|(_, tail)| tail.trim_end().trim_end_matches('.'))
        .unwrap_or_else(|| {
            panic!("the evaluator-test schema no longer names its reference types: {description}")
        });
    assert_no_drift(
        "action-types",
        &ids(&registry("action-types"), "entries"),
        "the evaluator-test schema's `type` description",
        &set(listed.split(", ")),
    );
}

/// The registry is closed (core spec 5), so it lists the action types of the
/// normative table and no others.
#[test]
fn action_types_match_the_core_specification_table() {
    let text = read("spec/hushspec-core.md");
    let start = text.find("## 5. Action Types").expect("core 5");
    let end = text[start..]
        .find("## 6.")
        .map_or(text.len(), |index| start + index);
    let tabled: BTreeSet<String> = text[start..end]
        .lines()
        .filter(|line| line.starts_with("| `"))
        .map(|line| {
            line.trim_start_matches("| `")
                .split('`')
                .next()
                .expect("a quoted action type")
                .to_string()
        })
        .collect();
    assert_no_drift(
        "action-types",
        &ids(&registry("action-types"), "entries"),
        "the core spec 5 table",
        &tabled,
    );
}

#[test]
fn gated_action_types_require_their_registered_capability() {
    let spec = HushSpec::parse(LOCKED_POSTURE_POLICY).expect("posture document");
    let capabilities = registry("capabilities");
    let gated: BTreeSet<String> = capabilities["entries"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|e| e["gates"].as_array().unwrap().iter())
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let registered = registry("action-types");
    for entry in registered["entries"].as_array().unwrap() {
        let action_type = entry["id"].as_str().unwrap();
        let action = action_of(action_type);
        let denied_by_posture = denied_by_capabilities(&spec, &action);
        let claims_capability = entry["required_capability"].is_string();
        assert_eq!(
            claims_capability,
            gated.contains(action_type),
            "{action_type}: action-types and capabilities registries disagree"
        );
        assert_eq!(
            denied_by_posture, claims_capability,
            "{action_type}: registry says gated={claims_capability}, evaluator says {denied_by_posture}"
        );
    }
}

/// Which capability unlocks which action type, not merely that some
/// capability does (posture spec 3.3): a state granting exactly the
/// registered capability must clear the guard, and a state granting only
/// another registered capability must not.
#[test]
fn each_gated_action_type_is_unlocked_by_the_capability_it_registers() {
    let all: Vec<String> = ids(&registry("capabilities"), "entries")
        .into_iter()
        .collect();

    for entry in registry("action-types")["entries"].as_array().unwrap() {
        let action_type = entry["id"].as_str().unwrap();
        let Some(capability) = entry["required_capability"].as_str() else {
            continue;
        };
        let action = action_of(action_type);

        let granting = HushSpec::parse(&posture_policy(&[capability])).expect("posture document");
        assert!(
            !denied_by_capabilities(&granting, &action),
            "{action_type}: a state granting `{capability}` must clear the posture guard"
        );

        for other in all.iter().filter(|name| name.as_str() != capability) {
            let withholding = HushSpec::parse(&posture_policy(&[other])).expect("posture document");
            assert!(
                denied_by_capabilities(&withholding, &action),
                "{action_type} requires `{capability}`, but a state granting only \
                 `{other}` let it through"
            );
        }
    }
}

/// Whether the posture capability guard is what refused the action.
fn denied_by_capabilities(spec: &HushSpec, action: &EvaluationAction) -> bool {
    evaluate(spec, action)
        .matched_rule
        .as_deref()
        .is_some_and(|rule| rule.ends_with(".capabilities"))
}

fn posture_policy(capabilities: &[&str]) -> String {
    format!(
        "hushspec: \"0.2.0\"\nextensions:\n  posture:\n    initial: locked\n    \
         states:\n      locked:\n        capabilities: [{}]\n    transitions: []\n",
        capabilities.join(", ")
    )
}

#[test]
fn detectors_match_the_reference_registry() {
    let document = registry("detectors");
    let registered = ids(&document, "entries");
    let categories = ids(&document, "categories");

    let reference = DetectorRegistry::with_defaults();
    let mut found = BTreeSet::new();
    let mut found_categories = BTreeSet::new();
    for category in [
        DetectionCategory::PromptInjection,
        DetectionCategory::Jailbreak,
        DetectionCategory::DataExfiltration,
    ] {
        // Exhaustive by design: a new `DetectionCategory` stops this match
        // compiling until it is registered and listed above.
        let id = match category {
            DetectionCategory::PromptInjection => "prompt_injection",
            DetectionCategory::Jailbreak => "jailbreak",
            DetectionCategory::DataExfiltration => "data_exfiltration",
        };
        let wire = serde_json::to_value(&category).expect("a category serializes");
        assert_eq!(
            wire.as_str(),
            Some(id),
            "the detection category `{id}` does not serialize under that name"
        );
        found_categories.insert(id.to_string());
        for detector in reference.detectors_for(category.clone()) {
            found.insert(format!("{}@1", detector.name()));
        }
    }
    assert_no_drift(
        "detectors",
        &registered,
        "the default detector registry",
        &found,
    );
    assert_no_drift(
        "detectors",
        &categories,
        "the `DetectionCategory` type",
        &found_categories,
    );
}

#[test]
fn capabilities_match_the_posture_specification() {
    let text = read("spec/hushspec-posture.md");
    let start = text
        .find("### 3.1 Standard Capabilities")
        .expect("posture 3.1");
    let end = text[start..]
        .find("### 3.2")
        .map_or(text.len(), |i| start + i);
    let listed: BTreeSet<String> = text[start..end]
        .lines()
        .filter(|line| line.starts_with("| `"))
        .map(|line| {
            line.trim_start_matches("| `")
                .split('`')
                .next()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_no_drift(
        "capabilities",
        &ids(&registry("capabilities"), "entries"),
        "the posture spec 3.1 table",
        &listed,
    );
}

/// Declares all twelve rule blocks, so a trace records each of them as run
/// rather than absent.
const ALL_BLOCKS_POLICY: &str = r#"
hushspec: "0.2.0"
name: every-rule-block
rules:
  forbidden_paths:
    patterns: ["**/.ssh/**"]
  path_allowlist:
    enabled: true
    read: ["/tmp/**"]
    write: ["/tmp/**"]
    patch: ["/tmp/**"]
  egress:
    allow: ["api.example.com"]
    default: block
  secret_patterns:
    patterns:
      - name: aws_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
  patch_integrity:
    max_additions: 500
  shell_commands:
    forbidden_patterns: ["rm -rf /"]
  tool_access:
    allow: ["read_file"]
    default: block
  computer_use:
    enabled: true
    mode: guardrail
    allowed_actions: ["remote.session.connect"]
  remote_desktop_channels:
    enabled: true
    clipboard: false
  input_injection:
    enabled: true
    allowed_types: ["keyboard"]
  browser_automation:
    enabled: true
    allowed_domains: ["*.example.com"]
  code_execution:
    enabled: true
    language_allowlist: ["python"]
"#;

/// One profile that a `slack` origin matches and a `deny` default for one
/// that matches nothing, so both halves of the origins stage are recorded.
const ORIGINS_POLICY: &str = r#"
hushspec: "0.2.0"
name: origins-stage
extensions:
  origins:
    default_behavior: deny
    profiles:
      - id: incident-room
        match:
          provider: slack
"#;

/// A posture state that grants nothing, so the capability guard refuses every
/// gated action type.
const LOCKED_POSTURE_POLICY: &str = r#"
hushspec: "0.2.0"
extensions:
  posture:
    initial: locked
    states:
      locked:
        capabilities: []
    transitions: []
"#;
