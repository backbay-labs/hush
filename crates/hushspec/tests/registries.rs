//! The registries under `spec/registries/` are normative lists. Each one
//! validates against its published schema, and the closed ones are checked
//! against the code and schemas they describe so that the two cannot drift.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::PathBuf;

use hushspec::{
    CompiledPolicy, DetectionCategory, DetectorRegistry, EvaluationAction, HushSpec, evaluate,
};
use jsonschema::{Draft, JSONSchema};
use serde_json::Value;

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

fn assert_valid(name: &str) {
    let schema = load_json(&format!("schemas/hushspec-registry-{name}.v0.schema.json"));
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema)
        .unwrap_or_else(|e| panic!("{name}: schema does not compile: {e}"));
    let document = registry(name);
    if let Err(errors) = compiled.validate(&document) {
        let messages: Vec<String> = errors
            .map(|e| format!("{} at {}", e, e.instance_path))
            .collect();
        panic!("spec/registries/{name}.yaml fails its schema: {messages:?}");
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

/// The registries published with a `hushspec-registry-<name>.v0.schema.json`
/// of their own. Kept exhaustive by
/// `every_published_registry_schema_is_covered`.
const REGISTRIES: [&str; 7] = [
    "action-types",
    "rule-blocks",
    "rule-paths",
    "capabilities",
    "detectors",
    "condition-types",
    "media-types",
];

#[test]
fn every_registry_validates_against_its_schema() {
    for name in REGISTRIES {
        assert_valid(name);
    }
}

/// A registry schema added to `schemas/` but not to `REGISTRIES` would be
/// published without anything ever validating the YAML it describes, and the
/// omission would look exactly like a passing suite. The list is therefore
/// compared against the directory rather than trusted.
#[test]
fn every_published_registry_schema_is_covered() {
    const PREFIX: &str = "hushspec-registry-";
    const SUFFIX: &str = ".v0.schema.json";

    let mut published: Vec<String> = fs::read_dir(root().join("schemas"))
        .expect("schemas/ is readable")
        .filter_map(|entry| {
            let name = entry.ok()?.file_name().to_string_lossy().into_owned();
            let stem = name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)?;
            Some(stem.to_string())
        })
        .collect();
    published.sort();

    let mut covered: Vec<String> = REGISTRIES.iter().map(|n| (*n).to_string()).collect();
    covered.sort();

    assert_eq!(
        published, covered,
        "the registry schemas in schemas/ and the REGISTRIES list have diverged; \
         add the new registry to the list so its YAML is validated too"
    );
}

#[test]
fn rule_blocks_match_the_core_schema() {
    let core = load_json("schemas/hushspec-core.v0.schema.json");
    assert_eq!(
        ids(&registry("rule-blocks"), "entries"),
        keys(&core, "Rules")
    );
}

#[test]
fn condition_types_match_the_core_schema() {
    let core = load_json("schemas/hushspec-core.v0.schema.json");
    assert_eq!(
        ids(&registry("condition-types"), "entries"),
        keys(&core, "Condition")
    );
}

#[test]
fn rule_paths_match_the_receipt_schema() {
    let receipt = load_json("schemas/hushspec-receipt.v0.schema.json");
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
    assert_eq!(
        registered, trace_ids,
        "rule_block identifiers drifted from the receipt schema"
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
    let expected: BTreeSet<String> = [
        "__hushspec_panic__",
        "__unknown_action_type__",
        "__hushspec_policy_unverified__",
        "detection",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(reserved, expected);
}

#[test]
fn action_types_match_the_evaluator() {
    let spec = HushSpec::parse("hushspec: \"0.2.0\"\n").expect("minimal document");
    let registered = ids(&registry("action-types"), "entries");

    for action_type in &registered {
        let action = EvaluationAction {
            action_type: action_type.clone(),
            target: Some("/tmp/example".into()),
            ..Default::default()
        };
        let result = evaluate(&spec, &action);
        if action_type == "custom" {
            assert_eq!(
                result.decision,
                hushspec::Decision::Deny,
                "custom without posture must deny"
            );
        } else {
            assert_ne!(
                result.matched_rule.as_deref(),
                Some("__unknown_action_type__"),
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
        Some("__unknown_action_type__")
    );
}

#[test]
fn gated_action_types_require_their_registered_capability() {
    let spec = HushSpec::parse(
        "hushspec: \"0.2.0\"\nextensions:\n  posture:\n    initial: locked\n    states:\n      locked:\n        capabilities: []\n    transitions: []\n",
    )
    .expect("posture document");
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
        let action = EvaluationAction {
            action_type: action_type.to_string(),
            target: Some("/tmp/example".into()),
            ..Default::default()
        };
        let result = evaluate(&spec, &action);
        let denied_by_posture = result
            .matched_rule
            .as_deref()
            .is_some_and(|rule| rule.ends_with(".capabilities"));
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
        let name = serde_json::to_value(&category).unwrap();
        found_categories.insert(name.as_str().unwrap().to_string());
        for detector in reference.detectors_for(category.clone()) {
            found.insert(format!("{}@1", detector.name()));
        }
    }
    assert_eq!(found, registered, "detector identifiers drifted");
    assert_eq!(found_categories, categories, "detector categories drifted");
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
    assert_eq!(ids(&registry("capabilities"), "entries"), listed);
}

#[test]
fn action_types_list_the_blocks_the_evaluator_consults() {
    let spec = HushSpec::parse(
        "hushspec: \"0.2.0\"\nrules:\n  forbidden_paths:\n    patterns: [\"/never/**\"]\n  path_allowlist:\n    enabled: true\n    read: [\"/**\"]\n    write: [\"/**\"]\n    patch: [\"/**\"]\n  egress:\n    allow: [\"example.com\"]\n    default: block\n  secret_patterns:\n    patterns:\n      - name: marker\n        pattern: \"zzz\"\n        severity: warn\n  patch_integrity:\n    max_additions: 10\n  shell_commands:\n    forbidden_patterns: [\"never\"]\n  tool_access:\n    default: allow\n  computer_use:\n    enabled: true\n    allowed_actions: [\"click\"]\n  remote_desktop_channels:\n    enabled: true\n    clipboard: true\n    file_transfer: true\n    audio: true\n    drive_mapping: true\n  input_injection:\n    enabled: true\n    allowed_types: [\"keyboard\"]\n  browser_automation:\n    enabled: true\n    allowed_domains: [\"example.com\"]\n  code_execution:\n    enabled: true\n    language_allowlist: [\"python\"]\n",
    )
    .expect("every rule block present");
    let policy = CompiledPolicy::compile(&spec).expect("policy compiles");
    let engine_stages = [
        "origin_profile",
        "posture_capability",
        "panic",
        "unknown_action_type",
        "default",
    ];
    let document = registry("action-types");
    for entry in document["entries"].as_array().unwrap() {
        let action_type = entry["id"].as_str().unwrap();
        let registered: Vec<String> = entry["rule_blocks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let action = EvaluationAction {
            action_type: action_type.to_string(),
            target: Some("/tmp/example".to_string()),
            content: Some("hello".to_string()),
            ..Default::default()
        };
        let traced = policy.evaluate_traced(&action, None, &HashMap::new());
        let consulted: Vec<String> = traced
            .trace
            .iter()
            .map(|entry| entry.rule_block.clone())
            .filter(|block| !engine_stages.contains(&block.as_str()))
            .collect();
        assert_eq!(
            consulted, registered,
            "{action_type}: the evaluator consulted {consulted:?} but the registry lists {registered:?}"
        );
    }
}
