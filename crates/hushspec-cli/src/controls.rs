//! Shared analysis of `metadata.controls` for `h2h lint` (L011-L013) and
//! `h2h audit --controls`.
//!
//! Control mappings are declarative governance metadata: they never influence
//! evaluation (core spec 2.5). The SDK validators only check a mapping's
//! *shape*; the semantic questions -- does this path point at anything, is this
//! framework registered, is every rule block accounted for -- are answered here,
//! against the resolved document and the embedded framework registry, so that
//! `spec/registries/frameworks.yaml` stays out of the four SDKs.

use crate::generated_frameworks;
use hushspec::HushSpec;
use serde_json::Value;

/// Roots a `rule_paths` entry may start from (core spec 2.5 path grammar).
const PATH_ROOTS: [&str; 2] = ["rules", "extensions"];

/// A `rule_paths` entry split into its dot segments and optional `[selector]`.
struct ParsedPath<'a> {
    segments: Vec<&'a str>,
    selector: Option<&'a str>,
}

fn parse_path(rule_path: &str) -> Option<ParsedPath<'_>> {
    let (base, selector) = match rule_path.find('[') {
        Some(open) => {
            if !rule_path.ends_with(']') {
                return None;
            }
            let inner = &rule_path[open + 1..rule_path.len() - 1];
            if inner.is_empty() || inner.contains('[') || inner.contains(']') {
                return None;
            }
            (&rule_path[..open], Some(inner))
        }
        None => (rule_path, None),
    };

    if base.is_empty() {
        return None;
    }

    let segments: Vec<&str> = base.split('.').collect();
    if segments.iter().any(|segment| segment.is_empty()) {
        return None;
    }
    if !PATH_ROOTS.contains(&segments[0]) {
        return None;
    }

    Some(ParsedPath { segments, selector })
}

/// The rule blocks the document declares, as dot paths (`rules.egress`), in
/// document order. Drives the L011 coverage check and the audit coverage line.
#[must_use]
pub fn rule_block_paths(doc: &Value) -> Vec<String> {
    doc.get("rules")
        .and_then(Value::as_object)
        .map(|rules| rules.keys().map(|name| format!("rules.{name}")).collect())
        .unwrap_or_default()
}

/// Does `rule_path` cover the rule block named by `block_path`?
///
/// A mapping to `rules` covers every block; a mapping to `rules.<block>` covers
/// that block, as does any mapping *inside* it (`rules.secret_patterns` covers
/// its patterns, and `rules.secret_patterns.patterns[ssn]` still counts the
/// `secret_patterns` block as mapped).
///
/// A mapping that does not resolve against `doc` covers nothing: a path that
/// points at no part of the policy is a broken claim about what the policy
/// implements (lint L012), and counting it as coverage would overstate how
/// much of the policy the controls account for.
#[must_use]
pub fn path_covers_block(doc: &Value, rule_path: &str, block_path: &str) -> bool {
    let Some(parsed) = parse_path(rule_path) else {
        return false;
    };
    if parsed.segments[0] != "rules" || !path_resolves(doc, rule_path) {
        return false;
    }
    match parsed.segments.get(1) {
        // A bare `rules` mapping covers every block.
        None => true,
        Some(block) => block_path == format!("rules.{block}"),
    }
}

/// Does `rule_path` point at something in the resolved document?
///
/// The final segment may carry a `[selector]` that names one list entry by its
/// `name` or `id` field (`rules.secret_patterns.patterns[ssn]`) or one key of a
/// mapping (`extensions.posture.states[warm]`).
#[must_use]
pub fn path_resolves(doc: &Value, rule_path: &str) -> bool {
    let Some(parsed) = parse_path(rule_path) else {
        return false;
    };

    let mut current = doc;
    for segment in &parsed.segments {
        match current.get(segment) {
            Some(next) => current = next,
            None => return false,
        }
    }

    let Some(selector) = parsed.selector else {
        return true;
    };

    match current {
        Value::Array(items) => items.iter().any(|item| {
            ["name", "id"]
                .iter()
                .any(|key| item.get(key).and_then(Value::as_str) == Some(selector))
        }),
        Value::Object(map) => map.contains_key(selector),
        _ => false,
    }
}

/// Verdict for one control mapping's framework and control id (lint L013).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryVerdict {
    /// The framework is registered and the control id matches its pattern.
    Ok,
    /// The framework id is not in `spec/registries/frameworks.yaml`.
    UnknownFramework,
    /// The framework is registered but the control id does not match its
    /// `control_id_pattern`.
    ControlIdMismatch,
}

/// Check one mapping against the embedded framework registry.
///
/// A `control_id_pattern` that fails to compile yields
/// [`RegistryVerdict::ControlIdMismatch`] for every control id: no id can be
/// shown to match a pattern the engine cannot read, so the verdict is the same
/// fail-closed one a genuine mismatch gets. The registry generator rejects
/// patterns this crate's regex engine cannot compile, so a registered
/// framework should not produce one.
#[must_use]
pub fn registry_verdict(framework: &str, control_id: &str) -> RegistryVerdict {
    let Some(entry) = generated_frameworks::framework(framework) else {
        return RegistryVerdict::UnknownFramework;
    };
    match regex::Regex::new(entry.control_id_pattern) {
        Ok(pattern) if pattern.is_match(control_id) => RegistryVerdict::Ok,
        _ => RegistryVerdict::ControlIdMismatch,
    }
}

/// Project a document to the JSON value that `rule_paths` are resolved against.
///
/// Serialization never fails for a parsed `HushSpec`; an empty object is
/// returned in the impossible error case so every path simply fails to resolve
/// (L012) rather than the command aborting.
#[must_use]
pub fn document_json(spec: &HushSpec) -> Value {
    serde_json::to_value(spec).unwrap_or_else(|_| Value::Object(serde_json::Map::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> Value {
        serde_json::json!({
            "rules": {
                "egress": { "allow": ["api.example.com"], "default": "block" },
                "secret_patterns": {
                    "patterns": [{ "name": "ssn", "pattern": "x", "severity": "critical" }]
                }
            },
            "extensions": {
                "posture": { "initial": "cold", "states": { "cold": {} }, "transitions": [] }
            }
        })
    }

    #[test]
    fn resolves_blocks_fields_and_selectors() {
        let doc = doc();
        assert!(path_resolves(&doc, "rules"));
        assert!(path_resolves(&doc, "rules.egress"));
        assert!(path_resolves(&doc, "rules.egress.allow"));
        assert!(path_resolves(&doc, "rules.secret_patterns.patterns[ssn]"));
        assert!(path_resolves(&doc, "extensions.posture"));
        assert!(path_resolves(&doc, "extensions.posture.states[cold]"));
    }

    #[test]
    fn rejects_missing_targets_and_malformed_paths() {
        let doc = doc();
        assert!(!path_resolves(&doc, "rules.tool_access"));
        assert!(!path_resolves(&doc, "rules.egress.nope"));
        assert!(!path_resolves(&doc, "rules.secret_patterns.patterns[nope]"));
        // Outside the path grammar: bad root, empty segment, unbalanced selector.
        assert!(!path_resolves(&doc, "metadata.author"));
        assert!(!path_resolves(&doc, "rules..egress"));
        assert!(!path_resolves(&doc, "rules.secret_patterns.patterns[ssn"));
        assert!(!path_resolves(&doc, ""));
    }

    #[test]
    fn coverage_flows_down_from_rules_and_from_a_block() {
        let doc = doc();
        assert!(path_covers_block(&doc, "rules", "rules.egress"));
        assert!(path_covers_block(&doc, "rules.egress", "rules.egress"));
        assert!(path_covers_block(
            &doc,
            "rules.egress.allow",
            "rules.egress"
        ));
        assert!(path_covers_block(
            &doc,
            "rules.secret_patterns.patterns[ssn]",
            "rules.secret_patterns"
        ));
        assert!(!path_covers_block(
            &doc,
            "rules.egress",
            "rules.tool_access"
        ));
        assert!(!path_covers_block(
            &doc,
            "extensions.posture",
            "rules.egress"
        ));
    }

    #[test]
    fn a_path_that_does_not_resolve_covers_nothing() {
        let doc = doc();
        for rule_path in [
            "rules.egress.nope",
            "rules.secret_patterns.patterns[nope]",
            "rules..egress",
        ] {
            assert!(!path_resolves(&doc, rule_path), "{rule_path} resolves");
            assert!(
                !path_covers_block(&doc, rule_path, "rules.egress"),
                "{rule_path} covers rules.egress"
            );
            assert!(
                !path_covers_block(&doc, rule_path, "rules.secret_patterns"),
                "{rule_path} covers rules.secret_patterns"
            );
        }
    }

    #[test]
    fn registry_verdicts() {
        assert_eq!(
            registry_verdict("hipaa-2013", "164.312(e)(1)"),
            RegistryVerdict::Ok
        );
        assert_eq!(
            registry_verdict("hipaa-2013", "CC6.1"),
            RegistryVerdict::ControlIdMismatch
        );
        assert_eq!(
            registry_verdict("acme-internal", "SEC-1"),
            RegistryVerdict::UnknownFramework
        );
    }

    #[test]
    fn rule_block_paths_lists_declared_blocks() {
        assert_eq!(
            rule_block_paths(&doc()),
            vec![
                "rules.egress".to_string(),
                "rules.secret_patterns".to_string()
            ]
        );
    }
}
