//! SARIF 2.1.0 output for `h2h lint`.
//!
//! SARIF is what GitHub code scanning ingests, so this is the format that turns
//! a lint finding into an annotation on the pull request that introduced it.
//! The document is built by hand rather than through a SARIF crate: the subset
//! in play is small (one run, one driver, a rule catalog, results with one
//! physical location each, and removal fixes), and `sarif_output_validates`
//! in `tests/lint_span_tests.rs` checks every emitted document against the
//! vendored SARIF 2.1.0 JSON Schema, which is a stronger guarantee than a
//! typed builder would give on its own.
//!
//! The vendored schema is the draft-07 rendition published by SchemaStore --
//! the one GitHub's own tooling validates against -- copied into this crate so
//! the test never reaches the network.

use super::{FileLintResult, FindingJson};
use serde_json::{Value, json};

/// Canonical SARIF schema URL. Only an identifier in the emitted document; the
/// bytes it names are vendored at `crates/hushspec-cli/schemas/`.
const SCHEMA_URL: &str = "https://json.schemastore.org/sarif-2.1.0.json";

const INFORMATION_URI: &str = "https://github.com/backbay-labs/hush";

/// Where the rule catalog is documented in prose. Every rule points at the same
/// section rather than at a per-code anchor: the catalog is one table, and a
/// fragment that does not exist is worse than one that lands on the table.
const HELP_URI: &str =
    "https://github.com/backbay-labs/hush/blob/main/docs/src/reference/cli.md#lint-rules";

/// One lint code's catalog entry.
///
/// This is the single source of truth for what each code means. `docs/src/
/// reference/cli.md` documents the same set, and `documented_codes_match_the_
/// catalog` in `tests/lint_span_tests.rs` fails if the two drift.
pub(super) struct RuleDoc {
    pub(super) id: &'static str,
    pub(super) name: &'static str,
    pub(super) short: &'static str,
    pub(super) full: &'static str,
    /// SARIF level: `error`, `warning` or `note`.
    pub(super) level: &'static str,
}

/// Every code `h2h lint` can emit, in code order.
///
/// `L005` is absent on purpose: it reported a permissive default as information
/// and only when the allow list was non-empty, which `L017` now covers as a
/// warning in every case. The identifier stays retired rather than reused.
pub(super) const RULES: &[RuleDoc] = &[
    RuleDoc {
        id: "E000",
        name: "file-unreadable",
        short: "The policy file could not be read.",
        full: "The path does not exist, or the file could not be read as UTF-8. Nothing was linted.",
        level: "error",
    },
    RuleDoc {
        id: "E001",
        name: "parse-error",
        short: "The document is not a valid HushSpec policy.",
        full: "YAML parsing or deserialization failed. HushSpec rejects unknown keys (`deny_unknown_fields`), so a typo in a field name lands here rather than being silently ignored.",
        level: "error",
    },
    RuleDoc {
        id: "E002",
        name: "unresolvable-extends",
        short: "The `extends` chain could not be resolved.",
        full: "A base policy could not be loaded, the chain is circular, exceeds the maximum depth, or a pinned digest did not match. Lint reports the resolved document, so an unresolvable chain leaves nothing to lint.",
        level: "error",
    },
    RuleDoc {
        id: "L001",
        name: "empty-rule-block",
        short: "An enabled rule block has no entries and a permissive default.",
        full: "The block is enabled but declares nothing to allow or deny, so it makes no decision. Either populate it or remove it; a block that looks like enforcement but is not is worse than an absent one.",
        level: "warning",
    },
    RuleDoc {
        id: "L002",
        name: "overlapping-patterns",
        short: "Two patterns in the same list may match the same target.",
        full: "Sampled synthetic targets matched both patterns. Overlap is not itself a defect -- but a redundant pair is dead weight, and `--fix` removes the later entry when the two are byte-identical.",
        level: "warning",
    },
    RuleDoc {
        id: "L003",
        name: "shadowed-exception",
        short: "A `forbidden_paths` exception matches no forbidden pattern.",
        full: "The exception re-permits a path that nothing denies, so it has no effect. Either the pattern it was meant to carve out was removed, or the exception has a typo.",
        level: "warning",
    },
    RuleDoc {
        id: "L004",
        name: "overly-broad-allow",
        short: "An allow list contains a match-everything wildcard.",
        full: "`allow: [\"*\"]` permits every target, which makes the rest of the allow list decorative and the block ineffective as a narrowing device.",
        level: "warning",
    },
    RuleDoc {
        id: "L006",
        name: "regex-complexity",
        short: "A regex is long, heavily alternated, or has nested quantifiers.",
        full: "Nested quantifiers are a ReDoS risk, and very long or heavily alternated patterns are hard to review. Split the pattern, or move the alternation into separate named entries.",
        level: "warning",
    },
    RuleDoc {
        id: "L007",
        name: "disabled-rule",
        short: "A rule block is explicitly disabled.",
        full: "`enabled: false` makes the block inert, which *permits* whatever it would otherwise govern. Reported for every one of the twelve rule blocks so a disabled control is never invisible.",
        level: "note",
    },
    RuleDoc {
        id: "L008",
        name: "duplicate-pattern",
        short: "A list entry repeats an earlier entry exactly.",
        full: "A byte-identical repeat contributes nothing. This is the one finding whose removal is provably decision-neutral, so `--fix` always applies it.",
        level: "warning",
    },
    RuleDoc {
        id: "L009",
        name: "missing-secret-patterns",
        short: "The policy declares no `secret_patterns` block.",
        full: "Without secret detection, a `file_write` carrying a credential is indistinguishable from any other write.",
        level: "note",
    },
    RuleDoc {
        id: "L010",
        name: "unreachable-allow",
        short: "An allow entry is also in the block list.",
        full: "Block takes precedence over allow, so the allow entry can never decide anything.",
        level: "warning",
    },
    RuleDoc {
        id: "L011",
        name: "unmapped-rule-block",
        short: "A rule block has no `metadata.controls` mapping.",
        full: "Once a policy maps controls, an unmapped block is enforcement with no stated reason. Policies that map nothing at all are silent here.",
        level: "warning",
    },
    RuleDoc {
        id: "L012",
        name: "broken-control-mapping",
        short: "A control mapping names a rule path that does not exist.",
        full: "The mapping claims the policy implements a control through a path that resolves to nothing in the resolved document -- a false compliance claim, so it is an error.",
        level: "error",
    },
    RuleDoc {
        id: "L013",
        name: "unregistered-control",
        short: "A control mapping's framework or control id is unrecognized.",
        full: "The framework is not in `spec/registries/frameworks.yaml`, or the control id does not match that framework's id pattern. The registry is advisory, so this is an unverifiable claim rather than an invalid document.",
        level: "warning",
    },
    RuleDoc {
        id: "L014",
        name: "credential-paths-uncovered",
        short: "A filesystem denylist misses well-known credential locations.",
        full: "`.env`, `.ssh`, `.aws`, `.gnupg`, `.kube` and `id_rsa` are where agent credentials actually live; a denylist that does not reach all of them leaks the ones it misses. A policy that runs a `path_allowlist` instead is silent, since everything outside the allowlist is already denied. A policy with neither block is reported as information, not as a defect: that is a legitimate shape for a capability-scoped document meant to be composed onto a base.",
        level: "warning",
    },
    RuleDoc {
        id: "L015",
        name: "under-graded-credential-pattern",
        short: "A well-known credential pattern is graded below `critical`.",
        full: "Severity drives what an engine does with a match, so a pattern that recognizes an AWS key id, a GitHub token, a PEM private key header or an OpenAI key and reports `warn` has downgraded a credential leak to a note.",
        level: "warning",
    },
    RuleDoc {
        id: "L016",
        name: "overbroad-forbidden-pattern",
        short: "A forbidden pattern matches every possible input.",
        full: "Forbidden patterns are unanchored, so `.*`, `.+`, a bare single character, or anything that matches the empty string matches every command or diff. Beside other patterns that is a defect (they become dead) and is reported as a warning; as the only entry in its list it is a coherent deny-all and is reported as information.",
        level: "warning",
    },
    RuleDoc {
        id: "L017",
        name: "permissive-default",
        short: "A rule block's default permits.",
        full: "`egress.default: allow` permits every host outside `block`, making the allow list decorative; `tool_access.default: allow` with empty `block` and `require_confirmation` permits every tool. Supersedes L005, which reported the same shape as information.",
        level: "warning",
    },
    RuleDoc {
        id: "L018",
        name: "empty-capability-allowlist",
        short: "A capability block is enabled with an empty allowlist.",
        full: "`enabled: false` makes a block inert, which permits the capability, so `enabled: true` with an empty allowlist is the spec's only way to deny one outright -- reported as information. It is promoted to a warning where the document contradicts itself (`computer_use` permits `input.inject` while `input_injection` denies every type) or where the block does nothing at all (`computer_use` in `observe` mode with nothing allowed).",
        level: "warning",
    },
    RuleDoc {
        id: "L019",
        name: "unreachable-extension",
        short: "Extension configuration that nothing can ever reach.",
        full: "A posture state that is neither `initial` nor the target of any transition is never entered; a transition naming an undefined state never fires; an origin profile with no `match` object is never a candidate (origins spec 3) and one that repeats an earlier profile's `match` always loses the document-order tie; an overlay `allow` entry the base allowlist does not match can never allow anything (origins spec 4.1).",
        level: "error",
    },
    RuleDoc {
        id: "L020",
        name: "inert-condition",
        short: "A `when` clause narrows nothing.",
        full: "The engine reads `start == end` as an always-open 24-hour window and an empty `days` as every day, so a window written that way reads like a restriction and is not one. An `all_of`/`any_of` with no members is likewise always true.",
        level: "note",
    },
];

fn rule_index(code: &str) -> Option<usize> {
    RULES.iter().position(|rule| rule.id == code)
}

/// Map a lint severity onto a SARIF level.
fn level_for(severity: &str) -> &'static str {
    match severity {
        "error" => "error",
        "warning" => "warning",
        _ => "note",
    }
}

/// Percent-encode anything that is not legal in a URI reference.
///
/// Policy paths are used verbatim as `artifactLocation.uri`, which the SARIF
/// schema declares `format: uri-reference`. Windows separators become `/`, and
/// the stdin pseudo-path `<stdin>` -- whose angle brackets are not URI
/// characters -- survives as `%3Cstdin%3E` rather than producing a document
/// that fails validation.
fn uri_for(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for ch in path.chars() {
        match ch {
            '\\' => out.push('/'),
            'A'..='Z' | 'a'..='z' | '0'..='9' => out.push(ch),
            '-' | '.' | '_' | '~' | '/' | ':' | '@' | '!' | '$' | '&' | '\'' | '(' | ')' | '*'
            | '+' | ',' | ';' | '=' => out.push(ch),
            _ => {
                let mut buf = [0u8; 4];
                for byte in ch.encode_utf8(&mut buf).as_bytes() {
                    out.push_str(&format!("%{byte:02X}"));
                }
            }
        }
    }
    out
}

/// Build the SARIF document for a whole lint run.
pub(super) fn document(results: &[FileLintResult]) -> Value {
    let rules: Vec<Value> = RULES
        .iter()
        .map(|rule| {
            json!({
                "id": rule.id,
                "name": rule.name,
                "shortDescription": {"text": rule.short},
                "fullDescription": {"text": rule.full},
                "defaultConfiguration": {"level": rule.level},
                "helpUri": HELP_URI,
            })
        })
        .collect();

    let mut sarif_results = Vec::new();
    for file in results {
        for finding in &file.findings {
            sarif_results.push(result(file, finding));
        }
    }

    json!({
        "$schema": SCHEMA_URL,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "h2h",
                    "version": env!("CARGO_PKG_VERSION"),
                    "semanticVersion": env!("CARGO_PKG_VERSION"),
                    "informationUri": INFORMATION_URI,
                    "rules": rules,
                }
            },
            "results": sarif_results,
        }]
    })
}

fn result(file: &FileLintResult, finding: &FindingJson) -> Value {
    // A finding inherited from a base policy reports the base's file, not the
    // leaf's: that is where the offending key is actually written.
    let uri = uri_for(
        finding
            .span
            .as_ref()
            .map_or(file.file.as_str(), |span| span.file.as_str()),
    );

    let mut physical = json!({"artifactLocation": {"uri": uri.clone()}});
    if let Some(span) = &finding.span {
        physical["region"] = json!({
            "startLine": span.line,
            "startColumn": span.column,
            "endLine": span.end_line,
            "endColumn": span.end_column,
        });
    }

    let mut location = json!({"physicalLocation": physical});
    if let Some(path) = &finding.path {
        // `logicalLocations` carries the document path, so a consumer that
        // cannot use line numbers (a diff-less rerun, a moved file) can still
        // say which key the finding is about.
        location["logicalLocations"] = json!([{
            "fullyQualifiedName": path,
            "kind": "member",
        }]);
    }

    let mut result = json!({
        "ruleId": finding.code,
        "level": level_for(&finding.severity),
        "message": {"text": finding.message},
        "locations": [location],
    });
    if let Some(index) = rule_index(&finding.code) {
        result["ruleIndex"] = json!(index);
    }

    // Every fixable finding is a list-entry removal (see `cmd_lint::fix`), so
    // the fix is a deleted region and no inserted content.
    if finding.fixable
        && let Some(span) = &finding.span
    {
        result["fixes"] = json!([{
            "description": {"text": "Remove this entry (`h2h lint --fix`)."},
            "artifactChanges": [{
                "artifactLocation": {"uri": uri},
                "replacements": [{
                    "deletedRegion": {
                        "startLine": span.line,
                        "startColumn": span.column,
                        "endLine": span.end_line,
                        "endColumn": span.end_column,
                    }
                }]
            }]
        }]);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_ids_are_unique_and_ordered() {
        let ids: Vec<&str> = RULES.iter().map(|rule| rule.id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "duplicate rule id in the catalog");
        assert!(ids.windows(2).all(|pair| pair[0] < pair[1]), "{ids:?}");
        assert!(
            !ids.contains(&"L005"),
            "L005 is retired in favour of L017 and must not be reused"
        );
    }

    #[test]
    fn every_rule_declares_a_valid_level() {
        for rule in RULES {
            assert!(
                matches!(rule.level, "error" | "warning" | "note"),
                "{} has level {:?}",
                rule.id,
                rule.level
            );
            assert!(
                !rule.short.is_empty() && !rule.full.is_empty(),
                "{}",
                rule.id
            );
        }
    }

    #[test]
    fn uri_encoding_keeps_paths_and_escapes_the_stdin_pseudo_path() {
        assert_eq!(uri_for("rulesets/default.yaml"), "rulesets/default.yaml");
        assert_eq!(uri_for("a\\b.yaml"), "a/b.yaml");
        assert_eq!(uri_for("<stdin>"), "%3Cstdin%3E");
        assert_eq!(uri_for("my policy.yaml"), "my%20policy.yaml");
    }
}
