//! Decision-neutral auto-fixes. A fix may only fire where the corresponding
//! lint check has already proven the rewrite is a semantic no-op -- and,
//! because two of the three checks are themselves sampling heuristics rather
//! than exhaustive proofs (see the module-level notes below), this module
//! independently reverifies a strictly narrower, exact condition before ever
//! mutating the model. Fail-closed beats over-fixing: a smaller fixable
//! surface here is a deliberate feature, not a shortfall.
//!
//! ## Codes (verified against `cmd_lint`'s actual emitted `code:` values --
//! not the descriptive slugs an earlier draft of this plan assumed)
//!
//! - `L008` (`check_duplicate_patterns`): an entry is a byte-identical repeat
//!   of an earlier entry in the same list. Provably neutral by construction
//!   (string equality), no glob semantics involved -- this is the only one
//!   of the three with no caveats.
//! - `L002` (`check_overlapping_patterns`): flags pairs that *may* overlap
//!   using a small fixed set of synthetic sample paths
//!   (`generate_synthetic_paths`). That proves "not disjoint" on the sample,
//!   never subsumption -- two genuinely different patterns that overlap
//!   (e.g. `*.secret` and `file.*`, both matching `file.secret`) are not
//!   interchangeable, and removing either would change decisions for paths
//!   that match only one of them. The only case this module treats as fixed
//!   is the degenerate one where the flagged pair is byte-identical, which
//!   collapses to the exact same removal `L008` already performs.
//! - `L003` (`check_shadowed_exceptions`): flags an exception as dead when
//!   none of its synthetic sample paths match any forbidden pattern. The
//!   same sampling gap applies: for a wildcarded exception, the fixed
//!   substitution set (`generate_synthetic_paths`) can miss the specific
//!   string that would prove a real pattern/exception overlap (again,
//!   `*.secret` / `file.*` via `file.secret` is a concrete counterexample).
//!   This module only fixes the subset where the exception is a *literal*
//!   path (no `*`/`?`): a literal glob matches exactly one string, so
//!   testing that one string against every pattern is an exact answer, not
//!   an approximation.
use super::{LintFinding, run_all_checks};
use hushspec::HushSpec;
use hushspec::evaluate::glob_matches;
use std::collections::HashMap;

const CODE_DUPLICATE: &str = "L008";
const CODE_OVERLAP: &str = "L002";
const CODE_SHADOWED_EXCEPTION: &str = "L003";

/// Whether `code` is one this engine ever attempts to fix. Necessary but not
/// sufficient per finding -- see [`finding_is_fixable`] for the precise,
/// per-finding answer used to populate the JSON `fixable` field.
pub(crate) fn is_fixable(code: &str) -> bool {
    matches!(
        code,
        CODE_DUPLICATE | CODE_OVERLAP | CODE_SHADOWED_EXCEPTION
    )
}

/// Would `apply_fixes` actually remove the entry `finding` points at, given
/// `spec`'s current state? Stricter than `is_fixable(&finding.code)` alone:
/// most `L002` findings (and wildcarded `L003` findings) have a fixable
/// *code* but are not, individually, safe to act on.
pub(crate) fn finding_is_fixable(spec: &HushSpec, finding: &LintFinding) -> bool {
    let Some(rules) = spec.rules.as_ref() else {
        return false;
    };
    let Some((block, field, idx)) = parse_location(&finding.location) else {
        return false;
    };
    is_safe_removal(rules, &finding.code, block, field, idx)
}

/// Apply fixes to a fixpoint (max 3 passes). Returns one code per finding
/// actually resolved, in the order its removal was applied (a file with two
/// fixed duplicates yields two entries, e.g. `["L002", "L008"]`).
pub(crate) fn apply_fixes(spec: &mut HushSpec, initial: &[LintFinding]) -> Vec<String> {
    let mut all_fixed = Vec::new();
    let mut findings: Vec<LintFinding> = initial.to_vec();

    for _pass in 0..3 {
        let fixed_this_pass = apply_one_pass(spec, &findings);
        if fixed_this_pass.is_empty() {
            break;
        }
        all_fixed.extend(fixed_this_pass);
        findings = run_all_checks(spec, "(fixing)");
    }

    all_fixed
}

/// One fixpoint pass. Verification happens read-only against the pass's
/// *starting* state, entirely before any mutation; the actual removals are
/// then grouped per list and applied in descending index order. Both
/// precautions matter once a single pass can remove more than one entry from
/// the same list (e.g. `[a, b, a, c, c]`): mutating while iterating findings
/// would invalidate not-yet-processed indices, and removing in ascending
/// order would shift every later index out from under the next removal.
fn apply_one_pass(spec: &mut HushSpec, findings: &[LintFinding]) -> Vec<String> {
    let mut fixed_codes = Vec::new();
    let mut to_remove: HashMap<(String, String), Vec<usize>> = HashMap::new();

    {
        let Some(rules) = spec.rules.as_ref() else {
            return fixed_codes;
        };
        for f in findings {
            if !is_fixable(&f.code) {
                continue;
            }
            let Some((block, field, idx)) = parse_location(&f.location) else {
                continue;
            };
            if is_safe_removal(rules, &f.code, block, field, idx) {
                to_remove
                    .entry((block.to_string(), field.to_string()))
                    .or_default()
                    .push(idx);
                fixed_codes.push(f.code.clone());
            }
        }
    }

    if to_remove.is_empty() {
        return fixed_codes;
    }

    let Some(rules) = spec.rules.as_mut() else {
        // Findings referenced rules that no longer exist (shouldn't happen
        // within a single pass, but never mutate on an inconsistent state).
        return Vec::new();
    };
    for ((block, field), mut idxs) in to_remove {
        idxs.sort_unstable_by(|a, b| b.cmp(a));
        idxs.dedup();
        if let Some(list) = list_mut(rules, &block, &field) {
            for idx in idxs {
                if idx < list.len() {
                    list.remove(idx);
                }
            }
        }
    }

    fixed_codes
}

/// The one condition each fixable code is allowed to act on -- see the
/// module docs for why `L002` and `L003` are narrowed relative to what the
/// lint check itself flags.
fn is_safe_removal(
    rules: &hushspec::Rules,
    code: &str,
    block: &str,
    field: &str,
    idx: usize,
) -> bool {
    match code {
        CODE_DUPLICATE | CODE_OVERLAP => {
            list_ref(rules, block, field).is_some_and(|l| is_duplicate_at(l, idx))
        }
        CODE_SHADOWED_EXCEPTION if block == "forbidden_paths" && field == "exceptions" => rules
            .forbidden_paths
            .as_ref()
            .is_some_and(|fp| is_dead_literal_exception(&fp.patterns, &fp.exceptions, idx)),
        _ => false,
    }
}

/// Is `list[idx]` a byte-identical repeat of some earlier entry? Sound
/// regardless of whether the entries are glob patterns: removing a literal
/// duplicate string can never change which targets any pattern in the list
/// matches, because the duplicate contributes nothing the earlier occurrence
/// didn't already contribute.
fn is_duplicate_at(list: &[String], idx: usize) -> bool {
    idx < list.len() && list[..idx].contains(&list[idx])
}

/// Is `exceptions[idx]` a literal path (no `*`/`?`) that matches none of
/// `patterns`? Restricting to literal exceptions makes this an *exact*
/// check rather than the lint check's sampled one: a wildcard-free glob
/// matches only its own text, so testing that one string against every
/// pattern is a complete answer, not an approximation.
fn is_dead_literal_exception(patterns: &[String], exceptions: &[String], idx: usize) -> bool {
    let Some(exception) = exceptions.get(idx) else {
        return false;
    };
    if exception.contains('*') || exception.contains('?') {
        return false;
    }
    !patterns.iter().any(|p| glob_matches(p, exception))
}

/// Parse the `rules.<block>.<field>[<idx>]` location grammar that `L002`,
/// `L003`, and `L008` emit (see their `location:` construction in
/// `cmd_lint/mod.rs`). Other codes still use a file-level location and are
/// simply not fixable -- `parse_location` returning `None` for those is
/// expected, not an error.
fn parse_location(location: &str) -> Option<(&str, &str, usize)> {
    let rest = location.strip_prefix("rules.")?;
    let (block, rest) = rest.split_once('.')?;
    let (field, idx_str) = rest.split_once('[')?;
    let idx: usize = idx_str.strip_suffix(']')?.parse().ok()?;
    Some((block, field, idx))
}

/// Every `(block, field)` pair any of the three checks can flag (each check
/// enumerates its own list of rule blocks; this is the union).
fn list_ref<'a>(rules: &'a hushspec::Rules, block: &str, field: &str) -> Option<&'a Vec<String>> {
    match (block, field) {
        ("forbidden_paths", "patterns") => rules.forbidden_paths.as_ref().map(|r| &r.patterns),
        ("forbidden_paths", "exceptions") => rules.forbidden_paths.as_ref().map(|r| &r.exceptions),
        ("egress", "allow") => rules.egress.as_ref().map(|r| &r.allow),
        ("egress", "block") => rules.egress.as_ref().map(|r| &r.block),
        ("tool_access", "allow") => rules.tool_access.as_ref().map(|r| &r.allow),
        ("tool_access", "block") => rules.tool_access.as_ref().map(|r| &r.block),
        ("tool_access", "require_confirmation") => {
            rules.tool_access.as_ref().map(|r| &r.require_confirmation)
        }
        ("shell_commands", "forbidden_patterns") => {
            rules.shell_commands.as_ref().map(|r| &r.forbidden_patterns)
        }
        _ => None,
    }
}

fn list_mut<'a>(
    rules: &'a mut hushspec::Rules,
    block: &str,
    field: &str,
) -> Option<&'a mut Vec<String>> {
    match (block, field) {
        ("forbidden_paths", "patterns") => rules.forbidden_paths.as_mut().map(|r| &mut r.patterns),
        ("forbidden_paths", "exceptions") => {
            rules.forbidden_paths.as_mut().map(|r| &mut r.exceptions)
        }
        ("egress", "allow") => rules.egress.as_mut().map(|r| &mut r.allow),
        ("egress", "block") => rules.egress.as_mut().map(|r| &mut r.block),
        ("tool_access", "allow") => rules.tool_access.as_mut().map(|r| &mut r.allow),
        ("tool_access", "block") => rules.tool_access.as_mut().map(|r| &mut r.block),
        ("tool_access", "require_confirmation") => rules
            .tool_access
            .as_mut()
            .map(|r| &mut r.require_confirmation),
        ("shell_commands", "forbidden_patterns") => rules
            .shell_commands
            .as_mut()
            .map(|r| &mut r.forbidden_patterns),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(yaml: &str) -> hushspec::HushSpec {
        hushspec::HushSpec::parse(yaml).unwrap()
    }

    #[test]
    fn removes_exact_duplicate_patterns() {
        let mut s = spec(
            "hushspec: \"0.1.0\"\nname: t\nrules:\n  forbidden_paths:\n    patterns:\n      - \"**/.ssh/**\"\n      - \"**/.aws/**\"\n      - \"**/.ssh/**\"\n",
        );
        let findings = run_all_checks(&s, "t.yaml");
        let fixed = apply_fixes(&mut s, &findings);
        assert!(!fixed.is_empty());
        let patterns = &s
            .rules
            .as_ref()
            .unwrap()
            .forbidden_paths
            .as_ref()
            .unwrap()
            .patterns;
        assert_eq!(
            patterns,
            &vec!["**/.ssh/**".to_string(), "**/.aws/**".to_string()]
        );
    }

    #[test]
    fn fixes_preserve_decisions() {
        let yaml = "hushspec: \"0.1.0\"\nname: t\nrules:\n  forbidden_paths:\n    patterns:\n      - \"**/.ssh/**\"\n      - \"**/.ssh/**\"\n";
        let original = spec(yaml);
        let mut fixed = spec(yaml);
        let findings = run_all_checks(&fixed, "t.yaml");
        apply_fixes(&mut fixed, &findings);
        let action = hushspec::EvaluationAction {
            action_type: "file_read".into(),
            target: Some("/home/u/.ssh/id_rsa".into()),
            content: None,
            origin: None,
            posture: None,
            args_size: None,
        };
        assert_eq!(
            hushspec::evaluate(&original, &action).decision,
            hushspec::evaluate(&fixed, &action).decision
        );
    }

    #[test]
    fn fix_is_idempotent() {
        let mut s = spec(
            "hushspec: \"0.1.0\"\nname: t\nrules:\n  forbidden_paths:\n    patterns: [\"**/.ssh/**\", \"**/.ssh/**\"]\n",
        );
        let f1 = run_all_checks(&s, "t.yaml");
        apply_fixes(&mut s, &f1);
        let f2 = run_all_checks(&s, "t.yaml");
        assert!(
            apply_fixes(&mut s, &f2).is_empty(),
            "second pass must fix nothing"
        );
    }

    #[test]
    fn does_not_fix_heuristic_only_overlap() {
        // Two genuinely distinct patterns that the sampling heuristic flags
        // as "may overlap" -- neither is a duplicate of the other, so
        // removing either would change which targets match. Regression
        // guard for treating L002 as "always fixable by code".
        let mut s = spec(
            "hushspec: \"0.1.0\"\nname: t\nrules:\n  egress:\n    allow:\n      - \"*.example.com\"\n      - \"api.example.com\"\n    block: []\n    default: block\n",
        );
        let findings = run_all_checks(&s, "t.yaml");
        assert!(
            findings.iter().any(|f| f.code == "L002"),
            "fixture should trigger the overlap heuristic"
        );
        let fixed = apply_fixes(&mut s, &findings);
        assert!(fixed.is_empty(), "non-duplicate overlap must not be fixed");
        let allow = &s.rules.as_ref().unwrap().egress.as_ref().unwrap().allow;
        assert_eq!(allow.len(), 2, "both distinct entries must survive");
    }

    #[test]
    fn removes_dead_literal_exception() {
        let mut s = spec(
            "hushspec: \"0.1.0\"\nname: t\nrules:\n  forbidden_paths:\n    patterns:\n      - \"**/.ssh/**\"\n    exceptions:\n      - \"totally/unrelated/literal/path\"\n",
        );
        let findings = run_all_checks(&s, "t.yaml");
        assert!(findings.iter().any(|f| f.code == "L003"));
        let fixed = apply_fixes(&mut s, &findings);
        assert!(fixed.contains(&"L003".to_string()));
        let exceptions = &s
            .rules
            .as_ref()
            .unwrap()
            .forbidden_paths
            .as_ref()
            .unwrap()
            .exceptions;
        assert!(exceptions.is_empty());
    }

    #[test]
    fn does_not_remove_wildcarded_shadowed_exception() {
        // The lint check's synthetic-sample heuristic can miss a real
        // pattern/exception overlap for wildcarded exceptions, so even
        // though it flags this one as shadowed, apply_fixes must not touch
        // it -- only literal exceptions are provably dead.
        let mut s = spec(
            "hushspec: \"0.1.0\"\nname: t\nrules:\n  forbidden_paths:\n    patterns:\n      - \"**/.ssh/**\"\n    exceptions:\n      - \"**/unrelated/**\"\n",
        );
        let findings = run_all_checks(&s, "t.yaml");
        assert!(findings.iter().any(|f| f.code == "L003"));
        let fixed = apply_fixes(&mut s, &findings);
        assert!(fixed.is_empty());
        let exceptions = &s
            .rules
            .as_ref()
            .unwrap()
            .forbidden_paths
            .as_ref()
            .unwrap()
            .exceptions;
        assert_eq!(exceptions.len(), 1);
    }

    #[test]
    fn removes_multiple_duplicates_in_one_pass_without_index_shift_bug() {
        let mut s = spec(
            "hushspec: \"0.1.0\"\nname: t\nrules:\n  forbidden_paths:\n    patterns: [\"a\", \"b\", \"a\", \"c\", \"c\"]\n",
        );
        let findings = run_all_checks(&s, "t.yaml");
        let fixed = apply_fixes(&mut s, &findings);
        assert!(!fixed.is_empty());
        let patterns = &s
            .rules
            .as_ref()
            .unwrap()
            .forbidden_paths
            .as_ref()
            .unwrap()
            .patterns;
        assert_eq!(
            patterns,
            &vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn finding_is_fixable_is_true_for_exact_duplicate() {
        let s = spec(
            "hushspec: \"0.1.0\"\nname: t\nrules:\n  forbidden_paths:\n    patterns:\n      - \"**/.ssh/**\"\n      - \"**/.ssh/**\"\n",
        );
        let findings = run_all_checks(&s, "t.yaml");
        let dup = findings
            .iter()
            .find(|f| f.code == "L008")
            .expect("expected a duplicate finding");
        assert!(finding_is_fixable(&s, dup));
    }

    #[test]
    fn finding_is_fixable_is_false_for_heuristic_only_overlap() {
        let s = spec(
            "hushspec: \"0.1.0\"\nname: t\nrules:\n  egress:\n    allow:\n      - \"*.example.com\"\n      - \"api.example.com\"\n    block: []\n    default: block\n",
        );
        let findings = run_all_checks(&s, "t.yaml");
        let overlap = findings
            .iter()
            .find(|f| f.code == "L002")
            .expect("expected an overlap finding");
        assert!(!finding_is_fixable(&s, overlap));
    }

    #[test]
    fn is_fixable_covers_exactly_the_three_provably_neutral_codes() {
        for code in ["L008", "L002", "L003"] {
            assert!(is_fixable(code), "{code} should be fixable");
        }
        for code in [
            "L001", "L004", "L005", "L006", "L007", "L009", "L010", "E000", "E001",
        ] {
            assert!(!is_fixable(code), "{code} should not be fixable");
        }
    }

    #[test]
    fn parse_location_round_trips_the_grammar_the_checks_emit() {
        assert_eq!(
            parse_location("rules.forbidden_paths.patterns[2]"),
            Some(("forbidden_paths", "patterns", 2))
        );
        assert_eq!(
            parse_location("rules.tool_access.require_confirmation[0]"),
            Some(("tool_access", "require_confirmation", 0))
        );
        assert_eq!(parse_location("rulesets/strict.yaml"), None);
        assert_eq!(parse_location("rules.egress"), None);
    }
}
