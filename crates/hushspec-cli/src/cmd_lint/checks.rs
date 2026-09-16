//! Lint checks L014 through L020.
//!
//! Each check answers a question the existing L001-L013 set could not: L001-L010
//! ask whether a rule block is internally coherent, L011-L013 ask whether its
//! control mappings are honest. These ask whether the *security posture* the
//! document describes is the one its author meant -- the credential locations a
//! filesystem denylist forgot (L014), a secret pattern graded below the class it
//! detects (L015), a forbidden pattern broad enough to swallow its neighbours
//! (L016), a default that permits (L017), an allowlist that is empty (L018), a
//! posture state or origin profile nothing can ever reach (L019), and a `when`
//! condition that narrows nothing (L020).
//!
//! **Severity is a function of provability, not of alarm.** A check reports
//! `error` only where the document contains configuration that can never take
//! effect under the spec's own rules, `warning` where a construct defeats
//! something else the same document declares, and `info` where the construct is
//! coherent but easy to arrive at by accident. Two of these checks (L016, L018)
//! therefore emit at two different severities depending on which of those the
//! document is doing: a lone `.*` forbidden pattern *is* "block every command",
//! and `enabled: true` with an empty allowlist *is* the only way the spec lets a
//! document deny a capability outright (`enabled: false` makes the block inert,
//! which permits it). Reporting either of those as a defect would be wrong, and
//! would make `--fail-on-warnings` unusable for the deny-all presets that exist
//! precisely to say "nothing".

use super::LintFinding;
use hushspec::conditions::{Condition, DAY_ABBREVIATIONS, TimeWindowCondition};
use hushspec::evaluate::glob_matches;
use hushspec::{ComputerUseMode, DefaultAction, HushSpec, Rules, Severity};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Credential locations a filesystem denylist is expected to reach, each with
/// the probe paths that decide it. *Every* probe must be blocked for the
/// location to count as covered: a policy that blocks `**/.ssh/**` but no
/// `id_rsa*` glob still leaks a key copied to `/tmp`, and reporting that as
/// covered would be the more dangerous answer.
const CREDENTIAL_LOCATIONS: &[(&str, &[&str])] = &[
    (".env", &["/srv/app/.env", "/home/agent/project/.env"]),
    (
        ".ssh",
        &["/home/agent/.ssh/id_ed25519", "/root/.ssh/authorized_keys"],
    ),
    (".aws", &["/home/agent/.aws/credentials"]),
    (".gnupg", &["/home/agent/.gnupg/secring.gpg"]),
    (".kube", &["/home/agent/.kube/config"]),
    ("id_rsa", &["/home/agent/.ssh/id_rsa", "/tmp/backup/id_rsa"]),
];

/// L014 (warning/info): credential locations a filesystem denylist misses.
///
/// A `path_allowlist` inverts the model -- everything outside the allowlist is
/// already denied -- so a policy that runs one is silent here regardless of what
/// its denylist says.
pub(super) fn check_credential_coverage(
    rules: &Rules,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    let allowlisted = rules
        .path_allowlist
        .as_ref()
        .is_some_and(|allowlist| allowlist.enabled);
    if allowlisted {
        return;
    }

    let Some(forbidden) = rules.forbidden_paths.as_ref().filter(|rule| rule.enabled) else {
        // No denylist and no allowlist: the document states nothing at all about
        // the filesystem. That is a legitimate shape for a capability-scoped
        // policy meant to be composed onto a base (`rulesets/remote-desktop.yaml`
        // is one), so it is reported as information, not as a defect.
        findings.push(LintFinding::keyed(
            "L014",
            "info",
            "policy declares neither rules.forbidden_paths nor rules.path_allowlist -- \
             no filesystem location is protected by this document"
                .into(),
            file,
            "rules".into(),
        ));
        return;
    };

    let missing: Vec<&str> = CREDENTIAL_LOCATIONS
        .iter()
        .filter(|(_, probes)| {
            !probes.iter().all(|probe| {
                forbidden
                    .patterns
                    .iter()
                    .any(|pattern| glob_matches(pattern, probe))
                    && !forbidden
                        .exceptions
                        .iter()
                        .any(|exception| glob_matches(exception, probe))
            })
        })
        .map(|(name, _)| *name)
        .collect();

    if !missing.is_empty() {
        findings.push(LintFinding::keyed(
            "L014",
            "warning",
            format!(
                "rules.forbidden_paths does not cover {} -- add a glob that reaches each \
                 (\"**/.aws/**\" for a directory, \"**/id_rsa*\" for a file) or declare \
                 rules.path_allowlist instead",
                missing.join(", ")
            ),
            file,
            "rules.forbidden_paths.patterns".into(),
        ));
    }
}

/// Well-known credential classes, as OR-of-AND substring groups over the raw
/// regex source. Substrings are matched against the *pattern text*, not against
/// any input: a pattern that literally writes `AKIA` is looking for an AWS key
/// id whatever else it does.
const CREDENTIAL_CLASSES: &[(&str, &[&[&str]])] = &[
    ("an AWS access key id", &[&["AKIA"], &["ASIA"]]),
    (
        "a GitHub token",
        &[
            &["gh[opsur]_"],
            &["ghp_"],
            &["gho_"],
            &["ghs_"],
            &["ghu_"],
            &["ghr_"],
            &["github_pat_"],
        ],
    ),
    ("a PEM private key header", &[&["BEGIN", "PRIVATE"]]),
    ("an OpenAI API key", &[&["sk-"]]),
];

/// L015 (warning): a secret pattern that detects a well-known credential class
/// but is graded below `critical`.
///
/// Severity drives what an engine does with a match (core spec 3.4), so a
/// pattern that recognizes a live AWS key id and reports it as `warn` has
/// downgraded a credential leak to a note.
pub(super) fn check_credential_severity(
    rules: &Rules,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    let Some(secret_patterns) = &rules.secret_patterns else {
        return;
    };
    for (index, pattern) in secret_patterns.patterns.iter().enumerate() {
        if pattern.severity == Severity::Critical {
            continue;
        }
        let Some(class) = credential_class(&pattern.pattern) else {
            continue;
        };
        findings.push(LintFinding::keyed(
            "L015",
            "warning",
            format!(
                "rules.secret_patterns.patterns[{index}] {:?} detects {class} but is graded {:?} -- \
                 set severity: critical so a match is treated as a credential leak",
                pattern.name,
                severity_name(pattern.severity)
            ),
            file,
            format!("rules.secret_patterns.patterns[{index}].severity"),
        ));
    }
}

fn credential_class(pattern: &str) -> Option<&'static str> {
    CREDENTIAL_CLASSES
        .iter()
        .find(|(_, groups)| {
            groups
                .iter()
                .any(|group| group.iter().all(|marker| pattern.contains(marker)))
        })
        .map(|(label, _)| *label)
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::Error => "error",
        Severity::Warn => "warn",
    }
}

/// L016 (warning/info): a forbidden pattern broad enough to match every input.
///
/// `shell_commands` and `patch_integrity` forbidden patterns are unanchored
/// regexes tested against the whole command or diff, so a pattern that matches
/// the empty string matches every one of them.
pub(super) fn check_overbroad_forbidden_patterns(
    rules: &Rules,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    let lists: [(&str, Option<&[String]>); 2] = [
        (
            "rules.shell_commands.forbidden_patterns",
            rules
                .shell_commands
                .as_ref()
                .map(|rule| rule.forbidden_patterns.as_slice()),
        ),
        (
            "rules.patch_integrity.forbidden_patterns",
            rules
                .patch_integrity
                .as_ref()
                .map(|rule| rule.forbidden_patterns.as_slice()),
        ),
    ];

    for (list_path, patterns) in lists {
        let Some(patterns) = patterns else { continue };
        for (index, pattern) in patterns.iter().enumerate() {
            let Some(reason) = overbroad_reason(pattern) else {
                continue;
            };
            // One entry that matches everything is a deny-all: coherent, and the
            // only way this rule block can express one. The same entry sitting
            // beside others silently kills those others, which is a defect.
            let (severity, message) = if patterns.len() > 1 {
                (
                    "warning",
                    format!(
                        "{list_path}[{index}] {pattern:?} {reason} -- the other {} pattern(s) in \
                         this list can never add anything; drop them, or narrow this one",
                        patterns.len() - 1
                    ),
                )
            } else {
                (
                    "info",
                    format!(
                        "{list_path}[{index}] {pattern:?} {reason} -- this block denies everything, \
                         which is coherent for a deny-all policy; prefer denying the tool in \
                         rules.tool_access when that is not the intent"
                    ),
                )
            };
            findings.push(LintFinding::keyed(
                "L016",
                severity,
                message,
                file,
                format!("{list_path}[{index}]"),
            ));
        }
    }
}

/// Why `pattern` matches every possible input, if it does.
fn overbroad_reason(pattern: &str) -> Option<&'static str> {
    if pattern == ".*" || pattern == ".+" {
        return Some("matches every input");
    }
    // A single character is a substring test against the whole command: `a`
    // forbids every command containing an `a`. Anchors alone are excluded --
    // `^` and `$` are handled by the empty-string test below.
    let mut chars = pattern.chars();
    if let (Some(only), None) = (chars.next(), chars.next())
        && !matches!(only, '^' | '$')
    {
        return Some("is a single character, so it matches any input containing it");
    }
    // Unanchored matching means an expression that can match the empty string
    // matches at offset 0 of every input.
    if Regex::new(pattern).is_ok_and(|compiled| compiled.is_match("")) {
        return Some("matches the empty string, so it matches every input");
    }
    None
}

/// L017 (warning): a rule block whose default permits.
///
/// Supersedes L005, which reported the same shape as information and only when
/// the allow list was non-empty. `egress` defaults to `block` in the schema, so
/// an explicit `allow` is always a deliberate widening; `tool_access` defaults
/// to `allow`, so it is only reported once nothing else in the block narrows it.
pub(super) fn check_permissive_defaults(
    rules: &Rules,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    if let Some(egress) = &rules.egress
        && egress.enabled
        && egress.default == DefaultAction::Allow
    {
        findings.push(LintFinding::keyed(
            "L017",
            "warning",
            format!(
                "rules.egress.default is \"allow\" -- every host outside the {} block entry/entries \
                 is permitted and the {} allow entry/entries decide nothing; \
                 prefer default: block with an explicit allow list",
                egress.block.len(),
                egress.allow.len()
            ),
            file,
            "rules.egress.default".into(),
        ));
    }

    if let Some(tool_access) = &rules.tool_access
        && tool_access.enabled
        && tool_access.default == DefaultAction::Allow
        && tool_access.block.is_empty()
        && tool_access.require_confirmation.is_empty()
    {
        findings.push(LintFinding::keyed(
            "L017",
            "warning",
            "rules.tool_access.default is \"allow\" with empty block and require_confirmation \
             lists -- every tool is permitted; prefer default: block, or name the tools to deny"
                .into(),
            file,
            "rules.tool_access.default".into(),
        ));
    }
}

/// L018 (warning/info): a capability block enabled with an empty allowlist.
///
/// `enabled: false` makes a block inert, which *permits* the capability, so
/// `enabled: true` with an empty allowlist is the spec's only way to deny one
/// outright. That is reported as information. It is promoted to a warning only
/// where the same document contradicts itself or where the block, so configured,
/// does nothing at all.
pub(super) fn check_empty_capability_allowlists(
    rules: &Rules,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    if let Some(computer_use) = &rules.computer_use
        && computer_use.enabled
        && computer_use.allowed_actions.is_empty()
    {
        let (severity, message) = if computer_use.mode == ComputerUseMode::Observe {
            (
                "warning",
                "rules.computer_use is enabled with an empty allowed_actions list in \
                 \"observe\" mode -- observe never denies an unlisted action and nothing is \
                 listed, so the block has no effect"
                    .to_string(),
            )
        } else {
            (
                "info",
                format!(
                    "rules.computer_use is enabled with an empty allowed_actions list in {:?} \
                     mode -- every computer-use action is denied",
                    computer_use_mode_name(computer_use.mode)
                ),
            )
        };
        findings.push(LintFinding::keyed(
            "L018",
            severity,
            message,
            file,
            "rules.computer_use.allowed_actions".into(),
        ));
    }

    if let Some(input_injection) = &rules.input_injection
        && input_injection.enabled
        && input_injection.allowed_types.is_empty()
    {
        // `input.inject` in `computer_use.allowed_actions` says the agent may
        // inject; an empty `allowed_types` says every injection is denied. One
        // of the two is wrong.
        let contradicted = rules.computer_use.as_ref().is_some_and(|computer_use| {
            computer_use.enabled
                && computer_use
                    .allowed_actions
                    .iter()
                    .any(|action| action == "input.inject")
        });
        let (severity, message) = if contradicted {
            (
                "warning",
                "rules.input_injection is enabled with an empty allowed_types list while \
                 rules.computer_use.allowed_actions permits \"input.inject\" -- the action is \
                 allowed but every injection it could carry is denied"
                    .to_string(),
            )
        } else {
            (
                "info",
                "rules.input_injection is enabled with an empty allowed_types list -- every \
                 input injection is denied"
                    .to_string(),
            )
        };
        findings.push(LintFinding::keyed(
            "L018",
            severity,
            message,
            file,
            "rules.input_injection.allowed_types".into(),
        ));
    }
}

fn computer_use_mode_name(mode: ComputerUseMode) -> &'static str {
    match mode {
        ComputerUseMode::Observe => "observe",
        ComputerUseMode::Guardrail => "guardrail",
        ComputerUseMode::FailClosed => "fail_closed",
    }
}

/// L019 (error): extension configuration nothing can ever reach.
///
/// Everything reported here is provably dead under the extension specs, not a
/// judgement call: a posture state no transition leads to is never entered, and
/// an origin profile with no `match` object "is never a candidate"
/// (`spec/hushspec-origins.md` section 3).
pub(super) fn check_unreachable_extensions(
    spec: &HushSpec,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    let Some(extensions) = &spec.extensions else {
        return;
    };

    if let Some(posture) = &extensions.posture {
        // Transitions naming a state that does not exist. `from: "*"` is the
        // documented wildcard; `to` has no wildcard form.
        for (index, transition) in posture.transitions.iter().enumerate() {
            if transition.from != "*" && !posture.states.contains_key(&transition.from) {
                findings.push(LintFinding::keyed(
                    "L019",
                    "error",
                    format!(
                        "extensions.posture.transitions[{index}].from {:?} is not a defined posture state",
                        transition.from
                    ),
                    file,
                    format!("extensions.posture.transitions[{index}].from"),
                ));
            }
            if !posture.states.contains_key(&transition.to) {
                findings.push(LintFinding::keyed(
                    "L019",
                    "error",
                    format!(
                        "extensions.posture.transitions[{index}].to {:?} is not a defined posture state",
                        transition.to
                    ),
                    file,
                    format!("extensions.posture.transitions[{index}].to"),
                ));
            }
        }

        if posture.states.contains_key(&posture.initial) {
            // Reachability from `initial`, following transitions as directed
            // edges. `from: "*"` leaves every state, so it makes its target
            // reachable as soon as any state is.
            let mut reachable: HashSet<&str> = HashSet::new();
            reachable.insert(posture.initial.as_str());
            loop {
                let mut grew = false;
                for transition in &posture.transitions {
                    if !posture.states.contains_key(&transition.to) {
                        continue;
                    }
                    let from_reachable = if transition.from == "*" {
                        !reachable.is_empty()
                    } else {
                        reachable.contains(transition.from.as_str())
                    };
                    if from_reachable && reachable.insert(transition.to.as_str()) {
                        grew = true;
                    }
                }
                if !grew {
                    break;
                }
            }
            for name in posture.states.keys() {
                if !reachable.contains(name.as_str()) {
                    findings.push(LintFinding::keyed(
                        "L019",
                        "error",
                        format!(
                            "extensions.posture.states.{name} is unreachable -- it is not {:?} and \
                             no transition leads to it",
                            posture.initial
                        ),
                        file,
                        format!("extensions.posture.states.{name}"),
                    ));
                }
            }
        } else {
            // With no starting state nothing is reachable, so reporting every
            // state individually would bury the one problem that matters.
            findings.push(LintFinding::keyed(
                "L019",
                "error",
                format!(
                    "extensions.posture.initial {:?} is not a defined posture state -- no state is \
                     ever entered",
                    posture.initial
                ),
                file,
                "extensions.posture.initial".into(),
            ));
        }
    }

    if let Some(origins) = &extensions.origins {
        // Match objects already seen, in document order. Selection ties break by
        // document order (origins spec section 3), so a later profile with the
        // same match is never the one selected.
        let mut seen_matches: BTreeMap<String, String> = BTreeMap::new();
        for (index, profile) in origins.profiles.iter().enumerate() {
            let Some(match_rules) = &profile.match_rules else {
                findings.push(LintFinding::keyed(
                    "L019",
                    "error",
                    format!(
                        "extensions.origins.profiles[{index}] {:?} has no `match` object -- a \
                         profile whose match is absent is never a candidate (origins spec 3), so \
                         everything it overlays is dead",
                        profile.id
                    ),
                    file,
                    format!("extensions.origins.profiles[{index}]"),
                ));
                continue;
            };

            let fingerprint = serde_json::to_string(match_rules).unwrap_or_default();
            match seen_matches.get(&fingerprint) {
                Some(earlier) => findings.push(LintFinding::keyed(
                    "L019",
                    "error",
                    format!(
                        "extensions.origins.profiles[{index}] {:?} has the same `match` as {earlier:?} -- \
                         candidates that tie break by document order, so this profile is never selected",
                        profile.id
                    ),
                    file,
                    format!("extensions.origins.profiles[{index}].match"),
                )),
                None => {
                    seen_matches.insert(fingerprint, profile.id.clone());
                }
            }

            check_dead_overlay_entries(spec, profile, index, file, findings);
        }
    }
}

/// An overlay `allow` list intersects with the base's (origins spec 4.1), so a
/// literal entry the base allowlist does not match contributes nothing. Only
/// literal entries are checked: a wildcarded overlay entry can intersect a base
/// glob in ways a sample cannot rule out.
fn check_dead_overlay_entries(
    spec: &HushSpec,
    profile: &hushspec::extensions::OriginProfile,
    index: usize,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    let Some(overlay) = &profile.tool_access else {
        return;
    };
    let Some(base_allow) = spec
        .rules
        .as_ref()
        .and_then(|rules| rules.tool_access.as_ref())
        .map(|rule| rule.allow.as_slice())
        .filter(|allow| !allow.is_empty())
    else {
        return;
    };

    for (entry_index, entry) in overlay.allow.iter().enumerate() {
        if entry.contains('*') || entry.contains('?') {
            continue;
        }
        if base_allow
            .iter()
            .any(|pattern| glob_matches(pattern, entry))
        {
            continue;
        }
        findings.push(LintFinding::keyed(
            "L019",
            "error",
            format!(
                "extensions.origins.profiles[{index}].tool_access.allow[{entry_index}] {entry:?} \
                 is not in rules.tool_access.allow -- overlay allowlists intersect with the base \
                 (origins spec 4.1), so this entry can never allow anything"
            ),
            file,
            format!("extensions.origins.profiles[{index}].tool_access.allow[{entry_index}]"),
        ));
    }
}

/// L020 (info): a `when` condition clause that narrows nothing.
///
/// Note what this check does *not* claim. `check_time_window` treats
/// `start == end` as an always-open 24-hour window and an empty `days` as every
/// day, and an unevaluable window leaves the block active (core spec 3.13), so
/// there is no way to write a window that is never true -- the failure mode is a
/// window that is always true while reading like a restriction.
pub(super) fn check_degenerate_conditions(
    rules: &Rules,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    for (block, condition) in rule_block_conditions(rules) {
        if let Some(condition) = condition {
            walk_condition(condition, &format!("{block}.when"), file, findings);
        }
    }
}

/// L021 (warning): a `when.capability` that names a capability no posture state
/// grants can never be true when the policy has a posture extension, so its
/// block is permanently inert -- a control that reads as conditional and is
/// actually switched off. Without a posture extension the predicate is
/// unevaluable and the block stays active (core spec 3.13), so nothing is
/// reported: the policy is then simply not using posture yet.
pub(super) fn check_ungranted_capability_conditions(
    spec: &HushSpec,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    let Some(rules) = spec.rules.as_ref() else {
        return;
    };
    let Some(posture) = spec
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.posture.as_ref())
    else {
        return;
    };
    let mut granted: Vec<&str> = posture
        .states
        .values()
        .flat_map(|state| state.capabilities.iter().map(String::as_str))
        .collect();
    granted.sort_unstable();
    granted.dedup();
    for (block, condition) in rule_block_conditions(rules) {
        if let Some(condition) = condition {
            walk_capabilities(
                condition,
                &format!("{block}.when"),
                &granted,
                file,
                findings,
            );
        }
    }
}

fn walk_capabilities(
    condition: &Condition,
    path: &str,
    granted: &[&str],
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    if let Some(name) = &condition.capability
        && granted.binary_search(&name.as_str()).is_err()
    {
        findings.push(LintFinding::keyed(
            "L021",
            "warning",
            format!(
                "{path}.capability names `{name}`, which no posture state grants -- the block can never be active"
            ),
            file,
            format!("{path}.capability"),
        ));
    }
    if let Some(all_of) = &condition.all_of {
        for (index, child) in all_of.iter().enumerate() {
            walk_capabilities(
                child,
                &format!("{path}.all_of[{index}]"),
                granted,
                file,
                findings,
            );
        }
    }
    if let Some(any_of) = &condition.any_of {
        for (index, child) in any_of.iter().enumerate() {
            walk_capabilities(
                child,
                &format!("{path}.any_of[{index}]"),
                granted,
                file,
                findings,
            );
        }
    }
    if let Some(not) = &condition.not {
        walk_capabilities(not, &format!("{path}.not"), granted, file, findings);
    }
}

fn walk_condition(condition: &Condition, path: &str, file: &str, findings: &mut Vec<LintFinding>) {
    if let Some(window) = &condition.time_window {
        check_time_window(window, path, file, findings);
    }
    if let Some(all_of) = &condition.all_of {
        if all_of.is_empty() {
            findings.push(LintFinding::keyed(
                "L020",
                "info",
                format!(
                    "{path}.all_of is empty -- an empty AND is always true and narrows nothing"
                ),
                file,
                format!("{path}.all_of"),
            ));
        }
        for (index, child) in all_of.iter().enumerate() {
            walk_condition(child, &format!("{path}.all_of[{index}]"), file, findings);
        }
    }
    if let Some(any_of) = &condition.any_of {
        if any_of.is_empty() {
            findings.push(LintFinding::keyed(
                "L020",
                "info",
                format!(
                    "{path}.any_of is empty -- the engine skips an empty OR rather than failing \
                     it, so this clause narrows nothing"
                ),
                file,
                format!("{path}.any_of"),
            ));
        }
        for (index, child) in any_of.iter().enumerate() {
            walk_condition(child, &format!("{path}.any_of[{index}]"), file, findings);
        }
    }
    if let Some(not) = &condition.not {
        walk_condition(not, &format!("{path}.not"), file, findings);
    }
}

fn check_time_window(
    window: &TimeWindowCondition,
    path: &str,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    let all_days = !window.days.is_empty()
        && DAY_ABBREVIATIONS.iter().all(|known| {
            window
                .days
                .iter()
                .any(|day| day.eq_ignore_ascii_case(known))
        });
    if window.start == window.end {
        let qualifier = if window.days.is_empty() || all_days {
            " and `days` does not restrict either, so the whole window is inert"
        } else {
            ", so only `days` narrows this block"
        };
        findings.push(LintFinding::keyed(
            "L020",
            "info",
            format!(
                "{path}.time_window has start == end ({:?}) -- the engine reads that as an \
                 always-open 24-hour window{qualifier}",
                window.start
            ),
            file,
            format!("{path}.time_window.start"),
        ));
    } else if all_days {
        let listed: BTreeSet<String> = window
            .days
            .iter()
            .map(|day| day.to_ascii_lowercase())
            .collect();
        findings.push(LintFinding::keyed(
            "L020",
            "info",
            format!(
                "{path}.time_window.days lists all seven days ({}) -- that is the default, so the \
                 field narrows nothing",
                listed.into_iter().collect::<Vec<_>>().join(", ")
            ),
            file,
            format!("{path}.time_window.days"),
        ));
    }
}

/// Every rule block that can carry a `when`, paired with its path. Kept
/// alongside `check_disabled_rules`'s list so the twelve blocks are enumerated
/// in exactly two places, both guarded by `every_rule_block_is_covered`.
fn rule_block_conditions(rules: &Rules) -> Vec<(&'static str, Option<&Condition>)> {
    vec![
        (
            "rules.forbidden_paths",
            rules.forbidden_paths.as_ref().and_then(|r| r.when.as_ref()),
        ),
        (
            "rules.path_allowlist",
            rules.path_allowlist.as_ref().and_then(|r| r.when.as_ref()),
        ),
        (
            "rules.egress",
            rules.egress.as_ref().and_then(|r| r.when.as_ref()),
        ),
        (
            "rules.secret_patterns",
            rules.secret_patterns.as_ref().and_then(|r| r.when.as_ref()),
        ),
        (
            "rules.patch_integrity",
            rules.patch_integrity.as_ref().and_then(|r| r.when.as_ref()),
        ),
        (
            "rules.shell_commands",
            rules.shell_commands.as_ref().and_then(|r| r.when.as_ref()),
        ),
        (
            "rules.tool_access",
            rules.tool_access.as_ref().and_then(|r| r.when.as_ref()),
        ),
        (
            "rules.computer_use",
            rules.computer_use.as_ref().and_then(|r| r.when.as_ref()),
        ),
        (
            "rules.remote_desktop_channels",
            rules
                .remote_desktop_channels
                .as_ref()
                .and_then(|r| r.when.as_ref()),
        ),
        (
            "rules.input_injection",
            rules.input_injection.as_ref().and_then(|r| r.when.as_ref()),
        ),
        (
            "rules.browser_automation",
            rules
                .browser_automation
                .as_ref()
                .and_then(|r| r.when.as_ref()),
        ),
        (
            "rules.code_execution",
            rules.code_execution.as_ref().and_then(|r| r.when.as_ref()),
        ),
    ]
}

/// L022 (warning): an empty string in `tool_access.allow`, `block`, or
/// `require_confirmation`, or in an origins overlay list. Tool names match
/// exactly (core spec 3.7) and host patterns match normalized hosts (core
/// spec 3.3), so an empty entry can never match anything: it is dead weight
/// and usually a templating or editing mistake.
pub(super) fn check_empty_list_entries(
    spec: &HushSpec,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    let mut report = |path: String, entries: &[String]| {
        for (index, entry) in entries.iter().enumerate() {
            if entry.is_empty() {
                findings.push(LintFinding::keyed(
                    "L022",
                    "warning",
                    format!("{path}[{index}] is an empty string and can never match"),
                    file,
                    format!("{path}[{index}]"),
                ));
            }
        }
    };

    if let Some(tool_access) = spec
        .rules
        .as_ref()
        .and_then(|rules| rules.tool_access.as_ref())
    {
        report("rules.tool_access.allow".to_string(), &tool_access.allow);
        report("rules.tool_access.block".to_string(), &tool_access.block);
        report(
            "rules.tool_access.require_confirmation".to_string(),
            &tool_access.require_confirmation,
        );
    }

    let profiles = spec
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.origins.as_ref())
        .map(|origins| origins.profiles.as_slice())
        .unwrap_or_default();
    for profile in profiles {
        let prefix = format!("extensions.origins.profiles.{}", profile.id);
        if let Some(overlay) = &profile.tool_access {
            report(format!("{prefix}.tool_access.allow"), &overlay.allow);
            report(format!("{prefix}.tool_access.block"), &overlay.block);
            report(
                format!("{prefix}.tool_access.require_confirmation"),
                &overlay.require_confirmation,
            );
        }
        if let Some(overlay) = &profile.egress {
            report(format!("{prefix}.egress.allow"), &overlay.allow);
            report(format!("{prefix}.egress.block"), &overlay.block);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_of(yaml: &str) -> Rules {
        HushSpec::parse(yaml)
            .expect("test policy parses")
            .rules
            .expect("test policy declares rules")
    }

    fn codes(findings: &[LintFinding]) -> Vec<(String, String)> {
        findings
            .iter()
            .map(|f| (f.code.clone(), f.severity.clone()))
            .collect()
    }

    /// The twelve rule blocks are enumerated by hand in two places: L007's
    /// `enabled` list and L020's `when` list. `Rules` gaining a thirteenth block
    /// must not silently skip either -- a block missing from L007 is a control
    /// that can be switched off without the lint saying so.
    #[test]
    fn every_rule_block_is_covered() {
        // `Rules` skips its `None` fields when serialized, so the field list
        // comes from the published schema rather than from a default value.
        let declared: BTreeSet<String> = crate::generated_schemas::schema_body("core")
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
            .and_then(|schema| {
                schema
                    .pointer("/$defs/Rules/properties")
                    .and_then(|properties| properties.as_object())
                    .map(|properties| properties.keys().cloned().collect())
            })
            .expect("core schema declares Rules.properties");
        assert_eq!(declared.len(), 12, "the spec declares twelve rule blocks");

        let all = Rules::default();
        let with_conditions: BTreeSet<String> = rule_block_conditions(&all)
            .into_iter()
            .map(|(path, _)| path.trim_start_matches("rules.").to_string())
            .collect();
        assert_eq!(with_conditions, declared, "L020 must walk every rule block");

        let with_enabled: BTreeSet<String> = super::super::rule_block_enabled(&all)
            .into_iter()
            .map(|(path, _)| path.trim_start_matches("rules.").to_string())
            .collect();
        assert_eq!(with_enabled, declared, "L007 must cover every rule block");
    }

    #[test]
    fn l014_lists_only_the_credential_locations_a_denylist_misses() {
        let rules = rules_of(
            "hushspec: \"0.1.0\"\nrules:\n  forbidden_paths:\n    patterns:\n      - \"**/.ssh/**\"\n      - \"**/id_rsa*\"\n",
        );
        let mut findings = Vec::new();
        check_credential_coverage(&rules, "p.yaml", &mut findings);
        assert_eq!(findings.len(), 1);
        let message = &findings[0].message;
        // Only the list before the hint names what is missing; the hint after
        // `--` is static and mentions locations that are covered.
        let listed = message.split(" -- ").next().unwrap();
        assert!(listed.contains(".env"), "{message}");
        assert!(listed.contains(".aws"), "{message}");
        assert!(!listed.contains("id_rsa"), "{message}");
        assert!(!listed.contains(".ssh"), "{message}");
    }

    #[test]
    fn l014_is_silent_for_a_complete_denylist_and_for_an_allowlist() {
        let complete = rules_of(
            "hushspec: \"0.1.0\"\nrules:\n  forbidden_paths:\n    patterns:\n      - \"**/.ssh/**\"\n      - \"**/id_rsa*\"\n      - \"**/.env\"\n      - \"**/.env.*\"\n      - \"**/.aws/**\"\n      - \"**/.gnupg/**\"\n      - \"**/.kube/**\"\n",
        );
        let mut findings = Vec::new();
        check_credential_coverage(&complete, "p.yaml", &mut findings);
        assert!(findings.is_empty(), "{findings:?}");

        let allowlisted = rules_of(
            "hushspec: \"0.1.0\"\nrules:\n  path_allowlist:\n    enabled: true\n    read: [\"/workspace/**\"]\n",
        );
        findings.clear();
        check_credential_coverage(&allowlisted, "p.yaml", &mut findings);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn l014_reports_an_exception_that_reopens_a_credential_location() {
        let rules = rules_of(
            "hushspec: \"0.1.0\"\nrules:\n  forbidden_paths:\n    patterns:\n      - \"**\"\n    exceptions:\n      - \"**/.aws/**\"\n",
        );
        let mut findings = Vec::new();
        check_credential_coverage(&rules, "p.yaml", &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains(".aws"), "{:?}", findings[0]);
    }

    #[test]
    fn l015_fires_per_class_and_only_below_critical() {
        let rules = rules_of(
            "hushspec: \"0.1.0\"\nrules:\n  secret_patterns:\n    patterns:\n      - name: aws\n        pattern: \"(AKIA|ASIA)[0-9A-Z]{16}\"\n        severity: warn\n      - name: gh\n        pattern: \"gh[opsur]_[A-Za-z0-9]{36}\"\n        severity: error\n      - name: pem\n        pattern: \"-----BEGIN PRIVATE KEY-----\"\n        severity: critical\n      - name: generic\n        pattern: \"(?i)apikey[:=][A-Za-z0-9]{32,}\"\n        severity: warn\n",
        );
        let mut findings = Vec::new();
        check_credential_severity(&rules, "p.yaml", &mut findings);
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(findings[0].message.contains("AWS access key id"));
        assert!(findings[1].message.contains("GitHub token"));
    }

    #[test]
    fn l016_separates_a_deny_all_from_a_pattern_that_shadows_its_neighbours() {
        let sole = rules_of(
            "hushspec: \"0.1.0\"\nrules:\n  shell_commands:\n    forbidden_patterns:\n      - \".*\"\n",
        );
        let mut findings = Vec::new();
        check_overbroad_forbidden_patterns(&sole, "p.yaml", &mut findings);
        assert_eq!(codes(&findings), vec![("L016".into(), "info".into())]);

        let shadowing = rules_of(
            "hushspec: \"0.1.0\"\nrules:\n  shell_commands:\n    forbidden_patterns:\n      - \".*\"\n      - \"rm -rf /\"\n",
        );
        findings.clear();
        check_overbroad_forbidden_patterns(&shadowing, "p.yaml", &mut findings);
        assert_eq!(codes(&findings), vec![("L016".into(), "warning".into())]);
    }

    #[test]
    fn l016_recognizes_every_over_broad_shape() {
        assert!(overbroad_reason(".*").is_some());
        assert!(overbroad_reason(".+").is_some());
        assert!(overbroad_reason("a").is_some());
        assert!(overbroad_reason(".").is_some());
        assert!(overbroad_reason("^.*$").is_some());
        assert!(overbroad_reason("(foo)?").is_some());
        assert!(overbroad_reason("x*").is_some());
        assert!(overbroad_reason("rm -rf /").is_none());
        assert!(overbroad_reason("(?i)mkfs").is_none());
        // An invalid regex is a different lint's problem, never silently broad.
        assert!(overbroad_reason("(unclosed").is_none());
    }

    #[test]
    fn l017_reports_a_permissive_default_but_not_a_narrowed_one() {
        let permissive = rules_of(
            "hushspec: \"0.1.0\"\nrules:\n  egress:\n    allow: [\"*\"]\n    default: allow\n  tool_access:\n    default: allow\n",
        );
        let mut findings = Vec::new();
        check_permissive_defaults(&permissive, "p.yaml", &mut findings);
        assert_eq!(
            codes(&findings),
            vec![
                ("L017".into(), "warning".into()),
                ("L017".into(), "warning".into())
            ]
        );

        let narrowed = rules_of(
            "hushspec: \"0.1.0\"\nrules:\n  egress:\n    allow: [\"api.example.com\"]\n    default: block\n  tool_access:\n    block: [\"shell_exec\"]\n    default: allow\n",
        );
        findings.clear();
        check_permissive_defaults(&narrowed, "p.yaml", &mut findings);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn l018_grades_a_deny_all_as_info_and_a_contradiction_as_a_warning() {
        let deny_all = rules_of(
            "hushspec: \"0.1.0\"\nrules:\n  computer_use:\n    enabled: true\n    mode: fail_closed\n    allowed_actions: []\n  input_injection:\n    enabled: true\n    allowed_types: []\n",
        );
        let mut findings = Vec::new();
        check_empty_capability_allowlists(&deny_all, "p.yaml", &mut findings);
        assert_eq!(
            codes(&findings),
            vec![
                ("L018".into(), "info".into()),
                ("L018".into(), "info".into())
            ]
        );

        let contradictory = rules_of(
            "hushspec: \"0.1.0\"\nrules:\n  computer_use:\n    enabled: true\n    mode: guardrail\n    allowed_actions: [\"input.inject\"]\n  input_injection:\n    enabled: true\n    allowed_types: []\n",
        );
        findings.clear();
        check_empty_capability_allowlists(&contradictory, "p.yaml", &mut findings);
        assert_eq!(codes(&findings), vec![("L018".into(), "warning".into())]);

        let observing = rules_of(
            "hushspec: \"0.1.0\"\nrules:\n  computer_use:\n    enabled: true\n    mode: observe\n    allowed_actions: []\n",
        );
        findings.clear();
        check_empty_capability_allowlists(&observing, "p.yaml", &mut findings);
        assert_eq!(codes(&findings), vec![("L018".into(), "warning".into())]);
    }

    #[test]
    fn l020_reports_only_windows_that_narrow_nothing() {
        let inert = rules_of(
            "hushspec: \"0.1.0\"\nrules:\n  egress:\n    when:\n      time_window:\n        start: \"09:00\"\n        end: \"09:00\"\n    default: block\n",
        );
        let mut findings = Vec::new();
        check_degenerate_conditions(&inert, "p.yaml", &mut findings);
        assert_eq!(codes(&findings), vec![("L020".into(), "info".into())]);
        assert!(findings[0].message.contains("always-open"));

        let every_day = rules_of(
            "hushspec: \"0.1.0\"\nrules:\n  egress:\n    when:\n      time_window:\n        start: \"09:00\"\n        end: \"17:00\"\n        days: [\"mon\", \"tue\", \"wed\", \"thu\", \"fri\", \"sat\", \"sun\"]\n    default: block\n",
        );
        findings.clear();
        check_degenerate_conditions(&every_day, "p.yaml", &mut findings);
        assert_eq!(codes(&findings), vec![("L020".into(), "info".into())]);
        assert!(findings[0].message.contains("all seven days"));

        let real = rules_of(
            "hushspec: \"0.1.0\"\nrules:\n  egress:\n    when:\n      time_window:\n        start: \"09:00\"\n        end: \"17:00\"\n        days: [\"mon\", \"fri\"]\n    default: block\n",
        );
        findings.clear();
        check_degenerate_conditions(&real, "p.yaml", &mut findings);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn l020_walks_into_compound_conditions() {
        let nested = rules_of(
            "hushspec: \"0.1.0\"\nrules:\n  egress:\n    when:\n      any_of: []\n    default: block\n",
        );
        let mut findings = Vec::new();
        check_degenerate_conditions(&nested, "p.yaml", &mut findings);
        assert_eq!(codes(&findings), vec![("L020".into(), "info".into())]);
        assert_eq!(
            findings[0].path.as_deref(),
            Some("rules.egress.when.any_of")
        );
    }

    #[test]
    fn l019_reports_unreachable_states_and_unknown_transition_endpoints() {
        let spec = HushSpec::parse(
            "hushspec: \"0.1.0\"\nextensions:\n  posture:\n    initial: normal\n    states:\n      normal: {}\n      locked: {}\n      orphan: {}\n    transitions:\n      - from: normal\n        to: locked\n        on: critical_violation\n      - from: nowhere\n        to: ghost\n        on: user_approval\n",
        )
        .expect("posture policy parses");
        let mut findings = Vec::new();
        check_unreachable_extensions(&spec, "p.yaml", &mut findings);
        let messages: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
        assert!(findings.iter().all(|f| f.severity == "error"));
        assert!(
            messages.iter().any(|m| m.contains("\"nowhere\"")),
            "{messages:?}"
        );
        assert!(
            messages.iter().any(|m| m.contains("\"ghost\"")),
            "{messages:?}"
        );
        assert!(
            messages.iter().any(|m| m.contains("states.orphan")),
            "{messages:?}"
        );
        assert!(
            !messages.iter().any(|m| m.contains("states.locked")),
            "a state a transition leads to is reachable: {messages:?}"
        );
    }

    #[test]
    fn l019_reports_an_undefined_initial_state_once_not_per_state() {
        let spec = HushSpec::parse(
            "hushspec: \"0.1.0\"\nextensions:\n  posture:\n    initial: missing\n    states:\n      normal: {}\n      locked: {}\n    transitions:\n      - from: normal\n        to: locked\n        on: any_violation\n",
        )
        .expect("posture policy parses");
        let mut findings = Vec::new();
        check_unreachable_extensions(&spec, "p.yaml", &mut findings);
        // Nothing is reachable without a starting state, so listing every state
        // would bury the one problem that matters.
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(
            findings[0].path.as_deref(),
            Some("extensions.posture.initial")
        );
        assert!(findings[0].message.contains("\"missing\""));
    }

    #[test]
    fn l019_reports_profiles_that_can_never_be_selected() {
        let spec = HushSpec::parse(
            "hushspec: \"0.1.0\"\nextensions:\n  origins:\n    profiles:\n      - id: no-match\n        egress:\n          allow: [\"a.example.com\"]\n      - id: first\n        match:\n          provider: slack\n      - id: shadowed\n        match:\n          provider: slack\n",
        )
        .expect("origins policy parses");
        let mut findings = Vec::new();
        check_unreachable_extensions(&spec, "p.yaml", &mut findings);
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(findings[0].message.contains("no `match` object"));
        assert!(findings[1].message.contains("same `match`"));
    }

    #[test]
    fn l019_reports_overlay_allow_entries_the_base_never_allows() {
        let spec = HushSpec::parse(
            "hushspec: \"0.1.0\"\nrules:\n  tool_access:\n    allow: [\"read_file\", \"search\"]\n    default: block\nextensions:\n  origins:\n    profiles:\n      - id: dm\n        match:\n          space_type: dm\n        tool_access:\n          allow: [\"read_file\", \"deploy\", \"sea*\"]\n",
        )
        .expect("overlay policy parses");
        let mut findings = Vec::new();
        check_unreachable_extensions(&spec, "p.yaml", &mut findings);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("\"deploy\""));
        assert_eq!(
            findings[0].path.as_deref(),
            Some("extensions.origins.profiles[0].tool_access.allow[1]")
        );
    }
}
