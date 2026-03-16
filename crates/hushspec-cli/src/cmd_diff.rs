use clap::ValueEnum;
use colored::Colorize;
use hushspec::{Decision, EvaluationAction, EvaluationResult, HushSpec, evaluate};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(clap::Args)]
pub struct DiffArgs {
    /// Base policy file (before change)
    old: PathBuf,

    /// Updated policy file (after change)
    new: PathBuf,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: DiffOutputFormat,
}

#[derive(Clone, Copy, ValueEnum)]
enum DiffOutputFormat {
    Text,
    Json,
}

#[derive(Clone, Debug, serde::Serialize)]
struct DecisionChange {
    action: ProbeAction,
    old_decision: String,
    new_decision: String,
    old_rule: Option<String>,
    new_rule: Option<String>,
    change_type: String,
}

#[derive(Clone, Debug, serde::Serialize)]
struct ProbeAction {
    #[serde(rename = "type")]
    action_type: String,
    target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    args_size: Option<usize>,
}

pub fn run(args: DiffArgs) -> i32 {
    // Load old policy
    let old_spec = match load_policy(&args.old) {
        Ok(s) => s,
        Err(msg) => {
            eprintln!("{} {}", "error".red(), msg);
            return 2;
        }
    };

    // Load new policy
    let new_spec = match load_policy(&args.new) {
        Ok(s) => s,
        Err(msg) => {
            eprintln!("{} {}", "error".red(), msg);
            return 2;
        }
    };

    // Generate probes from both policies
    let probes = generate_probes(&old_spec, &new_spec);

    // Evaluate each probe against both policies
    let mut changes: Vec<DecisionChange> = Vec::new();

    for probe in &probes {
        let action = EvaluationAction {
            action_type: probe.action_type.clone(),
            target: Some(probe.target.clone()),
            content: probe.content.clone(),
            args_size: probe.args_size,
            ..Default::default()
        };

        let old_result = evaluate(&old_spec, &action);
        let new_result = evaluate(&new_spec, &action);

        let change_type = classify_change(&old_result, &new_result);

        changes.push(DecisionChange {
            action: probe.clone(),
            old_decision: format_decision(&old_result.decision),
            new_decision: format_decision(&new_result.decision),
            old_rule: old_result.matched_rule,
            new_rule: new_result.matched_rule,
            change_type,
        });
    }

    match args.format {
        DiffOutputFormat::Text => print_text_diff(&args, &changes),
        DiffOutputFormat::Json => print_json_diff(&changes),
    }

    0
}

fn load_policy(path: &Path) -> Result<HushSpec, String> {
    if !path.exists() {
        return Err(format!("file not found: {}", path.display()));
    }

    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;

    HushSpec::parse(&content).map_err(|e| format!("failed to parse {}: {e}", path.display()))
}

fn generate_probes(old: &HushSpec, new: &HushSpec) -> Vec<ProbeAction> {
    let mut probes = BTreeSet::new();

    // Extract targets from forbidden_paths
    extract_path_targets(old, &mut probes);
    extract_path_targets(new, &mut probes);

    // Extract targets from path_allowlist
    extract_path_allowlist_targets(old, &mut probes);
    extract_path_allowlist_targets(new, &mut probes);

    // Extract targets from egress
    extract_egress_targets(old, &mut probes);
    extract_egress_targets(new, &mut probes);

    // Extract content-driven probes from secret_patterns
    extract_secret_targets(old, &mut probes);
    extract_secret_targets(new, &mut probes);

    // Extract patch probes from patch_integrity
    extract_patch_targets(old, &mut probes);
    extract_patch_targets(new, &mut probes);

    // Extract targets from tool_access
    extract_tool_targets(old, &mut probes);
    extract_tool_targets(new, &mut probes);

    // Extract shell_command probes from forbidden_patterns
    extract_shell_targets(old, &mut probes);
    extract_shell_targets(new, &mut probes);

    // Extract computer_use and channel probes
    extract_computer_use_targets(old, &mut probes);
    extract_computer_use_targets(new, &mut probes);

    // Extract input injection probes
    extract_input_injection_targets(old, &mut probes);
    extract_input_injection_targets(new, &mut probes);

    // Add standard probes that test common scenarios
    insert_probe(&mut probes, "file_read", "/etc/passwd", None, None);
    insert_probe(&mut probes, "file_read", "/etc/shadow", None, None);
    insert_probe(
        &mut probes,
        "file_write",
        "/tmp/output.txt",
        Some("hello world".to_string()),
        None,
    );
    insert_probe(
        &mut probes,
        "patch_apply",
        "patch.diff",
        Some(build_patch(2, 1)),
        None,
    );
    insert_probe(&mut probes, "egress", "example.com", None, None);
    insert_probe(&mut probes, "tool_call", "unknown_tool", None, None);
    insert_probe(&mut probes, "shell_command", "rm -rf /", None, None);
    insert_probe(&mut probes, "shell_command", "ls", None, None);
    insert_probe(&mut probes, "computer_use", "remote.clipboard", None, None);
    insert_probe(&mut probes, "input_inject", "keyboard", None, None);

    probes
        .into_iter()
        .map(|(action_type, target, content, args_size)| ProbeAction {
            action_type,
            target,
            content,
            args_size,
        })
        .collect()
}

fn insert_probe(
    probes: &mut BTreeSet<(String, String, Option<String>, Option<usize>)>,
    action_type: &str,
    target: &str,
    content: Option<String>,
    args_size: Option<usize>,
) {
    probes.insert((
        action_type.to_string(),
        target.to_string(),
        content,
        args_size,
    ));
}

fn extract_path_targets(
    spec: &HushSpec,
    probes: &mut BTreeSet<(String, String, Option<String>, Option<usize>)>,
) {
    let Some(rules) = &spec.rules else { return };

    if let Some(forbidden_paths) = &rules.forbidden_paths {
        for pattern in &forbidden_paths.patterns {
            let concrete = concretize_glob(pattern);
            insert_probe(probes, "file_read", &concrete, None, None);
        }
        for pattern in &forbidden_paths.exceptions {
            let concrete = concretize_glob(pattern);
            insert_probe(probes, "file_read", &concrete, None, None);
        }
    }
}

fn extract_path_allowlist_targets(
    spec: &HushSpec,
    probes: &mut BTreeSet<(String, String, Option<String>, Option<usize>)>,
) {
    let Some(rules) = &spec.rules else { return };

    if let Some(path_allowlist) = &rules.path_allowlist {
        for pattern in &path_allowlist.read {
            let concrete = concretize_glob(pattern);
            insert_probe(probes, "file_read", &concrete, None, None);
        }
        for pattern in &path_allowlist.write {
            let concrete = concretize_glob(pattern);
            insert_probe(
                probes,
                "file_write",
                &concrete,
                Some("hello world".to_string()),
                None,
            );
        }
        for pattern in &path_allowlist.patch {
            let concrete = concretize_glob(pattern);
            insert_probe(
                probes,
                "patch_apply",
                &concrete,
                Some(build_patch(1, 0)),
                None,
            );
        }
    }
}

fn extract_egress_targets(
    spec: &HushSpec,
    probes: &mut BTreeSet<(String, String, Option<String>, Option<usize>)>,
) {
    let Some(rules) = &spec.rules else { return };

    if let Some(egress) = &rules.egress {
        for entry in &egress.allow {
            let concrete = concretize_domain(entry);
            insert_probe(probes, "egress", &concrete, None, None);
        }
        for entry in &egress.block {
            let concrete = concretize_domain(entry);
            insert_probe(probes, "egress", &concrete, None, None);
        }
    }
}

fn extract_secret_targets(
    spec: &HushSpec,
    probes: &mut BTreeSet<(String, String, Option<String>, Option<usize>)>,
) {
    let Some(rules) = &spec.rules else { return };

    if let Some(secret_patterns) = &rules.secret_patterns {
        for pattern in &secret_patterns.patterns {
            let literal = extract_regex_literal(&pattern.pattern);
            let content = if literal.is_empty() {
                pattern.name.clone()
            } else {
                literal
            };
            insert_probe(probes, "file_write", "/tmp/secret.txt", Some(content), None);
        }
        for pattern in &secret_patterns.skip_paths {
            let concrete = concretize_glob(pattern);
            insert_probe(
                probes,
                "file_write",
                &concrete,
                Some("api_key = abcdefghijklmnopqrstuvwxyz123456".to_string()),
                None,
            );
        }
    }
}

fn extract_patch_targets(
    spec: &HushSpec,
    probes: &mut BTreeSet<(String, String, Option<String>, Option<usize>)>,
) {
    let Some(rules) = &spec.rules else { return };

    if let Some(patch_integrity) = &rules.patch_integrity {
        for pattern in &patch_integrity.forbidden_patterns {
            let literal = extract_regex_literal(pattern);
            let content = if literal.is_empty() {
                build_patch(1, 0)
            } else {
                format!("@@\n+{literal}")
            };
            insert_probe(probes, "patch_apply", "patch.diff", Some(content), None);
        }

        insert_probe(
            probes,
            "patch_apply",
            "patch.diff",
            Some(build_patch(
                patch_integrity.max_additions.saturating_add(1),
                0,
            )),
            None,
        );
        insert_probe(
            probes,
            "patch_apply",
            "patch.diff",
            Some(build_patch(
                0,
                patch_integrity.max_deletions.saturating_add(1),
            )),
            None,
        );
    }
}

fn extract_tool_targets(
    spec: &HushSpec,
    probes: &mut BTreeSet<(String, String, Option<String>, Option<usize>)>,
) {
    let Some(rules) = &spec.rules else { return };

    if let Some(tool_access) = &rules.tool_access {
        for entry in &tool_access.allow {
            insert_probe(probes, "tool_call", entry, None, None);
        }
        for entry in &tool_access.block {
            insert_probe(probes, "tool_call", entry, None, None);
        }
        for entry in &tool_access.require_confirmation {
            insert_probe(probes, "tool_call", entry, None, None);
        }
    }
}

fn extract_shell_targets(
    spec: &HushSpec,
    probes: &mut BTreeSet<(String, String, Option<String>, Option<usize>)>,
) {
    let Some(rules) = &spec.rules else { return };

    if let Some(shell_commands) = &rules.shell_commands {
        for pattern in &shell_commands.forbidden_patterns {
            // Extract literal fragments from regex to build a matching command
            let literal = extract_regex_literal(pattern);
            if !literal.is_empty() {
                insert_probe(probes, "shell_command", &literal, None, None);
            }
        }
    }
}

fn extract_computer_use_targets(
    spec: &HushSpec,
    probes: &mut BTreeSet<(String, String, Option<String>, Option<usize>)>,
) {
    let Some(rules) = &spec.rules else { return };

    if let Some(computer_use) = &rules.computer_use {
        for action in &computer_use.allowed_actions {
            insert_probe(probes, "computer_use", action, None, None);
        }
    }

    if rules.remote_desktop_channels.is_some() {
        for action in [
            "remote.clipboard",
            "remote.file_transfer",
            "remote.audio",
            "remote.drive_mapping",
        ] {
            insert_probe(probes, "computer_use", action, None, None);
        }
    }
}

fn extract_input_injection_targets(
    spec: &HushSpec,
    probes: &mut BTreeSet<(String, String, Option<String>, Option<usize>)>,
) {
    let Some(rules) = &spec.rules else { return };

    if let Some(input_injection) = &rules.input_injection {
        for input_type in &input_injection.allowed_types {
            insert_probe(probes, "input_inject", input_type, None, None);
        }
        for input_type in ["keyboard", "mouse", "touch"] {
            insert_probe(probes, "input_inject", input_type, None, None);
        }
    }
}

/// Turn a glob pattern into a concrete path for probing
fn concretize_glob(pattern: &str) -> String {
    pattern.replace("**", "/home/user").replace('*', "example")
}

/// Turn a domain pattern into a concrete domain for probing
fn concretize_domain(pattern: &str) -> String {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        format!("api.{suffix}")
    } else {
        pattern.to_string()
    }
}

/// Extract literal characters from a regex pattern to build a probe string
fn extract_regex_literal(pattern: &str) -> String {
    let mut result = String::new();
    let mut chars = pattern.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                if let Some(next) = chars.next() {
                    match next {
                        's' => result.push(' '),
                        'd' => result.push('0'),
                        'w' => result.push('a'),
                        'n' => result.push('\n'),
                        't' => result.push('\t'),
                        _ => result.push(next),
                    }
                }
            }
            '[' => {
                // Skip character class, add first literal if present
                let mut found_literal = false;
                for inner in chars.by_ref() {
                    if inner == ']' {
                        break;
                    }
                    if !found_literal && inner != '^' && inner != '-' {
                        result.push(inner);
                        found_literal = true;
                    }
                }
            }
            '{' => {
                for inner in chars.by_ref() {
                    if inner == '}' {
                        break;
                    }
                }
            }
            '(' | ')' | '?' | '+' | '*' | '}' | '|' | '^' | '$' => {
                // Skip metacharacters
            }
            '.' => {
                result.push('a'); // . matches any char
            }
            _ => {
                result.push(ch);
            }
        }
    }

    result
}

fn build_patch(additions: usize, deletions: usize) -> String {
    let mut patch = vec!["@@".to_string()];
    for idx in 0..additions {
        patch.push(format!("+added_{idx}"));
    }
    for idx in 0..deletions {
        patch.push(format!("-removed_{idx}"));
    }
    patch.join("\n")
}

fn classify_change(old: &EvaluationResult, new: &EvaluationResult) -> String {
    if old.decision == new.decision {
        return "unchanged".to_string();
    }

    match (&old.decision, &new.decision) {
        // Relaxation: deny/warn -> allow
        (Decision::Deny, Decision::Allow) | (Decision::Warn, Decision::Allow) => {
            "relaxed".to_string()
        }
        // Tightening: allow -> warn/deny
        (Decision::Allow, Decision::Deny) | (Decision::Allow, Decision::Warn) => {
            "tightened".to_string()
        }
        // Escalation: warn -> deny
        (Decision::Warn, Decision::Deny) => "escalated".to_string(),
        // Demotion: deny -> warn
        (Decision::Deny, Decision::Warn) => "demoted".to_string(),
        // All equal cases already returned above.
        _ => unreachable!(),
    }
}

fn format_decision(d: &Decision) -> String {
    match d {
        Decision::Allow => "allow".to_string(),
        Decision::Warn => "warn".to_string(),
        Decision::Deny => "deny".to_string(),
    }
}

fn format_decision_cell(decision: &str) -> String {
    let padded = format!("{decision:<9}");
    match decision {
        "allow" => padded.green().to_string(),
        "deny" => padded.red().to_string(),
        "warn" => padded.yellow().to_string(),
        _ => padded,
    }
}

fn print_text_diff(args: &DiffArgs, changes: &[DecisionChange]) {
    println!(
        "Comparing {} -> {}\n",
        args.old.display(),
        args.new.display()
    );

    let changed: Vec<&DecisionChange> = changes
        .iter()
        .filter(|c| c.change_type != "unchanged")
        .collect();

    if changed.is_empty() {
        println!(
            "No decision changes detected ({} probes evaluated)",
            changes.len()
        );
        return;
    }

    println!("Decision changes ({} found):\n", changed.len());

    // Print header
    println!(
        "  {:<34} {:<9} {:<9} {}",
        "Action".bold(),
        "Old".bold(),
        "New".bold(),
        "Rule".bold()
    );
    println!(
        "  {:<34} {:<9} {:<9} {}",
        "\u{2500}".repeat(34),
        "\u{2500}".repeat(7),
        "\u{2500}".repeat(7),
        "\u{2500}".repeat(20)
    );

    for c in &changed {
        let action_desc = format!(
            "{} -> {}",
            c.action.action_type,
            truncate_str(&c.action.target, 22)
        );

        let old_colored = format_decision_cell(&c.old_decision);
        let new_colored = format_decision_cell(&c.new_decision);

        let rule = c.new_rule.as_deref().unwrap_or("(none)");

        println!(
            "  {:<34} {} {} {}",
            action_desc, old_colored, new_colored, rule
        );
    }

    // Summary
    let tightened = changed
        .iter()
        .filter(|c| c.change_type == "tightened")
        .count();
    let relaxed = changed
        .iter()
        .filter(|c| c.change_type == "relaxed")
        .count();
    let escalated = changed
        .iter()
        .filter(|c| c.change_type == "escalated")
        .count();
    let demoted = changed
        .iter()
        .filter(|c| c.change_type == "demoted")
        .count();

    println!();
    let mut parts = Vec::new();
    if tightened > 0 {
        parts.push(format!("{tightened} tightened"));
    }
    if relaxed > 0 {
        parts.push(format!("{relaxed} relaxed"));
    }
    if escalated > 0 {
        parts.push(format!("{escalated} escalated"));
    }
    if demoted > 0 {
        parts.push(format!("{demoted} demoted"));
    }
    println!("Summary: {}", parts.join(", "));
}

fn print_json_diff(changes: &[DecisionChange]) {
    if let Ok(json) = serde_json::to_string_pretty(changes) {
        println!("{json}");
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let cutoff = floor_char_boundary(s, max_len.saturating_sub(3));
        format!("{}...", &s[..cutoff])
    }
}

fn floor_char_boundary(s: &str, max_len: usize) -> usize {
    let mut boundary = max_len.min(s.len());
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}

#[cfg(test)]
mod tests {
    use super::{extract_regex_literal, format_decision_cell, truncate_str};

    fn strip_ansi(value: &str) -> String {
        let mut stripped = String::new();
        let mut chars = value.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\u{1b}' && chars.peek() == Some(&'[') {
                chars.next();
                for inner in chars.by_ref() {
                    if inner.is_ascii_alphabetic() {
                        break;
                    }
                }
                continue;
            }
            stripped.push(ch);
        }
        stripped
    }

    #[test]
    fn truncate_str_respects_utf8_boundaries() {
        let value = "deploy-🚀-target";
        let truncated = truncate_str(value, 11);

        assert_eq!(truncated, "deploy-...");
        assert!(truncated.is_char_boundary(truncated.len()));
    }

    #[test]
    fn format_decision_cell_preserves_column_width_without_counting_ansi() {
        let colored = format_decision_cell("allow");
        assert_eq!(strip_ansi(&colored), "allow    ");
    }

    #[test]
    fn extract_regex_literal_skips_quantifier_arguments() {
        let literal = extract_regex_literal(r"AKIA[0-9A-Z]{16}");
        assert_eq!(literal, "AKIA0");
    }
}
