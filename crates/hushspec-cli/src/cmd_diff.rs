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

    // Extract targets from egress
    extract_egress_targets(old, &mut probes);
    extract_egress_targets(new, &mut probes);

    // Extract targets from tool_access
    extract_tool_targets(old, &mut probes);
    extract_tool_targets(new, &mut probes);

    // Extract shell_command probes from forbidden_patterns
    extract_shell_targets(old, &mut probes);
    extract_shell_targets(new, &mut probes);

    // Add standard probes that test common scenarios
    probes.insert(("file_read".to_string(), "/etc/passwd".to_string()));
    probes.insert(("file_read".to_string(), "/etc/shadow".to_string()));
    probes.insert(("egress".to_string(), "example.com".to_string()));
    probes.insert(("tool_call".to_string(), "unknown_tool".to_string()));
    probes.insert(("shell_command".to_string(), "rm -rf /".to_string()));
    probes.insert(("shell_command".to_string(), "ls".to_string()));

    probes
        .into_iter()
        .map(|(action_type, target)| ProbeAction {
            action_type,
            target,
        })
        .collect()
}

fn extract_path_targets(spec: &HushSpec, probes: &mut BTreeSet<(String, String)>) {
    let Some(rules) = &spec.rules else { return };

    if let Some(forbidden_paths) = &rules.forbidden_paths {
        for pattern in &forbidden_paths.patterns {
            let concrete = concretize_glob(pattern);
            probes.insert(("file_read".to_string(), concrete));
        }
        for pattern in &forbidden_paths.exceptions {
            let concrete = concretize_glob(pattern);
            probes.insert(("file_read".to_string(), concrete));
        }
    }
}

fn extract_egress_targets(spec: &HushSpec, probes: &mut BTreeSet<(String, String)>) {
    let Some(rules) = &spec.rules else { return };

    if let Some(egress) = &rules.egress {
        for entry in &egress.allow {
            let concrete = concretize_domain(entry);
            probes.insert(("egress".to_string(), concrete));
        }
        for entry in &egress.block {
            let concrete = concretize_domain(entry);
            probes.insert(("egress".to_string(), concrete));
        }
    }
}

fn extract_tool_targets(spec: &HushSpec, probes: &mut BTreeSet<(String, String)>) {
    let Some(rules) = &spec.rules else { return };

    if let Some(tool_access) = &rules.tool_access {
        for entry in &tool_access.allow {
            probes.insert(("tool_call".to_string(), entry.clone()));
        }
        for entry in &tool_access.block {
            probes.insert(("tool_call".to_string(), entry.clone()));
        }
        for entry in &tool_access.require_confirmation {
            probes.insert(("tool_call".to_string(), entry.clone()));
        }
    }
}

fn extract_shell_targets(spec: &HushSpec, probes: &mut BTreeSet<(String, String)>) {
    let Some(rules) = &spec.rules else { return };

    if let Some(shell_commands) = &rules.shell_commands {
        for pattern in &shell_commands.forbidden_patterns {
            // Extract literal fragments from regex to build a matching command
            let literal = extract_regex_literal(pattern);
            if !literal.is_empty() {
                probes.insert(("shell_command".to_string(), literal));
            }
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
            '(' | ')' | '?' | '+' | '*' | '{' | '}' | '|' | '^' | '$' => {
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

        let old_colored = match c.old_decision.as_str() {
            "allow" => c.old_decision.green().to_string(),
            "deny" => c.old_decision.red().to_string(),
            "warn" => c.old_decision.yellow().to_string(),
            _ => c.old_decision.clone(),
        };

        let new_colored = match c.new_decision.as_str() {
            "allow" => c.new_decision.green().to_string(),
            "deny" => c.new_decision.red().to_string(),
            "warn" => c.new_decision.yellow().to_string(),
            _ => c.new_decision.clone(),
        };

        let rule = c.new_rule.as_deref().unwrap_or("(none)");

        println!(
            "  {:<34} {:<9} {:<9} {}",
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
    use super::truncate_str;

    #[test]
    fn truncate_str_respects_utf8_boundaries() {
        let value = "deploy-🚀-target";
        let truncated = truncate_str(value, 11);

        assert_eq!(truncated, "deploy-...");
        assert!(truncated.is_char_boundary(truncated.len()));
    }
}
