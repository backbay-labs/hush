use colored::Colorize;
use hushspec::{
    AuditConfig, Decision, DecisionReceipt, EvaluationAction, HushSpec, evaluate_audited, validate,
};

const KNOWN_ACTION_TYPES: &[&str] = &[
    "file_read",
    "file_write",
    "patch_apply",
    "shell_command",
    "tool_call",
    "egress",
    "computer_use",
    "input_inject",
];

#[derive(clap::Args)]
pub struct EvalArgs {
    /// Policy YAML file, or a builtin reference (e.g. "builtin:default")
    policy: String,

    /// Action type (file_read, file_write, patch_apply, shell_command,
    /// tool_call, egress, computer_use, input_inject)
    #[arg(long = "type", value_name = "TYPE")]
    action_type: String,

    /// Action target (path, domain, tool name, command, channel)
    #[arg(long, value_name = "TARGET")]
    target: Option<String>,
}

pub fn run(args: EvalArgs) -> i32 {
    let spec = match load_policy(&args.policy) {
        Ok(spec) => spec,
        Err(message) => {
            eprintln!("{} {message}", "error:".red());
            return 2;
        }
    };

    let action = build_action(&args);

    if !KNOWN_ACTION_TYPES.contains(&action.action_type.as_str()) {
        eprintln!(
            "{} '{}' is not a reference action type; no rules apply to it",
            "note:".yellow(),
            action.action_type
        );
    }

    let receipt = evaluate_audited(&spec, &action, &AuditConfig::default());
    print_compact(&receipt);
    decision_exit_code(receipt.decision)
}

/// Load a policy from a builtin reference or a filesystem path, resolve
/// its extends chain, and validate the resolved document.
fn load_policy(reference: &str) -> Result<HushSpec, String> {
    let resolved = if let Some(yaml) = hushspec::load_builtin(reference) {
        let unresolved = HushSpec::parse(yaml)
            .map_err(|e| format!("failed to parse builtin '{reference}': {e}"))?;
        let source = if reference.starts_with("builtin:") {
            reference.to_string()
        } else {
            format!("builtin:{reference}")
        };
        let loader = hushspec::create_composite_loader();
        hushspec::resolve_with_loader(&unresolved, Some(&source), &loader)
            .map_err(|e| format!("failed to resolve '{reference}': {e}"))?
    } else {
        let path = std::path::Path::new(reference);
        if !path.exists() {
            return Err(format!("file not found: {reference}"));
        }
        hushspec::resolve_from_path_with_builtins(path)
            .map_err(|e| format!("failed to resolve {reference}: {e}"))?
    };

    let validation = validate(&resolved);
    if !validation.is_valid() {
        let errors: Vec<String> = validation.errors.iter().map(|e| e.to_string()).collect();
        return Err(format!("policy failed validation: {}", errors.join(", ")));
    }

    Ok(resolved)
}

fn build_action(args: &EvalArgs) -> EvaluationAction {
    EvaluationAction {
        action_type: args.action_type.clone(),
        target: args.target.clone(),
        ..Default::default()
    }
}

fn decision_exit_code(decision: Decision) -> i32 {
    match decision {
        Decision::Allow => 0,
        Decision::Deny => 1,
        Decision::Warn => 4,
    }
}

fn decision_label(decision: Decision) -> colored::ColoredString {
    match decision {
        Decision::Allow => "ALLOW".green().bold(),
        Decision::Warn => "WARN".yellow().bold(),
        Decision::Deny => "DENY".red().bold(),
    }
}

fn print_compact(receipt: &DecisionReceipt) {
    let action = match &receipt.action.target {
        Some(target) => format!("{} -> {}", receipt.action.action_type, target),
        None => receipt.action.action_type.clone(),
    };
    println!("{}  {}", decision_label(receipt.decision), action);
    if let Some(rule) = &receipt.matched_rule {
        println!("  rule:    {rule}");
    }
    if let Some(reason) = &receipt.reason {
        println!("  reason:  {reason}");
    }
    if let Some(profile) = &receipt.origin_profile {
        println!("  origin:  {profile}");
    }
    if let Some(posture) = &receipt.posture {
        println!("  posture: {} -> {}", posture.current, posture.next);
    }
}

#[cfg(test)]
mod tests {
    use super::decision_exit_code;
    use hushspec::Decision;

    #[test]
    fn exit_codes_map_decisions() {
        assert_eq!(decision_exit_code(Decision::Allow), 0);
        assert_eq!(decision_exit_code(Decision::Deny), 1);
        assert_eq!(decision_exit_code(Decision::Warn), 4);
    }
}
