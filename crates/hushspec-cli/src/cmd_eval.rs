use colored::Colorize;
use hushspec::receipt::RuleOutcome;
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

#[derive(Clone, Copy, clap::ValueEnum)]
enum EvalOutputFormat {
    Text,
    Json,
    Receipt,
}

#[derive(clap::Args)]
pub struct EvalArgs {
    /// Policy YAML file, or a builtin reference (e.g. "builtin:default")
    policy: String,

    /// Action type (file_read, file_write, patch_apply, shell_command,
    /// tool_call, egress, computer_use, input_inject)
    #[arg(
        long = "type",
        value_name = "TYPE",
        required_unless_present_any = ["action_json", "action_file"],
        conflicts_with_all = ["action_json", "action_file"]
    )]
    action_type: Option<String>,

    /// Action target (path, domain, tool name, command, channel)
    #[arg(long, value_name = "TARGET", conflicts_with_all = ["action_json", "action_file"])]
    target: Option<String>,

    /// Action content (file body, patch text)
    #[arg(
        long,
        value_name = "STRING",
        conflicts_with_all = ["content_file", "action_json", "action_file"]
    )]
    content: Option<String>,

    /// Read action content from a file
    #[arg(long, value_name = "PATH", conflicts_with_all = ["action_json", "action_file"])]
    content_file: Option<std::path::PathBuf>,

    /// Serialized tool-argument size in bytes
    #[arg(long, value_name = "N", conflicts_with_all = ["action_json", "action_file"])]
    args_size: Option<usize>,

    /// Origin context field as KEY=VALUE (repeatable). Keys: provider, tenant_id,
    /// space_id, space_type, visibility, external_participants, tags, sensitivity, actor_role
    #[arg(long = "origin", value_name = "KEY=VALUE", conflicts_with_all = ["action_json", "action_file"])]
    origin: Vec<String>,

    /// Current posture state (defaults to the policy's posture "initial" state)
    #[arg(long, value_name = "STATE", conflicts_with_all = ["action_json", "action_file"])]
    posture: Option<String>,

    /// Posture transition signal
    #[arg(long, value_name = "SIGNAL", conflicts_with_all = ["action_json", "action_file"])]
    signal: Option<String>,

    /// Full action as an inline JSON object
    #[arg(long, value_name = "JSON", conflicts_with = "action_file")]
    action_json: Option<String>,

    /// Full action as a YAML or JSON file; "-" reads stdin
    #[arg(long, value_name = "PATH")]
    action_file: Option<String>,

    /// Render the rule-by-rule trace (text output only)
    #[arg(long)]
    explain: bool,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: EvalOutputFormat,
}

pub fn run(args: EvalArgs) -> i32 {
    let policy = match load_policy(&args.policy) {
        Ok(policy) => policy,
        Err(message) => {
            eprintln!("{} {message}", "error:".red());
            return 2;
        }
    };

    let action = match build_action(&args) {
        Ok(action) => action,
        Err(message) => {
            eprintln!("{} {message}", "error:".red());
            return 2;
        }
    };

    if !KNOWN_ACTION_TYPES.contains(&action.action_type.as_str()) {
        eprintln!(
            "{} '{}' is not a reference action type; no rules apply to it",
            "note:".yellow(),
            action.action_type
        );
    }

    let receipt = evaluate_audited(&policy.spec, &action, &AuditConfig::default());

    match args.format {
        EvalOutputFormat::Text => {
            if args.explain {
                print_explain(&receipt, &policy);
            } else {
                print_compact(&receipt);
            }
        }
        EvalOutputFormat::Json => {
            if let Err(code) = print_json_report(&EvalReport::from(&receipt)) {
                return code;
            }
        }
        EvalOutputFormat::Receipt => {
            if let Err(code) = print_json_report(&receipt) {
                return code;
            }
        }
    }
    decision_exit_code(receipt.decision)
}

/// `h2h explain` — identical to `h2h eval` with trace rendering forced on.
pub fn run_explain(mut args: EvalArgs) -> i32 {
    args.explain = true;
    run(args)
}

/// A resolved, validated policy plus display metadata.
struct LoadedPolicy {
    spec: HushSpec,
    extends: Option<String>,
    source: String,
}

/// Load a policy from a builtin reference or a filesystem path, resolve
/// its extends chain, and validate the resolved document.
fn load_policy(reference: &str) -> Result<LoadedPolicy, String> {
    if let Some(yaml) = hushspec::load_builtin(reference) {
        let unresolved = HushSpec::parse(yaml)
            .map_err(|e| format!("failed to parse builtin '{reference}': {e}"))?;
        let extends = unresolved.extends.clone();
        let source = if reference.starts_with("builtin:") {
            reference.to_string()
        } else {
            format!("builtin:{reference}")
        };
        let loader = hushspec::create_composite_loader();
        let spec = hushspec::resolve_with_loader(&unresolved, Some(&source), &loader)
            .map_err(|e| format!("failed to resolve '{reference}': {e}"))?;
        return validated(LoadedPolicy {
            spec,
            extends,
            source,
        });
    }

    let path = std::path::Path::new(reference);
    if !path.exists() {
        return Err(format!("file not found: {reference}"));
    }
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read {reference}: {e}"))?;
    let unresolved =
        HushSpec::parse(&content).map_err(|e| format!("failed to parse {reference}: {e}"))?;
    let extends = unresolved.extends.clone();
    let spec = hushspec::resolve_from_path_with_builtins(path)
        .map_err(|e| format!("failed to resolve {reference}: {e}"))?;
    validated(LoadedPolicy {
        spec,
        extends,
        source: reference.to_string(),
    })
}

fn validated(policy: LoadedPolicy) -> Result<LoadedPolicy, String> {
    let validation = validate(&policy.spec);
    if !validation.is_valid() {
        let errors: Vec<String> = validation.errors.iter().map(|e| e.to_string()).collect();
        return Err(format!("policy failed validation: {}", errors.join(", ")));
    }
    Ok(policy)
}

fn build_action(args: &EvalArgs) -> Result<EvaluationAction, String> {
    if let Some(json) = &args.action_json {
        return parse_action_document(json);
    }
    if let Some(source) = &args.action_file {
        let text = if source == "-" {
            use std::io::Read;
            let mut buffer = String::new();
            std::io::stdin()
                .read_to_string(&mut buffer)
                .map_err(|e| format!("failed to read action from stdin: {e}"))?;
            buffer
        } else {
            std::fs::read_to_string(source)
                .map_err(|e| format!("failed to read action file {source}: {e}"))?
        };
        return parse_action_document(&text);
    }

    let action_type = args
        .action_type
        .clone()
        .ok_or_else(|| "missing --type".to_string())?;

    let content = match (&args.content, &args.content_file) {
        (Some(content), _) => Some(content.clone()),
        (None, Some(path)) => Some(
            std::fs::read_to_string(path)
                .map_err(|e| format!("failed to read content file {}: {e}", path.display()))?,
        ),
        (None, None) => None,
    };

    let origin = if args.origin.is_empty() {
        None
    } else {
        Some(parse_origin_pairs(&args.origin)?)
    };

    let posture = if args.posture.is_none() && args.signal.is_none() {
        None
    } else {
        Some(hushspec::PostureContext {
            current: args.posture.clone(),
            signal: args.signal.clone(),
        })
    };

    Ok(EvaluationAction {
        action_type,
        target: args.target.clone(),
        content,
        origin,
        posture,
        args_size: args.args_size,
    })
}

/// Parse a full action document (YAML or JSON) via the same two-step
/// path cmd_test.rs uses for fixture actions; deny_unknown_fields on
/// EvaluationAction rejects unknown keys (fail-closed).
fn parse_action_document(text: &str) -> Result<EvaluationAction, String> {
    let value: serde_json::Value =
        serde_yaml::from_str(text).map_err(|e| format!("invalid action document: {e}"))?;
    serde_json::from_value(value).map_err(|e| format!("invalid action: {e}"))
}

/// Build a typed OriginContext from repeated KEY=VALUE flags. Coerces
/// external_participants to bool and tags to a comma-separated list; the
/// deny_unknown_fields deserialization rejects unknown keys (fail-closed).
fn parse_origin_pairs(pairs: &[String]) -> Result<hushspec::OriginContext, String> {
    let mut map = serde_json::Map::new();
    for pair in pairs {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| format!("invalid --origin '{pair}': expected KEY=VALUE"))?;
        let json_value = match key {
            "external_participants" => serde_json::Value::Bool(
                value
                    .parse::<bool>()
                    .map_err(|_| format!("invalid --origin '{pair}': expected true or false"))?,
            ),
            "tags" => serde_json::Value::Array(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|tag| !tag.is_empty())
                    .map(|tag| serde_json::Value::String(tag.to_string()))
                    .collect(),
            ),
            _ => serde_json::Value::String(value.to_string()),
        };
        if map.insert(key.to_string(), json_value).is_some() {
            return Err(format!("duplicate --origin key '{key}'"));
        }
    }
    serde_json::from_value(serde_json::Value::Object(map))
        .map_err(|e| format!("invalid origin context: {e}"))
}

/// Serialize `value` as pretty JSON and print it to stdout. `to_string_pretty`
/// cannot fail for any type this CLI currently serializes (no NaN/infinite
/// floats, no non-string map keys), so the error arm is unreachable today.
/// It exists so that if a future field ever does fail to serialize, the CLI
/// fails closed — an error on stderr and the input-usage exit code — rather
/// than silently printing nothing while the caller still exits with a
/// decision code.
fn print_json_report<T: serde::Serialize>(value: &T) -> Result<(), i32> {
    match serde_json::to_string_pretty(value) {
        Ok(json) => {
            println!("{json}");
            Ok(())
        }
        Err(e) => {
            eprintln!("{} failed to serialize output: {e}", "error:".red());
            Err(2)
        }
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

fn outcome_text(outcome: RuleOutcome) -> &'static str {
    match outcome {
        RuleOutcome::Allow => "ALLOW",
        RuleOutcome::Warn => "WARN",
        RuleOutcome::Deny => "DENY",
        RuleOutcome::Skip => "SKIP",
    }
}

/// Pad before coloring so ANSI escapes do not break column alignment.
fn outcome_label(outcome: RuleOutcome) -> String {
    let padded = format!("{:<6}", outcome_text(outcome));
    match outcome {
        RuleOutcome::Allow => padded.green().to_string(),
        RuleOutcome::Warn => padded.yellow().to_string(),
        RuleOutcome::Deny => padded.red().to_string(),
        RuleOutcome::Skip => padded.dimmed().to_string(),
    }
}

/// Rule consultation order per action type, verified against the dispatch
/// in crates/hushspec/src/evaluate.rs. computer_use and input_inject omit
/// "posture capabilities" because required_capability() returns None for them.
/// file_read, file_write, and patch_apply all route through the shared
/// evaluate_path_guards() helper, so all three must list every path-guard
/// stage it can resolve on -- including the forbidden_paths exceptions
/// allow, which runs before file_write/patch_apply fall through to their
/// own rule block.
fn precedence_note(action_type: &str) -> Option<&'static str> {
    match action_type {
        "tool_call" => Some(
            "panic > posture capabilities > max_args_size > block > require_confirmation > allow > default",
        ),
        "egress" => Some("panic > posture capabilities > block > allow > default"),
        "file_read" => Some(
            "panic > posture capabilities > forbidden_paths > path_allowlist > forbidden_paths exceptions",
        ),
        "file_write" => Some(
            "panic > posture capabilities > forbidden_paths > path_allowlist > forbidden_paths exceptions > secret_patterns",
        ),
        "patch_apply" => Some(
            "panic > posture capabilities > forbidden_paths > path_allowlist > forbidden_paths exceptions > patch_integrity",
        ),
        "shell_command" => {
            Some("panic > posture capabilities > forbidden_patterns (first match denies)")
        }
        "computer_use" => Some(
            "panic > computer_use combined with remote_desktop_channels (more restrictive outcome wins)",
        ),
        "input_inject" => Some("panic > allowed_types allowlist (empty list denies all)"),
        _ => None,
    }
}

fn print_explain(receipt: &DecisionReceipt, policy: &LoadedPolicy) {
    let name = receipt.policy.name.as_deref().unwrap_or("(unnamed)");
    println!("Policy: {} ({})", name.bold(), receipt.policy.version);
    println!("  source:  {}", policy.source);
    println!("  sha256:  {}", receipt.policy.content_hash);
    if let Some(extends) = &policy.extends {
        println!("  extends: {extends} (resolved)");
    }
    println!();

    let action = match &receipt.action.target {
        Some(target) => format!("{} -> {}", receipt.action.action_type, target),
        None => receipt.action.action_type.clone(),
    };
    println!("Action: {action}");
    println!();

    println!("Rule trace:");
    for (index, entry) in receipt.rule_trace.iter().enumerate() {
        let matched = match &entry.matched_rule {
            Some(rule) => rule.clone(),
            None if !entry.evaluated => "(not evaluated)".to_string(),
            None => String::new(),
        };
        let line = format!(
            "  {}. {:<18} {} {}",
            index + 1,
            entry.rule_block,
            outcome_label(entry.outcome),
            matched
        );
        println!("{}", line.trim_end());
        if let Some(reason) = &entry.reason {
            println!("       {}", reason.dimmed());
        }
    }
    if let Some(note) = precedence_note(&receipt.action.action_type) {
        println!("Precedence: {note}");
    }
    println!();

    println!("Decision: {}", decision_label(receipt.decision));
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

/// Deterministic machine report: the receipt minus its non-deterministic
/// fields (receipt_id, timestamp, hushspec_version, evaluation_duration_us).
/// Identical inputs produce byte-identical output.
#[derive(serde::Serialize)]
struct EvalReport<'a> {
    policy: &'a hushspec::receipt::PolicySummary,
    action: &'a hushspec::receipt::ActionSummary,
    decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    matched_rule: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin_profile: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    posture: Option<&'a hushspec::PostureResult>,
    rule_trace: &'a [hushspec::receipt::RuleEvaluation],
}

impl<'a> From<&'a DecisionReceipt> for EvalReport<'a> {
    fn from(receipt: &'a DecisionReceipt) -> Self {
        Self {
            policy: &receipt.policy,
            action: &receipt.action,
            decision: receipt.decision,
            matched_rule: receipt.matched_rule.as_ref(),
            reason: receipt.reason.as_ref(),
            origin_profile: receipt.origin_profile.as_ref(),
            posture: receipt.posture.as_ref(),
            rule_trace: &receipt.rule_trace,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decision_exit_code, parse_action_document, parse_origin_pairs, precedence_note,
        print_json_report,
    };
    use hushspec::Decision;

    #[test]
    fn exit_codes_map_decisions() {
        assert_eq!(decision_exit_code(Decision::Allow), 0);
        assert_eq!(decision_exit_code(Decision::Deny), 1);
        assert_eq!(decision_exit_code(Decision::Warn), 4);
    }

    #[test]
    fn print_json_report_fails_closed_on_serialize_error() {
        // No real HushSpec type can fail serde_json serialization today, so
        // this stands in for the theoretical future field that can: the
        // point under test is that print_json_report never lets a
        // serialization error pass silently — it must report exit code 2
        // (the input-usage code), matching every other error path in this
        // module, instead of returning Ok with nothing printed.
        struct AlwaysFailsToSerialize;

        impl serde::Serialize for AlwaysFailsToSerialize {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::Error;
                Err(S::Error::custom("boom"))
            }
        }

        assert_eq!(print_json_report(&AlwaysFailsToSerialize), Err(2));
    }

    #[test]
    fn parse_origin_pairs_builds_typed_context() {
        let pairs = vec![
            "provider=slack".to_string(),
            "visibility=public".to_string(),
            "external_participants=true".to_string(),
            "tags=prod, external".to_string(),
        ];
        let origin = parse_origin_pairs(&pairs).unwrap();
        assert_eq!(origin.provider.as_deref(), Some("slack"));
        assert_eq!(origin.visibility.as_deref(), Some("public"));
        assert_eq!(origin.external_participants, Some(true));
        assert_eq!(
            origin.tags,
            vec!["prod".to_string(), "external".to_string()]
        );
    }

    #[test]
    fn parse_origin_pairs_rejects_missing_equals() {
        let error = parse_origin_pairs(&["visibility".to_string()]).unwrap_err();
        assert!(error.contains("expected KEY=VALUE"));
    }

    #[test]
    fn parse_origin_pairs_rejects_unknown_key() {
        let error = parse_origin_pairs(&["nope=1".to_string()]).unwrap_err();
        assert!(error.contains("invalid origin context"));
    }

    #[test]
    fn parse_origin_pairs_rejects_duplicate_key() {
        let error =
            parse_origin_pairs(&["provider=slack".to_string(), "provider=teams".to_string()])
                .unwrap_err();
        assert!(error.contains("duplicate --origin key"));
    }

    #[test]
    fn parse_origin_pairs_rejects_bad_bool() {
        let error = parse_origin_pairs(&["external_participants=maybe".to_string()]).unwrap_err();
        assert!(error.contains("expected true or false"));
    }

    #[test]
    fn parse_action_document_accepts_yaml() {
        let action = parse_action_document("type: egress\ntarget: api.github.com\n").unwrap();
        assert_eq!(action.action_type, "egress");
        assert_eq!(action.target.as_deref(), Some("api.github.com"));
    }

    #[test]
    fn parse_action_document_accepts_json() {
        let action =
            parse_action_document(r#"{"type": "tool_call", "target": "deploy", "args_size": 12}"#)
                .unwrap();
        assert_eq!(action.action_type, "tool_call");
        assert_eq!(action.args_size, Some(12));
    }

    #[test]
    fn parse_action_document_rejects_unknown_fields() {
        let error = parse_action_document(r#"{"type": "egress", "bogus": 1}"#).unwrap_err();
        assert!(error.contains("invalid action"));
    }

    #[test]
    fn precedence_note_covers_reference_action_types() {
        assert!(
            precedence_note("egress")
                .unwrap()
                .contains("block > allow > default")
        );
        // file_read, file_write, and patch_apply all route through
        // evaluate_path_guards(), which can resolve the decision via a
        // forbidden_paths.exceptions allow before either the file_write or
        // patch_apply evaluator gets a chance to consult its own rule
        // block. All three notes must mention that stage, in the order the
        // evaluator actually consults it (after path_allowlist, before the
        // action-specific block).
        assert!(
            precedence_note("file_read")
                .unwrap()
                .contains("path_allowlist > forbidden_paths exceptions")
        );
        assert!(
            precedence_note("file_write")
                .unwrap()
                .contains("path_allowlist > forbidden_paths exceptions > secret_patterns")
        );
        assert!(
            precedence_note("patch_apply")
                .unwrap()
                .contains("path_allowlist > forbidden_paths exceptions > patch_integrity")
        );
        assert!(precedence_note("frobnicate").is_none());
    }
}
