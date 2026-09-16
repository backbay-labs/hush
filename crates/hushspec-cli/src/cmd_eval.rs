use colored::Colorize;
use hushspec::evaluate::REFERENCE_ACTION_TYPES;
use hushspec::log::{ChainedFileSink, PolicyEvent};
use hushspec::receipt::{DetectorEvaluation, RuleOutcome, RuleTraceEntry};
use hushspec::{
    Actor, AuditConfig, AuditContext, CompiledPolicy, Decision, DecisionReceipt, EnforcementMode,
    EnforcementSummary, EvaluationAction, HushSpec, Policy, PolicyError, PolicySummary, Resolution,
    ResolveError, ResolveOptions, policy_summary, unverified_policy_receipt,
};

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
    /// tool_call, egress, computer_use, input_inject, browser_action,
    /// code_exec, custom)
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

    /// browser_action: navigation destination URL
    #[arg(long, value_name = "URL", conflicts_with_all = ["action_json", "action_file"])]
    url: Option<String>,

    /// code_exec: the call requests network access
    #[arg(long, conflicts_with_all = ["action_json", "action_file"])]
    network: bool,

    /// code_exec: requested execution time in milliseconds
    #[arg(long, value_name = "MS", conflicts_with_all = ["action_json", "action_file"])]
    timeout_ms: Option<u64>,

    /// Runtime context for `when` conditions: an inline JSON object, or
    /// @PATH to read a YAML/JSON file
    #[arg(long, value_name = "JSON|@PATH")]
    context: Option<String>,

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

    /// Panic sentinel file to consult before evaluating; if it exists the
    /// process denies all actions (default: .hushspec_panic)
    #[arg(long, value_name = "PATH")]
    sentinel: Option<std::path::PathBuf>,

    /// Render the rule-by-rule trace (text output only)
    #[arg(long)]
    explain: bool,

    #[command(flatten)]
    verify: crate::verify_opts::VerifyOnLoadArgs,

    /// Record the decision in monitor mode (a warn or deny is recorded as
    /// would_block instead of blocked)
    #[arg(long)]
    monitor: bool,

    /// Actor recorded in the receipt: the agent
    #[arg(long, value_name = "ID")]
    agent_id: Option<String>,

    /// Actor recorded in the receipt: the session, run, or job
    #[arg(long, value_name = "ID")]
    session_id: Option<String>,

    /// Actor recorded in the receipt: the principal the agent acts for
    #[arg(long, value_name = "ID")]
    principal: Option<String>,

    /// Append the receipt to a hash-linked log (log spec), recording a
    /// policy_loaded event first
    #[arg(long, value_name = "PATH")]
    log: Option<std::path::PathBuf>,

    /// Sign log entries with this Ed25519 private key (PEM)
    #[arg(long, value_name = "PATH", requires = "log")]
    log_key: Option<std::path::PathBuf>,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: EvalOutputFormat,
}

pub fn run(args: EvalArgs) -> i32 {
    // A file-based `h2h panic activate` sentinel must flip the process-global
    // panic latch before evaluation, otherwise the kill switch is a no-op here.
    crate::cmd_panic::check_sentinel(args.sentinel.as_deref());

    let options = match args.verify.to_options() {
        Ok(options) => options,
        Err(code) => return code,
    };

    let mut action = match build_action(&args) {
        Ok(action) => action,
        Err(message) => {
            eprintln!("{} {message}", "error:".red());
            return 2;
        }
    };

    if let Some(source) = &args.context {
        match parse_context_argument(source) {
            Ok(context) => action.context = Some(context),
            Err(message) => {
                eprintln!("{} {message}", "error:".red());
                return 2;
            }
        }
    }

    if !REFERENCE_ACTION_TYPES.contains(&action.action_type.as_str()) {
        eprintln!(
            "{} '{}' is not a reference action type; it is denied fail-closed",
            "note:".yellow(),
            action.action_type
        );
    }

    let ctx = audit_context(&args);

    let policy = match load_policy(&args.policy, options) {
        Ok(policy) => policy,
        Err(LoadFailure::Unverified { summary, message }) => {
            // Signing spec 6.5: refuse to evaluate against an unverified
            // policy, but still emit the evidence that the refusal happened.
            eprintln!("{} {message}", "error:".red());
            let receipt = unverified_policy_receipt(*summary, &action, &ctx);
            if let Err(code) = record_log(&args, None, &receipt) {
                return code;
            }
            if let Err(code) = emit(&args, &receipt, None) {
                return code;
            }
            return 1;
        }
        Err(LoadFailure::Other(message)) => {
            eprintln!("{} {message}", "error:".red());
            return 2;
        }
    };

    let receipt = match policy
        .compiled
        .evaluate_audited(&action, &AuditConfig::default(), &ctx)
    {
        Ok(receipt) => receipt,
        Err(error) => {
            eprintln!("{} {error}", "error:".red());
            return 2;
        }
    };
    let resolution = policy.compiled.resolution().ok();
    if let Err(code) = record_log(&args, resolution, &receipt) {
        return code;
    }
    if let Err(code) = emit(&args, &receipt, Some(&policy)) {
        return code;
    }
    decision_exit_code(receipt.decision)
}

fn audit_context(args: &EvalArgs) -> AuditContext {
    AuditContext {
        actor: Some(Actor {
            agent_id: args.agent_id.clone(),
            session_id: args.session_id.clone(),
            principal: args.principal.clone(),
            runtime: Some(format!("h2h/{}", env!("CARGO_PKG_VERSION"))),
        }),
        enforcement_mode: if args.monitor {
            EnforcementMode::Monitor
        } else {
            EnforcementMode::Enforce
        },
        ..AuditContext::default()
    }
}

/// Append the receipt (and, when a resolution is in hand, a preceding
/// `policy_loaded` event) to the log named by `--log`.
fn record_log(
    args: &EvalArgs,
    resolution: Option<&Resolution>,
    receipt: &DecisionReceipt,
) -> Result<(), i32> {
    let Some(path) = &args.log else {
        return Ok(());
    };
    let failed = |message: String| {
        eprintln!("{} {message}", "error:".red());
        2
    };
    let mut sink = ChainedFileSink::open(path)
        .map_err(|e| failed(format!("failed to open log {}: {e}", path.display())))?;
    if let Some(key_path) = &args.log_key {
        let key = hushspec::signing::load_private_key(key_path)
            .map_err(|e| failed(format!("failed to load {}: {e}", key_path.display())))?;
        sink = sink.with_signer(key);
    }
    if let Some(resolution) = resolution {
        let mode = if args.monitor {
            EnforcementMode::Monitor
        } else {
            EnforcementMode::Enforce
        };
        sink.record_policy_event(&PolicyEvent::loaded(policy_summary(resolution), mode))
            .map_err(|e| failed(format!("failed to write policy event: {e}")))?;
    }
    hushspec::sink::ReceiptSink::send(&sink, receipt)
        .map_err(|e| failed(format!("failed to write receipt: {e}")))?;
    Ok(())
}

fn emit(
    args: &EvalArgs,
    receipt: &DecisionReceipt,
    policy: Option<&LoadedPolicy>,
) -> Result<(), i32> {
    match args.format {
        EvalOutputFormat::Text => {
            match (args.explain, policy) {
                (true, Some(policy)) => print_explain(receipt, policy),
                _ => print_compact(receipt),
            }
            Ok(())
        }
        EvalOutputFormat::Json => print_json_report(&EvalReport::from(receipt)),
        EvalOutputFormat::Receipt => print_json_report(receipt),
    }
}

/// `h2h explain` — identical to `h2h eval` with trace rendering forced on.
pub fn run_explain(mut args: EvalArgs) -> i32 {
    args.explain = true;
    run(args)
}

/// A resolved, validated, compiled policy plus display metadata.
struct LoadedPolicy {
    compiled: CompiledPolicy,
    extends: Option<String>,
    source: String,
}

enum LoadFailure {
    /// Verification on load failed (signing spec 6.5): the evaluation is
    /// refused and a deny receipt records why.
    Unverified {
        summary: Box<PolicySummary>,
        message: String,
    },
    Other(String),
}

/// Load a policy from a builtin reference or a filesystem path and run the
/// whole pipeline -- resolve with verify-on-load, validate, compile -- through
/// the [`Policy`] façade, so `h2h eval` takes exactly the path the SDK
/// documents.
fn load_policy(reference: &str, options: ResolveOptions) -> Result<LoadedPolicy, LoadFailure> {
    let (policy, source) = if let Some(yaml) = hushspec::load_builtin(reference) {
        let source = if reference.starts_with("builtin:") {
            reference.to_string()
        } else {
            format!("builtin:{reference}")
        };
        let policy = Policy::from_str(yaml)
            .map_err(|e| LoadFailure::Other(format!("failed to parse builtin '{reference}': {e}")))?
            .with_source(source.clone());
        (policy, source)
    } else {
        let path = std::path::Path::new(reference);
        if !path.exists() {
            return Err(LoadFailure::Other(format!("file not found: {reference}")));
        }
        let policy = Policy::from_path(path).map_err(|e| LoadFailure::Other(e.to_string()))?;
        (policy, reference.to_string())
    };

    let extends = policy.spec().extends.clone();
    // Kept for the unverified-policy receipt, which reports on the leaf.
    let leaf = policy.spec().clone();
    let compiled = policy
        .resolve(options)
        .compile()
        .map_err(|error| map_policy_error(error, &leaf, &source))?;
    Ok(LoadedPolicy {
        compiled,
        extends,
        source,
    })
}

fn map_policy_error(error: PolicyError, leaf: &HushSpec, source: &str) -> LoadFailure {
    match error {
        PolicyError::Resolve(ResolveError::SignatureRequired { document, status }) => {
            match hushspec::own_content_hash(leaf, source) {
                Ok(content_hash) => LoadFailure::Unverified {
                    summary: Box::new(PolicySummary {
                        name: leaf.name.clone(),
                        version: leaf
                            .metadata
                            .as_ref()
                            .and_then(|m| m.policy_version)
                            .map(|v| v as u64),
                        spec_version: leaf.hushspec.clone(),
                        content_hash,
                        extends_chain: None,
                        signature: Some(status.clone()),
                    }),
                    message: format!(
                        "policy did not verify ({document}): {}",
                        status.reason.as_deref().unwrap_or("unverified")
                    ),
                },
                Err(e) => LoadFailure::Other(format!("failed to resolve {source}: {e}")),
            }
        }
        PolicyError::Resolve(other) => {
            LoadFailure::Other(format!("failed to resolve {source}: {other}"))
        }
        other => LoadFailure::Other(other.to_string()),
    }
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

    // Every action type except patch_apply (which acts on `content`) is
    // meaningless without a target. In flag mode a missing --target is a
    // mistake, and evaluating against an empty target would silently score
    // against "" -- e.g. a `**` allowlist matches it and reports ALLOW. The
    // --action-json/--action-file escape hatches are intentionally not
    // constrained here: they mirror the raw EvaluationAction a host passes to
    // evaluate(), which tolerates an absent target.
    const TARGET_REQUIRED: &[&str] = &[
        "file_read",
        "file_write",
        "shell_command",
        "tool_call",
        "egress",
        "computer_use",
        "input_inject",
        "browser_action",
        "code_exec",
    ];
    if TARGET_REQUIRED.contains(&action_type.as_str()) && args.target.is_none() {
        return Err(format!("--type {action_type} requires --target"));
    }

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
        url: args.url.clone(),
        network: if args.network { Some(true) } else { None },
        timeout_ms: args.timeout_ms,
        context: None,
    })
}

/// Parse `--context`: an inline JSON object, or `@PATH` naming a YAML/JSON
/// file. Unknown keys are rejected (fail-closed) by the RuntimeContext type.
fn parse_context_argument(source: &str) -> Result<hushspec::RuntimeContext, String> {
    let text = match source.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read context file {path}: {e}"))?,
        None => source.to_string(),
    };
    let value: serde_json::Value =
        serde_yaml::from_str(&text).map_err(|e| format!("invalid context document: {e}"))?;
    serde_json::from_value(value).map_err(|e| format!("invalid context: {e}"))
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

/// Evaluation order per action type (core spec Sections 5 and 6.1): the
/// extension guards run first, then every applicable rule block is
/// evaluated -- none short-circuits on an allow -- and the outcomes are
/// aggregated with deny > warn > allow.
fn precedence_note(action_type: &str) -> Option<String> {
    let blocks = match action_type {
        "file_read" => "forbidden_paths > path_allowlist",
        "file_write" => "forbidden_paths > path_allowlist > secret_patterns",
        "patch_apply" => "forbidden_paths > path_allowlist > patch_integrity > secret_patterns",
        "shell_command" => "shell_commands",
        "egress" => "egress > secret_patterns (when content is present)",
        "tool_call" => "tool_access > secret_patterns (when content is present)",
        "computer_use" => "computer_use > remote_desktop_channels",
        "input_inject" => "input_injection",
        "browser_action" => "browser_automation",
        "code_exec" => "code_execution",
        "custom" => {
            "no rule blocks (permitted only by a posture state granting the custom capability)"
        }
        _ => return None,
    };
    Some(format!(
        "panic > origins default_behavior > posture capabilities > {blocks}; every applicable block is evaluated and deny > warn > allow"
    ))
}

fn enum_label<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .unwrap_or_default()
        .trim_matches('"')
        .to_string()
}

fn print_explain(receipt: &DecisionReceipt, policy: &LoadedPolicy) {
    let name = receipt.policy.name.as_deref().unwrap_or("(unnamed)");
    println!(
        "Policy: {} (hushspec {})",
        name.bold(),
        receipt.policy.spec_version
    );
    println!("  source:  {}", policy.source);
    println!("  hash:    {}", receipt.policy.content_hash);
    if let Some(version) = receipt.policy.version {
        println!("  version: {version}");
    }
    if let Some(extends) = &policy.extends {
        println!("  extends: {extends} (resolved)");
    }
    if let Some(chain) = &receipt.policy.extends_chain {
        println!("  chain:");
        for link in chain {
            println!("    {}  {}", link.content_hash, link.source);
        }
    }
    if let Some(signature) = &receipt.policy.signature {
        let status = if signature.verified {
            format!(
                "verified ({})",
                signature.key_id.as_deref().unwrap_or("unknown key")
            )
            .green()
            .to_string()
        } else {
            format!(
                "NOT verified: {}",
                signature.reason.as_deref().unwrap_or("unverified")
            )
            .red()
            .to_string()
        };
        println!("  signature: {status}");
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
        let matched = match &entry.rule_path {
            Some(rule) => rule.clone(),
            None if !entry.evaluated => "(not evaluated)".to_string(),
            None => String::new(),
        };
        let line = format!(
            "  {}. {:<20} {} {}",
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
    if let Some(trace) = &receipt.detection_trace {
        println!();
        println!("Detection trace:");
        if trace.is_empty() {
            println!("  (no detector ran)");
        }
        for detector in trace {
            println!(
                "  {:<22} {:<18} score {:.2}  level {:<10} {}",
                detector.detector_id,
                enum_label(&detector.category),
                detector.score,
                enum_label(&detector.level),
                if detector.matched { "matched" } else { "" }
            );
        }
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
    println!(
        "  enforce: {} / {}",
        enum_label(&receipt.enforcement.mode),
        enum_label(&receipt.enforcement.outcome)
    );
}

/// Deterministic machine report: the receipt minus its non-deterministic
/// fields (receipt_id, timestamp, actor runtime, duration_us).
/// Identical inputs produce byte-identical output.
#[derive(serde::Serialize)]
struct EvalReport<'a> {
    policy: &'a PolicySummary,
    action: &'a hushspec::ActionSummary,
    decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    matched_rule: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin_profile: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    posture: Option<&'a hushspec::PostureResult>,
    rule_trace: &'a [RuleTraceEntry],
    #[serde(skip_serializing_if = "Option::is_none")]
    detection_trace: Option<&'a Vec<DetectorEvaluation>>,
    enforcement: &'a EnforcementSummary,
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
            detection_trace: receipt.detection_trace.as_ref(),
            enforcement: &receipt.enforcement,
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
        // Every applicable block is evaluated (core spec 6.1); the note lists
        // the Section 5 evaluation order for each reference action type.
        assert!(
            precedence_note("egress")
                .unwrap()
                .contains("egress > secret_patterns")
        );
        assert!(
            precedence_note("file_read")
                .unwrap()
                .contains("forbidden_paths > path_allowlist")
        );
        assert!(
            precedence_note("file_write")
                .unwrap()
                .contains("forbidden_paths > path_allowlist > secret_patterns")
        );
        assert!(
            precedence_note("patch_apply")
                .unwrap()
                .contains("path_allowlist > patch_integrity > secret_patterns")
        );
        assert!(
            precedence_note("code_exec")
                .unwrap()
                .contains("code_execution")
        );
        assert!(precedence_note("frobnicate").is_none());
    }

    /// The command-line surface carries two tables the evaluator also carries:
    /// the reference action types a note is written for, and the rule blocks
    /// those notes and `h2h lint` name. Both are checked against the published
    /// core schema, which is what the evaluator's own tables are generated
    /// from, so a block added to the specification cannot be missed here.
    #[test]
    fn the_command_tables_match_the_core_schema() {
        let schema: serde_json::Value = serde_json::from_str(
            crate::generated_schemas::schema_body("core").expect("core schema"),
        )
        .expect("the embedded core schema parses");
        let mut rule_blocks: Vec<&str> = schema["$defs"]["Rules"]["properties"]
            .as_object()
            .expect("`Rules` declares its blocks")
            .keys()
            .map(String::as_str)
            .collect();
        rule_blocks.sort_unstable();

        // `h2h lint` reports one `enabled` state per rule block.
        let listed = crate::cmd_lint::rule_block_enabled(&hushspec::Rules::default());
        let mut linted: Vec<&str> = listed
            .iter()
            .map(|(name, _)| name.strip_prefix("rules.").expect("a `rules.` path"))
            .collect();
        linted.sort_unstable();
        assert_eq!(linted, rule_blocks);

        // Every reference action type has a precedence note, and between them
        // the notes name every rule block.
        let mut named: Vec<&str> = Vec::new();
        for action_type in hushspec::evaluate::REFERENCE_ACTION_TYPES {
            let note = precedence_note(action_type)
                .unwrap_or_else(|| panic!("{action_type} has no precedence note"));
            for block in &rule_blocks {
                if note.contains(block) && !named.contains(block) {
                    named.push(block);
                }
            }
        }
        named.sort_unstable();
        assert_eq!(named, rule_blocks);
    }
}
