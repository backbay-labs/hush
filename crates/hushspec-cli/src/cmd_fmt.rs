use clap::ValueEnum;
use colored::Colorize;
use hushspec::HushSpec;
use hushspec::schema::MergeStrategy;
use serde::Serialize;
use similar::TextDiff;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct FmtArgs {
    /// Policy YAML files to format
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// Check formatting without modifying files (exit 1 if changes needed)
    #[arg(long)]
    check: bool,

    /// Show what would change without modifying files
    #[arg(long)]
    diff: bool,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: FmtOutputFormat,
}

#[derive(Clone, Copy, ValueEnum)]
enum FmtOutputFormat {
    Text,
    Json,
}

#[derive(serde::Serialize)]
struct FmtResult {
    file: String,
    changed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<String>,
}

/// Canonical field order for rule blocks
const RULE_ORDER: &[&str] = &[
    "forbidden_paths",
    "path_allowlist",
    "egress",
    "secret_patterns",
    "patch_integrity",
    "shell_commands",
    "tool_access",
    "computer_use",
    "remote_desktop_channels",
    "input_injection",
    "browser_automation",
    "code_execution",
];

/// Lists whose entries should be sorted alphabetically
const SORTABLE_LISTS: &[&str] = &[
    "allow",
    "block",
    "require_confirmation",
    "patterns",
    "exceptions",
    "read",
    "write",
    "patch",
    "skip_paths",
    "forbidden_patterns",
    "allowed_actions",
    "allowed_types",
    "allowed_domains",
    "blocked_domains",
    "allowed_verbs",
    "extra_credential_patterns",
    "language_allowlist",
    "module_denylist",
];

pub fn run(args: FmtArgs) -> i32 {
    let mut any_would_change = false;
    let mut any_error = false;
    let mut results: Vec<FmtResult> = Vec::new();

    for path in &args.files {
        if !path.exists() {
            match args.format {
                FmtOutputFormat::Text => {
                    eprintln!("{} file not found: {}", "error".red(), path.display());
                }
                FmtOutputFormat::Json => {}
            }
            any_error = true;
            results.push(FmtResult {
                file: path.display().to_string(),
                changed: false,
                diff: None,
            });
            continue;
        }

        let original = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                match args.format {
                    FmtOutputFormat::Text => {
                        eprintln!("{} failed to read {}: {e}", "error".red(), path.display());
                    }
                    FmtOutputFormat::Json => {}
                }
                any_error = true;
                results.push(FmtResult {
                    file: path.display().to_string(),
                    changed: false,
                    diff: None,
                });
                continue;
            }
        };

        // Parse and canonically format in one step (also validates it's valid YAML).
        let formatted = match format_canonical(&original) {
            Ok(f) => f,
            Err(e) => {
                match args.format {
                    FmtOutputFormat::Text => {
                        eprintln!("{} failed to parse {}: {e}", "error".red(), path.display());
                    }
                    FmtOutputFormat::Json => {}
                }
                any_error = true;
                results.push(FmtResult {
                    file: path.display().to_string(),
                    changed: false,
                    diff: None,
                });
                continue;
            }
        };

        // Normalize: ensure both end with single newline for comparison
        let original_normalized = normalize_trailing_newline(&original);
        let formatted_normalized = normalize_trailing_newline(&formatted);

        let changed = original_normalized != formatted_normalized;

        if changed {
            any_would_change = true;
        }

        let diff_text = if args.diff && changed {
            Some(compute_diff(
                &original_normalized,
                &formatted_normalized,
                path,
            ))
        } else {
            None
        };

        match args.format {
            FmtOutputFormat::Text => {
                if args.check {
                    if changed {
                        println!("{} {} would be reformatted", "FAIL".red(), path.display());
                    } else {
                        println!("{} {} already formatted", "ok".green(), path.display());
                    }
                } else if args.diff {
                    if changed {
                        if let Some(ref diff) = diff_text {
                            println!("{diff}");
                        }
                    } else {
                        println!("{} {} already formatted", "ok".green(), path.display());
                    }
                } else {
                    // Actually write the formatted output
                    if changed {
                        if let Err(e) = std::fs::write(path, &formatted_normalized) {
                            eprintln!("{} failed to write {}: {e}", "error".red(), path.display());
                            any_error = true;
                        } else {
                            println!("{} {} formatted", "DONE".green(), path.display());
                        }
                    } else {
                        println!("{} {} already formatted", "ok".green(), path.display());
                    }
                }
            }
            FmtOutputFormat::Json => {
                // Persist the formatted output just like the Text arm, minus the
                // human-readable status lines. --check and --diff stay
                // non-writing; the JSON summary is emitted once after the loop.
                if !args.check
                    && !args.diff
                    && changed
                    && let Err(e) = std::fs::write(path, &formatted_normalized)
                {
                    eprintln!("{} failed to write {}: {e}", "error".red(), path.display());
                    any_error = true;
                }
            }
        }

        results.push(FmtResult {
            file: path.display().to_string(),
            changed,
            diff: diff_text,
        });
    }

    if matches!(args.format, FmtOutputFormat::Json)
        && let Ok(json) = serde_json::to_string_pretty(&results)
    {
        println!("{json}");
    }

    if any_error {
        2
    } else if args.check && any_would_change {
        1
    } else {
        0
    }
}

pub(crate) fn normalize_trailing_newline(s: &str) -> String {
    let trimmed = s.trim_end_matches('\n').trim_end_matches('\r');
    format!("{trimmed}\n")
}

/// Split a leading yaml-language-server modeline (first line only) from the body.
///
/// Only this exact leading-comment form is preserved; the serde round-trip
/// through `format_spec` cannot carry arbitrary comments, and the modeline is
/// the one editors rely on for schema-driven completion.
pub(crate) fn split_modeline(input: &str) -> (Option<&str>, &str) {
    if let Some(first) = input.lines().next()
        && first.trim_start().starts_with("# yaml-language-server:")
    {
        let body = &input[first.len()..];
        return (Some(first), body.strip_prefix('\n').unwrap_or(body));
    }
    (None, input)
}

/// Rejoin a modeline previously extracted by [`split_modeline`] with freshly
/// canonicalized body text. Shared by `format_canonical` (the `h2h fmt` path)
/// and `cmd_lint`'s `--fix`/`--dry-run` path, which canonicalizes an
/// already-parsed-and-mutated `HushSpec` directly rather than routing through
/// `format_canonical`.
pub(crate) fn rejoin_modeline(modeline: Option<&str>, canonical: &str) -> String {
    match modeline {
        Some(m) => format!("{m}\n{canonical}"),
        None => canonical.to_string(),
    }
}

/// Parse `input` and render it as canonical HushSpec YAML, preserving a
/// leading yaml-language-server modeline if present.
///
/// Parses the ORIGINAL `input`, not the modeline-stripped body: the modeline
/// is a parse-inert YAML comment, so `HushSpec::parse` ignores it either way,
/// but parsing the stripped body would shift any parse-error line number
/// down by one line relative to `h2h lint` (which parses the original file
/// content directly). `split_modeline` is used here only to pull the
/// modeline text back out for `rejoin_modeline`.
pub(crate) fn format_canonical(input: &str) -> Result<String, String> {
    let (modeline, _) = split_modeline(input);
    let spec = HushSpec::parse(input).map_err(|e| e.to_string())?;
    Ok(rejoin_modeline(modeline, &format_spec(&spec)))
}

/// Format a HushSpec document into canonical YAML
pub(crate) fn format_spec(spec: &HushSpec) -> String {
    let mut out = String::new();

    // hushspec (always first, always quoted)
    out.push_str(&format!(
        "hushspec: {}\n",
        yaml_double_quoted_scalar(&spec.hushspec)
    ));

    // name
    if let Some(name) = &spec.name {
        out.push_str(&format!("name: {}\n", yaml_scalar(name)));
    }

    // description
    if let Some(desc) = &spec.description {
        out.push_str(&format!("description: {}\n", yaml_scalar(desc)));
    }

    // extends
    if let Some(extends) = &spec.extends {
        out.push_str(&format!("extends: {}\n", yaml_scalar(extends)));
    }

    // merge_strategy
    if let Some(ms) = &spec.merge_strategy {
        let ms_str = format_merge_strategy(ms);
        out.push_str(&format!("merge_strategy: {ms_str}\n"));
    }

    // rules
    if let Some(rules) = &spec.rules {
        let mut rules_out = String::new();
        format_rules(rules, &mut rules_out);
        if !rules_out.is_empty() {
            out.push_str("rules:\n");
            out.push_str(&rules_out);
        }
    }

    // extensions
    if let Some(extensions) = &spec.extensions
        && let Some(block) = indented_yaml_block(extensions, 2)
    {
        out.push_str("extensions:\n");
        out.push_str(&block);
    }

    // metadata
    if let Some(metadata) = &spec.metadata
        && let Some(block) = indented_yaml_block(metadata, 2)
    {
        out.push_str("metadata:\n");
        out.push_str(&block);
    }

    out
}

fn format_rules(rules: &hushspec::Rules, out: &mut String) {
    // Output rule blocks in canonical order
    for &rule_name in RULE_ORDER {
        match rule_name {
            "forbidden_paths" => {
                if let Some(r) = &rules.forbidden_paths {
                    out.push_str("  forbidden_paths:\n");
                    format_forbidden_paths(r, out);
                }
            }
            "path_allowlist" => {
                if let Some(r) = &rules.path_allowlist {
                    out.push_str("  path_allowlist:\n");
                    format_path_allowlist(r, out);
                }
            }
            "egress" => {
                if let Some(r) = &rules.egress {
                    out.push_str("  egress:\n");
                    format_egress(r, out);
                }
            }
            "secret_patterns" => {
                if let Some(r) = &rules.secret_patterns {
                    out.push_str("  secret_patterns:\n");
                    format_secret_patterns(r, out);
                }
            }
            "patch_integrity" => {
                if let Some(r) = &rules.patch_integrity {
                    out.push_str("  patch_integrity:\n");
                    format_patch_integrity(r, out);
                }
            }
            "shell_commands" => {
                if let Some(r) = &rules.shell_commands {
                    out.push_str("  shell_commands:\n");
                    format_shell_commands(r, out);
                }
            }
            "tool_access" => {
                if let Some(r) = &rules.tool_access {
                    out.push_str("  tool_access:\n");
                    format_tool_access(r, out);
                }
            }
            "computer_use" => {
                if let Some(r) = &rules.computer_use {
                    out.push_str("  computer_use:\n");
                    format_computer_use(r, out);
                }
            }
            "remote_desktop_channels" => {
                if let Some(r) = &rules.remote_desktop_channels {
                    out.push_str("  remote_desktop_channels:\n");
                    format_remote_desktop(r, out);
                }
            }
            "input_injection" => {
                if let Some(r) = &rules.input_injection {
                    out.push_str("  input_injection:\n");
                    format_input_injection(r, out);
                }
            }
            "browser_automation" => {
                if let Some(r) = &rules.browser_automation {
                    out.push_str("  browser_automation:\n");
                    format_browser_automation(r, out);
                }
            }
            "code_execution" => {
                if let Some(r) = &rules.code_execution {
                    out.push_str("  code_execution:\n");
                    format_code_execution(r, out);
                }
            }
            _ => {}
        }
    }
}

fn format_forbidden_paths(r: &hushspec::ForbiddenPathsRule, out: &mut String) {
    if !r.enabled {
        out.push_str("    enabled: false\n");
    }
    format_sorted_string_list("patterns", &r.patterns, 4, out);
    format_sorted_string_list("exceptions", &r.exceptions, 4, out);
}

fn format_path_allowlist(r: &hushspec::PathAllowlistRule, out: &mut String) {
    if !r.enabled {
        out.push_str("    enabled: false\n");
    } else {
        out.push_str("    enabled: true\n");
    }
    format_sorted_string_list("read", &r.read, 4, out);
    format_sorted_string_list("write", &r.write, 4, out);
    format_sorted_string_list("patch", &r.patch, 4, out);
}

fn format_egress(r: &hushspec::EgressRule, out: &mut String) {
    if !r.enabled {
        out.push_str("    enabled: false\n");
    }
    format_sorted_string_list("allow", &r.allow, 4, out);
    format_sorted_string_list("block", &r.block, 4, out);
    let default_str = match r.default {
        hushspec::DefaultAction::Allow => "allow",
        hushspec::DefaultAction::Block => "block",
    };
    out.push_str(&format!("    default: {default_str}\n"));
}

fn format_secret_patterns(r: &hushspec::SecretPatternsRule, out: &mut String) {
    if !r.enabled {
        out.push_str("    enabled: false\n");
    }
    if !r.patterns.is_empty() {
        out.push_str("    patterns:\n");
        for p in &r.patterns {
            out.push_str(&format!("      - name: {}\n", yaml_scalar(&p.name)));
            out.push_str(&format!("        pattern: {}\n", yaml_scalar(&p.pattern)));
            let sev = format_severity(&p.severity);
            out.push_str(&format!("        severity: {sev}\n"));
            if let Some(desc) = &p.description {
                out.push_str(&format!("        description: {}\n", yaml_scalar(desc)));
            }
        }
    }
    format_sorted_string_list("skip_paths", &r.skip_paths, 4, out);
}

fn format_patch_integrity(r: &hushspec::PatchIntegrityRule, out: &mut String) {
    if !r.enabled {
        out.push_str("    enabled: false\n");
    }
    out.push_str(&format!("    max_additions: {}\n", r.max_additions));
    out.push_str(&format!("    max_deletions: {}\n", r.max_deletions));
    out.push_str(&format!("    require_balance: {}\n", r.require_balance));
    out.push_str(&format!(
        "    max_imbalance_ratio: {}\n",
        format_f64(r.max_imbalance_ratio)
    ));
    format_sorted_string_list("forbidden_patterns", &r.forbidden_patterns, 4, out);
}

fn format_shell_commands(r: &hushspec::ShellCommandsRule, out: &mut String) {
    if !r.enabled {
        out.push_str("    enabled: false\n");
    }
    format_sorted_string_list("forbidden_patterns", &r.forbidden_patterns, 4, out);
}

fn format_tool_access(r: &hushspec::ToolAccessRule, out: &mut String) {
    if !r.enabled {
        out.push_str("    enabled: false\n");
    }
    format_sorted_string_list("allow", &r.allow, 4, out);
    format_sorted_string_list("block", &r.block, 4, out);
    format_sorted_string_list("require_confirmation", &r.require_confirmation, 4, out);
    let default_str = match r.default {
        hushspec::DefaultAction::Allow => "allow",
        hushspec::DefaultAction::Block => "block",
    };
    out.push_str(&format!("    default: {default_str}\n"));
    if let Some(max_args) = r.max_args_size {
        out.push_str(&format!("    max_args_size: {max_args}\n"));
    }
}

fn format_computer_use(r: &hushspec::ComputerUseRule, out: &mut String) {
    if !r.enabled {
        out.push_str("    enabled: false\n");
    } else {
        out.push_str("    enabled: true\n");
    }
    let mode = format_computer_use_mode(&r.mode);
    out.push_str(&format!("    mode: {mode}\n"));
    format_sorted_string_list("allowed_actions", &r.allowed_actions, 4, out);
}

fn format_remote_desktop(r: &hushspec::RemoteDesktopChannelsRule, out: &mut String) {
    if !r.enabled {
        out.push_str("    enabled: false\n");
    } else {
        out.push_str("    enabled: true\n");
    }
    out.push_str(&format!("    clipboard: {}\n", r.clipboard));
    out.push_str(&format!("    file_transfer: {}\n", r.file_transfer));
    out.push_str(&format!("    audio: {}\n", r.audio));
    out.push_str(&format!("    drive_mapping: {}\n", r.drive_mapping));
}

fn format_input_injection(r: &hushspec::InputInjectionRule, out: &mut String) {
    if !r.enabled {
        out.push_str("    enabled: false\n");
    } else {
        out.push_str("    enabled: true\n");
    }
    format_sorted_string_list("allowed_types", &r.allowed_types, 4, out);
    out.push_str(&format!(
        "    require_postcondition_probe: {}\n",
        r.require_postcondition_probe
    ));
}

fn format_browser_automation(r: &hushspec::BrowserAutomationRule, out: &mut String) {
    if !r.enabled {
        out.push_str("    enabled: false\n");
    } else {
        out.push_str("    enabled: true\n");
    }
    format_sorted_string_list("allowed_domains", &r.allowed_domains, 4, out);
    format_sorted_string_list("blocked_domains", &r.blocked_domains, 4, out);
    format_sorted_string_list("allowed_verbs", &r.allowed_verbs, 4, out);
    out.push_str(&format!(
        "    credential_detection: {}\n",
        r.credential_detection
    ));
    format_sorted_string_list(
        "extra_credential_patterns",
        &r.extra_credential_patterns,
        4,
        out,
    );
}

fn format_code_execution(r: &hushspec::CodeExecutionRule, out: &mut String) {
    if !r.enabled {
        out.push_str("    enabled: false\n");
    } else {
        out.push_str("    enabled: true\n");
    }
    format_sorted_string_list("language_allowlist", &r.language_allowlist, 4, out);
    format_sorted_string_list("module_denylist", &r.module_denylist, 4, out);
    out.push_str(&format!("    network_access: {}\n", r.network_access));
    if let Some(max_time) = r.max_execution_time_ms {
        out.push_str(&format!("    max_execution_time_ms: {max_time}\n"));
    }
    if let Some(max_bytes) = r.max_scan_bytes {
        out.push_str(&format!("    max_scan_bytes: {max_bytes}\n"));
    }
}

/// Format a list of strings, sorted and deduplicated
fn format_sorted_string_list(field: &str, list: &[String], indent: usize, out: &mut String) {
    let prefix = " ".repeat(indent);

    if list.is_empty() {
        out.push_str(&format!("{prefix}{field}: []\n"));
        return;
    }

    // Deduplicate and sort if this is a sortable list
    let mut items: Vec<&str> = list.iter().map(|s| s.as_str()).collect();
    if SORTABLE_LISTS.contains(&field) {
        items.sort();
        items.dedup();
    }

    out.push_str(&format!("{prefix}{field}:\n"));
    for item in items {
        out.push_str(&format!("{prefix}  - {}\n", yaml_scalar(item)));
    }
}

/// Quote a YAML scalar if it contains special characters
fn yaml_scalar(s: &str) -> String {
    // These need quoting
    let needs_quoting = s.is_empty()
        || s.contains(':')
        || s.contains('#')
        || s.contains('\'')
        || s.contains('"')
        || s.contains('\n')
        || s.contains('\\')
        || s.contains('{')
        || s.contains('}')
        || s.contains('[')
        || s.contains(']')
        || s.contains('&')
        || s.contains('*')
        || s.contains('!')
        || s.contains('|')
        || s.contains('>')
        || s.contains('%')
        || s.contains('@')
        || s.contains('`')
        || s.contains(',')
        || s.starts_with(' ')
        || s.ends_with(' ')
        || s.starts_with('-')
        || s.starts_with('?')
        || looks_like_special_yaml(s);

    if needs_quoting {
        yaml_double_quoted_scalar(s)
    } else {
        s.to_string()
    }
}

fn yaml_double_quoted_scalar(s: &str) -> String {
    let escaped = s
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    format!("\"{escaped}\"")
}

fn looks_like_special_yaml(s: &str) -> bool {
    if looks_like_yaml_11_keyword(s)
        || looks_like_yaml_11_radix_number(s)
        || looks_like_yaml_11_float_literal(s)
    {
        return true;
    }

    let candidate = format!("value: {s}\n");
    let Ok(parsed) = serde_yaml::from_str::<serde_yaml::Value>(&candidate) else {
        return true;
    };

    let key = serde_yaml::Value::String("value".to_string());
    match parsed {
        serde_yaml::Value::Mapping(map) => {
            !matches!(map.get(&key), Some(serde_yaml::Value::String(value)) if value == s)
        }
        _ => true,
    }
}

fn looks_like_yaml_11_keyword(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "true" | "false" | "yes" | "no" | "on" | "off" | "null" | "~" | "y" | "n"
    )
}

fn looks_like_yaml_11_radix_number(s: &str) -> bool {
    let unsigned = s.strip_prefix(['+', '-']).unwrap_or(s);
    let is_digits = |value: &str, radix: u32| {
        !value.is_empty() && value.chars().all(|ch| ch == '_' || ch.is_digit(radix))
    };

    if let Some(value) = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
    {
        return is_digits(value, 16);
    }

    if let Some(value) = unsigned
        .strip_prefix("0o")
        .or_else(|| unsigned.strip_prefix("0O"))
    {
        return is_digits(value, 8);
    }

    if let Some(value) = unsigned
        .strip_prefix("0b")
        .or_else(|| unsigned.strip_prefix("0B"))
    {
        return is_digits(value, 2);
    }

    false
}

fn looks_like_yaml_11_float_literal(s: &str) -> bool {
    matches!(
        s.strip_prefix(['+', '-'])
            .unwrap_or(s)
            .to_ascii_lowercase()
            .as_str(),
        ".inf" | ".nan"
    )
}

fn format_f64(v: f64) -> String {
    if v == v.floor() {
        format!("{v:.1}")
    } else {
        format!("{v}")
    }
}

fn format_merge_strategy(strategy: &MergeStrategy) -> &'static str {
    match strategy {
        MergeStrategy::Replace => "replace",
        MergeStrategy::Merge => "merge",
        MergeStrategy::DeepMerge => "deep_merge",
    }
}

fn indented_yaml_block<T: Serialize>(value: &T, indent: usize) -> Option<String> {
    let yaml = serde_yaml::to_string(value).ok()?;
    let indent_str = " ".repeat(indent);
    let mut block = String::new();

    for line in yaml.lines() {
        let trimmed = line.trim();
        if trimmed == "---" || trimmed.is_empty() || trimmed == "{}" || trimmed == "null" {
            continue;
        }
        block.push_str(&indent_str);
        block.push_str(line);
        block.push('\n');
    }

    if block.is_empty() { None } else { Some(block) }
}

fn format_severity(severity: &hushspec::Severity) -> &'static str {
    match severity {
        hushspec::Severity::Critical => "critical",
        hushspec::Severity::Error => "error",
        hushspec::Severity::Warn => "warn",
    }
}

fn format_computer_use_mode(mode: &hushspec::ComputerUseMode) -> &'static str {
    match mode {
        hushspec::ComputerUseMode::Observe => "observe",
        hushspec::ComputerUseMode::Guardrail => "guardrail",
        hushspec::ComputerUseMode::FailClosed => "fail_closed",
    }
}

pub(crate) fn compute_diff(original: &str, formatted: &str, path: &std::path::Path) -> String {
    TextDiff::from_lines(original, formatted)
        .unified_diff()
        .header(
            &format!("{} (original)", path.display()),
            &format!("{} (formatted)", path.display()),
        )
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{format_canonical, format_spec, yaml_scalar};
    use hushspec::HushSpec;
    use hushspec::schema::MergeStrategy;

    const MODELINE: &str =
        "# yaml-language-server: $schema=https://hushspec.dev/schemas/hushspec-core.v0.schema.json";

    #[test]
    fn fmt_preserves_leading_modeline() {
        let input = format!("{MODELINE}\nhushspec: \"0.1.0\"\nname: t\n");
        let out = format_canonical(&input).unwrap();
        assert!(
            out.starts_with(&format!("{MODELINE}\n")),
            "modeline stripped:\n{out}"
        );
        // Idempotent with the modeline present:
        assert_eq!(format_canonical(&out).unwrap(), out);
    }

    #[test]
    fn fmt_without_modeline_is_unchanged_behavior() {
        let input = "hushspec: \"0.1.0\"\nname: t\n";
        let out = format_canonical(input).unwrap();
        assert!(!out.contains("yaml-language-server"));
        assert_eq!(format_canonical(&out).unwrap(), out);
    }

    #[test]
    fn format_spec_preserves_newlines_and_tabs_in_scalars() {
        let spec = HushSpec {
            hushspec: "0.1.0".to_string(),
            name: Some("line1\nline2\tend".to_string()),
            description: Some("tab\tvalue".to_string()),
            extends: None,
            merge_strategy: None,
            rules: None,
            extensions: None,
            metadata: None,
        };

        let formatted = format_spec(&spec);
        let reparsed = HushSpec::parse(&formatted).expect("formatted YAML should parse");

        assert_eq!(reparsed.name.as_deref(), Some("line1\nline2\tend"));
        assert_eq!(reparsed.description.as_deref(), Some("tab\tvalue"));
    }

    #[test]
    fn format_spec_serializes_enums_without_document_markers() {
        let spec = HushSpec {
            hushspec: "0.1.0".to_string(),
            name: Some("enum-check".to_string()),
            description: None,
            extends: None,
            merge_strategy: Some(MergeStrategy::DeepMerge),
            rules: Some(hushspec::Rules {
                secret_patterns: Some(hushspec::SecretPatternsRule {
                    enabled: true,
                    patterns: vec![hushspec::SecretPattern {
                        name: "token".to_string(),
                        pattern: "token".to_string(),
                        severity: hushspec::Severity::Critical,
                        description: None,
                    }],
                    skip_paths: vec![],
                }),
                computer_use: Some(hushspec::ComputerUseRule {
                    enabled: true,
                    mode: hushspec::ComputerUseMode::Guardrail,
                    allowed_actions: vec![],
                }),
                ..Default::default()
            }),
            extensions: None,
            metadata: None,
        };

        let formatted = format_spec(&spec);
        assert!(!formatted.contains("---\n"));
        assert!(formatted.contains("merge_strategy: deep_merge\n"));
        assert!(formatted.contains("severity: critical\n"));
        assert!(formatted.contains("mode: guardrail\n"));

        let reparsed = HushSpec::parse(&formatted).expect("formatted YAML should parse");
        assert_eq!(reparsed.merge_strategy, Some(MergeStrategy::DeepMerge));
        assert_eq!(
            reparsed
                .rules
                .as_ref()
                .and_then(|rules| rules.secret_patterns.as_ref())
                .and_then(|rule| rule.patterns.first())
                .map(|pattern| pattern.severity),
            Some(hushspec::Severity::Critical)
        );
        assert_eq!(
            reparsed
                .rules
                .as_ref()
                .and_then(|rules| rules.computer_use.as_ref())
                .map(|rule| rule.mode),
            Some(hushspec::ComputerUseMode::Guardrail)
        );
    }

    #[test]
    fn format_preserves_browser_automation_and_code_execution() {
        let input = r#"hushspec: "0.1.0"
name: guards
rules:
  browser_automation:
    enabled: true
    allowed_domains:
      - "*.example.com"
    allowed_verbs:
      - navigate
    credential_detection: true
  code_execution:
    enabled: true
    language_allowlist:
      - python
    module_denylist:
      - subprocess
      - socket
    network_access: false
    max_execution_time_ms: 5000
"#;
        let formatted = format_canonical(input).unwrap();
        assert!(
            formatted.contains("  browser_automation:\n"),
            "browser_automation block dropped:\n{formatted}"
        );
        assert!(
            formatted.contains("  code_execution:\n"),
            "code_execution block dropped:\n{formatted}"
        );

        let reparsed = HushSpec::parse(&formatted).expect("formatted YAML should parse");
        let rules = reparsed.rules.as_ref().expect("rules preserved");
        let ba = rules
            .browser_automation
            .as_ref()
            .expect("browser_automation preserved");
        assert!(ba.enabled);
        assert_eq!(ba.allowed_domains, vec!["*.example.com".to_string()]);
        assert_eq!(ba.allowed_verbs, vec!["navigate".to_string()]);
        let ce = rules
            .code_execution
            .as_ref()
            .expect("code_execution preserved");
        assert_eq!(ce.language_allowlist, vec!["python".to_string()]);
        assert_eq!(ce.max_execution_time_ms, Some(5000));

        // Formatting must be idempotent.
        assert_eq!(format_canonical(&formatted).unwrap(), formatted);
    }

    #[test]
    fn format_spec_escapes_hushspec_version_scalar() {
        let spec = HushSpec {
            hushspec: "0.1.0\"\nnext".to_string(),
            name: None,
            description: None,
            extends: None,
            merge_strategy: None,
            rules: None,
            extensions: None,
            metadata: None,
        };

        let formatted = format_spec(&spec);
        assert!(formatted.starts_with("hushspec: \"0.1.0\\\"\\nnext\"\n"));

        let parsed: serde_yaml::Value =
            serde_yaml::from_str(&formatted).expect("formatted YAML should stay parseable");
        assert_eq!(
            parsed.get("hushspec").and_then(|value| value.as_str()),
            Some("0.1.0\"\nnext")
        );
    }

    #[test]
    fn format_spec_omits_empty_sections_to_stay_idempotent() {
        let spec = HushSpec::parse(
            r#"hushspec: "0.1.0"
rules: {}
extensions: {}
metadata: {}
"#,
        )
        .expect("spec should parse");

        let formatted = format_spec(&spec);
        assert!(!formatted.contains("\nrules:\n"));
        assert!(!formatted.contains("\nextensions:\n"));
        assert!(!formatted.contains("\nmetadata:\n"));

        let reparsed = HushSpec::parse(&formatted).expect("formatted YAML should parse");
        let reformatted = format_spec(&reparsed);
        assert_eq!(formatted, reformatted);
    }

    #[test]
    fn yaml_scalar_quotes_yaml_11_special_values() {
        for value in ["Y", "n", "0xFF", "0o777", "0b1010", ".inf", ".nan"] {
            let rendered = yaml_scalar(value);
            assert!(
                rendered.starts_with('"') && rendered.ends_with('"'),
                "{value} should be quoted, got {rendered}"
            );

            let parsed: serde_yaml::Value =
                serde_yaml::from_str(&format!("field: {rendered}\n")).expect("YAML should parse");
            assert_eq!(
                parsed.get("field").and_then(|node| node.as_str()),
                Some(value),
                "round-trip changed {value}"
            );
        }
    }
}
