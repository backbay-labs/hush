use clap::ValueEnum;
use colored::Colorize;
use hushspec::HushSpec;
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
];

/// Lists whose entries should be sorted alphabetically
const SORTABLE_LISTS: &[&str] = &[
    "allow",
    "block",
    "require_confirmation",
    "patterns",
    "exceptions",
    "skip_paths",
    "forbidden_patterns",
    "allowed_actions",
    "allowed_types",
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

        // Parse to validate it's valid YAML
        let spec = match HushSpec::parse(&original) {
            Ok(s) => s,
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

        let formatted = format_spec(&spec);

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
            FmtOutputFormat::Json => {}
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

fn normalize_trailing_newline(s: &str) -> String {
    let trimmed = s.trim_end_matches('\n').trim_end_matches('\r');
    format!("{trimmed}\n")
}

/// Format a HushSpec document into canonical YAML
fn format_spec(spec: &HushSpec) -> String {
    let mut out = String::new();

    // hushspec (always first, always quoted)
    out.push_str(&format!("hushspec: \"{}\"\n", spec.hushspec));

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
        let ms_str = serde_yaml::to_string(ms)
            .unwrap_or_default()
            .trim()
            .to_string();
        out.push_str(&format!("merge_strategy: {ms_str}\n"));
    }

    // rules
    if let Some(rules) = &spec.rules {
        out.push_str("rules:\n");
        format_rules(rules, &mut out);
    }

    // extensions
    if let Some(extensions) = &spec.extensions {
        out.push_str("extensions:\n");
        // Serialize extensions using serde_yaml and indent
        if let Ok(yaml) = serde_yaml::to_string(extensions) {
            for line in yaml.lines() {
                if line == "---" {
                    continue;
                }
                out.push_str(&format!("  {line}\n"));
            }
        }
    }

    // metadata
    if let Some(metadata) = &spec.metadata {
        out.push_str("metadata:\n");
        if let Ok(yaml) = serde_yaml::to_string(metadata) {
            for line in yaml.lines() {
                if line == "---" {
                    continue;
                }
                out.push_str(&format!("  {line}\n"));
            }
        }
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
            let sev = serde_yaml::to_string(&p.severity)
                .unwrap_or_default()
                .trim()
                .to_string();
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
    let mode = serde_yaml::to_string(&r.mode)
        .unwrap_or_default()
        .trim()
        .to_string();
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
        // Use double quotes, escaping internal double quotes and backslashes
        let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        s.to_string()
    }
}

fn looks_like_special_yaml(s: &str) -> bool {
    matches!(
        s.to_lowercase().as_str(),
        "true" | "false" | "yes" | "no" | "on" | "off" | "null" | "~"
    ) || s.parse::<f64>().is_ok()
}

fn format_f64(v: f64) -> String {
    if v == v.floor() {
        format!("{v:.1}")
    } else {
        format!("{v}")
    }
}

fn compute_diff(original: &str, formatted: &str, path: &std::path::Path) -> String {
    let mut diff_output = String::new();
    diff_output.push_str(&format!("--- {} (original)\n", path.display()));
    diff_output.push_str(&format!("+++ {} (formatted)\n", path.display()));

    let old_lines: Vec<&str> = original.lines().collect();
    let new_lines: Vec<&str> = formatted.lines().collect();

    // Simple line-by-line diff
    let max_len = old_lines.len().max(new_lines.len());
    for i in 0..max_len {
        let old_line = old_lines.get(i).copied();
        let new_line = new_lines.get(i).copied();

        match (old_line, new_line) {
            (Some(o), Some(n)) if o == n => {
                diff_output.push_str(&format!(" {o}\n"));
            }
            (Some(o), Some(n)) => {
                diff_output.push_str(&format!("-{o}\n"));
                diff_output.push_str(&format!("+{n}\n"));
            }
            (Some(o), None) => {
                diff_output.push_str(&format!("-{o}\n"));
            }
            (None, Some(n)) => {
                diff_output.push_str(&format!("+{n}\n"));
            }
            (None, None) => {}
        }
    }

    diff_output
}
