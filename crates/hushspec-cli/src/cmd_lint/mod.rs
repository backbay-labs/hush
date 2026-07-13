mod fix;

use clap::ValueEnum;
use colored::Colorize;
use hushspec::{DefaultAction, HushSpec};
use regex::Regex;
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct LintArgs {
    /// Policy YAML files to lint
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: LintOutputFormat,

    /// Exit 1 if any warnings are reported (not just errors)
    #[arg(long)]
    fail_on_warnings: bool,

    /// Apply decision-neutral auto-fixes in place
    #[arg(long, conflicts_with = "dry_run")]
    fix: bool,

    /// Show what --fix would change without modifying files
    #[arg(long)]
    dry_run: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum LintOutputFormat {
    Text,
    Json,
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct LintFinding {
    code: String,
    severity: String,
    message: String,
    /// Machine-parseable pointer for the subset of findings that support
    /// entry-precise auto-fixing: `rules.<block>.<field>[<idx>]`. Findings
    /// that can't point at a single list entry fall back to the file path.
    location: String,
}

/// JSON view of a finding: identical to `LintFinding` plus the derived
/// `fixable` flag (additive field; text output is unaffected).
#[derive(serde::Serialize)]
struct FindingJson {
    code: String,
    severity: String,
    message: String,
    location: String,
    fixable: bool,
}

impl FindingJson {
    fn new(spec: &HushSpec, finding: &LintFinding) -> Self {
        FindingJson {
            code: finding.code.clone(),
            severity: finding.severity.clone(),
            message: finding.message.clone(),
            location: finding.location.clone(),
            fixable: fix::finding_is_fixable(spec, finding),
        }
    }
}

#[derive(serde::Serialize)]
struct FileLintResult {
    file: String,
    findings: Vec<FindingJson>,
    /// Codes actually remediated by `--fix`/`--dry-run` for this file (additive
    /// field; empty when neither flag was passed or nothing was fixable).
    fixed: Vec<String>,
}

pub fn run(args: LintArgs) -> i32 {
    let mut all_results: Vec<FileLintResult> = Vec::new();
    let mut any_errors = false;
    let mut any_warnings = false;
    let mut any_parse_error = false;
    let mut any_write_error = false;
    let want_fix = args.fix || args.dry_run;

    for path in &args.files {
        if !path.exists() {
            if matches!(args.format, LintOutputFormat::Text) {
                eprintln!("{} file not found: {}", "error".red(), path.display());
            }
            all_results.push(FileLintResult {
                file: path.display().to_string(),
                findings: vec![FindingJson {
                    code: "E000".into(),
                    severity: "error".into(),
                    message: format!("file not found: {}", path.display()),
                    location: path.display().to_string(),
                    fixable: false,
                }],
                fixed: Vec::new(),
            });
            any_parse_error = true;
            continue;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                if matches!(args.format, LintOutputFormat::Text) {
                    eprintln!("{} failed to read {}: {e}", "error".red(), path.display());
                }
                all_results.push(FileLintResult {
                    file: path.display().to_string(),
                    findings: vec![FindingJson {
                        code: "E000".into(),
                        severity: "error".into(),
                        message: format!("failed to read file: {e}"),
                        location: path.display().to_string(),
                        fixable: false,
                    }],
                    fixed: Vec::new(),
                });
                any_parse_error = true;
                continue;
            }
        };

        // Never rewrite a file that failed to parse: on a parse error we
        // record the finding and move on without touching `--fix`/`--dry-run`.
        let mut spec = match HushSpec::parse(&content) {
            Ok(s) => s,
            Err(e) => {
                if matches!(args.format, LintOutputFormat::Text) {
                    eprintln!("{} failed to parse {}: {e}", "error".red(), path.display());
                }
                all_results.push(FileLintResult {
                    file: path.display().to_string(),
                    findings: vec![FindingJson {
                        code: "E001".into(),
                        severity: "error".into(),
                        message: format!("YAML parse error: {e}"),
                        location: path.display().to_string(),
                        fixable: false,
                    }],
                    fixed: Vec::new(),
                });
                any_parse_error = true;
                continue;
            }
        };

        let mut findings = run_all_checks(&spec, &path.display().to_string());
        let mut fixed_codes: Vec<String> = Vec::new();

        if want_fix {
            fixed_codes = fix::apply_fixes(&mut spec, &findings);

            // Only touch the file when something was actually fixed. Writing
            // unconditionally through the canonical formatter would also
            // silently strip comments and reflow untouched-but-unsorted
            // policies -- fine for `h2h fmt` (that's its whole job), but a
            // surprising side effect for a lint `--fix` that's supposed to be
            // limited to the specific findings it resolved.
            if !fixed_codes.is_empty() {
                // Re-lint against the fixed model so the report (and the exit
                // code below) reflects only what's actually left.
                findings = run_all_checks(&spec, &path.display().to_string());

                // `spec` was mutated in place by `apply_fixes`, so this canonicalizes
                // the in-memory model directly rather than routing through
                // `format_canonical` -- but the original file's modeline (if any)
                // must still be preserved, so it's split from `content` and rejoined
                // the same way `format_canonical` would.
                let (modeline, _) = crate::cmd_fmt::split_modeline(&content);
                let canonical = crate::cmd_fmt::format_spec(&spec);
                let formatted = crate::cmd_fmt::normalize_trailing_newline(
                    &crate::cmd_fmt::rejoin_modeline(modeline, &canonical),
                );

                if args.fix {
                    if let Err(e) = std::fs::write(path, &formatted) {
                        eprintln!("{} failed to write {}: {e}", "error".red(), path.display());
                        any_write_error = true;
                    } else if matches!(args.format, LintOutputFormat::Text) {
                        println!(
                            "{} {} ({} fix(es) applied: {})",
                            "FIXED".green(),
                            path.display(),
                            fixed_codes.len(),
                            fixed_codes.join(", ")
                        );
                    }
                } else if matches!(args.format, LintOutputFormat::Text) {
                    // --dry-run: never write, just show what would change.
                    let original_normalized = crate::cmd_fmt::normalize_trailing_newline(&content);
                    println!(
                        "{}",
                        crate::cmd_fmt::compute_diff(&original_normalized, &formatted, path)
                    );
                }
            } else if args.dry_run && matches!(args.format, LintOutputFormat::Text) {
                println!("{} {} nothing to fix", "ok".green(), path.display());
            }
        }

        for f in &findings {
            match f.severity.as_str() {
                "error" => any_errors = true,
                "warning" => any_warnings = true,
                _ => {}
            }
        }

        if matches!(args.format, LintOutputFormat::Text) {
            print_text_findings(&findings, &path.display().to_string());
        }

        all_results.push(FileLintResult {
            file: path.display().to_string(),
            findings: findings
                .iter()
                .map(|f| FindingJson::new(&spec, f))
                .collect(),
            fixed: fixed_codes,
        });
    }

    if matches!(args.format, LintOutputFormat::Json)
        && let Ok(json) = serde_json::to_string_pretty(&all_results)
    {
        println!("{json}");
    }

    if any_write_error {
        2
    } else if any_parse_error || any_errors || (any_warnings && args.fail_on_warnings) {
        1
    } else {
        0
    }
}

fn print_text_findings(findings: &[LintFinding], _file: &str) {
    for f in findings {
        let severity_colored = match f.severity.as_str() {
            "error" => format!("error[{}]", f.code).red().to_string(),
            "warning" => format!("warning[{}]", f.code).yellow().to_string(),
            _ => format!("info[{}]", f.code).cyan().to_string(),
        };
        println!("{}: {}", severity_colored, f.message);
        println!("  {} {}", "-->".dimmed(), f.location);
        println!();
    }
}

/// Run every lint check against `spec` and return the findings. Shared by the
/// CLI's plain lint pass and by `fix::apply_fixes`'s fixpoint re-linting.
pub(crate) fn run_all_checks(spec: &HushSpec, file: &str) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    let Some(rules) = &spec.rules else {
        return findings;
    };

    // L001: empty-rule-block
    check_empty_rule_blocks(rules, file, &mut findings);

    // L002: overlapping-patterns
    check_overlapping_patterns(rules, file, &mut findings);

    // L003: shadowed-exception
    check_shadowed_exceptions(rules, file, &mut findings);

    // L004: overly-broad-egress
    check_overly_broad_egress(rules, file, &mut findings);

    // L005: empty blocklist with default allow
    check_empty_blocklist_with_default_allow(rules, file, &mut findings);

    // L006: regex-complexity
    check_regex_complexity(rules, file, &mut findings);

    // L007: disabled-rule
    check_disabled_rules(rules, file, &mut findings);

    // L008: duplicate-patterns
    check_duplicate_patterns(rules, file, &mut findings);

    // L009: missing-secret-patterns
    check_missing_secret_patterns(rules, file, &mut findings);

    // L010: unreachable-allow
    check_unreachable_allow(rules, file, &mut findings);

    findings
}

fn check_empty_rule_blocks(rules: &hushspec::Rules, file: &str, findings: &mut Vec<LintFinding>) {
    if let Some(egress) = &rules.egress
        && egress.enabled
        && egress.allow.is_empty()
        && egress.block.is_empty()
        && egress.default == DefaultAction::Allow
    {
        findings.push(LintFinding {
            code: "L001".into(),
            severity: "warning".into(),
            message:
                "rules.egress has no allow or block entries and default is allow -- rule block has no effect"
                    .into(),
            location: file.into(),
        });
    }

    if let Some(tool_access) = &rules.tool_access
        && tool_access.enabled
        && tool_access.allow.is_empty()
        && tool_access.block.is_empty()
        && tool_access.require_confirmation.is_empty()
        && tool_access.default == DefaultAction::Allow
    {
        findings.push(LintFinding {
            code: "L001".into(),
            severity: "warning".into(),
            message:
                "rules.tool_access has no allow, block, or require_confirmation entries and default is allow -- rule block has no effect"
                    .into(),
            location: file.into(),
        });
    }

    if let Some(forbidden_paths) = &rules.forbidden_paths
        && forbidden_paths.enabled
        && forbidden_paths.patterns.is_empty()
    {
        findings.push(LintFinding {
            code: "L001".into(),
            severity: "warning".into(),
            message: "rules.forbidden_paths has no patterns -- rule block has no effect".into(),
            location: file.into(),
        });
    }

    if let Some(shell_commands) = &rules.shell_commands
        && shell_commands.enabled
        && shell_commands.forbidden_patterns.is_empty()
    {
        findings.push(LintFinding {
            code: "L001".into(),
            severity: "warning".into(),
            message: "rules.shell_commands has no forbidden_patterns -- rule block has no effect"
                .into(),
            location: file.into(),
        });
    }

    if let Some(secret_patterns) = &rules.secret_patterns
        && secret_patterns.enabled
        && secret_patterns.patterns.is_empty()
    {
        findings.push(LintFinding {
            code: "L001".into(),
            severity: "warning".into(),
            message: "rules.secret_patterns has no patterns -- rule block has no effect".into(),
            location: file.into(),
        });
    }
}

fn check_overlapping_patterns(
    rules: &hushspec::Rules,
    _file: &str,
    findings: &mut Vec<LintFinding>,
) {
    if let Some(forbidden_paths) = &rules.forbidden_paths {
        find_overlapping_globs(
            &forbidden_paths.patterns,
            "rules.forbidden_paths.patterns",
            findings,
        );
    }

    if let Some(egress) = &rules.egress {
        find_overlapping_globs(&egress.allow, "rules.egress.allow", findings);
        find_overlapping_globs(&egress.block, "rules.egress.block", findings);
    }

    if let Some(tool_access) = &rules.tool_access {
        find_overlapping_globs(&tool_access.allow, "rules.tool_access.allow", findings);
        find_overlapping_globs(&tool_access.block, "rules.tool_access.block", findings);
    }
}

fn find_overlapping_globs(patterns: &[String], path: &str, findings: &mut Vec<LintFinding>) {
    // Precompile once: `globs_may_overlap` is called O(n^2) times below, and
    // recompiling each pattern's regex on every pairwise/candidate check made
    // this quadratic in `Regex::new` calls (visibly slow on real-sized policies
    // in debug builds). Reusing the compiled matcher keeps behavior identical
    // while making the fixpoint re-lint in `fix::apply_fixes` practical.
    let compiled = compile_globs(patterns);

    for i in 0..patterns.len() {
        for j in (i + 1)..patterns.len() {
            if globs_may_overlap(&patterns[i], &compiled[i], &patterns[j], &compiled[j]) {
                findings.push(LintFinding {
                    code: "L002".into(),
                    severity: "warning".into(),
                    message: format!(
                        "{path}[{i}] {:?} and {path}[{j}] {:?} may overlap",
                        patterns[i], patterns[j]
                    ),
                    // Points at the later entry, mirroring L008's convention of
                    // flagging the redundant occurrence. `fix::apply_fixes` only
                    // ever acts on this when it independently reverifies the
                    // pair is byte-identical -- this check merely proves "may
                    // overlap" via sampling, not general subsumption.
                    location: format!("{path}[{j}]"),
                });
            }
        }
    }
}

/// Heuristic check: do two glob patterns potentially match the same target?
/// This proves "disjoint" is false on a sample of synthetic candidates; it is
/// NOT a proof of subsumption in either direction, so callers must not treat
/// a positive result as license to drop either pattern (except when `a == b`).
fn globs_may_overlap(a: &str, ra: &Option<Regex>, b: &str, rb: &Option<Regex>) -> bool {
    if a == b {
        return true;
    }

    let test_paths = generate_synthetic_paths(a)
        .into_iter()
        .chain(generate_synthetic_paths(b));

    for path in test_paths {
        if regex_is_match(ra, &path) && regex_is_match(rb, &path) {
            return true;
        }
    }

    false
}

/// Translate a HushSpec glob (`*`, `**`, literal chars) into a compiled regex.
/// Mirrors `hushspec::evaluate::glob_matches`'s translation exactly -- kept
/// local (rather than shared) so this lint-only performance cache can't be
/// mistaken for a second source of truth for real policy evaluation. The
/// `glob_translation_matches_evaluate_semantics` test below pins agreement.
fn compile_glob(pattern: &str) -> Option<Regex> {
    let mut regex_str = String::from("^");
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '*' => {
                if matches!(chars.peek(), Some('*')) {
                    chars.next();
                    regex_str.push_str(".*");
                } else {
                    regex_str.push_str("[^/]*");
                }
            }
            '?' => regex_str.push('.'),
            '.' | '+' | '(' | ')' | '{' | '}' | '[' | ']' | '^' | '$' | '|' | '\\' => {
                regex_str.push('\\');
                regex_str.push(ch);
            }
            _ => regex_str.push(ch),
        }
    }
    regex_str.push('$');
    Regex::new(&regex_str).ok()
}

fn compile_globs(patterns: &[String]) -> Vec<Option<Regex>> {
    patterns.iter().map(|p| compile_glob(p)).collect()
}

fn regex_is_match(compiled: &Option<Regex>, target: &str) -> bool {
    compiled.as_ref().is_some_and(|r| r.is_match(target))
}

/// Generate synthetic test paths from a glob pattern by extracting literal segments
fn generate_synthetic_paths(pattern: &str) -> Vec<String> {
    let mut paths = Vec::new();

    let stripped = pattern.replace("**", "/synthetic").replace('*', "example");

    paths.push(stripped.clone());

    let alt = pattern.replace("**", "/home/user").replace('*', "test");
    if alt != stripped {
        paths.push(alt);
    }

    let dotvar = pattern.replace("**", "/app").replace('*', "file.txt");
    if dotvar != stripped {
        paths.push(dotvar);
    }

    paths
}

fn check_shadowed_exceptions(
    rules: &hushspec::Rules,
    _file: &str,
    findings: &mut Vec<LintFinding>,
) {
    let Some(forbidden_paths) = &rules.forbidden_paths else {
        return;
    };

    if forbidden_paths.patterns.is_empty() {
        return;
    }

    // Precompile once and reuse across every exception (see `find_overlapping_globs`
    // for why: this loop is patterns x exceptions x synthetic candidates, and
    // recompiling per candidate was the dominant cost on real policies).
    let compiled_patterns = compile_globs(&forbidden_paths.patterns);

    for (i, exception) in forbidden_paths.exceptions.iter().enumerate() {
        let synthetic = generate_synthetic_paths(exception);
        let any_blocked = synthetic.iter().any(|test_path| {
            compiled_patterns
                .iter()
                .any(|r| regex_is_match(r, test_path))
        });

        if !any_blocked {
            findings.push(LintFinding {
                code: "L003".into(),
                severity: "warning".into(),
                message: format!(
                    "rules.forbidden_paths.exceptions[{i}] {:?} does not match any forbidden pattern -- exception has no effect",
                    exception
                ),
                location: format!("rules.forbidden_paths.exceptions[{i}]"),
            });
        }
    }
}

fn check_overly_broad_egress(rules: &hushspec::Rules, file: &str, findings: &mut Vec<LintFinding>) {
    if let Some(egress) = &rules.egress {
        for (i, pattern) in egress.allow.iter().enumerate() {
            if pattern == "*" || pattern == "*.*" {
                findings.push(LintFinding {
                    code: "L004".into(),
                    severity: "warning".into(),
                    message: format!(
                        "rules.egress.allow[{i}] contains wildcard pattern {:?} -- this allows all egress, making the rule ineffective",
                        pattern
                    ),
                    location: file.into(),
                });
            }
        }
    }

    if let Some(tool_access) = &rules.tool_access {
        for (i, pattern) in tool_access.allow.iter().enumerate() {
            if pattern == "*" {
                findings.push(LintFinding {
                    code: "L004".into(),
                    severity: "warning".into(),
                    message: format!(
                        "rules.tool_access.allow[{i}] contains wildcard pattern {:?} -- this allows all tools, making the rule ineffective",
                        pattern
                    ),
                    location: file.into(),
                });
            }
        }
    }
}

fn check_empty_blocklist_with_default_allow(
    rules: &hushspec::Rules,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    if let Some(egress) = &rules.egress
        && egress.enabled
        && !egress.allow.is_empty()
        && egress.block.is_empty()
        && egress.default == DefaultAction::Allow
    {
        findings.push(LintFinding {
            code: "L005".into(),
            severity: "info".into(),
            message:
                "rules.egress has default \"allow\" with an empty block list -- all egress is permitted regardless of the allow list"
                    .into(),
            location: file.into(),
        });
    }

    if let Some(tool_access) = &rules.tool_access
        && tool_access.enabled
        && !tool_access.allow.is_empty()
        && tool_access.block.is_empty()
        && tool_access.require_confirmation.is_empty()
        && tool_access.default == DefaultAction::Allow
    {
        findings.push(LintFinding {
            code: "L005".into(),
            severity: "info".into(),
            message:
                "rules.tool_access has default \"allow\" with empty block and require_confirmation lists -- all tools are permitted regardless of the allow list"
                    .into(),
            location: file.into(),
        });
    }
}

fn check_regex_complexity(rules: &hushspec::Rules, file: &str, findings: &mut Vec<LintFinding>) {
    if let Some(secret_patterns) = &rules.secret_patterns {
        for (i, pat) in secret_patterns.patterns.iter().enumerate() {
            check_single_regex(
                &pat.pattern,
                &format!("rules.secret_patterns.patterns[{i}]"),
                file,
                findings,
            );
        }
    }

    if let Some(shell_commands) = &rules.shell_commands {
        for (i, pat) in shell_commands.forbidden_patterns.iter().enumerate() {
            check_single_regex(
                pat,
                &format!("rules.shell_commands.forbidden_patterns[{i}]"),
                file,
                findings,
            );
        }
    }

    if let Some(patch_integrity) = &rules.patch_integrity {
        for (i, pat) in patch_integrity.forbidden_patterns.iter().enumerate() {
            check_single_regex(
                pat,
                &format!("rules.patch_integrity.forbidden_patterns[{i}]"),
                file,
                findings,
            );
        }
    }
}

fn check_single_regex(pattern: &str, path: &str, file: &str, findings: &mut Vec<LintFinding>) {
    let mut reasons = Vec::new();

    if pattern.len() > 200 {
        reasons.push("pattern exceeds 200 characters");
    }

    let alternation_count = pattern.matches('|').count();
    if alternation_count > 5 {
        reasons.push("pattern has more than 5 alternations");
    }

    if has_nested_quantifiers(pattern) {
        reasons.push("pattern has nested quantifiers (potential ReDoS risk)");
    }

    if !reasons.is_empty() {
        findings.push(LintFinding {
            code: "L006".into(),
            severity: "warning".into(),
            message: format!("{path}: regex complexity warning -- {}", reasons.join("; ")),
            location: file.into(),
        });
    }
}

/// Heuristic detection of nested quantifiers that could cause ReDoS
fn has_nested_quantifiers(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut depth = 0;
    let mut has_inner_quantifier = false;
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'(' => {
                depth += 1;
                has_inner_quantifier = false;
            }
            b')' => {
                if depth > 0 {
                    depth -= 1;
                    if has_inner_quantifier
                        && i + 1 < bytes.len()
                        && matches!(bytes[i + 1], b'+' | b'*' | b'{')
                    {
                        return true;
                    }
                }
                has_inner_quantifier = false;
            }
            b'+' | b'*' if depth > 0 => {
                has_inner_quantifier = true;
            }
            _ => {}
        }
        i += 1;
    }

    false
}

fn check_disabled_rules(rules: &hushspec::Rules, file: &str, findings: &mut Vec<LintFinding>) {
    let disabled_checks: &[(&str, Option<bool>)] = &[
        (
            "rules.forbidden_paths",
            rules.forbidden_paths.as_ref().map(|r| r.enabled),
        ),
        ("rules.egress", rules.egress.as_ref().map(|r| r.enabled)),
        (
            "rules.secret_patterns",
            rules.secret_patterns.as_ref().map(|r| r.enabled),
        ),
        (
            "rules.shell_commands",
            rules.shell_commands.as_ref().map(|r| r.enabled),
        ),
        (
            "rules.tool_access",
            rules.tool_access.as_ref().map(|r| r.enabled),
        ),
        (
            "rules.patch_integrity",
            rules.patch_integrity.as_ref().map(|r| r.enabled),
        ),
        (
            "rules.computer_use",
            rules.computer_use.as_ref().map(|r| r.enabled),
        ),
        (
            "rules.remote_desktop_channels",
            rules.remote_desktop_channels.as_ref().map(|r| r.enabled),
        ),
        (
            "rules.input_injection",
            rules.input_injection.as_ref().map(|r| r.enabled),
        ),
    ];

    for &(name, enabled) in disabled_checks {
        if enabled == Some(false) {
            findings.push(LintFinding {
                code: "L007".into(),
                severity: "info".into(),
                message: format!("{name} is explicitly disabled"),
                location: file.into(),
            });
        }
    }
}

fn check_duplicate_patterns(rules: &hushspec::Rules, _file: &str, findings: &mut Vec<LintFinding>) {
    if let Some(forbidden_paths) = &rules.forbidden_paths {
        find_duplicates(
            &forbidden_paths.patterns,
            "rules.forbidden_paths.patterns",
            findings,
        );
        find_duplicates(
            &forbidden_paths.exceptions,
            "rules.forbidden_paths.exceptions",
            findings,
        );
    }

    if let Some(egress) = &rules.egress {
        find_duplicates(&egress.allow, "rules.egress.allow", findings);
        find_duplicates(&egress.block, "rules.egress.block", findings);
    }

    if let Some(tool_access) = &rules.tool_access {
        find_duplicates(&tool_access.allow, "rules.tool_access.allow", findings);
        find_duplicates(&tool_access.block, "rules.tool_access.block", findings);
        find_duplicates(
            &tool_access.require_confirmation,
            "rules.tool_access.require_confirmation",
            findings,
        );
    }

    if let Some(shell_commands) = &rules.shell_commands {
        find_duplicates(
            &shell_commands.forbidden_patterns,
            "rules.shell_commands.forbidden_patterns",
            findings,
        );
    }
}

/// Location is entry-precise (`{path}[{i}]`) rather than the file-level
/// fallback other checks use: `fix::apply_fixes` relies on it to remove
/// exactly the flagged (later) occurrence of an exact duplicate.
fn find_duplicates(list: &[String], path: &str, findings: &mut Vec<LintFinding>) {
    let mut seen: HashSet<&str> = HashSet::new();
    for (i, entry) in list.iter().enumerate() {
        if !seen.insert(entry.as_str()) {
            findings.push(LintFinding {
                code: "L008".into(),
                severity: "warning".into(),
                message: format!("{path}[{i}]: duplicate pattern {:?}", entry),
                location: format!("{path}[{i}]"),
            });
        }
    }
}

fn check_missing_secret_patterns(
    rules: &hushspec::Rules,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    if rules.secret_patterns.is_none() {
        findings.push(LintFinding {
            code: "L009".into(),
            severity: "info".into(),
            message: "policy has no secret_patterns rule -- consider adding secret detection for file_write operations".into(),
            location: file.into(),
        });
    }
}

fn check_unreachable_allow(rules: &hushspec::Rules, file: &str, findings: &mut Vec<LintFinding>) {
    if let Some(egress) = &rules.egress {
        let block_set: HashSet<&str> = egress.block.iter().map(|s| s.as_str()).collect();
        for (i, entry) in egress.allow.iter().enumerate() {
            if block_set.contains(entry.as_str()) {
                findings.push(LintFinding {
                    code: "L010".into(),
                    severity: "warning".into(),
                    message: format!(
                        "rules.egress.allow[{i}] {:?} is also in the block list -- block takes precedence, allow entry is dead",
                        entry
                    ),
                    location: file.into(),
                });
            }
        }
    }

    if let Some(tool_access) = &rules.tool_access {
        let block_set: HashSet<&str> = tool_access.block.iter().map(|s| s.as_str()).collect();
        for (i, entry) in tool_access.allow.iter().enumerate() {
            if block_set.contains(entry.as_str()) {
                findings.push(LintFinding {
                    code: "L010".into(),
                    severity: "warning".into(),
                    message: format!(
                        "rules.tool_access.allow[{i}] {:?} is also in the block list -- block takes precedence, allow entry is dead",
                        entry
                    ),
                    location: file.into(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hushspec::evaluate::glob_matches;

    #[test]
    fn test_has_nested_quantifiers() {
        assert!(has_nested_quantifiers("(a+)+"));
        assert!(has_nested_quantifiers("(.*a)+"));
        assert!(has_nested_quantifiers("([a-z]+)*"));
        assert!(!has_nested_quantifiers("a+b+c+"));
        assert!(!has_nested_quantifiers("[a-z]+"));
        assert!(!has_nested_quantifiers("(abc)"));
    }

    #[test]
    fn test_glob_matches() {
        assert!(glob_matches("*.txt", "hello.txt"));
        assert!(!glob_matches("*.txt", "hello.rs"));
        assert!(glob_matches("**/.ssh/**", "/home/user/.ssh/id_rsa"));
        assert!(glob_matches("*", "anything"));
    }

    /// `compile_glob`/`regex_is_match` is a local performance cache for the
    /// exact same glob semantics `hushspec::evaluate::glob_matches` uses.
    /// This pins agreement so the two can't silently drift apart.
    #[test]
    fn glob_translation_matches_evaluate_semantics() {
        let cases: &[(&str, &str)] = &[
            ("*.txt", "hello.txt"),
            ("*.txt", "hello.rs"),
            ("**/.ssh/**", "/home/user/.ssh/id_rsa"),
            ("*", "anything"),
            ("*", "a/b"),
            ("file.*", "file.secret"),
            ("*.secret", "file.secret"),
            ("**/.env.*", "/repo/.env.local"),
            ("a?c", "abc"),
            ("a?c", "ac"),
            ("literal[with]chars", "literal[with]chars"),
            ("**/customer-data/**", "/x/customer-data/y"),
        ];
        for (pattern, target) in cases {
            let compiled = compile_glob(pattern);
            assert_eq!(
                regex_is_match(&compiled, target),
                glob_matches(pattern, target),
                "compile_glob disagreed with glob_matches for pattern {pattern:?} target {target:?}"
            );
        }
    }
}
