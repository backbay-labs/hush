mod checks;
mod fix;
mod sarif;
mod spans;

use clap::ValueEnum;
use colored::Colorize;
use hushspec::{DefaultAction, HushSpec};
use regex::Regex;
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct LintArgs {
    /// Policy YAML files to lint; "-" reads the document from stdin
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

    /// Write the report to this file instead of stdout (json and sarif only)
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum LintOutputFormat {
    Text,
    Json,
    /// SARIF 2.1.0, the format GitHub code scanning ingests.
    Sarif,
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct LintFinding {
    code: String,
    severity: String,
    message: String,
    /// Machine-parseable pointer for the subset of findings that support
    /// entry-precise auto-fixing: `rules.<block>.<field>[<idx>]`. Findings
    /// that can't point at a single list entry fall back to the file path.
    ///
    /// This is deliberately *not* the span lookup key: `fix::parse_location`
    /// parses this grammar and must keep seeing exactly what it saw before
    /// spans existed.
    location: String,
    /// Document path of the offending key or list entry, used to look up a
    /// source span. `None` only for findings about the document as a whole.
    path: Option<String>,
}

impl LintFinding {
    /// A finding that points at one list entry the fix engine can act on: the
    /// document path doubles as `location`.
    fn entry(code: &str, severity: &str, message: String, path: String) -> Self {
        LintFinding {
            code: code.into(),
            severity: severity.into(),
            message,
            location: path.clone(),
            path: Some(path),
        }
    }

    /// A finding reported against the file, but which still knows which key it
    /// is about. `location` stays the file (so the fix engine ignores it) while
    /// `path` carries the key a span is resolved from.
    fn keyed(code: &str, severity: &str, message: String, file: &str, path: String) -> Self {
        LintFinding {
            code: code.into(),
            severity: severity.into(),
            message,
            location: file.into(),
            path: Some(path),
        }
    }
}

/// Where a finding's key is written. `file` is the *document that declares it*,
/// which for a policy with `extends` is often a base rather than the file that
/// was linted.
#[derive(Clone, Debug, serde::Serialize)]
struct FindingSpan {
    file: String,
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
}

impl FindingSpan {
    fn new(file: &str, span: spans::Span) -> Self {
        FindingSpan {
            file: file.to_string(),
            line: span.line,
            column: span.column,
            end_line: span.end_line,
            end_column: span.end_column,
        }
    }
}

/// JSON view of a finding: `LintFinding` plus the derived `fixable` flag, the
/// document `path` the finding is about, and the source `span` that path
/// resolves to (all additive fields).
#[derive(serde::Serialize)]
struct FindingJson {
    code: String,
    severity: String,
    message: String,
    location: String,
    fixable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    span: Option<FindingSpan>,
}

impl FindingJson {
    fn new(spec: &HushSpec, finding: &LintFinding, sources: &SpanSources) -> Self {
        FindingJson {
            code: finding.code.clone(),
            severity: finding.severity.clone(),
            message: finding.message.clone(),
            location: finding.location.clone(),
            fixable: fix::finding_is_fixable(spec, finding),
            span: finding
                .path
                .as_deref()
                .and_then(|path| sources.resolve(path)),
            path: finding.path.clone(),
        }
    }

    /// A finding raised before the document could be linted at all (unreadable,
    /// unparseable, unresolvable). There is no model and no span map yet.
    fn preflight(code: &str, message: String, file: &str) -> Self {
        FindingJson {
            code: code.into(),
            severity: "error".into(),
            message,
            location: file.into(),
            fixable: false,
            path: None,
            span: None,
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

/// Span maps for every document a finding could have come from: the linted file
/// first, then each base in the `extends` chain from nearest to furthest.
///
/// Lint reports the *resolved* document, so a finding about `rules.egress.allow`
/// in a policy that inherits that block belongs to the base that wrote it. The
/// leaf is consulted first so an override lands on the overriding document.
struct SpanSources {
    sources: Vec<(String, spans::SpanMap)>,
}

impl SpanSources {
    fn build(display: &str, content: &str, resolution: Option<&hushspec::Resolution>) -> Self {
        let mut sources = vec![(display.to_string(), spans::SpanMap::build(content))];
        if let Some(resolution) = resolution {
            // `chain` is root-first, leaf-last, and the leaf is `content`.
            for link in resolution.chain.iter().rev().skip(1) {
                if let Some(text) = read_chain_source(&link.source) {
                    sources.push((link.source.clone(), spans::SpanMap::build(&text)));
                }
            }
        }
        SpanSources { sources }
    }

    fn resolve(&self, path: &str) -> Option<FindingSpan> {
        // An exact hit anywhere in the chain beats an approximate hit in the
        // leaf, so the exact pass runs over every source first.
        for (file, map) in &self.sources {
            if let Some(span) = map.get(path) {
                return Some(FindingSpan::new(file, span));
            }
        }
        for (file, map) in &self.sources {
            if let Some(span) = map.nearest(path) {
                return Some(FindingSpan::new(file, span));
            }
        }
        None
    }
}

/// Raw text for one `extends` chain link, when it is available locally.
/// Remote references are not re-fetched to draw a span.
fn read_chain_source(source: &str) -> Option<String> {
    if let Some(name) = source.strip_prefix("builtin:") {
        return hushspec::load_builtin(name).map(str::to_string);
    }
    if source.contains("://") || source == hushspec::MEMORY_SOURCE {
        return None;
    }
    std::fs::read_to_string(source).ok()
}

pub fn run(args: LintArgs) -> i32 {
    let mut all_results: Vec<FileLintResult> = Vec::new();
    let mut any_errors = false;
    let mut any_warnings = false;
    let mut any_parse_error = false;
    let mut any_write_error = false;
    let want_fix = args.fix || args.dry_run;

    // `--fix` rewrites files in place, which stdin has no way to receive:
    // refuse up front rather than reading the document and silently dropping
    // the fixed output. (`--dry-run` only prints a diff, so it is fine.)
    // `--out` writes one machine-readable report; text output is streamed per
    // file and interleaved with `--fix` progress, so it has nothing coherent to
    // write to a file.
    if args.out.is_some() && args.format == LintOutputFormat::Text {
        eprintln!(
            "{} --out requires --format json or --format sarif",
            "error".red()
        );
        return 2;
    }

    if args.fix && args.files.iter().any(|p| crate::input::is_stdin(p)) {
        eprintln!(
            "{} --fix cannot rewrite stdin; write the document to a file first, \
             or use `h2h fmt -` / `h2h lint - --dry-run`",
            "error".red()
        );
        return 2;
    }

    for path in &args.files {
        let display = crate::input::display(path);

        let content = match crate::input::read_policy(path) {
            Ok(c) => c,
            Err(crate::input::ReadError::NotFound) => {
                if matches!(args.format, LintOutputFormat::Text) {
                    eprintln!("{} file not found: {display}", "error".red());
                }
                all_results.push(FileLintResult {
                    findings: vec![FindingJson::preflight(
                        "E000",
                        format!("file not found: {display}"),
                        &display,
                    )],
                    file: display,
                    fixed: Vec::new(),
                });
                any_parse_error = true;
                continue;
            }
            Err(crate::input::ReadError::Io(e)) => {
                if matches!(args.format, LintOutputFormat::Text) {
                    eprintln!("{} {e}", "error".red());
                }
                all_results.push(FileLintResult {
                    findings: vec![FindingJson::preflight(
                        "E000",
                        format!("failed to read file: {e}"),
                        &display,
                    )],
                    file: display,
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
                    eprintln!("{} failed to parse {display}: {e}", "error".red());
                }
                all_results.push(FileLintResult {
                    findings: vec![FindingJson::preflight(
                        "E001",
                        format!("YAML parse error: {e}"),
                        &display,
                    )],
                    file: display,
                    fixed: Vec::new(),
                });
                any_parse_error = true;
                continue;
            }
        };

        // Lint the *resolved* document. A policy that extends a base is
        // enforced as the merged result, so linting the bare leaf both misses
        // real problems inherited from the base and invents findings for
        // blocks the base supplies (L009 fires on every `extends:` policy that
        // inherits `secret_patterns`). A chain that will not resolve is an
        // error finding, never a silent fall back to the leaf.
        // The full `Resolution` (not just the merged spec) is what is needed
        // here: its `chain` names every document that contributed, which is how
        // a finding about an inherited block is located in the base that
        // actually writes it.
        let resolution = if spec.extends.is_some() {
            let options = hushspec::ResolveOptions::default();
            let resolution = if crate::input::is_stdin(path) {
                // A document read from stdin has no path to resolve relative
                // `extends` against, so relative references resolve from the
                // working directory instead (builtins still work).
                let loader = hushspec::create_composite_loader();
                hushspec::resolve_with_options(&spec, None, &loader, &options)
            } else {
                hushspec::resolve_path_with_options(path, &options)
            };
            match resolution {
                Ok(resolution) => Some(resolution),
                Err(e) => {
                    if matches!(args.format, LintOutputFormat::Text) {
                        eprintln!("{} failed to resolve {display}: {e}", "error".red());
                    }
                    all_results.push(FileLintResult {
                        findings: vec![FindingJson::preflight(
                            "E002",
                            format!("failed to resolve extends: {e}"),
                            &display,
                        )],
                        file: display,
                        fixed: Vec::new(),
                    });
                    any_parse_error = true;
                    continue;
                }
            }
        } else {
            None
        };

        let resolved = resolution.as_ref().map(|resolution| &resolution.spec);

        let mut span_sources = SpanSources::build(&display, &content, resolution.as_ref());

        let mut findings = match resolved {
            Some(resolved) => run_all_checks(resolved, &display),
            None => run_all_checks(&spec, &display),
        };
        let mut fixed_codes: Vec<String> = Vec::new();

        if want_fix && resolved.is_some() {
            // Findings describe the resolved document, whose list indices do
            // not line up with the on-disk leaf, so applying them in place
            // would rewrite the wrong entries -- and materialize inherited
            // rules into a file that deliberately delegates them.
            if matches!(args.format, LintOutputFormat::Text) {
                eprintln!(
                    "{} {}: --fix/--dry-run is not supported for policies with `extends` (findings describe the resolved document)",
                    "warning".yellow(),
                    path.display()
                );
            }
        } else if want_fix {
            fixed_codes = fix::apply_fixes(&mut spec, &findings);

            // Only touch the file when something was actually fixed. Writing
            // unconditionally through the canonical formatter would also
            // silently strip comments and reflow untouched-but-unsorted
            // policies -- fine for `h2h fmt` (that's its whole job), but a
            // surprising side effect for a lint `--fix` that's supposed to be
            // limited to the specific findings it resolved.
            if !fixed_codes.is_empty() {
                // Findings that still describe the on-disk file (used if a
                // `--fix` write fails, so the report never claims a file was
                // fixed that was never actually written).
                let pre_fix_findings = findings.clone();

                // Re-lint against the fixed model so the report (and the exit
                // code below) reflects only what's actually left.
                findings = run_all_checks(&spec, &display);

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
                        // The on-disk file is unchanged, so report its actual
                        // (pre-fix) findings and no applied fixes. `span_sources`
                        // already describes `content`, which is still what is on
                        // disk, so it is left alone.
                        findings = pre_fix_findings;
                        fixed_codes = Vec::new();
                    } else {
                        // The rewritten file has different line numbers, so the
                        // findings that remain must be located against it, not
                        // against the text read at the top of the loop.
                        span_sources = SpanSources::build(&display, &formatted, None);
                        if matches!(args.format, LintOutputFormat::Text) {
                            println!(
                                "{} {} ({} fix(es) applied: {})",
                                "FIXED".green(),
                                path.display(),
                                fixed_codes.len(),
                                fixed_codes.join(", ")
                            );
                        }
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
                println!("{} {display} nothing to fix", "ok".green());
            }
        }

        for f in &findings {
            match f.severity.as_str() {
                "error" => any_errors = true,
                "warning" => any_warnings = true,
                _ => {}
            }
        }

        let rendered: Vec<FindingJson> = findings
            .iter()
            .map(|f| FindingJson::new(resolved.unwrap_or(&spec), f, &span_sources))
            .collect();

        if matches!(args.format, LintOutputFormat::Text) {
            print_text_findings(&rendered, &display);
        }

        all_results.push(FileLintResult {
            file: display,
            findings: rendered,
            fixed: fixed_codes,
        });
    }

    let report = match args.format {
        LintOutputFormat::Text => None,
        LintOutputFormat::Json => serde_json::to_string_pretty(&all_results).ok(),
        LintOutputFormat::Sarif => {
            serde_json::to_string_pretty(&sarif::document(&all_results)).ok()
        }
    };
    if let Some(report) = report {
        match &args.out {
            Some(path) => {
                if let Err(e) = std::fs::write(path, format!("{report}\n")) {
                    eprintln!("{} failed to write {}: {e}", "error".red(), path.display());
                    return 2;
                }
            }
            None => println!("{report}"),
        }
    }

    if any_write_error {
        2
    } else if any_parse_error || any_errors || (any_warnings && args.fail_on_warnings) {
        1
    } else {
        0
    }
}

/// `code: message` followed by `file:line:column`, with the document path on a
/// second line when there is one. A finding whose key could not be located
/// falls back to the pre-span `location` string so nothing is ever reported
/// without a pointer of some kind.
fn print_text_findings(findings: &[FindingJson], _file: &str) {
    for f in findings {
        let severity_colored = match f.severity.as_str() {
            "error" => format!("error[{}]", f.code).red().to_string(),
            "warning" => format!("warning[{}]", f.code).yellow().to_string(),
            _ => format!("info[{}]", f.code).cyan().to_string(),
        };
        println!("{}: {}", severity_colored, f.message);
        match (&f.span, &f.path) {
            (Some(span), Some(path)) => {
                println!(
                    "  {} {}:{}:{}",
                    "-->".dimmed(),
                    span.file,
                    span.line,
                    span.column
                );
                println!("   {} {}", "|".dimmed(), path.dimmed());
            }
            (Some(span), None) => println!(
                "  {} {}:{}:{}",
                "-->".dimmed(),
                span.file,
                span.line,
                span.column
            ),
            (None, _) => println!("  {} {}", "-->".dimmed(), f.location),
        }
        println!();
    }
}

/// Run every lint check against `spec` and return the findings. Shared by the
/// CLI's plain lint pass and by `fix::apply_fixes`'s fixpoint re-linting.
pub(crate) fn run_all_checks(spec: &HushSpec, file: &str) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    // L011/L012/L013: control mappings. Run before the `rules` guard so a
    // document that maps only extensions (or maps nothing that exists) is still
    // checked.
    check_control_mappings(spec, file, &mut findings);

    // L019: extension configuration nothing can reach. Runs outside the `rules`
    // guard for the same reason as the control mappings: a document may declare
    // extensions and no rule blocks at all.
    checks::check_unreachable_extensions(spec, file, &mut findings);

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

    // L014: credential locations a filesystem denylist misses
    checks::check_credential_coverage(rules, file, &mut findings);

    // L015: a credential-class secret pattern graded below critical
    checks::check_credential_severity(rules, file, &mut findings);

    // L016: a forbidden pattern that matches every input
    checks::check_overbroad_forbidden_patterns(rules, file, &mut findings);

    // L017: a rule block whose default permits (supersedes L005)
    checks::check_permissive_defaults(rules, file, &mut findings);

    // L018: a capability block enabled with an empty allowlist
    checks::check_empty_capability_allowlists(rules, file, &mut findings);

    // L020: a `when` clause that narrows nothing
    checks::check_degenerate_conditions(rules, file, &mut findings);

    // L021: a `when.capability` no posture state grants
    checks::check_ungranted_capability_conditions(spec, file, &mut findings);

    findings
}

/// L011 (warning), L012 (error), L013 (warning): `metadata.controls`.
///
/// Mappings are advisory and never influence evaluation, so a policy that
/// declares none is silent here -- L011 only fires once a policy has started
/// mapping controls and then leaves a rule block out. L012 and L013 fire per
/// mapping regardless.
fn check_control_mappings(spec: &HushSpec, file: &str, findings: &mut Vec<LintFinding>) {
    let Some(metadata) = &spec.metadata else {
        return;
    };
    if metadata.controls.is_empty() {
        return;
    }

    let doc = crate::controls::document_json(spec);

    // L012: a rule path that points at nothing is a broken claim about what the
    // policy implements, so it is an error rather than a warning.
    for (index, control) in metadata.controls.iter().enumerate() {
        for (entry, rule_path) in control.rule_paths.iter().enumerate() {
            if !crate::controls::path_resolves(&doc, rule_path) {
                findings.push(LintFinding::keyed(
                    "L012",
                    "error",
                    format!(
                        "metadata.controls[{index}].rule_paths[{entry}] {rule_path:?} \
                         ({} {}) does not resolve to anything in the resolved document",
                        control.framework, control.control_id
                    ),
                    file,
                    format!("metadata.controls[{index}].rule_paths[{entry}]"),
                ));
            }
        }
    }

    // L013: the registry is advisory -- an unregistered framework is a valid
    // document, just an unverifiable claim, so both halves are warnings.
    for (index, control) in metadata.controls.iter().enumerate() {
        match crate::controls::registry_verdict(&control.framework, &control.control_id) {
            crate::controls::RegistryVerdict::Ok => {}
            crate::controls::RegistryVerdict::UnknownFramework => {
                findings.push(LintFinding::keyed(
                    "L013",
                    "warning",
                    format!(
                        "metadata.controls[{index}].framework {:?} is not in the HushSpec framework registry (spec/registries/frameworks.yaml)",
                        control.framework
                    ),
                    file,
                    format!("metadata.controls[{index}].framework"),
                ));
            }
            crate::controls::RegistryVerdict::ControlIdMismatch => {
                let pattern = crate::generated_frameworks::framework(&control.framework)
                    .map_or("", |entry| entry.control_id_pattern);
                findings.push(LintFinding::keyed(
                    "L013",
                    "warning",
                    format!(
                        "metadata.controls[{index}].control_id {:?} does not match the {} control id pattern {pattern:?}",
                        control.control_id, control.framework
                    ),
                    file,
                    format!("metadata.controls[{index}].control_id"),
                ));
            }
        }
    }

    // L011: once a policy maps controls, every rule block it declares should be
    // accounted for -- an unmapped block is enforcement with no stated reason.
    for block_path in crate::controls::rule_block_paths(&doc) {
        let covered = metadata.controls.iter().any(|control| {
            control
                .rule_paths
                .iter()
                .any(|rule_path| crate::controls::path_covers_block(rule_path, &block_path))
        });
        if !covered {
            findings.push(LintFinding::keyed(
                "L011",
                "warning",
                format!("rule block `{block_path}` has no control mapping"),
                file,
                block_path.clone(),
            ));
        }
    }
}

fn check_empty_rule_blocks(rules: &hushspec::Rules, file: &str, findings: &mut Vec<LintFinding>) {
    if let Some(egress) = &rules.egress
        && egress.enabled
        && egress.allow.is_empty()
        && egress.block.is_empty()
        && egress.default == DefaultAction::Allow
    {
        findings.push(LintFinding::keyed(
            "L001",
            "warning",
            "rules.egress has no allow or block entries and default is allow -- rule block has no effect"
                .into(),
            file,
            "rules.egress".into(),
        ));
    }

    if let Some(tool_access) = &rules.tool_access
        && tool_access.enabled
        && tool_access.allow.is_empty()
        && tool_access.block.is_empty()
        && tool_access.require_confirmation.is_empty()
        && tool_access.default == DefaultAction::Allow
    {
        findings.push(LintFinding::keyed(
            "L001",
            "warning",
            "rules.tool_access has no allow, block, or require_confirmation entries and default is allow -- rule block has no effect"
                .into(),
            file,
            "rules.tool_access".into(),
        ));
    }

    if let Some(forbidden_paths) = &rules.forbidden_paths
        && forbidden_paths.enabled
        && forbidden_paths.patterns.is_empty()
    {
        findings.push(LintFinding::keyed(
            "L001",
            "warning",
            "rules.forbidden_paths has no patterns -- rule block has no effect".into(),
            file,
            "rules.forbidden_paths".into(),
        ));
    }

    if let Some(shell_commands) = &rules.shell_commands
        && shell_commands.enabled
        && shell_commands.forbidden_patterns.is_empty()
    {
        findings.push(LintFinding::keyed(
            "L001",
            "warning",
            "rules.shell_commands has no forbidden_patterns -- rule block has no effect".into(),
            file,
            "rules.shell_commands".into(),
        ));
    }

    if let Some(secret_patterns) = &rules.secret_patterns
        && secret_patterns.enabled
        && secret_patterns.patterns.is_empty()
    {
        findings.push(LintFinding::keyed(
            "L001",
            "warning",
            "rules.secret_patterns has no patterns -- rule block has no effect".into(),
            file,
            "rules.secret_patterns".into(),
        ));
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
                // Points at the later entry, mirroring L008's convention of
                // flagging the redundant occurrence. `fix::apply_fixes` only
                // ever acts on this when it independently reverifies the pair
                // is byte-identical -- this check merely proves "may overlap"
                // via sampling, not general subsumption.
                findings.push(LintFinding::entry(
                    "L002",
                    "warning",
                    format!(
                        "{path}[{i}] {:?} and {path}[{j}] {:?} may overlap",
                        patterns[i], patterns[j]
                    ),
                    format!("{path}[{j}]"),
                ));
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
            findings.push(LintFinding::entry(
                "L003",
                "warning",
                format!(
                    "rules.forbidden_paths.exceptions[{i}] {:?} does not match any forbidden pattern -- exception has no effect",
                    exception
                ),
                format!("rules.forbidden_paths.exceptions[{i}]"),
            ));
        }
    }
}

fn check_overly_broad_egress(rules: &hushspec::Rules, file: &str, findings: &mut Vec<LintFinding>) {
    if let Some(egress) = &rules.egress {
        for (i, pattern) in egress.allow.iter().enumerate() {
            if pattern == "*" || pattern == "*.*" {
                findings.push(LintFinding::keyed(
                    "L004",
                    "warning",
                    format!(
                        "rules.egress.allow[{i}] contains wildcard pattern {:?} -- this allows all egress, making the rule ineffective",
                        pattern
                    ),
                    file,
                    format!("rules.egress.allow[{i}]"),
                ));
            }
        }
    }

    if let Some(tool_access) = &rules.tool_access {
        for (i, pattern) in tool_access.allow.iter().enumerate() {
            if pattern == "*" {
                findings.push(LintFinding::keyed(
                    "L004",
                    "warning",
                    format!(
                        "rules.tool_access.allow[{i}] contains wildcard pattern {:?} -- this allows all tools, making the rule ineffective",
                        pattern
                    ),
                    file,
                    format!("rules.tool_access.allow[{i}]"),
                ));
            }
        }
    }
}

/// L006: regex complexity.
fn check_regex_complexity(rules: &hushspec::Rules, file: &str, findings: &mut Vec<LintFinding>) {
    if let Some(secret_patterns) = &rules.secret_patterns {
        for (i, pat) in secret_patterns.patterns.iter().enumerate() {
            check_single_regex(
                &pat.pattern,
                &format!("rules.secret_patterns.patterns[{i}]"),
                &format!("rules.secret_patterns.patterns[{i}].pattern"),
                file,
                findings,
            );
        }
    }

    if let Some(shell_commands) = &rules.shell_commands {
        for (i, pat) in shell_commands.forbidden_patterns.iter().enumerate() {
            let path = format!("rules.shell_commands.forbidden_patterns[{i}]");
            check_single_regex(pat, &path, &path, file, findings);
        }
    }

    if let Some(patch_integrity) = &rules.patch_integrity {
        for (i, pat) in patch_integrity.forbidden_patterns.iter().enumerate() {
            let path = format!("rules.patch_integrity.forbidden_patterns[{i}]");
            check_single_regex(pat, &path, &path, file, findings);
        }
    }
}

fn check_single_regex(
    pattern: &str,
    label: &str,
    path: &str,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
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
        findings.push(LintFinding::keyed(
            "L006",
            "warning",
            format!(
                "{label}: regex complexity warning -- {}",
                reasons.join("; ")
            ),
            file,
            path.into(),
        ));
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

/// L007: every rule block's `enabled` flag, paired with its path.
///
/// All twelve blocks are listed. `enabled: false` makes a block inert, which
/// *permits* whatever it would otherwise govern, so a block missing from this
/// list would be a control that can be switched off silently.
/// `checks::tests::every_rule_block_is_covered` fails if the spec grows a
/// thirteenth block and this list does not.
pub(crate) fn rule_block_enabled(rules: &hushspec::Rules) -> Vec<(&'static str, Option<bool>)> {
    vec![
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
        (
            "rules.path_allowlist",
            rules.path_allowlist.as_ref().map(|r| r.enabled),
        ),
        (
            "rules.browser_automation",
            rules.browser_automation.as_ref().map(|r| r.enabled),
        ),
        (
            "rules.code_execution",
            rules.code_execution.as_ref().map(|r| r.enabled),
        ),
    ]
}

fn check_disabled_rules(rules: &hushspec::Rules, file: &str, findings: &mut Vec<LintFinding>) {
    for (name, enabled) in rule_block_enabled(rules) {
        if enabled == Some(false) {
            findings.push(LintFinding::keyed(
                "L007",
                "info",
                format!("{name} is explicitly disabled"),
                file,
                format!("{name}.enabled"),
            ));
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
            findings.push(LintFinding::entry(
                "L008",
                "warning",
                format!("{path}[{i}]: duplicate pattern {:?}", entry),
                format!("{path}[{i}]"),
            ));
        }
    }
}

fn check_missing_secret_patterns(
    rules: &hushspec::Rules,
    file: &str,
    findings: &mut Vec<LintFinding>,
) {
    if rules.secret_patterns.is_none() {
        findings.push(LintFinding::keyed(
            "L009",
            "info",
            "policy has no secret_patterns rule -- consider adding secret detection for file_write operations".into(),
            file,
            "rules".into(),
        ));
    }
}

fn check_unreachable_allow(rules: &hushspec::Rules, file: &str, findings: &mut Vec<LintFinding>) {
    if let Some(egress) = &rules.egress {
        let block_set: HashSet<&str> = egress.block.iter().map(|s| s.as_str()).collect();
        for (i, entry) in egress.allow.iter().enumerate() {
            if block_set.contains(entry.as_str()) {
                findings.push(LintFinding::keyed(
                    "L010",
                    "warning",
                    format!(
                        "rules.egress.allow[{i}] {:?} is also in the block list -- block takes precedence, allow entry is dead",
                        entry
                    ),
                    file,
                    format!("rules.egress.allow[{i}]"),
                ));
            }
        }
    }

    if let Some(tool_access) = &rules.tool_access {
        let block_set: HashSet<&str> = tool_access.block.iter().map(|s| s.as_str()).collect();
        for (i, entry) in tool_access.allow.iter().enumerate() {
            if block_set.contains(entry.as_str()) {
                findings.push(LintFinding::keyed(
                    "L010",
                    "warning",
                    format!(
                        "rules.tool_access.allow[{i}] {:?} is also in the block list -- block takes precedence, allow entry is dead",
                        entry
                    ),
                    file,
                    format!("rules.tool_access.allow[{i}]"),
                ));
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
