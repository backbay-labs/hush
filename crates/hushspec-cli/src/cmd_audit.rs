use clap::ValueEnum;
use colored::Colorize;
use hushspec::{HushSpec, validate_governance};
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct AuditArgs {
    /// Policy YAML file to audit
    #[arg(required = true)]
    file: PathBuf,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,

    /// Report the control -> rule-path matrix and rule-block coverage
    #[arg(long)]
    controls: bool,

    /// Exit non-zero when a governance check fails or a control rule path does
    /// not resolve (lint L012)
    #[arg(long)]
    strict: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(serde::Serialize)]
struct AuditReport {
    file: String,
    name: Option<String>,
    author: Option<String>,
    approved_by: Option<String>,
    approval_date: Option<String>,
    classification: Option<String>,
    lifecycle_state: Option<String>,
    policy_version: Option<usize>,
    change_ticket: Option<String>,
    effective_date: Option<String>,
    expiry_date: Option<String>,
    checks: Vec<AuditCheck>,
    /// Present only with `--controls`, so the default JSON shape is unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    controls: Option<ControlsReport>,
}

#[derive(serde::Serialize)]
struct AuditCheck {
    name: String,
    passed: bool,
    detail: Option<String>,
}

/// The control -> rule-path matrix for a policy, grouped by framework.
#[derive(serde::Serialize)]
struct ControlsReport {
    /// Version of `spec/registries/frameworks.yaml` this run was checked against.
    registry_version: String,
    frameworks: Vec<FrameworkControls>,
    coverage: Coverage,
}

#[derive(serde::Serialize)]
struct FrameworkControls {
    framework: String,
    /// `false` when the id is not in the framework registry (lint L013).
    registered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    controls: Vec<ControlRow>,
}

#[derive(serde::Serialize)]
struct ControlRow {
    control_id: String,
    /// `false` when the id does not match its framework's `control_id_pattern`.
    control_id_valid: bool,
    rule_paths: Vec<String>,
    /// Entries of `rule_paths` that point at nothing (lint L012).
    unresolved_rule_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
}

#[derive(serde::Serialize)]
struct Coverage {
    mapped_rule_blocks: usize,
    total_rule_blocks: usize,
    unmapped_rule_blocks: Vec<String>,
}

pub fn run(args: AuditArgs) -> i32 {
    if !args.file.exists() {
        eprintln!(
            "{} file not found: {}",
            "\u{2717}".red(),
            args.file.display()
        );
        return 2;
    }

    let content = match std::fs::read_to_string(&args.file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} failed to read file: {}", "\u{2717}".red(), e);
            return 2;
        }
    };

    let spec = match HushSpec::parse(&content) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} YAML parse error: {}", "\u{2717}".red(), e);
            return 1;
        }
    };

    let governance_warnings = validate_governance(&spec);
    let warning_codes: Vec<&str> = governance_warnings
        .iter()
        .map(|w| w.code.as_str())
        .collect();

    let metadata = spec.metadata.as_ref();

    let author = metadata.and_then(|m| m.author.clone());
    let approved_by = metadata.and_then(|m| m.approved_by.clone());
    let approval_date = metadata.and_then(|m| m.approval_date.clone());
    let classification = metadata.and_then(|m| {
        m.classification.as_ref().and_then(|c| {
            serde_json::to_value(c)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
        })
    });
    let lifecycle_state = metadata.and_then(|m| {
        m.lifecycle_state.as_ref().and_then(|s| {
            serde_json::to_value(s)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
        })
    });
    let policy_version = metadata.and_then(|m| m.policy_version);
    let change_ticket = metadata.and_then(|m| m.change_ticket.clone());
    let effective_date = metadata.and_then(|m| m.effective_date.clone());
    let expiry_date = metadata.and_then(|m| m.expiry_date.clone());

    let mut checks = Vec::new();

    checks.push(AuditCheck {
        name: "Has author".into(),
        passed: author.is_some(),
        detail: None,
    });

    checks.push(AuditCheck {
        name: "Has approver".into(),
        passed: approved_by.is_some(),
        detail: None,
    });

    checks.push(AuditCheck {
        name: "Has approval date".into(),
        passed: approval_date.is_some(),
        detail: if warning_codes.contains(&"GOV_MISSING_APPROVAL_DATE") {
            Some("approved_by set without approval_date".into())
        } else {
            None
        },
    });

    checks.push(AuditCheck {
        name: "Classification set".into(),
        passed: classification.is_some(),
        detail: None,
    });

    checks.push(AuditCheck {
        name: "Lifecycle state set".into(),
        passed: lifecycle_state.is_some(),
        detail: if warning_codes.contains(&"GOV_LIFECYCLE") {
            governance_warnings
                .iter()
                .find(|w| w.code == "GOV_LIFECYCLE")
                .map(|w| w.message.clone())
        } else {
            None
        },
    });

    checks.push(AuditCheck {
        name: "Policy version set".into(),
        passed: policy_version.is_some(),
        detail: None,
    });

    checks.push(AuditCheck {
        name: "Expiry date set".into(),
        passed: expiry_date.is_some(),
        detail: if warning_codes.contains(&"GOV_EXPIRED") {
            governance_warnings
                .iter()
                .find(|w| w.code == "GOV_EXPIRED")
                .map(|w| w.message.clone())
        } else {
            None
        },
    });

    checks.push(AuditCheck {
        name: "Restricted approval check".into(),
        passed: !warning_codes.contains(&"GOV_RESTRICTED_NO_APPROVER"),
        detail: if warning_codes.contains(&"GOV_RESTRICTED_NO_APPROVER") {
            Some("restricted classification requires approved_by".into())
        } else {
            None
        },
    });

    // Control mappings describe the *enforced* document, so coverage is
    // computed over the resolved `extends` chain, exactly as `h2h lint` does.
    // A chain that will not resolve is reported rather than silently falling
    // back to the leaf, which would invent uncovered rule blocks.
    let controls = if args.controls {
        let resolved = if spec.extends.is_some() {
            match hushspec::resolve_from_path_with_builtins(&args.file) {
                Ok(resolved) => resolved,
                Err(e) => {
                    eprintln!("{} failed to resolve extends: {e}", "\u{2717}".red());
                    return 1;
                }
            }
        } else {
            spec.clone()
        };
        Some(build_controls_report(&resolved))
    } else {
        None
    };

    let unresolved_paths = controls.as_ref().is_some_and(|report| {
        report
            .frameworks
            .iter()
            .flat_map(|framework| &framework.controls)
            .any(|control| !control.unresolved_rule_paths.is_empty())
    });
    let failed_checks = checks.iter().any(|check| !check.passed);

    let report = AuditReport {
        file: args.file.display().to_string(),
        name: spec.name.clone(),
        author,
        approved_by,
        approval_date,
        classification,
        lifecycle_state,
        policy_version,
        change_ticket,
        effective_date,
        expiry_date,
        checks,
        controls,
    };

    match args.format {
        OutputFormat::Text => print_text_report(&report),
        OutputFormat::Json => {
            if let Ok(json) = serde_json::to_string_pretty(&report) {
                println!("{json}");
            }
        }
    }

    // Governance is advisory -- without --strict the command always exits 0
    // regardless of check outcomes. --strict promotes a failed check, and an
    // unresolvable control rule path (lint L012), to a non-zero exit.
    if args.strict && (failed_checks || unresolved_paths) {
        1
    } else {
        0
    }
}

/// Build the control -> rule-path matrix for `spec`, grouped by framework in
/// first-appearance order (so the report reads in the order the policy author
/// wrote the mappings).
fn build_controls_report(spec: &HushSpec) -> ControlsReport {
    let doc = crate::controls::document_json(spec);
    let block_paths = crate::controls::rule_block_paths(&doc);
    let mappings = spec
        .metadata
        .as_ref()
        .map(|metadata| metadata.controls.as_slice())
        .unwrap_or_default();

    let mut frameworks: Vec<FrameworkControls> = Vec::new();
    for mapping in mappings {
        let unresolved: Vec<String> = mapping
            .rule_paths
            .iter()
            .filter(|path| !crate::controls::path_resolves(&doc, path))
            .cloned()
            .collect();
        let row = ControlRow {
            control_id: mapping.control_id.clone(),
            control_id_valid: !matches!(
                crate::controls::registry_verdict(&mapping.framework, &mapping.control_id),
                crate::controls::RegistryVerdict::ControlIdMismatch
            ),
            rule_paths: mapping.rule_paths.clone(),
            unresolved_rule_paths: unresolved,
            notes: mapping.notes.clone(),
        };

        match frameworks
            .iter_mut()
            .find(|group| group.framework == mapping.framework)
        {
            Some(group) => group.controls.push(row),
            None => {
                let registered = crate::generated_frameworks::framework(&mapping.framework);
                frameworks.push(FrameworkControls {
                    framework: mapping.framework.clone(),
                    registered: registered.is_some(),
                    name: registered.map(|entry| entry.name.to_string()),
                    version: registered.map(|entry| entry.version.to_string()),
                    url: registered.map(|entry| entry.url.to_string()),
                    controls: vec![row],
                });
            }
        }
    }

    let unmapped: Vec<String> = block_paths
        .iter()
        .filter(|block| {
            !mappings.iter().any(|mapping| {
                mapping
                    .rule_paths
                    .iter()
                    .any(|path| crate::controls::path_covers_block(path, block))
            })
        })
        .cloned()
        .collect();

    ControlsReport {
        registry_version: crate::generated_frameworks::REGISTRY_VERSION.to_string(),
        coverage: Coverage {
            mapped_rule_blocks: block_paths.len() - unmapped.len(),
            total_rule_blocks: block_paths.len(),
            unmapped_rule_blocks: unmapped,
        },
        frameworks,
    }
}

fn print_controls_report(report: &ControlsReport) {
    println!();
    println!(
        "{}  (registry {})",
        "Control mappings:".bold(),
        report.registry_version
    );

    if report.frameworks.is_empty() {
        println!("  (none declared)");
    }

    for framework in &report.frameworks {
        let heading = match (&framework.name, &framework.version) {
            (Some(name), Some(version)) => format!("{} -- {name} ({version})", framework.framework),
            _ => format!("{} -- unregistered framework", framework.framework),
        };
        println!();
        if framework.registered {
            println!("  {}", heading.bold());
        } else {
            println!("  {} {}", heading.bold(), "\u{26a0}".yellow());
        }

        let width = framework
            .controls
            .iter()
            .map(|control| control.control_id.chars().count())
            .max()
            .unwrap_or(0)
            .max("CONTROL".len());

        // Padded columns are written without color: a ColoredString pads to the
        // width of its escape sequences, not of its visible text.
        println!("    {:<width$}  RULE PATHS", "CONTROL");
        for control in &framework.controls {
            let id = if control.control_id_valid {
                control.control_id.clone()
            } else {
                format!("{} \u{26a0}", control.control_id)
            };
            println!("    {:<width$}  {}", id, control.rule_paths.join(", "));
            for path in &control.unresolved_rule_paths {
                println!(
                    "    {:<width$}  {}",
                    "",
                    format!("{path} does not resolve").red()
                );
            }
            if let Some(notes) = &control.notes {
                println!("    {:<width$}  {}", "", notes.dimmed());
            }
        }
    }

    println!();
    println!(
        "{}  {} of {} rule blocks mapped",
        "Coverage:".bold(),
        report.coverage.mapped_rule_blocks,
        report.coverage.total_rule_blocks
    );
    for block in &report.coverage.unmapped_rule_blocks {
        println!("  {} {block} has no control mapping", "\u{2717}".red());
    }
}

fn print_text_report(report: &AuditReport) {
    println!(
        "{}  {}",
        "Policy:".bold(),
        report.name.as_deref().unwrap_or("(unnamed)")
    );

    fn print_field(label: &str, value: &Option<String>) {
        if let Some(v) = value {
            println!("{}  {}", format!("{label}:").bold(), v);
        }
    }

    print_field("Author", &report.author);
    print_field("Approved by", &report.approved_by);
    print_field("Approval date", &report.approval_date);
    print_field("Classification", &report.classification);
    print_field("Lifecycle", &report.lifecycle_state);
    print_field(
        "Policy version",
        &report.policy_version.map(|v| v.to_string()),
    );
    print_field("Change ticket", &report.change_ticket);
    print_field("Effective date", &report.effective_date);
    print_field("Expiry date", &report.expiry_date);

    println!();
    println!("{}", "Governance checks:".bold());
    for check in &report.checks {
        if check.passed {
            print!("  {} {}", "\u{2713}".green(), check.name);
        } else {
            print!("  {} {}", "\u{2717}".red(), check.name);
        }
        if let Some(detail) = &check.detail {
            print!(" ({})", detail.yellow());
        }
        println!();
    }

    if let Some(controls) = &report.controls {
        print_controls_report(controls);
    }
}
