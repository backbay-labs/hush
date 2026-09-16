use crate::regex_profile::compile_profile_regex;
use crate::schema::HushSpec;
use crate::version;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ValidationError {
    #[error(
        "unsupported hushspec version: {0} (this engine accepts minor versions {minors})",
        minors = version::HUSHSPEC_SUPPORTED_MINORS.join(", ")
    )]
    UnsupportedVersion(String),
    #[error("duplicate secret pattern name: {0}")]
    DuplicatePatternName(String),
    /// Regex is rejected as ReDoS-unsafe. Either it uses features outside the RE2
    /// subset (backreferences, lookahead, etc.) -- rejected by the `regex` crate's
    /// RE2 semantics -- or it contains a nested unbounded quantifier (e.g. `(a+)+`)
    /// that catastrophically backtracks on the backtracking SDK engines (JavaScript
    /// `RegExp`, Python `re`). Any accepted pattern is safe across all HushSpec SDKs.
    #[error("{field}: invalid regex pattern {pattern:?}: {message}")]
    InvalidRegex {
        field: String,
        pattern: String,
        message: String,
    },
    /// A governance date field that is not an ISO 8601 calendar date
    /// (`YYYY-MM-DD`). Dates are compared as strings throughout the toolchain,
    /// so a value in any other shape would silently compare wrong rather than
    /// fail -- an expired policy could read as current.
    #[error("{field}: {value:?} is not an ISO 8601 date (YYYY-MM-DD)")]
    InvalidDate { field: String, value: String },
    #[error("{0}")]
    Custom(String),
}

#[must_use = "validation result should be checked"]
pub fn validate(spec: &HushSpec) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    if !version::is_supported(&spec.hushspec) {
        errors.push(ValidationError::UnsupportedVersion(spec.hushspec.clone()));
    }

    if spec.name.as_deref() == Some("") && requires_non_empty_name(&spec.hushspec) {
        errors.push(ValidationError::Custom(
            "name: must not be empty when present".to_string(),
        ));
    }

    if let Some(rules) = &spec.rules {
        validate_rules(rules, &mut errors);

        if rules.forbidden_paths.is_none()
            && rules.path_allowlist.is_none()
            && rules.egress.is_none()
            && rules.secret_patterns.is_none()
            && rules.patch_integrity.is_none()
            && rules.shell_commands.is_none()
            && rules.tool_access.is_none()
            && rules.computer_use.is_none()
            && rules.remote_desktop_channels.is_none()
            && rules.input_injection.is_none()
            && rules.browser_automation.is_none()
            && rules.code_execution.is_none()
        {
            warnings.push("no rules configured".to_string());
        }
    } else {
        warnings.push("no rules section present".to_string());
    }

    if let Some(ext) = &spec.extensions {
        validate_posture(ext, &mut errors, &mut warnings);
        validate_origins(ext, &mut errors);
        validate_detection(ext, &mut errors, &mut warnings);
    }

    if let Some(metadata) = &spec.metadata {
        validate_control_mappings(&metadata.controls, &mut errors);
        validate_metadata_dates(metadata, &mut errors);
    }

    for finding in crate::governance::validate_governance(spec) {
        match finding.severity {
            crate::governance::GovernanceSeverity::Error => {
                errors.push(ValidationError::Custom(finding.message));
            }
            crate::governance::GovernanceSeverity::Warning => warnings.push(finding.message),
        }
    }

    ValidationResult { errors, warnings }
}

/// Whether a document declaring `version` must give a present `name` a
/// non-empty value.
///
/// This is the one constraint the 1.0 document format adds to 0.2
/// (spec/versioning.md section 10): the frozen 0.x format allows `name: ""`.
/// A version this engine cannot read as `MAJOR.MINOR.PATCH` is already refused
/// as unsupported, and is held to the current format's constraints here so an
/// unreadable version can never relax one.
fn requires_non_empty_name(version: &str) -> bool {
    version::major_version(version).is_none_or(|major| major >= 1)
}

fn validate_rules(rules: &crate::rules::Rules, errors: &mut Vec<ValidationError>) {
    if let Some(secret_patterns) = &rules.secret_patterns {
        let mut seen = HashSet::new();
        for pattern in &secret_patterns.patterns {
            if !seen.insert(&pattern.name) {
                errors.push(ValidationError::DuplicatePatternName(pattern.name.clone()));
            }
            validate_regex(
                &pattern.pattern,
                &format!("secret_patterns.patterns.{}", pattern.name),
                errors,
            );
        }
    }

    if let Some(patch_integrity) = &rules.patch_integrity {
        if !patch_integrity.max_imbalance_ratio.is_finite() {
            // Reject NaN/±Inf first (fail-closed): a non-finite ratio slips past
            // the `<= 0` check below (every NaN comparison is false) and then
            // makes `require_balance` fail OPEN, since `ratio > NaN` is always
            // false.
            errors.push(ValidationError::Custom(
                "rules.patch_integrity.max_imbalance_ratio must be a finite number".to_string(),
            ));
        } else if patch_integrity.max_imbalance_ratio <= 0.0 {
            errors.push(ValidationError::Custom(
                "rules.patch_integrity.max_imbalance_ratio must be > 0".to_string(),
            ));
        }
        for (index, pattern) in patch_integrity.forbidden_patterns.iter().enumerate() {
            validate_regex(
                pattern,
                &format!("rules.patch_integrity.forbidden_patterns[{index}]"),
                errors,
            );
        }
    }

    if let Some(shell_commands) = &rules.shell_commands {
        for (index, pattern) in shell_commands.forbidden_patterns.iter().enumerate() {
            validate_regex(
                pattern,
                &format!("rules.shell_commands.forbidden_patterns[{index}]"),
                errors,
            );
        }
    }

    if let Some(tool_access) = &rules.tool_access
        && matches!(tool_access.max_args_size, Some(0))
    {
        errors.push(ValidationError::Custom(
            "rules.tool_access.max_args_size must be >= 1".to_string(),
        ));
    }

    if let Some(browser) = &rules.browser_automation {
        for (index, pattern) in browser.extra_credential_patterns.iter().enumerate() {
            validate_regex(
                pattern,
                &format!("rules.browser_automation.extra_credential_patterns[{index}]"),
                errors,
            );
        }
    }

    if let Some(code) = &rules.code_execution
        && matches!(code.max_scan_bytes, Some(0))
    {
        errors.push(ValidationError::Custom(
            "rules.code_execution.max_scan_bytes must be >= 1".to_string(),
        ));
    }

    validate_conditions(rules, errors);
}

/// Validate every rule block's `when` condition (core spec 3.13, 7.10).
fn validate_conditions(rules: &crate::rules::Rules, errors: &mut Vec<ValidationError>) {
    let blocks: [(&str, Option<&crate::conditions::Condition>); 12] = [
        (
            "forbidden_paths",
            rules.forbidden_paths.as_ref().and_then(|r| r.when.as_ref()),
        ),
        (
            "path_allowlist",
            rules.path_allowlist.as_ref().and_then(|r| r.when.as_ref()),
        ),
        (
            "egress",
            rules.egress.as_ref().and_then(|r| r.when.as_ref()),
        ),
        (
            "secret_patterns",
            rules.secret_patterns.as_ref().and_then(|r| r.when.as_ref()),
        ),
        (
            "patch_integrity",
            rules.patch_integrity.as_ref().and_then(|r| r.when.as_ref()),
        ),
        (
            "shell_commands",
            rules.shell_commands.as_ref().and_then(|r| r.when.as_ref()),
        ),
        (
            "tool_access",
            rules.tool_access.as_ref().and_then(|r| r.when.as_ref()),
        ),
        (
            "computer_use",
            rules.computer_use.as_ref().and_then(|r| r.when.as_ref()),
        ),
        (
            "remote_desktop_channels",
            rules
                .remote_desktop_channels
                .as_ref()
                .and_then(|r| r.when.as_ref()),
        ),
        (
            "input_injection",
            rules.input_injection.as_ref().and_then(|r| r.when.as_ref()),
        ),
        (
            "browser_automation",
            rules
                .browser_automation
                .as_ref()
                .and_then(|r| r.when.as_ref()),
        ),
        (
            "code_execution",
            rules.code_execution.as_ref().and_then(|r| r.when.as_ref()),
        ),
    ];
    for (name, condition) in blocks {
        if let Some(condition) = condition {
            for message in
                crate::conditions::validate_condition(condition, &format!("rules.{name}.when"))
            {
                errors.push(ValidationError::Custom(message));
            }
        }
    }
}

fn validate_posture(
    ext: &crate::extensions::Extensions,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<String>,
) {
    if let Some(posture) = &ext.posture {
        if posture.states.is_empty() {
            errors.push(ValidationError::Custom(
                "posture.states must define at least one state".to_string(),
            ));
        }

        if !posture.states.contains_key(&posture.initial) {
            errors.push(ValidationError::Custom(format!(
                "posture.initial '{}' does not reference a defined state",
                posture.initial
            )));
        }

        for (state_name, state) in &posture.states {
            for capability in &state.capabilities {
                if !matches!(
                    capability.as_str(),
                    "file_access"
                        | "file_write"
                        | "egress"
                        | "shell"
                        | "tool_call"
                        | "patch"
                        | "custom"
                ) {
                    warnings.push(format!(
                        "posture.states.{state_name}.capabilities includes unknown capability '{capability}'"
                    ));
                }
            }

            for (budget_key, &value) in &state.budgets {
                if value < 0 {
                    errors.push(ValidationError::Custom(format!(
                        "posture.states.{state_name}.budgets.{budget_key} must be non-negative, got {value}"
                    )));
                }
                if !matches!(
                    budget_key.as_str(),
                    "file_writes"
                        | "egress_calls"
                        | "shell_commands"
                        | "tool_calls"
                        | "patches"
                        | "custom_calls"
                ) {
                    warnings.push(format!(
                        "posture.states.{state_name}.budgets uses unknown budget key '{budget_key}'"
                    ));
                }
            }
        }

        for (index, transition) in posture.transitions.iter().enumerate() {
            if transition.from != "*" && !posture.states.contains_key(&transition.from) {
                errors.push(ValidationError::Custom(format!(
                    "posture.transitions[{index}].from '{}' does not reference a defined state",
                    transition.from
                )));
            }
            if transition.to == "*" {
                errors.push(ValidationError::Custom(format!(
                    "posture.transitions[{index}].to cannot be '*'"
                )));
            } else if !posture.states.contains_key(&transition.to) {
                errors.push(ValidationError::Custom(format!(
                    "posture.transitions[{index}].to '{}' does not reference a defined state",
                    transition.to
                )));
            }

            if transition.on != crate::extensions::TransitionTrigger::Timeout
                && let Some(after) = &transition.after
                && !is_valid_duration(after)
            {
                errors.push(ValidationError::Custom(format!(
                    "posture.transitions[{index}].after must match ^\\d+[smhd]$"
                )));
            }

            if transition.on == crate::extensions::TransitionTrigger::Timeout {
                match transition.after.as_deref() {
                    Some(after) if is_valid_duration(after) => {}
                    Some(_) => errors.push(ValidationError::Custom(format!(
                        "posture.transitions[{index}].after must match ^\\d+[smhd]$"
                    ))),
                    None => errors.push(ValidationError::Custom(format!(
                        "posture.transitions[{index}]: timeout trigger requires 'after' field"
                    ))),
                }
            }
        }
    }
}

fn validate_origins(ext: &crate::extensions::Extensions, errors: &mut Vec<ValidationError>) {
    if let Some(origins) = &ext.origins {
        let mut seen_ids = HashSet::new();
        let posture_states = ext.posture.as_ref().map(|posture| {
            posture
                .states
                .keys()
                .map(String::as_str)
                .collect::<HashSet<_>>()
        });

        for (index, profile) in origins.profiles.iter().enumerate() {
            if !seen_ids.insert(&profile.id) {
                errors.push(ValidationError::Custom(format!(
                    "duplicate origin profile id: '{}'",
                    profile.id
                )));
            }

            if let Some(match_rules) = &profile.match_rules {
                if let Some(space_type) = &match_rules.space_type
                    && !crate::generated_contract::ORIGIN_SPACE_TYPES.contains(&space_type.as_str())
                {
                    errors.push(ValidationError::Custom(format!(
                        "origins.profiles[{index}].match.space_type '{space_type}' is not valid"
                    )));
                }

                if let Some(visibility) = &match_rules.visibility
                    && !crate::generated_contract::ORIGIN_VISIBILITIES
                        .contains(&visibility.as_str())
                {
                    errors.push(ValidationError::Custom(format!(
                        "origins.profiles[{index}].match.visibility '{visibility}' is not valid"
                    )));
                }

                // A present-but-empty free-text match field (e.g. `provider: ""`)
                // is an unsatisfiable constraint: no origin carries an empty
                // provider or tenant. The enum fields above already reject ""
                // as an invalid enum value.
                for (field_name, value) in [
                    ("provider", &match_rules.provider),
                    ("tenant_id", &match_rules.tenant_id),
                    ("space_id", &match_rules.space_id),
                    ("sensitivity", &match_rules.sensitivity),
                    ("actor_role", &match_rules.actor_role),
                ] {
                    if let Some(value) = value
                        && value.is_empty()
                    {
                        errors.push(ValidationError::Custom(format!(
                            "origins.profiles[{index}].match.{field_name} must not be empty"
                        )));
                    }
                }
            }

            if let Some(overlay) = &profile.tool_access
                && matches!(overlay.max_args_size, Some(0))
            {
                errors.push(ValidationError::Custom(format!(
                    "origins.profiles[{index}].tool_access.max_args_size must be >= 1"
                )));
            }

            if let Some(posture_state) = &profile.posture {
                match &posture_states {
                    Some(states) if states.contains(posture_state.as_str()) => {}
                    Some(_) => errors.push(ValidationError::Custom(format!(
                        "origins.profiles[{index}].posture '{}' does not reference a defined posture state",
                        posture_state
                    ))),
                    None => errors.push(ValidationError::Custom(format!(
                        "origins.profiles[{index}].posture requires extensions.posture to be defined"
                    ))),
                }
            }

            if let Some(bridge) = &profile.bridge {
                for (target_index, target) in bridge.allowed_targets.iter().enumerate() {
                    if let Some(space_type) = &target.space_type
                        && !crate::generated_contract::ORIGIN_SPACE_TYPES
                            .contains(&space_type.as_str())
                    {
                        errors.push(ValidationError::Custom(format!(
                            "origins.profiles[{index}].bridge.allowed_targets[{target_index}].space_type '{space_type}' is not valid"
                        )));
                    }

                    if let Some(visibility) = &target.visibility
                        && !crate::generated_contract::ORIGIN_VISIBILITIES
                            .contains(&visibility.as_str())
                    {
                        errors.push(ValidationError::Custom(format!(
                            "origins.profiles[{index}].bridge.allowed_targets[{target_index}].visibility '{visibility}' is not valid"
                        )));
                    }
                }
            }
        }
    }
}

fn validate_detection(
    ext: &crate::extensions::Extensions,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<String>,
) {
    if let Some(detection) = &ext.detection {
        if let Some(prompt_injection) = &detection.prompt_injection {
            if matches!(prompt_injection.max_scan_bytes, Some(0)) {
                errors.push(ValidationError::Custom(
                    "detection.prompt_injection.max_scan_bytes must be >= 1".to_string(),
                ));
            }

            let warn_level = prompt_injection
                .warn_at_or_above
                .unwrap_or(crate::extensions::DetectionLevel::Suspicious);
            let block_level = prompt_injection
                .block_at_or_above
                .unwrap_or(crate::extensions::DetectionLevel::High);
            if block_level < warn_level {
                warnings.push(
                    "detection.prompt_injection: block_at_or_above is less strict than warn_at_or_above"
                        .to_string(),
                );
            }
        }

        if let Some(jailbreak) = &detection.jailbreak {
            if matches!(jailbreak.block_threshold, Some(value) if value > 100) {
                errors.push(ValidationError::Custom(
                    "detection.jailbreak.block_threshold must be between 0 and 100".to_string(),
                ));
            }
            if matches!(jailbreak.warn_threshold, Some(value) if value > 100) {
                errors.push(ValidationError::Custom(
                    "detection.jailbreak.warn_threshold must be between 0 and 100".to_string(),
                ));
            }
            if matches!(jailbreak.max_input_bytes, Some(0)) {
                errors.push(ValidationError::Custom(
                    "detection.jailbreak.max_input_bytes must be >= 1".to_string(),
                ));
            }

            let block_threshold = jailbreak.block_threshold.unwrap_or(80);
            let warn_threshold = jailbreak.warn_threshold.unwrap_or(50);
            if block_threshold < warn_threshold {
                warnings.push(
                    "detection.jailbreak: block_threshold is lower than warn_threshold".to_string(),
                );
            }
        }

        if let Some(threat_intel) = &detection.threat_intel {
            if let Some(similarity_threshold) = threat_intel.similarity_threshold {
                if !similarity_threshold.is_finite() {
                    // Reject NaN/±Inf first (fail-closed): a non-finite value
                    // only lands in the range branch by accident of NaN
                    // comparison semantics, and ±Inf would otherwise report a
                    // misleading "between 0.0 and 1.0" error.
                    errors.push(ValidationError::Custom(
                        "detection.threat_intel.similarity_threshold must be a finite number"
                            .to_string(),
                    ));
                } else if !(0.0..=1.0).contains(&similarity_threshold) {
                    errors.push(ValidationError::Custom(
                        "detection.threat_intel.similarity_threshold must be between 0.0 and 1.0"
                            .to_string(),
                    ));
                }
            }
            if matches!(threat_intel.top_k, Some(0)) {
                errors.push(ValidationError::Custom(
                    "detection.threat_intel.top_k must be >= 1".to_string(),
                ));
            }
        }
    }
}

/// Structural checks for `metadata.controls` (core spec 2.5).
///
/// Control mappings are declarative governance metadata and never influence
/// evaluation, but a malformed mapping is still a rejected document: the
/// framework id must match the registry's id grammar, the control id must be
/// non-empty, and the mapping must name at least one rule path. Whether the
/// framework is *registered*, and whether its paths *resolve*, are semantic
/// questions answered by `h2h lint` (L012, L013) rather than by the SDK
/// validators -- that keeps `spec/registries/frameworks.yaml` out of the four
/// SDKs.
fn validate_control_mappings(
    controls: &[crate::generated_models::ControlMapping],
    errors: &mut Vec<ValidationError>,
) {
    for (index, control) in controls.iter().enumerate() {
        let path = format!("metadata.controls[{index}]");

        if !is_framework_id(&control.framework) {
            errors.push(ValidationError::Custom(format!(
                "{path}.framework {:?} must match ^[a-z0-9][a-z0-9.-]*$",
                control.framework
            )));
        }

        if control.control_id.is_empty() {
            errors.push(ValidationError::Custom(format!(
                "{path}.control_id must not be empty"
            )));
        }

        if control.rule_paths.is_empty() {
            errors.push(ValidationError::Custom(format!(
                "{path}.rule_paths must list at least one rule path"
            )));
        }

        for (entry, rule_path) in control.rule_paths.iter().enumerate() {
            if rule_path.is_empty() {
                errors.push(ValidationError::Custom(format!(
                    "{path}.rule_paths[{entry}] must not be empty"
                )));
            }
        }
    }
}

/// Every governance date field must be an ISO 8601 calendar date (core spec
/// 2.5). The whole toolchain compares these dates as strings -- lexicographic
/// order is calendar order only for `YYYY-MM-DD` -- so an unchecked
/// `01/02/2026` would make an expired policy compare as current instead of
/// failing loudly.
fn validate_metadata_dates(
    metadata: &crate::generated_models::GovernanceMetadata,
    errors: &mut Vec<ValidationError>,
) {
    let fields = [
        ("metadata.approval_date", &metadata.approval_date),
        ("metadata.effective_date", &metadata.effective_date),
        ("metadata.expiry_date", &metadata.expiry_date),
        ("metadata.next_review_date", &metadata.next_review_date),
    ];

    for (field, value) in fields {
        if let Some(value) = value
            && crate::governance::parse_iso_date(value).is_none()
        {
            errors.push(ValidationError::InvalidDate {
                field: field.to_string(),
                value: value.clone(),
            });
        }
    }

    for (index, entry) in metadata.changelog.iter().enumerate() {
        if crate::governance::parse_iso_date(&entry.date).is_none() {
            errors.push(ValidationError::InvalidDate {
                field: format!("metadata.changelog[{index}].date"),
                value: entry.date.clone(),
            });
        }
    }
}

/// `^[a-z0-9][a-z0-9.-]*$`, spelled out so the check needs no regex engine.
fn is_framework_id(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
}

fn validate_regex(pattern: &str, path: &str, errors: &mut Vec<ValidationError>) {
    // Portability pre-check first: reject constructs that are unsupported by, or
    // behave differently across, the four SDK regex engines (possessive
    // quantifiers, `\Z`/`\z` end-anchors, empty character classes) so a pattern
    // validates identically everywhere, regardless of what any single engine
    // does with them. The HushSpec regex profile check follows it.
    if let Some(message) = disallowed_regex_feature(pattern) {
        errors.push(ValidationError::InvalidRegex {
            field: path.to_string(),
            pattern: pattern.to_string(),
            message: message.to_string(),
        });
        return;
    }

    // Profile check second: `compile_profile_regex` applies the HushSpec regex
    // profile (ASCII `\d`/`\w`/`\s`/`\b`, leading-only inline flags, portable
    // escapes) and then compiles, so the `regex` crate's own rejection of
    // non-RE2 features (backreferences, lookaround, ...) comes for free. This
    // is the *same* call the evaluator makes, so a pattern that validates here
    // can never fail to compile at evaluation time -- and vice versa.
    if let Err(error) = compile_profile_regex(pattern) {
        errors.push(ValidationError::InvalidRegex {
            field: path.to_string(),
            pattern: pattern.to_string(),
            message: error.message().to_string(),
        });
        return;
    }

    // Nested-quantifier check third: RE2 tolerates shapes like `(a+)+` that
    // catastrophically backtrack on the backtracking SDK engines, so reject them
    // here to keep the safety contract identical across all four SDKs.
    if has_nested_quantifier(pattern) {
        errors.push(ValidationError::InvalidRegex {
            field: path.to_string(),
            pattern: pattern.to_string(),
            message: crate::regex_profile::NESTED_QUANTIFIER_MESSAGE.to_string(),
        });
    }
}

/// Shared rejection message for possessive quantifiers.
const POSSESSIVE_MESSAGE: &str = "possessive quantifiers (*+, ++, ?+, {n}+, {n,}+, {n,m}+) are not portable \
     across the HushSpec SDK regex engines";

/// Portability pre-check: reject regex constructs that are unsupported by, or
/// behave differently across, the four SDK engines so a pattern validates
/// identically everywhere. Scanning outside character classes and honoring
/// `\`-escapes, it rejects:
///   * possessive quantifiers `*+`, `++`, `?+` and possessive braces `{n}+`,
///     `{n,}+`, `{n,m}+` (Rust's `regex` silently downgrades possessive to
///     greedy; JavaScript `RegExp` and Go RE2 reject them at compile time),
///   * `\Z` and `\z` end-anchors (Rust/Python/Go accept them with differing
///     semantics; JavaScript reads `\Z`/`\z` as a literal letter -- users
///     anchor with `$`),
///   * empty character classes `[]` and `[^]` (JavaScript accepts them; the
///     others reject them).
///
/// Must stay byte-identical to the TypeScript, Python, and Go implementations.
pub(crate) fn disallowed_regex_feature(pattern: &str) -> Option<&'static str> {
    let chars: Vec<char> = pattern.chars().collect();
    let n = chars.len();
    let mut in_class = false;
    let mut i = 0;
    while i < n {
        let c = chars[i];
        if c == '\\' {
            // `\Z` / `\z` are end-anchors only outside a character class; inside
            // one they are an escaped literal letter, so ignore them there.
            if !in_class && i + 1 < n && matches!(chars[i + 1], 'Z' | 'z') {
                return Some(
                    "\\Z and \\z end-anchors are not portable across the HushSpec SDK regex \
                     engines; anchor with $",
                );
            }
            i += 2; // skip the escaped char
            continue;
        }
        if in_class {
            if c == ']' {
                in_class = false;
            }
            i += 1;
            continue;
        }
        match c {
            '[' => {
                // Empty class `[]` or negated-empty `[^]` (JS matches
                // none/any; the other engines reject the bare form).
                let mut j = i + 1;
                if j < n && chars[j] == '^' {
                    j += 1;
                }
                if j < n && chars[j] == ']' {
                    return Some(
                        "empty character classes [] and [^] are not portable across the \
                         HushSpec SDK regex engines",
                    );
                }
                in_class = true;
                i += 1;
            }
            '*' | '+' | '?' => {
                // A quantifier immediately followed by `+` is possessive.
                if i + 1 < n && chars[i + 1] == '+' {
                    return Some(POSSESSIVE_MESSAGE);
                }
                i += 1;
            }
            '{' => {
                // Treat `{...}` as a quantifier only when it parses as one; a
                // literal `{` is scanned through. A quantifier brace followed by
                // `+` is possessive (`{n}+`, `{n,}+`, `{n,m}+`).
                let mut j = i + 1;
                while j < n && chars[j] != '}' {
                    j += 1;
                }
                if j < n {
                    let inner: String = chars[i + 1..j].iter().collect();
                    if brace_kind(&inner) != QuantKind::None {
                        if j + 1 < n && chars[j + 1] == '+' {
                            return Some(POSSESSIVE_MESSAGE);
                        }
                        i = j + 1;
                        continue;
                    }
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

#[derive(PartialEq, Eq)]
enum QuantKind {
    None,
    Bounded,
    Unbounded,
}

/// Fail-closed over-approximation that flags nested unbounded quantifiers such
/// as `(a+)+`, `([0-9]+)*`, or `((ab)+)+`. Scans `(`...`)` group nesting --
/// ignoring escaped parens and character-class contents -- and rejects when a
/// group whose body contains an unbounded quantifier (`*`, `+`, `{n,}`) is
/// itself immediately followed by an unbounded quantifier. Bounded quantifiers
/// (`(a{1,3}){1,3}`, `(abc)+`) are accepted. Must stay identical to the
/// TypeScript, Python, and Go implementations.
pub(crate) fn has_nested_quantifier(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    let n = chars.len();
    // Per open group: whether its body has seen an unbounded quantifier.
    let mut stack: Vec<bool> = Vec::new();
    let mut in_class = false;
    let mut i = 0;
    while i < n {
        let c = chars[i];
        if c == '\\' {
            // Escaped char (e.g. `\(`, `\)`, `\[`, `\+`) -- skip both.
            i += 2;
            continue;
        }
        if in_class {
            if c == ']' {
                in_class = false;
            }
            i += 1;
            continue;
        }
        match c {
            '[' => {
                in_class = true;
                i += 1;
            }
            '(' => {
                stack.push(false);
                i += 1;
            }
            ')' => {
                let closed_unbounded = stack.pop().unwrap_or(false);
                let (kind, qlen) = classify_quantifier(&chars, i + 1);
                if kind == QuantKind::Unbounded {
                    if closed_unbounded {
                        return true;
                    }
                    // The just-closed group is unbounded-quantified, so it is an
                    // unbounded quantifier within the parent group's body.
                    if let Some(top) = stack.last_mut() {
                        *top = true;
                    }
                    i += 1 + qlen;
                } else {
                    i += 1;
                }
            }
            _ => {
                let (kind, qlen) = classify_quantifier(&chars, i);
                match kind {
                    QuantKind::Unbounded => {
                        if let Some(top) = stack.last_mut() {
                            *top = true;
                        }
                        i += qlen;
                    }
                    QuantKind::Bounded => i += qlen,
                    QuantKind::None => i += 1,
                }
            }
        }
    }
    false
}

/// Classify the quantifier token starting at `pos`, returning its kind and the
/// number of chars it spans (including any trailing lazy/possessive marker).
fn classify_quantifier(chars: &[char], pos: usize) -> (QuantKind, usize) {
    if pos >= chars.len() {
        return (QuantKind::None, 0);
    }
    match chars[pos] {
        '*' | '+' => (
            QuantKind::Unbounded,
            1 + usize::from(marker_follows(chars, pos + 1)),
        ),
        '?' => (
            QuantKind::Bounded,
            1 + usize::from(marker_follows(chars, pos + 1)),
        ),
        '{' => {
            let mut j = pos + 1;
            while j < chars.len() && chars[j] != '}' {
                j += 1;
            }
            if j >= chars.len() {
                return (QuantKind::None, 0); // unterminated `{` -> literal
            }
            let inner: String = chars[pos + 1..j].iter().collect();
            match brace_kind(&inner) {
                QuantKind::None => (QuantKind::None, 0),
                kind => (
                    kind,
                    (j - pos + 1) + usize::from(marker_follows(chars, j + 1)),
                ),
            }
        }
        _ => (QuantKind::None, 0),
    }
}

fn marker_follows(chars: &[char], pos: usize) -> bool {
    pos < chars.len() && (chars[pos] == '?' || chars[pos] == '+')
}

/// Classify the content between `{` and `}`: `{n,}` is unbounded, `{n}` and
/// `{n,m}` are bounded, anything else is a literal brace (not a quantifier).
fn brace_kind(inner: &str) -> QuantKind {
    if inner.is_empty() {
        return QuantKind::None;
    }
    let commas = inner.matches(',').count();
    if commas == 0 {
        return if inner.bytes().all(|b| b.is_ascii_digit()) {
            QuantKind::Bounded
        } else {
            QuantKind::None
        };
    }
    if commas == 1 {
        let (lo, hi) = inner.split_once(',').unwrap();
        let lo_ok = lo.is_empty() || lo.bytes().all(|b| b.is_ascii_digit());
        let hi_ok = hi.is_empty() || hi.bytes().all(|b| b.is_ascii_digit());
        if !lo_ok || !hi_ok || (lo.is_empty() && hi.is_empty()) {
            return QuantKind::None;
        }
        return if hi.is_empty() {
            QuantKind::Unbounded
        } else {
            QuantKind::Bounded
        };
    }
    QuantKind::None
}

fn is_valid_duration(value: &str) -> bool {
    matches!(
        value.as_bytes(),
        [b'0'..=b'9', .., b's' | b'm' | b'h' | b'd']
    ) && value[..value.len() - 1]
        .bytes()
        .all(|byte| byte.is_ascii_digit())
}
