use crate::schema::HushSpec;
use crate::version;
use regex::Regex;
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
    #[error("unsupported hushspec version: {0}")]
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

    for gw in crate::governance::validate_governance(spec) {
        warnings.push(gw.message);
    }

    ValidationResult { errors, warnings }
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
        if patch_integrity.max_imbalance_ratio <= 0.0 {
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
                    && !contains_allowed_value(
                        space_type,
                        crate::generated_contract::ORIGIN_SPACE_TYPES,
                    )
                {
                    errors.push(ValidationError::Custom(format!(
                        "origins.profiles[{index}].match.space_type '{space_type}' is not valid"
                    )));
                }

                if let Some(visibility) = &match_rules.visibility
                    && !contains_allowed_value(
                        visibility,
                        crate::generated_contract::ORIGIN_VISIBILITIES,
                    )
                {
                    errors.push(ValidationError::Custom(format!(
                        "origins.profiles[{index}].match.visibility '{visibility}' is not valid"
                    )));
                }
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
                        && !contains_allowed_value(
                            space_type,
                            crate::generated_contract::ORIGIN_SPACE_TYPES,
                        )
                    {
                        errors.push(ValidationError::Custom(format!(
                            "origins.profiles[{index}].bridge.allowed_targets[{target_index}].space_type '{space_type}' is not valid"
                        )));
                    }

                    if let Some(visibility) = &target.visibility
                        && !contains_allowed_value(
                            visibility,
                            crate::generated_contract::ORIGIN_VISIBILITIES,
                        )
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
            if let Some(similarity_threshold) = threat_intel.similarity_threshold
                && !(0.0..=1.0).contains(&similarity_threshold)
            {
                errors.push(ValidationError::Custom(
                    "detection.threat_intel.similarity_threshold must be between 0.0 and 1.0"
                        .to_string(),
                ));
            }
            if matches!(threat_intel.top_k, Some(0)) {
                errors.push(ValidationError::Custom(
                    "detection.threat_intel.top_k must be >= 1".to_string(),
                ));
            }
        }
    }
}

fn validate_regex(pattern: &str, path: &str, errors: &mut Vec<ValidationError>) {
    // RE2-feature check first: the `regex` crate rejects non-RE2 features
    // (backreferences, lookaround, ...) at compile time.
    if let Err(error) = Regex::new(pattern) {
        errors.push(ValidationError::InvalidRegex {
            field: path.to_string(),
            pattern: pattern.to_string(),
            message: error.to_string(),
        });
        return;
    }

    // Nested-quantifier check second: RE2 tolerates shapes like `(a+)+` that
    // catastrophically backtrack on the backtracking SDK engines, so reject them
    // here to keep the safety contract identical across all four SDKs.
    if has_nested_quantifier(pattern) {
        errors.push(ValidationError::InvalidRegex {
            field: path.to_string(),
            pattern: pattern.to_string(),
            message: "pattern contains a nested unbounded quantifier (e.g. (a+)+) \
                      that can cause catastrophic backtracking (ReDoS)"
                .to_string(),
        });
    }
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
fn has_nested_quantifier(pattern: &str) -> bool {
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

fn contains_allowed_value(value: &str, allowed: &[&str]) -> bool {
    allowed.contains(&value)
}
