use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::evaluate::{Decision, EvaluationAction, EvaluationResult, evaluate};
use crate::extensions::DetectionLevel;
use crate::schema::HushSpec;

/// Result from a single detector run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetectionResult {
    pub detector_name: String,
    pub category: DetectionCategory,
    /// Aggregate risk score in 0.0..=1.0.
    pub score: f64,
    pub matched_patterns: Vec<MatchedPattern>,
    pub explanation: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionCategory {
    PromptInjection,
    Jailbreak,
    DataExfiltration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatchedPattern {
    pub name: String,
    /// Contribution to the aggregate score.
    pub weight: f64,
    pub matched_text: Option<String>,
}

/// Implement this trait for custom detection backends.
pub trait Detector: Send + Sync {
    fn name(&self) -> &str;
    fn category(&self) -> DetectionCategory;
    fn detect(&self, input: &str) -> DetectionResult;
}

/// Holds a set of detectors and runs them all against input.
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    pub fn register(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(RegexInjectionDetector::new()));
        registry.register(Box::new(RegexJailbreakDetector::new()));
        registry.register(Box::new(RegexExfiltrationDetector::new()));
        registry
    }

    pub fn detect_all(&self, input: &str) -> Vec<DetectionResult> {
        self.detectors.iter().map(|d| d.detect(input)).collect()
    }

    /// Return the first registered detector whose category matches, if any.
    ///
    /// The spec-driven `evaluate_with_detection` uses this to run a single
    /// category's detector against its own byte budget, rather than
    /// `detect_all`, which scans every detector over one shared input.
    pub fn detector_for(&self, category: DetectionCategory) -> Option<&dyn Detector> {
        self.detectors
            .iter()
            .find(|detector| detector.category() == category)
            .map(|detector| &**detector)
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// A compiled detection pattern used by regex-based detectors.
struct DetectionPattern {
    name: String,
    regex: Regex,
    weight: f64,
}

/// Regex-based prompt injection detector.
///
/// Patterns are compiled once at construction time.
pub struct RegexInjectionDetector {
    patterns: Vec<DetectionPattern>,
}

impl RegexInjectionDetector {
    pub fn new() -> Self {
        let patterns = vec![
            DetectionPattern {
                name: "ignore_instructions".to_string(),
                regex: Regex::new(
                    r"(?i)ignore[ \t\n\r\f]+(all[ \t\n\r\f]+)?(previous|prior|above)[ \t\n\r\f]+(instructions|rules|prompts)",
                )
                .expect("ignore_instructions regex"),
                weight: 0.4,
            },
            DetectionPattern {
                name: "new_instructions".to_string(),
                regex: Regex::new(
                    r"(?i)(new|updated|revised)[ \t\n\r\f]+instructions?[ \t\n\r\f]*:",
                )
                .expect("new_instructions regex"),
                weight: 0.3,
            },
            DetectionPattern {
                name: "system_prompt_extract".to_string(),
                regex: Regex::new(
                    r"(?i)(reveal|show|display|print|output)[ \t\n\r\f]+(your|the)[ \t\n\r\f]+(system[ \t\n\r\f]+)?(prompt|instructions|rules)",
                )
                .expect("system_prompt_extract regex"),
                weight: 0.4,
            },
            DetectionPattern {
                name: "role_override".to_string(),
                regex: Regex::new(
                    r"(?i)you[ \t\n\r\f]+are[ \t\n\r\f]+now[ \t\n\r\f]+(a|an|the)[ \t\n\r\f]+",
                )
                .expect("role_override regex"),
                weight: 0.3,
            },
            DetectionPattern {
                name: "pretend_mode".to_string(),
                regex: Regex::new(
                    r"(?i)(pretend|imagine|act[ \t\n\r\f]+as[ \t\n\r\f]+if|suppose)[ \t\n\r\f]+(you|that|we)",
                )
                .expect("pretend_mode regex"),
                weight: 0.2,
            },
            DetectionPattern {
                name: "delimiter_injection".to_string(),
                regex: Regex::new(
                    r"(?i)(---+|===+|```)[ \t\n\r\f]*(system|assistant|user)[ \t\n\r\f]*[:\n]",
                )
                .expect("delimiter_injection regex"),
                weight: 0.4,
            },
            DetectionPattern {
                name: "encoding_evasion".to_string(),
                regex: Regex::new(
                    r"(?i)(base64|rot13|hex|url.?encod|unicode)[ \t\n\r\f]*(decod|encod|convert)",
                )
                .expect("encoding_evasion regex"),
                weight: 0.1,
            },
        ];

        Self { patterns }
    }
}

impl Default for RegexInjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for RegexInjectionDetector {
    fn name(&self) -> &str {
        "regex_injection"
    }

    fn category(&self) -> DetectionCategory {
        DetectionCategory::PromptInjection
    }

    fn detect(&self, input: &str) -> DetectionResult {
        let mut matched_patterns = Vec::new();
        let mut total_weight = 0.0;

        for pattern in &self.patterns {
            if let Some(m) = pattern.regex.find(input) {
                total_weight += pattern.weight;
                matched_patterns.push(MatchedPattern {
                    name: pattern.name.clone(),
                    weight: pattern.weight,
                    matched_text: Some(m.as_str().to_string()),
                });
            }
        }

        let score = total_weight.min(1.0);

        let explanation = if matched_patterns.is_empty() {
            None
        } else {
            let names: Vec<&str> = matched_patterns.iter().map(|p| p.name.as_str()).collect();
            Some(format!(
                "matched {} injection pattern(s): {}",
                matched_patterns.len(),
                names.join(", ")
            ))
        };

        DetectionResult {
            detector_name: self.name().to_string(),
            category: self.category(),
            score,
            matched_patterns,
            explanation,
        }
    }
}

/// Regex-based jailbreak detector.
pub struct RegexJailbreakDetector {
    patterns: Vec<DetectionPattern>,
}

impl RegexJailbreakDetector {
    pub fn new() -> Self {
        let patterns = vec![DetectionPattern {
            name: "jailbreak_dan".to_string(),
            regex: Regex::new(
                r"(?i)(DAN|do[ \t\n\r\f]+anything[ \t\n\r\f]+now|developer[ \t\n\r\f]+mode|jailbreak)",
            )
            .expect("jailbreak_dan regex"),
            weight: 0.5,
        }];

        Self { patterns }
    }
}

impl Default for RegexJailbreakDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for RegexJailbreakDetector {
    fn name(&self) -> &str {
        "regex_jailbreak"
    }

    fn category(&self) -> DetectionCategory {
        DetectionCategory::Jailbreak
    }

    fn detect(&self, input: &str) -> DetectionResult {
        let mut matched_patterns = Vec::new();
        let mut total_weight = 0.0;

        for pattern in &self.patterns {
            if let Some(m) = pattern.regex.find(input) {
                total_weight += pattern.weight;
                matched_patterns.push(MatchedPattern {
                    name: pattern.name.clone(),
                    weight: pattern.weight,
                    matched_text: Some(m.as_str().to_string()),
                });
            }
        }

        let score = total_weight.min(1.0);

        let explanation = if matched_patterns.is_empty() {
            None
        } else {
            let names: Vec<&str> = matched_patterns.iter().map(|p| p.name.as_str()).collect();
            Some(format!(
                "matched {} jailbreak pattern(s): {}",
                matched_patterns.len(),
                names.join(", ")
            ))
        };

        DetectionResult {
            detector_name: self.name().to_string(),
            category: self.category(),
            score,
            matched_patterns,
            explanation,
        }
    }
}

/// Regex-based data exfiltration detector (PII, credentials, sensitive data).
pub struct RegexExfiltrationDetector {
    patterns: Vec<DetectionPattern>,
}

impl RegexExfiltrationDetector {
    pub fn new() -> Self {
        let patterns = vec![
            DetectionPattern {
                // Explicit ASCII non-digit boundaries instead of `\b`, plus an
                // ASCII `[0-9]` digit class instead of `\d`: Rust's `regex` and
                // Python's `re` treat both `\b` and `\d` as Unicode-aware, so
                // `café123-45-6789` was missed and fullwidth-digit runs like
                // `１２３-４５-６７８９` were matched -- disagreeing with Go (RE2)
                // and JS, where `\b`/`\d` are ASCII-only. The
                // `(?:^|[^0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}(?:[^0-9]|$)` form is
                // RE2-safe (no backreferences/lookaround) and byte-identical
                // across all four SDKs.
                name: "ssn".to_string(),
                regex: Regex::new(r"(?:^|[^0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}(?:[^0-9]|$)")
                    .expect("ssn regex"),
                weight: 0.8,
            },
            DetectionPattern {
                name: "credit_card".to_string(),
                regex: Regex::new(
                    r"(?:^|[^0-9])(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})(?:[^0-9]|$)",
                )
                .expect("credit_card regex"),
                weight: 0.8,
            },
            DetectionPattern {
                // Explicit ASCII boundaries instead of `\b`: Rust's `regex` and
                // Python's `re` treat `\b` as a Unicode word boundary, so the
                // local part's ASCII character class disagreed with the
                // Unicode-aware `\b` at non-ASCII edges (e.g. `café`), matching
                // differently than Go (RE2) and JS. The consuming
                // `(?:^|[^...]) ... (?:[^...]|$)` form is RE2-safe and
                // byte-identical across all four SDKs.
                name: "email_address".to_string(),
                regex: Regex::new(
                    r"(?:^|[^A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:[^A-Za-z0-9.-]|$)",
                )
                .expect("email_address regex"),
                weight: 0.3,
            },
            DetectionPattern {
                name: "api_key_pattern".to_string(),
                regex: Regex::new(
                    r"(?i)(api[_\-]?key|secret[_\-]?key|access[_\-]?token)[ \t\n\r\f]*[:=][ \t\n\r\f]*[^ \t\n\r\f]+",
                )
                .expect("api_key_pattern regex"),
                weight: 0.6,
            },
            DetectionPattern {
                name: "private_key".to_string(),
                regex: Regex::new(r"-----BEGIN[ \t\n\r\f]+(RSA[ \t\n\r\f]+)?PRIVATE[ \t\n\r\f]+KEY-----")
                    .expect("private_key regex"),
                weight: 0.9,
            },
        ];

        Self { patterns }
    }
}

impl Default for RegexExfiltrationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for RegexExfiltrationDetector {
    fn name(&self) -> &str {
        "regex_exfiltration"
    }

    fn category(&self) -> DetectionCategory {
        DetectionCategory::DataExfiltration
    }

    fn detect(&self, input: &str) -> DetectionResult {
        let mut matched_patterns = Vec::new();
        let mut total_weight = 0.0;

        for pattern in &self.patterns {
            if let Some(m) = pattern.regex.find(input) {
                total_weight += pattern.weight;
                matched_patterns.push(MatchedPattern {
                    name: pattern.name.clone(),
                    weight: pattern.weight,
                    matched_text: Some(m.as_str().to_string()),
                });
            }
        }

        let score = total_weight.min(1.0);

        let explanation = if matched_patterns.is_empty() {
            None
        } else {
            let names: Vec<&str> = matched_patterns.iter().map(|p| p.name.as_str()).collect();
            Some(format!(
                "matched {} exfiltration pattern(s): {}",
                matched_patterns.len(),
                names.join(", ")
            ))
        };

        DetectionResult {
            detector_name: self.name().to_string(),
            category: self.category(),
            score,
            matched_patterns,
            explanation,
        }
    }
}

/// Result of running policy evaluation followed by content detection.
#[derive(Clone, Debug)]
pub struct EvaluationWithDetection {
    /// The final decision callers act on (base evaluation, possibly escalated
    /// by detection).
    pub evaluation: EvaluationResult,
    /// The `DetectionResult` produced by each detector that ran.
    pub detections: Vec<DetectionResult>,
    /// The strictest contribution across detectors (`None` < `Warn` < `Deny`).
    pub detection_decision: Option<Decision>,
}

/// Default byte budget for a single detection scan when the policy sets none.
/// Applies to prompt_injection `max_scan_bytes` and jailbreak `max_input_bytes`.
const DEFAULT_SCAN_BYTES: usize = 200_000;

/// Evaluate an action against policy rules, then fold in the policy's
/// `detection:` extension (if any) using the built-in detectors.
///
/// Spec-driven and fail-closed: which detectors run, their byte budgets, and
/// their thresholds all come from `spec.extensions.detection`. When there is no
/// detection extension or no content to scan, this is an *exact* no-op over
/// [`evaluate`] -- every existing evaluation fixture/policy has no detection
/// extension and must therefore be unaffected.
///
/// Detection can only *escalate* a decision (allow -> warn -> deny); it never
/// weakens a policy decision. On escalation the returned evaluation carries
/// `matched_rule = "detection"`; otherwise the base evaluation is returned
/// unchanged, so a policy deny keeps its own matched_rule.
pub fn evaluate_with_detection(
    spec: &HushSpec,
    action: &EvaluationAction,
) -> EvaluationWithDetection {
    let base = evaluate(spec, action);

    let Some(detection) = spec
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.detection.as_ref())
    else {
        return EvaluationWithDetection {
            evaluation: base,
            detections: Vec::new(),
            detection_decision: None,
        };
    };

    let content = action.content.as_deref().unwrap_or_default();
    if content.is_empty() {
        return EvaluationWithDetection {
            evaluation: base,
            detections: Vec::new(),
            detection_decision: None,
        };
    }

    let registry = DetectorRegistry::with_defaults();
    let mut detections: Vec<DetectionResult> = Vec::new();
    // (category, contribution) for each detector that raised a warn/deny.
    let mut contributions: Vec<(&'static str, Decision)> = Vec::new();

    // prompt_injection -> injection detector, DetectionLevel thresholds.
    if let Some(prompt_injection) = &detection.prompt_injection
        && prompt_injection.enabled != Some(false)
        && let Some(detector) = registry.detector_for(DetectionCategory::PromptInjection)
    {
        let scan = truncate_to_bytes(
            content,
            prompt_injection
                .max_scan_bytes
                .unwrap_or(DEFAULT_SCAN_BYTES),
        );
        let result = detector.detect(scan);
        let score = result.score;
        detections.push(result);

        let block_floor = level_floor(
            prompt_injection
                .block_at_or_above
                .unwrap_or(DetectionLevel::High),
        );
        let warn_floor = level_floor(
            prompt_injection
                .warn_at_or_above
                .unwrap_or(DetectionLevel::Suspicious),
        );
        if score >= block_floor {
            contributions.push(("prompt_injection", Decision::Deny));
        } else if score >= warn_floor {
            contributions.push(("prompt_injection", Decision::Warn));
        }
    }

    // jailbreak -> jailbreak detector, 0-100 thresholds (score * 100).
    if let Some(jailbreak) = &detection.jailbreak
        && jailbreak.enabled != Some(false)
        && let Some(detector) = registry.detector_for(DetectionCategory::Jailbreak)
    {
        let scan = truncate_to_bytes(
            content,
            jailbreak.max_input_bytes.unwrap_or(DEFAULT_SCAN_BYTES),
        );
        let result = detector.detect(scan);
        let scaled = result.score * 100.0;
        detections.push(result);

        let block_threshold = jailbreak.block_threshold.unwrap_or(80) as f64;
        let warn_threshold = jailbreak.warn_threshold.unwrap_or(50) as f64;
        if scaled >= block_threshold {
            contributions.push(("jailbreak", Decision::Deny));
        } else if scaled >= warn_threshold {
            contributions.push(("jailbreak", Decision::Warn));
        }
    }

    // threat_intel is intentionally NOT wired: the built-in regex engine has no
    // pattern-db / similarity model to satisfy it. Satisfying threat_intel
    // requires a custom detector registered through the DetectorRegistry API.

    let detection_decision = contributions
        .iter()
        .map(|(_, decision)| *decision)
        .max_by_key(|decision| severity(*decision));

    let final_decision = match detection_decision {
        Some(decision) => strictest(base.decision, decision),
        None => base.decision,
    };

    if final_decision == base.decision {
        // No escalation: return the base evaluation untouched so a policy deny
        // keeps its own matched_rule and detection never weakens a decision.
        return EvaluationWithDetection {
            evaluation: base,
            detections,
            detection_decision,
        };
    }

    // Detection escalated. Attribute it to the first detector whose
    // contribution reached the strictest detection decision.
    let category = contributions
        .iter()
        .find(|(_, decision)| Some(*decision) == detection_decision)
        .map(|(category, _)| *category)
        .unwrap_or("prompt_injection");

    EvaluationWithDetection {
        evaluation: EvaluationResult {
            decision: final_decision,
            matched_rule: Some("detection".to_string()),
            reason: Some(format!("content flagged by {category} detection")),
            origin_profile: base.origin_profile.clone(),
            posture: base.posture.clone(),
        },
        detections,
        detection_decision,
    }
}

/// Score floor for a `DetectionLevel`, mapping the injection detector's
/// 0.0-1.0 score onto the policy's coarse levels.
fn level_floor(level: DetectionLevel) -> f64 {
    match level {
        DetectionLevel::Safe => 0.0,
        DetectionLevel::Suspicious => 0.25,
        DetectionLevel::High => 0.5,
        DetectionLevel::Critical => 0.75,
    }
}

/// Severity rank for merging decisions: deny > warn > allow.
fn severity(decision: Decision) -> u8 {
    match decision {
        Decision::Allow => 0,
        Decision::Warn => 1,
        Decision::Deny => 2,
    }
}

/// The stricter (higher-severity) of two decisions.
fn strictest(left: Decision, right: Decision) -> Decision {
    if severity(right) > severity(left) {
        right
    } else {
        left
    }
}

/// Truncate `input` to at most `max_bytes` bytes without splitting a UTF-8
/// character, returning the largest valid prefix.
fn truncate_to_bytes(input: &str, max_bytes: usize) -> &str {
    if input.len() <= max_bytes {
        return input;
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    &input[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_category_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&DetectionCategory::PromptInjection).unwrap(),
            "\"prompt_injection\""
        );
        assert_eq!(
            serde_json::to_string(&DetectionCategory::Jailbreak).unwrap(),
            "\"jailbreak\""
        );
        assert_eq!(
            serde_json::to_string(&DetectionCategory::DataExfiltration).unwrap(),
            "\"data_exfiltration\""
        );
    }

    #[test]
    fn injection_detector_compiles_all_patterns() {
        let detector = RegexInjectionDetector::new();
        assert_eq!(detector.patterns.len(), 7);
    }

    #[test]
    fn jailbreak_detector_compiles_all_patterns() {
        let detector = RegexJailbreakDetector::new();
        assert_eq!(detector.patterns.len(), 1);
    }

    #[test]
    fn exfiltration_detector_compiles_all_patterns() {
        let detector = RegexExfiltrationDetector::new();
        assert_eq!(detector.patterns.len(), 5);
    }

    #[test]
    fn exfiltration_ssn_matches_across_non_ascii_boundaries() {
        // Regression for the `\b` divergence (spec §3): Rust's `regex` treats
        // `\b` as a Unicode word boundary, so a digit run preceded by a
        // non-ASCII letter (`café123-45-6789`, `中123-45-6789`) used to be
        // missed here while Go/JS matched it. The explicit ASCII non-digit
        // boundaries make all four SDKs agree.
        let detector = RegexExfiltrationDetector::new();
        for input in ["café123-45-6789", "中123-45-6789", "123-45-6789"] {
            let result = detector.detect(input);
            assert!(
                result.matched_patterns.iter().any(|p| p.name == "ssn"),
                "expected ssn match for {input:?}"
            );
        }
        // An over-long digit run must still NOT match.
        let result = detector.detect("1234-56-7890");
        assert!(
            !result.matched_patterns.iter().any(|p| p.name == "ssn"),
            "over-long digit run must not match ssn"
        );
    }

    #[test]
    fn exfiltration_fullwidth_digit_ssn_scores_zero() {
        // Cross-SDK parity (spec §3): the ssn body uses an ASCII `[0-9]` class
        // rather than `\d`, so fullwidth/Unicode digits no longer match in
        // Rust's `regex` / Python's `re` (which treat `\d` as Unicode) --
        // agreeing with Go (RE2) and JS, where `\d` is ASCII-only. A
        // fullwidth-digit SSN (U+FF11.. with ASCII hyphens) must score 0.
        let detector = RegexExfiltrationDetector::new();
        let result = detector.detect("１２３-４５-６７８９");
        assert_eq!(result.score, 0.0, "fullwidth-digit SSN must score 0");
        assert!(
            !result.matched_patterns.iter().any(|p| p.name == "ssn"),
            "fullwidth-digit SSN must not match the ssn pattern"
        );
    }

    #[test]
    fn injection_nbsp_separated_content_scores_zero() {
        // Cross-SDK parity (spec §B): the built-in patterns use ASCII-only
        // whitespace classes `[ \t\n\r\f]`, so injection separated by NBSP
        // (U+00A0) no longer matches -- Rust's `regex`/Python's `re` treat
        // `\s` as Unicode (matching NBSP) while Go RE2 / JS `RegExp` treat it
        // as ASCII. Catching Unicode-obfuscated content is the separately
        // deferred input-normalization item; the goal here is that all four
        // SDKs agree, which ASCII-only whitespace restores.
        let detector = RegexInjectionDetector::new();
        let nbsp = "ignore\u{a0}all\u{a0}previous\u{a0}instructions";
        let result = detector.detect(nbsp);
        assert_eq!(result.score, 0.0, "NBSP-separated injection must score 0");
        assert!(
            result.matched_patterns.is_empty(),
            "no pattern should match NBSP-separated content, got {:?}",
            result.matched_patterns
        );

        // A normal ASCII space in the same phrase must still match (fixtures
        // rely on this).
        let ascii = detector.detect("ignore all previous instructions");
        assert!(ascii.score > 0.0, "ASCII-space injection must still match");
    }
}
