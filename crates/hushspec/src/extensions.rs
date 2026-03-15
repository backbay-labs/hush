use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::rules::{EgressRule, ToolAccessRule};

// --- Top-level Extensions container ---

/// Optional extension modules for advanced features.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Extensions {
    /// Declarative posture state machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureExtension>,
    /// Origin-aware policy projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origins: Option<OriginsExtension>,
    /// Detection engine threshold configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection: Option<DetectionExtension>,
}

// --- Posture Extension ---

/// Declarative state machine for capability and budget management.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureExtension {
    /// Name of the starting state.
    pub initial: String,
    /// Named security states with capabilities and budgets.
    pub states: BTreeMap<String, PostureState>,
    /// Rules governing transitions between states.
    pub transitions: Vec<PostureTransition>,
}

/// A named security state with capabilities and budgets.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureState {
    /// Human-readable description of this state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Capabilities available in this state.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Resource budgets (e.g. `"tool_calls": 100`). Must be non-negative.
    #[serde(default)]
    pub budgets: BTreeMap<String, i64>,
}

/// A transition rule between posture states.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureTransition {
    /// Source state name, or `"*"` for any state.
    pub from: String,
    /// Target state name.
    pub to: String,
    /// Event that triggers this transition.
    pub on: TransitionTrigger,
    /// Duration string required for `Timeout` triggers (e.g. `"30s"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

/// Event that triggers a posture state transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionTrigger {
    /// Operator approved the current action.
    UserApproval,
    /// Operator denied the current action.
    UserDenial,
    /// A critical-severity violation occurred.
    CriticalViolation,
    /// Any violation occurred.
    AnyViolation,
    /// A duration elapsed (requires `after` field).
    Timeout,
    /// A budget counter reached zero.
    BudgetExhausted,
    /// A threat-intel pattern matched.
    PatternMatch,
}

// --- Origins Extension ---

/// Origin-aware policy projection with match-based profiles.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginsExtension {
    /// Behavior when no origin profile matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_behavior: Option<OriginDefaultBehavior>,
    /// Ordered list of origin profiles; first match wins.
    #[serde(default)]
    pub profiles: Vec<OriginProfile>,
}

/// Behavior when no origin profile matches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginDefaultBehavior {
    /// Deny all actions from unmatched origins.
    #[default]
    Deny,
    /// Apply a minimal-privilege profile.
    MinimalProfile,
}

/// An origin profile with match rules and security overrides.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginProfile {
    /// Unique identifier for this profile.
    pub id: String,
    /// Criteria for matching an origin context to this profile.
    #[serde(default, rename = "match", skip_serializing_if = "Option::is_none")]
    pub match_rules: Option<OriginMatch>,
    /// Posture state to activate for this origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<String>,
    /// Tool access overrides for this origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_access: Option<ToolAccessRule>,
    /// Egress overrides for this origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressRule>,
    /// Data handling policy for this origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<OriginDataPolicy>,
    /// Budget limits for this origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budgets: Option<OriginBudgets>,
    /// Cross-origin transition controls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<BridgePolicy>,
    /// Human-readable rationale for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
}

/// Criteria for matching an origin context to a profile.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginMatch {
    /// Platform provider (e.g. `"slack"`, `"github"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Tenant/organization identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Specific space/channel identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    /// Space type (e.g. `"channel"`, `"dm"`, `"thread"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_type: Option<String>,
    /// Visibility level (e.g. `"public"`, `"private"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    /// Whether external participants are present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_participants: Option<bool>,
    /// Required tags on the origin context.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Data sensitivity classification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
    /// Required actor role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_role: Option<String>,
}

/// Data handling policy for an origin.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginDataPolicy {
    /// Whether data may be shared with external parties.
    #[serde(default)]
    pub allow_external_sharing: bool,
    /// Whether to redact sensitive content before sending.
    #[serde(default)]
    pub redact_before_send: bool,
    /// Whether to suppress sensitive outputs entirely.
    #[serde(default)]
    pub block_sensitive_outputs: bool,
}

/// Budget limits for an origin profile.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginBudgets {
    /// Maximum tool invocations allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<u64>,
    /// Maximum network egress calls allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_calls: Option<u64>,
    /// Maximum shell commands allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell_commands: Option<u64>,
}

/// Cross-origin transition control.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgePolicy {
    /// Whether cross-origin transitions are permitted.
    #[serde(default)]
    pub allow_cross_origin: bool,
    /// Permitted cross-origin targets.
    #[serde(default)]
    pub allowed_targets: Vec<BridgeTarget>,
    /// Whether cross-origin transitions require operator approval.
    #[serde(default)]
    pub require_approval: bool,
}

/// A permitted cross-origin target.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeTarget {
    /// Target platform provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Target space type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_type: Option<String>,
    /// Required tags on the target.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Required visibility level on the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
}

// --- Detection Extension ---

/// Detection engine threshold configuration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionExtension {
    /// Prompt injection detection thresholds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_injection: Option<PromptInjectionDetection>,
    /// Jailbreak detection thresholds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jailbreak: Option<JailbreakDetection>,
    /// Threat intelligence screening configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_intel: Option<ThreatIntelDetection>,
}

/// Prompt injection detection thresholds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptInjectionDetection {
    /// Whether prompt injection detection is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Detection level at or above which a warning is emitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warn_at_or_above: Option<DetectionLevel>,
    /// Detection level at or above which the action is blocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_at_or_above: Option<DetectionLevel>,
    /// Maximum input bytes to scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_scan_bytes: Option<usize>,
}

/// Ordered severity level for detection results.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionLevel {
    /// No threat detected.
    Safe,
    /// Possible threat; warrants review.
    Suspicious,
    /// Likely threat; should block by default.
    High,
    /// Definite threat; must block.
    Critical,
}

/// Jailbreak detection thresholds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailbreakDetection {
    /// Whether jailbreak detection is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Score at or above which the action is blocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_threshold: Option<u32>,
    /// Score at or above which a warning is emitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warn_threshold: Option<u32>,
    /// Maximum input bytes to scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_input_bytes: Option<usize>,
}

/// Threat intelligence screening configuration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatIntelDetection {
    /// Whether threat intel screening is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Path to the pattern database, or `builtin:` prefix for embedded patterns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern_db: Option<String>,
    /// Cosine similarity threshold for matching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub similarity_threshold: Option<f64>,
    /// Number of top matches to return.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_k: Option<usize>,
}
