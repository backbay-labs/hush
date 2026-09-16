use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;

use crate::evaluate::{Decision, EvaluationAction, PostureResult, evaluate_traced};
use crate::schema::HushSpec;
use crate::version::HUSHSPEC_VERSION;

pub use crate::evaluate::{RuleEvaluation, RuleOutcome};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionReceipt {
    pub receipt_id: String,
    pub timestamp: String,
    pub hushspec_version: String,
    pub action: ActionSummary,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub rule_trace: Vec<RuleEvaluation>,
    pub policy: PolicySummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement: Option<EnforcementSummary>,
    pub evaluation_duration_us: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSummary {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub content_redacted: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub version: String,
    /// SHA-256 hex digest of the canonical JSON serialization. Omitted from
    /// serialized output when audit is disabled (the zero-overhead
    /// disabled-audit fast path never computes a hash); the in-memory value
    /// is `""` in that case, matching the other three SDKs.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_hash: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    Enforce,
    Monitor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementOutcome {
    Allowed,
    Confirmed,
    Blocked,
    WouldBlock,
}

/// How the runtime applied a decision. `DecisionReceipt.decision` is always
/// the evaluated policy decision; this records what the enforcement point did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementSummary {
    pub mode: EnforcementMode,
    pub outcome: EnforcementOutcome,
}

#[derive(Clone, Debug)]
pub struct AuditConfig {
    pub enabled: bool,
    pub include_rule_trace: bool,
    pub redact_content: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            include_rule_trace: true,
            redact_content: true,
        }
    }
}

/// Wrap `evaluate()` with timing, the recorded rule trace, and policy hashing.
///
/// When `config.enabled` is false, skips overhead but still returns a
/// correct decision.
pub fn evaluate_audited(
    spec: &HushSpec,
    action: &EvaluationAction,
    config: &AuditConfig,
) -> DecisionReceipt {
    let start = if config.enabled {
        Some(Instant::now())
    } else {
        None
    };

    let traced = evaluate_traced(spec, action, None, &HashMap::new());
    let result = traced.result;

    let duration_us = start.map(|s| s.elapsed().as_micros() as u64).unwrap_or(0);

    let rule_trace = if config.enabled && config.include_rule_trace {
        traced.trace
    } else {
        Vec::new()
    };

    let policy = if config.enabled {
        build_policy_summary(spec)
    } else {
        PolicySummary {
            name: spec.name.clone(),
            version: spec.hushspec.clone(),
            content_hash: String::new(),
        }
    };

    let action_summary = ActionSummary {
        action_type: action.action_type.clone(),
        target: action.target.clone(),
        content_redacted: config.redact_content && action.content.is_some(),
    };

    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    DecisionReceipt {
        receipt_id: Uuid::new_v4().to_string(),
        timestamp,
        hushspec_version: HUSHSPEC_VERSION.to_string(),
        action: action_summary,
        decision: result.decision,
        matched_rule: result.matched_rule,
        reason: result.reason,
        rule_trace,
        policy,
        origin_profile: result.origin_profile,
        posture: result.posture,
        enforcement: None,
        evaluation_duration_us: duration_us,
    }
}

fn build_policy_summary(spec: &HushSpec) -> PolicySummary {
    let content_hash = compute_policy_hash(spec);
    PolicySummary {
        name: spec.name.clone(),
        version: spec.hushspec.clone(),
        content_hash,
    }
}

/// SHA-256 hex digest of the canonical JSON serialization. Deterministic.
pub fn compute_policy_hash(spec: &HushSpec) -> String {
    let json = serde_json::to_string(spec).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    format!("{:x}", hasher.finalize())
}
