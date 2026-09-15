//! Reference evaluator for HushSpec 0.2 (core spec Sections 3, 5, and 6).
//!
//! Evaluation of one action is:
//! 1. extension guards (panic, origins `default_behavior`, posture capability),
//! 2. every applicable rule block for the action type -- present, `enabled`,
//!    and with a satisfied `when` condition -- evaluated in the order of the
//!    Section 5 table, never short-circuiting on an allow,
//! 3. aggregation: deny beats warn beats allow; `matched_rule`/`reason` come
//!    from the first block in evaluation order whose decision equals the
//!    aggregate and which named a rule.
//!
//! Unknown action types deny (`__unknown_action_type__`). Hosts and paths are
//! normalized as specified in Section 3.14 before any pattern is consulted.

use crate::HushSpec;
use crate::compiled::{
    CompiledBrowserAutomation, CompiledEgress, CompiledForbiddenPaths, CompiledMatchers,
    CompiledPathAllowlist, CompiledRegex, CompiledSecretPatterns,
};
use crate::conditions::{Condition, RuntimeContext, evaluate_condition};
use crate::extensions::{
    OriginEgressOverlay, OriginProfile, OriginToolAccessOverlay, PostureExtension,
    TransitionTrigger,
};
use crate::panic::PanicState;
use crate::regex_profile::compile_profile_regex;
use crate::rules::{
    BrowserAutomationRule, CodeExecutionRule, ComputerUseMode, ComputerUseRule, DefaultAction,
    EgressRule, InputInjectionRule, PatchIntegrityRule, RemoteDesktopChannelsRule,
    SecretPatternsRule, Severity, ShellCommandsRule, ToolAccessRule,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::LazyLock;
use unicode_normalization::UnicodeNormalization;

/// `matched_rule` reported when the action type is unknown to the specification.
pub const UNKNOWN_ACTION_TYPE_RULE: &str = "__unknown_action_type__";
/// `matched_rule` reported when the emergency panic protocol is active.
pub const PANIC_RULE: &str = "__hushspec_panic__";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Warn,
    Deny,
}

impl Decision {
    fn rank(self) -> u8 {
        match self {
            Decision::Allow => 1,
            Decision::Warn => 2,
            Decision::Deny => 3,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationAction {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<OriginContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_size: Option<usize>,
    /// `browser_action`: navigation destination (core spec 3.11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// `code_exec`: whether the call requests network access (core spec 3.12).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<bool>,
    /// `code_exec`: requested execution time in milliseconds (core spec 3.12).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Runtime context consulted by `when` conditions (core spec 3.13). When
    /// absent, conditions see an empty context and the engine clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<RuntimeContext>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_participants: Option<bool>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_role: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationResult {
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureResult>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureResult {
    pub current: String,
    pub next: String,
}

/// Outcome of consulting one rule block (or extension guard) during an
/// evaluation. `Skip` means the block was applicable but not evaluated
/// (absent, disabled, condition false, or short-circuited by a guard deny).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleOutcome {
    Allow,
    Warn,
    Deny,
    Skip,
}

impl From<Decision> for RuleOutcome {
    fn from(decision: Decision) -> Self {
        match decision {
            Decision::Allow => RuleOutcome::Allow,
            Decision::Warn => RuleOutcome::Warn,
            Decision::Deny => RuleOutcome::Deny,
        }
    }
}

/// One recorded rule-block consultation. Produced by the evaluator itself,
/// in evaluation order, so receipts reflect exactly what ran.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleEvaluation {
    pub rule_block: String,
    pub outcome: RuleOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub evaluated: bool,
}

/// An evaluation result together with its recorded rule trace.
#[derive(Clone, Debug, PartialEq)]
pub struct TracedEvaluation {
    pub result: EvaluationResult,
    pub trace: Vec<RuleEvaluation>,
}

/// Evaluate `action` against a resolved document.
///
/// `when` conditions are evaluated against `action.context` (an empty context
/// and the engine clock when absent).
///
/// This compiles the document's patterns on every call. Evaluating repeatedly
/// against one policy should go through
/// [`CompiledPolicy`](crate::CompiledPolicy), which compiles them once.
pub fn evaluate(spec: &HushSpec, action: &EvaluationAction) -> EvaluationResult {
    evaluate_traced(spec, action, None, &HashMap::new()).result
}

/// Like [`evaluate`] with an explicit runtime context and an out-of-band map
/// of conditions keyed by rule-block name. The explicit `context` replaces
/// `action.context`; out-of-band conditions are ANDed with each block's own
/// `when` (core spec 3.13).
///
/// Compiles on the fly; see [`CompiledPolicy::evaluate_with_context`].
///
/// [`CompiledPolicy::evaluate_with_context`]: crate::CompiledPolicy::evaluate_with_context
pub fn evaluate_with_context(
    spec: &HushSpec,
    action: &EvaluationAction,
    context: &RuntimeContext,
    conditions: &HashMap<String, Condition>,
) -> EvaluationResult {
    evaluate_traced(spec, action, Some(context), conditions).result
}

/// Full evaluation with the recorded rule trace (used by receipts and `h2h explain`).
///
/// Compiles on the fly; see [`CompiledPolicy::evaluate_traced`].
///
/// [`CompiledPolicy::evaluate_traced`]: crate::CompiledPolicy::evaluate_traced
pub fn evaluate_traced(
    spec: &HushSpec,
    action: &EvaluationAction,
    context: Option<&RuntimeContext>,
    conditions: &HashMap<String, Condition>,
) -> TracedEvaluation {
    let matchers = CompiledMatchers::lazy(spec);
    run_evaluation(
        spec,
        &matchers,
        &PanicState::shared(),
        action,
        context,
        conditions,
    )
}

/// The one evaluation path. Both [`CompiledPolicy`](crate::CompiledPolicy) and
/// the free functions above reach the evaluator through here; the only
/// difference is whether the matchers were compiled once or per call.
pub(crate) fn run_evaluation(
    spec: &HushSpec,
    matchers: &CompiledMatchers,
    panic: &PanicState,
    action: &EvaluationAction,
    context: Option<&RuntimeContext>,
    conditions: &HashMap<String, Condition>,
) -> TracedEvaluation {
    let default_context = RuntimeContext::default();
    let context = context
        .or(action.context.as_ref())
        .unwrap_or(&default_context);
    Evaluator {
        spec,
        matchers,
        panic,
        action,
        context,
        conditions,
        active: Vec::new(),
        trace: Vec::new(),
    }
    .run()
}

/// Rule blocks applicable to each reference action type, in evaluation order
/// (core spec Section 5). `None` means the type is unknown to the specification.
fn applicable_blocks(action_type: &str) -> Option<&'static [&'static str]> {
    Some(match action_type {
        "file_read" => &["forbidden_paths", "path_allowlist"],
        "file_write" => &["forbidden_paths", "path_allowlist", "secret_patterns"],
        "patch_apply" => &[
            "forbidden_paths",
            "path_allowlist",
            "patch_integrity",
            "secret_patterns",
        ],
        "shell_command" => &["shell_commands"],
        "egress" => &["egress", "secret_patterns"],
        "tool_call" => &["tool_access", "secret_patterns"],
        "computer_use" => &["computer_use", "remote_desktop_channels"],
        "input_inject" => &["input_injection"],
        "browser_action" => &["browser_automation"],
        "code_exec" => &["code_execution"],
        "custom" => &[],
        _ => return None,
    })
}

/// Decision contributed by one rule block.
struct BlockDecision {
    decision: Decision,
    matched_rule: Option<String>,
    reason: Option<String>,
}

impl BlockDecision {
    fn allow(matched_rule: Option<&str>, reason: Option<&str>) -> Self {
        Self::new(Decision::Allow, matched_rule, reason)
    }
    fn warn(matched_rule: &str, reason: &str) -> Self {
        Self::new(Decision::Warn, Some(matched_rule), Some(reason))
    }
    fn deny(matched_rule: &str, reason: &str) -> Self {
        Self::new(Decision::Deny, Some(matched_rule), Some(reason))
    }
    fn new(decision: Decision, matched_rule: Option<&str>, reason: Option<&str>) -> Self {
        Self {
            decision,
            matched_rule: matched_rule.map(str::to_string),
            reason: reason.map(str::to_string),
        }
    }
}

/// Why an applicable block was not evaluated.
enum Inactive {
    Absent,
    Disabled,
    ConditionFalse,
    OutOfBandConditionFalse,
}

impl Inactive {
    fn reason(&self, block: &str) -> String {
        match self {
            Inactive::Absent => format!("no {block} rule configured"),
            Inactive::Disabled => "rule disabled".to_string(),
            Inactive::ConditionFalse => "when condition is false".to_string(),
            Inactive::OutOfBandConditionFalse => "out-of-band condition is false".to_string(),
        }
    }
}

/// Whether a block's conditions hold, decided once per evaluation from the
/// runtime context rather than at each block's turn.
#[derive(Clone, Copy, Default)]
struct BlockActivity {
    when_false: bool,
    oob_false: bool,
}

struct Evaluator<'a> {
    spec: &'a HushSpec,
    matchers: &'a CompiledMatchers,
    panic: &'a PanicState,
    action: &'a EvaluationAction,
    context: &'a RuntimeContext,
    conditions: &'a HashMap<String, Condition>,
    /// Active-block mask, parallel to the action type's applicable blocks.
    /// Empty when no applicable block carries a condition at all, which is
    /// the common case and costs nothing.
    active: Vec<BlockActivity>,
    trace: Vec<RuleEvaluation>,
}

impl Evaluator<'_> {
    fn run(mut self) -> TracedEvaluation {
        if self.panic.is_active() {
            self.record(
                "panic",
                RuleOutcome::Deny,
                Some(PANIC_RULE),
                Some("emergency panic mode is active"),
                true,
            );
            return self.finish(
                Decision::Deny,
                Some(PANIC_RULE.to_string()),
                Some("emergency panic mode is active".to_string()),
                None,
                None,
            );
        }

        let action_type = self.action.action_type.as_str();
        let Some(blocks) = applicable_blocks(action_type) else {
            let reason = format!("action type '{action_type}' is unknown to the specification");
            self.record(
                "default",
                RuleOutcome::Deny,
                Some(UNKNOWN_ACTION_TYPE_RULE),
                Some(&reason),
                true,
            );
            return self.finish(
                Decision::Deny,
                Some(UNKNOWN_ACTION_TYPE_RULE.to_string()),
                Some(reason),
                None,
                None,
            );
        };

        self.active = self.active_mask(blocks);

        // Origins guard: select a profile or apply default_behavior.
        let origins = self
            .spec
            .extensions
            .as_ref()
            .and_then(|extensions| extensions.origins.as_ref());
        let matched_index = select_origin_profile(self.spec, self.action.origin.as_ref());
        let matched_profile =
            matched_index.and_then(|index| origins.and_then(|origins| origins.profiles.get(index)));
        let origin_profile_id = matched_profile.map(|profile| profile.id.clone());
        if let Some(origins) = origins
            && matched_profile.is_none()
            && origins.default_behavior.unwrap_or_default()
                == crate::extensions::OriginDefaultBehavior::Deny
        {
            let reason = "no origin profile matched and default_behavior is deny";
            self.record(
                "origins",
                RuleOutcome::Deny,
                Some("extensions.origins.default_behavior"),
                Some(reason),
                true,
            );
            self.skip_all(blocks, "short-circuited by origins deny");
            return self.finish(
                Decision::Deny,
                Some("extensions.origins.default_behavior".to_string()),
                Some(reason.to_string()),
                None,
                None,
            );
        }

        // Posture guard.
        let posture = resolve_posture(self.spec, matched_profile, self.action.posture.as_ref());
        if let Some(denied) = self.posture_capability_guard(&posture) {
            self.skip_all(blocks, "short-circuited by posture deny");
            return self.finish(
                Decision::Deny,
                denied.matched_rule,
                denied.reason,
                origin_profile_id,
                posture,
            );
        }

        if action_type == "custom" {
            // Only a posture state granting the `custom` capability can vouch
            // for an engine-defined action (core spec Section 5).
            if posture.is_none() {
                let reason =
                    "custom actions require a posture state granting the custom capability";
                self.record(
                    "default",
                    RuleOutcome::Deny,
                    Some(UNKNOWN_ACTION_TYPE_RULE),
                    Some(reason),
                    true,
                );
                return self.finish(
                    Decision::Deny,
                    Some(UNKNOWN_ACTION_TYPE_RULE.to_string()),
                    Some(reason.to_string()),
                    origin_profile_id,
                    None,
                );
            }
            return self.finish(Decision::Allow, None, None, origin_profile_id, posture);
        }

        // Block evaluation and aggregation (core spec 6.1).
        let normalized_path = self.action.target.as_deref().map(normalize_path);
        let mut decisions: Vec<BlockDecision> = Vec::new();
        for (index, block) in blocks.iter().enumerate() {
            match self.evaluate_block(
                index,
                block,
                matched_index,
                matched_profile,
                normalized_path.as_deref(),
            ) {
                Ok(decision) => {
                    self.record(
                        block,
                        decision.decision.into(),
                        decision.matched_rule.as_deref(),
                        decision.reason.as_deref(),
                        true,
                    );
                    decisions.push(decision);
                }
                Err(inactive) => {
                    let reason = inactive.reason(block);
                    self.record(block, RuleOutcome::Skip, None, Some(&reason), false);
                }
            }
        }

        let aggregate = decisions
            .iter()
            .map(|decision| decision.decision)
            .max_by_key(|decision| decision.rank())
            .unwrap_or(Decision::Allow);
        let winner = decisions
            .iter()
            .find(|decision| decision.decision == aggregate && decision.matched_rule.is_some());
        let (matched_rule, reason) = match winner {
            Some(decision) => (decision.matched_rule.clone(), decision.reason.clone()),
            None => (None, None),
        };
        self.finish(aggregate, matched_rule, reason, origin_profile_id, posture)
    }

    fn finish(
        self,
        decision: Decision,
        matched_rule: Option<String>,
        reason: Option<String>,
        origin_profile: Option<String>,
        posture: Option<PostureResult>,
    ) -> TracedEvaluation {
        TracedEvaluation {
            result: EvaluationResult {
                decision,
                matched_rule,
                reason,
                origin_profile,
                posture,
            },
            trace: self.trace,
        }
    }

    fn record(
        &mut self,
        block: &str,
        outcome: RuleOutcome,
        matched_rule: Option<&str>,
        reason: Option<&str>,
        evaluated: bool,
    ) {
        self.trace.push(RuleEvaluation {
            rule_block: block.to_string(),
            outcome,
            matched_rule: matched_rule.map(str::to_string),
            reason: reason.map(str::to_string),
            evaluated,
        });
    }

    fn skip_all(&mut self, blocks: &[&str], reason: &str) {
        for block in blocks {
            self.record(block, RuleOutcome::Skip, None, Some(reason), false);
        }
    }

    /// A block's own `when`, as declared in the document.
    fn block_when(&self, block: &str) -> Option<&Condition> {
        let rules = self.spec.rules.as_ref()?;
        match block {
            "forbidden_paths" => rules.forbidden_paths.as_ref()?.when.as_ref(),
            "path_allowlist" => rules.path_allowlist.as_ref()?.when.as_ref(),
            "secret_patterns" => rules.secret_patterns.as_ref()?.when.as_ref(),
            "patch_integrity" => rules.patch_integrity.as_ref()?.when.as_ref(),
            "shell_commands" => rules.shell_commands.as_ref()?.when.as_ref(),
            "tool_access" => rules.tool_access.as_ref()?.when.as_ref(),
            "egress" => rules.egress.as_ref()?.when.as_ref(),
            "computer_use" => rules.computer_use.as_ref()?.when.as_ref(),
            "remote_desktop_channels" => rules.remote_desktop_channels.as_ref()?.when.as_ref(),
            "input_injection" => rules.input_injection.as_ref()?.when.as_ref(),
            "browser_automation" => rules.browser_automation.as_ref()?.when.as_ref(),
            "code_execution" => rules.code_execution.as_ref()?.when.as_ref(),
            _ => None,
        }
    }

    /// Decide, once per evaluation, which of the action type's applicable
    /// blocks the runtime context leaves active. Returns an empty mask -- read
    /// as "every block active" -- when no applicable block carries a condition,
    /// so a policy without `when` pays nothing.
    fn active_mask(&self, blocks: &[&str]) -> Vec<BlockActivity> {
        let any_condition = !self.conditions.is_empty()
            || blocks.iter().any(|block| self.block_when(block).is_some());
        if !any_condition {
            return Vec::new();
        }
        blocks
            .iter()
            .map(|block| BlockActivity {
                when_false: self
                    .block_when(block)
                    .is_some_and(|condition| !evaluate_condition(condition, self.context)),
                oob_false: self
                    .conditions
                    .get(*block)
                    .is_some_and(|condition| !evaluate_condition(condition, self.context)),
            })
            .collect()
    }

    /// Whether a present block is active: enabled, and its `when` plus any
    /// out-of-band condition hold for the runtime context (read off the mask
    /// computed in [`Evaluator::active_mask`]).
    fn activity(&self, index: usize, enabled: bool) -> Result<(), Inactive> {
        if !enabled {
            return Err(Inactive::Disabled);
        }
        let Some(activity) = self.active.get(index) else {
            return Ok(());
        };
        if activity.when_false {
            return Err(Inactive::ConditionFalse);
        }
        if activity.oob_false {
            return Err(Inactive::OutOfBandConditionFalse);
        }
        Ok(())
    }

    fn evaluate_block(
        &self,
        index: usize,
        block: &str,
        matched_index: Option<usize>,
        matched_profile: Option<&OriginProfile>,
        normalized_path: Option<&str>,
    ) -> Result<BlockDecision, Inactive> {
        let rules = self.spec.rules.as_ref();
        let compiled = self.matchers;
        let action = self.action;
        let content = action.content.as_deref();
        match block {
            "forbidden_paths" => {
                let rule = rules
                    .and_then(|rules| rules.forbidden_paths.as_ref())
                    .ok_or(Inactive::Absent)?;
                self.activity(index, rule.enabled)?;
                let compiled = compiled.forbidden_paths(rule);
                Ok(evaluate_forbidden_paths(
                    compiled,
                    normalized_path.unwrap_or_default(),
                ))
            }
            "path_allowlist" => {
                let rule = rules
                    .and_then(|rules| rules.path_allowlist.as_ref())
                    .ok_or(Inactive::Absent)?;
                self.activity(index, rule.enabled)?;
                let compiled = compiled.path_allowlist(rule);
                let operation = match action.action_type.as_str() {
                    "file_read" => PathOperation::Read,
                    "patch_apply" => PathOperation::Patch,
                    _ => PathOperation::Write,
                };
                Ok(evaluate_path_allowlist(
                    compiled,
                    normalized_path.unwrap_or_default(),
                    operation,
                ))
            }
            "secret_patterns" => {
                let rule = rules
                    .and_then(|rules| rules.secret_patterns.as_ref())
                    .ok_or(Inactive::Absent)?;
                let path_bearing =
                    matches!(action.action_type.as_str(), "file_write" | "patch_apply");
                // egress and tool_call are scanned only when they carry content.
                if !path_bearing && content.is_none() {
                    return Err(Inactive::Absent);
                }
                self.activity(index, rule.enabled)?;
                let compiled = compiled.secret_patterns(rule);
                let skip_path = if path_bearing { normalized_path } else { None };
                Ok(evaluate_secret_patterns(
                    rule,
                    compiled,
                    skip_path,
                    content.unwrap_or_default(),
                ))
            }
            "patch_integrity" => {
                let rule = rules
                    .and_then(|rules| rules.patch_integrity.as_ref())
                    .ok_or(Inactive::Absent)?;
                self.activity(index, rule.enabled)?;
                let compiled = compiled.patch_integrity(rule);
                Ok(evaluate_patch_integrity(
                    rule,
                    compiled,
                    content.unwrap_or_default(),
                ))
            }
            "shell_commands" => {
                let rule = rules
                    .and_then(|rules| rules.shell_commands.as_ref())
                    .ok_or(Inactive::Absent)?;
                self.activity(index, rule.enabled)?;
                let compiled = compiled.shell_commands(rule);
                Ok(evaluate_shell_commands(
                    rule,
                    compiled,
                    action.target.as_deref().unwrap_or_default(),
                ))
            }
            "tool_access" => {
                let base = rules.and_then(|rules| rules.tool_access.as_ref());
                let overlay = matched_profile.and_then(|profile| {
                    profile
                        .tool_access
                        .as_ref()
                        .map(|overlay| (profile.id.as_str(), overlay))
                });
                if base.is_none() && overlay.is_none() {
                    return Err(Inactive::Absent);
                }
                if let Some(rule) = base {
                    self.activity(index, rule.enabled)?;
                }
                Ok(evaluate_tool_access(base, overlay, action))
            }
            "egress" => {
                let base = rules.and_then(|rules| rules.egress.as_ref());
                let overlay = matched_profile.and_then(|profile| {
                    profile
                        .egress
                        .as_ref()
                        .map(|overlay| (profile.id.as_str(), overlay))
                });
                if base.is_none() && overlay.is_none() {
                    return Err(Inactive::Absent);
                }
                if let Some(rule) = base {
                    self.activity(index, rule.enabled)?;
                }
                let base_compiled = base.map(|rule| compiled.egress(rule));
                let overlay_compiled = matched_index
                    .zip(overlay)
                    .and_then(|(position, (_, overlay))| compiled.origin_egress(position, overlay));
                let host = action.target.as_deref().and_then(normalize_host);
                Ok(evaluate_egress(
                    base,
                    base_compiled,
                    overlay,
                    overlay_compiled,
                    host.as_deref(),
                ))
            }
            "computer_use" => {
                let rule = rules
                    .and_then(|rules| rules.computer_use.as_ref())
                    .ok_or(Inactive::Absent)?;
                self.activity(index, rule.enabled)?;
                Ok(evaluate_computer_use(
                    rule,
                    action.target.as_deref().unwrap_or_default(),
                ))
            }
            "remote_desktop_channels" => {
                let rule = rules
                    .and_then(|rules| rules.remote_desktop_channels.as_ref())
                    .ok_or(Inactive::Absent)?;
                self.activity(index, rule.enabled)?;
                evaluate_remote_desktop_channels(rule, action.target.as_deref().unwrap_or_default())
                    .ok_or(Inactive::Absent)
            }
            "input_injection" => {
                let rule = rules
                    .and_then(|rules| rules.input_injection.as_ref())
                    .ok_or(Inactive::Absent)?;
                self.activity(index, rule.enabled)?;
                Ok(evaluate_input_injection(
                    rule,
                    action.target.as_deref().unwrap_or_default(),
                ))
            }
            "browser_automation" => {
                let rule = rules
                    .and_then(|rules| rules.browser_automation.as_ref())
                    .ok_or(Inactive::Absent)?;
                self.activity(index, rule.enabled)?;
                let compiled = compiled.browser_automation(rule);
                Ok(evaluate_browser_automation(rule, compiled, action))
            }
            "code_execution" => {
                let rule = rules
                    .and_then(|rules| rules.code_execution.as_ref())
                    .ok_or(Inactive::Absent)?;
                self.activity(index, rule.enabled)?;
                Ok(evaluate_code_execution(rule, action))
            }
            _ => Err(Inactive::Absent),
        }
    }

    fn posture_capability_guard(
        &mut self,
        posture: &Option<PostureResult>,
    ) -> Option<BlockDecision> {
        let posture_result = posture.as_ref()?;
        let posture_extension = self
            .spec
            .extensions
            .as_ref()
            .and_then(|extensions| extensions.posture.as_ref())?;
        let capability = required_capability(self.action.action_type.as_str())?;
        let Some(current_state) = posture_extension.states.get(&posture_result.current) else {
            let rule = format!("extensions.posture.states.{}", posture_result.current);
            let reason = format!("unknown posture state '{}'", posture_result.current);
            self.record(
                "posture_capability",
                RuleOutcome::Deny,
                Some(&rule),
                Some(&reason),
                true,
            );
            return Some(BlockDecision::deny(&rule, &reason));
        };

        if current_state
            .capabilities
            .iter()
            .any(|entry| entry == capability)
        {
            self.record(
                "posture_capability",
                RuleOutcome::Allow,
                None,
                Some("posture capabilities satisfied"),
                true,
            );
            return None;
        }

        let rule = format!(
            "extensions.posture.states.{}.capabilities",
            posture_result.current
        );
        let reason = format!(
            "posture '{}' does not allow capability '{capability}'",
            posture_result.current
        );
        self.record(
            "posture_capability",
            RuleOutcome::Deny,
            Some(&rule),
            Some(&reason),
            true,
        );
        Some(BlockDecision::deny(&rule, &reason))
    }
}

// ---------------------------------------------------------------------------
// Rule blocks
// ---------------------------------------------------------------------------

fn evaluate_forbidden_paths(compiled: &CompiledForbiddenPaths, path: &str) -> BlockDecision {
    if compiled.exceptions.matches(path) {
        return BlockDecision::allow(
            Some("rules.forbidden_paths.exceptions"),
            Some("path matched an explicit exception"),
        );
    }
    if compiled.patterns.matches(path) {
        return BlockDecision::deny(
            "rules.forbidden_paths.patterns",
            "path matched a forbidden pattern",
        );
    }
    BlockDecision::allow(None, Some("path did not match any forbidden pattern"))
}

fn evaluate_path_allowlist(
    compiled: &CompiledPathAllowlist,
    path: &str,
    operation: PathOperation,
) -> BlockDecision {
    let patterns = match operation {
        PathOperation::Read => &compiled.read,
        PathOperation::Write => &compiled.write,
        PathOperation::Patch => compiled.patch(),
    };
    if patterns.matches(path) {
        BlockDecision::allow(Some("rules.path_allowlist"), Some("path matched allowlist"))
    } else {
        BlockDecision::deny("rules.path_allowlist", "path did not match allowlist")
    }
}

/// Guard the one invariant the compiled matchers rest on: a block's compiled
/// pattern list is positionally parallel to the one the document declares.
///
/// It holds by construction -- the matchers are compiled from the same
/// document the rule is read from -- so this only fires on a future refactor
/// that broke that. It fails closed rather than iterating the shorter of the
/// two, which would silently stop consulting patterns the policy declared.
fn pattern_count_mismatch(block: &str, declared: usize, compiled: usize) -> Option<BlockDecision> {
    if declared == compiled {
        return None;
    }
    debug_assert_eq!(
        declared, compiled,
        "compiled pattern count for {block} does not match the document"
    );
    Some(BlockDecision::deny(
        block,
        "the compiled pattern set does not match the policy",
    ))
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Warn => 1,
        Severity::Error => 2,
        Severity::Critical => 3,
    }
}

fn evaluate_secret_patterns(
    rule: &SecretPatternsRule,
    compiled: &CompiledSecretPatterns,
    skip_path: Option<&str>,
    content: &str,
) -> BlockDecision {
    if let Some(path) = skip_path
        && compiled.skip_paths.matches(path)
    {
        return BlockDecision::allow(
            Some("rules.secret_patterns.skip_paths"),
            Some("path is excluded from secret scanning"),
        );
    }

    if let Some(denied) = pattern_count_mismatch(
        "rules.secret_patterns.patterns",
        rule.patterns.len(),
        compiled.patterns.len(),
    ) {
        return denied;
    }

    let mut best: Option<(u8, &crate::rules::SecretPattern)> = None;
    for (pattern, compiled) in rule.patterns.iter().zip(&compiled.patterns) {
        // Fail closed: a pattern that will not compile under the HushSpec regex
        // profile denies the action rather than being skipped (core spec 3.14.3).
        let regex = match compiled {
            Ok(regex) => regex,
            Err(error) => {
                return BlockDecision::deny(
                    &format!("rules.secret_patterns.patterns.{}.pattern", pattern.name),
                    &format!(
                        "secret pattern '{}' is invalid: {}",
                        pattern.name,
                        error.message()
                    ),
                );
            }
        };
        if regex.is_match(content) {
            let rank = severity_rank(pattern.severity);
            // Strictly greater keeps the first pattern in document order among
            // those at the highest matched severity.
            if best.is_none_or(|(best_rank, _)| rank > best_rank) {
                best = Some((rank, pattern));
            }
        }
    }

    match best {
        None => BlockDecision::allow(None, Some("content did not match any secret pattern")),
        Some((_, pattern)) => {
            let matched_rule = format!("rules.secret_patterns.patterns.{}", pattern.name);
            let reason = format!("content matched secret pattern '{}'", pattern.name);
            match pattern.severity {
                Severity::Warn => BlockDecision::warn(&matched_rule, &reason),
                Severity::Error | Severity::Critical => BlockDecision::deny(&matched_rule, &reason),
            }
        }
    }
}

fn evaluate_patch_integrity(
    rule: &PatchIntegrityRule,
    compiled: &[CompiledRegex],
    content: &str,
) -> BlockDecision {
    if let Some(denied) = pattern_count_mismatch(
        "rules.patch_integrity.forbidden_patterns",
        rule.forbidden_patterns.len(),
        compiled.len(),
    ) {
        return denied;
    }
    for (index, pattern) in compiled.iter().enumerate() {
        let regex = match pattern {
            Ok(regex) => regex,
            Err(error) => {
                return BlockDecision::deny(
                    &format!("rules.patch_integrity.forbidden_patterns[{index}]"),
                    &format!("patch forbidden pattern is invalid: {}", error.message()),
                );
            }
        };
        if regex.is_match(content) {
            return BlockDecision::deny(
                &format!("rules.patch_integrity.forbidden_patterns[{index}]"),
                "patch content matched a forbidden pattern",
            );
        }
    }

    let stats = patch_stats(content);
    if stats.additions > rule.max_additions {
        return BlockDecision::deny(
            "rules.patch_integrity.max_additions",
            "patch additions exceeded max_additions",
        );
    }
    if stats.deletions > rule.max_deletions {
        return BlockDecision::deny(
            "rules.patch_integrity.max_deletions",
            "patch deletions exceeded max_deletions",
        );
    }
    if rule.require_balance {
        let one_sided = (stats.additions == 0) != (stats.deletions == 0);
        if one_sided {
            return BlockDecision::deny(
                "rules.patch_integrity.max_imbalance_ratio",
                "patch has changes on only one side; the imbalance ratio is infinite",
            );
        }
        if stats.additions > 0 && stats.deletions > 0 {
            let larger = stats.additions.max(stats.deletions) as f64;
            let smaller = stats.additions.min(stats.deletions) as f64;
            if larger / smaller > rule.max_imbalance_ratio {
                return BlockDecision::deny(
                    "rules.patch_integrity.max_imbalance_ratio",
                    "patch exceeded max imbalance ratio",
                );
            }
        }
    }

    BlockDecision::allow(None, Some("patch passed integrity checks"))
}

fn evaluate_shell_commands(
    rule: &ShellCommandsRule,
    compiled: &[CompiledRegex],
    command: &str,
) -> BlockDecision {
    if let Some(denied) = pattern_count_mismatch(
        "rules.shell_commands.forbidden_patterns",
        rule.forbidden_patterns.len(),
        compiled.len(),
    ) {
        return denied;
    }
    for (index, pattern) in compiled.iter().enumerate() {
        let regex = match pattern {
            Ok(regex) => regex,
            Err(error) => {
                return BlockDecision::deny(
                    &format!("rules.shell_commands.forbidden_patterns[{index}]"),
                    &format!("shell forbidden pattern is invalid: {}", error.message()),
                );
            }
        };
        if regex.is_match(command) {
            return BlockDecision::deny(
                &format!("rules.shell_commands.forbidden_patterns[{index}]"),
                "shell command matched a forbidden pattern",
            );
        }
    }
    BlockDecision::allow(None, Some("command did not match any forbidden pattern"))
}

/// Tool names are exact, case-sensitive strings after NFC normalization
/// (core spec 3.7); no glob or regex metacharacters.
fn tool_list_contains(entries: &[String], tool: &str) -> bool {
    entries.iter().any(|entry| entry.nfc().eq(tool.nfc()))
}

fn evaluate_tool_access(
    base: Option<&ToolAccessRule>,
    overlay: Option<(&str, &OriginToolAccessOverlay)>,
    action: &EvaluationAction,
) -> BlockDecision {
    let tool = action.target.as_deref().unwrap_or_default();
    let prefix = overlay.map(|(id, _)| format!("extensions.origins.profiles.{id}.tool_access"));
    let overlay = overlay.map(|(_, overlay)| overlay);

    // 1. max_args_size: the smaller of the two when both are specified.
    let base_limit = base
        .and_then(|rule| rule.max_args_size)
        .map(|limit| (limit, "rules.tool_access.max_args_size".to_string()));
    let overlay_limit = overlay
        .and_then(|rule| rule.max_args_size)
        .zip(prefix.as_ref())
        .map(|(limit, prefix)| (limit, format!("{prefix}.max_args_size")));
    let limit = match (base_limit, overlay_limit) {
        (Some(base), Some(overlay)) => Some(if overlay.0 < base.0 { overlay } else { base }),
        (base, overlay) => base.or(overlay),
    };
    if let Some((max_args_size, matched_rule)) = limit
        && action.args_size.unwrap_or_default() > max_args_size
    {
        return BlockDecision::deny(&matched_rule, "tool arguments exceeded max_args_size");
    }

    // 2. block: union of both lists.
    if base.is_some_and(|rule| tool_list_contains(&rule.block, tool)) {
        return BlockDecision::deny("rules.tool_access.block", "tool is explicitly blocked");
    }
    if let (Some(rule), Some(prefix)) = (overlay, prefix.as_ref())
        && tool_list_contains(&rule.block, tool)
    {
        return BlockDecision::deny(&format!("{prefix}.block"), "tool is explicitly blocked");
    }

    // 3. require_confirmation: union of both lists.
    if base.is_some_and(|rule| tool_list_contains(&rule.require_confirmation, tool)) {
        return BlockDecision::warn(
            "rules.tool_access.require_confirmation",
            "tool requires confirmation",
        );
    }
    if let (Some(rule), Some(prefix)) = (overlay, prefix.as_ref())
        && tool_list_contains(&rule.require_confirmation, tool)
    {
        return BlockDecision::warn(
            &format!("{prefix}.require_confirmation"),
            "tool requires confirmation",
        );
    }

    // 4/5. allowlist mode: intersection when both lists are non-empty.
    let base_allow = base
        .map(|rule| rule.allow.as_slice())
        .filter(|list| !list.is_empty());
    let overlay_allow = overlay
        .map(|rule| rule.allow.as_slice())
        .filter(|list| !list.is_empty());
    if base_allow.is_some() || overlay_allow.is_some() {
        if let Some(list) = base_allow
            && !tool_list_contains(list, tool)
        {
            return BlockDecision::deny("rules.tool_access.allow", "tool is not in the allowlist");
        }
        if let (Some(list), Some(prefix)) = (overlay_allow, prefix.as_ref())
            && !tool_list_contains(list, tool)
        {
            return BlockDecision::deny(&format!("{prefix}.allow"), "tool is not in the allowlist");
        }
        let matched_rule = match (overlay_allow, prefix.as_ref()) {
            (Some(_), Some(prefix)) => format!("{prefix}.allow"),
            _ => "rules.tool_access.allow".to_string(),
        };
        return BlockDecision::allow(Some(&matched_rule), Some("tool is explicitly allowed"));
    }

    // 6. default: block when the base says block or the overlay specifies block.
    let base_default = base
        .map(|rule| rule.default)
        .unwrap_or(DefaultAction::Allow);
    let overlay_default = overlay.and_then(|rule| rule.default);
    let effective =
        if base_default == DefaultAction::Block || overlay_default == Some(DefaultAction::Block) {
            DefaultAction::Block
        } else {
            DefaultAction::Allow
        };
    let matched_rule = default_rule_path(
        base.is_some(),
        base_default,
        overlay_default,
        effective,
        "rules.tool_access.default",
        prefix.as_deref(),
    );
    match effective {
        DefaultAction::Allow => {
            BlockDecision::allow(Some(&matched_rule), Some("tool matched default allow"))
        }
        DefaultAction::Block => BlockDecision::deny(&matched_rule, "tool matched default block"),
    }
}

/// Path reported for a `default` decision: the object whose `default` field
/// determined the effective value.
fn default_rule_path(
    base_present: bool,
    base_default: DefaultAction,
    overlay_default: Option<DefaultAction>,
    effective: DefaultAction,
    base_path: &str,
    prefix: Option<&str>,
) -> String {
    let overlay_path = prefix.map(|prefix| format!("{prefix}.default"));
    match (effective, overlay_path) {
        (DefaultAction::Block, Some(overlay_path)) => {
            if base_present && base_default == DefaultAction::Block {
                base_path.to_string()
            } else {
                overlay_path
            }
        }
        (DefaultAction::Allow, Some(overlay_path)) => {
            if base_present || overlay_default.is_none() {
                base_path.to_string()
            } else {
                overlay_path
            }
        }
        (_, None) => base_path.to_string(),
    }
}

fn evaluate_egress(
    base: Option<&EgressRule>,
    base_compiled: Option<&CompiledEgress>,
    overlay: Option<(&str, &OriginEgressOverlay)>,
    overlay_compiled: Option<&CompiledEgress>,
    host: Option<&str>,
) -> BlockDecision {
    let prefix = overlay.map(|(id, _)| format!("extensions.origins.profiles.{id}.egress"));
    let overlay = overlay.map(|(_, overlay)| overlay);

    // 1. block: union of both lists.
    if base.is_some() && base_compiled.is_some_and(|compiled| compiled.block.matches(host)) {
        return BlockDecision::deny("rules.egress.block", "domain is explicitly blocked");
    }
    if let (Some(_), Some(prefix)) = (overlay, prefix.as_ref())
        && overlay_compiled.is_some_and(|compiled| compiled.block.matches(host))
    {
        return BlockDecision::deny(&format!("{prefix}.block"), "domain is explicitly blocked");
    }

    // 2. allow: intersection when both lists are non-empty.
    let base_allow = base
        .zip(base_compiled)
        .map(|(_, compiled)| &compiled.allow)
        .filter(|list| !list.is_empty());
    let overlay_allow = overlay
        .zip(overlay_compiled)
        .map(|(_, compiled)| &compiled.allow)
        .filter(|list| !list.is_empty());
    if base_allow.is_some() || overlay_allow.is_some() {
        let base_ok = base_allow.is_none_or(|list| list.matches(host));
        let overlay_ok = overlay_allow.is_none_or(|list| list.matches(host));
        if base_ok && overlay_ok {
            let matched_rule = match (overlay_allow, prefix.as_ref()) {
                (Some(_), Some(prefix)) => format!("{prefix}.allow"),
                _ => "rules.egress.allow".to_string(),
            };
            return BlockDecision::allow(Some(&matched_rule), Some("domain is explicitly allowed"));
        }
    }

    // 3. default.
    let base_default = base
        .map(|rule| rule.default)
        .unwrap_or(DefaultAction::Block);
    let overlay_default = overlay.and_then(|rule| rule.default);
    let effective =
        if base_default == DefaultAction::Block || overlay_default == Some(DefaultAction::Block) {
            DefaultAction::Block
        } else {
            DefaultAction::Allow
        };
    let matched_rule = default_rule_path(
        base.is_some(),
        base_default,
        overlay_default,
        effective,
        "rules.egress.default",
        prefix.as_deref(),
    );
    match effective {
        DefaultAction::Allow => {
            BlockDecision::allow(Some(&matched_rule), Some("domain matched default allow"))
        }
        DefaultAction::Block => BlockDecision::deny(&matched_rule, "domain matched default block"),
    }
}

fn evaluate_computer_use(rule: &ComputerUseRule, target: &str) -> BlockDecision {
    if rule.allowed_actions.iter().any(|action| action == target) {
        return BlockDecision::allow(
            Some("rules.computer_use.allowed_actions"),
            Some("computer-use action is explicitly allowed"),
        );
    }
    match rule.mode {
        ComputerUseMode::Observe => BlockDecision::allow(
            Some("rules.computer_use.mode"),
            Some("observe mode does not block unlisted actions"),
        ),
        // guardrail and fail_closed have identical reference semantics (D9).
        ComputerUseMode::Guardrail | ComputerUseMode::FailClosed => BlockDecision::deny(
            "rules.computer_use.mode",
            "unlisted computer-use action is denied",
        ),
    }
}

fn evaluate_remote_desktop_channels(
    rule: &RemoteDesktopChannelsRule,
    target: &str,
) -> Option<BlockDecision> {
    let (field, allowed) = match target {
        "remote.clipboard" => ("clipboard", rule.clipboard),
        "remote.file_transfer" => ("file_transfer", rule.file_transfer),
        "remote.audio" => ("audio", rule.audio),
        "remote.drive_mapping" => ("drive_mapping", rule.drive_mapping),
        _ => return None,
    };
    let matched_rule = format!("rules.remote_desktop_channels.{field}");
    Some(if allowed {
        BlockDecision::allow(
            Some(&matched_rule),
            Some(&format!("remote desktop channel '{field}' is enabled")),
        )
    } else {
        BlockDecision::deny(
            &matched_rule,
            &format!("remote desktop channel '{field}' is disabled"),
        )
    })
}

fn evaluate_input_injection(rule: &InputInjectionRule, target: &str) -> BlockDecision {
    if rule.allowed_types.is_empty() {
        return BlockDecision::deny(
            "rules.input_injection.allowed_types",
            "input injection is not allowed when allowed_types is empty",
        );
    }
    if rule.allowed_types.iter().any(|allowed| allowed == target) {
        return BlockDecision::allow(
            Some("rules.input_injection.allowed_types"),
            Some("input injection type is explicitly allowed"),
        );
    }
    BlockDecision::deny(
        "rules.input_injection.allowed_types",
        "input injection type is not allowed",
    )
}

/// Built-in credential detectors consulted by `browser_automation` when
/// `credential_detection` is true (core spec 3.11). Documents needing portable
/// detection list their own patterns in `extra_credential_patterns`.
pub const BUILTIN_CREDENTIAL_PATTERNS: &[(&str, &str)] = &[
    ("aws_access_key", "(AKIA|ASIA)[0-9A-Z]{16}"),
    ("github_token", "gh[opsur]_[A-Za-z0-9]{36}"),
    ("github_fine_grained_pat", "github_pat_[0-9a-zA-Z_]{50,}"),
    ("openai_key", "sk-[A-Za-z0-9_-]{20,}"),
    ("slack_token", "xox[baprs]-[0-9A-Za-z-]{10,}"),
    (
        "private_key",
        "-----BEGIN[ \\t]+(RSA[ \\t]+|EC[ \\t]+|OPENSSH[ \\t]+)?PRIVATE[ \\t]+KEY-----",
    ),
    (
        "jwt",
        "eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}",
    ),
];

/// The built-in credential detectors, compiled once per process. A detector
/// whose pattern will not compile is `None` and matches nothing, exactly as
/// the per-call `compile_profile_regex(..).is_ok_and(..)` did.
static BUILTIN_CREDENTIAL_REGEXES: LazyLock<Vec<(&'static str, Option<Regex>)>> =
    LazyLock::new(|| {
        BUILTIN_CREDENTIAL_PATTERNS
            .iter()
            .map(|(name, pattern)| (*name, compile_profile_regex(pattern).ok()))
            .collect()
    });

fn evaluate_browser_automation(
    rule: &BrowserAutomationRule,
    compiled: &CompiledBrowserAutomation,
    action: &EvaluationAction,
) -> BlockDecision {
    let verb = action.target.as_deref().unwrap_or_default();

    // 1. verb allowlist (exact match).
    if !rule.allowed_verbs.is_empty() && !rule.allowed_verbs.iter().any(|allowed| allowed == verb) {
        return BlockDecision::deny(
            "rules.browser_automation.allowed_verbs",
            "browser verb is not in the allowlist",
        );
    }

    // 2. destination host.
    if let Some(url) = action.url.as_deref() {
        let host = normalize_host(url);
        if compiled.blocked_domains.matches(host.as_deref()) {
            return BlockDecision::deny(
                "rules.browser_automation.blocked_domains",
                "destination host is explicitly blocked",
            );
        }
        if !compiled.allowed_domains.is_empty()
            && !compiled.allowed_domains.matches(host.as_deref())
        {
            return BlockDecision::deny(
                "rules.browser_automation.allowed_domains",
                "destination host is not in the allowlist",
            );
        }
    }

    // 3. credential detection on typed input.
    if rule.credential_detection
        && let Some(content) = action.content.as_deref()
    {
        for (name, regex) in BUILTIN_CREDENTIAL_REGEXES.iter() {
            if regex.as_ref().is_some_and(|regex| regex.is_match(content)) {
                return BlockDecision::deny(
                    "rules.browser_automation.credential_detection",
                    &format!("typed input matched built-in credential detector '{name}'"),
                );
            }
        }
        if let Some(denied) = pattern_count_mismatch(
            "rules.browser_automation.extra_credential_patterns",
            rule.extra_credential_patterns.len(),
            compiled.extra_credential_patterns.len(),
        ) {
            return denied;
        }
        for (index, pattern) in compiled.extra_credential_patterns.iter().enumerate() {
            let regex = match pattern {
                Ok(regex) => regex,
                Err(error) => {
                    return BlockDecision::deny(
                        &format!("rules.browser_automation.extra_credential_patterns[{index}]"),
                        &format!("credential pattern is invalid: {}", error.message()),
                    );
                }
            };
            if regex.is_match(content) {
                return BlockDecision::deny(
                    "rules.browser_automation.credential_detection",
                    &format!("typed input matched extra_credential_patterns[{index}]"),
                );
            }
        }
    }

    BlockDecision::allow(
        Some("rules.browser_automation"),
        Some("browser action is permitted"),
    )
}

fn evaluate_code_execution(rule: &CodeExecutionRule, action: &EvaluationAction) -> BlockDecision {
    let language = action.target.as_deref().unwrap_or_default();

    // 1. language allowlist (exact, case-sensitive).
    if !rule.language_allowlist.is_empty()
        && !rule
            .language_allowlist
            .iter()
            .any(|allowed| allowed == language)
    {
        return BlockDecision::deny(
            "rules.code_execution.language_allowlist",
            "language is not in the allowlist",
        );
    }

    // 2. network access.
    if action.network == Some(true) && !rule.network_access {
        return BlockDecision::deny(
            "rules.code_execution.network_access",
            "network access is not permitted for code execution",
        );
    }

    // 3. execution time bound.
    if let (Some(limit), Some(requested)) = (rule.max_execution_time_ms, action.timeout_ms)
        && requested > limit as u64
    {
        return BlockDecision::deny(
            "rules.code_execution.max_execution_time_ms",
            "requested execution time exceeds max_execution_time_ms",
        );
    }

    // 4. module denylist: literal word match within the scanned prefix.
    if let Some(content) = action.content.as_deref() {
        let scanned = match rule.max_scan_bytes {
            Some(limit) if limit < content.len() => {
                let mut end = limit;
                while end > 0 && !content.is_char_boundary(end) {
                    end -= 1;
                }
                &content[..end]
            }
            _ => content,
        };
        for module in &rule.module_denylist {
            if contains_word(scanned, module) {
                return BlockDecision::deny(
                    "rules.code_execution.module_denylist",
                    &format!("code references denied module '{module}'"),
                );
            }
        }
    }

    BlockDecision::allow(
        Some("rules.code_execution"),
        Some("code execution is permitted"),
    )
}

/// Whether `word` occurs in `text` bounded by non-`[A-Za-z0-9_]` characters
/// or the text boundaries (core spec 3.12 step 4).
fn contains_word(text: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let is_word_byte = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let bytes = text.as_bytes();
    let mut start = 0;
    while let Some(offset) = text[start..].find(word) {
        let at = start + offset;
        let end = at + word.len();
        let before_ok = at == 0 || !is_word_byte(bytes[at - 1]);
        let after_ok = end == bytes.len() || !is_word_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        start = at + 1;
        while start < bytes.len() && !text.is_char_boundary(start) {
            start += 1;
        }
        if start >= bytes.len() {
            break;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Posture and origins
// ---------------------------------------------------------------------------

fn resolve_posture(
    spec: &HushSpec,
    matched_profile: Option<&OriginProfile>,
    posture: Option<&PostureContext>,
) -> Option<PostureResult> {
    let posture_extension = spec
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.posture.as_ref())?;

    let current = matched_profile
        .and_then(|profile| profile.posture.clone())
        .or_else(|| posture.and_then(|context| context.current.clone()))
        .unwrap_or_else(|| posture_extension.initial.clone());

    let signal = posture
        .and_then(|context| context.signal.as_deref())
        .filter(|signal| *signal != "none");
    let next = signal
        .and_then(|signal| next_posture_state(posture_extension, &current, signal))
        .unwrap_or_else(|| current.clone());

    Some(PostureResult { current, next })
}

fn next_posture_state(posture: &PostureExtension, current: &str, signal: &str) -> Option<String> {
    // D18 (pending): first matching transition in document order.
    posture.transitions.iter().find_map(|transition| {
        if transition.from != "*" && transition.from != current {
            return None;
        }
        if trigger_name(&transition.on) != signal {
            return None;
        }
        Some(transition.to.clone())
    })
}

/// Origin profile selection (origins spec Section 3): candidates are profiles
/// with a `match` object every present field of which is satisfied; a
/// `space_id` match wins outright, then the greatest matched-field count,
/// then document order.
///
/// Returns the winning profile's *position*, which also indexes the compiled
/// overlays a [`CompiledPolicy`](crate::CompiledPolicy) built for it.
fn select_origin_profile(spec: &HushSpec, origin: Option<&OriginContext>) -> Option<usize> {
    let origin = origin?;
    let profiles = spec
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.origins.as_ref())
        .map(|origins| origins.profiles.as_slice())?;

    let mut best: Option<(u32, usize)> = None;
    for (position, profile) in profiles.iter().enumerate() {
        let Some(rules) = profile.match_rules.as_ref() else {
            continue;
        };
        let Some(matched_fields) = match_origin(rules, origin) else {
            continue;
        };
        if rules.space_id.is_some() {
            return Some(position);
        }
        if best.is_none_or(|(best_count, _)| matched_fields > best_count) {
            best = Some((matched_fields, position));
        }
    }
    best.map(|(_, position)| position)
}

/// Number of `match` fields satisfied by `origin`, or `None` when any present
/// field is not satisfied. `tags` counts as one field.
fn match_origin(rules: &crate::extensions::OriginMatch, origin: &OriginContext) -> Option<u32> {
    let mut count = 0;
    let mut check_string = |expected: &Option<String>, actual: &Option<String>| -> bool {
        match expected {
            None => true,
            Some(expected) => {
                if actual.as_ref() == Some(expected) {
                    count += 1;
                    true
                } else {
                    false
                }
            }
        }
    };
    if !check_string(&rules.provider, &origin.provider)
        || !check_string(&rules.tenant_id, &origin.tenant_id)
        || !check_string(&rules.space_id, &origin.space_id)
        || !check_string(&rules.space_type, &origin.space_type)
        || !check_string(&rules.visibility, &origin.visibility)
        || !check_string(&rules.sensitivity, &origin.sensitivity)
        || !check_string(&rules.actor_role, &origin.actor_role)
    {
        return None;
    }
    if let Some(external_participants) = rules.external_participants {
        if origin.external_participants != Some(external_participants) {
            return None;
        }
        count += 1;
    }
    if !rules.tags.is_empty() {
        if !rules
            .tags
            .iter()
            .all(|tag| origin.tags.iter().any(|candidate| candidate == tag))
        {
            return None;
        }
        count += 1;
    }
    Some(count)
}

/// Capability the posture guard requires per action type (posture spec 3.3).
fn required_capability(action_type: &str) -> Option<&'static str> {
    match action_type {
        "file_read" => Some("file_access"),
        "file_write" => Some("file_write"),
        "patch_apply" => Some("patch"),
        "shell_command" => Some("shell"),
        "tool_call" => Some("tool_call"),
        "egress" => Some("egress"),
        "custom" => Some("custom"),
        _ => None,
    }
}

fn trigger_name(trigger: &TransitionTrigger) -> &'static str {
    match trigger {
        TransitionTrigger::UserApproval => "user_approval",
        TransitionTrigger::UserDenial => "user_denial",
        TransitionTrigger::CriticalViolation => "critical_violation",
        TransitionTrigger::AnyViolation => "any_violation",
        TransitionTrigger::Timeout => "timeout",
        TransitionTrigger::BudgetExhausted => "budget_exhausted",
        TransitionTrigger::PatternMatch => "pattern_match",
    }
}

// ---------------------------------------------------------------------------
// Path globs (core spec 3.14.1)
// ---------------------------------------------------------------------------

/// Normalize a filesystem path for matching: NFC, `\` to `/`, collapsed
/// separators, lexical `.`/`..` resolution, no trailing `/`.
pub fn normalize_path(target: &str) -> String {
    let unified: String = target.nfc().collect::<String>().replace('\\', "/");
    let absolute = unified.starts_with('/');
    let mut segments: Vec<&str> = Vec::new();
    for segment in unified.split('/') {
        match segment {
            "" | "." => {}
            ".." => match segments.last() {
                Some(last) if *last != ".." => {
                    segments.pop();
                }
                _ if absolute => {}
                _ => segments.push(".."),
            },
            other => segments.push(other),
        }
    }
    let joined = segments.join("/");
    if absolute {
        format!("/{joined}")
    } else {
        joined
    }
}

/// Compile a path glob (core spec 3.14.1) into an anchored regex.
///
/// [`CompiledPolicy`](crate::CompiledPolicy) calls this once per declared glob
/// and keeps the automaton; `None` (an uncompilable glob) matches nothing.
pub(crate) fn path_glob_regex(pattern: &str) -> Option<Regex> {
    let chars: Vec<char> = pattern.nfc().collect();
    let mut regex = String::from("^");
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        if ch == '*' && chars.get(index + 1) == Some(&'*') {
            let at_segment_start = index == 0 || chars[index - 1] == '/';
            if at_segment_start && chars.get(index + 2) == Some(&'/') {
                // `**/`: zero or more complete leading segments.
                regex.push_str("(?:[^/]*/)*");
                index += 3;
            } else {
                regex.push_str(".*");
                index += 2;
            }
            continue;
        }
        match ch {
            '*' => regex.push_str("[^/]*"),
            '?' => regex.push_str("[^/]"),
            other => regex.push_str(&regex::escape(&other.to_string())),
        }
        index += 1;
    }
    regex.push('$');
    Regex::new(&regex).ok()
}

/// Whether `path` (already normalized) matches the path glob `pattern`.
pub fn path_glob_matches(pattern: &str, path: &str) -> bool {
    path_glob_regex(pattern).is_some_and(|regex| regex.is_match(path))
}

/// Match a raw path target against a path glob, normalizing the target first.
///
/// Kept only for the `h2h lint` code that has to agree with the evaluator's
/// glob semantics pattern by pattern; it compiles the glob on every call.
/// Everything that evaluates actions goes through
/// [`CompiledPolicy`](crate::CompiledPolicy) instead.
#[doc(hidden)]
pub fn glob_matches(pattern: &str, target: &str) -> bool {
    path_glob_matches(pattern, &normalize_path(target))
}

// ---------------------------------------------------------------------------
// Host patterns (core spec 3.14.2)
// ---------------------------------------------------------------------------

/// Reduce an egress target (host, `host:port`, or URL) to a normalized host.
/// Returns `None` when the target cannot be reduced to a syntactically valid
/// host, in which case it matches nothing.
pub fn normalize_host(target: &str) -> Option<String> {
    let target = target.trim();
    let mut authority = match target.find("://") {
        Some(index) => &target[index + 3..],
        None => target,
    };
    let end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
    authority = &authority[..end];
    if let Some(at) = authority.rfind('@') {
        authority = &authority[at + 1..];
    }
    if authority.is_empty() {
        return None;
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']')?;
        let inner = &rest[..close];
        if inner.is_empty()
            || !inner
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        {
            return None;
        }
        return Some(format!("[{}]", inner.to_ascii_lowercase()));
    }

    let mut host = authority;
    if let Some(colon) = host.rfind(':') {
        let port = &host[colon + 1..];
        if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
            host = &host[..colon];
        }
    }
    if host.contains(':') {
        return None;
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() {
        return None;
    }

    let mut labels = Vec::new();
    for label in host.split('.') {
        if label.is_empty() {
            return None;
        }
        labels.push(normalize_host_label(label)?);
    }
    let normalized = labels.join(".");
    if !normalized
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
    {
        return None;
    }
    Some(normalized)
}

/// Normalize one host label: ASCII lowercase, or the IDNA A-label (punycode)
/// of the NFC-normalized, lowercased label when it is not ASCII.
fn normalize_host_label(label: &str) -> Option<String> {
    if label.is_ascii() {
        return Some(label.to_ascii_lowercase());
    }
    let folded: String = label.to_lowercase().nfc().collect();
    if folded.is_ascii() {
        return Some(folded);
    }
    Some(format!("xn--{}", punycode_encode(&folded)?))
}

/// Normalize a host pattern (steps 5-7 of core spec 3.14.2), preserving `*`.
pub(crate) fn normalize_host_pattern(pattern: &str) -> String {
    let pattern = pattern.trim();
    let pattern = pattern.strip_suffix('.').unwrap_or(pattern);
    if pattern.starts_with('[') {
        return pattern.to_ascii_lowercase();
    }
    pattern
        .split('.')
        .map(|label| {
            if label.is_ascii() {
                label.to_ascii_lowercase()
            } else {
                normalize_host_label(label).unwrap_or_else(|| label.to_lowercase())
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn is_ipv4_literal(host: &str) -> bool {
    let octets: Vec<&str> = host.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && octet.len() <= 3
                && octet.bytes().all(|b| b.is_ascii_digit())
                && octet.parse::<u16>().is_ok_and(|value| value <= 255)
        })
}

pub(crate) fn is_ip_literal(host: &str) -> bool {
    host.starts_with('[') || is_ipv4_literal(host)
}

/// Compile an already-normalized host pattern (core spec 3.14.2) into an
/// anchored regex: `*` is one or more non-dot characters, `**` one or more
/// characters including dots, everything else literal.
///
/// The IP-literal rule is *not* in the automaton: an IP-literal host matches
/// only a byte-equal pattern, which the caller checks first (see
/// [`host_pattern_matches`] and the compiled host sets).
pub(crate) fn host_pattern_regex(normalized_pattern: &str) -> Option<Regex> {
    let mut regex = String::from("^");
    let chars: Vec<char> = normalized_pattern.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '*' {
            if chars.get(index + 1) == Some(&'*') {
                regex.push_str(".+");
                index += 2;
            } else {
                regex.push_str("[^.]+");
                index += 1;
            }
            continue;
        }
        regex.push_str(&regex::escape(&chars[index].to_string()));
        index += 1;
    }
    regex.push('$');
    Regex::new(&regex).ok()
}

/// Whether a normalized host matches a host pattern (core spec 3.14.2):
/// `*` is one or more non-dot characters, `**` one or more characters
/// including dots, everything else literal. IP literals match only exactly.
///
/// Compiles the pattern on every call; evaluation goes through the host sets a
/// [`CompiledPolicy`](crate::CompiledPolicy) built once.
pub fn host_pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = normalize_host_pattern(pattern);
    if is_ip_literal(host) {
        return pattern == host;
    }
    host_pattern_regex(&pattern).is_some_and(|regex| regex.is_match(host))
}

/// RFC 3492 punycode encoding of one label (without the `xn--` prefix).
pub fn punycode_encode(input: &str) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    const INITIAL_BIAS: u32 = 72;
    const INITIAL_N: u32 = 128;

    fn adapt(mut delta: u32, num_points: u32, first_time: bool) -> u32 {
        delta = if first_time { delta / DAMP } else { delta / 2 };
        delta += delta / num_points;
        let mut k = 0;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            k += BASE;
        }
        k + (((BASE - TMIN + 1) * delta) / (delta + SKEW))
    }

    fn digit(value: u32) -> u8 {
        if value < 26 {
            b'a' + value as u8
        } else {
            b'0' + (value - 26) as u8
        }
    }

    let code_points: Vec<u32> = input.chars().map(|ch| ch as u32).collect();
    let mut output: Vec<u8> = code_points
        .iter()
        .filter(|&&cp| cp < 128)
        .map(|&cp| cp as u8)
        .collect();
    let basic_count = output.len() as u32;
    let mut handled = basic_count;
    if basic_count > 0 {
        output.push(b'-');
    }

    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;
    while (handled as usize) < code_points.len() {
        let m = code_points.iter().copied().filter(|&cp| cp >= n).min()?;
        delta = delta.checked_add((m - n).checked_mul(handled + 1)?)?;
        n = m;
        for &cp in &code_points {
            if cp < n {
                delta = delta.checked_add(1)?;
            }
            if cp == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        TMIN
                    } else if k >= bias + TMAX {
                        TMAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    output.push(digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                output.push(digit(q));
                bias = adapt(delta, handled + 1, handled == basic_count);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }
    String::from_utf8(output).ok()
}

// ---------------------------------------------------------------------------
// Patch statistics
// ---------------------------------------------------------------------------

fn patch_stats(content: &str) -> PatchStats {
    let mut additions = 0usize;
    let mut deletions = 0usize;
    for line in content.lines() {
        if line.starts_with("+++") || line.starts_with("---") {
            continue;
        }
        if line.starts_with('+') {
            additions += 1;
        } else if line.starts_with('-') {
            deletions += 1;
        }
    }
    PatchStats {
        additions,
        deletions,
    }
}

#[derive(Clone, Copy)]
enum PathOperation {
    Read,
    Write,
    Patch,
}

struct PatchStats {
    additions: usize,
    deletions: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_paths_lexically() {
        assert_eq!(normalize_path("/proj/../.env"), "/.env");
        assert_eq!(normalize_path("C:\\proj\\..\\.env"), "C:/.env");
        assert_eq!(normalize_path("//data//x//"), "/data/x");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("/a/../../b"), "/b");
        assert_eq!(normalize_path("../a"), "../a");
        assert_eq!(normalize_path("./a/./b"), "a/b");
        assert_eq!(normalize_path("/data/cafe\u{301}/x"), "/data/caf\u{e9}/x");
    }

    #[test]
    fn path_globs_follow_the_spec_table() {
        assert!(path_glob_matches("**/.env", ".env"));
        assert!(path_glob_matches("**/.env", "a/.env"));
        assert!(path_glob_matches("**/.env", "/home/u/.env"));
        assert!(path_glob_matches("/home/**", "/home/x/y"));
        assert!(!path_glob_matches("/home/**", "/home"));
        assert!(path_glob_matches("/proj/**/secret.txt", "/proj/secret.txt"));
        assert!(path_glob_matches("/tmp/*.log", "/tmp/a.log"));
        assert!(!path_glob_matches("/tmp/*.log", "/tmp/sub/a.log"));
        assert!(path_glob_matches("/a?b", "/axb"));
        assert!(!path_glob_matches("/a?b", "/a/b"));
        assert!(path_glob_matches("/logs/[old]/**", "/logs/[old]/a"));
        assert!(!path_glob_matches("/logs/[old]/**", "/logs/o/a"));
    }

    #[test]
    fn normalizes_hosts() {
        assert_eq!(
            normalize_host("API.EXAMPLE.COM:443").as_deref(),
            Some("api.example.com")
        );
        assert_eq!(
            normalize_host("https://user:pw@api.example.com:8443/v1?x=1#f").as_deref(),
            Some("api.example.com")
        );
        assert_eq!(
            normalize_host("api.example.com.").as_deref(),
            Some("api.example.com")
        );
        assert_eq!(normalize_host("[::1]:8080").as_deref(), Some("[::1]"));
        assert_eq!(
            normalize_host("B\u{dc}CHER.example").as_deref(),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(normalize_host(""), None);
        assert_eq!(normalize_host("a..b"), None);
        assert_eq!(normalize_host("bad host"), None);
    }

    #[test]
    fn host_patterns_follow_the_spec_table() {
        assert!(host_pattern_matches("*.example.com", "api.example.com"));
        assert!(!host_pattern_matches("*.example.com", "a.b.example.com"));
        assert!(!host_pattern_matches("*.example.com", "example.com"));
        assert!(host_pattern_matches(
            "api-*.example.com",
            "api-1.example.com"
        ));
        assert!(host_pattern_matches("**.example.com", "a.b.example.com"));
        assert!(!host_pattern_matches("**.example.com", "example.com"));
        assert!(host_pattern_matches(
            "b\u{fc}cher.example",
            "xn--bcher-kva.example"
        ));
        assert!(!host_pattern_matches("10.0.*.*", "10.0.0.1"));
        assert!(host_pattern_matches("10.0.0.1", "10.0.0.1"));
        assert!(host_pattern_matches("[::1]", "[::1]"));
    }

    #[test]
    fn punycode_matches_rfc_examples() {
        assert_eq!(punycode_encode("b\u{fc}cher").as_deref(), Some("bcher-kva"));
        assert_eq!(
            punycode_encode("m\u{fc}nchen").as_deref(),
            Some("mnchen-3ya")
        );
    }

    #[test]
    fn word_containment_respects_identifier_boundaries() {
        assert!(contains_word("import subprocess\n", "subprocess"));
        assert!(!contains_word("subprocessing = 1", "subprocess"));
        assert!(contains_word("x=socket.socket()", "socket"));
        assert!(!contains_word("", "socket"));
    }
}
