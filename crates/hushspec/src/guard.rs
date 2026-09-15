//! The enforcement point: one object an agent runtime asks before it acts.
//!
//! [`HushGuard`] wraps a compiled policy with everything an enforcement point
//! needs and a bare [`CompiledPolicy`] deliberately does not have: an
//! enforcement mode (with per-rule-path overrides), a confirmation channel for
//! `warn`, a receipt sink, observers, the acting [`Actor`], and a policy that
//! can be swapped underneath live traffic.
//!
//! ```no_run
//! use hushspec::{EvaluationAction, HushGuard, Policy};
//!
//! let guard = HushGuard::from_policy(Policy::from_path("rulesets/default.yaml")?)?;
//!
//! let action = EvaluationAction {
//!     action_type: "egress".to_string(),
//!     target: Some("api.example.com".to_string()),
//!     ..Default::default()
//! };
//!
//! let decision = guard.check(&action);
//! if !decision.allowed() {
//!     // refuse the tool call
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Fail-closed
//!
//! - A `warn` with no [`HushGuardBuilder::on_warn`] handler is a deny (core
//!   spec 6). There is no "warn means proceed" default.
//! - A policy that did not verify under `require_signature` puts the guard in
//!   the [refused](HushGuard::refused) state: every action is denied with
//!   `__hushspec_policy_unverified__` and an
//!   [`unverified_policy_receipt`], so the
//!   attempt is on the record rather than silently absent (signing spec 6.5).
//! - Panic mode and the refusal deny under *enforce* whatever the configured
//!   mode says: a kill switch that monitor mode could wave through would not
//!   be a kill switch.
//! - [`HushGuard::swap_policy`] keeps the policy already in force when the new
//!   one will not resolve, validate or compile.
//! - Monitor mode requires a sink or an observer, because a shadow decision
//!   nobody records is indistinguishable from no policy at all.
//!
//! # Thread safety
//!
//! A guard is `Send + Sync` and takes `&self` everywhere: share one across an
//! agent's worker threads behind an `Arc`. The policy lives behind an
//! `RwLock<Arc<..>>`, so an evaluation takes the read lock only long enough to
//! clone one `Arc` and a hot swap never blocks an in-flight decision.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use crate::compiled::CompiledPolicy;
use crate::evaluate::{Decision, EvaluationAction, EvaluationResult, PANIC_RULE};
use crate::generated_contract::{EXTENSION_KEYS, RULE_KEYS};
use crate::log::PolicyEvent;
use crate::observer::{EvaluationObserver, ObservableEvaluator};
use crate::panic::PanicState;
use crate::policy::{Policy, PolicyError};
use crate::receipt::{
    Actor, AuditConfig, AuditContext, DecisionReceipt, EnforcementMode, EnforcementOutcome,
    EnforcementSummary, POLICY_UNVERIFIED_RULE, PolicySummary, TimeSource, policy_summary,
    unverified_policy_receipt,
};
use crate::resolve::{Resolution, ResolveError, SignatureStatus, own_content_hash};
use crate::sink::ReceiptSink;

/// Decides whether a `warn` may proceed. Returning `true` is the runtime
/// saying "the operator confirmed this"; the receipt records
/// [`EnforcementOutcome::Confirmed`].
pub type WarnHandler = dyn Fn(&EvaluationResult, &EvaluationAction) -> bool + Send + Sync;

/// Guard-level enforcement mode plus per-rule-path overrides.
///
/// An override key is a rule path prefix -- `rules.egress`,
/// `extensions.detection`, `rules.secret_patterns.patterns` -- and the
/// *longest* matching prefix wins over [`EnforcementConfig::mode`]. A prefix
/// matches only at a segment boundary, so `rules.egress` matches
/// `rules.egress.default` but not `rules.egress_extra`.
#[derive(Clone, Debug, Default)]
pub struct EnforcementConfig {
    /// The mode for anything no override covers. Default:
    /// [`EnforcementMode::Enforce`].
    pub mode: EnforcementMode,
    /// Rule-path prefix -> mode.
    pub overrides: BTreeMap<String, EnforcementMode>,
}

impl EnforcementConfig {
    /// Enforce everything (the default).
    #[must_use]
    pub fn enforce() -> Self {
        Self::default()
    }

    /// Record every decision without acting on it. Needs a sink or an
    /// observer; see the module docs.
    #[must_use]
    pub fn monitor() -> Self {
        Self {
            mode: EnforcementMode::Monitor,
            overrides: BTreeMap::new(),
        }
    }

    /// Override the mode for one rule path prefix.
    #[must_use]
    pub fn with_override(mut self, rule_path: impl Into<String>, mode: EnforcementMode) -> Self {
        self.overrides.insert(rule_path.into(), mode);
        self
    }

    /// Reject a configuration an operator would misread.
    ///
    /// `observable` says whether a sink or observer is configured: monitor
    /// mode without one is refused, because it would silently allow
    /// everything the policy denies.
    fn validate(&self, observable: bool) -> Result<(), GuardError> {
        let mut monitor_reachable = self.mode == EnforcementMode::Monitor;
        for (key, mode) in &self.overrides {
            if *mode == EnforcementMode::Monitor {
                monitor_reachable = true;
            }
            // Only the top segment is checked: below it, paths are
            // policy-dependent (a pattern name, an index) and hot-swappable.
            if let Some(rest) = key.strip_prefix("rules.") {
                let block = top_segment(rest);
                if !RULE_KEYS.contains(&block) {
                    return Err(GuardError::Enforcement(format!(
                        "unknown rule in enforcement override '{key}': '{block}' is not a core rule"
                    )));
                }
            } else if let Some(rest) = key.strip_prefix("extensions.") {
                let extension = top_segment(rest);
                if !EXTENSION_KEYS.contains(&extension) {
                    return Err(GuardError::Enforcement(format!(
                        "unknown extension in enforcement override '{key}': '{extension}' is not a core extension"
                    )));
                }
            } else {
                return Err(GuardError::Enforcement(format!(
                    "enforcement override keys must start with 'rules.' or 'extensions.': '{key}'"
                )));
            }
        }
        if monitor_reachable && !observable {
            return Err(GuardError::Enforcement(
                "monitor mode requires an observer or a receipt sink: shadow decisions would be unobservable"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// The mode in force for `matched_rule`: the longest matching override, or
    /// [`EnforcementConfig::mode`].
    fn mode_for(&self, matched_rule: Option<&str>) -> EnforcementMode {
        let Some(matched) = matched_rule else {
            return self.mode;
        };
        // The detection pipeline reports the bare literal `detection` rather
        // than a hierarchical path, so an override keyed
        // `extensions.detection` would otherwise never match.
        let matched = if matched == "detection" {
            "extensions.detection"
        } else {
            matched
        };
        let mut best: Option<(&str, EnforcementMode)> = None;
        for (key, mode) in &self.overrides {
            if matches_rule_path_prefix(matched, key)
                && best.is_none_or(|(current, _)| key.len() > current.len())
            {
                best = Some((key, *mode));
            }
        }
        best.map_or(self.mode, |(_, mode)| mode)
    }
}

/// True when `matched_rule` equals `key` or continues past it at a segment
/// boundary (`.` or `[`).
#[must_use]
pub fn matches_rule_path_prefix(matched_rule: &str, key: &str) -> bool {
    if matched_rule == key {
        return true;
    }
    matched_rule
        .strip_prefix(key)
        .is_some_and(|rest| rest.starts_with('.') || rest.starts_with('['))
}

fn top_segment(path: &str) -> &str {
    &path[..path.find(['.', '[']).unwrap_or(path.len())]
}

/// Anything that can stop a [`HushGuard`] being built or a policy being
/// swapped in.
#[derive(Debug, thiserror::Error)]
pub enum GuardError {
    /// The policy would not load, resolve, validate or compile.
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// The policy's provenance could not be established.
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    /// The enforcement configuration is not usable; see the message.
    #[error("invalid enforcement configuration: {0}")]
    Enforcement(String),
}

/// Raised by [`HushGuard::enforce`] when an action may not proceed.
#[derive(Clone, Debug, thiserror::Error)]
#[error("action denied: {}", .result.reason.as_deref().or(.result.matched_rule.as_deref()).unwrap_or("policy denial"))]
pub struct Denied {
    /// The decision that stopped the action. Boxed so a `Result<_, Denied>`
    /// stays cheap to return on the common, allowed path.
    pub result: Box<EvaluationResult>,
    /// The receipt for it, when the guard built one.
    pub receipt: Option<Box<DecisionReceipt>>,
}

/// What a guard decided, and what it did about it.
#[derive(Clone, Debug)]
pub struct GuardDecision {
    /// The policy's decision.
    pub result: EvaluationResult,
    /// The evidence for it. Present unless [`AuditConfig::enabled`] is off.
    pub receipt: Option<DecisionReceipt>,
    /// True exactly when the action was stopped -- a `deny`, or a `warn` no
    /// confirmation channel approved, under an effective mode of
    /// [`EnforcementMode::Enforce`].
    ///
    /// False for an allow, for a confirmed warn, and for a decision that was
    /// only *recorded* (monitor mode, [`EnforcementOutcome::WouldBlock`]).
    /// [`GuardDecision::allowed`] is its complement and is what a caller
    /// branches on.
    pub enforced: bool,
    /// Mode and disposition, exactly as the receipt records them.
    pub enforcement: EnforcementSummary,
    /// Wall time of the evaluation.
    pub duration_us: u64,
}

impl GuardDecision {
    /// Whether the runtime may go ahead with the action.
    #[must_use]
    pub fn allowed(&self) -> bool {
        !self.enforced
    }

    /// The policy's decision, for a caller that only wants the verdict.
    #[must_use]
    pub fn decision(&self) -> Decision {
        self.result.decision
    }
}

/// The policy a guard is holding: one it can evaluate against, or one it
/// refused.
enum GuardPolicy {
    Active {
        compiled: Arc<CompiledPolicy>,
        resolution: Arc<Resolution>,
    },
    /// Verification was required and did not pass. The guard still knows what
    /// it was handed -- receipts name it -- but nothing is evaluated against
    /// it (signing spec 6.5).
    Refused {
        summary: Box<PolicySummary>,
        document: String,
        status: Box<SignatureStatus>,
    },
}

impl GuardPolicy {
    fn summary(&self) -> PolicySummary {
        match self {
            Self::Active { resolution, .. } => policy_summary(resolution),
            Self::Refused { summary, .. } => (**summary).clone(),
        }
    }

    fn content_hash(&self) -> &str {
        match self {
            Self::Active { resolution, .. } => &resolution.content_hash,
            Self::Refused { summary, .. } => &summary.content_hash,
        }
    }

    fn name(&self) -> Option<&str> {
        match self {
            Self::Active { resolution, .. } => resolution.spec.name.as_deref(),
            Self::Refused { summary, .. } => summary.name.as_deref(),
        }
    }
}

/// Builds a [`HushGuard`]. Start from [`HushGuard::builder`].
#[derive(Default)]
pub struct HushGuardBuilder {
    enforcement: EnforcementConfig,
    sink: Option<Box<dyn ReceiptSink>>,
    observers: ObservableEvaluator,
    actor: Option<Actor>,
    time_source: TimeSource,
    audit: AuditConfig,
    on_warn: Option<Box<WarnHandler>>,
}

impl std::fmt::Debug for HushGuardBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HushGuardBuilder")
            .field("enforcement", &self.enforcement)
            .field("sink", &self.sink.is_some())
            .field("observers", &self.observers)
            .field("actor", &self.actor)
            .field("time_source", &self.time_source)
            .field("audit", &self.audit)
            .field("on_warn", &self.on_warn.is_some())
            .finish()
    }
}

impl HushGuardBuilder {
    /// Enforce or monitor everything this guard decides.
    #[must_use]
    pub fn enforcement_mode(mut self, mode: EnforcementMode) -> Self {
        self.enforcement.mode = mode;
        self
    }

    /// Override the mode for one rule path prefix (see [`EnforcementConfig`]).
    #[must_use]
    pub fn enforcement_override(
        mut self,
        rule_path: impl Into<String>,
        mode: EnforcementMode,
    ) -> Self {
        self.enforcement.overrides.insert(rule_path.into(), mode);
        self
    }

    /// Replace the whole enforcement configuration.
    #[must_use]
    pub fn enforcement(mut self, enforcement: EnforcementConfig) -> Self {
        self.enforcement = enforcement;
        self
    }

    /// Where receipts and policy events go. One sink; fan out with
    /// [`MultiSink`](crate::MultiSink).
    #[must_use]
    pub fn sink(mut self, sink: Box<dyn ReceiptSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// Add an observer. Call more than once to add several.
    #[must_use]
    pub fn observer(mut self, observer: Arc<dyn EvaluationObserver>) -> Self {
        self.observers.add_observer(observer);
        self
    }

    /// Who actions are evaluated for (receipt spec 4.1). An enforcement point
    /// SHOULD populate every field it knows.
    #[must_use]
    pub fn actor(mut self, actor: Actor) -> Self {
        self.actor = Some(actor);
        self
    }

    /// How much to trust the receipt clock (receipt spec 3.3).
    #[must_use]
    pub fn time_source(mut self, time_source: TimeSource) -> Self {
        self.time_source = time_source;
        self
    }

    /// What to record. The default records everything; `enabled: false` stops
    /// the guard building receipts at all, and
    /// [`GuardDecision::receipt`] is then `None`.
    #[must_use]
    pub fn audit(mut self, audit: AuditConfig) -> Self {
        self.audit = audit;
        self
    }

    /// The confirmation channel for `warn`: return `true` to let the action
    /// through as [`EnforcementOutcome::Confirmed`].
    ///
    /// Without one, a `warn` is a deny (core spec 6).
    #[must_use]
    pub fn on_warn(
        mut self,
        handler: impl Fn(&EvaluationResult, &EvaluationAction) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.on_warn = Some(Box::new(handler));
        self
    }

    /// Resolve, validate, compile and guard `policy`.
    ///
    /// A policy that fails verification under `require_signature` does *not*
    /// fail here: the guard is built in the refused state so the attempt is
    /// recorded (signing spec 6.5). Every other load failure is an error --
    /// there is no document to refuse against.
    ///
    /// # Errors
    ///
    /// [`GuardError::Policy`] or [`GuardError::Enforcement`].
    pub fn build_from_policy(self, policy: Policy) -> Result<HushGuard, GuardError> {
        let leaf = policy.spec().clone();
        let source = policy.source().to_string();
        let panic = policy.panic_state().clone();
        match policy.compile() {
            Ok(compiled) => self.build_from_compiled(compiled),
            Err(PolicyError::Resolve(ResolveError::SignatureRequired { document, status })) => {
                let content_hash = own_content_hash(&leaf, &source)?;
                let summary = PolicySummary {
                    name: leaf.name.clone(),
                    version: leaf
                        .metadata
                        .as_ref()
                        .and_then(|metadata| metadata.policy_version)
                        .map(|version| version as u64),
                    spec_version: leaf.hushspec.clone(),
                    content_hash,
                    extends_chain: None,
                    signature: Some(status.clone()),
                };
                self.finish(
                    GuardPolicy::Refused {
                        summary: Box::new(summary),
                        document,
                        status: Box::new(status),
                    },
                    panic,
                )
            }
            Err(error) => Err(GuardError::Policy(error)),
        }
    }

    /// Validate, compile and guard an already-resolved policy.
    ///
    /// # Errors
    ///
    /// [`GuardError::Policy`] or [`GuardError::Enforcement`].
    pub fn build_from_resolution(self, resolution: Resolution) -> Result<HushGuard, GuardError> {
        self.build_from_resolution_with(resolution, PanicState::default())
    }

    /// [`HushGuardBuilder::build_from_resolution`] with a scoped kill switch
    /// instead of the process-wide one (see [`PanicState`]).
    ///
    /// # Errors
    ///
    /// As [`HushGuardBuilder::build_from_resolution`].
    pub fn build_from_resolution_with(
        self,
        resolution: Resolution,
        panic: PanicState,
    ) -> Result<HushGuard, GuardError> {
        let compiled = Policy::compile_resolution(resolution.clone(), panic.clone())?;
        self.finish(
            GuardPolicy::Active {
                compiled: Arc::new(compiled),
                resolution: Arc::new(resolution),
            },
            panic,
        )
    }

    /// Guard a policy that is already compiled.
    ///
    /// # Errors
    ///
    /// [`GuardError::Resolve`] when the policy has no canonical form (so no
    /// receipt could name it), or [`GuardError::Enforcement`].
    pub fn build_from_compiled(self, compiled: CompiledPolicy) -> Result<HushGuard, GuardError> {
        let resolution = Arc::new(compiled.resolution()?.clone());
        let panic = compiled.panic_state().clone();
        self.finish(
            GuardPolicy::Active {
                compiled: Arc::new(compiled),
                resolution,
            },
            panic,
        )
    }

    fn finish(self, policy: GuardPolicy, panic: PanicState) -> Result<HushGuard, GuardError> {
        let observable = self.sink.is_some() || !self.observers.is_empty();
        self.enforcement.validate(observable)?;

        let Self {
            enforcement,
            sink,
            observers,
            actor,
            time_source,
            audit,
            on_warn,
        } = self;

        let guard = HushGuard {
            policy: RwLock::new(Arc::new(policy)),
            swapping: Mutex::new(()),
            enforcement,
            sink,
            observers,
            actor,
            time_source,
            audit,
            on_warn,
            panic,
        };

        // A policy-in-effect record before any receipt evaluated under it
        // (log spec 6): a reader maps every receipt to the policy in force by
        // walking back to the nearest policy event.
        let summary = guard.policy_summary();
        guard.emit_policy_event(PolicyEvent::loaded(summary.clone(), guard.enforcement.mode));
        guard
            .observers
            .notify_policy_loaded(summary.name.as_deref(), &summary.content_hash);
        Ok(guard)
    }
}

/// An enforcement point. See the module documentation.
pub struct HushGuard {
    policy: RwLock<Arc<GuardPolicy>>,
    /// Serializes whole swaps, so two of them cannot interleave their
    /// `policy_swapped` records. Held only by [`HushGuard::swap_policy`];
    /// an evaluation never touches it, so a slow sink delays the next swap
    /// rather than the next decision.
    swapping: Mutex<()>,
    enforcement: EnforcementConfig,
    sink: Option<Box<dyn ReceiptSink>>,
    observers: ObservableEvaluator,
    actor: Option<Actor>,
    time_source: TimeSource,
    audit: AuditConfig,
    on_warn: Option<Box<WarnHandler>>,
    panic: PanicState,
}

impl std::fmt::Debug for HushGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HushGuard")
            .field("content_hash", &self.content_hash())
            .field("refused", &self.refused())
            .field("enforcement", &self.enforcement)
            .field("sink", &self.sink.is_some())
            .field("observers", &self.observers)
            .finish()
    }
}

impl HushGuard {
    /// Configure a guard.
    #[must_use]
    pub fn builder() -> HushGuardBuilder {
        HushGuardBuilder::default()
    }

    /// Guard `policy` with default options: enforce everything, no sink, no
    /// observers, `warn` denies.
    ///
    /// # Errors
    ///
    /// As [`HushGuardBuilder::build_from_policy`].
    pub fn from_policy(policy: Policy) -> Result<Self, GuardError> {
        Self::builder().build_from_policy(policy)
    }

    /// Guard the policy file at `path` with default options.
    ///
    /// # Errors
    ///
    /// As [`HushGuardBuilder::build_from_policy`], plus
    /// [`GuardError::Policy`] when the file cannot be read or parsed.
    pub fn from_path(path: impl AsRef<std::path::Path>) -> Result<Self, GuardError> {
        Self::builder().build_from_policy(Policy::from_path(path)?)
    }

    /// Guard an already-resolved policy with default options.
    ///
    /// # Errors
    ///
    /// As [`HushGuardBuilder::build_from_resolution`].
    pub fn from_resolution(resolution: Resolution) -> Result<Self, GuardError> {
        Self::builder().build_from_resolution(resolution)
    }

    // -- state -----------------------------------------------------------

    fn snapshot(&self) -> Arc<GuardPolicy> {
        // A poisoned lock means a previous holder panicked while swapping.
        // The value behind it is an immutable `Arc` -- there is no half-written
        // policy to observe -- so recover rather than turn every later
        // decision into a panic.
        match self.policy.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Whether the guard refused its policy: verification was required and did
    /// not pass, so every action is denied (signing spec 6.5).
    #[must_use]
    pub fn refused(&self) -> bool {
        matches!(*self.snapshot(), GuardPolicy::Refused { .. })
    }

    /// The document that would not verify and the verifier's outcome, when the
    /// guard is [refused](HushGuard::refused).
    #[must_use]
    pub fn refusal(&self) -> Option<(String, SignatureStatus)> {
        match &*self.snapshot() {
            GuardPolicy::Refused {
                document, status, ..
            } => Some((document.clone(), (**status).clone())),
            GuardPolicy::Active { .. } => None,
        }
    }

    /// The identity of the policy in force, as a receipt and a log entry carry
    /// it.
    #[must_use]
    pub fn policy_summary(&self) -> PolicySummary {
        self.snapshot().summary()
    }

    /// The canonical content hash of the policy in force.
    #[must_use]
    pub fn content_hash(&self) -> String {
        self.snapshot().content_hash().to_string()
    }

    /// The chain, hashes and signature outcome behind the policy in force, or
    /// `None` when the guard refused it.
    #[must_use]
    pub fn resolution(&self) -> Option<Arc<Resolution>> {
        match &*self.snapshot() {
            GuardPolicy::Active { resolution, .. } => Some(resolution.clone()),
            GuardPolicy::Refused { .. } => None,
        }
    }

    /// The compiled policy the guard evaluates through. Hold it to evaluate
    /// outside the guard (a benchmark, a batch) without recompiling. `None`
    /// when the guard refused its policy.
    #[must_use]
    pub fn compiled(&self) -> Option<Arc<CompiledPolicy>> {
        match &*self.snapshot() {
            GuardPolicy::Active { compiled, .. } => Some(compiled.clone()),
            GuardPolicy::Refused { .. } => None,
        }
    }

    /// The guard-level enforcement configuration.
    #[must_use]
    pub fn enforcement(&self) -> &EnforcementConfig {
        &self.enforcement
    }

    /// This guard's kill switch. Arming it denies every subsequent action,
    /// under enforce mode whatever the configuration says.
    #[must_use]
    pub fn panic_state(&self) -> &PanicState {
        &self.panic
    }

    /// Arm the kill switch if the sentinel file at `path` exists (governance
    /// spec: file-based panic activation). Fails closed: an I/O error that
    /// cannot prove the file absent arms it. Returns whether panic is now on.
    ///
    /// A [`PolicyWatcher`](crate::PolicyWatcher) or
    /// [`PolicyPoller`](crate::PolicyPoller) can call this on every tick; see
    /// their `panic_sentinel` option.
    pub fn check_panic_sentinel(&self, path: impl AsRef<std::path::Path>) -> bool {
        self.panic.check_sentinel(path)
    }

    // -- evaluation ------------------------------------------------------

    /// Evaluate `action` and enforce the outcome.
    ///
    /// This is the single enforcement path: it resolves the effective mode,
    /// consults the `warn` confirmation channel, records the receipt through
    /// the sink, notifies observers, and reports whether the runtime may
    /// proceed.
    #[must_use]
    pub fn check(&self, action: &EvaluationAction) -> GuardDecision {
        let policy = self.snapshot();
        let evaluated = self.run(&policy, action);
        let mode = self.effective_mode(&evaluated.result);

        let (enforced, outcome) = match evaluated.result.decision {
            Decision::Allow => (false, EnforcementOutcome::Allowed),
            Decision::Warn if mode == EnforcementMode::Monitor => {
                (false, EnforcementOutcome::WouldBlock)
            }
            Decision::Warn => match &self.on_warn {
                Some(handler) if handler(&evaluated.result, action) => {
                    (false, EnforcementOutcome::Confirmed)
                }
                // Core spec 6: with no confirmation channel, a warn denies.
                _ => (true, EnforcementOutcome::Blocked),
            },
            Decision::Deny if mode == EnforcementMode::Monitor => {
                (false, EnforcementOutcome::WouldBlock)
            }
            Decision::Deny => (true, EnforcementOutcome::Blocked),
        };

        let enforcement = EnforcementSummary { mode, outcome };
        let Evaluated {
            result,
            receipt,
            duration_us,
        } = evaluated;
        let receipt = self.record(action, &result, duration_us, receipt, Some(enforcement));
        GuardDecision {
            result,
            receipt,
            enforced,
            enforcement,
            duration_us,
        }
    }

    /// [`HushGuard::check`], reduced to the go/no-go a tool boundary needs.
    #[must_use]
    pub fn allows(&self, action: &EvaluationAction) -> bool {
        self.check(action).allowed()
    }

    /// [`HushGuard::check`], as a `Result` for a `?`-shaped call site.
    ///
    /// # Errors
    ///
    /// [`Denied`] when the action may not proceed.
    pub fn enforce(&self, action: &EvaluationAction) -> Result<GuardDecision, Denied> {
        let decision = self.check(action);
        if decision.allowed() {
            return Ok(decision);
        }
        Err(Denied {
            result: Box::new(decision.result),
            receipt: decision.receipt.map(Box::new),
        })
    }

    /// Evaluate `action` without enforcing anything.
    ///
    /// The decision is still recorded -- receipt to the sink, event to the
    /// observers -- with the disposition the decision *implies* under the mode
    /// in force for it (receipt spec 4.7). Use it to score an action the
    /// runtime has already handled.
    ///
    /// The mode is the *effective* one, so a per-rule override applies here
    /// too, and a panic or a refused policy still reads as enforced.
    #[must_use]
    pub fn evaluate(&self, action: &EvaluationAction) -> EvaluationResult {
        let policy = self.snapshot();
        let Evaluated {
            result,
            receipt,
            duration_us,
        } = self.run(&policy, action);
        let enforcement =
            EnforcementSummary::implied(result.decision, self.effective_mode(&result));
        self.record(action, &result, duration_us, receipt, Some(enforcement));
        result
    }

    // -- hot reload ------------------------------------------------------

    /// Put `resolution` in force from the next action on.
    ///
    /// Atomic and fail-closed: the document is validated and compiled first,
    /// and a failure leaves the policy already in force untouched. A guard
    /// that had refused its policy leaves the refused state only if the new
    /// one is good -- a swap never *enters* refusal, because keeping a policy
    /// that did verify is strictly safer than adopting one that did not.
    ///
    /// Records a `policy_swapped` event through the sink, naming the hash it
    /// replaced (log spec 6).
    ///
    /// # Errors
    ///
    /// [`GuardError::Policy`] when the new document will not validate or
    /// compile.
    pub fn swap_policy(&self, resolution: Resolution) -> Result<(), GuardError> {
        let compiled = Policy::compile_resolution(resolution.clone(), self.panic.clone())?;
        let next = Arc::new(GuardPolicy::Active {
            compiled: Arc::new(compiled),
            resolution: Arc::new(resolution),
        });
        let summary = next.summary();
        let name = next.name().map(str::to_string);
        let content_hash = summary.content_hash.clone();

        // One swap at a time, all the way through the record. Without this,
        // two swaps could take the write lock in one order and reach the sink
        // in the other, and a reader walking back from a receipt to the
        // nearest policy event would name the wrong policy (log spec 6).
        // A poisoned lock means a previous swap panicked mid-record; the
        // policy behind the `RwLock` is still one whole `Arc`, so continue.
        let _serialized = match self.swapping.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let previous_hash = {
            let mut slot = match self.policy.write() {
                Ok(slot) => slot,
                Err(poisoned) => poisoned.into_inner(),
            };
            let previous = slot.content_hash().to_string();
            *slot = next;
            previous
        };

        self.emit_policy_event(PolicyEvent::swapped(
            summary,
            self.enforcement.mode,
            previous_hash.clone(),
        ));
        self.observers.notify_policy_reloaded(
            name.as_deref(),
            &content_hash,
            Some(previous_hash.as_str()),
        );
        Ok(())
    }

    /// Report a policy load that failed, so the observer stream shows the gap.
    /// The policy in force is unchanged.
    pub fn report_load_failure(&self, error: &str, source: Option<&str>) {
        self.observers.notify_policy_load_failed(error, source);
    }

    // -- internals -------------------------------------------------------

    fn run(&self, policy: &GuardPolicy, action: &EvaluationAction) -> Evaluated {
        match policy {
            GuardPolicy::Refused {
                summary,
                document,
                status,
            } => {
                let result = EvaluationResult {
                    decision: Decision::Deny,
                    matched_rule: Some(POLICY_UNVERIFIED_RULE.to_string()),
                    reason: Some(format!(
                        "policy signature verification failed for {document}: {}",
                        status.reason.as_deref().unwrap_or("unverified")
                    )),
                    origin_profile: None,
                    posture: None,
                };
                let receipt = self.audit.enabled.then(|| {
                    unverified_policy_receipt(
                        (**summary).clone(),
                        action,
                        &self.audit_context(None),
                    )
                });
                Evaluated {
                    result,
                    receipt,
                    duration_us: 0,
                }
            }
            GuardPolicy::Active {
                compiled,
                resolution,
            } => {
                if self.audit.enabled {
                    // `record_receipt` runs the detection pipeline itself, so a
                    // policy's `detection:` extension is honoured here exactly
                    // as it is below, and `detection_trace` records what ran.
                    let receipt = crate::receipt::record_receipt(
                        compiled,
                        resolution,
                        action,
                        &self.audit,
                        &self.audit_context(None),
                    );
                    return Evaluated {
                        result: EvaluationResult {
                            decision: receipt.decision,
                            matched_rule: receipt.matched_rule.clone(),
                            reason: receipt.reason.clone(),
                            origin_profile: receipt.origin_profile.clone(),
                            posture: receipt.posture.clone(),
                        },
                        duration_us: receipt.duration_us.unwrap_or(0),
                        receipt: Some(receipt),
                    };
                }
                let start = std::time::Instant::now();
                let result = compiled.evaluate_with_detection(action).evaluation;
                Evaluated {
                    result,
                    receipt: None,
                    duration_us: start.elapsed().as_micros() as u64,
                }
            }
        }
    }

    /// The mode in force for a decision.
    ///
    /// Panic mode and a refused policy always enforce: monitor mode waving
    /// either through would be exactly the fail-open they exist to prevent.
    fn effective_mode(&self, result: &EvaluationResult) -> EnforcementMode {
        let matched = result.matched_rule.as_deref();
        if self.panic.is_active()
            || matched == Some(PANIC_RULE)
            || matched == Some(POLICY_UNVERIFIED_RULE)
        {
            return EnforcementMode::Enforce;
        }
        self.enforcement.mode_for(matched)
    }

    fn audit_context(&self, enforcement: Option<EnforcementSummary>) -> AuditContext {
        AuditContext {
            actor: self.actor.clone(),
            enforcement,
            enforcement_mode: self.enforcement.mode,
            time_source: self.time_source,
            ..AuditContext::default()
        }
    }

    /// Stamp the receipt with what the enforcement point did, send it, and
    /// tell the observers.
    fn record(
        &self,
        action: &EvaluationAction,
        result: &EvaluationResult,
        duration_us: u64,
        mut receipt: Option<DecisionReceipt>,
        enforcement: Option<EnforcementSummary>,
    ) -> Option<DecisionReceipt> {
        if let (Some(receipt), Some(enforcement)) = (receipt.as_mut(), enforcement) {
            receipt.enforcement = enforcement;
        }
        if let (Some(sink), Some(receipt)) = (self.sink.as_ref(), receipt.as_ref()) {
            // A sink must never break enforcement: a full disk is not a reason
            // to let an action through, nor to stop one.
            let _ = sink.send(receipt);
        }
        self.observers.notify_evaluation_completed(
            action,
            result,
            duration_us,
            enforcement,
            receipt.as_ref(),
        );
        receipt
    }

    fn emit_policy_event(&self, event: PolicyEvent) {
        if let Some(sink) = self.sink.as_ref() {
            // Sinks must not break policy loading, either.
            let _ = sink.record_policy_event(&event);
        }
    }
}

struct Evaluated {
    result: EvaluationResult,
    receipt: Option<DecisionReceipt>,
    duration_us: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::{
        ErrorEvent, EvaluationCompletedEvent, MetricsCollector, PolicyLoadedEvent,
    };
    use crate::sink::{NullSink, SinkError};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const EGRESS_POLICY: &str = r#"
hushspec: "0.1.0"
name: guard-test
rules:
  egress:
    allow: ["*.example.com"]
    default: block
"#;

    const WARN_POLICY: &str = r#"
hushspec: "0.1.0"
name: warn-test
rules:
  tool_access:
    allow: ["deploy", "read_file"]
    require_confirmation: ["deploy"]
"#;

    fn action(action_type: &str, target: &str) -> EvaluationAction {
        EvaluationAction {
            action_type: action_type.to_string(),
            target: Some(target.to_string()),
            ..Default::default()
        }
    }

    fn policy(yaml: &str) -> Policy {
        // A scoped latch: the panic tests arm the process-wide one and the lib
        // test binary runs them in parallel with these.
        Policy::from_str(yaml)
            .expect("parses")
            .with_panic_state(PanicState::new())
    }

    fn guard(yaml: &str) -> HushGuard {
        HushGuard::from_policy(policy(yaml)).expect("builds")
    }

    /// Captures everything a sink is handed.
    #[derive(Default)]
    struct RecordingSink {
        receipts: Mutex<Vec<DecisionReceipt>>,
        events: Mutex<Vec<PolicyEvent>>,
    }

    impl ReceiptSink for RecordingSink {
        fn send(&self, receipt: &DecisionReceipt) -> Result<(), SinkError> {
            self.receipts.lock().expect("lock").push(receipt.clone());
            Ok(())
        }
        fn record_policy_event(&self, event: &PolicyEvent) -> Result<(), SinkError> {
            self.events.lock().expect("lock").push(event.clone());
            Ok(())
        }
    }

    struct SharedSink(Arc<RecordingSink>);
    impl ReceiptSink for SharedSink {
        fn send(&self, receipt: &DecisionReceipt) -> Result<(), SinkError> {
            self.0.send(receipt)
        }
        fn record_policy_event(&self, event: &PolicyEvent) -> Result<(), SinkError> {
            self.0.record_policy_event(event)
        }
    }

    #[test]
    fn allows_and_denies_with_a_receipt_for_each() {
        let guard = guard(EGRESS_POLICY);

        let allowed = guard.check(&action("egress", "api.example.com"));
        assert!(allowed.allowed());
        assert!(!allowed.enforced);
        assert_eq!(allowed.enforcement.outcome, EnforcementOutcome::Allowed);
        assert_eq!(allowed.enforcement.mode, EnforcementMode::Enforce);
        let receipt = allowed.receipt.expect("audit is on by default");
        assert_eq!(receipt.decision, Decision::Allow);
        assert_eq!(receipt.policy.name.as_deref(), Some("guard-test"));

        let denied = guard.check(&action("egress", "evil.test"));
        assert!(!denied.allowed());
        assert!(denied.enforced);
        assert_eq!(denied.enforcement.outcome, EnforcementOutcome::Blocked);
        assert_eq!(
            denied.receipt.expect("receipt").enforcement.outcome,
            EnforcementOutcome::Blocked,
            "the receipt carries what the enforcement point did, not what the decision implied"
        );
    }

    #[test]
    fn a_warn_without_a_confirmation_channel_denies() {
        let guard = guard(WARN_POLICY);
        let decision = guard.check(&action("tool_call", "deploy"));
        assert_eq!(decision.result.decision, Decision::Warn);
        assert!(!decision.allowed(), "core spec 6: warn fails closed");
        assert_eq!(decision.enforcement.outcome, EnforcementOutcome::Blocked);
    }

    #[test]
    fn a_confirmed_warn_proceeds_and_is_recorded_as_confirmed() {
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = seen.clone();
        let guard = HushGuard::builder()
            .on_warn(move |result, _action| {
                assert_eq!(result.decision, Decision::Warn);
                counter.fetch_add(1, Ordering::SeqCst);
                true
            })
            .build_from_policy(policy(WARN_POLICY))
            .expect("builds");

        let decision = guard.check(&action("tool_call", "deploy"));
        assert!(decision.allowed());
        assert_eq!(decision.enforcement.outcome, EnforcementOutcome::Confirmed);
        assert_eq!(seen.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_declined_warn_blocks() {
        let guard = HushGuard::builder()
            .on_warn(|_, _| false)
            .build_from_policy(policy(WARN_POLICY))
            .expect("builds");
        let decision = guard.check(&action("tool_call", "deploy"));
        assert!(!decision.allowed());
        assert_eq!(decision.enforcement.outcome, EnforcementOutcome::Blocked);
    }

    #[test]
    fn monitor_mode_records_would_block_and_lets_the_action_through() {
        let sink = Arc::new(RecordingSink::default());
        let guard = HushGuard::builder()
            .enforcement_mode(EnforcementMode::Monitor)
            .sink(Box::new(SharedSink(sink.clone())))
            .build_from_policy(policy(EGRESS_POLICY))
            .expect("builds");

        let decision = guard.check(&action("egress", "evil.test"));
        assert_eq!(decision.result.decision, Decision::Deny);
        assert!(
            decision.allowed(),
            "monitor mode observes, it does not block"
        );
        assert!(!decision.enforced);
        assert_eq!(decision.enforcement.outcome, EnforcementOutcome::WouldBlock);
        assert_eq!(decision.enforcement.mode, EnforcementMode::Monitor);
        assert_eq!(
            sink.receipts.lock().expect("lock").len(),
            1,
            "a monitored block is never silent"
        );
    }

    #[test]
    fn monitor_mode_without_a_sink_or_observer_is_refused() {
        let error = HushGuard::builder()
            .enforcement_mode(EnforcementMode::Monitor)
            .build_from_policy(policy(EGRESS_POLICY))
            .expect_err("unobservable monitoring must not build");
        assert!(
            matches!(&error, GuardError::Enforcement(message) if message.contains("observer")),
            "{error}"
        );

        // An observer alone is enough, as is a sink alone.
        HushGuard::builder()
            .enforcement_mode(EnforcementMode::Monitor)
            .observer(Arc::new(MetricsCollector::new()))
            .build_from_policy(policy(EGRESS_POLICY))
            .expect("an observer makes monitoring observable");
        HushGuard::builder()
            .enforcement_mode(EnforcementMode::Monitor)
            .sink(Box::new(NullSink))
            .build_from_policy(policy(EGRESS_POLICY))
            .expect("a sink makes monitoring observable");
    }

    #[test]
    fn a_per_rule_override_monitors_one_block_and_enforces_the_rest() {
        let guard = HushGuard::builder()
            .enforcement_override("rules.egress", EnforcementMode::Monitor)
            .sink(Box::new(NullSink))
            .build_from_policy(policy(
                r#"
hushspec: "0.1.0"
rules:
  egress:
    allow: []
    default: block
  tool_access:
    block: ["rm"]
"#,
            ))
            .expect("builds");

        let egress = guard.check(&action("egress", "evil.test"));
        assert!(egress.allowed(), "the override monitors this block");
        assert_eq!(egress.enforcement.mode, EnforcementMode::Monitor);

        let tool = guard.check(&action("tool_call", "rm"));
        assert!(!tool.allowed(), "everything else still enforces");
        assert_eq!(tool.enforcement.mode, EnforcementMode::Enforce);
    }

    #[test]
    fn the_longest_matching_override_wins() {
        let config = EnforcementConfig::enforce()
            .with_override("rules.secret_patterns", EnforcementMode::Monitor)
            .with_override("rules.secret_patterns.patterns", EnforcementMode::Enforce);
        assert_eq!(
            config.mode_for(Some("rules.secret_patterns.patterns.aws_key")),
            EnforcementMode::Enforce
        );
        assert_eq!(
            config.mode_for(Some("rules.secret_patterns.skip_paths")),
            EnforcementMode::Monitor
        );
    }

    #[test]
    fn a_prefix_only_matches_at_a_segment_boundary() {
        assert!(matches_rule_path_prefix("rules.egress", "rules.egress"));
        assert!(matches_rule_path_prefix(
            "rules.egress.default",
            "rules.egress"
        ));
        assert!(matches_rule_path_prefix("rules.egress[0]", "rules.egress"));
        assert!(
            !matches_rule_path_prefix("rules.egress_extra.default", "rules.egress"),
            "a longer sibling name is not a child"
        );
    }

    #[test]
    fn the_bare_detection_rule_matches_an_extensions_detection_override() {
        let config = EnforcementConfig::enforce()
            .with_override("extensions.detection", EnforcementMode::Monitor);
        assert_eq!(
            config.mode_for(Some("detection")),
            EnforcementMode::Monitor,
            "the detection pipeline reports a bare literal, not a path"
        );
    }

    #[test]
    fn an_unknown_override_key_is_refused() {
        for key in ["rules.not_a_rule", "extensions.nope", "egress"] {
            let error = HushGuard::builder()
                .enforcement_override(key, EnforcementMode::Enforce)
                .build_from_policy(policy(EGRESS_POLICY))
                .expect_err("an override the operator will misread must not build");
            assert!(
                matches!(error, GuardError::Enforcement(_)),
                "{key}: {error}"
            );
        }
    }

    #[test]
    fn panic_mode_enforces_whatever_the_configured_mode_says() {
        let latch = PanicState::new();
        let guard = HushGuard::builder()
            .enforcement_mode(EnforcementMode::Monitor)
            .sink(Box::new(NullSink))
            .build_from_resolution_with(
                crate::resolve::Resolution::from_resolved(
                    &crate::HushSpec::parse(EGRESS_POLICY).expect("parses"),
                    None,
                )
                .expect("resolves"),
                latch.clone(),
            )
            .expect("builds");

        assert!(guard.check(&action("egress", "api.example.com")).allowed());
        latch.activate();
        let decision = guard.check(&action("egress", "api.example.com"));
        assert!(
            !decision.allowed(),
            "a kill switch monitor mode can wave through is not one"
        );
        assert_eq!(decision.enforcement.mode, EnforcementMode::Enforce);
        assert_eq!(decision.result.matched_rule.as_deref(), Some(PANIC_RULE));
    }

    /// A policy with no signature, resolved under `require_signature`.
    fn unverifiable() -> Policy {
        policy(EGRESS_POLICY).resolve(crate::resolve::ResolveOptions {
            require_signature: true,
            ..crate::resolve::ResolveOptions::default()
        })
    }

    #[test]
    fn a_policy_that_will_not_verify_refuses_rather_than_failing_to_build() {
        let sink = Arc::new(RecordingSink::default());
        let guard = HushGuard::builder()
            .sink(Box::new(SharedSink(sink.clone())))
            .build_from_policy(unverifiable())
            .expect("a guard that never existed would record nothing (signing spec 6.5)");

        assert!(guard.refused());
        let (document, status) = guard.refusal().expect("the guard knows what it refused");
        assert_eq!(document, "memory");
        assert!(!status.verified);
        assert!(
            guard.compiled().is_none(),
            "there is nothing to evaluate against"
        );
        assert_eq!(
            sink.events.lock().expect("lock").len(),
            1,
            "the refused policy is still recorded as the one in effect"
        );

        let decision = guard.check(&action("egress", "api.example.com"));
        assert!(
            !decision.allowed(),
            "an unverified policy denies everything"
        );
        assert!(decision.enforced);
        assert_eq!(
            decision.result.matched_rule.as_deref(),
            Some(POLICY_UNVERIFIED_RULE)
        );

        let receipt = decision.receipt.expect("the attempt is on the record");
        assert_eq!(receipt.decision, Decision::Deny);
        assert_eq!(
            receipt.matched_rule.as_deref(),
            Some(POLICY_UNVERIFIED_RULE)
        );
        assert!(
            !receipt
                .policy
                .signature
                .as_ref()
                .expect("the failing hop's outcome")
                .verified,
            "signing spec 6.5: the receipt records policy.signature.verified: false"
        );
        assert!(receipt.rule_trace.is_empty(), "nothing was evaluated");
        assert_eq!(sink.receipts.lock().expect("lock").len(), 1);
    }

    #[test]
    fn monitor_mode_cannot_wave_a_refused_policy_through() {
        let guard = HushGuard::builder()
            .enforcement_mode(EnforcementMode::Monitor)
            .sink(Box::new(NullSink))
            .build_from_policy(unverifiable())
            .expect("builds refused");

        let decision = guard.check(&action("egress", "api.example.com"));
        assert!(
            !decision.allowed(),
            "there is no policy to monitor against: refusing is the whole point"
        );
        assert_eq!(decision.enforcement.mode, EnforcementMode::Enforce);
        assert_eq!(decision.enforcement.outcome, EnforcementOutcome::Blocked);
    }

    #[test]
    fn a_refused_guard_recovers_when_a_good_policy_is_swapped_in() {
        let guard = HushGuard::builder()
            .build_from_policy(unverifiable())
            .expect("builds refused");
        assert!(guard.refused());

        guard
            .swap_policy(
                crate::resolve::Resolution::from_resolved(
                    &crate::HushSpec::parse(EGRESS_POLICY).expect("parses"),
                    None,
                )
                .expect("resolves"),
            )
            .expect("swaps");

        assert!(!guard.refused());
        assert!(guard.check(&action("egress", "api.example.com")).allowed());
    }

    #[test]
    fn a_load_failure_that_is_not_a_verification_failure_still_errors() {
        let error =
            HushGuard::from_policy(policy("hushspec: \"0.1.0\"\nextends: \"builtin:nope\"\n"))
                .expect_err("there is no document to refuse against");
        assert!(
            matches!(error, GuardError::Policy(PolicyError::Resolve(_))),
            "{error}"
        );
    }

    #[test]
    fn a_policy_event_precedes_every_receipt() {
        let sink = Arc::new(RecordingSink::default());
        let guard = HushGuard::builder()
            .sink(Box::new(SharedSink(sink.clone())))
            .build_from_policy(policy(EGRESS_POLICY))
            .expect("builds");

        let events = sink.events.lock().expect("lock");
        assert_eq!(events.len(), 1, "construction records policy_loaded");
        assert_eq!(events[0].event, crate::log::PolicyEventKind::Loaded);
        assert_eq!(events[0].policy.content_hash, guard.content_hash());
        assert!(events[0].previous_content_hash.is_none());
    }

    #[test]
    fn swapping_a_policy_records_the_hash_it_replaced() {
        let sink = Arc::new(RecordingSink::default());
        let guard = HushGuard::builder()
            .sink(Box::new(SharedSink(sink.clone())))
            .build_from_policy(policy(EGRESS_POLICY))
            .expect("builds");
        let first = guard.content_hash();
        assert!(guard.check(&action("egress", "api.example.com")).allowed());

        let next = crate::resolve::Resolution::from_resolved(
            &crate::HushSpec::parse(
                "hushspec: \"0.1.0\"\nname: tighter\nrules:\n  egress:\n    allow: []\n    default: block\n",
            )
            .expect("parses"),
            None,
        )
        .expect("resolves");
        guard.swap_policy(next).expect("swaps");

        assert_ne!(guard.content_hash(), first);
        assert!(
            !guard.check(&action("egress", "api.example.com")).allowed(),
            "the new policy is in force from the next action on"
        );

        let events = sink.events.lock().expect("lock");
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].event, crate::log::PolicyEventKind::Swapped);
        assert_eq!(
            events[1].previous_content_hash.as_deref(),
            Some(first.as_str())
        );
    }

    #[test]
    fn a_swap_that_will_not_compile_keeps_the_last_good_policy() {
        let guard = guard(EGRESS_POLICY);
        let good = guard.content_hash();

        let mut broken = crate::HushSpec::parse(EGRESS_POLICY).expect("parses");
        broken.hushspec = "99.0.0".to_string();
        let resolution =
            crate::resolve::Resolution::from_resolved(&broken, None).expect("resolves");

        let error = guard.swap_policy(resolution).expect_err("must not swap");
        assert!(
            matches!(error, GuardError::Policy(PolicyError::Validation { .. })),
            "{error}"
        );
        assert_eq!(
            guard.content_hash(),
            good,
            "the last good policy stays in force"
        );
        assert!(guard.check(&action("egress", "api.example.com")).allowed());
    }

    #[test]
    fn evaluate_records_the_implied_disposition_without_enforcing() {
        let sink = Arc::new(RecordingSink::default());
        let guard = HushGuard::builder()
            .sink(Box::new(SharedSink(sink.clone())))
            .build_from_policy(policy(EGRESS_POLICY))
            .expect("builds");

        let result = guard.evaluate(&action("egress", "evil.test"));
        assert_eq!(result.decision, Decision::Deny);
        let receipts = sink.receipts.lock().expect("lock");
        assert_eq!(
            receipts.len(),
            1,
            "an unenforced evaluation is still evidence"
        );
        assert_eq!(receipts[0].enforcement.outcome, EnforcementOutcome::Blocked);
    }

    #[test]
    fn evaluate_records_the_mode_in_force_for_the_rule_that_matched() {
        let sink = Arc::new(RecordingSink::default());
        let guard = HushGuard::builder()
            .enforcement_override("rules.egress", EnforcementMode::Monitor)
            .sink(Box::new(SharedSink(sink.clone())))
            .build_from_policy(policy(EGRESS_POLICY))
            .expect("builds");

        let _ = guard.evaluate(&action("egress", "evil.test"));
        let receipts = sink.receipts.lock().expect("lock");
        assert_eq!(receipts[0].enforcement.mode, EnforcementMode::Monitor);
        assert_eq!(
            receipts[0].enforcement.outcome,
            EnforcementOutcome::WouldBlock,
            "the per-rule override applies to an unenforced evaluation too"
        );
    }

    #[test]
    fn audit_can_be_switched_off() {
        let guard = HushGuard::builder()
            .audit(AuditConfig {
                enabled: false,
                include_rule_trace: false,
                record_duration: false,
            })
            .build_from_policy(policy(EGRESS_POLICY))
            .expect("builds");
        let decision = guard.check(&action("egress", "evil.test"));
        assert!(decision.receipt.is_none());
        assert!(!decision.allowed(), "the decision is unchanged");
    }

    #[test]
    fn the_actor_reaches_every_receipt() {
        let guard = HushGuard::builder()
            .actor(Actor {
                agent_id: Some("agent-1".to_string()),
                session_id: Some("s-9".to_string()),
                ..Actor::default()
            })
            .time_source(TimeSource::Trusted)
            .build_from_policy(policy(EGRESS_POLICY))
            .expect("builds");
        let receipt = guard
            .check(&action("egress", "evil.test"))
            .receipt
            .expect("receipt");
        assert_eq!(
            receipt.actor.expect("actor").agent_id.as_deref(),
            Some("agent-1")
        );
        assert_eq!(receipt.time_source, TimeSource::Trusted);
    }

    #[test]
    fn enforce_reports_a_denial_as_an_error() {
        let guard = guard(EGRESS_POLICY);
        guard
            .enforce(&action("egress", "api.example.com"))
            .expect("an allowed action passes through");
        let denied = guard
            .enforce(&action("egress", "evil.test"))
            .expect_err("a denied action is an error");
        assert_eq!(denied.result.decision, Decision::Deny);
        assert!(denied.to_string().starts_with("action denied:"));
    }

    #[test]
    fn observers_see_decisions_with_content_stripped() {
        #[derive(Default)]
        struct Capture {
            actions: Mutex<Vec<EvaluationCompletedEvent>>,
            policies: Mutex<Vec<PolicyLoadedEvent>>,
            errors: Mutex<Vec<ErrorEvent>>,
        }
        impl EvaluationObserver for Capture {
            fn on_evaluation(&self, event: &EvaluationCompletedEvent) {
                self.actions.lock().expect("lock").push(event.clone());
            }
            fn on_policy_loaded(&self, event: &PolicyLoadedEvent) {
                self.policies.lock().expect("lock").push(event.clone());
            }
            fn on_error(&self, event: &ErrorEvent) {
                self.errors.lock().expect("lock").push(event.clone());
            }
        }

        let capture = Arc::new(Capture::default());
        let guard = HushGuard::builder()
            .observer(capture.clone())
            .build_from_policy(policy(
                r#"
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: aws_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
"#,
            ))
            .expect("builds");

        let mut write = action("file_write", "/src/config.rs");
        write.content = Some("AKIAIOSFODNN7EXAMPLE".to_string());
        let decision = guard.check(&write);
        assert_eq!(decision.result.decision, Decision::Deny);

        let events = capture.actions.lock().expect("lock");
        assert_eq!(events.len(), 1);
        assert!(
            events[0].action.content.is_none(),
            "the secret must not leak into telemetry"
        );
        assert!(events[0].content_redacted);
        assert_eq!(
            events[0].enforcement.expect("enforcement").outcome,
            EnforcementOutcome::Blocked
        );
        assert!(events[0].receipt.is_some());

        assert_eq!(capture.policies.lock().expect("lock").len(), 1);
        guard.report_load_failure("boom", Some("p.yaml"));
        assert_eq!(capture.errors.lock().expect("lock").len(), 1);
    }

    #[test]
    fn a_guard_is_shareable_across_threads() {
        let guard = Arc::new(guard(EGRESS_POLICY));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let guard = guard.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    assert!(guard.check(&action("egress", "api.example.com")).allowed());
                    assert!(!guard.check(&action("egress", "evil.test")).allowed());
                }
            }));
        }
        for handle in handles {
            handle.join().expect("no thread panicked");
        }
    }

    #[test]
    fn parallel_swaps_record_a_consistent_chain_of_policy_events() {
        let sink = Arc::new(RecordingSink::default());
        let guard = Arc::new(
            HushGuard::builder()
                .sink(Box::new(SharedSink(sink.clone())))
                .build_from_policy(policy(EGRESS_POLICY))
                .expect("builds"),
        );
        let first = guard.content_hash();

        let mut handles = Vec::new();
        for index in 0..4 {
            let guard = guard.clone();
            handles.push(std::thread::spawn(move || {
                for round in 0..5 {
                    let yaml = format!(
                        "hushspec: \"0.1.0\"\nname: swap-{index}-{round}\nrules:\n  egress:\n    allow: [\"*.example.com\"]\n    default: block\n"
                    );
                    let resolution = crate::resolve::Resolution::from_resolved(
                        &crate::HushSpec::parse(&yaml).expect("parses"),
                        None,
                    )
                    .expect("resolves");
                    guard.swap_policy(resolution).expect("swaps");
                }
            }));
        }
        for handle in handles {
            handle.join().expect("no thread panicked");
        }

        let events = sink.events.lock().expect("lock");
        assert_eq!(events.len(), 21, "one load plus twenty swaps");
        // Every swap names the hash the previous record put in force, so a
        // reader can walk the chain back without gaps or crossings.
        let mut expected = first;
        for event in &events[1..] {
            assert_eq!(
                event.previous_content_hash.as_deref(),
                Some(expected.as_str()),
                "policy events crossed: a receipt would map to the wrong policy"
            );
            expected = event.policy.content_hash.clone();
        }
        assert_eq!(guard.content_hash(), expected);
    }

    #[test]
    fn swapping_under_live_traffic_never_evaluates_a_half_loaded_policy() {
        let guard = Arc::new(guard(EGRESS_POLICY));
        let reader = {
            let guard = guard.clone();
            std::thread::spawn(move || {
                for _ in 0..500 {
                    // Either policy allows `api.example.com`; what must never
                    // happen is a torn read or a panic.
                    let _ = guard.check(&action("egress", "api.example.com"));
                }
            })
        };
        for index in 0..20 {
            let yaml = format!(
                "hushspec: \"0.1.0\"\nname: swap-{index}\nrules:\n  egress:\n    allow: [\"*.example.com\"]\n    default: block\n"
            );
            let resolution = crate::resolve::Resolution::from_resolved(
                &crate::HushSpec::parse(&yaml).expect("parses"),
                None,
            )
            .expect("resolves");
            guard.swap_policy(resolution).expect("swaps");
        }
        reader.join().expect("no thread panicked");
    }
}
