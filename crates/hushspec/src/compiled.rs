//! Compiled policies: pay the pattern-compilation cost once, not per action.
//!
//! [`CompiledPolicy`] is a resolved [`HushSpec`] with every matcher it needs
//! already built:
//!
//! * every policy-authored regex (`secret_patterns`,
//!   `patch_integrity.forbidden_patterns`,
//!   `shell_commands.forbidden_patterns`,
//!   `browser_automation.extra_credential_patterns`) compiled once through the
//!   [regex profile](crate::regex_profile) compiler,
//! * every path glob compiled once into its anchored regex,
//! * every host pattern normalized once and compiled once,
//! * the origins overlays' host patterns compiled alongside their profiles,
//! * the built-in [`DetectorRegistry`] built once when the document carries a
//!   `detection:` extension,
//! * a [`PanicState`] handle (the process-wide one by default) rather than a
//!   process-global static.
//!
//! Evaluation cost is then independent of how many patterns the policy
//! declares *to compile* -- only of how many it has to match against.
//!
//! # Fail-closed
//!
//! Compilation never silently skips a pattern. A pattern that is not
//! expressible in the HushSpec regex profile is recorded with the profile
//! compiler's error and **denies** the action whose block consults it,
//! carrying that pattern's rule path -- exactly the deny the per-call
//! compilation produced (core spec 3.14.3). A path glob or host pattern that
//! cannot be compiled matches nothing, as before.
//!
//! [`CompiledPolicy::compile`] itself is a hard error for a document that is
//! not resolved: a policy still declaring `extends` has no single set of rules
//! to compile, so it is refused rather than evaluated against its leaf only.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, OnceLock};

use regex::Regex;

use crate::conditions::{Condition, RuntimeContext};
use crate::detection::{DetectorRegistry, EvaluationWithDetection, TracedEvaluationWithDetection};
use crate::evaluate::{EvaluationAction, EvaluationResult, TracedEvaluation};
use crate::extensions::{OriginEgressOverlay, OriginProfile};
use crate::panic::PanicState;
use crate::receipt::{AuditConfig, AuditContext, DecisionReceipt};
use crate::regex_profile::{RegexProfileError, compile_profile_regex};
use crate::resolve::{Resolution, ResolveError};
use crate::rules::{
    BrowserAutomationRule, EgressRule, ForbiddenPathsRule, PatchIntegrityRule, PathAllowlistRule,
    SecretPatternsRule, ShellCommandsRule,
};
use crate::schema::HushSpec;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a document could not be compiled into a [`CompiledPolicy`].
///
/// Compilation is fail-closed: an unusable document is refused here rather
/// than producing a policy that quietly allows what it cannot check.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    /// The document still declares `extends`, so its rules are not the rules
    /// that would be in force. Resolve it first (see [`crate::Policy`] or
    /// [`crate::resolve_with_options`]).
    #[error("policy still declares `extends: {reference}`; resolve the chain before compiling it")]
    Unresolved {
        /// The unresolved `extends` reference.
        reference: String,
    },
}

// ---------------------------------------------------------------------------
// Matchers
// ---------------------------------------------------------------------------

/// One policy-authored regex, compiled through the profile compiler.
///
/// `Err` is kept, not dropped: the block that consults this pattern denies
/// with the profile compiler's message, the same way per-call compilation did.
pub(crate) type CompiledRegex = Result<Regex, RegexProfileError>;

fn compile_regexes<'a>(patterns: impl IntoIterator<Item = &'a String>) -> Vec<CompiledRegex> {
    patterns
        .into_iter()
        .map(|pattern| compile_profile_regex(pattern))
        .collect()
}

/// A set of path globs (core spec 3.14.1) compiled into anchored regexes.
///
/// A glob that cannot be compiled is stored as `None` and matches nothing --
/// the behaviour of the uncompiled matcher, which discarded the same failure.
#[derive(Debug, Default)]
pub(crate) struct CompiledPathSet {
    matchers: Vec<Option<Regex>>,
}

impl CompiledPathSet {
    fn compile(patterns: &[String]) -> Self {
        Self {
            matchers: patterns
                .iter()
                .map(|pattern| crate::evaluate::path_glob_regex(pattern))
                .collect(),
        }
    }

    /// Whether any glob in the set matches `path` (already normalized).
    pub(crate) fn matches(&self, path: &str) -> bool {
        self.matchers
            .iter()
            .any(|matcher| matcher.as_ref().is_some_and(|regex| regex.is_match(path)))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.matchers.is_empty()
    }
}

/// One host pattern (core spec 3.14.2), normalized and compiled once.
///
/// Both halves are kept because the rule is subject-dependent: an IP-literal
/// host matches only a byte-equal normalized pattern, anything else matches
/// through the compiled automaton.
#[derive(Debug)]
struct CompiledHostPattern {
    normalized: String,
    regex: Option<Regex>,
}

impl CompiledHostPattern {
    fn compile(pattern: &str) -> Self {
        let normalized = crate::evaluate::normalize_host_pattern(pattern);
        let regex = crate::evaluate::host_pattern_regex(&normalized);
        Self { normalized, regex }
    }

    fn matches(&self, host: &str) -> bool {
        if crate::evaluate::is_ip_literal(host) {
            return self.normalized == host;
        }
        self.regex
            .as_ref()
            .is_some_and(|regex| regex.is_match(host))
    }
}

/// A set of host patterns compiled once.
#[derive(Debug, Default)]
pub(crate) struct CompiledHostSet {
    matchers: Vec<CompiledHostPattern>,
}

impl CompiledHostSet {
    fn compile(patterns: &[String]) -> Self {
        Self {
            matchers: patterns
                .iter()
                .map(|pattern| CompiledHostPattern::compile(pattern))
                .collect(),
        }
    }

    /// Whether any pattern matches `host`. A `None` host matches nothing.
    pub(crate) fn matches(&self, host: Option<&str>) -> bool {
        let Some(host) = host else {
            return false;
        };
        self.matchers.iter().any(|matcher| matcher.matches(host))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.matchers.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Per-block compiled rules
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub(crate) struct CompiledForbiddenPaths {
    pub(crate) patterns: CompiledPathSet,
    pub(crate) exceptions: CompiledPathSet,
}

#[derive(Debug, Default)]
pub(crate) struct CompiledPathAllowlist {
    pub(crate) read: CompiledPathSet,
    pub(crate) write: CompiledPathSet,
    patch: CompiledPathSet,
}

impl CompiledPathAllowlist {
    /// The set a `patch_apply` consults: `patch` when the rule declares one,
    /// otherwise `write` (core spec 5).
    pub(crate) fn patch(&self) -> &CompiledPathSet {
        if self.patch.is_empty() {
            &self.write
        } else {
            &self.patch
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct CompiledSecretPatterns {
    /// Parallel to `SecretPatternsRule::patterns`.
    pub(crate) patterns: Vec<CompiledRegex>,
    pub(crate) skip_paths: CompiledPathSet,
}

#[derive(Debug, Default)]
pub(crate) struct CompiledEgress {
    pub(crate) allow: CompiledHostSet,
    pub(crate) block: CompiledHostSet,
}

#[derive(Debug, Default)]
pub(crate) struct CompiledBrowserAutomation {
    pub(crate) allowed_domains: CompiledHostSet,
    pub(crate) blocked_domains: CompiledHostSet,
    /// Parallel to `BrowserAutomationRule::extra_credential_patterns`.
    pub(crate) extra_credential_patterns: Vec<CompiledRegex>,
}

/// Every matcher a document needs.
///
/// Each block's matchers live behind a [`OnceLock`], so the same type serves
/// both callers:
///
/// * [`CompiledPolicy`] fills every slot up front
///   ([`CompiledMatchers::compile`]), which is the point of compiling: the
///   per-action cost is then pure matching, and a pattern that will not
///   compile is discovered once rather than at each action;
/// * the free `evaluate(&HushSpec, ..)` wrappers start empty
///   ([`CompiledMatchers::lazy`]) and fill only the blocks the action actually
///   consults, so a compile-per-call caller pays no more than it used to.
///
/// It borrows nothing from the document, so a compiled policy can own the
/// document behind an `Arc` without being self-referential.
#[derive(Debug, Default)]
pub(crate) struct CompiledMatchers {
    forbidden_paths: OnceLock<CompiledForbiddenPaths>,
    path_allowlist: OnceLock<CompiledPathAllowlist>,
    secret_patterns: OnceLock<CompiledSecretPatterns>,
    /// Parallel to `PatchIntegrityRule::forbidden_patterns`.
    patch_integrity: OnceLock<Vec<CompiledRegex>>,
    /// Parallel to `ShellCommandsRule::forbidden_patterns`.
    shell_commands: OnceLock<Vec<CompiledRegex>>,
    egress: OnceLock<CompiledEgress>,
    browser_automation: OnceLock<CompiledBrowserAutomation>,
    /// One slot per `extensions.origins.profiles` entry, in document order.
    origin_egress: Vec<OnceLock<CompiledEgress>>,
}

impl CompiledMatchers {
    /// Empty slots sized for `spec`'s origins profiles; every matcher is built
    /// on first use.
    pub(crate) fn lazy(spec: &HushSpec) -> Self {
        Self {
            origin_egress: (0..origin_profile_count(spec))
                .map(|_| OnceLock::new())
                .collect(),
            ..Self::default()
        }
    }

    /// Every matcher the document declares, built now.
    pub(crate) fn compile(spec: &HushSpec) -> Self {
        let matchers = Self::lazy(spec);
        if let Some(rules) = spec.rules.as_ref() {
            if let Some(rule) = rules.forbidden_paths.as_ref() {
                matchers.forbidden_paths(rule);
            }
            if let Some(rule) = rules.path_allowlist.as_ref() {
                matchers.path_allowlist(rule);
            }
            if let Some(rule) = rules.secret_patterns.as_ref() {
                matchers.secret_patterns(rule);
            }
            if let Some(rule) = rules.patch_integrity.as_ref() {
                matchers.patch_integrity(rule);
            }
            if let Some(rule) = rules.shell_commands.as_ref() {
                matchers.shell_commands(rule);
            }
            if let Some(rule) = rules.egress.as_ref() {
                matchers.egress(rule);
            }
            if let Some(rule) = rules.browser_automation.as_ref() {
                matchers.browser_automation(rule);
            }
        }
        for (index, profile) in origin_profiles(spec).iter().enumerate() {
            if let Some(overlay) = profile.egress.as_ref() {
                matchers.origin_egress(index, overlay);
            }
        }
        matchers
    }

    pub(crate) fn forbidden_paths(&self, rule: &ForbiddenPathsRule) -> &CompiledForbiddenPaths {
        self.forbidden_paths.get_or_init(|| CompiledForbiddenPaths {
            patterns: CompiledPathSet::compile(&rule.patterns),
            exceptions: CompiledPathSet::compile(&rule.exceptions),
        })
    }

    pub(crate) fn path_allowlist(&self, rule: &PathAllowlistRule) -> &CompiledPathAllowlist {
        self.path_allowlist.get_or_init(|| CompiledPathAllowlist {
            read: CompiledPathSet::compile(&rule.read),
            write: CompiledPathSet::compile(&rule.write),
            patch: CompiledPathSet::compile(&rule.patch),
        })
    }

    pub(crate) fn secret_patterns(&self, rule: &SecretPatternsRule) -> &CompiledSecretPatterns {
        self.secret_patterns.get_or_init(|| CompiledSecretPatterns {
            patterns: rule
                .patterns
                .iter()
                .map(|pattern| compile_profile_regex(&pattern.pattern))
                .collect(),
            skip_paths: CompiledPathSet::compile(&rule.skip_paths),
        })
    }

    pub(crate) fn patch_integrity(&self, rule: &PatchIntegrityRule) -> &[CompiledRegex] {
        self.patch_integrity
            .get_or_init(|| compile_regexes(&rule.forbidden_patterns))
    }

    pub(crate) fn shell_commands(&self, rule: &ShellCommandsRule) -> &[CompiledRegex] {
        self.shell_commands
            .get_or_init(|| compile_regexes(&rule.forbidden_patterns))
    }

    pub(crate) fn egress(&self, rule: &EgressRule) -> &CompiledEgress {
        self.egress.get_or_init(|| CompiledEgress {
            allow: CompiledHostSet::compile(&rule.allow),
            block: CompiledHostSet::compile(&rule.block),
        })
    }

    pub(crate) fn browser_automation(
        &self,
        rule: &BrowserAutomationRule,
    ) -> &CompiledBrowserAutomation {
        self.browser_automation
            .get_or_init(|| CompiledBrowserAutomation {
                allowed_domains: CompiledHostSet::compile(&rule.allowed_domains),
                blocked_domains: CompiledHostSet::compile(&rule.blocked_domains),
                extra_credential_patterns: compile_regexes(&rule.extra_credential_patterns),
            })
    }

    pub(crate) fn origin_egress(
        &self,
        index: usize,
        overlay: &OriginEgressOverlay,
    ) -> Option<&CompiledEgress> {
        let slot = self.origin_egress.get(index)?;
        Some(slot.get_or_init(|| CompiledEgress {
            allow: CompiledHostSet::compile(&overlay.allow),
            block: CompiledHostSet::compile(&overlay.block),
        }))
    }
}

fn origin_profiles(spec: &HushSpec) -> &[OriginProfile] {
    spec.extensions
        .as_ref()
        .and_then(|extensions| extensions.origins.as_ref())
        .map(|origins| origins.profiles.as_slice())
        .unwrap_or_default()
}

fn origin_profile_count(spec: &HushSpec) -> usize {
    origin_profiles(spec).len()
}

// ---------------------------------------------------------------------------
// Shared detector registry
// ---------------------------------------------------------------------------

/// The built-in detectors, built once per process.
///
/// The three regex detectors are stateless and their patterns are fixed, so
/// one registry serves every policy that opts into detection.
static DEFAULT_DETECTORS: LazyLock<Arc<DetectorRegistry>> =
    LazyLock::new(|| Arc::new(DetectorRegistry::with_defaults()));

/// The process-wide built-in [`DetectorRegistry`] (13 regexes), compiled once.
#[must_use]
pub fn default_detector_registry() -> Arc<DetectorRegistry> {
    DEFAULT_DETECTORS.clone()
}

// ---------------------------------------------------------------------------
// CompiledPolicy
// ---------------------------------------------------------------------------

/// A resolved policy with every matcher it needs already compiled.
///
/// Build one per policy, then evaluate many actions against it. This is the
/// evaluation entry point the SDK is built around; the free functions
/// ([`crate::evaluate()`], [`crate::evaluate_with_detection`], ...) are thin
/// wrappers that compile on the fly and are a per-call cost.
///
/// ```
/// use hushspec::{CompiledPolicy, EvaluationAction, HushSpec};
///
/// let spec = HushSpec::parse("hushspec: \"0.1.0\"\n").unwrap();
/// let policy = CompiledPolicy::compile(&spec).unwrap();
/// let action = EvaluationAction {
///     action_type: "tool_call".to_string(),
///     target: Some("read_file".to_string()),
///     ..Default::default()
/// };
/// let result = policy.evaluate(&action);
/// ```
#[derive(Debug)]
pub struct CompiledPolicy {
    spec: Arc<HushSpec>,
    matchers: CompiledMatchers,
    detectors: Option<Arc<DetectorRegistry>>,
    panic: PanicState,
    resolution: OnceLock<Arc<Resolution>>,
}

impl CompiledPolicy {
    /// Compile a resolved, validated document.
    ///
    /// # Errors
    ///
    /// [`CompileError::Unresolved`] when the document still declares
    /// `extends`.
    pub fn compile(spec: &HushSpec) -> Result<Self, CompileError> {
        if let Some(reference) = spec.extends.as_deref() {
            return Err(CompileError::Unresolved {
                reference: reference.to_string(),
            });
        }
        Ok(Self::compile_resolved(Arc::new(spec.clone()), None))
    }

    /// Compile the document a [`Resolution`] produced, keeping the resolution
    /// (chain, signature status, content hash) so
    /// [`CompiledPolicy::evaluate_audited`] needs nothing else.
    ///
    /// # Errors
    ///
    /// [`CompileError::Unresolved`] when the resolved document still declares
    /// `extends`, which would mean the chain was not consumed.
    pub fn from_resolution(resolution: Resolution) -> Result<Self, CompileError> {
        if let Some(reference) = resolution.spec.extends.as_deref() {
            return Err(CompileError::Unresolved {
                reference: reference.to_string(),
            });
        }
        let spec = Arc::new(resolution.spec.clone());
        Ok(Self::compile_resolved(spec, Some(Arc::new(resolution))))
    }

    fn compile_resolved(spec: Arc<HushSpec>, resolution: Option<Arc<Resolution>>) -> Self {
        let matchers = CompiledMatchers::compile(&spec);
        let detectors = spec
            .extensions
            .as_ref()
            .and_then(|extensions| extensions.detection.as_ref())
            .map(|_| default_detector_registry());
        let cell = OnceLock::new();
        if let Some(resolution) = resolution {
            let _ = cell.set(resolution);
        }
        Self {
            spec,
            matchers,
            detectors,
            panic: PanicState::default(),
            resolution: cell,
        }
    }

    /// Use `state` as this policy's kill switch instead of the process-wide
    /// latch. Tenant-scoped embedders want one handle per tenant.
    #[must_use]
    pub fn with_panic_state(mut self, state: PanicState) -> Self {
        self.panic = state;
        self
    }

    /// Replace the detector registry detection runs against. Only consulted
    /// when the document carries a `detection:` extension.
    #[must_use]
    pub fn with_detectors(mut self, detectors: Arc<DetectorRegistry>) -> Self {
        if self.detectors.is_some() {
            self.detectors = Some(detectors);
        }
        self
    }

    /// The document this policy was compiled from.
    #[must_use]
    pub fn spec(&self) -> &HushSpec {
        &self.spec
    }

    /// A shared handle on the document, for callers that need to keep it.
    #[must_use]
    pub fn spec_arc(&self) -> Arc<HushSpec> {
        self.spec.clone()
    }

    /// This policy's kill switch.
    #[must_use]
    pub fn panic_state(&self) -> &PanicState {
        &self.panic
    }

    /// The detector registry detection runs against, when the document opts
    /// into detection.
    #[must_use]
    pub fn detectors(&self) -> Option<&DetectorRegistry> {
        self.detectors.as_deref()
    }

    /// The policy's provenance: the [`Resolution`] it was compiled from, or a
    /// single-link resolution of the document itself, computed on first use
    /// and cached.
    ///
    /// # Errors
    ///
    /// [`ResolveError::Canonical`] when the document has no canonical form.
    pub fn resolution(&self) -> Result<&Resolution, ResolveError> {
        if let Some(resolution) = self.resolution.get() {
            return Ok(resolution);
        }
        let resolution = Arc::new(Resolution::from_resolved(&self.spec, None)?);
        Ok(self.resolution.get_or_init(|| resolution))
    }

    /// The policy's content hash (canonical spec 5), computed once.
    ///
    /// # Errors
    ///
    /// As [`CompiledPolicy::resolution`].
    pub fn content_hash(&self) -> Result<&str, ResolveError> {
        Ok(&self.resolution()?.content_hash)
    }

    // -- evaluation ------------------------------------------------------

    /// Evaluate `action` against this policy.
    ///
    /// `when` conditions see `action.context` (an empty context and the engine
    /// clock when absent).
    #[must_use]
    pub fn evaluate(&self, action: &EvaluationAction) -> EvaluationResult {
        self.evaluate_traced(action, None, &HashMap::new()).result
    }

    /// [`CompiledPolicy::evaluate`] with an explicit runtime context and an
    /// out-of-band map of conditions keyed by rule-block name. The explicit
    /// `context` replaces `action.context`; out-of-band conditions are ANDed
    /// with each block's own `when` (core spec 3.13).
    #[must_use]
    pub fn evaluate_with_context(
        &self,
        action: &EvaluationAction,
        context: &RuntimeContext,
        conditions: &HashMap<String, Condition>,
    ) -> EvaluationResult {
        self.evaluate_traced(action, Some(context), conditions)
            .result
    }

    /// Full evaluation with the recorded rule trace (used by receipts and
    /// `h2h explain`).
    #[must_use]
    pub fn evaluate_traced(
        &self,
        action: &EvaluationAction,
        context: Option<&RuntimeContext>,
        conditions: &HashMap<String, Condition>,
    ) -> TracedEvaluation {
        crate::evaluate::run_evaluation(
            &self.spec,
            &self.matchers,
            &self.panic,
            action,
            context,
            conditions,
        )
    }

    /// Evaluate, then fold in the policy's `detection:` extension using this
    /// policy's detector registry.
    #[must_use]
    pub fn evaluate_with_detection(&self, action: &EvaluationAction) -> EvaluationWithDetection {
        let traced = self.evaluate_with_detection_traced(action, None, &HashMap::new());
        EvaluationWithDetection {
            evaluation: traced.evaluation,
            detections: traced.detections,
            detection_decision: traced.detection_decision,
        }
    }

    /// [`CompiledPolicy::evaluate_with_detection`] with the recorded rule
    /// trace and per-detector receipt entries.
    #[must_use]
    pub fn evaluate_with_detection_traced(
        &self,
        action: &EvaluationAction,
        context: Option<&RuntimeContext>,
        conditions: &HashMap<String, Condition>,
    ) -> TracedEvaluationWithDetection {
        crate::detection::run_detection(self, action, context, conditions)
    }

    /// Evaluate `action` and record the receipt, using the resolution this
    /// policy carries (or one derived from the document).
    ///
    /// # Errors
    ///
    /// As [`CompiledPolicy::resolution`].
    pub fn evaluate_audited(
        &self,
        action: &EvaluationAction,
        config: &AuditConfig,
        ctx: &AuditContext,
    ) -> Result<DecisionReceipt, ResolveError> {
        let resolution = self.resolution()?;
        Ok(crate::receipt::record_receipt(
            self, resolution, action, config, ctx,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(yaml: &str) -> HushSpec {
        HushSpec::parse(yaml).expect("policy parses")
    }

    #[test]
    fn refuses_an_unresolved_document() {
        let doc = spec("hushspec: \"0.1.0\"\nextends: \"builtin:default\"\n");
        let error = CompiledPolicy::compile(&doc).expect_err("extends must be refused");
        assert_eq!(
            error,
            CompileError::Unresolved {
                reference: "builtin:default".to_string()
            }
        );
    }

    #[test]
    fn keeps_a_pattern_that_will_not_compile_as_a_deny() {
        // A backreference is outside the regex profile: the pattern must be
        // recorded with its error, not dropped.
        let doc = spec(
            r#"
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: bad
        pattern: "(a)\\1"
        severity: critical
"#,
        );
        // A scoped latch: the panic tests arm the process-wide one, and the
        // lib test binary runs them concurrently with this.
        let policy = CompiledPolicy::compile(&doc)
            .expect("compiles")
            .with_panic_state(PanicState::new());
        let compiled = policy
            .matchers
            .secret_patterns
            .get()
            .expect("compile() fills every declared block up front");
        assert!(compiled.patterns[0].is_err());

        let action = EvaluationAction {
            action_type: "file_write".to_string(),
            target: Some("/src/a.rs".to_string()),
            content: Some("anything".to_string()),
            ..Default::default()
        };
        let result = policy.evaluate(&action);
        assert_eq!(result.decision, crate::Decision::Deny);
        assert_eq!(
            result.matched_rule.as_deref(),
            Some("rules.secret_patterns.patterns.bad.pattern")
        );
    }

    #[test]
    fn detectors_are_built_only_for_detection_policies() {
        let plain = CompiledPolicy::compile(&spec("hushspec: \"0.1.0\"\n")).expect("compiles");
        assert!(plain.detectors().is_none());

        let detecting = CompiledPolicy::compile(&spec(
            r#"
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      enabled: true
"#,
        ))
        .expect("compiles");
        assert!(detecting.detectors().is_some());
    }

    #[test]
    fn content_hash_is_computed_once_and_cached() {
        let policy =
            CompiledPolicy::compile(&spec("hushspec: \"0.1.0\"\nname: x\n")).expect("compiles");
        let first = policy.content_hash().expect("hash").to_string();
        let second = policy.content_hash().expect("hash");
        assert_eq!(first, second);
        assert_eq!(
            first,
            crate::content_hash(policy.spec()).expect("hash"),
            "the cached hash must equal the document's content hash"
        );
    }

    #[test]
    fn a_compiled_policy_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CompiledPolicy>();
    }
}
