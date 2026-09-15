//! HushSpec: portable security policy for the tool boundary of AI agent
//! runtimes.
//!
//! # Getting started
//!
//! [`Policy`] is the recommended entry point. It runs the whole pipeline --
//! `load → resolve → verify → validate → compile` -- so no caller has to
//! remember the order, and hands back a [`CompiledPolicy`] with every regex,
//! glob and host pattern already compiled and its [`Resolution`] (chain,
//! signature status, content hash) attached:
//!
//! ```
//! use hushspec::{EvaluationAction, Policy};
//!
//! let policy = Policy::from_str("hushspec: \"0.1.0\"\n")?.compile()?;
//! let action = EvaluationAction {
//!     action_type: "tool_call".to_string(),
//!     target: Some("read_file".to_string()),
//!     ..Default::default()
//! };
//! let decision = policy.evaluate(&action);
//! # Ok::<(), hushspec::PolicyError>(())
//! ```
//!
//! Compile once, evaluate many: evaluation against a [`CompiledPolicy`] costs
//! only the matching, never the pattern compilation. The free functions
//! ([`evaluate()`], [`evaluate_with_detection`], [`evaluate_audited`], ...) stay
//! available and behave identically, but compile the policy on every call.
//!
//! Panic mode is carried by a [`PanicState`] handle, not a process global, so
//! a multi-tenant host can arm one tenant's kill switch alone. A policy
//! compiled without an explicit handle holds the process-wide one, which
//! [`panic::activate_panic`] and the `h2h panic` sentinel drive.

#[cfg(feature = "signing")]
pub mod bundle;
pub mod canonical;
pub mod compiled;
pub mod conditions;
pub mod detection;
pub mod evaluate;
pub mod extensions;
mod generated_builtins;
mod generated_canonical_schemas;
mod generated_contract;
mod generated_models;
pub mod governance;
pub mod log;
pub mod merge;
pub mod panic;
pub mod policy;
pub mod receipt;
pub mod regex_profile;
pub mod report;
pub mod resolve;
pub mod rules;
pub mod schema;
#[cfg(feature = "signing")]
pub mod signing;
pub mod sink;
pub mod validate;
pub mod version;

#[cfg(feature = "signing")]
pub use bundle::{
    BUNDLE_VERSION, BundleError, BundleOptions, BundleReason, BundleVerified, BundleVerifyError,
    DsseEnvelope, DsseSignature, PAYLOAD_TYPE, PREDICATE_TYPE, PolicyBundlePredicate,
    PolicyIdentity, STATEMENT_TYPE, Statement, Subject, SubjectDigest, VerifyBundleOptions,
    build_statement, bundle_resolution, pae, sign_statement, unsigned_envelope, verify_bundle,
};
pub use canonical::{
    CONTENT_HASH_PREFIX, CanonicalError, canonical_json, canonical_json_value, canonical_value,
    canonical_value_of, content_hash, content_hash_value, serialize_jcs,
};
pub use compiled::{CompileError, CompiledPolicy, default_detector_registry};
pub use conditions::{Condition, RuntimeContext, TimeWindowCondition, evaluate_condition};
pub use detection::{
    DetectionCategory, DetectionResult, Detector, DetectorEvaluation, DetectorLevel,
    DetectorRegistry, EvaluationWithDetection, MatchedPattern, RegexExfiltrationDetector,
    RegexInjectionDetector, RegexJailbreakDetector, TracedEvaluationWithDetection,
    evaluate_with_detection, evaluate_with_detection_traced,
};
pub use evaluate::{
    Decision, EvaluationAction, EvaluationResult, OriginContext, PostureContext, PostureResult,
    evaluate, evaluate_with_context,
};
pub use extensions::Extensions;
pub use governance::{ControlMapping, GovernanceMetadata, GovernanceWarning, validate_governance};
pub use log::{
    ChainedFileSink, EntryType, GENESIS_HASH, LOG_VERSION, LogEntry, LogError, LogSignature,
    LogStarted, LogVerifyOptions, LogVerifyReport, Payload, PolicyEvent, PolicyEventKind, SdkInfo,
    verify_log, verify_log_files, verify_logs,
};
pub use merge::merge;
pub use panic::{
    PanicState, activate_panic, check_panic_sentinel, deactivate_panic, is_panic_active,
    panic_policy,
};
pub use policy::{Policy, PolicyError};
pub use receipt::{
    ActionSummary, Actor, AuditConfig, AuditContext, DecisionReceipt, EnforcementMode,
    EnforcementOutcome, EnforcementSummary, POLICY_UNVERIFIED_RULE, PolicySummary, RECEIPT_VERSION,
    ReceiptChainLink, ReceiptError, RuleTraceEntry, TimeSource, deterministic_uuid_v7,
    evaluate_audited, evaluate_audited_spec, format_timestamp, policy_summary,
    unverified_policy_receipt,
};
pub use regex_profile::{RegexProfileError, compile_profile_regex};
pub use report::{
    ActionTypeRow, ActorRow, ChainSummary, ControlEvidenceRow, ControlsEvidence, DecisionTotals,
    DetectorRow, FrameworkEvidence, LevelTotals, ModeTotals, OutcomeTotals, PolicyRow,
    PolicyTimelineRow, REPORT_VERSION, ReasonCount, Report, ReportOptions, RuleBlockRow,
    RulePathCount, SignatureSummary, Totals, Window, build_report, in_window,
};
pub use resolve::{
    BUILTIN_NAMES, ChainLink, LoadedSpec, MEMORY_SOURCE, Resolution, ResolveError, ResolveOptions,
    SignatureLocator, SignatureStatus, create_composite_loader, load_builtin, own_content_hash,
    resolve_from_path, resolve_from_path_with_builtins, resolve_path_with_options,
    resolve_with_loader, resolve_with_options, split_digest_pin,
};
pub use rules::{
    BrowserAutomationRule, CodeExecutionRule, ComputerUseMode, ComputerUseRule, DefaultAction,
    EgressRule, ForbiddenPathsRule, InputInjectionRule, PatchIntegrityRule, PathAllowlistRule,
    RemoteDesktopChannelsRule, Rules, SecretPattern, SecretPatternsRule, Severity,
    ShellCommandsRule, ToolAccessRule,
};
pub use schema::HushSpec;
pub use sink::{
    CallbackSink, FileReceiptSink, FilteredSink, MultiSink, NullSink, ReceiptSink, SinkError,
    StderrReceiptSink,
};
pub use validate::{ValidationError, ValidationResult, validate};
pub use version::HUSHSPEC_VERSION;
