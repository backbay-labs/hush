pub mod canonical;
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
pub mod receipt;
pub mod regex_profile;
pub mod resolve;
pub mod rules;
pub mod schema;
#[cfg(feature = "signing")]
pub mod signing;
pub mod sink;
pub mod validate;
pub mod version;

pub use canonical::{
    CONTENT_HASH_PREFIX, CanonicalError, canonical_json, canonical_json_value, content_hash,
    content_hash_value, serialize_jcs,
};
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
    activate_panic, check_panic_sentinel, deactivate_panic, is_panic_active, panic_policy,
};
pub use receipt::{
    ActionSummary, Actor, AuditConfig, AuditContext, DecisionReceipt, EnforcementMode,
    EnforcementOutcome, EnforcementSummary, POLICY_UNVERIFIED_RULE, PolicySummary, RECEIPT_VERSION,
    ReceiptChainLink, ReceiptError, RuleTraceEntry, TimeSource, deterministic_uuid_v7,
    evaluate_audited, evaluate_audited_spec, format_timestamp, policy_summary,
    unverified_policy_receipt,
};
pub use regex_profile::{RegexProfileError, compile_profile_regex};
pub use resolve::{
    BUILTIN_NAMES, ChainLink, LoadedSpec, MEMORY_SOURCE, Resolution, ResolveError, ResolveOptions,
    SignatureLocator, SignatureStatus, create_composite_loader, load_builtin, own_content_hash,
    resolve_from_path, resolve_from_path_with_builtins, resolve_path_with_options,
    resolve_with_loader, resolve_with_options, split_digest_pin,
};
pub use rules::*;
pub use schema::HushSpec;
pub use sink::{
    CallbackSink, FileReceiptSink, FilteredSink, MultiSink, NullSink, ReceiptSink, SinkError,
    StderrReceiptSink,
};
pub use validate::{ValidationError, ValidationResult, validate};
pub use version::HUSHSPEC_VERSION;
