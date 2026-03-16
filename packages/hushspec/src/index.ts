export type { HushSpec, MergeStrategy, GovernanceMetadata, Classification, LifecycleState } from './schema.js';
export type {
  Rules,
  ForbiddenPathsRule,
  PathAllowlistRule,
  EgressRule,
  SecretPatternsRule,
  SecretPattern,
  PatchIntegrityRule,
  ShellCommandsRule,
  ToolAccessRule,
  ComputerUseRule,
  ComputerUseMode,
  RemoteDesktopChannelsRule,
  InputInjectionRule,
  Severity,
  DefaultAction,
} from './rules.js';
export type {
  Extensions,
  PostureExtension,
  PostureState,
  PostureTransition,
  TransitionTrigger,
  OriginsExtension,
  OriginDefaultBehavior,
  OriginProfile,
  OriginMatch,
  OriginDataPolicy,
  OriginBudgets,
  BridgePolicy,
  BridgeTarget,
  DetectionExtension,
  PromptInjectionDetection,
  DetectionLevel,
  JailbreakDetection,
  ThreatIntelDetection,
} from './extensions.js';
export { parse, parseOrThrow } from './parse.js';
export { validate, isSafeRegex, type ValidationResult, type ValidationError } from './validate.js';
export { merge } from './merge.js';
export { resolve, resolveFromFile, createCompositeLoader, type LoadedSpec, type ResolveOptions, type ResolveResult } from './resolve.js';
export { loadBuiltin, BUILTIN_NAMES, type BuiltinName } from './builtin.js';
export { createHttpLoader, createSyncHttpLoader, type HttpLoaderConfig } from './http-loader.js';
export { evaluate, activatePanic, deactivatePanic, isPanicActive, panicPolicy, type EvaluationAction, type EvaluationResult, type Decision, type OriginContext, type PostureContext, type PostureResult } from './evaluate.js';
export { evaluateCondition, evaluateWithContext, type Condition, type TimeWindowCondition, type RuntimeContext } from './conditions.js';
export { HushGuard, HushSpecDenied, type WarnHandler } from './middleware.js';
export { mapClaudeToolToAction, createSecureToolHandler } from './adapters/anthropic.js';
export { mapOpenAIToolCall, createOpenAIGuard } from './adapters/openai.js';
export { mapMCPToolCall, extractDomain, createMCPGuard } from './adapters/mcp.js';
export { HUSHSPEC_VERSION, SUPPORTED_VERSIONS, isSupported } from './version.js';
export {
  evaluateAudited,
  computePolicyHash,
  DEFAULT_AUDIT_CONFIG,
  type DecisionReceipt,
  type ActionSummary,
  type RuleEvaluation,
  type RuleOutcome,
  type PolicySummary,
  type AuditConfig,
} from './receipt.js';
export {
  type ReceiptSink,
  FileReceiptSink,
  ConsoleReceiptSink,
  FilteredSink,
  MultiSink,
  CallbackSink,
  NullSink,
} from './sinks.js';
export {
  evaluateWithDetection,
  DetectorRegistry,
  RegexInjectionDetector,
  RegexJailbreakDetector,
  RegexExfiltrationDetector,
  DEFAULT_DETECTION_CONFIG,
  type DetectionCategory,
  type DetectionResult,
  type MatchedPattern,
  type Detector,
  type DetectionConfig,
  type EvaluationWithDetection,
} from './detection.js';
export { PolicyWatcher, type WatcherOptions } from './watcher.js';
export { PolicyPoller, type PollerOptions } from './poller.js';
export { type PolicyProvider, FileProvider, HttpProvider } from './policy-provider.js';
export {
  ObservableEvaluator,
  JsonLineObserver,
  ConsoleObserver,
  MetricsCollector,
  type EvaluationObserver,
  type EvaluationEvent,
  type EvaluationCompletedEvent,
  type PolicyLoadedEvent,
  type PolicyLoadFailedEvent,
  type PolicyReloadedEvent,
  type ObserverEvent,
} from './observer.js';
