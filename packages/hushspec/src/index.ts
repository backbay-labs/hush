export type { HushSpec, MergeStrategy, GovernanceMetadata, ControlMapping, Classification, LifecycleState } from './schema.js';
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
  BrowserAutomationRule,
  CodeExecutionRule,
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
  OriginToolAccessOverlay,
  OriginEgressOverlay,
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
export {
  parse,
  parseOrThrow,
  yamlProfileViolation,
  MAX_DOCUMENT_BYTES,
  MAX_DOCUMENT_DEPTH,
  MAX_NODE_COUNT,
  type ParseResult,
} from './parse.js';
export { validate, isSafeRegex, type ValidationResult, type ValidationError } from './validate.js';
export { merge } from './merge.js';
export { canonicalJson, contentHash, CanonicalError, type JsonValue } from './canonical.js';
export { resolve, resolveFromFile, createCompositeLoader, createBuiltinLoader, type LoadedSpec, type ResolveOptions, type ResolveResult } from './resolve.js';
export { loadBuiltin, BUILTIN_NAMES, type BuiltinName } from './builtin.js';
export { createHttpLoader, createSyncHttpLoader, type HttpLoaderConfig } from './http-loader.js';
export {
  evaluate,
  evaluateTraced,
  evaluateWithContext,
  activatePanic,
  deactivatePanic,
  isPanicActive,
  panicPolicy,
  normalizeHost,
  normalizePath,
  hostPatternMatches,
  pathGlobMatches,
  punycodeEncode,
  UNKNOWN_ACTION_TYPE_RULE,
  PANIC_RULE,
  BUILTIN_CREDENTIAL_PATTERNS,
  type EvaluationAction,
  type EvaluationResult,
  type TracedEvaluation,
  type Decision,
  type OriginContext,
  type PostureContext,
  type PostureResult,
} from './evaluate.js';
export {
  evaluateCondition,
  validateCondition,
  validateConditions,
  timezoneIsKnown,
  MAX_NESTING_DEPTH,
  DAY_ABBREVIATIONS,
  CONDITION_RULE_BLOCKS,
  type Condition,
  type TimeWindowCondition,
  type RuntimeContext,
} from './conditions.js';
export {
  HushGuard,
  HushSpecDenied,
  matchesRulePathPrefix,
  resolvePolicyOrThrow,
  type WarnHandler,
  type EnforcementConfig,
  type GateOutcome,
  type HushGuardOptions,
  type PolicyResolveOptions,
} from './middleware.js';
export { mapClaudeToolToAction, createSecureToolHandler } from './adapters/anthropic.js';
export { mapOpenAIToolCall, createOpenAIGuard } from './adapters/openai.js';
export { mapMCPToolCall, extractDomain, createMCPGuard } from './adapters/mcp.js';
export {
  HUSHSPEC_VERSION,
  HUSHSPEC_SUPPORTED_MINORS,
  SUPPORTED_VERSIONS,
  isSupported,
  supportedMinor,
} from './version.js';
export {
  evaluateAudited,
  computePolicyHash,
  DEFAULT_AUDIT_CONFIG,
  type DecisionReceipt,
  type ActionSummary,
  type RuleEvaluation,
  type RuleOutcome,
  type EnforcementMode,
  type EnforcementOutcome,
  type EnforcementSummary,
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
  type DetectionCategory,
  type DetectionResult,
  type MatchedPattern,
  type Detector,
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
