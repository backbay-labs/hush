export type { HushSpec, MergeStrategy } from './schema.js';
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
export { validate, type ValidationResult, type ValidationError } from './validate.js';
export { merge } from './merge.js';
export { resolve, resolveFromFile, type LoadedSpec, type ResolveOptions, type ResolveResult } from './resolve.js';
export { HUSHSPEC_VERSION, SUPPORTED_VERSIONS, isSupported } from './version.js';
