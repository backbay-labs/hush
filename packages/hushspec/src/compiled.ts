/**
 * Compiled policies: the evaluation engine of HushSpec 0.2 (core spec Sections
 * 3, 5 and 6), with every pattern, matcher and lookup table built once.
 *
 * A {@link CompiledPolicy} is a policy document turned into the form the
 * evaluator actually needs:
 *
 * - every policy regex compiled once under the HushSpec regex profile,
 * - every path glob and host pattern normalized and compiled once (host
 *   patterns are normalized at compile time, not per match),
 * - tool lists NFC-normalized into sets,
 * - `when` conditions, `enabled` defaults and per-action-type block
 *   applicability resolved into a per-block table, so an evaluation walks an
 *   array instead of a `switch` over the document,
 * - severity ranks, `matched_rule` paths and reasons precomputed,
 * - the detection configuration (and its detectors) compiled when the policy
 *   carries a `detection:` extension.
 *
 * The source document is kept as-is for receipts and hashing; `contentHash`
 * is computed on first use and cached.
 *
 * Semantics are identical to evaluating the document directly -- this is a
 * representation change, not a behavior change. Decisions, rule traces,
 * receipts and hashes are byte-for-byte what the uncompiled path produced, so
 * the shared fixtures, the expected-receipt vectors and the differential
 * fuzzer all hold the two paths to the same standard.
 *
 * Evaluation of one action is unchanged:
 * 1. extension guards (panic, origins `default_behavior`, posture capability),
 * 2. every applicable rule block for the action type -- present, `enabled`,
 *    and with a satisfied `when` condition -- evaluated in the order of the
 *    Section 5 table, never short-circuiting on an allow,
 * 3. aggregation: deny beats warn beats allow; `matched_rule`/`reason` come
 *    from the first block in evaluation order whose decision equals the
 *    aggregate and which named a rule.
 *
 * This file is a port of `crates/hushspec/src/evaluate.rs`, which is the
 * normative reference implementation; keep the two in lockstep.
 */
import type { HushSpec } from './schema.js';
import type {
  BrowserAutomationRule,
  CodeExecutionRule,
  ComputerUseRule,
  DefaultAction,
  EgressRule,
  ForbiddenPathsRule,
  InputInjectionRule,
  PatchIntegrityRule,
  PathAllowlistRule,
  RemoteDesktopChannelsRule,
  Rules,
  SecretPatternsRule,
  Severity,
  ShellCommandsRule,
  ToolAccessRule,
} from './rules.js';
import type {
  OriginEgressOverlay,
  OriginMatch,
  OriginProfile,
  OriginToolAccessOverlay,
  PostureExtension,
  PostureTransition,
} from './extensions.js';
import type { Condition, RuntimeContext } from './conditions.js';
import { evaluateCondition } from './conditions.js';
import { compileProfileRegex } from './regex.js';
import type {
  Decision,
  EvaluationAction,
  EvaluationResult,
  OriginContext,
  PostureContext,
  PostureResult,
  RuleEvaluation,
  RuleOutcome,
  TracedEvaluation,
} from './evaluate.js';
import {
  BUILTIN_CREDENTIAL_PATTERNS,
  PANIC_RULE,
  UNKNOWN_ACTION_TYPE_RULE,
  compileHostPattern,
  compilePathGlob,
  isPanicActive,
  hostMatcherMatches,
  normalizeHost,
  normalizePath,
  type CompiledHostPattern,
} from './evaluate.js';
import type {
  CompiledDetection,
  EvaluationWithDetection,
  TracedEvaluationWithDetection,
} from './detection.js';
import { compileDetection, runDetection } from './detection.js';
import type { AuditConfig, AuditContext, DecisionReceipt } from './receipt.js';
import { DEFAULT_AUDIT_CONFIG, receiptFromEvaluation } from './receipt.js';
import type { Resolution } from './resolve.js';
import { resolutionFromResolved } from './resolve.js';
import { contentHash } from './canonical.js';

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * A policy could not be compiled: a pattern outside the HushSpec regex profile
 * (core spec 3.14.3).
 *
 * {@link compilePolicy} raises this rather than handing back a policy that
 * would deny at evaluation time with the same message -- an operator who
 * compiles ahead of time learns about a broken pattern before an action does.
 * The non-throwing form ({@link compilePolicy} with `strict: false`, which is
 * what the free `evaluate()` functions and `HushGuard` use) keeps the
 * fail-closed evaluation-time deny instead, so those paths are unchanged.
 */
export class CompileError extends Error {
  /** The `matched_rule` path of the offending pattern. */
  readonly path: string;

  constructor(path: string, detail: string) {
    super(`${path}: ${detail}`);
    this.name = 'CompileError';
    this.path = path;
  }
}

// ---------------------------------------------------------------------------
// Compiled pattern primitives
// ---------------------------------------------------------------------------

/**
 * One policy regex. Fail-closed: a pattern outside the regex profile compiles
 * to its error instead of a matcher, and the block that owns it denies with
 * that message (core spec 3.14.3) exactly as the uncompiled evaluator did.
 */
interface CompiledRegex {
  regex?: RegExp;
  error?: string;
}

/** A path glob set: entries that would not compile match nothing. */
type CompiledGlobSet = ReadonlyArray<RegExp | undefined>;

/** A host pattern set, normalized once (core spec 3.14.2 steps 5-7). */
type CompiledHostSet = readonly CompiledHostPattern[];

const EMPTY_GLOBS: CompiledGlobSet = Object.freeze([]);
const EMPTY_HOSTS: CompiledHostSet = Object.freeze([]);

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function compileRegex(pattern: string): CompiledRegex {
  try {
    return { regex: compileProfileRegex(pattern).regex };
  } catch (error) {
    return { error: errorMessage(error) };
  }
}

function compileGlobs(patterns: string[] | undefined): CompiledGlobSet {
  if (patterns == null || patterns.length === 0) return EMPTY_GLOBS;
  return patterns.map((pattern) => compilePathGlob(pattern));
}

function compileHosts(patterns: string[] | undefined): CompiledHostSet {
  if (patterns == null || patterns.length === 0) return EMPTY_HOSTS;
  return patterns.map((pattern) => compileHostPattern(pattern));
}

/** Host sets whose "absent or empty" state is load-bearing (`nonEmpty`). */
function compileHostsOrUndefined(patterns: string[] | undefined): CompiledHostSet | undefined {
  if (patterns == null || patterns.length === 0) return undefined;
  return compileHosts(patterns);
}

function anyGlobMatches(set: CompiledGlobSet, path: string): boolean {
  for (const regex of set) {
    if (regex !== undefined && regex.test(path)) return true;
  }
  return false;
}

function anyHostMatches(set: CompiledHostSet | undefined, host: string | undefined): boolean {
  if (host == null || set == null) return false;
  for (const pattern of set) {
    if (hostMatcherMatches(pattern, host)) return true;
  }
  return false;
}

/**
 * Tool names are exact, case-sensitive strings after NFC normalization
 * (core spec 3.7); no glob or regex metacharacters. Normalizing the entries
 * once leaves only the action's own tool name to normalize per evaluation.
 */
function compileToolSet(entries: string[] | undefined): Set<string> {
  const set = new Set<string>();
  for (const entry of entries ?? []) {
    set.add(entry.normalize('NFC'));
  }
  return set;
}

/** Like {@link compileToolSet}, but `undefined` for an absent or empty list. */
function compileToolSetOrUndefined(entries: string[] | undefined): Set<string> | undefined {
  if (entries == null || entries.length === 0) return undefined;
  return compileToolSet(entries);
}

/** An exact-match set that keeps "absent or empty" distinguishable. */
function compileExactSetOrUndefined(entries: string[] | undefined): Set<string> | undefined {
  if (entries == null || entries.length === 0) return undefined;
  return new Set(entries);
}

// ---------------------------------------------------------------------------
// Compiled rule blocks
// ---------------------------------------------------------------------------

/** Every block id the reference specification defines, in no particular order. */
type BlockId =
  | 'forbidden_paths'
  | 'path_allowlist'
  | 'secret_patterns'
  | 'patch_integrity'
  | 'shell_commands'
  | 'tool_access'
  | 'egress'
  | 'computer_use'
  | 'remote_desktop_channels'
  | 'input_injection'
  | 'browser_automation'
  | 'code_execution';

/** `enabled` and `when`, resolved once per block. */
interface BlockGate {
  /** `enabled` with the block's own default applied. */
  enabled: boolean;
  when?: Condition;
}

interface CompiledForbiddenPaths extends BlockGate {
  patterns: CompiledGlobSet;
  exceptions: CompiledGlobSet;
}

interface CompiledPathAllowlist extends BlockGate {
  read: CompiledGlobSet;
  write: CompiledGlobSet;
  patch: CompiledGlobSet;
  /** `patch` falls back to `write` only when it is absent or empty. */
  patchPresent: boolean;
}

interface CompiledSecretPattern {
  regex?: RegExp;
  rank: number;
  severity: Severity;
  matchedRule: string;
  reason: string;
  /** Precomputed deny for a pattern outside the regex profile. */
  invalid?: BlockDecision;
}

interface CompiledSecretPatterns extends BlockGate {
  patterns: readonly CompiledSecretPattern[];
  skipPaths: CompiledGlobSet;
}

interface CompiledIndexedPattern {
  regex?: RegExp;
  rulePath: string;
  /** Precomputed deny for a pattern outside the regex profile. */
  invalid?: BlockDecision;
}

interface CompiledPatchIntegrity extends BlockGate {
  forbidden: readonly CompiledIndexedPattern[];
  maxAdditions: number;
  maxDeletions: number;
  requireBalance: boolean;
  maxImbalanceRatio: number;
}

interface CompiledShellCommands extends BlockGate {
  forbidden: readonly CompiledIndexedPattern[];
}

/** The tool lists of a base rule or an origin overlay. */
interface CompiledToolLists {
  allow?: Set<string>;
  block: Set<string>;
  requireConfirmation: Set<string>;
  default?: DefaultAction;
  maxArgsSize?: number;
}

interface CompiledToolAccess extends BlockGate, CompiledToolLists {}

/** An origin overlay plus the `matched_rule` prefix its decisions report. */
interface CompiledToolOverlay extends CompiledToolLists {
  paths: OverlayPaths;
}

interface CompiledEgressLists {
  allow?: CompiledHostSet;
  block: CompiledHostSet;
  default?: DefaultAction;
}

interface CompiledEgress extends BlockGate, CompiledEgressLists {}

interface CompiledEgressOverlayRule extends CompiledEgressLists {
  paths: OverlayPaths;
}

/** Precomputed `matched_rule` paths under one origin profile's overlay. */
interface OverlayPaths {
  block: string;
  allow: string;
  requireConfirmation: string;
  maxArgsSize: string;
  default: string;
}

interface CompiledComputerUse extends BlockGate {
  allowedActions: Set<string>;
  observe: boolean;
}

interface CompiledRemoteDesktopChannels extends BlockGate {
  clipboard: boolean;
  fileTransfer: boolean;
  audio: boolean;
  driveMapping: boolean;
}

interface CompiledInputInjection extends BlockGate {
  allowedTypes?: Set<string>;
}

interface CompiledBrowserAutomation extends BlockGate {
  allowedVerbs?: Set<string>;
  allowedDomains?: CompiledHostSet;
  blockedDomains: CompiledHostSet;
  credentialDetection: boolean;
  extraCredentialPatterns: readonly CompiledIndexedPattern[];
}

interface CompiledCodeExecution extends BlockGate {
  languageAllowlist?: Set<string>;
  moduleDenylist: readonly string[];
  networkAccess: boolean;
  maxExecutionTimeMs?: number;
  maxScanBytes?: number;
}

/** The compiled rule blocks, keyed the way the document keys them. */
interface CompiledRules {
  forbidden_paths?: CompiledForbiddenPaths;
  path_allowlist?: CompiledPathAllowlist;
  secret_patterns?: CompiledSecretPatterns;
  patch_integrity?: CompiledPatchIntegrity;
  shell_commands?: CompiledShellCommands;
  tool_access?: CompiledToolAccess;
  egress?: CompiledEgress;
  computer_use?: CompiledComputerUse;
  remote_desktop_channels?: CompiledRemoteDesktopChannels;
  input_injection?: CompiledInputInjection;
  browser_automation?: CompiledBrowserAutomation;
  code_execution?: CompiledCodeExecution;
}

// ---------------------------------------------------------------------------
// Compiled extensions
// ---------------------------------------------------------------------------

/** One origin profile's `match` object, flattened for comparison. */
interface CompiledOriginMatch {
  /** `[expected, field]` for every present string field, in document order. */
  strings: ReadonlyArray<readonly [string, keyof OriginContext]>;
  externalParticipants?: boolean;
  tags?: readonly string[];
  /** A `space_id` match wins outright (origins spec Section 3). */
  hasSpaceId: boolean;
}

interface CompiledOriginProfile {
  id: string;
  posture?: string;
  match?: CompiledOriginMatch;
  toolAccess?: CompiledToolOverlay;
  egress?: CompiledEgressOverlayRule;
}

/**
 * The `origins` extension, compiled. Its presence is the extension's presence:
 * a document without one has no `CompiledOrigins` and skips the guard.
 */
interface CompiledOrigins {
  denyByDefault: boolean;
  profiles: readonly CompiledOriginProfile[];
}

interface CompiledPostureState {
  capabilities: Set<string>;
  /** `extensions.posture.states.<id>.capabilities`. */
  capabilityPath: string;
}

interface CompiledPosture {
  initial: string;
  states: Map<string, CompiledPostureState>;
  transitions: readonly PostureTransition[];
}

// ---------------------------------------------------------------------------
// Static tables
// ---------------------------------------------------------------------------

/**
 * Rule blocks applicable to each reference action type, in evaluation order
 * (core spec Section 5). A missing entry means the type is unknown to the
 * specification -- a `Map`, not an object, so an action type that happens to
 * name an `Object.prototype` member is still unknown.
 */
const APPLICABLE_BLOCKS: ReadonlyMap<string, readonly BlockId[]> = new Map([
  ['file_read', ['forbidden_paths', 'path_allowlist']],
  ['file_write', ['forbidden_paths', 'path_allowlist', 'secret_patterns']],
  ['patch_apply', ['forbidden_paths', 'path_allowlist', 'patch_integrity', 'secret_patterns']],
  ['shell_command', ['shell_commands']],
  ['egress', ['egress', 'secret_patterns']],
  ['tool_call', ['tool_access', 'secret_patterns']],
  ['computer_use', ['computer_use', 'remote_desktop_channels']],
  ['input_inject', ['input_injection']],
  ['browser_action', ['browser_automation']],
  ['code_exec', ['code_execution']],
  ['custom', []],
] satisfies ReadonlyArray<readonly [string, BlockId[]]>);

/** Capability the posture guard requires per action type (posture spec 3.3). */
const REQUIRED_CAPABILITY: ReadonlyMap<string, string> = new Map([
  ['file_read', 'file_access'],
  ['file_write', 'file_write'],
  ['patch_apply', 'patch'],
  ['shell_command', 'shell'],
  ['tool_call', 'tool_call'],
  ['egress', 'egress'],
  ['custom', 'custom'],
]);

const enum PathOperation {
  Read,
  Write,
  Patch,
}

const EMPTY_CONTEXT: RuntimeContext = {};
const NO_CONDITIONS: Record<string, Condition> = {};

function decisionRank(decision: Decision): number {
  switch (decision) {
    case 'allow': return 1;
    case 'warn': return 2;
    case 'deny': return 3;
  }
}

function severityRank(severity: Severity): number {
  switch (severity) {
    case 'warn': return 1;
    case 'error': return 2;
    case 'critical': return 3;
    default: return 0;
  }
}

/** Decision contributed by one rule block. */
interface BlockDecision {
  decision: Decision;
  matched_rule?: string;
  reason?: string;
}

function blockAllow(matchedRule?: string, reason?: string): BlockDecision {
  return { decision: 'allow', matched_rule: matchedRule, reason };
}

function blockWarn(matchedRule: string, reason: string): BlockDecision {
  return { decision: 'warn', matched_rule: matchedRule, reason };
}

function blockDeny(matchedRule: string, reason: string): BlockDecision {
  return { decision: 'deny', matched_rule: matchedRule, reason };
}

/** Why an applicable block was not evaluated. */
type InactiveReason = 'absent' | 'disabled' | 'condition_false' | 'out_of_band_condition_false';

function inactiveReasonText(reason: InactiveReason, block: string): string {
  switch (reason) {
    case 'absent': return `no ${block} rule configured`;
    case 'disabled': return 'rule disabled';
    case 'condition_false': return 'when condition is false';
    case 'out_of_band_condition_false': return 'out-of-band condition is false';
  }
}

interface Inactive {
  inactive: InactiveReason;
}

const ABSENT: Inactive = { inactive: 'absent' };
const DISABLED: Inactive = { inactive: 'disabled' };
const CONDITION_FALSE: Inactive = { inactive: 'condition_false' };
const OUT_OF_BAND_FALSE: Inactive = { inactive: 'out_of_band_condition_false' };

function isInactive(value: BlockDecision | Inactive): value is Inactive {
  return (value as Inactive).inactive !== undefined;
}

/**
 * The built-in credential detectors of `browser_automation` (core spec 3.11),
 * compiled once for the process on first use rather than per policy: they are
 * the same patterns for every document.
 */
let builtinCredentialRegexes: ReadonlyArray<readonly [string, RegExp | undefined]> | undefined;

function credentialDetectors(): ReadonlyArray<readonly [string, RegExp | undefined]> {
  if (builtinCredentialRegexes === undefined) {
    builtinCredentialRegexes = BUILTIN_CREDENTIAL_PATTERNS.map(([name, pattern]) => {
      try {
        return [name, compileProfileRegex(pattern).regex] as const;
      } catch {
        return [name, undefined] as const;
      }
    });
  }
  return builtinCredentialRegexes;
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

export interface CompileOptions {
  /**
   * Raise {@link CompileError} on a pattern outside the regex profile instead
   * of deferring it to a fail-closed deny at evaluation time. Default `true`.
   */
  strict?: boolean;
}

/**
 * Compile `spec` into the form the evaluator runs against.
 *
 * Every regex, glob, host pattern and tool list is built once here, so an
 * evaluation costs only the matching itself: the cost of a policy's patterns
 * is paid at compile time, not per action.
 *
 * Fail-closed: by default any pattern outside the HushSpec regex profile
 * raises {@link CompileError} rather than producing a policy that silently
 * carries a dead pattern. Pass `{ strict: false }` to keep the evaluation-time
 * deny instead (what the free `evaluate()` functions do, so a hand-built
 * document still denies with the pattern's own `matched_rule` and reason).
 *
 * @throws {CompileError}
 */
export function compilePolicy(spec: HushSpec, options?: CompileOptions): CompiledPolicy {
  return new CompiledPolicy(spec, undefined, options?.strict !== false);
}

/**
 * {@link compilePolicy} for a resolved policy whose provenance is known: the
 * compiled policy reports this resolution (chain, content hash, signature
 * outcome) to every receipt it builds, instead of deriving a single-link one
 * from the document.
 */
export function compileResolution(resolution: Resolution, options?: CompileOptions): CompiledPolicy {
  return new CompiledPolicy(resolution.spec, resolution, options?.strict !== false);
}

/**
 * Compiled policies keyed by the document object they were compiled from, so
 * the free functions -- `evaluate()`, `evaluateTraced()`, detection, receipts
 * -- compile a given spec object once no matter how often they are called
 * with it. Weak, so a policy that is dropped takes its compilation with it.
 */
const SPEC_CACHE = new WeakMap<HushSpec, CompiledPolicy>();
const RESOLUTION_CACHE = new WeakMap<Resolution, CompiledPolicy>();

/**
 * The compiled form of `spec`, compiled on first use and reused afterwards.
 *
 * Keyed by object identity, so a document mutated in place after it has been
 * evaluated keeps its first compilation. Policies are values here -- parse,
 * merge and resolve all produce new documents -- so this only bites a caller
 * that edits a live document, which was never a supported way to change a
 * policy.
 *
 * Non-strict: a pattern outside the regex profile stays a fail-closed deny at
 * evaluation time, which is what every caller of the free functions expects.
 */
export function compiledFor(spec: HushSpec): CompiledPolicy {
  const cached = SPEC_CACHE.get(spec);
  if (cached !== undefined) return cached;
  const compiled = new CompiledPolicy(spec, undefined, false);
  SPEC_CACHE.set(spec, compiled);
  return compiled;
}

/** {@link compiledFor} for a {@link Resolution}, keyed by the resolution. */
export function compiledForResolution(resolution: Resolution): CompiledPolicy {
  const cached = RESOLUTION_CACHE.get(resolution);
  if (cached !== undefined) return cached;
  const compiled = new CompiledPolicy(resolution.spec, resolution, false);
  RESOLUTION_CACHE.set(resolution, compiled);
  return compiled;
}

/** Collects pattern failures so `strict` can report the first one. */
class CompileSink {
  first?: CompileError;

  record(path: string, detail: string | undefined): void {
    if (detail === undefined || this.first !== undefined) return;
    this.first = new CompileError(path, detail);
  }
}

function compileIndexed(
  patterns: string[] | undefined,
  pathOf: (index: number) => string,
  invalidReason: (detail: string) => string,
  sink: CompileSink,
): readonly CompiledIndexedPattern[] {
  if (patterns == null || patterns.length === 0) return [];
  return patterns.map((pattern, index) => {
    const compiled = compileRegex(pattern);
    const rulePath = pathOf(index);
    sink.record(rulePath, compiled.error);
    return {
      regex: compiled.regex,
      rulePath,
      ...(compiled.error === undefined
        ? {}
        : { invalid: blockDeny(rulePath, invalidReason(compiled.error)) }),
    };
  });
}

function compileToolLists(
  rule: ToolAccessRule | OriginToolAccessOverlay,
): CompiledToolLists {
  return {
    allow: compileToolSetOrUndefined(rule.allow),
    block: compileToolSet(rule.block),
    requireConfirmation: compileToolSet(rule.require_confirmation),
    ...(rule.default === undefined ? {} : { default: rule.default }),
    ...(rule.max_args_size === undefined ? {} : { maxArgsSize: rule.max_args_size }),
  };
}

function compileEgressLists(rule: EgressRule | OriginEgressOverlay): CompiledEgressLists {
  return {
    allow: compileHostsOrUndefined(rule.allow),
    block: compileHosts(rule.block),
    ...(rule.default === undefined ? {} : { default: rule.default }),
  };
}

function gate(enabled: boolean | undefined, fallback: boolean, when?: Condition): BlockGate {
  return { enabled: enabled ?? fallback, ...(when === undefined ? {} : { when }) };
}

function compileRules(rules: Rules | undefined, sink: CompileSink): CompiledRules {
  const compiled: CompiledRules = {};
  if (rules == null) return compiled;

  const forbiddenPaths: ForbiddenPathsRule | undefined = rules.forbidden_paths;
  if (forbiddenPaths != null) {
    compiled.forbidden_paths = {
      ...gate(forbiddenPaths.enabled, true, forbiddenPaths.when),
      patterns: compileGlobs(forbiddenPaths.patterns),
      exceptions: compileGlobs(forbiddenPaths.exceptions),
    };
  }

  const pathAllowlist: PathAllowlistRule | undefined = rules.path_allowlist;
  if (pathAllowlist != null) {
    compiled.path_allowlist = {
      ...gate(pathAllowlist.enabled, false, pathAllowlist.when),
      read: compileGlobs(pathAllowlist.read),
      write: compileGlobs(pathAllowlist.write),
      patch: compileGlobs(pathAllowlist.patch),
      patchPresent: (pathAllowlist.patch?.length ?? 0) > 0,
    };
  }

  const secretPatterns: SecretPatternsRule | undefined = rules.secret_patterns;
  if (secretPatterns != null) {
    const patterns = (secretPatterns.patterns ?? []).map((pattern): CompiledSecretPattern => {
      const regex = compileRegex(pattern.pattern);
      const errorRule = `rules.secret_patterns.patterns.${pattern.name}.pattern`;
      sink.record(errorRule, regex.error);
      return {
        regex: regex.regex,
        rank: severityRank(pattern.severity),
        severity: pattern.severity,
        matchedRule: `rules.secret_patterns.patterns.${pattern.name}`,
        reason: `content matched secret pattern '${pattern.name}'`,
        ...(regex.error === undefined
          ? {}
          : {
              invalid: blockDeny(
                errorRule,
                `secret pattern '${pattern.name}' is invalid: ${regex.error}`,
              ),
            }),
      };
    });
    compiled.secret_patterns = {
      ...gate(secretPatterns.enabled, true, secretPatterns.when),
      patterns,
      skipPaths: compileGlobs(secretPatterns.skip_paths),
    };
  }

  const patchIntegrity: PatchIntegrityRule | undefined = rules.patch_integrity;
  if (patchIntegrity != null) {
    compiled.patch_integrity = {
      ...gate(patchIntegrity.enabled, true, patchIntegrity.when),
      forbidden: compileIndexed(
        patchIntegrity.forbidden_patterns,
        (index) => `rules.patch_integrity.forbidden_patterns[${index}]`,
        (detail) => `patch forbidden pattern is invalid: ${detail}`,
        sink,
      ),
      maxAdditions: patchIntegrity.max_additions ?? 1000,
      maxDeletions: patchIntegrity.max_deletions ?? 500,
      requireBalance: patchIntegrity.require_balance === true,
      maxImbalanceRatio: patchIntegrity.max_imbalance_ratio ?? 10.0,
    };
  }

  const shellCommands: ShellCommandsRule | undefined = rules.shell_commands;
  if (shellCommands != null) {
    compiled.shell_commands = {
      ...gate(shellCommands.enabled, true, shellCommands.when),
      forbidden: compileIndexed(
        shellCommands.forbidden_patterns,
        (index) => `rules.shell_commands.forbidden_patterns[${index}]`,
        (detail) => `shell forbidden pattern is invalid: ${detail}`,
        sink,
      ),
    };
  }

  const toolAccess: ToolAccessRule | undefined = rules.tool_access;
  if (toolAccess != null) {
    compiled.tool_access = {
      ...gate(toolAccess.enabled, true, toolAccess.when),
      ...compileToolLists(toolAccess),
    };
  }

  const egress: EgressRule | undefined = rules.egress;
  if (egress != null) {
    compiled.egress = {
      ...gate(egress.enabled, true, egress.when),
      ...compileEgressLists(egress),
    };
  }

  const computerUse: ComputerUseRule | undefined = rules.computer_use;
  if (computerUse != null) {
    compiled.computer_use = {
      ...gate(computerUse.enabled, false, computerUse.when),
      allowedActions: new Set(computerUse.allowed_actions ?? []),
      observe: (computerUse.mode ?? 'guardrail') === 'observe',
    };
  }

  const channels: RemoteDesktopChannelsRule | undefined = rules.remote_desktop_channels;
  if (channels != null) {
    compiled.remote_desktop_channels = {
      ...gate(channels.enabled, false, channels.when),
      clipboard: channels.clipboard ?? false,
      fileTransfer: channels.file_transfer ?? false,
      audio: channels.audio ?? true,
      driveMapping: channels.drive_mapping ?? false,
    };
  }

  const inputInjection: InputInjectionRule | undefined = rules.input_injection;
  if (inputInjection != null) {
    compiled.input_injection = {
      ...gate(inputInjection.enabled, false, inputInjection.when),
      allowedTypes: compileExactSetOrUndefined(inputInjection.allowed_types),
    };
  }

  const browser: BrowserAutomationRule | undefined = rules.browser_automation;
  if (browser != null) {
    compiled.browser_automation = {
      ...gate(browser.enabled, false, browser.when),
      allowedVerbs: compileExactSetOrUndefined(browser.allowed_verbs),
      allowedDomains: compileHostsOrUndefined(browser.allowed_domains),
      blockedDomains: compileHosts(browser.blocked_domains),
      credentialDetection: browser.credential_detection ?? true,
      extraCredentialPatterns: compileIndexed(
        browser.extra_credential_patterns,
        (index) => `rules.browser_automation.extra_credential_patterns[${index}]`,
        (detail) => `credential pattern is invalid: ${detail}`,
        sink,
      ),
    };
  }

  const codeExecution: CodeExecutionRule | undefined = rules.code_execution;
  if (codeExecution != null) {
    compiled.code_execution = {
      ...gate(codeExecution.enabled, false, codeExecution.when),
      languageAllowlist: compileExactSetOrUndefined(codeExecution.language_allowlist),
      moduleDenylist: codeExecution.module_denylist ?? [],
      networkAccess: codeExecution.network_access === true,
      ...(codeExecution.max_execution_time_ms === undefined
        ? {}
        : { maxExecutionTimeMs: codeExecution.max_execution_time_ms }),
      ...(codeExecution.max_scan_bytes === undefined
        ? {}
        : { maxScanBytes: codeExecution.max_scan_bytes }),
    };
  }

  return compiled;
}

function overlayPaths(profileId: string, block: 'tool_access' | 'egress'): OverlayPaths {
  const prefix = `extensions.origins.profiles.${profileId}.${block}`;
  return {
    block: `${prefix}.block`,
    allow: `${prefix}.allow`,
    requireConfirmation: `${prefix}.require_confirmation`,
    maxArgsSize: `${prefix}.max_args_size`,
    default: `${prefix}.default`,
  };
}

function compileOriginMatch(match: OriginMatch): CompiledOriginMatch {
  const strings: Array<readonly [string, keyof OriginContext]> = [];
  const push = (expected: string | undefined, field: keyof OriginContext): void => {
    if (expected !== undefined) strings.push([expected, field] as const);
  };
  push(match.provider, 'provider');
  push(match.tenant_id, 'tenant_id');
  push(match.space_id, 'space_id');
  push(match.space_type, 'space_type');
  push(match.visibility, 'visibility');
  push(match.sensitivity, 'sensitivity');
  push(match.actor_role, 'actor_role');
  return {
    strings,
    ...(match.external_participants === undefined
      ? {}
      : { externalParticipants: match.external_participants }),
    ...(match.tags == null || match.tags.length === 0 ? {} : { tags: match.tags }),
    hasSpaceId: match.space_id != null,
  };
}

function compileOriginProfile(profile: OriginProfile): CompiledOriginProfile {
  return {
    id: profile.id,
    ...(profile.posture === undefined ? {} : { posture: profile.posture }),
    ...(profile.match == null ? {} : { match: compileOriginMatch(profile.match) }),
    ...(profile.tool_access == null
      ? {}
      : {
          toolAccess: {
            ...compileToolLists(profile.tool_access),
            paths: overlayPaths(profile.id, 'tool_access'),
          },
        }),
    ...(profile.egress == null
      ? {}
      : {
          egress: {
            ...compileEgressLists(profile.egress),
            paths: overlayPaths(profile.id, 'egress'),
          },
        }),
  };
}

function compilePosture(posture: PostureExtension | undefined): CompiledPosture | undefined {
  if (posture == null) return undefined;
  const states = new Map<string, CompiledPostureState>();
  for (const [id, state] of Object.entries(posture.states ?? {})) {
    states.set(id, {
      capabilities: new Set(state.capabilities ?? []),
      capabilityPath: `extensions.posture.states.${id}.capabilities`,
    });
  }
  return {
    initial: posture.initial,
    states,
    transitions: posture.transitions ?? [],
  };
}

// ---------------------------------------------------------------------------
// CompiledPolicy
// ---------------------------------------------------------------------------

/**
 * A policy compiled for evaluation.
 *
 * Hold one per policy document and evaluate every action through it: the
 * patterns, matchers and tables are built once at construction, and an
 * evaluation allocates only its own trace.
 *
 * ```ts
 * const compiled = compilePolicy(parseOrThrow(yaml));
 * compiled.evaluate({ type: 'egress', target: 'api.example.com' });
 * ```
 */
export class CompiledPolicy {
  /** The document this was compiled from, kept verbatim for receipts. */
  readonly spec: HushSpec;

  private readonly rules: CompiledRules;
  private readonly origins?: CompiledOrigins;
  private readonly posture?: CompiledPosture;
  /** Compiled detection configuration; `undefined` without the extension. */
  readonly detection?: CompiledDetection;

  private resolutionValue?: Resolution;
  private hash?: string;

  /** @internal Use {@link compilePolicy} or {@link compileResolution}. */
  constructor(spec: HushSpec, resolution: Resolution | undefined, strict: boolean) {
    const sink = new CompileSink();
    this.spec = spec;
    this.rules = compileRules(spec.rules, sink);
    const origins = spec.extensions?.origins;
    if (origins != null) {
      this.origins = {
        denyByDefault: (origins.default_behavior ?? 'deny') === 'deny',
        profiles: (origins.profiles ?? []).map(compileOriginProfile),
      };
    }
    this.posture = compilePosture(spec.extensions?.posture);
    const detection = compileDetection(spec.extensions?.detection);
    if (detection !== undefined) this.detection = detection;
    if (resolution !== undefined) {
      this.resolutionValue = resolution;
      this.hash = resolution.content_hash;
    }
    if (strict && sink.first !== undefined) {
      throw sink.first;
    }
  }

  /**
   * Canonical content hash of the policy (`sha256:` + hex), computed on first
   * use and cached: policy identity costs nothing per receipt.
   *
   * @throws {CanonicalError} when the document has no canonical form (it still
   * declares `extends`).
   */
  get contentHash(): string {
    if (this.hash === undefined) {
      this.hash = this.resolutionValue?.content_hash ?? contentHash(this.spec);
    }
    return this.hash;
  }

  /**
   * The resolution receipts built from this policy report. Either the one the
   * policy was compiled with ({@link compileResolution}) or a single-link
   * resolution derived from the document on first use.
   */
  get resolution(): Resolution {
    if (this.resolutionValue === undefined) {
      this.resolutionValue = resolutionFromResolved(this.spec);
      this.hash = this.resolutionValue.content_hash;
    }
    return this.resolutionValue;
  }

  /**
   * Evaluate `action`.
   *
   * `when` conditions see `action.context` (an empty context and the engine
   * clock when absent).
   */
  evaluate(action: EvaluationAction): EvaluationResult {
    return this.evaluateTraced(action).result;
  }

  /** Full evaluation with the recorded rule trace (used by receipts). */
  evaluateTraced(
    action: EvaluationAction,
    context?: RuntimeContext,
    conditions: Record<string, Condition> = NO_CONDITIONS,
  ): TracedEvaluation {
    const effectiveContext = context ?? action.context ?? EMPTY_CONTEXT;
    return new Evaluation(
      this.rules,
      this.origins,
      this.posture,
      action,
      effectiveContext,
      conditions,
    ).run();
  }

  /**
   * {@link evaluate} with an explicit runtime context and an out-of-band map of
   * conditions keyed by rule-block name. The explicit `context` replaces
   * `action.context`; out-of-band conditions are ANDed with each block's own
   * `when` (core spec 3.13).
   */
  evaluateWithContext(
    action: EvaluationAction,
    context: RuntimeContext,
    conditions: Record<string, Condition> = NO_CONDITIONS,
  ): EvaluationResult {
    return this.evaluateTraced(action, context, conditions).result;
  }

  /** Evaluation with the policy's `detection:` extension folded in. */
  evaluateWithDetection(action: EvaluationAction): EvaluationWithDetection {
    const traced = this.evaluateWithDetectionTraced(action);
    return {
      evaluation: traced.evaluation,
      detections: traced.detections,
      detectionDecision: traced.detectionDecision,
    };
  }

  /**
   * {@link evaluateWithDetection} with the recorded rule trace and the
   * per-detector receipt entries (receipt spec 4.6).
   */
  evaluateWithDetectionTraced(
    action: EvaluationAction,
    context?: RuntimeContext,
    conditions: Record<string, Condition> = NO_CONDITIONS,
  ): TracedEvaluationWithDetection {
    const traced = this.evaluateTraced(action, context, conditions);
    return runDetection(this.detection, traced, action);
  }

  /**
   * Evaluate and record a decision receipt against this policy's
   * {@link CompiledPolicy.resolution}.
   */
  evaluateAudited(
    action: EvaluationAction,
    config: AuditConfig = DEFAULT_AUDIT_CONFIG,
    ctx: AuditContext = {},
  ): DecisionReceipt {
    const timed = config.enabled && config.recordDuration;
    const start = timed ? performance.now() : 0;
    const detected = this.evaluateWithDetectionTraced(
      action,
      ctx.context,
      ctx.conditions ?? NO_CONDITIONS,
    );
    const durationUs = timed ? Math.round((performance.now() - start) * 1000) : undefined;
    return receiptFromEvaluation(this.resolution, action, detected, durationUs, config, ctx);
  }
}

// ---------------------------------------------------------------------------
// One evaluation
// ---------------------------------------------------------------------------

class Evaluation {
  private readonly trace: RuleEvaluation[] = [];

  constructor(
    private readonly rules: CompiledRules,
    private readonly origins: CompiledOrigins | undefined,
    private readonly posture: CompiledPosture | undefined,
    private readonly action: EvaluationAction,
    private readonly context: RuntimeContext,
    private readonly conditions: Record<string, Condition>,
  ) {}

  run(): TracedEvaluation {
    if (isPanicActive()) {
      this.record('panic', 'deny', PANIC_RULE, 'emergency panic mode is active', true);
      return this.finish('deny', PANIC_RULE, 'emergency panic mode is active', undefined, undefined);
    }

    const actionType = this.action.type;
    const blocks = APPLICABLE_BLOCKS.get(actionType);
    if (blocks == null) {
      const reason = `action type '${actionType}' is unknown to the specification`;
      this.record('default', 'deny', UNKNOWN_ACTION_TYPE_RULE, reason, true);
      return this.finish('deny', UNKNOWN_ACTION_TYPE_RULE, reason, undefined, undefined);
    }

    // Origins guard: select a profile or apply default_behavior.
    const origins = this.origins;
    const matchedProfile = selectOriginProfile(origins, this.action.origin);
    const originProfileId = matchedProfile?.id;
    if (origins != null && matchedProfile == null && origins.denyByDefault) {
      const reason = 'no origin profile matched and default_behavior is deny';
      this.record('origins', 'deny', 'extensions.origins.default_behavior', reason, true);
      this.skipAll(blocks, 'short-circuited by origins deny');
      return this.finish('deny', 'extensions.origins.default_behavior', reason, undefined, undefined);
    }

    // Posture guard.
    const posture = resolvePosture(this.posture, matchedProfile, this.action.posture);
    const denied = this.postureCapabilityGuard(posture);
    if (denied != null) {
      this.skipAll(blocks, 'short-circuited by posture deny');
      return this.finish('deny', denied.matched_rule, denied.reason, originProfileId, posture);
    }

    if (actionType === 'custom') {
      // Only a posture state granting the `custom` capability can vouch for an
      // engine-defined action (core spec Section 5).
      if (posture == null) {
        const reason = 'custom actions require a posture state granting the custom capability';
        this.record('default', 'deny', UNKNOWN_ACTION_TYPE_RULE, reason, true);
        return this.finish('deny', UNKNOWN_ACTION_TYPE_RULE, reason, originProfileId, undefined);
      }
      return this.finish('allow', undefined, undefined, originProfileId, posture);
    }

    // Block evaluation and aggregation (core spec 6.1).
    const normalizedPath = this.action.target != null ? normalizePath(this.action.target) : undefined;
    const decisions: BlockDecision[] = [];
    for (const block of blocks) {
      const outcome = this.evaluateBlock(block, matchedProfile, normalizedPath);
      if (isInactive(outcome)) {
        this.record(block, 'skip', undefined, inactiveReasonText(outcome.inactive, block), false);
      } else {
        this.record(block, outcome.decision, outcome.matched_rule, outcome.reason, true);
        decisions.push(outcome);
      }
    }

    let aggregate: Decision = 'allow';
    for (const decision of decisions) {
      if (decisionRank(decision.decision) > decisionRank(aggregate)) {
        aggregate = decision.decision;
      }
    }
    const winner = decisions.find(
      (decision) => decision.decision === aggregate && decision.matched_rule != null,
    );

    return this.finish(aggregate, winner?.matched_rule, winner?.reason, originProfileId, posture);
  }

  private finish(
    decision: Decision,
    matchedRule: string | undefined,
    reason: string | undefined,
    originProfile: string | undefined,
    posture: PostureResult | undefined,
  ): TracedEvaluation {
    return {
      result: {
        decision,
        matched_rule: matchedRule,
        reason,
        origin_profile: originProfile,
        posture,
      },
      trace: this.trace,
    };
  }

  private record(
    block: string,
    outcome: RuleOutcome,
    matchedRule: string | undefined,
    reason: string | undefined,
    evaluated: boolean,
  ): void {
    this.trace.push({
      rule_block: block,
      outcome,
      matched_rule: matchedRule,
      reason,
      evaluated,
    });
  }

  private skipAll(blocks: readonly string[], reason: string): void {
    for (const block of blocks) {
      this.record(block, 'skip', undefined, reason, false);
    }
  }

  /**
   * The active-block mask for one block: a present block is active when it is
   * enabled and its `when` plus any out-of-band condition hold for the runtime
   * context. Nothing is cloned or rebuilt -- the compiled block is consulted
   * in place and only the mask is per-evaluation.
   */
  private activity(block: string, compiled: BlockGate): Inactive | undefined {
    if (!compiled.enabled) {
      return DISABLED;
    }
    if (compiled.when !== undefined && !evaluateCondition(compiled.when, this.context)) {
      return CONDITION_FALSE;
    }
    const outOfBand = Object.prototype.hasOwnProperty.call(this.conditions, block)
      ? this.conditions[block]
      : undefined;
    if (outOfBand != null && !evaluateCondition(outOfBand, this.context)) {
      return OUT_OF_BAND_FALSE;
    }
    return undefined;
  }

  private evaluateBlock(
    block: BlockId,
    matchedProfile: CompiledOriginProfile | undefined,
    normalizedPath: string | undefined,
  ): BlockDecision | Inactive {
    const rules = this.rules;
    const action = this.action;
    const content = action.content;

    switch (block) {
      case 'forbidden_paths': {
        const rule = rules.forbidden_paths;
        if (rule == null) return ABSENT;
        const inactive = this.activity(block, rule);
        if (inactive) return inactive;
        return evaluateForbiddenPaths(rule, normalizedPath ?? '');
      }
      case 'path_allowlist': {
        const rule = rules.path_allowlist;
        if (rule == null) return ABSENT;
        const inactive = this.activity(block, rule);
        if (inactive) return inactive;
        const operation = action.type === 'file_read'
          ? PathOperation.Read
          : action.type === 'patch_apply'
            ? PathOperation.Patch
            : PathOperation.Write;
        return evaluatePathAllowlist(rule, normalizedPath ?? '', operation);
      }
      case 'secret_patterns': {
        const rule = rules.secret_patterns;
        if (rule == null) return ABSENT;
        const pathBearing = action.type === 'file_write' || action.type === 'patch_apply';
        // egress and tool_call are scanned only when they carry content.
        if (!pathBearing && content == null) return ABSENT;
        const inactive = this.activity(block, rule);
        if (inactive) return inactive;
        const skipPath = pathBearing ? normalizedPath : undefined;
        return evaluateSecretPatterns(rule, skipPath, content ?? '');
      }
      case 'patch_integrity': {
        const rule = rules.patch_integrity;
        if (rule == null) return ABSENT;
        const inactive = this.activity(block, rule);
        if (inactive) return inactive;
        return evaluatePatchIntegrity(rule, content ?? '');
      }
      case 'shell_commands': {
        const rule = rules.shell_commands;
        if (rule == null) return ABSENT;
        const inactive = this.activity(block, rule);
        if (inactive) return inactive;
        return evaluateShellCommands(rule, action.target ?? '');
      }
      case 'tool_access': {
        const base = rules.tool_access;
        const overlay = matchedProfile?.toolAccess;
        if (base == null && overlay == null) return ABSENT;
        if (base != null) {
          const inactive = this.activity(block, base);
          if (inactive) return inactive;
        }
        return evaluateToolAccess(base, overlay, action);
      }
      case 'egress': {
        const base = rules.egress;
        const overlay = matchedProfile?.egress;
        if (base == null && overlay == null) return ABSENT;
        if (base != null) {
          const inactive = this.activity(block, base);
          if (inactive) return inactive;
        }
        const host = action.target != null ? normalizeHost(action.target) : undefined;
        return evaluateEgress(base, overlay, host);
      }
      case 'computer_use': {
        const rule = rules.computer_use;
        if (rule == null) return ABSENT;
        const inactive = this.activity(block, rule);
        if (inactive) return inactive;
        return evaluateComputerUse(rule, action.target ?? '');
      }
      case 'remote_desktop_channels': {
        const rule = rules.remote_desktop_channels;
        if (rule == null) return ABSENT;
        const inactive = this.activity(block, rule);
        if (inactive) return inactive;
        return evaluateRemoteDesktopChannels(rule, action.target ?? '') ?? ABSENT;
      }
      case 'input_injection': {
        const rule = rules.input_injection;
        if (rule == null) return ABSENT;
        const inactive = this.activity(block, rule);
        if (inactive) return inactive;
        return evaluateInputInjection(rule, action.target ?? '');
      }
      case 'browser_automation': {
        const rule = rules.browser_automation;
        if (rule == null) return ABSENT;
        const inactive = this.activity(block, rule);
        if (inactive) return inactive;
        return evaluateBrowserAutomation(rule, action);
      }
      case 'code_execution': {
        const rule = rules.code_execution;
        if (rule == null) return ABSENT;
        const inactive = this.activity(block, rule);
        if (inactive) return inactive;
        return evaluateCodeExecution(rule, action);
      }
      default:
        return ABSENT;
    }
  }

  private postureCapabilityGuard(posture: PostureResult | undefined): BlockDecision | undefined {
    if (posture == null) return undefined;
    const compiled = this.posture;
    if (compiled == null) return undefined;
    const capability = REQUIRED_CAPABILITY.get(this.action.type);
    if (capability == null) return undefined;

    const currentState = compiled.states.get(posture.current);
    if (currentState == null) {
      const rule = `extensions.posture.states.${posture.current}`;
      const reason = `unknown posture state '${posture.current}'`;
      this.record('posture_capability', 'deny', rule, reason, true);
      return blockDeny(rule, reason);
    }

    if (currentState.capabilities.has(capability)) {
      this.record('posture_capability', 'allow', undefined, 'posture capabilities satisfied', true);
      return undefined;
    }

    const rule = currentState.capabilityPath;
    const reason = `posture '${posture.current}' does not allow capability '${capability}'`;
    this.record('posture_capability', 'deny', rule, reason, true);
    return blockDeny(rule, reason);
  }
}

// ---------------------------------------------------------------------------
// Rule blocks
// ---------------------------------------------------------------------------

function evaluateForbiddenPaths(rule: CompiledForbiddenPaths, path: string): BlockDecision {
  if (anyGlobMatches(rule.exceptions, path)) {
    return blockAllow('rules.forbidden_paths.exceptions', 'path matched an explicit exception');
  }
  if (anyGlobMatches(rule.patterns, path)) {
    return blockDeny('rules.forbidden_paths.patterns', 'path matched a forbidden pattern');
  }
  return blockAllow(undefined, 'path did not match any forbidden pattern');
}

function evaluatePathAllowlist(
  rule: CompiledPathAllowlist,
  path: string,
  operation: PathOperation,
): BlockDecision {
  let patterns: CompiledGlobSet;
  switch (operation) {
    case PathOperation.Read:
      patterns = rule.read;
      break;
    case PathOperation.Write:
      patterns = rule.write;
      break;
    case PathOperation.Patch:
      patterns = rule.patchPresent ? rule.patch : rule.write;
      break;
  }
  if (anyGlobMatches(patterns, path)) {
    return blockAllow('rules.path_allowlist', 'path matched allowlist');
  }
  return blockDeny('rules.path_allowlist', 'path did not match allowlist');
}

function evaluateSecretPatterns(
  rule: CompiledSecretPatterns,
  skipPath: string | undefined,
  content: string,
): BlockDecision {
  if (skipPath != null && anyGlobMatches(rule.skipPaths, skipPath)) {
    return blockAllow('rules.secret_patterns.skip_paths', 'path is excluded from secret scanning');
  }

  let bestRank = 0;
  let best: CompiledSecretPattern | undefined;
  for (const pattern of rule.patterns) {
    // Fail closed: a pattern that will not compile under the HushSpec regex
    // profile denies the action rather than being skipped (core spec 3.14.3).
    if (pattern.invalid !== undefined) {
      return pattern.invalid;
    }
    if (pattern.regex!.test(content)) {
      // Strictly greater keeps the first pattern in document order among
      // those at the highest matched severity.
      if (best == null || pattern.rank > bestRank) {
        bestRank = pattern.rank;
        best = pattern;
      }
    }
  }

  if (best == null) {
    return blockAllow(undefined, 'content did not match any secret pattern');
  }

  return best.severity === 'warn'
    ? blockWarn(best.matchedRule, best.reason)
    : blockDeny(best.matchedRule, best.reason);
}

function evaluatePatchIntegrity(rule: CompiledPatchIntegrity, content: string): BlockDecision {
  for (const pattern of rule.forbidden) {
    if (pattern.invalid !== undefined) {
      return pattern.invalid;
    }
    if (pattern.regex!.test(content)) {
      return blockDeny(pattern.rulePath, 'patch content matched a forbidden pattern');
    }
  }

  const stats = patchStats(content);
  if (stats.additions > rule.maxAdditions) {
    return blockDeny('rules.patch_integrity.max_additions', 'patch additions exceeded max_additions');
  }
  if (stats.deletions > rule.maxDeletions) {
    return blockDeny('rules.patch_integrity.max_deletions', 'patch deletions exceeded max_deletions');
  }

  if (rule.requireBalance) {
    const oneSided = (stats.additions === 0) !== (stats.deletions === 0);
    if (oneSided) {
      return blockDeny(
        'rules.patch_integrity.max_imbalance_ratio',
        'patch has changes on only one side; the imbalance ratio is infinite',
      );
    }
    if (stats.additions > 0 && stats.deletions > 0) {
      const larger = Math.max(stats.additions, stats.deletions);
      const smaller = Math.min(stats.additions, stats.deletions);
      if (larger / smaller > rule.maxImbalanceRatio) {
        return blockDeny(
          'rules.patch_integrity.max_imbalance_ratio',
          'patch exceeded max imbalance ratio',
        );
      }
    }
  }

  return blockAllow(undefined, 'patch passed integrity checks');
}

function evaluateShellCommands(rule: CompiledShellCommands, command: string): BlockDecision {
  for (const pattern of rule.forbidden) {
    if (pattern.invalid !== undefined) {
      return pattern.invalid;
    }
    if (pattern.regex!.test(command)) {
      return blockDeny(pattern.rulePath, 'shell command matched a forbidden pattern');
    }
  }
  return blockAllow(undefined, 'command did not match any forbidden pattern');
}

function evaluateToolAccess(
  base: CompiledToolAccess | undefined,
  overlay: CompiledToolOverlay | undefined,
  action: EvaluationAction,
): BlockDecision {
  const tool = (action.target ?? '').normalize('NFC');
  const paths = overlay?.paths;

  // 1. max_args_size: the smaller of the two when both are specified.
  const baseLimit = base?.maxArgsSize != null
    ? { limit: base.maxArgsSize, matchedRule: 'rules.tool_access.max_args_size' }
    : undefined;
  const overlayLimit = overlay?.maxArgsSize != null && paths != null
    ? { limit: overlay.maxArgsSize, matchedRule: paths.maxArgsSize }
    : undefined;
  const limit = baseLimit != null && overlayLimit != null
    ? (overlayLimit.limit < baseLimit.limit ? overlayLimit : baseLimit)
    : (baseLimit ?? overlayLimit);
  if (limit != null && (action.args_size ?? 0) > limit.limit) {
    return blockDeny(limit.matchedRule, 'tool arguments exceeded max_args_size');
  }

  // 2. block: union of both lists.
  if (base != null && base.block.has(tool)) {
    return blockDeny('rules.tool_access.block', 'tool is explicitly blocked');
  }
  if (overlay != null && paths != null && overlay.block.has(tool)) {
    return blockDeny(paths.block, 'tool is explicitly blocked');
  }

  // 3. require_confirmation: union of both lists.
  if (base != null && base.requireConfirmation.has(tool)) {
    return blockWarn('rules.tool_access.require_confirmation', 'tool requires confirmation');
  }
  if (overlay != null && paths != null && overlay.requireConfirmation.has(tool)) {
    return blockWarn(paths.requireConfirmation, 'tool requires confirmation');
  }

  // 4/5. allowlist mode: intersection when both lists are non-empty.
  const baseAllow = base?.allow;
  const overlayAllow = overlay?.allow;
  if (baseAllow != null || overlayAllow != null) {
    if (baseAllow != null && !baseAllow.has(tool)) {
      return blockDeny('rules.tool_access.allow', 'tool is not in the allowlist');
    }
    if (overlayAllow != null && paths != null && !overlayAllow.has(tool)) {
      return blockDeny(paths.allow, 'tool is not in the allowlist');
    }
    const matchedRule = overlayAllow != null && paths != null ? paths.allow : 'rules.tool_access.allow';
    return blockAllow(matchedRule, 'tool is explicitly allowed');
  }

  // 6. default: block when the base says block or the overlay specifies block.
  const baseDefault = base?.default ?? 'allow';
  const overlayDefault = overlay?.default;
  const effective = baseDefault === 'block' || overlayDefault === 'block' ? 'block' : 'allow';
  const matchedRule = defaultRulePath(
    base != null,
    baseDefault,
    overlayDefault,
    effective,
    'rules.tool_access.default',
    paths?.default,
  );
  return effective === 'allow'
    ? blockAllow(matchedRule, 'tool matched default allow')
    : blockDeny(matchedRule, 'tool matched default block');
}

/**
 * Path reported for a `default` decision: the object whose `default` field
 * determined the effective value.
 */
function defaultRulePath(
  basePresent: boolean,
  baseDefault: DefaultAction,
  overlayDefault: DefaultAction | undefined,
  effective: DefaultAction,
  basePath: string,
  overlayPath: string | undefined,
): string {
  if (overlayPath == null) return basePath;
  if (effective === 'block') {
    return basePresent && baseDefault === 'block' ? basePath : overlayPath;
  }
  return basePresent || overlayDefault == null ? basePath : overlayPath;
}

function evaluateEgress(
  base: CompiledEgress | undefined,
  overlay: CompiledEgressOverlayRule | undefined,
  host: string | undefined,
): BlockDecision {
  const paths = overlay?.paths;

  // 1. block: union of both lists.
  if (base != null && anyHostMatches(base.block, host)) {
    return blockDeny('rules.egress.block', 'domain is explicitly blocked');
  }
  if (overlay != null && paths != null && anyHostMatches(overlay.block, host)) {
    return blockDeny(paths.block, 'domain is explicitly blocked');
  }

  // 2. allow: intersection when both lists are non-empty.
  const baseAllow = base?.allow;
  const overlayAllow = overlay?.allow;
  if (baseAllow != null || overlayAllow != null) {
    const baseOk = baseAllow == null || anyHostMatches(baseAllow, host);
    const overlayOk = overlayAllow == null || anyHostMatches(overlayAllow, host);
    if (baseOk && overlayOk) {
      const matchedRule = overlayAllow != null && paths != null ? paths.allow : 'rules.egress.allow';
      return blockAllow(matchedRule, 'domain is explicitly allowed');
    }
  }

  // 3. default.
  const baseDefault = base?.default ?? 'block';
  const overlayDefault = overlay?.default;
  const effective = baseDefault === 'block' || overlayDefault === 'block' ? 'block' : 'allow';
  const matchedRule = defaultRulePath(
    base != null,
    baseDefault,
    overlayDefault,
    effective,
    'rules.egress.default',
    paths?.default,
  );
  return effective === 'allow'
    ? blockAllow(matchedRule, 'domain matched default allow')
    : blockDeny(matchedRule, 'domain matched default block');
}

function evaluateComputerUse(rule: CompiledComputerUse, target: string): BlockDecision {
  if (rule.allowedActions.has(target)) {
    return blockAllow(
      'rules.computer_use.allowed_actions',
      'computer-use action is explicitly allowed',
    );
  }
  if (rule.observe) {
    return blockAllow('rules.computer_use.mode', 'observe mode does not block unlisted actions');
  }
  // guardrail and fail_closed have identical reference semantics (D9).
  return blockDeny('rules.computer_use.mode', 'unlisted computer-use action is denied');
}

function evaluateRemoteDesktopChannels(
  rule: CompiledRemoteDesktopChannels,
  target: string,
): BlockDecision | undefined {
  let field: string;
  let allowed: boolean;
  switch (target) {
    case 'remote.clipboard':
      field = 'clipboard';
      allowed = rule.clipboard;
      break;
    case 'remote.file_transfer':
      field = 'file_transfer';
      allowed = rule.fileTransfer;
      break;
    case 'remote.audio':
      field = 'audio';
      allowed = rule.audio;
      break;
    case 'remote.drive_mapping':
      field = 'drive_mapping';
      allowed = rule.driveMapping;
      break;
    default:
      return undefined;
  }

  const matchedRule = `rules.remote_desktop_channels.${field}`;
  return allowed
    ? blockAllow(matchedRule, `remote desktop channel '${field}' is enabled`)
    : blockDeny(matchedRule, `remote desktop channel '${field}' is disabled`);
}

function evaluateInputInjection(rule: CompiledInputInjection, target: string): BlockDecision {
  if (rule.allowedTypes == null) {
    return blockDeny(
      'rules.input_injection.allowed_types',
      'input injection is not allowed when allowed_types is empty',
    );
  }
  if (rule.allowedTypes.has(target)) {
    return blockAllow(
      'rules.input_injection.allowed_types',
      'input injection type is explicitly allowed',
    );
  }
  return blockDeny('rules.input_injection.allowed_types', 'input injection type is not allowed');
}

function evaluateBrowserAutomation(
  rule: CompiledBrowserAutomation,
  action: EvaluationAction,
): BlockDecision {
  const verb = action.target ?? '';

  // 1. verb allowlist (exact match).
  if (rule.allowedVerbs != null && !rule.allowedVerbs.has(verb)) {
    return blockDeny(
      'rules.browser_automation.allowed_verbs',
      'browser verb is not in the allowlist',
    );
  }

  // 2. destination host.
  if (action.url != null) {
    const host = normalizeHost(action.url);
    if (anyHostMatches(rule.blockedDomains, host)) {
      return blockDeny(
        'rules.browser_automation.blocked_domains',
        'destination host is explicitly blocked',
      );
    }
    if (rule.allowedDomains != null && !anyHostMatches(rule.allowedDomains, host)) {
      return blockDeny(
        'rules.browser_automation.allowed_domains',
        'destination host is not in the allowlist',
      );
    }
  }

  // 3. credential detection on typed input.
  if (rule.credentialDetection && action.content != null) {
    const content = action.content;
    for (const [name, regex] of credentialDetectors()) {
      if (regex !== undefined && regex.test(content)) {
        return blockDeny(
          'rules.browser_automation.credential_detection',
          `typed input matched built-in credential detector '${name}'`,
        );
      }
    }
    for (let index = 0; index < rule.extraCredentialPatterns.length; index++) {
      const pattern = rule.extraCredentialPatterns[index];
      if (pattern.invalid !== undefined) {
        return pattern.invalid;
      }
      if (pattern.regex!.test(content)) {
        return blockDeny(
          'rules.browser_automation.credential_detection',
          `typed input matched extra_credential_patterns[${index}]`,
        );
      }
    }
  }

  return blockAllow('rules.browser_automation', 'browser action is permitted');
}

function evaluateCodeExecution(
  rule: CompiledCodeExecution,
  action: EvaluationAction,
): BlockDecision {
  const language = action.target ?? '';

  // 1. language allowlist (exact, case-sensitive).
  if (rule.languageAllowlist != null && !rule.languageAllowlist.has(language)) {
    return blockDeny(
      'rules.code_execution.language_allowlist',
      'language is not in the allowlist',
    );
  }

  // 2. network access.
  if (action.network === true && !rule.networkAccess) {
    return blockDeny(
      'rules.code_execution.network_access',
      'network access is not permitted for code execution',
    );
  }

  // 3. execution time bound.
  if (
    rule.maxExecutionTimeMs != null
    && action.timeout_ms != null
    && action.timeout_ms > rule.maxExecutionTimeMs
  ) {
    return blockDeny(
      'rules.code_execution.max_execution_time_ms',
      'requested execution time exceeds max_execution_time_ms',
    );
  }

  // 4. module denylist: literal word match within the scanned prefix.
  if (action.content != null) {
    const scanned = rule.maxScanBytes != null
      ? truncateUtf8(action.content, rule.maxScanBytes)
      : action.content;
    for (const module of rule.moduleDenylist) {
      if (containsWord(scanned, module)) {
        return blockDeny(
          'rules.code_execution.module_denylist',
          `code references denied module '${module}'`,
        );
      }
    }
  }

  return blockAllow('rules.code_execution', 'code execution is permitted');
}

/** Truncate `content` to at most `limit` UTF-8 bytes, on a code-point boundary. */
function truncateUtf8(content: string, limit: number): string {
  const bytes = new TextEncoder().encode(content);
  if (bytes.length <= limit) return content;
  let end = limit;
  // UTF-8 continuation bytes are 0b10xxxxxx; back off until a lead byte.
  while (end > 0 && (bytes[end]! & 0xc0) === 0x80) {
    end -= 1;
  }
  return new TextDecoder().decode(bytes.subarray(0, end));
}

/**
 * Whether `word` occurs in `text` bounded by non-`[A-Za-z0-9_]` characters or
 * the text boundaries (core spec 3.12 step 4).
 */
function containsWord(text: string, word: string): boolean {
  if (word.length === 0) return false;
  const isWordChar = (ch: string | undefined): boolean =>
    ch != null && /[A-Za-z0-9_]/.test(ch);

  let start = 0;
  for (;;) {
    const at = text.indexOf(word, start);
    if (at < 0) return false;
    const end = at + word.length;
    const beforeOk = at === 0 || !isWordChar(text[at - 1]);
    const afterOk = end === text.length || !isWordChar(text[end]);
    if (beforeOk && afterOk) return true;
    start = at + 1;
  }
}

// ---------------------------------------------------------------------------
// Posture and origins
// ---------------------------------------------------------------------------

function resolvePosture(
  posture: CompiledPosture | undefined,
  matchedProfile: CompiledOriginProfile | undefined,
  context: PostureContext | undefined,
): PostureResult | undefined {
  if (posture == null) return undefined;

  const current = matchedProfile?.posture ?? context?.current ?? posture.initial;

  const rawSignal = context?.signal;
  const signal = rawSignal != null && rawSignal !== 'none' ? rawSignal : undefined;
  const next = signal != null
    ? nextPostureState(posture, current, signal) ?? current
    : current;

  return { current, next };
}

function nextPostureState(
  posture: CompiledPosture,
  current: string,
  signal: string,
): string | undefined {
  // D18 (pending): first matching transition in document order.
  for (const transition of posture.transitions) {
    if (transition.from !== '*' && transition.from !== current) continue;
    if (transition.on !== signal) continue;
    return transition.to;
  }
  return undefined;
}

/**
 * Origin profile selection (origins spec Section 3): candidates are profiles
 * with a `match` object every present field of which is satisfied; a
 * `space_id` match wins outright, then the greatest matched-field count, then
 * document order.
 */
function selectOriginProfile(
  origins: CompiledOrigins | undefined,
  origin: OriginContext | undefined,
): CompiledOriginProfile | undefined {
  if (origin == null || origins == null) return undefined;

  let bestCount = -1;
  let best: CompiledOriginProfile | undefined;
  for (const profile of origins.profiles) {
    const match = profile.match;
    if (match == null) continue;
    const matchedFields = matchOrigin(match, origin);
    if (matchedFields == null) continue;
    if (match.hasSpaceId) {
      return profile;
    }
    if (matchedFields > bestCount) {
      bestCount = matchedFields;
      best = profile;
    }
  }
  return best;
}

/**
 * Number of `match` fields satisfied by `origin`, or `undefined` when any
 * present field is not satisfied. `tags` counts as one field.
 */
function matchOrigin(match: CompiledOriginMatch, origin: OriginContext): number | undefined {
  let count = 0;
  for (const [expected, field] of match.strings) {
    if (origin[field] !== expected) return undefined;
    count += 1;
  }

  if (match.externalParticipants != null) {
    if (origin.external_participants !== match.externalParticipants) return undefined;
    count += 1;
  }

  if (match.tags != null) {
    const originTags = origin.tags ?? [];
    for (const tag of match.tags) {
      if (!originTags.includes(tag)) return undefined;
    }
    count += 1;
  }

  return count;
}

// ---------------------------------------------------------------------------
// Patch statistics
// ---------------------------------------------------------------------------

interface PatchStats {
  additions: number;
  deletions: number;
}

function patchStats(content: string): PatchStats {
  let additions = 0;
  let deletions = 0;

  for (const line of splitLines(content)) {
    if (line.startsWith('+++') || line.startsWith('---')) continue;
    if (line.startsWith('+')) {
      additions += 1;
    } else if (line.startsWith('-')) {
      deletions += 1;
    }
  }

  return { additions, deletions };
}

/**
 * Mirrors Rust's `str::lines`: split on `\n`, drop a trailing `\r`, and treat a
 * trailing newline as a terminator rather than producing a final empty line.
 */
function splitLines(content: string): string[] {
  if (content.length === 0) return [];
  const parts = content.split('\n');
  if (parts[parts.length - 1] === '') parts.pop();
  return parts.map((line) => (line.endsWith('\r') ? line.slice(0, -1) : line));
}
