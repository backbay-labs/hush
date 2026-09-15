/**
 * Reference evaluator for HushSpec 0.2 (core spec Sections 3, 5, and 6).
 *
 * Evaluation of one action is:
 * 1. extension guards (panic, origins `default_behavior`, posture capability),
 * 2. every applicable rule block for the action type -- present, `enabled`,
 *    and with a satisfied `when` condition -- evaluated in the order of the
 *    Section 5 table, never short-circuiting on an allow,
 * 3. aggregation: deny beats warn beats allow; `matched_rule`/`reason` come
 *    from the first block in evaluation order whose decision equals the
 *    aggregate and which named a rule.
 *
 * Unknown action types deny (`__unknown_action_type__`). Hosts and paths are
 * normalized as specified in Section 3.14 before any pattern is consulted.
 *
 * The engine itself lives in `compiled.ts`: a policy is compiled once --
 * regexes, globs, host patterns, tool sets, `when` conditions and block
 * applicability -- and evaluated through a {@link CompiledPolicy}. The
 * functions here are the document-in, decision-out form of that engine; they
 * compile the document on first use and reuse the compilation for as long as
 * the caller holds the document object. Hold a `CompiledPolicy` (or a
 * `HushGuard`) directly when evaluating the same policy repeatedly.
 *
 * This file is a port of `crates/hushspec/src/evaluate.rs`, which is the
 * normative reference implementation; keep the two in lockstep.
 */
import type { HushSpec } from './schema.js';
import type { Condition, RuntimeContext } from './conditions.js';
import { parseOrThrow } from './parse.js';
import { compiledFor } from './compiled.js';

/** `matched_rule` reported when the action type is unknown to the specification. */
export const UNKNOWN_ACTION_TYPE_RULE = '__unknown_action_type__';
/** `matched_rule` reported when the emergency panic protocol is active. */
export const PANIC_RULE = '__hushspec_panic__';

export type Decision = 'allow' | 'warn' | 'deny';

export interface EvaluationAction {
  type: string;
  target?: string;
  content?: string;
  origin?: OriginContext;
  posture?: PostureContext;
  args_size?: number;
  /** `browser_action`: navigation destination (core spec 3.11). */
  url?: string;
  /** `code_exec`: whether the call requests network access (core spec 3.12). */
  network?: boolean;
  /** `code_exec`: requested execution time in milliseconds (core spec 3.12). */
  timeout_ms?: number;
  /**
   * Runtime context consulted by `when` conditions (core spec 3.13). When
   * absent, conditions see an empty context and the engine clock.
   */
  context?: RuntimeContext;
  /** Set on the redacted copy emitted to observers when content is stripped. */
  content_redacted?: boolean;
}

export interface OriginContext {
  provider?: string;
  tenant_id?: string;
  space_id?: string;
  space_type?: string;
  visibility?: string;
  external_participants?: boolean;
  tags?: string[];
  sensitivity?: string;
  actor_role?: string;
}

export interface PostureContext {
  current?: string;
  signal?: string;
}

export interface EvaluationResult {
  decision: Decision;
  matched_rule?: string;
  reason?: string;
  origin_profile?: string;
  posture?: PostureResult;
}

export interface PostureResult {
  current: string;
  next: string;
}

export type RuleOutcome = 'allow' | 'warn' | 'deny' | 'skip';

/**
 * One recorded rule-block consultation. Produced by the evaluator itself, in
 * evaluation order, so receipts reflect exactly what ran.
 */
export interface RuleEvaluation {
  rule_block: string;
  outcome: RuleOutcome;
  matched_rule?: string;
  reason?: string;
  evaluated: boolean;
}

/** An evaluation result together with its recorded rule trace. */
export interface TracedEvaluation {
  result: EvaluationResult;
  trace: RuleEvaluation[];
}

/**
 * Evaluate `action` against a resolved document.
 *
 * `when` conditions are evaluated against `action.context` (an empty context
 * and the engine clock when absent).
 *
 * The document is compiled on first use and the compilation is cached against
 * the document object, so repeated calls with the same object pay for the
 * policy's patterns once. The cache is keyed by object identity: a document
 * mutated in place after it has been evaluated keeps its first compilation, so
 * build a new document (or a new {@link CompiledPolicy}) to change a policy.
 */
export function evaluate(spec: HushSpec, action: EvaluationAction): EvaluationResult {
  return compiledFor(spec).evaluate(action);
}

/**
 * Like {@link evaluate} with an explicit runtime context and an out-of-band map
 * of conditions keyed by rule-block name. The explicit `context` replaces
 * `action.context`; out-of-band conditions are ANDed with each block's own
 * `when` (core spec 3.13).
 */
export function evaluateWithContext(
  spec: HushSpec,
  action: EvaluationAction,
  context: RuntimeContext,
  conditions: Record<string, Condition>,
): EvaluationResult {
  return compiledFor(spec).evaluateWithContext(action, context, conditions);
}

/** Full evaluation with the recorded rule trace (used by receipts). */
export function evaluateTraced(
  spec: HushSpec,
  action: EvaluationAction,
  context?: RuntimeContext,
  conditions: Record<string, Condition> = {},
): TracedEvaluation {
  return compiledFor(spec).evaluateTraced(action, context, conditions);
}

/**
 * Built-in credential detectors consulted by `browser_automation` when
 * `credential_detection` is true (core spec 3.11). Documents needing portable
 * detection list their own patterns in `extra_credential_patterns`.
 */
export const BUILTIN_CREDENTIAL_PATTERNS: ReadonlyArray<readonly [string, string]> = [
  ['aws_access_key', '(AKIA|ASIA)[0-9A-Z]{16}'],
  ['github_token', 'gh[opsur]_[A-Za-z0-9]{36}'],
  ['github_fine_grained_pat', 'github_pat_[0-9a-zA-Z_]{50,}'],
  ['openai_key', 'sk-[A-Za-z0-9_-]{20,}'],
  ['slack_token', 'xox[baprs]-[0-9A-Za-z-]{10,}'],
  ['private_key', '-----BEGIN[ \\t]+(RSA[ \\t]+|EC[ \\t]+|OPENSSH[ \\t]+)?PRIVATE[ \\t]+KEY-----'],
  ['jwt', 'eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}'],
];

// ---------------------------------------------------------------------------
// Path globs (core spec 3.14.1)
// ---------------------------------------------------------------------------

/**
 * Normalize a filesystem path for matching: NFC, `\` to `/`, collapsed
 * separators, lexical `.`/`..` resolution, no trailing `/`.
 */
export function normalizePath(target: string): string {
  const unified = target.normalize('NFC').replace(/\\/g, '/');
  const absolute = unified.startsWith('/');
  const segments: string[] = [];
  for (const segment of unified.split('/')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      const last = segments[segments.length - 1];
      if (last != null && last !== '..') {
        segments.pop();
      } else if (!absolute) {
        segments.push('..');
      }
      continue;
    }
    segments.push(segment);
  }
  const joined = segments.join('/');
  return absolute ? `/${joined}` : joined;
}

/** Escape one character for use as a literal in a `u`-flagged RegExp source. */
function regexEscape(ch: string): string {
  return /[.*+?^${}()|[\]\\/]/.test(ch) ? `\\${ch}` : ch;
}

/**
 * Compiled-pattern caches. Bounded so a process that hot-reloads many distinct
 * policies cannot accumulate compiled patterns without limit; on overflow the
 * cache is cleared rather than grown.
 */
const MAX_COMPILED_PATTERN_CACHE = 4096;

function cachePut<K, V>(cache: Map<K, V>, key: K, value: V): V {
  if (cache.size >= MAX_COMPILED_PATTERN_CACHE) {
    cache.clear();
  }
  cache.set(key, value);
  return value;
}

const pathGlobCache = new Map<string, RegExp | undefined>();

/**
 * Compile a path glob (core spec 3.14.1) into an anchored regex, or
 * `undefined` when the glob has no regular expression (it then matches
 * nothing).
 *
 * Compiled policies call this once per pattern at compile time; the cache
 * serves the per-call `pathGlobMatches` form and repeated compilations of the
 * same pattern across policies.
 */
export function compilePathGlob(pattern: string): RegExp | undefined {
  const cached = pathGlobCache.get(pattern);
  if (cached !== undefined || pathGlobCache.has(pattern)) return cached;

  const chars = Array.from(pattern.normalize('NFC'));
  let source = '^';
  let index = 0;
  while (index < chars.length) {
    const ch = chars[index];
    if (ch === '*' && chars[index + 1] === '*') {
      const atSegmentStart = index === 0 || chars[index - 1] === '/';
      if (atSegmentStart && chars[index + 2] === '/') {
        // `**/`: zero or more complete leading segments.
        source += '(?:[^/]*/)*';
        index += 3;
      } else {
        // The reference engine's `.` excludes only `\n`; JavaScript's `.`
        // additionally excludes `\r`, U+2028 and U+2029, so spell it out.
        source += '[^\\n]*';
        index += 2;
      }
      continue;
    }
    if (ch === '*') {
      source += '[^/]*';
    } else if (ch === '?') {
      source += '[^/]';
    } else {
      source += regexEscape(ch);
    }
    index += 1;
  }
  source += '$';

  let compiled: RegExp | undefined;
  try {
    compiled = new RegExp(source, 'u');
  } catch {
    compiled = undefined;
  }
  return cachePut(pathGlobCache, pattern, compiled);
}

/** Whether `path` (already normalized) matches the path glob `pattern`. */
export function pathGlobMatches(pattern: string, path: string): boolean {
  const regex = compilePathGlob(pattern);
  return regex != null && regex.test(path);
}

/**
 * Match a raw path target against a path glob, normalizing the target first.
 * Kept for callers outside the evaluator; prefer {@link pathGlobMatches} with
 * an already-normalized path.
 */
export function globMatches(pattern: string, target: string): boolean {
  return pathGlobMatches(pattern, normalizePath(target));
}

// ---------------------------------------------------------------------------
// Host patterns (core spec 3.14.2)
// ---------------------------------------------------------------------------

function isAscii(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) > 127) return false;
  }
  return true;
}

function asciiLowercase(value: string): string {
  let out = '';
  for (const ch of value) {
    const code = ch.charCodeAt(0);
    out += code >= 65 && code <= 90 && ch.length === 1 ? String.fromCharCode(code + 32) : ch;
  }
  return out;
}

/**
 * Reduce an egress target (host, `host:port`, or URL) to a normalized host.
 * Returns `undefined` when the target cannot be reduced to a syntactically
 * valid host, in which case it matches nothing.
 */
export function normalizeHost(target: string): string | undefined {
  const trimmed = target.trim();
  const schemeIndex = trimmed.indexOf('://');
  let authority = schemeIndex >= 0 ? trimmed.slice(schemeIndex + 3) : trimmed;
  const end = firstIndexOfAny(authority, ['/', '?', '#']);
  authority = end >= 0 ? authority.slice(0, end) : authority;
  const at = authority.lastIndexOf('@');
  if (at >= 0) {
    authority = authority.slice(at + 1);
  }
  if (authority.length === 0) return undefined;

  if (authority.startsWith('[')) {
    const rest = authority.slice(1);
    const close = rest.indexOf(']');
    if (close < 0) return undefined;
    const inner = rest.slice(0, close);
    if (inner.length === 0 || !/^[0-9A-Fa-f:.]+$/.test(inner)) return undefined;
    return `[${asciiLowercase(inner)}]`;
  }

  let host = authority;
  const colon = host.lastIndexOf(':');
  if (colon >= 0) {
    const port = host.slice(colon + 1);
    if (port.length > 0 && /^[0-9]+$/.test(port)) {
      host = host.slice(0, colon);
    }
  }
  if (host.includes(':')) return undefined;
  if (host.endsWith('.')) {
    host = host.slice(0, -1);
  }
  if (host.length === 0) return undefined;

  const labels: string[] = [];
  for (const label of host.split('.')) {
    if (label.length === 0) return undefined;
    const normalized = normalizeHostLabel(label);
    if (normalized == null) return undefined;
    labels.push(normalized);
  }
  const normalized = labels.join('.');
  if (!/^[A-Za-z0-9\-._]*$/.test(normalized)) return undefined;
  return normalized;
}

function firstIndexOfAny(value: string, needles: string[]): number {
  let best = -1;
  for (const needle of needles) {
    const index = value.indexOf(needle);
    if (index >= 0 && (best < 0 || index < best)) best = index;
  }
  return best;
}

/**
 * Normalize one host label: ASCII lowercase, or the IDNA A-label (punycode)
 * of the NFC-normalized, lowercased label when it is not ASCII.
 */
function normalizeHostLabel(label: string): string | undefined {
  if (isAscii(label)) {
    return asciiLowercase(label);
  }
  const folded = label.toLowerCase().normalize('NFC');
  if (isAscii(folded)) {
    return folded;
  }
  const encoded = punycodeEncode(folded);
  return encoded != null ? `xn--${encoded}` : undefined;
}

/** Normalize a host pattern (steps 5-7 of core spec 3.14.2), preserving `*`. */
function normalizeHostPattern(pattern: string): string {
  let normalized = pattern.trim();
  if (normalized.endsWith('.')) {
    normalized = normalized.slice(0, -1);
  }
  if (normalized.startsWith('[')) {
    return asciiLowercase(normalized);
  }
  return normalized
    .split('.')
    .map(label => (isAscii(label)
      ? asciiLowercase(label)
      : normalizeHostLabel(label) ?? label.toLowerCase()))
    .join('.');
}

function isIpv4Literal(host: string): boolean {
  const octets = host.split('.');
  return octets.length === 4
    && octets.every(octet =>
      octet.length > 0
      && octet.length <= 3
      && /^[0-9]+$/.test(octet)
      && Number(octet) <= 255);
}

function isIpLiteral(host: string): boolean {
  return host.startsWith('[') || isIpv4Literal(host);
}

/**
 * A host pattern normalized (core spec 3.14.2 steps 5-7) and compiled once.
 *
 * `normalized` is what an IP literal is compared against -- IP literals match
 * only exactly -- and `regex` is the wildcard matcher for every other host.
 */
export interface CompiledHostPattern {
  normalized: string;
  regex?: RegExp;
}

const hostPatternCache = new Map<string, CompiledHostPattern>();

/**
 * Normalize and compile a host pattern (core spec 3.14.2): `*` is one or more
 * non-dot characters, `**` one or more characters including dots, everything
 * else literal.
 *
 * Compiled policies call this once per pattern, so a per-action match costs a
 * single regex test rather than re-normalizing the pattern every time.
 */
export function compileHostPattern(pattern: string): CompiledHostPattern {
  const cached = hostPatternCache.get(pattern);
  if (cached !== undefined) return cached;

  const normalized = normalizeHostPattern(pattern);
  let source = '^';
  const chars = Array.from(normalized);
  let index = 0;
  while (index < chars.length) {
    if (chars[index] === '*') {
      if (chars[index + 1] === '*') {
        // Reference `.` excludes only `\n`; spell it out for JS parity.
        source += '[^\\n]+';
        index += 2;
      } else {
        source += '[^.]+';
        index += 1;
      }
      continue;
    }
    source += regexEscape(chars[index]);
    index += 1;
  }
  source += '$';

  let regex: RegExp | undefined;
  try {
    regex = new RegExp(source, 'u');
  } catch {
    regex = undefined;
  }
  return cachePut(hostPatternCache, pattern, { normalized, ...(regex === undefined ? {} : { regex }) });
}

/** Whether a normalized host matches an already-compiled host pattern. */
export function hostMatcherMatches(pattern: CompiledHostPattern, host: string): boolean {
  if (isIpLiteral(host)) {
    return pattern.normalized === host;
  }
  return pattern.regex != null && pattern.regex.test(host);
}

/**
 * Whether a normalized host matches a host pattern (core spec 3.14.2): `*` is
 * one or more non-dot characters, `**` one or more characters including dots,
 * everything else literal. IP literals match only exactly.
 */
export function hostPatternMatches(pattern: string, host: string): boolean {
  return hostMatcherMatches(compileHostPattern(pattern), host);
}

/** RFC 3492 punycode encoding of one label (without the `xn--` prefix). */
export function punycodeEncode(input: string): string | undefined {
  const BASE = 36;
  const TMIN = 1;
  const TMAX = 26;
  const SKEW = 38;
  const DAMP = 700;
  const INITIAL_BIAS = 72;
  const INITIAL_N = 128;
  const MAX_U32 = 0xffffffff;

  const adapt = (delta: number, numPoints: number, firstTime: boolean): number => {
    let d = Math.floor(firstTime ? delta / DAMP : delta / 2);
    d += Math.floor(d / numPoints);
    let k = 0;
    while (d > Math.floor(((BASE - TMIN) * TMAX) / 2)) {
      d = Math.floor(d / (BASE - TMIN));
      k += BASE;
    }
    return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
  };

  const digit = (value: number): string =>
    value < 26
      ? String.fromCharCode(0x61 + value)
      : String.fromCharCode(0x30 + (value - 26));

  const codePoints = Array.from(input).map(ch => ch.codePointAt(0) as number);
  const output: string[] = [];
  for (const cp of codePoints) {
    if (cp < 128) output.push(String.fromCharCode(cp));
  }
  const basicCount = output.length;
  let handled = basicCount;
  if (basicCount > 0) {
    output.push('-');
  }

  let n = INITIAL_N;
  let delta = 0;
  let bias = INITIAL_BIAS;
  while (handled < codePoints.length) {
    let m = Number.POSITIVE_INFINITY;
    for (const cp of codePoints) {
      if (cp >= n && cp < m) m = cp;
    }
    if (!Number.isFinite(m)) return undefined;
    delta += (m - n) * (handled + 1);
    if (delta > MAX_U32) return undefined;
    n = m;
    for (const cp of codePoints) {
      if (cp < n) {
        delta += 1;
        if (delta > MAX_U32) return undefined;
      }
      if (cp === n) {
        let q = delta;
        let k = BASE;
        for (;;) {
          const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
          if (q < t) break;
          output.push(digit(t + ((q - t) % (BASE - t))));
          q = Math.floor((q - t) / (BASE - t));
          k += BASE;
        }
        output.push(digit(q));
        bias = adapt(delta, handled + 1, handled === basicCount);
        delta = 0;
        handled += 1;
      }
    }
    delta += 1;
    n += 1;
    if (delta > MAX_U32 || n > MAX_U32) return undefined;
  }

  return output.join('');
}

// ---------------------------------------------------------------------------
// Panic protocol
// ---------------------------------------------------------------------------

let panicActive = false;
const PANIC_POLICY_YAML = `hushspec: "0.2.0"
name: "__hushspec_panic__"
description: "Emergency deny-all policy. Activated by panic mode."

rules:
  forbidden_paths:
    enabled: true
    patterns:
      - "**"
    exceptions: []

  egress:
    enabled: true
    allow: []
    block:
      - "*"
    default: block

  shell_commands:
    enabled: true
    forbidden_patterns:
      - ".*"

  tool_access:
    enabled: true
    allow: []
    block:
      - "*"
    require_confirmation: []
    default: block

  computer_use:
    enabled: true
    mode: fail_closed
    allowed_actions: []

  input_injection:
    enabled: true
    allowed_types: []
`;

export function activatePanic(): void {
  panicActive = true;
}

export function deactivatePanic(): void {
  panicActive = false;
}

export function isPanicActive(): boolean {
  return panicActive;
}

export function panicPolicy(): HushSpec {
  return parseOrThrow(PANIC_POLICY_YAML);
}
