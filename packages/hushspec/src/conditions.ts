/**
 * Conditional rules system for HushSpec (core spec 3.13).
 *
 * A `Condition` gates whether a rule block is active. Conditions are a
 * document field (`when`) on every rule block; the out-of-band map accepted by
 * `evaluateWithContext` is kept as an override that is ANDed with each block's
 * own `when`.
 *
 * Design principles:
 * - **Fail-closed toward enforcement**: a missing context field makes the
 *   condition false (the block goes inert), but a condition the engine cannot
 *   evaluate at all -- unresolvable time zone, unparsable `current_time`, a
 *   malformed `HH:MM` that escaped validation, or nesting past the depth cap --
 *   leaves the block ACTIVE.
 * - **Deterministic**: same context + condition = same result, always.
 * - **Not Turing-complete**: fixed predicate types composed with AND/OR/NOT.
 */

/** Maximum allowed nesting depth for compound conditions (core spec 3.13). */
export const MAX_NESTING_DEPTH = 8;

/** Day abbreviations accepted in `time_window.days`. */
export const DAY_ABBREVIATIONS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'] as const;

export interface TimeWindowCondition {
  start: string;
  end: string;
  timezone?: string;
  days?: string[];
}

/**
 * How a {@link RateCondition} compares its counter with its threshold.
 *
 * `gte`: true when `counter >= threshold`; `lt`: true when `counter < threshold`.
 */
export const RATE_COMPARISONS = ['gte', 'lt'] as const;

export type RateComparison = (typeof RATE_COMPARISONS)[number];

/**
 * A rate predicate: an engine-supplied counter compared with a threshold
 * (core spec 3.13).
 *
 * HushSpec never stores state and never increments anything; the engine owns
 * the counter and its window and supplies the current value in
 * {@link RuntimeContext.counters}.
 */
export interface RateCondition {
  /** Name of the counter in {@link RuntimeContext.counters}. */
  counter: string;
  /** Non-negative threshold the counter is compared against. */
  threshold: number;
  comparison: RateComparison;
}

/** Multiple fields are ANDed; all present fields must evaluate to true. */
export interface Condition {
  time_window?: TimeWindowCondition;
  context?: Record<string, unknown>;
  all_of?: Condition[];
  any_of?: Condition[];
  not?: Condition;
  /**
   * The effective posture state must grant this capability (core spec 3.13).
   * Unevaluable -- and therefore held -- when the policy has no posture
   * extension.
   */
  capability?: string;
  /**
   * A runtime counter compared against a threshold (core spec 3.13).
   * Unevaluable -- and therefore held -- when the context carries no such
   * counter.
   */
  rate?: RateCondition;
}

export interface RuntimeContext {
  user?: Record<string, unknown>;
  environment?: string;
  deployment?: Record<string, unknown>;
  agent?: Record<string, unknown>;
  session?: Record<string, unknown>;
  request?: Record<string, unknown>;
  custom?: Record<string, unknown>;
  /**
   * Engine-maintained counters consulted by `rate` conditions (core spec
   * 3.13). The engine owns the window; HushSpec only compares.
   */
  counters?: Record<string, number>;
  /** Override for testing (ISO 8601). */
  current_time?: string;
}

/**
 * Missing context fields evaluate to false (fail-closed).
 *
 * A `capability` predicate is unevaluable through this entry point (no
 * posture state is known) and therefore holds; use
 * {@link evaluateConditionWithCapabilities} from an evaluator that has
 * resolved the effective posture state.
 */
export function evaluateCondition(
  condition: Condition,
  context: RuntimeContext,
): boolean {
  return evaluateConditionDepth(condition, context, undefined, 0) !== 'false';
}

/**
 * The capabilities an effective posture state grants, as either a list (the
 * document spelling) or a set (what a compiled policy holds).
 */
export type GrantedCapabilities = ReadonlySet<string> | readonly string[];

/**
 * {@link evaluateCondition} with the capabilities the effective posture state
 * grants: `undefined` when the policy has no posture extension (a
 * `capability` predicate is then unevaluable and holds), a list otherwise (an
 * unknown state grants nothing, so the predicate is false).
 */
export function evaluateConditionWithCapabilities(
  condition: Condition,
  context: RuntimeContext,
  capabilities: GrantedCapabilities | undefined,
): boolean {
  return evaluateConditionDepth(condition, context, capabilities, 0) !== 'false';
}

/**
 * What a condition evaluates to (core spec 3.13). `unevaluable` is a
 * predicate the engine lacks the means to decide -- no posture extension, no
 * such counter, a clock it cannot read -- and it never switches a block off:
 * a block is inert only on an evaluated `false`.
 */
type Verdict = 'true' | 'false' | 'unevaluable';

function verdictOf(value: boolean): Verdict {
  return value ? 'true' : 'false';
}

function negate(verdict: Verdict): Verdict {
  if (verdict === 'unevaluable') return 'unevaluable';
  return verdict === 'true' ? 'false' : 'true';
}

/** AND: `false` wins, then `unevaluable`, then `true`. */
function conjoin(left: Verdict, right: Verdict): Verdict {
  if (left === 'false' || right === 'false') return 'false';
  if (left === 'unevaluable' || right === 'unevaluable') return 'unevaluable';
  return 'true';
}

/** OR: `true` wins, then `unevaluable`, then `false`. */
function disjoin(left: Verdict, right: Verdict): Verdict {
  if (left === 'true' || right === 'true') return 'true';
  if (left === 'unevaluable' || right === 'unevaluable') return 'unevaluable';
  return 'false';
}

function grants(capabilities: GrantedCapabilities, name: string): boolean {
  return Array.isArray(capabilities)
    ? capabilities.includes(name)
    : (capabilities as ReadonlySet<string>).has(name);
}

function evaluateConditionDepth(
  condition: Condition,
  context: RuntimeContext,
  capabilities: GrantedCapabilities | undefined,
  depth: number,
): Verdict {
  if (depth > MAX_NESTING_DEPTH) {
    // Validation rejects this at parse time; an out-of-band condition that
    // exceeds the depth cannot be evaluated, and an unevaluable condition must
    // not switch a control off (core spec 3.13).
    return 'unevaluable';
  }

  // The fields of one condition object are ANDed. An evaluated `false`
  // settles the object, so later fields are not consulted.
  let verdict: Verdict = 'true';

  if (condition.time_window != null) {
    verdict = conjoin(verdict, checkTimeWindow(condition.time_window, context));
    if (verdict === 'false') return verdict;
  }

  if (condition.context != null) {
    verdict = conjoin(verdict, verdictOf(checkContextMatch(condition.context, context)));
    if (verdict === 'false') return verdict;
  }

  // `capability`: unevaluable without a posture extension; otherwise the
  // effective state must list the capability.
  if (condition.capability != null) {
    verdict = conjoin(
      verdict,
      capabilities == null ? 'unevaluable' : verdictOf(grants(capabilities, condition.capability)),
    );
    if (verdict === 'false') return verdict;
  }

  // `rate`: unevaluable when the engine supplied no such counter.
  if (condition.rate != null) {
    const count = counterValue(context, condition.rate.counter);
    verdict = conjoin(
      verdict,
      count == null ? 'unevaluable' : verdictOf(rateHolds(condition.rate, count)),
    );
    if (verdict === 'false') return verdict;
  }

  if (condition.all_of != null) {
    let combined: Verdict = 'true';
    for (const member of condition.all_of) {
      combined = conjoin(combined, evaluateConditionDepth(member, context, capabilities, depth + 1));
    }
    verdict = conjoin(verdict, combined);
    if (verdict === 'false') return verdict;
  }

  if (condition.any_of != null && condition.any_of.length > 0) {
    let combined: Verdict = 'false';
    for (const member of condition.any_of) {
      combined = disjoin(combined, evaluateConditionDepth(member, context, capabilities, depth + 1));
    }
    verdict = conjoin(verdict, combined);
    if (verdict === 'false') return verdict;
  }

  if (condition.not != null) {
    verdict = conjoin(
      verdict,
      negate(evaluateConditionDepth(condition.not, context, capabilities, depth + 1)),
    );
  }

  return verdict;
}

/**
 * The counter the engine supplied under `name`, or `undefined` when it
 * supplied none. A value that is not a finite number is read as absent: the
 * predicate is then unevaluable and holds, which leaves the block active
 * (core spec 3.13) rather than switching a control off on malformed input.
 */
function counterValue(context: RuntimeContext, name: string): number | undefined {
  const counters = context.counters;
  if (counters == null || !Object.prototype.hasOwnProperty.call(counters, name)) {
    return undefined;
  }
  const value = counters[name];
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function rateHolds(rate: RateCondition, count: number): boolean {
  return rate.comparison === 'gte' ? count >= rate.threshold : count < rate.threshold;
}

function checkTimeWindow(
  tw: TimeWindowCondition,
  context: RuntimeContext,
): Verdict {
  // A window the engine cannot evaluate -- unresolvable time zone, unparsable
  // current_time, or a malformed HH:MM that escaped validation -- is
  // unevaluable and leaves the block active (core spec 3.13).
  const now = resolveCurrentTime(context, tw.timezone);
  if (now == null) {
    return 'unevaluable';
  }

  const [hour, minute, dayOfWeek] = now;

  const startParsed = parseHHMM(tw.start);
  if (startParsed == null) {
    return 'unevaluable';
  }
  const endParsed = parseHHMM(tw.end);
  if (endParsed == null) {
    return 'unevaluable';
  }

  const [startH, startM] = startParsed;
  const [endH, endM] = endParsed;

  const currentMinutes = hour * 60 + minute;
  const startMinutes = startH * 60 + startM;
  const endMinutes = endH * 60 + endM;
  const wrapsMidnight = startMinutes > endMinutes;

  if (tw.days != null && tw.days.length > 0) {
    const effectiveDay = wrapsMidnight && currentMinutes < endMinutes
      ? (dayOfWeek + 6) % 7
      : dayOfWeek;
    const dayAbbrev = dayAbbreviation(effectiveDay);
    if (
      !tw.days.some(
        (d) => d.toLowerCase() === dayAbbrev,
      )
    ) {
      return 'false';
    }
  }

  if (startMinutes === endMinutes) {
    return 'true';
  }

  if (startMinutes < endMinutes) {
    return verdictOf(currentMinutes >= startMinutes && currentMinutes < endMinutes);
  }
  return verdictOf(currentMinutes >= startMinutes || currentMinutes < endMinutes);
}

function parseHHMM(s: string): [number, number] | undefined {
  const parts = s.split(':');
  if (parts.length !== 2) return undefined;
  // Both halves must be purely digits: `09.9` and `09xx` are malformed times
  // rather than values to truncate to 9.
  if (!/^\d+$/.test(parts[0]) || !/^\d+$/.test(parts[1])) {
    return undefined;
  }
  const hour = parseInt(parts[0], 10);
  const minute = parseInt(parts[1], 10);
  if (hour > 23 || minute > 59) {
    return undefined;
  }
  return [hour, minute];
}

function dayAbbreviation(day: number): string {
  return DAY_ABBREVIATIONS[day] ?? 'mon';
}

/** Returns [hour, minute, dayOfWeek] where dayOfWeek is 0=Mon..6=Sun. */
function resolveCurrentTime(
  context: RuntimeContext,
  timezone?: string,
): [number, number, number] | undefined {
  let date: Date;

  if (context.current_time != null) {
    // A zoneless ISO datetime (no trailing 'Z' or +/-HH:MM offset) is read as
    // UTC rather than as the host's local time, so the same context evaluates
    // the same way wherever the engine runs.
    const raw = context.current_time;
    const hasTimezone = /(?:[zZ]|[+-]\d{2}:?\d{2})$/.test(raw);
    const normalized = !hasTimezone && raw.includes('T') ? `${raw}Z` : raw;
    date = new Date(normalized);
    if (isNaN(date.getTime())) {
      return undefined;
    }
  } else {
    date = new Date();
  }

  const tz = timezone ?? 'UTC';
  // The IANA database is consulted before the fixed-offset table, so
  // `US/Eastern` keeps its DST rules rather than collapsing to a fixed -05:00.
  const utcOffset = parseUtcOrNumericOffsetMinutes(tz);
  if (utcOffset != null) {
    const adjusted = new Date(date.getTime() + utcOffset * 60_000);
    return utcDateParts(adjusted);
  }

  const intlParts = resolveViaIntl(date, tz);
  if (intlParts != null) {
    return intlParts;
  }

  const aliasOffset = FIXED_OFFSET_ALIASES[tz];
  if (aliasOffset != null) {
    const adjusted = new Date(date.getTime() + aliasOffset * 60_000);
    return utcDateParts(adjusted);
  }

  return undefined;
}

function resolveViaIntl(date: Date, tz: string): [number, number, number] | undefined {
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      hour: '2-digit',
      minute: '2-digit',
      weekday: 'short',
      hourCycle: 'h23',
    }).formatToParts(date);

    const hour = parseInt(parts.find((part) => part.type === 'hour')?.value ?? '', 10);
    const minute = parseInt(parts.find((part) => part.type === 'minute')?.value ?? '', 10);
    const weekday = parts.find((part) => part.type === 'weekday')?.value.toLowerCase().slice(0, 3);
    if (Number.isNaN(hour) || Number.isNaN(minute) || weekday == null) {
      return undefined;
    }

    const dayOfWeek = (DAY_ABBREVIATIONS as readonly string[]).indexOf(weekday);
    if (dayOfWeek < 0) {
      return undefined;
    }

    return [hour, minute, dayOfWeek];
  } catch {
    return undefined;
  }
}

function utcDateParts(date: Date): [number, number, number] {
  const jsDay = date.getUTCDay();
  const dayOfWeek = jsDay === 0 ? 6 : jsDay - 1;
  return [date.getUTCHours(), date.getUTCMinutes(), dayOfWeek];
}

/**
 * Legacy zone names accepted as fixed offsets. Consulted only after the IANA
 * database, so a name the platform knows (`EST`, `CET`, `US/Eastern`) keeps
 * its real rules and only an unknown one falls back to the offset here.
 */
const FIXED_OFFSET_ALIASES: Record<string, number> = {
  'US/Eastern': -5 * 60,
  EST: -5 * 60,
  'US/Central': -6 * 60,
  CST: -6 * 60,
  'US/Mountain': -7 * 60,
  MST: -7 * 60,
  'US/Pacific': -8 * 60,
  PST: -8 * 60,
  GB: 0,
  CET: 60,
  EET: 120,
  Japan: 9 * 60,
  JST: 9 * 60,
  PRC: 8 * 60,
  IST: 5 * 60 + 30,
};

const UTC_ALIASES = new Set(['UTC', 'utc', 'Etc/UTC', 'Etc/GMT', 'GMT']);

function parseUtcOrNumericOffsetMinutes(tz: string): number | undefined {
  const normalized = tz.trim();
  if (UTC_ALIASES.has(normalized)) {
    return 0;
  }

  const match = normalized.match(/^([+-])(\d{1,2})(?::?(\d{2}))?$/);
  if (!match) {
    return undefined;
  }

  const hours = parseInt(match[2], 10);
  const minutes = parseInt(match[3] ?? '0', 10);
  if (Number.isNaN(hours) || Number.isNaN(minutes) || hours > 23 || minutes > 59) {
    return undefined;
  }

  const totalMinutes = hours * 60 + minutes;
  return match[1] === '-' ? -totalMinutes : totalMinutes;
}

/**
 * Whether `tz` is an identifier this engine can resolve: an IANA zone, a
 * known fixed-offset alias, or a numeric `+HH:MM` / `-HH:MM` offset.
 */
export function timezoneIsKnown(tz: string): boolean {
  if (parseUtcOrNumericOffsetMinutes(tz) != null) return true;
  if (Object.prototype.hasOwnProperty.call(FIXED_OFFSET_ALIASES, tz)) return true;
  try {
    // `Intl` throws RangeError on an unknown time zone.
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

function checkContextMatch(
  expected: Record<string, unknown>,
  context: RuntimeContext,
): boolean {
  for (const [key, expectedValue] of Object.entries(expected)) {
    const actual = resolveContextValue(key, context);
    if (!matchValue(actual, expectedValue)) {
      return false;
    }
  }
  return true;
}

function resolveContextValue(
  path: string,
  context: RuntimeContext,
): unknown {
  const dotIdx = path.indexOf('.');
  const topLevel = dotIdx >= 0 ? path.slice(0, dotIdx) : path;
  const rest = dotIdx >= 0 ? path.slice(dotIdx + 1) : undefined;

  switch (topLevel) {
    case 'environment':
      return context.environment;
    case 'user':
      return rest != null ? context.user?.[rest] : context.user;
    case 'deployment':
      return rest != null ? context.deployment?.[rest] : context.deployment;
    case 'agent':
      return rest != null ? context.agent?.[rest] : context.agent;
    case 'session':
      return rest != null ? context.session?.[rest] : context.session;
    case 'request':
      return rest != null ? context.request?.[rest] : context.request;
    case 'custom':
      return rest != null ? context.custom?.[rest] : context.custom;
    default:
      return undefined;
  }
}

/**
 * Typed scalar equality with no cross-type coercion (core spec 3.13): a number
 * is never equal to a boolean or a string even where JavaScript's `==` would
 * agree (`1 == true`), because `===` already enforces matching types.
 */
function valuesEqual(actual: unknown, expected: unknown): boolean {
  if (typeof expected === 'string' || typeof expected === 'boolean' || typeof expected === 'number') {
    return actual === expected;
  }
  return false;
}

/**
 * If `actual` is an array, true when any element equals `expected`
 * (membership); otherwise a direct scalar comparison.
 */
function matchesScalarOrMembership(actual: unknown, expected: unknown): boolean {
  if (Array.isArray(actual)) {
    return actual.some((item) => valuesEqual(item, expected));
  }
  return valuesEqual(actual, expected);
}

/**
 * One `context` predicate (core spec 3.13). Missing or null context fields
 * fail closed. A scalar `expected` (string/bool/number) matches via
 * `matchesScalarOrMembership`, which covers both scalar-vs-scalar equality
 * and scalar-vs-array membership (in either direction: a number/bool/string
 * `expected` matches an `actual` array containing it, and vice versa). An
 * array `expected` matches iff `actual` equals or contains at least one of
 * its elements -- checking every candidate via `matchesScalarOrMembership`
 * against `actual` also covers array-vs-array as a set intersection (true
 * iff any expected element is present in the actual array).
 */
function matchValue(actual: unknown, expected: unknown): boolean {
  if (actual == null) {
    return false;
  }

  if (typeof expected === 'string' || typeof expected === 'boolean' || typeof expected === 'number') {
    return matchesScalarOrMembership(actual, expected);
  }

  if (Array.isArray(expected)) {
    return expected.some((candidate) => matchesScalarOrMembership(actual, candidate));
  }

  return false;
}

/**
 * Parse-time validation of one condition (core spec 3.13). Unknown keys are
 * rejected by the document validator; this checks the `HH:MM` fields, the
 * timezone, the day abbreviations, and the nesting depth. Returns one message
 * per violation, each prefixed with `path` (for example `rules.egress.when`).
 */
export function validateCondition(condition: Condition, path: string): string[] {
  const errors: string[] = [];
  validateConditionDepth(condition, path, 0, errors);
  return errors;
}

function validateConditionDepth(
  condition: Condition,
  path: string,
  depth: number,
  errors: string[],
): void {
  if (depth > MAX_NESTING_DEPTH) {
    errors.push(
      `${path}: conditions nest deeper than the maximum of ${MAX_NESTING_DEPTH} levels`,
    );
    return;
  }

  const tw = condition.time_window;
  if (tw != null && typeof tw === 'object') {
    for (const field of ['start', 'end'] as const) {
      const value = tw[field];
      if (typeof value !== 'string' || parseHHMM(value) == null) {
        errors.push(
          `${path}.time_window.${field}: ${debugQuote(value)} is not a valid HH:MM time`,
        );
      }
    }
    if (tw.timezone != null) {
      if (typeof tw.timezone !== 'string' || !timezoneIsKnown(tw.timezone)) {
        errors.push(
          `${path}.time_window.timezone: ${debugQuote(tw.timezone)} is neither an IANA time zone nor a fixed offset`,
        );
      }
    }
    if (Array.isArray(tw.days)) {
      for (const day of tw.days) {
        const known = typeof day === 'string'
          && (DAY_ABBREVIATIONS as readonly string[]).includes(day.toLowerCase());
        if (!known) {
          errors.push(
            `${path}.time_window.days: ${debugQuote(day)} is not one of mon, tue, wed, thu, fri, sat, sun`,
          );
        }
      }
    }
  }

  if (condition.capability != null && !isCapabilityIdentifier(condition.capability)) {
    errors.push(
      `${path}.capability: ${debugQuote(condition.capability)} is not a capability identifier (lowercase ASCII letters, digits and underscores in dot-separated segments that start with a letter)`,
    );
  }

  const rate = condition.rate;
  if (rate != null && typeof rate === 'object' && !isCapabilityIdentifier(rate.counter)) {
    errors.push(
      `${path}.rate.counter: ${debugQuote(rate.counter)} is not a counter identifier (lowercase ASCII letters, digits and underscores in dot-separated segments that start with a letter)`,
    );
  }

  if (Array.isArray(condition.all_of)) {
    condition.all_of.forEach((child, index) => {
      validateConditionDepth(child, `${path}.all_of[${index}]`, depth + 1, errors);
    });
  }
  if (Array.isArray(condition.any_of)) {
    condition.any_of.forEach((child, index) => {
      validateConditionDepth(child, `${path}.any_of[${index}]`, depth + 1, errors);
    });
  }
  if (condition.not != null) {
    validateConditionDepth(condition.not, `${path}.not`, depth + 1, errors);
  }
}

function debugQuote(value: unknown): string {
  return typeof value === 'string' ? JSON.stringify(value) : String(value);
}

/**
 * The identifier grammar shared by posture capabilities and rate counters
 * (core spec 3.13): one or more dot-separated segments, each a lowercase
 * ASCII letter followed by lowercase letters, digits or underscores.
 *
 * ```abnf
 * identifier = segment *("." segment)
 * segment    = %x61-7A *(%x61-7A / %x30-39 / "_")
 * ```
 */
export function isCapabilityIdentifier(name: unknown): boolean {
  return typeof name === 'string'
    && name.length > 0
    && name.split('.').every(segment => /^[a-z][a-z0-9_]*$/.test(segment));
}

/**
 * Rule blocks that may carry a `when` condition, in core spec Section 5 order.
 */
export const CONDITION_RULE_BLOCKS = [
  'forbidden_paths',
  'path_allowlist',
  'egress',
  'secret_patterns',
  'patch_integrity',
  'shell_commands',
  'tool_access',
  'computer_use',
  'remote_desktop_channels',
  'input_injection',
  'browser_automation',
  'code_execution',
] as const;

/**
 * Validate every rule block's `when` condition (core spec 3.13, 7.10).
 * Returns one message per violation, each prefixed with the rule path.
 */
export function validateConditions(rules: RulesWithConditions): string[] {
  const errors: string[] = [];
  for (const name of CONDITION_RULE_BLOCKS) {
    const when = rules[name]?.when;
    if (when != null) {
      errors.push(...validateCondition(when, `rules.${name}.when`));
    }
  }
  return errors;
}

type RulesWithConditions = {
  [K in (typeof CONDITION_RULE_BLOCKS)[number]]?: { when?: Condition };
};
