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

/** Multiple fields are ANDed; all present fields must evaluate to true. */
export interface Condition {
  time_window?: TimeWindowCondition;
  context?: Record<string, unknown>;
  all_of?: Condition[];
  any_of?: Condition[];
  not?: Condition;
}

export interface RuntimeContext {
  user?: Record<string, unknown>;
  environment?: string;
  deployment?: Record<string, unknown>;
  agent?: Record<string, unknown>;
  session?: Record<string, unknown>;
  request?: Record<string, unknown>;
  custom?: Record<string, unknown>;
  /** Override for testing (ISO 8601). */
  current_time?: string;
}

/** Missing context fields evaluate to false (fail-closed). */
export function evaluateCondition(
  condition: Condition,
  context: RuntimeContext,
): boolean {
  return evaluateConditionDepth(condition, context, 0);
}

function evaluateConditionDepth(
  condition: Condition,
  context: RuntimeContext,
  depth: number,
): boolean {
  if (depth > MAX_NESTING_DEPTH) {
    // Validation rejects this at parse time; an out-of-band condition that
    // exceeds the depth cannot be evaluated, and an unevaluable condition must
    // not switch a control off (core spec 3.13), so treat it as held.
    return true;
  }

  if (condition.time_window != null) {
    if (!checkTimeWindow(condition.time_window, context)) {
      return false;
    }
  }

  if (condition.context != null) {
    if (!checkContextMatch(condition.context, context)) {
      return false;
    }
  }

  if (condition.all_of != null) {
    if (
      !condition.all_of.every((c) =>
        evaluateConditionDepth(c, context, depth + 1),
      )
    ) {
      return false;
    }
  }

  if (condition.any_of != null && condition.any_of.length > 0) {
    if (
      !condition.any_of.some((c) =>
        evaluateConditionDepth(c, context, depth + 1),
      )
    ) {
      return false;
    }
  }

  if (condition.not != null) {
    if (evaluateConditionDepth(condition.not, context, depth + 1)) {
      return false;
    }
  }

  return true;
}

function checkTimeWindow(
  tw: TimeWindowCondition,
  context: RuntimeContext,
): boolean {
  // Fail closed toward enforcement (core spec 3.13): a window the engine
  // cannot evaluate -- unresolvable time zone, unparsable current_time, or a
  // malformed HH:MM that escaped validation -- leaves the block ACTIVE.
  const now = resolveCurrentTime(context, tw.timezone);
  if (now == null) {
    return true;
  }

  const [hour, minute, dayOfWeek] = now;

  const startParsed = parseHHMM(tw.start);
  if (startParsed == null) {
    return true;
  }
  const endParsed = parseHHMM(tw.end);
  if (endParsed == null) {
    return true;
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
      return false;
    }
  }

  if (startMinutes === endMinutes) {
    return true;
  }

  if (startMinutes < endMinutes) {
    return currentMinutes >= startMinutes && currentMinutes < endMinutes;
  } else {
    return currentMinutes >= startMinutes || currentMinutes < endMinutes;
  }
}

function parseHHMM(s: string): [number, number] | undefined {
  const parts = s.split(':');
  if (parts.length !== 2) return undefined;
  // Reject any token that is not purely digits (Rust parses each part as u8;
  // "09.9" / "09xx" must fail rather than truncate).
  if (!/^\d+$/.test(parts[0]) || !/^\d+$/.test(parts[1])) {
    return undefined;
  }
  const hour = parseInt(parts[0], 10);
  const minute = parseInt(parts[1], 10);
  if (isNaN(hour) || isNaN(minute) || hour > 23 || minute > 59 || hour < 0 || minute < 0) {
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
    // A zoneless ISO datetime (no trailing 'Z' or +/-HH:MM offset) is interpreted
    // as UTC to match Rust/Python/Go, not the host's local time.
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
  // Order mirrors Rust: the IANA database (chrono-tz there, Intl here) is
  // consulted before the fixed-offset table, so `US/Eastern` keeps its DST
  // rules rather than collapsing to a fixed -05:00.
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
 * Fixed-offset aliases accepted by the reference engine (Rust
 * `parse_timezone_offset`). Consulted only after the IANA database, so a name
 * the platform knows (e.g. `EST`, `CET`, `US/Eastern`) keeps its real rules.
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
    // Intl throws RangeError on an unknown time zone.
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
 * Typed scalar equality with no cross-type coercion -- mirrors Rust's
 * `values_equal` (crates/hushspec/src/conditions.rs). A number is never
 * equal to a boolean or a string even if JS's `==` would agree (`1 == true`),
 * because `===` (used below) already enforces matching types.
 */
function valuesEqual(actual: unknown, expected: unknown): boolean {
  if (typeof expected === 'string' || typeof expected === 'boolean' || typeof expected === 'number') {
    return actual === expected;
  }
  return false;
}

/**
 * Mirrors Rust's `matches_scalar_or_membership`: if `actual` is an array,
 * true iff any element equals `expected` (membership); otherwise a direct
 * scalar comparison.
 */
function matchesScalarOrMembership(actual: unknown, expected: unknown): boolean {
  if (Array.isArray(actual)) {
    return actual.some((item) => valuesEqual(item, expected));
  }
  return valuesEqual(actual, expected);
}

/**
 * Mirrors Rust's `match_value`. Missing/null context fields fail closed. A
 * scalar `expected` (string/bool/number) matches via
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
