import type { HushSpec } from './schema.js';
import type { EvaluationAction, EvaluationResult } from './evaluate.js';
import { evaluate } from './evaluate.js';

const MAX_NESTING_DEPTH = 8;

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
    return false;
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
  const now = resolveCurrentTime(context, tw.timezone);
  if (now == null) {
    return false;
  }

  const [hour, minute, dayOfWeek] = now;

  const startParsed = parseHHMM(tw.start);
  const endParsed = parseHHMM(tw.end);
  if (startParsed == null || endParsed == null) {
    return false;
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
  const days = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];
  return days[day] ?? 'mon';
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
  const offsetMinutes = parseTimezoneOffsetMinutes(tz);
  if (offsetMinutes != null) {
    const adjusted = new Date(date.getTime() + offsetMinutes * 60_000);
    return utcDateParts(adjusted);
  }

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

    const dayOfWeek = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'].indexOf(weekday);
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

function parseTimezoneOffsetMinutes(tz: string): number | undefined {
  const normalized = tz.trim();
  if (['UTC', 'utc', 'Etc/UTC', 'Etc/GMT', 'GMT'].includes(normalized)) {
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

export function evaluateWithContext(
  spec: HushSpec,
  action: EvaluationAction,
  context: RuntimeContext,
  conditions: Record<string, Condition>,
): EvaluationResult {
  const effectiveSpec = applyConditions(spec, context, conditions);
  return evaluate(effectiveSpec, action);
}

function applyConditions(
  spec: HushSpec,
  context: RuntimeContext,
  conditions: Record<string, Condition>,
): HushSpec {
  if (!spec.rules) {
    return spec;
  }

  const effectiveRules = { ...spec.rules };
  let changed = false;

  for (const [blockName, condition] of Object.entries(conditions)) {
    if (!evaluateCondition(condition, context)) {
      const key = blockName as keyof typeof effectiveRules;
      if (key in effectiveRules && effectiveRules[key] != null) {
        (effectiveRules as Record<string, unknown>)[key] = undefined;
        changed = true;
      }
    }
  }

  if (!changed) {
    return spec;
  }

  return { ...spec, rules: effectiveRules };
}
