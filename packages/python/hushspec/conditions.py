from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta, tzinfo
from typing import Any, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from hushspec.evaluate import EvaluationAction, EvaluationResult, evaluate
from hushspec.schema import HushSpec

MAX_NESTING_DEPTH = 8





@dataclass
class TimeWindowCondition:
    """Time window during which a rule block is active."""

    start: str
    """Start time in HH:MM (24-hour) format."""

    end: str
    """End time in HH:MM (24-hour) format."""

    timezone: Optional[str] = None
    """IANA timezone identifier. Defaults to 'UTC'."""

    days: list[str] = field(default_factory=list)
    """Day abbreviations: mon, tue, wed, thu, fri, sat, sun."""


@dataclass
class Condition:
    """A condition that gates whether a rule block is active.

    Multiple fields on a single Condition are combined with AND semantics:
    all present fields must evaluate to True.
    """

    time_window: Optional[TimeWindowCondition] = None
    """Time window during which the rule block is active."""

    context: Optional[dict[str, Any]] = None
    """Context key-value pairs that must match the runtime context."""

    all_of: Optional[list[Condition]] = None
    """All sub-conditions must be true (AND)."""

    any_of: Optional[list[Condition]] = None
    """At least one sub-condition must be true (OR)."""

    not_: Optional[Condition] = None
    """The sub-condition must be false (NOT)."""


@dataclass
class RuntimeContext:
    """Runtime context provided by the enforcement engine at evaluation time."""

    user: dict[str, Any] = field(default_factory=dict)
    """User attributes (id, role, tier, groups, department, etc.)."""

    environment: Optional[str] = None
    """Deployment environment label (e.g., 'production', 'staging')."""

    deployment: dict[str, Any] = field(default_factory=dict)
    """Deployment metadata (region, cluster, cloud_provider)."""

    agent: dict[str, Any] = field(default_factory=dict)
    """Agent metadata (id, type, model, capabilities, version)."""

    session: dict[str, Any] = field(default_factory=dict)
    """Session metadata (id, started_at, action_count, duration_seconds)."""

    request: dict[str, Any] = field(default_factory=dict)
    """Request metadata (id, timestamp)."""

    custom: dict[str, Any] = field(default_factory=dict)
    """Engine-specific custom fields."""

    current_time: Optional[str] = None
    """Current time override for testing (ISO 8601)."""





def evaluate_condition(condition: Condition, context: RuntimeContext) -> bool:
    return _evaluate_condition_depth(condition, context, 0)


def _evaluate_condition_depth(
    condition: Condition, context: RuntimeContext, depth: int
) -> bool:
    if depth > MAX_NESTING_DEPTH:
        return False

    if condition.time_window is not None:
        if not _check_time_window(condition.time_window, context):
            return False

    if condition.context is not None:
        if not _check_context_match(condition.context, context):
            return False

    if condition.all_of is not None:
        if not all(
            _evaluate_condition_depth(c, context, depth + 1) for c in condition.all_of
        ):
            return False

    if condition.any_of:
        if not any(
            _evaluate_condition_depth(c, context, depth + 1) for c in condition.any_of
        ):
            return False

    if condition.not_ is not None:
        if _evaluate_condition_depth(condition.not_, context, depth + 1):
            return False

    return True





def _check_time_window(tw: TimeWindowCondition, context: RuntimeContext) -> bool:
    now = _resolve_current_time(context, tw.timezone)
    if now is None:
        return False

    hour, minute, day_of_week = now

    start_parsed = _parse_hhmm(tw.start)
    end_parsed = _parse_hhmm(tw.end)
    if start_parsed is None or end_parsed is None:
        return False

    start_h, start_m = start_parsed
    end_h, end_m = end_parsed
    current_minutes = hour * 60 + minute
    start_minutes = start_h * 60 + start_m
    end_minutes = end_h * 60 + end_m
    wraps_midnight = start_minutes > end_minutes

    if tw.days:
        effective_day = (
            (day_of_week + 6) % 7
            if wraps_midnight and current_minutes < end_minutes
            else day_of_week
        )
        day_abbrev = _day_abbreviation(effective_day)
        if not any(d.lower() == day_abbrev for d in tw.days):
            return False

    if start_minutes == end_minutes:
        return True

    if start_minutes < end_minutes:
        return start_minutes <= current_minutes < end_minutes

    return current_minutes >= start_minutes or current_minutes < end_minutes


def _parse_hhmm(s: str) -> Optional[tuple[int, int]]:
    parts = s.split(":")
    if len(parts) != 2:
        return None
    hour = _parse_strict_uint(parts[0])
    minute = _parse_strict_uint(parts[1])
    if hour is None or minute is None:
        return None
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        return None
    return (hour, minute)


def _parse_strict_uint(s: str) -> Optional[int]:
    """Parse *s* as a base-10 non-negative integer of pure ASCII digits.

    Unlike ``int()``, this rejects underscores, surrounding whitespace, and
    any other characters ``int()`` tolerates (e.g. ``"1_2"``, ``"  9 "``),
    matching Rust's and Go's strict numeric-string parsing
    (``str::parse::<u8>`` / ``strconv.Atoi``).
    """
    if s == "" or not all("0" <= ch <= "9" for ch in s):
        return None
    return int(s)


def _day_abbreviation(day: int) -> str:
    days = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
    if 0 <= day < len(days):
        return days[day]
    return "mon"


def _resolve_current_time(
    context: RuntimeContext, tz: Optional[str]
) -> Optional[tuple[int, int, int]]:
    """Returns (hour, minute, day_of_week) where day_of_week is 0=Mon..6=Sun."""
    if context.current_time is not None:
        try:
            dt = datetime.fromisoformat(context.current_time.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
    else:
        dt = datetime.now(timezone.utc)

    tz_name = tz or "UTC"
    resolved_timezone = _resolve_timezone(tz_name)
    if resolved_timezone is None:
        return None
    adjusted = dt.astimezone(resolved_timezone)

    hour = adjusted.hour
    minute = adjusted.minute
    day_of_week = adjusted.weekday()

    return (hour, minute, day_of_week)


_FIXED_TIMEZONE_OFFSETS: dict[str, int] = {
    "UTC": 0,
    "utc": 0,
    "Etc/UTC": 0,
    "Etc/GMT": 0,
    "GMT": 0,
    "EST": -5 * 60,
    "CST": -6 * 60,
    "MST": -7 * 60,
    "PST": -8 * 60,
    "GB": 0,
    "CET": 60,
    "EET": 120,
    "Japan": 9 * 60,
    "JST": 9 * 60,
    "PRC": 8 * 60,
    "IST": 5 * 60 + 30,
}


def _resolve_timezone(tz: str) -> Optional[tzinfo]:
    try:
        return ZoneInfo(tz)
    except ZoneInfoNotFoundError:
        pass

    if tz in _FIXED_TIMEZONE_OFFSETS:
        return timezone(timedelta(minutes=_FIXED_TIMEZONE_OFFSETS[tz]))

    if tz.startswith("+"):
        offset_minutes = _parse_offset_value(tz[1:])
        if offset_minutes is None:
            return None
        return timezone(timedelta(minutes=offset_minutes))
    if tz.startswith("-"):
        offset_minutes = _parse_offset_value(tz[1:])
        if offset_minutes is None:
            return None
        return timezone(timedelta(minutes=-offset_minutes))

    return None


def _parse_offset_value(s: str) -> Optional[int]:
    if ":" in s:
        hours_str, minutes_str = s.split(":", 1)
    else:
        hours_str = s
        minutes_str = "0"
    try:
        hours = int(hours_str)
        minutes = int(minutes_str)
    except ValueError:
        return None
    if hours < 0 or hours > 23 or minutes < 0 or minutes > 59:
        return None
    return hours * 60 + minutes





def _check_context_match(
    expected: dict[str, Any], context: RuntimeContext
) -> bool:
    for key, expected_value in expected.items():
        actual = _resolve_context_value(key, context)
        if not _match_value(actual, expected_value):
            return False
    return True


def _resolve_context_value(path: str, context: RuntimeContext) -> Any:
    parts = path.split(".", 1)
    top_level = parts[0]
    rest = parts[1] if len(parts) > 1 else None

    if top_level == "environment":
        return context.environment
    elif top_level == "user":
        return context.user.get(rest) if rest is not None else context.user
    elif top_level == "deployment":
        return context.deployment.get(rest) if rest is not None else context.deployment
    elif top_level == "agent":
        return context.agent.get(rest) if rest is not None else context.agent
    elif top_level == "session":
        return context.session.get(rest) if rest is not None else context.session
    elif top_level == "request":
        return context.request.get(rest) if rest is not None else context.request
    elif top_level == "custom":
        return context.custom.get(rest) if rest is not None else context.custom
    else:
        return None


def _match_value(actual: Any, expected: Any) -> bool:
    if actual is None:
        return False

    if isinstance(expected, str):
        if isinstance(actual, str):
            return actual == expected
        if isinstance(actual, list):
            return expected in actual
        return False

    if isinstance(expected, bool):
        return actual is expected

    if isinstance(expected, (int, float)):
        if isinstance(actual, bool):
            # bool is a subclass of int in Python, but a boolean actual
            # must never spuriously match a numeric expected (e.g.
            # `user.is_admin: 1` must not match actual `True`), matching
            # Rust/TS/Go where booleans and numbers are distinct types.
            return False
        if isinstance(actual, (int, float)):
            return actual == expected
        return False

    if isinstance(expected, list):
        if isinstance(actual, str):
            return actual in expected
        return False

    return False


def evaluate_with_context(
    spec: HushSpec,
    action: EvaluationAction,
    context: RuntimeContext,
    conditions: dict[str, Condition],
) -> EvaluationResult:
    effective_spec = _apply_conditions(spec, context, conditions)
    return evaluate(effective_spec, action)


def _apply_conditions(
    spec: HushSpec,
    context: RuntimeContext,
    conditions: dict[str, Condition],
) -> HushSpec:
    if spec.rules is None:
        return spec

    effective = copy.copy(spec)
    effective.rules = copy.copy(spec.rules)

    for block_name, condition in conditions.items():
        if not evaluate_condition(condition, context):
            if hasattr(effective.rules, block_name):
                setattr(effective.rules, block_name, None)

    return effective
