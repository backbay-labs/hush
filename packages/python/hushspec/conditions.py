"""Conditional rules for HushSpec (core spec 3.13).

A :class:`Condition` gates whether a rule block is active. Conditions are
carried in the document as the ``when`` field of every rule block and are
evaluated against a :class:`RuntimeContext`.

Design principles:

* **Fail-closed toward enforcement.** A missing context field makes a context
  predicate false (the block is inert), but a condition the engine *cannot
  evaluate* -- an unresolvable timezone, an unparsable ``current_time``, a
  malformed ``HH:MM``, or nesting past the depth cap -- leaves the block
  ACTIVE, because an unevaluable condition must never switch a security
  control off.
* **Deterministic**: same context + condition = same result, always.
* **Not Turing-complete**: fixed predicate types composed with AND/OR/NOT.

This module deliberately does not import :mod:`hushspec.evaluate` at module
scope: ``evaluate`` imports the condition types, so the dependency runs one
way only. :func:`evaluate_with_context` defers its import to call time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta, tzinfo
from enum import Enum
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Optional, Sequence
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from hushspec.generated_contract import (
    CONDITION_KEYS,
    RATE_CONDITION_KEYS,
    TIME_WINDOW_KEYS,
)
from hushspec.schema import HushSpec

if TYPE_CHECKING:
    from hushspec.evaluate import EvaluationResult

#: Maximum allowed nesting depth for compound conditions (core spec 3.13).
MAX_NESTING_DEPTH = 8

#: Day abbreviations accepted in ``time_window.days``.
DAY_ABBREVIATIONS: tuple[str, ...] = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")

#: Field names accepted inside a per-case ``RuntimeContext``.
RUNTIME_CONTEXT_KEYS = frozenset(
    (
        "user",
        "environment",
        "deployment",
        "agent",
        "session",
        "request",
        "custom",
        "counters",
        "current_time",
    )
)


class RateComparison(str, Enum):
    """How a :class:`RateCondition` compares its counter with its threshold."""

    #: True when ``counter >= threshold``.
    GTE = "gte"
    #: True when ``counter < threshold``.
    LT = "lt"


@dataclass
class RateCondition:
    """An engine-supplied counter compared with a threshold (core spec 3.13).

    HushSpec never stores state: the engine owns the counter and its window
    and supplies the current value in :attr:`RuntimeContext.counters`; this is
    a pure comparison of the value supplied for one evaluation.
    """

    counter: str
    """Name of the counter in the runtime context's ``counters`` map."""

    threshold: int
    """Non-negative threshold the counter is compared against."""

    comparison: RateComparison
    """``gte``: ``counter >= threshold``; ``lt``: ``counter < threshold``."""

    @classmethod
    def from_dict(cls, data: Any) -> RateCondition:
        """Decode a ``when.rate`` mapping.

        Shape violations are *parse* errors (core spec 3.13, registry code
        E001), so every one of them raises rather than being collected as a
        constraint violation. The wording is part of the contract: a shared
        fixture's ``message_contains`` must hold in every SDK.
        """
        if not isinstance(data, dict):
            raise ValueError("when.rate: invalid type, expected an object")
        unknown = sorted(set(data) - RATE_CONDITION_KEYS)
        if unknown:
            raise ValueError(f"unknown field `{unknown[0]}` in when.rate")
        for required in ("counter", "threshold", "comparison"):
            if required not in data:
                raise ValueError(f"when.rate: missing field `{required}`")

        counter = data["counter"]
        if not isinstance(counter, str):
            raise ValueError(
                "when.rate.counter: invalid type, expected a string"
            )

        threshold = data["threshold"]
        # `bool` is an `int` subclass in Python but is never a threshold; a
        # boolean and a negative integer are both refused at parse time.
        if isinstance(threshold, bool) or not isinstance(threshold, int):
            raise ValueError(
                f"when.rate.threshold: invalid type: {threshold!r}, "
                "expected a non-negative integer"
            )
        if threshold < 0:
            raise ValueError(
                f"when.rate.threshold: invalid type: integer `{threshold}`, "
                "expected a non-negative integer"
            )

        comparison = data["comparison"]
        if (
            not isinstance(comparison, str)
            or comparison not in _RATE_COMPARISONS
        ):
            raise ValueError(
                f"when.rate.comparison: unknown variant `{comparison}`, "
                "expected `gte` or `lt`"
            )

        return cls(
            counter=counter,
            threshold=threshold,
            comparison=RateComparison(comparison),
        )

    def to_dict(self) -> dict:
        return {
            "counter": self.counter,
            "threshold": self.threshold,
            "comparison": self.comparison.value,
        }


_RATE_COMPARISONS = frozenset(item.value for item in RateComparison)


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

    @classmethod
    def from_dict(cls, data: dict) -> TimeWindowCondition:
        if not isinstance(data, dict):
            raise ValueError("time_window must be an object")
        unknown = sorted(set(data) - TIME_WINDOW_KEYS)
        if unknown:
            raise ValueError(f"unknown field `{unknown[0]}` in when.time_window")
        start = data.get("start")
        end = data.get("end")
        if not isinstance(start, str) or not isinstance(end, str):
            raise ValueError("time_window.start and time_window.end are required strings")
        tz = data.get("timezone")
        if tz is not None and not isinstance(tz, str):
            raise ValueError("time_window.timezone must be a string")
        days = data.get("days") or []
        if not isinstance(days, list) or not all(isinstance(day, str) for day in days):
            raise ValueError("time_window.days must be an array of strings")
        return cls(start=start, end=end, timezone=tz, days=list(days))

    def to_dict(self) -> dict:
        data: dict = {"start": self.start, "end": self.end}
        if self.timezone is not None:
            data["timezone"] = self.timezone
        if self.days:
            data["days"] = list(self.days)
        return data


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
    """The sub-condition must be false (NOT). Serialized as ``not``."""

    capability: Optional[str] = None
    """The effective posture state must grant this capability.

    Unevaluable -- and therefore held -- when the policy has no posture
    extension (core spec 3.13).
    """

    rate: Optional[RateCondition] = None
    """A runtime counter compared against a threshold.

    Unevaluable -- and therefore held -- when the context carries no such
    counter.
    """

    @classmethod
    def from_dict(cls, data: dict) -> Condition:
        """Decode a document ``when`` mapping, rejecting unknown keys.

        The generated models carry ``when`` as an opaque ``dict`` so that
        ``generated_models`` never has to import this module; this is the
        decoder both validation and evaluation run it through.
        """
        if not isinstance(data, dict):
            raise ValueError("when must be an object")
        unknown = sorted(set(data) - CONDITION_KEYS)
        if unknown:
            raise ValueError(f"unknown field `{unknown[0]}` in when")

        time_window = (
            TimeWindowCondition.from_dict(data["time_window"])
            if data.get("time_window") is not None
            else None
        )

        context = data.get("context")
        if context is not None and not isinstance(context, dict):
            raise ValueError("when.context must be an object")

        def _decode_list(key: str) -> Optional[list[Condition]]:
            value = data.get(key)
            if value is None:
                return None
            if not isinstance(value, list):
                raise ValueError(f"when.{key} must be an array")
            return [cls.from_dict(item) for item in value]

        capability = data.get("capability")
        if capability is not None and not isinstance(capability, str):
            raise ValueError("when.capability: invalid type, expected a string")

        rate_value = data.get("rate")
        rate = RateCondition.from_dict(rate_value) if rate_value is not None else None

        not_value = data.get("not")
        return cls(
            time_window=time_window,
            context=dict(context) if context is not None else None,
            all_of=_decode_list("all_of"),
            any_of=_decode_list("any_of"),
            not_=cls.from_dict(not_value) if not_value is not None else None,
            capability=capability,
            rate=rate,
        )

    def to_dict(self) -> dict:
        data: dict = {}
        if self.time_window is not None:
            data["time_window"] = self.time_window.to_dict()
        if self.context is not None:
            data["context"] = dict(self.context)
        if self.all_of is not None:
            data["all_of"] = [item.to_dict() for item in self.all_of]
        if self.any_of is not None:
            data["any_of"] = [item.to_dict() for item in self.any_of]
        if self.not_ is not None:
            data["not"] = self.not_.to_dict()
        if self.capability is not None:
            data["capability"] = self.capability
        if self.rate is not None:
            data["rate"] = self.rate.to_dict()
        return data


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

    counters: dict[str, int] = field(default_factory=dict)
    """Engine-maintained counters consulted by ``rate`` conditions.

    The engine owns the window (per session, per minute, per agent -- whatever
    it measures); HushSpec only compares (core spec 3.13).
    """

    current_time: Optional[str] = None
    """Current time override for testing (ISO 8601)."""

    @classmethod
    def from_dict(cls, data: dict) -> RuntimeContext:
        if not isinstance(data, dict):
            raise ValueError("context must be an object")
        unknown = sorted(set(data) - RUNTIME_CONTEXT_KEYS)
        if unknown:
            raise ValueError(f"unknown context field: {unknown[0]}")
        return cls(
            user=dict(data.get("user") or {}),
            environment=data.get("environment"),
            deployment=dict(data.get("deployment") or {}),
            agent=dict(data.get("agent") or {}),
            session=dict(data.get("session") or {}),
            request=dict(data.get("request") or {}),
            custom=dict(data.get("custom") or {}),
            counters=_coerce_counters(data.get("counters")),
            current_time=data.get("current_time"),
        )


def _counter_events(value: Any) -> Optional[int]:
    """*value* read as a counter, or ``None`` when it is not one.

    A counter is a non-negative whole number of events. A boolean, a string, a
    fraction, a negative and a non-finite float are none of those, so the
    ``rate`` predicate reading such a counter is unevaluable and holds, which
    leaves the rule block active (core spec 3.13) instead of switching a
    security control off on malformed input.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        whole = value
    elif isinstance(value, float) and value.is_integer():
        whole = int(value)
    else:
        return None
    return whole if whole >= 0 else None


def _coerce_counters(counters: Any) -> dict[str, int]:
    """The counters of an untyped ``counters`` mapping, malformed ones dropped."""
    if not isinstance(counters, dict):
        return {}
    coerced: dict[str, int] = {}
    for name, value in counters.items():
        whole = _counter_events(value)
        if whole is not None:
            coerced[name] = whole
    return coerced


def decode_condition(when: Any) -> Optional[Condition]:
    """Best-effort decode of a document ``when`` value for evaluation.

    Validation rejects malformed conditions at parse time; if one still
    reaches the evaluator it cannot be evaluated, and an unevaluable condition
    must leave the rule block active (core spec 3.13), so this returns
    ``None`` -- "no condition" -- rather than raising.
    """
    if when is None:
        return None
    if isinstance(when, Condition):
        return when
    try:
        return Condition.from_dict(when)
    except (ValueError, TypeError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Validation (core spec 3.13, 7.10)
# ---------------------------------------------------------------------------


def validate_condition(condition: Condition, path: str) -> list[str]:
    """Parse-time validation of a condition.

    Unknown keys are rejected by :meth:`Condition.from_dict`; this checks the
    ``HH:MM`` fields, the timezone, the day abbreviations, and the nesting
    depth. Returns one message per violation, each prefixed with *path* (for
    example ``rules.egress.when``).
    """
    errors: list[str] = []
    _validate_condition_depth(condition, path, 0, errors)
    return errors


def _validate_condition_depth(
    condition: Condition, path: str, depth: int, errors: list[str]
) -> None:
    if depth > MAX_NESTING_DEPTH:
        errors.append(
            f"{path}: conditions nest deeper than the maximum of "
            f"{MAX_NESTING_DEPTH} levels"
        )
        return

    tw = condition.time_window
    if tw is not None:
        for field_name, value in (("start", tw.start), ("end", tw.end)):
            if _parse_hhmm(value) is None:
                errors.append(
                    f"{path}.time_window.{field_name}: {value!r} is not a valid HH:MM time"
                )
        if tw.timezone is not None and not timezone_is_known(tw.timezone):
            errors.append(
                f"{path}.time_window.timezone: {tw.timezone!r} is neither an "
                "IANA time zone nor a fixed offset"
            )
        for day in tw.days:
            if not any(day.lower() == known for known in DAY_ABBREVIATIONS):
                errors.append(
                    f"{path}.time_window.days: {day!r} is not one of "
                    "mon, tue, wed, thu, fri, sat, sun"
                )

    if condition.capability is not None and not is_capability_identifier(
        condition.capability
    ):
        errors.append(
            f"{path}.capability: {condition.capability!r} is not a capability "
            "identifier (lowercase ASCII letters, digits and underscores in "
            "dot-separated segments that start with a letter)"
        )

    if condition.rate is not None and not is_capability_identifier(
        condition.rate.counter
    ):
        errors.append(
            f"{path}.rate.counter: {condition.rate.counter!r} is not a counter "
            "identifier (lowercase ASCII letters, digits and underscores in "
            "dot-separated segments that start with a letter)"
        )

    if condition.all_of is not None:
        for index, child in enumerate(condition.all_of):
            _validate_condition_depth(child, f"{path}.all_of[{index}]", depth + 1, errors)
    if condition.any_of is not None:
        for index, child in enumerate(condition.any_of):
            _validate_condition_depth(child, f"{path}.any_of[{index}]", depth + 1, errors)
    if condition.not_ is not None:
        _validate_condition_depth(condition.not_, f"{path}.not", depth + 1, errors)


def is_capability_identifier(name: str) -> bool:
    """The identifier grammar shared by capabilities and rate counters.

    Core spec 3.13: one or more dot-separated segments, each a lowercase ASCII
    letter followed by lowercase ASCII letters, digits, or underscores::

        identifier = segment *("." segment)
        segment    = %x61-7A *(%x61-7A / %x30-39 / "_")
    """
    if not isinstance(name, str) or not name:
        return False
    for segment in name.split("."):
        if not segment or not ("a" <= segment[0] <= "z"):
            return False
        for char in segment[1:]:
            if not ("a" <= char <= "z" or "0" <= char <= "9" or char == "_"):
                return False
    return True


def timezone_is_known(tz: str) -> bool:
    """Whether *tz* is an IANA identifier, a known alias, or a fixed offset."""
    return _resolve_timezone(tz) is not None


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate_condition(condition: Condition, context: RuntimeContext) -> bool:
    """Evaluate *condition* with no posture state known.

    A ``capability`` predicate is unevaluable through this entry point and
    therefore holds; an evaluator that has resolved the effective posture
    state calls :func:`evaluate_condition_with_capabilities` instead.
    """
    return _evaluate_condition_depth(condition, context, None, 0) is not _Verdict.FALSE


def evaluate_condition_with_capabilities(
    condition: Condition,
    context: RuntimeContext,
    capabilities: Optional[Sequence[str]],
) -> bool:
    """:func:`evaluate_condition` with the capabilities the effective posture
    state grants.

    *capabilities* is ``None`` when the policy has no posture extension -- a
    ``capability`` predicate is then unevaluable and holds -- and a (possibly
    empty) sequence otherwise, so an unknown state grants nothing and the
    predicate is false.
    """
    return _evaluate_condition_depth(condition, context, capabilities, 0) is not _Verdict.FALSE


class _Verdict(Enum):
    """What a condition evaluates to (core spec 3.13).

    ``UNEVALUABLE`` is a predicate the engine lacks the means to decide -- no
    posture extension, no such counter, a clock it cannot read -- and it
    never switches a block off: a block is inert only on an evaluated
    ``FALSE``.
    """

    TRUE = "true"
    FALSE = "false"
    UNEVALUABLE = "unevaluable"


def _verdict_of(value: bool) -> _Verdict:
    return _Verdict.TRUE if value else _Verdict.FALSE


def _negate(verdict: _Verdict) -> _Verdict:
    if verdict is _Verdict.UNEVALUABLE:
        return _Verdict.UNEVALUABLE
    return _Verdict.FALSE if verdict is _Verdict.TRUE else _Verdict.TRUE


def _conjoin(left: _Verdict, right: _Verdict) -> _Verdict:
    """AND: false wins, then unevaluable, then true."""
    if _Verdict.FALSE in (left, right):
        return _Verdict.FALSE
    if _Verdict.UNEVALUABLE in (left, right):
        return _Verdict.UNEVALUABLE
    return _Verdict.TRUE


def _disjoin(left: _Verdict, right: _Verdict) -> _Verdict:
    """OR: true wins, then unevaluable, then false."""
    if _Verdict.TRUE in (left, right):
        return _Verdict.TRUE
    if _Verdict.UNEVALUABLE in (left, right):
        return _Verdict.UNEVALUABLE
    return _Verdict.FALSE


def _evaluate_condition_depth(
    condition: Condition,
    context: RuntimeContext,
    capabilities: Optional[Sequence[str]],
    depth: int,
) -> _Verdict:
    if depth > MAX_NESTING_DEPTH:
        # Validation rejects this at parse time; an out-of-band condition that
        # exceeds the depth cannot be evaluated, and an unevaluable condition
        # must not switch a control off (core spec 3.13).
        return _Verdict.UNEVALUABLE

    # The fields of one condition object are ANDed. An evaluated false
    # settles the object, so later fields are not consulted.
    verdict = _Verdict.TRUE

    if condition.time_window is not None:
        verdict = _conjoin(verdict, _check_time_window(condition.time_window, context))
        if verdict is _Verdict.FALSE:
            return verdict

    if condition.context is not None:
        verdict = _conjoin(
            verdict, _verdict_of(_check_context_match(condition.context, context))
        )
        if verdict is _Verdict.FALSE:
            return verdict

    # `capability`: unevaluable without a posture extension; otherwise the
    # effective state must list the capability.
    if condition.capability is not None:
        verdict = _conjoin(
            verdict,
            _Verdict.UNEVALUABLE
            if capabilities is None
            else _verdict_of(condition.capability in capabilities),
        )
        if verdict is _Verdict.FALSE:
            return verdict

    # `rate`: unevaluable when the engine supplied no such counter.
    if condition.rate is not None:
        count = _counter_events(context.counters.get(condition.rate.counter))
        verdict = _conjoin(
            verdict,
            _Verdict.UNEVALUABLE
            if count is None
            else _verdict_of(_compare_rate(condition.rate, count)),
        )
        if verdict is _Verdict.FALSE:
            return verdict

    if condition.all_of is not None:
        combined = _Verdict.TRUE
        for member in condition.all_of:
            combined = _conjoin(
                combined,
                _evaluate_condition_depth(member, context, capabilities, depth + 1),
            )
        verdict = _conjoin(verdict, combined)
        if verdict is _Verdict.FALSE:
            return verdict

    if condition.any_of:
        combined = _Verdict.FALSE
        for member in condition.any_of:
            combined = _disjoin(
                combined,
                _evaluate_condition_depth(member, context, capabilities, depth + 1),
            )
        verdict = _conjoin(verdict, combined)
        if verdict is _Verdict.FALSE:
            return verdict

    if condition.not_ is not None:
        verdict = _conjoin(
            verdict,
            _negate(
                _evaluate_condition_depth(condition.not_, context, capabilities, depth + 1)
            ),
        )

    return verdict


def _compare_rate(rate: RateCondition, count: int) -> bool:
    if rate.comparison is RateComparison.GTE:
        return count >= rate.threshold
    return count < rate.threshold


def _check_time_window(tw: TimeWindowCondition, context: RuntimeContext) -> _Verdict:
    # A window the engine cannot evaluate -- unresolvable time zone,
    # unparsable current_time, or a malformed HH:MM that escaped validation --
    # is unevaluable and leaves the block active (core spec 3.13).
    now = _resolve_current_time(context, tw.timezone)
    if now is None:
        return _Verdict.UNEVALUABLE

    hour, minute, day_of_week = now

    start_parsed = _parse_hhmm(tw.start)
    if start_parsed is None:
        return _Verdict.UNEVALUABLE
    end_parsed = _parse_hhmm(tw.end)
    if end_parsed is None:
        return _Verdict.UNEVALUABLE

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
            return _Verdict.FALSE

    if start_minutes == end_minutes:
        return _Verdict.TRUE

    if start_minutes < end_minutes:
        return _verdict_of(start_minutes <= current_minutes < end_minutes)

    return _verdict_of(current_minutes >= start_minutes or current_minutes < end_minutes)


def _parse_hhmm(s: str) -> Optional[tuple[int, int]]:
    """A ``time_window`` bound: exactly two ASCII digits per component
    (``schemas/hushspec-core.v1.schema.json`` ``$defs.TimeWindow``).

    ``9:05``, ``09:5``, ``009:05`` and ``+9:00`` are all outside that shape, so
    they are not times: validation refuses them and an evaluator that meets one
    leaves the window unevaluable and the rule block active (core spec 3.13).
    """
    if not isinstance(s, str):
        return None
    parts = s.split(":")
    if len(parts) != 2:
        return None
    hour = _two_digit_field(parts[0])
    minute = _two_digit_field(parts[1])
    if hour is None or minute is None:
        return None
    if hour > 23 or minute > 59:
        return None
    return (hour, minute)


def _two_digit_field(s: str) -> Optional[int]:
    """Exactly two ASCII digits read as a number, or ``None``."""
    if len(s) != 2 or not all("0" <= ch <= "9" for ch in s):
        return None
    return int(s)


def _day_abbreviation(day: int) -> str:
    if 0 <= day < len(DAY_ABBREVIATIONS):
        return DAY_ABBREVIATIONS[day]
    return "mon"


def _resolve_current_time(
    context: RuntimeContext, tz: Optional[str]
) -> Optional[tuple[int, int, int]]:
    """Returns (hour, minute, day_of_week) where day_of_week is 0=Mon..6=Sun."""
    if context.current_time is not None:
        try:
            dt = datetime.fromisoformat(context.current_time.replace("Z", "+00:00"))
        except (ValueError, TypeError, AttributeError):
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
    "US/Eastern": -5 * 60,
    "EST": -5 * 60,
    "US/Central": -6 * 60,
    "CST": -6 * 60,
    "US/Mountain": -7 * 60,
    "MST": -7 * 60,
    "US/Pacific": -8 * 60,
    "PST": -8 * 60,
    "GB": 0,
    "CET": 60,
    "EET": 120,
    "Japan": 9 * 60,
    "JST": 9 * 60,
    "PRC": 8 * 60,
    "IST": 5 * 60 + 30,
}


@lru_cache(maxsize=256)
def _resolve_timezone(tz: str) -> Optional[tzinfo]:
    """The ``tzinfo`` for an IANA name or a fixed ``+HH:MM`` offset.

    Cached: this runs once per conditional rule block per action, and the
    names zoneinfo cannot resolve (fixed offsets, the short aliases below)
    each pay a tzpath walk and an exception before reaching the fallback.
    Both branches return immutable objects, so sharing one is safe.
    """
    if not isinstance(tz, str):
        return None
    try:
        return ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError, OSError):
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
    """Minutes for a fixed offset body, the part of a ``timezone`` after its
    sign: ``HH`` or ``HH:MM``, two ASCII digits per field (core spec 3.13).

    Anything else is not an offset. A zone that cannot be resolved leaves the
    rule block active, so tolerating a one-digit field, a missing colon,
    whitespace or non-ASCII digits here would resolve a zone another engine
    refuses and could switch a control off.
    """
    if ":" in s:
        hours_str, minutes_str = s.split(":", 1)
    else:
        hours_str = s
        minutes_str = "00"
    hours = _two_digit_field(hours_str)
    minutes = _two_digit_field(minutes_str)
    if hours is None or minutes is None:
        return None
    if hours > 23 or minutes > 59:
        return None
    return hours * 60 + minutes


# ---------------------------------------------------------------------------
# Context matching
# ---------------------------------------------------------------------------


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


def _values_equal(actual: Any, expected: Any) -> bool:
    """Leaf-level scalar equality for a ``when.context`` predicate.

    ``expected`` is always a non-array scalar (str/bool/int/float) here --
    array unwrapping happens one level up, in ``_matches_scalar_or_membership``.
    ``actual`` may be any JSON-ish value; it is compared structurally, never
    unwrapped further.
    """
    if isinstance(expected, str):
        return isinstance(actual, str) and actual == expected

    if isinstance(expected, bool):
        # A boolean is not numeric: it compares equal only to another
        # boolean, never to a number.
        return isinstance(actual, bool) and actual == expected

    if isinstance(expected, (int, float)):
        # Numbers compare by exact value with no tolerance, so 0.3 does not
        # match 0.30000000000000004, and by value alone: the integer 1 and the
        # float 1.0 are the same number whichever spelling either side used.
        if isinstance(actual, bool) or not isinstance(actual, (int, float)):
            return False
        return actual == expected

    return False


def _matches_scalar_or_membership(actual: Any, expected: Any) -> bool:
    """Scalar-or-membership comparison: if ``actual`` is an array, match iff
    any element equals ``expected``; otherwise compare the two scalars
    directly."""
    if isinstance(actual, list):
        return any(_values_equal(item, expected) for item in actual)
    return _values_equal(actual, expected)


def _match_value(actual: Any, expected: Any) -> bool:
    """Match a ``when.context`` value against the value the rule expects.

    Matching rules:
    - Missing context field (``actual is None``) -> fail-closed ``False``.
    - Scalar expected (str/bool/int/float) vs actual scalar or array -> match
      iff the actual scalar equals expected, or (when actual is an array) any
      element of actual equals expected (membership).
    - Array expected vs actual scalar or array -> match iff at least one
      expected element matches actual under the same scalar-or-membership
      rule; when actual is also an array, this is equivalent to a non-empty
      set intersection between expected and actual.
    - Anything else (object/null expected) -> ``False``.
    """
    if actual is None:
        return False

    if isinstance(expected, (str, bool, int, float)):
        return _matches_scalar_or_membership(actual, expected)

    if isinstance(expected, list):
        return any(_matches_scalar_or_membership(actual, candidate) for candidate in expected)

    return False


def evaluate_with_context(
    spec: HushSpec,
    action: Any,
    context: RuntimeContext,
    conditions: dict[str, Condition],
) -> "EvaluationResult":
    """Evaluate with an explicit runtime context and out-of-band conditions.

    The explicit *context* replaces ``action.context``; each entry in
    *conditions* is ANDed with its rule block's own ``when`` (core spec 3.13).
    """
    from hushspec.compiled import compiled_for_spec

    return compiled_for_spec(spec).evaluate_with_context(action, context, conditions)
