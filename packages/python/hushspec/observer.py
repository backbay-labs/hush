from __future__ import annotations

import dataclasses
import enum
import json
import sys
import threading
import time
from abc import ABC, abstractmethod
from collections import deque
from datetime import datetime, timezone
from typing import Any, Optional, TextIO
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hushspec.receipt import DecisionReceipt, EnforcementSummary

from hushspec.evaluate import EvaluationAction, EvaluationResult
from hushspec.schema import HushSpec

#: How many recent durations :class:`MetricsCollector` keeps for its
#: percentile. A collector lives as long as the process, so the window is
#: bounded; the counters and the histogram it reports are exact regardless.
DURATION_WINDOW = 10_000

#: Upper bounds of the latency histogram, in microseconds. The last bucket is
#: ``+Inf``, which the exposition adds.
DURATION_BUCKETS_US: tuple[int, ...] = (10, 25, 50, 100, 250, 500, 1_000, 5_000, 10_000)


class _Histogram:
    """One action type's cumulative latency histogram."""

    __slots__ = ("buckets", "total", "count")

    def __init__(self) -> None:
        self.buckets = [0] * len(DURATION_BUCKETS_US)
        self.total = 0.0
        self.count = 0

    def record(self, duration_us: float) -> None:
        self.count += 1
        self.total += duration_us
        for index, bound in enumerate(DURATION_BUCKETS_US):
            if duration_us <= bound:
                self.buckets[index] += 1

    def copy(self) -> "_Histogram":
        clone = _Histogram()
        clone.buckets = list(self.buckets)
        clone.total = self.total
        clone.count = self.count
        return clone


def rule_block_of(matched_rule: Optional[str]) -> Optional[str]:
    """The rule block a ``matched_rule`` belongs to, for the metric label.

    ``rules.egress.default`` is ``egress``; ``extensions.posture.budgets`` is
    ``posture``; the bare ``detection`` the detection pipeline emits is
    ``detection``; a reserved ``__hushspec_x__`` id is ``hushspec_x``. ``None``
    for an evaluation no rule decided (a default allow).
    """
    if not matched_rule:
        return None
    if matched_rule.startswith("__"):
        return matched_rule.strip("_")
    for prefix in ("rules.", "extensions."):
        if matched_rule.startswith(prefix):
            return _first_segment(matched_rule[len(prefix):])
    return _first_segment(matched_rule)


def _first_segment(path: str) -> str:
    for index, character in enumerate(path):
        if character in ".[":
            return path[:index]
    return path


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _format_number(value: float) -> str:
    """A duration sum as Prometheus reads it: an integer when it is whole."""
    return str(int(value)) if value == int(value) else repr(value)


class EvaluationObserver(ABC):
    @abstractmethod
    def on_event(self, event: dict[str, Any]) -> None: ...


class JsonLineObserver(EvaluationObserver):

    def __init__(self, stream: TextIO = sys.stderr) -> None:
        self._stream = stream

    def on_event(self, event: dict[str, Any]) -> None:
        self._stream.write(json.dumps(event, default=_json_default) + "\n")


class ConsoleObserver(EvaluationObserver):

    def __init__(self, level: str = "all") -> None:
        self._level = level

    def on_event(self, event: dict[str, Any]) -> None:
        if self._level == "deny_only" and event.get("type") == "evaluation.completed":
            result = event.get("result")
            if result is not None and getattr(result, "decision", None) is not None:
                if result.decision.value != "deny":
                    return
            elif isinstance(result, dict) and result.get("decision") != "deny":
                return
        print(f"[hushspec] {event.get('type')} at {event.get('timestamp')}", event, file=sys.stderr)


class MetricsCollector(EvaluationObserver):
    """Counters and a latency histogram over the evaluation stream.

    Safe to attach to a guard that several threads evaluate through: every
    counter update is taken under a lock. The duration samples are a bounded
    window (:data:`DURATION_WINDOW`), so the collector does not grow for the
    life of the process; the average and the percentile it reports describe
    that window, while the counters and the histogram are exact.

    :meth:`to_prometheus` renders the series the observability specification
    names, so a dashboard or a recording rule works against any SDK unchanged:

    ==============================  =========  =========================
    Series                          Type       Labels
    ==============================  =========  =========================
    ``hushspec_evaluate_total``     counter    ``decision``, ``action_type``
    ``hushspec_evaluate_duration_us``  histogram  ``action_type``
    ``hushspec_rule_match_total``   counter    ``rule_block``, ``decision``
    ``hushspec_policy_load_total``  counter    ``status``
    ==============================  =========  =========================
    """

    def __init__(self, duration_window: int = DURATION_WINDOW) -> None:
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}
        self._evaluations: dict[tuple[str, str], int] = {}
        self._rule_matches: dict[tuple[str, str], int] = {}
        self._policy_loads: dict[str, int] = {}
        self._histograms: dict[str, _Histogram] = {}
        self._durations: deque[float] = deque(maxlen=duration_window)
        self._evaluation_count = 0

    def on_event(self, event: dict[str, Any]) -> None:
        event_type = event.get("type", "")
        with self._lock:
            self._counts[event_type] = self._counts.get(event_type, 0) + 1
            if event_type == "evaluation.completed":
                self._record_evaluation(event)
            elif event_type in ("policy.loaded", "policy.reloaded"):
                self._policy_loads["success"] = self._policy_loads.get("success", 0) + 1
            elif event_type == "policy.load_failed":
                self._policy_loads["failure"] = self._policy_loads.get("failure", 0) + 1

    def _record_evaluation(self, event: dict[str, Any]) -> None:
        """Count one decision and record its latency. Called under the lock."""
        result = event.get("result")
        decision = "unknown"
        matched_rule: Optional[str] = None
        if isinstance(result, dict):
            decision = str(result.get("decision", "unknown"))
            matched = result.get("matched_rule")
            matched_rule = None if matched is None else str(matched)
        elif result is not None:
            decision = _decision_name(result.decision)
            matched_rule = result.matched_rule

        action = event.get("action")
        if isinstance(action, dict):
            action_type = str(action.get("type", ""))
        elif action is not None:
            action_type = action.type
        else:
            action_type = ""

        key = f"evaluate.{decision}"
        self._counts[key] = self._counts.get(key, 0) + 1
        self._evaluations[(decision, action_type)] = (
            self._evaluations.get((decision, action_type), 0) + 1
        )

        rule_block = rule_block_of(matched_rule)
        if rule_block is not None:
            self._rule_matches[(rule_block, decision)] = (
                self._rule_matches.get((rule_block, decision), 0) + 1
            )

        duration_us = max(0.0, float(event.get("duration_us", 0) or 0))
        histogram = self._histograms.setdefault(action_type, _Histogram())
        histogram.record(duration_us)
        self._durations.append(duration_us)
        self._evaluation_count += 1

    def get_count(self, key: str) -> int:
        with self._lock:
            return self._counts.get(key, 0)

    def get_total_evaluations(self) -> int:
        with self._lock:
            return self._evaluation_count

    def get_average_duration_us(self) -> float:
        """Mean latency over the sample window, in microseconds."""
        with self._lock:
            durations = list(self._durations)
        if not durations:
            return 0.0
        return sum(durations) / len(durations)

    def get_p99_duration_us(self) -> float:
        """99th percentile latency over the sample window, in microseconds."""
        with self._lock:
            durations = sorted(self._durations)
        if not durations:
            return 0.0
        index = min(int(len(durations) * 0.99), len(durations) - 1)
        return durations[index]

    def to_prometheus(self) -> str:
        """Prometheus text exposition (version 0.0.4) of every series."""
        with self._lock:
            evaluations = dict(self._evaluations)
            rule_matches = dict(self._rule_matches)
            policy_loads = dict(self._policy_loads)
            histograms = {name: histogram.copy() for name, histogram in self._histograms.items()}

        lines = [
            "# HELP hushspec_evaluate_total Total HushSpec evaluations",
            "# TYPE hushspec_evaluate_total counter",
        ]
        for (decision, action_type), count in sorted(evaluations.items()):
            lines.append(
                f'hushspec_evaluate_total{{decision="{decision}",'
                f'action_type="{_escape_label(action_type)}"}} {count}'
            )

        lines.append("# HELP hushspec_evaluate_duration_us Evaluation duration in microseconds")
        lines.append("# TYPE hushspec_evaluate_duration_us histogram")
        for action_type, histogram in sorted(histograms.items()):
            label = _escape_label(action_type)
            for bound, count in zip(DURATION_BUCKETS_US, histogram.buckets):
                lines.append(
                    f'hushspec_evaluate_duration_us_bucket{{action_type="{label}",'
                    f'le="{bound}"}} {count}'
                )
            lines.append(
                f'hushspec_evaluate_duration_us_bucket{{action_type="{label}",'
                f'le="+Inf"}} {histogram.count}'
            )
            lines.append(
                f'hushspec_evaluate_duration_us_sum{{action_type="{label}"}} '
                f"{_format_number(histogram.total)}"
            )
            lines.append(
                f'hushspec_evaluate_duration_us_count{{action_type="{label}"}} {histogram.count}'
            )

        lines.append("# HELP hushspec_rule_match_total Rule block match counts")
        lines.append("# TYPE hushspec_rule_match_total counter")
        for (rule_block, decision), count in sorted(rule_matches.items()):
            lines.append(
                f'hushspec_rule_match_total{{rule_block="{_escape_label(rule_block)}",'
                f'decision="{decision}"}} {count}'
            )

        lines.append("# HELP hushspec_policy_load_total Policy load operations")
        lines.append("# TYPE hushspec_policy_load_total counter")
        for status, count in sorted(policy_loads.items()):
            lines.append(f'hushspec_policy_load_total{{status="{status}"}} {count}')

        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        with self._lock:
            self._counts.clear()
            self._evaluations.clear()
            self._rule_matches.clear()
            self._policy_loads.clear()
            self._histograms.clear()
            self._durations.clear()
            self._evaluation_count = 0


class ObservableEvaluator:
    """Evaluates a policy and announces the outcome to its observers."""

    def __init__(self, redact_content: bool = True) -> None:
        self._observers: list[EvaluationObserver] = []
        self._redact_content = redact_content

    def add_observer(self, observer: EvaluationObserver) -> None:
        self._observers.append(observer)

    def remove_observer(self, observer: EvaluationObserver) -> None:
        self._observers = [o for o in self._observers if o is not observer]

    def evaluate(self, spec: HushSpec, action: EvaluationAction) -> EvaluationResult:
        """Evaluate *action* against *spec* and emit ``evaluation.completed``.

        Routes through the detection pipeline, as every other evaluation
        surface does: for a policy carrying an ``extensions.detection`` block
        an escalated decision must not come back as an allow simply because
        the caller went through an observer (detection spec section 4).
        """
        from hushspec.detection import evaluate_with_detection

        start_ns = time.perf_counter_ns()
        result = evaluate_with_detection(spec, action).evaluation
        duration_us = (time.perf_counter_ns() - start_ns) // 1000
        self._emit({
            "type": "evaluation.completed",
            "timestamp": _iso_now(),
            "action": self._redact(action),
            "result": result,
            "duration_us": duration_us,
        })
        return result

    def notify_evaluation_completed(
        self,
        action: EvaluationAction,
        result: EvaluationResult,
        duration_us: int,
        enforcement: Optional["EnforcementSummary"] = None,
        receipt: Optional["DecisionReceipt"] = None,
    ) -> None:
        event: dict[str, Any] = {
            "type": "evaluation.completed",
            "timestamp": _iso_now(),
            "action": self._redact(action),
            "result": result,
            "duration_us": duration_us,
        }
        if enforcement is not None:
            event["enforcement"] = enforcement
        if receipt is not None:
            event["receipt"] = receipt
        self._emit(event)

    def _redact(self, action: EvaluationAction) -> EvaluationAction:
        """Return *action* with ``content`` stripped for observer emission.

        Evaluation itself (``evaluate()`` above) always runs against the real,
        unredacted action -- this only affects what gets embedded in observer
        events. A 0.2 receipt needs no such switch: it records the content's
        hash and size and has no field content could go in (receipt spec 4.4).
        """
        if self._redact_content and action.content is not None:
            return dataclasses.replace(action, content=None)
        return action

    def notify_policy_loaded(self, name: Optional[str] = None, hash: Optional[str] = None) -> None:
        """Announce the policy now in force. ``hash`` is its canonical content
        hash (``sha256:<hex>``), the same value its receipts carry."""
        self._emit({
            "type": "policy.loaded",
            "timestamp": _iso_now(),
            "policy_name": name,
            "content_hash": hash or "",
        })

    def notify_policy_load_failed(self, error: str, source: Optional[str] = None) -> None:
        self._emit({
            "type": "policy.load_failed",
            "timestamp": _iso_now(),
            "error": error,
            "source": source,
        })

    def notify_sink_error(self, error: str, source: Optional[str] = None) -> None:
        """Announce a receipt sink that refused what it was handed.

        The decision it belonged to stands: a sink is evidence, never
        enforcement. *source* names the sink that refused.
        """
        self._emit({
            "type": "sink.error",
            "timestamp": _iso_now(),
            "error": error,
            "source": source,
        })

    def notify_policy_reloaded(
        self,
        name: Optional[str] = None,
        hash: Optional[str] = None,
        previous_hash: Optional[str] = None,
    ) -> None:
        self._emit({
            "type": "policy.reloaded",
            "timestamp": _iso_now(),
            "policy_name": name,
            "content_hash": hash or "",
            "previous_hash": previous_hash,
        })

    def notify_error(self, error: str, source: Optional[str] = None) -> None:
        """Announce a failure the guard absorbed.

        Neither a policy load nor a sink: an observer that raised, say. The
        evaluation that produced the event stands -- an observer is a
        bystander, never enforcement.
        """
        self._emit({
            "type": "error",
            "timestamp": _iso_now(),
            "error": error,
            "source": source,
        })

    def _emit(self, event: dict[str, Any]) -> None:
        # Over a snapshot: an observer that registers another one while being
        # notified must not mutate the list this loop is walking.
        for observer in tuple(self._observers):
            try:
                observer.on_event(event)
            except Exception as exc:  # noqa: BLE001 - an observer is never fatal
                if event.get("type") == "error":
                    continue
                # The failure goes back to the observer that raised it: one
                # nobody is told about is the one that goes unnoticed. An
                # observer that raises reporting its own failure is dropped
                # rather than retried.
                try:
                    observer.on_event({
                        "type": "error",
                        "timestamp": _iso_now(),
                        "error": f"observer raised: {exc}",
                        "source": None,
                    })
                except Exception:  # noqa: BLE001
                    pass


def _decision_name(decision: Any) -> str:
    """A decision as the string a metric or a JSON line carries."""
    return decision.value if isinstance(decision, enum.Enum) else str(decision)


def _json_default(obj: Any) -> Any:
    from hushspec.receipt import DecisionReceipt, receipt_to_dict

    if isinstance(obj, DecisionReceipt):
        # Route through the shared helper (rather than a plain asdict) so a
        # receipt embedded in an observer event serializes identically to one
        # sent through a ReceiptSink: spec member order, enums as their string
        # values, and absent optional fields omitted rather than null.
        return receipt_to_dict(obj)
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if isinstance(obj, enum.Enum):
        return obj.value
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
