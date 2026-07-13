from __future__ import annotations

import json
import sys
import time
from abc import ABC, abstractmethod
from typing import Any, Optional, TextIO
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hushspec.receipt import DecisionReceipt, EnforcementSummary

from hushspec.evaluate import EvaluationAction, EvaluationResult, evaluate
from hushspec.schema import HushSpec





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

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._durations: list[float] = []

    def on_event(self, event: dict[str, Any]) -> None:
        event_type = event.get("type", "")

        if event_type == "evaluation.completed":
            result = event.get("result")
            if result is not None:
                if isinstance(result, dict):
                    decision = result.get("decision", "unknown")
                else:
                    decision = result.decision.value if hasattr(result.decision, "value") else str(result.decision)
                key = f"evaluate.{decision}"
                self._counts[key] = self._counts.get(key, 0) + 1
            duration_us = event.get("duration_us", 0)
            self._durations.append(duration_us)

        self._counts[event_type] = self._counts.get(event_type, 0) + 1

    def get_count(self, key: str) -> int:
        return self._counts.get(key, 0)

    def get_total_evaluations(self) -> int:
        return len(self._durations)

    def get_average_duration_us(self) -> float:
        if not self._durations:
            return 0.0
        return sum(self._durations) / len(self._durations)

    def get_p99_duration_us(self) -> float:
        if not self._durations:
            return 0.0
        sorted_durations = sorted(self._durations)
        index = int(len(sorted_durations) * 0.99)
        if index >= len(sorted_durations):
            index = len(sorted_durations) - 1
        return sorted_durations[index]

    def to_prometheus(self) -> str:
        lines: list[str] = []
        for key, value in self._counts.items():
            lines.append(f"hushspec_{key.replace('.', '_')}_total {value}")
        if self._durations:
            lines.append(f"hushspec_evaluate_duration_us_avg {self.get_average_duration_us()}")
            lines.append(f"hushspec_evaluate_duration_us_p99 {self.get_p99_duration_us()}")
        return "\n".join(lines)

    def reset(self) -> None:
        self._counts.clear()
        self._durations.clear()





class ObservableEvaluator:

    def __init__(self) -> None:
        self._observers: list[EvaluationObserver] = []

    def add_observer(self, observer: EvaluationObserver) -> None:
        self._observers.append(observer)

    def remove_observer(self, observer: EvaluationObserver) -> None:
        self._observers = [o for o in self._observers if o is not observer]

    def evaluate(self, spec: HushSpec, action: EvaluationAction) -> EvaluationResult:
        start_ns = time.perf_counter_ns()
        result = evaluate(spec, action)
        duration_us = (time.perf_counter_ns() - start_ns) // 1000
        self._emit({
            "type": "evaluation.completed",
            "timestamp": _iso_now(),
            "action": action,
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
            "action": action,
            "result": result,
            "duration_us": duration_us,
        }
        if enforcement is not None:
            event["enforcement"] = enforcement
        if receipt is not None:
            event["receipt"] = receipt
        self._emit(event)

    def notify_policy_loaded(self, name: Optional[str] = None, hash: Optional[str] = None) -> None:
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

    def _emit(self, event: dict[str, Any]) -> None:
        for observer in self._observers:
            try:
                observer.on_event(event)
            except Exception:
                pass





def _json_default(obj: Any) -> Any:
    import dataclasses
    import enum
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if isinstance(obj, enum.Enum):
        return obj.value
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
