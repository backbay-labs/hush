from __future__ import annotations

import json
import sys
from abc import ABC, abstractmethod
from typing import Callable, Optional

from hushspec.receipt import DecisionReceipt, receipt_to_dict





class ReceiptSink(ABC):
    @abstractmethod
    def send(self, receipt: DecisionReceipt) -> None: ...





class FileReceiptSink(ReceiptSink):

    def __init__(self, path: str) -> None:
        self._path = path

    def send(self, receipt: DecisionReceipt) -> None:
        data = receipt_to_dict(receipt)
        if hasattr(data.get("decision"), "value"):
            data["decision"] = data["decision"].value
        line = json.dumps(data, default=_json_default)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


class StderrReceiptSink(ReceiptSink):

    def send(self, receipt: DecisionReceipt) -> None:
        data = receipt_to_dict(receipt)
        if hasattr(data.get("decision"), "value"):
            data["decision"] = data["decision"].value
        line = json.dumps(data, indent=2, default=_json_default)
        print(f"[hushspec] {line}", file=sys.stderr)


class FilteredSink(ReceiptSink):

    def __init__(self, inner: ReceiptSink, decisions: list[str]) -> None:
        self._inner = inner
        self._decisions = decisions

    @classmethod
    def deny_only(cls, sink: ReceiptSink) -> "FilteredSink":
        return cls(sink, ["deny"])

    def send(self, receipt: DecisionReceipt) -> None:
        decision_value = (
            receipt.decision.value
            if hasattr(receipt.decision, "value")
            else str(receipt.decision)
        )
        if decision_value in self._decisions:
            self._inner.send(receipt)


class MultiSink(ReceiptSink):

    def __init__(self, sinks: list[ReceiptSink]) -> None:
        self._sinks = list(sinks)

    def send(self, receipt: DecisionReceipt) -> None:
        for sink in self._sinks:
            try:
                sink.send(receipt)
            except Exception:
                pass


class CallbackSink(ReceiptSink):

    def __init__(self, callback: Callable[[DecisionReceipt], None]) -> None:
        self._callback = callback

    def send(self, receipt: DecisionReceipt) -> None:
        self._callback(receipt)


class NullSink(ReceiptSink):

    def send(self, receipt: DecisionReceipt) -> None:
        pass





def _json_default(obj: object) -> object:
    import enum

    if isinstance(obj, enum.Enum):
        return obj.value
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
