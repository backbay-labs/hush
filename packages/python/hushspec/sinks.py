"""Where receipts go.

A sink is the seam between an enforcement point and the evidence it produces:
:class:`FileReceiptSink` appends JSON Lines, :class:`~hushspec.log.ChainedFileSink`
appends a hash-linked log, and the rest compose them. Every sink also accepts a
policy-in-effect event (log spec section 6); only a log does anything with one.
"""

from __future__ import annotations

import json
import sys
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Callable

from hushspec.receipt import DecisionReceipt, receipt_to_dict

if TYPE_CHECKING:
    from hushspec.log import PolicyEvent


class ReceiptSink(ABC):
    @abstractmethod
    def send(self, receipt: DecisionReceipt) -> None: ...

    def record_policy_event(self, event: "PolicyEvent") -> None:
        """Record which policy came into force (log spec section 6).

        Sinks that carry only receipts ignore it; the hash-linked log writes it
        as an entry. Defaulted so every existing sink keeps working unchanged.
        """
        return None


class FileReceiptSink(ReceiptSink):

    def __init__(self, path: str) -> None:
        self._path = path

    def send(self, receipt: DecisionReceipt) -> None:
        line = json.dumps(receipt_to_dict(receipt), default=_json_default)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


class StderrReceiptSink(ReceiptSink):

    def send(self, receipt: DecisionReceipt) -> None:
        line = json.dumps(receipt_to_dict(receipt), indent=2, default=_json_default)
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

    def record_policy_event(self, event: "PolicyEvent") -> None:
        # A policy event is not a decision, so no decision filter applies to it:
        # a log that drops the policy-in-effect record cannot map its receipts
        # back to a policy at all.
        self._inner.record_policy_event(event)


class MultiSink(ReceiptSink):

    def __init__(self, sinks: list[ReceiptSink]) -> None:
        self._sinks = list(sinks)

    def send(self, receipt: DecisionReceipt) -> None:
        for sink in self._sinks:
            try:
                sink.send(receipt)
            except Exception:
                pass

    def record_policy_event(self, event: "PolicyEvent") -> None:
        for sink in self._sinks:
            try:
                sink.record_policy_event(event)
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
