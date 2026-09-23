"""Where receipts go.

A sink is the seam between an enforcement point and the evidence it produces:
:class:`FileReceiptSink` appends JSON Lines, :class:`~hushspec.log.ChainedFileSink`
appends a hash-linked log, and the rest compose them. Every sink also accepts a
policy-in-effect event (log spec section 6); only a log does anything with one.
"""

from __future__ import annotations

import enum
import json
import sys
import threading
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import TYPE_CHECKING, Callable, Optional

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
    """Appends each receipt to a file as one JSON line.

    The file is opened per receipt, so nothing is buffered across calls and a
    crash loses only a receipt that was mid-write. Writes are serialized on an
    instance lock: ``O_APPEND`` alone is atomic for a small record on a local
    filesystem, but not for one larger than the buffer size, and not on NFS.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()

    def send(self, receipt: DecisionReceipt) -> None:
        line = json.dumps(receipt_to_dict(receipt), default=_json_default)
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line + "\n")


class StderrReceiptSink(ReceiptSink):

    def send(self, receipt: DecisionReceipt) -> None:
        line = json.dumps(receipt_to_dict(receipt), indent=2, default=_json_default)
        print(f"[hushspec] {line}", file=sys.stderr)


class FilteredSink(ReceiptSink):
    """Passes on only the receipts whose decision is in *decisions*."""

    def __init__(self, inner: ReceiptSink, decisions: Iterable[str]) -> None:
        if isinstance(decisions, (str, bytes)) or not isinstance(
            decisions, Iterable
        ):
            raise TypeError(
                "FilteredSink(decisions=...) takes a collection of decision "
                'names, e.g. ["deny", "warn"]; see FilteredSink.deny_only'
            )
        self._inner = inner
        self._decisions = frozenset(
            value.value if isinstance(value, enum.Enum) else str(value)
            for value in decisions
        )

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
    """Fans a receipt out to several sinks.

    Every sink is attempted whatever the ones before it did -- one destination
    refusing a receipt must not cost the others theirs -- and the first failure
    is then raised, naming the sink that refused, so a guard reports it as a
    ``sink.error`` observer event instead of losing the evidence quietly.
    Each failure is also counted in :attr:`dropped` and passed to *on_error*,
    which sees every sink that refused rather than only the first.
    """

    def __init__(
        self,
        sinks: list[ReceiptSink],
        on_error: Optional[Callable[[ReceiptSink, Exception], None]] = None,
    ) -> None:
        self._sinks = list(sinks)
        self._on_error = on_error
        #: Records a downstream sink refused, across every sink.
        self.dropped = 0

    def send(self, receipt: DecisionReceipt) -> None:
        self._fan_out(lambda sink: sink.send(receipt))

    def record_policy_event(self, event: "PolicyEvent") -> None:
        self._fan_out(lambda sink: sink.record_policy_event(event))

    def _fan_out(self, deliver: Callable[[ReceiptSink], None]) -> None:
        first_failure: Optional[tuple[ReceiptSink, Exception]] = None
        for sink in self._sinks:
            try:
                deliver(sink)
            except Exception as exc:  # noqa: BLE001
                self._failed(sink, exc)
                if first_failure is None:
                    first_failure = (sink, exc)
        if first_failure is not None:
            sink, exc = first_failure
            raise SinkFanoutError(type(sink).__name__, exc) from exc

    def _failed(self, sink: ReceiptSink, exc: Exception) -> None:
        self.dropped += 1
        if self._on_error is None:
            return
        try:
            self._on_error(sink, exc)
        except Exception:  # noqa: BLE001 - a broken handler is not fatal
            pass


class SinkFanoutError(RuntimeError):
    """A sink behind a :class:`MultiSink` refused what it was handed."""

    def __init__(self, sink: str, error: Exception) -> None:
        super().__init__(f"sink {sink}: {error}")
        #: The sink that refused, by type name.
        self.sink = sink
        #: What it raised.
        self.error = error


class CallbackSink(ReceiptSink):

    def __init__(self, callback: Callable[[DecisionReceipt], None]) -> None:
        self._callback = callback

    def send(self, receipt: DecisionReceipt) -> None:
        self._callback(receipt)


class NullSink(ReceiptSink):

    def send(self, receipt: DecisionReceipt) -> None:
        pass


def _json_default(obj: object) -> object:
    if isinstance(obj, enum.Enum):
        return obj.value
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
