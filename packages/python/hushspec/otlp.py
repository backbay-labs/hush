"""OTLP/HTTP receipt sink: receipts as OpenTelemetry logs.

Every receipt and every policy-in-effect event becomes one OTLP log record
whose body is the entry's *canonical* JSON -- the exact bytes its hash is taken
over (receipt spec section 6) -- so evidence that went through a collector, a
queue and a SIEM can still be re-hashed and verified against a signed log. The
searchable facts (decision, action type, matched rule, policy content hash,
enforcement disposition) are lifted into attributes so a dashboard never has to
parse the body to filter on them.

The mapping is fixed across the Rust, TypeScript, Python and Go SDKs: one
``logRecord`` per entry, ``timeUnixNano`` from the entry's own timestamp,
``observedTimeUnixNano`` from when the sink took it, ``severityText`` and
``severityNumber`` of ``INFO``/9, ``WARN``/13 and ``ERROR``/17 for
allow/warn/deny, and the ``hushspec.*`` attributes below. A receipt exported by
one SDK is indistinguishable from the same receipt exported by another.

Export is off the hot path: :meth:`OtlpReceiptSink.send` renders the record and
hands it to a bounded queue, and a daemon thread batches, posts and retries. It
never blocks an evaluation, and it never grows without bound -- when the queue
is full the record is dropped, counted, and reported through ``on_error``,
because an enforcement point that stalls or exhausts memory because a collector
is down has failed worse than one that loses telemetry.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Optional
from urllib.parse import urlparse

from hushspec.canonical import canonical_json_value
from hushspec.log import SDK_NAME, SdkInfo, policy_event_to_dict
from hushspec.receipt import DecisionReceipt, canonical_json, digest
from hushspec.sinks import ReceiptSink
from hushspec.version import HUSHSPEC_VERSION

if TYPE_CHECKING:
    from hushspec.log import PolicyEvent

__all__ = [
    "OtlpError",
    "OtlpExportError",
    "OtlpQueueFullError",
    "OtlpReceiptSink",
]

#: The OTLP/HTTP logs path appended to a base endpoint.
LOGS_PATH = "/v1/logs"

_DEFAULT_BATCH_SIZE = 64
_DEFAULT_FLUSH_INTERVAL_S = 5.0
_DEFAULT_TIMEOUT_S = 10.0
_DEFAULT_MAX_QUEUE = 2048
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_RETRY_BACKOFF_S = 0.1

#: Severity text and number per decision, as the OpenTelemetry logs data model
#: numbers them: an allow is routine, a warn is worth a look, a denial is an
#: incident, so a collector's default severity filters surface denials without
#: a rule of their own.
_SEVERITY_BY_DECISION = {
    "allow": ("INFO", 9),
    "warn": ("WARN", 13),
    "deny": ("ERROR", 17),
}
#: A decision this build does not know is not an "INFO".
_SEVERITY_UNKNOWN = ("ERROR", 17)
#: A policy event decided nothing, so it is informational whatever the policy
#: says.
_POLICY_EVENT_SEVERITY = ("INFO", 9)

_ENTRY_TYPE_RECEIPT = "receipt"
_ENTRY_TYPE_BY_POLICY_EVENT = {
    "loaded": "policy_loaded",
    "swapped": "policy_swapped",
}

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class OtlpError(RuntimeError):
    """Something went wrong exporting telemetry. Never fatal to enforcement."""


class OtlpExportError(OtlpError):
    """A batch could not be delivered."""

    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        records: int = 0,
        attempts: int = 0,
    ) -> None:
        super().__init__(message)
        #: HTTP status, when the collector answered at all.
        self.status = status
        #: How many records were lost with this batch.
        self.records = records
        #: How many delivery attempts were made.
        self.attempts = attempts


class OtlpQueueFullError(OtlpError):
    """A record was dropped because the export queue was full."""

    def __init__(self, message: str, *, dropped: int) -> None:
        super().__init__(message)
        #: Total records dropped by this sink so far, this one included.
        self.dropped = dropped


def _value(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


def _attribute(key: str, value: Any) -> dict[str, Any]:
    return {"key": key, "value": {"stringValue": str(_value(value))}}


def _attributes(pairs: list[tuple[str, Any]]) -> list[dict[str, Any]]:
    """Attributes for every pair with a value. Absent means absent: an unmatched
    receipt carries no ``hushspec.matched_rule`` rather than an empty one."""
    return [_attribute(key, value) for key, value in pairs if value not in (None, "")]


def _time_unix_nano(timestamp: Optional[str], fallback: str) -> str:
    """Nanoseconds since the epoch, from a receipt's RFC 3339 UTC timestamp.

    OTLP/JSON carries 64-bit integers as strings. An unparseable timestamp falls
    back to *fallback*, the time the sink took the entry: a record with no time
    at all would be dropped by collectors, and the body still carries the
    entry's own timestamp verbatim.
    """
    if timestamp:
        text = timestamp.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            moment = None
        if moment is not None:
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
            delta = moment - _EPOCH
            nanos = (
                (delta.days * 86_400 + delta.seconds) * 1_000_000_000
                + delta.microseconds * 1000
            )
            return str(nanos)
    return fallback


def _receipt_record(receipt: DecisionReceipt) -> dict[str, Any]:
    decision = str(_value(receipt.decision))
    enforcement = receipt.enforcement
    policy = receipt.policy
    action = receipt.action
    body = canonical_json(receipt)
    observed = str(time.time_ns())
    severity_text, severity_number = _SEVERITY_BY_DECISION.get(
        decision, _SEVERITY_UNKNOWN
    )
    return {
        "timeUnixNano": _time_unix_nano(receipt.timestamp, observed),
        "observedTimeUnixNano": observed,
        "severityNumber": severity_number,
        "severityText": severity_text,
        "body": {"stringValue": body},
        "attributes": _attributes(
            [
                ("hushspec.entry_type", _ENTRY_TYPE_RECEIPT),
                ("hushspec.receipt_version", receipt.receipt_version),
                ("hushspec.decision", decision),
                ("hushspec.action_type", action.type if action is not None else None),
                ("hushspec.matched_rule", receipt.matched_rule),
                (
                    "hushspec.policy.content_hash",
                    policy.content_hash if policy is not None else None,
                ),
                # Taken from the same bytes the body carries, so a reader can
                # join on it without re-canonicalizing anything.
                ("hushspec.receipt_hash", digest(body)),
                (
                    "hushspec.enforcement.mode",
                    enforcement.mode if enforcement is not None else None,
                ),
                (
                    "hushspec.enforcement.outcome",
                    enforcement.outcome if enforcement is not None else None,
                ),
            ]
        ),
    }


def _policy_event_record(event: "PolicyEvent") -> dict[str, Any]:
    kind = str(_value(event.event))
    policy = event.policy
    body = canonical_json_value(policy_event_to_dict(event))
    observed = str(time.time_ns())
    severity_text, severity_number = _POLICY_EVENT_SEVERITY
    return {
        "timeUnixNano": _time_unix_nano(event.timestamp, observed),
        "observedTimeUnixNano": observed,
        "severityNumber": severity_number,
        "severityText": severity_text,
        "body": {"stringValue": body},
        "attributes": _attributes(
            [
                (
                    "hushspec.entry_type",
                    _ENTRY_TYPE_BY_POLICY_EVENT.get(kind, kind),
                ),
                (
                    "hushspec.policy.content_hash",
                    policy.content_hash if policy is not None else None,
                ),
                ("hushspec.enforcement.mode", event.enforcement_mode),
            ]
        ),
    }


class OtlpReceiptSink(ReceiptSink):
    """Exports receipts and policy events to an OTLP/HTTP collector as logs.

    ``endpoint`` is the collector's base URL (``http://localhost:4318``), to
    which ``/v1/logs`` is appended unless it already ends there. ``headers``
    carries whatever the collector needs for authentication.

        sink = OtlpReceiptSink("http://localhost:4318")
        guard = HushGuard.from_file("policy.yaml", sink=sink)
        ...
        sink.close()

    Records queue up to ``max_queue`` and are posted in batches of at most
    ``batch_size``, or after ``flush_interval_s``, whichever comes first.
    Delivery is retried with exponential backoff on network errors, ``429`` and
    ``5xx``; a ``4xx`` is a configuration mistake the collector will keep
    refusing, so the batch is dropped and reported rather than retried forever.
    :meth:`flush` waits for what is queued; :meth:`close` flushes and stops the
    thread. Both are safe to call more than once.
    """

    def __init__(
        self,
        endpoint: str,
        headers: Optional[dict[str, str]] = None,
        service_name: str = "hushspec",
        batch_size: int = _DEFAULT_BATCH_SIZE,
        flush_interval_s: float = _DEFAULT_FLUSH_INTERVAL_S,
        timeout_s: float = _DEFAULT_TIMEOUT_S,
        max_queue: int = _DEFAULT_MAX_QUEUE,
        on_error: Optional[Callable[[Exception], None]] = None,
        *,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        retry_backoff_s: float = _DEFAULT_RETRY_BACKOFF_S,
        start: bool = True,
    ) -> None:
        if batch_size < 1:
            raise ValueError(f"batch_size must be positive: {batch_size!r}")
        if max_queue < 1:
            raise ValueError(f"max_queue must be positive: {max_queue!r}")
        if flush_interval_s <= 0:
            raise ValueError(f"flush_interval_s must be positive: {flush_interval_s!r}")
        self.endpoint = _logs_endpoint(endpoint)
        self._headers = {"Content-Type": "application/json", **(headers or {})}
        self._batch_size = batch_size
        self._flush_interval_s = flush_interval_s
        self._timeout_s = timeout_s
        self._max_queue = max_queue
        self._on_error = on_error
        self._max_retries = max(0, max_retries)
        self._retry_backoff_s = retry_backoff_s

        sdk = SdkInfo.this_sdk()
        self._resource = {
            "attributes": _attributes(
                [
                    ("service.name", service_name),
                    ("hushspec.sdk", SDK_NAME),
                    ("hushspec.sdk.version", sdk.version),
                    ("hushspec.spec_version", HUSHSPEC_VERSION),
                ]
            )
        }
        self._scope = {"name": SDK_NAME, "version": sdk.version}

        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._idle = threading.Condition(self._lock)
        self._pending: deque[dict[str, Any]] = deque()
        self._inflight = 0
        self._flush_requested = False
        self._stopping = False
        self._closed = False
        #: Records dropped because the queue was full, and batches that could
        #: not be delivered. Counters, not exceptions: telemetry loss is
        #: reportable, never fatal.
        self.dropped = 0
        self.exported = 0
        self.failed = 0
        self._thread: Optional[threading.Thread] = None
        if start:
            self._start()

    # -- ReceiptSink -------------------------------------------------------- #

    def send(self, receipt: DecisionReceipt) -> None:
        """Queue a receipt. Renders now, exports later; never blocks on I/O."""
        self._enqueue(_receipt_record(receipt))

    def record_policy_event(self, event: "PolicyEvent") -> None:
        """Queue a policy-in-effect event (log spec section 6)."""
        self._enqueue(_policy_event_record(event))

    # -- lifecycle ---------------------------------------------------------- #

    def flush(self, timeout: Optional[float] = None) -> bool:
        """Export everything queued. True when the queue drained in time."""
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._lock:
            if not self._pending and self._inflight == 0:
                return True
            self._flush_requested = True
            self._not_empty.notify_all()
            while self._pending or self._inflight:
                if self._thread is None or not self._thread.is_alive():
                    return False
                if deadline is None:
                    self._idle.wait(0.5)
                else:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return False
                    self._idle.wait(remaining)
            return True

    def start(self) -> None:
        """Start the export thread, for a sink built with ``start=False``.

        A no-op once the thread is running. A sink that is never started
        queues until ``max_queue`` and then drops, so this is the other half
        of deferred construction.
        """
        with self._lock:
            if self._closed:
                raise OtlpError("sink is closed")
            if self._thread is not None and self._thread.is_alive():
                return
        self._start()

    def close(self, timeout: Optional[float] = 10.0) -> bool:
        """Flush, stop the export thread, and refuse further records.

        Returns whether the thread is gone. ``timeout`` is the budget for the
        whole shutdown, split between the flush and the join, so ``close(10)``
        takes at most ten seconds rather than twice that. A join that times out
        keeps the thread reference: forgetting a thread still mid-export would
        leave it unobservable and unjoinable.
        """
        with self._lock:
            if self._closed:
                return self._thread is None or not self._thread.is_alive()
            self._closed = True
        deadline = None if timeout is None else time.monotonic() + timeout
        self.flush(timeout)
        with self._lock:
            self._stopping = True
            self._not_empty.notify_all()
        thread = self._thread
        if thread is None or thread is threading.current_thread():
            return thread is None
        remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
        thread.join(remaining)
        if thread.is_alive():
            return False
        with self._lock:
            if self._thread is thread:
                self._thread = None
        return True

    def __enter__(self) -> "OtlpReceiptSink":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    # -- internals ---------------------------------------------------------- #

    def _start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name="hushspec-otlp", daemon=True
        )
        self._thread.start()

    def _enqueue(self, record: dict[str, Any]) -> None:
        overflow = 0
        closed = False
        with self._lock:
            # Drop the newest rather than evicting the oldest: the records
            # already queued are the ones closest to being evidence.
            if self._closed:
                self.dropped += 1
                overflow = self.dropped
                closed = True
            elif len(self._pending) >= self._max_queue:
                self.dropped += 1
                overflow = self.dropped
            else:
                self._pending.append(record)
                self._not_empty.notify()
        if not overflow:
            return
        if closed:
            # A wrong-lifecycle drop, not back-pressure: reporting it as a full
            # queue would send an operator after the wrong problem.
            self._report(
                OtlpExportError(
                    "OTLP sink is closed; record dropped", records=1
                )
            )
        else:
            self._report(
                OtlpQueueFullError(
                    f"OTLP export queue full ({self._max_queue}); record dropped",
                    dropped=overflow,
                )
            )

    def _run(self) -> None:
        while True:
            batch = self._take_batch()
            if batch is None:
                return
            if batch:
                try:
                    self._export(batch)
                except Exception as exc:  # noqa: BLE001
                    # _export reports its own failures, so reaching here is a
                    # bug rather than a transport error. The thread must
                    # survive it: once it dies the sink silently drops every
                    # later receipt.
                    with self._lock:
                        self.failed += len(batch)
                    self._report(
                        OtlpExportError(
                            f"OTLP export raised unexpectedly: {exc}",
                            records=len(batch),
                        )
                    )
            with self._lock:
                self._inflight = 0
                if not self._pending:
                    self._flush_requested = False
                self._idle.notify_all()

    def _take_batch(self) -> Optional[list[dict[str, Any]]]:
        """Wait for records, then accumulate a batch. ``None`` means stop."""
        with self._lock:
            while not self._pending and not self._stopping:
                self._not_empty.wait(self._flush_interval_s)
            if not self._pending:
                return None
            deadline = time.monotonic() + self._flush_interval_s
            while (
                len(self._pending) < self._batch_size
                and not self._stopping
                and not self._flush_requested
            ):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._not_empty.wait(remaining)
            count = min(len(self._pending), self._batch_size)
            batch = [self._pending.popleft() for _ in range(count)]
            self._inflight = count
            return batch

    def _export(self, records: list[dict[str, Any]]) -> None:
        payload = json.dumps(
            {
                "resourceLogs": [
                    {
                        "resource": self._resource,
                        "scopeLogs": [
                            {"scope": self._scope, "logRecords": records}
                        ],
                    }
                ]
            }
        ).encode("utf-8")

        attempt = 0
        while True:
            attempt += 1
            status, error = self._post(payload)
            if error is None:
                with self._lock:
                    self.exported += len(records)
                return
            retryable = status is None or status == 429 or status >= 500
            if not retryable or attempt > self._max_retries:
                with self._lock:
                    self.failed += len(records)
                self._report(
                    OtlpExportError(
                        f"OTLP export to {self.endpoint} failed: {error}",
                        status=status,
                        records=len(records),
                        attempts=attempt,
                    )
                )
                return
            backoff = self._retry_backoff_s * (2 ** (attempt - 1))
            if self._sleep(backoff):
                # Shutting down: give up rather than hold close() open.
                with self._lock:
                    self.failed += len(records)
                self._report(
                    OtlpExportError(
                        f"OTLP export to {self.endpoint} abandoned at shutdown: {error}",
                        status=status,
                        records=len(records),
                        attempts=attempt,
                    )
                )
                return

    def _post(self, payload: bytes) -> tuple[Optional[int], Optional[str]]:
        request = urllib.request.Request(
            self.endpoint, data=payload, headers=self._headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_s) as response:
                status = getattr(response, "status", None) or response.getcode()
                response.read()
        except urllib.error.HTTPError as exc:
            try:
                exc.read()
            except Exception:  # noqa: BLE001 - draining is best effort
                pass
            finally:
                exc.close()
            return exc.code, f"HTTP {exc.code} {exc.reason}"
        except Exception as exc:  # noqa: BLE001 - URLError, timeouts, DNS, TLS
            return None, str(exc) or type(exc).__name__
        if status is not None and status >= 400:
            return status, f"HTTP {status}"
        return status, None

    def _sleep(self, seconds: float) -> bool:
        """Sleep between retries. True when shutdown interrupted the wait."""
        deadline = time.monotonic() + seconds
        with self._lock:
            while not self._stopping:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._not_empty.wait(remaining)
            return True

    def _report(self, error: Exception) -> None:
        if self._on_error is None:
            return
        try:
            self._on_error(error)
        except Exception:  # noqa: BLE001 - a broken handler is not fatal
            pass


def _logs_endpoint(endpoint: str) -> str:
    """``<endpoint>/v1/logs``, unless the caller already pointed at the signal.

    Rejects anything that is not HTTP(S) up front: a sink that silently accepted
    ``file:`` would turn a misconfiguration into evidence written somewhere
    nobody is looking.
    """
    if not endpoint or not endpoint.strip():
        raise ValueError("OTLP endpoint must not be empty")
    endpoint = endpoint.strip()
    parsed = urlparse(endpoint)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"OTLP endpoint must be http:// or https://, got {endpoint!r}"
        )
    if not parsed.netloc:
        raise ValueError(f"OTLP endpoint has no host: {endpoint!r}")
    trimmed = endpoint.rstrip("/")
    if trimmed.endswith(LOGS_PATH):
        return trimmed
    return trimmed + LOGS_PATH
