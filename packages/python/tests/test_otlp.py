"""The OTLP/HTTP receipt sink, against a real HTTP server.

The collector here is ``http.server``: the sink builds real requests, so the
tests assert on the bytes a collector would actually receive rather than on an
internal representation of them.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional

import pytest

from hushspec.canonical import canonical_json_value
from hushspec.evaluate import Decision
from hushspec.log import PolicyEvent, policy_event_to_dict
from hushspec.otlp import (
    OtlpExportError,
    OtlpQueueFullError,
    OtlpReceiptSink,
    _policy_event_record,
    _receipt_record,
)
from hushspec.receipt import (
    ActionSummary,
    DecisionReceipt,
    EnforcementSummary,
    PolicySummary,
    RuleOutcome,
    RuleTraceEntry,
    receipt_hash,
)
from hushspec.version import HUSHSPEC_VERSION


# --------------------------------------------------------------------------- #
# A collector
# --------------------------------------------------------------------------- #


class _Collector:
    """An OTLP/HTTP endpoint that records what it was sent."""

    def __init__(self, statuses: Optional[list[int]] = None) -> None:
        self.requests: list[dict[str, Any]] = []
        self.headers: list[dict[str, str]] = []
        self.paths: list[str] = []
        self._statuses = list(statuses or [])
        self._lock = threading.Lock()
        self._received = threading.Event()
        collector = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                with collector._lock:
                    collector.paths.append(self.path)
                    # HTTP header names are case-insensitive, and urllib
                    # recapitalizes them on the way out.
                    collector.headers.append(
                        {k.lower(): v for k, v in self.headers.items()}
                    )
                    collector.requests.append(json.loads(body))
                    status = (
                        collector._statuses.pop(0) if collector._statuses else 200
                    )
                collector._received.set()
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args: Any) -> None:  # silence the test output
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def endpoint(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def records(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for payload in self.requests:
            for resource in payload["resourceLogs"]:
                for scope in resource["scopeLogs"]:
                    out.extend(scope["logRecords"])
        return out

    def wait(self, timeout: float = 5.0) -> bool:
        return self._received.wait(timeout)

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def collector():
    server = _Collector()
    try:
        yield server
    finally:
        server.close()


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def _policy_summary() -> PolicySummary:
    return PolicySummary(
        name="test-policy",
        spec_version="0.1.0",
        content_hash="sha256:" + "ab" * 32,
    )


def _receipt(
    decision: Decision = Decision.ALLOW,
    *,
    outcome: str = "allowed",
    matched_rule: Optional[str] = "rules.egress.allow[0]",
) -> DecisionReceipt:
    return DecisionReceipt(
        receipt_id="01994b7e-2c1a-7c3e-8f4a-0123456789ab",
        timestamp="2025-09-15T12:34:56.789Z",
        policy=_policy_summary(),
        action=ActionSummary(type="egress", target="api.example.com"),
        decision=decision,
        matched_rule=matched_rule,
        reason="because",
        rule_trace=[
            RuleTraceEntry(
                rule_block="egress", outcome=RuleOutcome.ALLOW, evaluated=True
            )
        ],
        enforcement=EnforcementSummary(mode="enforce", outcome=outcome),
    )


def _attributes(record: dict[str, Any]) -> dict[str, str]:
    return {
        attribute["key"]: attribute["value"]["stringValue"]
        for attribute in record["attributes"]
    }


def _sink(collector: _Collector, **kwargs: Any) -> OtlpReceiptSink:
    kwargs.setdefault("batch_size", 1)
    kwargs.setdefault("flush_interval_s", 0.05)
    return OtlpReceiptSink(collector.endpoint, **kwargs)


# --------------------------------------------------------------------------- #
# Wire format
# --------------------------------------------------------------------------- #


class TestWireFormat:
    def test_posts_to_the_logs_path(self, collector: _Collector):
        sink = _sink(collector)
        sink.send(_receipt())
        assert sink.flush(5.0)
        sink.close()

        assert collector.paths == ["/v1/logs"]
        assert collector.headers[0]["content-type"] == "application/json"

    def test_endpoint_already_naming_the_signal_is_not_doubled(
        self, collector: _Collector
    ):
        sink = OtlpReceiptSink(collector.endpoint + "/v1/logs", batch_size=1)
        sink.send(_receipt())
        assert sink.flush(5.0)
        sink.close()

        assert collector.paths == ["/v1/logs"]

    def test_resource_identifies_the_sdk(self, collector: _Collector):
        sink = _sink(collector, service_name="checkout-agent")
        sink.send(_receipt())
        assert sink.flush(5.0)
        sink.close()

        resource = collector.requests[0]["resourceLogs"][0]["resource"]
        attributes = {
            a["key"]: a["value"]["stringValue"] for a in resource["attributes"]
        }
        assert attributes["service.name"] == "checkout-agent"
        assert attributes["hushspec.sdk"] == "hushspec-python"
        assert attributes["hushspec.spec_version"] == HUSHSPEC_VERSION
        assert attributes["hushspec.sdk.version"]

    def test_body_is_the_canonical_receipt(self, collector: _Collector):
        receipt = _receipt()
        sink = _sink(collector)
        sink.send(receipt)
        assert sink.flush(5.0)
        sink.close()

        record = collector.records[0]
        assert record["body"]["stringValue"] == receipt.canonical_json()
        # ...so the evidence can still be verified after the trip.
        assert (
            _attributes(record)["hushspec.receipt_hash"] == receipt_hash(receipt)
        )

    def test_timestamp_becomes_nanoseconds(self, collector: _Collector):
        sink = _sink(collector)
        sink.send(_receipt())
        assert sink.flush(5.0)
        sink.close()

        # 2025-09-15T12:34:56.789Z
        assert collector.records[0]["timeUnixNano"] == "1757939696789000000"

    def test_receipt_attributes(self, collector: _Collector):
        sink = _sink(collector)
        sink.send(_receipt())
        assert sink.flush(5.0)
        sink.close()

        attributes = _attributes(collector.records[0])
        assert attributes == {
            "hushspec.entry_type": "receipt",
            "hushspec.receipt_version": "0.2",
            "hushspec.decision": "allow",
            "hushspec.action_type": "egress",
            "hushspec.matched_rule": "rules.egress.allow[0]",
            "hushspec.policy.content_hash": "sha256:" + "ab" * 32,
            "hushspec.receipt_hash": attributes["hushspec.receipt_hash"],
            "hushspec.enforcement.mode": "enforce",
            "hushspec.enforcement.outcome": "allowed",
        }

    def test_an_absent_field_carries_no_attribute(self, collector: _Collector):
        sink = _sink(collector)
        sink.send(_receipt(matched_rule=None))
        assert sink.flush(5.0)
        sink.close()

        assert "hushspec.matched_rule" not in _attributes(collector.records[0])

    @pytest.mark.parametrize(
        ("decision", "severity", "number"),
        [
            (Decision.ALLOW, "INFO", 9),
            (Decision.WARN, "WARN", 13),
            (Decision.DENY, "ERROR", 17),
        ],
    )
    def test_severity_follows_the_decision(
        self, collector: _Collector, decision: Decision, severity: str, number: int
    ):
        sink = _sink(collector)
        sink.send(_receipt(decision, outcome="blocked"))
        assert sink.flush(5.0)
        sink.close()

        assert collector.records[0]["severityText"] == severity
        assert collector.records[0]["severityNumber"] == number

    def test_a_receipt_and_a_policy_event_carry_the_same_record_members(self):
        # The wire mapping every HushSpec SDK's exporter emits, so one
        # collector pipeline and one set of dashboard queries read all four.
        members = {
            "timeUnixNano",
            "observedTimeUnixNano",
            "severityNumber",
            "severityText",
            "body",
            "attributes",
        }
        receipt_record = _receipt_record(_receipt(Decision.DENY, outcome="blocked"))
        event_record = _policy_event_record(
            PolicyEvent.loaded(_policy_summary(), "enforce")
        )

        assert set(receipt_record) == members
        assert set(event_record) == members

    def test_policy_events_are_exported(self, collector: _Collector):
        event = PolicyEvent.loaded(_policy_summary(), "monitor")
        sink = _sink(collector)
        sink.record_policy_event(event)
        assert sink.flush(5.0)
        sink.close()

        record = collector.records[0]
        assert record["severityText"] == "INFO"
        assert record["body"]["stringValue"] == canonical_json_value(
            policy_event_to_dict(event)
        )
        attributes = _attributes(record)
        assert attributes == {
            "hushspec.entry_type": "policy_loaded",
            "hushspec.policy.content_hash": "sha256:" + "ab" * 32,
            "hushspec.enforcement.mode": "monitor",
        }

    def test_a_swap_is_labelled_as_one(self, collector: _Collector):
        sink = _sink(collector)
        sink.record_policy_event(
            PolicyEvent.swapped(_policy_summary(), "enforce", "sha256:" + "cd" * 32)
        )
        assert sink.flush(5.0)
        sink.close()

        attributes = _attributes(collector.records[0])
        assert attributes["hushspec.entry_type"] == "policy_swapped"

    def test_custom_headers_are_sent(self, collector: _Collector):
        sink = _sink(collector, headers={"x-api-key": "secret"})
        sink.send(_receipt())
        assert sink.flush(5.0)
        sink.close()

        assert collector.headers[0]["x-api-key"] == "secret"


# --------------------------------------------------------------------------- #
# Batching, retry, backpressure
# --------------------------------------------------------------------------- #


class TestBatching:
    def test_records_are_batched_into_one_request(self, collector: _Collector):
        sink = OtlpReceiptSink(
            collector.endpoint, batch_size=5, flush_interval_s=30, start=False
        )
        for _ in range(5):
            sink.send(_receipt())
        sink._start()
        assert sink.flush(5.0)
        sink.close()

        assert len(collector.requests) == 1
        assert len(collector.records) == 5
        assert sink.exported == 5

    def test_flush_exports_a_partial_batch(self, collector: _Collector):
        sink = OtlpReceiptSink(
            collector.endpoint, batch_size=1000, flush_interval_s=30
        )
        sink.send(_receipt())
        sink.send(_receipt())

        assert sink.flush(5.0)
        assert len(collector.records) == 2
        sink.close()

    def test_a_batch_larger_than_batch_size_is_split(self, collector: _Collector):
        sink = OtlpReceiptSink(
            collector.endpoint, batch_size=2, flush_interval_s=30, start=False
        )
        for _ in range(4):
            sink.send(_receipt())
        sink._start()
        assert sink.flush(5.0)
        sink.close()

        assert len(collector.requests) == 2
        assert [len(r["resourceLogs"][0]["scopeLogs"][0]["logRecords"]) for r in collector.requests] == [2, 2]

    def test_close_flushes_what_is_queued(self, collector: _Collector):
        sink = OtlpReceiptSink(
            collector.endpoint, batch_size=100, flush_interval_s=30
        )
        sink.send(_receipt())
        sink.close()

        assert len(collector.records) == 1

    def test_close_is_idempotent(self, collector: _Collector):
        sink = _sink(collector)
        assert sink.close() is True
        assert sink.close() is True

    def test_a_closed_sink_drops_and_says_why(self, collector: _Collector):
        errors: list[Exception] = []
        sink = _sink(collector, on_error=errors.append)
        sink.close()
        sink.send(_receipt())
        assert sink.dropped == 1
        assert [str(exc) for exc in errors] == ["OTLP sink is closed; record dropped"]

    def test_a_deferred_sink_can_be_started(self, collector: _Collector):
        sink = OtlpReceiptSink(
            collector.endpoint, batch_size=1, flush_interval_s=0.05, start=False
        )
        sink.send(_receipt())
        assert collector.records == []
        sink.start()
        assert sink.flush(5.0) is True
        sink.close()
        assert len(collector.records) == 1


class TestRetry:
    def test_retries_a_server_error(self):
        collector = _Collector(statuses=[503, 200])
        try:
            errors: list[Exception] = []
            sink = OtlpReceiptSink(
                collector.endpoint,
                batch_size=1,
                flush_interval_s=0.05,
                retry_backoff_s=0.01,
                on_error=errors.append,
            )
            sink.send(_receipt())
            assert sink.flush(5.0)
            sink.close()

            assert len(collector.requests) == 2
            assert errors == []
            assert sink.exported == 1
            assert sink.failed == 0
        finally:
            collector.close()

    def test_gives_up_after_max_retries_and_reports(self):
        collector = _Collector(statuses=[500, 500, 500])
        try:
            errors: list[Exception] = []
            sink = OtlpReceiptSink(
                collector.endpoint,
                batch_size=1,
                flush_interval_s=0.05,
                max_retries=2,
                retry_backoff_s=0.01,
                on_error=errors.append,
            )
            sink.send(_receipt())
            assert sink.flush(5.0)
            sink.close()

            assert len(collector.requests) == 3  # 1 attempt + 2 retries
            assert len(errors) == 1
            assert isinstance(errors[0], OtlpExportError)
            assert errors[0].status == 500
            assert errors[0].records == 1
            assert sink.failed == 1
        finally:
            collector.close()

    def test_a_client_error_is_not_retried(self):
        collector = _Collector(statuses=[400])
        try:
            errors: list[Exception] = []
            sink = OtlpReceiptSink(
                collector.endpoint,
                batch_size=1,
                flush_interval_s=0.05,
                retry_backoff_s=0.01,
                on_error=errors.append,
            )
            sink.send(_receipt())
            assert sink.flush(5.0)
            sink.close()

            assert len(collector.requests) == 1
            assert isinstance(errors[0], OtlpExportError)
            assert errors[0].status == 400
        finally:
            collector.close()

    def test_an_unreachable_collector_is_reported_not_raised(self):
        errors: list[Exception] = []
        # Port 1 on loopback: nothing listens there.
        sink = OtlpReceiptSink(
            "http://127.0.0.1:1",
            batch_size=1,
            flush_interval_s=0.05,
            max_retries=1,
            retry_backoff_s=0.01,
            timeout_s=0.5,
            on_error=errors.append,
        )
        sink.send(_receipt())  # must not raise
        assert sink.flush(10.0)
        sink.close()

        assert len(errors) == 1
        assert isinstance(errors[0], OtlpExportError)
        assert errors[0].status is None


class TestBackpressure:
    def test_overflow_drops_counts_and_reports(self, collector: _Collector):
        errors: list[Exception] = []
        sink = OtlpReceiptSink(
            collector.endpoint,
            batch_size=1,
            flush_interval_s=30,
            max_queue=2,
            on_error=errors.append,
            start=False,  # nothing drains the queue
        )
        for _ in range(5):
            sink.send(_receipt())

        assert sink.dropped == 3
        assert len(errors) == 3
        assert isinstance(errors[0], OtlpQueueFullError)
        assert errors[-1].dropped == 3

    def test_send_never_raises_when_no_handler_is_given(self, collector: _Collector):
        sink = OtlpReceiptSink(
            collector.endpoint, max_queue=1, flush_interval_s=30, start=False
        )
        sink.send(_receipt())
        sink.send(_receipt())
        assert sink.dropped == 1

    def test_a_broken_error_handler_does_not_break_send(self, collector: _Collector):
        def explode(_error: Exception) -> None:
            raise RuntimeError("handler is broken")

        sink = OtlpReceiptSink(
            collector.endpoint,
            max_queue=1,
            flush_interval_s=30,
            on_error=explode,
            start=False,
        )
        sink.send(_receipt())
        sink.send(_receipt())
        assert sink.dropped == 1


class TestConfiguration:
    @pytest.mark.parametrize(
        "endpoint",
        ["", "   ", "file:///tmp/x", "localhost:4318", "ftp://host/v1/logs"],
    )
    def test_rejects_an_endpoint_that_is_not_http(self, endpoint: str):
        with pytest.raises(ValueError):
            OtlpReceiptSink(endpoint)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"batch_size": 0},
            {"max_queue": 0},
            {"flush_interval_s": 0},
        ],
    )
    def test_rejects_nonsense_limits(self, collector: _Collector, kwargs: dict):
        with pytest.raises(ValueError):
            OtlpReceiptSink(collector.endpoint, **kwargs)


class TestWithGuard:
    def test_a_guard_exports_receipts_and_its_policy_event(
        self, collector: _Collector
    ):
        from hushspec.evaluate import EvaluationAction
        from hushspec.middleware import HushGuard

        policy = """
hushspec: "0.1.0"
name: otlp-policy
rules:
  tool_access:
    allow: [read_file]
    default: block
"""
        sink = _sink(collector, batch_size=100, flush_interval_s=30)
        guard = HushGuard.from_yaml(policy, sink=sink)
        guard.check(EvaluationAction(type="tool_call", target="read_file"))
        guard.check(EvaluationAction(type="tool_call", target="rm_rf"))
        assert sink.flush(5.0)
        sink.close()

        kinds = [_attributes(r)["hushspec.entry_type"] for r in collector.records]
        assert kinds == ["policy_loaded", "receipt", "receipt"]
        severities = [r["severityText"] for r in collector.records]
        assert severities == ["INFO", "INFO", "ERROR"]
