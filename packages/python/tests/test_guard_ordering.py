"""Policy events bracket complete decisions, including confirmation."""
import threading
import unittest

from hushspec import HushGuard, EvaluationAction, parse_or_raise
from hushspec.observer import EvaluationObserver


OLD = "hushspec: '1.0.0'\nname: old\nrules:\n  tool_access:\n    require_confirmation: [edit]\n"
NEW = "hushspec: '1.0.0'\nname: new\n"
ACTION = EvaluationAction(type="tool_call", target="edit")


class Sink:
    def __init__(self):
        self.entries = []
        self.entered = threading.Event()
        self.release = threading.Event()
        self.pause_swap = False

    def send(self, receipt):
        self.entries.append(("receipt", receipt.policy.content_hash))

    def record_policy_event(self, event):
        if self.pause_swap and event.event == "swapped":
            self.entered.set()
            assert self.release.wait(5), "test did not release policy append"
        self.entries.append((event.event, event.policy.content_hash))


def assert_order(test, entries):
    current = None
    for kind, identity in entries:
        if kind == "receipt":
            test.assertEqual(identity, current, entries)
        else:
            current = identity


class OrderingTests(unittest.TestCase):
    def test_new_receipt_cannot_precede_swap_record(self):
        sink = Sink()
        guard = HushGuard.from_yaml(OLD, sink=sink)
        sink.pause_swap = True
        swap = threading.Thread(target=lambda: guard.swap_policy(parse_or_raise(NEW)))
        done = threading.Event()
        check = threading.Thread(target=lambda: (guard.evaluate(ACTION), done.set()))
        swap.start()
        try:
            self.assertTrue(sink.entered.wait(5))
            check.start()
            completed_early = done.wait(0.2)
        finally:
            sink.release.set()
            swap.join(5)
            if check.ident is not None:
                check.join(5)
        self.assertFalse(swap.is_alive() or check.is_alive())
        self.assertFalse(completed_early, "evaluation passed an unrecorded swap")
        assert_order(self, sink.entries)

    def test_old_confirmation_cannot_record_after_new_policy_event(self):
        sink = Sink()
        entered, release, swapped = threading.Event(), threading.Event(), threading.Event()

        def confirm(_result, _action):
            entered.set()
            assert release.wait(5)
            return True

        guard = HushGuard.from_yaml(OLD, sink=sink, on_warn=confirm)
        check = threading.Thread(target=lambda: guard.gate(ACTION))
        swap = threading.Thread(target=lambda: (guard.swap_policy(parse_or_raise(NEW)), swapped.set()))
        check.start()
        try:
            self.assertTrue(entered.wait(5))
            swap.start()
            completed_early = swapped.wait(0.2)
        finally:
            release.set()
            check.join(5)
            if swap.ident is not None:
                swap.join(5)
        self.assertFalse(swap.is_alive() or check.is_alive())
        self.assertFalse(completed_early, "reload passed an unrecorded confirmation")
        assert_order(self, sink.entries)

    def test_reload_observer_can_evaluate_after_swap_event(self):
        sink = Sink()
        guard = None

        class Observer(EvaluationObserver):
            def on_event(self, event):
                if event.get("type") == "policy.reloaded":
                    guard.evaluate(ACTION)

        guard = HushGuard.from_yaml(OLD, sink=sink, observer=Observer())
        guard.swap_policy(parse_or_raise(NEW))
        self.assertTrue(any(kind == "receipt" for kind, _ in sink.entries))
        assert_order(self, sink.entries)

    def test_evaluation_and_sink_error_observers_can_reload(self):
        for event_type in ("evaluation.completed", "sink.error"):
            with self.subTest(event_type=event_type):
                entered = []
                sink = Sink()
                if event_type == "sink.error":
                    def fail(_receipt):
                        raise OSError("unavailable")
                    sink.send = fail
                guard = None

                class Observer(EvaluationObserver):
                    def on_event(self, event):
                        if event.get("type") == event_type and not entered:
                            entered.append(True)
                            guard.swap_policy(parse_or_raise(NEW))

                guard = HushGuard.from_yaml(OLD, sink=sink, observer=Observer())
                worker = threading.Thread(target=lambda: guard.evaluate(ACTION), daemon=True)
                worker.start()
                worker.join(5)
                self.assertFalse(worker.is_alive(), "observer deadlocked")
                self.assertEqual(entered, [True])

    def test_concurrent_swaps_and_decisions_preserve_nearest_policy(self):
        sink = Sink()
        guard = HushGuard.from_yaml(OLD, sink=sink)
        errors = []

        def exercise(index):
            try:
                for count in range(25):
                    if index % 2:
                        guard.swap_policy(parse_or_raise(NEW if count % 2 else OLD))
                    else:
                        guard.evaluate(ACTION)
            except BaseException as error:
                errors.append(error)

        workers = [threading.Thread(target=exercise, args=(index,), daemon=True) for index in range(4)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(5)
        self.assertFalse(any(worker.is_alive() for worker in workers))
        self.assertEqual(errors, [])
        self.assertEqual(sum(kind == "receipt" for kind, _ in sink.entries), 50)
        assert_order(self, sink.entries)
