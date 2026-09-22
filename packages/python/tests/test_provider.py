"""Policy providers and hot reload.

Every tick is driven explicitly through ``check_once()`` unless the test is
specifically about the background thread, so nothing here depends on a sleep
being long enough.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from hushspec.evaluate import (
    Decision,
    EvaluationAction,
    is_panic_active,
)
from hushspec.middleware import HushGuard
from hushspec.observer import EvaluationObserver
from hushspec.provider import (
    DEFAULT_PANIC_SENTINEL,
    CallbackProvider,
    FileProvider,
    PolicyPoller,
    PolicyProvider,
    PolicyWatcher,
)
from hushspec.resolve import (
    REASON_MISSING_SIGNATURE,
    PolicyVerificationError,
    ResolveOptions,
    Resolution,
)

ALLOW_POLICY = """
hushspec: "0.1.0"
name: allow-policy
rules:
  tool_access:
    allow: [read_file]
    default: block
"""

BLOCK_POLICY = """
hushspec: "0.1.0"
name: block-policy
rules:
  tool_access:
    block: [read_file]
    default: block
"""

EXTENDS_POLICY = """
hushspec: "0.1.0"
extends: "builtin:default"
name: leaf-policy
rules:
  tool_access:
    allow: [read_file]
    default: block
"""

READ_FILE = EvaluationAction(type="tool_call", target="read_file")


def _write(path: Path, text: str) -> None:
    """Write *text* and push mtime forward, so a watcher's stat cannot miss it.

    Two writes inside the same filesystem timestamp tick are exactly the case a
    mtime check gets wrong, and a test must not depend on the host's clock
    resolution to decide whether it passes.
    """
    existed = path.exists()
    mtime_ns = path.stat().st_mtime_ns if existed else 0
    path.write_text(text)
    if existed:
        bumped = max(mtime_ns + 1_000_000_000, path.stat().st_mtime_ns)
        os.utime(path, ns=(bumped, bumped))


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    _write(path, ALLOW_POLICY)
    return path


class _RecordingObserver(EvaluationObserver):
    def __init__(self) -> None:
        self.events: list[dict] = []

    def on_event(self, event: dict) -> None:
        self.events.append(event)

    @property
    def reloads(self) -> list[dict]:
        return [e for e in self.events if e.get("type") == "policy.reloaded"]


# --------------------------------------------------------------------------- #
# Providers
# --------------------------------------------------------------------------- #


class TestFileProvider:
    def test_loads_and_resolves(self, policy_file: Path):
        provider = FileProvider(policy_file)
        resolution = provider.load()

        assert isinstance(resolution, Resolution)
        assert resolution.spec.name == "allow-policy"
        assert resolution.content_hash.startswith("sha256:")
        assert provider.source == str(policy_file.resolve())

    def test_satisfies_the_provider_protocol(self, policy_file: Path):
        assert isinstance(FileProvider(policy_file), PolicyProvider)

    def test_resolves_extends_against_the_policy_directory(self, tmp_path: Path):
        base = tmp_path / "base.yaml"
        base.write_text(
            'hushspec: "0.1.0"\nname: base\n'
            "rules:\n  egress:\n    allow: [api.example.com]\n    default: block\n"
        )
        leaf = tmp_path / "leaf.yaml"
        leaf.write_text(
            'hushspec: "0.1.0"\nextends: "base.yaml"\nname: leaf\n'
            "rules:\n  tool_access:\n    allow: [read_file]\n    default: block\n"
        )

        resolution = FileProvider(leaf).load()

        assert resolution.spec.extends is None
        assert resolution.spec.rules.egress is not None
        assert len(resolution.chain) == 2

    def test_resolves_builtin_extends(self, tmp_path: Path):
        path = tmp_path / "leaf.yaml"
        path.write_text(EXTENDS_POLICY)

        resolution = FileProvider(path).load()

        assert resolution.spec.extends is None
        assert resolution.spec.rules.forbidden_paths is not None

    def test_raises_on_a_broken_document(self, tmp_path: Path):
        path = tmp_path / "policy.yaml"
        path.write_text("hushspec: '0.1.0'\nname: x\nnot_a_field: 1\n")

        with pytest.raises(ValueError, match="unknown field `not_a_field`"):
            FileProvider(path).load()

    def test_raises_on_a_missing_file(self, tmp_path: Path):
        with pytest.raises(OSError):
            FileProvider(tmp_path / "nope.yaml").load()

    def test_require_signature_is_carried_into_every_load(self, policy_file: Path):
        # No keyring and no signature: the load fails closed rather than
        # returning a policy nobody proved.
        provider = FileProvider(policy_file, ResolveOptions(require_signature=True))

        # Specifically the signature refusal: a bare ValueError would also be
        # raised by a document that simply failed to parse, which would let the
        # test pass with require_signature dropped entirely.
        with pytest.raises(PolicyVerificationError) as refused:
            provider.load()
        assert refused.value.code == REASON_MISSING_SIGNATURE

    def test_fingerprint_moves_with_the_file(self, policy_file: Path):
        provider = FileProvider(policy_file)
        before = provider.fingerprint()
        _write(policy_file, BLOCK_POLICY)

        assert before is not None
        assert provider.fingerprint() != before

    def test_fingerprint_is_none_when_the_file_is_gone(self, tmp_path: Path):
        assert FileProvider(tmp_path / "nope.yaml").fingerprint() is None


class TestCallbackProvider:
    def test_parses_and_resolves_returned_text(self):
        provider = CallbackProvider(lambda: ALLOW_POLICY, source="config-service")

        resolution = provider.load()

        assert resolution.spec.name == "allow-policy"
        assert provider.source == "config-service"

    def test_passes_a_resolution_through_untouched(self, policy_file: Path):
        loaded = FileProvider(policy_file).load()
        assert CallbackProvider(lambda: loaded).load() is loaded

    def test_resolves_builtin_extends(self):
        resolution = CallbackProvider(lambda: EXTENDS_POLICY).load()

        assert resolution.spec.extends is None
        assert resolution.spec.rules.forbidden_paths is not None


# --------------------------------------------------------------------------- #
# Watcher
# --------------------------------------------------------------------------- #


class TestPolicyWatcher:
    def test_unchanged_file_is_not_reloaded(self, policy_file: Path):
        changes: list[Resolution] = []
        watcher = PolicyWatcher(FileProvider(policy_file), 0.01, changes.append)
        watcher.start(load=False)
        watcher.stop()

        assert watcher.check_once() is not None  # first tick adopts
        assert watcher.check_once() is None
        assert watcher.check_once() is None
        assert len(changes) == 1

    def test_changed_file_is_reloaded(self, policy_file: Path):
        changes: list[Resolution] = []
        watcher = PolicyWatcher(FileProvider(policy_file), 0.01, changes.append)
        watcher.adopt(FileProvider(policy_file).load())

        assert watcher.check_once() is None

        _write(policy_file, BLOCK_POLICY)
        reloaded = watcher.check_once()

        assert reloaded is not None
        assert reloaded.spec.name == "block-policy"
        assert watcher.current is reloaded
        assert watcher.content_hash == reloaded.content_hash
        assert [c.spec.name for c in changes] == ["block-policy"]
        assert watcher.reload_count == 1

    def test_a_rewrite_during_the_adopted_load_is_picked_up(self, policy_file: Path):
        changes: list[Resolution] = []
        provider = FileProvider(policy_file)
        watcher = PolicyWatcher(provider, 0.01, changes.append)

        adopted = provider.load()
        # The writer lands between the read above and the adoption below. A
        # fingerprint taken at adoption time would be the new file's, and the
        # loop would treat the version it never read as already seen.
        _write(policy_file, BLOCK_POLICY)
        watcher.adopt(adopted)

        reloaded = watcher.check_once()

        assert reloaded is not None
        assert reloaded.spec.name == "block-policy"
        assert [c.spec.name for c in changes] == ["block-policy"]

    def test_touch_without_a_content_change_announces_nothing(self, policy_file: Path):
        changes: list[Resolution] = []
        watcher = PolicyWatcher(FileProvider(policy_file), 0.01, changes.append)
        watcher.adopt(FileProvider(policy_file).load())

        _write(policy_file, ALLOW_POLICY)

        assert watcher.check_once() is None
        assert changes == []

    def test_a_broken_edit_keeps_the_last_good_policy(self, policy_file: Path):
        errors: list[Exception] = []
        changes: list[Resolution] = []
        provider = FileProvider(policy_file)
        watcher = PolicyWatcher(provider, 0.01, changes.append, errors.append)
        good = provider.load()
        watcher.adopt(good)

        _write(policy_file, "hushspec: '0.1.0'\nname: broken\nbogus_key: true\n")

        assert watcher.check_once() is None
        assert watcher.current is good
        assert changes == []
        assert len(errors) == 1
        assert watcher.error_count == 1

        # ...and the next good edit is picked up, so a bad save is not terminal.
        _write(policy_file, BLOCK_POLICY)
        assert watcher.check_once() is not None
        assert watcher.current.spec.name == "block-policy"

    def test_a_rejected_change_is_retried_on_the_next_tick(self, policy_file: Path):
        errors: list[Exception] = []
        attempts: list[str] = []

        def refuse_once(resolution: Resolution) -> None:
            attempts.append(resolution.spec.name)
            if len(attempts) == 1:
                raise RuntimeError("downstream said no")

        provider = FileProvider(policy_file)
        watcher = PolicyWatcher(provider, 0.01, refuse_once, errors.append)
        good = provider.load()
        watcher.adopt(good)
        _write(policy_file, BLOCK_POLICY)

        assert watcher.check_once() is None
        assert watcher.current is good  # the rejected policy was not adopted
        assert len(errors) == 1

        assert watcher.check_once() is not None
        assert attempts == ["block-policy", "block-policy"]
        assert watcher.current.spec.name == "block-policy"

    def test_start_loads_and_stop_ends_the_thread(self, policy_file: Path):
        watcher = PolicyWatcher(FileProvider(policy_file), 0.01)
        initial = watcher.start()

        assert initial is not None
        assert watcher.running
        watcher.stop()
        assert not watcher.running

    def test_context_manager_reloads_in_the_background(self, policy_file: Path):
        reloaded = threading.Event()

        with PolicyWatcher(
            FileProvider(policy_file), 0.01, lambda _r: reloaded.set()
        ) as watcher:
            assert watcher.running
            _write(policy_file, BLOCK_POLICY)
            assert reloaded.wait(5.0), "watcher never picked up the change"
            assert watcher.current.spec.name == "block-policy"

        assert not watcher.running

    def test_start_twice_is_refused(self, policy_file: Path):
        with PolicyWatcher(FileProvider(policy_file), 0.01) as watcher:
            with pytest.raises(RuntimeError):
                watcher.start()

    def test_rejects_a_non_positive_interval(self, policy_file: Path):
        with pytest.raises(ValueError):
            PolicyWatcher(FileProvider(policy_file), 0)


class TestPanicSentinel:
    def test_tick_activates_panic_when_the_sentinel_appears(
        self, tmp_path: Path, policy_file: Path
    ):
        sentinel = tmp_path / DEFAULT_PANIC_SENTINEL
        panics: list[int] = []
        watcher = PolicyWatcher(
            FileProvider(policy_file),
            0.01,
            panic_sentinel=str(sentinel),
            on_panic=lambda: panics.append(1),
        )

        watcher.check_once()
        assert not is_panic_active()
        assert panics == []

        sentinel.write_text("")
        watcher.check_once()

        assert is_panic_active()
        assert panics == [1]

        # Reported once per activation, not once per tick.
        watcher.check_once()
        assert panics == [1]

    def test_no_sentinel_configured_means_no_check(self, policy_file: Path):
        PolicyWatcher(FileProvider(policy_file), 0.01).check_once()
        assert not is_panic_active()


# --------------------------------------------------------------------------- #
# Poller
# --------------------------------------------------------------------------- #


class TestPolicyPoller:
    def test_reloads_any_provider_on_a_content_change(self):
        documents = [ALLOW_POLICY, ALLOW_POLICY, BLOCK_POLICY]
        provider = CallbackProvider(lambda: documents.pop(0), source="test")
        changes: list[Resolution] = []
        poller = PolicyPoller(provider, 0.01, changes.append)

        first = poller.check_once()
        assert first is not None and first.spec.name == "allow-policy"
        assert poller.check_once() is None  # same content, no change
        third = poller.check_once()
        assert third is not None and third.spec.name == "block-policy"
        assert [c.spec.name for c in changes] == ["allow-policy", "block-policy"]

    def test_load_failure_keeps_the_last_good_policy(self):
        state = {"fail": False}

        def load() -> str:
            if state["fail"]:
                raise ConnectionError("config service is down")
            return ALLOW_POLICY

        errors: list[Exception] = []
        poller = PolicyPoller(CallbackProvider(load), 0.01, None, errors.append)
        good = poller.check_once()
        state["fail"] = True

        assert poller.check_once() is None
        assert poller.current is good
        assert isinstance(errors[0], ConnectionError)

    def test_ignores_a_fingerprint_it_should_not_trust(self, policy_file: Path):
        # A poller must reload even when the source *could* be fingerprinted:
        # that shortcut belongs to the watcher.
        poller = PolicyPoller(FileProvider(policy_file), 0.01)
        poller.adopt(FileProvider(policy_file).load())
        _write(policy_file, BLOCK_POLICY)
        os.utime(policy_file, ns=(0, 0))  # pretend the mtime never moved

        assert poller.check_once() is not None


# --------------------------------------------------------------------------- #
# HushGuard.from_provider
# --------------------------------------------------------------------------- #


class TestGuardFromProvider:
    def test_builds_a_guard_carrying_the_provider_evidence(self, tmp_path: Path):
        path = tmp_path / "leaf.yaml"
        path.write_text(EXTENDS_POLICY)
        provider = FileProvider(path)
        expected = provider.load()

        guard = HushGuard.from_provider(provider)

        assert guard.check(READ_FILE)
        assert guard.resolution is not None
        assert guard.resolution.content_hash == expected.content_hash
        # The chain the provider resolved, not a one-link re-resolution of the
        # merged document.
        assert len(guard.resolution.chain) == 2
        assert guard.watcher is None

    def test_watch_swaps_the_policy_the_guard_enforces(self, policy_file: Path):
        provider = FileProvider(policy_file)
        # A long interval: the background thread must not race the explicit tick.
        guard = HushGuard.from_provider(provider, watch=True, interval_s=3600)
        try:
            assert guard.watcher is not None and guard.watcher.running
            assert guard.check(READ_FILE)

            _write(policy_file, BLOCK_POLICY)
            assert guard.watcher.check_once() is not None

            assert not guard.check(READ_FILE)
            assert guard.resolution.spec.name == "block-policy"
        finally:
            guard.watcher.stop()

    def test_reload_notifies_the_observer_and_calls_back(self, policy_file: Path):
        observer = _RecordingObserver()
        reloaded: list[Resolution] = []
        provider = FileProvider(policy_file)
        guard = HushGuard.from_provider(
            provider,
            observer=observer,
            watch=True,
            interval_s=3600,
            on_reload=reloaded.append,
        )
        try:
            _write(policy_file, BLOCK_POLICY)
            guard.watcher.check_once()
        finally:
            guard.watcher.stop()

        assert [r.spec.name for r in reloaded] == ["block-policy"]
        assert len(observer.reloads) == 1
        event = observer.reloads[0]
        assert event["policy_name"] == "block-policy"
        assert event["previous_hash"] not in (None, event["content_hash"])

    def test_a_broken_edit_leaves_the_guard_enforcing(self, policy_file: Path):
        errors: list[Exception] = []
        provider = FileProvider(policy_file)
        guard = HushGuard.from_provider(
            provider, watch=True, interval_s=3600, on_error=errors.append
        )
        try:
            _write(policy_file, "hushspec: '0.1.0'\nname: broken\nbogus: 1\n")
            guard.watcher.check_once()
        finally:
            guard.watcher.stop()

        assert len(errors) == 1
        assert guard.check(READ_FILE)  # still the last good policy
        assert guard.resolution.spec.name == "allow-policy"

    def test_poll_drives_a_non_file_provider(self):
        documents = [ALLOW_POLICY, BLOCK_POLICY]
        provider = CallbackProvider(lambda: documents.pop(0), source="test")
        guard = HushGuard.from_provider(provider, poll=True, interval_s=3600)
        try:
            assert guard.check(READ_FILE)
            guard.watcher.check_once()
            assert not guard.check(READ_FILE)
        finally:
            guard.watcher.stop()

    def test_watch_and_poll_together_is_refused(self, policy_file: Path):
        with pytest.raises(ValueError):
            HushGuard.from_provider(FileProvider(policy_file), watch=True, poll=True)

    def test_require_signature_refuses_an_unverified_resolution(self, policy_file: Path):
        # The provider resolved without demanding a signature; the guard demands
        # one, and must not enforce a policy nobody proved.
        guard = HushGuard.from_provider(FileProvider(policy_file), require_signature=True)

        assert guard.refusal is not None
        assert not guard.check(READ_FILE)
        assert guard.evaluate(READ_FILE).decision == Decision.DENY

    def test_swap_resolution_rejects_an_unresolved_document(self, policy_file: Path):
        from hushspec.parse import parse_or_raise
        from hushspec.resolve import Resolution as _Resolution

        guard = HushGuard.from_provider(FileProvider(policy_file))
        unresolved = parse_or_raise(EXTENDS_POLICY)
        bogus = _Resolution(spec=unresolved, content_hash="sha256:" + "0" * 64)

        with pytest.raises(ValueError):
            guard.swap_resolution(bogus)
        assert guard.check(READ_FILE)


class TestGuardLifecycle:
    """A guard that owns a reload loop can be closed."""

    def test_close_stops_the_watcher(self, policy_file: Path):
        guard = HushGuard.from_provider(FileProvider(policy_file), watch=True)
        assert guard.watcher is not None
        assert guard.watcher.running is True

        guard.close()
        assert guard.watcher.running is False

    def test_close_is_safe_without_a_watcher(self):
        guard = HushGuard.from_yaml(ALLOW_POLICY)
        assert guard.watcher is None
        guard.close()
        guard.close()

    def test_the_guard_is_a_context_manager(self, policy_file: Path):
        with HushGuard.from_provider(FileProvider(policy_file), watch=True) as guard:
            watcher = guard.watcher
            assert watcher.running is True
        assert watcher.running is False
