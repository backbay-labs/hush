"""Where a guard's policy comes from, and how it is kept current.

A :class:`PolicyProvider` is the seam between an enforcement point and the
document it enforces: it answers :meth:`~PolicyProvider.load` with a
:class:`~hushspec.resolve.Resolution` -- the resolved policy *and* the evidence
gathered while resolving it -- so a guard built from a provider carries the same
content hash, ``extends`` chain and signature status into every receipt it
writes.

:class:`PolicyWatcher` and :class:`PolicyPoller` keep that policy current.
Both run one tick at a time (:meth:`~_ReloadLoop.check_once`), on a daemon
thread when started, and both fail *safe* rather than open: a document that
cannot be read, parsed, resolved, verified or applied leaves the policy already
in force untouched and is reported through ``on_error``. The last good policy is
never replaced by a bad one, and never by nothing.

The difference between them is only how much work a tick does: the watcher
consults the file's mtime and size first and reloads only when they move, while
the poller reloads on every tick because a provider's source need not be a file
with a mtime at all.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import (
    Any,
    Callable,
    Optional,
    Protocol,
    TypeVar,
    Union,
    runtime_checkable,
)

from hushspec.evaluate import check_panic_sentinel
from hushspec.middleware import resolve_policy_resolution
from hushspec.parse import parse_or_raise
from hushspec.resolve import Resolution, ResolveOptions, Resolver

__all__ = [
    "DEFAULT_PANIC_SENTINEL",
    "DEFAULT_WATCH_INTERVAL_S",
    "DEFAULT_POLL_INTERVAL_S",
    "PolicyProvider",
    "FileProvider",
    "CallbackProvider",
    "PolicyWatcher",
    "PolicyPoller",
]

#: The sentinel file ``h2h panic`` creates, and the one a loop consults when
#: asked to check for one without being told where to look.
DEFAULT_PANIC_SENTINEL = ".hushspec_panic"

#: A watcher tick is a ``stat`` unless the file moved, so it can be frequent.
DEFAULT_WATCH_INTERVAL_S = 1.0

#: A poller tick is a full load -- possibly a remote one -- so it is not.
DEFAULT_POLL_INTERVAL_S = 60.0

ChangeHandler = Callable[[Resolution], None]
ErrorHandler = Callable[[Exception], None]


@runtime_checkable
class PolicyProvider(Protocol):
    """Something a policy can be loaded from, with its evidence.

    ``source`` names the origin (a path, a URL, ``memory``) for error messages
    and for the chain a receipt records; :meth:`load` returns the resolved
    policy or raises. A provider that cannot produce a policy must raise rather
    than return a partial or unresolved one -- a guard never holds a document
    whose ``extends`` is still set.
    """

    source: str

    def load(self) -> Resolution:
        """Load, resolve and (as its options demand) verify the policy."""
        ...


class FileProvider:
    """A policy file on disk, resolved against its own directory.

    ``options`` carries the trust requirements of the load -- ``require_signature``
    and the keyring -- so a provider driving hot reload applies the same proof to
    every reloaded document that the first load demanded. Relative ``extends``
    references resolve against the file's directory and a detached signature is
    looked up next to it (``<path>.sig``), exactly as
    :meth:`hushspec.middleware.HushGuard.from_file` does.
    """

    def __init__(
        self,
        path: Union[str, Path],
        options: Optional[ResolveOptions] = None,
        *,
        loader: Optional[Resolver] = None,
        base_dir: Optional[str] = None,
    ) -> None:
        self.path = Path(path)
        #: The absolute path the leaf resolves and verifies from.
        self.source = str(self.path.resolve())
        self.options = options
        self._loader = loader
        self._base_dir = base_dir or str(Path(self.source).parent)

    def load(self) -> Resolution:
        spec = parse_or_raise(self.path.read_text(encoding="utf-8"))
        return resolve_policy_resolution(
            spec,
            loader=self._loader,
            base_dir=self._base_dir,
            source=self.source,
            options=self.options,
        )

    def fingerprint(self) -> Optional[tuple[int, int]]:
        """``(mtime_ns, size)``, or ``None`` when the file cannot be stat'd.

        ``None`` means "cannot tell", so a watcher reloads rather than assuming
        nothing changed: the cheap check may never stand in for the real one.
        """
        try:
            stat = self.path.stat()
        except OSError:
            return None
        return (stat.st_mtime_ns, stat.st_size)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"FileProvider({self.source!r})"


class CallbackProvider:
    """A provider built from a callable, for sources that are not files.

    The callable returns either a :class:`~hushspec.resolve.Resolution` or the
    policy text, which is parsed and resolved here; anything it raises is
    reported the same way a file read failure would be.
    """

    def __init__(
        self,
        load: Callable[[], Union[Resolution, str]],
        source: str = "memory",
        options: Optional[ResolveOptions] = None,
        *,
        loader: Optional[Resolver] = None,
        base_dir: Optional[str] = None,
    ) -> None:
        self._load = load
        self.source = source
        self.options = options
        self._loader = loader
        self._base_dir = base_dir

    def load(self) -> Resolution:
        loaded = self._load()
        if isinstance(loaded, Resolution):
            return loaded
        spec = parse_or_raise(loaded)
        # `source` stays unset: a document that came from a callable has no file
        # of its own, so a relative `extends` needs an explicit `base_dir` (or a
        # loader) exactly as `HushGuard.from_yaml` requires one.
        return resolve_policy_resolution(
            spec,
            loader=self._loader,
            base_dir=self._base_dir,
            options=self.options,
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"CallbackProvider({self.source!r})"


#: So ``with PolicyWatcher(...) as watcher`` types as a ``PolicyWatcher``
#: from the one ``__enter__`` both subclasses share.
_LoopT = TypeVar("_LoopT", bound="_ReloadLoop")


class _ReloadLoop:
    """The shared body of the watcher and the poller.

    State advances only on a tick that succeeded end to end: loaded, resolved,
    and accepted by ``on_change``. A tick that fails anywhere leaves the last
    good resolution -- and the fingerprint that would suppress a retry -- exactly
    as they were, so the next tick tries the same document again.
    """

    #: Consult the source's cheap fingerprint before loading.
    _use_fingerprint = False

    def __init__(
        self,
        provider: PolicyProvider,
        interval_s: float = DEFAULT_POLL_INTERVAL_S,
        on_change: Optional[ChangeHandler] = None,
        on_error: Optional[ErrorHandler] = None,
        *,
        panic_sentinel: Optional[Union[str, bool]] = None,
        on_panic: Optional[Callable[[], None]] = None,
    ) -> None:
        if interval_s <= 0:
            raise ValueError(f"interval_s must be positive: {interval_s!r}")
        self._provider = provider
        self._interval_s = interval_s
        self._on_change = on_change
        self._on_error = on_error
        if panic_sentinel is True:
            panic_sentinel = DEFAULT_PANIC_SENTINEL
        self._panic_sentinel: Optional[str] = (
            None if panic_sentinel in (None, False) else str(panic_sentinel)
        )
        self._on_panic = on_panic
        self._panic_reported = False
        self._lock = threading.RLock()
        #: Serializes whole ticks. Reentrant so a tick may be driven from an
        #: ``on_change`` callback without deadlocking; across threads it stops
        #: two ticks from loading at once and the slower one from
        #: overwriting the newer policy.
        self._tick_lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._current: Optional[Resolution] = None
        self._fingerprint: Any = None
        #: Ticks that changed the policy, and ticks that failed. Counters make a
        #: background loop observable without a callback per outcome.
        self.reload_count = 0
        self.error_count = 0

    # -- state ------------------------------------------------------------- #

    @property
    def provider(self) -> PolicyProvider:
        return self._provider

    @property
    def source(self) -> str:
        return self._provider.source

    @property
    def interval_s(self) -> float:
        return self._interval_s

    @property
    def current(self) -> Optional[Resolution]:
        """The last resolution that loaded, resolved and applied cleanly."""
        with self._lock:
            return self._current

    @property
    def content_hash(self) -> Optional[str]:
        with self._lock:
            return self._current.content_hash if self._current is not None else None

    @property
    def running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def adopt(self, resolution: Resolution) -> None:
        """Seed the loop with a policy loaded elsewhere, without calling back.

        Used when a guard was already built from ``provider.load()``: the loop
        starts from what is in force rather than announcing it as a change.
        """
        with self._lock:
            self._current = resolution
            self._fingerprint = self._stat_fingerprint()

    # -- ticking ------------------------------------------------------------ #

    def check_once(self) -> Optional[Resolution]:
        """Run one tick. Returns the new resolution, or ``None`` for no change.

        Never raises: a failed tick is reported through ``on_error`` and changes
        nothing, because an enforcement point that loses its policy on a bad
        edit is worse than one running a slightly stale good policy.

        Ticks are serialized, so driving one by hand while the loop is running
        cannot interleave two loads and let the slower one win.
        """
        with self._tick_lock:
            return self._tick()

    def _tick(self) -> Optional[Resolution]:
        try:
            self._check_panic()
            fingerprint = self._stat_fingerprint()
            with self._lock:
                unchanged = (
                    self._use_fingerprint
                    and fingerprint is not None
                    and fingerprint == self._fingerprint
                )
            if unchanged:
                return None
            resolution = self._provider.load()
        except Exception as exc:  # noqa: BLE001 - every failure is reportable
            self._report(exc)
            return None

        with self._lock:
            current = self._current
        if current is not None and resolution.content_hash == current.content_hash:
            # The file was touched but says the same thing: remember the new
            # fingerprint so the next tick is a stat again, and announce nothing.
            with self._lock:
                self._fingerprint = fingerprint
            return None

        if self._on_change is not None:
            try:
                self._on_change(resolution)
            except Exception as exc:  # noqa: BLE001
                # The new policy was rejected downstream (it would not compile,
                # or a guard refused it). Keep the last good one and retry.
                self._report(exc)
                return None

        with self._lock:
            self._current = resolution
            self._fingerprint = fingerprint
            self.reload_count += 1
        return resolution

    def _stat_fingerprint(self) -> Any:
        if not self._use_fingerprint:
            return None
        fingerprint = getattr(self._provider, "fingerprint", None)
        return fingerprint() if callable(fingerprint) else None

    def _check_panic(self) -> None:
        """Consult the kill switch before doing anything else with the policy.

        :func:`~hushspec.evaluate.check_panic_sentinel` latches panic mode on and
        fails closed on any stat error it cannot read as "absent".
        """
        if self._panic_sentinel is None:
            return
        active = check_panic_sentinel(self._panic_sentinel)
        with self._lock:
            announce = active and not self._panic_reported
            self._panic_reported = active
        if announce and self._on_panic is not None:
            try:
                self._on_panic()
            except Exception as exc:  # noqa: BLE001
                self._report(exc)

    def _report(self, exc: Exception) -> None:
        with self._lock:
            self.error_count += 1
        if self._on_error is not None:
            try:
                self._on_error(exc)
            except Exception:  # noqa: BLE001 - a broken handler is not fatal
                pass

    # -- lifecycle ---------------------------------------------------------- #

    def start(self, *, load: bool = True) -> Optional[Resolution]:
        """Load once, then tick every ``interval_s`` on a daemon thread.

        The initial load raises: a loop that never had a policy has nothing to
        fall back to, so the caller must hear about it. Every *later* failure is
        reported through ``on_error`` instead. Pass ``load=False`` when the
        policy is already in force (see :meth:`adopt`).
        """
        if self.running:
            raise RuntimeError("already started")
        initial: Optional[Resolution] = None
        if load:
            initial = self._provider.load()
            self.adopt(initial)
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            name=f"hushspec-{type(self).__name__.lower()}",
            daemon=True,
        )
        self._thread.start()
        return initial

    def stop(self, timeout: Optional[float] = 5.0) -> bool:
        """Stop ticking. Safe to call more than once, and from any thread.

        Returns whether the loop thread is gone. A join that times out keeps
        the thread reference rather than dropping it: forgetting a thread that
        is still inside a tick would make :attr:`running` report ``False`` and
        let a later :meth:`start` run a second loop alongside the first.
        Calling this from inside a tick returns ``False`` -- the loop exits when
        that tick returns, but a thread cannot join itself.
        """
        self._stop.set()
        thread = self._thread
        if thread is None:
            return True
        if thread is threading.current_thread():
            return False
        thread.join(timeout)
        if thread.is_alive():
            return False
        with self._lock:
            if self._thread is thread:
                self._thread = None
        return True

    def _run(self) -> None:
        # wait() returns True only when stop() set the event, so this both
        # sleeps between ticks and wakes immediately on shutdown.
        while not self._stop.wait(self._interval_s):
            try:
                self.check_once()
            except BaseException as exc:  # noqa: BLE001
                # check_once() reports its own failures, so reaching here means
                # something outside a tick's control failed. The loop must
                # survive it: a dead reload thread silently freezes the policy.
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                self._report(exc)

    def __enter__(self: _LoopT) -> _LoopT:
        self.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.stop()


class PolicyWatcher(_ReloadLoop):
    """Watches a policy file, reloading it when its bytes change.

    Each tick stats the file first: when mtime and size are unchanged nothing is
    read, parsed or hashed. When they have moved the policy is loaded and its
    content hash compared, so a touch that does not change the document -- or an
    editor's save of identical bytes -- announces nothing.

        >>> guard = HushGuard.from_provider(FileProvider("policy.yaml"), watch=True)

    Or directly, driving anything::

        with PolicyWatcher(FileProvider(path), 0.5, on_change=apply) as watcher:
            ...
    """

    _use_fingerprint = True

    def __init__(
        self,
        provider: PolicyProvider,
        interval_s: float = DEFAULT_WATCH_INTERVAL_S,
        on_change: Optional[ChangeHandler] = None,
        on_error: Optional[ErrorHandler] = None,
        *,
        panic_sentinel: Optional[Union[str, bool]] = None,
        on_panic: Optional[Callable[[], None]] = None,
    ) -> None:
        super().__init__(
            provider,
            interval_s,
            on_change,
            on_error,
            panic_sentinel=panic_sentinel,
            on_panic=on_panic,
        )

class PolicyPoller(_ReloadLoop):
    """Reloads from any provider on a fixed interval.

    Unlike :class:`PolicyWatcher` it makes no assumption that the source is a
    file, so every tick is a full load; only a changed content hash is a change.
    Use it for providers whose source cannot be cheaply fingerprinted.
    """

    _use_fingerprint = False

