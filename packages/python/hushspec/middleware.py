from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Sequence, Union, TYPE_CHECKING

from hushspec.compiled import CompiledPolicy, compile_policy
from hushspec.evaluate import (
    Decision,
    EvaluationAction,
    EvaluationResult,
    args_size_of,
    is_panic_active,
)
from hushspec.generated_contract import EXTENSION_KEYS, RULE_KEYS
from hushspec.parse import parse_or_raise
from hushspec.resolve import (
    PolicyVerificationError,
    ResolveOptions,
    Resolution,
    Resolver,
    SignatureStatus,
    VerifyOptions,
    create_builtin_loader,
    create_composite_loader,
    resolve_with_options_or_raise,
)
from hushspec.receipt import POLICY_UNVERIFIED_RULE
from hushspec.schema import HushSpec
from hushspec.signing import Keyring

if TYPE_CHECKING:
    from hushspec.observer import EvaluationObserver
    from hushspec.provider import PolicyProvider, PolicyPoller, PolicyWatcher
    from hushspec.receipt import (
        Actor,
        AuditConfig,
        AuditContext,
        DecisionReceipt,
        EnforcementSummary,
    )
    from hushspec.sinks import ReceiptSink

WarnHandler = Callable[[EvaluationResult, EvaluationAction], bool]

_ENFORCEMENT_MODES = frozenset(("enforce", "monitor"))

#: ``matched_rule`` of the denial a guard returns while it is refusing to
#: enforce an unverified policy (signing spec section 6.5, receipt spec 4.5).
#: Like the panic sentinel it is a guard-level rule, not a policy rule, so it
#: can never be relaxed by an enforcement override. It is the same reserved
#: name the receipt carries -- one spelling per fact.
POLICY_SIGNATURE_RULE = POLICY_UNVERIFIED_RULE

#: ``matched_rule`` for a denial issued because an enforcement point's policy
#: provider cannot serve a policy to evaluate against: it has not loaded one,
#: it handed back a document that still declares ``extends``, or it failed when
#: asked (core spec 6.2).
#:
#: A :class:`HushGuard` takes its policy from a provider that pushes each
#: reload into :meth:`HushGuard.swap_resolution`, so a reload that fails leaves
#: the policy already in force and the guard never reaches that state. The
#: value is exported for readers of receipts an enforcement point of the other
#: kind emitted. Distinct from :data:`POLICY_SIGNATURE_RULE`, which means the
#: policy was obtained and rejected.
POLICY_PROVIDER_RULE = "__hushspec_policy_provider__"


@dataclass
class EnforcementConfig:
    mode: str = "enforce"                                     # 'enforce' | 'monitor'
    overrides: dict[str, str] = field(default_factory=dict)   # rule-path prefix -> mode


@dataclass
class GateOutcome:
    result: EvaluationResult
    proceed: bool
    enforcement: "EnforcementSummary"


def matches_rule_path_prefix(matched_rule: str, key: str) -> bool:
    """True when matched_rule equals key or continues past it at a '.' or '[' boundary."""
    if matched_rule == key:
        return True
    return matched_rule.startswith(key + ".") or matched_rule.startswith(key + "[")


def _validate_enforcement_config(config: EnforcementConfig, observable: bool) -> None:
    """Reject a configuration an operator would misread.

    *observable* says whether a shadow decision is recorded anywhere: monitor
    mode without an observer, or without a sink that auditing actually writes
    receipts to, is refused, because it would silently allow everything the
    policy denies.
    """
    if config.mode not in _ENFORCEMENT_MODES:
        raise ValueError(f"invalid enforcement mode: {config.mode!r}")
    monitor_reachable = config.mode == "monitor"
    for key, value in config.overrides.items():
        if value not in _ENFORCEMENT_MODES:
            raise ValueError(f"invalid enforcement mode for override {key!r}: {value!r}")
        if value == "monitor":
            monitor_reachable = True
        if key.startswith("rules."):
            parts = key.split(".")
            segment = parts[1] if len(parts) > 1 else ""
            if segment not in RULE_KEYS:
                raise ValueError(
                    f"unknown rule in enforcement override {key!r}: {segment!r} is not a core rule"
                )
        elif key.startswith("extensions."):
            parts = key.split(".")
            segment = parts[1] if len(parts) > 1 else ""
            # Only the top extension segment (posture/origins/detection) is validated
            # here; deeper segments are policy-dependent and hot-swappable, mirroring
            # how "rules." overrides only validate their top segment.
            if segment not in EXTENSION_KEYS:
                raise ValueError(
                    f"unknown extension in enforcement override {key!r}: {segment!r} is not a core extension"
                )
        else:
            raise ValueError(
                f"enforcement override keys must start with 'rules.' or 'extensions.': {key!r}"
            )
    if monitor_reachable and not observable:
        raise ValueError(
            "monitor mode requires an observer or a receipt sink: "
            "shadow decisions would be unobservable"
        )


def resolve_policy_resolution(
    policy: HushSpec,
    *,
    loader: Optional[Resolver] = None,
    base_dir: Optional[str] = None,
    source: Optional[str] = None,
    options: Optional[ResolveOptions] = None,
) -> Resolution:
    """Resolve a policy's ``extends`` chain and gather its evidence, or raise.

    Every entry point into :class:`HushGuard` funnels through this: the guard
    must never hold a spec whose ``extends`` is still set. An unresolved leaf
    silently drops every rule block its base declares -- ``library/general/
    recommended.yaml`` extends ``builtin:default`` and declares no
    ``forbidden_paths``, so evaluating it unresolved would allow reads of
    ``~/.ssh/id_rsa`` -- and hashes the wrong document into every receipt.
    Fail closed: if the base cannot be loaded, no evaluation happens at all.

    ``source`` is the policy's own location, when it has one. It is both what a
    relative ``extends`` resolves against and what a detached signature is
    looked up next to (``<source>.sig``), so ``HushGuard.from_file`` passes the
    real path rather than the ``base_dir`` placeholder.

    Raises :class:`~hushspec.resolve.PolicyVerificationError` (unwrapped, so a
    caller can read its ``status``) when a hop fails its digest pin or its
    signature, and :class:`ValueError` when the chain cannot be resolved.
    """
    if loader is None:
        loader = (
            create_composite_loader()
            if base_dir is not None or source is not None
            else create_builtin_loader()
        )
    if source is None and base_dir is not None:
        # Resolution treats `source` as the *file* a relative reference resolves
        # from, so point it at a placeholder inside base_dir.
        source = str(Path(base_dir).resolve() / "<policy>")

    try:
        resolution = resolve_with_options_or_raise(
            policy, source=source, loader=loader, options=options
        )
    except PolicyVerificationError:
        raise
    except ValueError as exc:
        raise ValueError(
            f"failed to resolve policy 'extends: {policy.extends}': {exc}"
        ) from exc
    if resolution.spec.extends is not None:
        raise ValueError(
            f"failed to resolve policy 'extends: {policy.extends}': "
            "resolver returned an unresolved policy"
        )
    return resolution


def resolve_policy_or_raise(
    policy: HushSpec,
    *,
    loader: Optional[Resolver] = None,
    base_dir: Optional[str] = None,
) -> HushSpec:
    """Resolve a policy's ``extends`` chain, or raise. Returns just the document.

    A thin wrapper over :func:`resolve_policy_resolution` with default options:
    no signature is required and none is looked for.
    """
    return resolve_policy_resolution(policy, loader=loader, base_dir=base_dir).spec


def _build_resolve_options(
    *,
    require_signature: bool,
    keyring: Any,
    trusted_keys: Optional[Sequence[str]],
    verify: Optional[VerifyOptions],
) -> ResolveOptions:
    """Fold a guard's trust settings into :class:`ResolveOptions`.

    ``trusted_keys`` is the convenience form: bare SPKI public-key PEMs, which
    become a keyring whose ids are recomputed from the key bits (signing spec
    section 5.3). Pass ``keyring`` when the deployment has a real keyring
    document with retirement and revocation.
    """
    if keyring is not None and trusted_keys:
        raise ValueError("pass either `keyring` or `trusted_keys`, not both")
    if isinstance(trusted_keys, str):
        # A bare PEM is a sequence of characters, so without this a single key
        # passed unwrapped would be read as one key per character.
        trusted_keys = [trusted_keys]
    if trusted_keys:
        keyring = Keyring(
            keys=tuple(
                Keyring.from_public_key(pem).keys[0] for pem in trusted_keys
            )
        )
    return ResolveOptions(
        require_signature=require_signature,
        keyring=keyring,
        verify=verify,
    )


@dataclass(frozen=True)
class _GuardState:
    """The policy a guard is enforcing, as one immutable unit.

    A hot reload replaces the whole object in a single attribute store, so an
    evaluation on another thread sees either every field of the outgoing
    policy or every field of the incoming one. Read field by field, a swap
    landing mid-evaluation could pair one policy's decision with another
    policy's content hash -- which is exactly what the hash in a receipt is
    there to rule out (receipt spec 4.2).
    """

    policy: HushSpec
    compiled: CompiledPolicy
    resolution: Optional[Resolution]
    #: Why the guard is denying everything, or ``None`` when it is enforcing.
    refusal: Optional[SignatureStatus]
    #: The document a refusal is about: merged and hashed, never verified, and
    #: never evaluated. It is what a refusal receipt names (signing spec
    #: section 6.5), which is why it is kept apart from :attr:`resolution`.
    refused: Optional[Resolution]
    policy_hash: Optional[str]


class HushSpecDenied(Exception):
    def __init__(self, result: EvaluationResult) -> None:
        self.result = result
        reason = result.reason or result.matched_rule or "policy denial"
        super().__init__(f"Action denied: {reason}")


class HushGuard:
    """Fail-closed policy guard: wraps evaluate / check / enforce semantics."""

    def __init__(
        self,
        policy: Union[HushSpec, Resolution],
        on_warn: Optional[WarnHandler] = None,
        observer: Optional["EvaluationObserver"] = None,
        enforcement: Optional[EnforcementConfig] = None,
        sink: Optional["ReceiptSink"] = None,
        audit: Optional["AuditConfig"] = None,
        loader: Optional[Resolver] = None,
        base_dir: Optional[str] = None,
        source: Optional[str] = None,
        require_signature: bool = False,
        keyring: Any = None,
        trusted_keys: Optional[Sequence[str]] = None,
        verify: Optional[VerifyOptions] = None,
        actor: Optional["Actor"] = None,
    ) -> None:
        config = enforcement or EnforcementConfig()
        if audit is None:
            from hushspec.receipt import AuditConfig
            audit = AuditConfig()
        # A sink only counts as observability when auditing is on: with
        # ``enabled=False`` no receipt is built, so the sink is handed nothing
        # and the shadow decision leaves no trace at all.
        observable = (sink is not None and audit.enabled) or observer is not None
        _validate_enforcement_config(config, observable)
        self._enforcement_mode = config.mode
        self._enforcement_overrides = dict(config.overrides)
        self._sink = sink
        self._audit = audit
        #: Who the guard evaluates for (receipt spec 4.1). Every receipt it
        #: emits carries it; an empty actor is omitted from receipts.
        self._actor = actor
        self._resolve_loader = loader
        self._resolve_base_dir = base_dir
        self._resolve_source = source
        self._resolve_options = _build_resolve_options(
            require_signature=require_signature,
            keyring=keyring,
            trusted_keys=trusted_keys,
            verify=verify,
        )
        self._watcher: Any = None
        resolution: Optional[Resolution] = None
        refused: Optional[Resolution] = None
        refusal: Optional[SignatureStatus] = None
        # Resolve before anything else touches the spec: a guard never holds an
        # unresolved document, and the receipt hash covers the resolved policy.
        # A policy that cannot be *verified* does not raise -- the guard has to
        # stay alive to deny, and to record the refusal (signing spec 6.5).
        # A chain that would not merge at all does raise: there is no document
        # to refuse against, so there is nothing a receipt could name.
        try:
            resolution = (
                self._adopt_resolution(policy)
                if isinstance(policy, Resolution)
                else self._resolve(policy)
            )
            resolved = resolution.spec
        except PolicyVerificationError as exc:
            if exc.resolution is None:
                raise
            refusal = exc.status
            refused = exc.resolution
            # A deny-everything policy as a backstop: nothing should reach it
            # (every evaluation short-circuits on the refusal), and if anything
            # ever did, it must not be the document that failed verification.
            from hushspec.evaluate import panic_policy
            resolved = panic_policy()
        # Compile once, here: the guard evaluates the same document over and
        # over, so its patterns, matchers and conditions are prepared at load
        # time rather than per action. Lenient, because a pattern outside the
        # regex profile must deny the actions that reach it (the reference
        # behaviour), not stop the guard from loading.
        self._state = _GuardState(
            policy=resolved,
            compiled=compile_policy(
                resolution if resolution is not None else resolved,
                strict=False,
            ),
            resolution=resolution,
            refusal=refusal,
            refused=refused,
            policy_hash=(
                resolution.content_hash if resolution is not None else None
            ),
        )
        self._on_warn: WarnHandler = on_warn or (lambda _r, _a: False)
        self._observable_evaluator = None
        if observer is not None:
            from hushspec.observer import ObservableEvaluator
            self._observable_evaluator = ObservableEvaluator(
                redact_content=self._audit.redact_content
            )
            self._observable_evaluator.add_observer(observer)
            if self._state.refusal is None:
                self._observable_evaluator.notify_policy_loaded(
                    self._state.policy.name, self._state.policy_hash
                )
            # A refused guard announces no policy: it loaded none. The backstop
            # deny-all document is an implementation detail, not something an
            # observer should record as the policy in force.
        # The log records which policy came into force before any receipt
        # evaluated under it (log spec section 6). A refused guard loaded none.
        if self._state.refusal is None:
            self._record_policy_event(loaded=True)

    @classmethod
    def from_file(
        cls,
        path: str,
        on_warn: Optional[WarnHandler] = None,
        observer: Optional["EvaluationObserver"] = None,
        enforcement: Optional[EnforcementConfig] = None,
        sink: Optional["ReceiptSink"] = None,
        audit: Optional["AuditConfig"] = None,
        loader: Optional[Resolver] = None,
        base_dir: Optional[str] = None,
        require_signature: bool = False,
        keyring: Any = None,
        trusted_keys: Optional[Sequence[str]] = None,
        verify: Optional[VerifyOptions] = None,
        actor: Optional["Actor"] = None,
    ) -> HushGuard:
        """Load a policy file and resolve its ``extends`` chain.

        Relative references resolve against the policy file's own directory
        (overridable with ``base_dir``/``loader``); ``builtin:`` references come
        from the embedded rulesets. Raises if the chain cannot be resolved.

        The file's own path is the ``source`` of the leaf, so its detached
        signature is looked up at ``<path>.sig`` (then ``<stem>.sig``) when a
        keyring is configured.
        """
        with open(path, encoding="utf-8") as f:
            spec = parse_or_raise(f.read())
        resolved_path = str(Path(path).resolve())
        if base_dir is None:
            base_dir = str(Path(resolved_path).parent)
        return cls(
            spec,
            on_warn,
            observer=observer,
            enforcement=enforcement,
            sink=sink,
            audit=audit,
            loader=loader,
            base_dir=base_dir,
            source=resolved_path,
            require_signature=require_signature,
            keyring=keyring,
            trusted_keys=trusted_keys,
            verify=verify,
            actor=actor,
        )

    @classmethod
    def from_yaml(
        cls,
        yaml_str: str,
        on_warn: Optional[WarnHandler] = None,
        observer: Optional["EvaluationObserver"] = None,
        enforcement: Optional[EnforcementConfig] = None,
        sink: Optional["ReceiptSink"] = None,
        audit: Optional["AuditConfig"] = None,
        loader: Optional[Resolver] = None,
        base_dir: Optional[str] = None,
        require_signature: bool = False,
        keyring: Any = None,
        trusted_keys: Optional[Sequence[str]] = None,
        verify: Optional[VerifyOptions] = None,
        actor: Optional["Actor"] = None,
    ) -> HushGuard:
        """Parse a policy document and resolve its ``extends`` chain.

        ``builtin:`` references resolve out of the box; file references need an
        explicit ``base_dir`` (or ``loader``) since a YAML string has no
        directory of its own. Raises if the chain cannot be resolved.

        A document with no file of its own has no ``<source>.sig`` either, so
        under ``require_signature`` it can only be admitted through a caller
        supplied locator; otherwise the guard refuses it.
        """
        spec = parse_or_raise(yaml_str)
        return cls(
            spec,
            on_warn,
            observer=observer,
            enforcement=enforcement,
            sink=sink,
            audit=audit,
            loader=loader,
            base_dir=base_dir,
            require_signature=require_signature,
            keyring=keyring,
            trusted_keys=trusted_keys,
            verify=verify,
            actor=actor,
        )

    def _resolve(self, policy: HushSpec) -> Resolution:
        return resolve_policy_resolution(
            policy,
            loader=self._resolve_loader,
            base_dir=self._resolve_base_dir,
            source=self._resolve_source,
            options=self._resolve_options,
        )

    def _adopt_resolution(self, resolution: Resolution) -> Resolution:
        """Accept a resolution produced elsewhere, or refuse it.

        A provider resolves under its own :class:`~hushspec.resolve.ResolveOptions`,
        so the guard re-checks the two things it would otherwise have proved
        itself: that the document is actually resolved, and -- when this guard
        was built with ``require_signature`` -- that every hop proved itself.
        Without the second check a signature requirement would be silently
        dropped by passing the policy in pre-resolved, which is precisely the
        fail-open the requirement exists to prevent.
        """
        if resolution.spec.extends is not None:
            raise ValueError(
                "provider returned an unresolved policy "
                f"('extends: {resolution.spec.extends}')"
            )
        unproven = self._unproven_hop(resolution)
        if unproven is not None:
            source, status = unproven
            raise PolicyVerificationError(
                "policy was resolved without a verified signature, but this "
                "guard requires one",
                source=source,
                status=status,
                resolution=resolution,
            )
        return resolution

    def _unproven_hop(
        self, resolution: Resolution
    ) -> Optional[tuple[str, SignatureStatus]]:
        """The first hop of an adopted chain that has not proved itself.

        ``builtin:`` hops are exempt, as they are during resolution: they are
        embedded in the SDK, not loaded from anywhere signable. Every other hop
        proves itself by a verified signature on its link. A hop proved by a
        digest pin cannot be re-checked from a resolution -- the chain records
        the hash each hop had, not the digest its child pinned it to -- so an
        adopted chain has to carry signatures.
        """
        if not self._resolve_options.require_signature:
            return None
        for link in resolution.chain:
            if link.source.startswith("builtin:"):
                continue
            if link.signature is not None and link.signature.verified:
                continue
            status = link.signature or SignatureStatus(
                verified=False, reason="missing_signature"
            )
            return link.source, status
        return None

    @classmethod
    def from_provider(
        cls,
        provider: "PolicyProvider",
        on_warn: Optional[WarnHandler] = None,
        observer: Optional["EvaluationObserver"] = None,
        enforcement: Optional[EnforcementConfig] = None,
        sink: Optional["ReceiptSink"] = None,
        audit: Optional["AuditConfig"] = None,
        actor: Optional["Actor"] = None,
        require_signature: bool = False,
        *,
        watch: bool = False,
        poll: bool = False,
        interval_s: Optional[float] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
        on_reload: Optional[Callable[[Resolution], None]] = None,
        panic_sentinel: Optional[Union[str, bool]] = None,
    ) -> HushGuard:
        """Build a guard from a provider, optionally keeping it hot.

        The provider has already resolved the policy and gathered its evidence,
        so nothing is resolved twice: the chain hashes and signature outcome it
        returned are what every receipt carries. ``require_signature`` here does
        not re-run verification (the provider's ``options`` do that) -- it
        asserts that the resolution the provider handed over actually verified,
        so a misconfigured provider cannot quietly downgrade a guard.

        With ``watch=True`` a :class:`~hushspec.provider.PolicyWatcher` reloads
        the policy when the file changes; with ``poll=True`` a
        :class:`~hushspec.provider.PolicyPoller` reloads it on a fixed interval
        for sources that are not files. Either one calls :meth:`swap_resolution`
        on every change and leaves the policy in force untouched when a reload
        fails, reporting the failure through ``on_error``. The loop is available
        as :attr:`watcher`; close the guard (or use it as a context manager)
        when it is done, which stops the loop.

        The *first* load is not caught: whatever the provider raises propagates,
        because a guard with no policy at all has nothing to enforce.
        """
        from hushspec.provider import (
            DEFAULT_POLL_INTERVAL_S,
            DEFAULT_WATCH_INTERVAL_S,
            PolicyPoller,
            PolicyWatcher,
        )

        if watch and poll:
            raise ValueError("pass either `watch` or `poll`, not both")

        guard = cls(
            provider.load(),
            on_warn,
            observer=observer,
            enforcement=enforcement,
            sink=sink,
            audit=audit,
            actor=actor,
            require_signature=require_signature,
        )
        if not (watch or poll):
            return guard

        def apply(resolution: Resolution) -> None:
            guard.swap_resolution(resolution)
            if on_reload is not None:
                on_reload(resolution)

        loop_cls = PolicyWatcher if watch else PolicyPoller
        default_interval = (
            DEFAULT_WATCH_INTERVAL_S if watch else DEFAULT_POLL_INTERVAL_S
        )
        loop = loop_cls(
            provider,
            interval_s if interval_s is not None else default_interval,
            apply,
            on_error,
            panic_sentinel=panic_sentinel,
        )
        # The guard already holds what the provider loaded, so the loop starts
        # from it rather than announcing it as a change. A guard that refused
        # the load holds nothing, so the loop keeps the change to announce: the
        # next tick offers the document again, and a fixed one is adopted.
        if guard.resolution is not None:
            loop.adopt(guard.resolution)
        loop.start(load=False)
        guard._watcher = loop
        return guard

    @property
    def watcher(self) -> Optional[Union["PolicyWatcher", "PolicyPoller"]]:
        """The hot-reload loop attached by :meth:`from_provider`, if any.

        Stop it (``guard.watcher.stop()``) when the guard is done: it holds a
        daemon thread that would otherwise keep reloading.
        """
        return self._watcher

    def close(self, timeout: Optional[float] = 5.0) -> None:
        """Stop the hot-reload loop, if :meth:`from_provider` attached one.

        Safe to call more than once, and on a guard with no loop. The loop
        holds a reference back to this guard, so dropping the guard alone
        neither stops the thread nor lets the guard be collected.
        """
        watcher = self._watcher
        if watcher is not None:
            watcher.stop(timeout)

    def __enter__(self) -> "HushGuard":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    @property
    def enforcement_mode(self) -> str:
        """The guard's configured mode, ``"enforce"`` or ``"monitor"``.

        Per-rule overrides and panic resolution apply per action, so the mode a
        given decision was enforced under is the one on its
        :class:`~hushspec.receipt.EnforcementSummary`, not this.
        """
        return self._enforcement_mode

    @property
    def policy(self) -> HushSpec:
        """The resolved policy in force, as every evaluation sees it.

        For a guard that is refusing an unverified policy this is the deny-all
        backstop, not the document that failed to verify.
        """
        return self._state.policy

    @property
    def resolution(self) -> Optional[Resolution]:
        """Evidence from the policy load: chain hashes and signature outcomes.

        ``None`` while the guard is refusing an unverified policy: there is a
        document, and its hash and chain go into every refusal receipt, but it
        is not a resolution this guard will enforce. :attr:`refusal` says why.
        """
        return self._state.resolution

    @property
    def refusal(self) -> Optional[SignatureStatus]:
        """Why the guard is denying everything, or ``None`` when it is not."""
        return self._state.refusal

    @property
    def compiled(self) -> CompiledPolicy:
        """The compiled policy in force, as every evaluation sees it.

        Recompiled on :meth:`swap_policy`; for a guard that is refusing an
        unverified policy this is the deny-all backstop, not the document that
        failed to verify.
        """
        return self._state.compiled

    def evaluate(self, action: EvaluationAction) -> EvaluationResult:
        # Always routes through _run_evaluation() (sink or not) so this is
        # detection-aware the same way gate()/check()/enforce() are -- a
        # guard must not answer differently from .evaluate() than from
        # .check() for the same action against the same policy.
        from hushspec.receipt import EnforcementSummary

        result, duration_us, receipt = self._run_evaluation(action)
        if receipt is not None:
            # A 0.2 receipt always says what the enforcement point did (receipt
            # spec 4.7). `evaluate()` applies nothing, so the disposition is the
            # one the decision implies under this guard's effective mode.
            receipt.enforcement = EnforcementSummary.implied(
                result.decision, self._effective_mode(result)
            )
            try:
                self._sink.send(receipt)
            except Exception as exc:  # noqa: BLE001
                self._report_sink_failure(exc)
        if self._observable_evaluator is not None:
            self._observable_evaluator.notify_evaluation_completed(
                action, result, duration_us, receipt=receipt
            )
        return result

    def check(self, action: EvaluationAction) -> bool:
        return self.gate(action).proceed

    def enforce(self, action: EvaluationAction) -> None:
        outcome = self.gate(action)
        if not outcome.proceed:
            raise HushSpecDenied(outcome.result)

    def gate(self, action: EvaluationAction) -> GateOutcome:
        """Evaluate, resolve the effective enforcement mode, record the
        outcome, and report whether execution may proceed. The single
        enforcement path: check() and enforce() delegate here."""
        from hushspec.receipt import EnforcementSummary

        result, duration_us, receipt = self._run_evaluation(action)
        mode = self._effective_mode(result)
        if result.decision == Decision.ALLOW:
            proceed, outcome = True, "allowed"
        elif result.decision == Decision.WARN:
            if mode == "monitor":
                proceed, outcome = True, "would_block"
            elif self._on_warn(result, action):
                proceed, outcome = True, "confirmed"
            else:
                proceed, outcome = False, "blocked"
        else:
            proceed = mode == "monitor"
            outcome = "would_block" if proceed else "blocked"

        enforcement = EnforcementSummary(mode=mode, outcome=outcome)
        self._record(action, result, duration_us, enforcement, receipt)
        return GateOutcome(result=result, proceed=proceed, enforcement=enforcement)

    def _effective_mode(self, result: EvaluationResult) -> str:
        if is_panic_active() or result.matched_rule == "__hushspec_panic__":
            return "enforce"
        if self._state.refusal is not None or result.matched_rule == POLICY_SIGNATURE_RULE:
            # A refusal is not a policy decision, so no enforcement override can
            # downgrade it to monitor: there is no verified policy to monitor.
            return "enforce"
        matched = result.matched_rule
        # detection.py emits the bare literal matched_rule "detection" (see
        # hushspec/detection.py) rather than a hierarchical rule path, so an
        # override keyed "extensions.detection" would otherwise silently
        # never match. Normalize before prefix matching.
        if matched == "detection":
            matched = "extensions.detection"
        if matched is not None:
            best_key: Optional[str] = None
            best_mode: Optional[str] = None
            for key, mode in self._enforcement_overrides.items():
                if matches_rule_path_prefix(matched, key) and (
                    best_key is None or len(key) > len(best_key)
                ):
                    best_key, best_mode = key, mode
            if best_mode is not None:
                return best_mode
        return self._enforcement_mode

    def _audit_context(self) -> "AuditContext":
        from hushspec.receipt import AuditContext

        return AuditContext(
            actor=self._actor,
            enforcement_mode=self._enforcement_mode,
        )

    def _run_evaluation(
        self, action: EvaluationAction
    ) -> tuple[EvaluationResult, int, Optional["DecisionReceipt"]]:
        # One read of the state for the whole evaluation: a hot reload on
        # another thread must not pair one policy's decision with another's
        # hash.
        state = self._state
        if state.refusal is not None:
            return self._refused_evaluation(action, state)
        if self._sink is not None:
            # The audited path routes through the detection pipeline itself, so
            # the receipt's decision is already the one an enforcement point
            # acts on -- identical to the sink-free path below, which is the
            # same pipeline without the recording.
            receipt = state.compiled.evaluate_audited(
                action, self._audit, self._audit_context(), state.resolution
            )
            result = EvaluationResult(
                decision=receipt.decision,
                matched_rule=receipt.matched_rule,
                reason=receipt.reason,
                origin_profile=receipt.origin_profile,
                posture=receipt.posture,
            )
            return result, receipt.duration_us or 0, receipt
        start_ns = time.perf_counter_ns()
        # The detection pipeline is an exact no-op unless the policy carries an
        # extensions.detection block, so every non-detection policy behaves
        # identically to a plain evaluate() call here.
        result = state.compiled.evaluate_with_detection(action).evaluation
        duration_us = (time.perf_counter_ns() - start_ns) // 1000
        return result, duration_us, None

    def _refused_evaluation(
        self, action: EvaluationAction, state: "_GuardState"
    ) -> tuple[EvaluationResult, int, Optional["DecisionReceipt"]]:
        """Deny without evaluating: the policy was never verified (signing 6.5).

        No rule ran, so the receipt carries an empty ``rule_trace``. It names
        the refused document by its real content hash and chain, so an auditor
        can see *which* load was refused, and carries the verifier's own
        outcome, so nobody can read it as a policy that was proven.
        """
        refusal = state.refusal
        reason = (refusal.reason if refusal is not None else None) or "unverified"
        result = EvaluationResult(
            decision=Decision.DENY,
            matched_rule=POLICY_SIGNATURE_RULE,
            reason=f"policy signature verification failed: {reason}",
        )
        if self._sink is None or state.refused is None:
            return result, 0, None

        from hushspec.receipt import policy_summary, unverified_policy_receipt

        summary = policy_summary(state.refused)
        if summary.signature is None:
            # The resolver stopped at the failing hop, so the leaf has no
            # outcome of its own; the refusal is that outcome.
            summary.signature = refusal
        receipt = unverified_policy_receipt(summary, action, self._audit_context())
        return result, 0, receipt

    def _record(
        self,
        action: EvaluationAction,
        result: EvaluationResult,
        duration_us: int,
        enforcement: "EnforcementSummary",
        receipt: Optional["DecisionReceipt"],
    ) -> None:
        if receipt is not None:
            receipt.enforcement = enforcement
            if self._sink is not None:
                # A sink must never break enforcement: a full disk is not a
                # reason to let an action through, nor to stop one. The failure
                # still reaches the observers, so the gap is visible.
                try:
                    self._sink.send(receipt)
                except Exception as exc:  # noqa: BLE001
                    self._report_sink_failure(exc)
        if self._observable_evaluator is not None:
            self._observable_evaluator.notify_evaluation_completed(
                action, result, duration_us, enforcement=enforcement, receipt=receipt
            )

    @staticmethod
    def map_tool_call(
        tool_name: str,
        args: Optional[dict] = None,
    ) -> EvaluationAction:
        return EvaluationAction(
            type="tool_call",
            target=tool_name,
            # Core spec 3.7: the UTF-8 byte length of the canonical JSON.
            args_size=args_size_of(args) if args is not None else None,
        )

    @staticmethod
    def map_file_read(path: str) -> EvaluationAction:
        return EvaluationAction(type="file_read", target=path)

    @staticmethod
    def map_file_write(path: str, content: Optional[str] = None) -> EvaluationAction:
        return EvaluationAction(type="file_write", target=path, content=content)

    @staticmethod
    def map_egress(domain: str) -> EvaluationAction:
        return EvaluationAction(type="egress", target=domain)

    @staticmethod
    def map_shell_command(command: str) -> EvaluationAction:
        return EvaluationAction(type="shell_command", target=command)

    def swap_policy(self, new_policy: HushSpec) -> None:
        # Hot-reload is a policy load like any other: a document that does not
        # resolve, or that does not verify under `require_signature`, is
        # rejected here rather than swapped in, leaving the policy in force. A
        # failed swap therefore raises and changes nothing -- including a guard
        # that is already refusing, which keeps refusing.
        self._swap(self._resolve(new_policy))

    def swap_resolution(self, resolution: Resolution) -> None:
        """Swap in a policy a provider already resolved (the hot-reload path).

        The same load as :meth:`swap_policy` minus the resolution, which a
        :class:`~hushspec.provider.PolicyProvider` performed -- so the evidence
        the provider gathered (chain hashes, signature outcome) is the evidence
        every later receipt carries, rather than being recomputed and lost. A
        resolution this guard will not accept is rejected here, leaving the
        policy in force untouched.
        """
        self._swap(self._adopt_resolution(resolution))

    def _swap(self, resolution: Resolution) -> None:
        resolved = resolution.spec
        # Compile before anything is swapped in: the guard never holds a
        # policy it has not prepared.
        compiled = compile_policy(resolution, strict=False)
        previous_hash = self._state.policy_hash
        # One store, so an evaluator on another thread sees either the whole
        # old policy or the whole new one. A swap that verifies also clears an
        # earlier refusal: the guard now holds a policy it was able to prove.
        self._state = _GuardState(
            policy=resolved,
            compiled=compiled,
            resolution=resolution,
            refusal=None,
            refused=None,
            policy_hash=resolution.content_hash,
        )
        if self._observable_evaluator is not None:
            self._observable_evaluator.notify_policy_reloaded(
                resolved.name,
                resolution.content_hash,
                previous_hash,
            )
        # The log must carry the swap before any receipt evaluated under the
        # new policy (log spec section 6).
        self._record_policy_event(loaded=False, previous_content_hash=previous_hash)

    def _record_policy_event(
        self, *, loaded: bool, previous_content_hash: Optional[str] = None
    ) -> None:
        """Write the policy-in-effect record for this load or swap.

        Goes through the sink, so a hash-linked log gets a `policy_loaded` /
        `policy_swapped` entry and a plain receipt sink ignores it. A sink that
        raises must not take the guard down with it.
        """
        resolution = self._state.resolution
        if self._sink is None or resolution is None:
            return
        from hushspec.log import PolicyEvent
        from hushspec.receipt import policy_summary

        summary = policy_summary(resolution)
        event = (
            PolicyEvent.loaded(summary, self._enforcement_mode)
            if loaded
            else PolicyEvent.swapped(
                summary, self._enforcement_mode, previous_content_hash
            )
        )
        try:
            self._sink.record_policy_event(event)
        except Exception as exc:  # noqa: BLE001
            self._report_sink_failure(exc)

    def _report_sink_failure(self, exc: Exception) -> None:
        """Put a sink failure on the observer channel as ``sink.error``.

        Named by the sink that refused, so an operator can tell which
        destination stopped taking evidence.
        """
        if self._observable_evaluator is None:
            return
        self._observable_evaluator.notify_sink_error(
            str(exc), type(self._sink).__name__
        )
