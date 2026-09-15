from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, TYPE_CHECKING

from hushspec.detection import evaluate_with_detection
from hushspec.evaluate import Decision, EvaluationAction, EvaluationResult, is_panic_active
from hushspec.generated_contract import EXTENSION_KEYS, RULE_KEYS
from hushspec.parse import parse_or_raise
from hushspec.resolve import Resolver, create_builtin_loader, create_composite_loader, resolve
from hushspec.schema import HushSpec

if TYPE_CHECKING:
    from hushspec.observer import EvaluationObserver
    from hushspec.receipt import AuditConfig, DecisionReceipt, EnforcementSummary
    from hushspec.sinks import ReceiptSink

WarnHandler = Callable[[EvaluationResult, EvaluationAction], bool]

_ENFORCEMENT_MODES = frozenset(("enforce", "monitor"))


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


def _apply_detection(
    receipt: "DecisionReceipt", spec: HushSpec, action: EvaluationAction
) -> None:
    """Fold a policy's ``detection:`` extension into an already-built receipt.

    Mirrors the Rust reference ``apply_detection``
    (crates/hushspec-cli/src/cmd_eval.rs): ``evaluate_audited`` builds the
    receipt from the core rules only, so when content detection escalates the
    decision this reconciles the receipt -- overwriting decision/matched_rule/
    reason with the detected values and appending a ``detection`` rule-trace
    entry whose outcome is the escalated decision. A no-op when the policy has
    no detection extension, there is no content, or detection does not
    escalate (detection never weakens a policy decision), so receipts for
    every non-detection policy are byte-for-byte unchanged.
    """
    from hushspec.receipt import RuleEvaluation, RuleOutcome

    detected = evaluate_with_detection(spec, action).evaluation
    if detected.decision == receipt.decision:
        return

    receipt.rule_trace.append(
        RuleEvaluation(
            rule_block="detection",
            outcome=RuleOutcome(detected.decision.value),
            matched_rule=detected.matched_rule,
            reason=detected.reason,
            evaluated=True,
        )
    )
    receipt.decision = detected.decision
    receipt.matched_rule = detected.matched_rule
    receipt.reason = detected.reason


def resolve_policy_or_raise(
    policy: HushSpec,
    *,
    loader: Optional[Resolver] = None,
    base_dir: Optional[str] = None,
) -> HushSpec:
    """Resolve a policy's ``extends`` chain, or raise.

    Every entry point into :class:`HushGuard` funnels through this: the guard
    must never hold a spec whose ``extends`` is still set. An unresolved leaf
    silently drops every rule block its base declares -- ``library/general/
    recommended.yaml`` extends ``builtin:default`` and declares no
    ``forbidden_paths``, so evaluating it unresolved would allow reads of
    ``~/.ssh/id_rsa`` -- and hashes the wrong document into every receipt.
    Fail closed: if the base cannot be loaded, no evaluation happens at all.
    """
    if policy.extends is None:
        return policy

    if loader is None:
        loader = create_composite_loader() if base_dir is not None else create_builtin_loader()
    # `resolve()` treats `source` as the *file* a relative reference resolves
    # from, so point it at a placeholder inside base_dir.
    source = str(Path(base_dir).resolve() / "<policy>") if base_dir is not None else None

    ok, result = resolve(policy, source=source, loader=loader)
    if not ok:
        raise ValueError(f"failed to resolve policy 'extends: {policy.extends}': {result}")
    assert isinstance(result, HushSpec)
    if result.extends is not None:
        raise ValueError(
            f"failed to resolve policy 'extends: {policy.extends}': "
            "resolver returned an unresolved policy"
        )
    return result


class HushSpecDenied(Exception):
    def __init__(self, result: EvaluationResult) -> None:
        self.result = result
        reason = result.reason or result.matched_rule or "policy denial"
        super().__init__(f"Action denied: {reason}")


class HushGuard:
    """Fail-closed policy guard: wraps evaluate / check / enforce semantics."""

    def __init__(
        self,
        policy: HushSpec,
        on_warn: Optional[WarnHandler] = None,
        observer: Optional["EvaluationObserver"] = None,
        enforcement: Optional[EnforcementConfig] = None,
        sink: Optional["ReceiptSink"] = None,
        audit: Optional["AuditConfig"] = None,
        loader: Optional[Resolver] = None,
        base_dir: Optional[str] = None,
    ) -> None:
        config = enforcement or EnforcementConfig()
        _validate_enforcement_config(config, observer is not None or sink is not None)
        self._enforcement_mode = config.mode
        self._enforcement_overrides = dict(config.overrides)
        self._sink = sink
        if audit is None:
            from hushspec.receipt import AuditConfig
            audit = AuditConfig()
        self._audit = audit
        self._resolve_loader = loader
        self._resolve_base_dir = base_dir
        # Resolve before anything else touches the spec: a guard never holds an
        # unresolved document, and the receipt hash covers the resolved policy.
        self._policy = resolve_policy_or_raise(policy, loader=loader, base_dir=base_dir)
        self._on_warn: WarnHandler = on_warn or (lambda _r, _a: False)
        self._observable_evaluator = None
        self._policy_hash: Optional[str] = None
        if observer is not None:
            from hushspec.observer import ObservableEvaluator
            from hushspec.receipt import compute_policy_hash
            self._observable_evaluator = ObservableEvaluator(
                redact_content=self._audit.redact_content
            )
            self._observable_evaluator.add_observer(observer)
            self._policy_hash = compute_policy_hash(self._policy)
            self._observable_evaluator.notify_policy_loaded(self._policy.name, self._policy_hash)

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
    ) -> HushGuard:
        """Load a policy file and resolve its ``extends`` chain.

        Relative references resolve against the policy file's own directory
        (overridable with ``base_dir``/``loader``); ``builtin:`` references come
        from the embedded rulesets. Raises if the chain cannot be resolved.
        """
        with open(path) as f:
            spec = parse_or_raise(f.read())
        if base_dir is None:
            base_dir = str(Path(path).resolve().parent)
        return cls(
            spec,
            on_warn,
            observer=observer,
            enforcement=enforcement,
            sink=sink,
            audit=audit,
            loader=loader,
            base_dir=base_dir,
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
    ) -> HushGuard:
        """Parse a policy document and resolve its ``extends`` chain.

        ``builtin:`` references resolve out of the box; file references need an
        explicit ``base_dir`` (or ``loader``) since a YAML string has no
        directory of its own. Raises if the chain cannot be resolved.
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
        )

    def evaluate(self, action: EvaluationAction) -> EvaluationResult:
        # Always routes through _run_evaluation() (sink or not) so this is
        # detection-aware the same way gate()/check()/enforce() are -- a
        # guard must not answer differently from .evaluate() than from
        # .check() for the same action against the same policy.
        result, duration_us, receipt = self._run_evaluation(action)
        if receipt is not None:
            try:
                self._sink.send(receipt)
            except Exception:
                pass  # sinks must not break evaluation
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
        matched = result.matched_rule
        # detection.py emits the bare literal matched_rule "detection" (see
        # hushspec/detection.py) rather than a hierarchical rule path, so an
        # override keyed "extensions.detection" would otherwise silently
        # never match. Normalize before prefix matching (mirrors TS
        # middleware.ts's effectiveMode normalization).
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

    def _run_evaluation(
        self, action: EvaluationAction
    ) -> tuple[EvaluationResult, int, Optional["DecisionReceipt"]]:
        if self._sink is not None:
            from hushspec.receipt import evaluate_audited

            # evaluate_audited() builds the receipt from the core rules only
            # (it never consults extensions.detection), so fold detection in
            # afterward -- exactly as the non-sink branch below routes through
            # evaluate_with_detection() -- and build `result` from the
            # possibly-reconciled receipt so the enforced decision honors the
            # policy's detection extension identically to the sink-free path.
            receipt = evaluate_audited(self._policy, action, self._audit)
            _apply_detection(receipt, self._policy, action)
            result = EvaluationResult(
                decision=receipt.decision,
                matched_rule=receipt.matched_rule,
                reason=receipt.reason,
                origin_profile=receipt.origin_profile,
                posture=receipt.posture,
            )
            return result, receipt.evaluation_duration_us, receipt
        start_ns = time.perf_counter_ns()
        # evaluate_with_detection() is an exact no-op unless the policy
        # carries an extensions.detection block, so every non-detection
        # policy behaves identically to a plain evaluate() call here.
        result = evaluate_with_detection(self._policy, action).evaluation
        duration_us = (time.perf_counter_ns() - start_ns) // 1000
        return result, duration_us, None

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
                try:
                    self._sink.send(receipt)
                except Exception:
                    pass  # sinks must not break enforcement
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
            args_size=len(json.dumps(args)) if args is not None else None,
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
        # Hot-reload is a policy load like any other: an unresolved document is
        # rejected here rather than swapped in, leaving the policy in force.
        resolved = resolve_policy_or_raise(
            new_policy, loader=self._resolve_loader, base_dir=self._resolve_base_dir
        )
        previous_hash = self._policy_hash
        self._policy = resolved
        if self._observable_evaluator is not None:
            from hushspec.receipt import compute_policy_hash
            self._policy_hash = compute_policy_hash(resolved)
            self._observable_evaluator.notify_policy_reloaded(
                resolved.name,
                self._policy_hash,
                previous_hash,
            )
