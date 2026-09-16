"""Reference evaluator for HushSpec 0.2 (core spec Sections 3, 5, and 6).

Evaluation of one action is:

1. extension guards (panic, origins ``default_behavior``, posture capability),
2. every applicable rule block for the action type -- present, ``enabled``,
   and with a satisfied ``when`` condition -- evaluated in the order of the
   Section 5 table, never short-circuiting on an allow,
3. aggregation: deny beats warn beats allow; ``matched_rule``/``reason`` come
   from the first block in evaluation order whose decision equals the
   aggregate and which named a rule.

Unknown action types deny (``__unknown_action_type__``). Hosts and paths are
normalized as specified in Section 3.14 before any pattern is consulted.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from hushspec.conditions import (
    Condition,
    RuntimeContext,
    decode_condition,
    evaluate_condition,
)
from hushspec.extensions import (
    OriginDefaultBehavior,
    OriginEgressOverlay,
    OriginMatch,
    OriginProfile,
    OriginToolAccessOverlay,
    PostureExtension,
    TransitionTrigger,
)
from hushspec.regex_profile import compile_profile_regex
from hushspec.rules import (
    BrowserAutomationRule,
    CodeExecutionRule,
    ComputerUseMode,
    ComputerUseRule,
    DefaultAction,
    EgressRule,
    ForbiddenPathsRule,
    InputInjectionRule,
    PatchIntegrityRule,
    PathAllowlistRule,
    RemoteDesktopChannelsRule,
    SecretPatternsRule,
    Severity,
    ShellCommandsRule,
    ToolAccessRule,
)
from hushspec.schema import HushSpec

#: ``matched_rule`` reported when the action type is unknown to the specification.
UNKNOWN_ACTION_TYPE_RULE = "__unknown_action_type__"
#: ``matched_rule`` reported when the emergency panic protocol is active.
PANIC_RULE = "__hushspec_panic__"

PANIC_POLICY_YAML = """hushspec: "0.1.0"
name: "__hushspec_panic__"
description: "Emergency deny-all policy. Activated by panic mode."

rules:
  forbidden_paths:
    enabled: true
    patterns:
      - "**"
    exceptions: []

  egress:
    enabled: true
    allow: []
    block:
      - "*"
    default: block

  shell_commands:
    enabled: true
    forbidden_patterns:
      - ".*"

  tool_access:
    enabled: true
    allow: []
    block:
      - "*"
    require_confirmation: []
    default: block

  computer_use:
    enabled: true
    mode: fail_closed
    allowed_actions: []

  input_injection:
    enabled: true
    allowed_types: []
"""


class Decision(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    DENY = "deny"


_DECISION_RANK: dict[Decision, int] = {
    Decision.ALLOW: 1,
    Decision.WARN: 2,
    Decision.DENY: 3,
}


class RuleOutcome(str, Enum):
    """Outcome of consulting one rule block (or extension guard).

    ``SKIP`` means the block was applicable but not evaluated (absent,
    disabled, condition false, or short-circuited by a guard deny).
    """

    ALLOW = "allow"
    WARN = "warn"
    DENY = "deny"
    SKIP = "skip"


def _outcome_of(decision: Decision) -> RuleOutcome:
    return RuleOutcome(decision.value)


@dataclass
class OriginContext:
    provider: Optional[str] = None
    tenant_id: Optional[str] = None
    space_id: Optional[str] = None
    space_type: Optional[str] = None
    visibility: Optional[str] = None
    external_participants: Optional[bool] = None
    tags: list[str] = field(default_factory=list)
    sensitivity: Optional[str] = None
    actor_role: Optional[str] = None


@dataclass
class PostureContext:
    current: Optional[str] = None
    signal: Optional[str] = None


@dataclass
class EvaluationAction:
    type: str
    target: Optional[str] = None
    content: Optional[str] = None
    origin: Optional[OriginContext] = None
    posture: Optional[PostureContext] = None
    args_size: Optional[int] = None
    url: Optional[str] = None
    """``browser_action``: navigation destination (core spec 3.11)."""
    network: Optional[bool] = None
    """``code_exec``: whether the call requests network access (core spec 3.12)."""
    timeout_ms: Optional[int] = None
    """``code_exec``: requested execution time in milliseconds (core spec 3.12)."""
    context: Optional[RuntimeContext] = None
    """Runtime context consulted by ``when`` conditions (core spec 3.13)."""


@dataclass
class PostureResult:
    current: str
    next: str


@dataclass
class EvaluationResult:
    decision: Decision
    matched_rule: Optional[str] = None
    reason: Optional[str] = None
    origin_profile: Optional[str] = None
    posture: Optional[PostureResult] = None


@dataclass
class RuleEvaluation:
    """One recorded rule-block consultation, in evaluation order."""

    rule_block: str
    outcome: RuleOutcome
    evaluated: bool
    matched_rule: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class TracedEvaluation:
    """An evaluation result together with its recorded rule trace."""

    result: EvaluationResult
    trace: list[RuleEvaluation]


class _PathOperation(Enum):
    READ = "read"
    WRITE = "write"
    PATCH = "patch"


@dataclass
class _PatchStats:
    additions: int
    deletions: int


@dataclass
class _BlockDecision:
    """Decision contributed by one rule block."""

    decision: Decision
    matched_rule: Optional[str] = None
    reason: Optional[str] = None


def _allow(matched_rule: Optional[str], reason: Optional[str]) -> _BlockDecision:
    return _BlockDecision(Decision.ALLOW, matched_rule, reason)


def _warn(matched_rule: str, reason: str) -> _BlockDecision:
    return _BlockDecision(Decision.WARN, matched_rule, reason)


def _deny(matched_rule: str, reason: str) -> _BlockDecision:
    return _BlockDecision(Decision.DENY, matched_rule, reason)


class _Inactive(Exception):
    """Why an applicable block was not evaluated."""

    ABSENT = "absent"
    DISABLED = "disabled"
    CONDITION_FALSE = "condition_false"
    OUT_OF_BAND_CONDITION_FALSE = "out_of_band_condition_false"

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind

    def reason(self, block: str) -> str:
        if self.kind == _Inactive.ABSENT:
            return f"no {block} rule configured"
        if self.kind == _Inactive.DISABLED:
            return "rule disabled"
        if self.kind == _Inactive.CONDITION_FALSE:
            return "when condition is false"
        return "out-of-band condition is false"


#: Rule blocks applicable to each reference action type, in evaluation order
#: (core spec Section 5). An action type absent from this table is unknown to
#: the specification.
_APPLICABLE_BLOCKS: dict[str, tuple[str, ...]] = {
    "file_read": ("forbidden_paths", "path_allowlist"),
    "file_write": ("forbidden_paths", "path_allowlist", "secret_patterns"),
    "patch_apply": (
        "forbidden_paths",
        "path_allowlist",
        "patch_integrity",
        "secret_patterns",
    ),
    "shell_command": ("shell_commands",),
    "egress": ("egress", "secret_patterns"),
    "tool_call": ("tool_access", "secret_patterns"),
    "computer_use": ("computer_use", "remote_desktop_channels"),
    "input_inject": ("input_injection",),
    "browser_action": ("browser_automation",),
    "code_exec": ("code_execution",),
    "custom": (),
}


def applicable_blocks(action_type: str) -> Optional[tuple[str, ...]]:
    return _APPLICABLE_BLOCKS.get(action_type)


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def evaluate(spec: HushSpec, action: EvaluationAction) -> EvaluationResult:
    """Evaluate *action* against a resolved document.

    ``when`` conditions are evaluated against ``action.context`` (an empty
    context and the engine clock when absent).
    """
    return evaluate_traced(spec, action, None, {}).result


def evaluate_traced(
    spec: HushSpec,
    action: EvaluationAction,
    context: Optional[RuntimeContext] = None,
    conditions: Optional[dict[str, Condition]] = None,
) -> TracedEvaluation:
    """Full evaluation with the recorded rule trace (used by receipts)."""
    effective_context = context
    if effective_context is None:
        effective_context = action.context
    if effective_context is None:
        effective_context = RuntimeContext()
    return _Evaluator(spec, action, effective_context, conditions or {}).run()


class _Evaluator:
    def __init__(
        self,
        spec: HushSpec,
        action: EvaluationAction,
        context: RuntimeContext,
        conditions: dict[str, Condition],
    ) -> None:
        self.spec = spec
        self.action = action
        self.context = context
        self.conditions = conditions
        self.trace: list[RuleEvaluation] = []

    # -- trace helpers ------------------------------------------------------

    def _record(
        self,
        block: str,
        outcome: RuleOutcome,
        matched_rule: Optional[str],
        reason: Optional[str],
        evaluated: bool,
    ) -> None:
        self.trace.append(
            RuleEvaluation(
                rule_block=block,
                outcome=outcome,
                matched_rule=matched_rule,
                reason=reason,
                evaluated=evaluated,
            )
        )

    def _skip_all(self, blocks: tuple[str, ...], reason: str) -> None:
        for block in blocks:
            self._record(block, RuleOutcome.SKIP, None, reason, False)

    def _finish(
        self,
        decision: Decision,
        matched_rule: Optional[str],
        reason: Optional[str],
        origin_profile: Optional[str],
        posture: Optional[PostureResult],
    ) -> TracedEvaluation:
        return TracedEvaluation(
            result=EvaluationResult(
                decision=decision,
                matched_rule=matched_rule,
                reason=reason,
                origin_profile=origin_profile,
                posture=posture,
            ),
            trace=self.trace,
        )

    # -- main loop ----------------------------------------------------------

    def run(self) -> TracedEvaluation:
        if is_panic_active():
            reason = "emergency panic mode is active"
            self._record("panic", RuleOutcome.DENY, PANIC_RULE, reason, True)
            return self._finish(Decision.DENY, PANIC_RULE, reason, None, None)

        action_type = self.action.type
        blocks = applicable_blocks(action_type)
        if blocks is None:
            reason = f"action type '{action_type}' is unknown to the specification"
            self._record(
                "default", RuleOutcome.DENY, UNKNOWN_ACTION_TYPE_RULE, reason, True
            )
            return self._finish(
                Decision.DENY, UNKNOWN_ACTION_TYPE_RULE, reason, None, None
            )

        # Origins guard: select a profile or apply default_behavior.
        origins = (
            self.spec.extensions.origins if self.spec.extensions is not None else None
        )
        matched_profile = select_origin_profile(self.spec, self.action.origin)
        origin_profile_id = matched_profile.id if matched_profile is not None else None
        if (
            origins is not None
            and matched_profile is None
            and (origins.default_behavior or OriginDefaultBehavior.DENY)
            == OriginDefaultBehavior.DENY
        ):
            reason = "no origin profile matched and default_behavior is deny"
            rule = "extensions.origins.default_behavior"
            self._record("origins", RuleOutcome.DENY, rule, reason, True)
            self._skip_all(blocks, "short-circuited by origins deny")
            return self._finish(Decision.DENY, rule, reason, None, None)

        # Posture guard.
        posture = resolve_posture(self.spec, matched_profile, self.action.posture)
        denied = self._posture_capability_guard(posture)
        if denied is not None:
            self._skip_all(blocks, "short-circuited by posture deny")
            return self._finish(
                Decision.DENY,
                denied.matched_rule,
                denied.reason,
                origin_profile_id,
                posture,
            )

        if action_type == "custom":
            # Only a posture state granting the `custom` capability can vouch
            # for an engine-defined action (core spec Section 5).
            if posture is None:
                reason = (
                    "custom actions require a posture state granting the "
                    "custom capability"
                )
                self._record(
                    "default", RuleOutcome.DENY, UNKNOWN_ACTION_TYPE_RULE, reason, True
                )
                return self._finish(
                    Decision.DENY,
                    UNKNOWN_ACTION_TYPE_RULE,
                    reason,
                    origin_profile_id,
                    None,
                )
            return self._finish(Decision.ALLOW, None, None, origin_profile_id, posture)

        # Block evaluation and aggregation (core spec 6.1).
        normalized_path = (
            normalize_path(self.action.target) if self.action.target is not None else None
        )
        decisions: list[_BlockDecision] = []
        for block in blocks:
            try:
                decision = self._evaluate_block(block, matched_profile, normalized_path)
            except _Inactive as inactive:
                self._record(
                    block, RuleOutcome.SKIP, None, inactive.reason(block), False
                )
                continue
            self._record(
                block,
                _outcome_of(decision.decision),
                decision.matched_rule,
                decision.reason,
                True,
            )
            decisions.append(decision)

        aggregate = Decision.ALLOW
        for decision in decisions:
            if _DECISION_RANK[decision.decision] > _DECISION_RANK[aggregate]:
                aggregate = decision.decision
        matched_rule: Optional[str] = None
        reason: Optional[str] = None
        for decision in decisions:
            if decision.decision == aggregate and decision.matched_rule is not None:
                matched_rule = decision.matched_rule
                reason = decision.reason
                break
        return self._finish(
            aggregate, matched_rule, reason, origin_profile_id, posture
        )

    # -- activity -----------------------------------------------------------

    def _activity(self, block: str, enabled: bool, when: Any) -> None:
        """Raise :class:`_Inactive` unless the block is enabled and its
        ``when`` plus any out-of-band condition hold for the runtime context."""
        if not enabled:
            raise _Inactive(_Inactive.DISABLED)
        condition = decode_condition(when)
        if condition is not None and not evaluate_condition(condition, self.context):
            raise _Inactive(_Inactive.CONDITION_FALSE)
        out_of_band = self.conditions.get(block)
        if out_of_band is not None and not evaluate_condition(
            out_of_band, self.context
        ):
            raise _Inactive(_Inactive.OUT_OF_BAND_CONDITION_FALSE)

    # -- per-block dispatch -------------------------------------------------

    def _evaluate_block(
        self,
        block: str,
        matched_profile: Optional[OriginProfile],
        normalized_path: Optional[str],
    ) -> _BlockDecision:
        rules = self.spec.rules
        action = self.action
        content = action.content

        if block == "forbidden_paths":
            rule = rules.forbidden_paths if rules is not None else None
            if rule is None:
                raise _Inactive(_Inactive.ABSENT)
            self._activity(block, rule.enabled, rule.when)
            return evaluate_forbidden_paths(rule, normalized_path or "")

        if block == "path_allowlist":
            rule = rules.path_allowlist if rules is not None else None
            if rule is None:
                raise _Inactive(_Inactive.ABSENT)
            self._activity(block, rule.enabled, rule.when)
            if action.type == "file_read":
                operation = _PathOperation.READ
            elif action.type == "patch_apply":
                operation = _PathOperation.PATCH
            else:
                operation = _PathOperation.WRITE
            return evaluate_path_allowlist(rule, normalized_path or "", operation)

        if block == "secret_patterns":
            rule = rules.secret_patterns if rules is not None else None
            if rule is None:
                raise _Inactive(_Inactive.ABSENT)
            path_bearing = action.type in ("file_write", "patch_apply")
            # egress and tool_call are scanned only when they carry content.
            if not path_bearing and content is None:
                raise _Inactive(_Inactive.ABSENT)
            self._activity(block, rule.enabled, rule.when)
            skip_path = normalized_path if path_bearing else None
            return evaluate_secret_patterns(rule, skip_path, content or "")

        if block == "patch_integrity":
            rule = rules.patch_integrity if rules is not None else None
            if rule is None:
                raise _Inactive(_Inactive.ABSENT)
            self._activity(block, rule.enabled, rule.when)
            return evaluate_patch_integrity(rule, content or "")

        if block == "shell_commands":
            rule = rules.shell_commands if rules is not None else None
            if rule is None:
                raise _Inactive(_Inactive.ABSENT)
            self._activity(block, rule.enabled, rule.when)
            return evaluate_shell_commands(rule, action.target or "")

        if block == "tool_access":
            base = rules.tool_access if rules is not None else None
            overlay = None
            if matched_profile is not None and matched_profile.tool_access is not None:
                overlay = (matched_profile.id, matched_profile.tool_access)
            if base is None and overlay is None:
                raise _Inactive(_Inactive.ABSENT)
            if base is not None:
                self._activity(block, base.enabled, base.when)
            return evaluate_tool_access(base, overlay, action)

        if block == "egress":
            base = rules.egress if rules is not None else None
            overlay = None
            if matched_profile is not None and matched_profile.egress is not None:
                overlay = (matched_profile.id, matched_profile.egress)
            if base is None and overlay is None:
                raise _Inactive(_Inactive.ABSENT)
            if base is not None:
                self._activity(block, base.enabled, base.when)
            host = normalize_host(action.target) if action.target is not None else None
            return evaluate_egress(base, overlay, host)

        if block == "computer_use":
            rule = rules.computer_use if rules is not None else None
            if rule is None:
                raise _Inactive(_Inactive.ABSENT)
            self._activity(block, rule.enabled, rule.when)
            return evaluate_computer_use(rule, action.target or "")

        if block == "remote_desktop_channels":
            rule = rules.remote_desktop_channels if rules is not None else None
            if rule is None:
                raise _Inactive(_Inactive.ABSENT)
            self._activity(block, rule.enabled, rule.when)
            decision = evaluate_remote_desktop_channels(rule, action.target or "")
            if decision is None:
                raise _Inactive(_Inactive.ABSENT)
            return decision

        if block == "input_injection":
            rule = rules.input_injection if rules is not None else None
            if rule is None:
                raise _Inactive(_Inactive.ABSENT)
            self._activity(block, rule.enabled, rule.when)
            return evaluate_input_injection(rule, action.target or "")

        if block == "browser_automation":
            rule = rules.browser_automation if rules is not None else None
            if rule is None:
                raise _Inactive(_Inactive.ABSENT)
            self._activity(block, rule.enabled, rule.when)
            return evaluate_browser_automation(rule, action)

        if block == "code_execution":
            rule = rules.code_execution if rules is not None else None
            if rule is None:
                raise _Inactive(_Inactive.ABSENT)
            self._activity(block, rule.enabled, rule.when)
            return evaluate_code_execution(rule, action)

        raise _Inactive(_Inactive.ABSENT)

    # -- posture ------------------------------------------------------------

    def _posture_capability_guard(
        self, posture: Optional[PostureResult]
    ) -> Optional[_BlockDecision]:
        if posture is None:
            return None
        posture_extension = (
            self.spec.extensions.posture if self.spec.extensions is not None else None
        )
        if posture_extension is None:
            return None
        capability = required_capability(self.action.type)
        if capability is None:
            return None

        current_state = posture_extension.states.get(posture.current)
        if current_state is None:
            rule = f"extensions.posture.states.{posture.current}"
            reason = f"unknown posture state '{posture.current}'"
            self._record("posture_capability", RuleOutcome.DENY, rule, reason, True)
            return _deny(rule, reason)

        if capability in current_state.capabilities:
            self._record(
                "posture_capability",
                RuleOutcome.ALLOW,
                None,
                "posture capabilities satisfied",
                True,
            )
            return None

        rule = f"extensions.posture.states.{posture.current}.capabilities"
        reason = (
            f"posture '{posture.current}' does not allow capability '{capability}'"
        )
        self._record("posture_capability", RuleOutcome.DENY, rule, reason, True)
        return _deny(rule, reason)


# ---------------------------------------------------------------------------
# Rule blocks
# ---------------------------------------------------------------------------


def evaluate_forbidden_paths(rule: ForbiddenPathsRule, path: str) -> _BlockDecision:
    if _any_path_glob_matches(rule.exceptions, path):
        return _allow(
            "rules.forbidden_paths.exceptions", "path matched an explicit exception"
        )
    if _any_path_glob_matches(rule.patterns, path):
        return _deny(
            "rules.forbidden_paths.patterns", "path matched a forbidden pattern"
        )
    return _allow(None, "path did not match any forbidden pattern")


def evaluate_path_allowlist(
    rule: PathAllowlistRule, path: str, operation: _PathOperation
) -> _BlockDecision:
    if operation == _PathOperation.READ:
        patterns = rule.read
    elif operation == _PathOperation.PATCH:
        patterns = rule.patch if rule.patch else rule.write
    else:
        patterns = rule.write
    if _any_path_glob_matches(patterns, path):
        return _allow("rules.path_allowlist", "path matched allowlist")
    return _deny("rules.path_allowlist", "path did not match allowlist")


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.WARN: 1,
    Severity.ERROR: 2,
    Severity.CRITICAL: 3,
}


def evaluate_secret_patterns(
    rule: SecretPatternsRule, skip_path: Optional[str], content: str
) -> _BlockDecision:
    if skip_path is not None and _any_path_glob_matches(rule.skip_paths, skip_path):
        return _allow(
            "rules.secret_patterns.skip_paths",
            "path is excluded from secret scanning",
        )

    best_rank = 0
    best = None
    for pattern in rule.patterns:
        # Fail closed: a pattern that will not compile under the HushSpec regex
        # profile denies the action rather than being skipped (core spec 3.14.3).
        try:
            compiled = compile_profile_regex(pattern.pattern)
        except ValueError as exc:
            return _deny(
                f"rules.secret_patterns.patterns.{pattern.name}.pattern",
                f"secret pattern '{pattern.name}' is invalid: {exc}",
            )
        if compiled.search(content):
            rank = _SEVERITY_RANK[pattern.severity]
            # Strictly greater keeps the first pattern in document order among
            # those at the highest matched severity.
            if rank > best_rank:
                best_rank = rank
                best = pattern

    if best is None:
        return _allow(None, "content did not match any secret pattern")

    matched_rule = f"rules.secret_patterns.patterns.{best.name}"
    reason = f"content matched secret pattern '{best.name}'"
    if best.severity == Severity.WARN:
        return _warn(matched_rule, reason)
    return _deny(matched_rule, reason)


def evaluate_patch_integrity(rule: PatchIntegrityRule, content: str) -> _BlockDecision:
    for index, pattern in enumerate(rule.forbidden_patterns):
        try:
            compiled = compile_profile_regex(pattern)
        except ValueError as exc:
            return _deny(
                f"rules.patch_integrity.forbidden_patterns[{index}]",
                f"patch forbidden pattern is invalid: {exc}",
            )
        if compiled.search(content):
            return _deny(
                f"rules.patch_integrity.forbidden_patterns[{index}]",
                "patch content matched a forbidden pattern",
            )

    stats = patch_stats(content)
    if stats.additions > rule.max_additions:
        return _deny(
            "rules.patch_integrity.max_additions",
            "patch additions exceeded max_additions",
        )
    if stats.deletions > rule.max_deletions:
        return _deny(
            "rules.patch_integrity.max_deletions",
            "patch deletions exceeded max_deletions",
        )
    if rule.require_balance:
        one_sided = (stats.additions == 0) != (stats.deletions == 0)
        if one_sided:
            return _deny(
                "rules.patch_integrity.max_imbalance_ratio",
                "patch has changes on only one side; the imbalance ratio is infinite",
            )
        if stats.additions > 0 and stats.deletions > 0:
            larger = float(max(stats.additions, stats.deletions))
            smaller = float(min(stats.additions, stats.deletions))
            if larger / smaller > rule.max_imbalance_ratio:
                return _deny(
                    "rules.patch_integrity.max_imbalance_ratio",
                    "patch exceeded max imbalance ratio",
                )

    return _allow(None, "patch passed integrity checks")


def evaluate_shell_commands(rule: ShellCommandsRule, command: str) -> _BlockDecision:
    for index, pattern in enumerate(rule.forbidden_patterns):
        try:
            compiled = compile_profile_regex(pattern)
        except ValueError as exc:
            return _deny(
                f"rules.shell_commands.forbidden_patterns[{index}]",
                f"shell forbidden pattern is invalid: {exc}",
            )
        if compiled.search(command):
            return _deny(
                f"rules.shell_commands.forbidden_patterns[{index}]",
                "shell command matched a forbidden pattern",
            )
    return _allow(None, "command did not match any forbidden pattern")


def tool_list_contains(entries: list[str], tool: str) -> bool:
    """Tool names are exact, case-sensitive strings after NFC normalization
    (core spec 3.7); no glob or regex metacharacters."""
    normalized = unicodedata.normalize("NFC", tool)
    return any(unicodedata.normalize("NFC", entry) == normalized for entry in entries)


def _default_rule_path(
    base_present: bool,
    base_default: DefaultAction,
    overlay_default: Optional[DefaultAction],
    effective: DefaultAction,
    base_path: str,
    prefix: Optional[str],
) -> str:
    """Path reported for a ``default`` decision: the object whose ``default``
    field determined the effective value."""
    if prefix is None:
        return base_path
    overlay_path = f"{prefix}.default"
    if effective == DefaultAction.BLOCK:
        if base_present and base_default == DefaultAction.BLOCK:
            return base_path
        return overlay_path
    if base_present or overlay_default is None:
        return base_path
    return overlay_path


def evaluate_tool_access(
    base: Optional[ToolAccessRule],
    overlay: Optional[tuple[str, OriginToolAccessOverlay]],
    action: EvaluationAction,
) -> _BlockDecision:
    tool = action.target or ""
    prefix: Optional[str] = None
    overlay_rule: Optional[OriginToolAccessOverlay] = None
    if overlay is not None:
        prefix = f"extensions.origins.profiles.{overlay[0]}.tool_access"
        overlay_rule = overlay[1]

    # 1. max_args_size: the smaller of the two when both are specified.
    base_limit = (
        (base.max_args_size, "rules.tool_access.max_args_size")
        if base is not None and base.max_args_size is not None
        else None
    )
    overlay_limit = (
        (overlay_rule.max_args_size, f"{prefix}.max_args_size")
        if overlay_rule is not None
        and overlay_rule.max_args_size is not None
        and prefix is not None
        else None
    )
    if base_limit is not None and overlay_limit is not None:
        limit = overlay_limit if overlay_limit[0] < base_limit[0] else base_limit
    else:
        limit = base_limit if base_limit is not None else overlay_limit
    if limit is not None and (action.args_size or 0) > limit[0]:
        return _deny(limit[1], "tool arguments exceeded max_args_size")

    # 2. block: union of both lists.
    if base is not None and tool_list_contains(base.block, tool):
        return _deny("rules.tool_access.block", "tool is explicitly blocked")
    if (
        overlay_rule is not None
        and prefix is not None
        and tool_list_contains(overlay_rule.block, tool)
    ):
        return _deny(f"{prefix}.block", "tool is explicitly blocked")

    # 3. require_confirmation: union of both lists.
    if base is not None and tool_list_contains(base.require_confirmation, tool):
        return _warn(
            "rules.tool_access.require_confirmation", "tool requires confirmation"
        )
    if (
        overlay_rule is not None
        and prefix is not None
        and tool_list_contains(overlay_rule.require_confirmation, tool)
    ):
        return _warn(f"{prefix}.require_confirmation", "tool requires confirmation")

    # 4/5. allowlist mode: intersection when both lists are non-empty.
    base_allow = base.allow if base is not None and base.allow else None
    overlay_allow = (
        overlay_rule.allow if overlay_rule is not None and overlay_rule.allow else None
    )
    if base_allow is not None or overlay_allow is not None:
        if base_allow is not None and not tool_list_contains(base_allow, tool):
            return _deny("rules.tool_access.allow", "tool is not in the allowlist")
        if (
            overlay_allow is not None
            and prefix is not None
            and not tool_list_contains(overlay_allow, tool)
        ):
            return _deny(f"{prefix}.allow", "tool is not in the allowlist")
        matched_rule = (
            f"{prefix}.allow"
            if overlay_allow is not None and prefix is not None
            else "rules.tool_access.allow"
        )
        return _allow(matched_rule, "tool is explicitly allowed")

    # 6. default: block when the base says block or the overlay specifies block.
    base_default = base.default if base is not None else DefaultAction.ALLOW
    overlay_default = overlay_rule.default if overlay_rule is not None else None
    effective = (
        DefaultAction.BLOCK
        if base_default == DefaultAction.BLOCK
        or overlay_default == DefaultAction.BLOCK
        else DefaultAction.ALLOW
    )
    matched_rule = _default_rule_path(
        base is not None,
        base_default,
        overlay_default,
        effective,
        "rules.tool_access.default",
        prefix,
    )
    if effective == DefaultAction.ALLOW:
        return _allow(matched_rule, "tool matched default allow")
    return _deny(matched_rule, "tool matched default block")


def evaluate_egress(
    base: Optional[EgressRule],
    overlay: Optional[tuple[str, OriginEgressOverlay]],
    host: Optional[str],
) -> _BlockDecision:
    prefix: Optional[str] = None
    overlay_rule: Optional[OriginEgressOverlay] = None
    if overlay is not None:
        prefix = f"extensions.origins.profiles.{overlay[0]}.egress"
        overlay_rule = overlay[1]

    # 1. block: union of both lists.
    if base is not None and _any_host_pattern_matches(base.block, host):
        return _deny("rules.egress.block", "domain is explicitly blocked")
    if (
        overlay_rule is not None
        and prefix is not None
        and _any_host_pattern_matches(overlay_rule.block, host)
    ):
        return _deny(f"{prefix}.block", "domain is explicitly blocked")

    # 2. allow: intersection when both lists are non-empty.
    base_allow = base.allow if base is not None and base.allow else None
    overlay_allow = (
        overlay_rule.allow if overlay_rule is not None and overlay_rule.allow else None
    )
    if base_allow is not None or overlay_allow is not None:
        base_ok = base_allow is None or _any_host_pattern_matches(base_allow, host)
        overlay_ok = overlay_allow is None or _any_host_pattern_matches(
            overlay_allow, host
        )
        if base_ok and overlay_ok:
            matched_rule = (
                f"{prefix}.allow"
                if overlay_allow is not None and prefix is not None
                else "rules.egress.allow"
            )
            return _allow(matched_rule, "domain is explicitly allowed")

    # 3. default.
    base_default = base.default if base is not None else DefaultAction.BLOCK
    overlay_default = overlay_rule.default if overlay_rule is not None else None
    effective = (
        DefaultAction.BLOCK
        if base_default == DefaultAction.BLOCK
        or overlay_default == DefaultAction.BLOCK
        else DefaultAction.ALLOW
    )
    matched_rule = _default_rule_path(
        base is not None,
        base_default,
        overlay_default,
        effective,
        "rules.egress.default",
        prefix,
    )
    if effective == DefaultAction.ALLOW:
        return _allow(matched_rule, "domain matched default allow")
    return _deny(matched_rule, "domain matched default block")


def evaluate_computer_use(rule: ComputerUseRule, target: str) -> _BlockDecision:
    if target in rule.allowed_actions:
        return _allow(
            "rules.computer_use.allowed_actions",
            "computer-use action is explicitly allowed",
        )
    if rule.mode == ComputerUseMode.OBSERVE:
        return _allow(
            "rules.computer_use.mode",
            "observe mode does not block unlisted actions",
        )
    # guardrail and fail_closed have identical reference semantics (D9).
    return _deny(
        "rules.computer_use.mode", "unlisted computer-use action is denied"
    )


def evaluate_remote_desktop_channels(
    rule: RemoteDesktopChannelsRule, target: str
) -> Optional[_BlockDecision]:
    if target == "remote.clipboard":
        field_name, allowed = "clipboard", rule.clipboard
    elif target == "remote.file_transfer":
        field_name, allowed = "file_transfer", rule.file_transfer
    elif target == "remote.audio":
        field_name, allowed = "audio", rule.audio
    elif target == "remote.drive_mapping":
        field_name, allowed = "drive_mapping", rule.drive_mapping
    else:
        return None

    matched_rule = f"rules.remote_desktop_channels.{field_name}"
    if allowed:
        return _allow(
            matched_rule, f"remote desktop channel '{field_name}' is enabled"
        )
    return _deny(matched_rule, f"remote desktop channel '{field_name}' is disabled")


def evaluate_input_injection(rule: InputInjectionRule, target: str) -> _BlockDecision:
    if not rule.allowed_types:
        return _deny(
            "rules.input_injection.allowed_types",
            "input injection is not allowed when allowed_types is empty",
        )
    if target in rule.allowed_types:
        return _allow(
            "rules.input_injection.allowed_types",
            "input injection type is explicitly allowed",
        )
    return _deny(
        "rules.input_injection.allowed_types", "input injection type is not allowed"
    )


#: Built-in credential detectors consulted by ``browser_automation`` when
#: ``credential_detection`` is true (core spec 3.11). Documents needing
#: portable detection list their own patterns in ``extra_credential_patterns``.
BUILTIN_CREDENTIAL_PATTERNS: tuple[tuple[str, str], ...] = (
    ("aws_access_key", "(AKIA|ASIA)[0-9A-Z]{16}"),
    ("github_token", "gh[opsur]_[A-Za-z0-9]{36}"),
    ("github_fine_grained_pat", "github_pat_[0-9a-zA-Z_]{50,}"),
    ("openai_key", "sk-[A-Za-z0-9_-]{20,}"),
    ("slack_token", "xox[baprs]-[0-9A-Za-z-]{10,}"),
    (
        "private_key",
        "-----BEGIN[ \\t]+(RSA[ \\t]+|EC[ \\t]+|OPENSSH[ \\t]+)?PRIVATE[ \\t]+KEY-----",
    ),
    (
        "jwt",
        "eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}",
    ),
)


def evaluate_browser_automation(
    rule: BrowserAutomationRule, action: EvaluationAction
) -> _BlockDecision:
    verb = action.target or ""

    # 1. verb allowlist (exact match).
    if rule.allowed_verbs and verb not in rule.allowed_verbs:
        return _deny(
            "rules.browser_automation.allowed_verbs",
            "browser verb is not in the allowlist",
        )

    # 2. destination host.
    if action.url is not None:
        host = normalize_host(action.url)
        if _any_host_pattern_matches(rule.blocked_domains, host):
            return _deny(
                "rules.browser_automation.blocked_domains",
                "destination host is explicitly blocked",
            )
        if rule.allowed_domains and not _any_host_pattern_matches(
            rule.allowed_domains, host
        ):
            return _deny(
                "rules.browser_automation.allowed_domains",
                "destination host is not in the allowlist",
            )

    # 3. credential detection on typed input.
    if rule.credential_detection and action.content is not None:
        content = action.content
        for name, pattern in BUILTIN_CREDENTIAL_PATTERNS:
            try:
                compiled = compile_profile_regex(pattern)
            except ValueError:
                continue
            if compiled.search(content):
                return _deny(
                    "rules.browser_automation.credential_detection",
                    f"typed input matched built-in credential detector '{name}'",
                )
        for index, pattern in enumerate(rule.extra_credential_patterns):
            try:
                compiled = compile_profile_regex(pattern)
            except ValueError as exc:
                return _deny(
                    f"rules.browser_automation.extra_credential_patterns[{index}]",
                    f"credential pattern is invalid: {exc}",
                )
            if compiled.search(content):
                return _deny(
                    "rules.browser_automation.credential_detection",
                    f"typed input matched extra_credential_patterns[{index}]",
                )

    return _allow("rules.browser_automation", "browser action is permitted")


def evaluate_code_execution(
    rule: CodeExecutionRule, action: EvaluationAction
) -> _BlockDecision:
    language = action.target or ""

    # 1. language allowlist (exact, case-sensitive).
    if rule.language_allowlist and language not in rule.language_allowlist:
        return _deny(
            "rules.code_execution.language_allowlist",
            "language is not in the allowlist",
        )

    # 2. network access.
    if action.network is True and not rule.network_access:
        return _deny(
            "rules.code_execution.network_access",
            "network access is not permitted for code execution",
        )

    # 3. execution time bound.
    if (
        rule.max_execution_time_ms is not None
        and action.timeout_ms is not None
        and action.timeout_ms > rule.max_execution_time_ms
    ):
        return _deny(
            "rules.code_execution.max_execution_time_ms",
            "requested execution time exceeds max_execution_time_ms",
        )

    # 4. module denylist: literal word match within the scanned prefix.
    if action.content is not None:
        scanned = _scan_prefix(action.content, rule.max_scan_bytes)
        for module in rule.module_denylist:
            if contains_word(scanned, module):
                return _deny(
                    "rules.code_execution.module_denylist",
                    f"code references denied module '{module}'",
                )

    return _allow("rules.code_execution", "code execution is permitted")


def _scan_prefix(content: str, max_scan_bytes: Optional[int]) -> str:
    """The leading ``max_scan_bytes`` UTF-8 bytes of *content*, truncated to a
    character boundary (mirrors Rust's byte slice with boundary back-off)."""
    if max_scan_bytes is None:
        return content
    encoded = content.encode("utf-8")
    if max_scan_bytes >= len(encoded):
        return content
    end = max_scan_bytes
    while end > 0 and (encoded[end] & 0xC0) == 0x80:
        end -= 1
    return encoded[:end].decode("utf-8", errors="ignore")


def _is_word_char(ch: str) -> bool:
    return ch.isascii() and (ch.isalnum() or ch == "_")


def contains_word(text: str, word: str) -> bool:
    """Whether *word* occurs in *text* bounded by non-``[A-Za-z0-9_]``
    characters or the text boundaries (core spec 3.12 step 4)."""
    if not word:
        return False
    start = 0
    while True:
        at = text.find(word, start)
        if at < 0:
            return False
        end = at + len(word)
        before_ok = at == 0 or not _is_word_char(text[at - 1])
        after_ok = end == len(text) or not _is_word_char(text[end])
        if before_ok and after_ok:
            return True
        start = at + 1
        if start >= len(text):
            return False


# ---------------------------------------------------------------------------
# Posture and origins
# ---------------------------------------------------------------------------


_REQUIRED_CAPABILITIES: dict[str, str] = {
    "file_read": "file_access",
    "file_write": "file_write",
    "patch_apply": "patch",
    "shell_command": "shell",
    "tool_call": "tool_call",
    "egress": "egress",
    "custom": "custom",
}


def required_capability(action_type: str) -> Optional[str]:
    """Capability the posture guard requires per action type (posture 3.3)."""
    return _REQUIRED_CAPABILITIES.get(action_type)


_TRIGGER_NAMES: dict[TransitionTrigger, str] = {
    TransitionTrigger.USER_APPROVAL: "user_approval",
    TransitionTrigger.USER_DENIAL: "user_denial",
    TransitionTrigger.CRITICAL_VIOLATION: "critical_violation",
    TransitionTrigger.ANY_VIOLATION: "any_violation",
    TransitionTrigger.TIMEOUT: "timeout",
    TransitionTrigger.BUDGET_EXHAUSTED: "budget_exhausted",
    TransitionTrigger.PATTERN_MATCH: "pattern_match",
}


def _trigger_name(trigger: TransitionTrigger) -> str:
    return _TRIGGER_NAMES.get(trigger, "")


def _next_posture_state(
    posture_ext: PostureExtension, current: str, signal: str
) -> Optional[str]:
    # D18 (pending): first matching transition in document order.
    for transition in posture_ext.transitions:
        if transition.from_state != "*" and transition.from_state != current:
            continue
        if _trigger_name(transition.on) != signal:
            continue
        return transition.to
    return None


def resolve_posture(
    spec: HushSpec,
    matched_profile: Optional[OriginProfile],
    posture: Optional[PostureContext],
) -> Optional[PostureResult]:
    if spec.extensions is None or spec.extensions.posture is None:
        return None
    posture_ext = spec.extensions.posture

    current: Optional[str] = None
    if matched_profile is not None and matched_profile.posture is not None:
        current = matched_profile.posture
    elif posture is not None and posture.current is not None:
        current = posture.current
    if current is None:
        current = posture_ext.initial

    signal: Optional[str] = None
    if posture is not None and posture.signal is not None and posture.signal != "none":
        signal = posture.signal

    if signal is not None:
        next_state = _next_posture_state(posture_ext, current, signal)
        if next_state is not None:
            return PostureResult(current=current, next=next_state)

    return PostureResult(current=current, next=current)


def _match_origin(rules: OriginMatch, origin: OriginContext) -> Optional[int]:
    """Number of ``match`` fields satisfied by *origin*, or ``None`` when any
    present field is not satisfied. ``tags`` counts as one field."""
    count = 0
    pairs = (
        (rules.provider, origin.provider),
        (rules.tenant_id, origin.tenant_id),
        (rules.space_id, origin.space_id),
        (rules.space_type, origin.space_type),
        (rules.visibility, origin.visibility),
        (rules.sensitivity, origin.sensitivity),
        (rules.actor_role, origin.actor_role),
    )
    for expected, actual in pairs:
        if expected is None:
            continue
        if actual != expected:
            return None
        count += 1

    if rules.external_participants is not None:
        if origin.external_participants != rules.external_participants:
            return None
        count += 1

    if rules.tags:
        if not all(tag in origin.tags for tag in rules.tags):
            return None
        count += 1

    return count


def select_origin_profile(
    spec: HushSpec, origin: Optional[OriginContext]
) -> Optional[OriginProfile]:
    """Origin profile selection (origins spec Section 3): candidates are
    profiles with a ``match`` object every present field of which is satisfied;
    a ``space_id`` match wins outright, then the greatest matched-field count,
    then document order."""
    if origin is None:
        return None
    if spec.extensions is None or spec.extensions.origins is None:
        return None

    best: Optional[tuple[int, OriginProfile]] = None
    for profile in spec.extensions.origins.profiles:
        if profile.match_rules is None:
            continue
        matched_fields = _match_origin(profile.match_rules, origin)
        if matched_fields is None:
            continue
        if profile.match_rules.space_id is not None:
            return profile
        if best is None or matched_fields > best[0]:
            best = (matched_fields, profile)

    return best[1] if best is not None else None


# ---------------------------------------------------------------------------
# Path globs (core spec 3.14.1)
# ---------------------------------------------------------------------------


def normalize_path(target: str) -> str:
    """Normalize a filesystem path for matching: NFC, ``\\`` to ``/``,
    collapsed separators, lexical ``.``/``..`` resolution, no trailing ``/``."""
    unified = unicodedata.normalize("NFC", target).replace("\\", "/")
    absolute = unified.startswith("/")
    segments: list[str] = []
    for segment in unified.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments and segments[-1] != "..":
                segments.pop()
            elif absolute:
                pass
            else:
                segments.append("..")
            continue
        segments.append(segment)
    joined = "/".join(segments)
    return f"/{joined}" if absolute else joined


def _path_glob_regex(pattern: str) -> Optional[re.Pattern[str]]:
    """Compile a path glob (core spec 3.14.1) into an anchored regex."""
    chars = list(unicodedata.normalize("NFC", pattern))
    regex = "^"
    index = 0
    length = len(chars)
    while index < length:
        ch = chars[index]
        if ch == "*" and index + 1 < length and chars[index + 1] == "*":
            at_segment_start = index == 0 or chars[index - 1] == "/"
            if (
                at_segment_start
                and index + 2 < length
                and chars[index + 2] == "/"
            ):
                # `**/`: zero or more complete leading segments.
                regex += "(?:[^/]*/)*"
                index += 3
            else:
                regex += ".*"
                index += 2
            continue
        if ch == "*":
            regex += "[^/]*"
        elif ch == "?":
            regex += "[^/]"
        else:
            regex += re.escape(ch)
        index += 1
    # \Z (not $): Python's `$` also matches just before a trailing "\n", so a
    # glob like "internal.corp" would wrongly match "internal.corp\n". \Z is a
    # true end-of-string anchor with no newline exception, matching Rust
    # `regex`/Go RE2/JS non-multiline `$` end-of-text semantics.
    regex += r"\Z"
    try:
        return re.compile(regex)
    except re.error:
        return None


def path_glob_matches(pattern: str, path: str) -> bool:
    """Whether *path* (already normalized) matches the path glob *pattern*."""
    compiled = _path_glob_regex(pattern)
    return compiled is not None and compiled.search(path) is not None


def _any_path_glob_matches(patterns: list[str], path: str) -> bool:
    return any(path_glob_matches(pattern, path) for pattern in patterns)


def glob_matches(pattern: str, target: str) -> bool:
    """Match a raw path target against a path glob, normalizing it first.

    Kept for callers outside the evaluator (lint, diff); prefer
    :func:`path_glob_matches` with an already-normalized path.
    """
    return path_glob_matches(pattern, normalize_path(target))


# ---------------------------------------------------------------------------
# Host patterns (core spec 3.14.2)
# ---------------------------------------------------------------------------

_HOST_CHARS = re.compile(r"\A[0-9A-Za-z._-]+\Z")
_ASCII_DIGITS = re.compile(r"\A[0-9]+\Z")
_IPV6_INNER = re.compile(r"\A[0-9A-Fa-f:.]+\Z")


def normalize_host(target: str) -> Optional[str]:
    """Reduce an egress target (host, ``host:port``, or URL) to a normalized
    host. Returns ``None`` when the target cannot be reduced to a
    syntactically valid host, in which case it matches nothing."""
    if not isinstance(target, str):
        return None
    target = target.strip()
    scheme = target.find("://")
    authority = target[scheme + 3 :] if scheme >= 0 else target
    end = len(authority)
    for ch in ("/", "?", "#"):
        found = authority.find(ch)
        if found >= 0:
            end = min(end, found)
    authority = authority[:end]
    at = authority.rfind("@")
    if at >= 0:
        authority = authority[at + 1 :]
    if not authority:
        return None

    if authority.startswith("["):
        rest = authority[1:]
        close = rest.find("]")
        if close < 0:
            return None
        inner = rest[:close]
        if not inner or _IPV6_INNER.match(inner) is None:
            return None
        return f"[{inner.lower()}]"

    host = authority
    colon = host.rfind(":")
    if colon >= 0:
        port = host[colon + 1 :]
        if port and _ASCII_DIGITS.match(port) is not None:
            host = host[:colon]
    if ":" in host:
        return None
    if host.endswith("."):
        host = host[:-1]
    if not host:
        return None

    labels: list[str] = []
    for label in host.split("."):
        if not label:
            return None
        normalized_label = _normalize_host_label(label)
        if normalized_label is None:
            return None
        labels.append(normalized_label)
    normalized = ".".join(labels)
    if _HOST_CHARS.match(normalized) is None:
        return None
    return normalized


def _normalize_host_label(label: str) -> Optional[str]:
    """Normalize one host label: ASCII lowercase, or the IDNA A-label
    (punycode) of the NFC-normalized, lowercased label when it is not ASCII."""
    if label.isascii():
        return label.lower()
    folded = unicodedata.normalize("NFC", label.lower())
    if folded.isascii():
        return folded
    encoded = punycode_encode(folded)
    if encoded is None:
        return None
    return f"xn--{encoded}"


def _normalize_host_pattern(pattern: str) -> str:
    """Normalize a host pattern (steps 5-7 of core spec 3.14.2), keeping ``*``."""
    pattern = pattern.strip()
    if pattern.endswith("."):
        pattern = pattern[:-1]
    if pattern.startswith("["):
        return pattern.lower()
    labels = []
    for label in pattern.split("."):
        if label.isascii():
            labels.append(label.lower())
        else:
            normalized = _normalize_host_label(label)
            labels.append(normalized if normalized is not None else label.lower())
    return ".".join(labels)


def _is_ipv4_literal(host: str) -> bool:
    octets = host.split(".")
    if len(octets) != 4:
        return False
    for octet in octets:
        if not octet or len(octet) > 3 or _ASCII_DIGITS.match(octet) is None:
            return False
        if int(octet) > 255:
            return False
    return True


def _is_ip_literal(host: str) -> bool:
    return host.startswith("[") or _is_ipv4_literal(host)


def host_pattern_matches(pattern: str, host: str) -> bool:
    """Whether a normalized *host* matches a host pattern (core spec 3.14.2):
    ``*`` is one or more non-dot characters, ``**`` one or more characters
    including dots, everything else literal. IP literals match only exactly."""
    pattern = _normalize_host_pattern(pattern)
    if _is_ip_literal(host):
        return pattern == host
    regex = "^"
    chars = list(pattern)
    index = 0
    length = len(chars)
    while index < length:
        if chars[index] == "*":
            if index + 1 < length and chars[index + 1] == "*":
                regex += ".+"
                index += 2
            else:
                regex += "[^.]+"
                index += 1
            continue
        regex += re.escape(chars[index])
        index += 1
    regex += r"\Z"
    try:
        compiled = re.compile(regex)
    except re.error:
        return False
    return compiled.search(host) is not None


def _any_host_pattern_matches(patterns: list[str], host: Optional[str]) -> bool:
    if host is None:
        return False
    return any(host_pattern_matches(pattern, host) for pattern in patterns)


_PUNYCODE_BASE = 36
_PUNYCODE_TMIN = 1
_PUNYCODE_TMAX = 26
_PUNYCODE_SKEW = 38
_PUNYCODE_DAMP = 700
_PUNYCODE_INITIAL_BIAS = 72
_PUNYCODE_INITIAL_N = 128
_U32_MAX = 0xFFFFFFFF


def _punycode_adapt(delta: int, num_points: int, first_time: bool) -> int:
    delta = delta // _PUNYCODE_DAMP if first_time else delta // 2
    delta += delta // num_points
    k = 0
    while delta > ((_PUNYCODE_BASE - _PUNYCODE_TMIN) * _PUNYCODE_TMAX) // 2:
        delta //= _PUNYCODE_BASE - _PUNYCODE_TMIN
        k += _PUNYCODE_BASE
    return k + (((_PUNYCODE_BASE - _PUNYCODE_TMIN + 1) * delta) // (delta + _PUNYCODE_SKEW))


def _punycode_digit(value: int) -> str:
    if value < 26:
        return chr(ord("a") + value)
    return chr(ord("0") + value - 26)


def punycode_encode(text: str) -> Optional[str]:
    """RFC 3492 punycode encoding of one label (without the ``xn--`` prefix)."""
    code_points = [ord(ch) for ch in text]
    output = [chr(cp) for cp in code_points if cp < 128]
    basic_count = len(output)
    handled = basic_count
    if basic_count > 0:
        output.append("-")

    n = _PUNYCODE_INITIAL_N
    delta = 0
    bias = _PUNYCODE_INITIAL_BIAS
    while handled < len(code_points):
        candidates = [cp for cp in code_points if cp >= n]
        if not candidates:
            return None
        m = min(candidates)
        delta += (m - n) * (handled + 1)
        if delta > _U32_MAX:
            return None
        n = m
        for cp in code_points:
            if cp < n:
                delta += 1
                if delta > _U32_MAX:
                    return None
            if cp == n:
                q = delta
                k = _PUNYCODE_BASE
                while True:
                    if k <= bias:
                        t = _PUNYCODE_TMIN
                    elif k >= bias + _PUNYCODE_TMAX:
                        t = _PUNYCODE_TMAX
                    else:
                        t = k - bias
                    if q < t:
                        break
                    output.append(_punycode_digit(t + (q - t) % (_PUNYCODE_BASE - t)))
                    q = (q - t) // (_PUNYCODE_BASE - t)
                    k += _PUNYCODE_BASE
                output.append(_punycode_digit(q))
                bias = _punycode_adapt(delta, handled + 1, handled == basic_count)
                delta = 0
                handled += 1
        delta += 1
        n += 1
        if delta > _U32_MAX or n > _U32_MAX:
            return None
    return "".join(output)


# ---------------------------------------------------------------------------
# Patch statistics
# ---------------------------------------------------------------------------


def patch_stats(content: str) -> _PatchStats:
    additions = 0
    deletions = 0
    # `str.splitlines()` also splits on \r, \v, \f, and the Unicode NEL/LS/PS
    # line separators, but Rust's `.lines()` and the TS/Go SDKs only split on
    # \n. A bare \r (no \n) inside patch content would otherwise be treated
    # as a line break here but not in the other three SDKs, double-counting
    # additions/deletions. Splitting on "\n" alone keeps the count identical
    # across all four SDKs.
    for line in content.split("\n"):
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            additions += 1
        elif line.startswith("-"):
            deletions += 1
    return _PatchStats(additions=additions, deletions=deletions)


def imbalance_ratio(additions: int, deletions: int) -> float:
    if additions == 0 and deletions == 0:
        return 0.0
    if additions == 0:
        return float(deletions)
    if deletions == 0:
        return float(additions)
    larger = float(max(additions, deletions))
    smaller = float(min(additions, deletions))
    return larger / smaller


# ---------------------------------------------------------------------------
# Panic protocol
# ---------------------------------------------------------------------------


_panic_active = False


def activate_panic() -> None:
    global _panic_active
    _panic_active = True


def deactivate_panic() -> None:
    global _panic_active
    _panic_active = False


def is_panic_active() -> bool:
    return _panic_active


def panic_policy() -> HushSpec:
    from hushspec.parse import parse_or_raise

    return parse_or_raise(PANIC_POLICY_YAML)


def check_panic_sentinel(path: str) -> bool:
    """Activate panic mode if the sentinel file at *path* exists.

    This is a kill switch, so it **fails closed**: if the file's existence
    cannot be determined (a permission or other I/O error from ``os.stat``),
    the sentinel is treated as present and panic mode is activated. Only a
    definitive "not found" (``FileNotFoundError`` / ``NotADirectoryError``)
    counts as absent. This mirrors Rust's ``try_exists().unwrap_or(true)`` --
    ``os.path.isfile`` was wrong here because it silently returns ``False`` on
    any stat error, letting the kill switch fail OPEN.
    """
    import os

    try:
        os.stat(path)
        present = True
    except (FileNotFoundError, NotADirectoryError):
        present = False
    except OSError:
        # Could not prove the sentinel is absent (e.g. PermissionError);
        # treat it as present so the kill switch never fails open.
        present = True

    if present:
        activate_panic()
    return present
