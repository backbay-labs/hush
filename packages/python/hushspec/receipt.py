from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from hushspec.evaluate import (
    Decision,
    EvaluationAction,
    EvaluationResult,
    PostureResult,
    evaluate,
)
from hushspec.schema import HushSpec
from hushspec.version import HUSHSPEC_VERSION





@dataclass
class ActionSummary:
    type: str
    target: Optional[str] = None
    content_redacted: bool = False


@dataclass
class RuleEvaluation:
    rule_block: str
    outcome: str  # 'allow' | 'warn' | 'deny' | 'skip'
    evaluated: bool
    matched_rule: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class PolicySummary:
    version: str
    content_hash: str
    name: Optional[str] = None


@dataclass
class AuditConfig:
    enabled: bool = True
    include_rule_trace: bool = True
    redact_content: bool = True


@dataclass
class EnforcementSummary:
    """How the runtime applied a decision.

    DecisionReceipt.decision is always the evaluated policy decision;
    this records what the enforcement point did with it.
    """

    mode: str      # 'enforce' | 'monitor'
    outcome: str   # 'allowed' | 'confirmed' | 'blocked' | 'would_block'


@dataclass
class DecisionReceipt:
    receipt_id: str
    timestamp: str
    hushspec_version: str
    action: ActionSummary
    decision: Decision
    rule_trace: list[RuleEvaluation]
    policy: PolicySummary
    evaluation_duration_us: int
    matched_rule: Optional[str] = None
    reason: Optional[str] = None
    origin_profile: Optional[str] = None
    posture: Optional[PostureResult] = None
    enforcement: Optional[EnforcementSummary] = None





def evaluate_audited(
    spec: HushSpec,
    action: EvaluationAction,
    config: AuditConfig,
) -> DecisionReceipt:
    start_ns = time.perf_counter_ns() if config.enabled else 0
    result = evaluate(spec, action)

    duration_us = (
        (time.perf_counter_ns() - start_ns) // 1000 if config.enabled else 0
    )

    rule_trace: list[RuleEvaluation] = (
        _collect_rule_trace(spec, action, result)
        if config.enabled and config.include_rule_trace
        else []
    )

    # The policy content hash is a single cheap hash and is required by the
    # receipt schema (`^[0-9a-f]{64}$`), so it is always computed regardless
    # of config.enabled. Only the expensive rule-trace collection above is
    # skipped when audit is disabled.
    policy = _build_policy_summary(spec)

    action_summary = ActionSummary(
        type=action.type,
        target=action.target,
        content_redacted=config.redact_content and action.content is not None,
    )

    return DecisionReceipt(
        receipt_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        hushspec_version=HUSHSPEC_VERSION,
        action=action_summary,
        decision=result.decision,
        matched_rule=result.matched_rule,
        reason=result.reason,
        rule_trace=rule_trace,
        policy=policy,
        origin_profile=result.origin_profile,
        posture=result.posture,
        evaluation_duration_us=duration_us,
    )


def compute_policy_hash(spec: HushSpec) -> str:
    spec_dict = spec.to_dict()
    json_str = json.dumps(spec_dict, separators=(",", ":"), sort_keys=False)
    return hashlib.sha256(json_str.encode("utf-8")).hexdigest()





def _build_policy_summary(spec: HushSpec) -> PolicySummary:
    return PolicySummary(
        name=spec.name,
        version=spec.hushspec,
        content_hash=compute_policy_hash(spec),
    )


def _outcome_from_decision(decision: Decision) -> str:
    return decision.value


def _collect_rule_trace(
    spec: HushSpec,
    action: EvaluationAction,
    result: EvaluationResult,
) -> list[RuleEvaluation]:
    trace: list[RuleEvaluation] = []

    if result.posture is not None:
        posture_denied = (
            result.matched_rule is not None
            and result.matched_rule.startswith("extensions.posture.states.")
        )

        if posture_denied:
            trace.append(
                RuleEvaluation(
                    rule_block="posture_capability",
                    outcome="deny",
                    matched_rule=result.matched_rule,
                    reason=result.reason,
                    evaluated=True,
                )
            )
            _append_skipped_rules(
                action, trace, "short-circuited by posture deny"
            )
            return trace

        trace.append(
            RuleEvaluation(
                rule_block="posture_capability",
                outcome="allow",
                matched_rule=None,
                reason="posture capabilities satisfied",
                evaluated=True,
            )
        )

    action_type = action.type

    if action_type == "tool_call":
        _trace_tool_access(spec, action, result, trace)
    elif action_type == "egress":
        _trace_egress(spec, result, trace)
    elif action_type == "file_read":
        _trace_path_guards(spec, result, trace)
    elif action_type == "file_write":
        _trace_path_guards(spec, result, trace)
        _trace_secret_patterns(spec, result, trace)
    elif action_type == "patch_apply":
        _trace_path_guards(spec, result, trace)
        _trace_patch_integrity(spec, result, trace)
    elif action_type == "shell_command":
        _trace_shell_commands(spec, result, trace)
    elif action_type == "computer_use":
        _trace_computer_use(spec, result, trace)
    else:
        trace.append(
            RuleEvaluation(
                rule_block="default",
                outcome=_outcome_from_decision(result.decision),
                matched_rule=result.matched_rule,
                reason=result.reason,
                evaluated=True,
            )
        )

    return trace


def _trace_tool_access(
    spec: HushSpec,
    action: EvaluationAction,
    result: EvaluationResult,
    trace: list[RuleEvaluation],
) -> None:
    has_origin_rule = (
        result.matched_rule is not None
        and result.matched_rule.startswith("extensions.origins.profiles.")
    )

    has_rule = (
        has_origin_rule
        or (spec.rules is not None and spec.rules.tool_access is not None)
        or action.origin is not None
    )

    if has_rule:
        trace.append(
            RuleEvaluation(
                rule_block="tool_access",
                outcome=_outcome_from_decision(result.decision),
                matched_rule=result.matched_rule,
                reason=result.reason,
                evaluated=True,
            )
        )
    else:
        trace.append(
            RuleEvaluation(
                rule_block="tool_access",
                outcome="skip",
                matched_rule=None,
                reason="no tool_access rule configured",
                evaluated=False,
            )
        )


def _trace_egress(
    spec: HushSpec,
    result: EvaluationResult,
    trace: list[RuleEvaluation],
) -> None:
    has_origin_rule = (
        result.matched_rule is not None and "egress" in result.matched_rule
    )

    has_rule = has_origin_rule or (
        spec.rules is not None and spec.rules.egress is not None
    )

    if has_rule:
        trace.append(
            RuleEvaluation(
                rule_block="egress",
                outcome=_outcome_from_decision(result.decision),
                matched_rule=result.matched_rule,
                reason=result.reason,
                evaluated=True,
            )
        )
    else:
        trace.append(
            RuleEvaluation(
                rule_block="egress",
                outcome="skip",
                matched_rule=None,
                reason="no egress rule configured",
                evaluated=False,
            )
        )


def _trace_path_guards(
    spec: HushSpec,
    result: EvaluationResult,
    trace: list[RuleEvaluation],
) -> None:
    rules = spec.rules
    decided_by_forbidden = (
        result.matched_rule is not None
        and "forbidden_paths" in result.matched_rule
    )
    decided_by_allowlist = (
        result.matched_rule is not None
        and "path_allowlist" in result.matched_rule
    )

    # forbidden_paths
    fp = rules.forbidden_paths if rules is not None else None
    if fp is not None:
        if fp.enabled:
            if decided_by_forbidden:
                trace.append(
                    RuleEvaluation(
                        rule_block="forbidden_paths",
                        outcome=_outcome_from_decision(result.decision),
                        matched_rule=result.matched_rule,
                        reason=result.reason,
                        evaluated=True,
                    )
                )
            else:
                trace.append(
                    RuleEvaluation(
                        rule_block="forbidden_paths",
                        outcome="allow",
                        matched_rule=None,
                        reason="path did not match any forbidden pattern",
                        evaluated=True,
                    )
                )
        else:
            trace.append(
                RuleEvaluation(
                    rule_block="forbidden_paths",
                    outcome="skip",
                    matched_rule=None,
                    reason="rule disabled",
                    evaluated=False,
                )
            )

    # path_allowlist
    pa = rules.path_allowlist if rules is not None else None
    if pa is not None:
        if pa.enabled:
            short_circuited = (
                decided_by_forbidden and result.decision == Decision.DENY
            )
            if short_circuited:
                trace.append(
                    RuleEvaluation(
                        rule_block="path_allowlist",
                        outcome="skip",
                        matched_rule=None,
                        reason="short-circuited by prior deny",
                        evaluated=False,
                    )
                )
            elif decided_by_allowlist:
                trace.append(
                    RuleEvaluation(
                        rule_block="path_allowlist",
                        outcome=_outcome_from_decision(result.decision),
                        matched_rule=result.matched_rule,
                        reason=result.reason,
                        evaluated=True,
                    )
                )
            else:
                trace.append(
                    RuleEvaluation(
                        rule_block="path_allowlist",
                        outcome="allow",
                        matched_rule=None,
                        reason="path matched allowlist",
                        evaluated=True,
                    )
                )
        else:
            trace.append(
                RuleEvaluation(
                    rule_block="path_allowlist",
                    outcome="skip",
                    matched_rule=None,
                    reason="rule disabled",
                    evaluated=False,
                )
            )


def _trace_secret_patterns(
    spec: HushSpec,
    result: EvaluationResult,
    trace: list[RuleEvaluation],
) -> None:
    decided_by_secret = (
        result.matched_rule is not None
        and "secret_patterns" in result.matched_rule
    )
    prior_deny = any(t.outcome == "deny" and t.evaluated for t in trace)

    sp = spec.rules.secret_patterns if spec.rules is not None else None
    if sp is not None:
        if sp.enabled:
            if prior_deny:
                trace.append(
                    RuleEvaluation(
                        rule_block="secret_patterns",
                        outcome="skip",
                        matched_rule=None,
                        reason="short-circuited by prior deny",
                        evaluated=False,
                    )
                )
            elif decided_by_secret:
                trace.append(
                    RuleEvaluation(
                        rule_block="secret_patterns",
                        outcome=_outcome_from_decision(result.decision),
                        matched_rule=result.matched_rule,
                        reason=result.reason,
                        evaluated=True,
                    )
                )
            else:
                trace.append(
                    RuleEvaluation(
                        rule_block="secret_patterns",
                        outcome="allow",
                        matched_rule=None,
                        reason="content did not match any secret pattern",
                        evaluated=True,
                    )
                )
        else:
            trace.append(
                RuleEvaluation(
                    rule_block="secret_patterns",
                    outcome="skip",
                    matched_rule=None,
                    reason="rule disabled",
                    evaluated=False,
                )
            )


def _trace_patch_integrity(
    spec: HushSpec,
    result: EvaluationResult,
    trace: list[RuleEvaluation],
) -> None:
    decided_by_patch = (
        result.matched_rule is not None
        and "patch_integrity" in result.matched_rule
    )
    prior_deny = any(t.outcome == "deny" and t.evaluated for t in trace)

    pi = spec.rules.patch_integrity if spec.rules is not None else None
    if pi is not None:
        if pi.enabled:
            if prior_deny:
                trace.append(
                    RuleEvaluation(
                        rule_block="patch_integrity",
                        outcome="skip",
                        matched_rule=None,
                        reason="short-circuited by prior deny",
                        evaluated=False,
                    )
                )
            elif decided_by_patch:
                trace.append(
                    RuleEvaluation(
                        rule_block="patch_integrity",
                        outcome=_outcome_from_decision(result.decision),
                        matched_rule=result.matched_rule,
                        reason=result.reason,
                        evaluated=True,
                    )
                )
            else:
                trace.append(
                    RuleEvaluation(
                        rule_block="patch_integrity",
                        outcome="allow",
                        matched_rule=None,
                        reason="patch passed integrity checks",
                        evaluated=True,
                    )
                )
        else:
            trace.append(
                RuleEvaluation(
                    rule_block="patch_integrity",
                    outcome="skip",
                    matched_rule=None,
                    reason="rule disabled",
                    evaluated=False,
                )
            )


def _trace_shell_commands(
    spec: HushSpec,
    result: EvaluationResult,
    trace: list[RuleEvaluation],
) -> None:
    decided_by_shell = (
        result.matched_rule is not None
        and "shell_commands" in result.matched_rule
    )

    sc = spec.rules.shell_commands if spec.rules is not None else None
    if sc is not None:
        if sc.enabled:
            if decided_by_shell:
                trace.append(
                    RuleEvaluation(
                        rule_block="shell_commands",
                        outcome=_outcome_from_decision(result.decision),
                        matched_rule=result.matched_rule,
                        reason=result.reason,
                        evaluated=True,
                    )
                )
            else:
                trace.append(
                    RuleEvaluation(
                        rule_block="shell_commands",
                        outcome="allow",
                        matched_rule=None,
                        reason="command did not match any forbidden pattern",
                        evaluated=True,
                    )
                )
        else:
            trace.append(
                RuleEvaluation(
                    rule_block="shell_commands",
                    outcome="skip",
                    matched_rule=None,
                    reason="rule disabled",
                    evaluated=False,
                )
            )


def _trace_computer_use(
    spec: HushSpec,
    result: EvaluationResult,
    trace: list[RuleEvaluation],
) -> None:
    decided_by_computer = (
        result.matched_rule is not None
        and "computer_use" in result.matched_rule
    )

    cu = spec.rules.computer_use if spec.rules is not None else None
    if cu is not None:
        if cu.enabled:
            if decided_by_computer:
                trace.append(
                    RuleEvaluation(
                        rule_block="computer_use",
                        outcome=_outcome_from_decision(result.decision),
                        matched_rule=result.matched_rule,
                        reason=result.reason,
                        evaluated=True,
                    )
                )
            else:
                trace.append(
                    RuleEvaluation(
                        rule_block="computer_use",
                        outcome="allow",
                        matched_rule=None,
                        reason="action allowed by computer_use rule",
                        evaluated=True,
                    )
                )
        else:
            trace.append(
                RuleEvaluation(
                    rule_block="computer_use",
                    outcome="skip",
                    matched_rule=None,
                    reason="rule disabled",
                    evaluated=False,
                )
            )


def _append_skipped_rules(
    action: EvaluationAction,
    trace: list[RuleEvaluation],
    reason: str,
) -> None:
    blocks_map = {
        "tool_call": ["tool_access"],
        "egress": ["egress"],
        "file_read": ["forbidden_paths", "path_allowlist"],
        "file_write": ["forbidden_paths", "path_allowlist", "secret_patterns"],
        "patch_apply": ["forbidden_paths", "path_allowlist", "patch_integrity"],
        "shell_command": ["shell_commands"],
        "computer_use": ["computer_use"],
    }
    blocks = blocks_map.get(action.type, [])

    for block in blocks:
        trace.append(
            RuleEvaluation(
                rule_block=block,
                outcome="skip",
                matched_rule=None,
                reason=reason,
                evaluated=False,
            )
        )
