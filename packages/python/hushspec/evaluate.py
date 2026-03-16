from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from hushspec.extensions import (
    OriginMatch,
    OriginProfile,
    PostureExtension,
    TransitionTrigger,
)
from hushspec.rules import (
    ComputerUseMode,
    ComputerUseRule,
    DefaultAction,
    EgressRule,
    ForbiddenPathsRule,
    PatchIntegrityRule,
    PathAllowlistRule,
    SecretPatternsRule,
    ShellCommandsRule,
    ToolAccessRule,
)
from hushspec.schema import HushSpec

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
"""



class Decision(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    DENY = "deny"


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




class _PathOperation(Enum):
    READ = "read"
    WRITE = "write"
    PATCH = "patch"


@dataclass
class _PatchStats:
    additions: int
    deletions: int




def _allow_result(
    matched_rule: Optional[str],
    reason: Optional[str],
    origin_profile: Optional[str],
    posture: Optional[PostureResult],
) -> EvaluationResult:
    return EvaluationResult(
        decision=Decision.ALLOW,
        matched_rule=matched_rule,
        reason=reason,
        origin_profile=origin_profile,
        posture=posture,
    )


def _warn_result(
    matched_rule: Optional[str],
    reason: Optional[str],
    origin_profile: Optional[str],
    posture: Optional[PostureResult],
) -> EvaluationResult:
    return EvaluationResult(
        decision=Decision.WARN,
        matched_rule=matched_rule,
        reason=reason,
        origin_profile=origin_profile,
        posture=posture,
    )


def _deny_result(
    matched_rule: Optional[str],
    reason: Optional[str],
    origin_profile: Optional[str],
    posture: Optional[PostureResult],
) -> EvaluationResult:
    return EvaluationResult(
        decision=Decision.DENY,
        matched_rule=matched_rule,
        reason=reason,
        origin_profile=origin_profile,
        posture=posture,
    )




def glob_matches(pattern: str, target: str) -> bool:
    """Convert a HushSpec glob pattern to regex and test against *target*.

    ``*``  matches any character except ``/``.
    ``**`` matches any character (including ``/``).
    ``?``  matches a single character.
    All other regex meta-characters are escaped.
    """
    regex = "^"
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                regex += ".*"
                i += 2
                continue
            regex += "[^/]*"
        elif ch == "?":
            regex += "."
        elif ch in r"\.+(){}[]^$|":
            regex += "\\" + ch
        else:
            regex += ch
        i += 1
    regex += "$"
    try:
        return re.search(regex, target) is not None
    except re.error:
        return False


def _find_first_match(target: str, patterns: list[str]) -> Optional[int]:
    for index, pattern in enumerate(patterns):
        if glob_matches(pattern, target):
            return index
    return None




def _prefixed_rule(prefix: Optional[str], suffix: str) -> Optional[str]:
    if prefix is not None:
        return f"{prefix}.{suffix}"
    return None


def _profile_rule_prefix(profile_id: str, field_name: str) -> str:
    return f"extensions.origins.profiles.{profile_id}.{field_name}"




def patch_stats(content: str) -> _PatchStats:
    additions = 0
    deletions = 0
    for line in content.splitlines():
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




_REQUIRED_CAPABILITIES: dict[str, str] = {
    "file_read": "file_access",
    "file_write": "file_write",
    "patch_apply": "patch",
    "shell_command": "shell",
    "tool_call": "tool_call",
    "egress": "egress",
}


def required_capability(action_type: str) -> Optional[str]:
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
    score = 0

    if rules.provider is not None:
        if origin.provider != rules.provider:
            return None
        score += 4

    if rules.tenant_id is not None:
        if origin.tenant_id != rules.tenant_id:
            return None
        score += 6

    if rules.space_id is not None:
        if origin.space_id != rules.space_id:
            return None
        score += 8

    if rules.space_type is not None:
        if origin.space_type != rules.space_type:
            return None
        score += 4

    if rules.visibility is not None:
        if origin.visibility != rules.visibility:
            return None
        score += 4

    if rules.external_participants is not None:
        if origin.external_participants != rules.external_participants:
            return None
        score += 2

    if rules.tags:
        if not all(tag in origin.tags for tag in rules.tags):
            return None
        score += len(rules.tags)

    if rules.sensitivity is not None:
        if origin.sensitivity != rules.sensitivity:
            return None
        score += 4

    if rules.actor_role is not None:
        if origin.actor_role != rules.actor_role:
            return None
        score += 4

    return score


def select_origin_profile(
    spec: HushSpec, origin: Optional[OriginContext]
) -> Optional[OriginProfile]:
    if origin is None:
        return None
    if spec.extensions is None or spec.extensions.origins is None:
        return None
    profiles = spec.extensions.origins.profiles

    best: Optional[tuple[int, OriginProfile]] = None
    for profile in profiles:
        if profile.match_rules is None:
            continue
        score = _match_origin(profile.match_rules, origin)
        if score is None:
            continue
        if best is None or score > best[0]:
            best = (score, profile)

    return best[1] if best is not None else None




def posture_capability_guard(
    action: EvaluationAction,
    posture: Optional[PostureResult],
    spec: HushSpec,
    origin_profile_id: Optional[str],
) -> Optional[EvaluationResult]:
    if posture is None:
        return None
    if spec.extensions is None or spec.extensions.posture is None:
        return None
    posture_ext = spec.extensions.posture
    current_state = posture_ext.states.get(posture.current)
    if current_state is None:
        return None

    capability = required_capability(action.type)
    if capability is None:
        return None

    if capability in current_state.capabilities:
        return None

    return _deny_result(
        matched_rule=f"extensions.posture.states.{posture.current}.capabilities",
        reason=f"posture '{posture.current}' does not allow capability '{capability}'",
        origin_profile=origin_profile_id,
        posture=PostureResult(current=posture.current, next=posture.next),
    )




def evaluate_tool_access_rule(
    rule: Optional[ToolAccessRule],
    prefix: Optional[str],
    target: str,
    args_size: Optional[int],
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> EvaluationResult:
    if rule is None:
        return _allow_result(None, None, origin_profile_id, posture)

    if not rule.enabled:
        return _allow_result(None, None, origin_profile_id, posture)

    if rule.max_args_size is not None and (args_size or 0) > rule.max_args_size:
        return _deny_result(
            _prefixed_rule(prefix, "max_args_size"),
            "tool arguments exceeded max_args_size",
            origin_profile_id,
            posture,
        )

    if _find_first_match(target, rule.block) is not None:
        return _deny_result(
            _prefixed_rule(prefix, "block"),
            "tool is explicitly blocked",
            origin_profile_id,
            posture,
        )

    if _find_first_match(target, rule.require_confirmation) is not None:
        return _warn_result(
            _prefixed_rule(prefix, "require_confirmation"),
            "tool requires confirmation",
            origin_profile_id,
            posture,
        )

    if _find_first_match(target, rule.allow) is not None:
        return _allow_result(
            _prefixed_rule(prefix, "allow"),
            "tool is explicitly allowed",
            origin_profile_id,
            posture,
        )

    if rule.default == DefaultAction.ALLOW:
        return _allow_result(
            _prefixed_rule(prefix, "default"),
            "tool matched default allow",
            origin_profile_id,
            posture,
        )
    return _deny_result(
        _prefixed_rule(prefix, "default"),
        "tool matched default block",
        origin_profile_id,
        posture,
    )


def evaluate_egress_rule(
    rule: EgressRule,
    prefix: str,
    target: str,
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> EvaluationResult:
    if not rule.enabled:
        return _allow_result(None, None, origin_profile_id, posture)

    if _find_first_match(target, rule.block) is not None:
        return _deny_result(
            _prefixed_rule(prefix, "block"),
            "domain is explicitly blocked",
            origin_profile_id,
            posture,
        )

    if _find_first_match(target, rule.allow) is not None:
        return _allow_result(
            _prefixed_rule(prefix, "allow"),
            "domain is explicitly allowed",
            origin_profile_id,
            posture,
        )

    if rule.default == DefaultAction.ALLOW:
        return _allow_result(
            _prefixed_rule(prefix, "default"),
            "domain matched default allow",
            origin_profile_id,
            posture,
        )
    return _deny_result(
        _prefixed_rule(prefix, "default"),
        "domain matched default block",
        origin_profile_id,
        posture,
    )


def evaluate_secret_patterns(
    rule: SecretPatternsRule,
    target: str,
    content: str,
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> EvaluationResult:
    if not rule.enabled:
        return _allow_result(None, None, origin_profile_id, posture)

    if _find_first_match(target, rule.skip_paths) is not None:
        return _allow_result(
            "rules.secret_patterns.skip_paths",
            "path is excluded from secret scanning",
            origin_profile_id,
            posture,
        )

    for pattern in rule.patterns:
        try:
            if re.search(pattern.pattern, content):
                return _deny_result(
                    f"rules.secret_patterns.patterns.{pattern.name}",
                    f"content matched secret pattern '{pattern.name}'",
                    origin_profile_id,
                    posture,
                )
        except re.error:
            pass

    return _allow_result(None, None, origin_profile_id, posture)


def evaluate_patch_integrity(
    rule: PatchIntegrityRule,
    content: str,
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> EvaluationResult:
    if not rule.enabled:
        return _allow_result(None, None, origin_profile_id, posture)

    for index, pattern in enumerate(rule.forbidden_patterns):
        try:
            if re.search(pattern, content):
                return _deny_result(
                    f"rules.patch_integrity.forbidden_patterns[{index}]",
                    "patch content matched a forbidden pattern",
                    origin_profile_id,
                    posture,
                )
        except re.error:
            pass

    stats = patch_stats(content)

    if stats.additions > rule.max_additions:
        return _deny_result(
            "rules.patch_integrity.max_additions",
            "patch additions exceeded max_additions",
            origin_profile_id,
            posture,
        )

    if stats.deletions > rule.max_deletions:
        return _deny_result(
            "rules.patch_integrity.max_deletions",
            "patch deletions exceeded max_deletions",
            origin_profile_id,
            posture,
        )

    if rule.require_balance:
        ratio = imbalance_ratio(stats.additions, stats.deletions)
        if ratio > rule.max_imbalance_ratio:
            return _deny_result(
                "rules.patch_integrity.max_imbalance_ratio",
                "patch exceeded max imbalance ratio",
                origin_profile_id,
                posture,
            )

    return _allow_result(None, None, origin_profile_id, posture)


def evaluate_shell_rule(
    rule: ShellCommandsRule,
    target: str,
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> EvaluationResult:
    if not rule.enabled:
        return _allow_result(None, None, origin_profile_id, posture)

    for index, pattern in enumerate(rule.forbidden_patterns):
        try:
            if re.search(pattern, target):
                return _deny_result(
                    f"rules.shell_commands.forbidden_patterns[{index}]",
                    "shell command matched a forbidden pattern",
                    origin_profile_id,
                    posture,
                )
        except re.error:
            pass

    return _allow_result(None, None, origin_profile_id, posture)


def evaluate_computer_use_rule(
    rule: ComputerUseRule,
    target: str,
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> EvaluationResult:
    if not rule.enabled:
        return _allow_result(None, None, origin_profile_id, posture)

    if target in rule.allowed_actions:
        return _allow_result(
            "rules.computer_use.allowed_actions",
            "computer-use action is explicitly allowed",
            origin_profile_id,
            posture,
        )

    if rule.mode == ComputerUseMode.OBSERVE:
        return _allow_result(
            "rules.computer_use.mode",
            "observe mode does not block unlisted actions",
            origin_profile_id,
            posture,
        )
    elif rule.mode == ComputerUseMode.GUARDRAIL:
        return _warn_result(
            "rules.computer_use.mode",
            "guardrail mode warns on unlisted actions",
            origin_profile_id,
            posture,
        )
    else:  # FAIL_CLOSED
        return _deny_result(
            "rules.computer_use.mode",
            "fail_closed mode denies unlisted actions",
            origin_profile_id,
            posture,
        )




def evaluate_forbidden_paths(
    rule: ForbiddenPathsRule,
    target: str,
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> Optional[EvaluationResult]:
    if not rule.enabled:
        return None

    if _find_first_match(target, rule.exceptions) is not None:
        return _allow_result(
            "rules.forbidden_paths.exceptions",
            "path matched an explicit exception",
            origin_profile_id,
            posture,
        )

    if _find_first_match(target, rule.patterns) is not None:
        return _deny_result(
            "rules.forbidden_paths.patterns",
            "path matched a forbidden pattern",
            origin_profile_id,
            posture,
        )

    return None


def evaluate_path_allowlist(
    rule: PathAllowlistRule,
    target: str,
    operation: _PathOperation,
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> Optional[EvaluationResult]:
    if not rule.enabled:
        return None

    if operation == _PathOperation.READ:
        patterns = rule.read
    elif operation == _PathOperation.WRITE:
        patterns = rule.write
    else:  # PATCH
        patterns = rule.patch if rule.patch else rule.write

    if _find_first_match(target, patterns) is not None:
        return _allow_result(
            "rules.path_allowlist",
            "path matched allowlist",
            origin_profile_id,
            posture,
        )

    return _deny_result(
        "rules.path_allowlist",
        "path did not match allowlist",
        origin_profile_id,
        posture,
    )


def _evaluate_path_guards(
    spec: HushSpec,
    target: str,
    operation: _PathOperation,
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> Optional[EvaluationResult]:
    if spec.rules is None:
        return None

    if spec.rules.forbidden_paths is not None:
        result = evaluate_forbidden_paths(
            spec.rules.forbidden_paths, target, posture, origin_profile_id
        )
        if result is not None:
            return result

    if spec.rules.path_allowlist is not None:
        result = evaluate_path_allowlist(
            spec.rules.path_allowlist, target, operation, posture, origin_profile_id
        )
        if result is not None:
            return result

    return None




def _evaluate_tool_call(
    spec: HushSpec,
    action: EvaluationAction,
    matched_profile: Optional[OriginProfile],
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> EvaluationResult:
    rule: Optional[ToolAccessRule] = None
    prefix: Optional[str] = None

    if matched_profile is not None and matched_profile.tool_access is not None:
        rule = matched_profile.tool_access
        prefix = _profile_rule_prefix(matched_profile.id, "tool_access")
    elif spec.rules is not None and spec.rules.tool_access is not None:
        rule = spec.rules.tool_access
        prefix = "rules.tool_access"

    return evaluate_tool_access_rule(
        rule,
        prefix,
        action.target or "",
        action.args_size,
        posture,
        origin_profile_id,
    )


def _evaluate_egress(
    spec: HushSpec,
    action: EvaluationAction,
    matched_profile: Optional[OriginProfile],
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> EvaluationResult:
    rule: Optional[EgressRule] = None
    prefix: Optional[str] = None

    if matched_profile is not None and matched_profile.egress is not None:
        rule = matched_profile.egress
        prefix = _profile_rule_prefix(matched_profile.id, "egress")
    elif spec.rules is not None and spec.rules.egress is not None:
        rule = spec.rules.egress
        prefix = "rules.egress"

    if rule is not None:
        return evaluate_egress_rule(
            rule,
            prefix or "rules.egress",
            action.target or "",
            posture,
            origin_profile_id,
        )
    return _allow_result(None, None, origin_profile_id, posture)


def _evaluate_file_read(
    spec: HushSpec,
    action: EvaluationAction,
    _matched_profile: Optional[OriginProfile],
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> EvaluationResult:
    result = _evaluate_path_guards(
        spec, action.target or "", _PathOperation.READ, posture, origin_profile_id
    )
    if result is not None:
        return result
    return _allow_result(None, None, origin_profile_id, posture)


def _evaluate_file_write(
    spec: HushSpec,
    action: EvaluationAction,
    _matched_profile: Optional[OriginProfile],
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> EvaluationResult:
    result = _evaluate_path_guards(
        spec, action.target or "", _PathOperation.WRITE, posture, origin_profile_id
    )
    if result is not None:
        return result

    if spec.rules is not None and spec.rules.secret_patterns is not None:
        return evaluate_secret_patterns(
            spec.rules.secret_patterns,
            action.target or "",
            action.content or "",
            posture,
            origin_profile_id,
        )

    return _allow_result(None, None, origin_profile_id, posture)


def _evaluate_patch(
    spec: HushSpec,
    action: EvaluationAction,
    _matched_profile: Optional[OriginProfile],
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> EvaluationResult:
    result = _evaluate_path_guards(
        spec, action.target or "", _PathOperation.PATCH, posture, origin_profile_id
    )
    if result is not None:
        return result

    if spec.rules is not None and spec.rules.patch_integrity is not None:
        return evaluate_patch_integrity(
            spec.rules.patch_integrity,
            action.content or "",
            posture,
            origin_profile_id,
        )

    return _allow_result(None, None, origin_profile_id, posture)


def _evaluate_shell_command(
    spec: HushSpec,
    action: EvaluationAction,
    _matched_profile: Optional[OriginProfile],
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> EvaluationResult:
    if spec.rules is not None and spec.rules.shell_commands is not None:
        return evaluate_shell_rule(
            spec.rules.shell_commands,
            action.target or "",
            posture,
            origin_profile_id,
        )
    return _allow_result(None, None, origin_profile_id, posture)


def _evaluate_computer_use(
    spec: HushSpec,
    action: EvaluationAction,
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> EvaluationResult:
    if spec.rules is not None and spec.rules.computer_use is not None:
        return evaluate_computer_use_rule(
            spec.rules.computer_use,
            action.target or "",
            posture,
            origin_profile_id,
        )
    return _allow_result(None, None, origin_profile_id, posture)




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
    """Activate panic mode if the sentinel file at *path* exists."""
    import os

    exists = os.path.isfile(path)
    if exists:
        activate_panic()
    return exists




def evaluate(spec: HushSpec, action: EvaluationAction) -> EvaluationResult:
    if _panic_active:
        return EvaluationResult(
            decision=Decision.DENY,
            matched_rule="__hushspec_panic__",
            reason="emergency panic mode is active",
        )

    matched_profile = select_origin_profile(spec, action.origin)
    origin_profile_id = matched_profile.id if matched_profile is not None else None
    posture = resolve_posture(spec, matched_profile, action.posture)

    denied = posture_capability_guard(action, posture, spec, origin_profile_id)
    if denied is not None:
        return denied

    action_type = action.type

    if action_type == "tool_call":
        return _evaluate_tool_call(
            spec, action, matched_profile, posture, origin_profile_id
        )
    elif action_type == "egress":
        return _evaluate_egress(
            spec, action, matched_profile, posture, origin_profile_id
        )
    elif action_type == "file_read":
        return _evaluate_file_read(
            spec, action, matched_profile, posture, origin_profile_id
        )
    elif action_type == "file_write":
        return _evaluate_file_write(
            spec, action, matched_profile, posture, origin_profile_id
        )
    elif action_type == "patch_apply":
        return _evaluate_patch(
            spec, action, matched_profile, posture, origin_profile_id
        )
    elif action_type == "shell_command":
        return _evaluate_shell_command(
            spec, action, matched_profile, posture, origin_profile_id
        )
    elif action_type == "computer_use":
        return _evaluate_computer_use(spec, action, posture, origin_profile_id)
    else:
        return EvaluationResult(
            decision=Decision.ALLOW,
            matched_rule=None,
            reason="no reference evaluator rule for this action type",
            origin_profile=origin_profile_id,
            posture=posture,
        )
