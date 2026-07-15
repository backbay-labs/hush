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
    InputInjectionRule,
    PatchIntegrityRule,
    PathAllowlistRule,
    RemoteDesktopChannelsRule,
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

  input_injection:
    enabled: true
    allowed_types: []
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

    ``*``   matches any character except ``/``.
    ``**``  matches any character (including ``/``).
    ``**/`` matches zero or more leading path segments, so ``**/x`` matches
            both the bare ``x`` and ``a/b/x``. A standalone ``**`` (not
            followed by ``/``) stays the ``.*`` behavior above.
    ``?``   matches a single character.
    All other regex meta-characters are escaped.
    """
    regex = "^"
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                if i + 2 < len(pattern) and pattern[i + 2] == "/":
                    regex += "(?:.*/)?"
                    i += 3
                    continue
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
    # \Z (not $): Python's `$` also matches just before a trailing "\n", so
    # a glob like "internal.corp" would wrongly match "internal.corp\n". \Z
    # is a true end-of-string anchor with no newline exception, matching
    # Rust `regex`/Go RE2/JS non-multiline `$` end-of-text semantics.
    regex += r"\Z"
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


def _has_patterns(patterns: Optional[list[str]]) -> bool:
    return bool(patterns)


def _is_rule_active(rule: object) -> bool:
    return rule is not None and getattr(rule, "enabled", False) is not False


def _decision_rank(decision: Decision) -> int:
    if decision == Decision.ALLOW:
        return 1
    if decision == Decision.WARN:
        return 2
    return 3


def _more_restrictive_result(
    left: EvaluationResult, right: EvaluationResult
) -> EvaluationResult:
    left_rank = _decision_rank(left.decision)
    right_rank = _decision_rank(right.decision)
    if right_rank > left_rank:
        return right
    if left_rank > right_rank:
        return left
    return right if right.matched_rule is not None else left




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

    capability = required_capability(action.type)
    if capability is None:
        return None

    current_state = posture_ext.states.get(posture.current)
    if current_state is None:
        # Fail-closed: a posture referencing an undefined state must deny,
        # not fall through as if no guard applied.
        return _deny_result(
            matched_rule=f"extensions.posture.states.{posture.current}",
            reason=f"unknown posture state '{posture.current}'",
            origin_profile=origin_profile_id,
            posture=PostureResult(current=posture.current, next=posture.next),
        )

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


def evaluate_remote_desktop_channels_rule(
    rule: RemoteDesktopChannelsRule,
    target: str,
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> Optional[EvaluationResult]:
    if not rule.enabled:
        return None

    if target == "remote.clipboard":
        field = "clipboard"
        allowed = rule.clipboard
    elif target == "remote.file_transfer":
        field = "file_transfer"
        allowed = rule.file_transfer
    elif target == "remote.audio":
        field = "audio"
        allowed = rule.audio
    elif target == "remote.drive_mapping":
        field = "drive_mapping"
        allowed = rule.drive_mapping
    else:
        return None

    if allowed:
        return _allow_result(
            f"rules.remote_desktop_channels.{field}",
            f"remote desktop channel '{field}' is enabled",
            origin_profile_id,
            posture,
        )
    return _deny_result(
        f"rules.remote_desktop_channels.{field}",
        f"remote desktop channel '{field}' is disabled",
        origin_profile_id,
        posture,
    )


def evaluate_input_injection_rule(
    rule: InputInjectionRule,
    target: str,
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> EvaluationResult:
    if not rule.enabled:
        return _allow_result(None, None, origin_profile_id, posture)

    if len(rule.allowed_types) == 0:
        return _deny_result(
            "rules.input_injection.allowed_types",
            "input injection is not allowed when allowed_types is empty",
            origin_profile_id,
            posture,
        )

    if target in rule.allowed_types:
        return _allow_result(
            "rules.input_injection.allowed_types",
            "input injection type is explicitly allowed",
            origin_profile_id,
            posture,
        )

    return _deny_result(
        "rules.input_injection.allowed_types",
        "input injection type is not allowed",
        origin_profile_id,
        posture,
    )




def evaluate_forbidden_paths(
    rule: ForbiddenPathsRule,
    target: str,
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> tuple[Optional[EvaluationResult], bool]:
    if not rule.enabled:
        return None, False

    if _find_first_match(target, rule.exceptions) is not None:
        return None, True

    if _find_first_match(target, rule.patterns) is not None:
        return (
            _deny_result(
                "rules.forbidden_paths.patterns",
                "path matched a forbidden pattern",
                origin_profile_id,
                posture,
            ),
            False,
        )

    return None, False


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

    forbidden_exception_matched = False

    if spec.rules.forbidden_paths is not None:
        result, forbidden_exception_matched = evaluate_forbidden_paths(
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

    if forbidden_exception_matched:
        return _allow_result(
            "rules.forbidden_paths.exceptions",
            "path matched an explicit exception",
            origin_profile_id,
            posture,
        )

    return None




def _evaluate_tool_call(
    spec: HushSpec,
    action: EvaluationAction,
    matched_profile: Optional[OriginProfile],
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> EvaluationResult:
    base_rule = (
        spec.rules.tool_access
        if spec.rules is not None and _is_rule_active(spec.rules.tool_access)
        else None
    )
    profile_rule = (
        matched_profile.tool_access
        if matched_profile is not None and _is_rule_active(matched_profile.tool_access)
        else None
    )

    if base_rule is None and profile_rule is None:
        return _allow_result(None, None, origin_profile_id, posture)

    target = action.target or ""
    profile_prefix = (
        _profile_rule_prefix(matched_profile.id, "tool_access")
        if matched_profile is not None
        else None
    )

    smallest_arg_limit: Optional[tuple[int, str]] = None
    if base_rule is not None and base_rule.max_args_size is not None:
        smallest_arg_limit = (base_rule.max_args_size, "rules.tool_access.max_args_size")
    if (
        profile_rule is not None
        and profile_rule.max_args_size is not None
        and profile_prefix is not None
        and (
            smallest_arg_limit is None
            or profile_rule.max_args_size < smallest_arg_limit[0]
        )
    ):
        smallest_arg_limit = (
            profile_rule.max_args_size,
            f"{profile_prefix}.max_args_size",
        )

    if (
        smallest_arg_limit is not None
        and (action.args_size or 0) > smallest_arg_limit[0]
    ):
        return _deny_result(
            smallest_arg_limit[1],
            "tool arguments exceeded max_args_size",
            origin_profile_id,
            posture,
        )

    if base_rule is not None and _find_first_match(target, base_rule.block) is not None:
        return _deny_result(
            "rules.tool_access.block",
            "tool is explicitly blocked",
            origin_profile_id,
            posture,
        )
    if (
        profile_rule is not None
        and profile_prefix is not None
        and _find_first_match(target, profile_rule.block) is not None
    ):
        return _deny_result(
            f"{profile_prefix}.block",
            "tool is explicitly blocked",
            origin_profile_id,
            posture,
        )

    if (
        base_rule is not None
        and _find_first_match(target, base_rule.require_confirmation) is not None
    ):
        return _warn_result(
            "rules.tool_access.require_confirmation",
            "tool requires confirmation",
            origin_profile_id,
            posture,
        )
    if (
        profile_rule is not None
        and profile_prefix is not None
        and _find_first_match(target, profile_rule.require_confirmation) is not None
    ):
        return _warn_result(
            f"{profile_prefix}.require_confirmation",
            "tool requires confirmation",
            origin_profile_id,
            posture,
        )

    base_has_allow = _has_patterns(base_rule.allow if base_rule is not None else None)
    profile_has_allow = _has_patterns(
        profile_rule.allow if profile_rule is not None else None
    )
    base_allow_match = (
        not base_has_allow
        or (
            base_rule is not None
            and _find_first_match(target, base_rule.allow) is not None
        )
    )
    profile_allow_match = (
        not profile_has_allow
        or (
            profile_rule is not None
            and _find_first_match(target, profile_rule.allow) is not None
        )
    )
    if (base_has_allow or profile_has_allow) and base_allow_match and profile_allow_match:
        matched_rule: Optional[str]
        if profile_has_allow and profile_prefix is not None:
            matched_rule = f"{profile_prefix}.allow"
        elif base_has_allow:
            matched_rule = "rules.tool_access.allow"
        else:
            matched_rule = None
        return _allow_result(
            matched_rule,
            "tool is explicitly allowed",
            origin_profile_id,
            posture,
        )

    default_action = (
        DefaultAction.BLOCK
        if (
            (base_rule is not None and base_rule.default == DefaultAction.BLOCK)
            or (
                profile_rule is not None
                and profile_rule.default == DefaultAction.BLOCK
            )
        )
        else DefaultAction.ALLOW
    )
    matched_rule = (
        f"{profile_prefix}.default"
        if profile_rule is not None and profile_prefix is not None
        else "rules.tool_access.default"
        if base_rule is not None
        else None
    )
    if default_action == DefaultAction.ALLOW:
        return _allow_result(
            matched_rule,
            "tool matched default allow",
            origin_profile_id,
            posture,
        )
    return _deny_result(
        matched_rule,
        "tool matched default block",
        origin_profile_id,
        posture,
    )


def _evaluate_egress(
    spec: HushSpec,
    action: EvaluationAction,
    matched_profile: Optional[OriginProfile],
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> EvaluationResult:
    base_rule = (
        spec.rules.egress
        if spec.rules is not None and _is_rule_active(spec.rules.egress)
        else None
    )
    profile_rule = (
        matched_profile.egress
        if matched_profile is not None and _is_rule_active(matched_profile.egress)
        else None
    )

    if base_rule is None and profile_rule is None:
        return _allow_result(None, None, origin_profile_id, posture)

    target = action.target or ""
    profile_prefix = (
        _profile_rule_prefix(matched_profile.id, "egress")
        if matched_profile is not None
        else None
    )

    if base_rule is not None and _find_first_match(target, base_rule.block) is not None:
        return _deny_result(
            "rules.egress.block",
            "domain is explicitly blocked",
            origin_profile_id,
            posture,
        )
    if (
        profile_rule is not None
        and profile_prefix is not None
        and _find_first_match(target, profile_rule.block) is not None
    ):
        return _deny_result(
            f"{profile_prefix}.block",
            "domain is explicitly blocked",
            origin_profile_id,
            posture,
        )

    base_has_allow = _has_patterns(base_rule.allow if base_rule is not None else None)
    profile_has_allow = _has_patterns(
        profile_rule.allow if profile_rule is not None else None
    )
    base_allow_match = (
        not base_has_allow
        or (
            base_rule is not None
            and _find_first_match(target, base_rule.allow) is not None
        )
    )
    profile_allow_match = (
        not profile_has_allow
        or (
            profile_rule is not None
            and _find_first_match(target, profile_rule.allow) is not None
        )
    )
    if (base_has_allow or profile_has_allow) and base_allow_match and profile_allow_match:
        matched_rule: Optional[str]
        if profile_has_allow and profile_prefix is not None:
            matched_rule = f"{profile_prefix}.allow"
        elif base_has_allow:
            matched_rule = "rules.egress.allow"
        else:
            matched_rule = None
        return _allow_result(
            matched_rule,
            "domain is explicitly allowed",
            origin_profile_id,
            posture,
        )

    default_action = (
        DefaultAction.BLOCK
        if (
            (base_rule is not None and base_rule.default == DefaultAction.BLOCK)
            or (
                profile_rule is not None
                and profile_rule.default == DefaultAction.BLOCK
            )
        )
        else DefaultAction.ALLOW
    )
    matched_rule = (
        f"{profile_prefix}.default"
        if profile_rule is not None and profile_prefix is not None
        else "rules.egress.default"
        if base_rule is not None
        else None
    )
    if default_action == DefaultAction.ALLOW:
        return _allow_result(
            matched_rule,
            "domain matched default allow",
            origin_profile_id,
            posture,
        )
    return _deny_result(
        matched_rule,
        "domain matched default block",
        origin_profile_id,
        posture,
    )


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
    computer_use_result = (
        evaluate_computer_use_rule(
            spec.rules.computer_use,
            action.target or "",
            posture,
            origin_profile_id,
        )
        if spec.rules is not None and spec.rules.computer_use is not None
        else None
    )
    remote_desktop_result = (
        evaluate_remote_desktop_channels_rule(
            spec.rules.remote_desktop_channels,
            action.target or "",
            posture,
            origin_profile_id,
        )
        if spec.rules is not None and spec.rules.remote_desktop_channels is not None
        else None
    )

    if computer_use_result is not None and remote_desktop_result is not None:
        return _more_restrictive_result(computer_use_result, remote_desktop_result)
    if computer_use_result is not None:
        return computer_use_result
    if remote_desktop_result is not None:
        return remote_desktop_result
    return _allow_result(None, None, origin_profile_id, posture)


def _evaluate_input_injection(
    spec: HushSpec,
    action: EvaluationAction,
    posture: Optional[PostureResult],
    origin_profile_id: Optional[str],
) -> EvaluationResult:
    if spec.rules is not None and spec.rules.input_injection is not None:
        return evaluate_input_injection_rule(
            spec.rules.input_injection,
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
    elif action_type == "input_inject":
        return _evaluate_input_injection(spec, action, posture, origin_profile_id)
    else:
        return EvaluationResult(
            decision=Decision.ALLOW,
            matched_rule=None,
            reason="no reference evaluator rule for this action type",
            origin_profile=origin_profile_id,
            posture=posture,
        )
