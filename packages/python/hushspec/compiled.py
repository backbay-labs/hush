"""Compiled policies: pay for a policy's patterns once, not per action.

:func:`compile_policy` turns a resolved :class:`~hushspec.schema.HushSpec` into
a :class:`CompiledPolicy` -- the same evaluator, with everything that does not
depend on the action done ahead of time:

* every policy regex compiled once through the HushSpec regex profile,
* every path glob and host pattern compiled/normalized once,
* tool-name lists NFC-normalized into sets once,
* every ``when`` condition decoded once,
* the per-action-type plan (which rule blocks apply, in which order, with
  which path operation) laid out once,
* the origin overlays folded into the base ``tool_access`` / ``egress`` rules
  once per profile, so an overlay costs nothing to apply,
* the constant decision objects -- ``matched_rule`` and ``reason`` strings are
  fixed by the policy, not the action -- allocated once,
* the detector wiring for ``extensions.detection`` resolved once.

Decisions, receipts, traces and hashes are byte-for-byte what the per-call
evaluator produced: this is a layout change, not a semantic one. The source
document is kept as :attr:`CompiledPolicy.spec` so receipts and hashing still
see exactly what was loaded, with :attr:`CompiledPolicy.content_hash` computed
at most once.

Fail-closed is preserved in both directions. :func:`compile_policy` refuses a
policy whose patterns are outside the regex profile (:class:`CompileError`),
and the lenient compile the free-function wrappers use records the offending
rule path instead, so evaluation still *denies* with the same
``matched_rule``/``reason`` the reference evaluator reported.
"""

from __future__ import annotations

import unicodedata
from typing import Any, Optional, Union

from hushspec.conditions import (
    Condition,
    RuntimeContext,
    decode_condition,
    evaluate_condition_with_capabilities,
)
from hushspec.detection import (
    DETECTOR_ID_VERSION,
    HEURISTIC_DETECTOR_NAME,
    DetectionCategory,
    DetectionResult,
    DetectorEvaluation,
    DetectorLevel,
    EvaluationWithDetection,
    TracedEvaluationWithDetection,
    _DEFAULT_JAILBREAK_BLOCK_THRESHOLD,
    _DEFAULT_JAILBREAK_WARN_THRESHOLD,
    _DEFAULT_MAX_INPUT_BYTES,
    _DEFAULT_MAX_SCAN_BYTES,
    _DEFAULT_PROMPT_INJECTION_BLOCK_AT,
    _DEFAULT_PROMPT_INJECTION_WARN_AT,
    _LEVEL_FLOORS,
    default_detector_registry,
    heuristic_integer,
    _truncate_to_bytes,
)
from hushspec.evaluate import (
    BUILTIN_CREDENTIAL_PATTERNS,
    PANIC_RULE,
    UNKNOWN_ACTION_TYPE_RULE,
    Decision,
    EvaluationAction,
    EvaluationResult,
    OriginContext,
    PostureContext,
    PostureResult,
    RuleEvaluation,
    RuleOutcome,
    TracedEvaluation,
    _APPLICABLE_BLOCKS,
    _default_rule_path,
    _host_pattern_regex,
    _is_ip_literal,
    _match_origin,
    _normalize_host_pattern,
    _path_glob_regex,
    _scan_prefix,
    _trigger_name,
    contains_word,
    is_panic_active,
    normalize_host,
    normalize_path,
    patch_stats,
    required_capability,
)
from hushspec.extensions import (
    OriginDefaultBehavior,
    OriginEgressOverlay,
    OriginProfile,
    OriginToolAccessOverlay,
)
from hushspec.regex_profile import compile_profile_regex
from hushspec.rules import (
    BrowserAutomationRule,
    ComputerUseMode,
    CodeExecutionRule,
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

__all__ = [
    "CompileError",
    "CompiledPolicy",
    "compile_policy",
    "compiled_for_spec",
]


class CompileError(ValueError):
    """A document cannot be compiled: it still declares ``extends``, or a
    pattern is outside the HushSpec regex profile.

    Raised by :func:`compile_policy` (which is strict by default) so a caller
    that compiles ahead of time learns about an unusable pattern then, rather
    than as a deny on the first action that reaches it. An unresolved document
    is refused whatever ``strict`` says: core spec 2.3 forbids evaluating one.
    """

    def __init__(self, rule_path: str, message: str) -> None:
        super().__init__(f"{rule_path}: {message}")
        #: The document path the refusal is about, as a receipt would spell it.
        self.rule_path = rule_path
        #: Why, in the words of the check that refused it.
        self.message = message


# ---------------------------------------------------------------------------
# Decisions and inactivity, precomputed
# ---------------------------------------------------------------------------


class _BlockDecision:
    """One rule block's contribution, built at compile time and shared.

    ``matched_rule`` and ``reason`` are fixed by the policy, never by the
    action, so every possible decision of every block is allocated once here
    and handed out by reference. Never mutated after construction.
    """

    __slots__ = ("decision", "matched_rule", "reason", "outcome", "rank")

    def __init__(
        self,
        decision: Decision,
        matched_rule: Optional[str],
        reason: Optional[str],
        rank: int,
    ) -> None:
        self.decision = decision
        self.matched_rule = matched_rule
        self.reason = reason
        self.outcome = _OUTCOME_OF[decision]
        self.rank = rank


class _Inactive:
    """Why an applicable block was not evaluated (a ``skip`` trace entry)."""

    __slots__ = ("reason",)

    def __init__(self, reason: str) -> None:
        self.reason = reason


_OUTCOME_OF: dict[Decision, RuleOutcome] = {
    Decision.ALLOW: RuleOutcome.ALLOW,
    Decision.WARN: RuleOutcome.WARN,
    Decision.DENY: RuleOutcome.DENY,
}

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.WARN: 1,
    Severity.ERROR: 2,
    Severity.CRITICAL: 3,
}

_INACTIVE_DISABLED = _Inactive("rule disabled")
_INACTIVE_WHEN = _Inactive("when condition is false")
_INACTIVE_OUT_OF_BAND = _Inactive("out-of-band condition is false")


def _absent(block: str) -> _Inactive:
    return _Inactive(f"no {block} rule configured")


def _content_not_supplied(block: str) -> _Inactive:
    """A content-scanning block the action carries no content for."""
    return _Inactive(f"content not supplied; {block} not consulted")


def _target_not_a_channel(block: str) -> _Inactive:
    """A channel block whose target names no remote desktop channel."""
    return _Inactive(f"target is not a remote desktop channel; {block} not consulted")


def _allow(matched_rule: Optional[str], reason: Optional[str]) -> _BlockDecision:
    return _BlockDecision(Decision.ALLOW, matched_rule, reason, 1)


def _warn(matched_rule: str, reason: str) -> _BlockDecision:
    return _BlockDecision(Decision.WARN, matched_rule, reason, 2)


def _deny(matched_rule: str, reason: str) -> _BlockDecision:
    return _BlockDecision(Decision.DENY, matched_rule, reason, 3)


# ---------------------------------------------------------------------------
# Pattern sets, compiled once
# ---------------------------------------------------------------------------


class _PathGlobSet:
    """Path globs (core spec 3.14.1) compiled into anchored regexes.

    A glob that will not compile can never match, so it is dropped here --
    exactly what ``path_glob_matches`` does per call with its ``None`` guard.
    """

    __slots__ = ("_regexes", "_empty")

    def __init__(self, patterns: list[str]) -> None:
        compiled = []
        for pattern in patterns:
            regex = _path_glob_regex(pattern)
            if regex is not None:
                compiled.append(regex.search)
        self._regexes = tuple(compiled)
        self._empty = not compiled

    def matches(self, path: str) -> bool:
        if self._empty:
            return False
        for search in self._regexes:
            if search(path) is not None:
                return True
        return False


class _HostPatternSet:
    """Host patterns (core spec 3.14.2) normalized and compiled once.

    The normalized pattern is kept alongside the regex because an IP literal
    host matches only a pattern equal to it.
    """

    __slots__ = ("_literals", "_searches", "_empty")

    def __init__(self, patterns: list[str]) -> None:
        literals = []
        searches = []
        for pattern in patterns:
            normalized = _normalize_host_pattern(pattern)
            literals.append(normalized)
            regex = _host_pattern_regex(normalized)
            if regex is not None:
                searches.append(regex.search)
        self._literals = frozenset(literals)
        self._searches = tuple(searches)
        self._empty = not literals

    def matches(self, host: str, host_is_ip: bool) -> bool:
        if self._empty:
            return False
        if host_is_ip:
            return host in self._literals
        for search in self._searches:
            if search(host) is not None:
                return True
        return False


def _tool_set(entries: list[str]) -> frozenset[str]:
    """Tool names are exact, case-sensitive strings after NFC (core spec 3.7)."""
    return frozenset(unicodedata.normalize("NFC", entry) for entry in entries)


#: The built-in credential detectors of ``browser_automation``, compiled once
#: for the process. A built-in that will not compile is skipped, which is what
#: the per-call evaluator did with its ``except ValueError: continue``.
def _compile_builtin_credentials() -> tuple[tuple[str, Any], ...]:
    compiled = []
    for name, pattern in BUILTIN_CREDENTIAL_PATTERNS:
        try:
            compiled.append((name, compile_profile_regex(pattern).search))
        except ValueError:  # pragma: no cover - the built-ins are in profile
            continue
    return tuple(compiled)


_BUILTIN_CREDENTIAL_SEARCHES = _compile_builtin_credentials()


# ---------------------------------------------------------------------------
# Per-evaluation state
# ---------------------------------------------------------------------------


class _Eval:
    """Everything a compiled step needs from the action being evaluated."""

    __slots__ = (
        "action",
        "context",
        "conditions",
        "profile",
        "normalized_path",
        "capabilities",
    )

    def __init__(
        self,
        action: EvaluationAction,
        context: RuntimeContext,
        conditions: dict[str, Condition],
    ) -> None:
        self.action = action
        self.context = context
        self.conditions = conditions
        self.profile: Optional[OriginProfile] = None
        self.normalized_path: str = ""
        #: What the effective posture state grants, for `capability`
        #: predicates (core spec 3.13): ``None`` when the policy has no
        #: posture extension, so the predicate is unevaluable and holds.
        self.capabilities: Optional[list[str]] = None


#: Shared empty runtime context. Evaluation only ever reads a context, so the
#: default one does not have to be rebuilt per call.
_EMPTY_CONTEXT = RuntimeContext()
_NO_CONDITIONS: dict[str, Condition] = {}


# ---------------------------------------------------------------------------
# Compiled rule blocks
# ---------------------------------------------------------------------------


class _Step:
    """One rule block as it applies to one action type.

    ``run`` returns a shared :class:`_BlockDecision` or an :class:`_Inactive`
    saying why the block did not run.
    """

    __slots__ = ("block", "enabled", "condition")

    def __init__(self, block: str, enabled: bool, when: Any) -> None:
        self.block = block
        self.enabled = enabled
        self.condition = decode_condition(when)

    def _inactive(self, ev: _Eval) -> Optional[_Inactive]:
        """``None`` when the block is active for this evaluation."""
        if not self.enabled:
            return _INACTIVE_DISABLED
        condition = self.condition
        if condition is not None and not evaluate_condition_with_capabilities(
            condition, ev.context, ev.capabilities
        ):
            return _INACTIVE_WHEN
        conditions = ev.conditions
        if conditions:
            out_of_band = conditions.get(self.block)
            if out_of_band is not None and not evaluate_condition_with_capabilities(
                out_of_band, ev.context, ev.capabilities
            ):
                return _INACTIVE_OUT_OF_BAND
        return None

    def run(self, ev: _Eval) -> Union[_BlockDecision, _Inactive]:  # pragma: no cover
        raise NotImplementedError


class _AbsentStep:
    """A block the document does not configure at all."""

    __slots__ = ("block", "_absent")

    def __init__(self, block: str) -> None:
        self.block = block
        self._absent = _absent(block)

    def run(self, ev: _Eval) -> Union[_BlockDecision, _Inactive]:
        return self._absent


class _ForbiddenPathsStep(_Step):
    __slots__ = ("_exceptions", "_patterns", "_exception", "_deny", "_allow")

    def __init__(self, rule: ForbiddenPathsRule) -> None:
        super().__init__("forbidden_paths", rule.enabled, rule.when)
        self._exceptions = _PathGlobSet(rule.exceptions)
        self._patterns = _PathGlobSet(rule.patterns)
        self._exception = _allow(
            "rules.forbidden_paths.exceptions", "path matched an explicit exception"
        )
        self._deny = _deny(
            "rules.forbidden_paths.patterns", "path matched a forbidden pattern"
        )
        self._allow = _allow(None, "path did not match any forbidden pattern")

    def run(self, ev: _Eval) -> Union[_BlockDecision, _Inactive]:
        inactive = self._inactive(ev)
        if inactive is not None:
            return inactive
        path = ev.normalized_path
        if self._exceptions.matches(path):
            return self._exception
        if self._patterns.matches(path):
            return self._deny
        return self._allow


class _PathAllowlistStep(_Step):
    __slots__ = ("_patterns", "_allow", "_deny")

    def __init__(self, rule: PathAllowlistRule, patterns: list[str]) -> None:
        super().__init__("path_allowlist", rule.enabled, rule.when)
        self._patterns = _PathGlobSet(patterns)
        self._allow = _allow("rules.path_allowlist", "path matched allowlist")
        self._deny = _deny("rules.path_allowlist", "path did not match allowlist")

    def run(self, ev: _Eval) -> Union[_BlockDecision, _Inactive]:
        inactive = self._inactive(ev)
        if inactive is not None:
            return inactive
        if self._patterns.matches(ev.normalized_path):
            return self._allow
        return self._deny


class _SecretPatternsStep(_Step):
    """``secret_patterns`` for one action type.

    ``path_bearing`` is fixed by the action type: ``file_write`` and
    ``patch_apply`` carry a path to check against ``skip_paths``; ``egress``
    and ``tool_call`` are scanned only when they carry content.
    """

    __slots__ = (
        "_path_bearing",
        "_skip_paths",
        "_skip",
        "_patterns",
        "_invalid",
        "_clean",
        "_no_content",
    )

    def __init__(
        self,
        rule: SecretPatternsRule,
        path_bearing: bool,
        strict: bool,
        errors: list[CompileError],
    ) -> None:
        super().__init__("secret_patterns", rule.enabled, rule.when)
        self._path_bearing = path_bearing
        self._skip_paths = _PathGlobSet(rule.skip_paths)
        self._skip = _allow(
            "rules.secret_patterns.skip_paths",
            "path is excluded from secret scanning",
        )
        self._clean = _allow(None, "content did not match any secret pattern")
        self._no_content = _content_not_supplied("secret_patterns")
        # (rank, search, decision) in document order. Fail closed: the first
        # pattern outside the profile denies, whatever the others match.
        patterns: list[tuple[int, Any, _BlockDecision]] = []
        invalid: Optional[_BlockDecision] = None
        for pattern in rule.patterns:
            path = f"rules.secret_patterns.patterns.{pattern.name}.pattern"
            try:
                compiled = compile_profile_regex(pattern.pattern)
            except ValueError as exc:
                error = CompileError(path, str(exc))
                if strict:
                    raise error from exc
                errors.append(error)
                if invalid is None:
                    invalid = _deny(
                        path,
                        f"secret pattern '{pattern.name}' is invalid: {exc}",
                    )
                continue
            matched_rule = f"rules.secret_patterns.patterns.{pattern.name}"
            reason = f"content matched secret pattern '{pattern.name}'"
            decision = (
                _warn(matched_rule, reason)
                if pattern.severity == Severity.WARN
                else _deny(matched_rule, reason)
            )
            patterns.append((_SEVERITY_RANK[pattern.severity], compiled.search, decision))
        self._patterns = tuple(patterns)
        self._invalid = invalid

    def for_path_bearing(self, path_bearing: bool) -> "_SecretPatternsStep":
        """The same compiled patterns for the other kind of action type.

        ``file_write``/``patch_apply`` check ``skip_paths``; ``egress``/
        ``tool_call`` are content-only. Only that flag differs, so the
        compiled patterns are shared rather than compiled twice.
        """
        if path_bearing == self._path_bearing:
            return self
        clone = object.__new__(_SecretPatternsStep)
        for name in _Step.__slots__ + _SecretPatternsStep.__slots__:
            setattr(clone, name, getattr(self, name))
        clone._path_bearing = path_bearing
        return clone

    def run(self, ev: _Eval) -> Union[_BlockDecision, _Inactive]:
        action = ev.action
        content = action.content
        if not self._path_bearing and content is None:
            return self._no_content
        inactive = self._inactive(ev)
        if inactive is not None:
            return inactive
        if self._path_bearing and self._skip_paths.matches(ev.normalized_path):
            return self._skip
        if self._invalid is not None:
            return self._invalid
        if content is None:
            content = ""
        best_rank = 0
        best = self._clean
        for rank, search, decision in self._patterns:
            # Strictly greater keeps the first pattern in document order among
            # those at the highest matched severity -- so a pattern that cannot
            # raise the severity need not be searched for at all.
            if rank > best_rank and search(content) is not None:
                best_rank = rank
                best = decision
        return best


class _PatchIntegrityStep(_Step):
    __slots__ = (
        "_patterns",
        "_max_additions",
        "_max_deletions",
        "_require_balance",
        "_max_imbalance_ratio",
        "_too_many_additions",
        "_too_many_deletions",
        "_one_sided",
        "_imbalanced",
        "_allow",
    )

    def __init__(
        self, rule: PatchIntegrityRule, strict: bool, errors: list[CompileError]
    ) -> None:
        super().__init__("patch_integrity", rule.enabled, rule.when)
        patterns: list[tuple[Any, _BlockDecision]] = []
        for index, pattern in enumerate(rule.forbidden_patterns):
            path = f"rules.patch_integrity.forbidden_patterns[{index}]"
            try:
                compiled = compile_profile_regex(pattern)
            except ValueError as exc:
                error = CompileError(path, str(exc))
                if strict:
                    raise error from exc
                errors.append(error)
                # A pattern outside the profile denies where it stands, before
                # any later pattern is consulted.
                patterns.append(
                    (None, _deny(path, f"patch forbidden pattern is invalid: {exc}"))
                )
                continue
            patterns.append(
                (
                    compiled.search,
                    _deny(path, "patch content matched a forbidden pattern"),
                )
            )
        self._patterns = tuple(patterns)
        self._max_additions = rule.max_additions
        self._max_deletions = rule.max_deletions
        self._require_balance = rule.require_balance
        self._max_imbalance_ratio = rule.max_imbalance_ratio
        self._too_many_additions = _deny(
            "rules.patch_integrity.max_additions",
            "patch additions exceeded max_additions",
        )
        self._too_many_deletions = _deny(
            "rules.patch_integrity.max_deletions",
            "patch deletions exceeded max_deletions",
        )
        self._one_sided = _deny(
            "rules.patch_integrity.max_imbalance_ratio",
            "patch has changes on only one side; the imbalance ratio is infinite",
        )
        self._imbalanced = _deny(
            "rules.patch_integrity.max_imbalance_ratio",
            "patch exceeded max imbalance ratio",
        )
        self._allow = _allow(None, "patch passed integrity checks")

    def run(self, ev: _Eval) -> Union[_BlockDecision, _Inactive]:
        inactive = self._inactive(ev)
        if inactive is not None:
            return inactive
        content = ev.action.content or ""
        for search, decision in self._patterns:
            if search is None or search(content) is not None:
                return decision

        stats = patch_stats(content)
        additions = stats.additions
        deletions = stats.deletions
        if additions > self._max_additions:
            return self._too_many_additions
        if deletions > self._max_deletions:
            return self._too_many_deletions
        if self._require_balance:
            if (additions == 0) != (deletions == 0):
                return self._one_sided
            if additions > 0 and deletions > 0:
                larger = float(max(additions, deletions))
                smaller = float(min(additions, deletions))
                if larger / smaller > self._max_imbalance_ratio:
                    return self._imbalanced
        return self._allow


class _ShellCommandsStep(_Step):
    __slots__ = ("_patterns", "_allow")

    def __init__(
        self, rule: ShellCommandsRule, strict: bool, errors: list[CompileError]
    ) -> None:
        super().__init__("shell_commands", rule.enabled, rule.when)
        patterns: list[tuple[Any, _BlockDecision]] = []
        for index, pattern in enumerate(rule.forbidden_patterns):
            path = f"rules.shell_commands.forbidden_patterns[{index}]"
            try:
                compiled = compile_profile_regex(pattern)
            except ValueError as exc:
                error = CompileError(path, str(exc))
                if strict:
                    raise error from exc
                errors.append(error)
                patterns.append(
                    (None, _deny(path, f"shell forbidden pattern is invalid: {exc}"))
                )
                continue
            patterns.append(
                (
                    compiled.search,
                    _deny(path, "shell command matched a forbidden pattern"),
                )
            )
        self._patterns = tuple(patterns)
        self._allow = _allow(None, "command did not match any forbidden pattern")

    def run(self, ev: _Eval) -> Union[_BlockDecision, _Inactive]:
        inactive = self._inactive(ev)
        if inactive is not None:
            return inactive
        command = ev.action.target or ""
        for search, decision in self._patterns:
            if search is None or search(command) is not None:
                return decision
        return self._allow


class _CompiledToolAccess:
    """``rules.tool_access`` with one origin overlay already folded in.

    Every path a decision can take is fixed by the policy and the profile, so
    the whole precedence ladder (max_args_size, block, require_confirmation,
    allow, default) is resolved to shared decisions at compile time.
    """

    __slots__ = (
        "_limit",
        "_limit_deny",
        "_blocked",
        "_confirm",
        "_allowlists",
        "_allow_mode",
        "_allowed",
        "_default",
    )

    def __init__(
        self,
        base: Optional[ToolAccessRule],
        overlay: Optional[tuple[str, OriginToolAccessOverlay]],
    ) -> None:
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
        self._limit = limit[0] if limit is not None else None
        self._limit_deny = (
            _deny(limit[1], "tool arguments exceeded max_args_size")
            if limit is not None
            else None
        )

        # 2. block, then 3. require_confirmation: union of both lists.
        blocked: list[tuple[frozenset[str], _BlockDecision]] = []
        confirm: list[tuple[frozenset[str], _BlockDecision]] = []
        if base is not None:
            if base.block:
                blocked.append(
                    (
                        _tool_set(base.block),
                        _deny("rules.tool_access.block", "tool is explicitly blocked"),
                    )
                )
            if base.require_confirmation:
                confirm.append(
                    (
                        _tool_set(base.require_confirmation),
                        _warn(
                            "rules.tool_access.require_confirmation",
                            "tool requires confirmation",
                        ),
                    )
                )
        if overlay_rule is not None and prefix is not None:
            if overlay_rule.block:
                blocked.append(
                    (
                        _tool_set(overlay_rule.block),
                        _deny(f"{prefix}.block", "tool is explicitly blocked"),
                    )
                )
            if overlay_rule.require_confirmation:
                confirm.append(
                    (
                        _tool_set(overlay_rule.require_confirmation),
                        _warn(
                            f"{prefix}.require_confirmation", "tool requires confirmation"
                        ),
                    )
                )
        self._blocked = tuple(blocked)
        self._confirm = tuple(confirm)

        # 4/5. allowlist mode: intersection when both lists are non-empty.
        base_allow = base.allow if base is not None and base.allow else None
        overlay_allow = (
            overlay_rule.allow
            if overlay_rule is not None and overlay_rule.allow
            else None
        )
        allowlists: list[tuple[frozenset[str], _BlockDecision]] = []
        if base_allow is not None:
            allowlists.append(
                (
                    _tool_set(base_allow),
                    _deny("rules.tool_access.allow", "tool is not in the allowlist"),
                )
            )
        if overlay_allow is not None and prefix is not None:
            allowlists.append(
                (
                    _tool_set(overlay_allow),
                    _deny(f"{prefix}.allow", "tool is not in the allowlist"),
                )
            )
        self._allowlists = tuple(allowlists)
        self._allow_mode = base_allow is not None or overlay_allow is not None
        self._allowed = _allow(
            f"{prefix}.allow"
            if overlay_allow is not None and prefix is not None
            else "rules.tool_access.allow",
            "tool is explicitly allowed",
        )

        # 6. default: block when the base says block or the overlay says block.
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
        self._default = (
            _allow(matched_rule, "tool matched default allow")
            if effective == DefaultAction.ALLOW
            else _deny(matched_rule, "tool matched default block")
        )

    def decide(self, action: EvaluationAction) -> _BlockDecision:
        if self._limit is not None and (action.args_size or 0) > self._limit:
            return self._limit_deny  # type: ignore[return-value]
        tool = unicodedata.normalize("NFC", action.target or "")
        for names, decision in self._blocked:
            if tool in names:
                return decision
        for names, decision in self._confirm:
            if tool in names:
                return decision
        if self._allow_mode:
            for names, decision in self._allowlists:
                if tool not in names:
                    return decision
            return self._allowed
        return self._default


class _CompiledEgress:
    """``rules.egress`` with one origin overlay already folded in."""

    __slots__ = ("_blocked", "_allowlists", "_allow_mode", "_allowed", "_default")

    def __init__(
        self,
        base: Optional[EgressRule],
        overlay: Optional[tuple[str, OriginEgressOverlay]],
    ) -> None:
        prefix: Optional[str] = None
        overlay_rule: Optional[OriginEgressOverlay] = None
        if overlay is not None:
            prefix = f"extensions.origins.profiles.{overlay[0]}.egress"
            overlay_rule = overlay[1]

        # 1. block: union of both lists.
        blocked: list[tuple[_HostPatternSet, _BlockDecision]] = []
        if base is not None and base.block:
            blocked.append(
                (
                    _HostPatternSet(base.block),
                    _deny("rules.egress.block", "domain is explicitly blocked"),
                )
            )
        if overlay_rule is not None and prefix is not None and overlay_rule.block:
            blocked.append(
                (
                    _HostPatternSet(overlay_rule.block),
                    _deny(f"{prefix}.block", "domain is explicitly blocked"),
                )
            )
        self._blocked = tuple(blocked)

        # 2. allow: intersection when both lists are non-empty.
        base_allow = base.allow if base is not None and base.allow else None
        overlay_allow = (
            overlay_rule.allow
            if overlay_rule is not None and overlay_rule.allow
            else None
        )
        allowlists: list[_HostPatternSet] = []
        if base_allow is not None:
            allowlists.append(_HostPatternSet(base_allow))
        if overlay_allow is not None:
            allowlists.append(_HostPatternSet(overlay_allow))
        self._allowlists = tuple(allowlists)
        self._allow_mode = base_allow is not None or overlay_allow is not None
        self._allowed = _allow(
            f"{prefix}.allow"
            if overlay_allow is not None and prefix is not None
            else "rules.egress.allow",
            "domain is explicitly allowed",
        )

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
        self._default = (
            _allow(matched_rule, "domain matched default allow")
            if effective == DefaultAction.ALLOW
            else _deny(matched_rule, "domain matched default block")
        )

    def decide(self, host: Optional[str]) -> _BlockDecision:
        host_is_ip = host is not None and _is_ip_literal(host)
        if host is not None:
            for hosts, decision in self._blocked:
                if hosts.matches(host, host_is_ip):
                    return decision
        if self._allow_mode:
            allowed = True
            for hosts in self._allowlists:
                if host is None or not hosts.matches(host, host_is_ip):
                    allowed = False
                    break
            if allowed:
                return self._allowed
        return self._default


class _OverlayStep(_Step):
    """``tool_access`` / ``egress``: base rule plus per-profile overlays.

    One folded variant is compiled per origin profile that overlays the block,
    so selecting a profile costs a dict lookup rather than rebuilding matchers.
    """

    __slots__ = ("_base_present", "_base", "_variants", "_absent")

    def __init__(
        self,
        block: str,
        base: Any,
        variants: dict[int, Any],
        base_variant: Optional[Any],
    ) -> None:
        super().__init__(
            block,
            base.enabled if base is not None else True,
            base.when if base is not None else None,
        )
        self._base_present = base is not None
        self._base = base_variant
        self._variants = variants
        self._absent = _absent(block)

    def _variant(self, ev: _Eval) -> Optional[Any]:
        profile = ev.profile
        if profile is not None:
            variant = self._variants.get(id(profile))
            if variant is not None:
                return variant
        return self._base

    def _guard(self, ev: _Eval) -> Optional[_Inactive]:
        # A block present only as an overlay has no base `enabled`/`when` to
        # consult (core spec 6.1 read through the origins overlay rules).
        if self._base_present:
            return self._inactive(ev)
        return None


class _ToolAccessStep(_OverlayStep):
    __slots__ = ()

    def run(self, ev: _Eval) -> Union[_BlockDecision, _Inactive]:
        variant = self._variant(ev)
        if variant is None:
            return self._absent
        inactive = self._guard(ev)
        if inactive is not None:
            return inactive
        return variant.decide(ev.action)


class _EgressStep(_OverlayStep):
    __slots__ = ()

    def run(self, ev: _Eval) -> Union[_BlockDecision, _Inactive]:
        variant = self._variant(ev)
        if variant is None:
            return self._absent
        inactive = self._guard(ev)
        if inactive is not None:
            return inactive
        target = ev.action.target
        host = normalize_host(target) if target is not None else None
        return variant.decide(host)


class _ComputerUseStep(_Step):
    __slots__ = ("_allowed_actions", "_explicit", "_observe", "_deny")

    def __init__(self, rule: ComputerUseRule) -> None:
        super().__init__("computer_use", rule.enabled, rule.when)
        self._allowed_actions = frozenset(rule.allowed_actions)
        self._explicit = _allow(
            "rules.computer_use.allowed_actions",
            "computer-use action is explicitly allowed",
        )
        self._observe = (
            _allow(
                "rules.computer_use.mode",
                "observe mode does not block unlisted actions",
            )
            if rule.mode == ComputerUseMode.OBSERVE
            else None
        )
        # `guardrail` and its alias `fail_closed` both deny an unlisted
        # computer-use action (core spec 3.8).
        self._deny = _deny(
            "rules.computer_use.mode", "unlisted computer-use action is denied"
        )

    def run(self, ev: _Eval) -> Union[_BlockDecision, _Inactive]:
        inactive = self._inactive(ev)
        if inactive is not None:
            return inactive
        if (ev.action.target or "") in self._allowed_actions:
            return self._explicit
        if self._observe is not None:
            return self._observe
        return self._deny


class _RemoteDesktopChannelsStep(_Step):
    __slots__ = ("_channels", "_not_a_channel")

    def __init__(self, rule: RemoteDesktopChannelsRule) -> None:
        super().__init__("remote_desktop_channels", rule.enabled, rule.when)
        channels = {}
        for target, field_name, allowed in (
            ("remote.clipboard", "clipboard", rule.clipboard),
            ("remote.file_transfer", "file_transfer", rule.file_transfer),
            ("remote.audio", "audio", rule.audio),
            ("remote.drive_mapping", "drive_mapping", rule.drive_mapping),
        ):
            matched_rule = f"rules.remote_desktop_channels.{field_name}"
            channels[target] = (
                _allow(
                    matched_rule, f"remote desktop channel '{field_name}' is enabled"
                )
                if allowed
                else _deny(
                    matched_rule, f"remote desktop channel '{field_name}' is disabled"
                )
            )
        self._channels = channels
        self._not_a_channel = _target_not_a_channel("remote_desktop_channels")

    def run(self, ev: _Eval) -> Union[_BlockDecision, _Inactive]:
        inactive = self._inactive(ev)
        if inactive is not None:
            return inactive
        decision = self._channels.get(ev.action.target or "")
        if decision is None:
            # Not a remote-desktop channel target: the block does not apply.
            return self._not_a_channel
        return decision


class _InputInjectionStep(_Step):
    __slots__ = ("_allowed_types", "_empty_deny", "_allow", "_deny")

    def __init__(self, rule: InputInjectionRule) -> None:
        super().__init__("input_injection", rule.enabled, rule.when)
        self._allowed_types = frozenset(rule.allowed_types)
        self._empty_deny = (
            _deny(
                "rules.input_injection.allowed_types",
                "input injection is not allowed when allowed_types is empty",
            )
            if not rule.allowed_types
            else None
        )
        self._allow = _allow(
            "rules.input_injection.allowed_types",
            "input injection type is explicitly allowed",
        )
        self._deny = _deny(
            "rules.input_injection.allowed_types", "input injection type is not allowed"
        )

    def run(self, ev: _Eval) -> Union[_BlockDecision, _Inactive]:
        inactive = self._inactive(ev)
        if inactive is not None:
            return inactive
        if self._empty_deny is not None:
            return self._empty_deny
        if (ev.action.target or "") in self._allowed_types:
            return self._allow
        return self._deny


class _BrowserAutomationStep(_Step):
    __slots__ = (
        "_allowed_verbs",
        "_verb_deny",
        "_blocked_domains",
        "_blocked_deny",
        "_allowed_domains",
        "_domain_deny",
        "_credential_detection",
        "_builtin_denies",
        "_extra",
        "_allow",
    )

    def __init__(
        self, rule: BrowserAutomationRule, strict: bool, errors: list[CompileError]
    ) -> None:
        super().__init__("browser_automation", rule.enabled, rule.when)
        self._allowed_verbs = frozenset(rule.allowed_verbs) if rule.allowed_verbs else None
        self._verb_deny = _deny(
            "rules.browser_automation.allowed_verbs",
            "browser verb is not in the allowlist",
        )
        self._blocked_domains = _HostPatternSet(rule.blocked_domains)
        self._blocked_deny = _deny(
            "rules.browser_automation.blocked_domains",
            "destination host is explicitly blocked",
        )
        self._allowed_domains = (
            _HostPatternSet(rule.allowed_domains) if rule.allowed_domains else None
        )
        self._domain_deny = _deny(
            "rules.browser_automation.allowed_domains",
            "destination host is not in the allowlist",
        )
        self._credential_detection = rule.credential_detection
        self._builtin_denies = tuple(
            (
                search,
                _deny(
                    "rules.browser_automation.credential_detection",
                    f"typed input matched built-in credential detector '{name}'",
                ),
            )
            for name, search in _BUILTIN_CREDENTIAL_SEARCHES
        )
        extra: list[tuple[Any, _BlockDecision]] = []
        for index, pattern in enumerate(rule.extra_credential_patterns):
            path = f"rules.browser_automation.extra_credential_patterns[{index}]"
            try:
                compiled = compile_profile_regex(pattern)
            except ValueError as exc:
                error = CompileError(path, str(exc))
                if strict:
                    raise error from exc
                errors.append(error)
                extra.append(
                    (None, _deny(path, f"credential pattern is invalid: {exc}"))
                )
                continue
            extra.append(
                (
                    compiled.search,
                    _deny(
                        "rules.browser_automation.credential_detection",
                        f"typed input matched extra_credential_patterns[{index}]",
                    ),
                )
            )
        self._extra = tuple(extra)
        self._allow = _allow("rules.browser_automation", "browser action is permitted")

    def run(self, ev: _Eval) -> Union[_BlockDecision, _Inactive]:
        inactive = self._inactive(ev)
        if inactive is not None:
            return inactive
        action = ev.action

        # 1. verb allowlist (exact match).
        if self._allowed_verbs is not None and (action.target or "") not in self._allowed_verbs:
            return self._verb_deny

        # 2. destination host.
        if action.url is not None:
            host = normalize_host(action.url)
            if host is not None:
                host_is_ip = _is_ip_literal(host)
                if self._blocked_domains.matches(host, host_is_ip):
                    return self._blocked_deny
                if self._allowed_domains is not None and not self._allowed_domains.matches(
                    host, host_is_ip
                ):
                    return self._domain_deny
            elif self._allowed_domains is not None:
                # A target that is not a syntactically valid host matches no
                # pattern, so an allowlist cannot admit it.
                return self._domain_deny

        # 3. credential detection on typed input.
        content = action.content
        if self._credential_detection and content is not None:
            for search, decision in self._builtin_denies:
                if search(content) is not None:
                    return decision
            for search, decision in self._extra:
                if search is None or search(content) is not None:
                    return decision

        return self._allow


class _CodeExecutionStep(_Step):
    __slots__ = (
        "_languages",
        "_language_deny",
        "_network_access",
        "_network_deny",
        "_max_execution_time_ms",
        "_time_deny",
        "_modules",
        "_max_scan_bytes",
        "_allow",
    )

    def __init__(self, rule: CodeExecutionRule) -> None:
        super().__init__("code_execution", rule.enabled, rule.when)
        self._languages = (
            frozenset(rule.language_allowlist) if rule.language_allowlist else None
        )
        self._language_deny = _deny(
            "rules.code_execution.language_allowlist",
            "language is not in the allowlist",
        )
        self._network_access = rule.network_access
        self._network_deny = _deny(
            "rules.code_execution.network_access",
            "network access is not permitted for code execution",
        )
        self._max_execution_time_ms = rule.max_execution_time_ms
        self._time_deny = _deny(
            "rules.code_execution.max_execution_time_ms",
            "requested execution time exceeds max_execution_time_ms",
        )
        self._modules = tuple(
            (
                module,
                _deny(
                    "rules.code_execution.module_denylist",
                    f"code references denied module '{module}'",
                ),
            )
            for module in rule.module_denylist
        )
        self._max_scan_bytes = rule.max_scan_bytes
        self._allow = _allow("rules.code_execution", "code execution is permitted")

    def run(self, ev: _Eval) -> Union[_BlockDecision, _Inactive]:
        inactive = self._inactive(ev)
        if inactive is not None:
            return inactive
        action = ev.action

        # 1. language allowlist (exact, case-sensitive).
        if self._languages is not None and (action.target or "") not in self._languages:
            return self._language_deny

        # 2. network access.
        if action.network is True and not self._network_access:
            return self._network_deny

        # 3. execution time bound.
        if (
            self._max_execution_time_ms is not None
            and action.timeout_ms is not None
            and action.timeout_ms > self._max_execution_time_ms
        ):
            return self._time_deny

        # 4. module denylist: literal word match within the scanned prefix.
        if action.content is not None and self._modules:
            scanned = _scan_prefix(action.content, self._max_scan_bytes)
            for module, decision in self._modules:
                if contains_word(scanned, module):
                    return decision

        return self._allow


# ---------------------------------------------------------------------------
# Compiled extensions
# ---------------------------------------------------------------------------


class _CompiledDetection:
    """``extensions.detection`` resolved to the detectors that will run.

    The built-in detectors are stateless singletons (their own patterns are
    compiled once for the process); what is resolved here is which of them the
    document enables and the thresholds each is read against.
    """

    __slots__ = ("prompt_injection", "jailbreak")

    def __init__(self, detection: Any) -> None:
        self.prompt_injection = None
        self.jailbreak = None
        config = detection.prompt_injection
        if config is not None and config.enabled is not False:
            heuristics = config.heuristics
            self.prompt_injection = (
                config.max_scan_bytes
                if config.max_scan_bytes is not None
                else _DEFAULT_MAX_SCAN_BYTES,
                _LEVEL_FLOORS[
                    config.block_at_or_above
                    if config.block_at_or_above is not None
                    else _DEFAULT_PROMPT_INJECTION_BLOCK_AT
                ],
                _LEVEL_FLOORS[
                    config.warn_at_or_above
                    if config.warn_at_or_above is not None
                    else _DEFAULT_PROMPT_INJECTION_WARN_AT
                ],
                # heuristics.enabled defaults to true (detection spec 3.5.1).
                heuristics is None or heuristics.enabled is not False,
                heuristics.min_score
                if heuristics is not None and heuristics.min_score is not None
                else 0,
            )
        config = detection.jailbreak
        if config is not None and config.enabled is not False:
            self.jailbreak = (
                config.max_input_bytes
                if config.max_input_bytes is not None
                else _DEFAULT_MAX_INPUT_BYTES,
                config.block_threshold
                if config.block_threshold is not None
                else _DEFAULT_JAILBREAK_BLOCK_THRESHOLD,
                config.warn_threshold
                if config.warn_threshold is not None
                else _DEFAULT_JAILBREAK_WARN_THRESHOLD,
            )


class _Plan:
    """How one action type is evaluated: which blocks, in which order."""

    __slots__ = ("blocks", "steps", "needs_path", "capability")

    def __init__(
        self,
        blocks: tuple[str, ...],
        steps: tuple[Any, ...],
        needs_path: bool,
        capability: Optional[str],
    ) -> None:
        self.blocks = blocks
        self.steps = steps
        self.needs_path = needs_path
        self.capability = capability


#: Action types whose ``target`` is a filesystem path that has to be
#: normalized before any pattern is consulted (core spec 3.14). Every other
#: action type would normalize a path nothing reads.
_PATH_ACTIONS = frozenset(("file_read", "file_write", "patch_apply"))


# ---------------------------------------------------------------------------
# The compiled policy
# ---------------------------------------------------------------------------


class CompiledPolicy:
    """A policy with everything action-independent already computed.

    Construct with :func:`compile_policy`. The methods mirror the free
    functions in :mod:`hushspec.evaluate`, :mod:`hushspec.conditions`,
    :mod:`hushspec.detection` and :mod:`hushspec.receipt` with the ``spec``
    argument dropped, and return exactly what those functions return.
    """

    __slots__ = (
        "spec",
        "errors",
        "_plans",
        "_profiles",
        "_origins_deny_default",
        "_posture",
        "_detection",
        "_content_hash",
        "_resolution",
    )

    def __init__(self, spec: HushSpec, strict: bool) -> None:
        self.spec = spec
        errors: list[CompileError] = []
        self._content_hash: Optional[str] = None
        self._resolution: Optional[Any] = None

        rules = spec.rules
        extensions = spec.extensions
        origins = extensions.origins if extensions is not None else None
        posture = extensions.posture if extensions is not None else None
        detection = extensions.detection if extensions is not None else None

        self._origins_deny_default = origins is not None and (
            (origins.default_behavior or OriginDefaultBehavior.DENY)
            == OriginDefaultBehavior.DENY
        )
        profiles = tuple(origins.profiles) if origins is not None else ()
        self._profiles = tuple(
            (profile, profile.match_rules)
            for profile in profiles
            if profile.match_rules is not None
        )
        self._posture = posture
        self._detection = _CompiledDetection(detection) if detection is not None else None

        # -- rule blocks ----------------------------------------------------
        def block(name: str, rule: Any, build) -> Any:
            if rule is None:
                return _AbsentStep(name)
            return build(rule)

        forbidden_paths = block(
            "forbidden_paths",
            rules.forbidden_paths if rules is not None else None,
            _ForbiddenPathsStep,
        )
        path_allowlist_rule = rules.path_allowlist if rules is not None else None
        path_allowlist: dict[str, Any] = {}
        for operation in ("read", "write", "patch"):
            if path_allowlist_rule is None:
                path_allowlist[operation] = _AbsentStep("path_allowlist")
                continue
            if operation == "read":
                patterns = path_allowlist_rule.read
            elif operation == "patch":
                patterns = (
                    path_allowlist_rule.patch
                    if path_allowlist_rule.patch
                    else path_allowlist_rule.write
                )
            else:
                patterns = path_allowlist_rule.write
            path_allowlist[operation] = _PathAllowlistStep(path_allowlist_rule, patterns)

        secret_rule = rules.secret_patterns if rules is not None else None
        secret_patterns: dict[bool, Any] = {}
        if secret_rule is None:
            absent_secrets = _AbsentStep("secret_patterns")
            secret_patterns[True] = absent_secrets
            secret_patterns[False] = absent_secrets
        else:
            path_bearing_secrets = _SecretPatternsStep(
                secret_rule, True, strict, errors
            )
            secret_patterns[True] = path_bearing_secrets
            secret_patterns[False] = path_bearing_secrets.for_path_bearing(False)

        patch_integrity = block(
            "patch_integrity",
            rules.patch_integrity if rules is not None else None,
            lambda rule: _PatchIntegrityStep(rule, strict, errors),
        )
        shell_commands = block(
            "shell_commands",
            rules.shell_commands if rules is not None else None,
            lambda rule: _ShellCommandsStep(rule, strict, errors),
        )
        computer_use = block(
            "computer_use",
            rules.computer_use if rules is not None else None,
            _ComputerUseStep,
        )
        remote_desktop = block(
            "remote_desktop_channels",
            rules.remote_desktop_channels if rules is not None else None,
            _RemoteDesktopChannelsStep,
        )
        input_injection = block(
            "input_injection",
            rules.input_injection if rules is not None else None,
            _InputInjectionStep,
        )
        browser_automation = block(
            "browser_automation",
            rules.browser_automation if rules is not None else None,
            lambda rule: _BrowserAutomationStep(rule, strict, errors),
        )
        code_execution = block(
            "code_execution",
            rules.code_execution if rules is not None else None,
            _CodeExecutionStep,
        )

        # -- overlay-bearing blocks: one folded variant per origin profile ---
        tool_base = rules.tool_access if rules is not None else None
        egress_base = rules.egress if rules is not None else None
        tool_variants: dict[int, _CompiledToolAccess] = {}
        egress_variants: dict[int, _CompiledEgress] = {}
        for profile in profiles:
            if profile.tool_access is not None:
                tool_variants[id(profile)] = _CompiledToolAccess(
                    tool_base, (profile.id, profile.tool_access)
                )
            if profile.egress is not None:
                egress_variants[id(profile)] = _CompiledEgress(
                    egress_base, (profile.id, profile.egress)
                )
        tool_access = _ToolAccessStep(
            "tool_access",
            tool_base,
            tool_variants,
            _CompiledToolAccess(tool_base, None) if tool_base is not None else None,
        )
        egress = _EgressStep(
            "egress",
            egress_base,
            egress_variants,
            _CompiledEgress(egress_base, None) if egress_base is not None else None,
        )

        # -- per-action-type plans ------------------------------------------
        by_block = {
            "forbidden_paths": lambda action_type: forbidden_paths,
            "path_allowlist": lambda action_type: path_allowlist[
                "read"
                if action_type == "file_read"
                else "patch"
                if action_type == "patch_apply"
                else "write"
            ],
            "secret_patterns": lambda action_type: secret_patterns[
                action_type in ("file_write", "patch_apply")
            ],
            "patch_integrity": lambda action_type: patch_integrity,
            "shell_commands": lambda action_type: shell_commands,
            "tool_access": lambda action_type: tool_access,
            "egress": lambda action_type: egress,
            "computer_use": lambda action_type: computer_use,
            "remote_desktop_channels": lambda action_type: remote_desktop,
            "input_injection": lambda action_type: input_injection,
            "browser_automation": lambda action_type: browser_automation,
            "code_execution": lambda action_type: code_execution,
        }
        plans: dict[str, _Plan] = {}
        for action_type, blocks in _APPLICABLE_BLOCKS.items():
            plans[action_type] = _Plan(
                blocks,
                tuple(by_block[name](action_type) for name in blocks),
                action_type in _PATH_ACTIONS,
                required_capability(action_type),
            )
        self._plans = plans
        #: Every pattern a lenient compile could not compile, in document
        #: order. Empty for a policy compiled strictly (it would have raised).
        self.errors: tuple[CompileError, ...] = tuple(errors)

    # -- identity -----------------------------------------------------------

    @property
    def content_hash(self) -> str:
        """Canonical content hash of :attr:`spec`, computed at most once."""
        digest = self._content_hash
        if digest is None:
            from hushspec.canonical import content_hash

            digest = self._content_hash = content_hash(self.spec)
        return digest

    @property
    def resolution(self) -> Any:
        """The policy's :class:`~hushspec.resolve.Resolution`.

        The one it was compiled from, or a one-link ``memory`` resolution built
        (once) from :attr:`spec` for a policy compiled without provenance.
        """
        resolution = self._resolution
        if resolution is None:
            from hushspec.resolve import Resolution

            resolution = self._resolution = Resolution.from_resolved(self.spec)
            self._content_hash = resolution.content_hash
        return resolution

    # -- origins and posture ------------------------------------------------

    def select_origin_profile(
        self, origin: Optional[OriginContext]
    ) -> Optional[OriginProfile]:
        """Origin profile selection (origins spec Section 3)."""
        if origin is None or not self._profiles:
            return None
        best: Optional[tuple[int, OriginProfile]] = None
        for profile, match_rules in self._profiles:
            matched_fields = _match_origin(match_rules, origin)
            if matched_fields is None:
                continue
            if match_rules.space_id is not None:
                return profile
            if best is None or matched_fields > best[0]:
                best = (matched_fields, profile)
        return best[1] if best is not None else None

    def resolve_posture(
        self,
        matched_profile: Optional[OriginProfile],
        posture: Optional[PostureContext],
    ) -> Optional[PostureResult]:
        posture_ext = self._posture
        if posture_ext is None:
            return None

        current: Optional[str] = None
        if matched_profile is not None and matched_profile.posture is not None:
            current = matched_profile.posture
        elif posture is not None and posture.current is not None:
            current = posture.current
        if current is None:
            current = posture_ext.initial

        signal: Optional[str] = None
        if (
            posture is not None
            and posture.signal is not None
            and posture.signal != "none"
        ):
            signal = posture.signal

        if signal is not None:
            # Posture spec 5.3: a transition whose `from` names the
            # current state outranks one whose `from` is `"*"`; among equals,
            # document order. Two passes rather than one scan with a
            # best-so-far, so the named pass short-circuits on its first hit.
            for wildcard in (False, True):
                for transition in posture_ext.transitions:
                    source = transition.from_state
                    if (source == "*") is not wildcard:
                        continue
                    if not wildcard and source != current:
                        continue
                    if _trigger_name(transition.on) != signal:
                        continue
                    return PostureResult(current=current, next=transition.to)

        return PostureResult(current=current, next=current)

    # -- evaluation ---------------------------------------------------------

    def evaluate(self, action: EvaluationAction) -> EvaluationResult:
        """Evaluate *action*; ``when`` conditions read ``action.context``."""
        context = action.context
        return self._run(
            action,
            context if context is not None else _EMPTY_CONTEXT,
            _NO_CONDITIONS,
            None,
        )

    def evaluate_traced(
        self,
        action: EvaluationAction,
        context: Optional[RuntimeContext] = None,
        conditions: Optional[dict[str, Condition]] = None,
    ) -> TracedEvaluation:
        """Full evaluation with the recorded rule trace (used by receipts)."""
        return self._traced(action, context, conditions, record_trace=True)

    def _traced(
        self,
        action: EvaluationAction,
        context: Optional[RuntimeContext],
        conditions: Optional[dict[str, Condition]],
        *,
        record_trace: bool,
    ) -> TracedEvaluation:
        """:meth:`evaluate_traced` with the rule trace made optional.

        ``record_trace=False`` returns an empty trace and skips recording one;
        nothing else about the evaluation changes.
        """
        if context is None:
            context = action.context
            if context is None:
                context = _EMPTY_CONTEXT
        trace: list[RuleEvaluation] = []
        result = self._run(
            action,
            context,
            conditions or _NO_CONDITIONS,
            trace if record_trace else None,
        )
        return TracedEvaluation(result=result, trace=trace)

    def evaluate_with_context(
        self,
        action: EvaluationAction,
        context: RuntimeContext,
        conditions: dict[str, Condition],
    ) -> EvaluationResult:
        """Evaluate with an explicit runtime context and out-of-band conditions."""
        return self._run(action, context, conditions or _NO_CONDITIONS, None)

    def _run(
        self,
        action: EvaluationAction,
        context: RuntimeContext,
        conditions: dict[str, Condition],
        trace: Optional[list[RuleEvaluation]],
    ) -> EvaluationResult:
        if is_panic_active():
            reason = "emergency panic mode is active"
            if trace is not None:
                trace.append(
                    RuleEvaluation(
                        rule_block="panic",
                        outcome=RuleOutcome.DENY,
                        matched_rule=PANIC_RULE,
                        reason=reason,
                        evaluated=True,
                    )
                )
            return EvaluationResult(
                decision=Decision.DENY, matched_rule=PANIC_RULE, reason=reason
            )

        action_type = action.type
        plan = self._plans.get(action_type)
        if plan is None:
            reason = f"action type '{action_type}' is unknown to the specification"
            if trace is not None:
                trace.append(
                    RuleEvaluation(
                        rule_block="default",
                        outcome=RuleOutcome.DENY,
                        matched_rule=UNKNOWN_ACTION_TYPE_RULE,
                        reason=reason,
                        evaluated=True,
                    )
                )
            return EvaluationResult(
                decision=Decision.DENY,
                matched_rule=UNKNOWN_ACTION_TYPE_RULE,
                reason=reason,
            )

        # Origins guard: select a profile or apply default_behavior.
        matched_profile = self.select_origin_profile(action.origin)
        origin_profile_id = matched_profile.id if matched_profile is not None else None
        if matched_profile is None and self._origins_deny_default:
            reason = "no origin profile matched and default_behavior is deny"
            rule = "extensions.origins.default_behavior"
            if trace is not None:
                trace.append(
                    RuleEvaluation(
                        rule_block="origins",
                        outcome=RuleOutcome.DENY,
                        matched_rule=rule,
                        reason=reason,
                        evaluated=True,
                    )
                )
                _skip_all(trace, plan.blocks, "short-circuited by origins deny")
            return EvaluationResult(
                decision=Decision.DENY, matched_rule=rule, reason=reason
            )

        # Posture guard.
        posture = self.resolve_posture(matched_profile, action.posture)
        denied = self._posture_capability_guard(posture, plan.capability, trace)
        if denied is not None:
            if trace is not None:
                _skip_all(trace, plan.blocks, "short-circuited by posture deny")
            return EvaluationResult(
                decision=Decision.DENY,
                matched_rule=denied[0],
                reason=denied[1],
                origin_profile=origin_profile_id,
                posture=posture,
            )

        if action_type == "custom":
            # Only a posture state granting the `custom` capability can vouch
            # for an engine-defined action (core spec Section 5).
            if posture is None:
                reason = (
                    "custom actions require a posture state granting the "
                    "custom capability"
                )
                if trace is not None:
                    trace.append(
                        RuleEvaluation(
                            rule_block="default",
                            outcome=RuleOutcome.DENY,
                            matched_rule=UNKNOWN_ACTION_TYPE_RULE,
                            reason=reason,
                            evaluated=True,
                        )
                    )
                return EvaluationResult(
                    decision=Decision.DENY,
                    matched_rule=UNKNOWN_ACTION_TYPE_RULE,
                    reason=reason,
                    origin_profile=origin_profile_id,
                )
            return EvaluationResult(
                decision=Decision.ALLOW,
                origin_profile=origin_profile_id,
                posture=posture,
            )

        # Block evaluation and aggregation (core spec 6.1).
        ev = _Eval(action, context, conditions)
        ev.profile = matched_profile
        # `when` conditions read the effective posture state (core spec 3.13),
        # which the posture guard above has already resolved.
        ev.capabilities = self._posture_capabilities(posture)
        if plan.needs_path:
            target = action.target
            ev.normalized_path = normalize_path(target) if target is not None else ""

        decisions: list[_BlockDecision] = []
        for step in plan.steps:
            outcome = step.run(ev)
            if outcome.__class__ is _Inactive:
                if trace is not None:
                    trace.append(
                        RuleEvaluation(
                            rule_block=step.block,
                            outcome=RuleOutcome.SKIP,
                            matched_rule=None,
                            reason=outcome.reason,
                            evaluated=False,
                        )
                    )
                continue
            if trace is not None:
                trace.append(
                    RuleEvaluation(
                        rule_block=step.block,
                        outcome=outcome.outcome,
                        matched_rule=outcome.matched_rule,
                        reason=outcome.reason,
                        evaluated=True,
                    )
                )
            decisions.append(outcome)

        aggregate = Decision.ALLOW
        best_rank = 1
        for decision in decisions:
            if decision.rank > best_rank:
                best_rank = decision.rank
                aggregate = decision.decision
        matched_rule: Optional[str] = None
        reason = None
        for decision in decisions:
            if decision.rank == best_rank and decision.matched_rule is not None:
                matched_rule = decision.matched_rule
                reason = decision.reason
                break
        return EvaluationResult(
            decision=aggregate,
            matched_rule=matched_rule,
            reason=reason,
            origin_profile=origin_profile_id,
            posture=posture,
        )

    def _posture_capabilities(
        self, posture: Optional[PostureResult]
    ) -> Optional[list[str]]:
        """What the effective posture state grants, for ``capability``
        conditions (core spec 3.13).

        ``None`` when the policy has no posture extension -- the predicate is
        then unevaluable and holds; an unknown state grants nothing.
        """
        posture_extension = self._posture
        if posture_extension is None or posture is None:
            return None
        state = posture_extension.states.get(posture.current)
        return list(state.capabilities) if state is not None else []

    def _posture_capability_guard(
        self,
        posture: Optional[PostureResult],
        capability: Optional[str],
        trace: Optional[list[RuleEvaluation]],
    ) -> Optional[tuple[str, str]]:
        if posture is None:
            return None
        posture_extension = self._posture
        if posture_extension is None:
            return None

        # The state is looked up before the capability table is consulted, so
        # an unknown state denies even the action types the table does not
        # gate (posture spec 3.3).
        current_state = posture_extension.states.get(posture.current)
        if current_state is None:
            rule = f"extensions.posture.states.{posture.current}"
            reason = f"unknown posture state '{posture.current}'"
        elif capability is None:
            return None
        elif capability in current_state.capabilities:
            if trace is not None:
                trace.append(
                    RuleEvaluation(
                        rule_block="posture_capability",
                        outcome=RuleOutcome.ALLOW,
                        matched_rule=None,
                        reason="posture capabilities satisfied",
                        evaluated=True,
                    )
                )
            return None
        else:
            rule = f"extensions.posture.states.{posture.current}.capabilities"
            reason = (
                f"posture '{posture.current}' does not allow capability '{capability}'"
            )
        if trace is not None:
            trace.append(
                RuleEvaluation(
                    rule_block="posture_capability",
                    outcome=RuleOutcome.DENY,
                    matched_rule=rule,
                    reason=reason,
                    evaluated=True,
                )
            )
        return rule, reason

    # -- detection ----------------------------------------------------------

    def evaluate_with_detection(
        self, action: EvaluationAction
    ) -> EvaluationWithDetection:
        """Evaluate, then fold in the configured content detectors."""
        traced = self.run_with_detection(action, record_trace=False)
        return EvaluationWithDetection(
            evaluation=traced.evaluation,
            detections=traced.detections,
            detection_decision=traced.detection_decision,
        )

    def evaluate_with_detection_traced(
        self,
        action: EvaluationAction,
        context: Optional[RuntimeContext] = None,
        conditions: Optional[dict[str, Condition]] = None,
    ) -> TracedEvaluationWithDetection:
        """:meth:`evaluate_with_detection` with the rule and detector traces."""
        return self.run_with_detection(action, context, conditions, record_trace=True)

    def run_with_detection(
        self,
        action: EvaluationAction,
        context: Optional[RuntimeContext] = None,
        conditions: Optional[dict[str, Condition]] = None,
        *,
        record_trace: bool = True,
    ) -> TracedEvaluationWithDetection:
        """:meth:`evaluate_with_detection_traced` with the rule trace optional.

        The detector trace is recorded either way: a receipt has to say whether
        the detection pipeline ran (receipt spec 4.6) however little else it
        keeps.
        """
        detection = self._detection
        if detection is None:
            # Exact no-op for a policy with no `detection:` extension: no
            # detector trace at all (receipt spec 4.6).
            traced = self._traced(
                action, context, conditions, record_trace=record_trace
            )
            return TracedEvaluationWithDetection(
                traced=traced, evaluation=traced.result
            )
        traced = self._traced(action, context, conditions, record_trace=record_trace)
        base = traced.result
        content = action.content or ""
        if not content:
            return TracedEvaluationWithDetection(
                traced=traced, evaluation=base, detector_trace=[]
            )

        detections: list[DetectionResult] = []
        detector_trace: list[DetectorEvaluation] = []
        # (contribution, category) pairs in detector run order, used below to
        # find "the first detector that forced the escalation".
        contributions: list[tuple[Decision, str]] = []

        config = detection.prompt_injection
        if config is not None:
            (
                max_bytes,
                block_floor,
                warn_floor,
                heuristics_enabled,
                min_score,
            ) = config
            scan = _truncate_to_bytes(content, max_bytes)
            # Every prompt-injection detector runs -- the regex detector and
            # the normative heuristic one (detection spec 3.5) -- each scored
            # against the same byte budget and level floors, each recording
            # its own trace entry.
            registry = default_detector_registry()
            for detector in registry.detectors_for(
                DetectionCategory.PROMPT_INJECTION
            ):
                is_heuristic = detector.name == HEURISTIC_DETECTOR_NAME
                if is_heuristic and not heuristics_enabled:
                    continue
                result = detector.detect(scan)
                if is_heuristic and heuristic_integer(result.score) < min_score:
                    # Below the policy's floor the heuristic reports no signal
                    # (detection spec 3.5.4).
                    result = DetectionResult(
                        detector_name=result.detector_name,
                        category=result.category,
                        score=0.0,
                    )
                score = result.score
                contribution: Optional[Decision] = None
                if score >= block_floor:
                    contribution = Decision.DENY
                elif score >= warn_floor:
                    contribution = Decision.WARN
                detections.append(result)
                if contribution is not None:
                    contributions.append((contribution, "prompt_injection"))
                detector_trace.append(
                    DetectorEvaluation(
                        detector_id=f"{result.detector_name}{DETECTOR_ID_VERSION}",
                        category=DetectionCategory.PROMPT_INJECTION,
                        score=score,
                        level=DetectorLevel.from_score(score),
                        matched=contribution is not None,
                    )
                )

        config = detection.jailbreak
        if config is not None:
            max_bytes, block_threshold, warn_threshold = config
            detector = default_detector_registry().detector_for(
                DetectionCategory.JAILBREAK
            )
            if detector is None:
                raise CompileError(
                    "the built-in detector registry has no jailbreak detector"
                )
            result = detector.detect(_truncate_to_bytes(content, max_bytes))
            score = result.score
            percent = score * 100.0
            contribution = None
            if percent >= block_threshold:
                contribution = Decision.DENY
            elif percent >= warn_threshold:
                contribution = Decision.WARN
            detections.append(result)
            if contribution is not None:
                contributions.append((contribution, "jailbreak"))
            detector_trace.append(
                DetectorEvaluation(
                    detector_id=f"{result.detector_name}{DETECTOR_ID_VERSION}",
                    category=DetectionCategory.JAILBREAK,
                    score=score,
                    level=DetectorLevel.from_score(score),
                    matched=contribution is not None,
                )
            )

        # threat_intel is deliberately NOT auto-wired: the built-in engine ships
        # only regex detectors and has no pattern-db / similarity model to
        # satisfy detection.threat_intel.

        detection_decision: Optional[Decision] = None
        for contribution, _category in contributions:
            if (
                detection_decision is None
                or _DETECTION_RANK[contribution] > _DETECTION_RANK[detection_decision]
            ):
                detection_decision = contribution

        final_decision = (
            base.decision
            if detection_decision is None
            else (
                detection_decision
                if _DETECTION_RANK[detection_decision] > _DETECTION_RANK[base.decision]
                else base.decision
            )
        )

        if final_decision != base.decision:
            category = next(
                cat for decision, cat in contributions if decision == detection_decision
            )
            evaluation = EvaluationResult(
                decision=final_decision,
                matched_rule="detection",
                reason=f"content flagged by {category} detection",
                origin_profile=base.origin_profile,
                posture=base.posture,
            )
        else:
            evaluation = base

        return TracedEvaluationWithDetection(
            traced=traced,
            evaluation=evaluation,
            detections=detections,
            detection_decision=detection_decision,
            detector_trace=detector_trace,
        )

    # -- receipts -----------------------------------------------------------

    def evaluate_audited(
        self,
        action: EvaluationAction,
        config: Optional[Any] = None,
        context: Optional[Any] = None,
        resolution: Optional[Any] = None,
    ) -> Any:
        """Evaluate and record the :class:`~hushspec.receipt.DecisionReceipt`.

        *resolution* names the policy in the receipt; :attr:`resolution` is
        used when it is omitted.
        """
        from hushspec.receipt import audited_from_compiled

        return audited_from_compiled(
            self,
            resolution if resolution is not None else self.resolution,
            action,
            config,
            context,
        )


_DETECTION_RANK: dict[Decision, int] = {
    Decision.ALLOW: 0,
    Decision.WARN: 1,
    Decision.DENY: 2,
}

def _skip_all(
    trace: list[RuleEvaluation], blocks: tuple[str, ...], reason: str
) -> None:
    for block in blocks:
        trace.append(
            RuleEvaluation(
                rule_block=block,
                outcome=RuleOutcome.SKIP,
                matched_rule=None,
                reason=reason,
                evaluated=False,
            )
        )


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def compile_policy(
    policy: Union[HushSpec, Any], *, strict: bool = True
) -> CompiledPolicy:
    """Compile a resolved policy once, for repeated evaluation.

    *policy* is a :class:`~hushspec.schema.HushSpec` or a
    :class:`~hushspec.resolve.Resolution` (whose provenance the compiled policy
    then carries into receipts).

    Raises :class:`CompileError` for a document that still declares ``extends``
    and for the first pattern outside the HushSpec regex profile. Pass
    ``strict=False`` to keep the reference evaluator's deferred behaviour for
    patterns instead: the offending pattern is recorded in
    :attr:`CompiledPolicy.errors` and denies the actions that reach it, with
    the same ``matched_rule`` and ``reason`` an uncompiled evaluation gave. An
    unresolved document is refused either way (core spec 2.3).
    """
    resolution = None
    spec = policy
    if not isinstance(policy, HushSpec):
        resolution = policy
        spec = policy.spec
    if spec.extends is not None:
        # Core spec 2.3: an engine MUST refuse to evaluate a document that
        # still declares `extends`. Its rules are not the rules that would be
        # in force -- every block its base contributes would silently be
        # missing -- so there is nothing safe to compile.
        raise CompileError(
            "extends",
            f"policy still declares 'extends: {spec.extends}'; resolve the chain "
            "before compiling it",
        )
    compiled = CompiledPolicy(spec, strict)
    if resolution is not None:
        compiled._resolution = resolution
        compiled._content_hash = resolution.content_hash
    return compiled


#: Compiled policies for the free-function wrappers, keyed by ``id(spec)``.
#: The entry holds the spec itself, so an id can never be reused while it is
#: cached. Bounded: a run that evaluates thousands of one-shot documents (the
#: fixture suites, the differential fuzzer) must not retain them all.
_CACHE: dict[int, CompiledPolicy] = {}
_CACHE_MAX = 64


def compiled_for_spec(spec: HushSpec) -> CompiledPolicy:
    """The compiled form of *spec*, compiled on first use and reused after.

    Lenient by design: this backs the free ``evaluate*`` functions, which deny
    on an unusable pattern rather than raising.
    """
    key = id(spec)
    hit = _CACHE.get(key)
    if hit is not None and hit.spec is spec:
        return hit
    compiled = CompiledPolicy(spec, False)
    if len(_CACHE) >= _CACHE_MAX:
        _CACHE.clear()
    _CACHE[key] = compiled
    return compiled
