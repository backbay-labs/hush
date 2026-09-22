from __future__ import annotations

import math
import re
from typing import Any, Callable

from hushspec.conditions import Condition
from hushspec.error_codes import (
    ERROR_CONSTRAINT_VIOLATION,
    ERROR_DUPLICATE_PATTERN_NAME,
    ERROR_INVALID_REGEX,
    ERROR_PARSE,
    ERROR_UNSUPPORTED_VERSION,
    ErrorMessage,
)
from hushspec.regex_profile import NESTED_QUANTIFIER_MESSAGE, compile_profile_regex
# The regex-portability scanners are shared with hushspec.validate rather
# than copied: a pattern parse() refuses and one validate() refuses can then
# never drift apart.
from hushspec.validate import _disallowed_regex_feature, _has_nested_quantifier
from hushspec.generated_contract import (
    BROWSER_AUTOMATION_KEYS,
    CODE_EXECUTION_KEYS,
    ORIGIN_EGRESS_OVERLAY_KEYS,
    ORIGIN_TOOL_ACCESS_OVERLAY_KEYS,
    BRIDGE_POLICY_KEYS,
    BRIDGE_TARGET_KEYS,
    CLASSIFICATIONS,
    COMPUTER_USE_KEYS,
    COMPUTER_USE_MODES,
    CHANGELOG_ENTRY_KEYS,
    CONTROL_MAPPING_KEYS,
    DEFAULT_ACTIONS,
    DETECTION_KEYS,
    DETECTION_LEVELS,
    EGRESS_KEYS,
    EXTENSION_KEYS,
    FORBIDDEN_PATH_KEYS,
    GOVERNANCE_METADATA_KEYS,
    INPUT_INJECTION_KEYS,
    JAILBREAK_KEYS,
    LIFECYCLE_STATES,
    ORIGINS_KEYS,
    ORIGIN_BUDGET_KEYS,
    ORIGIN_DATA_KEYS,
    ORIGIN_DEFAULT_BEHAVIORS,
    ORIGIN_MATCH_KEYS,
    ORIGIN_PROFILE_KEYS,
    ORIGIN_SPACE_TYPES,
    ORIGIN_VISIBILITIES,
    PATCH_INTEGRITY_KEYS,
    PATH_ALLOWLIST_KEYS,
    POSTURE_KEYS,
    POSTURE_STATE_KEYS,
    POSTURE_TRANSITION_KEYS,
    PROMPT_INJECTION_HEURISTICS_KEYS,
    PROMPT_INJECTION_KEYS,
    REMOTE_DESKTOP_KEYS,
    RULE_KEYS,
    SECRET_PATTERNS_KEYS,
    SECRET_PATTERN_KEYS,
    SEVERITIES,
    SHELL_COMMAND_KEYS,
    THREAT_INTEL_KEYS,
    TOOL_ACCESS_KEYS,
    TOP_LEVEL_KEYS,
    TRANSITION_TRIGGERS,
)

DURATION_PATTERN = re.compile(r"^[0-9]+[smhd]$")
FRAMEWORK_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]*$")

#: Largest integer an IEEE 754 double holds exactly (canonical spec 4.3).
MAX_SAFE_INTEGER = 2**53 - 1


def unsafe_integer(value: Any, path: str = "$") -> str | None:
    """The first integer past the IEEE 754 safe range, or ``None``.

    The bound belongs to integer *syntax*: ``10000000000000000`` names an exact
    integer a double cannot hold, while ``1.0e+16`` names the double itself and
    is accepted whatever its magnitude. The decoded document is the last place
    that distinction survives -- PyYAML hands integer-syntax scalars over as
    ``int`` and float-syntax scalars as ``float`` -- so the bound is applied
    here, which keeps a rounded integer out of a content hash and refuses the
    document even for an engine that never hashes it.
    """
    if isinstance(value, bool):
        # A YAML boolean is not an integer, whatever Python's type hierarchy says.
        return None
    if isinstance(value, int):
        if value > MAX_SAFE_INTEGER or value < -MAX_SAFE_INTEGER:
            return f"{path}: integer {value} exceeds the safe range (2^53-1)"
        return None
    if isinstance(value, list):
        for index, item in enumerate(value):
            found = unsafe_integer(item, f"{path}[{index}]")
            if found is not None:
                return found
        return None
    if isinstance(value, dict):
        for key, item in value.items():
            found = unsafe_integer(item, f"{path}.{key}")
            if found is not None:
                return found
    return None



#: The declared members of a ``when`` condition, each with the type its value
#: must have (core spec 3.13).
_CONDITION_MEMBER_TYPES = {
    "time_window": "an object",
    "context": "an object",
    "all_of": "an array",
    "any_of": "an array",
    "not": "an object",
    "capability": "a string",
    "rate": "an object",
}


def _reject_null_condition_members(
    raw: Any, errors: list[str], path: str
) -> None:
    """Refuse a ``null`` written for a declared member of a condition.

    No HushSpec property is nullable (canonical spec 2.2), but a written null
    reads as an absent member to :meth:`Condition.from_dict`, which is the
    decoder both validation and evaluation run a ``when`` through.
    """
    if not isinstance(raw, dict):
        return
    for key, expected in _CONDITION_MEMBER_TYPES.items():
        if key in raw and raw[key] is None:
            errors.append(f"{path}.{key}: invalid type, expected {expected}")
    for key in ("all_of", "any_of"):
        children = raw.get(key)
        if isinstance(children, list):
            for index, child in enumerate(children):
                _reject_null_condition_members(child, errors, f"{path}.{key}[{index}]")
    if isinstance(raw.get("not"), dict):
        _reject_null_condition_members(raw["not"], errors, f"{path}.not")


def _validate_when(obj: dict[str, Any], errors: list[str], path: str) -> None:
    """Structural check of a rule block's ``when`` condition (core spec 3.13).

    Unknown keys and wrong types inside a condition are *parse* errors; the
    semantic checks --
    ``HH:MM`` values, timezone, day names, nesting depth -- belong to
    ``validate`` and live in hushspec.validate.validate_conditions.
    """
    if "when" not in obj:
        return
    _reject_null_condition_members(obj["when"], errors, f"{path}.when")
    try:
        Condition.from_dict(obj["when"])
    except (ValueError, TypeError, AttributeError) as exc:
        errors.append(f"{path}.when: {exc}")


def _constraint(message: str) -> ErrorMessage:
    """A core Section 7 / extension-module constraint violation (E004).

    Everything else this module reports is a parse-time refusal (E001): the
    shape, type, enum and unknown-key checks a document must pass before it
    decodes at all. Only the semantic constraints are tagged, so every SDK
    names the same registry code for the same vector.
    """
    return ErrorMessage(message, ERROR_CONSTRAINT_VIOLATION)


def validate_raw_document(doc: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(doc, dict):
        errors.append("HushSpec document must be a YAML mapping")
        return errors

    _validate_top_level(doc, errors)
    return errors


def _validate_top_level(obj: dict[str, Any], errors: list[str]) -> None:
    _reject_unknown_keys(obj, TOP_LEVEL_KEYS, errors, "the top level")

    if "hushspec" not in obj:
        errors.append("missing field `hushspec`")
    elif obj["hushspec"] is None:
        # The schema types `hushspec` as a string (canonical spec 2.2), so a
        # written null is a value of the wrong type -- there is no version here
        # to call unsupported.
        errors.append("hushspec: invalid type, expected a string")
    elif not isinstance(obj["hushspec"], str):
        # Present but not a version string at all -- `hushspec: 0.1` is a YAML
        # float, not `"0.1.0"`. The reference reports that as an unsupported
        # version rather than as a shape error.
        errors.append(
            ErrorMessage(
                "unsupported hushspec version: the `hushspec` field must be a "
                f"three-part version string, got {obj['hushspec']!r}",
                ERROR_UNSUPPORTED_VERSION,
            )
        )
    _validate_optional_string(obj, "name", errors, "name")
    _validate_optional_string(obj, "description", errors, "description")
    _validate_optional_string(obj, "extends", errors, "extends")
    _validate_optional_enum(
        obj, "merge_strategy", errors, "merge_strategy", {"replace", "merge", "deep_merge"}
    )

    if "rules" in obj:
        if not isinstance(obj["rules"], dict):
            errors.append("rules: invalid type, expected an object")
        else:
            _validate_rules(obj["rules"], errors)

    if "extensions" in obj:
        if not isinstance(obj["extensions"], dict):
            errors.append("extensions: invalid type, expected an object")
        else:
            _validate_extensions(obj["extensions"], errors)

    if "metadata" in obj:
        if not isinstance(obj["metadata"], dict):
            errors.append("metadata: invalid type, expected an object")
        else:
            _validate_governance_metadata(obj["metadata"], errors)


def _validate_rules(obj: dict[str, Any], errors: list[str]) -> None:
    _reject_unknown_keys(obj, RULE_KEYS, errors, "rules")
    _validate_optional_object(obj, "forbidden_paths", errors, "rules", _validate_forbidden_paths)
    _validate_optional_object(obj, "path_allowlist", errors, "rules", _validate_path_allowlist)
    _validate_optional_object(obj, "egress", errors, "rules", _validate_egress)
    _validate_optional_object(obj, "secret_patterns", errors, "rules", _validate_secret_patterns)
    _validate_optional_object(obj, "patch_integrity", errors, "rules", _validate_patch_integrity)
    _validate_optional_object(obj, "shell_commands", errors, "rules", _validate_shell_commands)
    _validate_optional_object(obj, "tool_access", errors, "rules", _validate_tool_access)
    _validate_optional_object(obj, "computer_use", errors, "rules", _validate_computer_use)
    _validate_optional_object(
        obj, "remote_desktop_channels", errors, "rules", _validate_remote_desktop_channels
    )
    _validate_optional_object(obj, "input_injection", errors, "rules", _validate_input_injection)
    _validate_optional_object(obj, "browser_automation", errors, "rules", _validate_browser_automation)
    _validate_optional_object(obj, "code_execution", errors, "rules", _validate_code_execution)


def _validate_forbidden_paths(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, FORBIDDEN_PATH_KEYS, errors, path)
    _validate_when(obj, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_string_array(obj, "patterns", errors, f"{path}.patterns")
    _validate_optional_string_array(obj, "exceptions", errors, f"{path}.exceptions")


def _validate_path_allowlist(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, PATH_ALLOWLIST_KEYS, errors, path)
    _validate_when(obj, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_string_array(obj, "read", errors, f"{path}.read")
    _validate_optional_string_array(obj, "write", errors, f"{path}.write")
    _validate_optional_string_array(obj, "patch", errors, f"{path}.patch")


def _validate_egress(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, EGRESS_KEYS, errors, path)
    _validate_when(obj, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_string_array(obj, "allow", errors, f"{path}.allow")
    _validate_optional_string_array(obj, "block", errors, f"{path}.block")
    _validate_optional_enum(obj, "default", errors, f"{path}.default", DEFAULT_ACTIONS)


def _validate_secret_patterns(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, SECRET_PATTERNS_KEYS, errors, path)
    _validate_when(obj, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_string_array(obj, "skip_paths", errors, f"{path}.skip_paths")

    if "patterns" not in obj:
        return
    patterns = obj["patterns"]
    if not isinstance(patterns, list):
        errors.append(f"{path}.patterns: invalid type, expected an array")
        return

    seen: set[str] = set()
    for index, pattern in enumerate(patterns):
        item_path = f"{path}.patterns[{index}]"
        if not isinstance(pattern, dict):
            errors.append(f"{item_path}: invalid type, expected an object")
            continue
        _reject_unknown_keys(pattern, SECRET_PATTERN_KEYS, errors, item_path)
        name = _validate_required_string(pattern, "name", errors, f"{item_path}.name is required")
        regex = _validate_required_string(
            pattern, "pattern", errors, f"{item_path}.pattern is required"
        )
        _validate_required_enum(
            pattern, "severity", errors, f"{item_path}.severity", SEVERITIES
        )
        _validate_optional_string(pattern, "description", errors, f"{item_path}.description")
        if name is not None:
            if name in seen:
                errors.append(
                    ErrorMessage(
                        f"duplicate secret pattern name: {name}",
                        ERROR_DUPLICATE_PATTERN_NAME,
                    )
                )
            seen.add(name)
        if regex is not None:
            _validate_regex(regex, errors, f"{item_path}.pattern")


def _validate_patch_integrity(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, PATCH_INTEGRITY_KEYS, errors, path)
    _validate_when(obj, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_int(obj, "max_additions", errors, f"{path}.max_additions", min_value=0)
    _validate_optional_int(obj, "max_deletions", errors, f"{path}.max_deletions", min_value=0)
    _validate_optional_bool(obj, "require_balance", errors, f"{path}.require_balance")
    _validate_optional_number(
        obj, "max_imbalance_ratio", errors, f"{path}.max_imbalance_ratio", min_exclusive=0
    )

    patterns = _validate_optional_string_array(
        obj, "forbidden_patterns", errors, f"{path}.forbidden_patterns"
    )
    if patterns is not None:
        for index, pattern in enumerate(patterns):
            _validate_regex(pattern, errors, f"{path}.forbidden_patterns[{index}]")


def _validate_shell_commands(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, SHELL_COMMAND_KEYS, errors, path)
    _validate_when(obj, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    patterns = _validate_optional_string_array(
        obj, "forbidden_patterns", errors, f"{path}.forbidden_patterns"
    )
    if patterns is not None:
        for index, pattern in enumerate(patterns):
            _validate_regex(pattern, errors, f"{path}.forbidden_patterns[{index}]")


def _validate_tool_access(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, TOOL_ACCESS_KEYS, errors, path)
    _validate_when(obj, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_string_array(obj, "allow", errors, f"{path}.allow")
    _validate_optional_string_array(obj, "block", errors, f"{path}.block")
    _validate_optional_string_array(
        obj, "require_confirmation", errors, f"{path}.require_confirmation"
    )
    _validate_optional_enum(obj, "default", errors, f"{path}.default", DEFAULT_ACTIONS)
    _validate_optional_int(obj, "max_args_size", errors, f"{path}.max_args_size", min_value=1)


def _validate_computer_use(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, COMPUTER_USE_KEYS, errors, path)
    _validate_when(obj, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_enum(obj, "mode", errors, f"{path}.mode", COMPUTER_USE_MODES)
    _validate_optional_string_array(obj, "allowed_actions", errors, f"{path}.allowed_actions")


def _validate_remote_desktop_channels(
    obj: dict[str, Any], errors: list[str], path: str
) -> None:
    _reject_unknown_keys(obj, REMOTE_DESKTOP_KEYS, errors, path)
    _validate_when(obj, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_bool(obj, "clipboard", errors, f"{path}.clipboard")
    _validate_optional_bool(obj, "file_transfer", errors, f"{path}.file_transfer")
    _validate_optional_bool(obj, "audio", errors, f"{path}.audio")
    _validate_optional_bool(obj, "drive_mapping", errors, f"{path}.drive_mapping")


def _validate_input_injection(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, INPUT_INJECTION_KEYS, errors, path)
    _validate_when(obj, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_string_array(obj, "allowed_types", errors, f"{path}.allowed_types")
    _validate_optional_bool(
        obj, "require_postcondition_probe", errors, f"{path}.require_postcondition_probe"
    )


def _validate_browser_automation(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, BROWSER_AUTOMATION_KEYS, errors, path)
    _validate_when(obj, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_string_array(obj, "allowed_domains", errors, f"{path}.allowed_domains")
    _validate_optional_string_array(obj, "blocked_domains", errors, f"{path}.blocked_domains")
    _validate_optional_string_array(obj, "allowed_verbs", errors, f"{path}.allowed_verbs")
    _validate_optional_bool(obj, "credential_detection", errors, f"{path}.credential_detection")

    patterns = _validate_optional_string_array(
        obj, "extra_credential_patterns", errors, f"{path}.extra_credential_patterns"
    )
    if patterns is not None:
        for index, pattern in enumerate(patterns):
            _validate_regex(pattern, errors, f"{path}.extra_credential_patterns[{index}]")


def _validate_code_execution(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, CODE_EXECUTION_KEYS, errors, path)
    _validate_when(obj, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_string_array(obj, "language_allowlist", errors, f"{path}.language_allowlist")
    _validate_optional_string_array(obj, "module_denylist", errors, f"{path}.module_denylist")
    _validate_optional_bool(obj, "network_access", errors, f"{path}.network_access")
    _validate_optional_int(
        obj, "max_execution_time_ms", errors, f"{path}.max_execution_time_ms", min_value=0
    )
    _validate_optional_int(obj, "max_scan_bytes", errors, f"{path}.max_scan_bytes", min_value=1)


def _validate_governance_metadata(obj: dict[str, Any], errors: list[str]) -> None:
    path = "metadata"
    _reject_unknown_keys(obj, GOVERNANCE_METADATA_KEYS, errors, path)
    _validate_optional_string(obj, "author", errors, f"{path}.author")
    _validate_optional_string(obj, "approved_by", errors, f"{path}.approved_by")
    _validate_optional_string(obj, "approval_date", errors, f"{path}.approval_date")
    _validate_optional_enum(obj, "classification", errors, f"{path}.classification", CLASSIFICATIONS)
    _validate_optional_string(obj, "change_ticket", errors, f"{path}.change_ticket")
    _validate_optional_enum(obj, "lifecycle_state", errors, f"{path}.lifecycle_state", LIFECYCLE_STATES)
    _validate_optional_int(obj, "policy_version", errors, f"{path}.policy_version", min_value=1)
    _validate_optional_string(obj, "effective_date", errors, f"{path}.effective_date")
    _validate_optional_string(obj, "expiry_date", errors, f"{path}.expiry_date")
    _validate_optional_string(obj, "owner", errors, f"{path}.owner")
    _validate_optional_string_array(obj, "reviewers", errors, f"{path}.reviewers")
    _validate_optional_string(obj, "next_review_date", errors, f"{path}.next_review_date")
    _validate_optional_string(obj, "supersedes", errors, f"{path}.supersedes")
    _validate_changelog(obj, errors, path)
    _validate_control_mappings(obj, errors, path)


def _validate_changelog(obj: dict[str, Any], errors: list[str], path: str) -> None:
    """Structural check of ``metadata.changelog`` (core spec 2.5.2).

    The typed model cannot tell a missing ``version`` from an empty one, so the
    required fields are checked here, at the raw level, exactly as the control
    mappings above are.
    """
    if "changelog" not in obj:
        return

    changelog = obj["changelog"]
    if not isinstance(changelog, list):
        errors.append(f"{path}.changelog: invalid type, expected an array")
        return

    for index, entry in enumerate(changelog):
        entry_path = f"{path}.changelog[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{entry_path}: invalid type, expected an object")
            continue

        _reject_unknown_keys(entry, CHANGELOG_ENTRY_KEYS, errors, entry_path)

        version = _validate_required_string(
            entry, "version", errors, f"{entry_path}.version is required"
        )
        if version == "":
            errors.append(f"{entry_path}.version must not be empty")

        _validate_required_string(entry, "date", errors, f"{entry_path}.date is required")

        _validate_optional_string(entry, "author", errors, f"{entry_path}.author")

        summary = _validate_required_string(
            entry, "summary", errors, f"{entry_path}.summary is required"
        )
        if summary == "":
            errors.append(f"{entry_path}.summary must not be empty")


def _validate_control_mappings(obj: dict[str, Any], errors: list[str], path: str) -> None:
    """Structural check of ``metadata.controls`` (core spec 2.5).

    Whether the framework is registered in ``spec/registries/frameworks.yaml``,
    and whether the rule paths resolve, are semantic questions answered by
    ``h2h lint`` (L012, L013); the registry deliberately stays out of the SDKs.
    """
    if "controls" not in obj:
        return

    controls = obj["controls"]
    if not isinstance(controls, list):
        errors.append(f"{path}.controls: invalid type, expected an array")
        return

    for index, entry in enumerate(controls):
        entry_path = f"{path}.controls[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{entry_path}: invalid type, expected an object")
            continue

        _reject_unknown_keys(entry, CONTROL_MAPPING_KEYS, errors, entry_path)

        framework = _validate_required_string(
            entry, "framework", errors, f"{entry_path}.framework is required"
        )
        if framework is not None and FRAMEWORK_ID_PATTERN.match(framework) is None:
            errors.append(
                _constraint(
                    f"{entry_path}.framework {framework!r} "
                    "must match ^[a-z0-9][a-z0-9.-]*$"
                )
            )

        control_id = _validate_required_string(
            entry, "control_id", errors, f"{entry_path}.control_id is required"
        )
        if control_id == "":
            errors.append(f"{entry_path}.control_id must not be empty")

        if "rule_paths" not in entry:
            errors.append(f"{entry_path}.rule_paths is required")
        else:
            rule_paths = _validate_optional_string_array(
                entry, "rule_paths", errors, f"{entry_path}.rule_paths"
            )
            if rule_paths is not None:
                if not rule_paths:
                    errors.append(
                        _constraint(
                            f"{entry_path}.rule_paths must list at least one rule path"
                        )
                    )
                for entry_index, rule_path in enumerate(rule_paths):
                    if rule_path == "":
                        errors.append(
                            f"{entry_path}.rule_paths[{entry_index}] must not be empty"
                        )

        _validate_optional_string(entry, "notes", errors, f"{entry_path}.notes")


def _validate_extensions(obj: dict[str, Any], errors: list[str]) -> None:
    _reject_unknown_keys(obj, EXTENSION_KEYS, errors, "extensions")
    _validate_optional_object(obj, "posture", errors, "extensions", _validate_posture)
    posture_states = (
        set(obj["posture"]["states"].keys())
        if isinstance(obj.get("posture"), dict) and isinstance(obj["posture"].get("states"), dict)
        else None
    )
    _validate_optional_object(
        obj,
        "origins",
        errors,
        "extensions",
        lambda value, errs, path: _validate_origins(value, errs, path, posture_states),
    )
    _validate_optional_object(obj, "detection", errors, "extensions", _validate_detection)


def _validate_posture(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, POSTURE_KEYS, errors, path)
    initial = _validate_required_string(obj, "initial", errors, f"{path}.initial is required")

    states = obj.get("states")
    if not isinstance(states, dict):
        errors.append(f"{path}.states: invalid type, expected an object")
        states = None
    transitions = obj.get("transitions")
    if not isinstance(transitions, list):
        errors.append(f"{path}.transitions: invalid type, expected an array")
        transitions = None

    state_names: set[str] = set()
    if states is not None:
        if len(states) == 0:
            errors.append(f"{path}.states must define at least one state")
        for state_name, state in states.items():
            if not isinstance(state_name, str):
                errors.append(f"{path}.states keys must be strings")
                continue
            state_names.add(state_name)
            state_path = f"{path}.states.{state_name}"
            if not isinstance(state, dict):
                errors.append(f"{state_path}: invalid type, expected an object")
                continue
            _reject_unknown_keys(state, POSTURE_STATE_KEYS, errors, state_path)
            _validate_optional_string(state, "description", errors, f"{state_path}.description")
            _validate_optional_string_array(state, "capabilities", errors, f"{state_path}.capabilities")
            if "budgets" in state:
                if not isinstance(state["budgets"], dict):
                    errors.append(f"{state_path}.budgets: invalid type, expected an object")
                else:
                    for budget_key, budget_value in state["budgets"].items():
                        if not isinstance(budget_key, str):
                            errors.append(f"{state_path}.budgets keys must be strings")
                            continue
                        _validate_int_value(
                            budget_value,
                            errors,
                            f"{state_path}.budgets.{budget_key}",
                            min_value=0,
                        )

    if initial is not None and state_names and initial not in state_names:
        errors.append(
            _constraint(f"posture.initial '{initial}' does not reference a defined state")
        )

    if transitions is not None:
        for index, transition in enumerate(transitions):
            transition_path = f"{path}.transitions[{index}]"
            if not isinstance(transition, dict):
                errors.append(f"{transition_path}: invalid type, expected an object")
                continue
            _reject_unknown_keys(transition, POSTURE_TRANSITION_KEYS, errors, transition_path)
            from_state = _validate_required_string(
                transition, "from", errors, f"{transition_path}.from is required"
            )
            to_state = _validate_required_string(
                transition, "to", errors, f"{transition_path}.to is required"
            )
            on = _validate_required_enum(
                transition, "on", errors, f"{transition_path}.on", TRANSITION_TRIGGERS
            )
            after = _validate_optional_string(transition, "after", errors, f"{transition_path}.after")

            if from_state is not None and from_state != "*" and from_state not in state_names:
                errors.append(
                    _constraint(
                        f"posture.transitions[{index}].from '{from_state}' "
                        "does not reference a defined state"
                    )
                )
            if to_state == "*":
                errors.append(
                    _constraint(f"posture.transitions[{index}].to cannot be '*'")
                )
            elif to_state is not None and to_state not in state_names:
                errors.append(
                    _constraint(
                        f"posture.transitions[{index}].to '{to_state}' "
                        "does not reference a defined state"
                    )
                )

            if on == "timeout":
                if after is None:
                    errors.append(
                        _constraint(
                            f"posture.transitions[{index}]: "
                            "timeout trigger requires 'after' field"
                        )
                    )
                elif not DURATION_PATTERN.match(after):
                    errors.append(
                        _constraint(f"{transition_path}.after must match ^\\d+[smhd]$")
                    )
            elif after is not None and not DURATION_PATTERN.match(after):
                errors.append(
                    _constraint(f"{transition_path}.after must match ^\\d+[smhd]$")
                )


def _validate_origins(
    obj: dict[str, Any], errors: list[str], path: str, posture_states: set[str] | None
) -> None:
    _reject_unknown_keys(obj, ORIGINS_KEYS, errors, path)
    _validate_optional_enum(
        obj, "default_behavior", errors, f"{path}.default_behavior", ORIGIN_DEFAULT_BEHAVIORS
    )

    if "profiles" not in obj:
        return
    profiles = obj["profiles"]
    if not isinstance(profiles, list):
        errors.append(f"{path}.profiles: invalid type, expected an array")
        return

    profile_ids: set[str] = set()
    for index, profile in enumerate(profiles):
        profile_path = f"{path}.profiles[{index}]"
        if not isinstance(profile, dict):
            errors.append(f"{profile_path}: invalid type, expected an object")
            continue
        _reject_unknown_keys(profile, ORIGIN_PROFILE_KEYS, errors, profile_path)
        profile_id = _validate_required_string(profile, "id", errors, f"{profile_path}.id is required")
        if profile_id is not None:
            if profile_id in profile_ids:
                errors.append(
                    _constraint(f"duplicate origin profile id: '{profile_id}'")
                )
            profile_ids.add(profile_id)

        if "match" in profile:
            match = profile["match"]
            if not isinstance(match, dict):
                errors.append(f"{profile_path}.match: invalid type, expected an object")
            else:
                _reject_unknown_keys(match, ORIGIN_MATCH_KEYS, errors, f"{profile_path}.match")
                _validate_optional_string(match, "provider", errors, f"{profile_path}.match.provider")
                _validate_optional_string(match, "tenant_id", errors, f"{profile_path}.match.tenant_id")
                _validate_optional_string(match, "space_id", errors, f"{profile_path}.match.space_id")
                _validate_constraint_enum(
                    match,
                    "space_type",
                    errors,
                    f"{profile_path}.match.space_type",
                    ORIGIN_SPACE_TYPES,
                )
                _validate_constraint_enum(
                    match,
                    "visibility",
                    errors,
                    f"{profile_path}.match.visibility",
                    ORIGIN_VISIBILITIES,
                )
                _validate_optional_bool(
                    match,
                    "external_participants",
                    errors,
                    f"{profile_path}.match.external_participants",
                )
                _validate_optional_string_array(match, "tags", errors, f"{profile_path}.match.tags")
                _validate_optional_string(match, "sensitivity", errors, f"{profile_path}.match.sensitivity")
                _validate_optional_string(match, "actor_role", errors, f"{profile_path}.match.actor_role")

                # A present-but-empty free-text match field (e.g.
                # `provider: ""`) is a degenerate constraint with no
                # consistent meaning, so it is rejected. `space_type` and
                # `visibility` are enums and already reject "" as an invalid
                # enum value via `_validate_optional_enum` above, so they are
                # excluded here.
                for match_field in (
                    "provider",
                    "tenant_id",
                    "space_id",
                    "sensitivity",
                    "actor_role",
                ):
                    _reject_empty_match_string(
                        match, match_field, f"{profile_path}.match.{match_field}", errors
                    )

        posture = _validate_optional_string(profile, "posture", errors, f"{profile_path}.posture")
        if posture is not None:
            if posture_states is None:
                errors.append(
                    _constraint(
                        f"{profile_path}.posture requires extensions.posture "
                        "to be defined"
                    )
                )
            elif posture not in posture_states:
                errors.append(
                    _constraint(
                        f"{profile_path}.posture '{posture}' does not reference "
                        "a defined posture state"
                    )
                )

        _validate_optional_object(
            profile, "tool_access", errors, profile_path, _validate_origin_tool_access
        )
        _validate_optional_object(
            profile, "egress", errors, profile_path, _validate_origin_egress
        )

        if "data" in profile:
            data = profile["data"]
            if not isinstance(data, dict):
                errors.append(f"{profile_path}.data: invalid type, expected an object")
            else:
                _reject_unknown_keys(data, ORIGIN_DATA_KEYS, errors, f"{profile_path}.data")
                _validate_optional_bool(
                    data, "allow_external_sharing", errors, f"{profile_path}.data.allow_external_sharing"
                )
                _validate_optional_bool(
                    data, "redact_before_send", errors, f"{profile_path}.data.redact_before_send"
                )
                _validate_optional_bool(
                    data,
                    "block_sensitive_outputs",
                    errors,
                    f"{profile_path}.data.block_sensitive_outputs",
                )

        if "budgets" in profile:
            budgets = profile["budgets"]
            if not isinstance(budgets, dict):
                errors.append(f"{profile_path}.budgets: invalid type, expected an object")
            else:
                _reject_unknown_keys(budgets, ORIGIN_BUDGET_KEYS, errors, f"{profile_path}.budgets")
                _validate_optional_int(
                    budgets, "tool_calls", errors, f"{profile_path}.budgets.tool_calls", min_value=0
                )
                _validate_optional_int(
                    budgets, "egress_calls", errors, f"{profile_path}.budgets.egress_calls", min_value=0
                )
                _validate_optional_int(
                    budgets,
                    "shell_commands",
                    errors,
                    f"{profile_path}.budgets.shell_commands",
                    min_value=0,
                )

        if "bridge" in profile:
            bridge = profile["bridge"]
            if not isinstance(bridge, dict):
                errors.append(f"{profile_path}.bridge: invalid type, expected an object")
            else:
                _reject_unknown_keys(bridge, BRIDGE_POLICY_KEYS, errors, f"{profile_path}.bridge")
                _validate_optional_bool(
                    bridge, "allow_cross_origin", errors, f"{profile_path}.bridge.allow_cross_origin"
                )
                _validate_optional_bool(
                    bridge, "require_approval", errors, f"{profile_path}.bridge.require_approval"
                )
                if "allowed_targets" in bridge:
                    targets = bridge["allowed_targets"]
                    if not isinstance(targets, list):
                        errors.append(f"{profile_path}.bridge.allowed_targets: invalid type, expected an array")
                    else:
                        for target_index, target in enumerate(targets):
                            target_path = f"{profile_path}.bridge.allowed_targets[{target_index}]"
                            if not isinstance(target, dict):
                                errors.append(f"{target_path}: invalid type, expected an object")
                                continue
                            _reject_unknown_keys(target, BRIDGE_TARGET_KEYS, errors, target_path)
                            _validate_optional_string(target, "provider", errors, f"{target_path}.provider")
                            _validate_constraint_enum(
                                target,
                                "space_type",
                                errors,
                                f"{target_path}.space_type",
                                ORIGIN_SPACE_TYPES,
                            )
                            _validate_optional_string_array(target, "tags", errors, f"{target_path}.tags")
                            _validate_constraint_enum(
                                target,
                                "visibility",
                                errors,
                                f"{target_path}.visibility",
                                ORIGIN_VISIBILITIES,
                            )

        _validate_optional_string(profile, "explanation", errors, f"{profile_path}.explanation")


def _validate_origin_tool_access(
    obj: dict[str, Any], errors: list[str], path: str
) -> None:
    """Tri-state tool_access overlay on an origin profile (origins spec 4)."""
    _reject_unknown_keys(obj, ORIGIN_TOOL_ACCESS_OVERLAY_KEYS, errors, path)
    _validate_optional_string_array(obj, "allow", errors, f"{path}.allow")
    _validate_optional_string_array(obj, "block", errors, f"{path}.block")
    _validate_optional_string_array(
        obj, "require_confirmation", errors, f"{path}.require_confirmation"
    )
    _validate_optional_enum(obj, "default", errors, f"{path}.default", DEFAULT_ACTIONS)
    _validate_optional_int(obj, "max_args_size", errors, f"{path}.max_args_size", min_value=1)


def _validate_origin_egress(obj: dict[str, Any], errors: list[str], path: str) -> None:
    """Tri-state egress overlay on an origin profile (origins spec 4)."""
    _reject_unknown_keys(obj, ORIGIN_EGRESS_OVERLAY_KEYS, errors, path)
    _validate_optional_string_array(obj, "allow", errors, f"{path}.allow")
    _validate_optional_string_array(obj, "block", errors, f"{path}.block")
    _validate_optional_enum(obj, "default", errors, f"{path}.default", DEFAULT_ACTIONS)


def _validate_detection(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, DETECTION_KEYS, errors, path)

    _validate_optional_object(
        obj, "prompt_injection", errors, path, _validate_detection_prompt,
    )
    _validate_optional_object(
        obj, "jailbreak", errors, path, _validate_detection_jailbreak,
    )
    _validate_optional_object(
        obj, "threat_intel", errors, path, _validate_detection_threat_intel,
    )


def _validate_detection_prompt(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, PROMPT_INJECTION_KEYS, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_enum(obj, "warn_at_or_above", errors, f"{path}.warn_at_or_above", DETECTION_LEVELS)
    _validate_optional_enum(
        obj, "block_at_or_above", errors, f"{path}.block_at_or_above", DETECTION_LEVELS
    )
    _validate_optional_int(
        obj, "max_scan_bytes", errors, f"{path}.max_scan_bytes", min_value=1, code=ERROR_CONSTRAINT_VIOLATION
    )
    _validate_optional_object(
        obj, "heuristics", errors, path, _validate_detection_heuristics,
    )


def _validate_detection_heuristics(
    obj: dict[str, Any], errors: list[str], path: str
) -> None:
    """``prompt_injection.heuristics`` (detection spec 3.5.1).

    ``min_score`` is a floor on the normalized 0-100 score, so a value outside
    that range names no score the detector can produce and is rejected
    (detection spec 9).
    """
    _reject_unknown_keys(obj, PROMPT_INJECTION_HEURISTICS_KEYS, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    min_score = _validate_optional_int(
        obj, "min_score", errors, f"{path}.min_score", min_value=0
    )
    if min_score is not None and min_score > 100:
        errors.append(_constraint(f"{path}.min_score must be between 0 and 100"))


def _validate_detection_jailbreak(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, JAILBREAK_KEYS, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_int(
        obj, "block_threshold", errors, f"{path}.block_threshold",
        min_value=0, max_value=100, code=ERROR_CONSTRAINT_VIOLATION,
    )
    _validate_optional_int(
        obj, "warn_threshold", errors, f"{path}.warn_threshold",
        min_value=0, max_value=100, code=ERROR_CONSTRAINT_VIOLATION,
    )
    _validate_optional_int(
        obj, "max_input_bytes", errors, f"{path}.max_input_bytes",
        min_value=1, code=ERROR_CONSTRAINT_VIOLATION,
    )


def _validate_detection_threat_intel(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, THREAT_INTEL_KEYS, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_string(obj, "pattern_db", errors, f"{path}.pattern_db")
    if "similarity_threshold" in obj:
        threshold = _validate_number_value(
            obj["similarity_threshold"], errors, f"{path}.similarity_threshold"
        )
        if threshold is not None and not 0.0 <= threshold <= 1.0:
            errors.append(
                _constraint(
                    f"{path}.similarity_threshold must be between 0.0 and 1.0"
                )
            )
    _validate_optional_int(
        obj, "top_k", errors, f"{path}.top_k", min_value=1, code=ERROR_CONSTRAINT_VIOLATION
    )


def _validate_optional_object(
    obj: dict[str, Any],
    key: str,
    errors: list[str],
    base_path: str,
    validator: Callable[[dict[str, Any], list[str], str], None],
) -> None:
    if key not in obj:
        return
    value = obj[key]
    path = f"{base_path}.{key}"
    if not isinstance(value, dict):
        errors.append(f"{path}: invalid type, expected an object")
        return
    validator(value, errors, path)


def _validate_required_string(
    obj: dict[str, Any], key: str, errors: list[str], missing_message: str
) -> str | None:
    if key not in obj or not isinstance(obj[key], str):
        errors.append(missing_message)
        return None
    return obj[key]


def _validate_required_enum(
    obj: dict[str, Any], key: str, errors: list[str], path: str, allowed: set[str]
) -> str | None:
    if key not in obj:
        errors.append(f"{path} is required")
        return None
    return _validate_enum_value(obj[key], errors, path, allowed)


def _validate_optional_string(
    obj: dict[str, Any], key: str, errors: list[str], path: str
) -> str | None:
    if key not in obj:
        return None
    return _validate_string_value(obj[key], errors, path)


def _validate_optional_bool(
    obj: dict[str, Any], key: str, errors: list[str], path: str
) -> bool | None:
    if key not in obj:
        return None
    value = obj[key]
    if not isinstance(value, bool):
        errors.append(f"{path}: invalid type, expected a boolean")
        return None
    return value


def _validate_constraint_enum(
    obj: dict[str, Any], key: str, errors: list[str], path: str, allowed: set[str]
) -> str | None:
    """An enum the model carries as a free string and `validate` checks (E004).

    Its diagnostic names the offending value rather than a missing variant,
    because nothing failed to deserialize: the document parsed, and the value
    is outside the set the module defines.
    """
    if key not in obj:
        return None
    value = obj[key]
    if not isinstance(value, str):
        errors.append(f"{path}: invalid type, expected a string")
        return None
    if value not in allowed:
        errors.append(_constraint(f"{path} '{value}' is not valid"))
        return None
    return value


def _validate_optional_enum(
    obj: dict[str, Any],
    key: str,
    errors: list[str],
    path: str,
    allowed: set[str],
    code: str = ERROR_PARSE,
) -> str | None:
    if key not in obj:
        return None
    return _validate_enum_value(obj[key], errors, path, allowed, code=code)


def _validate_optional_int(
    obj: dict[str, Any],
    key: str,
    errors: list[str],
    path: str,
    min_value: int | None = None,
    max_value: int | None = None,
    code: str = ERROR_PARSE,
) -> int | None:
    if key not in obj:
        return None
    return _validate_int_value(
        obj[key], errors, path, min_value=min_value, max_value=max_value, code=code
    )


def _validate_optional_number(
    obj: dict[str, Any],
    key: str,
    errors: list[str],
    path: str,
    min_value: float | None = None,
    max_value: float | None = None,
    min_exclusive: float | None = None,
    code: str = ERROR_PARSE,
) -> float | None:
    if key not in obj:
        return None
    return _validate_number_value(
        obj[key],
        errors,
        path,
        min_value=min_value,
        max_value=max_value,
        min_exclusive=min_exclusive,
        code=code,
    )


def _validate_optional_string_array(
    obj: dict[str, Any], key: str, errors: list[str], path: str
) -> list[str] | None:
    if key not in obj:
        return None
    value = obj[key]
    if not isinstance(value, list):
        errors.append(f"{path}: invalid type, expected an array")
        return None
    items: list[str] = []
    for index, item in enumerate(value):
        string_value = _validate_string_value(item, errors, f"{path}[{index}]")
        if string_value is not None:
            items.append(string_value)
    return items


def _validate_string_value(value: Any, errors: list[str], path: str) -> str | None:
    if not isinstance(value, str):
        errors.append(f"{path}: invalid type, expected a string")
        return None
    return value


def _reject_empty_match_string(
    obj: dict[str, Any], key: str, path: str, errors: list[str]
) -> None:
    """Reject a present free-text origin-match field whose value is the empty
    string. An absent field is untouched -- an all-absent match still matches
    every origin. Type errors are reported separately by
    `_validate_optional_string`, so a non-string value here is ignored."""
    value = obj.get(key)
    if isinstance(value, str) and value == "":
        errors.append(f"{path} must not be empty")


def _validate_enum_value(
    value: Any, errors: list[str], path: str, allowed: set[str], code: str = ERROR_PARSE
) -> str | None:
    if not isinstance(value, str):
        # A value of the wrong type is a parse refusal whatever the field is.
        errors.append(f"{path}: invalid type, expected a string")
        return None
    if value not in allowed:
        errors.append(
            ErrorMessage(
                f"{path}: unknown variant `{value}`, "
                f"expected one of: {', '.join(sorted(allowed))}",
                code,
            )
        )
        return None
    return value


def _validate_int_value(
    value: Any,
    errors: list[str],
    path: str,
    min_value: int | None = None,
    max_value: int | None = None,
    code: str = ERROR_PARSE,
) -> int | None:
    if not isinstance(value, int) or isinstance(value, bool):
        errors.append(f"{path}: invalid type, expected an integer")
        return None
    if min_value is not None and value < min_value:
        errors.append(ErrorMessage(f"{path} must be >= {min_value}", code))
        return None
    if max_value is not None and value > max_value:
        errors.append(ErrorMessage(f"{path} must be <= {max_value}", code))
        return None
    return value


def _validate_number_value(
    value: Any,
    errors: list[str],
    path: str,
    min_value: float | None = None,
    max_value: float | None = None,
    min_exclusive: float | None = None,
    code: str = ERROR_PARSE,
) -> float | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        errors.append(f"{path}: invalid type, expected a number")
        return None
    value = float(value)
    if not math.isfinite(value):
        errors.append(ErrorMessage(f"{path} must be a finite number", code))
        return None
    if min_value is not None and value < min_value:
        errors.append(ErrorMessage(f"{path} must be >= {min_value}", code))
        return None
    if max_value is not None and value > max_value:
        errors.append(ErrorMessage(f"{path} must be <= {max_value}", code))
        return None
    if min_exclusive is not None and value <= min_exclusive:
        errors.append(ErrorMessage(f"{path} must be > {min_exclusive}", code))
        return None
    return value


def _validate_regex(pattern: str, errors: list[str], path: str) -> None:
    def reject(message: str) -> None:
        errors.append(
            ErrorMessage(
                f"{path} must be a valid regular expression: {message}",
                ERROR_INVALID_REGEX,
            )
        )

    # Portability pre-check and the nested-quantifier (ReDoS) heuristic first.
    # These are hushspec.validate's own scanners, so what parse() refuses and
    # what validate() refuses cannot drift apart.
    feature = _disallowed_regex_feature(pattern)
    if feature is not None:
        reject(feature)
        return
    if _has_nested_quantifier(pattern):
        reject(NESTED_QUANTIFIER_MESSAGE)
        return

    # Everything else goes through compile_profile_regex, which repeats those
    # checks, refuses the rest of the non-RE2 syntax (lookaround,
    # backreferences, atomic and recursive groups) and then applies the
    # HushSpec regex profile (ASCII shorthands, leading-only inline flags,
    # portable escapes) before compiling. It is the exact call the evaluator
    # makes, so parse() rejects precisely the patterns evaluation would deny on.
    try:
        compile_profile_regex(pattern)
    except ValueError as exc:
        reject(str(exc))


# Nested-quantifier (catastrophic backtracking / ReDoS) heuristic.
# Kept identical to hushspec/validate.py and the other SDKs: reject a group whose
# body contains an unbounded quantifier (``*``, ``+``, ``{n,}``) when the group is
# itself immediately followed by an unbounded quantifier (e.g. ``(a+)+``).
# Escaped parens and character-class contents are ignored; bounded quantifiers
# (``(a{1,3}){1,3}``, ``(abc)+``) are accepted.
def _reject_unknown_keys(
    obj: dict[str, Any], allowed: frozenset[str] | set[str], errors: list[str], path: str
) -> None:
    for key in obj:
        if not isinstance(key, str):
            errors.append(f"{path} contains a non-string field name")
            continue
        if key not in allowed:
            errors.append(f"unknown field `{key}` at {path}")
