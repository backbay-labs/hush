from __future__ import annotations

import re
from typing import Any, Callable

from hushspec.generated_contract import (
    BRIDGE_POLICY_KEYS,
    BRIDGE_TARGET_KEYS,
    COMPUTER_USE_KEYS,
    COMPUTER_USE_MODES,
    DEFAULT_ACTIONS,
    DETECTION_KEYS,
    DETECTION_LEVELS,
    EGRESS_KEYS,
    EXTENSION_KEYS,
    FORBIDDEN_PATH_KEYS,
    INPUT_INJECTION_KEYS,
    JAILBREAK_KEYS,
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

DURATION_PATTERN = re.compile(r"^\d+[smhd]$")


def validate_raw_document(doc: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(doc, dict):
        errors.append("HushSpec document must be a YAML mapping")
        return errors

    _validate_top_level(doc, errors)
    return errors


def _validate_top_level(obj: dict[str, Any], errors: list[str]) -> None:
    _reject_unknown_keys(obj, TOP_LEVEL_KEYS, errors, "top-level field")

    _validate_required_string(obj, "hushspec", errors, 'missing or invalid "hushspec" version field')
    _validate_optional_string(obj, "name", errors, "name")
    _validate_optional_string(obj, "description", errors, "description")
    _validate_optional_string(obj, "extends", errors, "extends")
    _validate_optional_enum(
        obj, "merge_strategy", errors, "merge_strategy", {"replace", "merge", "deep_merge"}
    )

    if "rules" in obj:
        if not isinstance(obj["rules"], dict):
            errors.append("rules must be an object")
        else:
            _validate_rules(obj["rules"], errors)

    if "extensions" in obj:
        if not isinstance(obj["extensions"], dict):
            errors.append("extensions must be an object")
        else:
            _validate_extensions(obj["extensions"], errors)


def _validate_rules(obj: dict[str, Any], errors: list[str]) -> None:
    _reject_unknown_keys(obj, RULE_KEYS, errors, "rule")
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


def _validate_forbidden_paths(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, FORBIDDEN_PATH_KEYS, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_string_array(obj, "patterns", errors, f"{path}.patterns")
    _validate_optional_string_array(obj, "exceptions", errors, f"{path}.exceptions")


def _validate_path_allowlist(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, PATH_ALLOWLIST_KEYS, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_string_array(obj, "read", errors, f"{path}.read")
    _validate_optional_string_array(obj, "write", errors, f"{path}.write")
    _validate_optional_string_array(obj, "patch", errors, f"{path}.patch")


def _validate_egress(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, EGRESS_KEYS, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_string_array(obj, "allow", errors, f"{path}.allow")
    _validate_optional_string_array(obj, "block", errors, f"{path}.block")
    _validate_optional_enum(obj, "default", errors, f"{path}.default", DEFAULT_ACTIONS)


def _validate_secret_patterns(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, SECRET_PATTERNS_KEYS, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_string_array(obj, "skip_paths", errors, f"{path}.skip_paths")

    if "patterns" not in obj:
        return
    patterns = obj["patterns"]
    if not isinstance(patterns, list):
        errors.append(f"{path}.patterns must be an array")
        return

    seen: set[str] = set()
    for index, pattern in enumerate(patterns):
        item_path = f"{path}.patterns[{index}]"
        if not isinstance(pattern, dict):
            errors.append(f"{item_path} must be an object")
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
                errors.append(f"duplicate secret pattern name: {name}")
            seen.add(name)
        if regex is not None:
            _validate_regex(regex, errors, f"{item_path}.pattern")


def _validate_patch_integrity(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, PATCH_INTEGRITY_KEYS, errors, path)
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
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    patterns = _validate_optional_string_array(
        obj, "forbidden_patterns", errors, f"{path}.forbidden_patterns"
    )
    if patterns is not None:
        for index, pattern in enumerate(patterns):
            _validate_regex(pattern, errors, f"{path}.forbidden_patterns[{index}]")


def _validate_tool_access(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, TOOL_ACCESS_KEYS, errors, path)
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
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_enum(obj, "mode", errors, f"{path}.mode", COMPUTER_USE_MODES)
    _validate_optional_string_array(obj, "allowed_actions", errors, f"{path}.allowed_actions")


def _validate_remote_desktop_channels(
    obj: dict[str, Any], errors: list[str], path: str
) -> None:
    _reject_unknown_keys(obj, REMOTE_DESKTOP_KEYS, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_bool(obj, "clipboard", errors, f"{path}.clipboard")
    _validate_optional_bool(obj, "file_transfer", errors, f"{path}.file_transfer")
    _validate_optional_bool(obj, "audio", errors, f"{path}.audio")
    _validate_optional_bool(obj, "drive_mapping", errors, f"{path}.drive_mapping")


def _validate_input_injection(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, INPUT_INJECTION_KEYS, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_string_array(obj, "allowed_types", errors, f"{path}.allowed_types")
    _validate_optional_bool(
        obj, "require_postcondition_probe", errors, f"{path}.require_postcondition_probe"
    )


def _validate_extensions(obj: dict[str, Any], errors: list[str]) -> None:
    _reject_unknown_keys(obj, EXTENSION_KEYS, errors, "extension")
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
        errors.append(f"{path}.states must be an object")
        states = None
    transitions = obj.get("transitions")
    if not isinstance(transitions, list):
        errors.append(f"{path}.transitions must be an array")
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
                errors.append(f"{state_path} must be an object")
                continue
            _reject_unknown_keys(state, POSTURE_STATE_KEYS, errors, state_path)
            _validate_optional_string(state, "description", errors, f"{state_path}.description")
            _validate_optional_string_array(state, "capabilities", errors, f"{state_path}.capabilities")
            if "budgets" in state:
                if not isinstance(state["budgets"], dict):
                    errors.append(f"{state_path}.budgets must be an object")
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
        errors.append(f"posture.initial '{initial}' does not reference a defined state")

    if transitions is not None:
        for index, transition in enumerate(transitions):
            transition_path = f"{path}.transitions[{index}]"
            if not isinstance(transition, dict):
                errors.append(f"{transition_path} must be an object")
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
                    f"posture.transitions[{index}].from '{from_state}' does not reference a defined state"
                )
            if to_state == "*":
                errors.append(f"posture.transitions[{index}].to cannot be '*'")
            elif to_state is not None and to_state not in state_names:
                errors.append(
                    f"posture.transitions[{index}].to '{to_state}' does not reference a defined state"
                )

            if on == "timeout":
                if after is None:
                    errors.append(
                        f"posture.transitions[{index}]: timeout trigger requires 'after' field"
                    )
                elif not DURATION_PATTERN.match(after):
                    errors.append(f"{transition_path}.after must match ^\\d+[smhd]$")
            elif after is not None and not DURATION_PATTERN.match(after):
                errors.append(f"{transition_path}.after must match ^\\d+[smhd]$")


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
        errors.append(f"{path}.profiles must be an array")
        return

    profile_ids: set[str] = set()
    for index, profile in enumerate(profiles):
        profile_path = f"{path}.profiles[{index}]"
        if not isinstance(profile, dict):
            errors.append(f"{profile_path} must be an object")
            continue
        _reject_unknown_keys(profile, ORIGIN_PROFILE_KEYS, errors, profile_path)
        profile_id = _validate_required_string(profile, "id", errors, f"{profile_path}.id is required")
        if profile_id is not None:
            if profile_id in profile_ids:
                errors.append(f"duplicate origin profile id: '{profile_id}'")
            profile_ids.add(profile_id)

        if "match" in profile:
            match = profile["match"]
            if not isinstance(match, dict):
                errors.append(f"{profile_path}.match must be an object")
            else:
                _reject_unknown_keys(match, ORIGIN_MATCH_KEYS, errors, f"{profile_path}.match")
                _validate_optional_string(match, "provider", errors, f"{profile_path}.match.provider")
                _validate_optional_string(match, "tenant_id", errors, f"{profile_path}.match.tenant_id")
                _validate_optional_string(match, "space_id", errors, f"{profile_path}.match.space_id")
                _validate_optional_enum(
                    match,
                    "space_type",
                    errors,
                    f"{profile_path}.match.space_type",
                    ORIGIN_SPACE_TYPES,
                )
                _validate_optional_enum(
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

        posture = _validate_optional_string(profile, "posture", errors, f"{profile_path}.posture")
        if posture is not None:
            if posture_states is None:
                errors.append(f"{profile_path}.posture requires extensions.posture to be defined")
            elif posture not in posture_states:
                errors.append(f"{profile_path}.posture '{posture}' does not reference a defined posture state")

        _validate_optional_object(profile, "tool_access", errors, profile_path, _validate_tool_access)
        _validate_optional_object(profile, "egress", errors, profile_path, _validate_egress)

        if "data" in profile:
            data = profile["data"]
            if not isinstance(data, dict):
                errors.append(f"{profile_path}.data must be an object")
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
                errors.append(f"{profile_path}.budgets must be an object")
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
                errors.append(f"{profile_path}.bridge must be an object")
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
                        errors.append(f"{profile_path}.bridge.allowed_targets must be an array")
                    else:
                        for target_index, target in enumerate(targets):
                            target_path = f"{profile_path}.bridge.allowed_targets[{target_index}]"
                            if not isinstance(target, dict):
                                errors.append(f"{target_path} must be an object")
                                continue
                            _reject_unknown_keys(target, BRIDGE_TARGET_KEYS, errors, target_path)
                            _validate_optional_string(target, "provider", errors, f"{target_path}.provider")
                            _validate_optional_enum(
                                target,
                                "space_type",
                                errors,
                                f"{target_path}.space_type",
                                ORIGIN_SPACE_TYPES,
                            )
                            _validate_optional_string_array(target, "tags", errors, f"{target_path}.tags")
                            _validate_optional_enum(
                                target,
                                "visibility",
                                errors,
                                f"{target_path}.visibility",
                                ORIGIN_VISIBILITIES,
                            )

        _validate_optional_string(profile, "explanation", errors, f"{profile_path}.explanation")


def _validate_detection(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, DETECTION_KEYS, errors, path)

    _validate_optional_object(
        obj,
        "prompt_injection",
        errors,
        path,
        lambda section, errs, section_path: _validate_detection_prompt(section, errs, section_path),
    )
    _validate_optional_object(
        obj,
        "jailbreak",
        errors,
        path,
        lambda section, errs, section_path: _validate_detection_jailbreak(section, errs, section_path),
    )
    _validate_optional_object(
        obj,
        "threat_intel",
        errors,
        path,
        lambda section, errs, section_path: _validate_detection_threat_intel(section, errs, section_path),
    )


def _validate_detection_prompt(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, PROMPT_INJECTION_KEYS, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_enum(obj, "warn_at_or_above", errors, f"{path}.warn_at_or_above", DETECTION_LEVELS)
    _validate_optional_enum(
        obj, "block_at_or_above", errors, f"{path}.block_at_or_above", DETECTION_LEVELS
    )
    _validate_optional_int(obj, "max_scan_bytes", errors, f"{path}.max_scan_bytes", min_value=1)


def _validate_detection_jailbreak(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, JAILBREAK_KEYS, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_int(obj, "block_threshold", errors, f"{path}.block_threshold", min_value=0, max_value=100)
    _validate_optional_int(obj, "warn_threshold", errors, f"{path}.warn_threshold", min_value=0, max_value=100)
    _validate_optional_int(obj, "max_input_bytes", errors, f"{path}.max_input_bytes", min_value=1)


def _validate_detection_threat_intel(obj: dict[str, Any], errors: list[str], path: str) -> None:
    _reject_unknown_keys(obj, THREAT_INTEL_KEYS, errors, path)
    _validate_optional_bool(obj, "enabled", errors, f"{path}.enabled")
    _validate_optional_string(obj, "pattern_db", errors, f"{path}.pattern_db")
    _validate_optional_number(
        obj, "similarity_threshold", errors, f"{path}.similarity_threshold", min_value=0, max_value=1
    )
    _validate_optional_int(obj, "top_k", errors, f"{path}.top_k", min_value=1)


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
        errors.append(f"{path} must be an object")
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
        errors.append(f"{path} must be a boolean")
        return None
    return value


def _validate_optional_enum(
    obj: dict[str, Any], key: str, errors: list[str], path: str, allowed: set[str]
) -> str | None:
    if key not in obj:
        return None
    return _validate_enum_value(obj[key], errors, path, allowed)


def _validate_optional_int(
    obj: dict[str, Any],
    key: str,
    errors: list[str],
    path: str,
    min_value: int | None = None,
    max_value: int | None = None,
) -> int | None:
    if key not in obj:
        return None
    return _validate_int_value(obj[key], errors, path, min_value=min_value, max_value=max_value)


def _validate_optional_number(
    obj: dict[str, Any],
    key: str,
    errors: list[str],
    path: str,
    min_value: float | None = None,
    max_value: float | None = None,
    min_exclusive: float | None = None,
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
    )


def _validate_optional_string_array(
    obj: dict[str, Any], key: str, errors: list[str], path: str
) -> list[str] | None:
    if key not in obj:
        return None
    value = obj[key]
    if not isinstance(value, list):
        errors.append(f"{path} must be an array")
        return None
    items: list[str] = []
    for index, item in enumerate(value):
        string_value = _validate_string_value(item, errors, f"{path}[{index}]")
        if string_value is not None:
            items.append(string_value)
    return items


def _validate_string_value(value: Any, errors: list[str], path: str) -> str | None:
    if not isinstance(value, str):
        errors.append(f"{path} must be a string")
        return None
    return value


def _validate_enum_value(
    value: Any, errors: list[str], path: str, allowed: set[str]
) -> str | None:
    if not isinstance(value, str):
        errors.append(f"{path} must be a string")
        return None
    if value not in allowed:
        errors.append(f"{path} must be one of: {', '.join(sorted(allowed))}")
        return None
    return value


def _validate_int_value(
    value: Any,
    errors: list[str],
    path: str,
    min_value: int | None = None,
    max_value: int | None = None,
) -> int | None:
    if not isinstance(value, int) or isinstance(value, bool):
        errors.append(f"{path} must be an integer")
        return None
    if min_value is not None and value < min_value:
        errors.append(f"{path} must be >= {min_value}")
        return None
    if max_value is not None and value > max_value:
        errors.append(f"{path} must be <= {max_value}")
        return None
    return value


def _validate_number_value(
    value: Any,
    errors: list[str],
    path: str,
    min_value: float | None = None,
    max_value: float | None = None,
    min_exclusive: float | None = None,
) -> float | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        errors.append(f"{path} must be a number")
        return None
    value = float(value)
    if min_value is not None and value < min_value:
        errors.append(f"{path} must be >= {min_value}")
        return None
    if max_value is not None and value > max_value:
        errors.append(f"{path} must be <= {max_value}")
        return None
    if min_exclusive is not None and value <= min_exclusive:
        errors.append(f"{path} must be > {min_exclusive}")
        return None
    return value


def _validate_regex(pattern: str, errors: list[str], path: str) -> None:
    try:
        re.compile(pattern)
    except re.error as exc:
        errors.append(f"{path} must be a valid regular expression: {exc}")


def _reject_unknown_keys(
    obj: dict[str, Any], allowed: frozenset[str] | set[str], errors: list[str], path: str
) -> None:
    for key in obj.keys():
        if not isinstance(key, str):
            errors.append(f"{path} contains a non-string field name")
            continue
        if key not in allowed:
            if path == "top-level field":
                errors.append(f"unknown top-level field: {key}")
            elif path == "rule":
                errors.append(f"unknown rule: {key}")
            elif path == "extension":
                errors.append(f"unknown extension: {key}")
            else:
                errors.append(f"unknown field at {path}: {key}")
