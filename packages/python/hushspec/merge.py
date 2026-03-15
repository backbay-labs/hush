"""Merge HushSpec policies according to the child's merge strategy.

Ports the merge logic from Rust:
- replace: return child
- merge/deep_merge: child rules override base rules, base rules preserved
  when child doesn't define them
- Extensions: posture/detection deep-merge, origins merge by profile ID
"""

from __future__ import annotations

import copy
from typing import Optional

from hushspec.extensions import (
    DetectionExtension,
    Extensions,
    JailbreakDetection,
    OriginsExtension,
    PostureExtension,
    PromptInjectionDetection,
    ThreatIntelDetection,
)
from hushspec.rules import Rules
from hushspec.schema import HushSpec, MergeStrategy


def merge(base: HushSpec, child: HushSpec) -> HushSpec:
    """Merge a base HushSpec with a child according to the child's merge strategy."""
    strategy = child.merge_strategy or MergeStrategy.DEEP_MERGE
    if strategy == MergeStrategy.REPLACE:
        return copy.deepcopy(child)
    deep = strategy == MergeStrategy.DEEP_MERGE
    return _merge_with_strategy(base, child, deep)


def _merge_with_strategy(base: HushSpec, child: HushSpec, deep: bool) -> HushSpec:
    return HushSpec(
        hushspec=child.hushspec,
        name=child.name if child.name is not None else base.name,
        description=child.description if child.description is not None else base.description,
        extends=child.extends,
        merge_strategy=child.merge_strategy,
        rules=_merge_rules(base.rules, child.rules),
        extensions=(
            _merge_extensions_deep(base.extensions, child.extensions)
            if deep
            else _merge_extensions_merge(base.extensions, child.extensions)
        ),
    )


def _merge_rules(base: Optional[Rules], child: Optional[Rules]) -> Optional[Rules]:
    if child is not None:
        base_rules = base if base is not None else Rules()
        return Rules(
            forbidden_paths=(
                copy.deepcopy(child.forbidden_paths)
                if child.forbidden_paths is not None
                else copy.deepcopy(base_rules.forbidden_paths)
            ),
            path_allowlist=(
                copy.deepcopy(child.path_allowlist)
                if child.path_allowlist is not None
                else copy.deepcopy(base_rules.path_allowlist)
            ),
            egress=(
                copy.deepcopy(child.egress)
                if child.egress is not None
                else copy.deepcopy(base_rules.egress)
            ),
            secret_patterns=(
                copy.deepcopy(child.secret_patterns)
                if child.secret_patterns is not None
                else copy.deepcopy(base_rules.secret_patterns)
            ),
            patch_integrity=(
                copy.deepcopy(child.patch_integrity)
                if child.patch_integrity is not None
                else copy.deepcopy(base_rules.patch_integrity)
            ),
            shell_commands=(
                copy.deepcopy(child.shell_commands)
                if child.shell_commands is not None
                else copy.deepcopy(base_rules.shell_commands)
            ),
            tool_access=(
                copy.deepcopy(child.tool_access)
                if child.tool_access is not None
                else copy.deepcopy(base_rules.tool_access)
            ),
            computer_use=(
                copy.deepcopy(child.computer_use)
                if child.computer_use is not None
                else copy.deepcopy(base_rules.computer_use)
            ),
            remote_desktop_channels=(
                copy.deepcopy(child.remote_desktop_channels)
                if child.remote_desktop_channels is not None
                else copy.deepcopy(base_rules.remote_desktop_channels)
            ),
            input_injection=(
                copy.deepcopy(child.input_injection)
                if child.input_injection is not None
                else copy.deepcopy(base_rules.input_injection)
            ),
        )
    elif base is not None:
        return copy.deepcopy(base)
    else:
        return None


def _merge_extensions_merge(
    base: Optional[Extensions], child: Optional[Extensions]
) -> Optional[Extensions]:
    if child is not None:
        base_ext = base if base is not None else Extensions()
        return Extensions(
            posture=(
                copy.deepcopy(child.posture)
                if child.posture is not None
                else copy.deepcopy(base_ext.posture)
            ),
            origins=(
                copy.deepcopy(child.origins)
                if child.origins is not None
                else copy.deepcopy(base_ext.origins)
            ),
            detection=(
                copy.deepcopy(child.detection)
                if child.detection is not None
                else copy.deepcopy(base_ext.detection)
            ),
        )
    elif base is not None:
        return copy.deepcopy(base)
    else:
        return None


def _merge_extensions_deep(
    base: Optional[Extensions], child: Optional[Extensions]
) -> Optional[Extensions]:
    if child is not None:
        base_ext = base if base is not None else Extensions()
        return Extensions(
            posture=_merge_posture(base_ext.posture, child.posture),
            origins=_merge_origins(base_ext.origins, child.origins),
            detection=_merge_detection(base_ext.detection, child.detection),
        )
    elif base is not None:
        return copy.deepcopy(base)
    else:
        return None


def _merge_posture(
    base: Optional[PostureExtension], child: Optional[PostureExtension]
) -> Optional[PostureExtension]:
    if child is not None:
        if base is not None:
            states = copy.deepcopy(base.states)
            for name, state in child.states.items():
                states[name] = copy.deepcopy(state)
            return PostureExtension(
                initial=child.initial,
                states=states,
                transitions=copy.deepcopy(child.transitions),
            )
        else:
            return copy.deepcopy(child)
    elif base is not None:
        return copy.deepcopy(base)
    else:
        return None


def _merge_origins(
    base: Optional[OriginsExtension], child: Optional[OriginsExtension]
) -> Optional[OriginsExtension]:
    if child is not None:
        if base is not None:
            merged_profiles = copy.deepcopy(base.profiles)
            for child_profile in child.profiles:
                found = False
                for i, existing in enumerate(merged_profiles):
                    if existing.id == child_profile.id:
                        merged_profiles[i] = copy.deepcopy(child_profile)
                        found = True
                        break
                if not found:
                    merged_profiles.append(copy.deepcopy(child_profile))
            return OriginsExtension(
                default_behavior=(
                    child.default_behavior
                    if child.default_behavior is not None
                    else base.default_behavior
                ),
                profiles=merged_profiles,
            )
        else:
            return copy.deepcopy(child)
    elif base is not None:
        return copy.deepcopy(base)
    else:
        return None


def _merge_detection(
    base: Optional[DetectionExtension], child: Optional[DetectionExtension]
) -> Optional[DetectionExtension]:
    if child is not None:
        if base is not None:
            return DetectionExtension(
                prompt_injection=_merge_prompt_injection(
                    base.prompt_injection, child.prompt_injection
                ),
                jailbreak=_merge_jailbreak(base.jailbreak, child.jailbreak),
                threat_intel=_merge_threat_intel(base.threat_intel, child.threat_intel),
            )
        else:
            return copy.deepcopy(child)
    elif base is not None:
        return copy.deepcopy(base)
    else:
        return None


def _merge_prompt_injection(
    base: Optional[PromptInjectionDetection],
    child: Optional[PromptInjectionDetection],
) -> Optional[PromptInjectionDetection]:
    if child is not None:
        if base is not None:
            return PromptInjectionDetection(
                enabled=child.enabled if child.enabled is not None else base.enabled,
                warn_at_or_above=(
                    child.warn_at_or_above
                    if child.warn_at_or_above is not None
                    else base.warn_at_or_above
                ),
                block_at_or_above=(
                    child.block_at_or_above
                    if child.block_at_or_above is not None
                    else base.block_at_or_above
                ),
                max_scan_bytes=(
                    child.max_scan_bytes
                    if child.max_scan_bytes is not None
                    else base.max_scan_bytes
                ),
            )
        else:
            return copy.deepcopy(child)
    elif base is not None:
        return copy.deepcopy(base)
    else:
        return None


def _merge_jailbreak(
    base: Optional[JailbreakDetection],
    child: Optional[JailbreakDetection],
) -> Optional[JailbreakDetection]:
    if child is not None:
        if base is not None:
            return JailbreakDetection(
                enabled=child.enabled if child.enabled is not None else base.enabled,
                block_threshold=(
                    child.block_threshold
                    if child.block_threshold is not None
                    else base.block_threshold
                ),
                warn_threshold=(
                    child.warn_threshold
                    if child.warn_threshold is not None
                    else base.warn_threshold
                ),
                max_input_bytes=(
                    child.max_input_bytes
                    if child.max_input_bytes is not None
                    else base.max_input_bytes
                ),
            )
        else:
            return copy.deepcopy(child)
    elif base is not None:
        return copy.deepcopy(base)
    else:
        return None


def _merge_threat_intel(
    base: Optional[ThreatIntelDetection],
    child: Optional[ThreatIntelDetection],
) -> Optional[ThreatIntelDetection]:
    if child is not None:
        if base is not None:
            return ThreatIntelDetection(
                enabled=child.enabled if child.enabled is not None else base.enabled,
                pattern_db=(
                    child.pattern_db
                    if child.pattern_db is not None
                    else base.pattern_db
                ),
                similarity_threshold=(
                    child.similarity_threshold
                    if child.similarity_threshold is not None
                    else base.similarity_threshold
                ),
                top_k=child.top_k if child.top_k is not None else base.top_k,
            )
        else:
            return copy.deepcopy(child)
    elif base is not None:
        return copy.deepcopy(base)
    else:
        return None
