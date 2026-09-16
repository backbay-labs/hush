import type { HushSpec, MergeStrategy } from './schema.js';
import type { Rules } from './rules.js';
import type {
  DetectionExtension,
  Extensions,
  JailbreakDetection,
  OriginsExtension,
  PostureExtension,
  PromptInjectionDetection,
  ThreatIntelDetection,
} from './extensions.js';

/**
 * Fold a base and a child overlay into one resolved document (Core section
 * 2.3).
 *
 * `extends` and `merge_strategy` are resolution instructions, not policy: the
 * merge consumes both, so the document that comes back declares neither, under
 * every strategy. `canonicalJson` drops `merge_strategy` and refuses `extends`
 * anyway, so dropping them here moves no hash.
 *
 * Top-level `metadata` is replaced wholesale, never field-merged: a child that
 * declares `metadata` supplies the entire object (the base's `approved_by`,
 * `controls` and the rest are gone even if the child restates none of them),
 * and a child that declares none inherits the base's object unchanged. This
 * holds under `merge` and `deep_merge` alike -- deep merging descends into
 * `extensions`, not into governance metadata, because a half-inherited
 * approval record would attest to something no one approved.
 */
export function merge(base: HushSpec, child: HushSpec): HushSpec {
  const strategy: MergeStrategy = child.merge_strategy ?? 'deep_merge';

  switch (strategy) {
    case 'replace':
      return { ...child, extends: undefined, merge_strategy: undefined };
    case 'merge':
      return mergeWithStrategy(base, child, false);
    case 'deep_merge':
      return mergeWithStrategy(base, child, true);
  }
}

function mergeWithStrategy(base: HushSpec, child: HushSpec, deep: boolean): HushSpec {
  const baseRules = base.rules ?? {};
  const childRules = child.rules;

  let mergedRules: Rules | undefined;
  if (childRules) {
    mergedRules = {
      forbidden_paths: childRules.forbidden_paths ?? baseRules.forbidden_paths,
      path_allowlist: childRules.path_allowlist ?? baseRules.path_allowlist,
      egress: childRules.egress ?? baseRules.egress,
      secret_patterns: childRules.secret_patterns ?? baseRules.secret_patterns,
      patch_integrity: childRules.patch_integrity ?? baseRules.patch_integrity,
      shell_commands: childRules.shell_commands ?? baseRules.shell_commands,
      tool_access: childRules.tool_access ?? baseRules.tool_access,
      computer_use: childRules.computer_use ?? baseRules.computer_use,
      remote_desktop_channels: childRules.remote_desktop_channels ?? baseRules.remote_desktop_channels,
      input_injection: childRules.input_injection ?? baseRules.input_injection,
      browser_automation: childRules.browser_automation ?? baseRules.browser_automation,
      code_execution: childRules.code_execution ?? baseRules.code_execution,
    };
  } else if (base.rules) {
    mergedRules = { ...base.rules };
  }

  return {
    hushspec: child.hushspec,
    name: child.name ?? base.name,
    description: child.description ?? base.description,
    extends: undefined,
    merge_strategy: undefined,
    rules: mergedRules,
    extensions: deep
      ? mergeExtensionsDeep(base.extensions, child.extensions)
      : mergeExtensionsMerge(base.extensions, child.extensions),
    // Whole-object replacement, not a field merge: see `merge`. The
    // `replace` strategy above already carries the child's through its spread.
    metadata: child.metadata ?? base.metadata,
  };
}

function mergeExtensionsMerge(
  base: Extensions | undefined,
  child: Extensions | undefined,
): Extensions | undefined {
  if (!child) {
    return base ? { ...base } : undefined;
  }
  if (!base) {
    return { ...child };
  }

  return {
    posture: child.posture ?? base.posture,
    origins: child.origins ?? base.origins,
    detection: child.detection ?? base.detection,
  };
}

function mergeExtensionsDeep(
  base: Extensions | undefined,
  child: Extensions | undefined,
): Extensions | undefined {
  if (!child) {
    return base ? { ...base } : undefined;
  }
  if (!base) {
    return { ...child };
  }

  return {
    posture: mergePosture(base.posture, child.posture),
    origins: mergeOrigins(base.origins, child.origins),
    detection: mergeDetection(base.detection, child.detection),
  };
}

function mergePosture(
  base: PostureExtension | undefined,
  child: PostureExtension | undefined,
): PostureExtension | undefined {
  if (!child) return base;
  if (!base) return child;

  return {
    initial: child.initial,
    states: {
      ...base.states,
      ...child.states,
    },
    transitions: child.transitions,
  };
}

function mergeOrigins(
  base: OriginsExtension | undefined,
  child: OriginsExtension | undefined,
): OriginsExtension | undefined {
  if (!child) return base;
  if (!base) return child;

  const mergedProfiles = [...(base.profiles ?? [])];
  for (const childProfile of child.profiles ?? []) {
    const idx = mergedProfiles.findIndex(p => p.id === childProfile.id);
    if (idx >= 0) {
      mergedProfiles[idx] = childProfile;
    } else {
      mergedProfiles.push(childProfile);
    }
  }
  return {
    default_behavior: child.default_behavior ?? base.default_behavior,
    profiles: mergedProfiles,
  };
}

function mergeDetection(
  base: DetectionExtension | undefined,
  child: DetectionExtension | undefined,
): DetectionExtension | undefined {
  if (!child) return base;
  if (!base) return child;

  return {
    prompt_injection: mergePromptInjection(base.prompt_injection, child.prompt_injection),
    jailbreak: mergeObject(base.jailbreak, child.jailbreak),
    threat_intel: mergeObject(base.threat_intel, child.threat_intel),
  };
}

/**
 * `prompt_injection`, whose `heuristics` is itself merged field by field
 * (detection spec 8.1): a child that sets only `min_score` keeps the base's
 * `enabled` rather than replacing the whole block.
 */
function mergePromptInjection(
  base: PromptInjectionDetection | undefined,
  child: PromptInjectionDetection | undefined,
): PromptInjectionDetection | undefined {
  const merged = mergeObject(base, child);
  if (merged === undefined) return undefined;
  const baseHeuristics = base?.heuristics;
  const childHeuristics = child?.heuristics;
  if (baseHeuristics === undefined || childHeuristics === undefined) return merged;
  return { ...merged, heuristics: { ...baseHeuristics, ...childHeuristics } };
}

function mergeObject<T extends PromptInjectionDetection | JailbreakDetection | ThreatIntelDetection>(
  base: T | undefined,
  child: T | undefined,
): T | undefined {
  if (!child) return base;
  if (!base) return child;
  return {
    ...base,
    ...child,
  };
}
