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
 * Merge a base HushSpec with a child according to the child's merge strategy.
 *
 * Returns a new HushSpec combining base and child fields.
 * Does not modify either input.
 */
export function merge(base: HushSpec, child: HushSpec): HushSpec {
  const strategy: MergeStrategy = child.merge_strategy ?? 'deep_merge';

  switch (strategy) {
    case 'replace':
      return { ...child, extends: undefined };
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
    };
  } else if (base.rules) {
    mergedRules = { ...base.rules };
  }

  return {
    hushspec: child.hushspec,
    name: child.name ?? base.name,
    description: child.description ?? base.description,
    extends: undefined,
    merge_strategy: child.merge_strategy,
    rules: mergedRules,
    extensions: deep
      ? mergeExtensionsDeep(base.extensions, child.extensions)
      : mergeExtensionsMerge(base.extensions, child.extensions),
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
    prompt_injection: mergeObject(base.prompt_injection, child.prompt_injection),
    jailbreak: mergeObject(base.jailbreak, child.jailbreak),
    threat_intel: mergeObject(base.threat_intel, child.threat_intel),
  };
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
