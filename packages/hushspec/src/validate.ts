import type { HushSpec } from './schema.js';
import {
  BRIDGE_POLICY_KEYS_SET,
  BROWSER_AUTOMATION_KEYS_SET,
  CODE_EXECUTION_KEYS_SET,
  CONDITION_KEYS_SET,
  ORIGIN_EGRESS_OVERLAY_KEYS_SET,
  ORIGIN_TOOL_ACCESS_OVERLAY_KEYS_SET,
  TIME_WINDOW_KEYS_SET,
  BRIDGE_TARGET_KEYS_SET,
  CLASSIFICATIONS_SET,
  COMPUTER_USE_KEYS_SET,
  COMPUTER_USE_MODES_SET,
  CHANGELOG_ENTRY_KEYS_SET,
  CONTROL_MAPPING_KEYS_SET,
  DEFAULT_ACTIONS_SET,
  DETECTION_KEYS_SET,
  DETECTION_LEVELS_SET,
  EGRESS_KEYS_SET,
  EXTENSION_KEYS_SET,
  FORBIDDEN_PATH_KEYS_SET,
  GOVERNANCE_METADATA_KEYS_SET,
  INPUT_INJECTION_KEYS_SET,
  JAILBREAK_KEYS_SET,
  LIFECYCLE_STATES_SET,
  MERGE_STRATEGIES_SET,
  ORIGINS_KEYS_SET,
  ORIGIN_BUDGET_KEYS_SET,
  ORIGIN_DATA_KEYS_SET,
  ORIGIN_DEFAULT_BEHAVIORS_SET,
  ORIGIN_MATCH_KEYS_SET,
  ORIGIN_PROFILE_KEYS_SET,
  ORIGIN_SPACE_TYPES_SET,
  ORIGIN_VISIBILITIES_SET,
  PATH_ALLOWLIST_KEYS_SET,
  PATCH_INTEGRITY_KEYS_SET,
  POSTURE_KEYS_SET,
  POSTURE_STATE_KEYS_SET,
  POSTURE_TRANSITION_KEYS_SET,
  PROMPT_INJECTION_KEYS_SET,
  REMOTE_DESKTOP_KEYS_SET,
  RULE_KEYS_SET,
  SECRET_PATTERNS_KEYS_SET,
  SECRET_PATTERN_KEYS_SET,
  SEVERITIES_SET,
  SHELL_COMMAND_KEYS_SET,
  THREAT_INTEL_KEYS_SET,
  TOOL_ACCESS_KEYS_SET,
  TOP_LEVEL_KEYS_SET,
  TRANSITION_TRIGGERS_SET,
} from './generated/contract.js';
import { compileProfileRegex, isSafeRegex } from './regex.js';
import { HUSHSPEC_SUPPORTED_MINORS, isSupported } from './version.js';
import type { Condition } from './conditions.js';
import { MAX_NESTING_DEPTH, validateCondition } from './conditions.js';

export { isSafeRegex };

export interface ValidationError {
  code: string;
  message: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: string[];
}

type UnknownRecord = Record<string, unknown>;

/**
 * Whether `key` is present on `obj` *with a value*.
 *
 * `key in obj` alone counts `{ extends: undefined }` as present. In
 * TypeScript an optional property explicitly set to `undefined` is
 * indistinguishable from an absent one -- and setting it is exactly what
 * `merge()` (and therefore `resolve()`) does for the fields it clears, while
 * the Rust, Python and Go SDKs drop those fields outright. Treating
 * `undefined` as present made a resolved document valid in three SDKs and
 * invalid in this one ("extends must be a string"). YAML never yields
 * `undefined` -- an empty scalar parses as `null`, which still reaches the
 * type checks below -- so this only forgives the in-memory spelling.
 */
function hasValue(obj: unknown, key: string): boolean {
  return isRecord(obj) && key in obj && obj[key] !== undefined;
}

interface ValidationContext {
  errors: ValidationError[];
  warnings: string[];
  checkSupportedVersion: boolean;
  includeWarnings: boolean;
  /**
   * Semantic `when` checks (HH:MM, IANA zone, day names, nesting depth). The
   * reference engine performs these in `validate()`, not at parse time, where
   * only the structural shape is enforced.
   */
  checkConditionSemantics: boolean;
}

const DURATION_PATTERN = /^\d+[smhd]$/;

const CAPABILITY_NAMES = new Set([
  'file_access', 'file_write', 'egress', 'shell', 'tool_call', 'patch', 'custom',
]);
const BUDGET_NAMES = new Set([
  'file_writes', 'egress_calls', 'shell_commands', 'tool_calls', 'patches', 'custom_calls',
]);

/** Recursion bound for the structural condition walk; see validateConditionShape. */
const MAX_STRUCTURAL_CONDITION_DEPTH = 64;

export function validate(spec: HushSpec): ValidationResult {
  return validateDocument(spec as unknown, {
    checkSupportedVersion: true,
    includeWarnings: true,
    checkConditionSemantics: true,
  });
}

export function validateForParse(spec: unknown): ValidationResult {
  return validateDocument(spec, {
    checkSupportedVersion: false,
    includeWarnings: false,
    checkConditionSemantics: false,
  });
}

function validateDocument(
  spec: unknown,
  options: Pick<
    ValidationContext,
    'checkSupportedVersion' | 'includeWarnings' | 'checkConditionSemantics'
  >,
): ValidationResult {
  const ctx: ValidationContext = {
    errors: [],
    warnings: [],
    ...options,
  };

  if (!isRecord(spec)) {
    addError(ctx, 'invalid_document', 'HushSpec document must be a YAML mapping');
    return {
      valid: false,
      errors: ctx.errors,
      warnings: ctx.warnings,
    };
  }

  validateTopLevel(spec, ctx);

  return {
    valid: ctx.errors.length === 0,
    errors: ctx.errors,
    warnings: ctx.warnings,
  };
}

function validateTopLevel(obj: UnknownRecord, ctx: ValidationContext): void {
  rejectUnknownKeys(obj, TOP_LEVEL_KEYS_SET, ctx, 'unknown_top_level_field', key => `unknown top-level field: ${key}`);

  const hushspec = obj.hushspec;
  if (typeof hushspec !== 'string') {
    addError(ctx, 'missing_version', 'missing or invalid "hushspec" version field');
  } else if (ctx.checkSupportedVersion && !isSupported(hushspec)) {
    addError(
      ctx,
      'unsupported_version',
      `unsupported hushspec version: ${hushspec} (this engine accepts minor versions ${HUSHSPEC_SUPPORTED_MINORS.join(', ')})`,
    );
  }

  validateOptionalString(obj, 'name', ctx, 'name');
  validateOptionalString(obj, 'description', ctx, 'description');
  validateOptionalString(obj, 'extends', ctx, 'extends');
  validateOptionalEnum(obj, 'merge_strategy', ctx, 'merge_strategy', MERGE_STRATEGIES_SET);

  if (hasValue(obj, 'rules')) {
    if (!isRecord(obj.rules)) {
      addError(ctx, 'invalid_rules', 'rules must be an object');
    } else {
      validateRules(obj.rules, ctx);
    }
  } else if (ctx.includeWarnings) {
    ctx.warnings.push('no rules section present');
  }

  if (hasValue(obj, 'extensions')) {
    if (!isRecord(obj.extensions)) {
      addError(ctx, 'invalid_extensions', 'extensions must be an object');
    } else {
      validateExtensions(obj.extensions, ctx);
    }
  }

  if (hasValue(obj, 'metadata')) {
    if (!isRecord(obj.metadata)) {
      addError(ctx, 'invalid_metadata', 'metadata must be an object');
    } else {
      validateGovernanceMetadata(obj.metadata, ctx);
    }
  }
}

function validateRules(obj: UnknownRecord, ctx: ValidationContext): void {
  rejectUnknownKeys(obj, RULE_KEYS_SET, ctx, 'unknown_rule', key => `unknown rule: ${key}`);

  let configuredRules = 0;

  configuredRules += validateOptionalRuleObject(obj, 'forbidden_paths', ctx, validateForbiddenPathsRule, 'rules');
  configuredRules += validateOptionalRuleObject(obj, 'path_allowlist', ctx, validatePathAllowlistRule, 'rules');
  configuredRules += validateOptionalRuleObject(obj, 'egress', ctx, validateEgressRule, 'rules');
  configuredRules += validateOptionalRuleObject(obj, 'secret_patterns', ctx, validateSecretPatternsRule, 'rules');
  configuredRules += validateOptionalRuleObject(obj, 'patch_integrity', ctx, validatePatchIntegrityRule, 'rules');
  configuredRules += validateOptionalRuleObject(obj, 'shell_commands', ctx, validateShellCommandsRule, 'rules');
  configuredRules += validateOptionalRuleObject(obj, 'tool_access', ctx, validateToolAccessRule, 'rules');
  configuredRules += validateOptionalRuleObject(obj, 'computer_use', ctx, validateComputerUseRule, 'rules');
  configuredRules += validateOptionalRuleObject(obj, 'remote_desktop_channels', ctx, validateRemoteDesktopRule, 'rules');
  configuredRules += validateOptionalRuleObject(obj, 'input_injection', ctx, validateInputInjectionRule, 'rules');
  configuredRules += validateOptionalRuleObject(obj, 'browser_automation', ctx, validateBrowserAutomationRule, 'rules');
  configuredRules += validateOptionalRuleObject(obj, 'code_execution', ctx, validateCodeExecutionRule, 'rules');

  if (configuredRules === 0 && ctx.includeWarnings) {
    ctx.warnings.push('no rules configured');
  }
}

function validateForbiddenPathsRule(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  rejectUnknownKeys(obj, FORBIDDEN_PATH_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);
  validateWhen(obj, ctx, path);
  validateOptionalBoolean(obj, 'enabled', ctx, `${path}.enabled`);
  validateOptionalStringArray(obj, 'patterns', ctx, `${path}.patterns`);
  validateOptionalStringArray(obj, 'exceptions', ctx, `${path}.exceptions`);
}

function validatePathAllowlistRule(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  rejectUnknownKeys(obj, PATH_ALLOWLIST_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);
  validateWhen(obj, ctx, path);
  validateOptionalBoolean(obj, 'enabled', ctx, `${path}.enabled`);
  validateOptionalStringArray(obj, 'read', ctx, `${path}.read`);
  validateOptionalStringArray(obj, 'write', ctx, `${path}.write`);
  validateOptionalStringArray(obj, 'patch', ctx, `${path}.patch`);
}

function validateEgressRule(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  rejectUnknownKeys(obj, EGRESS_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);
  validateWhen(obj, ctx, path);
  validateOptionalBoolean(obj, 'enabled', ctx, `${path}.enabled`);
  validateOptionalStringArray(obj, 'allow', ctx, `${path}.allow`);
  validateOptionalStringArray(obj, 'block', ctx, `${path}.block`);
  validateOptionalEnum(obj, 'default', ctx, `${path}.default`, DEFAULT_ACTIONS_SET);
}

function validateSecretPatternsRule(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  rejectUnknownKeys(obj, SECRET_PATTERNS_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);
  validateWhen(obj, ctx, path);
  validateOptionalBoolean(obj, 'enabled', ctx, `${path}.enabled`);
  validateOptionalStringArray(obj, 'skip_paths', ctx, `${path}.skip_paths`);

  if (!hasValue(obj, 'patterns')) return;
  if (!Array.isArray(obj.patterns)) {
    addError(ctx, 'invalid_patterns', `${path}.patterns must be an array`);
    return;
  }

  const seen = new Set<string>();
  obj.patterns.forEach((pattern, index) => {
    const itemPath = `${path}.patterns[${index}]`;
    if (!isRecord(pattern)) {
      addError(ctx, 'invalid_pattern', `${itemPath} must be an object`);
      return;
    }
    rejectUnknownKeys(pattern, SECRET_PATTERN_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${itemPath}: ${key}`);
    const name = validateRequiredString(pattern, 'name', ctx, `${itemPath}.name`);
    const regex = validateRequiredString(pattern, 'pattern', ctx, `${itemPath}.pattern`);
    validateRequiredEnum(pattern, 'severity', ctx, `${itemPath}.severity`, SEVERITIES_SET);
    validateOptionalString(pattern, 'description', ctx, `${itemPath}.description`);

    if (name) {
      if (seen.has(name)) {
        addError(ctx, 'duplicate_pattern_name', `duplicate secret pattern name: ${name}`);
      }
      seen.add(name);
    }
    if (regex) {
      validateRegex(regex, ctx, `${itemPath}.pattern`);
    }
  });
}

function validatePatchIntegrityRule(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  rejectUnknownKeys(obj, PATCH_INTEGRITY_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);
  validateWhen(obj, ctx, path);
  validateOptionalBoolean(obj, 'enabled', ctx, `${path}.enabled`);
  validateOptionalInteger(obj, 'max_additions', ctx, `${path}.max_additions`, { min: 0 });
  validateOptionalInteger(obj, 'max_deletions', ctx, `${path}.max_deletions`, { min: 0 });
  validateOptionalBoolean(obj, 'require_balance', ctx, `${path}.require_balance`);

  if (hasValue(obj, 'forbidden_patterns')) {
    const patterns = validateOptionalStringArray(obj, 'forbidden_patterns', ctx, `${path}.forbidden_patterns`);
    patterns?.forEach((pattern, index) => validateRegex(pattern, ctx, `${path}.forbidden_patterns[${index}]`));
  }

  validateOptionalNumber(obj, 'max_imbalance_ratio', ctx, `${path}.max_imbalance_ratio`, { minExclusive: 0 });
}

function validateShellCommandsRule(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  rejectUnknownKeys(obj, SHELL_COMMAND_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);
  validateWhen(obj, ctx, path);
  validateOptionalBoolean(obj, 'enabled', ctx, `${path}.enabled`);

  if (hasValue(obj, 'forbidden_patterns')) {
    const patterns = validateOptionalStringArray(obj, 'forbidden_patterns', ctx, `${path}.forbidden_patterns`);
    patterns?.forEach((pattern, index) => validateRegex(pattern, ctx, `${path}.forbidden_patterns[${index}]`));
  }
}

function validateToolAccessRule(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  rejectUnknownKeys(obj, TOOL_ACCESS_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);
  validateWhen(obj, ctx, path);
  validateOptionalBoolean(obj, 'enabled', ctx, `${path}.enabled`);
  validateOptionalStringArray(obj, 'allow', ctx, `${path}.allow`);
  validateOptionalStringArray(obj, 'block', ctx, `${path}.block`);
  validateOptionalStringArray(obj, 'require_confirmation', ctx, `${path}.require_confirmation`);
  validateOptionalEnum(obj, 'default', ctx, `${path}.default`, DEFAULT_ACTIONS_SET);
  validateOptionalInteger(obj, 'max_args_size', ctx, `${path}.max_args_size`, { min: 1 });
}

function validateComputerUseRule(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  rejectUnknownKeys(obj, COMPUTER_USE_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);
  validateWhen(obj, ctx, path);
  validateOptionalBoolean(obj, 'enabled', ctx, `${path}.enabled`);
  validateOptionalEnum(obj, 'mode', ctx, `${path}.mode`, COMPUTER_USE_MODES_SET);
  validateOptionalStringArray(obj, 'allowed_actions', ctx, `${path}.allowed_actions`);
}

function validateRemoteDesktopRule(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  rejectUnknownKeys(obj, REMOTE_DESKTOP_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);
  validateWhen(obj, ctx, path);
  validateOptionalBoolean(obj, 'enabled', ctx, `${path}.enabled`);
  validateOptionalBoolean(obj, 'clipboard', ctx, `${path}.clipboard`);
  validateOptionalBoolean(obj, 'file_transfer', ctx, `${path}.file_transfer`);
  validateOptionalBoolean(obj, 'audio', ctx, `${path}.audio`);
  validateOptionalBoolean(obj, 'drive_mapping', ctx, `${path}.drive_mapping`);
}

function validateInputInjectionRule(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  rejectUnknownKeys(obj, INPUT_INJECTION_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);
  validateWhen(obj, ctx, path);
  validateOptionalBoolean(obj, 'enabled', ctx, `${path}.enabled`);
  validateOptionalStringArray(obj, 'allowed_types', ctx, `${path}.allowed_types`);
  validateOptionalBoolean(obj, 'require_postcondition_probe', ctx, `${path}.require_postcondition_probe`);
}

function validateBrowserAutomationRule(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  rejectUnknownKeys(obj, BROWSER_AUTOMATION_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);
  validateWhen(obj, ctx, path);
  validateOptionalBoolean(obj, 'enabled', ctx, `${path}.enabled`);
  validateOptionalStringArray(obj, 'allowed_domains', ctx, `${path}.allowed_domains`);
  validateOptionalStringArray(obj, 'blocked_domains', ctx, `${path}.blocked_domains`);
  validateOptionalStringArray(obj, 'allowed_verbs', ctx, `${path}.allowed_verbs`);
  validateOptionalBoolean(obj, 'credential_detection', ctx, `${path}.credential_detection`);

  if (hasValue(obj, 'extra_credential_patterns')) {
    const patterns = validateOptionalStringArray(obj, 'extra_credential_patterns', ctx, `${path}.extra_credential_patterns`);
    patterns?.forEach((pattern, index) => validateRegex(pattern, ctx, `${path}.extra_credential_patterns[${index}]`));
  }
}

function validateCodeExecutionRule(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  rejectUnknownKeys(obj, CODE_EXECUTION_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);
  validateWhen(obj, ctx, path);
  validateOptionalBoolean(obj, 'enabled', ctx, `${path}.enabled`);
  validateOptionalStringArray(obj, 'language_allowlist', ctx, `${path}.language_allowlist`);
  validateOptionalStringArray(obj, 'module_denylist', ctx, `${path}.module_denylist`);
  validateOptionalBoolean(obj, 'network_access', ctx, `${path}.network_access`);
  validateOptionalInteger(obj, 'max_execution_time_ms', ctx, `${path}.max_execution_time_ms`, { min: 0 });
  validateOptionalInteger(obj, 'max_scan_bytes', ctx, `${path}.max_scan_bytes`, { min: 1 });
}

function validateExtensions(obj: UnknownRecord, ctx: ValidationContext): void {
  rejectUnknownKeys(obj, EXTENSION_KEYS_SET, ctx, 'unknown_extension', key => `unknown extension: ${key}`);

  validateOptionalRuleObject(obj, 'posture', ctx, validatePostureExtension, 'extensions');
  const postureStateNames = getPostureStateNames(obj.posture);
  validateOptionalRuleObject(
    obj,
    'origins',
    ctx,
    (value, innerCtx, path) => validateOriginsExtension(value, innerCtx, path, postureStateNames),
    'extensions',
  );
  validateOptionalRuleObject(obj, 'detection', ctx, validateDetectionExtension, 'extensions');
}

function validatePostureExtension(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  rejectUnknownKeys(obj, POSTURE_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);

  const initial = validateRequiredString(obj, 'initial', ctx, `${path}.initial`);
  const states = validateRequiredRecord(obj, 'states', ctx, `${path}.states`);
  const transitions = validateRequiredArray(obj, 'transitions', ctx, `${path}.transitions`);

  const stateNames = new Set<string>();
  if (states) {
    const stateKeys = Object.keys(states);
    if (stateKeys.length === 0) {
      addError(ctx, 'empty_states', `${path}.states must define at least one state`);
    }
    for (const stateName of stateKeys) {
      stateNames.add(stateName);
      const state = states[stateName];
      const statePath = `${path}.states.${stateName}`;
      if (!isRecord(state)) {
        addError(ctx, 'invalid_state', `${statePath} must be an object`);
        continue;
      }
      rejectUnknownKeys(state, POSTURE_STATE_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${statePath}: ${key}`);
      validateOptionalString(state, 'description', ctx, `${statePath}.description`);

      const capabilities = validateOptionalStringArray(state, 'capabilities', ctx, `${statePath}.capabilities`);
      capabilities?.forEach(capability => {
        if (ctx.includeWarnings && !CAPABILITY_NAMES.has(capability)) {
          ctx.warnings.push(`${statePath}.capabilities includes unknown capability '${capability}'`);
        }
      });

      if (hasValue(state, 'budgets')) {
        if (!isRecord(state.budgets)) {
          addError(ctx, 'invalid_budgets', `${statePath}.budgets must be an object`);
        } else {
          for (const [budgetKey, budgetValue] of Object.entries(state.budgets)) {
            validateIntegerValue(budgetValue, ctx, `${statePath}.budgets.${budgetKey}`, { min: 0 });
            if (ctx.includeWarnings && !BUDGET_NAMES.has(budgetKey)) {
              ctx.warnings.push(`${statePath}.budgets uses unknown budget key '${budgetKey}'`);
            }
          }
        }
      }
    }
  }

  if (initial && states && !stateNames.has(initial)) {
    addError(ctx, 'invalid_posture_initial', `posture.initial '${initial}' does not reference a defined state`);
  }

  if (transitions) {
    transitions.forEach((transition, index) => {
      const transitionPath = `${path}.transitions[${index}]`;
      if (!isRecord(transition)) {
        addError(ctx, 'invalid_transition', `${transitionPath} must be an object`);
        return;
      }

      rejectUnknownKeys(transition, POSTURE_TRANSITION_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${transitionPath}: ${key}`);

      const from = validateRequiredString(transition, 'from', ctx, `${transitionPath}.from`);
      const to = validateRequiredString(transition, 'to', ctx, `${transitionPath}.to`);
      const on = validateRequiredEnum(transition, 'on', ctx, `${transitionPath}.on`, TRANSITION_TRIGGERS_SET);
      const after = validateOptionalString(transition, 'after', ctx, `${transitionPath}.after`);

      if (from && from !== '*' && !stateNames.has(from)) {
        addError(ctx, 'invalid_transition_from', `posture.transitions[${index}].from '${from}' does not reference a defined state`);
      }
      if (to === '*') {
        addError(ctx, 'invalid_transition_to', `posture.transitions[${index}].to cannot be '*'`);
      } else if (to && !stateNames.has(to)) {
        addError(ctx, 'invalid_transition_to', `posture.transitions[${index}].to '${to}' does not reference a defined state`);
      }
      if (on === 'timeout') {
        if (!after) {
          addError(ctx, 'missing_timeout_after', `posture.transitions[${index}]: timeout trigger requires 'after' field`);
        } else if (!DURATION_PATTERN.test(after)) {
          addError(ctx, 'invalid_duration', `${transitionPath}.after must match ^\\d+[smhd]$`);
        }
      } else if (after && !DURATION_PATTERN.test(after)) {
        addError(ctx, 'invalid_duration', `${transitionPath}.after must match ^\\d+[smhd]$`);
      }
    });
  }
}

function validateOriginsExtension(
  obj: UnknownRecord,
  ctx: ValidationContext,
  path: string,
  postureStates: Set<string> | undefined,
): void {
  rejectUnknownKeys(obj, ORIGINS_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);
  validateOptionalEnum(obj, 'default_behavior', ctx, `${path}.default_behavior`, ORIGIN_DEFAULT_BEHAVIORS_SET);

  if (!hasValue(obj, 'profiles')) return;
  if (!Array.isArray(obj.profiles)) {
    addError(ctx, 'invalid_profiles', `${path}.profiles must be an array`);
    return;
  }

  const profileIds = new Set<string>();
  obj.profiles.forEach((profile, index) => {
    const profilePath = `${path}.profiles[${index}]`;
    if (!isRecord(profile)) {
      addError(ctx, 'invalid_profile', `${profilePath} must be an object`);
      return;
    }

    rejectUnknownKeys(profile, ORIGIN_PROFILE_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${profilePath}: ${key}`);
    const id = validateRequiredString(profile, 'id', ctx, `${profilePath}.id`);
    if (id) {
      if (profileIds.has(id)) {
        addError(ctx, 'duplicate_origin_profile_id', `duplicate origin profile id: '${id}'`);
      }
      profileIds.add(id);
    }

    if (hasValue(profile, 'match')) {
      if (!isRecord(profile.match)) {
        addError(ctx, 'invalid_match', `${profilePath}.match must be an object`);
      } else {
        rejectUnknownKeys(profile.match, ORIGIN_MATCH_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${profilePath}.match: ${key}`);
        const provider = validateOptionalString(profile.match, 'provider', ctx, `${profilePath}.match.provider`);
        const tenantId = validateOptionalString(profile.match, 'tenant_id', ctx, `${profilePath}.match.tenant_id`);
        const spaceId = validateOptionalString(profile.match, 'space_id', ctx, `${profilePath}.match.space_id`);
        validateOptionalEnum(profile.match, 'space_type', ctx, `${profilePath}.match.space_type`, ORIGIN_SPACE_TYPES_SET);
        validateOptionalEnum(profile.match, 'visibility', ctx, `${profilePath}.match.visibility`, ORIGIN_VISIBILITIES_SET);
        validateOptionalBoolean(profile.match, 'external_participants', ctx, `${profilePath}.match.external_participants`);
        validateOptionalStringArray(profile.match, 'tags', ctx, `${profilePath}.match.tags`);
        const sensitivity = validateOptionalString(profile.match, 'sensitivity', ctx, `${profilePath}.match.sensitivity`);
        const actorRole = validateOptionalString(profile.match, 'actor_role', ctx, `${profilePath}.match.actor_role`);

        // Cross-SDK parity fix (spec item S2): a present-but-empty free-text
        // match field (e.g. `provider: ""`) is an unsatisfiable constraint
        // that Go's plain-string model can't distinguish from an absent
        // field; Go's raw validator already rejects it, so reject it here
        // too to restore fail-closed accept/reject parity across the SDKs
        // (mirrors Rust `validate_origins`). The enum fields above already
        // reject "" as an invalid enum value, so they're excluded here.
        const freeTextMatchFields: Array<[string, string | undefined]> = [
          ['provider', provider],
          ['tenant_id', tenantId],
          ['space_id', spaceId],
          ['sensitivity', sensitivity],
          ['actor_role', actorRole],
        ];
        for (const [fieldName, value] of freeTextMatchFields) {
          if (value === '') {
            addError(ctx, 'empty_match_field', `${profilePath}.match.${fieldName} must not be empty`);
          }
        }
      }
    }

    const posture = validateOptionalString(profile, 'posture', ctx, `${profilePath}.posture`);
    if (posture) {
      if (!postureStates) {
        addError(ctx, 'invalid_origin_posture', `${profilePath}.posture requires extensions.posture to be defined`);
      } else if (!postureStates.has(posture)) {
        addError(ctx, 'invalid_origin_posture', `${profilePath}.posture '${posture}' does not reference a defined posture state`);
      }
    }

    validateOptionalRuleObject(profile, 'tool_access', ctx, validateOriginToolAccessOverlay, profilePath);
    validateOptionalRuleObject(profile, 'egress', ctx, validateOriginEgressOverlay, profilePath);

    if (hasValue(profile, 'data')) {
      if (!isRecord(profile.data)) {
        addError(ctx, 'invalid_data_policy', `${profilePath}.data must be an object`);
      } else {
        rejectUnknownKeys(profile.data, ORIGIN_DATA_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${profilePath}.data: ${key}`);
        validateOptionalBoolean(profile.data, 'allow_external_sharing', ctx, `${profilePath}.data.allow_external_sharing`);
        validateOptionalBoolean(profile.data, 'redact_before_send', ctx, `${profilePath}.data.redact_before_send`);
        validateOptionalBoolean(profile.data, 'block_sensitive_outputs', ctx, `${profilePath}.data.block_sensitive_outputs`);
      }
    }

    if (hasValue(profile, 'budgets')) {
      if (!isRecord(profile.budgets)) {
        addError(ctx, 'invalid_origin_budgets', `${profilePath}.budgets must be an object`);
      } else {
        rejectUnknownKeys(profile.budgets, ORIGIN_BUDGET_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${profilePath}.budgets: ${key}`);
        validateOptionalInteger(profile.budgets, 'tool_calls', ctx, `${profilePath}.budgets.tool_calls`, { min: 0 });
        validateOptionalInteger(profile.budgets, 'egress_calls', ctx, `${profilePath}.budgets.egress_calls`, { min: 0 });
        validateOptionalInteger(profile.budgets, 'shell_commands', ctx, `${profilePath}.budgets.shell_commands`, { min: 0 });
      }
    }

    if (hasValue(profile, 'bridge')) {
      if (!isRecord(profile.bridge)) {
        addError(ctx, 'invalid_bridge_policy', `${profilePath}.bridge must be an object`);
      } else {
        rejectUnknownKeys(profile.bridge, BRIDGE_POLICY_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${profilePath}.bridge: ${key}`);
        validateOptionalBoolean(profile.bridge, 'allow_cross_origin', ctx, `${profilePath}.bridge.allow_cross_origin`);
        validateOptionalBoolean(profile.bridge, 'require_approval', ctx, `${profilePath}.bridge.require_approval`);

        if (hasValue(profile.bridge, 'allowed_targets')) {
          if (!Array.isArray(profile.bridge.allowed_targets)) {
            addError(ctx, 'invalid_bridge_targets', `${profilePath}.bridge.allowed_targets must be an array`);
          } else {
            profile.bridge.allowed_targets.forEach((target, targetIndex) => {
              const targetPath = `${profilePath}.bridge.allowed_targets[${targetIndex}]`;
              if (!isRecord(target)) {
                addError(ctx, 'invalid_bridge_target', `${targetPath} must be an object`);
                return;
              }
              rejectUnknownKeys(target, BRIDGE_TARGET_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${targetPath}: ${key}`);
              validateOptionalString(target, 'provider', ctx, `${targetPath}.provider`);
              validateOptionalEnum(target, 'space_type', ctx, `${targetPath}.space_type`, ORIGIN_SPACE_TYPES_SET);
              validateOptionalStringArray(target, 'tags', ctx, `${targetPath}.tags`);
              validateOptionalEnum(target, 'visibility', ctx, `${targetPath}.visibility`, ORIGIN_VISIBILITIES_SET);
            });
          }
        }
      }
    }

    validateOptionalString(profile, 'explanation', ctx, `${profilePath}.explanation`);
  });
}

/**
 * Tri-state tool-access overlay on an origin profile (origins spec 4, D12).
 * An overlay is not a rule block: it carries no `enabled` and no `when`, and
 * an omitted `default` / `max_args_size` stays absent rather than inheriting
 * the base rule's materialized default.
 */
function validateOriginToolAccessOverlay(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  rejectUnknownKeys(obj, ORIGIN_TOOL_ACCESS_OVERLAY_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);
  validateOptionalStringArray(obj, 'allow', ctx, `${path}.allow`);
  validateOptionalStringArray(obj, 'block', ctx, `${path}.block`);
  validateOptionalStringArray(obj, 'require_confirmation', ctx, `${path}.require_confirmation`);
  validateOptionalEnum(obj, 'default', ctx, `${path}.default`, DEFAULT_ACTIONS_SET);
  validateOptionalInteger(obj, 'max_args_size', ctx, `${path}.max_args_size`, { min: 1 });
}

/** Tri-state egress overlay on an origin profile (origins spec 4, D12). */
function validateOriginEgressOverlay(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  rejectUnknownKeys(obj, ORIGIN_EGRESS_OVERLAY_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);
  validateOptionalStringArray(obj, 'allow', ctx, `${path}.allow`);
  validateOptionalStringArray(obj, 'block', ctx, `${path}.block`);
  validateOptionalEnum(obj, 'default', ctx, `${path}.default`, DEFAULT_ACTIONS_SET);
}

/**
 * Validate a rule block's `when` condition (core spec 3.13, D15): the
 * structural shape always, the semantics (HH:MM, IANA zone, day names,
 * nesting depth) only in full `validate()`, mirroring the reference engine
 * where serde enforces the shape at parse time and `validate` the rest.
 */
function validateWhen(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  if (!hasValue(obj, 'when')) return;
  const whenPath = `${path}.when`;
  const value = obj.when;
  if (!isRecord(value)) {
    addError(ctx, 'invalid_object', `${whenPath} must be an object`);
    return;
  }
  const shapeErrorCount = ctx.errors.length;
  validateConditionShape(value, ctx, whenPath, 0);
  if (!ctx.checkConditionSemantics || ctx.errors.length !== shapeErrorCount) return;
  for (const message of validateCondition(value as Condition, whenPath)) {
    addError(ctx, 'invalid_condition', message);
  }
}

function validateConditionShape(
  obj: UnknownRecord,
  ctx: ValidationContext,
  path: string,
  depth: number,
): void {
  rejectUnknownKeys(obj, CONDITION_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);

  if (hasValue(obj, 'time_window')) {
    const tw = obj.time_window;
    const twPath = `${path}.time_window`;
    if (!isRecord(tw)) {
      addError(ctx, 'invalid_object', `${twPath} must be an object`);
    } else {
      rejectUnknownKeys(tw, TIME_WINDOW_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${twPath}: ${key}`);
      validateRequiredString(tw, 'start', ctx, `${twPath}.start`);
      validateRequiredString(tw, 'end', ctx, `${twPath}.end`);
      validateOptionalString(tw, 'timezone', ctx, `${twPath}.timezone`);
      validateOptionalStringArray(tw, 'days', ctx, `${twPath}.days`);
    }
  }

  if (hasValue(obj, 'context') && !isRecord(obj.context)) {
    addError(ctx, 'invalid_object', `${path}.context must be an object`);
  }

  // The depth cap (MAX_NESTING_DEPTH) is reported by validateCondition(). This
  // much looser bound only stops a hand-built object from exhausting the stack;
  // it is far deeper than the document nesting cap enforced by parse(), so
  // every condition in a parseable document is still shape-checked in full.
  if (depth > MAX_STRUCTURAL_CONDITION_DEPTH) return;

  for (const key of ['all_of', 'any_of'] as const) {
    if (!hasValue(obj, key)) continue;
    const list = obj[key];
    if (!Array.isArray(list)) {
      addError(ctx, 'invalid_array', `${path}.${key} must be an array`);
      continue;
    }
    list.forEach((child, index) => {
      const childPath = `${path}.${key}[${index}]`;
      if (!isRecord(child)) {
        addError(ctx, 'invalid_object', `${childPath} must be an object`);
        return;
      }
      validateConditionShape(child, ctx, childPath, depth + 1);
    });
  }

  if (hasValue(obj, 'not')) {
    const child = obj.not;
    const childPath = `${path}.not`;
    if (!isRecord(child)) {
      addError(ctx, 'invalid_object', `${childPath} must be an object`);
    } else {
      validateConditionShape(child, ctx, childPath, depth + 1);
    }
  }
}

/**
 * `YYYY-MM-DD`, and a date that actually exists (no Feb 29 outside a leap
 * year). Dates are compared as strings throughout the toolchain -- which is
 * calendar order only for this shape -- so an unchecked `01/02/2026` would
 * make an expired policy compare as current instead of failing loudly.
 */
function isIsoDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(5, 7));
  const day = Number(value.slice(8, 10));
  if (month < 1 || month > 12 || day < 1) return false;
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const lengths = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day <= lengths[month - 1];
}

function validateOptionalDate(
  obj: UnknownRecord,
  key: string,
  ctx: ValidationContext,
  path: string,
): void {
  const value = validateOptionalString(obj, key, ctx, path);
  if (value != null && !isIsoDate(value)) {
    addError(ctx, 'invalid_date', `${path}: '${value}' is not an ISO 8601 date (YYYY-MM-DD)`);
  }
}

/** Numeric when both versions are plain integers, lexicographic otherwise. */
function compareChangelogVersions(left: string, right: string): number {
  const a = Number(left.trim());
  const b = Number(right.trim());
  if (Number.isInteger(a) && Number.isInteger(b) && a >= 0 && b >= 0 && left.trim() !== '' && right.trim() !== '') {
    return a === b ? 0 : a < b ? -1 : 1;
  }
  return left === right ? 0 : left < right ? -1 : 1;
}

function validateChangelog(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  if (!('changelog' in obj)) return;

  const changelog = obj.changelog;
  if (!Array.isArray(changelog)) {
    addError(ctx, 'invalid_array', `${path}.changelog must be an array`);
    return;
  }

  changelog.forEach((entry, index) => {
    const entryPath = `${path}.changelog[${index}]`;
    if (!isRecord(entry)) {
      addError(ctx, 'invalid_type', `${entryPath} must be an object`);
      return;
    }

    rejectUnknownKeys(entry, CHANGELOG_ENTRY_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${entryPath}: ${key}`);

    const version = validateRequiredString(entry, 'version', ctx, `${entryPath}.version`);
    if (version === '') {
      addError(ctx, 'invalid_value', `${entryPath}.version must not be empty`);
    }

    const date = validateRequiredString(entry, 'date', ctx, `${entryPath}.date`);
    if (date != null && !isIsoDate(date)) {
      addError(ctx, 'invalid_date', `${entryPath}.date: '${date}' is not an ISO 8601 date (YYYY-MM-DD)`);
    }

    validateOptionalString(entry, 'author', ctx, `${entryPath}.author`);

    const summary = validateRequiredString(entry, 'summary', ctx, `${entryPath}.summary`);
    if (summary === '') {
      addError(ctx, 'invalid_value', `${entryPath}.summary must not be empty`);
    }
  });
}

/**
 * Index of the first changelog entry not ordered after the one above it (the
 * list runs newest first), or -1 when the list is ordered. Entries that are
 * not well-formed are skipped: `validateChangelog` already reported them.
 */
function changelogDisorder(changelog: unknown): number {
  if (!Array.isArray(changelog)) return -1;
  for (let index = 1; index < changelog.length; index += 1) {
    const previous = changelog[index - 1];
    const current = changelog[index];
    if (!isRecord(previous) || !isRecord(current)) continue;
    if (typeof previous.version !== 'string' || typeof current.version !== 'string') continue;
    if (typeof previous.date !== 'string' || typeof current.date !== 'string') continue;
    const versionOrder = compareChangelogVersions(previous.version, current.version);
    const ordered = versionOrder > 0 || (versionOrder === 0 && previous.date >= current.date);
    if (!ordered) return index;
  }
  return -1;
}

function validateGovernanceMetadata(obj: UnknownRecord, ctx: ValidationContext): void {
  const path = 'metadata';
  rejectUnknownKeys(obj, GOVERNANCE_METADATA_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);

  validateOptionalString(obj, 'author', ctx, `${path}.author`);
  validateOptionalString(obj, 'approved_by', ctx, `${path}.approved_by`);
  validateOptionalDate(obj, 'approval_date', ctx, `${path}.approval_date`);
  validateOptionalEnum(obj, 'classification', ctx, `${path}.classification`, CLASSIFICATIONS_SET);
  validateOptionalString(obj, 'change_ticket', ctx, `${path}.change_ticket`);
  validateOptionalEnum(obj, 'lifecycle_state', ctx, `${path}.lifecycle_state`, LIFECYCLE_STATES_SET);
  validateOptionalInteger(obj, 'policy_version', ctx, `${path}.policy_version`, { min: 1 });
  validateOptionalDate(obj, 'effective_date', ctx, `${path}.effective_date`);
  validateOptionalDate(obj, 'expiry_date', ctx, `${path}.expiry_date`);
  validateOptionalString(obj, 'owner', ctx, `${path}.owner`);
  validateOptionalStringArray(obj, 'reviewers', ctx, `${path}.reviewers`);
  validateOptionalDate(obj, 'next_review_date', ctx, `${path}.next_review_date`);
  validateChangelog(obj, ctx, path);
  validateOptionalString(obj, 'supersedes', ctx, `${path}.supersedes`);
  validateControlMappings(obj, ctx, path);

  // GOV_SELF_SUPERSEDES: a document that replaces its own version describes an
  // impossible lineage, so it is an error rather than an advisory warning.
  if (typeof obj.supersedes === 'string' && typeof obj.policy_version === 'number') {
    if (obj.supersedes.trim() === String(obj.policy_version)) {
      addError(
        ctx,
        'invalid_value',
        `${path}.supersedes '${obj.supersedes}' is the policy's own policy_version`,
      );
    }
  }

  if (!ctx.includeWarnings) return;

  const today = new Date().toISOString().slice(0, 10);

  const lifecycleState = typeof obj.lifecycle_state === 'string' ? obj.lifecycle_state : undefined;
  if (lifecycleState === 'deprecated' || lifecycleState === 'archived') {
    ctx.warnings.push(`policy lifecycle state is '${lifecycleState}'`);
  }

  if (typeof obj.expiry_date === 'string' && isIsoDate(obj.expiry_date) && obj.expiry_date < today) {
    ctx.warnings.push(`policy expiry_date '${obj.expiry_date}' is in the past`);
  }

  if (hasValue(obj, 'approved_by') && !hasValue(obj, 'approval_date')) {
    ctx.warnings.push('approved_by is set but approval_date is missing');
  }

  if (obj.classification === 'restricted' && !hasValue(obj, 'approved_by')) {
    ctx.warnings.push("classification is 'restricted' but no approved_by is set");
  }

  // GOV_SOD_VIOLATION. Compared trimmed and case-insensitively: a check that a
  // copy-paste with different capitalization defeats is no check at all.
  if (typeof obj.author === 'string' && typeof obj.approved_by === 'string') {
    const author = obj.author.trim();
    if (author !== '' && author.toLowerCase() === obj.approved_by.trim().toLowerCase()) {
      ctx.warnings.push(
        `author and approved_by are the same identity '${author}': separation of duties requires a different approver`,
      );
    }
  }

  // GOV_UNAPPROVED_STATE.
  if ((lifecycleState === 'approved' || lifecycleState === 'deployed') && !hasValue(obj, 'approved_by')) {
    ctx.warnings.push(`lifecycle_state is '${lifecycleState}' but no approved_by is set`);
  }

  // GOV_REVIEW_OVERDUE.
  if (
    typeof obj.next_review_date === 'string' &&
    isIsoDate(obj.next_review_date) &&
    obj.next_review_date < today
  ) {
    ctx.warnings.push(`policy next_review_date '${obj.next_review_date}' is in the past`);
  }

  // GOV_CHANGELOG_ORDER.
  const disorder = changelogDisorder(obj.changelog);
  if (disorder >= 0) {
    ctx.warnings.push(`changelog entries are not in descending version/date order at entry ${disorder}`);
  }
}

const FRAMEWORK_ID_PATTERN = /^[a-z0-9][a-z0-9.-]*$/;

/**
 * Structural checks for `metadata.controls` (core spec 2.5). Whether the
 * framework is registered in spec/registries/frameworks.yaml, and whether the
 * paths resolve, are semantic questions answered by `h2h lint` (L012, L013) --
 * the registry deliberately stays out of the SDKs.
 */
function validateControlMappings(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  if (!('controls' in obj)) return;

  const controls = obj.controls;
  if (!Array.isArray(controls)) {
    addError(ctx, 'invalid_array', `${path}.controls must be an array`);
    return;
  }

  controls.forEach((entry, index) => {
    const entryPath = `${path}.controls[${index}]`;
    if (!isRecord(entry)) {
      addError(ctx, 'invalid_type', `${entryPath} must be an object`);
      return;
    }

    rejectUnknownKeys(entry, CONTROL_MAPPING_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${entryPath}: ${key}`);

    const framework = validateRequiredString(entry, 'framework', ctx, `${entryPath}.framework`);
    if (framework != null && !FRAMEWORK_ID_PATTERN.test(framework)) {
      addError(ctx, 'invalid_value', `${entryPath}.framework '${framework}' must match ^[a-z0-9][a-z0-9.-]*$`);
    }

    const controlId = validateRequiredString(entry, 'control_id', ctx, `${entryPath}.control_id`);
    if (controlId === '') {
      addError(ctx, 'invalid_value', `${entryPath}.control_id must not be empty`);
    }

    if (!('rule_paths' in entry)) {
      addError(ctx, 'missing_field', `${entryPath}.rule_paths is required`);
    } else {
      const rulePaths = validateOptionalStringArray(entry, 'rule_paths', ctx, `${entryPath}.rule_paths`);
      if (rulePaths != null && rulePaths.length === 0) {
        addError(ctx, 'invalid_value', `${entryPath}.rule_paths must list at least one rule path`);
      }
      rulePaths?.forEach((rulePath, entryIndex) => {
        if (rulePath === '') {
          addError(ctx, 'invalid_value', `${entryPath}.rule_paths[${entryIndex}] must not be empty`);
        }
      });
    }

    validateOptionalString(entry, 'notes', ctx, `${entryPath}.notes`);
  });
}

function validateDetectionExtension(obj: UnknownRecord, ctx: ValidationContext, path: string): void {
  rejectUnknownKeys(obj, DETECTION_KEYS_SET, ctx, 'unknown_field', key => `unknown field at ${path}: ${key}`);

  validateOptionalRuleObject(obj, 'prompt_injection', ctx, (section, sectionCtx, sectionPath) => {
    rejectUnknownKeys(section, PROMPT_INJECTION_KEYS_SET, sectionCtx, 'unknown_field', key => `unknown field at ${sectionPath}: ${key}`);
    validateOptionalBoolean(section, 'enabled', sectionCtx, `${sectionPath}.enabled`);
    const warn = validateOptionalEnum(section, 'warn_at_or_above', sectionCtx, `${sectionPath}.warn_at_or_above`, DETECTION_LEVELS_SET);
    const block = validateOptionalEnum(section, 'block_at_or_above', sectionCtx, `${sectionPath}.block_at_or_above`, DETECTION_LEVELS_SET);
    validateOptionalInteger(section, 'max_scan_bytes', sectionCtx, `${sectionPath}.max_scan_bytes`, { min: 1 });

    if (sectionCtx.includeWarnings && warn && block) {
      const order: Record<string, number> = { safe: 0, suspicious: 1, high: 2, critical: 3 };
      if (order[block] < order[warn]) {
        sectionCtx.warnings.push('detection.prompt_injection: block_at_or_above is less strict than warn_at_or_above');
      }
    }
  });

  validateOptionalRuleObject(obj, 'jailbreak', ctx, (section, sectionCtx, sectionPath) => {
    rejectUnknownKeys(section, JAILBREAK_KEYS_SET, sectionCtx, 'unknown_field', key => `unknown field at ${sectionPath}: ${key}`);
    validateOptionalBoolean(section, 'enabled', sectionCtx, `${sectionPath}.enabled`);
    const block = validateOptionalInteger(section, 'block_threshold', sectionCtx, `${sectionPath}.block_threshold`, { min: 0, max: 100 });
    const warn = validateOptionalInteger(section, 'warn_threshold', sectionCtx, `${sectionPath}.warn_threshold`, { min: 0, max: 100 });
    validateOptionalInteger(section, 'max_input_bytes', sectionCtx, `${sectionPath}.max_input_bytes`, { min: 1 });

    if (sectionCtx.includeWarnings && block != null && warn != null && block < warn) {
      sectionCtx.warnings.push('detection.jailbreak: block_threshold is lower than warn_threshold');
    }
  });

  validateOptionalRuleObject(obj, 'threat_intel', ctx, (section, sectionCtx, sectionPath) => {
    rejectUnknownKeys(section, THREAT_INTEL_KEYS_SET, sectionCtx, 'unknown_field', key => `unknown field at ${sectionPath}: ${key}`);
    validateOptionalBoolean(section, 'enabled', sectionCtx, `${sectionPath}.enabled`);
    validateOptionalString(section, 'pattern_db', sectionCtx, `${sectionPath}.pattern_db`);
    validateOptionalNumber(section, 'similarity_threshold', sectionCtx, `${sectionPath}.similarity_threshold`, { min: 0, max: 1 });
    validateOptionalInteger(section, 'top_k', sectionCtx, `${sectionPath}.top_k`, { min: 1 });
  });
}

function validateOptionalRuleObject(
  obj: UnknownRecord,
  key: string,
  ctx: ValidationContext,
  validator: (value: UnknownRecord, ctx: ValidationContext, path: string) => void,
  basePath?: string,
): number {
  if (!hasValue(obj, key)) return 0;
  const value = obj[key];
  const path = basePath ? `${basePath}.${key}` : key;
  if (!isRecord(value)) {
    addError(ctx, 'invalid_object', `${path} must be an object`);
    return 1;
  }
  validator(value, ctx, path);
  return 1;
}

function validateRequiredRecord(
  obj: UnknownRecord,
  key: string,
  ctx: ValidationContext,
  path: string,
): UnknownRecord | undefined {
  if (!hasValue(obj, key)) {
    addError(ctx, 'missing_field', `${path} is required`);
    return undefined;
  }
  const value = obj[key];
  if (!isRecord(value)) {
    addError(ctx, 'invalid_object', `${path} must be an object`);
    return undefined;
  }
  return value;
}

function validateRequiredArray(
  obj: UnknownRecord,
  key: string,
  ctx: ValidationContext,
  path: string,
): unknown[] | undefined {
  if (!hasValue(obj, key)) {
    addError(ctx, 'missing_field', `${path} is required`);
    return undefined;
  }
  const value = obj[key];
  if (!Array.isArray(value)) {
    addError(ctx, 'invalid_array', `${path} must be an array`);
    return undefined;
  }
  return value;
}

function validateRequiredString(
  obj: UnknownRecord,
  key: string,
  ctx: ValidationContext,
  path: string,
): string | undefined {
  if (!hasValue(obj, key)) {
    addError(ctx, 'missing_field', `${path} is required`);
    return undefined;
  }
  return validateStringValue(obj[key], ctx, path);
}

function validateRequiredEnum(
  obj: UnknownRecord,
  key: string,
  ctx: ValidationContext,
  path: string,
  allowed: Iterable<string>,
): string | undefined {
  if (!hasValue(obj, key)) {
    addError(ctx, 'missing_field', `${path} is required`);
    return undefined;
  }
  return validateEnumValue(obj[key], ctx, path, allowed);
}

function validateOptionalString(
  obj: UnknownRecord,
  key: string,
  ctx: ValidationContext,
  path: string,
): string | undefined {
  if (!hasValue(obj, key)) return undefined;
  return validateStringValue(obj[key], ctx, path);
}

function validateOptionalBoolean(
  obj: UnknownRecord,
  key: string,
  ctx: ValidationContext,
  path: string,
): boolean | undefined {
  if (!hasValue(obj, key)) return undefined;
  const value = obj[key];
  if (typeof value !== 'boolean') {
    addError(ctx, 'invalid_type', `${path} must be a boolean`);
    return undefined;
  }
  return value;
}

function validateOptionalEnum(
  obj: UnknownRecord,
  key: string,
  ctx: ValidationContext,
  path: string,
  allowed: Iterable<string>,
): string | undefined {
  if (!hasValue(obj, key)) return undefined;
  return validateEnumValue(obj[key], ctx, path, allowed);
}

function validateOptionalInteger(
  obj: UnknownRecord,
  key: string,
  ctx: ValidationContext,
  path: string,
  bounds: NumberBounds = {},
): number | undefined {
  if (!hasValue(obj, key)) return undefined;
  return validateIntegerValue(obj[key], ctx, path, bounds);
}

function validateOptionalNumber(
  obj: UnknownRecord,
  key: string,
  ctx: ValidationContext,
  path: string,
  bounds: NumberBounds = {},
): number | undefined {
  if (!hasValue(obj, key)) return undefined;
  return validateNumberValue(obj[key], ctx, path, bounds);
}

function validateOptionalStringArray(
  obj: UnknownRecord,
  key: string,
  ctx: ValidationContext,
  path: string,
): string[] | undefined {
  if (!hasValue(obj, key)) return undefined;
  const value = obj[key];
  if (!Array.isArray(value)) {
    addError(ctx, 'invalid_array', `${path} must be an array`);
    return undefined;
  }

  const items: string[] = [];
  value.forEach((item, index) => {
    const itemPath = `${path}[${index}]`;
    const stringValue = validateStringValue(item, ctx, itemPath);
    if (stringValue != null) {
      items.push(stringValue);
    }
  });
  return items;
}

interface NumberBounds {
  min?: number;
  max?: number;
  minExclusive?: number;
}

function validateStringValue(value: unknown, ctx: ValidationContext, path: string): string | undefined {
  if (typeof value !== 'string') {
    addError(ctx, 'invalid_type', `${path} must be a string`);
    return undefined;
  }
  return value;
}

function validateEnumValue(
  value: unknown,
  ctx: ValidationContext,
  path: string,
  allowed: Iterable<string>,
): string | undefined {
  if (typeof value !== 'string') {
    addError(ctx, 'invalid_type', `${path} must be a string`);
    return undefined;
  }

  const set = allowed instanceof Set ? allowed : new Set(allowed);
  if (!set.has(value)) {
    addError(ctx, 'invalid_enum', `${path} must be one of: ${[...set].join(', ')}`);
    return undefined;
  }
  return value;
}

function validateIntegerValue(
  value: unknown,
  ctx: ValidationContext,
  path: string,
  bounds: NumberBounds = {},
): number | undefined {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    addError(ctx, 'invalid_type', `${path} must be an integer`);
    return undefined;
  }
  return validateBounds(value, ctx, path, bounds);
}

function validateNumberValue(
  value: unknown,
  ctx: ValidationContext,
  path: string,
  bounds: NumberBounds = {},
): number | undefined {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    addError(ctx, 'invalid_type', `${path} must be a number`);
    return undefined;
  }
  return validateBounds(value, ctx, path, bounds);
}

function validateBounds(
  value: number,
  ctx: ValidationContext,
  path: string,
  bounds: NumberBounds,
): number | undefined {
  if (bounds.min != null && value < bounds.min) {
    addError(ctx, 'out_of_range', `${path} must be >= ${bounds.min}`);
    return undefined;
  }
  if (bounds.max != null && value > bounds.max) {
    addError(ctx, 'out_of_range', `${path} must be <= ${bounds.max}`);
    return undefined;
  }
  if (bounds.minExclusive != null && value <= bounds.minExclusive) {
    addError(ctx, 'out_of_range', `${path} must be > ${bounds.minExclusive}`);
    return undefined;
  }
  return value;
}

function validateRegex(pattern: string, ctx: ValidationContext, path: string): void {
  // RE2/ReDoS safety first, so a lookaround or `(a+)+` keeps reporting the
  // dedicated `non_re2_regex` code rather than being swallowed by the profile
  // compile below (which also rejects them, to stay fail-closed at eval time).
  if (!isSafeRegex(pattern)) {
    addError(
      ctx,
      'non_re2_regex',
      `${path}: pattern uses features not in the RE2 subset (backreferences, lookaround, etc.) which may cause ReDoS`,
    );
    return;
  }

  // Profile check second: `compileProfileRegex` is the exact call the evaluator
  // makes, so a pattern that validates here can never fail to compile at
  // evaluation time -- and vice versa.
  try {
    compileProfileRegex(pattern);
  } catch (error) {
    addError(
      ctx,
      'invalid_regex',
      `${path} must be a valid regular expression: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function rejectUnknownKeys(
  obj: UnknownRecord,
  allowed: ReadonlySet<string>,
  ctx: ValidationContext,
  code: string,
  messageForKey: (key: string) => string,
): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) {
      addError(ctx, code, messageForKey(key));
    }
  }
}

function getPostureStateNames(value: unknown): Set<string> | undefined {
  if (!isRecord(value) || !isRecord(value.states)) {
    return undefined;
  }
  return new Set(Object.keys(value.states));
}

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function addError(ctx: ValidationContext, code: string, message: string): void {
  ctx.errors.push({ code, message });
}
