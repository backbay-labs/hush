import type { HushSpec } from './schema.js';
import type {
  ComputerUseRule,
  EgressRule,
  ForbiddenPathsRule,
  PatchIntegrityRule,
  PathAllowlistRule,
  SecretPatternsRule,
  ShellCommandsRule,
  ToolAccessRule,
} from './rules.js';
import type {
  OriginMatch,
  OriginProfile,
  PostureExtension,
} from './extensions.js';

export type Decision = 'allow' | 'warn' | 'deny';

export interface EvaluationAction {
  type: string;
  target?: string;
  content?: string;
  origin?: OriginContext;
  posture?: PostureContext;
  args_size?: number;
}

export interface OriginContext {
  provider?: string;
  tenant_id?: string;
  space_id?: string;
  space_type?: string;
  visibility?: string;
  external_participants?: boolean;
  tags?: string[];
  sensitivity?: string;
  actor_role?: string;
}

export interface PostureContext {
  current?: string;
  signal?: string;
}

export interface EvaluationResult {
  decision: Decision;
  matched_rule?: string;
  reason?: string;
  origin_profile?: string;
  posture?: PostureResult;
}

export interface PostureResult {
  current: string;
  next: string;
}

const enum PathOperation {
  Read,
  Write,
  Patch,
}

interface PatchStats {
  additions: number;
  deletions: number;
}

function allowResult(
  matchedRule: string | undefined,
  reason: string | undefined,
  originProfile: string | undefined,
  posture: PostureResult | undefined,
): EvaluationResult {
  return { decision: 'allow', matched_rule: matchedRule, reason, origin_profile: originProfile, posture };
}

function warnResult(
  matchedRule: string | undefined,
  reason: string | undefined,
  originProfile: string | undefined,
  posture: PostureResult | undefined,
): EvaluationResult {
  return { decision: 'warn', matched_rule: matchedRule, reason, origin_profile: originProfile, posture };
}

function denyResult(
  matchedRule: string | undefined,
  reason: string | undefined,
  originProfile: string | undefined,
  posture: PostureResult | undefined,
): EvaluationResult {
  return { decision: 'deny', matched_rule: matchedRule, reason, origin_profile: originProfile, posture };
}

function globMatches(pattern: string, target: string): boolean {
  let regex = '^';
  let i = 0;
  while (i < pattern.length) {
    const ch = pattern[i];
    if (ch === '*') {
      if (i + 1 < pattern.length && pattern[i + 1] === '*') {
        regex += '.*';
        i += 2;
      } else {
        regex += '[^/]*';
        i += 1;
      }
    } else if (ch === '?') {
      regex += '.';
      i += 1;
    } else if ('.+(){}[]^$|\\'.includes(ch)) {
      regex += '\\' + ch;
      i += 1;
    } else {
      regex += ch;
      i += 1;
    }
  }
  regex += '$';

  try {
    return new RegExp(regex).test(target);
  } catch {
    return false;
  }
}

function findFirstMatch(target: string, patterns: string[]): number | undefined {
  for (let i = 0; i < patterns.length; i++) {
    if (globMatches(patterns[i], target)) {
      return i;
    }
  }
  return undefined;
}

function prefixedRule(prefix: string | undefined, suffix: string): string | undefined {
  return prefix != null ? `${prefix}.${suffix}` : undefined;
}

function profileRulePrefix(profileId: string, field: string): string {
  return `extensions.origins.profiles.${profileId}.${field}`;
}

function patchStats(content: string): PatchStats {
  let additions = 0;
  let deletions = 0;

  for (const line of content.split('\n')) {
    if (line.startsWith('+++') || line.startsWith('---')) {
      continue;
    }
    if (line.startsWith('+')) {
      additions += 1;
    } else if (line.startsWith('-')) {
      deletions += 1;
    }
  }

  return { additions, deletions };
}

function imbalanceRatio(additions: number, deletions: number): number {
  if (additions === 0 && deletions === 0) return 0;
  if (additions === 0) return deletions;
  if (deletions === 0) return additions;
  const larger = Math.max(additions, deletions);
  const smaller = Math.min(additions, deletions);
  return larger / smaller;
}

function requiredCapability(actionType: string): string | undefined {
  switch (actionType) {
    case 'file_read': return 'file_access';
    case 'file_write': return 'file_write';
    case 'patch_apply': return 'patch';
    case 'shell_command': return 'shell';
    case 'tool_call': return 'tool_call';
    case 'egress': return 'egress';
    default: return undefined;
  }
}

function resolvePosture(
  spec: HushSpec,
  matchedProfile: OriginProfile | undefined,
  posture: PostureContext | undefined,
): PostureResult | undefined {
  const postureExtension = spec.extensions?.posture;
  if (!postureExtension) return undefined;

  const current =
    matchedProfile?.posture ??
    posture?.current ??
    postureExtension.initial;

  const signal = posture?.signal;
  const next = signal != null && signal !== 'none'
    ? nextPostureState(postureExtension, current, signal) ?? current
    : current;

  return { current, next };
}

function nextPostureState(
  posture: PostureExtension,
  current: string,
  signal: string,
): string | undefined {
  for (const transition of posture.transitions) {
    if (transition.from !== '*' && transition.from !== current) {
      continue;
    }
    if (transition.on !== signal) {
      continue;
    }
    return transition.to;
  }
  return undefined;
}

function postureCapabilityGuard(
  action: EvaluationAction,
  postureResult: PostureResult | undefined,
  spec: HushSpec,
  originProfileId: string | undefined,
): EvaluationResult | undefined {
  if (!postureResult) return undefined;

  const postureExtension = spec.extensions?.posture;
  if (!postureExtension) return undefined;

  const currentState = postureExtension.states[postureResult.current];
  if (!currentState) return undefined;

  const capability = requiredCapability(action.type);
  if (capability == null) return undefined;

  const capabilities = currentState.capabilities ?? [];
  if (capabilities.includes(capability)) {
    return undefined;
  }

  return denyResult(
    `extensions.posture.states.${postureResult.current}.capabilities`,
    `posture '${postureResult.current}' does not allow capability '${capability}'`,
    originProfileId,
    { ...postureResult },
  );
}

function selectOriginProfile(
  spec: HushSpec,
  origin: OriginContext | undefined,
): OriginProfile | undefined {
  if (!origin) return undefined;

  const profiles = spec.extensions?.origins?.profiles;
  if (!profiles) return undefined;

  let bestScore = -1;
  let bestProfile: OriginProfile | undefined;

  for (const profile of profiles) {
    if (!profile.match) continue;
    const score = matchOrigin(profile.match, origin);
    if (score != null && score > bestScore) {
      bestScore = score;
      bestProfile = profile;
    }
  }

  return bestProfile;
}

function matchOrigin(rules: OriginMatch, origin: OriginContext): number | undefined {
  let score = 0;

  if (rules.provider != null) {
    if (origin.provider !== rules.provider) return undefined;
    score += 4;
  }
  if (rules.tenant_id != null) {
    if (origin.tenant_id !== rules.tenant_id) return undefined;
    score += 6;
  }
  if (rules.space_id != null) {
    if (origin.space_id !== rules.space_id) return undefined;
    score += 8;
  }
  if (rules.space_type != null) {
    if (origin.space_type !== rules.space_type) return undefined;
    score += 4;
  }
  if (rules.visibility != null) {
    if (origin.visibility !== rules.visibility) return undefined;
    score += 4;
  }
  if (rules.external_participants != null) {
    if (origin.external_participants !== rules.external_participants) return undefined;
    score += 2;
  }
  if (rules.tags != null && rules.tags.length > 0) {
    const originTags = origin.tags ?? [];
    if (!rules.tags.every(tag => originTags.includes(tag))) return undefined;
    score += rules.tags.length;
  }
  if (rules.sensitivity != null) {
    if (origin.sensitivity !== rules.sensitivity) return undefined;
    score += 4;
  }
  if (rules.actor_role != null) {
    if (origin.actor_role !== rules.actor_role) return undefined;
    score += 4;
  }

  return score;
}

function evaluateToolAccessRule(
  rule: ToolAccessRule | undefined,
  prefix: string | undefined,
  target: string,
  argsSize: number | undefined,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult {
  if (!rule) {
    return allowResult(undefined, undefined, originProfileId, posture);
  }

  if (rule.enabled === false) {
    return allowResult(undefined, undefined, originProfileId, posture);
  }

  if (rule.max_args_size != null && (argsSize ?? 0) > rule.max_args_size) {
    return denyResult(
      prefixedRule(prefix, 'max_args_size'),
      'tool arguments exceeded max_args_size',
      originProfileId,
      posture,
    );
  }

  if (findFirstMatch(target, rule.block ?? []) != null) {
    return denyResult(
      prefixedRule(prefix, 'block'),
      'tool is explicitly blocked',
      originProfileId,
      posture,
    );
  }
  if (findFirstMatch(target, rule.require_confirmation ?? []) != null) {
    return warnResult(
      prefixedRule(prefix, 'require_confirmation'),
      'tool requires confirmation',
      originProfileId,
      posture,
    );
  }
  if (findFirstMatch(target, rule.allow ?? []) != null) {
    return allowResult(
      prefixedRule(prefix, 'allow'),
      'tool is explicitly allowed',
      originProfileId,
      posture,
    );
  }

  const defaultAction = rule.default ?? 'allow';
  if (defaultAction === 'allow') {
    return allowResult(
      prefixedRule(prefix, 'default'),
      'tool matched default allow',
      originProfileId,
      posture,
    );
  }
  return denyResult(
    prefixedRule(prefix, 'default'),
    'tool matched default block',
    originProfileId,
    posture,
  );
}

function evaluateEgressRule(
  rule: EgressRule,
  prefix: string,
  target: string,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult {
  if (rule.enabled === false) {
    return allowResult(undefined, undefined, originProfileId, posture);
  }

  if (findFirstMatch(target, rule.block ?? []) != null) {
    return denyResult(
      prefixedRule(prefix, 'block'),
      'domain is explicitly blocked',
      originProfileId,
      posture,
    );
  }
  if (findFirstMatch(target, rule.allow ?? []) != null) {
    return allowResult(
      prefixedRule(prefix, 'allow'),
      'domain is explicitly allowed',
      originProfileId,
      posture,
    );
  }

  const defaultAction = rule.default ?? 'block';
  if (defaultAction === 'allow') {
    return allowResult(
      prefixedRule(prefix, 'default'),
      'domain matched default allow',
      originProfileId,
      posture,
    );
  }
  return denyResult(
    prefixedRule(prefix, 'default'),
    'domain matched default block',
    originProfileId,
    posture,
  );
}

function evaluateSecretPatterns(
  rule: SecretPatternsRule,
  target: string,
  content: string,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult {
  if (rule.enabled === false) {
    return allowResult(undefined, undefined, originProfileId, posture);
  }

  if (findFirstMatch(target, rule.skip_paths ?? []) != null) {
    return allowResult(
      'rules.secret_patterns.skip_paths',
      'path is excluded from secret scanning',
      originProfileId,
      posture,
    );
  }

  for (const pattern of rule.patterns ?? []) {
    try {
      if (new RegExp(pattern.pattern).test(content)) {
        return denyResult(
          `rules.secret_patterns.patterns.${pattern.name}`,
          `content matched secret pattern '${pattern.name}'`,
          originProfileId,
          posture,
        );
      }
    } catch {
      // Invalid regex -- skip (fail-open for individual pattern match failures).
    }
  }

  return allowResult(undefined, undefined, originProfileId, posture);
}

function evaluatePatchIntegrity(
  rule: PatchIntegrityRule,
  content: string,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult {
  if (rule.enabled === false) {
    return allowResult(undefined, undefined, originProfileId, posture);
  }

  const forbiddenPatterns = rule.forbidden_patterns ?? [];
  for (let index = 0; index < forbiddenPatterns.length; index++) {
    try {
      if (new RegExp(forbiddenPatterns[index]).test(content)) {
        return denyResult(
          `rules.patch_integrity.forbidden_patterns[${index}]`,
          'patch content matched a forbidden pattern',
          originProfileId,
          posture,
        );
      }
    } catch {
      // Invalid regex -- skip.
    }
  }

  const stats = patchStats(content);
  const maxAdditions = rule.max_additions ?? Infinity;
  const maxDeletions = rule.max_deletions ?? Infinity;

  if (stats.additions > maxAdditions) {
    return denyResult(
      'rules.patch_integrity.max_additions',
      'patch additions exceeded max_additions',
      originProfileId,
      posture,
    );
  }
  if (stats.deletions > maxDeletions) {
    return denyResult(
      'rules.patch_integrity.max_deletions',
      'patch deletions exceeded max_deletions',
      originProfileId,
      posture,
    );
  }

  if (rule.require_balance) {
    const ratio = imbalanceRatio(stats.additions, stats.deletions);
    const maxRatio = rule.max_imbalance_ratio ?? Infinity;
    if (ratio > maxRatio) {
      return denyResult(
        'rules.patch_integrity.max_imbalance_ratio',
        'patch exceeded max imbalance ratio',
        originProfileId,
        posture,
      );
    }
  }

  return allowResult(undefined, undefined, originProfileId, posture);
}

function evaluateShellRule(
  rule: ShellCommandsRule,
  target: string,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult {
  if (rule.enabled === false) {
    return allowResult(undefined, undefined, originProfileId, posture);
  }

  const forbiddenPatterns = rule.forbidden_patterns ?? [];
  for (let index = 0; index < forbiddenPatterns.length; index++) {
    try {
      if (new RegExp(forbiddenPatterns[index]).test(target)) {
        return denyResult(
          `rules.shell_commands.forbidden_patterns[${index}]`,
          'shell command matched a forbidden pattern',
          originProfileId,
          posture,
        );
      }
    } catch {
      // Invalid regex -- skip.
    }
  }

  return allowResult(undefined, undefined, originProfileId, posture);
}

function evaluateComputerUseRule(
  rule: ComputerUseRule,
  target: string,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult {
  if (rule.enabled === false) {
    return allowResult(undefined, undefined, originProfileId, posture);
  }

  const allowedActions = rule.allowed_actions ?? [];
  if (allowedActions.includes(target)) {
    return allowResult(
      'rules.computer_use.allowed_actions',
      'computer-use action is explicitly allowed',
      originProfileId,
      posture,
    );
  }

  const mode = rule.mode ?? 'guardrail';
  switch (mode) {
    case 'observe':
      return allowResult(
        'rules.computer_use.mode',
        'observe mode does not block unlisted actions',
        originProfileId,
        posture,
      );
    case 'guardrail':
      return warnResult(
        'rules.computer_use.mode',
        'guardrail mode warns on unlisted actions',
        originProfileId,
        posture,
      );
    case 'fail_closed':
      return denyResult(
        'rules.computer_use.mode',
        'fail_closed mode denies unlisted actions',
        originProfileId,
        posture,
      );
  }
}

function evaluateForbiddenPaths(
  rule: ForbiddenPathsRule,
  target: string,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult | undefined {
  if (rule.enabled === false) {
    return undefined;
  }

  if (findFirstMatch(target, rule.exceptions ?? []) != null) {
    return allowResult(
      'rules.forbidden_paths.exceptions',
      'path matched an explicit exception',
      originProfileId,
      posture,
    );
  }

  if (findFirstMatch(target, rule.patterns ?? []) != null) {
    return denyResult(
      'rules.forbidden_paths.patterns',
      'path matched a forbidden pattern',
      originProfileId,
      posture,
    );
  }

  return undefined;
}

function evaluatePathAllowlist(
  rule: PathAllowlistRule,
  target: string,
  operation: PathOperation,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult | undefined {
  if (rule.enabled !== true) {
    return undefined;
  }

  let patterns: string[];
  switch (operation) {
    case PathOperation.Read:
      patterns = rule.read ?? [];
      break;
    case PathOperation.Write:
      patterns = rule.write ?? [];
      break;
    case PathOperation.Patch: {
      const patchPatterns = rule.patch ?? [];
      patterns = patchPatterns.length > 0 ? patchPatterns : (rule.write ?? []);
      break;
    }
  }

  if (findFirstMatch(target, patterns) != null) {
    return allowResult(
      'rules.path_allowlist',
      'path matched allowlist',
      originProfileId,
      posture,
    );
  }

  return denyResult(
    'rules.path_allowlist',
    'path did not match allowlist',
    originProfileId,
    posture,
  );
}

function evaluatePathGuards(
  spec: HushSpec,
  target: string,
  operation: PathOperation,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult | undefined {
  const rules = spec.rules;
  if (!rules) return undefined;

  if (rules.forbidden_paths) {
    const result = evaluateForbiddenPaths(
      rules.forbidden_paths,
      target,
      posture,
      originProfileId,
    );
    if (result) return result;
  }

  if (rules.path_allowlist) {
    const result = evaluatePathAllowlist(
      rules.path_allowlist,
      target,
      operation,
      posture,
      originProfileId,
    );
    if (result) return result;
  }

  return undefined;
}

function evaluateToolCall(
  spec: HushSpec,
  action: EvaluationAction,
  matchedProfile: OriginProfile | undefined,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult {
  let rule: ToolAccessRule | undefined;
  let prefix: string | undefined;

  if (matchedProfile?.tool_access) {
    rule = matchedProfile.tool_access;
    prefix = profileRulePrefix(matchedProfile.id, 'tool_access');
  } else if (spec.rules?.tool_access) {
    rule = spec.rules.tool_access;
    prefix = 'rules.tool_access';
  }

  return evaluateToolAccessRule(
    rule,
    prefix,
    action.target ?? '',
    action.args_size,
    posture,
    originProfileId,
  );
}

function evaluateEgress(
  spec: HushSpec,
  action: EvaluationAction,
  matchedProfile: OriginProfile | undefined,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult {
  let rule: EgressRule | undefined;
  let prefix: string | undefined;

  if (matchedProfile?.egress) {
    rule = matchedProfile.egress;
    prefix = profileRulePrefix(matchedProfile.id, 'egress');
  } else if (spec.rules?.egress) {
    rule = spec.rules.egress;
    prefix = 'rules.egress';
  }

  if (!rule) {
    return allowResult(undefined, undefined, originProfileId, posture);
  }

  return evaluateEgressRule(
    rule,
    prefix ?? 'rules.egress',
    action.target ?? '',
    posture,
    originProfileId,
  );
}

function evaluateFileRead(
  spec: HushSpec,
  action: EvaluationAction,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult {
  const pathResult = evaluatePathGuards(
    spec,
    action.target ?? '',
    PathOperation.Read,
    posture,
    originProfileId,
  );
  if (pathResult) return pathResult;

  return allowResult(undefined, undefined, originProfileId, posture);
}

function evaluateFileWrite(
  spec: HushSpec,
  action: EvaluationAction,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult {
  const pathResult = evaluatePathGuards(
    spec,
    action.target ?? '',
    PathOperation.Write,
    posture,
    originProfileId,
  );
  if (pathResult) return pathResult;

  const secretRule = spec.rules?.secret_patterns;
  if (secretRule) {
    return evaluateSecretPatterns(
      secretRule,
      action.target ?? '',
      action.content ?? '',
      posture,
      originProfileId,
    );
  }

  return allowResult(undefined, undefined, originProfileId, posture);
}

function evaluatePatch(
  spec: HushSpec,
  action: EvaluationAction,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult {
  const pathResult = evaluatePathGuards(
    spec,
    action.target ?? '',
    PathOperation.Patch,
    posture,
    originProfileId,
  );
  if (pathResult) return pathResult;

  const patchRule = spec.rules?.patch_integrity;
  if (patchRule) {
    return evaluatePatchIntegrity(
      patchRule,
      action.content ?? '',
      posture,
      originProfileId,
    );
  }

  return allowResult(undefined, undefined, originProfileId, posture);
}

function evaluateShellCommand(
  spec: HushSpec,
  action: EvaluationAction,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult {
  const shellRule = spec.rules?.shell_commands;
  if (shellRule) {
    return evaluateShellRule(
      shellRule,
      action.target ?? '',
      posture,
      originProfileId,
    );
  }

  return allowResult(undefined, undefined, originProfileId, posture);
}

function evaluateComputerUse(
  spec: HushSpec,
  action: EvaluationAction,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult {
  const computerRule = spec.rules?.computer_use;
  if (computerRule) {
    return evaluateComputerUseRule(
      computerRule,
      action.target ?? '',
      posture,
      originProfileId,
    );
  }

  return allowResult(undefined, undefined, originProfileId, posture);
}

let panicActive = false;

export function activatePanic(): void {
  panicActive = true;
}

export function deactivatePanic(): void {
  panicActive = false;
}

export function isPanicActive(): boolean {
  return panicActive;
}

export function panicPolicy(): HushSpec {
  const { readFileSync } = require('node:fs');
  const { join, dirname } = require('node:path');

  let dir = process.cwd();
  for (let i = 0; i < 10; i++) {
    const candidate = join(dir, 'rulesets', 'panic.yaml');
    try {
      const content = readFileSync(candidate, 'utf8');
      const YAML = require('yaml');
      return YAML.parse(content) as HushSpec;
    } catch {
      // not found here, continue searching upward
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error('Could not find rulesets/panic.yaml');
}

export function evaluate(spec: HushSpec, action: EvaluationAction): EvaluationResult {
  if (panicActive) {
    return {
      decision: 'deny',
      matched_rule: '__hushspec_panic__',
      reason: 'emergency panic mode is active',
    };
  }

  const matchedProfile = selectOriginProfile(spec, action.origin);
  const originProfileId = matchedProfile?.id;
  const posture = resolvePosture(spec, matchedProfile, action.posture);

  const denied = postureCapabilityGuard(action, posture, spec, originProfileId);
  if (denied) return denied;

  switch (action.type) {
    case 'tool_call':
      return evaluateToolCall(spec, action, matchedProfile, posture, originProfileId);
    case 'egress':
      return evaluateEgress(spec, action, matchedProfile, posture, originProfileId);
    case 'file_read':
      return evaluateFileRead(spec, action, posture, originProfileId);
    case 'file_write':
      return evaluateFileWrite(spec, action, posture, originProfileId);
    case 'patch_apply':
      return evaluatePatch(spec, action, posture, originProfileId);
    case 'shell_command':
      return evaluateShellCommand(spec, action, posture, originProfileId);
    case 'computer_use':
      return evaluateComputerUse(spec, action, posture, originProfileId);
    default:
      return {
        decision: 'allow',
        matched_rule: undefined,
        reason: 'no reference evaluator rule for this action type',
        origin_profile: originProfileId,
        posture,
      };
  }
}
