import type { HushSpec } from './schema.js';
import type {
  ComputerUseRule,
  EgressRule,
  ForbiddenPathsRule,
  InputInjectionRule,
  PatchIntegrityRule,
  PathAllowlistRule,
  RemoteDesktopChannelsRule,
  SecretPatternsRule,
  ShellCommandsRule,
  ToolAccessRule,
} from './rules.js';
import type {
  OriginMatch,
  OriginProfile,
  PostureExtension,
} from './extensions.js';
import { parseOrThrow } from './parse.js';
import { compileSafePolicyRegex } from './regex.js';

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

function decisionRank(decision: Decision): number {
  switch (decision) {
    case 'allow': return 1;
    case 'warn': return 2;
    case 'deny': return 3;
  }
}

function moreRestrictiveResult(left: EvaluationResult, right: EvaluationResult): EvaluationResult {
  const leftRank = decisionRank(left.decision);
  const rightRank = decisionRank(right.decision);
  if (rightRank > leftRank) {
    return right;
  }
  if (leftRank > rightRank) {
    return left;
  }
  return right.matched_rule != null ? right : left;
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

function hasPatterns(patterns: string[] | undefined): boolean {
  return (patterns?.length ?? 0) > 0;
}

function isRuleActive(rule: { enabled?: boolean } | undefined): boolean {
  return rule != null && rule.enabled !== false;
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
      if (compileSafePolicyRegex(pattern.pattern).regex.test(content)) {
        return denyResult(
          `rules.secret_patterns.patterns.${pattern.name}`,
          `content matched secret pattern '${pattern.name}'`,
          originProfileId,
          posture,
        );
      }
    } catch (error) {
      return denyResult(
        `rules.secret_patterns.patterns.${pattern.name}.pattern`,
        `secret pattern '${pattern.name}' is invalid: ${error instanceof Error ? error.message : String(error)}`,
        originProfileId,
        posture,
      );
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
      if (compileSafePolicyRegex(forbiddenPatterns[index]).regex.test(content)) {
        return denyResult(
          `rules.patch_integrity.forbidden_patterns[${index}]`,
          'patch content matched a forbidden pattern',
          originProfileId,
          posture,
        );
      }
    } catch (error) {
      return denyResult(
        `rules.patch_integrity.forbidden_patterns[${index}]`,
        `patch forbidden pattern is invalid: ${error instanceof Error ? error.message : String(error)}`,
        originProfileId,
        posture,
      );
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
      if (compileSafePolicyRegex(forbiddenPatterns[index]).regex.test(target)) {
        return denyResult(
          `rules.shell_commands.forbidden_patterns[${index}]`,
          'shell command matched a forbidden pattern',
          originProfileId,
          posture,
        );
      }
    } catch (error) {
      return denyResult(
        `rules.shell_commands.forbidden_patterns[${index}]`,
        `shell forbidden pattern is invalid: ${error instanceof Error ? error.message : String(error)}`,
        originProfileId,
        posture,
      );
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
  if (rule.enabled !== true) {
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

function evaluateRemoteDesktopChannelsRule(
  rule: RemoteDesktopChannelsRule,
  target: string,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult | undefined {
  if (rule.enabled !== true) {
    return undefined;
  }

  let field: string;
  let allowed: boolean;
  switch (target) {
    case 'remote.clipboard':
      field = 'clipboard';
      allowed = rule.clipboard ?? false;
      break;
    case 'remote.file_transfer':
      field = 'file_transfer';
      allowed = rule.file_transfer ?? false;
      break;
    case 'remote.audio':
      field = 'audio';
      allowed = rule.audio ?? true;
      break;
    case 'remote.drive_mapping':
      field = 'drive_mapping';
      allowed = rule.drive_mapping ?? false;
      break;
    default:
      return undefined;
  }

  if (allowed) {
    return allowResult(
      `rules.remote_desktop_channels.${field}`,
      `remote desktop channel '${field}' is enabled`,
      originProfileId,
      posture,
    );
  }

  return denyResult(
    `rules.remote_desktop_channels.${field}`,
    `remote desktop channel '${field}' is disabled`,
    originProfileId,
    posture,
  );
}

function evaluateInputInjectionRule(
  rule: InputInjectionRule,
  target: string,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult {
  if (rule.enabled !== true) {
    return allowResult(undefined, undefined, originProfileId, posture);
  }

  const allowedTypes = rule.allowed_types ?? [];
  if (allowedTypes.length === 0) {
    return denyResult(
      'rules.input_injection.allowed_types',
      'input injection is not allowed when allowed_types is empty',
      originProfileId,
      posture,
    );
  }

  if (allowedTypes.includes(target)) {
    return allowResult(
      'rules.input_injection.allowed_types',
      'input injection type is explicitly allowed',
      originProfileId,
      posture,
    );
  }

  return denyResult(
    'rules.input_injection.allowed_types',
    'input injection type is not allowed',
    originProfileId,
    posture,
  );
}

function evaluateForbiddenPaths(
  rule: ForbiddenPathsRule,
  target: string,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): { denied?: EvaluationResult; exceptionMatched: boolean } {
  if (rule.enabled === false) {
    return { exceptionMatched: false };
  }

  if (findFirstMatch(target, rule.exceptions ?? []) != null) {
    return { exceptionMatched: true };
  }

  if (findFirstMatch(target, rule.patterns ?? []) != null) {
    return {
      denied: denyResult(
        'rules.forbidden_paths.patterns',
        'path matched a forbidden pattern',
        originProfileId,
        posture,
      ),
      exceptionMatched: false,
    };
  }

  return { exceptionMatched: false };
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

  let forbiddenExceptionMatched = false;

  if (rules.forbidden_paths) {
    const result = evaluateForbiddenPaths(
      rules.forbidden_paths,
      target,
      posture,
      originProfileId,
    );
    if (result.denied) {
      return result.denied;
    }
    forbiddenExceptionMatched = result.exceptionMatched;
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

  if (forbiddenExceptionMatched) {
    return allowResult(
      'rules.forbidden_paths.exceptions',
      'path matched an explicit exception',
      originProfileId,
      posture,
    );
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
  const baseRule = isRuleActive(spec.rules?.tool_access) ? spec.rules?.tool_access : undefined;
  const profileRule = matchedProfile != null && isRuleActive(matchedProfile.tool_access)
    ? matchedProfile.tool_access
    : undefined;
  if (baseRule == null && profileRule == null) {
    return allowResult(undefined, undefined, originProfileId, posture);
  }

  const target = action.target ?? '';
  const profilePrefix = matchedProfile != null
    ? profileRulePrefix(matchedProfile.id, 'tool_access')
    : undefined;
  const argLimitCandidates = [
    baseRule?.max_args_size != null
      ? { maxArgsSize: baseRule.max_args_size, matchedRule: 'rules.tool_access.max_args_size' }
      : undefined,
    profileRule?.max_args_size != null && profilePrefix != null
      ? { maxArgsSize: profileRule.max_args_size, matchedRule: `${profilePrefix}.max_args_size` }
      : undefined,
  ].filter((candidate): candidate is { maxArgsSize: number; matchedRule: string } => candidate != null);
  let smallestArgLimit: { maxArgsSize: number; matchedRule: string } | undefined;
  for (const candidate of argLimitCandidates) {
    if (smallestArgLimit == null || candidate.maxArgsSize < smallestArgLimit.maxArgsSize) {
      smallestArgLimit = candidate;
    }
  }

  if (smallestArgLimit != null && (action.args_size ?? 0) > smallestArgLimit.maxArgsSize) {
    return denyResult(
      smallestArgLimit.matchedRule,
      'tool arguments exceeded max_args_size',
      originProfileId,
      posture,
    );
  }

  if (baseRule != null && findFirstMatch(target, baseRule.block ?? []) != null) {
    return denyResult('rules.tool_access.block', 'tool is explicitly blocked', originProfileId, posture);
  }
  if (profileRule != null && profilePrefix != null && findFirstMatch(target, profileRule.block ?? []) != null) {
    return denyResult(`${profilePrefix}.block`, 'tool is explicitly blocked', originProfileId, posture);
  }

  if (baseRule != null && findFirstMatch(target, baseRule.require_confirmation ?? []) != null) {
    return warnResult(
      'rules.tool_access.require_confirmation',
      'tool requires confirmation',
      originProfileId,
      posture,
    );
  }
  if (profileRule != null && profilePrefix != null && findFirstMatch(target, profileRule.require_confirmation ?? []) != null) {
    return warnResult(
      `${profilePrefix}.require_confirmation`,
      'tool requires confirmation',
      originProfileId,
      posture,
    );
  }

  const baseHasAllow = hasPatterns(baseRule?.allow);
  const profileHasAllow = hasPatterns(profileRule?.allow);
  const baseAllowMatch = !baseHasAllow || findFirstMatch(target, baseRule?.allow ?? []) != null;
  const profileAllowMatch = !profileHasAllow || findFirstMatch(target, profileRule?.allow ?? []) != null;
  if ((baseHasAllow || profileHasAllow) && baseAllowMatch && profileAllowMatch) {
    const matchedRule = profileHasAllow && profilePrefix != null
      ? `${profilePrefix}.allow`
      : baseHasAllow
        ? 'rules.tool_access.allow'
        : undefined;
    return allowResult(matchedRule, 'tool is explicitly allowed', originProfileId, posture);
  }

  const defaultAction = baseRule?.default === 'block' || profileRule?.default === 'block'
    ? 'block'
    : 'allow';
  const defaultRule = profileRule != null && profilePrefix != null
    ? `${profilePrefix}.default`
    : baseRule != null
      ? 'rules.tool_access.default'
      : undefined;
  if (defaultAction === 'allow') {
    return allowResult(defaultRule, 'tool matched default allow', originProfileId, posture);
  }

  return denyResult(defaultRule, 'tool matched default block', originProfileId, posture);
}

function evaluateEgress(
  spec: HushSpec,
  action: EvaluationAction,
  matchedProfile: OriginProfile | undefined,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult {
  const baseRule = isRuleActive(spec.rules?.egress) ? spec.rules?.egress : undefined;
  const profileRule = matchedProfile != null && isRuleActive(matchedProfile.egress)
    ? matchedProfile.egress
    : undefined;
  if (baseRule == null && profileRule == null) {
    return allowResult(undefined, undefined, originProfileId, posture);
  }

  const target = action.target ?? '';
  const profilePrefix = matchedProfile != null
    ? profileRulePrefix(matchedProfile.id, 'egress')
    : undefined;

  if (baseRule != null && findFirstMatch(target, baseRule.block ?? []) != null) {
    return denyResult('rules.egress.block', 'domain is explicitly blocked', originProfileId, posture);
  }
  if (profileRule != null && profilePrefix != null && findFirstMatch(target, profileRule.block ?? []) != null) {
    return denyResult(`${profilePrefix}.block`, 'domain is explicitly blocked', originProfileId, posture);
  }

  const baseHasAllow = hasPatterns(baseRule?.allow);
  const profileHasAllow = hasPatterns(profileRule?.allow);
  const baseAllowMatch = !baseHasAllow || findFirstMatch(target, baseRule?.allow ?? []) != null;
  const profileAllowMatch = !profileHasAllow || findFirstMatch(target, profileRule?.allow ?? []) != null;
  if ((baseHasAllow || profileHasAllow) && baseAllowMatch && profileAllowMatch) {
    const matchedRule = profileHasAllow && profilePrefix != null
      ? `${profilePrefix}.allow`
      : baseHasAllow
        ? 'rules.egress.allow'
        : undefined;
    return allowResult(matchedRule, 'domain is explicitly allowed', originProfileId, posture);
  }

  const defaultAction = baseRule?.default === 'block' || profileRule?.default === 'block'
    ? 'block'
    : 'allow';
  const defaultRule = profileRule != null && profilePrefix != null
    ? `${profilePrefix}.default`
    : baseRule != null
      ? 'rules.egress.default'
      : undefined;
  if (defaultAction === 'allow') {
    return allowResult(defaultRule, 'domain matched default allow', originProfileId, posture);
  }

  return denyResult(defaultRule, 'domain matched default block', originProfileId, posture);
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
  const target = action.target ?? '';
  const computerUseResult = spec.rules?.computer_use != null
    ? evaluateComputerUseRule(
      spec.rules.computer_use,
      target,
      posture,
      originProfileId,
    )
    : undefined;
  const remoteDesktopResult = spec.rules?.remote_desktop_channels != null
    ? evaluateRemoteDesktopChannelsRule(
      spec.rules.remote_desktop_channels,
      target,
      posture,
      originProfileId,
    )
    : undefined;

  if (computerUseResult != null && remoteDesktopResult != null) {
    return moreRestrictiveResult(computerUseResult, remoteDesktopResult);
  }
  if (computerUseResult != null) {
    return computerUseResult;
  }
  if (remoteDesktopResult != null) {
    return remoteDesktopResult;
  }

  return allowResult(undefined, undefined, originProfileId, posture);
}

function evaluateInputInjection(
  spec: HushSpec,
  action: EvaluationAction,
  posture: PostureResult | undefined,
  originProfileId: string | undefined,
): EvaluationResult {
  const inputInjectionRule = spec.rules?.input_injection;
  if (inputInjectionRule) {
    return evaluateInputInjectionRule(
      inputInjectionRule,
      action.target ?? '',
      posture,
      originProfileId,
    );
  }

  return allowResult(undefined, undefined, originProfileId, posture);
}

let panicActive = false;
const PANIC_POLICY_YAML = `hushspec: "0.1.0"
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
`;

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
  return parseOrThrow(PANIC_POLICY_YAML);
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
    case 'input_inject':
      return evaluateInputInjection(spec, action, posture, originProfileId);
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
