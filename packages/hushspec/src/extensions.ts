import type {
  DetectionLevelValue,
  OriginDefaultBehaviorValue,
  OriginSpaceTypeValue,
  OriginVisibilityValue,
  TransitionTriggerValue,
} from './generated/contract.js';
import type { DefaultAction } from './rules.js';

export interface Extensions {
  posture?: PostureExtension;
  origins?: OriginsExtension;
  detection?: DetectionExtension;
}

export interface PostureExtension {
  initial: string;
  states: Record<string, PostureState>;
  transitions: PostureTransition[];
}

export interface PostureState {
  description?: string;
  capabilities?: string[];
  budgets?: Record<string, number>;
}

export interface PostureTransition {
  from: string;
  to: string;
  on: TransitionTrigger;
  after?: string;
}

export type TransitionTrigger = TransitionTriggerValue;

export interface OriginsExtension {
  default_behavior?: OriginDefaultBehavior;
  profiles?: OriginProfile[];
}

export type OriginDefaultBehavior = OriginDefaultBehaviorValue;

export interface OriginProfile {
  id: string;
  match?: OriginMatch;
  posture?: string;
  tool_access?: OriginToolAccessOverlay;
  egress?: OriginEgressOverlay;
  data?: OriginDataPolicy;
  budgets?: OriginBudgets;
  bridge?: BridgePolicy;
  explanation?: string;
}

/**
 * Tri-state tool-access overlay for an origin profile (origins spec 4, D12).
 *
 * An overlay is not a rule block: it has no `enabled` and no `when`, and
 * `default` / `max_args_size` are genuinely absent when omitted rather than
 * materialized to the base rule's default.
 */
export interface OriginToolAccessOverlay {
  allow?: string[];
  block?: string[];
  require_confirmation?: string[];
  default?: DefaultAction;
  max_args_size?: number;
}

/** Tri-state egress overlay for an origin profile (origins spec 4, D12). */
export interface OriginEgressOverlay {
  allow?: string[];
  block?: string[];
  default?: DefaultAction;
}

export interface OriginMatch {
  provider?: string;
  tenant_id?: string;
  space_id?: string;
  space_type?: OriginSpaceTypeValue;
  visibility?: OriginVisibilityValue;
  external_participants?: boolean;
  tags?: string[];
  sensitivity?: string;
  actor_role?: string;
}

export interface OriginDataPolicy {
  allow_external_sharing?: boolean;
  redact_before_send?: boolean;
  block_sensitive_outputs?: boolean;
}

export interface OriginBudgets {
  tool_calls?: number;
  egress_calls?: number;
  shell_commands?: number;
}

export interface BridgePolicy {
  allow_cross_origin?: boolean;
  allowed_targets?: BridgeTarget[];
  require_approval?: boolean;
}

export interface BridgeTarget {
  provider?: string;
  space_type?: OriginSpaceTypeValue;
  tags?: string[];
  visibility?: OriginVisibilityValue;
}

export interface DetectionExtension {
  prompt_injection?: PromptInjectionDetection;
  jailbreak?: JailbreakDetection;
  threat_intel?: ThreatIntelDetection;
}

export interface PromptInjectionDetection {
  enabled?: boolean;
  warn_at_or_above?: DetectionLevel;
  block_at_or_above?: DetectionLevel;
  max_scan_bytes?: number;
}

export type DetectionLevel = DetectionLevelValue;

export interface JailbreakDetection {
  enabled?: boolean;
  block_threshold?: number;
  warn_threshold?: number;
  max_input_bytes?: number;
}

export interface ThreatIntelDetection {
  enabled?: boolean;
  pattern_db?: string;
  similarity_threshold?: number;
  top_k?: number;
}
