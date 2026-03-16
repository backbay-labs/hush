import type {
  DetectionLevelValue,
  OriginDefaultBehaviorValue,
  OriginSpaceTypeValue,
  OriginVisibilityValue,
  TransitionTriggerValue,
} from './generated/contract.js';
import type { EgressRule, ToolAccessRule } from './rules.js';

// --- Extensions container ---

/** Container for optional extension blocks (posture, origins, detection). */
export interface Extensions {
  posture?: PostureExtension;
  origins?: OriginsExtension;
  detection?: DetectionExtension;
}

// --- Posture Extension ---

/** Stateful security posture with capability budgets and transitions. */
export interface PostureExtension {
  initial: string;
  states: Record<string, PostureState>;
  transitions: PostureTransition[];
}

/** A single posture state with its allowed capabilities and budgets. */
export interface PostureState {
  description?: string;
  capabilities?: string[];
  budgets?: Record<string, number>;
}

/** A rule for transitioning between posture states. */
export interface PostureTransition {
  from: string;
  to: string;
  on: TransitionTrigger;
  after?: string;
}

/** Event that triggers a posture state transition. */
export type TransitionTrigger = TransitionTriggerValue;

// --- Origins Extension ---

/** Origin-aware policy enforcement for different message sources. */
export interface OriginsExtension {
  default_behavior?: OriginDefaultBehavior;
  profiles?: OriginProfile[];
}

/** Behavior when no origin profile matches an incoming message. */
export type OriginDefaultBehavior = OriginDefaultBehaviorValue;

/** A named origin profile binding match criteria to security rules. */
export interface OriginProfile {
  id: string;
  match?: OriginMatch;
  posture?: string;
  tool_access?: ToolAccessRule;
  egress?: EgressRule;
  data?: OriginDataPolicy;
  budgets?: OriginBudgets;
  bridge?: BridgePolicy;
  explanation?: string;
}

/** Criteria for matching an incoming message to an origin profile. */
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

/** Data handling rules for a specific origin. */
export interface OriginDataPolicy {
  allow_external_sharing?: boolean;
  redact_before_send?: boolean;
  block_sensitive_outputs?: boolean;
}

/** Per-origin rate limits for tool calls, egress, and shell commands. */
export interface OriginBudgets {
  tool_calls?: number;
  egress_calls?: number;
  shell_commands?: number;
}

/** Policy governing cross-origin bridging of agent actions. */
export interface BridgePolicy {
  allow_cross_origin?: boolean;
  allowed_targets?: BridgeTarget[];
  require_approval?: boolean;
}

/** Criteria identifying a valid bridge destination. */
export interface BridgeTarget {
  provider?: string;
  space_type?: OriginSpaceTypeValue;
  tags?: string[];
  visibility?: OriginVisibilityValue;
}

// --- Detection Extension ---

/** Configuration for runtime threat detection modules. */
export interface DetectionExtension {
  prompt_injection?: PromptInjectionDetection;
  jailbreak?: JailbreakDetection;
  threat_intel?: ThreatIntelDetection;
}

/** Prompt injection detection thresholds and limits. */
export interface PromptInjectionDetection {
  enabled?: boolean;
  warn_at_or_above?: DetectionLevel;
  block_at_or_above?: DetectionLevel;
  max_scan_bytes?: number;
}

/** Severity level for detection verdicts. */
export type DetectionLevel = DetectionLevelValue;

/** Jailbreak detection score thresholds and input limits. */
export interface JailbreakDetection {
  enabled?: boolean;
  block_threshold?: number;
  warn_threshold?: number;
  max_input_bytes?: number;
}

/** Threat intelligence pattern matching via embedding similarity. */
export interface ThreatIntelDetection {
  enabled?: boolean;
  pattern_db?: string;
  similarity_threshold?: number;
  top_k?: number;
}
