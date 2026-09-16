import type { ClassificationValue, LifecycleStateValue, MergeStrategyValue } from './generated/contract.js';
import type { Rules } from './rules.js';
import type { Extensions } from './extensions.js';

export type MergeStrategy = MergeStrategyValue;
export type Classification = ClassificationValue;
export type LifecycleState = LifecycleStateValue;

/**
 * One compliance control mapped onto the parts of the document that implement
 * it. Declarative only: mappings never influence evaluation.
 *
 * `rule_paths` entries are dot paths into the resolved document, optionally
 * ending in a `[name]` selector that picks one list entry by its `name`/`id`
 * field -- `rules`, `rules.egress`, `rules.egress.allow`,
 * `rules.secret_patterns.patterns[ssn]`, `extensions.posture`.
 */
export interface ControlMapping {
  framework: string;
  control_id: string;
  rule_paths: string[];
  notes?: string;
}

/** Informational only -- has no impact on evaluation. */
export interface GovernanceMetadata {
  author?: string;
  approved_by?: string;
  approval_date?: string;
  classification?: Classification;
  change_ticket?: string;
  lifecycle_state?: LifecycleState;
  policy_version?: number;
  effective_date?: string;
  expiry_date?: string;
  controls?: ControlMapping[];
}

export interface HushSpec {
  hushspec: string;
  name?: string;
  description?: string;
  extends?: string;
  merge_strategy?: MergeStrategy;
  rules?: Rules;
  extensions?: Extensions;
  metadata?: GovernanceMetadata;
}
