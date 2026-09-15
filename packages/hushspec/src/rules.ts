import type {
  ComputerUseModeValue,
  DefaultActionValue,
  SeverityValue,
} from './generated/contract.js';
import type { Condition } from './conditions.js';

export interface Rules {
  forbidden_paths?: ForbiddenPathsRule;
  path_allowlist?: PathAllowlistRule;
  egress?: EgressRule;
  secret_patterns?: SecretPatternsRule;
  patch_integrity?: PatchIntegrityRule;
  shell_commands?: ShellCommandsRule;
  tool_access?: ToolAccessRule;
  computer_use?: ComputerUseRule;
  remote_desktop_channels?: RemoteDesktopChannelsRule;
  input_injection?: InputInjectionRule;
  browser_automation?: BrowserAutomationRule;
  code_execution?: CodeExecutionRule;
}

export interface ForbiddenPathsRule {
  /** Gate on the runtime context (core spec 3.13). */
  when?: Condition;
  enabled?: boolean;
  patterns?: string[];
  exceptions?: string[];
}

export interface PathAllowlistRule {
  /** Gate on the runtime context (core spec 3.13). */
  when?: Condition;
  enabled?: boolean;
  read?: string[];
  write?: string[];
  patch?: string[];
}

export interface EgressRule {
  /** Gate on the runtime context (core spec 3.13). */
  when?: Condition;
  enabled?: boolean;
  allow?: string[];
  block?: string[];
  default?: DefaultAction;
}

export interface SecretPatternsRule {
  /** Gate on the runtime context (core spec 3.13). */
  when?: Condition;
  enabled?: boolean;
  patterns?: SecretPattern[];
  skip_paths?: string[];
}

export interface SecretPattern {
  name: string;
  pattern: string;
  severity: Severity;
  description?: string;
}

export interface PatchIntegrityRule {
  /** Gate on the runtime context (core spec 3.13). */
  when?: Condition;
  enabled?: boolean;
  max_additions?: number;
  max_deletions?: number;
  forbidden_patterns?: string[];
  require_balance?: boolean;
  max_imbalance_ratio?: number;
}

export interface ShellCommandsRule {
  /** Gate on the runtime context (core spec 3.13). */
  when?: Condition;
  enabled?: boolean;
  forbidden_patterns?: string[];
}

export interface ToolAccessRule {
  /** Gate on the runtime context (core spec 3.13). */
  when?: Condition;
  enabled?: boolean;
  allow?: string[];
  block?: string[];
  require_confirmation?: string[];
  default?: DefaultAction;
  max_args_size?: number;
}

export type ComputerUseMode = ComputerUseModeValue;

export interface ComputerUseRule {
  /** Gate on the runtime context (core spec 3.13). */
  when?: Condition;
  enabled?: boolean;
  mode?: ComputerUseMode;
  allowed_actions?: string[];
}

export interface RemoteDesktopChannelsRule {
  /** Gate on the runtime context (core spec 3.13). */
  when?: Condition;
  enabled?: boolean;
  clipboard?: boolean;
  file_transfer?: boolean;
  audio?: boolean;
  drive_mapping?: boolean;
}

export interface InputInjectionRule {
  /** Gate on the runtime context (core spec 3.13). */
  when?: Condition;
  enabled?: boolean;
  allowed_types?: string[];
  require_postcondition_probe?: boolean;
}

export interface BrowserAutomationRule {
  /** Gate on the runtime context (core spec 3.13). */
  when?: Condition;
  enabled?: boolean;
  allowed_domains?: string[];
  blocked_domains?: string[];
  allowed_verbs?: string[];
  credential_detection?: boolean;
  extra_credential_patterns?: string[];
}

export interface CodeExecutionRule {
  /** Gate on the runtime context (core spec 3.13). */
  when?: Condition;
  enabled?: boolean;
  language_allowlist?: string[];
  module_denylist?: string[];
  network_access?: boolean;
  max_execution_time_ms?: number;
  max_scan_bytes?: number;
}

export type Severity = SeverityValue;
export type DefaultAction = DefaultActionValue;
