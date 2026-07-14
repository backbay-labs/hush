import type {
  ComputerUseModeValue,
  DefaultActionValue,
  SeverityValue,
} from './generated/contract.js';

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
  enabled?: boolean;
  patterns?: string[];
  exceptions?: string[];
}

export interface PathAllowlistRule {
  enabled?: boolean;
  read?: string[];
  write?: string[];
  patch?: string[];
}

export interface EgressRule {
  enabled?: boolean;
  allow?: string[];
  block?: string[];
  default?: DefaultAction;
}

export interface SecretPatternsRule {
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
  enabled?: boolean;
  max_additions?: number;
  max_deletions?: number;
  forbidden_patterns?: string[];
  require_balance?: boolean;
  max_imbalance_ratio?: number;
}

export interface ShellCommandsRule {
  enabled?: boolean;
  forbidden_patterns?: string[];
}

export interface ToolAccessRule {
  enabled?: boolean;
  allow?: string[];
  block?: string[];
  require_confirmation?: string[];
  default?: DefaultAction;
  max_args_size?: number;
}

export type ComputerUseMode = ComputerUseModeValue;

export interface ComputerUseRule {
  enabled?: boolean;
  mode?: ComputerUseMode;
  allowed_actions?: string[];
}

export interface RemoteDesktopChannelsRule {
  enabled?: boolean;
  clipboard?: boolean;
  file_transfer?: boolean;
  audio?: boolean;
  drive_mapping?: boolean;
}

export interface InputInjectionRule {
  enabled?: boolean;
  allowed_types?: string[];
  require_postcondition_probe?: boolean;
}

export interface BrowserAutomationRule {
  enabled?: boolean;
  allowed_domains?: string[];
  blocked_domains?: string[];
  allowed_verbs?: string[];
  credential_detection?: boolean;
  extra_credential_patterns?: string[];
}

export interface CodeExecutionRule {
  enabled?: boolean;
  language_allowlist?: string[];
  module_denylist?: string[];
  network_access?: boolean;
  max_execution_time_ms?: number;
  max_scan_bytes?: number;
}

export type Severity = SeverityValue;
export type DefaultAction = DefaultActionValue;
