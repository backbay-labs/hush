import type {
  ComputerUseModeValue,
  DefaultActionValue,
  SeverityValue,
} from './generated/contract.js';

/** Container for all security rule configurations. */
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
}

/** Block access to sensitive filesystem paths by glob pattern. */
export interface ForbiddenPathsRule {
  enabled?: boolean;
  patterns?: string[];
  exceptions?: string[];
}

/** Allow filesystem access only to explicitly listed paths. */
export interface PathAllowlistRule {
  enabled?: boolean;
  read?: string[];
  write?: string[];
  patch?: string[];
}

/** Control network egress by domain allow/block lists. */
export interface EgressRule {
  enabled?: boolean;
  allow?: string[];
  block?: string[];
  default?: DefaultAction;
}

/** Detect secrets in file writes using regex patterns. */
export interface SecretPatternsRule {
  enabled?: boolean;
  patterns?: SecretPattern[];
  skip_paths?: string[];
}

/** A named regex pattern for detecting a specific type of secret. */
export interface SecretPattern {
  name: string;
  pattern: string;
  severity: Severity;
  description?: string;
}

/** Validate patch safety via size limits and forbidden patterns. */
export interface PatchIntegrityRule {
  enabled?: boolean;
  max_additions?: number;
  max_deletions?: number;
  forbidden_patterns?: string[];
  require_balance?: boolean;
  max_imbalance_ratio?: number;
}

/** Block dangerous shell commands before execution. */
export interface ShellCommandsRule {
  enabled?: boolean;
  forbidden_patterns?: string[];
}

/** Restrict which tools an agent may invoke. */
export interface ToolAccessRule {
  enabled?: boolean;
  allow?: string[];
  block?: string[];
  require_confirmation?: string[];
  default?: DefaultAction;
  max_args_size?: number;
}

/** Operating mode for computer-use actions. */
export type ComputerUseMode = ComputerUseModeValue;

/** Control computer-use agent actions for remote desktop sessions. */
export interface ComputerUseRule {
  enabled?: boolean;
  mode?: ComputerUseMode;
  allowed_actions?: string[];
}

/** Side-channel controls for clipboard, audio, drive mapping, and file transfer. */
export interface RemoteDesktopChannelsRule {
  enabled?: boolean;
  clipboard?: boolean;
  file_transfer?: boolean;
  audio?: boolean;
  drive_mapping?: boolean;
}

/** Restrict input injection capabilities in computer-use environments. */
export interface InputInjectionRule {
  enabled?: boolean;
  allowed_types?: string[];
  require_postcondition_probe?: boolean;
}

/** Severity level for secret pattern matches. */
export type Severity = SeverityValue;

/** Default action when no explicit allow/block rule matches. */
export type DefaultAction = DefaultActionValue;
