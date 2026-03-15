package hushspec

// Rules groups all guard rule configurations within a HushSpec document.
type Rules struct {
	ForbiddenPaths        *ForbiddenPathsRule        `yaml:"forbidden_paths,omitempty" json:"forbidden_paths,omitempty"`
	PathAllowlist         *PathAllowlistRule         `yaml:"path_allowlist,omitempty" json:"path_allowlist,omitempty"`
	Egress                *EgressRule                `yaml:"egress,omitempty" json:"egress,omitempty"`
	SecretPatterns        *SecretPatternsRule        `yaml:"secret_patterns,omitempty" json:"secret_patterns,omitempty"`
	PatchIntegrity        *PatchIntegrityRule        `yaml:"patch_integrity,omitempty" json:"patch_integrity,omitempty"`
	ShellCommands         *ShellCommandsRule         `yaml:"shell_commands,omitempty" json:"shell_commands,omitempty"`
	ToolAccess            *ToolAccessRule            `yaml:"tool_access,omitempty" json:"tool_access,omitempty"`
	ComputerUse           *ComputerUseRule           `yaml:"computer_use,omitempty" json:"computer_use,omitempty"`
	RemoteDesktopChannels *RemoteDesktopChannelsRule `yaml:"remote_desktop_channels,omitempty" json:"remote_desktop_channels,omitempty"`
	InputInjection        *InputInjectionRule        `yaml:"input_injection,omitempty" json:"input_injection,omitempty"`
}

// Severity indicates the importance of a secret-pattern match.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityError    Severity = "error"
	SeverityWarn     Severity = "warn"
)

// DefaultAction is the fallback verdict when no allow/block rule matches.
type DefaultAction string

const (
	DefaultActionAllow DefaultAction = "allow"
	DefaultActionBlock DefaultAction = "block"
)

// ForbiddenPathsRule blocks access to filesystem paths matching the given
// glob patterns, with optional exceptions.
type ForbiddenPathsRule struct {
	Enabled    bool     `yaml:"enabled" json:"enabled"`
	Patterns   []string `yaml:"patterns,omitempty" json:"patterns,omitempty"`
	Exceptions []string `yaml:"exceptions,omitempty" json:"exceptions,omitempty"`
}

// PathAllowlistRule restricts filesystem operations to explicitly allowed
// paths, separated by operation type.
type PathAllowlistRule struct {
	Enabled bool     `yaml:"enabled" json:"enabled"`
	Read    []string `yaml:"read,omitempty" json:"read,omitempty"`
	Write   []string `yaml:"write,omitempty" json:"write,omitempty"`
	Patch   []string `yaml:"patch,omitempty" json:"patch,omitempty"`
}

// EgressRule controls outbound network access by domain, with an explicit
// default action when no allow/block entry matches.
type EgressRule struct {
	Enabled bool          `yaml:"enabled" json:"enabled"`
	Allow   []string      `yaml:"allow,omitempty" json:"allow,omitempty"`
	Block   []string      `yaml:"block,omitempty" json:"block,omitempty"`
	Default DefaultAction `yaml:"default" json:"default"`
}

// SecretPatternsRule detects secrets (API keys, tokens, etc.) in file
// writes using configurable regex patterns.
type SecretPatternsRule struct {
	Enabled   bool            `yaml:"enabled" json:"enabled"`
	Patterns  []SecretPattern `yaml:"patterns,omitempty" json:"patterns,omitempty"`
	SkipPaths []string        `yaml:"skip_paths,omitempty" json:"skip_paths,omitempty"`
}

// SecretPattern defines a single secret-detection regex.
type SecretPattern struct {
	Name        string   `yaml:"name" json:"name"`
	Pattern     string   `yaml:"pattern" json:"pattern"`
	Severity    Severity `yaml:"severity" json:"severity"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
}

// PatchIntegrityRule validates that code patches stay within size and
// balance constraints.
type PatchIntegrityRule struct {
	Enabled           bool     `yaml:"enabled" json:"enabled"`
	MaxAdditions      int      `yaml:"max_additions" json:"max_additions"`
	MaxDeletions      int      `yaml:"max_deletions" json:"max_deletions"`
	ForbiddenPatterns []string `yaml:"forbidden_patterns,omitempty" json:"forbidden_patterns,omitempty"`
	RequireBalance    bool     `yaml:"require_balance" json:"require_balance"`
	MaxImbalanceRatio float64  `yaml:"max_imbalance_ratio" json:"max_imbalance_ratio"`
}

// ShellCommandsRule blocks dangerous shell commands before execution.
type ShellCommandsRule struct {
	Enabled           bool     `yaml:"enabled" json:"enabled"`
	ForbiddenPatterns []string `yaml:"forbidden_patterns,omitempty" json:"forbidden_patterns,omitempty"`
}

// ToolAccessRule controls which MCP tools an agent may invoke.
type ToolAccessRule struct {
	Enabled             bool          `yaml:"enabled" json:"enabled"`
	Allow               []string      `yaml:"allow,omitempty" json:"allow,omitempty"`
	Block               []string      `yaml:"block,omitempty" json:"block,omitempty"`
	RequireConfirmation []string      `yaml:"require_confirmation,omitempty" json:"require_confirmation,omitempty"`
	Default             DefaultAction `yaml:"default" json:"default"`
	MaxArgsSize         *int          `yaml:"max_args_size,omitempty" json:"max_args_size,omitempty"`
}

// ComputerUseMode defines how the computer-use guard operates.
type ComputerUseMode string

const (
	// ComputerUseModeObserve logs actions without blocking.
	ComputerUseModeObserve ComputerUseMode = "observe"

	// ComputerUseModeGuardrail blocks disallowed actions with an explanation.
	ComputerUseModeGuardrail ComputerUseMode = "guardrail"

	// ComputerUseModeFailClosed denies any action not explicitly allowed.
	ComputerUseModeFailClosed ComputerUseMode = "fail_closed"
)

// ComputerUseRule controls Computer Use Agent (CUA) actions for remote
// desktop sessions.
type ComputerUseRule struct {
	Enabled        bool            `yaml:"enabled" json:"enabled"`
	Mode           ComputerUseMode `yaml:"mode" json:"mode"`
	AllowedActions []string        `yaml:"allowed_actions,omitempty" json:"allowed_actions,omitempty"`
}

// RemoteDesktopChannelsRule controls side-channel capabilities in remote
// desktop sessions (clipboard, file transfer, audio, drive mapping).
type RemoteDesktopChannelsRule struct {
	Enabled      bool `yaml:"enabled" json:"enabled"`
	Clipboard    bool `yaml:"clipboard" json:"clipboard"`
	FileTransfer bool `yaml:"file_transfer" json:"file_transfer"`
	Audio        bool `yaml:"audio" json:"audio"`
	DriveMapping bool `yaml:"drive_mapping" json:"drive_mapping"`
}

// InputInjectionRule restricts input-injection capabilities in CUA
// environments.
type InputInjectionRule struct {
	Enabled                  bool     `yaml:"enabled" json:"enabled"`
	AllowedTypes             []string `yaml:"allowed_types,omitempty" json:"allowed_types,omitempty"`
	RequirePostconditionProbe bool    `yaml:"require_postcondition_probe" json:"require_postcondition_probe"`
}
