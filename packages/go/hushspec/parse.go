package hushspec

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type parsePresenceSpec struct {
	Rules *struct {
		ForbiddenPaths *struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"forbidden_paths"`
		Egress *struct {
			Enabled *bool          `yaml:"enabled"`
			Default *DefaultAction `yaml:"default"`
		} `yaml:"egress"`
		SecretPatterns *struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"secret_patterns"`
		PatchIntegrity *struct {
			Enabled           *bool    `yaml:"enabled"`
			MaxAdditions      *int     `yaml:"max_additions"`
			MaxDeletions      *int     `yaml:"max_deletions"`
			MaxImbalanceRatio *float64 `yaml:"max_imbalance_ratio"`
		} `yaml:"patch_integrity"`
		ShellCommands *struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"shell_commands"`
		ToolAccess *struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"tool_access"`
		RemoteDesktopChannels *struct {
			Audio *bool `yaml:"audio"`
		} `yaml:"remote_desktop_channels"`
		BrowserAutomation *struct {
			CredentialDetection *bool `yaml:"credential_detection"`
		} `yaml:"browser_automation"`
	} `yaml:"rules"`
}

// Parse decodes a YAML string into a HushSpec document. Unknown fields are
// rejected and the top-level "hushspec" version key must be present.
// Cross-field validation is performed separately by [Validate].
func Parse(yamlStr string) (*HushSpec, error) {
	// The HushSpec YAML profile (core spec 2.4) is enforced before the typed
	// decode: single document, no anchors/aliases/merge keys, YAML 1.2 Core
	// booleans, and bounded size, depth, and node count.
	if err := enforceYAMLProfile(yamlStr); err != nil {
		return nil, fmt.Errorf("failed to parse HushSpec YAML: %w", err)
	}

	var spec HushSpec
	decoder := yaml.NewDecoder(strings.NewReader(yamlStr))
	decoder.KnownFields(true)
	err := decoder.Decode(&spec)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HushSpec YAML: %w", err)
	}
	if spec.HushSpecVersion == "" {
		return nil, fmt.Errorf("missing or empty 'hushspec' version field")
	}

	var presence parsePresenceSpec
	if err := yaml.Unmarshal([]byte(yamlStr), &presence); err != nil {
		return nil, fmt.Errorf("failed to inspect HushSpec YAML defaults: %w", err)
	}
	applyParseDefaults(&spec, &presence)

	// Raw-document checks catch structural issues the typed decode swallows
	// (non-integer floats truncated into int fields, empty/invalid enum
	// sentinels, a posture missing its required transitions key), keeping Go's
	// accept/reject decision identical to the other SDKs.
	if issues := validateRawDocument(yamlStr); len(issues) > 0 {
		return nil, fmt.Errorf("invalid HushSpec document: %s", strings.Join(issues, "; "))
	}

	return &spec, nil
}

func applyParseDefaults(spec *HushSpec, presence *parsePresenceSpec) {
	if spec.Rules != nil && spec.Rules.ForbiddenPaths != nil {
		if presence.Rules == nil || presence.Rules.ForbiddenPaths == nil || presence.Rules.ForbiddenPaths.Enabled == nil {
			spec.Rules.ForbiddenPaths.Enabled = true
		}
	}
	if spec.Rules != nil && spec.Rules.Egress != nil {
		if presence.Rules == nil || presence.Rules.Egress == nil || presence.Rules.Egress.Enabled == nil {
			spec.Rules.Egress.Enabled = true
		}
		if presence.Rules == nil || presence.Rules.Egress == nil || presence.Rules.Egress.Default == nil {
			spec.Rules.Egress.Default = DefaultActionBlock
		}
	}
	if spec.Rules != nil && spec.Rules.SecretPatterns != nil {
		if presence.Rules == nil || presence.Rules.SecretPatterns == nil || presence.Rules.SecretPatterns.Enabled == nil {
			spec.Rules.SecretPatterns.Enabled = true
		}
	}
	if spec.Rules != nil && spec.Rules.PatchIntegrity != nil {
		if presence.Rules == nil || presence.Rules.PatchIntegrity == nil || presence.Rules.PatchIntegrity.Enabled == nil {
			spec.Rules.PatchIntegrity.Enabled = true
		}
		if presence.Rules == nil || presence.Rules.PatchIntegrity == nil || presence.Rules.PatchIntegrity.MaxAdditions == nil {
			spec.Rules.PatchIntegrity.MaxAdditions = 1000
		}
		if presence.Rules == nil || presence.Rules.PatchIntegrity == nil || presence.Rules.PatchIntegrity.MaxDeletions == nil {
			spec.Rules.PatchIntegrity.MaxDeletions = 500
		}
		if presence.Rules == nil || presence.Rules.PatchIntegrity == nil || presence.Rules.PatchIntegrity.MaxImbalanceRatio == nil {
			ratio := 10.0
			spec.Rules.PatchIntegrity.MaxImbalanceRatio = &ratio
		}
	}
	if spec.Rules != nil && spec.Rules.RemoteDesktopChannels != nil {
		if presence.Rules == nil || presence.Rules.RemoteDesktopChannels == nil || presence.Rules.RemoteDesktopChannels.Audio == nil {
			spec.Rules.RemoteDesktopChannels.Audio = true
		}
	}
	if spec.Rules != nil && spec.Rules.ShellCommands != nil {
		if presence.Rules == nil || presence.Rules.ShellCommands == nil || presence.Rules.ShellCommands.Enabled == nil {
			spec.Rules.ShellCommands.Enabled = true
		}
	}
	if spec.Rules != nil && spec.Rules.ToolAccess != nil {
		if presence.Rules == nil || presence.Rules.ToolAccess == nil || presence.Rules.ToolAccess.Enabled == nil {
			spec.Rules.ToolAccess.Enabled = true
		}
	}
	if spec.Rules != nil && spec.Rules.BrowserAutomation != nil {
		if presence.Rules == nil || presence.Rules.BrowserAutomation == nil || presence.Rules.BrowserAutomation.CredentialDetection == nil {
			spec.Rules.BrowserAutomation.CredentialDetection = true
		}
	}
	// Origin profile rule blocks are tri-state overlays (D12): they carry no
	// `enabled` flag and their `default` stays unset unless the document
	// states one, so no defaults are materialized for them here.
}

// Marshal serializes a HushSpec document to YAML.
func Marshal(spec *HushSpec) (string, error) {
	data, err := yaml.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("failed to marshal HushSpec to YAML: %w", err)
	}
	return string(data), nil
}
