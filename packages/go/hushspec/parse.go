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
	} `yaml:"rules"`
	Extensions *struct {
		Origins *struct {
			Profiles []struct {
				Egress *struct {
					Enabled *bool          `yaml:"enabled"`
					Default *DefaultAction `yaml:"default"`
				} `yaml:"egress"`
				ToolAccess *struct {
					Enabled *bool `yaml:"enabled"`
				} `yaml:"tool_access"`
			} `yaml:"profiles"`
		} `yaml:"origins"`
	} `yaml:"extensions"`
}

// Parse decodes a YAML string into a HushSpec document. Unknown fields are
// rejected and the top-level "hushspec" version key must be present.
// Cross-field validation is performed separately by [Validate].
func Parse(yamlStr string) (*HushSpec, error) {
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
	if spec.Extensions != nil && spec.Extensions.Origins != nil && presence.Extensions != nil && presence.Extensions.Origins != nil {
		for index := range spec.Extensions.Origins.Profiles {
			if spec.Extensions.Origins.Profiles[index].Egress != nil {
				if index >= len(presence.Extensions.Origins.Profiles) || presence.Extensions.Origins.Profiles[index].Egress == nil || presence.Extensions.Origins.Profiles[index].Egress.Enabled == nil {
					spec.Extensions.Origins.Profiles[index].Egress.Enabled = true
				}
				if index >= len(presence.Extensions.Origins.Profiles) || presence.Extensions.Origins.Profiles[index].Egress == nil || presence.Extensions.Origins.Profiles[index].Egress.Default == nil {
					spec.Extensions.Origins.Profiles[index].Egress.Default = DefaultActionBlock
				}
			}
			if spec.Extensions.Origins.Profiles[index].ToolAccess != nil {
				if index >= len(presence.Extensions.Origins.Profiles) || presence.Extensions.Origins.Profiles[index].ToolAccess == nil || presence.Extensions.Origins.Profiles[index].ToolAccess.Enabled == nil {
					spec.Extensions.Origins.Profiles[index].ToolAccess.Enabled = true
				}
			}
		}
	}
}

// Marshal serializes a HushSpec document to YAML.
func Marshal(spec *HushSpec) (string, error) {
	data, err := yaml.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("failed to marshal HushSpec to YAML: %w", err)
	}
	return string(data), nil
}
