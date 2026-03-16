package hushspec

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type parsePresenceSpec struct {
	Rules *struct {
		Egress *struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"egress"`
	} `yaml:"rules"`
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
	if spec.Rules != nil && spec.Rules.Egress != nil {
		if presence.Rules == nil || presence.Rules.Egress == nil || presence.Rules.Egress.Enabled == nil {
			spec.Rules.Egress.Enabled = true
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
