package hushspec

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Parse parses a YAML string into a HushSpec document.
//
// It validates that the document is well-formed YAML, rejects unknown fields,
// and requires the top-level "hushspec" version field to be present.
// Cross-field validation (supported versions, range checks, etc.) is
// performed separately by [Validate].
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
	return &spec, nil
}

// Marshal serialises a HushSpec document back to YAML.
func Marshal(spec *HushSpec) (string, error) {
	data, err := yaml.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("failed to marshal HushSpec to YAML: %w", err)
	}
	return string(data), nil
}
