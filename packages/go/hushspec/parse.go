package hushspec

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Parse parses a YAML string into a HushSpec document.
//
// It validates that the document is well-formed YAML and that the required
// "hushspec" version field is present. Structural validation (version
// support, cross-field constraints, etc.) is performed separately by
// [Validate].
//
// Limitation: gopkg.in/yaml.v3 does not natively reject unknown fields
// the way encoding/json's DisallowUnknownFields does. Unknown YAML keys
// are silently ignored during unmarshalling. Use [Validate] for stricter
// checking of the parsed result.
func Parse(yamlStr string) (*HushSpec, error) {
	var spec HushSpec
	err := yaml.Unmarshal([]byte(yamlStr), &spec)
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
