package hushspec

// MergeStrategy controls how child policies combine with base policies.
type MergeStrategy string

const (
	// MergeStrategyReplace discards the base entirely and uses the child as-is.
	MergeStrategyReplace MergeStrategy = "replace"

	// MergeStrategyMerge performs a shallow merge: child top-level fields
	// override base top-level fields.
	MergeStrategyMerge MergeStrategy = "merge"

	// MergeStrategyDeepMerge recursively merges child fields into base fields.
	// This is the default strategy when none is specified.
	MergeStrategyDeepMerge MergeStrategy = "deep_merge"
)

// HushSpec is the top-level policy document. The HushSpecVersion field
// (serialised as "hushspec") is required and must match a supported schema
// version.
type HushSpec struct {
	HushSpecVersion string        `yaml:"hushspec" json:"hushspec"`
	Name            string        `yaml:"name,omitempty" json:"name,omitempty"`
	Description     string        `yaml:"description,omitempty" json:"description,omitempty"`
	Extends         string        `yaml:"extends,omitempty" json:"extends,omitempty"`
	MergeStrategy   MergeStrategy `yaml:"merge_strategy,omitempty" json:"merge_strategy,omitempty"`
	Rules           *Rules        `yaml:"rules,omitempty" json:"rules,omitempty"`
	Extensions      *Extensions   `yaml:"extensions,omitempty" json:"extensions,omitempty"`
}
