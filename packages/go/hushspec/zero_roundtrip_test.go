package hushspec

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestExplicitZeroDefaultsSurviveSerializationAndMerge(t *testing.T) {
	policy := `hushspec: '1.0.0'
rules:
  forbidden_paths: {enabled: false}
  egress: {enabled: false}
  secret_patterns: {enabled: false}
  patch_integrity: {enabled: false, max_additions: 0, max_deletions: 0, max_imbalance_ratio: 0}
  shell_commands: {enabled: false}
  tool_access: {enabled: false}
  remote_desktop_channels: {audio: false}
  browser_automation: {credential_detection: false}
`
	spec, err := Parse(policy)
	if err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, got *HushSpec) {
		t.Helper()
		if !reflect.DeepEqual(spec.Rules, got.Rules) {
			t.Fatalf("explicit zero/false values changed: want %#v, got %#v", spec, got)
		}
	}
	t.Run("yaml", func(t *testing.T) {
		encoded, err := Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(encoded)
		if err != nil {
			t.Fatal(err)
		}
		check(t, got)
	})
	t.Run("json", func(t *testing.T) {
		encoded, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(string(encoded))
		if err != nil {
			t.Fatal(err)
		}
		check(t, got)
	})
	for _, strategy := range []MergeStrategy{MergeStrategyDeepMerge, MergeStrategyMerge, MergeStrategyReplace} {
		t.Run(string(strategy), func(t *testing.T) {
			child := &HushSpec{HushSpecVersion: "1.0.0", MergeStrategy: strategy}
			if strategy == MergeStrategyReplace {
				copy := *spec
				copy.MergeStrategy = strategy
				child = &copy
			}
			check(t, Merge(spec, child))
		})
	}
}
