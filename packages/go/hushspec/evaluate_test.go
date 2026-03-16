package hushspec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type evaluatorTestFixture struct {
	HushSpecTest string                     `yaml:"hushspec_test"`
	Description  string                     `yaml:"description"`
	Policy       map[string]any             `yaml:"policy"`
	Cases        []evaluatorTestFixtureCase `yaml:"cases"`
}

type evaluatorTestFixtureCase struct {
	Description string         `yaml:"description"`
	Action      map[string]any `yaml:"action"`
	Expect      struct {
		Decision      string         `yaml:"decision"`
		MatchedRule   string         `yaml:"matched_rule,omitempty"`
		OriginProfile string         `yaml:"origin_profile,omitempty"`
		Posture       *PostureResult `yaml:"posture,omitempty"`
	} `yaml:"expect"`
}

func TestEvaluationFixtures(t *testing.T) {
	repoRoot := evaluatorRepoRoot(t)

	dirs := []string{
		"core/evaluation",
		"posture/evaluation",
		"origins/evaluation",
	}

	for _, dir := range dirs {
		fixtureDir := filepath.Join(repoRoot, "fixtures", dir)
		entries, err := os.ReadDir(fixtureDir)
		if err != nil {
			t.Logf("skipping %s: %v", dir, err)
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml")) {
				continue
			}

			fixturePath := filepath.Join(fixtureDir, entry.Name())
			t.Run(filepath.Join(dir, entry.Name()), func(t *testing.T) {
				data, err := os.ReadFile(fixturePath)
				if err != nil {
					t.Fatalf("failed to read fixture %s: %v", fixturePath, err)
				}

				var fixture evaluatorTestFixture
				if err := yaml.Unmarshal(data, &fixture); err != nil {
					t.Fatalf("failed to parse fixture %s: %v", fixturePath, err)
				}

				policyBytes, err := yaml.Marshal(fixture.Policy)
				if err != nil {
					t.Fatalf("failed to re-encode policy: %v", err)
				}
				spec, err := Parse(string(policyBytes))
				if err != nil {
					t.Fatalf("embedded policy failed to parse: %v", err)
				}

				for i, tc := range fixture.Cases {
					t.Run(fmt.Sprintf("case_%d_%s", i, tc.Description), func(t *testing.T) {
						action := buildEvaluationAction(t, tc.Action)
						result := Evaluate(spec, action)

						if string(result.Decision) != tc.Expect.Decision {
							t.Errorf("decision mismatch: got %q, want %q (action: %+v)",
								result.Decision, tc.Expect.Decision, tc.Action)
						}

						if tc.Expect.MatchedRule != "" && result.MatchedRule != tc.Expect.MatchedRule {
							t.Errorf("matched_rule mismatch: got %q, want %q",
								result.MatchedRule, tc.Expect.MatchedRule)
						}

						if tc.Expect.OriginProfile != "" && result.OriginProfile != tc.Expect.OriginProfile {
							t.Errorf("origin_profile mismatch: got %q, want %q",
								result.OriginProfile, tc.Expect.OriginProfile)
						}

						if tc.Expect.Posture != nil {
							if result.Posture == nil {
								t.Errorf("expected posture %+v, got nil", tc.Expect.Posture)
							} else {
								if result.Posture.Current != tc.Expect.Posture.Current {
									t.Errorf("posture.current mismatch: got %q, want %q",
										result.Posture.Current, tc.Expect.Posture.Current)
								}
								if result.Posture.Next != tc.Expect.Posture.Next {
									t.Errorf("posture.next mismatch: got %q, want %q",
										result.Posture.Next, tc.Expect.Posture.Next)
								}
							}
						}
					})
				}
			})
		}
	}
}

func TestEvaluateUnknownActionType(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
	}
	action := &EvaluationAction{Type: "unknown_action"}
	result := Evaluate(spec, action)
	if result.Decision != DecisionAllow {
		t.Errorf("expected allow for unknown action type, got %q", result.Decision)
	}
	if result.Reason != "no reference evaluator rule for this action type" {
		t.Errorf("unexpected reason: %q", result.Reason)
	}
}

func TestGlobMatches(t *testing.T) {
	tests := []struct {
		pattern string
		target  string
		match   bool
	}{
		{"*.com", "example.com", true},
		{"*.com", "sub.example.com", true}, // * matches any non-/ chars, including dots
		{"**/.ssh/**", "/home/user/.ssh/id_rsa", true},
		{"**/.ssh/**", "/home/user/.ssh/config", true},
		{"read_file", "read_file", true},
		{"read_file", "read_files", false},
		{"?oo", "foo", true},
		{"?oo", "fooo", false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_vs_%s", tt.pattern, tt.target), func(t *testing.T) {
			got := globMatches(tt.pattern, tt.target)
			if got != tt.match {
				t.Errorf("globMatches(%q, %q) = %v, want %v", tt.pattern, tt.target, got, tt.match)
			}
		})
	}
}

func TestImbalanceRatio(t *testing.T) {
	tests := []struct {
		add, del int
		expected float64
	}{
		{0, 0, 0.0},
		{0, 5, 5.0},
		{5, 0, 5.0},
		{10, 2, 5.0},
		{2, 10, 5.0},
		{4, 4, 1.0},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d_%d", tt.add, tt.del), func(t *testing.T) {
			got := imbalanceRatio(tt.add, tt.del)
			if got != tt.expected {
				t.Errorf("imbalanceRatio(%d, %d) = %f, want %f", tt.add, tt.del, got, tt.expected)
			}
		})
	}
}

func TestPatchStats(t *testing.T) {
	content := "--- a/file.rs\n+++ b/file.rs\n@@ -1,3 +1,5 @@\n fn main() {\n+    println!(\"hello\");\n+    println!(\"world\");\n }"
	stats := computePatchStats(content)
	if stats.additions != 2 {
		t.Errorf("expected 2 additions, got %d", stats.additions)
	}
	if stats.deletions != 0 {
		t.Errorf("expected 0 deletions, got %d", stats.deletions)
	}
}

func TestEvaluateEgressDisabledAllowsAction(t *testing.T) {
	spec, err := Parse(`
hushspec: "0.1.0"
rules:
  egress:
    enabled: false
    allow: []
    block: []
    default: block
`)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	result := Evaluate(spec, &EvaluationAction{Type: "egress", Target: "blocked.example.com"})
	if result.Decision != DecisionAllow {
		t.Fatalf("expected disabled egress rule to allow, got %q (%s)", result.Decision, result.Reason)
	}
	if result.MatchedRule != "" {
		t.Fatalf("expected no matched rule for disabled egress, got %q", result.MatchedRule)
	}
}

func buildEvaluationAction(t *testing.T, actionMap map[string]any) *EvaluationAction {
	t.Helper()
	jsonBytes, err := json.Marshal(actionMap)
	if err != nil {
		t.Fatalf("failed to marshal action map to JSON: %v", err)
	}

	var action EvaluationAction
	if err := json.Unmarshal(jsonBytes, &action); err != nil {
		t.Fatalf("failed to unmarshal action from JSON: %v", err)
	}
	return &action
}

func evaluatorRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	root := filepath.Clean(filepath.Join(wd, "../../.."))
	if _, err := os.Stat(filepath.Join(root, "fixtures")); err != nil {
		t.Fatalf("cannot find fixtures directory at %s: %v", root, err)
	}
	return root
}
