package hushspec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var (
	validFixtureDirs = []string{
		"core/valid",
		"posture/valid",
		"origins/valid",
		"detection/valid",
	}
	invalidFixtureDirs = []string{
		"core/invalid",
		"posture/invalid",
		"origins/invalid",
		"detection/invalid",
	}
	evaluationFixtureDirs = []string{
		"core/evaluation",
		"posture/evaluation",
		"origins/evaluation",
	}
	mergeFixtureDirs = []string{
		"core/merge",
		"posture/merge",
		"origins/merge",
		"detection/merge",
	}
)

type evaluationFixture struct {
	HushSpecTest string                  `yaml:"hushspec_test"`
	Description  string                  `yaml:"description"`
	Policy       map[string]any          `yaml:"policy"`
	Cases        []evaluationFixtureCase `yaml:"cases"`
}

type evaluationFixtureCase struct {
	Description string         `yaml:"description"`
	Action      map[string]any `yaml:"action"`
	Expect      struct {
		Decision string `yaml:"decision"`
	} `yaml:"expect"`
}

func TestSharedFixtures(t *testing.T) {
	repoRoot := fixtureRepoRoot(t)

	for _, dir := range validFixtureDirs {
		for _, fixturePath := range fixtureFiles(t, repoRoot, dir) {
			t.Run("valid/"+filepath.ToSlash(strings.TrimPrefix(fixturePath, repoRoot+string(os.PathSeparator))), func(t *testing.T) {
				spec := parseFixtureOrFail(t, fixturePath)
				if result := Validate(spec); !result.IsValid() {
					t.Fatalf("%s: expected valid fixture, got errors: %+v", fixturePath, result.Errors)
				}
			})
		}
	}

	for _, dir := range invalidFixtureDirs {
		for _, fixturePath := range fixtureFiles(t, repoRoot, dir) {
			t.Run("invalid/"+filepath.ToSlash(strings.TrimPrefix(fixturePath, repoRoot+string(os.PathSeparator))), func(t *testing.T) {
				spec, err := Parse(readFixtureOrFail(t, fixturePath))
				if err == nil {
					if result := Validate(spec); result.IsValid() {
						t.Fatalf("%s: expected rejection", fixturePath)
					}
				}
			})
		}
	}

	for _, dir := range mergeFixtureDirs {
		basePath := filepath.Join(repoRoot, "fixtures", dir, "base.yaml")
		if _, err := os.Stat(basePath); err != nil {
			continue
		}
		base := parseFixtureOrFail(t, basePath)

		for _, childPath := range fixtureFiles(t, repoRoot, dir) {
			if !strings.HasPrefix(filepath.Base(childPath), "child-") {
				continue
			}
			expectedPath := filepath.Join(filepath.Dir(childPath), strings.Replace(filepath.Base(childPath), "child-", "expected-", 1))
			t.Run("merge/"+filepath.ToSlash(strings.TrimPrefix(childPath, repoRoot+string(os.PathSeparator))), func(t *testing.T) {
				expected := parseFixtureOrFail(t, expectedPath)
				merged := Merge(base, parseFixtureOrFail(t, childPath))
				assertSpecsEqual(t, merged, expected)
			})
		}
	}

	for _, dir := range evaluationFixtureDirs {
		for _, fixturePath := range fixtureFiles(t, repoRoot, dir) {
			t.Run("evaluation/"+filepath.ToSlash(strings.TrimPrefix(fixturePath, repoRoot+string(os.PathSeparator))), func(t *testing.T) {
				var fixture evaluationFixture
				if err := yaml.Unmarshal([]byte(readFixtureOrFail(t, fixturePath)), &fixture); err != nil {
					t.Fatalf("%s: failed to parse evaluator fixture: %v", fixturePath, err)
				}
				if fixture.HushSpecTest != "0.1.0" {
					t.Fatalf("%s: expected hushspec_test 0.1.0, got %q", fixturePath, fixture.HushSpecTest)
				}
				if strings.TrimSpace(fixture.Description) == "" {
					t.Fatalf("%s: evaluator fixture description must be non-empty", fixturePath)
				}
				if len(fixture.Cases) == 0 {
					t.Fatalf("%s: evaluator fixture must define at least one case", fixturePath)
				}
				for index, testCase := range fixture.Cases {
					if strings.TrimSpace(testCase.Description) == "" {
						t.Fatalf("%s: cases[%d] description must be non-empty", fixturePath, index)
					}
					if !slices.Contains([]string{"allow", "warn", "deny"}, testCase.Expect.Decision) {
						t.Fatalf("%s: cases[%d].expect.decision must be allow, warn, or deny", fixturePath, index)
					}
					if _, ok := testCase.Action["type"].(string); !ok {
						t.Fatalf("%s: cases[%d].action.type must be a string", fixturePath, index)
					}
				}

				policyBytes, err := yaml.Marshal(fixture.Policy)
				if err != nil {
					t.Fatalf("%s: failed to re-encode policy: %v", fixturePath, err)
				}
				spec, err := Parse(string(policyBytes))
				if err != nil {
					t.Fatalf("%s: embedded policy failed to parse: %v", fixturePath, err)
				}
				if result := Validate(spec); !result.IsValid() {
					t.Fatalf("%s: embedded policy failed validation: %+v", fixturePath, result.Errors)
				}
			})
		}
	}
}

func fixtureRepoRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test file path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "../../.."))
}

func fixtureFiles(t *testing.T, repoRoot, subdir string) []string {
	t.Helper()
	dir := filepath.Join(repoRoot, "fixtures", subdir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			files = append(files, filepath.Join(dir, name))
		}
	}
	slices.Sort(files)
	return files
}

func readFixtureOrFail(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: failed to read fixture: %v", path, err)
	}
	return string(data)
}

func parseFixtureOrFail(t *testing.T, path string) *HushSpec {
	t.Helper()
	spec, err := Parse(readFixtureOrFail(t, path))
	if err != nil {
		t.Fatalf("%s: failed to parse fixture: %v", path, err)
	}
	return spec
}

func assertSpecsEqual(t *testing.T, actual, expected *HushSpec) {
	t.Helper()
	actualJSON, err := json.Marshal(actual)
	if err != nil {
		t.Fatalf("failed to marshal actual merged spec: %v", err)
	}
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatalf("failed to marshal expected merged spec: %v", err)
	}
	if string(actualJSON) != string(expectedJSON) {
		t.Fatalf("merged output mismatch\nactual:   %s\nexpected: %s", actualJSON, expectedJSON)
	}
}
