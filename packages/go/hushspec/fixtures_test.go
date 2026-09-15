package hushspec

import (
	"encoding/json"
	"errors"
	"io/fs"
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
		"detection/evaluation",
	}
	// mergeFixtureDirs are the merge vector directories that must exist. The
	// runner walks fixtures/ for every directory shaped like one (a base.yaml
	// beside at least one child-*.yaml), so a new vector set -- the
	// digest-pinned ones, say -- is picked up without editing this list; these
	// four are then asserted to still be among what was found, so a rename
	// cannot silently drop coverage instead.
	mergeFixtureDirs = []string{
		"core/merge",
		"posture/merge",
		"origins/merge",
		"detection/merge",
	}
)

// expectedErrorSidecarSuffix names the file beside an `invalid/` vector that
// says which registered error code its rejection must carry. A file with this
// suffix is metadata, never a vector.
const expectedErrorSidecarSuffix = ".expect.yaml"

// expectedError is a `<name>.expect.yaml` sidecar
// (schemas/hushspec-error-codes.v0.schema.json#/$defs/ExpectedError).
type expectedError struct {
	// Reject is always true: a sidecar describes a refusal and nothing else.
	Reject bool `yaml:"reject"`
	// Code is the registered code of spec/registries/error-codes.yaml.
	Code string `yaml:"code"`
	// MessageContains is an optional literal substring the diagnostic must
	// contain, for the broad codes where the code alone does not identify the
	// requirement.
	MessageContains string `yaml:"message_contains"`
}

// loadExpectedError reads the sidecar beside an `invalid/` vector. A missing
// sidecar returns nil; a present but unusable one fails the test, because a
// sidecar that cannot be read is a check that silently stops running.
func loadExpectedError(t *testing.T, vectorPath string) *expectedError {
	t.Helper()
	stem := strings.TrimSuffix(strings.TrimSuffix(vectorPath, ".yaml"), ".yml")
	data, err := os.ReadFile(stem + expectedErrorSidecarSuffix)
	if err != nil {
		return nil
	}
	var expected expectedError
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&expected); err != nil {
		t.Fatalf("%s%s: not an expected-error sidecar: %v", stem, expectedErrorSidecarSuffix, err)
	}
	if !expected.Reject {
		t.Fatalf("%s%s: `reject` must be true; a sidecar exists only to describe a refusal",
			stem, expectedErrorSidecarSuffix)
	}
	if !slices.Contains(ErrorCodes, expected.Code) {
		t.Fatalf("%s%s: %q is not a registered error code",
			stem, expectedErrorSidecarSuffix, expected.Code)
	}
	return &expected
}

// rejectFixture parses and validates a vector, returning the registered code
// and the message of the first refusal. Parse and Validate are one gate: a
// document either survives both or it is rejected.
func rejectFixture(t *testing.T, fixturePath string) (code, message string, rejected bool) {
	t.Helper()
	spec, err := Parse(readFixtureOrFail(t, fixturePath))
	if err != nil {
		found, ok := ErrorCodeOf(err)
		if !ok {
			t.Fatalf("%s: a refusal must carry a registered code, got %T: %v",
				fixturePath, err, err)
		}
		return found, err.Error(), true
	}
	if result := Validate(spec); !result.IsValid() {
		first := result.Errors[0]
		return first.Code, first.Message, true
	}
	return "", "", false
}

type evaluationFixture struct {
	HushSpecTest string                  `yaml:"hushspec_test"`
	Description  string                  `yaml:"description"`
	Policy       map[string]any          `yaml:"policy"`
	Cases        []evaluationFixtureCase `yaml:"cases"`
}

type evaluationFixtureCase struct {
	Description string          `yaml:"description"`
	Action      map[string]any  `yaml:"action"`
	Context     *RuntimeContext `yaml:"context,omitempty"`
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
			if strings.HasSuffix(fixturePath, expectedErrorSidecarSuffix) {
				continue
			}
			t.Run("invalid/"+filepath.ToSlash(strings.TrimPrefix(fixturePath, repoRoot+string(os.PathSeparator))), func(t *testing.T) {
				code, message, rejected := rejectFixture(t, fixturePath)
				if !rejected {
					t.Fatalf("%s: expected rejection", fixturePath)
				}
				// Every invalid vector carries a sidecar naming the registered
				// code its rejection must have (core spec 8, Level 1), so
				// "the document was rejected" is checked as "rejected for this
				// reason".
				expected := loadExpectedError(t, fixturePath)
				if expected == nil {
					t.Fatalf("%s: every invalid vector needs an %s sidecar",
						fixturePath, expectedErrorSidecarSuffix)
				}
				if code != expected.Code {
					t.Errorf("expected %s but the document was rejected with %s: %s",
						expected.Code, code, message)
				}
				if expected.MessageContains != "" && !strings.Contains(message, expected.MessageContains) {
					t.Errorf("%s was reported, but the message does not contain %q: %s",
						code, expected.MessageContains, message)
				}
			})
		}
	}

	discovered := discoverMergeFixtureDirs(t, repoRoot)
	for _, want := range mergeFixtureDirs {
		if !slices.Contains(discovered, want) {
			t.Fatalf("merge vector directory %q is no longer discoverable under fixtures/", want)
		}
	}

	for _, dir := range discovered {
		basePath := filepath.Join(repoRoot, "fixtures", dir, "base.yaml")
		base := parseFixtureOrFail(t, basePath)

		for _, childPath := range fixtureFiles(t, repoRoot, dir) {
			name := filepath.Base(childPath)
			// A per-child manifest sits next to the vector it describes and
			// shares its name, so it matches the child- prefix without being
			// a vector of its own.
			if !strings.HasPrefix(name, "child-") || isMergeFixtureManifest(name) {
				continue
			}
			expectedPath := filepath.Join(filepath.Dir(childPath), strings.Replace(filepath.Base(childPath), "child-", "expected-", 1))
			t.Run("merge/"+filepath.ToSlash(strings.TrimPrefix(childPath, repoRoot+string(os.PathSeparator))), func(t *testing.T) {
				merged, err := composeMergeFixture(basePath, base, childPath)

				if mergeFixtureExpectsReject(t, childPath) {
					if err == nil {
						t.Fatalf("%s: expected the vector to be rejected, got a merged document", childPath)
					}
					return
				}
				if err != nil {
					t.Fatalf("%s: merge vector failed: %v", childPath, err)
				}
				if _, statErr := os.Stat(expectedPath); statErr != nil {
					t.Fatalf(
						"%s: no %s and no expect-reject marker; a rejected vector needs an \"expect-reject\" file or \"reject: true\" in a fixture.yaml",
						childPath, filepath.Base(expectedPath),
					)
				}
				assertSpecsEqual(t, merged, parseFixtureOrFail(t, expectedPath))
			})
		}
	}

	for _, dir := range evaluationFixtureDirs {
		for _, fixturePath := range fixtureFiles(t, repoRoot, dir) {
			t.Run("evaluation/"+filepath.ToSlash(strings.TrimPrefix(fixturePath, repoRoot+string(os.PathSeparator))), func(t *testing.T) {
				source := readFixtureOrFail(t, fixturePath)
				var fixture evaluationFixture
				if err := yaml.Unmarshal([]byte(source), &fixture); err != nil {
					t.Fatalf("%s: failed to parse evaluator fixture: %v", fixturePath, err)
				}
				if !slices.Contains(supportedTestVersions, fixture.HushSpecTest) {
					t.Fatalf("%s: unsupported hushspec_test version %q (supported: %s)",
						fixturePath, fixture.HushSpecTest, strings.Join(supportedTestVersions, ", "))
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
					// The evaluator-test schema accepts any non-empty action
					// type so unknown-type vectors can assert their deny.
					actionType, ok := testCase.Action["type"].(string)
					if !ok || actionType == "" {
						t.Fatalf("%s: cases[%d].action.type must be a non-empty string", fixturePath, index)
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

				// Actually evaluate every case: the shared-fixture CI job runs
				// only this test, so shape-checking alone would let an
				// evaluator regression through.
				runEvaluationFixture(t, fixturePath, source)
			})
		}
	}
}

// isMergeFixtureManifest reports whether a file in a merge directory is a
// fixture.yaml manifest rather than a vector.
func isMergeFixtureManifest(name string) bool {
	return name == "fixture.yaml" || name == "fixture.yml" ||
		strings.HasSuffix(name, ".fixture.yaml") || strings.HasSuffix(name, ".fixture.yml")
}

// discoverMergeFixtureDirs finds every merge vector directory under fixtures/:
// one holding a base.yaml and at least one child-*.yaml. Discovery rather than
// a fixed list keeps this runner working when the shared fixtures grow a new
// set of merge vectors, which is the only way the Go SDK sees them.
func discoverMergeFixtureDirs(t *testing.T, repoRoot string) []string {
	t.Helper()
	root := filepath.Join(repoRoot, "fixtures")
	dirs := make([]string, 0, 8)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		if _, statErr := os.Stat(filepath.Join(path, "base.yaml")); statErr != nil {
			return nil
		}
		children, readErr := os.ReadDir(path)
		if readErr != nil {
			return readErr
		}
		for _, child := range children {
			if !child.IsDir() && strings.HasPrefix(child.Name(), "child-") {
				relative, relErr := filepath.Rel(root, path)
				if relErr != nil {
					return relErr
				}
				dirs = append(dirs, filepath.ToSlash(relative))
				return nil
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk the fixtures tree: %v", err)
	}
	slices.Sort(dirs)
	return dirs
}

// composeMergeFixture produces the merged document a merge vector asserts.
//
// The vectors overlay base.yaml with the child directly, because that is what
// they are testing. A child that pins its base by digest
// (`extends: base.yaml#sha256:...`) is resolved instead, so the pin is
// actually checked -- a mismatched pin then surfaces as the error an
// expect-reject vector wants.
func composeMergeFixture(basePath string, base *HushSpec, childPath string) (*HushSpec, error) {
	source, err := os.ReadFile(childPath)
	if err != nil {
		return nil, err
	}
	child, err := Parse(string(source))
	if err != nil {
		return nil, err
	}
	if !strings.Contains(child.Extends, "#sha256:") {
		return Merge(base, child), nil
	}
	resolution, err := ResolveWithOptions(child, childPath, mergeFixtureLoader(basePath), ResolveOptions{})
	if err != nil {
		return nil, err
	}
	return resolution.Spec, nil
}

// mergeFixtureLoader resolves a merge vector's extends reference to the
// vector's own base.yaml. Merge vectors name their base either way -- `base`
// or `base.yaml` -- so both are accepted; `builtin:` goes to the real loader.
func mergeFixtureLoader(basePath string) ResolveLoader {
	composite := createCompositeLoader()
	return func(reference string, from string) (*LoadedSpec, error) {
		if strings.HasPrefix(reference, "builtin:") {
			return composite(reference, from)
		}
		if reference == "base" || reference == "base.yaml" || reference == "base.yml" {
			reference = basePath
		}
		return composite(reference, from)
	}
}

// mergeFixtureExpectsReject reports whether a merge vector is supposed to fail.
// The shared fixtures spell it two ways and either may appear: an
// "expect-reject" marker file (beside the child, named for it or for the whole
// directory), or `reject: true` in a fixture.yaml manifest (per child or per
// directory).
func mergeFixtureExpectsReject(t *testing.T, childPath string) bool {
	t.Helper()
	dir := filepath.Dir(childPath)
	name := filepath.Base(childPath)
	stem := strings.TrimSuffix(name, filepath.Ext(name))

	for _, marker := range []string{
		childPath + ".expect-reject",
		filepath.Join(dir, stem+".expect-reject"),
		filepath.Join(dir, "expect-reject"),
	} {
		if _, err := os.Stat(marker); err == nil {
			return true
		}
	}

	for _, manifest := range []string{
		filepath.Join(dir, stem+".fixture.yaml"),
		filepath.Join(dir, "fixture.yaml"),
	} {
		if reject, found := mergeFixtureManifestRejects(t, manifest, name, stem); found {
			return reject
		}
	}
	return false
}

// mergeFixtureManifestRejects reads `reject` out of a fixture.yaml, looking for
// a per-child entry before the directory-wide flag. It reports whether it found
// a statement at all, so a manifest that says nothing about this child falls
// through to the next candidate.
func mergeFixtureManifestRejects(t *testing.T, path, name, stem string) (bool, bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return false, false
	}
	var manifest map[string]any
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("%s: failed to parse the merge fixture manifest: %v", path, err)
	}

	lookup := func(scope map[string]any) (bool, bool) {
		for _, key := range []string{name, stem} {
			entry, ok := scope[key].(map[string]any)
			if !ok {
				continue
			}
			if reject, ok := entry["reject"].(bool); ok {
				return reject, true
			}
		}
		return false, false
	}

	if reject, found := lookup(manifest); found {
		return reject, true
	}
	for _, group := range []string{"cases", "children", "files", "vectors"} {
		nested, ok := manifest[group].(map[string]any)
		if !ok {
			continue
		}
		if reject, found := lookup(nested); found {
			return reject, true
		}
	}
	if reject, ok := manifest["reject"].(bool); ok {
		return reject, true
	}
	return false, false
}

// supportedTestVersions are the `hushspec_test` fixture-format versions this
// runner accepts (schemas/hushspec-evaluator-test.v0.schema.json). 0.2.0 adds
// per-case controls and tags and the rule_trace / receipt assertions.
var supportedTestVersions = []string{"0.1.0", "0.2.0"}

// repoRoot is the checkout this package lives in, resolved from this source
// file's own path so it does not depend on the working directory. It takes no
// testing handle, so a benchmark can use it too.
func repoRoot() (string, error) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("failed to resolve the test file path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "../../..")), nil
}

func fixtureRepoRoot(t *testing.T) string {
	t.Helper()
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	return root
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
