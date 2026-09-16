package hushspec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// The normative policy-bundle vectors (spec/hushspec-bundle.md section 7,
// fixtures/bundle/). An implementation conforms as a bundle verifier exactly
// when every case here returns the expected outcome, so this runner is the Go
// SDK's conformance statement for bundle verification.

// bundleVectorsVersion is the manifest version this runner understands.
const bundleVectorsVersion = "0.1.0"

// bundleVectorCaseCount is the number of cases the specification's table
// enumerates. Pinning it means a vector added upstream cannot be silently
// skipped by a runner that only iterates what it finds.
const bundleVectorCaseCount = 8

type bundleVectorFile struct {
	Version     string               `yaml:"hushspec_bundle_vectors"`
	Description string               `yaml:"description"`
	Defaults    bundleVectorDefaults `yaml:"defaults"`
	Cases       []bundleVectorCase   `yaml:"cases"`
}

type bundleVectorDefaults struct {
	Keyring string `yaml:"keyring"`
	Now     string `yaml:"now"`
}

type bundleVectorCase struct {
	Name    string    `yaml:"name"`
	Bundle  string    `yaml:"bundle"`
	Keyring string    `yaml:"keyring"`
	Policy  string    `yaml:"policy"`
	Now     string    `yaml:"now"`
	Expect  yaml.Node `yaml:"expect"`
	Note    string    `yaml:"note"`
}

// expectation reads the manifest's untagged `expect`: the scalar `valid`, or
// a mapping `{invalid: <reason code>}`.
func (c *bundleVectorCase) expectation(t *testing.T) string {
	t.Helper()
	var scalar string
	if err := c.Expect.Decode(&scalar); err == nil {
		if scalar != "valid" {
			t.Fatalf("%s: expect %q is neither \"valid\" nor an invalid mapping", c.Name, scalar)
		}
		return "valid"
	}
	var invalid struct {
		Invalid string `yaml:"invalid"`
	}
	if err := c.Expect.Decode(&invalid); err != nil || invalid.Invalid == "" {
		t.Fatalf("%s: expect is not {invalid: <reason code>}", c.Name)
	}
	return invalid.Invalid
}

func loadBundleVectors(t *testing.T) (string, *bundleVectorFile) {
	t.Helper()
	root := filepath.Join(fixtureRepoRoot(t), "fixtures", "bundle")
	raw, err := os.ReadFile(filepath.Join(root, "vectors.yaml"))
	if err != nil {
		t.Fatalf("failed to read the bundle vector manifest: %v", err)
	}
	var manifest bundleVectorFile
	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("failed to parse the bundle vector manifest: %v", err)
	}
	if manifest.Version != bundleVectorsVersion {
		t.Fatalf("manifest version %q, this runner understands %q",
			manifest.Version, bundleVectorsVersion)
	}
	if len(manifest.Cases) != bundleVectorCaseCount {
		t.Fatalf("bundle spec 7 publishes %d vectors, the manifest lists %d",
			bundleVectorCaseCount, len(manifest.Cases))
	}
	return root, &manifest
}

// TestBundleVectors walks fixtures/bundle/vectors.yaml: every case must return
// its expected outcome, valid or the expected reason code of bundle spec 5.4.
func TestBundleVectors(t *testing.T) {
	root, manifest := loadBundleVectors(t)

	for _, tc := range manifest.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			keyringPath := tc.Keyring
			if keyringPath == "" {
				keyringPath = manifest.Defaults.Keyring
			}
			keyringJSON, err := os.ReadFile(filepath.Join(root, keyringPath))
			if err != nil {
				t.Fatalf("failed to read the keyring: %v", err)
			}
			keyring, err := LoadKeyring(keyringJSON)
			if err != nil {
				t.Fatalf("the keyring did not load: %v", err)
			}

			nowText := tc.Now
			if nowText == "" {
				nowText = manifest.Defaults.Now
			}
			now, err := time.Parse(time.RFC3339, nowText)
			if err != nil {
				t.Fatalf("%q is not a timestamp: %v", nowText, err)
			}

			bundle, err := os.ReadFile(filepath.Join(root, tc.Bundle))
			if err != nil {
				t.Fatalf("failed to read the bundle: %v", err)
			}

			options := VerifyBundleOptions{Keyring: keyring, Now: now}
			if tc.Policy != "" {
				// Every vector that names a policy names one that resolves, so a
				// resolution failure is a broken fixture. Treating it as check 4's
				// own failure would let a vector expecting policy_mismatch pass
				// without the verifier ever running.
				resolution, resolveErr := ResolveFileWithOptions(
					filepath.Join(root, tc.Policy), ResolveOptions{})
				if resolveErr != nil {
					t.Fatalf("the vector names a policy that does not resolve: %v", resolveErr)
				}
				options.PolicyResolution = resolution
			}

			result := VerifyBundle(bundle, options)
			actual := result.Reason
			if result.OK {
				actual = "valid"
			}

			want := tc.expectation(t)
			if actual != want {
				t.Errorf("expected %s, got %s (%s)", want, actual, result.Detail)
			}
			if result.OK != (want == "valid") {
				t.Errorf("OK=%v but the expected outcome is %q", result.OK, want)
			}
			if result.OK && result.Reason != "" {
				t.Errorf("a valid bundle carries no reason code, got %q", result.Reason)
			}
			if want == "valid" {
				if len(result.KeyIDs) == 0 {
					t.Error("a valid bundle names at least one verifying key")
				}
				if result.PolicyChecked != (tc.Policy != "") {
					t.Errorf("PolicyChecked=%v for policy %q", result.PolicyChecked, tc.Policy)
				}
				if result.VerifiedAt != "2026-09-15T12:00:00.000Z" {
					t.Errorf("verified_at should stamp the verifier's clock, got %q", result.VerifiedAt)
				}
			}
		})
	}
}

// TestBundleVectorsUseTheClosedReasonSet keeps the manifest and this SDK on
// one vocabulary: a typo in a vector cannot pass as a new code, and every code
// the specification defines is exercised by some vector.
func TestBundleVectorsUseTheClosedReasonSet(t *testing.T) {
	_, manifest := loadBundleVectors(t)

	known := map[string]bool{}
	for _, reason := range BundleReasons {
		known[reason] = true
	}
	covered := map[string]bool{}
	for _, tc := range manifest.Cases {
		expected := tc.expectation(t)
		if expected == "valid" {
			continue
		}
		if !known[expected] {
			t.Errorf("%s: %q is not a bundle spec 5.4 reason code", tc.Name, expected)
		}
		covered[expected] = true
	}
	for _, reason := range BundleReasons {
		if !covered[reason] {
			t.Errorf("no vector expects %s", reason)
		}
	}
}

// TestBundlesValidateAgainstTheSchema checks every published bundle against
// schemas/hushspec-bundle.v0.schema.json: the envelope against the root, and
// the decoded payload against $defs/Statement. This SDK carries no JSON Schema
// engine, so the constraints the schema states for the members it reads are
// asserted directly -- the three `const` members are read out of the schema
// itself, so a bundle, a Go constant and the published schema cannot drift
// apart unnoticed.
func TestBundlesValidateAgainstTheSchema(t *testing.T) {
	root, manifest := loadBundleVectors(t)
	schemaPath := filepath.Join(fixtureRepoRoot(t), "schemas", "hushspec-bundle.v0.schema.json")
	schemaJSON, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("the bundle schema is not published: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(schemaJSON, &schema); err != nil {
		t.Fatalf("the bundle schema is not JSON: %v", err)
	}

	// The constants this SDK compares against are the schema's own, so a
	// divergence between the two is a failure here rather than a silent
	// disagreement with every other implementation.
	payloadType := schemaConst(t, schema, "properties", "payloadType")
	statementType := schemaConst(t, schema, "$defs", "Statement", "properties", "_type")
	predicateType := schemaConst(t, schema, "$defs", "Statement", "properties", "predicateType")
	for _, pin := range []struct{ schema, sdk string }{
		{payloadType, BundlePayloadType},
		{statementType, BundleStatementType},
		{predicateType, BundlePredicateType},
	} {
		if pin.schema != pin.sdk {
			t.Fatalf("the schema pins %q where this SDK uses %q", pin.schema, pin.sdk)
		}
	}

	seen := map[string]bool{}
	for _, tc := range manifest.Cases {
		if seen[tc.Bundle] {
			continue
		}
		seen[tc.Bundle] = true
		t.Run(tc.Bundle, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, tc.Bundle))
			if err != nil {
				t.Fatalf("failed to read the bundle: %v", err)
			}
			envelope, err := ParseBundle(data)
			if err != nil {
				t.Fatalf("every published bundle is a well-formed envelope: %v", err)
			}
			if envelope.PayloadType != payloadType {
				t.Errorf("payloadType %q, the schema pins %q", envelope.PayloadType, payloadType)
			}
			payload, err := envelope.PayloadBytes()
			if err != nil {
				t.Fatalf("the payload does not decode: %v", err)
			}
			// malformed-predicate-type is deliberately a statement this build
			// rejects, so only its envelope half is asserted here.
			var statement BundleStatement
			if err := strictUnmarshalJSON(payload, &statement); err != nil {
				t.Fatalf("the payload is not a statement: %v", err)
			}
			if len(statement.Subject) != 1 {
				t.Errorf("a bundle attests exactly one subject, found %d", len(statement.Subject))
			}
			if statement.Type != statementType {
				t.Errorf("_type %q, the schema pins %q", statement.Type, statementType)
			}
			if len(statement.Predicate.Chain) == 0 {
				t.Error("the chain must hold at least one link")
			}
		})
	}
}

// schemaConst reads the `const` of the schema member at path, failing when the
// path does not lead to one.
func schemaConst(t *testing.T, schema map[string]any, path ...string) string {
	t.Helper()
	node := schema
	for _, segment := range path {
		next, ok := node[segment].(map[string]any)
		if !ok {
			t.Fatalf("the bundle schema has no object at %s", strings.Join(path, "."))
		}
		node = next
	}
	value, ok := node["const"].(string)
	if !ok {
		t.Fatalf("the bundle schema member at %s has no string const", strings.Join(path, "."))
	}
	return value
}
