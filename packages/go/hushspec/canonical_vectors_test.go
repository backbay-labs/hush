package hushspec

import (
	"path/filepath"
	"strconv"
	"testing"

	"gopkg.in/yaml.v3"
)

// hashVectorVersion is the `hushspec_hash_vector` format version this runner
// understands (schemas/hushspec-hash-vector.v1.schema.json).
const hashVectorVersion = "0.1.0"

// expectedHashVectors is the size of the normative vector set; keep it in step
// with the table in fixtures/core/hash/README.md.
const expectedHashVectors = 14

// hashVector mirrors schemas/hushspec-hash-vector.v1.schema.json. `source` is
// informational -- it records the unresolved document `policy` came from -- so
// it is not decoded here.
type hashVector struct {
	Version     string         `yaml:"hushspec_hash_vector"`
	Description string         `yaml:"description"`
	Policy      map[string]any `yaml:"policy"`
	Canonical   string         `yaml:"canonical"`
	ContentHash string         `yaml:"content_hash"`
}

// TestCanonicalHashVectors runs the normative canonical-form vectors from
// fixtures/core/hash (spec/hushspec-canonical.md section 7). Every vector's
// `policy` is a resolved document; the expected `canonical` text and
// `content_hash` must be reproduced byte for byte.
func TestCanonicalHashVectors(t *testing.T) {
	repoRoot := fixtureRepoRoot(t)
	files := fixtureFiles(t, repoRoot, "core/hash")
	if len(files) != expectedHashVectors {
		t.Fatalf("expected %d canonical hash vectors under %s, found %d", expectedHashVectors,
			filepath.Join(repoRoot, "fixtures", "core", "hash"), len(files))
	}

	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			var vector hashVector
			if err := yaml.Unmarshal([]byte(readFixtureOrFail(t, path)), &vector); err != nil {
				t.Fatalf("%s: failed to decode vector: %v", path, err)
			}
			if vector.Version != hashVectorVersion {
				t.Fatalf("%s: unsupported hushspec_hash_vector version %q", path, vector.Version)
			}

			spec := parseVectorPolicy(t, path, vector.Policy)

			// Only valid documents have a canonical form (spec section 2.3);
			// a vector no conformant engine accepts would pin a hash no engine
			// can produce.
			if result := Validate(spec); !result.IsValid() {
				t.Fatalf("%s: vector policy is not a valid document: %v", path, result.Errors)
			}

			canonical, err := CanonicalJSON(spec)
			if err != nil {
				t.Fatalf("%s: CanonicalJSON failed: %v", path, err)
			}
			if canonical != vector.Canonical {
				t.Fatalf("%s: canonical JSON mismatch\n%s", path,
					canonicalDiff(vector.Canonical, canonical))
			}

			digest, err := ContentHash(spec)
			if err != nil {
				t.Fatalf("%s: ContentHash failed: %v", path, err)
			}
			if digest != vector.ContentHash {
				t.Fatalf("%s: content_hash mismatch\n  expected %s\n  actual   %s",
					path, vector.ContentHash, digest)
			}
		})
	}
}

// parseVectorPolicy runs a vector's policy through the same pipeline the SDK
// uses elsewhere: re-encode to YAML, parse, and -- for a vector whose policy
// still carries `extends` -- flatten the chain with the composite loader,
// which serves `builtin:<name>` from the embedded rulesets. Vectors today
// carry resolved policies (extends-resolved.yaml keeps the unresolved child in
// the informational `source` field), so the resolve branch is a guard against
// a future vector, not a live path.
func parseVectorPolicy(t *testing.T, path string, policy map[string]any) *HushSpec {
	t.Helper()
	encoded, err := yaml.Marshal(policy)
	if err != nil {
		t.Fatalf("%s: failed to re-encode policy: %v", path, err)
	}
	spec, err := Parse(string(encoded))
	if err != nil {
		t.Fatalf("%s: failed to parse policy: %v", path, err)
	}
	if spec.Extends != "" {
		resolved, err := Resolve(spec, "", nil)
		if err != nil {
			t.Fatalf("%s: failed to resolve policy: %v", path, err)
		}
		spec = resolved
	}
	return spec
}

// canonicalDiff renders the first divergence between two canonical strings
// with a window of surrounding context, so a failure points at the offending
// member instead of dumping two long single-line JSON documents.
func canonicalDiff(expected, actual string) string {
	i := 0
	for i < len(expected) && i < len(actual) && expected[i] == actual[i] {
		i++
	}
	const context = 60
	start := i - context
	if start < 0 {
		start = 0
	}
	window := func(s string) string {
		end := i + context
		if end > len(s) {
			end = len(s)
		}
		prefix, suffix := "", ""
		if start > 0 {
			prefix = "..."
		}
		if end < len(s) {
			suffix = "..."
		}
		return prefix + s[start:end] + suffix
	}
	return "  first difference at byte " + strconv.Itoa(i) + "\n" +
		"  expected " + window(expected) + "\n" +
		"  actual   " + window(actual)
}
