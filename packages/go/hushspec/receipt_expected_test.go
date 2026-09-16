package hushspec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// Expected receipts.
//
// For every case of every shared evaluation fixture, fixtures/receipts/expected
// holds the format 0.2 receipt a conformant SDK MUST produce under the fixed
// inputs its README describes. This runner rebuilds each one and compares it
// byte for byte after RFC 8785 canonicalization, so pretty-printing and key
// order in the files do not matter and every field value does.

// expectedReceiptClockMillis is the fixed evaluation time of every expected
// receipt: 2026-09-15T12:00:00.000Z.
const expectedReceiptClockMillis = 1789473600000

// expectedReceiptModules are the shared fixture modules that carry evaluation
// vectors.
var expectedReceiptModules = []string{"core", "posture", "origins", "detection"}

// expectedReceiptContext is the fixed AuditContext of the vectors: a named
// actor, a trusted clock pinned to the evaluation time, and a receipt id
// derived from the 0-based case index.
func expectedReceiptContext(caseIndex int) *AuditContext {
	clock := time.UnixMilli(expectedReceiptClockMillis).UTC()
	return &AuditContext{
		Actor: &Actor{
			AgentID:   "fixture-agent",
			SessionID: "fixture-session",
			Principal: "fixture@hushspec.dev",
			Runtime:   "hushspec-conformance/0.2",
		},
		EnforcementMode: EnforcementModeEnforce,
		TimeSource:      TimeSourceTrusted,
		Clock:           func() time.Time { return clock },
		ReceiptID:       DeterministicUUIDv7(expectedReceiptClockMillis, uint64(caseIndex)),
	}
}

// expectedReceiptConfig records the trace but not the duration: a vector's
// bytes must not depend on the machine that produced them.
func expectedReceiptConfig() *AuditConfig {
	return &AuditConfig{Enabled: true, IncludeRuleTrace: true, RecordDuration: false}
}

func TestExpectedReceipts(t *testing.T) {
	root := fixtureRepoRoot(t)
	checked := 0

	for _, module := range expectedReceiptModules {
		dir := filepath.Join(root, "fixtures", module, "evaluation")
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("cannot read %s: %v", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".test.yaml") {
				continue
			}
			stem := strings.TrimSuffix(entry.Name(), ".test.yaml")
			fixturePath := filepath.Join(dir, entry.Name())
			expectedDir := filepath.Join(root, "fixtures", "receipts", "expected", module, stem)
			t.Run(module+"/"+stem, func(t *testing.T) {
				checked += runExpectedReceiptFixture(t, fixturePath, expectedDir)
			})
		}
	}

	if checked == 0 {
		t.Fatal("no evaluation fixtures were found")
	}
	t.Logf("compared %d expected receipts", checked)
}

func runExpectedReceiptFixture(t *testing.T, fixturePath, expectedDir string) int {
	t.Helper()
	source, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", fixturePath, err)
	}
	var fixture evaluatorTestFixture
	if err := yaml.Unmarshal(source, &fixture); err != nil {
		t.Fatalf("%s: cannot parse the fixture: %v", fixturePath, err)
	}

	policyYAML, err := yaml.Marshal(fixture.Policy)
	if err != nil {
		t.Fatalf("%s: cannot re-encode the policy: %v", fixturePath, err)
	}
	spec, err := Parse(string(policyYAML))
	if err != nil {
		t.Fatalf("%s: the embedded policy does not parse: %v", fixturePath, err)
	}
	// The fixture's inline policy is treated as already resolved: a
	// single-link resolution, so no extends_chain is recorded.
	resolution, err := NewResolutionFromResolved(spec, "")
	if err != nil {
		t.Fatalf("%s: %v", fixturePath, err)
	}

	for index, testCase := range fixture.Cases {
		action := buildEvaluationAction(t, testCase.Action)
		// The case's own `context` applies to the action when the action has
		// none of its own.
		if action.Context == nil {
			action.Context = testCase.Context
		}
		receipt := EvaluateAudited(resolution, action, expectedReceiptConfig(),
			expectedReceiptContext(index))

		path := filepath.Join(expectedDir, fmt.Sprintf("%d.json", index))
		expected, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("case %d: cannot read the expected receipt %s: %v", index, path, err)
			continue
		}
		wantCanonical, err := canonicalizeExpectedReceipt(expected)
		if err != nil {
			t.Errorf("case %d: %s: %v", index, path, err)
			continue
		}
		gotCanonical, err := receipt.CanonicalJSON()
		if err != nil {
			t.Errorf("case %d: cannot canonicalize the produced receipt: %v", index, err)
			continue
		}
		if gotCanonical != wantCanonical {
			t.Errorf("case %d (%s) does not match %s:\n want: %s\n  got: %s",
				index, testCase.Description, path, wantCanonical, gotCanonical)
		}
	}
	return len(fixture.Cases)
}

// canonicalizeExpectedReceipt parses a committed vector strictly -- so an
// expected receipt this SDK's model cannot represent is a failure rather than
// a silently dropped field -- and returns its canonical form.
func canonicalizeExpectedReceipt(data []byte) (string, error) {
	receipt, err := ParseReceipt(data)
	if err != nil {
		return "", err
	}
	canonical, err := receipt.CanonicalJSON()
	if err != nil {
		return "", err
	}
	// Belt and braces: the round trip through the typed model must not have
	// changed the document, so canonicalize the raw JSON too and compare.
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", err
	}
	rawCanonical, err := canonicalJSONValue(raw)
	if err != nil {
		return "", err
	}
	if rawCanonical != canonical {
		return "", fmt.Errorf(
			"the typed model does not round-trip the vector:\n file: %s\nmodel: %s",
			rawCanonical, canonical)
	}
	return canonical, nil
}
