package hushspec

import (
	"testing"
)

func strPtr(s string) *string { return &s }

// ---------------------------------------------------------------------------
// S1: conditions context value-matching parity (matchValueGo / valuesEqual /
// matchesScalarOrMembership must mirror Rust's match_value).
// ---------------------------------------------------------------------------

func TestConditionArrayVsArrayIntersection(t *testing.T) {
	cond := &Condition{
		Context: map[string]interface{}{
			"user.groups": []interface{}{"admins", "ml-team"},
		},
	}
	// Actual context field is itself an array: match on a non-empty
	// intersection with the expected array.
	match := &RuntimeContext{User: map[string]interface{}{
		"groups": []interface{}{"ml-team", "sre"},
	}}
	if !EvaluateCondition(cond, match) {
		t.Error("expected array-vs-array with a shared element to match (intersection)")
	}

	disjoint := &RuntimeContext{User: map[string]interface{}{
		"groups": []interface{}{"sre", "oncall"},
	}}
	if EvaluateCondition(cond, disjoint) {
		t.Error("expected array-vs-array with no shared element to NOT match")
	}
}

func TestConditionNumberArrayMembership(t *testing.T) {
	cond := &Condition{
		Context: map[string]interface{}{
			"session.action_count": []interface{}{1, 2, 3},
		},
	}
	member := &RuntimeContext{Session: map[string]interface{}{"action_count": 2}}
	if !EvaluateCondition(cond, member) {
		t.Error("expected numeric scalar that is a member of the expected array to match")
	}
	nonMember := &RuntimeContext{Session: map[string]interface{}{"action_count": 9}}
	if EvaluateCondition(cond, nonMember) {
		t.Error("expected numeric scalar that is not a member to NOT match")
	}
}

func TestConditionBoolArrayMembership(t *testing.T) {
	cond := &Condition{
		Context: map[string]interface{}{
			"request.interactive": []interface{}{true},
		},
	}
	member := &RuntimeContext{Request: map[string]interface{}{"interactive": true}}
	if !EvaluateCondition(cond, member) {
		t.Error("expected bool scalar that is a member of the expected array to match")
	}
	nonMember := &RuntimeContext{Request: map[string]interface{}{"interactive": false}}
	if EvaluateCondition(cond, nonMember) {
		t.Error("expected bool scalar that is not a member to NOT match")
	}
}

// ---------------------------------------------------------------------------
// S2: reject the same exotic/non-portable regex constructs everywhere.
// ---------------------------------------------------------------------------

func TestRejectsNonPortableRegexConstructs(t *testing.T) {
	rejected := []string{
		`a*+`, `a++`, `a?+`, // possessive quantifiers
		`a{2}+`, `a{2,}+`, `a{2,3}+`, // possessive braces
		`foo\Z`, `foo\z`, // \Z / \z end-anchors
		`[]`, `[^]`, // empty character classes
	}
	for _, pattern := range rejected {
		if secretPatternValidates(pattern) {
			t.Errorf("pattern %q should be rejected as non-portable across the SDK regex engines", pattern)
		}
	}
}

func TestDisallowedRegexFeatureFiresBeforeCompile(t *testing.T) {
	// `\z` is a valid RE2 construct that Go would otherwise accept, so a
	// rejection here proves the portability pre-check ran rather than the RE2
	// compile step.
	if _, bad := disallowedRegexFeature(`foo\z`); !bad {
		t.Error("expected the portability pre-check to reject foo\\z")
	}
	// Possessive brace: the trailing `+` after a valid `{n,m}` brace.
	if _, bad := disallowedRegexFeature(`a{2,3}+`); !bad {
		t.Error("expected the portability pre-check to reject possessive brace a{2,3}+")
	}
	// A benign bounded brace (no trailing +) and escaped literals must pass.
	if _, bad := disallowedRegexFeature(`a{2,3}`); bad {
		t.Error("bounded brace a{2,3} must not be flagged")
	}
	if _, bad := disallowedRegexFeature(`\[\]`); bad {
		t.Error("escaped literal brackets \\[\\] must not be flagged as an empty class")
	}
}

// ---------------------------------------------------------------------------
// S3: exfiltration detector ASCII-only ssn/email; fullwidth-digit SSN scores 0.
// ---------------------------------------------------------------------------

func TestExfiltrationFullwidthSSNScoresZero(t *testing.T) {
	detector := NewRegexExfiltrationDetector()

	// Fullwidth digits (U+FF11..) must NOT match the ASCII-only [0-9] ssn body.
	fullwidth := detector.Detect("SSN: １２３-４５-６７８９")
	if fullwidth.Score != 0 {
		t.Errorf("expected fullwidth-digit SSN to score 0, got %v (patterns: %+v)", fullwidth.Score, fullwidth.MatchedPatterns)
	}

	// Control: an ASCII SSN must still match.
	ascii := detector.Detect("SSN: 123-45-6789")
	found := false
	for _, p := range ascii.MatchedPatterns {
		if p.Name == "ssn" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ASCII SSN to match the ssn pattern, got patterns: %+v", ascii.MatchedPatterns)
	}
}

// ---------------------------------------------------------------------------
// D3: an empty (or unknown) posture.current denies as an unknown state,
// while an absent current falls back to the initial state.
// ---------------------------------------------------------------------------

func postureSpecForParity() *HushSpec {
	return &HushSpec{
		HushSpecVersion: "0.1.0",
		Extensions: &Extensions{
			Posture: &PostureExtension{
				Initial: "normal",
				States: map[string]PostureState{
					"normal": {Capabilities: []string{"file_access"}},
				},
				Transitions: []PostureTransition{},
			},
		},
	}
}

func TestEmptyPostureCurrentDenies(t *testing.T) {
	spec := postureSpecForParity()

	// Explicit empty current -> unknown state "" -> deny (fail-closed).
	empty := Evaluate(spec, &EvaluationAction{
		Type:    "file_read",
		Target:  "/etc/hosts",
		Posture: &PostureContext{Current: strPtr("")},
	})
	if empty.Decision != DecisionDeny {
		t.Errorf("expected empty posture.current to deny, got %q (rule %q)", empty.Decision, empty.MatchedRule)
	}

	// Absent current -> falls back to the initial state, which allows.
	absent := Evaluate(spec, &EvaluationAction{
		Type:    "file_read",
		Target:  "/etc/hosts",
		Posture: &PostureContext{Current: nil},
	})
	if absent.Decision != DecisionAllow {
		t.Errorf("expected absent posture.current to fall back to initial and allow, got %q", absent.Decision)
	}

	// A non-empty unknown state also denies (regression control).
	unknown := Evaluate(spec, &EvaluationAction{
		Type:    "file_read",
		Target:  "/etc/hosts",
		Posture: &PostureContext{Current: strPtr("bogus")},
	})
	if unknown.Decision != DecisionDeny {
		t.Errorf("expected unknown posture.current to deny, got %q", unknown.Decision)
	}
}

// ---------------------------------------------------------------------------
// D4: a present-but-empty match field (e.g. `provider: ""`) is a real,
// unsatisfiable constraint in the reference SDKs. Because the generated Go
// model collapses "" and an absent field, Go rejects the empty sentinel at
// parse. An all-absent match must still match every origin with score 0.
// ---------------------------------------------------------------------------

func TestOriginMatchEmptyProviderRejected(t *testing.T) {
	empty := "hushspec: \"0.1.0\"\nextensions:\n  origins:\n    profiles:\n      - id: p\n        match:\n          provider: \"\"\n"
	if _, err := Parse(empty); err == nil {
		t.Error("expected an empty match.provider sentinel to be rejected at parse")
	}

	valid := "hushspec: \"0.1.0\"\nextensions:\n  origins:\n    profiles:\n      - id: p\n        match:\n          provider: slack\n"
	if _, err := Parse(valid); err != nil {
		t.Errorf("expected a valid match.provider to parse, got: %v", err)
	}
}

// TestOriginMatchAllAbsentStillSelects guards against regressing the score-0
// selection of an all-absent match rule (which Rust/TS/Python match with
// score 0), the exact shape the differential generator produces.
func TestOriginMatchAllAbsentStillSelects(t *testing.T) {
	spec := &HushSpec{
		HushSpecVersion: "0.1.0",
		Extensions: &Extensions{
			Origins: &OriginsExtension{
				Profiles: []OriginProfile{
					{ID: "catchall", Match: &OriginMatch{}},
				},
			},
		},
	}
	result := Evaluate(spec, &EvaluationAction{
		Type:   "tool_call",
		Target: "some.tool",
		Origin: &OriginContext{Provider: "slack"},
	})
	if result.OriginProfile != "catchall" {
		t.Errorf("expected an all-absent match to select with score 0, got %q", result.OriginProfile)
	}
}

// ---------------------------------------------------------------------------
// D5: non-integer floats in integer-typed fields are rejected at parse.
// ---------------------------------------------------------------------------

func TestRejectsNonIntegerFloatIntegerFields(t *testing.T) {
	rejected := map[string]string{
		"max_additions":   "hushspec: \"0.1.0\"\nrules:\n  patch_integrity:\n    max_additions: 1.5\n",
		"max_args_size":   "hushspec: \"0.1.0\"\nrules:\n  tool_access:\n    max_args_size: 2.5\n",
		"posture_budget":  "hushspec: \"0.1.0\"\nextensions:\n  posture:\n    initial: a\n    states:\n      a:\n        budgets:\n          tool_calls: 1.5\n    transitions: []\n",
		"block_threshold": "hushspec: \"0.1.0\"\nextensions:\n  detection:\n    jailbreak:\n      block_threshold: 1.5\n",
		"policy_version":  "hushspec: \"0.1.0\"\nmetadata:\n  policy_version: 1.5\n",
	}
	for name, doc := range rejected {
		if _, err := Parse(doc); err == nil {
			t.Errorf("%s: expected a non-integer float to be rejected at parse", name)
		}
	}

	// Control: an integer value parses cleanly.
	if _, err := Parse("hushspec: \"0.1.0\"\nrules:\n  patch_integrity:\n    max_additions: 2\n"); err != nil {
		t.Errorf("expected integer max_additions to parse, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Validation gaps: empty-string enum sentinels, invalid classification /
// lifecycle_state enums, and a posture missing its required transitions key.
// ---------------------------------------------------------------------------

func TestRejectsEmptyAndInvalidOriginVisibility(t *testing.T) {
	empty := "hushspec: \"0.1.0\"\nextensions:\n  origins:\n    profiles:\n      - id: p\n        match:\n          visibility: \"\"\n"
	if _, err := Parse(empty); err == nil {
		t.Error("expected empty match.visibility to be rejected")
	}

	invalid := "hushspec: \"0.1.0\"\nextensions:\n  origins:\n    profiles:\n      - id: p\n        match:\n          visibility: bogus\n"
	if _, err := Parse(invalid); err == nil {
		t.Error("expected invalid match.visibility to be rejected")
	}

	valid := "hushspec: \"0.1.0\"\nextensions:\n  origins:\n    profiles:\n      - id: p\n        match:\n          visibility: internal\n"
	if _, err := Parse(valid); err != nil {
		t.Errorf("expected valid match.visibility to parse, got: %v", err)
	}
}

func TestRejectsInvalidClassificationAndLifecycle(t *testing.T) {
	cases := []string{
		"hushspec: \"0.1.0\"\nmetadata:\n  classification: bogus\n",
		"hushspec: \"0.1.0\"\nmetadata:\n  classification: \"\"\n",
		"hushspec: \"0.1.0\"\nmetadata:\n  lifecycle_state: bogus\n",
		"hushspec: \"0.1.0\"\nmetadata:\n  lifecycle_state: \"\"\n",
	}
	for _, doc := range cases {
		if _, err := Parse(doc); err == nil {
			t.Errorf("expected invalid metadata enum to be rejected: %q", doc)
		}
	}

	valid := "hushspec: \"0.1.0\"\nmetadata:\n  classification: confidential\n  lifecycle_state: approved\n"
	if _, err := Parse(valid); err != nil {
		t.Errorf("expected valid classification/lifecycle_state to parse, got: %v", err)
	}
}

func TestRejectsPostureMissingTransitions(t *testing.T) {
	missing := "hushspec: \"0.1.0\"\nextensions:\n  posture:\n    initial: normal\n    states:\n      normal:\n        capabilities: [file_access]\n"
	if _, err := Parse(missing); err == nil {
		t.Error("expected a posture without a transitions key to be rejected")
	}

	// An explicitly empty transitions list is allowed.
	present := "hushspec: \"0.1.0\"\nextensions:\n  posture:\n    initial: normal\n    states:\n      normal:\n        capabilities: [file_access]\n    transitions: []\n"
	spec, err := Parse(present)
	if err != nil {
		t.Fatalf("expected posture with empty transitions to parse, got: %v", err)
	}
	if result := Validate(spec); !result.IsValid() {
		t.Fatalf("expected posture with empty transitions to validate, got: %+v", result.Errors)
	}
}
