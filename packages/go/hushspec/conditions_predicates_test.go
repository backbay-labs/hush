package hushspec

import (
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// capability and rate predicates (core spec 3.13)
// --------------------------------------------------------------------------

func TestIsCapabilityIdentifier(t *testing.T) {
	valid := []string{"shell", "tool_call", "a", "a1", "net.egress", "a_b.c9_d"}
	for _, name := range valid {
		if !IsCapabilityIdentifier(name) {
			t.Errorf("%q should be a valid identifier", name)
		}
	}
	invalid := []string{"", "Shell", "Shell-Access", "9lives", "_lead", "a..b", "a.", ".a", "a b", "a-b"}
	for _, name := range invalid {
		if IsCapabilityIdentifier(name) {
			t.Errorf("%q should not be a valid identifier", name)
		}
	}
}

func TestCapabilityPredicateIsUnevaluableWithoutPosture(t *testing.T) {
	condition := &Condition{Capability: "shell"}
	// No posture extension: unevaluable, so the block stays active.
	if !EvaluateCondition(condition, &RuntimeContext{}) {
		t.Error("a capability predicate with no posture state must hold")
	}
	if !EvaluateConditionWithCapabilities(condition, &RuntimeContext{}, []string{"tool_call", "shell"}, true) {
		t.Error("a granted capability must satisfy the predicate")
	}
	if EvaluateConditionWithCapabilities(condition, &RuntimeContext{}, []string{"tool_call"}, true) {
		t.Error("an ungranted capability must fail the predicate")
	}
	// An unknown state grants nothing.
	if EvaluateConditionWithCapabilities(condition, &RuntimeContext{}, nil, true) {
		t.Error("an unknown posture state grants nothing")
	}
}

func TestCapabilityPredicateUnderCompoundOperators(t *testing.T) {
	granted := []string{"shell"}
	cases := []struct {
		name      string
		condition Condition
		want      bool
	}{
		{"not of a granted capability", Condition{Not: &Condition{Capability: "shell"}}, false},
		{"not of an ungranted capability", Condition{Not: &Condition{Capability: "net"}}, true},
		{"any_of reaches a granted leaf", Condition{AnyOf: []Condition{{Capability: "net"}, {Capability: "shell"}}}, true},
		{"all_of fails on an ungranted leaf", Condition{AllOf: []Condition{{Capability: "shell"}, {Capability: "net"}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateConditionWithCapabilities(&tc.condition, &RuntimeContext{}, granted, true)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRatePredicate(t *testing.T) {
	gte := &Condition{Rate: &RateCondition{Counter: "calls", Threshold: 5, Comparison: RateComparisonGte}}
	lt := &Condition{Rate: &RateCondition{Counter: "calls", Threshold: 5, Comparison: RateComparisonLt}}

	cases := []struct {
		name      string
		condition *Condition
		counters  map[string]uint64
		want      bool
	}{
		{"gte at the threshold", gte, map[string]uint64{"calls": 5}, true},
		{"gte above the threshold", gte, map[string]uint64{"calls": 9}, true},
		{"gte below the threshold", gte, map[string]uint64{"calls": 4}, false},
		{"lt below the threshold", lt, map[string]uint64{"calls": 4}, true},
		{"lt at the threshold", lt, map[string]uint64{"calls": 5}, false},
		// An absent counter is unevaluable and must not switch the block off.
		{"absent counter holds", gte, map[string]uint64{"other": 1}, true},
		{"no counters at all holds", gte, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateCondition(tc.condition, &RuntimeContext{Counters: tc.counters})
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidateConditionRejectsBadIdentifiers(t *testing.T) {
	errs := ValidateCondition(&Condition{Capability: "Shell-Access"}, "rules.egress.when")
	if len(errs) != 1 || !strings.Contains(errs[0], "is not a capability identifier") {
		t.Fatalf("unexpected errors: %v", errs)
	}
	errs = ValidateCondition(&Condition{
		Rate: &RateCondition{Counter: "9lives", Threshold: 1, Comparison: RateComparisonGte},
	}, "rules.egress.when")
	if len(errs) != 1 || !strings.Contains(errs[0], "is not a counter identifier") {
		t.Fatalf("unexpected errors: %v", errs)
	}
	// A leaf predicate adds no nesting: eight levels of `not` around one is fine.
	deep := &Condition{Capability: "shell"}
	for i := 0; i < 8; i++ {
		deep = &Condition{Not: deep}
	}
	if errs := ValidateCondition(deep, "rules.egress.when"); len(errs) != 0 {
		t.Fatalf("eight levels of nesting must validate: %v", errs)
	}
}

// TestPostureTransitionPriority locks in posture spec 5.3: a transition whose
// `from` names the current state outranks a wildcard listed before it.
func TestPostureTransitionPriority(t *testing.T) {
	posture := &PostureExtension{
		Initial: "standard",
		Transitions: []PostureTransition{
			{From: "*", To: "locked", On: "critical_violation"},
			{From: "standard", To: "restricted", On: "critical_violation"},
		},
	}
	if got := nextPostureState(posture, "standard", "critical_violation"); got != "restricted" {
		t.Errorf("named-from transition must win: got %q", got)
	}
	if got := nextPostureState(posture, "elevated", "critical_violation"); got != "locked" {
		t.Errorf("the wildcard applies where no named transition exists: got %q", got)
	}
	if got := nextPostureState(posture, "standard", "clean_scan"); got != "" {
		t.Errorf("an unmatched trigger has no transition: got %q", got)
	}
}
