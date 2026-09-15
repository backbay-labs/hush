package hushspec

import (
	"testing"
)

func ctxWithEnv(env string) *RuntimeContext {
	return &RuntimeContext{Environment: env}
}

func ctxWithTimeStr(t string) *RuntimeContext {
	return &RuntimeContext{CurrentTime: t}
}

func ctxWithUserRole(role string) *RuntimeContext {
	return &RuntimeContext{
		User: map[string]interface{}{"role": role},
	}
}

func makeEgressSpecForCond() *HushSpec {
	return &HushSpec{
		HushSpecVersion: "0.1.0",
		Name:            "conditional-test",
		Rules: &Rules{
			Egress: &EgressRule{
				Enabled: true,
				Allow:   []string{"api.openai.com"},
				Default: DefaultActionBlock,
			},
		},
	}
}

func TestContextConditionMatchesEnvironment(t *testing.T) {
	cond := &Condition{
		Context: map[string]interface{}{"environment": "production"},
	}
	if !EvaluateCondition(cond, ctxWithEnv("production")) {
		t.Error("expected condition to match production environment")
	}
}

func TestContextConditionRejectsMismatch(t *testing.T) {
	cond := &Condition{
		Context: map[string]interface{}{"environment": "production"},
	}
	if EvaluateCondition(cond, ctxWithEnv("staging")) {
		t.Error("expected condition to reject staging environment")
	}
}

func TestContextConditionMissingFieldFailsClosed(t *testing.T) {
	cond := &Condition{
		Context: map[string]interface{}{"user.role": "admin"},
	}
	if EvaluateCondition(cond, &RuntimeContext{}) {
		t.Error("expected missing field to fail closed")
	}
}

func TestContextConditionMatchesUserRole(t *testing.T) {
	cond := &Condition{
		Context: map[string]interface{}{"user.role": "admin"},
	}
	if !EvaluateCondition(cond, ctxWithUserRole("admin")) {
		t.Error("expected admin to match")
	}
	if EvaluateCondition(cond, ctxWithUserRole("viewer")) {
		t.Error("expected viewer to not match")
	}
}

func TestContextConditionArrayOrMatch(t *testing.T) {
	cond := &Condition{
		Context: map[string]interface{}{
			"environment": []interface{}{"production", "staging"},
		},
	}
	if !EvaluateCondition(cond, ctxWithEnv("production")) {
		t.Error("expected production to match")
	}
	if !EvaluateCondition(cond, ctxWithEnv("staging")) {
		t.Error("expected staging to match")
	}
	if EvaluateCondition(cond, ctxWithEnv("development")) {
		t.Error("expected development to not match")
	}
}

func TestContextConditionScalarVsArrayMembership(t *testing.T) {
	ctx := &RuntimeContext{
		User: map[string]interface{}{
			"groups": []interface{}{"engineering", "ml-team"},
		},
	}
	cond := &Condition{
		Context: map[string]interface{}{"user.groups": "ml-team"},
	}
	if !EvaluateCondition(cond, ctx) {
		t.Error("expected ml-team to be found in groups array")
	}
}

func TestTimeWindowMatchesDuringBusinessHours(t *testing.T) {
	ctx := ctxWithTimeStr("2026-01-14T10:30:00Z")
	cond := &Condition{
		TimeWindow: &TimeWindowCondition{
			Start:    "09:00",
			End:      "17:00",
			Timezone: "UTC",
		},
	}
	if !EvaluateCondition(cond, ctx) {
		t.Error("expected business hours to match")
	}
}

func TestTimeWindowRejectsOutsideHours(t *testing.T) {
	ctx := ctxWithTimeStr("2026-01-14T20:00:00Z")
	cond := &Condition{
		TimeWindow: &TimeWindowCondition{
			Start:    "09:00",
			End:      "17:00",
			Timezone: "UTC",
		},
	}
	if EvaluateCondition(cond, ctx) {
		t.Error("expected outside hours to not match")
	}
}

func TestTimeWindowDayFilter(t *testing.T) {
	// 2026-01-14 is a Wednesday
	ctx := ctxWithTimeStr("2026-01-14T10:00:00Z")

	condWeekday := &Condition{
		TimeWindow: &TimeWindowCondition{
			Start:    "09:00",
			End:      "17:00",
			Timezone: "UTC",
			Days:     []string{"mon", "tue", "wed", "thu", "fri"},
		},
	}
	if !EvaluateCondition(condWeekday, ctx) {
		t.Error("expected weekday match on Wednesday")
	}

	condWeekend := &Condition{
		TimeWindow: &TimeWindowCondition{
			Start:    "09:00",
			End:      "17:00",
			Timezone: "UTC",
			Days:     []string{"sat", "sun"},
		},
	}
	if EvaluateCondition(condWeekend, ctx) {
		t.Error("expected weekend to not match on Wednesday")
	}
}

func TestTimeWindowWrapsMidnight(t *testing.T) {
	cond := &Condition{
		TimeWindow: &TimeWindowCondition{
			Start:    "22:00",
			End:      "06:00",
			Timezone: "UTC",
		},
	}

	if !EvaluateCondition(cond, ctxWithTimeStr("2026-01-14T23:00:00Z")) {
		t.Error("expected 23:00 to match night window")
	}
	if !EvaluateCondition(cond, ctxWithTimeStr("2026-01-14T03:00:00Z")) {
		t.Error("expected 03:00 to match night window")
	}
	if EvaluateCondition(cond, ctxWithTimeStr("2026-01-14T10:00:00Z")) {
		t.Error("expected 10:00 to not match night window")
	}
}

func TestTimeWindowSameStartEndMeansAllDay(t *testing.T) {
	cond := &Condition{
		TimeWindow: &TimeWindowCondition{
			Start:    "12:00",
			End:      "12:00",
			Timezone: "UTC",
		},
	}
	if !EvaluateCondition(cond, ctxWithTimeStr("2026-01-14T03:00:00Z")) {
		t.Error("expected same start/end to match all day")
	}
}

func TestTimeWindowSupportsMinuteOffsets(t *testing.T) {
	cond := &Condition{
		TimeWindow: &TimeWindowCondition{
			Start:    "05:30",
			End:      "06:30",
			Timezone: "+05:30",
		},
	}
	if !EvaluateCondition(cond, ctxWithTimeStr("2026-01-14T00:15:00Z")) {
		t.Error("expected +05:30 offset to match inside the window")
	}
	if EvaluateCondition(cond, ctxWithTimeStr("2026-01-14T01:15:00Z")) {
		t.Error("expected +05:30 offset to reject outside the window")
	}
}

func TestTimeWindowUsesDSTForIANATimezones(t *testing.T) {
	cond := &Condition{
		TimeWindow: &TimeWindowCondition{
			Start:    "08:30",
			End:      "09:30",
			Timezone: "America/New_York",
		},
	}
	if !EvaluateCondition(cond, ctxWithTimeStr("2026-01-14T13:45:00Z")) {
		t.Error("expected winter New York time to match")
	}
	if !EvaluateCondition(cond, ctxWithTimeStr("2026-07-14T12:45:00Z")) {
		t.Error("expected summer New York time to match under DST")
	}
}

func TestTimeWindowLoadsIANAZonesFromTzdata(t *testing.T) {
	// Neither zone is in the fixedTimezoneOffsets fallback table, so these
	// assertions only pass if time.LoadLocation finds a tz database. That is
	// what the blank `time/tzdata` import in conditions.go guarantees on
	// scratch/distroless images and Windows, which ship no system zoneinfo --
	// without it LoadLocation errors and the condition fails closed.
	newYork := &Condition{
		TimeWindow: &TimeWindowCondition{
			Start:    "09:00",
			End:      "10:00",
			Timezone: "America/New_York",
		},
	}
	// 09:30 in New York, winter (UTC-5) and summer (UTC-4).
	if !EvaluateCondition(newYork, ctxWithTimeStr("2026-01-14T14:30:00Z")) {
		t.Error("expected America/New_York to resolve in winter")
	}
	if !EvaluateCondition(newYork, ctxWithTimeStr("2026-07-14T13:30:00Z")) {
		t.Error("expected America/New_York to resolve under DST")
	}
	if EvaluateCondition(newYork, ctxWithTimeStr("2026-01-14T09:30:00Z")) {
		t.Error("expected America/New_York to reject outside the window")
	}

	kolkata := &Condition{
		TimeWindow: &TimeWindowCondition{
			Start:    "09:00",
			End:      "10:00",
			Timezone: "Asia/Kolkata",
		},
	}
	// 09:30 in Kolkata (UTC+5:30 year-round).
	if !EvaluateCondition(kolkata, ctxWithTimeStr("2026-01-14T04:00:00Z")) {
		t.Error("expected Asia/Kolkata to resolve inside the window")
	}
	if EvaluateCondition(kolkata, ctxWithTimeStr("2026-01-14T09:30:00Z")) {
		t.Error("expected Asia/Kolkata to reject outside the window")
	}
}

func TestTimeWindowWrapsMidnightWithDayFilter(t *testing.T) {
	cond := &Condition{
		TimeWindow: &TimeWindowCondition{
			Start:    "22:00",
			End:      "06:00",
			Timezone: "UTC",
			Days:     []string{"fri"},
		},
	}
	if !EvaluateCondition(cond, ctxWithTimeStr("2026-01-17T03:00:00Z")) {
		t.Error("expected Saturday early-morning time to count as Friday night")
	}
}

func TestTimeWindowInvalidTimezoneFailsClosed(t *testing.T) {
	cond := &Condition{
		TimeWindow: &TimeWindowCondition{
			Start:    "09:00",
			End:      "17:00",
			Timezone: "America/NeYork",
		},
	}
	if EvaluateCondition(cond, ctxWithTimeStr("2026-01-14T13:30:00Z")) {
		t.Error("expected invalid timezone to fail closed")
	}
}

func TestAllOfRequiresAllConditions(t *testing.T) {
	cond := &Condition{
		AllOf: []Condition{
			{Context: map[string]interface{}{"environment": "production"}},
			{Context: map[string]interface{}{"user.role": "admin"}},
		},
	}

	fullCtx := &RuntimeContext{
		Environment: "production",
		User:        map[string]interface{}{"role": "admin"},
	}
	if !EvaluateCondition(cond, fullCtx) {
		t.Error("expected both conditions to match")
	}

	if EvaluateCondition(cond, ctxWithEnv("production")) {
		t.Error("expected partial match to fail")
	}
}

func TestAnyOfRequiresAnyCondition(t *testing.T) {
	cond := &Condition{
		AnyOf: []Condition{
			{Context: map[string]interface{}{"environment": "production"}},
			{Context: map[string]interface{}{"environment": "staging"}},
		},
	}

	if !EvaluateCondition(cond, ctxWithEnv("production")) {
		t.Error("expected production to match")
	}
	if !EvaluateCondition(cond, ctxWithEnv("staging")) {
		t.Error("expected staging to match")
	}
	if EvaluateCondition(cond, ctxWithEnv("development")) {
		t.Error("expected development to not match")
	}
}

func TestNotNegatesCondition(t *testing.T) {
	cond := &Condition{
		Not: &Condition{
			Context: map[string]interface{}{"environment": "production"},
		},
	}

	if EvaluateCondition(cond, ctxWithEnv("production")) {
		t.Error("expected NOT production to fail")
	}
	if !EvaluateCondition(cond, ctxWithEnv("staging")) {
		t.Error("expected NOT production to pass for staging")
	}
}

func TestNestedCompoundConditions(t *testing.T) {
	cond := &Condition{
		AllOf: []Condition{
			{
				TimeWindow: &TimeWindowCondition{
					Start:    "09:00",
					End:      "17:00",
					Timezone: "UTC",
				},
			},
			{Context: map[string]interface{}{"environment": "production"}},
			{
				AnyOf: []Condition{
					{Context: map[string]interface{}{"user.role": "admin"}},
					{Context: map[string]interface{}{"user.role": "sre"}},
				},
			},
		},
	}

	ctx := &RuntimeContext{
		Environment: "production",
		CurrentTime: "2026-01-14T10:00:00Z",
		User:        map[string]interface{}{"role": "admin"},
	}
	if !EvaluateCondition(cond, ctx) {
		t.Error("expected nested compound to match")
	}

	ctxViewer := &RuntimeContext{
		Environment: "production",
		CurrentTime: "2026-01-14T10:00:00Z",
		User:        map[string]interface{}{"role": "viewer"},
	}
	if EvaluateCondition(cond, ctxViewer) {
		t.Error("expected viewer to fail nested compound")
	}
}

func TestEmptyConditionAlwaysTrue(t *testing.T) {
	cond := &Condition{}
	if !EvaluateCondition(cond, &RuntimeContext{}) {
		t.Error("expected empty condition to be true")
	}
}

func TestMaxNestingDepthExceeded(t *testing.T) {
	cond := &Condition{
		Context: map[string]interface{}{"environment": "production"},
	}
	for i := 0; i < 12; i++ {
		cond = &Condition{AllOf: []Condition{*cond}}
	}
	if EvaluateCondition(cond, ctxWithEnv("production")) {
		t.Error("expected max nesting to fail")
	}
}

func TestEvaluateWithContextPassesWhenConditionMet(t *testing.T) {
	spec := makeEgressSpecForCond()
	action := &EvaluationAction{Type: "egress", Target: "api.openai.com"}
	ctx := &RuntimeContext{Environment: "production"}
	conditions := map[string]*Condition{
		"egress": {Context: map[string]interface{}{"environment": "production"}},
	}

	result := EvaluateWithContext(spec, action, ctx, conditions)
	if result.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", result.Decision)
	}
}

func TestEvaluateWithContextSkipsRuleWhenConditionFails(t *testing.T) {
	spec := makeEgressSpecForCond()
	action := &EvaluationAction{Type: "egress", Target: "evil.example.com"}
	ctx := &RuntimeContext{Environment: "staging"}
	conditions := map[string]*Condition{
		"egress": {Context: map[string]interface{}{"environment": "production"}},
	}

	result := EvaluateWithContext(spec, action, ctx, conditions)
	if result.Decision != DecisionAllow {
		t.Errorf("expected allow (rule disabled), got %s", result.Decision)
	}
}

func TestEvaluateWithContextEnforcesRuleWhenConditionMet(t *testing.T) {
	spec := makeEgressSpecForCond()
	action := &EvaluationAction{Type: "egress", Target: "evil.example.com"}
	ctx := &RuntimeContext{Environment: "production"}
	conditions := map[string]*Condition{
		"egress": {Context: map[string]interface{}{"environment": "production"}},
	}

	result := EvaluateWithContext(spec, action, ctx, conditions)
	if result.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", result.Decision)
	}
}

func TestEvaluateWithContextNoConditionsBehavesLikeEvaluate(t *testing.T) {
	spec := makeEgressSpecForCond()
	action := &EvaluationAction{Type: "egress", Target: "evil.example.com"}
	ctx := &RuntimeContext{}
	conditions := map[string]*Condition{}

	result := EvaluateWithContext(spec, action, ctx, conditions)
	if result.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", result.Decision)
	}
}

func TestEvaluateWithContextMissingContextFailsClosed(t *testing.T) {
	spec := makeEgressSpecForCond()
	action := &EvaluationAction{Type: "egress", Target: "api.openai.com"}
	ctx := &RuntimeContext{}
	conditions := map[string]*Condition{
		"egress": {Context: map[string]interface{}{"environment": "production"}},
	}

	result := EvaluateWithContext(spec, action, ctx, conditions)
	if result.Decision != DecisionAllow {
		t.Errorf("expected allow (condition fails, rule disabled), got %s", result.Decision)
	}
}

func TestEvaluateWithContextCompoundCondition(t *testing.T) {
	spec := makeEgressSpecForCond()
	action := &EvaluationAction{Type: "egress", Target: "evil.example.com"}
	conditions := map[string]*Condition{
		"egress": {
			AllOf: []Condition{
				{Context: map[string]interface{}{"environment": "production"}},
				{Context: map[string]interface{}{"user.role": "admin"}},
			},
		},
	}

	fullCtx := &RuntimeContext{
		Environment: "production",
		User:        map[string]interface{}{"role": "admin"},
	}
	result := EvaluateWithContext(spec, action, fullCtx, conditions)
	if result.Decision != DecisionDeny {
		t.Errorf("expected deny, got %s", result.Decision)
	}

	partialCtx := &RuntimeContext{Environment: "production"}
	result2 := EvaluateWithContext(spec, action, partialCtx, conditions)
	if result2.Decision != DecisionAllow {
		t.Errorf("expected allow (partial condition fails), got %s", result2.Decision)
	}
}
