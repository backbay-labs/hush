package hushspec

import (
	"strconv"
	"strings"
	"time"
)

const MaxNestingDepth = 8

type TimeWindowCondition struct {
	Start    string   `yaml:"start" json:"start"`                           // HH:MM (24-hour)
	End      string   `yaml:"end" json:"end"`                               // HH:MM (24-hour)
	Timezone string   `yaml:"timezone,omitempty" json:"timezone,omitempty"` // IANA tz, defaults to UTC
	Days     []string `yaml:"days,omitempty" json:"days,omitempty"`         // mon..sun
}

// Condition gates whether a rule block is active. All present fields are
// combined with AND semantics. Fail-closed: missing context fields evaluate
// to false.
type Condition struct {
	TimeWindow *TimeWindowCondition   `yaml:"time_window,omitempty" json:"time_window,omitempty"`
	Context    map[string]interface{} `yaml:"context,omitempty" json:"context,omitempty"`
	AllOf      []Condition            `yaml:"all_of,omitempty" json:"all_of,omitempty"`
	AnyOf      []Condition            `yaml:"any_of,omitempty" json:"any_of,omitempty"`
	Not        *Condition             `yaml:"not,omitempty" json:"not,omitempty"`
}

// RuntimeContext is the runtime context provided by the enforcement engine.
type RuntimeContext struct {
	User        map[string]interface{} `yaml:"user,omitempty" json:"user,omitempty"`
	Environment string                 `yaml:"environment,omitempty" json:"environment,omitempty"`
	Deployment  map[string]interface{} `yaml:"deployment,omitempty" json:"deployment,omitempty"`
	Agent       map[string]interface{} `yaml:"agent,omitempty" json:"agent,omitempty"`
	Session     map[string]interface{} `yaml:"session,omitempty" json:"session,omitempty"`
	Request     map[string]interface{} `yaml:"request,omitempty" json:"request,omitempty"`
	Custom      map[string]interface{} `yaml:"custom,omitempty" json:"custom,omitempty"`
	CurrentTime string                 `yaml:"current_time,omitempty" json:"current_time,omitempty"` // RFC3339; defaults to system time
}

// EvaluateCondition returns true if the condition is satisfied by the context.
func EvaluateCondition(condition *Condition, context *RuntimeContext) bool {
	return evaluateConditionDepth(condition, context, 0)
}

func evaluateConditionDepth(condition *Condition, context *RuntimeContext, depth int) bool {
	if depth > MaxNestingDepth {
		return false
	}

	if condition.TimeWindow != nil {
		if !checkTimeWindow(condition.TimeWindow, context) {
			return false
		}
	}

	if condition.Context != nil {
		if !checkContextMatch(condition.Context, context) {
			return false
		}
	}

	for _, c := range condition.AllOf {
		if !evaluateConditionDepth(&c, context, depth+1) {
			return false
		}
	}

	if len(condition.AnyOf) > 0 {
		found := false
		for _, c := range condition.AnyOf {
			if evaluateConditionDepth(&c, context, depth+1) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if condition.Not != nil {
		if evaluateConditionDepth(condition.Not, context, depth+1) {
			return false
		}
	}

	return true
}

func checkTimeWindow(tw *TimeWindowCondition, context *RuntimeContext) bool {
	now := resolveCurrentTimeForCondition(context, tw.Timezone)
	if now == nil {
		return false
	}

	hour, minute, dayOfWeek := now[0], now[1], now[2]

	startH, startM, ok := parseHHMM(tw.Start)
	if !ok {
		return false
	}
	endH, endM, ok := parseHHMM(tw.End)
	if !ok {
		return false
	}

	currentMinutes := hour*60 + minute
	startMinutes := startH*60 + startM
	endMinutes := endH*60 + endM
	wrapsMidnight := startMinutes > endMinutes

	if len(tw.Days) > 0 {
		effectiveDay := dayOfWeek
		if wrapsMidnight && currentMinutes < endMinutes {
			effectiveDay = (dayOfWeek + 6) % 7
		}
		dayAbbrev := dayAbbreviationCond(effectiveDay)
		found := false
		for _, d := range tw.Days {
			if strings.EqualFold(d, dayAbbrev) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if startMinutes == endMinutes {
		return true
	}
	if startMinutes < endMinutes {
		return currentMinutes >= startMinutes && currentMinutes < endMinutes
	}
	return currentMinutes >= startMinutes || currentMinutes < endMinutes
}

func parseHHMM(s string) (int, int, bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, 0, false
	}
	// Require pure ASCII digits in each component. strconv.Atoi otherwise
	// accepts a leading sign (e.g. "+9"), which TS (^\d+$) and Python
	// (strict-uint) reject -- so a "+"-prefixed token must fail to parse and
	// leave the window inert, matching the other SDKs (fail-closed).
	if !isASCIIDigits(parts[0]) || !isASCIIDigits(parts[1]) {
		return 0, 0, false
	}
	hour, err := strconv.Atoi(parts[0])
	if err != nil || hour < 0 || hour > 23 {
		return 0, 0, false
	}
	minute, err := strconv.Atoi(parts[1])
	if err != nil || minute < 0 || minute > 59 {
		return 0, 0, false
	}
	return hour, minute, true
}

func dayAbbreviationCond(day int) string {
	days := []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
	if day >= 0 && day < len(days) {
		return days[day]
	}
	return "mon"
}

// resolveCurrentTimeForCondition returns [hour, minute, dayOfWeek (0=Mon..6=Sun)].
func resolveCurrentTimeForCondition(context *RuntimeContext, tz string) []int {
	var t time.Time

	if context.CurrentTime != "" {
		parsed, err := time.Parse(time.RFC3339, context.CurrentTime)
		if err != nil {
			// Try alternate format
			parsed, err = time.Parse("2006-01-02T15:04:05", context.CurrentTime)
			if err != nil {
				return nil
			}
			parsed = parsed.UTC()
		}
		t = parsed.UTC()
	} else {
		t = time.Now().UTC()
	}

	tzName := tz
	if tzName == "" {
		tzName = "UTC"
	}
	location := resolveConditionLocation(tzName)
	if location == nil {
		return nil
	}
	t = t.In(location)

	hour := t.Hour()
	minute := t.Minute()
	goDay := t.Weekday()
	var dayOfWeek int
	if goDay == time.Sunday {
		dayOfWeek = 6
	} else {
		dayOfWeek = int(goDay) - 1
	}

	return []int{hour, minute, dayOfWeek}
}

var fixedTimezoneOffsets = map[string]int{
	"UTC":     0,
	"utc":     0,
	"Etc/UTC": 0,
	"Etc/GMT": 0,
	"GMT":     0,
	"EST":     -5 * 60,
	"CST":     -6 * 60,
	"MST":     -7 * 60,
	"PST":     -8 * 60,
	"GB":      0,
	"CET":     60,
	"EET":     120,
	"Japan":   9 * 60,
	"JST":     9 * 60,
	"PRC":     8 * 60,
	"IST":     5*60 + 30,
}

func resolveConditionLocation(tz string) *time.Location {
	if location, err := time.LoadLocation(tz); err == nil {
		return location
	}

	if offset, ok := fixedTimezoneOffsets[tz]; ok {
		return time.FixedZone(tz, offset*60)
	}

	if strings.HasPrefix(tz, "+") {
		offset, ok := parseTimezoneOffsetGo(tz[1:])
		if !ok {
			return nil
		}
		return time.FixedZone(tz, offset*60)
	}
	if strings.HasPrefix(tz, "-") {
		offset, ok := parseTimezoneOffsetGo(tz[1:])
		if !ok {
			return nil
		}
		return time.FixedZone(tz, -offset*60)
	}

	return nil
}

func parseTimezoneOffsetGo(s string) (int, bool) {
	if idx := strings.Index(s, ":"); idx >= 0 {
		hours, err := strconv.Atoi(s[:idx])
		if err != nil {
			return 0, false
		}
		minutes, err := strconv.Atoi(s[idx+1:])
		if err != nil || hours < 0 || hours > 23 || minutes < 0 || minutes > 59 {
			return 0, false
		}
		return hours*60 + minutes, true
	}
	hours, err := strconv.Atoi(s)
	if err != nil || hours < 0 || hours > 23 {
		return 0, false
	}
	return hours * 60, true
}

func checkContextMatch(expected map[string]interface{}, context *RuntimeContext) bool {
	for key, expectedValue := range expected {
		actual := resolveContextValueGo(key, context)
		if !matchValueGo(actual, expectedValue) {
			return false
		}
	}
	return true
}

func resolveContextValueGo(path string, context *RuntimeContext) interface{} {
	dotIdx := strings.Index(path, ".")
	var topLevel, rest string
	if dotIdx >= 0 {
		topLevel = path[:dotIdx]
		rest = path[dotIdx+1:]
	} else {
		topLevel = path
		rest = ""
	}

	switch topLevel {
	case "environment":
		if context.Environment == "" {
			return nil
		}
		return context.Environment
	case "user":
		if rest != "" {
			return mapGet(context.User, rest)
		}
		return context.User
	case "deployment":
		if rest != "" {
			return mapGet(context.Deployment, rest)
		}
		return context.Deployment
	case "agent":
		if rest != "" {
			return mapGet(context.Agent, rest)
		}
		return context.Agent
	case "session":
		if rest != "" {
			return mapGet(context.Session, rest)
		}
		return context.Session
	case "request":
		if rest != "" {
			return mapGet(context.Request, rest)
		}
		return context.Request
	case "custom":
		if rest != "" {
			return mapGet(context.Custom, rest)
		}
		return context.Custom
	default:
		return nil
	}
}

func mapGet(m map[string]interface{}, key string) interface{} {
	if m == nil {
		return nil
	}
	return m[key]
}

// valuesEqual mirrors Rust's values_equal: scalar-to-scalar equality only.
// String is exact, bool is exact (bool is NOT numeric), and numbers preserve
// the int-vs-float distinction Rust draws through serde_json::Number (as_i64 /
// as_f64): an integer-shaped expected value matches ONLY an integer-typed
// actual, while a float-shaped expected value matches an integer or float
// actual by numeric value. Any other actual shape, or a type mismatch, is not
// equal.
func valuesEqual(actual, expected interface{}) bool {
	switch ev := expected.(type) {
	case string:
		av, ok := actual.(string)
		return ok && av == ev
	case bool:
		av, ok := actual.(bool)
		return ok && av == ev
	case int:
		return matchIntNumber(actual, int64(ev))
	case int64:
		return matchIntNumber(actual, ev)
	case float64:
		return matchFloatNumber(actual, ev)
	default:
		return false
	}
}

// matchesScalarOrMembership mirrors Rust's matches_scalar_or_membership: when
// the actual value is an array, the expected scalar must equal one of its
// elements (membership); otherwise it is a plain scalar comparison.
func matchesScalarOrMembership(actual, expected interface{}) bool {
	if arr, ok := actual.([]interface{}); ok {
		for _, item := range arr {
			if valuesEqual(item, expected) {
				return true
			}
		}
		return false
	}
	return valuesEqual(actual, expected)
}

// matchValueGo mirrors Rust's match_value. A missing context field (nil actual)
// fails closed. A scalar expected value matches a scalar or is a member of an
// actual array. An expected array matches when ANY of its candidates matches
// the actual value, so expected-array vs actual-array succeeds on a non-empty
// intersection and expected-array vs actual-scalar succeeds on membership --
// for string, number, and bool candidates alike.
func matchValueGo(actual, expected interface{}) bool {
	if actual == nil {
		return false
	}

	switch ev := expected.(type) {
	case string, bool, int, int64, float64:
		return matchesScalarOrMembership(actual, expected)
	case []interface{}:
		for _, candidate := range ev {
			if matchesScalarOrMembership(actual, candidate) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// matchIntNumber compares an integer-shaped expected value. Mirrors Rust's
// values_equal via serde_json::Number::as_i64: an integer expected matches
// ONLY an integer-typed actual (int/int64) with an equal value -- a float64
// actual such as 5.0 does NOT match, even when numerically equal.
func matchIntNumber(actual interface{}, expected int64) bool {
	switch av := actual.(type) {
	case int:
		return int64(av) == expected
	case int64:
		return av == expected
	default:
		return false
	}
}

// matchFloatNumber compares a float-shaped expected value. Mirrors Rust's
// values_equal via serde_json::Number::as_f64: a float expected matches an
// int/int64/float64 actual whose numeric value is equal.
func matchFloatNumber(actual interface{}, expected float64) bool {
	switch av := actual.(type) {
	case int:
		return float64(av) == expected
	case int64:
		return float64(av) == expected
	case float64:
		return av == expected
	default:
		return false
	}
}

// EvaluateWithContext evaluates with conditional rule activation. Rule blocks
// whose conditions evaluate to false are skipped (treated as absent).
func EvaluateWithContext(
	spec *HushSpec,
	action *EvaluationAction,
	context *RuntimeContext,
	conditions map[string]*Condition,
) EvaluationResult {
	effectiveSpec := applyConditions(spec, context, conditions)
	return Evaluate(effectiveSpec, action)
}

func applyConditions(
	spec *HushSpec,
	context *RuntimeContext,
	conditions map[string]*Condition,
) *HushSpec {
	if spec.Rules == nil {
		return spec
	}

	effective := *spec
	rulesCopy := *spec.Rules
	effective.Rules = &rulesCopy
	changed := false

	for blockName, condition := range conditions {
		if !EvaluateCondition(condition, context) {
			switch blockName {
			case "forbidden_paths":
				rulesCopy.ForbiddenPaths = nil
				changed = true
			case "path_allowlist":
				rulesCopy.PathAllowlist = nil
				changed = true
			case "egress":
				rulesCopy.Egress = nil
				changed = true
			case "secret_patterns":
				rulesCopy.SecretPatterns = nil
				changed = true
			case "patch_integrity":
				rulesCopy.PatchIntegrity = nil
				changed = true
			case "shell_commands":
				rulesCopy.ShellCommands = nil
				changed = true
			case "tool_access":
				rulesCopy.ToolAccess = nil
				changed = true
			case "computer_use":
				rulesCopy.ComputerUse = nil
				changed = true
			case "remote_desktop_channels":
				rulesCopy.RemoteDesktopChannels = nil
				changed = true
			case "input_injection":
				rulesCopy.InputInjection = nil
				changed = true
			case "browser_automation":
				rulesCopy.BrowserAutomation = nil
				changed = true
			case "code_execution":
				rulesCopy.CodeExecution = nil
				changed = true
			}
		}
	}

	if !changed {
		return spec
	}

	return &effective
}
