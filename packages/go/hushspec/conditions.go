package hushspec

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	// time.LoadLocation reads the *system* tz database ($GOROOT/lib/time or
	// /usr/share/zoneinfo), which scratch/distroless images and Windows do not
	// have, so a `time_window.timezone` rule would silently fail to resolve
	// there. Importing time/tzdata embeds the IANA database in the binary
	// (~450KB) as a fallback, consulted only when the system copy is missing.
	_ "time/tzdata"
)

// MaxNestingDepth is the maximum allowed nesting depth for compound
// conditions (core spec 3.13).
const MaxNestingDepth = 8

// DayAbbreviations are the day names accepted in time_window.days.
var DayAbbreviations = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

// TimeWindowCondition holds a rule block active only inside a daily window,
// optionally restricted to named days (core spec 3.13). A window the engine
// cannot evaluate leaves the block active.
type TimeWindowCondition struct {
	Start string `yaml:"start" json:"start"` // HH:MM (24-hour)
	End   string `yaml:"end" json:"end"`     // HH:MM (24-hour)
	// Timezone is an IANA identifier or a fixed offset; an absent one is UTC.
	// It is a *string because presence is part of the wire format: an absent
	// timezone takes the schema default and a written one is kept as it
	// stands, so the two carry different content hashes.
	Timezone *string  `yaml:"timezone,omitempty" json:"timezone,omitempty"`
	Days     []string `yaml:"days,omitempty" json:"days,omitempty"` // mon..sun
}

// RateComparison is how a [RateCondition] compares its counter with its
// threshold (core spec 3.13).
type RateComparison string

const (
	// RateComparisonGte is true when counter >= threshold.
	RateComparisonGte RateComparison = "gte"
	// RateComparisonLt is true when counter < threshold.
	RateComparisonLt RateComparison = "lt"
)

// RateComparisons is the closed set of `rate.comparison` values.
var RateComparisons = map[RateComparison]struct{}{
	RateComparisonGte: {},
	RateComparisonLt:  {},
}

// RateCondition compares an engine-supplied counter with a threshold (core
// spec 3.13).
//
// HushSpec never stores state and never increments anything: the engine owns
// the counter and its window and supplies the current value for this
// evaluation in [RuntimeContext.Counters]. A counter the engine did not supply
// makes the predicate unevaluable, which leaves the block active.
type RateCondition struct {
	// Counter names a key of RuntimeContext.Counters. Identifier grammar.
	Counter string `yaml:"counter" json:"counter"`
	// Threshold is the non-negative value the counter is compared against.
	Threshold uint64 `yaml:"threshold" json:"threshold"`
	// Comparison is "gte" or "lt".
	Comparison RateComparison `yaml:"comparison" json:"comparison"`
}

// Condition gates whether a rule block is active. All present fields are
// combined with AND semantics. Fail-closed: missing context fields evaluate
// to false.
type Condition struct {
	TimeWindow *TimeWindowCondition `yaml:"time_window,omitempty" json:"time_window,omitempty"`
	Context    map[string]any       `yaml:"context,omitempty" json:"context,omitempty"`
	AllOf      []Condition          `yaml:"all_of,omitempty" json:"all_of,omitempty"`
	AnyOf      []Condition          `yaml:"any_of,omitempty" json:"any_of,omitempty"`
	Not        *Condition           `yaml:"not,omitempty" json:"not,omitempty"`
	// Capability is true when the effective posture state -- the state the
	// posture guard uses, after origins profile selection and the action's
	// posture input -- grants it. Unevaluable, and therefore held, when the
	// policy has no posture extension (core spec 3.13). It is a *string
	// because presence is part of the wire format: a written "" is a present
	// value the canonical form keeps, and validation refuses it.
	Capability *string `yaml:"capability,omitempty" json:"capability,omitempty"`
	// Rate compares an engine-supplied counter with a threshold. Unevaluable,
	// and therefore held, when the context carries no such counter.
	Rate *RateCondition `yaml:"rate,omitempty" json:"rate,omitempty"`
}

// RuntimeContext is the runtime context provided by the enforcement engine.
type RuntimeContext struct {
	User        map[string]any `yaml:"user,omitempty" json:"user,omitempty"`
	Environment string         `yaml:"environment,omitempty" json:"environment,omitempty"`
	Deployment  map[string]any `yaml:"deployment,omitempty" json:"deployment,omitempty"`
	Agent       map[string]any `yaml:"agent,omitempty" json:"agent,omitempty"`
	Session     map[string]any `yaml:"session,omitempty" json:"session,omitempty"`
	Request     map[string]any `yaml:"request,omitempty" json:"request,omitempty"`
	Custom      map[string]any `yaml:"custom,omitempty" json:"custom,omitempty"`
	// Counters are the engine-maintained counters `rate` conditions consult
	// (core spec 3.13). The engine owns the window; HushSpec only compares.
	Counters    map[string]uint64 `yaml:"counters,omitempty" json:"counters,omitempty"`
	CurrentTime string            `yaml:"current_time,omitempty" json:"current_time,omitempty"` // RFC3339; defaults to system time
}

// grantedCapabilities is what the effective posture state grants, for the
// `capability` predicate of core spec 3.13. `known` is false when the policy
// has no posture extension, which makes the predicate unevaluable (and so
// held); a known-but-unlisted capability is false, and an unknown state grants
// nothing.
type grantedCapabilities struct {
	known bool
	list  []string
}

func (g grantedCapabilities) grants(name string) bool {
	for _, granted := range g.list {
		if granted == name {
			return true
		}
	}
	return false
}

// EvaluateCondition returns true if the condition is satisfied by the context.
//
// A `capability` predicate is unevaluable through this entry point -- no
// posture state is known here -- and therefore holds. An evaluator that has
// resolved the effective posture state calls
// [EvaluateConditionWithCapabilities] instead.
func EvaluateCondition(condition *Condition, context *RuntimeContext) bool {
	return evaluateConditionDepth(condition, context, grantedCapabilities{}, 0) != verdictFalse
}

// EvaluateConditionWithCapabilities is [EvaluateCondition] with the
// capabilities the effective posture state grants. Pass hasPosture=false when
// the policy has no posture extension: a `capability` predicate is then
// unevaluable and holds. With hasPosture=true an unknown state grants nothing,
// so the predicate is false.
func EvaluateConditionWithCapabilities(
	condition *Condition,
	context *RuntimeContext,
	capabilities []string,
	hasPosture bool,
) bool {
	return evaluateConditionDepth(condition, context,
		grantedCapabilities{known: hasPosture, list: capabilities}, 0) != verdictFalse
}

// conditionVerdict is what a condition evaluates to (core spec 3.13).
// verdictUnevaluable is a predicate the engine lacks the means to decide --
// no posture extension, no such counter, a clock it cannot read -- and it
// never switches a block off: a block is inert only on an evaluated false.
type conditionVerdict uint8

const (
	verdictTrue conditionVerdict = iota
	verdictFalse
	verdictUnevaluable
)

func verdictOf(value bool) conditionVerdict {
	if value {
		return verdictTrue
	}
	return verdictFalse
}

func (v conditionVerdict) negate() conditionVerdict {
	switch v {
	case verdictTrue:
		return verdictFalse
	case verdictFalse:
		return verdictTrue
	default:
		return verdictUnevaluable
	}
}

// and is AND: false wins, then unevaluable, then true.
func (v conditionVerdict) and(other conditionVerdict) conditionVerdict {
	if v == verdictFalse || other == verdictFalse {
		return verdictFalse
	}
	if v == verdictUnevaluable || other == verdictUnevaluable {
		return verdictUnevaluable
	}
	return verdictTrue
}

// or is OR: true wins, then unevaluable, then false.
func (v conditionVerdict) or(other conditionVerdict) conditionVerdict {
	if v == verdictTrue || other == verdictTrue {
		return verdictTrue
	}
	if v == verdictUnevaluable || other == verdictUnevaluable {
		return verdictUnevaluable
	}
	return verdictFalse
}

func evaluateConditionDepth(
	condition *Condition,
	context *RuntimeContext,
	capabilities grantedCapabilities,
	depth int,
) conditionVerdict {
	if depth > MaxNestingDepth {
		// Validation rejects this at parse time; an out-of-band condition that
		// exceeds the depth cannot be evaluated, and an unevaluable condition
		// must not switch a control off (core spec 3.13).
		return verdictUnevaluable
	}

	// The fields of one condition object are ANDed. An evaluated false
	// settles the object, so later fields are not consulted.
	verdict := verdictTrue

	if condition.TimeWindow != nil {
		verdict = verdict.and(checkTimeWindow(condition.TimeWindow, context))
		if verdict == verdictFalse {
			return verdict
		}
	}

	if condition.Context != nil {
		verdict = verdict.and(verdictOf(checkContextMatch(condition.Context, context)))
		if verdict == verdictFalse {
			return verdict
		}
	}

	// `capability`: unevaluable without a posture extension; otherwise the
	// effective state must list the capability.
	if condition.Capability != nil {
		if capabilities.known {
			verdict = verdict.and(verdictOf(capabilities.grants(*condition.Capability)))
		} else {
			verdict = verdict.and(verdictUnevaluable)
		}
		if verdict == verdictFalse {
			return verdict
		}
	}

	// `rate`: unevaluable when the engine supplied no such counter.
	if rate := condition.Rate; rate != nil {
		if count, ok := context.Counters[rate.Counter]; ok {
			satisfied := count >= rate.Threshold
			if rate.Comparison == RateComparisonLt {
				satisfied = count < rate.Threshold
			}
			verdict = verdict.and(verdictOf(satisfied))
		} else {
			verdict = verdict.and(verdictUnevaluable)
		}
		if verdict == verdictFalse {
			return verdict
		}
	}

	if len(condition.AllOf) > 0 {
		combined := verdictTrue
		for index := range condition.AllOf {
			combined = combined.and(evaluateConditionDepth(&condition.AllOf[index], context, capabilities, depth+1))
		}
		verdict = verdict.and(combined)
		if verdict == verdictFalse {
			return verdict
		}
	}

	if len(condition.AnyOf) > 0 {
		combined := verdictFalse
		for index := range condition.AnyOf {
			combined = combined.or(evaluateConditionDepth(&condition.AnyOf[index], context, capabilities, depth+1))
		}
		verdict = verdict.and(combined)
		if verdict == verdictFalse {
			return verdict
		}
	}

	if condition.Not != nil {
		verdict = verdict.and(evaluateConditionDepth(condition.Not, context, capabilities, depth+1).negate())
	}

	return verdict
}

func checkTimeWindow(tw *TimeWindowCondition, context *RuntimeContext) conditionVerdict {
	// A window the engine cannot evaluate -- unresolvable time zone,
	// unparsable current_time, or a malformed HH:MM that escaped validation --
	// is unevaluable and leaves the block active (core spec 3.13).
	now := resolveCurrentTimeForCondition(context, tw.Timezone)
	if now == nil {
		return verdictUnevaluable
	}

	hour, minute, dayOfWeek := now[0], now[1], now[2]

	startH, startM, ok := parseHHMM(tw.Start)
	if !ok {
		return verdictUnevaluable
	}
	endH, endM, ok := parseHHMM(tw.End)
	if !ok {
		return verdictUnevaluable
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
			return verdictFalse
		}
	}

	if startMinutes == endMinutes {
		return verdictTrue
	}
	if startMinutes < endMinutes {
		return verdictOf(currentMinutes >= startMinutes && currentMinutes < endMinutes)
	}
	return verdictOf(currentMinutes >= startMinutes || currentMinutes < endMinutes)
}

func parseHHMM(s string) (int, int, bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, 0, false
	}
	// Require pure ASCII digits in each component. strconv.Atoi would
	// otherwise accept a leading sign (e.g. "+9:00"), which the other engines
	// reject; the same token would then be a live window here and unevaluable
	// there. A non-digit component fails to parse, and the window is
	// unevaluable in every engine.
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
	if day >= 0 && day < len(DayAbbreviations) {
		return DayAbbreviations[day]
	}
	return "mon"
}

// ValidateConditions performs the parse-time validation of every rule block's
// `when` condition (core spec 3.13 and 7). Unknown keys are rejected by
// the decoder; this checks the HH:MM fields, the timezone, the day
// abbreviations, and the nesting depth. It returns one message per violation,
// each prefixed with the rule path (for example `rules.egress.when`).
func ValidateConditions(rules *Rules) []string {
	var errs []string
	for _, block := range ruleConditions(rules) {
		errs = append(errs, ValidateCondition(block.when, "rules."+block.name+".when")...)
	}
	return errs
}

// conditionBlock pairs a rule block's name with the `when` it declared.
type conditionBlock struct {
	name string
	when *Condition
}

// ruleConditions lists every rule block that declared a `when`, in the block
// order of core spec 5 -- the order a document's violations are reported in.
func ruleConditions(rules *Rules) []conditionBlock {
	if rules == nil {
		return nil
	}
	blocks := make([]conditionBlock, 0, blockCount)
	add := func(name string, when *Condition) {
		if when != nil {
			blocks = append(blocks, conditionBlock{name: name, when: when})
		}
	}
	if rule := rules.ForbiddenPaths; rule != nil {
		add("forbidden_paths", rule.When)
	}
	if rule := rules.PathAllowlist; rule != nil {
		add("path_allowlist", rule.When)
	}
	if rule := rules.Egress; rule != nil {
		add("egress", rule.When)
	}
	if rule := rules.SecretPatterns; rule != nil {
		add("secret_patterns", rule.When)
	}
	if rule := rules.PatchIntegrity; rule != nil {
		add("patch_integrity", rule.When)
	}
	if rule := rules.ShellCommands; rule != nil {
		add("shell_commands", rule.When)
	}
	if rule := rules.ToolAccess; rule != nil {
		add("tool_access", rule.When)
	}
	if rule := rules.ComputerUse; rule != nil {
		add("computer_use", rule.When)
	}
	if rule := rules.RemoteDesktopChannels; rule != nil {
		add("remote_desktop_channels", rule.When)
	}
	if rule := rules.InputInjection; rule != nil {
		add("input_injection", rule.When)
	}
	if rule := rules.BrowserAutomation; rule != nil {
		add("browser_automation", rule.When)
	}
	if rule := rules.CodeExecution; rule != nil {
		add("code_execution", rule.When)
	}
	return blocks
}

// ValidateCondition validates one condition subtree rooted at path.
func ValidateCondition(condition *Condition, path string) []string {
	var errs []string
	validateConditionDepth(condition, path, 0, &errs)
	return errs
}

func validateConditionDepth(condition *Condition, path string, depth int, errs *[]string) {
	if condition == nil {
		return
	}
	if depth > MaxNestingDepth {
		*errs = append(*errs, fmt.Sprintf(
			"%s: conditions nest deeper than the maximum of %d levels", path, MaxNestingDepth))
		return
	}
	if tw := condition.TimeWindow; tw != nil {
		for _, field := range []struct{ name, value string }{{"start", tw.Start}, {"end", tw.End}} {
			if _, _, ok := parseHHMM(field.value); !ok {
				*errs = append(*errs, fmt.Sprintf(
					"%s.time_window.%s: %q is not a valid HH:MM time", path, field.name, field.value))
			}
		}
		if tw.Timezone != nil && !TimezoneIsKnown(*tw.Timezone) {
			*errs = append(*errs, fmt.Sprintf(
				"%s.time_window.timezone: %q is neither an IANA time zone nor a fixed offset", path, *tw.Timezone))
		}
		for _, day := range tw.Days {
			known := false
			for _, abbrev := range DayAbbreviations {
				if strings.EqualFold(day, abbrev) {
					known = true
					break
				}
			}
			if !known {
				*errs = append(*errs, fmt.Sprintf(
					"%s.time_window.days: %q is not one of mon, tue, wed, thu, fri, sat, sun", path, day))
			}
		}
	}
	if name := condition.Capability; name != nil && !IsCapabilityIdentifier(*name) {
		*errs = append(*errs, fmt.Sprintf(
			"%s.capability: %q is not a capability identifier (lowercase ASCII letters, digits and underscores in dot-separated segments that start with a letter)",
			path, *name))
	}
	if rate := condition.Rate; rate != nil && !IsCapabilityIdentifier(rate.Counter) {
		*errs = append(*errs, fmt.Sprintf(
			"%s.rate.counter: %q is not a counter identifier (lowercase ASCII letters, digits and underscores in dot-separated segments that start with a letter)",
			path, rate.Counter))
	}
	for index := range condition.AllOf {
		validateConditionDepth(&condition.AllOf[index], fmt.Sprintf("%s.all_of[%d]", path, index), depth+1, errs)
	}
	for index := range condition.AnyOf {
		validateConditionDepth(&condition.AnyOf[index], fmt.Sprintf("%s.any_of[%d]", path, index), depth+1, errs)
	}
	if condition.Not != nil {
		validateConditionDepth(condition.Not, path+".not", depth+1, errs)
	}
}

// IsCapabilityIdentifier reports whether name matches the identifier grammar
// shared by posture capabilities and rate counters (core spec 3.13): one or
// more dot-separated segments, each a lowercase ASCII letter followed by
// lowercase ASCII letters, digits or underscores.
//
//	identifier = segment *("." segment)
//	segment    = %x61-7A *(%x61-7A / %x30-39 / "_")
func IsCapabilityIdentifier(name string) bool {
	if name == "" {
		return false
	}
	for _, segment := range strings.Split(name, ".") {
		if segment == "" {
			return false
		}
		for index := 0; index < len(segment); index++ {
			c := segment[index]
			switch {
			case c >= 'a' && c <= 'z':
			case index > 0 && (c >= '0' && c <= '9' || c == '_'):
			default:
				return false
			}
		}
	}
	return true
}

// TimezoneIsKnown reports whether tz is an IANA identifier known to this
// engine, a known alias, or a fixed `+HH:MM` / `-HH:MM` offset. An empty
// string is not a time zone -- an absent `timezone` field defaults to UTC, but
// an explicitly empty one is unresolvable.
func TimezoneIsKnown(tz string) bool {
	return tz != "" && resolveConditionLocation(tz) != nil
}

// resolveCurrentTimeForCondition returns [hour, minute, dayOfWeek (0=Mon..6=Sun)].
func resolveCurrentTimeForCondition(context *RuntimeContext, tz *string) []int {
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

	// An absent timezone is UTC (core spec 3.13); a written one is resolved as
	// it stands, so an unresolvable identifier leaves the window unevaluable.
	tzName := "UTC"
	if tz != nil {
		tzName = *tz
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
	// time.LoadLocation resolves "" to UTC and "Local" to the host zone; the
	// reference engines know neither, so both stay unresolvable here.
	if tz == "" || tz == "Local" {
		return nil
	}
	if location, err := time.LoadLocation(tz); err == nil {
		return location
	}

	if offset, ok := fixedTimezoneOffsets[tz]; ok {
		return time.FixedZone(tz, offset*60)
	}

	if strings.HasPrefix(tz, "+") {
		offset, ok := parseTimezoneOffset(tz[1:])
		if !ok {
			return nil
		}
		return time.FixedZone(tz, offset*60)
	}
	if strings.HasPrefix(tz, "-") {
		offset, ok := parseTimezoneOffset(tz[1:])
		if !ok {
			return nil
		}
		return time.FixedZone(tz, -offset*60)
	}

	return nil
}

func parseTimezoneOffset(s string) (int, bool) {
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

func checkContextMatch(expected map[string]any, context *RuntimeContext) bool {
	for key, expectedValue := range expected {
		actual := resolveContextValue(key, context)
		if !matchValue(actual, expectedValue) {
			return false
		}
	}
	return true
}

func resolveContextValue(path string, context *RuntimeContext) any {
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

func mapGet(m map[string]any, key string) any {
	if m == nil {
		return nil
	}
	return m[key]
}

// valuesEqual compares two scalars, and only scalars. String is exact, bool is
// exact (a bool is never numeric), and numbers keep the int-vs-float
// distinction the JSON value model draws: an integer-shaped expected value
// matches ONLY an integer-typed actual, while a float-shaped expected value
// matches an integer or float actual by numeric value. Any other actual shape,
// or a type mismatch, is not equal.
func valuesEqual(actual, expected any) bool {
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

// matchesScalarOrMembership compares an expected scalar with an actual value:
// when the actual value is an array, the scalar must equal one of its elements
// (membership); otherwise it is a plain scalar comparison.
func matchesScalarOrMembership(actual, expected any) bool {
	if arr, ok := actual.([]any); ok {
		for _, item := range arr {
			if valuesEqual(item, expected) {
				return true
			}
		}
		return false
	}
	return valuesEqual(actual, expected)
}

// matchValue compares one `when.context` entry. A missing context field (nil
// actual) fails closed. A scalar expected value matches a scalar or is a member of an
// actual array. An expected array matches when ANY of its candidates matches
// the actual value, so expected-array vs actual-array succeeds on a non-empty
// intersection and expected-array vs actual-scalar succeeds on membership --
// for string, number, and bool candidates alike.
func matchValue(actual, expected any) bool {
	if actual == nil {
		return false
	}

	switch ev := expected.(type) {
	case string, bool, int, int64, float64:
		return matchesScalarOrMembership(actual, expected)
	case []any:
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

// matchIntNumber compares an integer-shaped expected value: it matches ONLY an
// integer-typed actual (int/int64) with an equal value -- a float64 actual such
// as 5.0 does NOT match, even when numerically equal.
func matchIntNumber(actual any, expected int64) bool {
	switch av := actual.(type) {
	case int:
		return int64(av) == expected
	case int64:
		return av == expected
	default:
		return false
	}
}

// matchFloatNumber compares a float-shaped expected value: it matches an
// int/int64/float64 actual whose numeric value is exactly equal. There is no
// tolerance, so 0.3 does not match 0.30000000000000004 (core spec 3.13).
func matchFloatNumber(actual any, expected float64) bool {
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

// EvaluateWithContext evaluates with an explicit runtime context and an
// out-of-band map of conditions keyed by rule-block name. The explicit context
// replaces action.Context; out-of-band conditions are ANDed with each block's
// own in-document `when` (core spec 3.13). A block whose condition is false is
// inert for this evaluation.
func EvaluateWithContext(
	spec *HushSpec,
	action *EvaluationAction,
	context *RuntimeContext,
	conditions map[string]*Condition,
) EvaluationResult {
	return cachedCompile(spec).EvaluateWithContext(action, context, conditions)
}
