package hushspec

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// validateRawDocument inspects the raw YAML document for structural problems
// that the typed decode silently absorbs, so this engine accepts exactly the
// documents the schema accepts. Three classes of issue only survive at the raw
// level, because the typed Go model cannot express them:
//
//   - Non-integer floats in integer-typed fields. gopkg.in/yaml.v3 truncates a
//     scalar like `max_additions: 1.5` into a Go int (-> 1) without error,
//     where the schema rejects any non-integer value.
//   - Empty or invalid enum sentinels. The generated Go model represents an
//     optional enum (match.visibility, metadata.classification, ...) as a plain
//     string, whose zero value stands for an absent field; the schema treats ""
//     (and any other out-of-set value) as a real, invalid value.
//   - A posture extension missing its required `transitions` key, which the
//     schema requires and supplies no default for.
//
// It also refuses, at parse time, the present-but-empty strings the schema
// gives a minimum length: the top-level `name` and the free-text origin match
// fields. [Validate] refuses those too, for a document a caller built in
// memory; refusing them here as well keeps a document this engine parses one
// the schema accepts.
//
// It returns one issue per problem found, each carrying the registered error
// code of spec/registries/error-codes.yaml that the condition maps onto, or an
// empty list when the document is clean.
func validateRawDocument(yamlStr string) []ValidationError {
	var root map[string]any
	if err := yaml.Unmarshal([]byte(yamlStr), &root); err != nil {
		// The typed decode in Parse already surfaces structural parse errors;
		// a second report here would be redundant.
		return nil
	}

	var errs rawIssues
	validateRawName(root, &errs)
	checkRawVariant(root, "merge_strategy", "merge_strategy", MergeStrategies, &errs)
	validateRawRules(rawObject(root, "rules"), &errs)
	validateRawExtensions(rawObject(root, "extensions"), &errs)
	validateRawMetadata(rawObject(root, "metadata"), &errs)
	return errs.items
}

// rawIssues collects parse-time refusals together with the registered code
// each one carries.
type rawIssues struct{ items []ValidationError }

// add records a shape refusal: a missing or unknown member, a value of the
// wrong type, or an enum variant outside its closed set. Every one of those is
// refused at parse time, because the model denies unknown fields and every enum
// denies unknown variants, so they carry E001.
func (r *rawIssues) add(message string) {
	r.items = append(r.items, ValidationError{
		Code: ErrorCodeParse, Kind: "PARSE", Message: message,
	})
}

// addConstraint records a structural-constraint violation (E004): a value that
// deserializes but breaks a rule of core Section 7 or of an extension module.
func (r *rawIssues) addConstraint(path, message string) {
	r.items = append(r.items, ValidationError{
		Code: ErrorCodeConstraint, Kind: "INVALID_VALUE", Path: path, Message: message,
	})
}

// validateRawName refuses a present but empty top-level `name` (core spec 2),
// which the 1.0 document format requires to be non-empty; `name: null` is an
// absent name, as it is to every other SDK. See [requiresNonEmptyName] for the
// constraint and the version it belongs to.
func validateRawName(root map[string]any, errs *rawIssues) {
	value, present := root["name"]
	if !present {
		return
	}
	if !rawRequiresNonEmptyName(root) {
		return
	}
	if name, isString := value.(string); isString && name == "" {
		errs.addConstraint("name", "name: must not be empty when present")
	}
}

// rawRequiresNonEmptyName applies [requiresNonEmptyName] to the raw document's
// declared version. A version that is absent or not a string is refused
// elsewhere as unsupported, and is held to the current format's constraints
// here so an unreadable version can never relax one.
func rawRequiresNonEmptyName(root map[string]any) bool {
	declared, isString := root["hushspec"].(string)
	if !isString {
		return true
	}
	return requiresNonEmptyName(declared)
}

// rawConditionBlocks are the rule blocks whose `when` the raw validator walks.
// It is the block list of core spec 3.13, kept in the order ValidateConditions
// reports in so both spell a violation the same way.
var rawConditionBlocks = []string{
	"forbidden_paths", "path_allowlist", "egress", "secret_patterns",
	"patch_integrity", "shell_commands", "tool_access", "computer_use",
	"remote_desktop_channels", "input_injection", "browser_automation",
	"code_execution",
}

func validateRawRules(rules map[string]any, errs *rawIssues) {
	if rules == nil {
		return
	}
	for _, name := range rawConditionBlocks {
		block := rawObject(rules, name)
		if block == nil {
			continue
		}
		if when, present := block["when"]; present {
			validateRawCondition(when, fmt.Sprintf("rules.%s.when", name), 0, errs)
		}
	}
	// Enum-typed properties: a value outside the closed set is an unknown
	// variant, refused at parse time.
	if egress := rawObject(rules, "egress"); egress != nil {
		checkRawVariant(egress, "default", "rules.egress.default", DefaultActions, errs)
	}
	if ta := rawObject(rules, "tool_access"); ta != nil {
		checkRawVariant(ta, "default", "rules.tool_access.default", DefaultActions, errs)
	}
	if cu := rawObject(rules, "computer_use"); cu != nil {
		checkRawVariant(cu, "mode", "rules.computer_use.mode", ComputerUseModes, errs)
	}
	if sp := rawObject(rules, "secret_patterns"); sp != nil {
		for index, raw := range rawArray(sp, "patterns") {
			pattern, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			// `severity` is a required member of SecretPattern.
			checkRawRequiredVariant(pattern, "severity",
				fmt.Sprintf("rules.secret_patterns.patterns[%d]", index), Severities, errs)
		}
	}
	if pi := rawObject(rules, "patch_integrity"); pi != nil {
		// max_additions/max_deletions are required non-negative integers with a
		// schema default: an explicit null -- which the typed Go model would
		// otherwise silently coerce to that default -- is rejected here, as is a
		// non-integer float.
		checkRawRequiredInteger(pi, "max_additions", "rules.patch_integrity.max_additions", errs)
		checkRawRequiredInteger(pi, "max_deletions", "rules.patch_integrity.max_deletions", errs)
	}
	if ta := rawObject(rules, "tool_access"); ta != nil {
		checkRawInteger(ta, "max_args_size", "rules.tool_access.max_args_size", errs)
	}
	if ce := rawObject(rules, "code_execution"); ce != nil {
		// Optional non-negative integers: absent and null are accepted, but a
		// negative value must be rejected.
		checkRawNonNegativeInteger(ce, "max_execution_time_ms", "rules.code_execution.max_execution_time_ms", errs)
		checkRawNonNegativeInteger(ce, "max_scan_bytes", "rules.code_execution.max_scan_bytes", errs)
	}
}

// validateRawCondition checks the parts of a `when` object the typed decode
// cannot express: the `rate` predicate's required members, its non-negative
// integer threshold, and its closed `comparison` set (core spec 3.13). Those
// are shape failures, refused at parse time, so they are reported here rather
// than as constraint violations. The identifier grammar and the nesting depth
// stay with [ValidateConditions], which reports them as constraint
// violations.
//
// The walk descends `all_of`, `any_of` and `not` so a nested `rate` is checked
// too; it stops one level past the nesting cap, which ValidateConditions
// reports on its own.
func validateRawCondition(raw any, path string, depth int, errs *rawIssues) {
	if depth > MaxNestingDepth {
		return
	}
	condition, ok := raw.(map[string]any)
	if !ok {
		return
	}
	if rate, present := condition["rate"]; present {
		validateRawRate(rate, path+".rate", errs)
	}
	for _, key := range []string{"all_of", "any_of"} {
		children, isList := condition[key].([]any)
		if !isList {
			continue
		}
		for index, child := range children {
			validateRawCondition(child, fmt.Sprintf("%s.%s[%d]", path, key, index), depth+1, errs)
		}
	}
	if child, present := condition["not"]; present {
		validateRawCondition(child, path+".not", depth+1, errs)
	}
}

func validateRawRate(raw any, path string, errs *rawIssues) {
	rate, ok := raw.(map[string]any)
	if !ok {
		errs.add(fmt.Sprintf("%s: invalid type: %s, expected a rate condition object",
			path, describeRawScalar(raw)))
		return
	}
	for key := range rate {
		if _, known := RateConditionKeys[key]; !known {
			errs.add(fmt.Sprintf("%s: unknown field `%s`, expected one of `counter`, `threshold`, `comparison`",
				path, key))
		}
	}

	if _, present := rate["counter"]; !present {
		errs.add(fmt.Sprintf("%s: missing field `counter`", path))
	} else if _, isString := rate["counter"].(string); !isString {
		errs.add(fmt.Sprintf("%s.counter: invalid type: %s, expected a string",
			path, describeRawScalar(rate["counter"])))
	}

	threshold, present := rate["threshold"]
	switch {
	case !present:
		errs.add(fmt.Sprintf("%s: missing field `threshold`", path))
	case !isRawInteger(threshold):
		errs.add(fmt.Sprintf("%s.threshold: invalid type: %s, expected a non-negative integer",
			path, describeRawScalar(threshold)))
	case isRawNegativeInteger(threshold):
		errs.add(fmt.Sprintf("%s.threshold: invalid type: integer `%v`, expected a non-negative integer",
			path, threshold))
	}

	comparison, present := rate["comparison"]
	switch {
	case !present:
		errs.add(fmt.Sprintf("%s: missing field `comparison`", path))
	default:
		name, isString := comparison.(string)
		if !isString || !containsTyped(RateComparison(name), RateComparisons) {
			errs.add(fmt.Sprintf(
				"%s.comparison: unknown variant `%v`, expected `gte` or `lt`", path, comparison))
		}
	}
}

// describeRawScalar renders a raw YAML value the way a decoder names it in an
// "invalid type" diagnostic.
func describeRawScalar(v any) string {
	switch value := v.(type) {
	case nil:
		return "null"
	case string:
		return fmt.Sprintf("string %q", value)
	case bool:
		return fmt.Sprintf("boolean `%v`", value)
	case float32, float64:
		return fmt.Sprintf("floating point `%v`", value)
	case map[string]any:
		return "a map"
	case []any:
		return "a sequence"
	default:
		if isRawInteger(v) {
			return fmt.Sprintf("integer `%v`", value)
		}
		return fmt.Sprintf("`%v`", value)
	}
}

func validateRawExtensions(ext map[string]any, errs *rawIssues) {
	if ext == nil {
		return
	}

	if posture := rawObject(ext, "posture"); posture != nil {
		// transitions is a required field in the reference models: an absent
		// key is rejected (an empty list is fine).
		if raw, ok := posture["transitions"]; !ok {
			errs.add("extensions.posture: missing field `transitions`")
		} else if _, isArray := raw.([]any); !isArray {
			// A present-but-null `transitions:` decodes to a nil slice rather
			// than failing the typed decode, and Parse then materializes an
			// empty one -- so without this check Go alone would accept, and
			// hash, a document the other three SDKs refuse.
			errs.add("extensions.posture.transitions must be an array")
		}
		for index, raw := range rawArray(posture, "transitions") {
			transition, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			checkRawRequiredVariant(transition, "on",
				fmt.Sprintf("extensions.posture.transitions[%d]", index), TransitionTriggers, errs)
		}
		for stateName, raw := range rawObject(posture, "states") {
			state, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			budgets := rawObject(state, "budgets")
			for budgetKey := range budgets {
				checkRawInteger(budgets, budgetKey,
					fmt.Sprintf("extensions.posture.states.%s.budgets.%s", stateName, budgetKey), errs)
			}
		}
	}

	if origins := rawObject(ext, "origins"); origins != nil {
		checkRawVariant(origins, "default_behavior",
			"origins.default_behavior", OriginDefaultBehaviors, errs)
		for i, raw := range rawArray(origins, "profiles") {
			profile, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if match := rawObject(profile, "match"); match != nil {
				checkRawEnum(match, "space_type",
					fmt.Sprintf("origins.profiles[%d].match.space_type", i), OriginSpaceTypes, errs)
				checkRawEnum(match, "visibility",
					fmt.Sprintf("origins.profiles[%d].match.visibility", i), OriginVisibilities, errs)
				// A present-but-empty free-text match field (e.g.
				// `provider: ""`) is a real, unsatisfiable constraint: no
				// origin carries an empty provider or tenant. An absent field
				// is left untouched -- an all-absent match still matches every
				// origin with score 0.
				for _, field := range []string{"provider", "tenant_id", "space_id", "sensitivity", "actor_role"} {
					checkRawNonEmptyString(match, field,
						fmt.Sprintf("origins.profiles[%d].match.%s", i, field), errs)
				}
			}
			if overlay := rawObject(profile, "tool_access"); overlay != nil {
				checkRawVariant(overlay, "default",
					fmt.Sprintf("origins.profiles[%d].tool_access.default", i), DefaultActions, errs)
			}
			if overlay := rawObject(profile, "egress"); overlay != nil {
				checkRawVariant(overlay, "default",
					fmt.Sprintf("origins.profiles[%d].egress.default", i), DefaultActions, errs)
			}
			if budgets := rawObject(profile, "budgets"); budgets != nil {
				checkRawInteger(budgets, "tool_calls",
					fmt.Sprintf("origins.profiles[%d].budgets.tool_calls", i), errs)
				checkRawInteger(budgets, "egress_calls",
					fmt.Sprintf("origins.profiles[%d].budgets.egress_calls", i), errs)
				checkRawInteger(budgets, "shell_commands",
					fmt.Sprintf("origins.profiles[%d].budgets.shell_commands", i), errs)
			}
			if bridge := rawObject(profile, "bridge"); bridge != nil {
				for j, traw := range rawArray(bridge, "allowed_targets") {
					target, ok := traw.(map[string]any)
					if !ok {
						continue
					}
					checkRawEnum(target, "space_type",
						fmt.Sprintf("origins.profiles[%d].bridge.allowed_targets[%d].space_type", i, j), OriginSpaceTypes, errs)
					checkRawEnum(target, "visibility",
						fmt.Sprintf("origins.profiles[%d].bridge.allowed_targets[%d].visibility", i, j), OriginVisibilities, errs)
				}
			}
		}
	}

	if detection := rawObject(ext, "detection"); detection != nil {
		if pi := rawObject(detection, "prompt_injection"); pi != nil {
			checkRawInteger(pi, "max_scan_bytes", "detection.prompt_injection.max_scan_bytes", errs)
			checkRawVariant(pi, "warn_at_or_above",
				"detection.prompt_injection.warn_at_or_above", DetectionLevels, errs)
			checkRawVariant(pi, "block_at_or_above",
				"detection.prompt_injection.block_at_or_above", DetectionLevels, errs)
			if heuristics := rawObject(pi, "heuristics"); heuristics != nil {
				checkRawNonNegativeInteger(heuristics, "min_score",
					"detection.prompt_injection.heuristics.min_score", errs)
			}
		}
		if jb := rawObject(detection, "jailbreak"); jb != nil {
			checkRawInteger(jb, "block_threshold", "detection.jailbreak.block_threshold", errs)
			checkRawInteger(jb, "warn_threshold", "detection.jailbreak.warn_threshold", errs)
			checkRawInteger(jb, "max_input_bytes", "detection.jailbreak.max_input_bytes", errs)
		}
		if ti := rawObject(detection, "threat_intel"); ti != nil {
			checkRawInteger(ti, "top_k", "detection.threat_intel.top_k", errs)
		}
	}
}

func validateRawMetadata(md map[string]any, errs *rawIssues) {
	if md == nil {
		return
	}
	// policy_version is an optional non-negative integer: absent and null are
	// accepted, a non-integer float or a negative value is not.
	checkRawNonNegativeInteger(md, "policy_version", "metadata.policy_version", errs)
	checkRawVariant(md, "classification", "metadata.classification", Classifications, errs)
	checkRawVariant(md, "lifecycle_state", "metadata.lifecycle_state", LifecycleStates, errs)
	validateRawControls(md, errs)
	validateRawChangelog(md, errs)
}

// validateRawChangelog performs the structural checks on metadata.changelog
// that the typed decode cannot express: a missing `version`, `date` or
// `summary` is indistinguishable from an empty one in the typed struct.
func validateRawChangelog(md map[string]any, errs *rawIssues) {
	raw, ok := md["changelog"]
	if !ok {
		return
	}
	changelog, ok := raw.([]any)
	if !ok {
		errs.add("metadata.changelog must be an array")
		return
	}

	for i, entryRaw := range changelog {
		path := fmt.Sprintf("metadata.changelog[%d]", i)
		entry, ok := entryRaw.(map[string]any)
		if !ok {
			errs.add(path + " must be an object")
			continue
		}

		for key := range entry {
			if _, known := ChangelogEntryKeys[key]; !known {
				errs.add(fmt.Sprintf("%s: unknown field `%v`", path, key))
			}
		}

		if version, ok := entry["version"].(string); !ok {
			errs.add(path + ": missing field `version`")
		} else if version == "" {
			errs.addConstraint(path+".version", path+".version must not be empty")
		}

		if _, ok := entry["date"].(string); !ok {
			errs.add(path + ": missing field `date`")
		}

		if summary, ok := entry["summary"].(string); !ok {
			errs.add(path + ": missing field `summary`")
		} else if summary == "" {
			errs.addConstraint(path+".summary", path+".summary must not be empty")
		}
	}
}

// frameworkIDPattern is the `framework` grammar from the core schema. Whether
// the id is *registered* in spec/registries/frameworks.yaml, and whether the
// rule paths resolve, are semantic questions answered by `h2h lint` (L012,
// L013); the registry deliberately stays out of the SDKs.
var frameworkIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`)

// validateRawControls performs the structural checks on metadata.controls that
// the typed decode cannot express: required fields (a missing `framework` is
// indistinguishable from an empty one in the typed struct), a non-empty
// rule_paths list, and the framework id grammar.
func validateRawControls(md map[string]any, errs *rawIssues) {
	raw, ok := md["controls"]
	if !ok {
		return
	}
	controls, ok := raw.([]any)
	if !ok {
		errs.add("metadata.controls must be an array")
		return
	}

	for i, entryRaw := range controls {
		path := fmt.Sprintf("metadata.controls[%d]", i)
		entry, ok := entryRaw.(map[string]any)
		if !ok {
			errs.add(path + " must be an object")
			continue
		}

		for key := range entry {
			if _, known := ControlMappingKeys[key]; !known {
				errs.add(fmt.Sprintf("%s: unknown field `%v`", path, key))
			}
		}

		framework, ok := entry["framework"].(string)
		if !ok {
			errs.add(path + ": missing field `framework`")
		} else if !frameworkIDPattern.MatchString(framework) {
			errs.addConstraint(path+".framework", fmt.Sprintf(
				"%s.framework %q must match ^[a-z0-9][a-z0-9.-]*$", path, framework))
		}

		if controlID, ok := entry["control_id"].(string); !ok {
			errs.add(path + ": missing field `control_id`")
		} else if controlID == "" {
			errs.addConstraint(path+".control_id", path+".control_id must not be empty")
		}

		rulePathsRaw, present := entry["rule_paths"]
		if !present {
			errs.add(path + ": missing field `rule_paths`")
			continue
		}
		rulePaths, ok := rulePathsRaw.([]any)
		if !ok {
			errs.add(path + ".rule_paths must be an array")
			continue
		}
		if len(rulePaths) == 0 {
			errs.addConstraint(path+".rule_paths", path+".rule_paths must list at least one rule path")
		}
		for j, rulePathRaw := range rulePaths {
			rulePath, ok := rulePathRaw.(string)
			if !ok {
				errs.add(fmt.Sprintf("%s.rule_paths[%d] must be a string", path, j))
				continue
			}
			if rulePath == "" {
				errs.addConstraint(fmt.Sprintf("%s.rule_paths[%d]", path, j), fmt.Sprintf("%s.rule_paths[%d] must not be empty", path, j))
			}
		}
	}
}

// rawObject returns m[key] as a nested object, or nil when the key is absent or
// not a mapping.
func rawObject(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	obj, _ := m[key].(map[string]any)
	return obj
}

// rawArray returns m[key] as a sequence, or nil when the key is absent or not a
// sequence.
func rawArray(m map[string]any, key string) []any {
	if m == nil {
		return nil
	}
	arr, _ := m[key].([]any)
	return arr
}

// checkRawInteger records an error when key is present in obj with a value that
// is not an integer scalar (e.g. a float like 1.5, which yaml.v3 would silently
// truncate into a Go int field). Absent keys are ignored.
func checkRawInteger(obj map[string]any, key, path string, errs *rawIssues) {
	v, ok := obj[key]
	if !ok || v == nil {
		return
	}
	if !isRawInteger(v) {
		errs.add(fmt.Sprintf("%s must be an integer", path))
	}
}

func isRawInteger(v any) bool {
	switch v.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	default:
		return false
	}
}

// isRawNegativeInteger reports whether v is a signed integer scalar with a
// negative value. Unsigned integer types are never negative.
func isRawNegativeInteger(v any) bool {
	switch n := v.(type) {
	case int:
		return n < 0
	case int8:
		return n < 0
	case int16:
		return n < 0
	case int32:
		return n < 0
	case int64:
		return n < 0
	default:
		return false
	}
}

// checkRawNonNegativeInteger records an error when key is present with a
// non-null value that is not a non-negative integer scalar. It stands for an
// optional non-negative integer in the schema: an absent key or an explicit
// null is accepted (the field stays unset), while a non-integer (e.g. 1.5) or
// a negative integer (e.g. -5) is not. Absent and null are left untouched so
// an omitted optional field keeps its default.
func checkRawNonNegativeInteger(obj map[string]any, key, path string, errs *rawIssues) {
	v, ok := obj[key]
	if !ok || v == nil {
		return
	}
	if !isRawInteger(v) {
		errs.add(fmt.Sprintf("%s must be an integer", path))
		return
	}
	if isRawNegativeInteger(v) {
		errs.add(fmt.Sprintf("%s must be non-negative", path))
	}
}

// checkRawRequiredInteger records an error when key is present with a value
// that is null or not an integer scalar. It stands for a required non-negative
// integer with a schema default: an absent key is accepted (the typed model
// supplies the default), but an explicit null -- which the typed Go model would
// otherwise coerce to that default -- is rejected, as is a non-integer float. A
// negative value stays a cross-field concern of [Validate].
func checkRawRequiredInteger(obj map[string]any, key, path string, errs *rawIssues) {
	v, ok := obj[key]
	if !ok {
		return
	}
	if v == nil || !isRawInteger(v) {
		errs.add(fmt.Sprintf("%s must be an integer", path))
	}
}

// checkRawEnum records an error when key is present in obj with a value that is
// not one of allowed. A present-but-empty "" fails: "" is a real (invalid)
// value, not an absent field.
//
// These are the origins module's own `match` sets, which the schema carries as
// plain strings and checks at validation time, so they are constraint
// violations (E004) rather than unknown variants.
func checkRawEnum(obj map[string]any, key, path string, allowed map[string]struct{}, errs *rawIssues) {
	v, ok := obj[key]
	if !ok {
		return
	}
	if s, isStr := v.(string); !isStr || !containsTyped(s, allowed) {
		errs.addConstraint(path, fmt.Sprintf("%s %v is not valid", path, v))
	}
}

// checkRawVariant rejects an enum-typed property whose value is outside its
// closed set. The schema models these as closed enums, which refuse an unknown
// variant at parse time, so this is a shape refusal (E001) rather than a
// constraint violation. An absent key is left alone: the typed model supplies
// the schema default.
func checkRawVariant[T ~string](
	obj map[string]any, key, path string, allowed map[T]struct{}, errs *rawIssues,
) {
	v, ok := obj[key]
	if !ok {
		return
	}
	if name, isStr := v.(string); isStr && containsTyped(T(name), allowed) {
		return
	}
	errs.add(fmt.Sprintf("%s: unknown variant `%v`, expected one of %s",
		path, v, strings.Join(quotedVariants(allowed), ", ")))
}

// checkRawRequiredVariant is [checkRawVariant] for a property the schema
// requires: an absent key is a missing field, refused at parse time.
func checkRawRequiredVariant[T ~string](
	obj map[string]any, key, path string, allowed map[T]struct{}, errs *rawIssues,
) {
	if _, ok := obj[key]; !ok {
		errs.add(fmt.Sprintf("%s: missing field `%s`", path, key))
		return
	}
	checkRawVariant(obj, key, path+"."+key, allowed, errs)
}

// quotedVariants renders a closed set as the sorted, backtick-quoted list a
// diagnostic names, so the message is the same on every run.
func quotedVariants[T ~string](allowed map[T]struct{}) []string {
	names := make([]string, 0, len(allowed))
	for name := range allowed {
		names = append(names, "`"+string(name)+"`")
	}
	sort.Strings(names)
	return names
}

// checkRawNonEmptyString records an error when key is present in obj with an
// empty string value. An absent key is ignored, so only an explicit "" is
// rejected.
func checkRawNonEmptyString(obj map[string]any, key, path string, errs *rawIssues) {
	v, ok := obj[key]
	if !ok {
		return
	}
	if s, isStr := v.(string); isStr && s == "" {
		errs.addConstraint(path, fmt.Sprintf("%s must not be empty", path))
	}
}
