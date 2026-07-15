package hushspec

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// validateRawDocument inspects the raw YAML document for structural problems
// that the typed decode silently absorbs, so Go accepts or rejects a policy
// identically to the Rust, TypeScript, and Python SDKs. Three classes of issue
// only survive at the raw level, because the typed Go model cannot express
// them:
//
//   - Non-integer floats in integer-typed fields. gopkg.in/yaml.v3 truncates a
//     scalar like `max_additions: 1.5` into a Go int (-> 1) without error,
//     whereas the reference SDKs reject any non-integer value.
//   - Empty or invalid enum sentinels. The generated Go model represents
//     optional enum-ish strings (match.visibility, metadata.classification, ...)
//     as plain strings, so a present-but-empty "" is indistinguishable from an
//     absent field in the typed struct; the reference SDKs treat "" (and any
//     other out-of-set value) as a real, invalid value.
//   - A posture extension missing its required `transitions` key, which is a
//     required (non-defaulted) field in the reference models.
//
// It returns one message per problem found, or an empty slice when the document
// is clean. This mirrors the parse-time raw validation performed by the
// TypeScript and Python SDKs (validate_raw_document).
func validateRawDocument(yamlStr string) []string {
	var root map[string]any
	if err := yaml.Unmarshal([]byte(yamlStr), &root); err != nil {
		// The typed decode in Parse already surfaces structural parse errors;
		// a second report here would be redundant.
		return nil
	}

	var errs []string
	validateRawRules(rawObject(root, "rules"), &errs)
	validateRawExtensions(rawObject(root, "extensions"), &errs)
	validateRawMetadata(rawObject(root, "metadata"), &errs)
	return errs
}

func validateRawRules(rules map[string]any, errs *[]string) {
	if rules == nil {
		return
	}
	if pi := rawObject(rules, "patch_integrity"); pi != nil {
		// max_additions/max_deletions are required (non-Option) usize fields in
		// the reference models: an explicit null -- which serde rejects at parse
		// and which the typed Go model would otherwise silently coerce to a
		// default -- is rejected here, as is a non-integer float.
		checkRawRequiredInteger(pi, "max_additions", "rules.patch_integrity.max_additions", errs)
		checkRawRequiredInteger(pi, "max_deletions", "rules.patch_integrity.max_deletions", errs)
	}
	if ta := rawObject(rules, "tool_access"); ta != nil {
		checkRawInteger(ta, "max_args_size", "rules.tool_access.max_args_size", errs)
	}
	if ce := rawObject(rules, "code_execution"); ce != nil {
		// Option<usize> fields: absent/null are accepted, but a negative value
		// (which serde's unsigned type rejects at parse) must be rejected too.
		checkRawNonNegativeInteger(ce, "max_execution_time_ms", "rules.code_execution.max_execution_time_ms", errs)
		checkRawNonNegativeInteger(ce, "max_scan_bytes", "rules.code_execution.max_scan_bytes", errs)
	}
}

func validateRawExtensions(ext map[string]any, errs *[]string) {
	if ext == nil {
		return
	}

	if posture := rawObject(ext, "posture"); posture != nil {
		// transitions is a required field in the reference models: an absent
		// key is rejected (an empty list is fine).
		if _, ok := posture["transitions"]; !ok {
			*errs = append(*errs, "extensions.posture.transitions is required")
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
				// A present-but-empty free-string match field (e.g.
				// `provider: ""`) is a real, unsatisfiable constraint in the
				// reference SDKs, but the generated Go model collapses "" and an
				// absent field, so reject the empty sentinel here (D4). An
				// absent field is left untouched -- an all-absent match still
				// matches every origin with score 0, matching the others.
				for _, field := range []string{"provider", "tenant_id", "space_id", "sensitivity", "actor_role"} {
					checkRawNonEmptyString(match, field,
						fmt.Sprintf("origins.profiles[%d].match.%s", i, field), errs)
				}
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

func validateRawMetadata(md map[string]any, errs *[]string) {
	if md == nil {
		return
	}
	// policy_version is an Option<usize>: absent/null are accepted, but a
	// non-integer float or a negative value (rejected by the unsigned type at
	// parse in the reference models) is not.
	checkRawNonNegativeInteger(md, "policy_version", "metadata.policy_version", errs)
	if v, ok := md["classification"]; ok {
		if s, isStr := v.(string); !isStr || !containsTyped(Classification(s), Classifications) {
			*errs = append(*errs, fmt.Sprintf("metadata.classification %v is not a valid classification", v))
		}
	}
	if v, ok := md["lifecycle_state"]; ok {
		if s, isStr := v.(string); !isStr || !containsTyped(LifecycleState(s), LifecycleStates) {
			*errs = append(*errs, fmt.Sprintf("metadata.lifecycle_state %v is not a valid lifecycle_state", v))
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
func checkRawInteger(obj map[string]any, key, path string, errs *[]string) {
	v, ok := obj[key]
	if !ok || v == nil {
		return
	}
	if !isRawInteger(v) {
		*errs = append(*errs, fmt.Sprintf("%s must be an integer", path))
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
// non-null value that is not a non-negative integer scalar. It mirrors an
// Option<usize> field in the reference models: an absent key or an explicit
// null is accepted (the field stays None), while a non-integer (e.g. 1.5) or a
// negative integer (e.g. -5, which serde's unsigned type rejects at parse) is
// not. Absent/null are left untouched so an omitted optional field keeps its
// default, matching the other SDKs.
func checkRawNonNegativeInteger(obj map[string]any, key, path string, errs *[]string) {
	v, ok := obj[key]
	if !ok || v == nil {
		return
	}
	if !isRawInteger(v) {
		*errs = append(*errs, fmt.Sprintf("%s must be an integer", path))
		return
	}
	if isRawNegativeInteger(v) {
		*errs = append(*errs, fmt.Sprintf("%s must be non-negative", path))
	}
}

// checkRawRequiredInteger records an error when key is present with a value
// that is null or not an integer scalar. It mirrors a required (non-Option)
// usize field: an absent key is accepted (the typed model supplies the
// default), but an explicit null -- which serde rejects at parse and which the
// typed Go model would otherwise coerce to its default -- is rejected, as is a
// non-integer float. A negative value stays a cross-field concern of
// [Validate], matching the existing behavior for these fields.
func checkRawRequiredInteger(obj map[string]any, key, path string, errs *[]string) {
	v, ok := obj[key]
	if !ok {
		return
	}
	if v == nil || !isRawInteger(v) {
		*errs = append(*errs, fmt.Sprintf("%s must be an integer", path))
	}
}

// checkRawEnum records an error when key is present in obj with a value that is
// not one of allowed. A present-but-empty "" fails, matching the reference SDKs
// that treat "" as a real (invalid) value rather than an absent field.
func checkRawEnum(obj map[string]any, key, path string, allowed map[string]struct{}, errs *[]string) {
	v, ok := obj[key]
	if !ok {
		return
	}
	if s, isStr := v.(string); !isStr || !containsTyped(s, allowed) {
		*errs = append(*errs, fmt.Sprintf("%s %v is not valid", path, v))
	}
}

// checkRawNonEmptyString records an error when key is present in obj with an
// empty string value. An absent key is ignored, so only an explicit "" (which
// the typed model cannot distinguish from absent) is rejected.
func checkRawNonEmptyString(obj map[string]any, key, path string, errs *[]string) {
	v, ok := obj[key]
	if !ok {
		return
	}
	if s, isStr := v.(string); isStr && s == "" {
		*errs = append(*errs, fmt.Sprintf("%s must not be empty", path))
	}
}
