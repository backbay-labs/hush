package hushspec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// canonicalSchemaSources maps each generated model type onto the schema node
// it is projected against: a schema file plus a `$defs` name, or "" for that
// schema document's root.
var canonicalSchemaSources = map[reflect.Type]struct{ file, def string }{
	reflect.TypeOf(HushSpec{}):                  {"hushspec-core.v0.schema.json", ""},
	reflect.TypeOf(Rules{}):                     {"hushspec-core.v0.schema.json", "Rules"},
	reflect.TypeOf(ForbiddenPathsRule{}):        {"hushspec-core.v0.schema.json", "ForbiddenPaths"},
	reflect.TypeOf(PathAllowlistRule{}):         {"hushspec-core.v0.schema.json", "PathAllowlist"},
	reflect.TypeOf(EgressRule{}):                {"hushspec-core.v0.schema.json", "Egress"},
	reflect.TypeOf(SecretPatternsRule{}):        {"hushspec-core.v0.schema.json", "SecretPatterns"},
	reflect.TypeOf(SecretPattern{}):             {"hushspec-core.v0.schema.json", "SecretPattern"},
	reflect.TypeOf(PatchIntegrityRule{}):        {"hushspec-core.v0.schema.json", "PatchIntegrity"},
	reflect.TypeOf(ShellCommandsRule{}):         {"hushspec-core.v0.schema.json", "ShellCommands"},
	reflect.TypeOf(ToolAccessRule{}):            {"hushspec-core.v0.schema.json", "ToolAccess"},
	reflect.TypeOf(ComputerUseRule{}):           {"hushspec-core.v0.schema.json", "ComputerUse"},
	reflect.TypeOf(RemoteDesktopChannelsRule{}): {"hushspec-core.v0.schema.json", "RemoteDesktopChannels"},
	reflect.TypeOf(InputInjectionRule{}):        {"hushspec-core.v0.schema.json", "InputInjection"},
	reflect.TypeOf(BrowserAutomationRule{}):     {"hushspec-core.v0.schema.json", "BrowserAutomation"},
	reflect.TypeOf(CodeExecutionRule{}):         {"hushspec-core.v0.schema.json", "CodeExecution"},
	reflect.TypeOf(Condition{}):                 {"hushspec-core.v0.schema.json", "Condition"},
	reflect.TypeOf(TimeWindowCondition{}):       {"hushspec-core.v0.schema.json", "TimeWindow"},
	reflect.TypeOf(Extensions{}):                {"hushspec-core.v0.schema.json", "Extensions"},
	reflect.TypeOf(GovernanceMetadata{}):        {"hushspec-core.v0.schema.json", "GovernanceMetadata"},
	reflect.TypeOf(ControlMapping{}):            {"hushspec-core.v0.schema.json", "ControlMapping"},

	reflect.TypeOf(PostureExtension{}):  {"hushspec-posture.v0.schema.json", ""},
	reflect.TypeOf(PostureState{}):      {"hushspec-posture.v0.schema.json", "PostureState"},
	reflect.TypeOf(PostureTransition{}): {"hushspec-posture.v0.schema.json", "PostureTransition"},

	reflect.TypeOf(OriginsExtension{}):        {"hushspec-origins.v0.schema.json", ""},
	reflect.TypeOf(OriginProfile{}):           {"hushspec-origins.v0.schema.json", "OriginProfile"},
	reflect.TypeOf(OriginMatch{}):             {"hushspec-origins.v0.schema.json", "OriginMatch"},
	reflect.TypeOf(OriginToolAccessOverlay{}): {"hushspec-origins.v0.schema.json", "ToolAccessRule"},
	reflect.TypeOf(OriginEgressOverlay{}):     {"hushspec-origins.v0.schema.json", "EgressRule"},
	reflect.TypeOf(OriginDataPolicy{}):        {"hushspec-origins.v0.schema.json", "DataPolicy"},
	reflect.TypeOf(OriginBudgets{}):           {"hushspec-origins.v0.schema.json", "OriginBudgets"},
	reflect.TypeOf(BridgePolicy{}):            {"hushspec-origins.v0.schema.json", "BridgePolicy"},
	reflect.TypeOf(BridgeTarget{}):            {"hushspec-origins.v0.schema.json", "BridgeTarget"},

	reflect.TypeOf(DetectionExtension{}):       {"hushspec-detection.v0.schema.json", ""},
	reflect.TypeOf(PromptInjectionDetection{}): {"hushspec-detection.v0.schema.json", "PromptInjectionDetection"},
	reflect.TypeOf(JailbreakDetection{}):       {"hushspec-detection.v0.schema.json", "JailbreakDetection"},
	reflect.TypeOf(ThreatIntelDetection{}):     {"hushspec-detection.v0.schema.json", "ThreatIntelDetection"},
}

// TestCanonicalRulesMatchSchemas keeps canonicalSchemaRules honest against the
// published JSON Schemas. The canonical projection is schema-derived
// (spec/hushspec-canonical.md section 1.2), so a schema change that adds,
// removes, or retunes a `default` or a `required` entry must be reflected in
// the table -- otherwise the Go SDK silently stops agreeing with the other
// three on the content hash.
//
// `merge_strategy` is the one deliberate deviation: it carries a schema
// default but is a resolution field and must never be materialized
// (section 3.1). `preserveEmpty` is not schema-derivable -- it comes from the
// exception table in section 3.3 -- and is not checked here.
func TestCanonicalRulesMatchSchemas(t *testing.T) {
	repoRoot := fixtureRepoRoot(t)
	schemas := map[string]map[string]any{}
	loadSchema := func(file string) map[string]any {
		if cached, ok := schemas[file]; ok {
			return cached
		}
		data, err := os.ReadFile(filepath.Join(repoRoot, "schemas", file))
		if err != nil {
			t.Fatalf("failed to read schema %s: %v", file, err)
		}
		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("failed to parse schema %s: %v", file, err)
		}
		schemas[file] = doc
		return doc
	}

	// Every type the projection can reach must be mapped, so a new model type
	// cannot slip in unchecked.
	for goType := range canonicalSchemaRules {
		if _, ok := canonicalSchemaSources[goType]; !ok {
			t.Errorf("%s has canonical rules but no schema source mapping", goType.Name())
		}
	}

	for goType, source := range canonicalSchemaSources {
		node := loadSchema(source.file)
		if source.def != "" {
			defs, _ := node["$defs"].(map[string]any)
			sub, ok := defs[source.def].(map[string]any)
			if !ok {
				t.Errorf("%s: %s has no $defs/%s", goType.Name(), source.file, source.def)
				continue
			}
			node = sub
		}

		properties, _ := node["properties"].(map[string]any)
		required := map[string]bool{}
		if list, ok := node["required"].([]any); ok {
			for _, item := range list {
				if name, ok := item.(string); ok {
					required[name] = true
				}
			}
		}

		have := canonicalSchemaRules[goType]
		stripped := canonicalStripped[goType]
		seen := map[string]bool{}

		for key, raw := range properties {
			if stripped[key] {
				continue
			}
			property, _ := raw.(map[string]any)
			schemaDefault, hasDefault := property["default"]
			rule, mapped := have[key]
			seen[key] = true

			if hasDefault != rule.hasDefault {
				t.Errorf("%s.%s: schema hasDefault=%v but canonical rules say %v",
					goType.Name(), key, hasDefault, rule.hasDefault)
			} else if hasDefault && canonicalText(t, schemaDefault) != canonicalText(t, rule.def) {
				t.Errorf("%s.%s: schema default %s but canonical rules say %s",
					goType.Name(), key,
					canonicalText(t, schemaDefault), canonicalText(t, rule.def))
			}
			if required[key] != rule.required {
				t.Errorf("%s.%s: schema required=%v but canonical rules say %v",
					goType.Name(), key, required[key], rule.required)
			}
			if !mapped && (hasDefault || required[key]) {
				t.Errorf("%s.%s: unmapped property with a default or required flag",
					goType.Name(), key)
			}
		}

		for key := range have {
			if !seen[key] && !stripped[key] {
				t.Errorf("%s.%s: canonical rules name a property the schema does not declare",
					goType.Name(), key)
			}
		}

		// Every document property the Go model carries must exist in the
		// schema, otherwise the projection would emit a member no other SDK
		// knows about.
		for i := 0; i < goType.NumField(); i++ {
			field := goType.Field(i)
			if field.PkgPath != "" {
				continue
			}
			key, ok := canonicalKey(field)
			if !ok || key == "-" || stripped[key] {
				continue
			}
			if _, ok := properties[key]; !ok {
				t.Errorf("%s.%s (%s): no such property in %s",
					goType.Name(), field.Name, key, strings.TrimSuffix(source.file, ".json"))
			}
		}
	}
}

// canonicalText renders a value the way the canonical serializer would, so a
// schema's 10.0 and the table's int64(10) compare equal exactly when they
// canonicalize equal.
func canonicalText(t *testing.T, value any) string {
	t.Helper()
	var out strings.Builder
	if err := writeJCS(&out, normalizeJSONValue(value)); err != nil {
		t.Fatalf("failed to render %#v: %v", value, err)
	}
	return out.String()
}

// normalizeJSONValue converts encoding/json's decoding of a schema default
// (float64 for every number, []any / map[string]any for containers) into the
// value types the canonical serializer accepts.
func normalizeJSONValue(value any) any {
	switch v := value.(type) {
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, normalizeJSONValue(item))
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = normalizeJSONValue(item)
		}
		return out
	case int:
		return int64(v)
	default:
		return value
	}
}
