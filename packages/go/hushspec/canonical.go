package hushspec

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Canonical form of a HushSpec document (spec/hushspec-canonical.md 0.2.0).
//
// Two steps produce one identity that every SDK must agree on:
//
//  1. Canonical projection (spec section 3): walk the *resolved* document
//     alongside its JSON Schema, materialize every schema default inside an
//     object that is present, drop the resolution-only fields, and normalize
//     empty containers that have no default to absence.
//  2. Canonical serialization (spec section 4): RFC 8785 (JCS) over the
//     projected value -- keys ordered by UTF-16 code unit, minimal string
//     escapes, ECMAScript Number::toString formatting, no whitespace.
//
// [ContentHash] then prefixes the SHA-256 of those bytes with "sha256:"
// (spec section 5).
//
// Both entry points require a resolved document: canonicalizing a document
// that still carries `extends` would identify a fragment rather than the
// policy that is enforced, so it is refused.
//
// The projection is defined over the *document*, not over Go's structs. The
// generated model cannot always represent "absent", so this file pins the
// presence rule per field kind (see canonicalPresence) and relies on the
// parse-time default materialization in applyParseDefaults for the handful of
// non-pointer scalars whose schema default is not the Go zero value
// (`enabled`, `audio`, `credential_detection`, `max_additions`,
// `max_deletions`, `max_imbalance_ratio`, `egress.default`).

// contentHashPrefix is the self-describing algorithm prefix required by
// spec/hushspec-canonical.md section 5. Verifiers must reject any other
// prefix; only sha256 is defined in 0.2.
const contentHashPrefix = "sha256:"

// maxSafeInteger is 2^53-1, the largest integer that survives an IEEE 754
// double round trip (spec section 4.3). Larger integers are refused rather
// than rounded.
const maxSafeInteger int64 = 1<<53 - 1

// CanonicalJSON returns the canonical form of a resolved HushSpec document:
// the RFC 8785 serialization of the canonical projection, as a UTF-8 string
// with no whitespace, byte order mark, or trailing newline.
//
// The document must already be resolved; a non-empty Extends is an error.
func CanonicalJSON(spec *HushSpec) (string, error) {
	if spec == nil {
		return "", fmt.Errorf("cannot canonicalize a nil HushSpec document")
	}
	if spec.Extends != "" {
		return "", fmt.Errorf(
			"cannot canonicalize an unresolved HushSpec document: resolve extends %q first",
			spec.Extends,
		)
	}
	projected, err := canonicalProjectStruct(reflect.ValueOf(*spec))
	if err != nil {
		return "", err
	}
	var out strings.Builder
	if err := writeJCS(&out, projected); err != nil {
		return "", err
	}
	return out.String(), nil
}

// ContentHash returns the content hash of a resolved HushSpec document:
// "sha256:" followed by 64 lowercase hex digits of the SHA-256 of the
// canonical form (spec/hushspec-canonical.md section 5). The prefix is part
// of the wire value everywhere a content hash appears.
func ContentHash(spec *HushSpec) (string, error) {
	canonical, err := CanonicalJSON(spec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return contentHashPrefix + hex.EncodeToString(sum[:]), nil
}

// --------------------------------------------------------------------------
// Projection (spec/hushspec-canonical.md section 3)
// --------------------------------------------------------------------------

// canonicalRule captures the three schema facts the projection needs about a
// property: its default (materialized when the property is absent from a
// present object), whether it is required (required properties are never
// dropped by the empty-container rule), and whether an empty value is
// presence-significant (section 3.3's exception table).
type canonicalRule struct {
	def           any
	hasDefault    bool
	required      bool
	preserveEmpty bool
}

type canonicalRules map[string]canonicalRule

func withDefault(v any) canonicalRule { return canonicalRule{def: v, hasDefault: true} }

var (
	canonicalRequired      = canonicalRule{required: true}
	canonicalPreserveEmpty = canonicalRule{preserveEmpty: true}
)

// emptyArrayDefault is the schema default `[]`. Materialized copies are always
// fresh so a caller can never alias this value.
func emptyArrayDefault() any { return []any{} }

// canonicalSchemaRules mirrors, per generated model type, the `default` and
// `required` declarations of schemas/hushspec-{core,posture,origins,detection}
// .v0.schema.json plus the presence-significant exceptions listed in
// spec/hushspec-canonical.md section 3.3. A type absent from this map, or a
// property absent from its entry, has no default, is not required, and is not
// presence-significant.
//
// `merge_strategy` deliberately has no entry: it carries a schema default but
// is a resolution field and must never appear (section 3.1).
var canonicalSchemaRules = map[reflect.Type]canonicalRules{
	reflect.TypeOf(HushSpec{}): {
		"hushspec": canonicalRequired,
	},
	reflect.TypeOf(ForbiddenPathsRule{}): {
		"enabled":    withDefault(true),
		"patterns":   withDefault(emptyArrayDefault()),
		"exceptions": withDefault(emptyArrayDefault()),
	},
	reflect.TypeOf(PathAllowlistRule{}): {
		"enabled": withDefault(false),
		"read":    withDefault(emptyArrayDefault()),
		"write":   withDefault(emptyArrayDefault()),
		"patch":   withDefault(emptyArrayDefault()),
	},
	reflect.TypeOf(EgressRule{}): {
		"enabled": withDefault(true),
		"allow":   withDefault(emptyArrayDefault()),
		"block":   withDefault(emptyArrayDefault()),
		"default": withDefault(string(DefaultActionBlock)),
	},
	reflect.TypeOf(SecretPatternsRule{}): {
		"enabled":    withDefault(true),
		"patterns":   withDefault(emptyArrayDefault()),
		"skip_paths": withDefault(emptyArrayDefault()),
	},
	reflect.TypeOf(SecretPattern{}): {
		"name":     canonicalRequired,
		"pattern":  canonicalRequired,
		"severity": canonicalRequired,
	},
	reflect.TypeOf(PatchIntegrityRule{}): {
		"enabled":             withDefault(true),
		"max_additions":       withDefault(int64(1000)),
		"max_deletions":       withDefault(int64(500)),
		"forbidden_patterns":  withDefault(emptyArrayDefault()),
		"require_balance":     withDefault(false),
		"max_imbalance_ratio": withDefault(float64(10)),
	},
	reflect.TypeOf(ShellCommandsRule{}): {
		"enabled":            withDefault(true),
		"forbidden_patterns": withDefault(emptyArrayDefault()),
	},
	reflect.TypeOf(ToolAccessRule{}): {
		"enabled":              withDefault(true),
		"allow":                withDefault(emptyArrayDefault()),
		"block":                withDefault(emptyArrayDefault()),
		"require_confirmation": withDefault(emptyArrayDefault()),
		"default":              withDefault(string(DefaultActionAllow)),
	},
	reflect.TypeOf(ComputerUseRule{}): {
		"enabled":         withDefault(false),
		"mode":            withDefault(string(ComputerUseModeGuardrail)),
		"allowed_actions": withDefault(emptyArrayDefault()),
	},
	reflect.TypeOf(RemoteDesktopChannelsRule{}): {
		"enabled":       withDefault(false),
		"clipboard":     withDefault(false),
		"file_transfer": withDefault(false),
		"audio":         withDefault(true),
		"drive_mapping": withDefault(false),
	},
	reflect.TypeOf(InputInjectionRule{}): {
		"enabled":                     withDefault(false),
		"allowed_types":               withDefault(emptyArrayDefault()),
		"require_postcondition_probe": withDefault(false),
	},
	reflect.TypeOf(BrowserAutomationRule{}): {
		"enabled":                   withDefault(false),
		"allowed_domains":           withDefault(emptyArrayDefault()),
		"blocked_domains":           withDefault(emptyArrayDefault()),
		"allowed_verbs":             withDefault(emptyArrayDefault()),
		"credential_detection":      withDefault(true),
		"extra_credential_patterns": withDefault(emptyArrayDefault()),
	},
	reflect.TypeOf(CodeExecutionRule{}): {
		"enabled":            withDefault(false),
		"language_allowlist": withDefault(emptyArrayDefault()),
		"module_denylist":    withDefault(emptyArrayDefault()),
		"network_access":     withDefault(false),
	},
	reflect.TypeOf(TimeWindowCondition{}): {
		"start":    canonicalRequired,
		"end":      canonicalRequired,
		"timezone": withDefault("UTC"),
	},
	reflect.TypeOf(RateCondition{}): {
		"counter":    canonicalRequired,
		"threshold":  canonicalRequired,
		"comparison": canonicalRequired,
	},
	reflect.TypeOf(ControlMapping{}): {
		"framework":  canonicalRequired,
		"control_id": canonicalRequired,
		"rule_paths": canonicalRequired,
	},
	reflect.TypeOf(PostureExtension{}): {
		"initial":     canonicalRequired,
		"states":      canonicalRequired,
		"transitions": canonicalRequired,
	},
	reflect.TypeOf(PostureTransition{}): {
		"from": canonicalRequired,
		"to":   canonicalRequired,
		"on":   canonicalRequired,
	},
	reflect.TypeOf(OriginsExtension{}): {
		"default_behavior": withDefault(string(OriginDefaultBehaviorDeny)),
	},
	reflect.TypeOf(OriginProfile{}): {
		"id": canonicalRequired,
		// An explicit `match: {}` is the default profile; an absent `match`
		// never matches (origins spec section 3, D12).
		"match": canonicalPreserveEmpty,
	},
	// OriginToolAccessOverlay and OriginEgressOverlay need no entry: their
	// overlay lists carry no default, are not required, and are not
	// presence-significant. An absent overlay list inherits the base block and
	// an empty one contributes nothing, which evaluate the same (origins spec
	// section 4), so an empty one is omitted like any other empty container.
	reflect.TypeOf(OriginDataPolicy{}): {
		"allow_external_sharing":  withDefault(false),
		"redact_before_send":      withDefault(false),
		"block_sensitive_outputs": withDefault(false),
	},
	reflect.TypeOf(BridgePolicy{}): {
		"allow_cross_origin": withDefault(false),
		"require_approval":   withDefault(false),
	},
	reflect.TypeOf(PromptInjectionDetection{}): {
		"enabled":           withDefault(true),
		"warn_at_or_above":  withDefault(string(DetectionLevelSuspicious)),
		"block_at_or_above": withDefault(string(DetectionLevelHigh)),
		"max_scan_bytes":    withDefault(int64(200000)),
	},
	reflect.TypeOf(PromptInjectionHeuristics{}): {
		"enabled":   withDefault(true),
		"min_score": withDefault(int64(0)),
	},
	reflect.TypeOf(JailbreakDetection{}): {
		"enabled":         withDefault(true),
		"block_threshold": withDefault(int64(80)),
		"warn_threshold":  withDefault(int64(50)),
		"max_input_bytes": withDefault(int64(200000)),
	},
	reflect.TypeOf(ThreatIntelDetection{}): {
		"enabled":              withDefault(false),
		"similarity_threshold": withDefault(0.7),
		"top_k":                withDefault(int64(5)),
	},
}

// canonicalStripped lists the properties removed before projection
// (spec/hushspec-canonical.md section 3.1): the resolution fields, and the
// inline signature reserved by spec/hushspec-signing.md section 7, which must
// not be covered by the hash it signs.
var canonicalStripped = map[reflect.Type]map[string]bool{
	reflect.TypeOf(HushSpec{}): {
		"extends":        true,
		"merge_strategy": true,
	},
	reflect.TypeOf(GovernanceMetadata{}): {
		"signature": true,
	},
}

// canonicalProjectStruct projects a schema object (spec section 3.2) and then
// applies the empty-container rule (section 3.3) to each property.
func canonicalProjectStruct(v reflect.Value) (map[string]any, error) {
	t := v.Type()
	rules := canonicalSchemaRules[t]
	stripped := canonicalStripped[t]
	out := make(map[string]any, t.NumField())

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.PkgPath != "" {
			continue // unexported
		}
		key, ok := canonicalKey(field)
		if !ok {
			return nil, fmt.Errorf(
				"canonical projection: %s.%s has no json or yaml tag", t.Name(), field.Name)
		}
		if key == "-" || stripped[key] {
			continue
		}

		rule := rules[key]
		present, value := canonicalPresence(v.Field(i))
		if !present {
			// Absent: materialize the schema default verbatim, or stay absent.
			// A required property with no default stays absent too -- valid
			// documents always carry it, and inventing one would diverge from
			// the reference projection.
			if rule.hasDefault {
				out[key] = cloneCanonicalDefault(rule.def)
			}
			continue
		}

		projected, err := canonicalProjectValue(value)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", t.Name(), key, err)
		}
		if !rule.hasDefault && !rule.required && !rule.preserveEmpty &&
			isEmptyCanonicalContainer(projected) {
			continue
		}
		out[key] = projected
	}
	return out, nil
}

// canonicalPresence decides whether a struct field stands for a property that
// is present in the document, and returns the value to project.
//
//   - Pointers, slices and maps model presence directly: nil is absent, and a
//     non-nil empty slice or map is a present-but-empty container, which
//     section 3.3 (and its exception table) then judges.
//   - Strings use the SDK-wide omitempty convention: "" is absent. The Go
//     model cannot express a present-but-empty optional string, and every
//     such property is either an enum (where "" is invalid and rejected by
//     validateRawDocument) or free text that is inert when empty.
//   - Booleans, numbers and nested structs cannot express absence at all, so
//     they are always present; Parse materializes the schema defaults whose
//     value is not the Go zero value (see applyParseDefaults).
func canonicalPresence(v reflect.Value) (bool, reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return false, reflect.Value{}
		}
		return true, v.Elem()
	case reflect.Interface:
		if v.IsNil() {
			return false, reflect.Value{}
		}
		return true, v
	case reflect.Slice, reflect.Map:
		if v.IsNil() {
			return false, reflect.Value{}
		}
		return true, v
	case reflect.String:
		if v.Len() == 0 {
			return false, reflect.Value{}
		}
		return true, v
	default:
		return true, v
	}
}

// canonicalProjectValue projects a schema array, schema map, nested object or
// leaf. Free-form values (`when.context` and anything below it) reach this
// function as interfaces and pass through unchanged apart from number
// normalization.
func canonicalProjectValue(v reflect.Value) (any, error) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return nil, nil
		}
		return canonicalProjectValue(v.Elem())
	case reflect.Interface:
		if v.IsNil() {
			return nil, nil
		}
		return canonicalProjectValue(v.Elem())
	case reflect.Struct:
		return canonicalProjectStruct(v)
	case reflect.Slice, reflect.Array:
		out := make([]any, 0, v.Len())
		for i := 0; i < v.Len(); i++ {
			item, err := canonicalProjectValue(v.Index(i))
			if err != nil {
				return nil, fmt.Errorf("[%d]: %w", i, err)
			}
			out = append(out, item)
		}
		return out, nil
	case reflect.Map:
		out := make(map[string]any, v.Len())
		iter := v.MapRange()
		for iter.Next() {
			key := iter.Key()
			if key.Kind() == reflect.Interface {
				key = key.Elem()
			}
			if key.Kind() != reflect.String {
				return nil, fmt.Errorf("object key of kind %s is not a string", key.Kind())
			}
			item, err := canonicalProjectValue(iter.Value())
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key.String(), err)
			}
			out[key.String()] = item
		}
		return out, nil
	case reflect.String:
		return v.String(), nil
	case reflect.Bool:
		return v.Bool(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		u := v.Uint()
		if u > uint64(maxSafeInteger) {
			return nil, fmt.Errorf("integer %d exceeds the safe range (2^53-1)", u)
		}
		return int64(u), nil
	case reflect.Float32, reflect.Float64:
		return v.Float(), nil
	default:
		return nil, fmt.Errorf("unsupported value kind %s", v.Kind())
	}
}

// canonicalKey returns the document property name for a struct field, taken
// from its json tag and falling back to its yaml tag.
func canonicalKey(field reflect.StructField) (string, bool) {
	for _, tag := range []string{"json", "yaml"} {
		value, ok := field.Tag.Lookup(tag)
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(value, ",")
		if name != "" {
			return name, true
		}
	}
	return "", false
}

func cloneCanonicalDefault(v any) any {
	if arr, ok := v.([]any); ok {
		return append([]any{}, arr...)
	}
	return v
}

func isEmptyCanonicalContainer(v any) bool {
	switch x := v.(type) {
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	default:
		return false
	}
}

// --------------------------------------------------------------------------
// RFC 8785 serialization (spec/hushspec-canonical.md section 4)
// --------------------------------------------------------------------------

func writeJCS(out *strings.Builder, value any) error {
	switch v := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		writeJCSString(out, v)
	case int64:
		if v > maxSafeInteger || v < -maxSafeInteger {
			return fmt.Errorf("integer %d exceeds the safe range (2^53-1)", v)
		}
		out.WriteString(strconv.FormatInt(v, 10))
	case float64:
		text, err := es6Number(v)
		if err != nil {
			return err
		}
		out.WriteString(text)
	case []any:
		out.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeJCS(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := sortedUTF16Keys(v)
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			writeJCSString(out, key)
			out.WriteByte(':')
			if err := writeJCS(out, v[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical value type %T", value)
	}
	return nil
}

// sortedUTF16Keys orders object members by their UTF-16 code units
// (RFC 8785 section 3.2.3). Go's own string comparison is UTF-8 byte order,
// which differs above the Basic Multilingual Plane: "€" (U+20AC) must sort
// before "😀" (U+1F600, the surrogate pair D83D DE00), whereas by byte order
// and by code point the emoji comes first.
func sortedUTF16Keys(m map[string]any) []string {
	type encoded struct {
		key   string
		units []uint16
	}
	items := make([]encoded, 0, len(m))
	for key := range m {
		items = append(items, encoded{key: key, units: utf16.Encode([]rune(key))})
	}
	sort.Slice(items, func(i, j int) bool {
		return compareUTF16Units(items[i].units, items[j].units) < 0
	})
	keys := make([]string, len(items))
	for i, item := range items {
		keys[i] = item.key
	}
	return keys
}

func compareUTF16Units(a, b []uint16) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

const hexDigits = "0123456789abcdef"

// writeJCSString emits an RFC 8785 section 3.2.2.2 string: only quote,
// reverse solidus and the C0 controls are escaped. encoding/json cannot be
// used here -- it escapes "<", ">", "&", U+2028 and U+2029 by default, and
// none of those may be escaped in canonical output. Non-ASCII, U+007F and
// astral characters are emitted literally as UTF-8.
func writeJCSString(out *strings.Builder, s string) {
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		default:
			if r < 0x20 {
				out.WriteString(`\u00`)
				out.WriteByte(hexDigits[(r>>4)&0xF])
				out.WriteByte(hexDigits[r&0xF])
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}

// es6Number formats a double exactly as ECMAScript's Number::toString does
// (RFC 8785 section 3.2.2.3): the shortest decimal that round-trips, printed
// positionally between 1e-6 and 1e21 and in exponent notation outside that
// range. Whole values print without a decimal point or exponent, so 10.0 and
// the integer 10 share a canonical form.
func es6Number(value float64) (string, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return "", fmt.Errorf("NaN and Infinity are not representable in JSON")
	}
	if value == 0 {
		return "0", nil // also normalizes -0
	}
	sign := ""
	if value < 0 {
		sign = "-"
		value = -value
	}

	// strconv's 'g'/'e' with precision -1 yields the same shortest
	// round-tripping digits as ECMAScript; the exponential form makes the
	// digit string and the decimal exponent directly readable.
	shortest := strconv.FormatFloat(value, 'e', -1, 64)
	mantissa, exponent, found := strings.Cut(shortest, "e")
	if !found {
		return "", fmt.Errorf("unexpected float formatting %q", shortest)
	}
	exp, err := strconv.Atoi(exponent)
	if err != nil {
		return "", fmt.Errorf("unexpected float exponent %q: %w", shortest, err)
	}
	digits := strings.Replace(mantissa, ".", "", 1)
	for len(digits) > 1 && digits[len(digits)-1] == '0' {
		digits = digits[:len(digits)-1]
	}

	// value == 0.<digits> x 10^n, with k significant digits.
	k := len(digits)
	n := exp + 1

	var body string
	switch {
	case k <= n && n <= 21:
		body = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		body = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		body = "0." + strings.Repeat("0", -n) + digits
	default:
		e := n - 1
		esign := "+"
		if e < 0 {
			esign = "-"
			e = -e
		}
		if k == 1 {
			body = digits + "e" + esign + strconv.Itoa(e)
		} else {
			body = digits[:1] + "." + digits[1:] + "e" + esign + strconv.Itoa(e)
		}
	}
	return sign + body, nil
}
