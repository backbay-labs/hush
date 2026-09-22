package hushspec

// Model types are generated into generated_models.go via scripts/generate_sdk_models.py.
//
// This file carries the HushSpec YAML profile of core spec 2.4: a single
// document, YAML 1.2 Core scalar resolution, no anchors, aliases, or merge
// keys, no tab indentation, and bounded size, nesting depth, and node count.
// gopkg.in/yaml.v3 enforces only part of that on its own (it rejects duplicate
// mapping keys and tab indentation, and resolves `yes`/`no`/`on`/`off` as
// strings for untyped decoding), so the remaining rules are checked here
// before the typed decode.

import (
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Limits from core spec 2.4 (its RECOMMENDED defaults, which every HushSpec
// engine shares).
const (
	// MaxDocumentBytes is the maximum accepted document size in bytes.
	MaxDocumentBytes = 1024 * 1024
	// MaxDocumentNestingDepth is the maximum accepted YAML nesting depth.
	MaxDocumentNestingDepth = 32
	// MaxDocumentNodeCount is the maximum accepted YAML node count.
	MaxDocumentNodeCount = 100_000
)

// yaml11Booleans are the scalars gopkg.in/yaml.v3 coerces into a typed bool
// field for YAML 1.1 compatibility. Under the YAML 1.2 Core schema of the
// HushSpec profile they are plain strings, so a boolean-typed field that
// receives one is a type error.
var yaml11Booleans = map[string]struct{}{
	"y": {}, "Y": {}, "yes": {}, "Yes": {}, "YES": {},
	"n": {}, "N": {}, "no": {}, "No": {}, "NO": {},
	"on": {}, "On": {}, "ON": {},
	"off": {}, "Off": {}, "OFF": {},
}

// enforceYAMLProfile checks a raw document against the HushSpec YAML profile
// and returns a descriptive error, or nil when the document conforms. It is
// called by [Parse] before the typed decode.
func enforceYAMLProfile(yamlStr string) error {
	if len(yamlStr) > MaxDocumentBytes {
		return fmt.Errorf("document exceeds the maximum size of %d bytes", MaxDocumentBytes)
	}

	decoder := yaml.NewDecoder(strings.NewReader(yamlStr))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			// An empty stream: the typed decode reports the missing version.
			return nil
		}
		// A structural parse error (tab indentation, bad syntax); the typed
		// decode in Parse reports it with the same message.
		return nil
	}

	var second yaml.Node
	if err := decoder.Decode(&second); err == nil {
		return errors.New("multi-document streams are not allowed (YAML profile)")
	} else if !errors.Is(err, io.EOF) {
		// A malformed second document is still a second document.
		return errors.New("multi-document streams are not allowed (YAML profile)")
	}

	if len(root.Content) == 0 {
		return nil
	}
	if err := checkProfileNode(root.Content[0], 1); err != nil {
		return err
	}
	normalizeNonSpecificTags(root.Content[0], strings.Split(yamlStr, "\n"), 1)
	if err := normalizeCoreNode(root.Content[0], 1); err != nil {
		return err
	}
	if err := checkIntegerLiterals(root.Content[0], 1); err != nil {
		return err
	}

	depth, nodes := measureNode(root.Content[0], 1)
	if depth > MaxDocumentNestingDepth {
		return fmt.Errorf("document nesting exceeds the maximum depth of %d", MaxDocumentNestingDepth)
	}
	if nodes > MaxDocumentNodeCount {
		return fmt.Errorf("document exceeds the maximum node count of %d", MaxDocumentNodeCount)
	}

	return normalizeTypedScalars(root.Content[0], reflect.TypeOf(HushSpec{}), "")
}

// checkProfileNode rejects anchors, aliases, and merge keys anywhere in the
// document tree.
func checkProfileNode(node *yaml.Node, depth int) error {
	if node == nil {
		return nil
	}
	if depth > MaxDocumentNestingDepth+1 {
		// Bail out rather than recurse without bound; the depth check that
		// follows reports the violation.
		return nil
	}
	if node.Anchor != "" {
		return fmt.Errorf("line %d: anchors are not allowed (YAML profile)", node.Line)
	}
	if node.Kind == yaml.AliasNode {
		return fmt.Errorf("line %d: aliases are not allowed (YAML profile)", node.Line)
	}
	if node.Tag == "!!merge" {
		return fmt.Errorf("line %d: merge keys are not allowed (YAML profile)", node.Line)
	}
	for _, child := range node.Content {
		if err := checkProfileNode(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// integerLiteralPattern matches the integer syntax of the YAML 1.2 Core
// schema: an optional sign and digits, decimal or with a base prefix, and no
// fraction or exponent.
var integerLiteralPattern = regexp.MustCompile(`^(?:[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)$`)
var coreFloatPattern = regexp.MustCompile(`^[-+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]+)?$`)

// Normalize the scalar nodes, then feed exactly this interpretation to all
// typed/default/raw-validation passes. yaml.v3 otherwise applies YAML 1.1
// numeric and timestamp resolution separately in each of those passes.
func normalizeCoreYAML(source string) (string, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(source), &root); err != nil {
		return "", err
	}
	normalizeNonSpecificTags(&root, strings.Split(source, "\n"), 0)
	if err := normalizeCoreNode(&root, 0); err != nil {
		return "", err
	}
	if len(root.Content) > 0 {
		if err := normalizeTypedScalars(root.Content[0], reflect.TypeOf(HushSpec{}), ""); err != nil {
			return "", err
		}
	}
	data, err := yaml.Marshal(&root)
	return string(data), err
}

// yaml.v3 discards the non-specific `!` tag and implicitly resolves its scalar.
// Its node marker still points at that tag in the original source. Restore the
// mandated string type before the Core resolver sees the scalar spelling.
func normalizeNonSpecificTags(node *yaml.Node, lines []string, depth int) {
	if depth > MaxDocumentNestingDepth+1 {
		return
	}
	if node.Kind == yaml.ScalarNode && node.Line > 0 && node.Line <= len(lines) {
		line := []rune(lines[node.Line-1])
		index := node.Column - 1
		if index >= 0 && index < len(line) && line[index] == '!' && (index+1 == len(line) || line[index+1] == ' ' || line[index+1] == '\t' || line[index+1] == '\r') {
			node.Tag, node.Style = "!!str", yaml.DoubleQuotedStyle
		}
	}
	for _, child := range node.Content {
		normalizeNonSpecificTags(child, lines, depth+1)
	}
}

func normalizeCoreNode(node *yaml.Node, depth int) error {
	if depth > MaxDocumentNestingDepth+1 {
		return nil
	}
	if (node.Kind == yaml.MappingNode && node.Tag != "!!map") ||
		(node.Kind == yaml.SequenceNode && node.Tag != "!!seq") {
		return fmt.Errorf("line %d: unsupported or mismatched collection tag %s", node.Line, node.Tag)
	}
	if node.Kind == yaml.ScalarNode && node.Style&yaml.TaggedStyle != 0 {
		tag := node.Tag
		if tag == "!!str" {
			node.Style = yaml.DoubleQuotedStyle
			return nil
		}
		if tag != "!!int" && tag != "!!float" && tag != "!!bool" && tag != "!!null" {
			return fmt.Errorf("line %d: unsupported scalar tag %s", node.Line, tag)
		}
		if tag == "!!float" && !coreFloatPattern.MatchString(node.Value) {
			return fmt.Errorf("line %d: invalid YAML 1.2 Core float", node.Line)
		}
		node.Style = 0
		if err := normalizeCoreNode(node, depth); err != nil {
			return err
		}
		if tag == "!!float" && node.Tag == "!!int" {
			node.Tag, node.Value = "!!float", node.Value+".0"
		}
		if node.Tag != tag {
			return fmt.Errorf("line %d: invalid YAML 1.2 Core %s scalar", node.Line, tag)
		}
		return nil
	}
	if node.Kind == yaml.ScalarNode && node.Style == 0 {
		text := node.Value
		switch {
		case integerLiteralPattern.MatchString(text):
			base, digits := 10, text
			if strings.HasPrefix(text, "0o") {
				base, digits = 8, text[2:]
			}
			if strings.HasPrefix(text, "0x") {
				base, digits = 16, text[2:]
			}
			value, err := strconv.ParseInt(digits, base, 64)
			if err != nil || value > maxSafeInteger || value < -maxSafeInteger {
				return integerRangeError(node)
			}
			node.Tag, node.Value = "!!int", strconv.FormatInt(value, 10)
		case coreFloatPattern.MatchString(text):
			value, err := strconv.ParseFloat(text, 64)
			if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
				return fmt.Errorf("line %d: non-finite numbers are not allowed", node.Line)
			}
			node.Tag, node.Value = "!!float", strconv.FormatFloat(value, 'g', -1, 64)
			if !strings.ContainsAny(node.Value, ".eE") {
				node.Value += ".0"
			}
		case text == "true" || text == "True" || text == "TRUE" || text == "false" || text == "False" || text == "FALSE":
			node.Tag, node.Value = "!!bool", strings.ToLower(text)
		case text == "" || text == "~" || text == "null" || text == "Null" || text == "NULL":
			node.Tag, node.Value = "!!null", "null"
		case text == ".nan" || text == ".NaN" || text == ".NAN" || strings.EqualFold(strings.TrimLeft(text, "+-"), ".inf"):
			return fmt.Errorf("line %d: non-finite numbers are not allowed", node.Line)
		default:
			node.Tag = "!!str"
			// Quoting prevents yaml.v3 from reinterpreting Core strings during
			// any later decode, including legacy numbers and date-like text.
			node.Style = yaml.DoubleQuotedStyle
		}
	}
	for _, child := range node.Content {
		if err := normalizeCoreNode(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// checkIntegerLiterals refuses a plain scalar written in integer syntax whose
// magnitude an IEEE 754 double cannot hold exactly (canonical spec 4.3).
//
// The bound belongs to integer syntax, and this is the only place the document
// still carries any: gopkg.in/yaml.v3 hands a literal past int64 and uint64
// over as a float64, so by the time the canonical projection sees one it is
// indistinguishable from a float-syntax value, which carries no bound.
// Refusing here keeps a rounded integer out of a content hash.
func checkIntegerLiterals(node *yaml.Node, depth int) error {
	if node == nil || depth > MaxDocumentNestingDepth+1 {
		// The depth check that follows reports an over-deep document; stop
		// descending rather than recurse without bound.
		return nil
	}
	if node.Kind == yaml.ScalarNode {
		// A quoted scalar is a string, whatever its digits spell.
		if node.Style != 0 || !integerLiteralPattern.MatchString(node.Value) {
			return nil
		}
		if value, err := strconv.ParseInt(node.Value, 0, 64); err == nil {
			if value > maxSafeInteger || value < -maxSafeInteger {
				return integerRangeError(node)
			}
			return nil
		}
		if value, err := strconv.ParseUint(node.Value, 0, 64); err == nil {
			if value > uint64(maxSafeInteger) {
				return integerRangeError(node)
			}
			return nil
		}
		// Too large for either 64-bit form, so past the safe range as well.
		return integerRangeError(node)
	}
	for _, child := range node.Content {
		if err := checkIntegerLiterals(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func integerRangeError(node *yaml.Node) error {
	return fmt.Errorf("line %d: integer %s exceeds the safe range (2^53-1)", node.Line, node.Value)
}

// measureNode returns the document's nesting depth and node count as core spec
// 2.4 counts them: the root value sits at depth 1, a mapping counts its key and
// its value as separate nodes one level deeper, and every scalar counts as one
// node.
func measureNode(node *yaml.Node, depth int) (int, int) {
	if node == nil {
		return depth, 0
	}
	if depth > MaxDocumentNestingDepth {
		// The cap is already exceeded; stop descending rather than recursing
		// to the bottom of an adversarially deep document.
		return depth, 1
	}
	switch node.Kind {
	case yaml.SequenceNode, yaml.MappingNode:
		maxDepth, count := depth, 1
		for _, child := range node.Content {
			childDepth, childCount := measureNode(child, depth+1)
			if childDepth > maxDepth {
				maxDepth = childDepth
			}
			count += childCount
		}
		return maxDepth, count
	default:
		return depth, 1
	}
}

// normalizeTypedScalars walks the generated model types: string and boolean
// properties cannot coerce another scalar type; integer properties normalize
// integral doubles within the portable bound. Free-form values remain doubles.
func normalizeTypedScalars(node *yaml.Node, target reflect.Type, path string) error {
	if node == nil || target == nil {
		return nil
	}
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}

	switch node.Kind {
	case yaml.ScalarNode:
		if target.Kind() == reflect.String && node.Tag != "!!str" && node.Tag != "!!null" {
			return fmt.Errorf("%s: invalid type: %s, expected a string", path, node.Tag)
		}
		if target.Kind() >= reflect.Int && target.Kind() <= reflect.Uint64 && node.Tag == "!!float" {
			value, err := strconv.ParseFloat(node.Value, 64)
			if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || math.Abs(value) > float64(maxSafeInteger) {
				return fmt.Errorf("%s: integer field exceeds the safe range (2^53-1)", path)
			}
			if math.Trunc(value) == value {
				node.Tag, node.Value = "!!int", strconv.FormatInt(int64(value), 10)
			}
		}
		if target.Kind() != reflect.Bool {
			return nil
		}
		if node.Tag != "!!str" {
			return nil
		}
		if _, ok := yaml11Booleans[node.Value]; !ok {
			return nil
		}
		return fmt.Errorf(
			"line %d: %s expected a boolean; %q is a string under the YAML 1.2 Core schema (YAML profile)",
			node.Line, strings.TrimPrefix(path, "."), node.Value,
		)
	case yaml.SequenceNode:
		if target.Kind() != reflect.Slice && target.Kind() != reflect.Array {
			return nil
		}
		for index, child := range node.Content {
			if err := normalizeTypedScalars(child, target.Elem(), fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for index := 0; index+1 < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			switch target.Kind() {
			case reflect.Map:
				if err := normalizeTypedScalars(value, target.Elem(), path+"."+key.Value); err != nil {
					return err
				}
			case reflect.Struct:
				field, ok := structFieldByYAMLName(target, key.Value)
				if !ok {
					continue
				}
				if err := normalizeTypedScalars(value, field.Type, path+"."+key.Value); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// structFieldByYAMLName resolves a YAML mapping key to the struct field that
// carries it, using the generated `yaml:"name,..."` tags.
func structFieldByYAMLName(target reflect.Type, name string) (reflect.StructField, bool) {
	for index := 0; index < target.NumField(); index++ {
		field := target.Field(index)
		tag := field.Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		if tagName, _, _ := strings.Cut(tag, ","); tagName == name {
			return field, true
		}
	}
	return reflect.StructField{}, false
}
