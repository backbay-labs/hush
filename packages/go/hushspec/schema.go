package hushspec

// Model types are generated into generated_models.go via scripts/generate_sdk_models.py.
//
// This file carries the HushSpec YAML profile of core spec 2.4 (D17): a single
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
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// Limits from core spec 2.4 (RECOMMENDED defaults, shared with the Rust
// reference implementation).
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
// receives one is a type error, exactly as in the Rust, TypeScript, and
// Python SDKs.
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

	depth, nodes := measureNode(root.Content[0], 1)
	if depth > MaxDocumentNestingDepth {
		return fmt.Errorf("document nesting exceeds the maximum depth of %d", MaxDocumentNestingDepth)
	}
	if nodes > MaxDocumentNodeCount {
		return fmt.Errorf("document exceeds the maximum node count of %d", MaxDocumentNodeCount)
	}

	return checkTypedBooleans(root.Content[0], reflect.TypeOf(HushSpec{}), "")
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

// measureNode mirrors the Rust reference `measure`: the document's root value
// sits at depth 1, a mapping counts its key and its value as separate nodes
// one level deeper, and every scalar counts as one node.
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

// checkTypedBooleans walks the document alongside the generated model types
// and rejects a YAML 1.1 boolean scalar (`yes`, `no`, `on`, `off`, ...) that
// lands on a Go bool field. gopkg.in/yaml.v3 would silently coerce it; the
// reference SDKs treat it as the string it is under YAML 1.2 Core and fail the
// typed decode. Positions that are not boolean-typed are left alone, so
// `name: yes` stays the string "yes" exactly as in Rust.
func checkTypedBooleans(node *yaml.Node, target reflect.Type, path string) error {
	if node == nil || target == nil {
		return nil
	}
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}

	switch node.Kind {
	case yaml.ScalarNode:
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
			if err := checkTypedBooleans(child, target.Elem(), fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for index := 0; index+1 < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			switch target.Kind() {
			case reflect.Map:
				if err := checkTypedBooleans(value, target.Elem(), path+"."+key.Value); err != nil {
					return err
				}
			case reflect.Struct:
				field, ok := structFieldByYAMLName(target, key.Value)
				if !ok {
					continue
				}
				if err := checkTypedBooleans(value, field.Type, path+"."+key.Value); err != nil {
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
