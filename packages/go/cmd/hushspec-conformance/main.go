// Command hushspec-conformance exposes Go SDK observations to an external
// controller. It does not know the corpus's expected answers or grade itself.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"unicode/utf8"

	hushspec "github.com/backbay-labs/hush/packages/go/hushspec"
)

const protocol = "0.1.0"
const maxRequest = 16 * 1024 * 1024

type request struct {
	Protocol    string          `json:"protocol"`
	RunID       string          `json:"run_id"`
	CaseID      string          `json:"case_id"`
	Operation   string          `json:"operation"`
	InputSHA256 string          `json:"input_sha256"`
	Input       json.RawMessage `json:"input"`
}
type observation struct {
	Status     string         `json:"status"`
	Value      map[string]any `json:"value,omitempty"`
	Phase      string         `json:"phase,omitempty"`
	Diagnostic string         `json:"diagnostic,omitempty"`
	Code       string         `json:"code,omitempty"`
}
type response struct {
	Protocol    string      `json:"protocol"`
	RunID       string      `json:"run_id"`
	CaseID      string      `json:"case_id"`
	Operation   string      `json:"operation"`
	InputSHA256 string      `json:"input_sha256"`
	Result      observation `json:"result"`
}
type operationInput struct {
	Policy    string            `json:"policy"`
	Base      string            `json:"base"`
	Child     string            `json:"child"`
	Source    string            `json:"source"`
	Documents map[string]string `json:"documents"`
	Action    json.RawMessage   `json:"action"`
}

func strictJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("JSON is not UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch token := token.(type) {
		case json.Delim:
			if depth >= 64 {
				return fmt.Errorf("JSON depth exceeds 64")
			}
			switch token {
			case '{':
				seen := map[string]bool{}
				for decoder.More() {
					key, err := decoder.Token()
					if err != nil {
						return err
					}
					name, ok := key.(string)
					if !ok || seen[name] {
						return fmt.Errorf("duplicate or invalid JSON key")
					}
					seen[name] = true
					if err := value(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for decoder.More() {
					if err := value(depth + 1); err != nil {
						return err
					}
				}
			default:
				return fmt.Errorf("unexpected delimiter")
			}
			_, err = decoder.Token()
			return err
		case json.Number:
			_, err := token.Float64()
			return err
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}

func decodeClosed(raw []byte, target any, required []string) error {
	if err := strictJSON(raw); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if fields == nil || len(fields) != len(required) {
		return fmt.Errorf("missing or unknown request member")
	}
	for _, name := range required {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("missing or null %s", name)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func run(in io.Reader, out io.Writer) error {
	raw, err := io.ReadAll(io.LimitReader(in, maxRequest+1))
	if err != nil {
		return err
	}
	if len(raw) > maxRequest {
		return fmt.Errorf("request exceeds 16 MiB")
	}
	var req request
	if err := decodeClosed(raw, &req, []string{"protocol", "run_id", "case_id", "operation", "input_sha256", "input"}); err != nil {
		return err
	}
	if req.Protocol != protocol || req.RunID == "" || len(req.RunID) > 128 || req.CaseID == "" || len(req.CaseID) > 4096 {
		return fmt.Errorf("invalid protocol or binding")
	}
	switch req.Operation {
	case "parse", "validate", "merge", "resolve", "evaluate", "canonicalize":
	default:
		return fmt.Errorf("unknown protocol operation")
	}
	sum := sha256.Sum256(req.Input)
	if req.InputSHA256 != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("input digest mismatch")
	}
	result := observe(req.Operation, req.Input)
	return json.NewEncoder(out).Encode(response{Protocol: req.Protocol, RunID: req.RunID, CaseID: req.CaseID, Operation: req.Operation, InputSHA256: req.InputSHA256, Result: result})
}

func fault(err error) observation { return observation{Status: "error", Diagnostic: err.Error()} }
func rejected(phase string, err error) observation {
	code, _ := hushspec.ErrorCodeOf(err)
	if phase == "resolve" {
		if reason, ok := hushspec.ResolveReason(err); ok {
			code = reason
		}
	}
	return observation{Status: "rejected", Phase: phase, Diagnostic: err.Error(), Code: code}
}
func observed(value any) observation {
	raw, err := json.Marshal(value)
	if err != nil {
		return fault(err)
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		return fault(err)
	}
	return observation{Status: "ok", Value: object}
}
func validated(policy *hushspec.HushSpec) error {
	result := hushspec.Validate(policy)
	if len(result.Errors) > 0 {
		return &result.Errors[0]
	}
	return nil
}

// Names identify only entries in the request's map, never host paths or URLs.
func logicalName(name string) (string, error) {
	prefix := ""
	if strings.HasPrefix(name, "builtin:") {
		prefix = "builtin:"
		name = strings.TrimPrefix(name, prefix)
	}
	cleaned := path.Clean(name)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") || strings.ContainsAny(cleaned, "\\:\x00") {
		return "", fmt.Errorf("invalid logical document name %q", name)
	}
	return prefix + cleaned, nil
}

func suppliedResolver(input operationInput, policy *hushspec.HushSpec) (*hushspec.HushSpec, error) {
	documents := make(map[string]string, len(input.Documents))
	for name, text := range input.Documents {
		canonical, err := logicalName(name)
		if err != nil {
			return nil, err
		}
		if _, exists := documents[canonical]; exists {
			return nil, fmt.Errorf("duplicate document alias %q", name)
		}
		documents[canonical] = text
	}
	source, err := logicalName(input.Source)
	if err != nil {
		return nil, err
	}
	if text, present := documents[source]; present && text != input.Policy {
		return nil, fmt.Errorf("root source has conflicting document bytes")
	}
	loader := func(reference, from string) (*hushspec.LoadedSpec, error) {
		candidates := []string{reference}
		if !strings.HasPrefix(reference, "builtin:") && !strings.HasPrefix(from, "builtin:") {
			candidates = []string{path.Join(path.Dir(from), reference)}
		}
		for _, candidate := range candidates {
			name, err := logicalName(candidate)
			if err != nil {
				continue
			}
			aliases := []string{name}
			if !strings.HasPrefix(name, "builtin:") && path.Ext(name) == "" {
				aliases = append(aliases, name+".yaml", name+".yml")
			}
			for _, alias := range aliases {
				raw, present := documents[alias]
				if !present {
					continue
				}
				parsed, err := hushspec.Parse(raw)
				if err != nil {
					return nil, err
				}
				if err := validated(parsed); err != nil {
					return nil, err
				}
				return &hushspec.LoadedSpec{Source: alias, Spec: parsed}, nil
			}
		}
		return nil, &hushspec.NotFoundError{Reference: reference, Message: "not in supplied document map"}
	}
	resolved, err := hushspec.ResolveWithOptions(policy, source, loader, hushspec.ResolveOptions{
		// An omitted locator would read ambient .sig files beside source names.
		SignatureLocator: func(string) ([]byte, bool, error) { return nil, false, nil },
	})
	if err != nil {
		return nil, err
	}
	return resolved.Spec, nil
}

func observe(operation string, raw json.RawMessage) observation {
	var required []string
	switch operation {
	case "parse", "validate", "canonicalize":
		required = []string{"policy"}
	case "merge":
		required = []string{"base", "child"}
	case "resolve":
		required = []string{"policy", "source", "documents"}
	case "evaluate":
		required = []string{"policy", "source", "documents", "action"}
	default:
		return observation{Status: "unsupported"}
	}
	var input operationInput
	if err := decodeClosed(raw, &input, required); err != nil {
		return fault(err)
	}
	if operation == "merge" {
		base, err := hushspec.Parse(input.Base)
		if err != nil {
			return rejected("parse", err)
		}
		child, err := hushspec.Parse(input.Child)
		if err != nil {
			return rejected("parse", err)
		}
		for _, policy := range []*hushspec.HushSpec{base, child} {
			if err := validated(policy); err != nil {
				return rejected("validate", err)
			}
		}
		return observed(hushspec.Merge(base, child))
	}
	policy, err := hushspec.Parse(input.Policy)
	if err != nil {
		return rejected("parse", err)
	}
	if operation == "parse" {
		return observed(policy)
	}
	if err := validated(policy); err != nil {
		return rejected("validate", err)
	}
	switch operation {
	case "validate":
		return observed(policy)
	case "resolve", "evaluate":
		if input.Source == "" || input.Documents == nil {
			return fault(fmt.Errorf("source and document map are required"))
		}
		// null map values decode to empty strings in Go; reject them as malformed
		// protocol input instead of reinterpreting them as an empty policy.
		var envelope map[string]json.RawMessage
		_ = json.Unmarshal(raw, &envelope)
		var documents map[string]json.RawMessage
		_ = json.Unmarshal(envelope["documents"], &documents)
		for _, value := range documents {
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return fault(fmt.Errorf("null document source"))
			}
		}
		resolved, err := suppliedResolver(input, policy)
		if err != nil {
			return rejected("resolve", err)
		}
		if operation == "resolve" {
			return observed(resolved)
		}
		var action hushspec.EvaluationAction
		decoder := json.NewDecoder(bytes.NewReader(input.Action))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&action); err != nil {
			return fault(err)
		}
		if action.Type == "" {
			return fault(fmt.Errorf("action type is required"))
		}
		return observed(hushspec.EvaluateWithDetection(resolved, &action).Evaluation)
	case "canonicalize":
		canonical, err := hushspec.CanonicalJSON(policy)
		if err != nil {
			return rejected("canonicalize", err)
		}
		hash, err := hushspec.ContentHash(policy)
		if err != nil {
			return rejected("canonicalize", err)
		}
		return observed(map[string]any{"canonical": canonical, "content_hash": hash})
	}
	return fault(fmt.Errorf("unreachable operation"))
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
