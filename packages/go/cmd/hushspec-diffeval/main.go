// Command hushspec-diffeval evaluates a HushSpec differential case bundle
// and prints a JSON report for the cross-SDK differential runner.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	hushspec "github.com/backbay-labs/hush/packages/go/hushspec"
	"gopkg.in/yaml.v3"
)

type caseBundle struct {
	HushspecDiff string      `json:"hushspec_diff"`
	Seed         uint64      `json:"seed"`
	GeneratedBy  string      `json:"generated_by"`
	Groups       []caseGroup `json:"groups"`
}

type caseGroup struct {
	ID      string         `json:"id"`
	Policy  map[string]any `json:"policy"`
	Actions []caseAction   `json:"actions"`
}

type caseAction struct {
	ID     string          `json:"id"`
	Action json.RawMessage `json:"action"`
}

type verdict struct {
	Status  string            `json:"status"`
	Phase   string            `json:"phase,omitempty"`
	Message string            `json:"message,omitempty"`
	Result  *normalizedResult `json:"result,omitempty"`
}

type normalizedResult struct {
	Decision      string                  `json:"decision"`
	MatchedRule   string                  `json:"matched_rule,omitempty"`
	Reason        string                  `json:"reason,omitempty"`
	OriginProfile string                  `json:"origin_profile,omitempty"`
	Posture       *hushspec.PostureResult `json:"posture,omitempty"`
}

type report struct {
	SDK     string             `json:"sdk"`
	Results map[string]verdict `json:"results"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: hushspec-diffeval <bundle.json>")
		os.Exit(2)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read %s: %v\n", os.Args[1], err)
		os.Exit(2)
	}

	var bundle caseBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse bundle: %v\n", err)
		os.Exit(2)
	}
	if bundle.HushspecDiff != "0.1.0" {
		fmt.Fprintf(os.Stderr, "unsupported hushspec_diff version: %s\n", bundle.HushspecDiff)
		os.Exit(2)
	}

	results := make(map[string]verdict)
	for _, group := range bundle.Groups {
		spec, rejection := parsePolicy(group.Policy)
		for _, action := range group.Actions {
			key := group.ID + "/" + action.ID
			if rejection != nil {
				results[key] = *rejection
				continue
			}
			results[key] = evaluateCase(spec, action.Action)
		}
	}

	out, err := json.Marshal(report{SDK: "go", Results: results})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to serialize report: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(out))
}

func parsePolicy(policy map[string]any) (*hushspec.HushSpec, *verdict) {
	policyBytes, err := yaml.Marshal(policy)
	if err != nil {
		return nil, &verdict{Status: "error", Message: fmt.Sprintf("failed to re-encode policy: %v", err)}
	}
	spec, err := hushspec.Parse(string(policyBytes))
	if err != nil {
		return nil, &verdict{Status: "rejected", Phase: "parse", Message: err.Error()}
	}
	if result := hushspec.Validate(spec); !result.IsValid() {
		return nil, &verdict{Status: "rejected", Phase: "validate", Message: fmt.Sprintf("%v", result.Errors[0])}
	}
	return spec, nil
}

func evaluateCase(spec *hushspec.HushSpec, raw json.RawMessage) verdict {
	var action hushspec.EvaluationAction
	if err := json.Unmarshal(raw, &action); err != nil {
		return verdict{Status: "error", Message: fmt.Sprintf("invalid action: %v", err)}
	}
	result := hushspec.Evaluate(spec, &action)
	return verdict{
		Status: "ok",
		Result: &normalizedResult{
			Decision:      string(result.Decision),
			MatchedRule:   result.MatchedRule,
			Reason:        result.Reason,
			OriginProfile: result.OriginProfile,
			Posture:       result.Posture,
		},
	}
}
