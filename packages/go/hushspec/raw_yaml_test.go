package hushspec

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"testing"
)

func TestRawYAMLCoreScalars(t *testing.T) {
	data, err := os.ReadFile("../../../fixtures/core/raw-yaml/scalars.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		ID        string   `json:"id"`
		YAML      string   `json:"yaml"`
		Accept    bool     `json:"accept"`
		ValuePath []string `json:"value_path"`
		Value     any      `json:"value"`
		Canonical string   `json:"canonical"`
		Decision  string   `json:"decision"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		t.Run(vector.ID, func(t *testing.T) {
			policy, err := Parse(vector.YAML)
			if (err == nil) != vector.Accept {
				t.Fatalf("accept=%v, parse error: %v", vector.Accept, err)
			}
			if err != nil {
				return
			}
			canonical, err := CanonicalJSON(policy)
			if err != nil {
				t.Fatal(err)
			}
			var value any
			if err := json.Unmarshal([]byte(canonical), &value); err != nil {
				t.Fatal(err)
			}
			for _, key := range vector.ValuePath {
				if items, ok := value.([]any); ok {
					index, err := strconv.Atoi(key)
					if err != nil {
						t.Fatal(err)
					}
					value = items[index]
				} else {
					value = value.(map[string]any)[key]
				}
			}
			if !reflect.DeepEqual(value, vector.Value) {
				t.Fatalf("got %#v, expected %#v", value, vector.Value)
			}
			if vector.Canonical != "" {
				if canonical != vector.Canonical {
					t.Fatalf("canonical: got %s, expected %s", canonical, vector.Canonical)
				}
				hash, err := ContentHash(policy)
				if err != nil {
					t.Fatal(err)
				}
				if want := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(vector.Canonical))); hash != want {
					t.Fatalf("hash got %s, expected %s", hash, want)
				}
			}
			if vector.Decision != "" {
				var action EvaluationAction
				if err := json.Unmarshal([]byte(`{"type":"egress","target":"example.com","context":{"counters":{"requests":9}}}`), &action); err != nil {
					t.Fatal(err)
				}
				if got := string(Evaluate(policy, &action).Decision); got != vector.Decision {
					t.Fatalf("got decision %s, expected %s", got, vector.Decision)
				}
			}
		})
	}
}
