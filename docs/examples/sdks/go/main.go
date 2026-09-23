package main

import (
	"context"
	"fmt"
	hush "github.com/backbay-labs/hush/packages/go/hushspec"
	"os"
	"path/filepath"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

func main() {
	policyPath := "policy.yaml"
	if len(os.Args) > 1 {
		policyPath = os.Args[1]
	}
	raw, err := os.ReadFile(policyPath)
	must(err)
	document, err := hush.Parse(string(raw))
	must(err)
	require(hush.Validate(document).IsValid(), "invalid document")
	resolution, err := hush.ResolveFileWithOptions(policyPath, hush.ResolveOptions{})
	must(err)
	compiled, err := hush.CompilePolicy(resolution.Spec)
	must(err)
	checkTrust(policyPath, resolution.Spec)
	require(compiled.Evaluate(&hush.EvaluationAction{Type: "tool_call", Target: "search"}).Decision == hush.DecisionAllow, "search denied")
	var receipts []*hush.DecisionReceipt
	options := hush.GuardOptions{
		Actor: &hush.Actor{AgentID: "docs-agent", SessionID: "docs-session", Principal: "docs-user", Runtime: "docs/1.0.0"},
		Sink:  hush.NewCallbackSink(func(receipt *hush.DecisionReceipt) error { receipts = append(receipts, receipt); return nil }),
	}
	guard, err := hush.NewGuard(resolution, options)
	must(err)
	directory, err := os.MkdirTemp("", "hush-doc-effect-")
	must(err)
	defer os.RemoveAll(directory)
	output := filepath.Join(directory, "effect.txt")
	dispatches := 0
	dispatch := func(g *hush.Guard, tool string) bool {
		outcome, err := g.Check(context.Background(), &hush.EvaluationAction{Type: "tool_call", Target: tool})
		must(err)
		if !outcome.Allowed() {
			return false
		}
		file, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		must(err)
		_, err = file.WriteString("confirmed once\n")
		must(err)
		must(file.Close())
		dispatches++
		return true
	}
	require(!dispatch(guard, "deploy"), "deploy dispatched")
	require(!dispatch(guard, "write_file"), "unconfirmed write dispatched")
	_, err = os.Stat(output)
	require(os.IsNotExist(err) && dispatches == 0, "blocked effect exists")
	options.OnWarn = func(hush.EvaluationResult, *hush.EvaluationAction) bool { return true }
	confirmed, err := hush.NewGuard(resolution, options)
	must(err)
	require(dispatch(confirmed, "write_file") && dispatches == 1, "confirmation did not dispatch exactly once")
	effect, err := os.ReadFile(output)
	must(err)
	require(string(effect) == "confirmed once\n", "effect mismatch")
	require(receipts[len(receipts)-1].Enforcement.Outcome == hush.EnforcementOutcomeConfirmed, "receipt not confirmed")
	require(receipts[len(receipts)-1].Actor.AgentID == "docs-agent", "actor mismatch")
	_, err = hush.Parse("hushspec: \"1.0.0\"\nunknown_rule: true\n")
	require(err != nil, "invalid policy accepted")
	fmt.Println("PASS: deny=0 dispatches; unconfirmed warn=0; confirmed warn=1; invalid policy refused")
}
