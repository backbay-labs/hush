# Go SDK

Use the Go SDK at a runtime boundary you own. This guide needs Go 1.22 or newer
and the [quickstart policy](../../../examples/quickstart/policy.yaml).

The package is `github.com/backbay-labs/hush/packages/go/hushspec`. `Parse`, resolution and compilation return `(value, error)`. `Guard.Check` returns `(GuardDecision, error)`; stop on error, then branch on `Allowed()`. There is no exception-based enforcement API.

## Install and run the complete example

Create an empty directory. Download these files, preserving the listed relative
paths, and place `policy.yaml` at the top of that directory:

- [go.mod](../../../examples/sdks/go/go.mod)
- [main.go](../../../examples/sdks/go/main.go)
- [trust.go](../../../examples/sdks/go/trust.go)

The module version is `github.com/backbay-labs/hush/packages/go@v1.0.0`. Signing uses Go's standard cryptography support. The guard is named `Guard`, not `HushGuard`.

```sh
go mod tidy
go run . policy.yaml
```

Expected output: `PASS: deny=0 dispatches; unconfirmed warn=0; confirmed warn=1; invalid policy refused`.
All effects are in a fresh temporary directory. No model API or credentials are
required, and the program cleans up its own synthetic output.

## Enforce before the effect

The example parses and validates the policy, resolves it, and compiles it once.
It then attaches a consistent actor and callback receipt sink to the guard.
The synthetic handler creates one file only after enforcement permits dispatch.

<!-- docs-file: sdk-go-dispatch docs/examples/sdks/go/main.go -->
```go
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
```

The `on_warn` / `onWarn` callback in this demonstration approves one synthetic
test action. A real integration must obtain approval from an authenticated
channel and bind it to the pending action. Do not replace approval with
unconditional `true` in a production agent.

## Signing and keyrings

The companion `trust.go` program is called by the main example. It
creates an ephemeral test key, signs the resolved document, verifies with an
explicit keyring, and rejects a different keyring. It prints no private key and
does not persist one. Production signing identities belong to the operator.

Signing and verification must refer to the same resolved policy used for
evaluation. See [signing](../../signing-spec.md), [bundles](../../bundle-spec.md),
and the [exact signing APIs](../../reference/sdk-api.md#signing-keyrings-receipt-signing).
A successful signature proves authenticity relative to your trust roots, not
that a tool obeyed the policy.

## Providers and reload

`NewGuardFromProvider` loads the provider; use a `PolicyWatcher`/`PolicyPoller` with the documented lifecycle for ongoing reload. `Check` accepts a context. Confirmation, custom-sink and receipt-clock callbacks must not re-enter the same guard or wait on work that needs it. Observers run after the ordering gate releases.

Initial policy-load errors cannot fall back to a nonexistent policy. Ordinary
guard reload preserves the last good policy on a rejected update and reports
the error. It is not nonblocking: reload can wait for confirmation and receipt
delivery. See [hot reload](../hot-reload.md) for ordering and the distinct
experimental coordinator refusal contract.

## Receipts and failure handling

The callback sink makes receipt contents visible to the test. It is not durable
storage. Configure a chained file sink or another reviewed delivery path for
operational evidence, and handle `sink.error` through an observer.
A failed ordinary sink does not change the decision; if dispatch must require a
durable permit, use the separately bounded [experimental invocation workflow](../../reference/trusted-invocation.md).

Receipts record actor fields, policy hash, decision, trace and enforcement outcome.
They do not carry raw action content. The `confirmed` outcome distinguishes an
approved warning from a plain allow.

## API map and next steps

The [SDK API contract](../../reference/sdk-api.md) covers parse/validate,
resolve/merge, compile/evaluate, actors, receipts, sinks, signing, keyrings,
providers, panic mode and error conventions. For mapping effects, read
[MCP](../integrations/mcp.md) and [runtime integration](../runtime-integration.md).
Use [conformance](../../reference/conformance.md) to understand what a test
corpus establishes; this example is an integration regression, not an
independent conformance certificate.
