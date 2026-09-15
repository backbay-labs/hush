# hushspec (Go)

Portable specification types for AI agent security rules.

This is the Go SDK for [HushSpec](https://github.com/backbay-labs/hush), an open
format for declaring what an AI agent runtime is allowed to do at the tool
boundary. It parses, validates, resolves, and evaluates HushSpec documents, and
emits decision receipts for audit.

## Installation

```bash
go get github.com/backbay-labs/hush/packages/go@latest
```

```go
import "github.com/backbay-labs/hush/packages/go/hushspec"
```

Requires Go 1.22+.

### Versioning and tags

The SDK is a **nested module**: the repository root is not a Go module, and the
module path `github.com/backbay-labs/hush/packages/go` includes the
`packages/go` subdirectory. Go therefore resolves versions from tags that carry
that same directory prefix:

| Release | Git tag |
| --- | --- |
| `v0.1.1` of this module | `packages/go/v0.1.1` |

So a release is published by tagging `packages/go/v0.1.1`, and consumed as:

```bash
go get github.com/backbay-labs/hush/packages/go@v0.1.1
```

A plain `v0.1.1` tag at the repository root does **not** version this module —
`go get ...@v0.1.1` will not find it. Before the first prefixed tag exists,
depend on a branch or commit instead:

```bash
go get github.com/backbay-labs/hush/packages/go@main
```

Note that `go get` always asks for the *module* path (`.../packages/go`), while
your imports use the *package* path (`.../packages/go/hushspec`).

## Quick start

### Parse and validate

`Parse` is strict by design: unknown fields are an error, so a typo in a policy
fails at parse time instead of silently disabling a rule. `Validate` then checks
the semantics (supported version, regex safety, internal consistency).

```go
package main

import (
	"fmt"
	"log"

	"github.com/backbay-labs/hush/packages/go/hushspec"
)

const policyYAML = `
hushspec: "0.1.0"
name: my-policy
rules:
  egress:
    allow: ["api.github.com"]
    block: []
    default: block
`

func main() {
	spec, err := hushspec.Parse(policyYAML)
	if err != nil {
		log.Fatalf("parse failed: %v", err)
	}

	result := hushspec.Validate(spec)
	if !result.IsValid() {
		for _, e := range result.Errors {
			log.Printf("%s: %s", e.Code, e.Message)
		}
		log.Fatal("policy is invalid")
	}
	fmt.Println("policy ok:", spec.Name)
}
```

### Resolve `extends`

A policy may inherit from another file or from a built-in ruleset
(`extends: builtin:default`). `ResolveFile` reads a document from disk and
flattens its whole `extends` chain; `Resolve` does the same for an
already-parsed document, optionally through your own loader. The default loader
serves `builtin:` and filesystem references only — `http(s)://` references are
rejected rather than fetched, so supply your own `ResolveLoader` if you need
remote policies.

```go
// From disk, following extends (builtin: and filesystem references).
spec, err := hushspec.ResolveFile("./policy.yaml")

// Or flatten a document you already parsed. Pass nil to use the default loader.
resolved, err := hushspec.Resolve(spec, "./policy.yaml", nil)

// Built-in rulesets are embedded in the binary: default, strict, permissive,
// ai-agent, cicd, remote-desktop.
builtin, ok := hushspec.LoadBuiltin("builtin:strict")
```

### Evaluate an action

`Evaluate` takes a resolved policy plus the action the agent is about to take
and returns `allow`, `warn`, or `deny` with the rule that decided it. It is
fail-closed: an unknown action type or an ambiguous rule denies.

```go
action := &hushspec.EvaluationAction{
	Type:   "egress",
	Target: "api.github.com",
}

result := hushspec.Evaluate(spec, action)
switch result.Decision {
case hushspec.DecisionAllow:
	// proceed
case hushspec.DecisionWarn:
	log.Printf("warn: %s (%s)", result.Reason, result.MatchedRule)
case hushspec.DecisionDeny:
	log.Fatalf("denied by %s: %s", result.MatchedRule, result.Reason)
}
```

Other action types follow the same shape: `tool_call`, `file_read`,
`file_write`, `patch_apply`, `shell_command`, `computer_use`, and
`input_inject`. Pass file or command content in `Content` so the secret,
shell, and patch rules can inspect it.

### Decision receipts

`EvaluateAudited` evaluates an action against a resolved policy and records a
format 0.2 `DecisionReceipt` (`spec/hushspec-receipt.md`): who acted, the
resolved policy's canonical content hash, the action minus its content, the
decision, the rule blocks and detectors that actually ran, and what the
enforcement point did with it. With `AuditConfig{Enabled: false}` it skips
timing and the trace; the decision and the policy identity are always correct.

```go
resolution, err := hushspec.ResolveFileWithOptions("policy.yaml", hushspec.ResolveOptions{})
if err != nil {
	log.Fatal(err)
}

config := hushspec.DefaultAuditConfig()
receipt := hushspec.EvaluateAudited(resolution, action, &config, &hushspec.AuditContext{
	Actor: &hushspec.Actor{AgentID: "deploy-bot-3", SessionID: "run-0042"},
})

fmt.Println(receipt.ReceiptID, receipt.Decision, receipt.Policy.ContentHash)

// Persist receipts as JSON Lines; NewDenyOnlySink filters to denials only.
sink := hushspec.NewFileReceiptSink("./receipts.jsonl")
if err := sink.Send(&receipt); err != nil {
	log.Printf("receipt sink failed: %v", err)
}
```

`EvaluateAuditedSpec` does the same for a document you already hold in memory.
Sinks are composable: `NewMultiSink` fans out to several, `NewFilteredSink`
selects by decision, and `NewCallbackSink` forwards to your own function.

### Evidence chain

A receipt proves one evaluation. A **hash-linked log**
(`spec/hushspec-log.md`) proves a sequence of them: that nothing was removed,
inserted, edited or reordered, and which policy was in force at every point.

`ChainedFileSink` is a `ReceiptSink` that appends JSON Lines entries, each
naming the previous entry's hash and carrying its own hash over its RFC 8785
canonical form. Every line is fsynced under an exclusive file lock before the
append returns.

```go
sink, err := hushspec.OpenChainedFileSink("./audit.jsonl")
if err != nil {
	log.Fatal(err)
}
sink.WithSigner(privateKeyPEM) // optional: sign every entry (Ed25519)

// Write which policy is in force before the first receipt under it.
event := hushspec.NewPolicyLoadedEvent(resolution, hushspec.EnforcementModeEnforce, hushspec.SdkInfo{})
if err := sink.RecordPolicyEvent(&event); err != nil {
	log.Fatal(err)
}
if err := sink.Send(&receipt); err != nil {
	log.Fatal(err)
}

seq, head := sink.Head() // publish the head hash to make truncation detectable
```

`sink.Rotate("./audit-2.jsonl")` starts a new file whose first entry carries
the previous file's last hash, so the chain survives rotation.

Verification reports the first break by file and line:

```go
report, err := hushspec.VerifyLogFiles(
	[]string{"./audit.jsonl", "./audit-2.jsonl"},
	&hushspec.LogVerifyOptions{RequireSignatures: true, Keyring: keyring},
)
if err != nil {
	log.Fatalf("log broken: %v", err) // e.g. "audit.jsonl:3: prev_hash ... does not link"
}
fmt.Println(report.Entries, report.VerifiedSignatures, report.LastEntryHash)
```

Individual receipts can also be signed on their own, over the receipt hash so
that the receipt stays byte-stable whoever signs it:

```go
signed, err := hushspec.SignReceipt(&receipt, privateKeyPEM, hushspec.SignOptions{})
result := hushspec.VerifyReceipt(signed, hushspec.VerifyOptions{Keyring: keyring})
```

`ParseReceipt` accepts exactly what the 0.2 schema accepts -- unknown members,
open enums, non-millisecond timestamps and bare-hex hashes are all rejected --
so a receipt that parses is a receipt an auditor can rely on.

### Panic mode

`ActivatePanic()` flips a process-wide kill switch: every later `Evaluate` call
returns `deny` before any rule runs. `CheckPanicSentinel(path)` activates it
from the presence of a sentinel file and fails closed if the path cannot be
checked. `DeactivatePanic()` restores normal evaluation.

## Timezones

Rules can be gated by a `time_window` condition with an IANA timezone. The
package blank-imports `time/tzdata`, so zone lookups work on scratch and
distroless images that ship no system tz database.

## Documentation

- [Specification](https://github.com/backbay-labs/hush/tree/main/spec)
- [Repository and other SDKs](https://github.com/backbay-labs/hush)

## License

Apache-2.0. See [LICENSE](./LICENSE).
