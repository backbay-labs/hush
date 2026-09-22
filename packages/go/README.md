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
| `v1.0.0` of this module | `packages/go/v1.0.0` |
| `v0.1.1` of this module | `packages/go/v0.1.1` |

The HushSpec 1.0.0 release is tagged `packages/go/v1.0.0`, and consumed as:

```bash
go get github.com/backbay-labs/hush/packages/go@v1.0.0
```

A plain `v1.0.0` tag at the repository root does **not** version this module —
`go get ...@v1.0.0` will not find it. To track the branch instead of a release:

```bash
go get github.com/backbay-labs/hush/packages/go@main
```

Note that `go get` always asks for the *module* path (`.../packages/go`), while
your imports use the *package* path (`.../packages/go/hushspec`).

The module path carries no `/vN` suffix: that is required only from major
version 2 onward, and this module is at v1.

### Specification versions

`hushspec.Version` is the HushSpec version this engine writes, and
`hushspec.SupportedMinors` is what it accepts. Specification versions are
independent of the module version above (core spec 10.3).

| Constant | Value |
| --- | --- |
| `hushspec.Version` | `1.0.0` |
| `hushspec.SupportedMinors` | `0.1`, `0.2`, `1.0` |

An engine that supports minor `X.Y` accepts every `X.Y.Z` document, because
patch versions carry only clarifications and errata (core spec 2.2). A `1.0.Z`
document is evaluated exactly as a `0.2.Z` one — 1.0 freezes the 0.2 semantics
without changing them (core spec 10.2). The one validation difference is that a
present `name` must be non-empty, rejected with `E004`. Any other minor is
rejected with `E002`.

### JSON Schemas

Policies validate against the `.v1.` schema lineage, published under
`https://hushspec.dev/schemas/`. Point an editor at it with a modeline:

```yaml
# yaml-language-server: $schema=https://hushspec.dev/schemas/hushspec-core.v1.schema.json
```

| Document | Schema URL |
| --- | --- |
| Policy | `https://hushspec.dev/schemas/hushspec-core.v1.schema.json` |
| Receipt | `https://hushspec.dev/schemas/hushspec-receipt.v1.schema.json` |
| Log entry | `https://hushspec.dev/schemas/hushspec-log-entry.v1.schema.json` |
| Signature | `https://hushspec.dev/schemas/hushspec-signature.v1.schema.json` |
| Bundle | `https://hushspec.dev/schemas/hushspec-bundle.v1.schema.json` |

The `.v0.` files are frozen copies retained for documents that declare a 0.x
version; they are not edited, and `schemas/frozen-v0.json` pins their digests.

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
	// An optional string is a *string: nil is an absent property, and a
	// pointer to "" is one the document wrote as the empty string.
	if spec.Name != nil {
		fmt.Println("policy ok:", *spec.Name)
	}
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
// ai-agent, cicd, remote-desktop, and the vertical library under
// library/<vertical>/<name>. hushspec.BuiltinNames lists them all.
builtin, err := hushspec.LoadBuiltin("builtin:strict") // errors.Is(err, hushspec.ErrUnknownBuiltin) for a name that is not embedded
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

### Compile a policy once

`CompilePolicy` builds every matcher a policy needs up front -- its regexes,
path globs, host patterns, tool name lists, and the detectors its `detection`
extension wires -- so evaluating an action does matching and nothing else. An
enforcement point that evaluates many actions against one policy should hold a
`*CompiledPolicy`; it is immutable and safe to share across goroutines.

```go
policy, err := hushspec.CompilePolicy(spec)
if err != nil {
	// A pattern outside the HushSpec regex profile: fail closed.
	log.Fatalf("policy does not compile: %v", err)
}

result := policy.Evaluate(action)
receipt, err := policy.EvaluateAudited(resolution, action, nil, nil)
```

`CompiledPolicy` mirrors the free functions minus the document argument:
`Evaluate`, `EvaluateTraced`, `EvaluateWithContext`, `EvaluateWithDetection`,
`EvaluateWithDetectionTraced`, and `EvaluateAudited`, plus a cached
`ContentHash`. The decisions, traces, and receipts are identical either way --
the free functions compile on the fly and memoize the result, so existing code
needs no change. Compilation is stricter in one direction only: a pattern the
regex profile rejects is a `*CompileError` naming its rule path, where
evaluation reports it as a deny on that rule.

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
receipt, err := hushspec.EvaluateAudited(resolution, action, &config, &hushspec.AuditContext{
	Actor: &hushspec.Actor{AgentID: "deploy-bot-3", SessionID: "run-0042"},
})
if err != nil {
	// The policy has no content hash, so there is no receipt that could name it.
	log.Fatal(err)
}

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

### Enforcement point: `Guard`

`Guard` is the piece that sits at the tool boundary: it holds a compiled
policy, applies the enforcement mode, records a receipt, and answers whether
the action may proceed. `Check` gates, `Evaluate` records without gating, and
`SwapPolicy` replaces the policy in force without stopping in-flight
evaluations. It is safe to share across goroutines.

```go
guard, err := hushspec.NewGuardFromFile("policy.yaml", hushspec.GuardOptions{
	Actor:  &hushspec.Actor{AgentID: "deploy-bot-3", SessionID: "run-0042"},
	Sink:   sink,                      // receipts and policy_loaded / policy_swapped
	OnWarn: confirmWithOperator,       // nil denies every warn
})
if err != nil {
	log.Fatal(err)
}

decision, err := guard.Check(ctx, &hushspec.EvaluationAction{
	Type:   "egress",
	Target: "api.github.com",
})
if err != nil {
	// A cancelled context, or a sink that would not take the receipt.
	log.Printf("hushspec: %v", err)
}
if !decision.Allowed() {
	return fmt.Errorf("blocked by %s: %s", decision.Result.MatchedRule, decision.Result.Reason)
}
```

`GuardDecision` carries the policy's `Result`, the `Receipt` (when a sink is
configured), the `Enforcement` disposition that was recorded, and `Enforced` --
false exactly when monitor mode let a warn or deny through as `would_block`.

**Monitor mode.** `EnforcementMode: hushspec.EnforcementModeMonitor` records
what would have been blocked and lets it proceed; `RuleOverrides` narrows that
to one rule path, longest matching prefix first:

```go
hushspec.GuardOptions{
	EnforcementMode: hushspec.EnforcementModeMonitor,
	RuleOverrides: map[string]hushspec.EnforcementMode{
		"rules.egress": hushspec.EnforcementModeEnforce, // still blocked for real
	},
	Sink: sink,
}
```

Monitor mode without a sink or an observer is rejected at construction: a
shadow decision nobody can see is not a control. Panic mode and a policy that
did not verify always enforce, whatever the mode says.

**Verify on load.** With `RequireSignature` the guard refuses a chain that does
not verify, rather than failing to exist: it keeps the document, reports
`Refused()`, and denies every action with `__hushspec_policy_unverified__` and
a receipt recording `policy.signature.verified: false` and the verifier's
reason (signing spec 6.5).

```go
guard, err := hushspec.NewGuardFromFile("policy.yaml", hushspec.GuardOptions{
	RequireSignature: true,
	Keyring:          keyring,
	Sink:             sink,
})
if refused, status := guard.Refused(); refused {
	log.Printf("policy unverified (%s): every action is denied", status.Reason)
}
```

### Observers

An `EvaluationObserver` is told about every decision and every policy load, and
can change neither. Observers that panic are recovered; they never break
enforcement.

```go
metrics := hushspec.NewMetricsCollector()
guard, err := hushspec.NewGuardFromFile("policy.yaml", hushspec.GuardOptions{
	Observer: hushspec.NewObservableEvaluator(
		metrics,
		hushspec.NewJSONLineObserver(os.Stdout),
		hushspec.NewDenyOnlyStderrObserver(),
	),
})

// GET /metrics
fmt.Fprint(w, metrics.RenderPrometheus())
```

- `JSONLineObserver` writes one JSON object per event (`evaluation.completed`,
  `policy.loaded`, `policy.reloaded`, `error`). Action content is never
  written -- only the hash and size a receipt records.
- `StderrObserver` writes a human-readable line; `NewDenyOnlyStderrObserver`
  limits evaluation lines to denials.
- `MetricsCollector` counts by decision and action type, by rule block, and by
  policy load outcome, with a latency histogram. `Snapshot()` copies the
  counters; `RenderPrometheus()` renders `hushspec_evaluate_total`,
  `hushspec_evaluate_duration_us`, `hushspec_rule_match_total` and
  `hushspec_policy_load_total`.
- `WebhookObserver` POSTs each event to an HTTP endpoint from a background
  goroutine, with a bounded queue: a slow endpoint drops events rather than
  slowing an evaluation.

### Providers and hot reload

A `PolicyProvider` is where the policy comes from; `FileProvider` reads one
from disk, resolving and verifying its `extends` chain against the file's own
directory. `PolicyWatcher` polls that file's modification time and content hash
and swaps a changed policy into the guard; `PolicyPoller` does the same for any
provider on a fixed interval.

```go
provider := hushspec.NewFileProvider("policy.yaml", hushspec.ResolveOptions{
	RequireSignature: true,
	Keyring:          keyring,
})
guard, err := hushspec.NewGuardFromProvider(provider, hushspec.GuardOptions{Sink: sink})

watcher, err := hushspec.NewPolicyWatcher(provider, hushspec.ReloadOptions{
	Guard:         guard,
	Interval:      2 * time.Second,
	PanicSentinel: "/etc/hushspec/PANIC", // checked on every tick
	OnChange:      func(r *hushspec.Resolution) { log.Printf("policy %s in force", r.ContentHash) },
	OnError:       func(err error) { log.Printf("reload failed: %v", err) },
})
if err := watcher.Start(ctx); err != nil {
	log.Fatal(err)
}
defer watcher.Stop()
```

A reload that cannot be read, resolved, verified or compiled leaves the
previous policy in force and goes to `OnError` (and to the guard's observer):
a policy nobody checked must never take effect just because it arrived second.
A document whose content hash is unchanged is not a swap. `CheckOnce()` is the
whole of one tick, exposed so a test can drive reload deterministically instead
of waiting on a ticker.

### Agent framework adapters

The adapters map a runtime's tool call onto an `EvaluationAction`. The mapping
is the security-relevant part: a call evaluated as a bare `tool_call` meets
`tool_access` alone, while the same call mapped to `file_read` also meets
`forbidden_paths` and `path_allowlist`.

```go
action := hushspec.MapClaudeToolToAction("bash", input)          // shell_command
action = hushspec.MapMCPToolCall("fetch", args)                // egress, host only
action = hushspec.MapOpenAIToolCall("get_weather", arguments)  // tool_call + args size
```

`MapClaudeToolToAction` recognizes `bash` and `terminal`, the text editor tools
(dated revisions included -- a `view` reads, anything else writes and carries
its payload as content), `computer`, and `web_fetch`; an
`mcp__<server>__<tool>` name is evaluated under the inner tool name, so a
policy names the tool rather than the transport. `MapMCPToolCall` recognizes
the file, command and fetch tools. Anything unrecognized is a `tool_call`
against the tool's own name: guessing wrong would consult the wrong rule block,
which is worse than not guessing.

`GuardedToolHandler` (and the per-runtime `CreateSecureToolHandler`,
`GuardedOpenAIToolHandler`, `GuardedMCPToolHandler`) wraps a handler so the
check happens before the tool runs; a refused call returns a `*ToolDeniedError`
and the handler is never invoked.

```go
handler := hushspec.GuardedMCPToolHandler(guard, runTool)

result, err := handler(ctx, "write_file", map[string]any{
	"path":    "/etc/shadow",
	"content": payload,
})
var denied *hushspec.ToolDeniedError
if errors.As(err, &denied) {
	return denied.Result.Reason // the tool never ran
}
```

### OTLP export

`OTLPReceiptSink` exports receipts and policy events to an OpenTelemetry
collector as OTLP/HTTP JSON logs -- one log record per entry, POSTed to
`<endpoint>/v1/logs`. The body is the receipt's canonical JSON (the exact bytes
its receipt hash covers) and the decision, action type, matched rule, policy
hash, receipt hash and enforcement disposition are attributes, so a query never
has to parse the body. Severity is `INFO` for an allow, `WARN` for a warn and
`ERROR` for a deny.

```go
otlp, err := hushspec.NewOTLPReceiptSink(hushspec.OTLPOptions{
	Endpoint:      "http://localhost:4318",
	Headers:       map[string]string{"Authorization": "Bearer " + token},
	ServiceName:   "agent-runtime",
	BatchSize:     64,
	FlushInterval: 5 * time.Second,
	OnError:       func(err error) { log.Printf("otlp: %v", err) },
})
defer otlp.Close()

// Export is best-effort: pair it with a log when the audit trail must be complete.
guard, err := hushspec.NewGuardFromFile("policy.yaml", hushspec.GuardOptions{
	Sink: hushspec.NewMultiSink([]hushspec.ReceiptSink{chained, otlp}),
})
```

Export happens on a background goroutine, batched and retried with backoff on a
network error or one of 429, 502, 503 and 504; every other status is final.
`Send` never blocks an evaluation: a full queue drops the record, counts it in
`Dropped()` and reports through `OnError`.
`Flush(ctx)` waits for what is queued, and `Close()` flushes and stops.

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
