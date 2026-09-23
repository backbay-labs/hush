# Trusted invocation pilot

The experimental TypeScript coordinator owns one host-controlled MCP dispatch
boundary. It evaluates the qualified tool and all trusted effects against one
authenticated policy generation, asks at most once for confirmation, durably
records admission, and only then calls the bound handle.

This is not a general MCP gateway or a compliance certification. The demonstrated
profile uses owned tools, synthetic files and one controlled HTTP endpoint.
The existing `createMCPGuard` and framework adapters remain evaluation helpers.

## Reproduce the contained workflow

Requirements: Linux, a working Docker daemon, Node >=18 for the SDK (the test
toolchain uses Node >=20), and the repository's installed npm dependencies.
The actor image is pinned to a multiarchitecture digest in
[`io.mjs`](https://github.com/backbay-labs/hush/blob/main/scripts/mcp-pilot/io.mjs).
The first run pulls that official Python image if it is absent.

```bash
npm ci
npm --prefix packages/hushspec run build
node scripts/run_mcp_pilot.mjs --output target/my-mcp-pilot
node scripts/run_mcp_pilot.mjs --verify target/my-mcp-pilot --trust target/my-mcp-pilot.trust.json
```

Choose a fresh output directory for every run. Failed and deliberately incomplete
packets remain on disk; the controller never resumes an old journal. It removes
only its own UUID-named actor containers, leaving all evidence and cached images.
`--fault counter` deliberately returns nonzero after the completed workflow and
retains `failure.json` plus the preceding evidence.

The scripted coding actor reads a real source file through MCP, computes an
edit, patches it after one confirmation, and requests the controlled endpoint.
The policy blocks a protected file and an identically named tool on another
connection. The owned server refuses traversal, symlinks, hard links, stale
patch content and redirects. Direct actor file, shell-to-host-file and network
probes fail inside the selected container configuration.

Two additional runs SIGKILL the actual host immediately after durable admission
but before patch dispatch, and after the server has completed the patch but
before the host records completion. Both runs refuse complete verification.
Independent file hashes distinguish unchanged and changed state; the missing
terminal record alone cannot do so.

## Host integration contract

Public opt-in APIs are exported by `@hushspec/core`:

| API | Responsibility |
| --- | --- |
| `InvocationRegistry` | Capture host-owned connection IDs, extractors and dispatch handles |
| `AuthenticatedPolicy` / `InvocationEngine` | Authenticate one resolved policy and prepare a policy-hash-bound evaluator |
| `InvocationCoordinator` | Install policy, control panic, invoke, confirm and close |
| `FileInvocationJournal` | Exclusively create and synchronously fsync signed journal evidence |
| `OwnedMcpConnection` | Bound owned subprocess requests, results, deadlines and shutdown |
| `verifyInvocationJournal` | Verify a closed journal using caller-pinned keys and stream identity |
| `inspectInvocationJournal` | Inspect a valid prefix as incomplete forensic evidence |

The runnable host integration is
[`host.mjs`](https://github.com/backbay-labs/hush/blob/main/scripts/mcp-pilot/host.mjs).
It generates no reusable authorization token and does not trust discovery
metadata to select a connection. Registry identity is
`mcp:<host-connection-id>/<encodeURIComponent(NFC-tool-name)>`; names must
already be NFC. An unqualified tool allow entry does not authorize that target.

`invoke(connectionId, toolName, argumentsJson, trustedContext?)` accepts strict
raw JSON arguments. Duplicate keys, invalid Unicode, excessive depth, oversized
arguments and unknown/opaque effect mappings are refused. Extractors receive
immutable arguments and must describe every supported effect. The current
profile supports `file_read`, `file_write`, `patch_apply` and `egress`, in
addition to the original `tool_call`. The same arguments reach dispatch.
Host context is copied, frozen and given a captured current time; actor metadata
does not supply policy authority.

`installPolicy(document, envelope)` requires a validated resolved document,
a named integer policy version and matching authenticated envelope claims.
It refuses `extends`, `merge_strategy`, rollback, changed policy name and
unverified state. A failed reload leaves the coordinator refusing calls, rather
than silently retaining the old policy. Persist and supply `lastSeenVersion`
when rollback protection must survive restart. The initial policy trust root
comes from the operator, not the policy document.
Nested installation from an engine-preparation or policy-journal callback is
refused before changing the generation or identity/version pins. Reload from a
permit callback remains supported and invalidates that pending admission.

The engine seam prepares a snapshot from the authenticated resolution and
returns component receipts. The default uses the real compiled TypeScript
evaluator and traces. Engines are trusted executable code. The pilot binds
the engine identity to captured compiled SDK and YAML-parser artifacts; it does
not prove build provenance, engine honesty or independent authorship.

## Admission, failure and recovery

Any deny dominates all warnings and produces zero confirmation prompts.
Multiple warnings produce one immutable prompt bound to call ID, target,
arguments, effects and policy generation. Only literal `true` confirms.
Confirmation refusal, exception or timeout blocks dispatch.

No lock is held while waiting for confirmation. Final checks, a synchronous
durable permit and the call to the captured handle occur without an intervening
await. Reloads and both coordinator/global panic epochs invalidate earlier
approval. A policy change after admission cannot retract a started side effect.
Reentrant invalidation after the permit records `aborted_before_dispatch`, an
explicit trusted-host observation, rather than inferring prevention from silence.

Authoritative evidence failures throw `InvocationEvidenceError` with `callId`
and `admitted`. A terminal-write failure can occur after an effect and stops
future dispatch. A dispatch deadline returns `unknown`, leaves no fabricated
terminal and also stops future dispatch. Ordinary dispatch errors may represent
partial effects. There is no automatic retry, rollback or exactly-once promise.
Retain the incomplete stream, reconcile independently observed effects, then
create a new stream under operator control.

A custom journal must synchronously return a valid sequence/hash acknowledgment
only after durable storage. Returning a promise is not acknowledgment. The
filesystem journal creates 0700 directories and 0600 files, fsyncs new file and
directory entries before acknowledgment, and signs a final checkpoint only when
no attempt is pending. It requires a filesystem supporting these fsync semantics;
process-crash tests do not establish hardware power-loss guarantees.

Limits include 64 KiB argument JSON, depth 16, 4,096 JSON nodes, 16 KiB context,
16 effects, 16 pending calls and 2,000 calls per stream. Journals cap entries at
2 MiB, streams at 64 MiB and entry count at 20,000. Asynchronous waits are bounded;
a JavaScript timer cannot preempt arbitrary synchronous code in a trusted callback.

## Evidence and trust

The invocation journal/checkpoint is experimental `0.1.0`, separate from receipt
0.2, existing log entries and conformance reports. A component receipt describes
one evaluated action: `allowed` is neither an aggregate permit nor proof that
the action executed. Verification checks signatures, sequence, snapshot hashes,
policy generation, component ownership, confirmation disposition and terminal
coverage. A caller can additionally pin the expected final head.

The packet contains source/dependency/config/image digests, signed runtime
evidence, independently written server/endpoint observations, actor transcript,
file hashes, negative checks and explicit limitations. The complete scenario
reconciles six server calls and two endpoint requests. The two crash scenarios
remain incomplete, with unknown patch outcomes in the journal.

The `*.trust.json` file is generated separately using synthetic public keys.
Choose it explicitly for verification and retain its keys, stream identities
and manifest/head hashes through a trusted channel. Replacing both packet and
trust file defeats attribution; keys bundled alongside evidence do not establish
trust by themselves. CI uploads both for reproducibility, not as an independent
trust-root distribution service. Private keys exist only in host/controller
memory and the private child-input pipe, never in retained artifacts.

Journals retain arguments, file content and context. Treat real journals as
confidential. This pilot uses synthetic data; do not redact signed source bytes
and then claim the original signatures verify the redacted packet.

## What remains outside this claim

The trusted host, registry, extractors, engine, signer, clock, Docker daemon and
exclusive file ownership are assumptions. The actor has no repository/key/
journal/socket mount or external network route. Arbitrary third-party MCP
servers, unrestricted host shells, provider-executed tools, external concurrent
writers and kernel/container escapes are not covered. The transport deliberately
uses the owned [MCP 2026-07-28 request metadata](https://modelcontextprotocol.io/specification/2026-07-28/basic)
and [stdio](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio)
profile; it does not negotiate legacy initialization or implement every MCP feature.

An independently authored engine must qualify through the external controller and run this
same workflow without reference fallback. An external adopter must run their
own integration, and an outside practitioner must assess the scoped evidence.
Those evidence gates remain separate from this first-party pilot. A published
v1 package does not turn them into completed independent validation.
