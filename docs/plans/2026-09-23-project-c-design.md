# Project C: trusted MCP invocation boundary

Status: proposed implementation contract. Implements roadmap C, not the independent-engine or external-adopter gates. Baseline: `96fb38442543dcb746c10fe4c0ea3333b3dfef7d` on `wave-6`.

## Outcome and alternatives

Add an opt-in experimental TypeScript invocation coordinator and a reproducible, host-owned coding pilot. The coordinator owns admission, authenticated policy snapshots, confirmation and authoritative evidence. A registry binds host-assigned connection identities to effect extractors and real dispatch handles. Existing evaluation-only adapters remain unchanged.

Wrapping two `HushGuard.gate()` calls cannot establish one policy generation or authoritative durability. A general gateway would introduce transport, discovery and credential scope this pilot does not need. The selected coordinator is smaller, with a narrow replaceable engine seam and a deliberately constrained owned MCP server.

## Global constraints

- Use the existing `wave-6` checkout. Do not merge, tag, publish, contact adopters, or modify Chio.
- Preserve HushSpec 0.2, receipt 0.2, log and conformance-report wire formats and all existing adapter behavior.
- Node >=18; TypeScript in `packages/hushspec`; no new runtime dependencies. Linux is required only for the contained pilot.
- New evidence is experimental version `0.1.0`, domain-separated and never called a compliance certification, build attestation or exactly-once guarantee.
- Source, host, registry, engine, clock, policy trust roots, journal signer and Docker daemon are trusted. The actor, arguments, tool descriptions and server-reported identity are not.
- Commit, push and qualify exact-head CI after local verification and a fresh whole-change review. Preserve failures and incomplete packets.

## Registry, snapshots and policy

The immutable registry contains `{connectionId, toolName, extract, dispatch}` bindings. Connection IDs match `[a-z][a-z0-9_-]{0,63}`. Tool names are nonempty NFC Unicode strings of at most 128 UTF-8 bytes, with no control characters or lone surrogates. Identity is `mcp:<connectionId>/<encodeURIComponent(toolName)>`. Duplicate identities are rejected. Server names, annotations and actor metadata cannot select or replace a dispatch handle. Unqualified `tool_access` entries retain exact-match semantics and cannot authorize qualified names.

`invoke(connectionId, toolName, argumentsJson, trustedContext)` accepts raw JSON arguments. A bounded strict JSON parser rejects duplicate keys (including escape-equivalent keys), nonfinite numbers, invalid Unicode, excessive nesting and oversized input before evaluation. Limits: 64 KiB arguments, depth 16, 4,096 nodes; 16 KiB context; at most 16 effects. Canonical JSON is copied and recursively frozen. Arguments must be an object. The trusted host provides context and a captured current time; actor context cannot override it.

The extractor receives that exact immutable snapshot and produces only `file_read`, `file_write`, `patch` or `egress` actions. Each action has a nonempty target, content where applicable, and no caller-supplied origin, posture or context. Empty, unknown, excessive or malformed plans are blocked. The coordinator adds the original qualified `tool_call`, with canonical UTF-8 `args_size`. Arguments and the complete ordered action plan are hashed separately. The dispatch handle receives the same immutable arguments and a host-owned call ID.

Policy installation accepts a resolved policy document and detached envelope, not a caller assertion of verification. Validate, reject `extends` and `merge_strategy`, verify with a separately pinned policy key, compile strictly, then capture a private immutable resolution. Require named policies with integer `metadata.policy_version`; reject rollback within the coordinator lifetime. Recheck signature expiry immediately before admission. A failed reload advances the generation and leaves the coordinator refusing new calls; no silent fallback. Restart rollback protection requires an operator-provided last-seen version. Mode is strictly `enforce`; monitor is rejected.

The engine interface is `prepare(resolution): PreparedInvocationEngine`, returning the bound policy hash, operator-declared engine identity and `evaluate(action, context): DecisionReceipt | Promise<DecisionReceipt>`. The default implementation uses `compileResolution().evaluateAudited()`, including real traces. Validate returned receipt shape, policy hash, action binding, enforcement mode and unique receipt IDs. An engine is trusted executable code; metadata does not prove independent authorship or qualification. A future independently qualified engine must execute this same pilot before that roadmap gate closes.

## Invocation state machine

Each attempt gets a host UUID. Record the immutable attempt, evaluate the tool and all effects against one captured generation, then aggregate `deny > warn > allow`. Any deny produces zero prompts. Warnings produce exactly one prompt carrying the call ID, qualified target, argument/effect hashes and generation. Only literal `true` confirms. Refusal, exception or timeout blocks. Evaluator and confirmation waits are bounded; there are at most 16 pending attempts and 2,000 attempts per stream.

No global lock is held while awaiting evaluation or confirmation. Final admission is a synchronous JavaScript turn: check current generation, coordinator panic epoch, global panic active state, policy validity and journal health; write and fsync the signed permit; check again against reentrant trusted callbacks; immediately call the captured dispatch handle before the first await. A policy or panic change before this point invalidates prior approval. A later change cannot retract an admitted side effect. Only coordinator-owned panic transitions have an epoch; direct global panic toggles that turn off before admission are outside the captured transition contract.

Component receipts are recorded before a permit. Their enforcement outcomes reflect blocked/allowed/confirmed component disposition but are not aggregate permits or execution evidence. Confirmation refusal/error records blocked. Any authoritative write failure prevents admission and latches the coordinator closed. Terminal-write failure is surfaced, latches future dispatch off and leaves the admitted call unknown. Dispatch rejection records an observed error, not proof that no partial effect happened. No automatic dispatch retry is permitted. Results returned to the actor are bounded JSON.

## Experimental journal contract

Use a separate signed JSONL stream, not new receipt/log enums. Each entry contains `format_version`, `kind`, `stream_id`, consecutive `sequence` starting at 1, `previous_hash` (null for the first), UTC timestamp, a closed event payload, `entry_hash` and a detached signature. Hash the canonical unsigned body; the body includes the domain `hush.invocation.entry`. Reuse `signContentHash` and `verifyContentHash` with a runtime key distinct from policy trust. Events:

| Event | Payload and transition |
| --- | --- |
| policy | generation, accepted/refused; accepted includes resolved policy, envelope and engine identity |
| panic | monotonic epoch and active boolean |
| rejected | call ID and bounded reason, before a valid attempt exists |
| attempt | call ID, generation, policy hash, qualified target, arguments, ordered actions, context and both hashes |
| decision | call ID, aggregate decision, component receipts and receipt hashes |
| blocked | call ID and reason; no permit may exist |
| permit | call ID and binding copied from attempt, receipt IDs/hashes; requires non-deny decision |
| terminal | call ID and observed completed/error disposition; requires exactly one permit |

A separately signed `hush.invocation.checkpoint` object binds version, stream ID, entry count, final head hash and `closed:true`. Closing requires no pending attempts and no sink failure. The offline verifier requires caller-pinned policy and runtime public keys plus the expected stream ID, rather than trusting a bundled key. It checks all shapes, signatures, hashes, sequence, state transitions, receipt/action/policy bindings and checkpoint coverage. Missing terminal evidence yields unknown, never prevented. Missing checkpoint or incomplete calls fail complete-run verification; a separately requested prefix inspection reports incomplete status only. A replaced whole stream is detectable only with an independently retained expected checkpoint/head, so a packet alone cannot prove that no other stream existed.

The filesystem writer creates a fresh private directory (0700), opens new files exclusively (0600), writes synchronously, fsyncs entries before acknowledging permits, and fsyncs the checkpoint and containing directory before returning close. A synchronous `{sequence, entryHash}` acknowledgment is mandatory. Partial writes latch failure. No append/recovery into an old stream: retain it for reconciliation and create a new stream. Limits: 2 MiB per entry, 64 MiB per stream, 20,000 entries. Journals include arguments/content for replay and are confidential, not redacted public logs.

## Owned MCP pilot

Pin MCP `2026-07-28`. This version carries protocol version and client capabilities in each request's `params._meta`; the stdio subset uses bounded newline-delimited UTF-8 JSON-RPC. Do not silently fall back to the older initialize lifecycle. Implement only discovery, tool listing and tool calls needed by the pilot. Correlate IDs, reject malformed/foreign/duplicate responses, bound requests, lines, stderr, deadlines and child shutdown. No retries after uncertain sends.

The host runs the coordinator and two owned MCP subprocesses. Static host aliases map actor calls to registry identities. Both servers can advertise the same self-reported name; that name has no authority. Tool calls carry the host call ID in private metadata. The server independently journals received/completed/error events before/after effects to a different fsynced file.

The Linux file server pins an open root-directory descriptor and operates on flat basenames through `/proc/self/fd/<fd>/<name>`, rejecting path separators, symlinks, nonregular files, multiple hard links and oversized files. Read and patch only existing files. Patch arguments include old and new contents; the server verifies old content matches the current file before writing, and the trusted extractor constructs file-read, file-write and unified-patch actions from those same values. Writes use the verified open descriptor, then truncate/fsync. Host-exclusive ownership excludes external concurrent writers; failures may leave partial writes and are reported as errors, not rollback.

The network tool permits a single host-owned loopback HTTP origin and fixed paths, forbids credentials/query/fragment/noncanonical URLs, never follows redirects, and limits time and response bytes. There is no DNS or arbitrary network forwarding. An independent endpoint counter records actual requests. The containment helper is shared between the trusted extractor and server, but policy decisions are made only by the coordinator.

A deterministic Python coding actor runs in Docker with no network, read-only root, uid 65534, all capabilities dropped, no-new-privileges, bounded memory/processes and a bounded temporary filesystem. Only its fixed source is mounted, not the repository, keys, journal, Docker socket or server roots. It reads a real file via MCP, computes an edit, patches it and makes the bounded HTTP request. Direct file/network probes must fail; unrestricted shell, third-party servers, provider-side execution and kernel/container escapes are not covered. This is a replaceable scripted acceptance actor, not evidence of external adoption or arbitrary model behavior.

The packet retains source/config/image digests, signed runtime evidence, separate server/endpoint observations, actor transcript, file hashes and explicit scenario assertions. Public synthetic trust anchors are retained separately; private signing keys remain host memory only. Actual host-process crash probes kill before dispatch and after observed effect: both are incomplete journals and cannot pass completed-run verification, even when independent observations show zero or one effect. Do not delete failed packets.

## Acceptance and remaining gates

Tests cover same-name servers and spoofed metadata; mutation/duplicate/oversize arguments; denied tool with allowed effects and vice versa; multiple warnings with one prompt; deny with zero prompts; generation/panic change during confirmation; malformed extractors, evaluator receipts and sink acknowledgments; callback/transport failures; durable permit before independently observed effects; terminal failure latching; journal substitution/truncation/reordering/replay; policy expiry/rollback; real file edit, symlink/hardlink/redirect refusal; actor bypass probes; crashes before and after dispatch.

All existing SDK/schema/doc/conformance gates stay green. CI adds a contained pilot job with retained artifacts and exact source/run/attempt identity. Delivery closes the implementation and first-party pilot slice of C only. An independently authored qualified engine running this workflow and Project D's external adopter/assessor remain open.

## Primary references

- [MCP tools and server-scoped names](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [MCP basic protocol](https://modelcontextprotocol.io/specification/2026-07-28/basic)
- [MCP stdio transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio)
- [Docker run isolation controls](https://docs.docker.com/engine/containers/run/)
- [Node filesystem API](https://nodejs.org/api/fs.html)
- [Node crypto API](https://nodejs.org/api/crypto.html)
