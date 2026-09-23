# Project C Trusted Invocation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver and qualify the experimental trusted MCP invocation boundary and contained first-party coding pilot.

**Architecture:** An immutable host registry, authenticated policy snapshot and narrow engine interface feed one invocation state machine. A signed authoritative journal records admission and observed outcomes. An owned MCP transport/server and isolated actor exercise real file/network effects with independent observations.

**Tech Stack:** Existing TypeScript SDK, Node >=18 built-ins, existing Ed25519/canonical/receipt code, Python stdlib actor and Linux Docker pilot.

**Spec:** `docs/plans/2026-09-23-project-c-design.md`, bounded by roadmap C in `docs/plans/2026-09-22-foundation-assurance-roadmap.md`.

## Global Constraints

- Use the existing `wave-6` checkout. Do not merge, tag, publish, contact adopters, or modify Chio.
- Preserve HushSpec 0.2, receipt 0.2, log and conformance-report wire formats and all existing adapter behavior.
- Node >=18; TypeScript in `packages/hushspec`; no new runtime dependencies. Linux is required only for the contained pilot.
- New evidence is experimental version `0.1.0`, domain-separated and never called a compliance certification, build attestation or exactly-once guarantee.
- Source, host, registry, engine, clock, policy trust roots, journal signer and Docker daemon are trusted. The actor, arguments, tool descriptions and server-reported identity are not.
- Commit, push and qualify exact-head CI after local verification and a fresh whole-change review. Preserve failures and incomplete packets.

The user requested plan, review, implementation and review in one pass. Execute natively after independent plan review without another approval stop. Preserve the existing branch and publication limits. Record material rulings and deferred minors in this plan's execution ledger and final handoff.

## Review Focus

1. Reentrant host callbacks or delayed results must not bypass policy/panic admission checks or reuse approval after reload.
2. Signed but structurally plausible journal substitutions must fail cross-call, receipt, policy and checkpoint binding checks.
3. Duplicate/escaped JSON keys and Unicode identities must not create different authorized and dispatched values.
4. A partially successful file/network operation or lost terminal record must remain unknown/error, never proven prevented or safely retried.
5. Container/transport resource exhaustion and unexpected child exit must fail closed without leaving unbounded pending work or an alternate actor route.

## File responsibilities

- `packages/hushspec/src/invocation/json.ts`: bounded strict JSON snapshots and domain hashes.
- `packages/hushspec/src/invocation/registry.ts`: identity and immutable host dispatch bindings.
- `packages/hushspec/src/invocation/policy.ts`: authenticated resolved generations and engine seam.
- `packages/hushspec/src/invocation/journal.ts`: event types, signed durable writer and checkpoint.
- `packages/hushspec/src/invocation/verify.ts`: offline structural/cryptographic/state verification.
- `packages/hushspec/src/invocation/coordinator.ts`: capture, evaluation, confirmation, admission and completion.
- `packages/hushspec/src/invocation/stdio.ts`: bounded owned MCP request/response transport.
- `packages/hushspec/tests/invocation-*.test.ts`: contracts and negative tests.
- `scripts/mcp-pilot/{effects.mjs,server.mjs,agent.py,host.mjs}`: constrained real tools, actor and pilot host.
- `scripts/run_mcp_pilot.mjs`: scenario controller, independent observations and retained packets.
- `schemas/hushspec-invocation-journal-experimental.v1.schema.json`: separate experimental entry/checkpoint schema.
- `docs/src/reference/trusted-invocation.md`: operator API, trust boundaries, evidence interpretation and reproduction.

### Task 1: Immutable bindings and authenticated engine snapshots

**Files:** Create `src/invocation/{json,registry,policy}.ts` under the TS package; create `tests/invocation-bindings.test.ts`; export opt-in APIs from `src/index.ts`.

**Interfaces:** Produces `snapshotJson(text, {maxBytes?,maxDepth?,maxNodes?}): JsonValue`, `hashJson(value): string`, `qualifiedToolTarget(connectionId,toolName): string`, `InvocationRegistry`, `InvocationBinding`, `InvocationEngine`, `PreparedInvocationEngine`, `AuthenticatedPolicy`. `InvocationBinding.extract(args)` returns readonly effect actions; `dispatch(args, {callId})` returns unknown or a promise. `AuthenticatedPolicy(document,envelope,publicKeyPem,engine,lastSeenVersion?)` exposes frozen resolution/prepared engine and `verifyAt(now)`.

- [ ] Write tests with actual signed policies, real compiled evaluation and frozen nested arguments:

```ts
expect(() => snapshotJson('{"x":1,"\\u0078":2}')).toThrow();
expect(qualifiedToolTarget('repo', 'read/file')).toBe('mcp:repo/read%2Ffile');
expect(() => snapshotJson('{"x":1e999}')).toThrow();
expect(Object.isFrozen(snapshotJson('{"x":{"y":1}}'))).toBe(true);
```

Also assert control/lone-surrogate/duplicate identity refusal, UTF-8 limits, rollback/expiry/unresolved/unsigned refusal, engine policy hash binding, and real action receipt traces.
- [ ] Run `npm --prefix packages/hushspec test -- tests/invocation-bindings.test.ts`. Expected: missing APIs fail assertions before implementation.
- [ ] Implement a recursive JSON token parser with duplicate-key sets, raw-byte/depth/node limits and finite Unicode values; canonicalize and deep-freeze copied data. Snapshot registry bindings, enforce qualified identity grammar, verify resolved signed policy and compile the default engine. Reject monitor/unverified receipts at the later coordinator seam, not in legacy adapters.

```ts
const resolution = resolutionFromResolved(spec, 'host:invocation');
resolution.signature = { verified: true, key_id: verified.keyId,
  verified_at: now.toISOString() };
const compiled = compileResolution(resolution);
// Engine evaluates the captured compiled object, never mutable provider state.
```

- [ ] Run the focused test, then `npm --prefix packages/hushspec run build && npm --prefix packages/hushspec run lint && npm --prefix packages/hushspec test`. Expected: all pass, existing adapter semantics unchanged.
- [ ] Commit `feat: add authenticated invocation bindings and engine snapshots`.

### Task 2: Signed authoritative journal and offline verifier

**Files:** Create `src/invocation/{journal,verify}.ts`, `tests/invocation-journal.test.ts`, experimental schema; update generated CLI schema inclusion and reference schema index as required by existing generators.

**Interfaces:** Consumes Task 1 `snapshotJson/hashJson`, existing `receiptHash/parseReceipt/signContentHash/verifyContentHash`. Produces `InvocationEvent`, `InvocationJournal.append(event): {sequence:number,entryHash:string}`, `FileInvocationJournal.close(): InvocationCheckpoint`, and `verifyInvocationJournal(entriesJsonl,checkpointJson,{runtimePublicKeyPem,policyPublicKeyPem,expectedStreamId,expectedHeadHash?}): InvocationVerification`. Verification returns call dispositions and explicit completeness, never infers prevention from missing terminal evidence.

- [ ] Add real-key/fsync-file round trips, then mutation tests:

```ts
expect(() => verifyInvocationJournal(lines.slice(0, -1).join('\n'), checkpoint,
  trust)).toThrow();
expect(() => verifyInvocationJournal(reordered, checkpoint, trust)).toThrow();
expect(() => verifyInvocationJournal(foreignReceipt, checkpoint, trust)).toThrow();
```

Exercise wrong roots, duplicate/unknown fields, duplicate sequence/call/receipt IDs, signature tampering, cross-call permits, incomplete calls, policy expiry/generation disagreement, write/fsync/close failures and resource limits. A valid prefix without checkpoint is not a complete verification.
- [ ] Run `npm --prefix packages/hushspec test -- tests/invocation-journal.test.ts`. Expected: new journal APIs fail before implementation.
- [ ] Implement closed event shapes and semantic replay. Sign canonical domain-bearing bodies. Write exclusive 0600 files in a fresh 0700 directory, loop until all bytes written, fsync before acknowledgments, latch on any failure. Close signs count/head and fsyncs parent; no reopening old streams.

```ts
const body = { kind: 'hush.invocation.entry', format_version: '0.1.0',
  stream_id: streamId, sequence, previous_hash: previousHash,
  timestamp: new Date().toISOString(), event };
const entryHash = hashJson(body);
const signature = signContentHash(entryHash, privateKeyPem);
```

- [ ] Run focused/full TS tests, build/lint, `python3 scripts/generate_cli_schemas.py`, and generator `--check`. Expected: pass with existing receipt/log/report schemas byte-for-byte unchanged.
- [ ] Commit `feat: add signed durable invocation journals and verification`.

### Task 3: Fail-closed invocation coordinator

**Files:** Create `src/invocation/coordinator.ts`, `tests/invocation-coordinator.test.ts`; extend exports.

**Interfaces:** Consumes registry, authenticated policy, engine, journal. Produces `InvocationCoordinator({registry,journal,policyPublicKeyPem,engine?,confirm?,mode?:'enforce',timeoutMs?,lastSeenVersion?})`, `installPolicy(document,envelope)`, `setPanic(active)`, `invoke(connectionId,toolName,argumentsJson,trustedContext?)`, `close()`. Result discriminant is `blocked | completed | error | unknown`, always with `callId`; only completed returns a bounded JSON value.

- [ ] Add actual signed-policy/compiled-engine tests with dispatch counters:

```ts
await coordinator.invoke('repo', 'patch_file', args);
expect(prompts).toBe(0); // a denied tool dominates allowed effects
expect(dispatches).toBe(0);
// A second fixture warns on tool plus two effects: one prompt, one dispatch.
```

Cover mutation, malformed plans/receipts, same-name server, unqualified allow, evaluator timeout/rejection, prompt false/throw/timeout, reload/panic during confirmation, reentrant append changing generation, async/bad sink acknowledgments, sink failure before permit and after effects, bounded pending work, duplicate call/receipt IDs and close with pending work.
- [ ] Run `npm --prefix packages/hushspec test -- tests/invocation-coordinator.test.ts`. Expected: coordinator contract assertions fail before implementation.
- [ ] Implement the state machine with captured identity/args/actions/context/policy, deny-first aggregate, one bound prompt and no-await final admission:

```ts
assertCurrent(snapshot);
appendPermit(snapshot, receipts);
assertCurrent(snapshot);
const dispatched = binding.dispatch(snapshot.arguments, { callId });
const result = await dispatched;
```

Record abort/unknown consistently if the second check detects reentrancy after a permit. Do not claim a post-permit block proves prevention; close completeness reflects the terminal observation. Latch sink failures and reject further work. Capture/validate all evaluator receipts before durable decision, with no best-effort sink fallback.
- [ ] Run focused and full TS build/lint/tests. Expected: all pass, every prevented scenario has dispatch counter zero, all admitted outcomes reconcile.
- [ ] Commit `feat: enforce atomic trusted invocation admission`.

### Task 4: Owned MCP transport and contained effect server

**Files:** Create `src/invocation/stdio.ts`, `tests/invocation-stdio.test.ts`, `scripts/mcp-pilot/{effects,server}.mjs`; create `tests/invocation-server.test.ts`.

**Interfaces:** Produces `OwnedMcpConnection(command,args,options).callTool(name,args,{callId})`, `.listTools()`, `.close()`; host never uses discovery metadata for registry identity. `effects.mjs` exports `extractRead`, `extractPatch`, `extractFetch` using pinned logical root/origin and exact argument shapes. Server takes explicit root/audit/origin configuration and emits only protocol messages on stdout.

- [ ] Write child-process fixtures for foreign/duplicate/oversize IDs/results, invalid metadata/version, timeout, early exit and shutdown; Linux server tests exercise real read/patch and independent audit.

```ts
expect(await connection.callTool('read_file', {path:'note.txt'}, {callId}))
  .toMatchObject({content: expect.any(Array)});
await expect(connection.callTool('read_file', {path:'../secret'}, {callId}))
  .rejects.toThrow();
```

Also assert symlink/hardlink refusal, stale old-content refusal, patch effect fidelity, noncanonical URL/redirect refusal and partial-write error interpretation.
- [ ] Run `npm --prefix packages/hushspec test -- tests/invocation-stdio.test.ts tests/invocation-server.test.ts`. Expected: new interfaces fail before implementation.
- [ ] Implement bounded per-request MCP 2026-07-28 metadata and request correlation. Use synchronous root descriptor opens with `O_NOFOLLOW`, `fstat` and exact byte limits; verify old content, then write/truncate/fsync same descriptor. Network requests use only pinned loopback URL, redirect refusal, timeout and response-byte bound. Audit received and outcome separately with call IDs.

```js
const fd = openSync(`/proc/self/fd/${rootFd}/${basename}`, flags | constants.O_NOFOLLOW);
const stat = fstatSync(fd);
if (!stat.isFile() || stat.nlink !== 1 || stat.size > 65536) throw new Error('unsafe file');
```

- [ ] Run focused/full TS build/lint/tests. Expected: pass; platform-gated Linux filesystem checks run in the Linux CI pilot, not silently claimed on unsupported hosts.
- [ ] Commit `feat: add bounded owned MCP transport and pilot tools`.

### Task 5: Isolated coding workflow and independent reconciliation

**Files:** Create `scripts/mcp-pilot/{agent.py,host.mjs}`, `scripts/run_mcp_pilot.mjs`, `packages/hushspec/tests/invocation-pilot.test.ts`.

**Interfaces:** Controller CLI `node scripts/run_mcp_pilot.mjs --output <fresh-directory>` produces retained completed and deliberately incomplete packets. Host uses Task 3 coordinator and Task 4 connections; actor uses stdio MCP aliases only. Exit zero requires scenario assertions plus offline journal verification and independently observed effect reconciliation.

- [ ] Write acceptance assertions before actor/host implementation:

```ts
expect(packet.assertions.actual_file_edit).toBe(true);
expect(packet.assertions.direct_actor_routes_denied).toBe(true);
expect(packet.assertions.permits_match_server_calls).toBe(true);
expect(packet.crashes.every(c => c.complete_verification_refused)).toBe(true);
```

The controller must fail for a flipped counter, substituted source digest, missing server terminal or foreign call ID. Crash scenarios kill the host before dispatch and after the server effect; never fill missing terminals.
- [ ] Run `npm --prefix packages/hushspec test -- tests/invocation-pilot.test.ts`. Expected: missing controller contract fails before implementation.
- [ ] Implement synthetic signing keys, separate public trust file, digest-pinned official Python image, static tool aliases, isolated actor and controlled file/HTTP fixtures. Capture actor transcript, server audit, endpoint counts and content hashes independently. Reconcile only after children stop and files fsync. Retain source/config/image/run identity and all negative/crash evidence.

```js
const isolation = ['--network=none', '--read-only', '--user=65534:65534',
  '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=64',
  '--memory=128m', '--tmpfs=/tmp:rw,noexec,nosuid,size=16m'];
```

- [ ] Run focused tests and `node scripts/run_mcp_pilot.mjs --output target/project-c-pilot-local`. Expected: real file changes exactly as intended, endpoint requests reconcile, denied calls never reach server, bypass probes fail, both crash packets refuse complete verification. Repeated runs use fresh directories.
- [ ] Commit `test: qualify isolated MCP coding workflow and crash evidence`.

### Task 6: CI, operator documentation and complete qualification

**Files:** Modify `.github/workflows/ci.yml`, roadmap status, `docs/src/SUMMARY.md`, README integration pointer and schema reference; create `docs/src/reference/trusted-invocation.md` and `docs/plans/2026-09-23-project-c-qualification.md`.

**Interfaces:** Consumes pilot CLI and public APIs; produces read-only CI job `Trusted MCP Pilot`, retained evidence and exact-head qualification record.

- [ ] Add documentation/CI contract tests checking enforce-only example, explicit trust keys, no independent/adopter claim, and always-upload retained artifacts. Run before adding those integration pieces. Expected: missing doc/job assertions fail.
- [ ] Add Ubuntu Node 22 pilot job with digest-pinned actor image, `npm ci`, build and pilot controller; artifact upload uses `if: always()`, no private keys. Document lifecycle, generation boundary, sink contract, direct-route exclusions, evidence limits, reproduction and all open roadmap gates.

```yaml
- name: Exercise contained coding workflow
  run: node scripts/run_mcp_pilot.mjs --output target/project-c-pilot-ci
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: trusted-mcp-pilot
    path: target/project-c-pilot-ci
```

- [ ] Run all existing CI-equivalent gates: Rust fmt/clippy/workspace tests/no-default-features/MSRV/package; TS build/lint/full tests; Python tests; Go test/vet/race; all generated-source checks; canonical vectors, comment hygiene, cross-SDK raw parsing, doc snippets and mdBook; L5 reference/differential tests and Project B Go L3 execution qualification. Run packaging with fresh home-local scratch/cache/target identity, not stale synthetic registry configuration. Expected: pass with deliberate platform skips reported separately.
- [ ] Run the complete pilot again, record exact source/environment/digests and test counts, self-check every spec requirement, then commit `docs: document and qualify trusted invocation pilot`.
- [ ] Dispatch one fresh whole-change reviewer over baseline through HEAD with the Review Focus and ledger rulings. Fix Critical/Important findings in one RED/GREEN pass, run full affected suites and record deferred minors; do not dispatch another reviewer. Expected: no unfixed Critical/Important findings.
- [ ] Commit review fixes, push `wave-6`, dispatch exact-head CI and qualify both branch/PR attempts to terminal state, preserving failures and retry logs. Expected: local/remote/PR SHA agreement and all required terminal checks green. No merge or publication. Record unresolved review state distinctly.

## Self-review before implementation

The six tasks cover all design sections: Task 1 snapshots/trust/engine; Task 2 signing/checkpoints/replay; Task 3 lifecycle; Task 4 owned transport/effects; Task 5 containment/reconciliation/crash; Task 6 publication boundaries and qualification. Each Review Focus has explicit negative tests in its owning task. The shared interface graph is 1 -> 2/3, 2 -> 3/5, 3/4 -> 5, 5 -> 6. All new contracts are opt-in and experimental. No task supplies an independently authored engine or external-adopter evidence; those gates remain open by design.
