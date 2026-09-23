# Project C qualification record

Branch: `wave-6`. Baseline: `96fb38442543dcb746c10fe4c0ea3333b3dfef7d`.
Scope: [design](2026-09-23-project-c-design.md) and
[implementation plan](2026-09-23-project-c-implementation.md).
This record distinguishes implementation/local evidence from final review,
exact-head hosted qualification, merge and publication.

## Reviewed design and implementation

Independent plan review identified three Important issues before code:
durability of newly created directory entries, public panic on/off transitions,
and signed envelope/document name-version equality. All three were incorporated
into the design and tested. No Critical plan issue remained.

| Slice | Commit | Evidence |
| --- | --- | --- |
| Design and reconciliation | `c8840ad`, `977150a` | Reviewed host/engine/journal/containment contracts |
| Immutable bindings and authenticated snapshots | `499eaad` | 29 initial tests, including strict JSON, mutation, expiry and identity/rollback refusal |
| Signed authoritative evidence | `bc4df49` | 20 initial tests, including valid signatures over invalid semantics, fsync failures and incomplete-run refusal |
| Invocation admission | `05f98cd` | 38 tests, including single confirmation, zero-prompt denial, reload/panic races and terminal-write failure |
| Owned MCP transport and tools | `bf1f887` | 22 tests using real subprocesses, file edits and an HTTP endpoint |
| Isolated workflow and reconciliation | `41b0302` | Nine focused tests with Docker integration explicitly enabled, real host SIGKILL and offline packet verification |
| Transport shutdown and duplicate replies | `a510229` | Two reproduced regressions repaired; 14 transport tests and the nine-test Docker run passed |

The default TypeScript suite at the workflow commit passed 2,453 tests with one
intentional Docker integration skip. The separate opt-in run exercised that
integration and passed all nine tests in its file. Build and lint passed.

## Local regression qualification

At `a510229` with the CI/documentation changes staged for review:

- Rust workspace: 1,136 passed, one ignored; fmt, clippy, no-default-features
  build and Rust 1.88 locked build passed.
- All three Rust packages built using a fresh home-local Cargo home and target.
  Packaged source and the staged registry core source matched the checkout.
- TypeScript: 2,455 passed, one opt-in Docker integration skipped; the explicit
  Docker run passed all nine tests. Build, lint and npm audit passed with zero
  reported vulnerabilities.
- Python: 3,036 passed, four skipped. Go tests, vet and race checks passed.
- All 13 generators, 16 canonical vectors, comment hygiene, nine Project B
  packet-verifier tests, 35-document four-SDK roundtrip, snippets and mdBook passed.
- Reference L5: 197 passed. Seed-42 differential run: 2,000 actions, zero
  divergences. First-party Go L3 packet: 820 requests and 1,375 evidence slots.

The two transport regressions were duplicate replies in one read resolving the
first request successfully, and shutdown waiting indefinitely for inherited
pipes after the owned child exited. Regression tests failed before repair and
passed afterward. Closing inherited pipe endpoints bounds transport shutdown;
it does not sandbox arbitrary approved server executables.

## Fresh whole-change review and repair

A fresh read-only reviewer examined baseline `96fb384` through `baad902`,
including all five review-focus classes. It found no Critical issues, one
Important issue and no Minor issues. Nested policy installation from a journal
or engine-preparation callback could replace the initial name, bypass the
remembered version floor, or skip a journal generation. Subsequent dispatch
could succeed despite evidence that offline replay rejected.

Three real-journal regressions reproduced all three variants before repair.
The installation transaction now refuses nested installation before changing
state, covering authentication, engine preparation and journal acknowledgment.
Reload during permit acknowledgment remains supported and still aborts dispatch.
All 41 coordinator tests, the full TypeScript suite (2,458 passed, one deliberate
Docker skip), build/lint and the explicit nine-test Docker integration passed
after repair. No Critical/Important finding remains unaddressed; no minor was
deferred. The repair was verified by these regressions, not a second review.

Strict Rust audit, cargo-deny, npm audit, isolated Python dependency audit and
workflow lint passed locally. The clean `baad902` pilot packet and later repair
integration packets are retained alongside earlier failures and crash evidence.

## Actual workflow and fault evidence

The completed actor run made six server calls and two endpoint requests. It read
and edited a real file, received one confirmation for three warning components,
and was blocked from a protected file, another same-name server, unmapped shell
dispatch and out-of-profile paths/URLs. Server-side symlink/hardlink refusal and
redirect refusal produced error outcomes without a prevention/rollback claim.
Direct actor read/write, shell-to-host-file and network probes failed.

The pre-dispatch crash retained an unknown patch permit, one completed server
read and an unchanged file. The post-effect crash retained an unknown patch
permit, two observed server calls and the completed edit. Both were actual host
SIGKILLs, lacked closing checkpoints and refused complete verification.

The controller refuses flipped endpoint counters, missing server terminals,
foreign call IDs, changed argument bindings and substituted source digests.
An injected counter fault returned nonzero while retaining the completed journal
and failure record. Current packets bind the policy-event engine identity to
the captured compiled SDK/parser inventory. An earlier local packet predating
that binding is retained as historical evidence, not current-format qualification.

## Boundaries and qualification status

The pilot is a deterministic first-party actor under a controlled Linux/Docker
profile. Signatures attribute host assertions; they do not establish honest
execution, build attestation, independent engine authorship or external adoption.
The independent-engine-in-this-workflow and external adopter/assessor gates stay
open. Existing receipt/log/report wire formats and legacy adapter behavior are
unchanged.

Local regression and fresh review/repair are recorded above. Hosted results are
separate in the execution ledger and exact candidate CI history; these local
results do not establish that later gate. The `Trusted MCP Pilot`
job retains successful, deliberately crashed and failed-qualification artifacts.
Compare local, remote and PR SHA plus every terminal run/attempt before making
an exact-head readiness claim. No merge, tag or package publication is implied.
