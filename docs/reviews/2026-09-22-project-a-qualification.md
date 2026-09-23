# Project A qualification

Started: 2026-09-22; review repairs: 2026-09-23. Branch: `wave-6`. Implementation baseline: `df45623`;
review baseline: `3cca247`. Scope is the [approved trustworthy-evidence plan](../superpowers/plans/2026-09-22-trustworthy-evidence.md),
not the independent-engine or trusted MCP-dispatch milestones.

## Implemented and focused verification

| Area | Implementation | Focused evidence |
|---|---|---|
| Reference identity | `0324def` | Arbitrary engine labels rejected; mapper counterexample retained; unsupported integration claims corrected. |
| Callback failure | `bdc25d7`, `09f7aef` | Original failure preserved after one blocked-record attempt in all four SDKs; sink failure and Go nil panic covered. |
| Strict contracts and inputs | `bf45443`, `73d062e` | Closed experimental models, duplicate/depth refusals, bounded snapshots, exact-byte signatures and signer-role checks. |
| Streams, policy and inventory | `dc026d4` | Ordered rotations, policy state machine, independent heads, global duplicate IDs, policy origin and prefix/tail/whole-stream inventory checks. |
| Strict CLI and outputs | `bcb8cae` | Nine CLI tests and publication regressions; immutable inputs, byte-bound native report, no overwrite, sidecar-last completion. |
| OSCAL context and export | `d4dbe14`, `2af3dd4` | Pinned official schemas, five context tests, observation-only signed-monitor export, independent interval counts and refusal-without-publication cases. |

At the implementation checkpoint, all 138 CLI unit tests, 9 strict JSON CLI
tests, 8 OSCAL CLI tests and 16 legacy report tests passed. CLI clippy with
`-D warnings` passed. The later documentation fixture regression adds a ninth
OSCAL integration test. These are local results, not hosted qualification.

## Preserved failures and rulings

Original red results and retries are retained in the ignored execution ledger
`.superpowers/sdd/2026-09-22-trustworthy-evidence/`, not replaced with later
success logs. Notable integration failures were a test helper's borrowed path,
an extracted doc comment and a UUID test left behind after renderer extraction;
each was corrected and rerun without weakening assertions. The CLI's temporary
dead-code warning gate was deferred until context/export integration, then
passed unchanged with `-D warnings`.

Bounded implementation rulings:

- Add the already-locked `same-file` dependency edge to identify opened inputs,
  including hard links. Canonical path equality alone is insufficient.
- Expand only the experimental result's diagnostic basis bounds to cover legal
  input capacities (3,072 entries, 8,192 characters); input budgets stay fixed.
- Retain verified interval decision/enforcement totals in a nonserialized
  internal cache for OSCAL. Wire schemas remain unchanged; parsing an unsigned
  sidecar does not supply those trusted counts.
- Add schema-reference documentation required by the existing schema guard and
  isolate OSCAL-only test builders to avoid unused integration helpers.
- Apply the existing third-party-schema prose-lint exception to the four exact
  OSCAL paths. NIST's assessment-task descriptions triggered ten false positives;
  the pinned upstream bytes remain protected by SHA-256 tests.

The cost of these rulings is a small dependency edge, a larger bounded
diagnostic field, one internal cache and documentation/test organization. None
establishes stronger trust in producer assertions or changes Core semantics.

The single-package `cargo package -p hushspec-cli --locked` attempt failed on
the unpublished workspace dependency `hushspec ^1.0` (crates.io has 0.1.x).
The required final gate is `cargo package --workspace --locked`, which packages
the local prerequisites together. No version substitution or publication is
authorized by this repair.

The first workspace packaging run returned zero but was invalidated: Cargo
reused stale `hushspec 1.0.0` source from its synthetic local registry. Running
packaging concurrently also replaced `target/debug/h2h`, causing five existing
timestamp fixture failures in the full Rust suite. Rebuilding the current CLI
passed the unchanged failing fixture test. The workspace and newly packaged
`conditions.rs` digest was `a3807c9241e5cc7fc841893dab288841d6f27597f88c151c00b54e4e386938bd`;
the stale registry copy was `e83ab0799738a7e961f8de9774c33284b7bae87129a4dee4b300a6e410bd73a2`.
The repeat package gate passed using a fresh synthetic-registry cache and a
separate build directory. All packaged crate source trees and CLI schemas match
the checkout, including the new synthetic registry's core source. Full workspace
tests passed without competing package builds.
Neither the invalidated packaging result nor the failed full-suite attempt is
counted as a pass.

## Independent review and regression repair

A fresh whole-branch reviewer inspected `3cca247..4ee75d9`. It found three
Important issues, no Critical issues and no deferred Minor issues. Each was
reproduced before the repair, with original failing output retained:

| Finding | Repair and observed regression |
|---|---|
| Copied AP links could dangle in Assessment Results | Recursively reject structured links in copied reviewed controls and subjects. `copied_scope_links_are_explicitly_unsupported` failed before repair, then passed for root scope, nested selections and subjects. |
| SSP implemented controls could name absent catalog IDs | Resolve every implemented control and reject repeats. `ssp_controls_must_resolve_without_repetition` failed before repair, then passed; a separate positive test permits AP selections not yet implemented by the SSP. |
| Goexit became a panic | Recover within the callback closure, record/repanic only after it returns. `TestGuardWarnGoexitDoesNotPanic` failed with `PanicNilError`, then passed; ordinary and legacy nil-panic behavior remains covered. |

`unresolved_context_references_leave_no_packet` also failed before repair by
publishing successfully, then passed all five refusal cases. All eight context
tests and ten OSCAL CLI tests passed after repair. The full Go suite, vet, race
suite and `GODEBUG=panicnil=1` confirmation tests passed after repair.

Review rulings retain pinned upstream whitespace, make no maximum-capacity
performance claim, and keep fatal/abort/panic-on-drop behavior outside the
recoverable callback guarantee. Truthful instrumentation, independently
acquired inventory, key custody and unsigned-sidecar provenance remain explicit
operator assumptions. B/C/D, hosted readiness and human approval were not
established by the reviewer. The implementation tests and hosted checks must
establish their own bounded results; automated review is not approval.

## Final local qualification

Local gates passed after implementation and the review repair in `ff117f3`.
Rust/Go and affected documentation gates were repeated after those repairs;
unchanged TypeScript/Python and cross-SDK lanes retain their execution results.

| Gate | Result |
|---|---|
| Rust workspace, all features, locked | 1,098 passed, zero failed; one existing ignored benchmark is run separately in CI. |
| Rust format and clippy | Passed, including unchanged `-D warnings`. |
| No-default-features and MSRV | Passed; installed `1.88` toolchain reports Rust/Cargo 1.88.0. |
| Rust workspace packaging, locked | Passed with isolated synthetic registry and target; packaged source/schema comparisons passed. |
| TypeScript Node 20.20.2 and 24.16.0 | Build/lint and 2,331 tests passed on each; npm audit reported zero vulnerabilities. |
| Python 3.13.13 | 3,036 passed; four pre-existing skips. |
| Go 1.26.4 | Full tests, vet, race and legacy nil-panic confirmation tests passed. Hosted CI covers Go 1.22. |
| Conformance and differential | 197/197 reference cases; seed 42, 2,000 differential cases, zero divergences. This is not independent-engine qualification. |
| Interchange and snippets | 35 documents across four SDKs; eight markdown snippets passed. |
| Generated artifacts | SDK contracts/models/builtins, CLI/testkit/canonical schemas, frameworks, fixture manifest, canonical/bundle/log vectors passed. |
| Documentation and hygiene | mdBook 0.5.4, runnable signed/tampered/monitor guide examples, comment hygiene and authored-file whitespace passed. Pinned vendor whitespace is retained. |

Exact-head hosted CI is deliberately not claimed in this pre-push record.
The final source/documentation commit must precede qualification; matching
local/remote/PR head, terminal run URLs, attempts and jobs belong to the final
handoff and GitHub checks. A later commit requires new exact-head qualification.

No PR merge, release tag or package publication is part of this execution.
An automated review is not human approval. A qualified branch is not a shipped
standard.

## Remaining foundation gates

B: run a pinned independent engine through a real executable conformance
adapter, with identity tied to what ran. C: validate a coding-agent MCP workflow
with server/tool/argument/effect binding and durable no-permit/no-dispatch at
the side-effect boundary. D: obtain external assessor and adopter evidence.
These remain open in the [foundation roadmap](../plans/2026-09-22-foundation-assurance-roadmap.md).
