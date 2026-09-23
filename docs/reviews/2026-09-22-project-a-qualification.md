# Project A qualification

Date: 2026-09-22. Branch: `wave-6`. Implementation baseline: `df45623`;
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

## Final qualification gates

Full workspace/cross-SDK verification and an independent whole-branch review
are in progress. Exact-head hosted CI has not yet been run for the final
candidate. This record will be reconciled with completed local results before
the final source commit; hosted run URLs, attempts and the exact matching SHA
belong to the final handoff and GitHub checks.

No PR merge, release tag or package publication is part of this execution.
An automated review is not human approval. A qualified branch is not a shipped
standard.

## Remaining foundation gates

B: run a pinned independent engine through a real executable conformance
adapter, with identity tied to what ran. C: validate a coding-agent MCP workflow
with server/tool/argument/effect binding and durable no-permit/no-dispatch at
the side-effect boundary. D: obtain external assessor and adopter evidence.
These remain open in the [foundation roadmap](../plans/2026-09-22-foundation-assurance-roadmap.md).
