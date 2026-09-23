# Project D readiness and Chio candidate assessment

Status: repository-owned preparation only. **Project D is not complete.**
Scope: [design](../plans/2026-09-23-project-d-design.md) and
[stage-gated plan](../plans/2026-09-23-project-d-implementation.md).
Inspection date: 2026-09-23.

## Judgment

Chio is a useful real downstream integration target. It is internal and its
evaluator is a port of Hush's reference implementation, so it is not the
independently authored engine or external adopter the foundation milestone needs.
Upgrading it can expose and repair practical interoperability gaps; calling that
upgrade external validation would overstate the evidence.

The next implementation decision is an explicitly scoped Chio migration in an
approved non-main checkout: preserve/migrate native semantics or adopt the current
reference SDK. Both remain first-party, reference-derived paths. No Arc source
has been changed and no Chio build, conformance run or MCP integration run was
performed for this assessment.

## Source evidence

Hush: `385ca54961c673f03db81e7fe7c45ee48756bd82`, `wave-6`.
Arc: `f5566d9a765c21cb36652a99c79de64968a656bf`, clean `main`.
Read-only inspection followed Arc's instructions, including a graphify query
before detailed source exploration; its result was insufficient for the actual
dependency/provenance question, so the relevant files and git history were read.

- `chio-policy/Cargo.toml` has its own parser/guard dependencies and no Hush
  reference-crate dependency. Absence of a dependency is not source independence.
- Ancestor `56f2c6b09cde0fef05e15cec1c0f08da33efe892`,
  `crates/pact-policy/src/evaluate.rs:3`, explicitly states that the evaluator was
  ported from the HushSpec reference implementation. An ancestor check exited 0;
  comparison with Hush's `cfe1391` evaluator showed shared structure.
- Current Chio accepts only document version `0.1.0`. Its named action dispatch,
  aggregation, context, legacy receipts and noncanonical policy hashing differ
  from current Hush semantics. The design's migration matrix names exact files.
- The real control-plane path compiles policy into guards. Evaluator conformance
  cannot stand in for qualification of that distinct runtime path.
- C exposes an engine seam, but its runnable host evaluates with TypeScript and
  its packet verifier hashes TypeScript/YAML artifacts. A Chio adapter and real
  qualification/material binding do not yet exist.
- The older policy-expansion design exists on a separately known branch, not
  this Arc `main`. Proposed spec extensions in that draft are not current Core.

These observations are not a full vulnerability assessment, proof of exploitable
runtime behavior, or a count of conformance failures. No candidate was executed
through B; a version mismatch inferred from source is not a retained B report.

## Gate ledger

| Gate | Actual state | Required next evidence or decision |
| --- | --- | --- |
| Chio candidate selection | User selected internal Chio | Approved migration scope, architecture and checkout/branch |
| Chio current-semantic qualification | Open | Actual pinned migrated executable passing B L0-L3 |
| Chio same-workflow execution | Open | Reviewed C adapter/material binding and observed workflow |
| Independent implementation | Open; Chio's source is reference-derived | Different candidate with reviewed provenance, L3 qualification and the same workflow |
| Early external critique | Unmet; B/C proceeded internally | Authorized participant critique before D-specific design/scope freeze; record resulting B/C changes |
| Outside assessment | No practitioner selected | Accepted objectives, actual review, objections and dispositions |
| External adoption | No external adopter selected | Adopter-operated integration and retained evidence |
| OSCAL | Optional, not attempted | Actual assessment context and reviewed evidence bridge if needed |
| Merge/publication/outreach | Not performed | Separate explicit authority |

B's prior whole-change review was interrupted. Its recorded self-review and
qualification are not a completed fresh independent review. The D plan includes
that review before external qualification depends on B. C's review does not
retroactively cover B or the future Chio integration.

## Plan review and preparation verification

A fresh read-only plan reviewer found no Critical issues, two Important issues
and one Minor improvement:

1. The external-run example omitted `--bin hushspec-testkit`. The original help
   invocation reproduced Cargo exit 101 for ambiguous binary selection. The
   corrected invocation exited 0 and exposed the intended external CLI.
2. External participant critique was scheduled after migration/adapter work.
   The plan now puts authorized early critique before D-specific assessment
   design freeze and explicitly records that B/C lacked this external input.
3. The example now passes the clean Hush source SHA even for a local run and
   distinguishes it from the separate engine source/material identity.

All three were addressed before the readiness record. No plan finding was
deferred. The reviewer explicitly did not assess Chio build feasibility, migrated
semantics, guard equivalence, workflow execution, full B/C correctness, hosted
qualification, real participant independence/consent or OSCAL compliance. Those
remain separate gates, not implied approval.

Initial documentation checks passed: `git diff --check`, comment hygiene and
`mdbook build docs`. These do not run Chio or establish semantic conformance.
Direct inspection confirmed all 15 local Markdown targets in the changed
documents exist; plans outside mdBook are not covered by the book build.
The fresh final preparation review and candidate qualification are recorded
separately when performed; this section does not predict their outcome.

## Hosted baseline, not qualification of this preparation

Live checks found the Hush local, remote `wave-6` and PR #10 heads equal to
`385ca54961c673f03db81e7fe7c45ee48756bd82`. Both baseline CI runs completed
successfully on attempt 1: direct-head `35867295742` and PR `35867304719`, each
with 26 successful jobs. PR #10 remained open against `wave-5`.

Any preparation commit needs its own exact-head results. Baseline green CI is
not Project D completion, Chio qualification, participant approval or publication.
