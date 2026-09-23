# Project B qualification

Branch: `wave-6`. Baseline: `2835c86cce67f4bea930343a7685497460010615`.
Scope: the [reviewed implementation plan](../superpowers/plans/2026-09-23-implementation-bound-conformance.md)
and [design](../superpowers/specs/2026-09-23-implementation-bound-conformance-design.md).
The external controller and Go adapter are first-party bring-up. Independently
authored engine qualification, trusted MCP dispatch, external assessment and
adoption remain open. No merge, tag or publication is authorized here.

## Implementation and evidence

| Slice | Commit | Evidence |
|---|---|---|
| Reviewed design/plan | `6756593`, `24f4d12` | Independent plan review: five Important and two Minor refinements incorporated before implementation. |
| Contracts and snapshots | `f2c79e0` | Closed schemas, strict JSON, byte caps, alias/path refusal and running-controller inode identity. |
| Processes | `b1f087e` | Real timeout, crash, flood, environment and inherited-pipe descendant tests. |
| Corpus and scoring | `9b12929` | Explicit L0, every subcase, raw scalar spellings, required refusal codes, large integer comparisons and no reference fallback. |
| Go adapter | `4c9c6a7` | Public SDK operations, supplied-map-only resolution, no ambient signature sidecars; full Go/vet/race pass. |
| Controller and packets | `a5eb9c5` | Five black-box fault tests, atomic no-overwrite publication and complete real Go L3 run. |

The real Go retry dispatched all 820 planned requests. It passed L0:164,
L1:164, L2:23 and L3:547 result slots. L4 has 8 passed and 417 unattempted;
L5 has 52 unattempted. Highest qualifying level is 3. All 1375 unique slots
and 4023 artifact digests/lengths were checked. An optimized acceptance-driver
run repeated that outcome and passed offline packet consistency verification.

The verifier tests altered report/output bytes, rehashed inconsistent counts,
missing/duplicate/foreign terminal records, duplicate slots, rehashed stale
responses, exact wire-input hashing and symlink artifacts. It checks integrity
and cross-record consistency, not independent re-grading or authenticated
producer provenance. The CI job retains the packet even on nonqualification.

## Original failures retained

The initial Go packet at `target/project-b-go-attempt-1` completed all requests
but failed qualification. The unchanged corpus exposed three distinct causes:

1. The controller used the 1.x schema for valid frozen 0.x empty names. It now
   selects the declared lineage; frozen schemas were not modified.
2. The adapter called the core evaluator without the detection pipeline. It now
   uses the public detection-aware evaluator, verified with a literal injection.
3. Go serialization omitted explicit zero/false fields with nonzero parse
   defaults. Merge copies then restored permissive patch limits or enabled
   disabled rules. Generated Go tags now retain those scalar values. YAML/JSON
   roundtrips and all three merge strategies have failing-then-passing regressions.

The full TypeScript suite exposed unsupported `allOf`, `oneOf` and
`maxProperties` in its schema test helper. Behavior tests failed before support
was implemented. The unknown-keyword guard remains enforced, including
unreached combinator branches. Full build/lint and 2336 tests then passed.
Python passed 3036 tests with four intentional skips. Rust 1.88 workspace build
and the 35-document four-SDK roundtrip gate passed.

The original unstripped black-box matrix passed in 873.52 seconds. Subsequent
fault tests strip debug sections from a copy of the actual compiled controller,
retaining its actual running image and keeping all assertions/deadlines. This
reduces debug-byte hashing overhead; unstripped controller-inode and real Go
run evidence remain separate. Output-directory mode first failed a 0700
regression at 0775 and was repaired before the final controller commit.

Original logs, retries and the execution ledger are retained in the ignored
plan workspace until archival. No failing result is replaced by a later pass.

## Final review and repair

The independent whole-branch reviewer was interrupted by the platform. Its
partial findings are retained, but it did not complete the review or issue an
approval. After disclosure, the user directed continuation with an author
self-review, repairs and exact-head CI. That fallback is weaker than a completed
fresh review and is not a substitute for human review before merge.

The partial review established one Important finding: the aggregate request
budget was enforced after eager case expansion. Repeated policy text or builtin
dependency maps could exhaust memory before the controller returned an error.
Both real-CLI regressions failed under a 384 MiB address-space limit before the
repair and then passed with the same limit. Planning now checks case count and
exact retained request/input sizes incrementally, including canonical requests.
An exact-budget regression accepts N bytes and rejects N-1.

The author self-review found the adjacent pre-planning YAML alias expansion
path. Its CLI regression also failed before repair and passed afterward.
Decoded fixture containers now have separate bounded accounting; raw policy
text still reaches the engine unchanged. This accounting is not a fixed RSS
guarantee. Original failed logs are retained separately from passing retries.

The author reviewed capture/dispatch/publication boundaries, planning/scoring,
Go operation delegation and resolver isolation, verifier consistency checks,
schemas, tests and CI/docs. No additional blocking finding was established in
that pass. Neither review proves sandboxing, producer authentication, independent
authorship, build attestation, full L4/L5, or bounded filesystem latency.

Deferred Minor M1: Linux-specific snapshot tests are not consistently gated on
Linux, and a publication variable is used only on Linux. Non-Linux test/lint
portability remains unqualified; external execution is explicitly Linux-only.

## Post-repair local qualification

The post-repair Rust pipeline passed format, all-features workspace clippy with
warnings denied, full workspace tests (1136 passed, one intentional ignored
benchmark) and the no-default-features build. Rust 1.88 also built the
all-features workspace. All eight external CLI tests passed, including the
three memory-limited regressions, alongside the exact-budget scoring regression.
TypeScript passed build/lint and 2336 tests; Python passed 3036 tests with four
intentional skips; Go passed full tests, vet and race tests.

The optimized Go run again qualified at L3 with 820 requests and 1375 slots.
The original built-in runner qualified at L5, and the seed-42 differential run
completed 2000 actions with zero divergences. All 13 generators, 16 canonical
vectors, nine offline verifier tests, four-SDK roundtrips, snippets, hygiene and
the mdBook build passed. No corpus expectation or existing gate was weakened.

All three Rust packages verified using a fresh synthetic registry and separate
build directory (`target/project-b-package.R1lX2g`). Packaged source trees, CLI
schemas and the synthetic registry's core source match the checkout byte for
byte. This local packaging check used `--allow-dirty` before the repair commit;
it neither published packages nor reused the shared test executable directory.

## Hosted qualification and remaining gates

Hosted qualification is recorded separately by terminal PR/direct workflow runs
on the exact repair candidate. Compare local, remote and PR head SHA and inspect
all jobs and attempts; the [CI history](https://github.com/backbay-labs/hush/actions/workflows/ci.yml)
is the hosted record, not this local test summary.

The complete independent final-review gate remains open. PR #10 remains open
against `wave-5`; historical review threads and human approval remain separate
from test qualification. Independent-engine, trusted MCP dispatch and external
assessment/adoption gates remain open. No release readiness, merge, tag or
publication is implied.
