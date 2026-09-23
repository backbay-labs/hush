# Project D Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for the repository-owned steps. Steps use checkbox (`- [ ]`) syntax for tracking. Stop at an unsatisfied authority or participant gate; do not mark later steps complete.

**Goal:** Validate the coding-agent/MCP workflow with Chio as an internal integration candidate, a separately qualified independently authored engine, an external adopter and an outside practitioner.

**Architecture:** Reuse A's evidence discipline, B's engine-bound qualification and C's owned MCP workflow. Keep Chio migration separate from implementation independence and external adoption. This is a stage-gated operational plan: the Arc migration and concrete runtime adapter require a separately reviewed implementation design after their authority/architecture gate, not guessed code in this document.

**Tech Stack:** Existing Rust testkit, TypeScript invocation coordinator, Linux static executables, Docker-contained Python actor, signed JSONL and offline verifiers; Chio is Rust in `../arc`.

**Spec:** [Project D design](2026-09-23-project-d-design.md), subordinate to the [foundation roadmap](2026-09-22-foundation-assurance-roadmap.md).

## Global Constraints

- Continue Hush work in the existing `wave-6` checkout.
- Obtain the Chio migration scope and branch choice before modifying that separate repository.
- Keep the current Hush Core, canonical, receipt/log schemas and existing callers stable.
- No expected-answer access through the protocol, and no reference fallback.
- Retain failed attempts and unsupported operations.
- Private signing keys are never packet material.
- No third-party outreach, sharing private material, changes on Chio's `main`, merging, tagging or publication is authorized by this plan.
- Do not mark D complete until the independently authored engine ran the same workflow, the actual external adoption and assessment evidence exist, and the review dispositions and exact-head qualification are retained.

## Review Focus

1. Reference-derived Chio code labeled independent: inspect ancestry, not only Cargo dependencies (Task 1).
2. A green B packet attached to different runtime engine bytes: require artifact-substitution failures and no semantic fallback (Task 3).
3. A passing evaluator presented as Chio guard/kernel enforcement: require actual dispatch evidence or narrow the claim (Tasks 2-3).
4. A packet-contained key or missing terminal treated as trusted completeness: require separate trust handoff and negative offline checks (Task 4).
5. Internal/scripted evidence or invented OSCAL context presented as external assurance: retain early participant critique, consent, run provenance and recorded assessment scope (Tasks 2, 4-5).

## Task 1: Candidate and readiness record

**Files:** Create `docs/reviews/2026-09-23-project-d-readiness.md`; modify the execution update in `docs/plans/2026-09-22-foundation-assurance-roadmap.md`.

**Interfaces:** Consumes exact Hush/Arc revisions and current source/history. Produces a source-backed migration boundary, gate status and review record. No executable or runtime qualification is produced.

- [x] Review this design/plan with a fresh read-only reviewer. Address Critical/Important findings before executing the remaining preparation steps.
- [x] Confirm candidate provenance and current policy/receipt/runtime differences using these read-only checks from the Hush root:

  ```sh
  git rev-parse HEAD
  git status --short --branch
  git -C ../arc rev-parse HEAD
  git -C ../arc status --short --branch
  git -C ../arc show 56f2c6b09cde0fef05e15cec1c0f08da33efe892:crates/pact-policy/src/evaluate.rs
  git -C ../arc merge-base --is-ancestor 56f2c6b09cde0fef05e15cec1c0f08da33efe892 HEAD
  rg -n 'HUSHSPEC_SUPPORTED_VERSIONS' ../arc/crates/guards/chio-policy/src/version.rs
  rg -n 'typescriptInvocationEngine|engineMaterialDigest' scripts/mcp-pilot
  ```

  Expected: inspected baselines match the design; the ancestor's header identifies a reference port; Chio supports only `0.1.0`; C is still bound to the TS engine. If revisions differ, refresh the source assessment instead of borrowing the old conclusions.
- [x] Record the candidate findings and distinguish source inspection from tests, qualification, approval, adoption and publication. Link this plan from the roadmap without closing D.
- [x] Run `git diff --check`, `python3 scripts/check_comment_hygiene.py --check` and `mdbook build docs`. Expected: exit 0. Manually verify the new relative Markdown links; plans outside the book are not covered by mdBook.
- [ ] Commit the plan-reviewed preparation using `docs: plan project D and assess Chio integration` for a bounded final review range.
- [ ] Request a fresh final review of the preparation diff against the roadmap and all five Review Focus items. This is a code/document review, not D's outside assessment. Address findings and commit the review disposition before push.
- [ ] Push/qualify under the existing wave-6 commit/push authority; retain exact-head run/attempt status separately from D completion.

## Task 2: Authorized Chio migration and provenance decision

**Files:** Arc changes are gated. Read current `../arc/AGENTS.md` and `../arc/CLAUDE.md`; prospective ownership is `crates/guards/chio-policy`, its control-plane policy consumers and their tests. Do not pre-create those changes in Hush.

**Interfaces:** Consumes Task 1's source assessment and the user's migration/checkout decision. Produces an approved migration design, exact candidate build, current-semantic test evidence and truthful provenance classification.

- [ ] Before freezing D-specific migration/adapter design as assessment scope, identify a prospective external adopter and outside practitioner, obtain contact/data-sharing authority, and solicit their workflow/objective/evidence critique. Record their constraints, objections, required changes and agreed scope. B/C already proceeded without this input; acknowledge that unmet early gate rather than claiming retrospective approval. This does not prevent separately authorized internal migration work, but such work cannot be called participant-approved assessment preparation until reconciled with their critique.
- [ ] Obtain the approved Chio checkout/branch and choice between native-engine migration and reference-SDK adoption. Do not edit `main` or switch its branch automatically.
- [ ] Reconcile the old policy-expansion draft with current Core 1.0. Keep old policy compatibility explicitly versioned; do not copy proposed vendor keys into the stable Hush schema.
- [ ] Write and review a concrete migration plan for the selected architecture before code. Include failing tests for 1.0 parsing, browser/code actions, deny aggregation, patch secret scanning, inline conditions, canonical default projection/hash, current receipts and legacy Chio-only policy preservation/refusal. Verify the actual compiled guard path separately wherever runtime-equivalence claims are intended.
- [ ] Execute that reviewed plan with red/green regressions and actual parser/evaluator/guard tests. No version-only acceptance change, field stripping or silent downgrade.
- [ ] Confirm a suitable static native build for B on a secret-free Linux host; capture build commands, compiler/dependency identities and executable digest. If the approved candidate cannot fit B's backend, stop for a reviewed backend change rather than bypassing its restrictions.
- [ ] Run the Arc-mandated checks from its approved checkout:

  ```sh
  cargo build --workspace
  cargo test --workspace
  cargo clippy --workspace -- -D warnings
  cargo fmt --all -- --check
  ```

  Expected: terminal success with no weakened assertions or new exemptions. Record failures and additional repository-required gates. Run `graphify update .` after authorized code changes as its instructions require.
- [ ] Preserve the classification `first-party, reference-derived` for Chio. Select an actual independently authored candidate with parser/evaluator dependency and source-provenance review for the independent track; Chio qualification cannot close that gate.

## Task 3: Qualify the chosen engines and run the same workflow

**Files:** Read `docs/src/reference/external-conformance.md`, `schemas/hushspec-engine-profile-experimental.v1.schema.json`, `packages/hushspec/src/invocation/policy.ts`, `scripts/mcp-pilot/{host,packet}.mjs`, `scripts/run_mcp_pilot.mjs`. Any new adapter files and tests must be named in the concrete adapter plan before implementation.

**Interfaces:** Consumes approved executable profiles and Task 2's build/provenance evidence. Produces L3 qualifying packets and same-engine workflow packets, separately labeled for each implementation.

- [ ] Complete a fresh whole-change review of B before relying on it for external qualification; its previous whole-branch reviewer was interrupted. Repair/reverify any findings without changing the corpus to fit the candidate.
- [ ] Prepare an engine profile per B's closed schema with actual executable/material digests and implementation identity. Set `D_ENGINE_PROFILE` to its absolute path and `D_PACKET` to a fresh absolute directory under an existing operator-owned parent outside the corpus. These are operator inputs, not example digests. Confirm `git status --porcelain=v1` is empty; `D_SOURCE_SHA` below identifies the clean Hush controller checkout, while the engine profile/materials retain the separate engine source identity.
- [ ] Run from the pinned clean Hush checkout, with that executable pre-approved:

  ```sh
  D_SOURCE_SHA=$(git rev-parse HEAD)
  cargo run --release -p hushspec-testkit --bin hushspec-testkit -- external \
    --engine "$D_ENGINE_PROFILE" --fixtures fixtures --out "$D_PACKET" \
    --level 3 --source-sha "$D_SOURCE_SHA"
  python3 scripts/run_external_conformance.py --verify "$D_PACKET"
  ```

  Expected: external execution exits 0 with L0-L3 qualified and packet verification exits 0. Verification alone is insufficient: a valid nonqualifying packet can verify. Hosted runs also pass `--ci-run "$GITHUB_RUN_ID" --ci-attempt "$GITHUB_RUN_ATTEMPT"` to the external command. The Python driver's `--out` path builds the first-party Go adapter; it is not the selected-engine launcher.
- [ ] Write/review the concrete C adapter plan. Preserve synchronous policy preparation or explicitly redesign that interface; use bounded asynchronous per-action evaluation. Define current receipts/traces and actual engine plus qualification-packet identity binding, not a metadata override.
- [ ] Add tests that first fail for changed binary/material bytes, a different qualification record, crash/timeout/malformed output, wrong policy/action binding and attempted reference fallback. Implement the adapter and packet changes; those tests and the existing full C suite must then pass.
- [ ] Execute C's unchanged real-edit/blocked-operation and containment/crash scenarios through the chosen engine. Instrument server/endpoint effects, inspect dispatch reconciliation and retain original failures. Add a real policy-reload scenario if included in the accepted assessment objectives.
- [ ] Repeat for the independently authored candidate, with no reference fallback. Record which host/dispatch path actually ran; an evaluator under C's host is not Chio kernel qualification.

## Task 4: Offline packet and outside assessment

**Files:** Existing packet formats and verifiers; participant-owned assessment materials outside source control until sharing is approved. No new OSCAL bridge or evidence schema is assumed.

**Interfaces:** Consumes qualifying engine/workflow packets and an actual consenting practitioner. Produces authenticated evidence handoff, objective-specific observations/objections and final dispositions.

- [ ] Reconfirm the practitioner, permissions, accepted objectives and audience from Task 2's early critique. Record affiliation and paid-review relationship if applicable. Reopen the design/scope review if these changed. Do not dispatch outreach merely because this item is unchecked.
- [ ] Agree the five design objectives and limitations before treating any run as assessment evidence. If OSCAL is requested, obtain the actual assessment-plan/system/catalog inputs and separately design any needed C evidence bridge; no synthesized satisfaction finding.
- [ ] Assemble the design's required materials without rewriting signed artifacts. Inspect for secrets and internal-only source/licenses before approved sharing. Keep separate, authenticated public-key and expected checkpoint/head handoff records.
- [ ] Have the practitioner perform offline verification without executing the packaged engine, inspect scope and independent observations, and record objections/missing evidence. Demonstrate refusal of altered artifacts, untrusted/substituted keys, truncated streams and missing terminals; missing outcomes remain unknown.
- [ ] Respond with evidence or explicit limitations; retain both objections and dispositions, including unresolved objections. An AI reviewer or author's self-review is not this assessment.

## Task 5: External adoption and final qualification

**Files:** Adopter-owned run/configuration/evidence; append approved references and bounded conclusions to the D readiness/closeout record. Never invent a testimonial or upload private evidence without permission.

**Interfaces:** Consumes a named external adopter and Tasks 3-4 evidence. Produces an actual adopter-operated integration, reviewed dispositions and exact-candidate qualification.

- [ ] Reconfirm the external adopter and permitted data/use from Task 2's early critique. They run their own integration, not just view our demo or receive our packet. A replacement adopter requires their own early workflow/scope review before this step proceeds.
- [ ] Retain their source/configuration identity, policy/engine/run evidence, independently observed effects, failures and limitations with permission to retain/share them. Keep Chio's internal run separately labeled.
- [ ] Review the complete evidence against every roadmap D requirement. An unresolved objective-blocking objection keeps the corresponding gate open.
- [ ] Run full relevant local verification and exact-head hosted CI for each changed repository. Compare local/remote/PR SHAs, run attempts and terminal statuses; report merge and publication separately. Do not reuse a previous head's green result.
- [ ] Mark D complete only when all three independent-engine, external-adopter and outside-practitioner gates have retained evidence and final review is complete. One adopter or paid review does not establish universal compliance or standards adoption.

## Current stop condition

Task 1 is executable within Hush. Tasks 2-5 are not currently complete or fully
authorized: Chio is a reference-derived internal candidate, its migration choice
and branch are unapproved, and no independent candidate, external adopter or
outside practitioner has been selected. Preserve the complete milestone and ask
for the next authority/participant decision rather than declaring a local rehearsal
to be D completion.
