# Project D: validation with Chio and outside participants

Status: design and readiness assessment, not completed external validation.
Hush baseline: `385ca54961c673f03db81e7fe7c45ee48756bd82` (`wave-6`).
Chio inspection baseline: `f5566d9a765c21cb36652a99c79de64968a656bf`
(`../arc`, clean `main`).
Authority: the [foundation roadmap](2026-09-22-foundation-assurance-roadmap.md),
especially Project D. The user selected Chio as the integration candidate on
2026-09-23 and identified it as internal development.

## Intended outcome

Demonstrate the coding-agent/MCP workflow with pinned portable semantics,
retained execution evidence and a critique by a real outside practitioner.
Keep three distinct gates: independently authored engine, external adopter's
own integration, and outside security/assurance assessment. An internal Chio
run is useful, but does not substitute for any of those gates by itself.

The user's one-pass request covers planning, plan review, available execution
and final review. It does not authorize third-party outreach, sharing private
material, changes on Chio's `main`, merging, tagging or publication. Continue
Hush work in the existing `wave-6` checkout. Obtain the Chio migration scope and
branch choice before modifying that separate repository.

The roadmap required prospective adopter/practitioner critique before B/C design
freeze. B/C's first-party implementation proceeded without that external input;
this requirement remains unmet, not retroactively satisfied by internal reviews.
Obtain authorized participant input on workflow, objectives, evidence and practical
integration constraints before freezing the D-specific migration/adapter design
as assessment scope. Record disagreements and any changes needed to B/C. Internal
readiness research may proceed while this gate is open, but it is not an agreed
external assessment design.

## Candidate findings

Chio owns a parser, evaluator and compiler in `crates/guards/chio-policy`.
Its Cargo manifest has no `hushspec` reference-crate dependency. That is not
independent authorship: ancestor `56f2c6b09cde0fef05e15cec1c0f08da33efe892`,
`crates/pact-policy/src/evaluate.rs:3`, explicitly describes a port from the
HushSpec reference implementation. Comparing that file with Hush's historical
evaluator confirms substantial shared structure. Local maintenance and a
different crate name do not erase that provenance.

At the inspected Chio HEAD, these are concrete migration boundaries:

| Boundary | Current Chio source | Consequence for this milestone |
| --- | --- | --- |
| Document versions | `src/version.rs` supports only `0.1.0` | Current `1.0.0` pilot documents are rejected by validation. |
| Action coverage | `src/evaluate/engine.rs` has eight named dispatch arms, not `browser_action` or `code_exec` | Parsing a rule is not evidence that the evaluator implements its action. |
| Composition | `src/evaluate/matchers.rs` returns path results before later checks; patch evaluation does not scan secret patterns | Current Core aggregation and applicable-rule semantics require actual migration tests. |
| Conditions and context | `src/evaluate/context.rs` lacks current action `context`, `url`, `network`, `timeout_ms`; conditions are a separate map | Relabeling the version cannot provide the current action contract. |
| Policy identity | `src/receipt.rs::compute_policy_hash` hashes struct serialization with plain `serde_json::to_string` | This is not the specified default projection and RFC 8785 canonical hash. |
| Receipts | `src/receipt.rs` is a legacy receipt without the current enforcement/trace contract | Do not cast it into a current C component receipt or invent an engine trace. |
| Local dialect | `src/models/rules.rs` adds `velocity`/`human_in_loop`; `src/models/extensions.rs` adds `reputation`/`runtime_assurance`/`chio` | Preserve legacy behavior separately; do not relax Hush's closed Core schema to accept it. |
| Runtime path | `crates/platform/chio-control-plane/src/policy/loader.rs` resolves, validates and compiles into guards | Evaluator conformance alone does not qualify compiled guards or actual MCP dispatch. |

Paths in the first seven rows are relative to `crates/guards/chio-policy`.
These are source-backed observations, not a new build, runtime exploit test,
full Chio audit or conformance result.

An existing draft at Chio commit `15188f67be667aedf15b6bc3212b1a11b57052d2`,
`docs/superpowers/specs/2026-07-15-policy-expansion-design.md`, recognizes the
format split. It is on the locally known `origin/docs/policy-expansion-design`
branch, not in the inspected `main` tree. Its proposed 0.2 additions and vendor
namespace are not current Hush Core 1.0 contracts. Do not revive that broad
expansion program as an implicit part of D or describe its proposal as shipped.

## Approach and trade-offs

1. **Recommended: Chio as the first-party migration/integration track, with
   separate external validation tracks.** It exercises an actual downstream
   consumer and exposes interoperability gaps. Its reference-derived evaluator
   remains labeled as such, even after conformance succeeds.
2. **Reference-SDK adoption inside Chio.** This may reduce duplicated semantics,
   but changes Chio's architecture and still does not establish independent
   authorship. Decide that trade-off in the authorized Chio migration design,
   not as a hidden dependency swap in Hush.
3. **Call the old port an independent engine or rewrite it just for the label.**
   Reject. A label is not provenance; an extra first-party implementation is not
   an external adopter or assessor and is outside this validation project's scope.

Do not build a generic gateway, a fifth SDK, a new review platform or another
evidence format merely to make local activity stand in for missing participants.

## Integration and qualification contract

The [Chio migration research](2026-09-23-chio-hushspec-migration-research.md)
expands the loader, native-guard, approval, identity and SDK-consumer change map.
Its proposed architecture is not yet an approved migration implementation plan.

The Chio migration needs an explicit choice between maintaining its native
semantics and consuming the reference SDK, plus an approved non-main checkout.
The migration must preserve or explicitly reject existing deployment policies;
silently dropping Chio-only rules is unacceptable. Keep the current Hush Core,
canonical, receipt/log schemas and existing callers stable.

B's external protocol `0.1.0` grades the chosen executable, not its name.
Qualify a digest-pinned Linux static native ELF through the raw-input corpus at
L0-L3, with supplied-document-only resolution, no expected-answer access through
the protocol, and no reference fallback. Retain failed attempts and unsupported
operations. A valid packet is not necessarily a qualifying packet; verify both
packet integrity and `highest_level >= 3` with successful required slots.
Static linking/build feasibility for Chio has not been tested. Do not weaken B's
capture restrictions or execution deadlines to accommodate an unreviewed build.
Executables are trusted code; B is not a sandbox. Use a secret-free execution host.

C's public `InvocationEngine.prepare(resolution)` seam is replaceable, but the
current runnable host uses `typescriptInvocationEngine` and its packet verifier
hashes the compiled TypeScript SDK/YAML inventory. A Chio runtime adapter and
engine-material binding are therefore real implementation work, not an existing
CLI option. Do not change the metadata while retaining the reference evaluator.

A reviewed adapter must bind actual engine bytes and the exact qualification
record to the policy event and packet; bound subprocess input/output/time; reject
bad/missing receipts and artifact substitutions; and block dispatch on engine
failure. It must not manufacture evaluated-rule traces from a final allow/deny
alone. Sharing the current host's policy authentication or evidence serialization
is allowed if disclosed; semantic decisions must come from the selected engine.
Separate raw-parser conformance from host-normalized runtime input. L3 does not
confer L4 receipts, L5 signing, or compiled-guard equivalence.

Run the same controlled real-edit and blocked-operation scenarios for the chosen
engine. A Chio evaluator under C's host is not a demonstration of Chio's full
kernel/control-plane guard path; any claim about that path needs separate dispatch
tests. Repeat with an independently authored, qualified implementation before
closing the independent-engine/workflow gate.

## Assessment scope and packet

Proposed narrow objectives for an actual practitioner to amend and accept:

- A blocked tool/effect cannot reach the owned dispatch handle in the tested profile.
- Each admitted call is bound to authenticated policy, one generation, immutable
  arguments, qualified tool identity and recorded component decisions.
- Warnings require one confirmation and any deny requires zero prompts.
- Evidence distinguishes completed, observed error, aborted and unknown outcomes.
- Missing, truncated, substituted or altered evidence cannot pass complete-run
  verification under separately retained trust anchors and stream boundaries.

If the agreed objective includes policy changes, add a real reload scenario with
two authenticated generations and an invalidated pending confirmation. C's current
acceptance run installs one initial policy; unit tests are not an observed reload.

The offline packet must retain policy bytes/envelopes, exact engine/controller/
corpus identities, dependency/build/configuration material, B execution packet,
C signed journal, checkpoints, server and endpoint observations, actor transcript,
file before/after hashes, negative/fault evidence and scope limitations. Retain
failed/crashed attempts separately from retries. Deliver verification instructions
and trusted public keys plus expected stream/checkpoint identity through a
separate authenticated handoff. Private signing keys are never packet material.
Synthetic data is preferred; sharing even synthetic internal artifacts needs the
owner's approval. Redacted views must remain separate from signed originals.

Use existing offline verifiers without executing packaged engines. B verification
checks consistency, not independent re-grading or producer honesty. C verification
checks the declared controlled profile, not that the host exposed no other channel.
Host, extractor, signer, clock, Docker and exclusive-writer assumptions remain
explicit. No arbitrary shell/provider/third-party-server containment claim.

OSCAL is optional. If requested, use actual agreed assessment context and pinned
AP/SSP/catalog material, not a rule-count-to-compliance mapping. C journals are not
A's strict receipt-log input; do not feed them to that exporter or repackage
unsigned components as standalone signed receipts. Any bridge requires its own
reviewed design. Observations are not objective-satisfaction findings.
See [NIST Assessment Results concepts](https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/)
and the [pinned 1.1.2 model](https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-outline/).

## External gates and completion

An adopter outside the implementation organization must run their own integration
and retain their configuration, run evidence and limitations. A practitioner
outside the implementation team must inspect the agreed objectives and record
objections, missing evidence, responses and final dispositions. Record identities,
roles/affiliations, dates, permission to retain/share material, and any paid-review
relationship. A code-review subagent is not this practitioner.

Do not mark D complete until the independently authored engine ran the same
workflow, the actual external adoption and assessment evidence exist, and the
review dispositions and exact-head qualification are retained. No participants
have yet been selected for those external roles. Chio migration authority and
architecture are also unresolved. These are explicit next decisions, not tasks
the implementation agent can complete by inventing records or contacting people.
