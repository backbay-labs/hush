# Foundation assurance: proposed next milestone

Date: 2026-09-22. Status: research and proposed direction, not an execution or release record.

Research baseline: `wave-6`, `8c4bb871e6e8bd17076dace178779251b8ae4748`. The source had successful exact-head CI, but the findings below remain open. This proposal supplements [RFC 09](09-compliance-as-code-plan.md); it does not mark its checklist complete or supersede the [delivery ledger](STATUS.md).

## Judgment and intended outcome

Hush has a credible policy language and evidence substrate. The next investment should establish that its components compose into a trustworthy boundary, not add another SDK or a larger compliance catalog.

The milestone is one independently implemented engine and one real guarded agent workflow using pinned policy semantics, producing evidence that an outside security/assurance practitioner can inspect against explicitly scoped objectives. Implementation independence, an external adopter, and an external assessor are different gates. A second adapter around the reference evaluator satisfies none of them by itself.

Selected pilot (confirmed by the user on 2026-09-22): a coding agent using host-controlled MCP tools on synthetic, non-regulated repository data. The specific host and external adopter remain unselected. Keep those choices replaceable; do not make Chio integration or an external organization's cooperation an implicit dependency of local repair work. This workflow selection does not approve the separate first-project design or authorize implementation.

## Approaches considered

| Approach | Benefit | Limitation | Decision |
|---|---|---|---|
| Repair the known findings only | Fast, necessary cleanup | Does not demonstrate an independent implementation or an actual dispatch boundary | First project, not the whole milestone |
| Add opt-in assurance contracts around existing formats | Preserves existing policy semantics; independently testable integration boundaries | Requires explicit trust inputs and a small experimental evidence surface | Recommended |
| Build a general gateway/compliance platform | Could eventually centralize operations | Adds authentication, transport, tenancy, storage, bypass and service-operations scope before the core claim is demonstrated | Defer |

Keep Core 1.0 decisions, canonical hashes, receipt/log wire formats, and existing report consumers stable. New strict verification and runtime correlation belong in explicitly versioned experimental companion artifacts. Do not smuggle new fields into closed v1 schemas. Follow the existing [versioning policy](../../spec/versioning.md).

## Research findings that change the plan

1. **Tool names are not effect declarations.** MCP names are unique within a server, not globally; `serverInfo.name` is not a unique identity, and annotations are not inherently trustworthy. A host must bind a qualified tool identity to the actual connection and dispatch implementation. Automatic mapping of `fetch` to an egress check cannot replace a tool-access check. [MCP tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools).
2. **Assessment context cannot be synthesized from rule counts.** OSCAL separates observations from findings. For the exporter's existing 1.1.2 target, Assessment Results requires an assessment-plan reference and reviewed controls. A placeholder AP and a `satisfied` objective inferred from a receipt are not a defensible export. [NIST assessment-results concepts](https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/), [1.1.2 model outline](https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-outline/).
3. **The current testkit cannot attribute external implementation conformance.** `--implementation` changes report metadata; the runner still calls the reference evaluator. The differential harness has a useful subprocess seam, but its normalized input does not substitute for raw-parser conformance.
4. **A nearby integration needs migration.** At Chio checkout HEAD `f5566d9a765c21cb36652a99c79de64968a656bf`, `crates/guards/chio-policy/src/version.rs` advertises only HushSpec `0.1.0`; that path was clean during inspection. This is a candidate to investigate, not current 1.0 qualification. No Chio source was changed or built for this research.
5. **Existing standards are complementary.** AuthZEN addresses decision/enforcement-point interoperability without prescribing a policy language. OPA already has decision logs and signed bundles; Cedar provides application authorization. Hush's proposed contribution is an agent-action/control/evidence profile with portable, independently tested semantics, not exclusivity over YAML, signatures, or policy decisions. [AuthZEN 1.0](https://openid.net/specs/authorization-api-1_0.html), [OPA decision logs](https://www.openpolicyagent.org/docs/management-decision-logs), [OPA bundles](https://www.openpolicyagent.org/docs/management-bundles), [Cedar](https://docs.cedarpolicy.com/).

## Three projects, followed by an external validation gate

### A. Truthful evidence and claim repair

Build a strict authenticated-report path, distinguish stream continuity from completeness, remove automatic OSCAL satisfaction findings, retain attempted-action evidence on recoverable callback failure, and correct conformance attribution/documentation. The [first-project design](../superpowers/specs/2026-09-22-trustworthy-evidence-design.md) defines this bounded scope and its acceptance matrix.

This project does not claim to fix the complete tool-invocation boundary. Until C qualifies it, adapters remain evaluation helpers, not a demonstrated enforcement point. Ship prominent integration guidance and a regression demonstrating the missing tool-plus-effect composition as part of A's claim repair.

Exit: negative cases cannot produce an assurance-qualified success artifact; callback failure remains blocked and recorded when recording succeeds; reference-only results cannot masquerade as external-engine results. Exact-candidate tests and CI are required after implementation, separately from merge/publication.

### B. Implementation-bound conformance

Create an external-process protocol and controller that invokes the named implementation. The controller owns expected answers and grades observations; an engine must not simply return its own pass/fail verdict. Preserve raw YAML/JSON bytes for parse/validation tests. Supply operation-specific inputs for merge, evaluation, resolution and canonicalization without passing the reference answer to the engine.

Contract requirements:

- Every response binds a case ID, operation and input digest. Missing, duplicate, foreign, stale or malformed responses fail qualification. Unsupported cases remain unattempted, never reference-filled or silently passed.
- Run with bounded time, output and process lifetime. A timeout, crash, nonzero exit or output limit failure is visible. Adapter commands are operator-approved executable code, not a security sandbox; CI runs them isolated from host secrets.
- Keep the report v1 shape. A separate experimental execution record binds its digest to corpus/manifest, scorer, adapter and actual engine artifact digests, invocation, environment/dependency identity, and retained outputs. Record the exact CI source SHA, run and attempt. A signed record attributes a run to its producer; it does not prove the producer honest.
- Start with the operations needed to qualify L0-L3. Add L4/L5 only when that same implementation executes their operations. Report each attempted level honestly and keep lower-level dependency rules. Do not promise an L5 engine as an automatic byproduct of building the harness.
- Add handwritten semantic counterexamples and controlled faulty-engine tests alongside existing generated/shared fixtures. Flipping a result, skipping a case or substituting a different engine must fail the qualification check.

Existing seams: `crates/hushspec-testkit/src/{main,runner,report,diff}.rs`, raw-parser scripts and `schemas/hushspec-conformance-report.v1.schema.json`. Reuse useful serialization/scoring pieces, not the current reference-only attribution path. Execution provenance may borrow digest/producer concepts from [SLSA provenance](https://slsa.dev/spec/v1.1/provenance); it is not itself a SLSA build-level claim.

Select an engine only after checking its parser/evaluator dependencies and implementation provenance. Chio is a plausible first migration target but shares the organization; wrapping Hush's reference crate does not establish an independent implementation. An OPA/Cedar translation is also not conformant merely because its backend is independent: it must preserve every claimed Hush semantic and pass the same corpus. If no suitable engine is available, report B's runner delivered and the independent-engine gate open.

### C. One trusted invocation boundary

Proposed smallest implementation: an opt-in TypeScript invocation coordinator in the existing SDK, plus one swappable host-owned MCP coding pilot. Keep a narrow evaluator boundary so the reference engine can bring up the pilot and B's independently qualified engine can run the same scenario. The milestone does not close with an independent engine tested only in isolation from the demonstrated workflow. Do not implement a fifth SDK or a generic MCP gateway. Port the runtime contract further only after the pilot establishes what must be portable.

The host registry binds a stable, host-assigned connection identity to the actual dispatch handle and a trusted effect extractor. Use an unambiguous qualified tool target, such as `mcp:<host-id>/<encoded-tool-name>`, with explicitly defined escaping. Existing exact-match `tool_access` semantics apply; an old unqualified allow entry must not authorize a different server by coincidence.

Invocation sequence:

1. Admit a call with a unique ID. Freeze a JSON-only canonical argument snapshot and capture one resolved policy generation, its engine-bound compiled snapshot, authenticated policy identity and runtime context.
2. Derive the original qualified `tool_call` and every trusted, supported effect action from that snapshot. Missing required fields, unknown mappings or opaque effects fail closed in the pilot profile. Hash the arguments and effect plan; dispatch receives the same immutable values.
3. Evaluate all components against that same policy. Aggregate `deny > warn > allow`. Any deny means zero confirmation prompts. If warnings remain, ask once, binding confirmation to this identity, arguments, effect plan and policy generation. Strict mode refuses monitor-only enforcement and unverified/refused policy state.
4. Record component decision receipts and a durable correlated pre-dispatch journal record. On confirmation refusal/error, record blocked and do not dispatch. Any authoritative sink failure prevents dispatch. If the policy generation or panic state changes before dispatch, abort the stale invocation; do not reuse its approval for a new attempt.
5. Serialize the final policy/panic check with dispatch admission. Do not hold a global lock while awaiting a human. Policy changes after dispatch admission cannot retract an already started side effect; record the admitted generation.
6. Execute through the bound handle, then record observed completion/error. A missing terminal record means unknown execution outcome, not proven prevention. A terminal-write failure stops further dispatch and surfaces an incomplete run. No exactly-once or automatic safe-retry claim follows.

The runtime journal is a separate experimental format, not a new enum or action stuffed into a 0.2 receipt. It binds call ID, qualified identity, argument/effect hashes, policy generation/hash, component receipt IDs and hashes, aggregate disposition, and pre/post stage. Component receipts keep their action-local meaning; an `allowed` component is not an aggregate invocation permit or a claim that its effect executed. Partial receipt writes before a missing permit are incomplete evidence, never authorization. Its own signing, sequence and checkpoint contract needs a dedicated design before implementation, reusing existing cryptographic primitives.

The existing `createMCPGuard` evaluates only. Composing two current `HushGuard.gate()` calls is insufficient: they can read different policy generations, and sink errors are swallowed by the current best-effort delivery path. C needs explicit snapshot and authoritative durability semantics, not another wrapper claiming stronger guarantees.

Pilot operations: read and patch files through a controlled server and make a bounded request to a controlled local endpoint. Server-side path containment and network destination restrictions remain necessary, including symlink/redirect checks. The agent must have no alternative file, shell or network route within the claimed boundary. Unrestricted shell, child-process effects, arbitrary third-party MCP servers and provider-executed tools are excluded unless their actual dispatch is owned and constrained. An exclusion is not a control success.

Acceptance includes same-name tools on different servers, spoofed server metadata, mutated arguments, oversized arguments, allow-effect/deny-tool combinations, one prompt for multiple warnings, zero prompts when any component denies, policy reload during confirmation, callback and sink failures, malformed effect plans, direct-bypass attempts, and crashes before/after dispatch. Instrument the controlled server independently of the guard and reconcile attempts, admissions, dispatches and terminal records.

### D. External evidence review and adoption

Identify a prospective adopter and outside practitioner early, before B/C design freeze, and ask them to critique the proposed workflow and evidence objectives. This is a coordination dependency requiring authorized outreach, not permission for the implementation agent to contact third parties. Their actual assessment/adoption remains a later gate.

Run the controlled workflow to completion, including a real edit and a deliberately blocked operation, not just direct evaluator calls. Repeat the scenario with B's independently qualified engine and no reference fallback. Export a replayable offline packet: pinned policies, engine qualification, runtime build/configuration, signed evidence, trusted stream boundaries, negative-test results and explicit limitations. Redact secrets without rewriting signed source artifacts; use synthetic data for a public packet.

A practitioner outside the implementation team reviews whether the packet supports narrow objectives such as named-tool restriction, scoped file access and recorded policy changes. Record objections, required evidence and disposition. If OSCAL is used, the assessment plan and reviewed scope come from that assessment context, not guessed framework labels.

An external adopter must run their own integration to establish adoption; our own Chio integration is first-party evidence. Neither a hired review nor one adopter proves universal compliance or standards adoption. Do not mark D complete without an actual reviewer/adopter and retained evidence. Scheduling and permission to share data are external dependencies, not coding tasks.

## Finding-to-deliverable reconciliation

| Review finding at baseline | Required disposition |
|---|---|
| F1: OSCAL rule execution becomes objective satisfaction | A: observation-only export with real context; no automatic findings |
| F2: mapped effect drops tool-level controls | A: correct helper claims and preserve a failing composition case; C: qualified identity-plus-effects dispatch contract |
| F3: arbitrary implementation label on reference results | A: fix attribution/instructions; B: real engine execution and provenance |
| F4: reporting discards standalone receipt signatures | A: retain envelopes and verify every strict-profile source |
| F5: callback failure loses attempted-action receipt | A: recoverable error-path recording across SDKs; C: strict durability and attempt reconciliation |
| F6: per-file chain checks look like complete continuity | A: per-stream verification and bounded completeness; C/D: independent runtime/inventory evidence |
| F7: conformance/integration/governance documentation drift | A: withdraw unsupported claims and align command behavior; B/D: reintroduce only evidenced claims |

## Order, gates and intentional deferrals

A is the first implementation project. B and C get their own focused designs/plans; their research can proceed independently, but C's evidence export depends on A. D depends on A, the qualified engine from B and the workflow from C. Use reviewable commits and exact-head CI; never collapse source presence, local tests, hosted qualification, merge and publication into one state.

Do not add dashboards, tenancy, enterprise identity, cloud policy backends, broad control catalogs, a new detector family, a general policy-service transport or a new signature primitive during this milestone. AuthZEN interoperability can follow after the invocation contract is demonstrated. Those are retained future possibilities, not silently completed original requirements.

Success supports: “Hush has independently tested portable policy semantics and a demonstrated, scoped agent enforcement/evidence profile.” It does not support “Hush certifies compliance” or “Hush is already the foundational standard.” Adoption and assurance evidence must earn the stronger position.
