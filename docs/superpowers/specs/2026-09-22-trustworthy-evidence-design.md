# Trustworthy evidence and claim repair

Date: 2026-09-22. Status: design approved by the user; implementation-plan review is the next gate.

Baseline: `wave-6` at `8c4bb871e6e8bd17076dace178779251b8ae4748`. Parent direction: [foundation-assurance roadmap](../../plans/2026-09-22-foundation-assurance-roadmap.md), project A. No product changes are implied by this document.

## Intent and scope

Make Hush's evidence claims match what its inputs and runtime hooks can establish. An operator must be able to authenticate a report's inputs, inspect continuity per declared stream and understand precisely what completeness has not been established. Rule execution must never automatically become regulatory objective satisfaction.

Included: strict report verification, an experimental verification sidecar/profile, observation-only contextual OSCAL, recoverable confirmation-callback error recording, reference conformance attribution repair and targeted documentation correction. This addresses F1/F3/F4/F5/F6/F7 and contains misleading F2 integration claims. F2's complete tool-plus-effect execution fix remains project C, not a promise made by A.

Excluded: a new invocation coordinator, external-engine harness, key-management service, hosted evidence service, independent assessment conclusions and changes to Core 1.0 evaluation semantics.

## Compatibility decision

Keep ordinary `h2h report` as an exploratory aggregation command. Preserve the existing log-only scope of `--require-signatures`, but make it explicit in help and examples. Introduce opt-in strict behavior rather than silently changing the meaning of old report v1 fields.

Proposed CLI contract:

```text
h2h report <declared-files...> --format json --out report.json \
  --evidence-profile profile.json --keyring trusted-keys.json \
  --verification-out verification.json
```

These new flags are design proposals, not currently usable commands. Strict mode requires the profile, an independently operator-supplied key/keyring and a verification output destination. Reject `--lenient` and `--unverified`, undeclared extra files, missing files and ambiguous output destinations. Existing clock/revocation verification options apply with their documented limits.

Do not add fields to the closed receipt, log, conformance-report or report v1 schemas. Introduce separately versioned experimental profile/result schemas with explicit unknown-version rejection. Their initial naming and JSON field definitions will be fixed in the implementation plan before code; the semantic requirements below are not optional.

Experimental OSCAL may change behavior: it must require validated assessment context and must stop emitting automatic findings. Reference-only testkit identity options may be rejected when they try to name an unexecuted engine. Both are intentional claim-correction changes with migration notes, not new policy semantics.

## Evidence model

The profile is an operator's assertion of scope and expectations, not proof of those assertions. It identifies the run/window, permitted resolved policy hashes, named streams and ordered input files, expected byte digests, input classes, allowed signer key IDs, and any trusted boundary/inventory references. Keys embedded in received evidence never authorize themselves. Stream-to-key authorization is explicit; a matching key anywhere in a broad keyring is insufficient.

Three properties are reported separately:

| Property | What successful verification establishes | What it does not establish |
|---|---|---|
| Authenticity | Accepted records are covered by valid signatures from keys authorized by the operator for that source | Truth of observations, safe key custody or reliable wall-clock time |
| Continuity | Supplied entries link in order within a named stream and its listed rotations | Missing prefix/tail, missing whole streams or intercepted actions never recorded |
| Completeness relative to declared scope | Supplied endpoints/inventory match independently obtained expectations for that scope | Global completeness or honest runtime instrumentation |

Each property has explicit `verified`, `not-established` or `not-applicable` status and scope. A failed required check produces failure diagnostics, not a success result with a reassuring overall Boolean. Profiles may require anchored completeness; absent required anchors fail. When not required, absent anchors leave completeness `not-established`.

The verification sidecar binds the exact native report byte digest, profile digest, verified source byte digests, verifier version, trust-key identifiers, per-stream endpoints/counts, policy intervals and limitations. It must name which input identities and signatures were checked. Ordinary `chain_verified` continues to mean only what its existing schema says; consumers seeking stronger assurance must verify the sidecar/report binding.

The sidecar is reproducible verifier output, not automatically a signed attestation. An offline recipient reruns verification with their own trusted profile/key inputs or trusts a separately authenticated packet producer. Signing a sidecar alone cannot turn self-declared inventory into independent completeness.

## Verification pipeline and failure behavior

1. Validate the operator profile and trust inputs. Reject unsupported profile versions, duplicate declarations, invalid digests and unauthorized signer mappings. The first implementation is offline: no implicit URL fetching from profile values.
2. Snapshot input bytes into bounded local staging or hold a stable verified snapshot. Hash, parse and aggregate the same bytes. A pathname that changes between verification and aggregation must not substitute unverified data. Bound line size, total input and parser resource use with explicit configurable limits; report limit failures rather than dropping records.
3. Parse and schema-validate every nonblank line before filtering the report window. A file contains one declared record class. Reject mixed classes, malformed lines, repeated receipt IDs and repeated source entries; do not silently double-count or deduplicate conflicting records.
4. Verify standalone `SignedReceipt` envelopes with the existing receipt verifier. For signed log entries, the authenticated entry hash covers the embedded receipt; a second standalone receipt signature is not mandatory. Unsigned links alone do not establish authenticity. Reject unknown, unauthorized, revoked or otherwise invalid keys using the shared signing rules.
5. Group logs by declared stream and reuse ordered rotation verification. Two independent streams get separate heads. Reject unrelated files presented as one continuation and missing/reordered rotations. A first supplied rotated file may be structurally valid without proving the original stream start; preserve that limitation.
6. Check exact policy identity and policy-event ordering. For a single-policy assertion, reject unexpected receipt hashes instead of filtering them out. For approved transitions, verify the previous/new hash relation and the signed policy event preceding use of the new hash. Keep each policy interval and control mapping separate. A mid-stream start needs an authenticated boundary state to claim the policy already in force. Standalone receipts can bind policy identity but do not independently prove transition history.
7. Compare boundaries/inventory with trusted expectations if supplied. A start anchor binds stream identity and the starting predecessor or genesis; an end anchor binds the expected terminal entry hash and position. Inventory identifies expected streams/files, not just the subset handed to the verifier. Anchors need an explicitly trusted acquisition source distinct from merely accepting the evidence producer's current assertion. Timestamp range alone is not window completeness.
8. Aggregate verified records and produce native report plus verification sidecar. Validate both outputs. Publish success artifacts only after all required input checks pass; stage writes and ensure failures cannot leave a new assurance-qualified success file. Bind output digests so an old/new report-sidecar pair cannot be mistaken for one run. Existing outputs must not be silently overwritten.

Policy signature status inside a receipt records what the runtime said; it is not independent policy-origin verification. If that assurance is required, the profile must include the policy artifact and its separately verified trust binding. Likewise, action-attempt completeness needs a trusted upstream attempt record or independent instrumentation. A valid hash chain cannot establish an attempt it never contained. A supports bounded file/stream completeness; C adds the invocation reconciliation contract.

## Recoverable callback failures

On a confirmation callback failure, dispatch remains forbidden. Preserve the original evaluation decision/trace, usually `warn`; record the enforcement disposition as `blocked` using the existing receipt enum before propagating the failure. Do not rewrite a policy-decision reason to mean a callback exception. Diagnostic details use an out-of-band error channel without raw argument/secret leakage.

Cover TypeScript throws, Python ordinary exceptions, Go recoverable callback panics and Rust unwinding callback panics. In Go/Rust, record and re-propagate the original panic; do not turn it into a successful decision or suppress it. Avoid a second sink failure masking the original callback failure. Rust abort-mode panic, process termination, fatal runtime failures and unavailable storage cannot promise a receipt; document them and test the recoverable boundary explicitly. No catch-all claim of crash completeness is permitted.

This repair does not convert the existing best-effort observer/sink APIs into authoritative durable execution gates. If recording fails, no receipt can be promised. C must add the opt-in no-durable-permit/no-dispatch contract. Normal allow/deny/warn decisions, confirmation results and existing receipt hashes remain unchanged outside the corrected failure path.

## OSCAL export boundary

Continue targeting the exporter's pinned OSCAL 1.1.2 format; upgrading OSCAL itself is outside this repair. Export receipt-derived observations, not findings. State actual policy decisions and enforcement outcomes, including monitor `would_block`, plus policy identity, window, source digests and verification qualifications. Inspecting recorded receipts is an `EXAMINE` method; do not claim an active test was performed merely because receipts exist.

OSCAL output requires a real assessment-plan reference and declared reviewed controls/subjects. Proposed input is a local assessment-context package supplied by the assessor/integration: AP, referenced SSP and resolved control catalog/profile material necessary to resolve the selected scope. Verify local references and digests without automatic remote fetching. Restrict the initial exporter to this supported, locally resolvable context; reject unsupported/incomplete packages instead of synthesizing an AP or system inventory.

Omit `findings`, objective satisfaction statuses and inferred risks. A mapped framework control ID is not automatically an assessment objective ID. Empty evidence does not imply satisfied or not satisfied. Without assessment context, produce only the native report and verification result; requesting OSCAL exits nonzero with a clear missing-context diagnostic. `href: "#"` is not an acceptable placeholder AP.

OSCAL requires strict verified input, but unknown completeness may remain an explicit limitation unless the supplied profile requires it. Reference the native report and verification sidecar by digest from the assessment evidence. Do not create a circular digest dependency: the verification sidecar binds the native report, while OSCAL references both. Validate against the pinned OSCAL schema and check scope/reference semantics separately. A schema-valid document is not an assessor's endorsement.

These constraints follow the separation of observations and assessment conclusions in [NIST's assessment-results model](https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/) and the [1.1.2 field cardinalities](https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/json-outline/). No legal compliance conclusion is part of this exporter.

## Conformance attribution and documentation

Reference-runner reports must identify the reference implementation actually invoked. Reject arbitrary identity overrides; reserve third-party instructions for B's real executable adapter path. Preserve the existing report schema and distinguish testkit version, corpus version and implementation identity in documentation.

Withdraw the unqualified Clawdstrike L3 claim until a pinned implementation-bound report exists. Correct the guide's core-rule count and portable-signing description. Correct governance documentation to reflect current audit exit/strict behavior while retaining the distinction between policy metadata checks and repository identity/approval enforcement.

Explain that automatic tool mapping supplies an effect evaluation, not complete tool authorization. A controlled regression must retain the allow-egress/deny-tool counterexample so that future invocation work cannot declare it solved with effect checks alone. No current helper should be documented as proving interception or containment.

## Acceptance matrix

| Test | Required result |
|---|---|
| Valid signed receipt, authorized key, expected policy | Authenticated report; continuity/completeness not established where unsupported |
| Tampered receipt, unsigned source, wrong/unknown/revoked key, absent trust input | Strict failure; no success report/sidecar |
| Bad record outside selected time window | Strict failure before filtering |
| Mixed input classes, duplicate IDs, substituted bytes, resource limit exceeded | Strict failure, no silent skipping or double count |
| Valid ordered rotations within one named stream | Verified bounded continuity and exact endpoints |
| Unrelated or reordered files presented as one stream | Failure, not merged `chain_verified` assurance |
| Two explicitly independent streams | Separate verified heads and limitations |
| Missing tail without external expected head | Completeness not established |
| Missing prefix/tail/file/stream against trusted anchors/inventory | Completeness requirement fails |
| Wrong policy hash or new policy used before approved transition event | Strict failure for claimed policy interval |
| Recoverable confirmation callback failure, working sink, each SDK | Original failure propagates; blocked receipt recorded; no authorization |
| Callback failure plus sink failure; abort/crash boundary | No dispatch authorization; no fabricated recording/completeness claim |
| Monitor-only evidence or no evaluated controls | Observations only, no satisfaction finding |
| OSCAL without resolvable AP/scope or with invalid semantic references | Export fails even if a skeleton could satisfy JSON shape |
| Valid local assessment context and verified evidence | Schema-valid, reference-checked observation-only OSCAL |
| Reference testkit requested under nonexistent engine identity | Reject override; cannot produce attributed external pass |
| Mapped fetch allowed by egress but denied by tool-access policy | Regression demonstrates why the helper is not a complete gate; C remains open |
| Existing policy/hash/receipt/log conformance corpus | No changed stable semantics or wire compatibility |

Tests must include independently written negative cases, not only snapshots regenerated from the repaired implementation. Preserve the original failing reproduction, the regression and exact-candidate results. Cross-SDK exception behavior needs runtime tests, not just static similarity.

## Implementation boundaries and handoff

Likely files: `crates/hushspec-cli/src/cmd_report.rs` plus a focused evidence-verification module; existing `crates/hushspec/src/{log,signing,report}.rs` primitives; `crates/hushspec-cli/tests/report_tests.rs`; new experimental schemas and fixtures. Keep verification separate from aggregation/rendering instead of expanding the already large report command into a second security engine.

Callback repairs belong in the four existing guards/middleware and their tests. Attribution repair belongs in `crates/hushspec-testkit/src/main.rs` and its CLI tests. Documentation touches the CLI/conformance reference, runtime/integration guides and `GOVERNANCE.md`. No unrelated refactoring is required.

Before implementation, the written task plan must pin profile/sidecar JSON contracts, CLI conflicts/output behavior, resource-limit defaults, per-SDK failure mechanics, OSCAL context validation subset and regression commands. Those are implementation-plan deliverables, not permission to leave permissive fallbacks in code. Split A into reviewable repair, strict-verifier and contextual-export commits; qualify the final combined candidate.

Completion requires all applicable acceptance rows, existing cross-SDK/schema/documentation gates, a fresh adversarial review and terminal exact-head CI. Record local results separately from hosted results and retain any original failures/retries. Merging the stack, tagging and publishing remain distinct authorized actions. A's completion does not close projects B, C or D or establish foundational-standard adoption.
