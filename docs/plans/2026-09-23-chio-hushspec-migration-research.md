# Chio migration to current HushSpec: research and proposed design

Status: proposed architecture and staged change map, not an approved implementation
plan or completed migration. Updated 2026-09-23. Arc was inspected read-only.
This expands the [Project D candidate assessment](2026-09-23-project-d-design.md)
without changing its external-validation gates.

## Recommendation and scope

Embed the upstream Rust Hush SDK for portable policy parsing, resolution,
validation, canonical identity and evaluation. Keep Chio's capability system,
runtime admission, stateful controls and additional defenses in an explicit Chio
runtime profile. Do not maintain a second interpretation of portable rules by
translating them into native guards.

The intended result is a current-Hush coding-agent/MCP integration that preserves
Chio's security controls and makes portable semantics testable independently from
runtime enforcement. Start with a small host-owned MCP tool registry and real
kernel dispatch. Arbitrary shell containment, every existing SDK host, public
release and independent-engine validation are separate outcomes.

This research does not select an Arc branch, modify Arc, install dependencies,
run its build, contact participants, merge or publish. Architecture approval must
precede a code-ready implementation plan. Existing Project D remains open.

## Exact targets and what "latest" means

| Item | Inspected state | Planning consequence |
| --- | --- | --- |
| Hush source | `wave-6`, `5a35dca012dc215a35b5c23c42ae1085018a8f30`; workspace version `1.0.0` | Pin this source revision for initial integration experiments; refresh before execution. |
| Arc source | clean `main`, `f5566d9a765c21cb36652a99c79de64968a656bf` | Findings below refer to this tree, not all branches or deployed Chio. |
| Public Rust, npm and Python packages | Latest observed version `0.1.1` | A registry dependency on `1.0.0` cannot currently be assumed available. |
| GitHub release | `v0.1.1-alpha`, prerelease, published 2026-03-16 | Source qualification and publication are separate gates. |
| Document versions | Current Hush accepts the `0.1`, `0.2` and `1.0` minor families; Chio accepts only exact `0.1.0` | Many old portable documents need no version rewrite. Chio dialect migration is a different problem. |

Live package checks used the [Rust sparse index](https://index.crates.io/hu/sh/hushspec),
[npm registry](https://registry.npmjs.org/@hushspec%2fcore),
[PyPI](https://pypi.org/project/hushspec/) and
[Hush releases](https://github.com/backbay-labs/hush/releases).
The crates.io metadata API returned HTTP 403; the authoritative sparse index
succeeded and listed only `0.1.0` and `0.1.1`, neither yanked.

Arc's Rust floor is 1.94; Hush's is 1.88. That is not an obvious MSRV blocker,
but dependency unification, targets, feature combinations and supply-chain audits
are untested. Hush's default features are empty. Propose explicit `signing`, no
`http` or `otlp` initially. Arc's `serde_yml` dependency name aliases
`serde_yaml_ng` 0.10.0; do not mistake the alias for a different package.

## Compatibility evidence

### Document probe, not runtime conformance

The current Hush Python source parsed and validated all seven Arc example files
matching `examples/policies/*hushspec*.yaml` and all seven bundled Chio rulesets:

- 13 documents were accepted, all declaring `0.1.0`.
- `examples/policies/hushspec-reputation.yaml` was refused with
  ``unknown field `reputation` at extensions``.
- No accepted document produced a validation error or warning.

This probe did not resolve `extends`, verify signatures, evaluate actions, test
the Rust SDK, exercise Chio, or establish production-policy compatibility.
There was no automatic version replacement or field stripping. Reproduce from
the pinned Hush checkout, with Arc at the revision above:

```sh
PYTHONPATH=packages/python PYTHONDONTWRITEBYTECODE=1 python3 - <<'PY'
from pathlib import Path
from hushspec.parse import parse
from hushspec.validate import validate

arc = Path('../arc')
paths = sorted((arc / 'examples/policies').glob('*hushspec*.yaml'))
paths += sorted((arc / 'crates/guards/chio-policy/src/rulesets').glob('*.yaml'))
for path in paths:
    ok, result = parse(path.read_text())
    if not ok:
        print(path, 'PARSE_REFUSED', result)
    else:
        report = validate(result)
        print(path, 'VALID' if report.is_valid else 'INVALID',
              [str(error) for error in report.errors], report.warnings)
PY
```

### Builtin names conceal content changes

Direct comparison of Arc's `chio-policy/src/rulesets` and Hush's `rulesets`
found substantive changes in five of seven documents:

- `default`, `strict`, `ai-agent`, `cicd`: updated secret patterns and shell
  restrictions; additional tool/path restrictions in some profiles.
- `panic`: explicit input-injection denial added.
- `permissive`, `remote-desktop`: only the schema comment differed.

The newer documents still declare `0.1.0`. Treat builtin identity as resolved
content plus engine material, not a name or document version. Record the old and
new resolved hashes and scenario deltas for every deployed builtin. Do not
silently swap `builtin:strict` to new bytes and call that behavior preservation.

### Runtime and consumer findings

Paths below are relative to Arc. These are source-backed observations, not
exploits reproduced against a running kernel.

| Boundary | Evidence | Required change or preservation |
| --- | --- | --- |
| Portable evaluator | `crates/guards/chio-policy/src/evaluate/{engine,matchers,context}.rs`: eight named actions, early returns, older context shape | Use upstream current evaluation and traces; do not just change the supported-version constant. |
| Native compilation | `chio-policy/src/compiler/rules.rs`: empty forbidden-path/shell lists select native defaults; egress ignores its `default` field and empty lists select a built-in allowlist | Remove this translation as the authority for new portable policies. Preserve additional native restrictions explicitly. Add counterexample tests before changes. |
| Additional defenses | The compiler adds `InternalNetworkGuard` for egress and a post-invocation sanitizer for secret rules | Keep SSRF protections and output handling in the runtime profile; Hush input decisions are not substitutes. |
| Tool versus effect | `crates/guards/chio-guards/src/action/extractor.rs` selects one action using tool-name heuristics; `mcp_tool.rs` gates only `McpTool` actions | Always evaluate the original tool plus every declared effect from a trusted host registry. A recognized file action must not skip portable tool policy. |
| Capabilities | `chio-policy/src/compiler/scope.rs` derives wildcard/pattern grants from tool lists; some unsupported constraints yield an empty scope | Keep capability authorization independent. Exact Hush tool names must not become broader wildcard grants. Preserve fail-closed unsupported cases. |
| Warnings | `chio-guards/src/pipeline.rs` can preserve `PendingApproval`; `chio-kernel/src/kernel/dispatch.rs::evaluate_guards_sequential` rejects that verdict from generic guards | Integrate portable warning requirements into the dedicated approval/admission flow. A simple `Warn -> PendingApproval` guard adapter is insufficient. |
| Detection and budgets | `chio-policy/src/compiler/detection.rs` ignores jailbreak `warn_threshold`; `compiler/budgets.rs` collapses origin tool-call budgets into one 60-second ceiling | Separate portable detector results from additional native detectors. Define trusted per-origin/session state and budget accounting explicitly. |
| Runtime identity | `crates/platform/chio-control-plane/src/policy/util.rs::runtime_hash_for_hushspec` enumerates seven rule blocks, reputation, kernel/capabilities and assets | Some executable changes can leave this hash unchanged. Replace the partial projection with a versioned complete materialization identity, not merely the Hush document hash. |
| Runtime identity consumers | `chio-control-plane/src/lib.rs::build_kernel`, evidence export, CLI runtime manifests, remote-MCP session resume and threshold approval use policy identity | Migrate bindings and reject stale approvals/resumptions; preserve historical identity verification. |
| Loading and provenance | `chio-control-plane/src/policy/loader.rs` hashes leaf bytes, then resolves separately; `LoadedPolicy` retains native pipelines but not current Hush resolution/signature state | Capture one immutable verified input set, full chain and assets. Retain compiled portable policy and trust state through dispatch. |
| Analysis and replay | `chio-policy/src/analyze` uses old models and old receipt hash; CLI `policy_analysis.rs` and `replay/policy_ref.rs` use the old loader | Retarget analysis or explicitly report unsupported/not analyzed. Current replay accepts local files, not registry/hash resolution. |
| WASM composition | `crates/guards/chio-wasm-guards/src/wiring.rs` puts compiled native guards before WASM guards | Preserve mandatory WASM denials and manifest/config identity. A portable allow cannot skip later Chio guards. |

The legacy `chio-policy/src/receipt.rs` hash is plain struct serialization with
bare-hex SHA-256, not Hush's canonical default projection and `sha256:` identity.
Separately, the control plane's partial runtime hash is passed into kernel
configuration and rebound into threshold approval requirements. These are two
distinct migration problems, not one rename.

## Architecture alternatives

1. **Recommended: upstream portable core plus explicit Chio runtime profile.**
   One source of portable semantics; Chio remains the execution and authorization
   boundary. Requires careful approval, context and identity integration.
2. **Update and maintain Chio's fork.** Preserves local ownership but duplicates
   parsers, versions, rules, hashing, signing and receipt maintenance. Both the
   evaluator and compiler need proof against the current contract. No compelling
   requirement for this maintenance burden has emerged.
3. **Translate current Hush fields into existing native guards.** Smaller initial
   diff, but defaults, pattern languages, aggregation, detector behavior and
   runtime context still differ. Reject as the authority for claiming current
   portable semantics. It remains useful only as an explicitly limited legacy
   compatibility path with documented differences.

An embedded library adds no policy network service. Reusing Hush makes Chio
reference-derived, as its old evaluator already is; it does not establish an
independently authored engine or an external adopter.

## Proposed integration contracts

### Format and loader boundary

Keep portable Hush YAML unmodified. Store Chio-only controls in separately
versioned Chio configuration bound to that policy. The concrete configuration
schema needs review; no `extensions.vendor.chio` contract exists in current Core.

Retain legacy Chio YAML and legacy Chio-Hush dialect loading through explicitly
selected compatibility paths. New portable loading must not fall back to legacy
parsing after a refusal. Version `0.1.0` alone cannot identify the dialect because
both portable and extended documents use it. Unknown/ambiguous configuration
must produce a diagnostic, not silently discard native controls.

Use the SDK's `Policy` builder with a restricted supplied-document loader and
signature locator, then its resolve/validate/compile path. Do not bypass that
pipeline by deserializing into `HushSpec` and directly compiling. Load bounded
bytes once, bind their hashes and use those same bytes for parsing/verification;
do the same for auxiliary assets. No ambient HTTP resolution in the initial
profile. File references must stay within configured roots; signatures do not
make arbitrary file paths safe to read.

`ResolveOptions::require_signature` accepts valid pins for parent hops as well
as verified envelopes, and trusts builtins. It is not by itself a guarantee that
the root was signed by the deployment's trusted publisher. Require an authenticated
root, review per-hop policy, verify expiry and bind the declared policy revision
to authenticated content. Persist rollback state across restarts. Default SDK
resolution performs no verification; it is not the production loader default.

### One portable decision, independent runtime constraints

The admitted operation must pass all of: capability authorization, portable tool
and effect evaluation, mandatory Chio guards, approval requirements and final
dispatch revalidation. An allow in one layer never overrides a deny in another.

Use a host-owned registry keyed by authenticated server identity and tool name.
Snapshot immutable arguments once; derive a bounded ordered effect plan and
canonical argument size from it. Always add the original `tool_call`. Reject
unregistered or opaque effects in the initial profile. Do not let actor input or
untrusted server annotations define the effects or trusted evaluation context.
Define qualified tool naming and the conversion of old unqualified names before
issuing capabilities. Require explicit server bindings; do not add `*` grants.

Source clock, origin, posture and rate state from trusted host/kernel context.
Current `GuardContext` is insufficient on its own. Specify what is captured for
one evaluation and what must be rechecked immediately before dispatch. Use
tenant-scoped panic state plus the existing kernel emergency-stop boundary;
rechecking an inactive flag is insufficient if it toggled during confirmation.

Aggregate all applicable portable components before requesting confirmation.
Any portable or mandatory runtime deny must result in zero prompts. Collect
warnings into the existing kernel approval mechanism, bind approval to the
immutable request, effect plan, policy generation and complete runtime identity,
and revalidate on resume. Do not double-consume budgets or approval tokens during
dispatch revalidation. The kernel already has admission, nonce, cleanup and
revalidation machinery; extend those seams instead of adding a second coordinator.

Retain filesystem confinement, SSRF/redirect/DNS protections, native detector
defenses, output sanitization, velocity limits, runtime assurance, reputation and
mandatory WASM guards where configured. Distinguish policy evaluation from OS
containment. Preserve intended controls even where the old translation was lossy;
emit migration diagnostics instead of claiming exact equivalence.

### Identity, evidence and reload

Keep three explicit concepts:

1. Portable policy identity: SDK canonical content hash and resolution chain.
2. Runtime profile identity: domain/version-separated canonical hash of the
   complete materialized controls, effective defaults, assets, tool/effect
   registry and engine identity, bound to the portable hash.
3. Provenance: retained source bytes, dependency lock, build/artifact digests,
   verification results and configuration revision.

Define how identities extend existing Chio wire schemas before editing them.
Do not overwrite the meaning of old bare-hex hashes or manufacture new signatures
for historical receipts. Old records must continue to verify under their old
format. Approvals, nonce/session-resume admission and replay caches must reject
bindings from a different active runtime profile or generation.

Attach genuine SDK rule/detector traces as portable component evidence. Bind
their hashes into Chio's signed operation evidence alongside native guard
decisions and actual execution outcomes. A standalone evaluation receipt is not
proof of dispatch or completion. Do not relabel it as a C journal, claim L4/L5
from L3, or infer prevention from a missing terminal event.

Install an immutable authenticated policy/profile generation atomically. An
invalid attempted reload should refuse new work in the initial strict profile,
not silently retain a policy the operator intended to replace. Pending approvals
must be invalidated. Document the point after which an admitted external effect
cannot be retracted; retain accurate aborted/unknown outcome evidence on failure.

## Staged change map

These are reviewable work packages, not permission to execute or substitute for
the later test-first implementation plan. Paths are relative to Arc except where
explicitly marked Hush.

| Package | Files and responsibility | Exit evidence |
| --- | --- | --- |
| M0: inventory and target pin | `Cargo.toml`, `Cargo.lock`, `crates/guards/chio-policy/Cargo.toml`; policy examples/rulesets and deployment-owner inventory | Approved exact upstream revision/features; current Rust parser/resolver matrix; old/new builtin and deployed-policy deltas; dependency/target audit. |
| M1: explicit portable loading | `chio-policy/src/lib.rs` with focused new portable-loading module; `chio-control-plane/src/policy/{types,loader}.rs` | Strict parsing, restricted resolution, root/chain authentication, rollback, explicit legacy selection; retained immutable compiled policy. No runtime conformance claim yet. |
| M2: complete identity and evidence | `chio-control-plane/src/policy/util.rs`, `lib.rs`, `evidence_export.rs`; CLI runtime, `chio-mcp-remote/src/remote_mcp/session_resume.rs`; relevant core receipt/approval schema consumers | Every executable profile change affects identity; historical receipts still verify; stale approvals/resumptions rejected; portable traces bound without invented execution claims. |
| M3: trusted tool/effect admission | `chio-guards/src/action`, `pipeline.rs`; focused portable adapter in `chio-policy`; `chio-kernel/src/kernel/{mod,dispatch}.rs`, `evaluation/async_evaluation_core.rs`, `evaluation/nested_flow_evaluation.rs`, `validation.rs` and existing approval/revalidation tests | Tool plus all effects enforced; native denials retained; warnings use real approval; trusted context, race and budget tests; real owned-server dispatch assertions. |
| M4: compatibility migration and CLI | `chio-policy/src/compiler`, `analyze`, `receipt.rs`, `rulesets`; `chio-cli/src/cli/dispatch/policy_analysis.rs`, `replay/policy_ref.rs`, policy command definitions, examples/docs | Dry-run conversion reports retained/moved/rejected controls and behavioral changes; no source overwrite; unsupported analysis explicit; legacy hashes and explicit compatibility loader tested. |
| M5: qualification and bounded adoption | Hush B external runner/C adapter and engine-material verifier, plus Arc integration fixtures/CI | Exact-candidate engine conformance separately from full kernel tests; one real edit and blocked operations with independent observations; failure/approval/reload evidence; declared supported profile. |

Suggested sequencing: M0 -> M1 -> M2 -> M3 -> M4 -> M5. No new portable
runtime mode becomes a deployment default before M3/M4 pass. During development,
old-policy evaluation may be compared in shadow mode, but shadow results never
authorize a second dispatch or override the active enforcer. M4 behavior-delta
fixtures should be identified in M0 and used throughout, not added only at the end.

The C-host adapter and Chio kernel workflow are distinct tests: passing one is
not evidence for the other's execution boundary. Building an external B runner
still needs its own static-build and restricted-resolution qualification.

### Separate Python coding-agent follow-up

`sdks/python/chio-code-agent/src/chio_code_agent/policy.py` interprets native
`kernel/guards/capabilities` YAML with its own defaults and path/command checks.
It is not a current Hush parser. Its tools call the id-only
`ChioClient.evaluate_tool_call` before local execution. In the inspected current
Python SDK that method deliberately returns no authoritative allow and raises;
do not weaken this fail-closed behavior to make a demo run.

The full-token `evaluate_tool_call_mediated` helper issues a reserved authorization
and execution nonce, not a completed tool result. A follow-up must choose a real
owned executor/server that verifies and consumes the nonce and reconciles the
reservation, preserving local filesystem/symlink and command restrictions. It
must not simply swap SDK method names and execute locally after an allow.

Initially demonstrate the Rust kernel-owned MCP path. Plan the Python host as a
separately reviewable adoption slice, including `tools.py`, SDK `client.py`, policy
configuration and real-client tests. Mock-client success and identical bundled
YAML bytes are not proof that the current real-client workflow executes. Other
Python/TypeScript adapters require their own consumer inventory before claiming
that all Chio integrations were upgraded.

## Required acceptance cases

| Test class | Concrete assertions |
| --- | --- |
| Raw input | Duplicate/unknown keys, aliases, multiple documents, malformed versions, oversized/deep input and invalid regex refuse before execution; patch versions in supported minor families work. Invalid portable input never falls back to legacy. |
| Resolution and auth | Missing/substituted/escaped parents, builtin drift, expired/wrong-key root, stale revision, restart rollback and changed assets refuse or produce the expected new authenticated identity. No network fallback. |
| Semantic counterexamples | Empty-list egress `default: block` denies an API host previously in native defaults; explicit default allow behaves per Hush; path allow plus secret deny still denies; patch secret detection, conditions, browser/code actions match upstream results and traces. |
| Exact tool and capability scope | A blocked `read_file` with an otherwise allowed path still denies; allowed tool plus denied effect denies; same tool name on another server has no implied grant; literal `*`/qualified names cannot widen capability issuance. |
| Approval | Multiple warnings yield one approval flow; warning plus native/portable deny yields zero prompts; timeout/refusal denies; request/arguments/effects/profile/generation substitutions invalidate approval. Cover nested calls and retries, not just the top-level path. |
| State and dispatch races | Policy/panic/origin changes while waiting block stale admission; tenant counters remain isolated; concurrent calls cannot overspend; revalidation consumes no second quota/token; failed reservations are reconciled. |
| Runtime identity | Mutate each rule, extension, effective default, detector asset, registry binding and mandatory WASM config independently; every executable change alters the new profile identity. Source formatting alone leaves semantic identity stable. Historical identity fixtures remain valid. |
| Additional defenses | SSRF, redirected/DNS-changed destinations, filesystem escape/symlink, secret output and native detector denials survive SDK adoption. An SDK allow cannot bypass a mandatory runtime guard. |
| Evidence failures | Lost/substituted component receipts, sink failure, crash before/after the observed effect and missing terminal evidence are not reported as completed or proven prevented. Old hashes are not reinterpreted as canonical Hush identities. |
| Actual host | Owned MCP server observes exactly the admitted operation; blocked operations have no effects; Python real-client fail-closed path is retained until an authenticated executor integration replaces it. |

Focused Rust tests will cover `chio-policy`, `chio-guards`, `chio-kernel` and
`chio-control-plane`, plus affected CLI/remote-MCP/WASM paths. Full Arc acceptance
still requires workspace build/test, clippy with `-D warnings`, formatting and
its supply-chain/target gates. Use `CHIO_CHECKOUT_ROOT` when an external target
directory needs repository fixtures. Retain failures separately from retries.
Hosted qualification must match the actual candidate SHA; no Hush source CI
result substitutes for Arc's new integration CI.

## Design review and remaining decisions

Self-review changed the proposal in four material ways:

- Rejected a guard-only warning adapter after checking the kernel consumer,
  rather than assuming the pipeline enum implied an end-to-end approval flow.
- Separated package publication from the 1.0 source target and builtin content
  migration from document-version support.
- Added complete runtime identity and its downstream approval/resume consumers,
  rather than treating canonical Hush hashing as the whole migration.
- Kept the Python host out of the first runtime milestone after checking that
  the real id-only SDK entry point intentionally cannot authorize execution.

Recommended architecture decision: upstream portable core plus an explicit,
authenticated Chio runtime profile, with opt-in legacy coexistence and a narrow
Rust kernel-owned MCP acceptance profile first. Approval should also settle the
public configuration shape, qualified-tool naming, trusted context/state source,
warning-to-approval interface and versioned identity wire bindings. These are
design choices to resolve before writing exact task interfaces, not hidden
implementation assumptions.

No Arc build or runtime qualification was performed. The retained evidence is
source/history inspection, live publication metadata, the 14-document Hush
Python probe and builtin file comparison. No production deployment inventory or
operator policy set was available. This is internal integration planning, not
outside assurance or completion of Project D.
