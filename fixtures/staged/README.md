# Staged conformance vectors

Vectors under `fixtures/staged/<spec-version>/` encode requirements that the specification at that version has **ratified** but that the reference SDKs have **not yet implemented**. They mirror the layout of `fixtures/` (`<module>/{valid,invalid,evaluation}`) and use the same fixture format.

No test runner walks this directory. The four shared-fixture runners and the testkit enumerate only `fixtures/{core,posture,origins,detection}/{valid,invalid,merge,evaluation}`. A vector becomes normative for conformance when it is **promoted**: moved into the matching directory under `fixtures/` in the same change that makes every SDK pass it.

## Promotion rules

1. Promote a file only when all four SDKs (Rust, TypeScript, Python, Go) pass it. Never promote a subset of its cases.
2. When a staged vector supersedes an existing case, delete or rewrite the old case in the same change (listed below under "supersedes").
3. Vectors that need a change to `schemas/hushspec-evaluator-test.v0.schema.json` (new action types, new action fields, a per-case `context`) are promoted together with that schema change.
4. Update the "Test vectors" references in `spec/` if a file is renamed on promotion.

## 0.2.0

Owning work packages: P1-03 (Rust), P1-04 (TypeScript), P1-05 (Python), P1-06 (Go), P1-08 (`when` in schema and models), P1-07 (regex profile). See `docs/plans/09-compliance-as-code-plan.md`.

| File | Decision | Spec section | Notes |
|---|---|---|---|
| `core/evaluation/unknown-action.test.yaml` | D1 | core 5 | Needs `custom` in the evaluator-test action enum; unknown types (`teleport`) also need the enum relaxed or a `custom`-only vector |
| `core/evaluation/custom-action-capability.test.yaml` | D1 | core 5, posture 3.3 | Needs `custom` in the action enum |
| `core/evaluation/no-early-return.test.yaml` | D2 | core 6.1 | Reference evaluator returns early on `path_allowlist` and `forbidden_paths.exceptions` |
| `core/evaluation/tool-exact-match-staged.test.yaml` | D3 | core 3.7 | Reference evaluator glob-matches tool names; companion to the promoted `tool-exact-match.test.yaml` |
| `core/evaluation/tool-allowlist-deny.test.yaml` | D4 | core 3.7 | Reference evaluator falls through to `default` in allowlist mode |
| `core/evaluation/egress-normalization-staged.test.yaml` | D5 | core 3.3, 3.14.2 | Port, case, trailing dot, URL, IDNA, single-label `*`, IP-literal rule; companion to the promoted `egress-normalization.test.yaml` |
| `core/evaluation/path-normalization-staged.test.yaml` | D6 | core 3.14.1 | Lexical normalization; companion to the promoted `path-normalization.test.yaml` |
| `core/evaluation/regex-dialect-staged.test.yaml` | D7 | core 3.14.3 | ASCII class escapes, `$`, `.`; requires P1-07 in all four SDKs |
| `core/evaluation/severity-mapping-staged.test.yaml` | D8 | core 3.4 | `warn` severity and worst-severity-wins |
| `core/evaluation/content-scan-egress-tool.test.yaml` | D8 | core 3.4, 5 | `egress` and `tool_call` scanned when `content` is present |
| `core/evaluation/computer-use-guardrail-deny.test.yaml` | D9 | core 3.8 | **Supersedes** the "warn on unlisted action (guardrail mode)" case in `fixtures/core/evaluation/computer-use.test.yaml`; rewrite that case to `deny` on promotion |
| `core/evaluation/patch-balance-zero.test.yaml` | D10 | core 3.5 | Zero-side balance rule |
| `core/evaluation/browser-automation.test.yaml` | D13 | core 3.11 | Needs `browser_action` type and `url` field in the evaluator-test schema |
| `core/evaluation/code-execution.test.yaml` | D13 | core 3.12 | Needs `code_exec` type and `network`, `timeout_ms` fields in the evaluator-test schema |
| `core/valid/version-patch-accept.yaml` | D14 | core 2.2 | Engines must accept `0.1.1`; `version.rs` and its ports currently exact-match |
| `core/valid/when-conditions.yaml` | D15 | core 3.13 | Needs `when` in the core schema and generated models |
| `core/invalid/when-bad-time.yaml`, `when-bad-timezone.yaml`, `when-bad-day.yaml`, `when-unknown-key.yaml`, `when-too-deep.yaml` | D15 | core 3.13 | Parse-time condition validation |
| `core/evaluation/conditions.test.yaml` | D15 | core 3.13 | Needs a per-case `context` field in the evaluator-test schema and runners |
| `core/invalid/yaml-alias.yaml` | D17 | core 2.4 | All four SDKs currently accept aliases |
| `core/invalid/yaml-bool-yes.yaml` | D17 | core 2.4 | Python and Go currently accept `yes` as a boolean |
| `core/invalid/yaml-multi-doc.yaml` | D17 | core 2.4 | Go currently decodes only the first document |
| `origins/evaluation/default-behavior-deny.test.yaml` | D12 | origins 2.1 | `default_behavior` is not enforced by the reference evaluator |
| `origins/evaluation/priority-staged.test.yaml` | D12 | origins 3 | Reference evaluator uses weighted scores (`space_id` = 8, `tenant_id` = 6, others 4 or 2) |
| `origins/evaluation/tri-state-overlay.test.yaml` | D12 | origins 4 | Reference models materialize `default: block` into profile `egress` |
| `posture/evaluation/transition-priority.test.yaml` | D18 (pending) | posture 5.3 | Spec text unchanged in 0.2.0; the reference evaluator picks the first matching transition in document order. Ratify or amend before promotion. |

Requirements with no expressible vector: D16 (`warn` without a confirmation channel is engine configuration, not a document property) and the D7 rule that a regex failing to compile at evaluation time denies (validation rejects such documents before evaluation; test it as an SDK unit test by bypassing validation).
