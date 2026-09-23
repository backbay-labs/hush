# HushSpec Delivery Ledger

**Reviewed:** 2026-09-22
**Reviewed baseline:** `wave-6` at `a0637cbe9d2ceb65a6865bb35d8ee4f0af5f2f1b`
**Repair revision:** Project A evidence repairs on `wave-6`; qualification tracked below
**Authority:** This is the current status ledger for `docs/plans/`. The numbered RFCs retain their original requirements and design rationale; they are not completion records.

> **Evidence boundary:** The reviewed baseline and repair revision are different states. The complete local verification record below does not establish hosted qualification, merge, tag, or publication. Terminal [CI checks](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) attached to the exact candidate record hosted qualification separately.

## Project A evidence repair (2026-09-22)

Tasks 1-9 of the [approved implementation plan](../superpowers/plans/2026-09-22-trustworthy-evidence.md)
are implemented on the branch: honest reference-runner identity, four-SDK
confirmation-failure recording, bounded strict evidence verification, scoped
inventory/policy qualification and validated observation-only OSCAL. Focused
regressions pass. Full local qualification, the independent whole-branch review
and exact-head hosted CI are tracked in the [Project A qualification record](../reviews/2026-09-22-project-a-qualification.md).
No merge, tag, package publication or external assessment is implied.

The older repair and hosted snapshots below remain historical evidence for
their named revisions, not qualification of Project A. The [foundation roadmap](2026-09-22-foundation-assurance-roadmap.md)
still requires B (an executable independent-engine conformance harness), C
(trusted MCP tool-plus-effect authorization and durable no-permit/no-dispatch),
and D (external assessor/adopter validation). Signed records do not establish
these runtime or adoption properties.

### State definitions

| State | Meaning |
|---|---|
| Implemented on branch | Source and tests exist in the open stack. This does not establish correctness, merge, or release qualification. |
| Locally tested | The recorded local command passed on this repair revision. It is not hosted evidence. |
| Hosted exact-SHA qualified | Every required hosted check has passed for the precise candidate and attempt being considered. |
| Merged | The candidate is on `main`; it may still be unqualified or unpublished. |
| Published | A tagged artifact is resolvable from its intended public registry. |

## Earlier repair integration and release snapshot

| Item | State | Evidence and boundary |
|---|---|---|
| `main` | Merged through PR #4 only | `5227b89ec2a9113d773c49743254188ee5548108`; it does not contain the RFC 09 reset or Waves 0-6. |
| PR #5 | Open, stacked | Truth reset and fail-closed/spec/tooling baseline; not merged. |
| PR #6 | Open, stacked | Four evaluators and document-level conditions; raw-YAML and runtime-time repairs are locally verified in this revision. |
| PR #7 | Open, stacked | Fuzz, evidence specifications, and controls; normalized differential input is not an independent raw-parser oracle. |
| PR #8 | Open, stacked | Evidence chain in four SDKs; log-schema repair is locally verified in this revision. |
| PR #9 | Open, stacked | Reporting, conformance, parity, and hygiene; adapter, raw/log runner, and lifecycle repairs are locally verified, not hosted-qualified. |
| PR #10 / `wave-6` | Open, stacked | `a0637cb` is the README/documentation commit. It contains prior waves but is neither merged nor released. |
| Repair-revision qualification | Local verification recorded | Rust, TypeScript, Python, Go, cross-SDK, packaging, and documentation checks are recorded below. Hosted CI attaches its own status to the exact commit. |
| Review disposition | In reconciliation | The audit snapshot remains 39 unresolved platform threads. The preserved audit and post-repair record are [linked together](../reviews/2026-09-22-reconciliation.md#post-repair-verification). |
| 1.0 publication | Not published | Live tag/release state was `v0.1.1-alpha`; npm and PyPI latest were 0.1.1; no `hushspec` 1.0.0 crate and no Go 1.0 module tag were available. |

## Numbered-plan reconciliation

| Plan | Current classification | Implemented direction on the open stack | Retained original scope or gate |
|---|---|---|---|
| [01 Evaluation](01-evaluation-engine.md) | Historical design; active correctness work is RFC 09 | Four SDK evaluators, compiled forms, and shared fixtures. | Raw-YAML and strict runtime-time repairs are locally verified; M1 still requires merge, and hosted portability evidence is pending. |
| [02 Audit](02-audit-trail.md) | Historical design; active evidence work is RFC 09 | Receipts, traces, signing, logs, sinks, and OTLP-related source are present. | Log-schema repair is locally verified. Retention/backend/collector scope and full evidence-chain qualification remain unestablished. |
| [03 CLI](03-policy-cli.md) | Historical design | `h2h` commands, structured outputs, testing, diffing, and initialization source exist. | Registry distribution and all original watch/configuration aspirations require separate qualification; first-release package installation is not proven. |
| [04 Governance/security](04-governance-security.md) | Historical design | Signing, verify-on-load artifacts, governance checks, and panic controls are present. | Enterprise RBAC/OIDC/LDAP, lifecycle service, and keyless/X.509 scope remain deferred; watch-bootstrap/panic recovery is locally verified, with hosted qualification pending. |
| [05 Runtime](05-runtime-integration.md) | Historical design | Guards, providers, reload structure, and adapters are present. | Argument binding, shared adapter mapping, and provider recovery are locally verified; hosted qualification is pending, and the broader secured-client/agent-loop scope is deferred. |
| [06 Detection/observability](06-detection-observability.md) | Historical design | Regex/heuristic detector, observer, metric, and OTLP-related source is present. | Dedicated PII/encoding/multiturn systems, threat-intelligence feeds, dashboards, and operational runbooks remain deferred. |
| [07 Conditions/library](07-conditional-rules-library.md) | Historical design | Cross-SDK conditions and eight control-tagged library policies are present. | The larger vertical catalog, policy registry, and original catalog ambitions remain deferred. |
| [08 Extends/loading](08-extends-remote-loading.md) | Historical design | File, builtin, and HTTPS resolution plus pin/signature/polling/watch source is present. | Cloud/Vault/Git/registry providers, push reload, and shared-cache scope remain deferred; recovery is locally verified, with hosted qualification pending. |
| [09 Compliance-as-code](09-compliance-as-code-plan.md) | **Implementation in progress; active source-of-truth plan** | Most Wave 0-6 implementation artifacts are present in open PRs #5-10. | Its flagship checklist stays unchecked until the exact candidate is fixed/tested, hosted-qualified, merged, and, where required, published/resolvable. |

## Repair mapping and local verification

| Reviewed finding | Repair-revision state | Local verification | Still required |
|---|---|---|---|
| Raw YAML scalar portability | Locally tested | All four SDK raw parsers agree on the current shared corpus; raw report scoring passes. | Exact-commit hosted CI. |
| Python decorator action arguments | Locally tested | Decorator/middleware argument-binding checks pass. | Hosted CI. |
| Provider bootstrap, recovery, panic, DNS deadline | Locally tested | Watcher/HTTP lifecycle checks pass. The follow-up extends DNS-inclusive default connection budgets to every loader and tests bounded resolver capacity and late-answer refusal. | Exact-commit hosted CI; native resolver isolation is not established. |
| Log schema enforcement | Locally tested | Four SDK log checks and schema-vector generation pass. | Exact-commit hosted CI. |
| Strict runtime timestamps | Locally tested | Four SDK condition checks pass. | Exact-commit hosted CI. |
| MCP mapping and argument size | Locally tested | TypeScript, Python, and Go adapter-contract checks pass. | Hosted CI. |
| First-release Rust package qualification | Locally tested | `cargo package --workspace --locked` verified all three archives on clean repair commits `341675a` and `295022c`; CI/Publish enforce the same command for each candidate. | Qualify each final candidate, then authorized merge/tag/publication. |

### Local verification record

- Rust: the workspace suite and final 294-test core rerun passed with zero failures; one benchmark is intentionally ignored. All-features clippy and the no-default-features build passed.
- TypeScript: 2,328 tests plus build, lint, and V8 coverage passed after upgrading Vitest and its coverage provider to 4.1.11. Full and runtime-only npm audits report zero vulnerabilities. Local verification passed on both Node 20.20.2 and Node 24.16.0; hosted CI remains a separate gate.
- Python: 3,031 passed with four intentional YAML pre-document skips. Go full suite, `go vet`, and race-enabled DNS regressions passed.
- Cross-SDK: 86 raw cases in all four SDKs, 25 runtime-time cases, 471 log-schema cases, and 500 differential groups/2,000 actions with zero mismatches passed.
- Documentation: 35 documents × 4 SDK round-trip checks and eight executable snippets passed. MSRV 1.88 build passed.
- The L5 conformance report passed its 197 document fixtures plus raw/log cases. All six levels passed without failures or skips.
- Generated artifacts, schema guards, formatting, comment hygiene, workflow lint, documentation build, Cargo audit/deny, and 206 library cases with 129/129 rule coverage passed.

Adapter mapping remains supplemental SDK-integration evidence, not a core conformance level. Hosted CI records results against its exact commit; this ledger does not duplicate or predict that state.

The first hosted attempt exposed two test-fixture races, not a passing qualification. Their deterministic replacements, preserved assertions, and independent review are recorded in the [CI fixture follow-up](../reviews/2026-09-22-ci-fixture-review.md). This revision requires fresh hosted checks; predecessor failures are not erased by local passes.

The final workflow audit also corrected Rust feature selection: hosted clippy, tests, coverage, and the MSRV build now enable all features, including the optional HTTP loader. The separate no-default-features compile gate remains. All 294 core tests passed locally under all-feature LLVM coverage, and the locked all-feature workspace build passed on Rust 1.88. Earlier default-feature hosted results do not qualify the optional loader repairs.

### Resolver availability boundary

System DNS calls cannot generally be cancelled. Rust and Python cap detached/daemon resolver workers at eight per process; a stalled call retains its slot until it returns. TypeScript caps pending native/custom lookups at 32, but native `dns.lookup` still shares Node's worker pool and can occupy that pool after its caller times out. Go uses its standard context-aware resolver and native concurrency limit. Exhaustion fails closed; it is not a guarantee of uninterrupted availability or native resolver isolation.

Rust subtracts DNS elapsed time from reqwest's connection timeout, refuses expired admission after client construction, and retains the original total request budget. Client-construction/scheduling overhead is not a hard real-time connection deadline. A separate resolver/transport isolation design would require additional qualification.
