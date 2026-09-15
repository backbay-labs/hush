# RFC 09: Compliance-as-Code Plan (v0.2 → v1.0)

**Status:** Proposed
**Date:** 2026-09-14
**HushSpec Version:** 0.1.1 → 1.0.0
**Affects:** Specification, schemas, all four SDKs, h2h CLI, testkit, fixtures, library, CI
**Source:** Findings from the 2026-09-14 full-repo review (spec/schema, Rust core, cross-SDK parity, tooling, evidence chain). Every item below traces to a verified finding.

---

## 1. Goal

Make "agentic compliance as code" technically true: a HushSpec policy declares controls, maps them to frameworks, is signed, resolves with provenance, is enforced fail-closed by any conformant engine, emits tamper-evident receipts that any SDK hashes identically, and can be turned into a report an auditor accepts. Then freeze the spec at 1.0 with a published conformance program a third party can pass from the prose alone.

## 2. Operating rules

1. **Spec first.** Every behavior change lands as: ratify prose → add fixture → change all four SDKs → difftest. No SDK change without a vector.
2. **Fail-closed by default.** Any error, unknown value, or unresolvable input evaluates to deny. For conditions, an unresolvable input leaves the rule block active.
3. **No roadmap claim without code.** A checkbox flips only in the PR that ships the code and its test.
4. **One canonical form.** Policy hashes, signatures, and receipts are computed over RFC 8785 (JCS) canonical JSON of the resolved, defaults-materialized document.
5. **Packages are wave-sized.** Each work package fits one worktree / one agent, lists its dependencies, and has a testable exit criterion, so waves can run in parallel.

## 3. Milestones

| Milestone | Spec version | Exit criteria |
|---|---|---|
| **M1 Fail-closed** | 0.2.0 | Every MUST in `spec/` has a fixture. All Phase 1 packages merged. Difftest green with regex-dialect, normalization, unknown-action, condition, and extra-rule-block strategies. |
| **M2 Evidence** | 0.3.0 | JCS `content_hash` identical across four SDKs for every fixture. Receipt v0.2. Chained log with `h2h log verify`. Signing in four SDKs with verify-on-load. `metadata.controls` in schema and library. |
| **M3 Provable** | 0.4.0 | Versioned conformance bundle published on release with manifest. Levels 0–5 defined with report schema. `h2h report`, JUnit, SARIF. Library test suites in CI. |
| **M4 Flagship** | 1.0.0 | Spec frozen with registries, grammars, security considerations. Parity matrix all-yes or explicitly out of scope. All packages published and resolvable. |

---

## 4. Phase 0 — Truth reset (Wave 0, no dependencies)

| ID | Package | Files | Exit criterion |
|---|---|---|---|
| P0-01 | Re-label `ROADMAP.md`. Uncheck: byte-compatible receipts, signed extends chains, S3/GCS/Azure/Vault/Git loaders, hot reload outside TS, HeuristicInjectionDetector, OTLP sink, HushGuard "all SDKs", Ed25519 "all SDKs", SoD enforced, library test suites, `when` support. Mark Phase 4 "Partial". | `docs/plans/ROADMAP.md` | Every checked box has a file:line pointer to code + test |
| P0-02 | Fix conformance claims. Remove "Level 4" row from README until §8 defines it. Make `sdk-conformance.md` agree with README and CI on Level 3. | `README.md`, `docs/src/reference/sdk-conformance.md` | Both docs and `ci.yml` agree |
| P0-03 | Add `CHANGELOG.md` (Keep a Changelog), `SECURITY.md` (disclosure), `GOVERNANCE.md` (spec change/RFC/errata process), `CONTRIBUTING.md`. | repo root | Present, linked from README |
| P0-04 | Rename copy to "compliance as code" at all seven touchpoints. | `README.md`, `crates/hushspec/Cargo.toml`, `packages/python/pyproject.toml`, `packages/hushspec/package.json`, `docs/src/introduction.md`, `docs/schemastore-entry.json`, `CLAUDE.md` | `grep -ri "agent security rules"` returns nothing outside `docs/plans/` |
| P0-05 | CI hygiene. Lint-gate `rulesets/` and `library/` with `--fail-on-warnings`; fix `cicd.yaml` dead exceptions. Add `cargo-deny`, `cargo-audit`, `npm audit`, `pip-audit`, `rust-version` + MSRV job, coverage upload (llvm-cov, c8, pytest-cov, go -cover), dependabot, mdbook link check. Attest `SHA256SUMS`; switch PyPI to trusted publishing. | `.github/workflows/*.yml`, `Cargo.toml`, `docs/book.toml`, `rulesets/cicd.yaml` | All new jobs green on main |

---

## 5. Phase 1 — Fail-closed correctness (M1)

### 5.1 Decisions to ratify

Each decision becomes normative prose plus at least one fixture. Recommended defaults are chosen for fail-closed behavior and for matching the existing spec where the spec is stricter than the code.

| # | Question | Recommended | Rationale |
|---|---|---|---|
| D1 | Unknown or `custom` action type | **Deny** with `matched_rule: "__unknown_action_type__"`. `custom` denies unless a posture capability named `custom` is granted. | Spec §1.2 fail-closed. Currently allow in all four SDKs (`evaluate.rs:127-133`). |
| D2 | Early return on allowlist / exception match | **Never.** Evaluate every applicable block for the action type and aggregate per §6.1. | Allowlisted path currently skips `secret_patterns` and `patch_integrity` (`evaluate.rs:550-558, 970-989`). |
| D3 | Tool-name matching | **Exact** (spec §3.7). Add optional `allow_patterns` / `block_patterns` glob lists in 0.3 if needed. | Code globs today; spec says exact. |
| D4 | Tool allowlist mode, unlisted tool | **Deny** (spec §3.7 step 4). | Code falls through to `default`. |
| D5 | Egress host normalization | Lowercase, strip scheme/path/port/trailing dot, IDNA→punycode, IPv6 brackets. `*` = exactly one label. `**` = one or more labels; apex must be listed explicitly. | Ports and uppercase currently miss (`evaluate.rs:436-441, 1354`). |
| D6 | Path normalization | NFC, `\`→`/`, collapse `.` and `..`, strip trailing `/`. `?` and `*` never cross `/`. `[`, `{` are literal. | `/proj/../.env` currently matches exception `/proj/**`. |
| D7 | Regex profile | RE2-class syntax. ASCII classes only (`[0-9]` not `\d`), no lookaround/backrefs/possessive/nested unbounded quantifiers, inline flags only leading. Unanchored search. **Compile failure at eval = deny.** | Dialect divergence across SDKs; `unwrap_or(false)` fail-open in Rust/Go/Py. |
| D8 | Secret severity → decision | `critical`, `error` → deny; `warn` → warn. Scan `file_write`, `patch_apply`; scan `egress` and `tool_call` when `content` is supplied. | Spec leaves it "engine-defined"; code denies on all. |
| D9 | `computer_use` guardrail | **Deny** (spec §3.8). | Code warns. |
| D10 | `require_balance` with a zero side | **Deny** (spec §3.5). | Code allows 0 additions / 5 deletions. |
| D11 | Posture with empty `capabilities` | **Deny all** (ratify code; fix posture §3 and Appendix B). | Spec prose says "no restriction"; its own appendix disagrees. |
| D12 | Origins | Enforce `default_behavior`. Priority = `space_id`, then field count (spec order, not weighted score). Profile rule blocks are tri-state; no materialized `default: block`. Absent `match` never matches. | `default_behavior: deny` currently never consulted. |
| D13 | `browser_automation`, `code_execution` | **Implement.** Spec §3.11/§3.12, action types `browser_action` and `code_exec`, dispatch in four SDKs. | Parsed but dead in all SDKs. |
| D14 | Version acceptance | An engine declaring support for `X.Y` MUST accept `X.Y.*`. | `0.1.1` is rejected today. |
| D15 | `when` conditions | In-document field on every rule block. Unknown block name, bad tz/HH:MM/day, depth > 8 → **parse error**. Unresolvable tz at runtime → rule stays active. | Today a side-channel map; not portable. |
| D16 | `warn` with no confirmation channel | **MUST deny** (upgrade from SHOULD). | Fail-closed. |
| D17 | YAML profile | YAML 1.2 Core schema, single document, duplicate keys rejected, anchors/merge keys rejected, depth/alias caps. | `enabled: yes` valid in Python, invalid in Rust. |

### 5.2 Work packages

| ID | Package | Depends on | Exit criterion |
|---|---|---|---|
| P1-01 | Spec rewrite for D1–D17: core §3.3, §3.5, §3.7, §3.8, §5, §6, §7; new §3.11/§3.12; posture §3 + App B; origins §3; version rule; YAML profile section. | decisions | Every changed paragraph has a MUST and a fixture id |
| P1-02 | Fixtures for D1–D17 under `fixtures/core/evaluation/` (unknown-action, no-early-return, tool-exact, tool-allowlist-deny, egress-normalization incl. ports/IPv6/case, path-normalization incl. traversal + unicode, regex-dialect, severity-mapping, computer-use-deny, patch-balance-zero, browser/code blocks, version-patch-accept, conditions), posture/origins fixtures, YAML-profile invalid vectors. | P1-01 | Each decision has ≥1 vector; invalid vectors carry expected error code |
| P1-03 | Rust evaluator: implement D1–D14, D16. Remove early returns; aggregate. Regex compile error → deny. Dispatch browser/code blocks. | P1-01, P1-02 | All new fixtures pass; testkit green |
| P1-04 | TypeScript port of P1-03. | P1-03 | Shared fixtures green |
| P1-05 | Python port of P1-03. | P1-03 | Shared fixtures green |
| P1-06 | Go port of P1-03. | P1-03 | Shared fixtures green |
| P1-07 | Regex profile enforcement (D7) in `is_safe_regex` in four SDKs: reject `\d \w \s \b`, non-leading inline flags, bare `$`; Python compiles with `re.ASCII` and rewrites `$`→`\Z`. Update builtins/library that violate the profile. | P1-01 | Dialect fixtures produce identical decisions in four SDKs |
| P1-08 | `when` as document field (D15): schema `$defs.Condition`, generated models ×4, `validate_conditions` ×4, evaluator reads document conditions; side-channel map kept only as an override. Add `context` to evaluator-test schema and `--context` to `h2h eval`. | P1-01 | Condition fixtures pass in four SDKs |
| P1-09 | Resolve everywhere: `HushGuard.fromFile/fromYaml/fromProvider` (TS, Py) resolve `extends` or reject unresolved docs; `h2h diff`, `h2h lint`, `h2h test --policy` resolve via builtins loader. | — | Library policy loaded via guard has its `builtin:strict` base |
| P1-10 | `h2h test` fail-closed: `deny_unknown_fields` on fixture structs; validate fixture files against `hushspec-evaluator-test` schema before running. | — | Typo in `expect` fails the run |
| P1-11 | Timezone data: Python `tzdata` dependency; Go `_ "time/tzdata"`. | — | Condition tests pass on slim images |
| P1-12 | Difftest coverage: strategies for regex dialect, host/path normalization, unknown actions, browser/code blocks, conditions, `extends`; harnesses call `evaluate_with_context`; all four fixture runners assert the same field set (decision, matched_rule, reason, origin_profile, posture); Go shared-fixture CI job actually calls `Evaluate`. | P1-03..06 | Nightly fuzz green for 3 consecutive runs |

---

## 6. Phase 2 — Evidence chain (M2)

| ID | Package | Depends on | Exit criterion |
|---|---|---|---|
| P2-01 | **Canonical form spec** `spec/hushspec-canonical.md`: JCS (RFC 8785) over the resolved document with defaults materialized; projection excludes `extends` and `merge_strategy`, includes `metadata`; number formatting; UTF-8 NFC. Test vectors with expected digests. | P1-01 | Vectors in `fixtures/core/hash/` |
| P2-02 | `canonical_json()` + `content_hash` in four SDKs over P2-01; difftest compares hashes. | P2-01 | Identical digest for every fixture across four SDKs |
| P2-03 | **Receipt v0.2** schema + `spec/hushspec-receipt.md`. Add `receipt_version`, `actor{agent_id, session_id, principal, runtime}`, `policy.extends_chain[{source, content_hash}]`, `policy.signature{key_id, verified}`, `action.content_hash/content_size/args_size`, `detection_trace`, `enforcement` (populated in Rust), `time_source`. Timestamp = RFC 3339 UTC, millisecond precision, in all SDKs. `receipt_id` = UUID v7. | P2-01 | Schema meta-validates; 10 example receipts validate |
| P2-04 | Rule trace recorded, not reconstructed: thread a `Vec<RuleEvaluation>` through evaluators in four SDKs; `evaluate_audited` routes through detection; remove string-matching reconstruction. | P1-03..06, P2-03 | Receipt fixtures assert exact `rule_trace` order in four SDKs |
| P2-05 | **Log envelope** `schemas/hushspec-log-entry.v0.schema.json`: `seq`, `prev_hash`, `entry_hash`, optional `signature`. `ChainedFileSink` in four SDKs (fsync, advisory lock, rotation with chain carry-over). `h2h log verify <jsonl> [--key]` checks continuity, gaps, signatures. | P2-02, P2-03 | Tampered line, deleted line, and reordered line all detected |
| P2-06 | Receipt signing: `sign_receipt` / `verify_receipt` over JCS in four SDKs; `h2h receipts verify log.jsonl --policy p.yaml` re-evaluates and checks hash + signature. | P2-02, P2-07 | Cross-SDK: receipt signed in Go verifies in Rust/TS/Py |
| P2-07 | **Policy signing spec** `spec/hushspec-signing.md`: envelope = JCS; `key_id` = SHA-256 of SPKI; `signed_at`, `expires_at`, `policy_version` (rollback protection); `content_hash` over canonical form, not raw bytes; PKCS#8/SPKI PEM keys; keyring with multiple `key_id`s; align `FORMAT_VERSION`; base64url. Port sign/verify to TS, Py, Go. Test vectors. | P2-01 | Signature made in any SDK verifies in the other three |
| P2-08 | **Verify-on-load**: `resolve` verifies each chain hop against trusted keys (fail-closed when `require_signature`); `#sha256:` digest pinning for `https:` and file `extends`; `HushGuard` options `requireSignature`/`trustedKeys`; outcome written to `receipt.policy.signature`. Fix DNS re-resolution TOCTOU in HTTPS loader. | P2-07 | Unsigned or mis-signed hop denies with clear error |
| P2-09 | **Controls metadata**: `metadata.controls[]` `{framework, control_id, rule_paths[], notes}`; framework registry `spec/registries/frameworks.yaml` (hipaa-2013, soc2-tsc-2017, pci-dss-4.0, nist-800-53-r5, ferpa, iso-27001-2022, nist-ai-rmf-1.0); regenerate models ×4; spec prose for `metadata` (currently none); migrate 8 library policies from comments to structured mappings; lint L011 "rule block without control mapping when mappings exist"; `h2h audit --controls` prints control→rule matrix. | P1-01 | All library policies validate with structured controls |
| P2-10 | **Policy-in-effect record**: on guard construction and policy swap, write a `policy_loaded` entry (policy hash, chain hashes, key_id, enforcement config incl. overrides, SDK + spec version) to the sink, signed when a key is configured. Four SDKs. | P2-05 | Log shows what was enforced and when it changed |
| P2-11 | Governance hardening: `h2h audit --strict` non-zero exit; author ≠ approver check; add `owner`, `reviewers[]`, `next_review_date`, `changelog[]`, `supersedes`; `h2h sign` refuses unless `lifecycle_state` is approved/deployed; `expiry_date` format validated. | P2-09 | `audit` catches SoD violation |
| P2-12 | `h2h bundle`: resolved policy + every chain hop hash + key ids → DSSE / in-toto statement; `release.yml` attests `library/` bundles. | P2-08 | Bundle verifies with `cosign verify-blob-attestation` or equivalent |

---

## 7. Phase 3 — Reporting and test-as-evidence (M3)

| ID | Package | Depends on | Exit criterion |
|---|---|---|---|
| P3-01 | `h2h report` over JSONL receipts: `--since/--until`; per-rule-block fired counts; per-control evidence counts (via P2-09); deny/warn/would_block by enforcement mode; policy-hash timeline; JSON and CSV; OSCAL assessment-results exporter behind a flag. | P2-05, P2-09 | Report for a 24h synthetic log matches hand-computed totals |
| P3-02 | Evaluator-test schema v0.2: `controls[]`, `tags[]`, `context`, `conditions`, `expect.receipt`; `h2h test --format junit`; rule coverage (declared rule paths vs. paths hit by `matched_rule`) with `--fail-on-uncovered`. | P1-08, P2-03 | JUnit consumed by GitHub test summary |
| P3-03 | Library test suites: `fixtures/library/<vertical>/*.test.yaml` for all 8 policies, each case tagged with the control it proves; CI job runs them; embed library as `builtin:library/<path>` in four SDKs. | P3-02, P2-09 | Every library rule block hit by ≥1 case |
| P3-04 | Lint: YAML span map for line/col; SARIF output; new lints L011–L018 (missing `.env`/`.ssh`/`.aws` in forbidden_paths; non-critical severity on AWS/GitHub/private-key patterns; over-broad shell pattern like `.*`; `egress.default: allow` warning; `tool_access.default: allow` with empty block warning; `input_injection.allowed_types: []`; L007 covers browser/code blocks; extension checks for unreachable posture states and never-matching origins profiles). | P1-09 | SARIF uploads to code scanning |
| P3-05 | CLI completeness: `h2h resolve` (print merged doc), `h2h schema <name>`, `h2h diff --fail-on relaxed`, shell completions, `--version --json` (git sha, spec version, supported versions), stdin for `validate`/`lint`/`fmt`, `fmt` preserves comments, integration tests for `audit`/`sign`/`verify`, remove unused `jsonschema` dep or use it. | — | Every subcommand has `--format json` and documented exit codes |
| P3-06 | Integrations: `action.yml` (validate/lint/test with SARIF + JUnit), `.pre-commit-hooks.yaml`, `Dockerfile`; publish `@hushspec/cli`. | P3-04 | Action runs on this repo's PRs |

---

## 8. Phase 4 — Conformance program (M3)

| ID | Package | Depends on | Exit criterion |
|---|---|---|---|
| P4-01 | `fixtures/MANIFEST.json` (fixture version, sha256 per file); expected error codes on every `invalid/` vector; schema for `merge/` vectors; testkit `bundle` command producing `hushspec-conformance-<ver>.tar.gz` (fixtures + schemas + manifest) attached to releases. | P1-02 | Bundle reproducible byte-for-byte from a tag |
| P4-02 | Vector gaps: `enabled: false` per block; `max_args_size`; deny > warn precedence; non-critical severities; `threat_intel`; extends cycle and 3-hop chain; all three merge strategies for core and each extension; `metadata`; receipts; conditions; `custom`. | P1-02 | Coverage table in `docs/src/reference/conformance.md` has no empty cells |
| P4-03 | Levels: define **L4 Auditor** (receipt v0.2, JCS hash, recorded rule_trace) and **L5 Attested** (signing, verify-on-load, chained log). `hushspec-conformance-report.v0.schema.json`; testkit `report` computes level; conformance statement template; publish testkit to crates.io. | P2-03..P2-08 | A third-party runner can produce a valid report from the bundle |
| P4-04 | Fuzzer: cover `evaluate_with_detection`, `evaluate_with_context`, `evaluate_audited`; compare `rule_trace` and `content_hash` across SDKs; detection score strategies; keep minimizer. | P1-12, P2-04 | Nightly compares receipts, not just decisions |

---

## 9. Phase 5 — Spec 1.0 artifacts (M4)

| ID | Package | Depends on | Exit criterion |
|---|---|---|---|
| P5-01 | Normative sections for everything that is code-only today: `metadata`, `when`, panic (sentinel, latching, `__hushspec_panic__`, always-enforce), monitor/enforcement, resolution schemes (`builtin:`, file, `https:`, digest pinning, depth 32, SSRF rules), signing, receipts, log, canonical form, browser/code blocks, detection categories + score cut-points + `data_exfiltration`, origins composition. | P1, P2 | No public function in any SDK lacks a spec section |
| P5-02 | Grammars: ABNF for path glob, host glob, tool id, rule identifiers, `matched_rule` paths; YAML 1.2 profile; regex profile. | P1-01 | Each grammar has positive and negative vectors |
| P5-03 | Security Considerations (ReDoS, traversal, symlink/TOCTOU, SSRF, DNS rebinding, clock skew, log tampering). Registries under `spec/registries/`: action types, rule blocks, `matched_rule` paths, error codes, capabilities, detector ids, condition types, frameworks. Media types `application/vnd.hushspec+yaml`, `+json`, receipt, log. Extension versioning decision. Errata process. | P0-03 | Registries are the single source for generated enums |
| P5-04 | Schema fixes: `$ref` extension schemas from core with `unevaluatedProperties: false`; origins gets its own rule types (no `enabled`); evaluator-test action enum includes `custom`; receipt `rule_block` enum aligned with emitted ids; bind `hushspec.dev` `$id` host (serve `schemas/` from `docs.yml`, CNAME); SchemaStore entry updated. | P5-03 | Unknown key inside `extensions.posture` fails JSON Schema validation |
| P5-05 | Freeze: version acceptance rule, `merge_strategy` stripped from output, `metadata` merge rule, receipt/log/signature wire formats pinned, breaking-change policy. Tag `spec-1.0.0`. | all | `CHANGELOG.md` 1.0.0 entry lists every frozen surface |

---

## 10. Phase 6 — SDK parity, packaging, performance (M4, runs in parallel from M1)

| ID | Package | Depends on | Exit criterion |
|---|---|---|---|
| P6-01 | `CompiledPolicy` in four SDKs: precompiled regex/glob sets, cached `DetectorRegistry`, no per-call spec clone. Rust `Policy` façade: `load → resolve → verify → validate → compile`. Scoped `PanicState` handle instead of process-global static. `glob_matches` made crate-private. | P1-03 | Bench: evaluation cost independent of pattern count compile time; `bench_thresholds` gate still passes |
| P6-02 | Parity: `HushGuard` in Rust and Go; observers in Rust and Go; `PolicyProvider`/watcher/poller in Py, Go, Rust; Anthropic adapter in Py; Go adapters (Anthropic, OpenAI, MCP); OTLP receipt sink in four SDKs; heuristic injection detector in four SDKs; `capability` condition; `rate` condition backed by posture budgets. Anything not built is struck from README/roadmap. | P1-08, P2-05 | Matrix in README has no unexplained "No" |
| P6-03 | API contract doc `docs/src/reference/sdk-api.md`; rename for isomorphism (`ConsoleReceiptSink`→`StderrReceiptSink`, Go `WithDefaultDetectors`→`NewDefaultDetectorRegistry`, version consts); Go `Content *string`; Rust action field `type`; TS models generated by `generate_sdk_models.py`. | — | Same example program reads identically in four languages |
| P6-04 | Packaging: tag `packages/go/v0.x.y` and add `packages/go/README.md` + `LICENSE`; Python `py.typed`, classifiers, `tzdata`; TS `exports` order (`types` first), `engines`, optional CJS build; Rust `generated_builtins.rs` replacing `include_str!` + publish-time sed. | — | `go get`, `cargo package`, `npm pack`, `python -m build` all succeed from a clean clone |
| P6-05 | Tests: proptest round-trips for `HushSpec`, `Condition`, `DecisionReceipt` in `crates/hushspec`; fail-closed unit tests for D1, D2, D7; sink concurrency tests; HTTPS loader tests beyond URL validation. | P1-03 | CLAUDE.md proptest convention is true |

---

## 11. Waves

```
Wave 0  P0-01..05
Wave 1  P1-01 P1-02        | independent: P1-07 P1-09 P1-10 P1-11 P6-04 P6-05 P3-05
Wave 2  P1-03 → P1-04 P1-05 P1-06 | P1-08
Wave 3  P1-12 | specs: P2-01 P2-03 P2-07 | schema: P2-09
Wave 4  P2-02 P2-04 P2-05 P2-06 P2-08 P2-10 P2-11 P2-12 | P6-01
Wave 5  P3-01..04 P3-06 | P4-01..04 | P6-02 P6-03
Wave 6  P5-01..05 → tag spec-1.0.0
```

Rust lands first in each SDK-touching package because the testkit and difftest use it as the oracle; the three ports then run in parallel.

## 12. Definition of "flagship"

- [ ] No fail-open path: unknown action, eval-time regex failure, unresolvable extends, unverified signature, unknown condition block all deny.
- [ ] Spec and reference evaluator agree on every MUST; each MUST has a published vector.
- [ ] Same policy → same `content_hash` in Rust, TypeScript, Python, Go.
- [ ] Receipt carries policy hash, chain hashes, signature status, actor, recorded rule trace, detection trace, enforcement disposition.
- [ ] Log is tamper-evident and verifiable offline with `h2h log verify`.
- [ ] Policies are signed, verified on load in all SDKs, and pinned by digest across `extends`.
- [ ] Controls are structured metadata; `h2h report` produces per-control evidence from receipts.
- [ ] Library policies each have a control-tagged test suite that runs in CI.
- [ ] Conformance bundle, levels 0–5, and report schema published on every release; testkit on crates.io.
- [ ] Every SDK is installable from its registry from a clean environment; Go module resolves.
- [ ] Spec 1.0 frozen with grammars, registries, security considerations, and a change process.
