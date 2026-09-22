# Hush repair review

Review date: 2026-09-22. Baseline: `a0637cbe9d2ceb65a6865bb35d8ee4f0af5f2f1b`.
Candidate: the complete uncommitted `wave-6` working tree, including untracked source, vectors, and documentation. This is a review for committing and hosted qualification, not merge or release approval.

The review is read-only apart from this report. Source inspection included the four raw parsers and timestamp paths, Python decorators and MCP mappings, HTTP provider/poller/deadline handling, four log validators, independent log-vector generator, testkit/report integration, schemas, workflows, and delivery/review ledgers. Existing implementation reports supplied context but did not substitute for source inspection. Full suites are coordinated by the root agent and are not duplicated here.

## Behaviors considered but not judged

- Hosted CI execution, GitHub permissions, registry resolution, installation from public registries, and actual release publication: these require the eventual committed candidate and later authorized operations. Workflow source can establish wiring, not successful hosted execution.
- Every historical review thread and original RFC acceptance criterion: the cumulative reconciliation ledger was inspected for its state boundaries, but this pass did not independently re-audit all historical implementations. The root retains exact-head thread disposition responsibility.
- Frozen v0 schema redesign, missing enterprise governance/providers, and additional framework adapters: these are explicitly outside the repaired release scope. No v0 schema change was observed.
- All possible Unicode/custom-object framework argument behavior and arbitrary custom mapper correctness: the integration contract covers named mappings and typed mapper outputs; a caller-supplied mapper still owns the meaning of its operation.
- Cryptographic verification guarantees from the 471 schema mutations alone: the generator intentionally tests envelope structure without key material. Existing signature and signed-log vectors remain the cryptographic oracle.
- Pending text in the delivery ledger while full suites finish: this is expected coordination state, not a source defect. It must be refreshed before the final commit.

## Findings discovered and closed during review

No Critical finding. The following Important issues were reported immediately to the coordinator, repaired by their implementation owners, and reviewed again. All are now closed. Line references describe the source at discovery and may move during repair.

### Important: explicit YAML tags still escape the portable scalar contract

`packages/python/hushspec/parse.py:134-146` replaced implicit resolvers and integer/float constructors but retained PyYAML's boolean, null, and timestamp constructors. `packages/hushspec/src/parse.ts:59-74` allowed unresolved explicit tags to become warnings/fallback values and allowed the library's known timestamp tag.

Reproduced through the public parsers using `hushspec: "1.0.0"` and `rules.egress.when.context.x: TOKEN`:

| Token | Python | TypeScript |
|---|---|---|
| `!!bool yes` | boolean `true` | string `"yes"` |
| `!!null garbage` | null | string `"garbage"` |
| `!!bool bananas` | uncaught `KeyError` | string `"bananas"` |
| `!!timestamp 2020-01-01` | accepted `datetime.date` | accepted Date, canonically projected as `{}` |
| `!thing 010` | rejected | string `"010"` |
| `!!float 010` | numeric 10 | string `"010"` |

In a boolean field, `enabled: !!bool yes` is accepted by Python and rejected by TypeScript. Go's new normalizer explicitly rejects unsupported tags and invalid boolean tag values. This is still the original raw-byte portability defect at a different spelling boundary. Required closure: an explicit supported-tag contract, invalid/non-Core-tag refusal, and shared positive/negative tag vectors across all four SDKs.

Closure: the final parser source validates explicit scalar tags and their content, rejects non-Core tags, preserves the non-specific scalar tag's string meaning, and rejects Go custom collection tags. The owner independently reproduced the collection cases before repair. The shared corpus now has 86 cases, including the reported tag failures and nested condition-context fractions/large finite doubles. Final owner-reported focused runs passed all 86 cases in every SDK; TypeScript lint passed. The reviewer inspected the final guards and corpus.

### Important: provider lifecycle repairs leave late adoption and stale-state revival

First boundary: `packages/hushspec/src/policy-provider.ts:228` unconditionally assigned the resolution of `poller.start()` into provider state. Reproduction: replace `loadRemoteSpec` with a deferred promise; call `watch()`, then `stop()` before completion; resolve a snapshot named `stopped-result`; wait one microtask turn. `current()` became that policy and `resolution()` remained null, although no `onChange` fired. The poller's lifecycle check did not protect the provider's separate continuation.

Second boundary: `packages/hushspec/src/poller.ts:102` initialized a seeded snapshot's `lastSuccessfulLoad` to `Date.now()`. Reproduction: provider options `{maxStaleMs: 10, intervalMs: 10000}`; load once, watch, wait 25 ms; `current()` correctly throws stale. Calling `watch()` again makes the same policy immediately available with no successful network refresh. Restarting observation must not renew the age of accepted policy data.

Required closure: provider continuation identity/lifecycle checks and preservation of the last accepted successful-load timestamp across watch restarts, including stop/restart regressions.

Closure: provider continuations check the active poller identity. Seeded snapshots carry the accepted load time, and retiring a poller transfers its latest successful refresh time, including unchanged successful responses. This also closes the intermediate repair's false-staleness regression after healthy unchanged polls. The coordinator additionally authorized closing the pre-existing throwing-startup-reporter path; its detached continuation now contains reporter exceptions. The reviewer independently reran the four focused regressions for stale rewatch, healthy unchanged rewatch, reporter recovery, and deferred stop/restart: all four passed. The owner's complete HTTP/watcher selection passed 77 tests.

### Important: Python timezone conversion can throw outside fail-closed parsing

`packages/python/hushspec/conditions.py:807-811` caught datetime construction errors but performed `astimezone()` outside the catch. `_parse_runtime_timestamp("0001-01-01T00:00:00+01:00")` and `"9999-12-31T23:00:00-02:00"` both raised `OverflowError: date value out of range` rather than returning an unevaluable time. The boundary is rare but falls directly within the repaired strict-time contract.

Required closure: catch representability errors throughout conversion and add shared lower/upper UTC-boundary vectors so all SDKs fail closed consistently.

Follow-up reproductions extended this same finding: final configured-zone conversion also overflowed for year 0001 in `America/New_York` and year 9999 in `Asia/Tokyo`; Rust rejected a valid zoneless fraction such as `2026-01-01T20:00:00.123` while Python accepted it.

Closure: all SDKs now check both the UTC and configured-zone year bounds. Python contains conversion exceptions, TypeScript checks the Gregorian era as well as the formatted year, and Rust's zoneless fallback accepts fractions using `%.f`. The reviewer independently repeated all four Python overflow inputs and got `None`; the valid fraction resolves to 20:00. Repeating the Rust CLI egress reproduction now yields Allow with the time condition inactive. The owner reported all 25 shared condition cases passing in the four SDKs, with TypeScript/Python focused selections of 552/450 tests.

### Important: raw parse failures can still produce a passing Level 0 report

`crates/hushspec-testkit/src/raw_yaml.rs:133-157` emitted acceptance mismatches as `expected acceptance: ...` and `expected rejection but parsed successfully`. `report.rs:265-277` counts Level 0 failures only when Level 1 failure messages contain `runner::PARSE_FAILURE_PREFIX` (`Parse failed: `). Consequently a forbidden raw input accepted by the parser, or a required raw input rejected by it, fails Level 1 but is counted as a Level 0 pass and can leave `highest_level` at 0.

Required closure: classify raw acceptance mismatches as parser failures, preserve decoded-value-only failures at Level 1, and add report-level regressions that check those distinct outcomes. Missing/malformed raw corpora should not establish parser success either.

Closure: `VectorResult` carries a structured internal `parser_failure` flag, omitted from the serialized report contract. Raw acceptance mismatches and malformed corpora set it; decoded-value failures do not. Level 0 now uses that flag. The reviewer inspected the report-level mutation test, including malformed corpus and value-only distinctions, and the owner's terminal focused pass evidence. Array-index traversal in raw `value_path` was also corrected for the new nested-context cases.

## Positive evidence and limits

- Raw YAML is now carried verbatim in a shared JSON corpus and passed directly to each SDK parser. Canonical and decision assertions cover the original `010` bypass; generic finite doubles remain distinct from bounded integer properties.
- Python decorators bind actual invocation arguments, reject unmeasurable tool calls, require explicit mappers for non-tool actions, preserve async functions, and assert denied bodies do not run. The three MCP ports share an inventoried mapping corpus.
- Log mutations are independently sealed with standard sorted compact JSON and SHA-256 on ASCII/small-integer seeds. JSON Schema with date-time format assertions determines expected acceptance; Rust and Python tests independently recheck that oracle. Every SDK checks public verifier outcomes, and testkit includes the cases at Level 5.
- CI removes the stacked-PR base filter, propagates a supplied release SHA to every checkout, packages the Rust workspace together, and selects release artifacts explicitly. The delivery ledger distinguishes implementation, local evidence, hosted qualification, merge, and publication.

## Verification and remaining gates

The reviewer ran public-parser and runtime reproductions before repair, repeated the repaired Python/Rust time paths, ran the four selected current-source provider regressions, inspected final source and focused owner test evidence, and confirmed `git diff --check` passes. The root is running the final complete SDK/workspace, differential, MSRV, package, generator/manifest, and documentation gates on the stable code. Those terminal results must still be checked; focused passes cannot replace them.

The coordinator explicitly ruled actual release execution and registry publication outside current authorization. Hosted CI remains the next qualification step after the eventual commit/push. Final generated artifacts and status text remain coordinator-owned and require the final check.

## Verdict

Code-review pass for the commit-and-hosted-qualification workflow, subject to the required full-tree checks now running. No remaining Critical, Important, or Minor finding from this review blocks that workflow. The repairs now address the seven original findings and the concrete regressions discovered in this pass.

This is not a claim that the final full suites or hosted CI have passed, and is not merge, tag, or publication approval.

## Scoped qualification follow-up: Rust diagnostics and hygiene exception

The root's full checks exposed two diagnostic regressions after checked value-tree decoding: loss of original source locations and changed negative-integer refusal wording. This follow-up reviewed only `positioned_type_error` in `crates/hushspec/src/schema.rs`, its four regressions in `crates/hushspec/tests/parse.rs`, and the additional entry in `scripts/comment-hygiene-allow.txt`.

The checked `serde_yaml::from_value` result remains authoritative. Original-source parsing is consulted only after that result is already an error, and can replace only the diagnostic. Recovery compares the complete refusal reason, with a narrow normalization for negative-integer `invalid value` versus `invalid type` wording.

One Important diagnostic ambiguity was found and closed before this follow-up passed: an earlier Core-valid `max_additions: 010` and later invalid `max_deletions: '010'` produced the same native refusal text, so the initial recovery reported the earlier field at line 4. The reviewer reproduced that through `h2h validate -`. Recovery now additionally requires original and normalized typed-parser error bodies, including field paths, to agree. Repeating the CLI reproduction returns the checked error without the false location. An ambiguous case deliberately retains an unpositioned error rather than attributing it to the wrong field.

The reviewer also repeated the final multiline/Unicode unknown-field example and negative threshold example: they report original lines 6 and 5 respectively. The owner captured the ambiguous-field regression red, then reported all 29 parser tests, all 86 raw vectors, and the existing CLI modeline-location regression passing after the tighter check. The final let-chain cleanup preserves the inspected conditions; clippy and the full remaining qualification gates stay with the root.

The hygiene exception uses the checker's existing exact-file/exact-rule mechanism. Its seven current matches in `sdk-conformance.md` are source URL targets for the unreleased branch; no checker implementation or broader rule changed. Both the hygiene command and `git diff --check` passed in this review.

Scoped verdict: pass, with no remaining Critical, Important, or Minor finding in this follow-up. The main commit-and-hosted-qualification verdict remains unchanged, conditional on the root completing all required gates. No additional approval for release execution or publication is given.

## Scoped dependency follow-up: Vitest 4.1.11

Scope: the user-approved exact `vitest` and `@vitest/coverage-v8` development dependency pins, regenerated npm lockfile, and associated CONTRIBUTING/CHANGELOG wording. No test configuration, provider source, SDK runtime dependency, or runtime engine declaration changed in this delta.

The maintainer's [GHSA-82fw-gwwq-j7x9 advisory](https://github.com/vitest-dev/vitest/security/advisories/GHSA-82fw-gwwq-j7x9) identifies 4.1.11 as patched for both Vitest and its mocker dependency. The lock resolves the runner, coverage provider, and mocker to matching 4.1.11 versions. The reviewer checked manifest/lock agreement and the installed graph with `npm ls`, which exited successfully. All changed dependency records are development-only; the sole other changed lock record is the workspace metadata. The runtime YAML dependency record is unchanged. Every registry record has integrity metadata, and changed registry URLs remain under registry.npmjs.org.

The reviewer independently ran `npm audit --audit-level=moderate`: zero reported vulnerabilities. The owner's Node 24 evidence records clean `npm ci`, build and lint, all 43 files / 2,322 tests passing, and the same 2,322 tests passing under V8 coverage with the existing CI coverage options. Those full tests were not redundantly repeated by this reviewer.

Node 20 execution was not performed locally. CI explicitly selects Node 20; the locked dependency engine ranges support its current 20.x release. One Minor documentation precision correction was requested: CONTRIBUTING should name Node 20.19+ / 22.12+ / 24+, because locked Vite 7.3.6 has a narrower minimum than Vitest itself. This affects contributor setup guidance, not the SDK's retained Node 18 runtime declaration or readiness for the Node 20 CI job.

Acknowledged the root's stale Rust schema-exception removal: `integer-out-of-safe-range.yaml` correctly moved out of the 17-entry beyond-schema exception list now that v1 expresses the integer maximum; the resulting 16-entry list and fixture comment change have no runtime effect, and the root reports all 15 schema-guard tests passing.

Scoped verdict: ready to commit and qualify on Node 20 hosted CI, with no Critical or Important dependency finding. Apply the Minor contributor-version wording correction before commit. Hosted Node 20 success remains an explicit qualification gate, not established by the Node 24 run or engine declarations alone.

## Final local qualification record

After the review, the coordinator completed the full Rust workspace suite (1,025 passed, zero failed, one ignored benchmark), TypeScript suite (2,322 passed), Python suite (3,019 passed, four intentional pre-document skips), and Go suite/vet. TypeScript build, lint, and V8 coverage also passed on Vitest 4.1.11. Full and runtime-only npm audits reported zero vulnerabilities.

The independent dependency review's contributor-version correction is applied: development requires Node 20.19+ / 22.12+ / 24+. The SDK runtime declaration remains Node 18+. Node 20 execution is a hosted gate, not a local claim.

Cross-SDK differential testing passed 500 groups / 2,000 actions with zero divergence. The final conformance report passed all six levels without failures or skips. Clippy, no-default-features, MSRV 1.88, generators, schema guards, policy-library coverage, documentation, Cargo audit/deny, and formatting checks passed. The delivery ledger records these results and the remaining clean-package, exact-commit hosted, integration, and publication boundaries.
