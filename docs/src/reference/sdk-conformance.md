# SDK features and conformance evidence

The v1 SDKs implement the same policy semantics and evidence formats, with
language-specific APIs and lifecycle behavior. This page separates **available
features** from a **conformance claim**: a feature table or a passing example
does not certify an engine.

## Language guides

Start with a complete, tested program: [Rust](../guides/sdks/rust.md),
[TypeScript](../guides/sdks/typescript.md), [Python](../guides/sdks/python.md),
or [Go](../guides/sdks/go.md). For return types and every public API family,
see the [SDK API contract](sdk-api.md).

## Feature matrix

| Capability | Rust | TypeScript | Python | Go |
|---|---|---|---|---|
| Parse, validate, resolve, compile and evaluate | Yes | Yes | Yes | Yes |
| Guards, actors, receipts and sinks | Yes | Yes | Yes | Yes |
| File reload and policy polling | Yes | Yes | Yes | Yes |
| HTTPS policy provider | `http` feature | Yes | Yes | Yes |
| Policy/receipt signing and bundle verification | `signing` feature | Yes | `signing` extra | Yes |
| Bundle creation | Yes / CLI | CLI | CLI | CLI |
| Structural MCP, OpenAI and Anthropic adapters | Own guard boundary | Yes | Yes | Yes |
| LangChain adapter | Own guard boundary | Yes | Yes | Own guard boundary |
| CrewAI decorator | Own guard boundary | Own guard boundary | Yes | Own guard boundary |
| Governance lint and aggregate reporting | Rust / CLI | CLI | CLI | CLI |

Framework adapters do not establish server identity or contain unmediated
side effects. See [MCP dispatch](../guides/integrations/mcp.md).

## Current status

The immutable [v1.0.0 source](https://github.com/backbay-labs/hush/tree/e771ec647b7f26a0a09ff852886eb8a91093bc58)
contains L0-L5 vector runners for all four SDKs. Use the exact commit's
[CI checks](https://github.com/backbay-labs/hush/commit/e771ec647b7f26a0a09ff852886eb8a91093bc58/checks)
and saved conformance report to assess a specific candidate. This page is a
test-surface inventory, not an independent certification or an assertion that
another engine implements these levels.

A claim names its implementation revision, corpus digest, requested level,
feature configuration, complete result and execution attempt. Higher levels
include the lower-level contracts; skipping a required vector is not a pass.

## SDK-specific notes

### Rust SDK

L5 requires the `signing` Cargo feature. `cargo test --workspace` enables it
through the CLI dependency and Cargo feature unification; a standalone library
consumer must request it explicitly. HTTPS and OTLP have separate features.

### TypeScript SDK

Node.js 18 or newer is the SDK runtime floor. Provider watchers must be stopped
by their owner. Synchronous re-entry from a confirmation handler or sink is
rejected; post-recording observers may re-enter.

### Python SDK

L5 signing and bundle tests require `pip install "hushspec[signing]"`.
Unsigned canonicalization and receipts at L4 do not require `cryptography`.
Missing signing support raises `SigningUnavailable`; skipped signing tests
cannot support an L5 claim. Close guards and stop watchers/pollers.

### Go SDK

Go 1.22 or newer is required. Branch on both the `Check` error and
`GuardDecision.Allowed()`; `Evaluate` alone does not dispatch or stop a tool.
Cancel and close the provider loops your application owns.

## What each SDK runs

Paths are relative to the repository root.

### Levels 0-3: the document corpus

Every runner walks the same sixteen directories -- `{core,posture,origins,detection}/{valid,invalid,evaluation,merge}`.

| SDK | Runner | Notes |
|---|---|---|
| Rust | `crates/hushspec-testkit/src/runner.rs`, driven by `hushspec-testkit --fixtures fixtures --report report.json` | Also discovers `fixtures/library/` suites |
| TypeScript | [`packages/hushspec/tests/shared-fixtures.test.ts`](https://github.com/backbay-labs/hush/blob/e771ec647b7f26a0a09ff852886eb8a91093bc58/packages/hushspec/tests/shared-fixtures.test.ts) | `validDirs` / `invalidDirs` / `mergeDirs` / `evaluationDirs` |
| Python | [`packages/python/tests/test_shared_fixtures.py`](https://github.com/backbay-labs/hush/blob/e771ec647b7f26a0a09ff852886eb8a91093bc58/packages/python/tests/test_shared_fixtures.py) | `VALID_DIRS` / `INVALID_DIRS` / `MERGE_DIRS` / `EVALUATION_DIRS` |
| Go | [`packages/go/hushspec/fixtures_test.go`](https://github.com/backbay-labs/hush/blob/e771ec647b7f26a0a09ff852886eb8a91093bc58/packages/go/hushspec/fixtures_test.go) | `validFixtureDirs` / `invalidFixtureDirs` / `mergeFixtureDirs` / `evaluationFixtureDirs` |

The raw-source corpus is a separate shared runner because ordinary document
discovery cannot preserve scalar spelling:

| Vector family | Levels | Rust | TypeScript | Python | Go |
|---|:--:|---|---|---|---|
| `fixtures/core/raw-yaml/scalars.json` | Parser/evaluator/canonical checks | `hushspec-testkit::raw_yaml` report runner and `tests/raw_yaml.rs` | `tests/raw-yaml.test.ts` | `tests/test_raw_yaml.py` | `raw_yaml_test.go` |

### Levels 4 and 5: the evidence chain

| Vector family | Level | Rust | TypeScript | Python | Go |
|---|:--:|---|---|---|---|
| `fixtures/core/hash/` (16) | 4 | `crates/hushspec/tests/canonical_vectors.rs` | `tests/canonical-vectors.test.ts` | `tests/test_canonical_vectors.py` | `canonical_vectors_test.go` |
| `fixtures/core/resolve/` | 4 | `crates/hushspec/tests/resolve_vectors.rs` | `tests/resolve-vectors.test.ts` | `tests/test_resolve_vectors.py` | `resolve_vectors_test.go` |
| `fixtures/receipts/{valid,invalid}/` | 4 | `crates/hushspec/tests/receipt.rs` | `tests/receipt-vectors.test.ts` | `tests/test_receipt_vectors.py` | `receipt_vectors_test.go` |
| `fixtures/receipts/expected/` | 4 | `crates/hushspec/tests/receipt_expected.rs` | `tests/receipt-vectors.test.ts` | `tests/test_receipt_vectors.py` | `receipt_expected_test.go` |
| `fixtures/signing/vectors.yaml` (18) | 5 | `crates/hushspec/tests/signing_vectors.rs` | `tests/signing-vectors.test.ts` | `tests/test_signing_vectors.py` | `signing_vectors_test.go` |
| Verify-on-load, `receipt.policy.signature` | 5 | `crates/hushspec/src/{resolve,guard}.rs` tests | `tests/verify-load.test.ts`, `tests/guard-evidence.test.ts` | `tests/test_verify_on_load.py`, `tests/test_guard_evidence.py` | `resolve_verify_test.go`, `guard_test.go` |
| `fixtures/log/{valid,invalid}/`, break identified by line | 5 | `crates/hushspec/tests/log_chain.rs` | `tests/log.test.ts` | `tests/test_log.py` | `log_test.go` |
| `fixtures/log/schema-vectors.json` | 5 | `hushspec-testkit::log_schema` report runner and `tests/log_chain.rs` | `tests/log.test.ts` | `tests/test_log.py` | `log_test.go` |
| `fixtures/receipts/signed/{valid,invalid}/` | 5 | `crates/hushspec/tests/receipt_signing.rs` | `tests/receipt-signing.test.ts` | `tests/test_receipt_signing.py` | `receipt_vectors_test.go` |
| `fixtures/bundle/vectors.yaml` (10) | 5 | `crates/hushspec/tests/bundle_vectors.rs` | `tests/bundle-vectors.test.ts` | `tests/test_bundle_vectors.py` | `bundle_vectors_test.go` |

The invalid-log vectors are named `<what>-line-<n>.jsonl`, and each runner
parses `n` out of the file name and asserts the break is reported on exactly
that line -- spec section 8 Level 5 requires the verifier to say *where* the
chain breaks, not only that it does.

## Error codes at Level 1

All four fixture runners assert the registered error code, not merely that
the vector was rejected. Each `fixtures/<module>/invalid/<name>.yaml` has a
`<name>.expect.yaml` sidecar naming a code from
[`spec/registries/error-codes.yaml`](https://github.com/backbay-labs/hush/blob/e771ec647b7f26a0a09ff852886eb8a91093bc58/spec/registries/error-codes.yaml)
and an optional `message_contains` substring; the runners compare both.

| SDK | Where the code is asserted | Where the code comes from |
|---|---|---|
| Rust | `crates/hushspec-testkit/src/{expect,runner}.rs` | `hushspec_testkit::expect::validation_error_code`; `h2h validate --format json` derives the same codes in `crates/hushspec-cli/src/cmd_validate.rs` |
| TypeScript | `tests/shared-fixtures.test.ts` (`loadSidecar`, compares `refusal.code`) | `ParseResult.code` and `ValidationError.code`, typed by `ErrorCode` |
| Python | `tests/test_shared_fixtures.py` (`_expected_rejection`) | `hushspec.ERROR_CODES` and the `ErrorMessage.code` / `ValidationError.code` members |
| Go | `tests/fixtures_test.go` (`loadExpectedError`, checks the code is in `ErrorCodes`) | `hushspec.ErrorCodes`, `hushspec.ErrorCodeOf`, `ValidationError.Code` |

One asymmetry worth naming: the Rust **library** does not carry the code table.
`hushspec::ValidationError` is a typed enum, and the mapping to `E00x` lives in
`hushspec-testkit` and in the CLI. Core spec section 8 Level 1 is satisfied --
the implementations that report codes report the registered ones -- but a Rust
embedder wanting the code must map the enum itself or use the testkit helper.
The other three expose the codes directly. See
[SDK API Contract](sdk-api.md) for the exact spellings.

## Supplemental SDK integration corpus

`fixtures/adapters/mcp-contract.json` is an inventoried `integration` corpus,
run by the TypeScript, Python, and Go SDK adapter tests. It checks framework
tool-call mapping, not core policy parsing, evaluation, audit, or attestation.
It is deliberately unscored by the conformance report and cannot raise or
lower a core conformance level. Rust supplies no framework adapters; that is
not a missing Rust core-engine conformance requirement.

## CI configuration and qualification evidence

The workflow defines the following test surfaces. It runs on pushes to `main`
and pull requests without a base-branch filter. Its reusable form accepts an
optional `ref` and every checkout uses that supplied ref when present. The
checks attached to an exact commit are the hosted qualification record; this
page does not duplicate or predict their status.

- [`generated-sources`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) checks that schema-derived validator contracts, generated Rust/Python/Go model code, the embedded CLI and testkit schemas, and `fixtures/MANIFEST.json` are all up to date.
- [`rust`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml), [`typescript`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml), [`python`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml), and [`go`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) run each SDK's native unit and package tests, including every evidence-chain vector listed above.
- [`shared-fixtures`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) runs the same conformance fixture corpus against Rust, TypeScript, Python, and Go.
- [`cross-sdk-roundtrip`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) parses the shared corpus with all four SDKs and compares each document's canonical form byte for byte (`scripts/check_cross_sdk_roundtrip.py`).
- [`differential-fuzz`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) runs `hushspec-difftest` over 500 generated policy groups per commit, comparing each port against the in-process evaluator on decision, `matched_rule`, `reason`, recorded rule trace, canonical `content_hash` **and** receipt hash.
- [`smoke-snippets`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) executes the classified and marked documentation examples directly from the markdown source.
- [`docs`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) builds the mdBook site.

The workflow definition itself lives in
[`/.github/workflows/ci.yml`](https://github.com/backbay-labs/hush/blob/e771ec647b7f26a0a09ff852886eb8a91093bc58/.github/workflows/ci.yml).

To publish a conformance claim for an implementation of your own, use the
[Conformance Statement](conformance-statement.md) template after recording the
exact SHA, all required hosted attempts, and independent contract coverage. For
the entry-point names each SDK publishes and the contract they share, see the
[SDK API Contract](sdk-api.md).
