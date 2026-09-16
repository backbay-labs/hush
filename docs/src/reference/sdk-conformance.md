# SDK Conformance Matrix

This matrix captures the current SDK status on `main` against the
[conformance levels](conformance.md). It is intentionally strict: an SDK gets
credit for a level only once it runs that level's vectors and passes them, not
because it exposes the relevant API. A level is claimed only when every level
below it also passes.

Every claim below names the test file that executes the vectors, so the table
can be checked against the tree rather than taken on trust.

## Current Status

| SDK | L0 Parser | L1 Validator | L2 Merger | L3 Evaluator | L4 Auditor | L5 Attested | Highest |
|-----|-----------|--------------|-----------|--------------|------------|-------------|---------|
| Rust | Yes | Yes | Yes | Yes | Yes | Yes | **5** |
| TypeScript | Yes | Yes | Yes | Yes | Yes | Yes | **5** |
| Python | Yes | Yes | Yes | Yes | Yes | Yes | **5** |
| Go | Yes | Yes | Yes | Yes | Yes | Yes | **5** |

All four SDKs run every vector family the six levels require, including the
bundle vectors and the `.expect.yaml` error-code sidecars.

Two qualifications, neither of which changes the level:

- **Python** reaches Levels 4 and 5 only with the optional `signing` extra
  installed (`pip install "hushspec[signing]"`). Without `cryptography`, the
  signature, receipt-signing and bundle entry points raise `SigningUnavailable`
  rather than reporting an unverified signature as good, and their vector
  runners skip (`pytest.importorskip` in
  [`tests/test_bundle_vectors.py`](https://github.com/backbay-labs/hush/blob/main/packages/python/tests/test_bundle_vectors.py)).
  Failing closed and skipping is the honest behaviour; a Level 5 claim requires
  the extra.
- **Rust** reaches Level 5 only with the `signing` Cargo feature. It is off by
  default and on for `cargo test --workspace`, because `hushspec-cli` depends on
  `hushspec` with `features = ["signing"]` and the workspace unifies features.

## What each SDK runs

Paths are relative to the repository root.

### Levels 0-3: the document corpus

Every runner walks the same sixteen directories -- `{core,posture,origins,detection}/{valid,invalid,evaluation,merge}`.

| SDK | Runner | Notes |
|---|---|---|
| Rust | `crates/hushspec-testkit/src/runner.rs`, driven by `hushspec-testkit --fixtures fixtures --report report.json` | Also discovers `fixtures/library/` suites |
| TypeScript | [`packages/hushspec/tests/shared-fixtures.test.ts`](https://github.com/backbay-labs/hush/blob/main/packages/hushspec/tests/shared-fixtures.test.ts) | `validDirs` / `invalidDirs` / `mergeDirs` / `evaluationDirs` |
| Python | [`packages/python/tests/test_shared_fixtures.py`](https://github.com/backbay-labs/hush/blob/main/packages/python/tests/test_shared_fixtures.py) | `VALID_DIRS` / `INVALID_DIRS` / `MERGE_DIRS` / `EVALUATION_DIRS` |
| Go | [`packages/go/hushspec/fixtures_test.go`](https://github.com/backbay-labs/hush/blob/main/packages/go/hushspec/fixtures_test.go) | `validFixtureDirs` / `invalidFixtureDirs` / `mergeFixtureDirs` / `evaluationFixtureDirs` |

### Levels 4 and 5: the evidence chain

| Vector family | Level | Rust | TypeScript | Python | Go |
|---|:--:|---|---|---|---|
| `fixtures/core/hash/` (15) | 4 | `crates/hushspec/tests/canonical_vectors.rs` | `tests/canonical-vectors.test.ts` | `tests/test_canonical_vectors.py` | `canonical_vectors_test.go` |
| `fixtures/core/resolve/` | 4 | `crates/hushspec/tests/resolve_vectors.rs` | `tests/resolve-vectors.test.ts` | `tests/test_resolve_vectors.py` | `resolve_vectors_test.go` |
| `fixtures/receipts/{valid,invalid}/` | 4 | `crates/hushspec/tests/receipt.rs` | `tests/receipt-vectors.test.ts` | `tests/test_receipt_vectors.py` | `receipt_vectors_test.go` |
| `fixtures/receipts/expected/` | 4 | `crates/hushspec/tests/receipt_expected.rs` | `tests/receipt-vectors.test.ts` | `tests/test_receipt_vectors.py` | `receipt_expected_test.go` |
| `fixtures/signing/vectors.yaml` (17) | 5 | `crates/hushspec/tests/signing_vectors.rs` | `tests/signing-vectors.test.ts` | `tests/test_signing_vectors.py` | `signing_vectors_test.go` |
| Verify-on-load, `receipt.policy.signature` | 5 | `crates/hushspec/src/{resolve,guard}.rs` tests | `tests/verify-load.test.ts`, `tests/guard-evidence.test.ts` | `tests/test_verify_on_load.py`, `tests/test_guard_evidence.py` | `resolve_verify_test.go`, `guard_test.go` |
| `fixtures/log/{valid,invalid}/`, break identified by line | 5 | `crates/hushspec/tests/log_chain.rs` | `tests/log.test.ts` | `tests/test_log.py` | `log_test.go` |
| `fixtures/receipts/signed/{valid,invalid}/` | 5 | `crates/hushspec/tests/receipt_signing.rs` | `tests/receipt-signing.test.ts` | `tests/test_receipt_signing.py` | `receipt_vectors_test.go` |
| `fixtures/bundle/vectors.yaml` (8) | 5 | `crates/hushspec/tests/bundle_vectors.rs` | `tests/bundle-vectors.test.ts` | `tests/test_bundle_vectors.py` | `bundle_vectors_test.go` |

The invalid-log vectors are named `<what>-line-<n>.jsonl`, and each runner
parses `n` out of the file name and asserts the break is reported on exactly
that line -- spec section 8 Level 5 requires the verifier to say *where* the
chain breaks, not only that it does.

## Error codes at Level 1

All four fixture runners assert the registered error code, not merely that
the vector was rejected. Each `fixtures/<module>/invalid/<name>.yaml` has a
`<name>.expect.yaml` sidecar naming a code from
[`spec/registries/error-codes.yaml`](https://github.com/backbay-labs/hush/blob/main/spec/registries/error-codes.yaml)
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

## CI Evidence

The main CI workflow publishes the evidence this table relies on:

- [`generated-sources`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) checks that schema-derived validator contracts, generated Rust/Python/Go model code, the embedded CLI and testkit schemas, and `fixtures/MANIFEST.json` are all up to date.
- [`rust`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml), [`typescript`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml), [`python`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml), and [`go`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) run each SDK's native unit and package tests, including every evidence-chain vector listed above.
- [`shared-fixtures`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) runs the same conformance fixture corpus against Rust, TypeScript, Python, and Go.
- [`cross-sdk-roundtrip`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) round-trips the shared corpus through all four SDKs and compares the normalized outputs (`scripts/check_cross_sdk_roundtrip.py`).
- [`differential-fuzz`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) runs `hushspec-difftest` over 500 generated policy groups per commit, comparing each port against the Rust oracle on decision, `matched_rule`, `reason`, recorded rule trace, canonical `content_hash` **and** receipt hash.
- [`smoke-snippets`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) executes the marked README and getting-started examples directly from the markdown source.
- [`docs`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) builds the mdBook site.

The workflow definition itself lives in
[`/.github/workflows/ci.yml`](https://github.com/backbay-labs/hush/blob/main/.github/workflows/ci.yml).

To publish a conformance claim for an implementation of your own, use the
[Conformance Statement](conformance-statement.md) template. For the entry-point
names each SDK publishes and the contract they share, see the
[SDK API Contract](sdk-api.md).
