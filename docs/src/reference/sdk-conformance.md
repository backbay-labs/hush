# SDK Conformance Matrix

This matrix captures the current SDK status on `main` against the
[conformance levels](conformance.md). It is intentionally strict: an SDK gets
credit for a level only once it runs that level's vectors and passes them, not
because it exposes the relevant API. A level is claimed only when every level
below it also passes.

## Current Status

| SDK | L0 Parser | L1 Validator | L2 Merger | L3 Evaluator | L4 Auditor | L5 Attested | Highest |
|-----|-----------|--------------|-----------|--------------|------------|-------------|---------|
| Rust | Yes | Yes | Yes | Yes | Yes | Yes | **5** |
| TypeScript | Yes | Yes | Yes | Yes | Yes | No | **4** |
| Python | Yes | Yes | Yes | Yes | Yes | No | **4** |
| Go | Yes | Yes | Yes | Yes | Yes | No | **4** |

### What each SDK runs

| SDK | Vectors run | Evidence |
|---|---|---|
| Rust | The whole corpus. `hushspec-testkit --fixtures fixtures --report report.json` runs levels 0-3 from the document vectors and levels 4-5 from the evidence vectors, and reports `highest_level: 5`. | [`rust`], [`shared-fixtures (rust)`], [`cross-sdk-roundtrip`] |
| TypeScript | `shared-fixtures.test.ts` (valid, invalid, merge, evaluation), `canonical-vectors`, `resolve-vectors`, `receipt-vectors` including `receipts/expected/`, `signing-vectors`, `verify-load`, `receipt-signing`, `log`. Not run: `fixtures/bundle/`. | [`typescript`], [`shared-fixtures (typescript)`], [`cross-sdk-roundtrip`] |
| Python | `test_shared_fixtures.py`, `test_canonical_vectors`, `test_resolve_vectors`, `test_receipt_vectors` including `receipts/expected/`, `test_signing_vectors`, `test_verify_on_load`, `test_receipt_signing`, `test_log`. Not run: `fixtures/bundle/`. | [`python`], [`shared-fixtures (python)`], [`cross-sdk-roundtrip`] |
| Go | `fixtures_test.go`, `canonical_vectors_test.go`, `resolve_vectors_test.go`, `receipt_vectors_test.go`, `receipt_expected_test.go`, `signing_vectors_test.go`, `resolve_verify_test.go`, `log_test.go`. Not run: `fixtures/bundle/`. | [`go`], [`shared-fixtures (go)`], [`cross-sdk-roundtrip`] |

### Where the three ports fall short of Level 5

**Bundle verification is the only blocker.** Level 5 requires a verifier that
returns the expected outcome for every case in `fixtures/bundle/vectors.yaml`
(bundle spec section 5.4). TypeScript, Python and Go have no bundle module at
all: policy bundles are created and verified by `h2h bundle` and the Rust
`hushspec::bundle` API only. Everything else Level 5 asks for — the signing
verifier over all 16 signing vectors, verify-on-load with the outcome recorded
in `receipt.policy.signature`, the hash-linked log rejected at the named line,
and receipt signing — is implemented and exercised in all three.

### Where all three ports fall short at Level 1

Their validators do not emit the codes of
[`spec/registries/error-codes.yaml`](https://github.com/backbay-labs/hush/blob/main/spec/registries/error-codes.yaml),
so their fixture runners require only that each `invalid/` vector is rejected,
not that it is rejected with the code its `.expect.yaml` sidecar names. This
does **not** cost them Level 1 — the specification requires the registered code
only of implementations that report codes at all — but it does mean a refusal
for the wrong reason would currently pass in those three suites. Only the Rust
testkit asserts the code today. Closing this is
[RFC 09](https://github.com/backbay-labs/hush/blob/main/docs/plans/09-compliance-as-code-plan.md)
package P6-03; when it lands, the sidecar codes become enforced everywhere and
this note goes away.

[`rust`]: https://github.com/backbay-labs/hush/actions/workflows/ci.yml
[`typescript`]: https://github.com/backbay-labs/hush/actions/workflows/ci.yml
[`python`]: https://github.com/backbay-labs/hush/actions/workflows/ci.yml
[`go`]: https://github.com/backbay-labs/hush/actions/workflows/ci.yml
[`shared-fixtures (rust)`]: https://github.com/backbay-labs/hush/actions/workflows/ci.yml
[`shared-fixtures (typescript)`]: https://github.com/backbay-labs/hush/actions/workflows/ci.yml
[`shared-fixtures (python)`]: https://github.com/backbay-labs/hush/actions/workflows/ci.yml
[`shared-fixtures (go)`]: https://github.com/backbay-labs/hush/actions/workflows/ci.yml
[`cross-sdk-roundtrip`]: https://github.com/backbay-labs/hush/actions/workflows/ci.yml

## CI Evidence

The main CI workflow publishes the evidence this table relies on:

- [`generated-sources`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) checks that schema-derived validator contracts, generated Rust/Python/Go model code, the embedded CLI and testkit schemas, and `fixtures/MANIFEST.json` are all up to date.
- [`rust`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml), [`typescript`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml), [`python`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml), and [`go`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) run each SDK’s native unit and package tests, including the evidence-chain vectors listed above.
- [`shared-fixtures`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) runs the same conformance fixture corpus against Rust, TypeScript, Python, and Go.
- [`cross-sdk-roundtrip`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) round-trips the shared corpus through Rust, TypeScript, Python, and Go and compares the normalized outputs.
- [`smoke-snippets`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) executes the marked README and getting-started examples directly from the markdown source.
- [`docs`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) builds the mdBook site.

The workflow definition itself lives in
[`/.github/workflows/ci.yml`](https://github.com/backbay-labs/hush/blob/main/.github/workflows/ci.yml).

To publish a conformance claim for an implementation of your own, use the
[Conformance Statement](conformance-statement.md) template.
