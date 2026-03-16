# SDK Conformance Matrix

This matrix captures the current SDK status on `main` against the
[conformance levels](conformance.md). It is intentionally strict: an SDK only
gets Level 2 credit once it resolves `extends` and detects inheritance cycles,
not merely because it exposes merge helpers.

## Current Status

| SDK | Level 0 | Level 1 | Level 2 | Level 3 | Notes | Evidence |
|-----|---------|---------|---------|---------|-------|----------|
| Rust | Yes | Yes | Yes | Yes | Rust now provides filesystem-based `extends` resolution with cycle detection, executes the evaluator fixture corpus through the reference evaluator, and publishes structured evaluator outputs. | [`rust`], [`shared-fixtures (rust)`], [`cross-sdk-roundtrip`] |
| TypeScript | Yes | Yes | Yes | No | TypeScript now resolves filesystem-based `extends` chains with cycle detection and participates in the cross-SDK roundtrip corpus. It does not ship a reference evaluator. | [`typescript`], [`shared-fixtures (typescript)`], [`cross-sdk-roundtrip`] |
| Python | Yes | Yes | Yes | No | Python now resolves filesystem-based `extends` chains with cycle detection and participates in the cross-SDK roundtrip corpus. It does not ship a reference evaluator. | [`python`], [`shared-fixtures (python)`], [`cross-sdk-roundtrip`] |
| Go | Yes | Yes | Yes | No | Go now resolves filesystem-based `extends` chains with cycle detection and participates in the cross-SDK roundtrip corpus. It does not ship a reference evaluator. | [`go`], [`shared-fixtures (go)`], [`cross-sdk-roundtrip`] |

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

- [`generated-sources`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) checks that both schema-derived validator contracts and generated Rust/Python/Go model code are up to date.
- [`rust`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml), [`typescript`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml), [`python`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml), and [`go`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) run each SDK’s native unit and package tests.
- [`shared-fixtures`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) runs the same conformance fixture corpus against Rust, TypeScript, Python, and Go.
- [`cross-sdk-roundtrip`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) round-trips the shared corpus through Rust, TypeScript, Python, and Go and compares the normalized outputs.
- [`smoke-snippets`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) executes the marked README and getting-started examples directly from the markdown source.
- [`docs`](https://github.com/backbay-labs/hush/actions/workflows/ci.yml) builds the mdBook site.

The workflow definition itself lives in
[`/.github/workflows/ci.yml`](https://github.com/backbay-labs/hush/blob/main/.github/workflows/ci.yml).
