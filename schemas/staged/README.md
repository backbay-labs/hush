# Staged schemas

Schemas under `schemas/staged/<spec version>/` are **normative for that specification version
but not yet emitted by the SDKs**. They mirror the staged-fixture convention in
`fixtures/staged/`: the spec ratifies a format here, the SDKs are brought to it in a later
work package, and the file is then moved over its live counterpart in `schemas/`.

Each staged file keeps the `$id` of the live file it will replace, so consumers that resolve
by `$id` see one identity across the transition. Nothing in CI reads this directory, and the
`h2h schema` command serves only the live schemas.

| Staged schema | Replaces | Spec | Promoted by |
|---|---|---|---|

Why staged rather than replaced in place: the live receipt schema is validated against the
SDKs' *current* output by `crates/hushspec/tests/receipt.rs` and
`crates/hushspec/tests/proptest_roundtrip.rs`, and the 0.2 format is deliberately
incompatible (required `receipt_version`, `sha256:`-prefixed hashes, closed enums).
Replacing it before the SDKs change would turn the suite red for the wrong reason.

Promotion checklist (for the work package that lands the SDK change):

1. `git mv schemas/staged/0.2.0/<file> schemas/<file>`.
2. Update the schema count in `crates/hushspec-cli/tests/schema_guard_tests.rs` and
   `crates/hushspec-cli/tests/command_tests.rs`.
3. `python3 scripts/generate_cli_schemas.py` and commit the regenerated module.
4. Delete this table row; delete this directory when it is empty.
