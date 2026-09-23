# Governance

This document describes how changes to the HushSpec specification, schemas, reference
SDKs, and CLI are proposed, reviewed, and released today. It reflects the process
actually in use in this repository, not an aspirational one; where tooling does not yet
enforce something described here, that is called out explicitly.

## Roles

- **Maintainers.** Contributors with write access to `backbay-labs/hush` who can review,
  approve, and merge pull requests, and cut releases. The project is currently maintained
  by the HushSpec Core Team (backbay-labs).
- **Contributors.** Anyone who opens an issue or pull request. No special access is
  required to propose a change.

There is no formal RBAC or identity-provider integration for repository governance today
(`crates/hushspec/src/governance.rs` models policy-document lifecycle metadata, not
repository access control). Enterprise policy-lifecycle governance (author/approver
metadata, separation of duties) is a property of *policy documents* evaluated by `h2h
audit`. Error-severity findings fail the audit even without `--strict`.
`--strict` also fails on failed governance checks, warnings and unresolved control
rule paths. Other advisory findings do not change the default exit status.
These are policy-document checks, not authenticated repository approval or
identity enforcement, and they do not themselves gate merges in this repository.

## How Specification Changes Happen

HushSpec follows a **spec-first, fixture-first** process. The operating rule:

> Every behavior change lands as: ratify prose -> add fixture -> change all four SDKs ->
> difftest. No SDK change without a vector.

Concretely:

1. **Propose.** Non-trivial changes to the specification (`spec/`), schemas
   (`schemas/`), or cross-cutting SDK behavior start as an RFC document under
   `docs/plans/`. The RFCs already in that directory are the model: state the problem,
   the gap in current behavior, the proposed normative change, and the work needed to
   implement it. Small clarifications or obvious bug fixes (e.g. an evaluator diverging
   from already-normative prose) do not require a new RFC -- open a pull request directly
   and explain the discrepancy.
2. **Ratify.** The RFC (or the pull request, for smaller changes) is reviewed by
   maintainers. A change is "ratified" when its normative prose is merged into `spec/` --
   this is the point at which the behavior becomes part of the specification, independent
   of whether every SDK implements it yet.
3. **Fixture before SDK changes.** Before any SDK's evaluator, parser, or validator is
   changed to implement a ratified decision, a test fixture demonstrating the expected
   input/output is added under `fixtures/` (or `fixtures/core/evaluation/` for evaluator
   behavior). The fixture is the executable definition of the new behavior; SDK
   implementations are judged against it.
4. **Implement across SDKs.** Rust lands first -- the conformance testkit and the
   differential fuzzer compare the other SDKs against it -- then TypeScript, Python, and
   Go. A behavior change is not considered complete until all four SDKs pass the same
   fixture and, where applicable, `hushspec-testkit`'s differential fuzzer
   (`hushspec-difftest`) shows no divergence.
5. **No roadmap claim without code.** Status claims in `docs/plans/ROADMAP.md` and
   elsewhere are only checked off in the same pull request that ships the code and its
   test. See the 2026-09-14 correction to `docs/plans/ROADMAP.md` for what this looks
   like in practice.

## Versioning

Specification version numbers follow [`spec/versioning.md`](./spec/versioning.md):
within the `1.x` series a minor version only adds, never removes, renames, or changes a
default or a decision; patch versions (`1.0.0` -> `1.0.1`) are editorial and errata-only
changes; anything that would break an existing document, evaluation, canonical form or
wire format is a major version. SDK and CLI package version numbers are independent of
the specification version they implement -- there is no coupling between "HushSpec 1.0.0"
and, say, "`@hushspec/core` 1.0.2".

## Errata

Errata follow [`spec/errata.md`](./spec/errata.md): file an issue titled
`Erratum: <specification> <section>`, get it numbered `E-<year>-<n>`, and resolve it
with a pull request that changes prose, examples, grammars, or behavior-pinning vectors
only. Errata are folded into patch versions and recorded in the affected specification's
change appendix. A correction that would change document validity, evaluation
semantics, the canonical form, or a wire format is a change proposal, not an erratum.

## Change Proposals

A behavior change is proposed as a document under [`docs/plans/`](./docs/plans/) that
states the new normative text and the vectors that will pin it. It lands in this order:
the vectors and the prose first, then the reference implementations, then the ports;
no SDK changes behavior before a fixture exists for the new behavior
([`CONTRIBUTING.md`](./CONTRIBUTING.md)). What a minor version may and may not change
is defined in [`spec/versioning.md`](./spec/versioning.md), Section 6; anything outside
it is a major version, which additionally requires a migration note and a new schema
line.

## Who Can Merge

Pull requests are merged by maintainers after review. There is currently no
`CODEOWNERS`-enforced routing or required-approver configuration in this repository, and
no author-must-differ-from-approver enforcement (see Roles, above) -- reviewers are
expected to apply that discipline manually until `h2h audit` can gate merges. CI must be
green (`.github/workflows/ci.yml`: generated-sources, per-language unit tests, shared
fixtures across all four SDKs, smoke snippets, cross-SDK roundtrip, differential fuzz,
bench thresholds, docs build) before a pull request is merged.

## Releases

Releases are cut by maintainers from `main` and tagged (e.g. `v0.1.1-alpha`). See
[`CHANGELOG.md`](./CHANGELOG.md) for the release history and
[`CONTRIBUTING.md`](./CONTRIBUTING.md) for the local build/test commands CI runs.
