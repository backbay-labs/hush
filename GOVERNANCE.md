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
audit`, and `h2h audit` is currently advisory only: it reports findings but always exits
`0`. It does not gate merges in this repository. Making it enforceable is tracked as an
open RFC under [`docs/plans/`](./docs/plans/).

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
the `0.x` series permits breaking changes between minor versions; patch versions
(`0.1.0` -> `0.1.1`) are non-breaking, editorial/errata-only changes. SDK and CLI
package version numbers are independent of the specification version they implement --
there is no coupling between "HushSpec 0.1.0" and, say, "`@hushspec/core` 0.1.1".

## Errata

There is not yet a formalized errata submission process (defining one, along with a
security-considerations section and stable registries, is tracked as an open RFC under
[`docs/plans/`](./docs/plans/)). Until then, treat a spec/implementation divergence or
an ambiguous normative sentence as a bug: open an issue or a pull request against
`spec/` describing the divergence and the proposed clarification. Errata-level fixes
(patch versions) must not change document validity or evaluation semantics for
previously-valid documents; anything that would is a breaking (minor-version) change and
needs an RFC.

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
