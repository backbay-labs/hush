# v1 release-preparation review record

Audited baseline: `5a35dca012dc215a35b5c23c42ae1085018a8f30`, cumulative `wave-6`.
This is release preparation, not a release announcement or merge approval.

## Platform thread audit

A fresh read-only audit fetched every comment and reply in all 39 threads on
PRs #5-10, with complete pagination: 3, 3, 4, 4, 4 and 21 threads respectively.
All 49 cited repair commits are ancestors of the audited candidate. Source
inspection supports 38 addressed findings and one incomplete provenance repair.
All threads remain unresolved on GitHub. Older stack heads do not contain all
cumulative repairs; these dispositions apply to `wave-6`, not those older heads.
The [original per-thread ledger](2026-09-22-reconciliation.md) is retained with
the corrections below, rather than presenting its historical assertions as fresh
test results.

- [Packed branch provenance](https://github.com/backbay-labs/hush/pull/5#discussion_r4025984702):
  the earlier build script skipped nonexistent loose refs. A commit could create
  the ref without changing watched HEAD/packed-refs. New real Cargo/Git tests
  failed in ordinary and linked packed-ref checkouts and pass after watching
  the shared ref tree. The ordinary loose-ref test also passes. The earlier
  claim that committed build-script regressions covered branch movement was
  incorrect at the audited baseline.
- [Rust HTTP provider](https://github.com/backbay-labs/hush/pull/10#discussion_r4030746154):
  source correctly installs the configured locator while preserving overrides.
  Tests cover that wiring, not an end-to-end signed HTTPS provider load.
- Rust compatibility-sidecar tests cover derivation/dispatch seams, not a public
  HTTPS happy-path server. Python, Go and TypeScript have server fallback tests.
- Disabled-audit tests assert output rather than allocations. Rust/Python source
  avoids the trace allocation; the optimization is not established for TS/Go.
- DNS regressions bound callers and retained workers, not native resolver
  cancellation/isolation. The documented shared-pool/retained-slot limits stand.
- The three previously local fixes are committed in `341675a` and `295022c`:
  log scalar/schema constraints, provider bootstrap/sentinel recovery and DNS
  budgets. No additional enforcement/evidence defect was established in the
  other 38 threads. This audit itself did not rerun their tests.

## New release-preparation repairs

The completed [Project B review](2026-09-23-project-b-qualification.md#completed-fresh-review-during-v1-release-closure)
found an additional planning-resource gap outside the old platform threads.
Both oversized-plan regressions failed before the fix and pass locally now;
request accounting, corpus expectations and frozen Core semantics are unchanged.

Release workflow dry runs require a full candidate SHA and matching package
versions, build the existing five CLI targets and use a disposable policy key.
The publication jobs are excluded. Six shell-step tests and three real build
provenance tests pass locally. Actionlint 1.7.12 accepts the workflow; the local
1.7.7 binary incorrectly rejects the valid `macos-15-intel` runner label.
Hosted artifact rehearsal and clean-source packaging remain separate gates.

## Fresh preparation review and repair

A separate reviewer examined the complete release-preparation diff. It found no
Critical issue and one Important issue: the ARM64 Cross container would not
inherit the explicit candidate SHA. The workflow now requests Cross environment
passthrough and verifies executable JSON identity against the full SHA, version
and target. Native platforms execute directly; ARM64 uses Cross/QEMU, not a
native-runner claim. Invocation-contract and wrong-SHA/version/target probes
failed before repair and pass afterward; all eight release workflow tests pass.
Those probes do not replace the actual hosted platform build and execution.

Deferred Minor: the local workflow tests do not simulate GitHub's publisher-job
and production-secret expression guards or checkout-SHA mismatch. The reviewer
inspected these guards; hosted dry-run job outcomes remain required. No second
review is claimed for the repair, which follows the failing/passing regressions.

Local npm tarball and Python wheel installs in fresh isolated directories both
pass allow/deny evaluation and produce the same canonical policy hash. The
Python sdist/wheel builds pass. A fresh optimized first-party Go run qualifies
L3 with 1,375 result slots and passes packet verification; all nine offline
verifier tests pass. Rust clippy, boundary tests, workflow lint and mdBook pass.
The all-features Rust workspace suite completed with zero failures and one
intentional ignored benchmark. The three newer budget-boundary tests also pass
in their separate run. The no-default-features build and Rust 1.88 all-features
workspace build pass. TypeScript passes 2,458 tests with one opt-in Docker skip,
build and lint; Go passes full uncached tests and vet. Python distribution checks
pass after installing the missing local Twine tool into the isolated environment.
These are working-tree checks, not public-registry installation evidence.

## Remaining owner and integration gates

The owner explicitly deferred revocation of the supplied credentials until after
publication. No token values have been placed in source, artifacts or logs.
PyPI trusted publishing, signing-key ownership/public trust anchor, Homebrew
access and Pages/schema-domain availability need confirmation. Repository-secret
names alone do not prove values or organization-level configuration. Main
requires an approving review; there is no authorization to bypass it. No public
tag, registry upload, Homebrew change or release has been made by this work.
