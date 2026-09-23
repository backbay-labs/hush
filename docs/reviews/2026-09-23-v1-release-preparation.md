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

## First hosted preparation attempts

Candidate `e4726cd9fa57d83cdfc9f94130bd3fe57b62d170` was pushed and cumulative
[PR #11](https://github.com/backbay-labs/hush/pull/11) opened against `main`.
Clean `cargo package --workspace --locked` verified all three extracted Rust
archives with a fresh Cargo home and target directory.

The first rehearsal dispatch, `35885875406`, contained a hand-entered wrong SHA
and failed checkout; all publication jobs skipped. The corrected dispatch,
`35885912049`, selected the actual full SHA but failed the unchanged comment
hygiene gate: a new test fixture used a planning branch name. The original job
log is retained. The local hygiene scan had omitted that then-untracked script;
after commit it reproduced the hosted failure. A generic mutable branch name
preserves the rejection assertion without a planning reference. Later candidate
runs must qualify this correction; these failures are not converted to passes.

## Remaining owner and integration gates

The owner explicitly deferred revocation of the supplied credentials until after
publication. No token values have been placed in source, artifacts or logs.
At the owner's subsequent request, a dedicated production-policy signing key was
generated and stored in the GitHub secret with a matching public repository
variable and an owner-only backup outside the repository. The [public key](../../keys/hushspec-release-2026.pub.pem)
has key ID `sha256:19d582aef8ee788f6742b33c3723ced7f7feade9a73c6a4e8b86bd406bbf706d`.
Local/remote public fingerprints match; a signed default-policy bundle verifies
with the committed public key and re-resolved policy. No private key is committed.

PyPI trusted publishing, Homebrew access and Pages/schema-domain availability
still need confirmation. Repository-secret
names alone do not prove values or organization-level configuration. Main
requires an approving review; the owner subsequently authorized admin merge in
place of that approval. This does not waive unresolved technical findings or
exact-candidate qualification. No public tag, registry upload, Homebrew change
or release has been made by this work.

## Subsequent artifact rehearsal and ordering review

At `2a75cdf00e5f5a6f739c29ce25affd811ff6869a`, both PR CI runs succeeded.
Release rehearsal `35886420607`, attempt 1, passed reusable CI and the bundle job.
Linux x64 and macOS ARM64 builds passed. The ARM Linux smoke step failed; matrix
fail-fast cancelled macOS Intel and Windows. All publication jobs skipped. This
is an unsuccessful rehearsal, not five-platform qualification.

The ARM executable built and successfully validated the default policy. Cross
forwarded rustup's toolchain status to stdout ahead of the version JSON, causing
the identity parser to reject the capture. Quiet mode suppresses that status
without weakening SHA/version/target assertions. A regression reproduces the
same JSON parse error before the repair; all nine workflow tests pass afterward.
Another hosted rehearsal is still required.

PR #11 then identified policy-event ordering races in Python, Go and Rust.
Diagnostic tests also reproduce a TypeScript observer-ordering failure. The
owner chose serialized reload rather than weakening the log contract. A fresh
read-only design review additionally found TypeScript provider-pull adoption
without a policy event. The local repairs now cover complete evaluations through
receipt delivery under a separate ordering gate, exclusive policy transitions,
provider adoption and observer callbacks after the ordering gate releases. The
owner approved non-reentrant confirmation/sink callbacks; TypeScript throws on
such reentry. Each SDK's initial regression failed before repair and passes
locally afterward. Final review and exact-head CI are still required. Existing
sink-failure behavior remains an evidence-gap boundary, not a guarantee that
unavailable storage contains a complete log.

The fresh implementation review found no blocking correctness issue. Two minor
findings were corrected: threaded observer regressions now acquire the exclusive
swap gate when reentering from evaluation/error callbacks, and the plan no longer
describes completed repairs as missing. The runtime guide now documents waiting
reload, callback constraints and the single-guard/synchronous-sink boundary.

Local verification completed: Rust workspace 1,142 passed with one intentional
ignored benchmark; latest guard tests 38 passed and all-features clippy passed.
Python 3,041 passed with four skips and two subtests; TypeScript 2,462 passed with
one opt-in Docker skip, build and lint passed; Go full race-enabled tests and vet
passed. The nine workflow regressions pass. Hosted qualification must use the
new commit, not the earlier candidate's successful PR CI.

## Quiet-mode rehearsal correction

Rehearsal `35894067431` at `e2e01f9`, attempt 1, passed all reusable CI jobs,
bundles and three native CLI platforms, but ARM64 smoke failed with the same JSON
parse error; matrix fail-fast cancelled macOS Intel. The earlier quiet-mode test double modeled rustup incorrectly:
`rustup --quiet toolchain add` still prints the toolchain status to stdout.
Cross 0.2.5 also does not strip the newer `(active, default)` marker when deciding
whether the toolchain is installed, so it invokes that command again.

The corrected regression retains noisy output even with `--quiet` and fails
against the earlier workflow. Smoke now executes the already-built binary through
the pinned Cross image's QEMU runner directly, without invoking Cargo or rustup.
The container has no network and a read-only checkout. Exact SHA, version and
target checks remain unchanged; no output filtering accepts malformed JSON.
All ten workflow regressions pass. Actual hosted ARM64 execution remains a gate;
the local ARM64 host cannot launch this x86-64 container without host emulation.
