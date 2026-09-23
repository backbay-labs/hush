# HushSpec v1 release closure

Status: executing release preparation; publication is not yet qualified.
Baseline: `wave-6`, `5a35dca012dc215a35b5c23c42ae1085018a8f30`.
Authority: user approved the six-step release-closure proposal on 2026-09-23.
Keep work in the existing checkout. Preserve the local Chio research documents.
The release scope is the current specification, four SDKs, CLI, testkit and
declared distribution artifacts. Chio migration and Project D remain separate.

## Constraints

- Preserve Core semantics, canonical identity, frozen schemas and existing tests.
- The owner explicitly chose to revoke the supplied credentials after publication.
  Do not place credentials in source, artifacts or logs. Post-publication
  revocation remains an owner action, not a completed release gate.
- PyPI uses trusted publishing; do not silently introduce a token fallback.
- Release policy signing requires an owner-approved key and separately retained
  public trust identity. A rehearsal key is disposable and not production trust.
- No administrative bypass of required reviews or weakened verification gates.
- Every released artifact must identify the qualified candidate; post-release
  checks must install from the actual registries, not local source.
- Keep failed evidence and retries distinct. Do not declare a release from
  source version strings, local tests or a successful dry run.

## Execution sequence

### 1. Close outstanding technical review

- [x] Complete the interrupted Project B whole-change review against current code.
- [x] Audit all 39 unresolved PR threads at the cumulative head; retain the
  distinction between fixes in later commits and older individual PR heads.
- [ ] Repair Critical/Important findings with failing-then-passing regressions.
- [ ] Record dispositions and rerun the affected suites before resolving threads.

### 2. Prepare a reviewable release candidate

- [x] Reconcile the delivery ledger and changelog with current A/B/C evidence.
- [x] Review package metadata and migration instructions for stable versus
  experimental surfaces and supported platforms.
- [ ] Provide an explicit non-publishing rehearsal of the existing release
  builds and signed bundles against one full commit SHA.
- [ ] Rehearsal must skip GitHub releases, registries, provenance publication
  and Homebrew writes; test signing uses no production credentials.
- [ ] Review the release-preparation diff and commit/push it to `wave-6`.

### 3. Establish publishing configuration

- [ ] Establish npm/crates credentials securely for publication; the owner has
  deferred revocation until afterward. Never print secret values.
- [ ] Owner confirms PyPI trusted publisher configuration for this repository
  and `publish.yml`, with no environment unless the workflow is updated too.
- [ ] Owner supplies or approves production signing-key custody and trust anchor.
- [ ] Verify Homebrew publishing access or obtain an explicit scope deferral.
- [ ] Verify Pages/custom-domain configuration and canonical schema URLs.

### 4. Integrate the cumulative candidate

- [ ] Obtain the approving review required by `main` protection.
- [ ] Integrate the repaired cumulative tree; do not publish intermediate older
  stack heads as if they contain later repairs.
- [ ] Qualify the actual integration SHA with all required terminal checks.

### 5. Rehearse distribution

- [ ] Verify all three Rust packages together from clean source.
- [ ] Build/install npm and Python distributions in fresh environments.
- [ ] Build the five declared CLI platform artifacts and smoke-test native
  executables; keep cross-built execution limitations explicit.
- [ ] Verify signed policy bundles and reproducible conformance bundles.
- [ ] Retain exact-SHA CI, rehearsal run/attempt and artifact identities.

### 6. Publish and verify

- [ ] Check version/tag agreement and availability immediately before publishing.
- [ ] Create `v1.0.0` and `packages/go/v1.0.0` at the qualified release commit;
  reconcile the older plan's `spec-1.0.0` naming explicitly.
- [ ] Publish declared packages, binaries, bundles and documentation.
- [ ] Install all SDKs and CLI from their public distribution channels; verify
  release digests/provenance, signed bundles and canonical schema resolution.
- [ ] Record actual publication state and any failed/partial channel separately.

## Initial evidence and operator gates

The baseline has successful direct/PR CI, each with 26 successful jobs. PRs
#5-10 remain open; `main` requires one approving review. All 39 review threads
remain unresolved on GitHub, although the prior reconciliation maps many to
later fixes. Project B's prior fresh review was incomplete.

Repository secret names include `CRATES_TOKEN`, `NPM_TOKEN`, `PYPI_TOKEN`, but
not policy signing or Homebrew credentials. No repository variables were
listed. Organization secrets are not readable with this account. PyPI trusted
publisher configuration is unverified. `hushspec.dev` failed local DNS lookup;
the Pages API returned 404, which does not distinguish absence from access.
No registry credentials or production signing keys belong in this document.

## Review-closure progress

The [fresh review record](../reviews/2026-09-23-v1-release-preparation.md) records
the 39-thread audit, corrected historical coverage claims and completed Project
B review. Source repairs and rehearsal support are implemented locally; full
candidate qualification, integration and publication checkboxes remain separate.
The deferred non-Linux testkit portability limitation does not expand the
documented Linux-only external execution contract. Production CLI platforms
must pass their own artifact builds and native smoke checks.
