# Changelog

All notable changes to HushSpec are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
HushSpec follows the versioning policy in [`spec/versioning.md`](./spec/versioning.md);
until 1.0.0 the specification and SDKs are an unstable `0.x` series.

## [Unreleased]

### Added (RFC 09 Wave 4, Rust)

- Receipt format 0.2 in the Rust SDK: `evaluate_audited` now takes a `Resolution` and an
  `AuditContext`, records actor, canonical `policy.content_hash`, `extends_chain`, signature
  status, recorded rule and detection traces, and the enforcement disposition; UUID v7 ids and
  millisecond timestamps. The staged receipt schema is promoted.
- Verify-on-load and digest pinning: `resolve_with_options` / `resolve_path_with_options`
  return a `Resolution` with per-hop chain links and verification outcomes;
  `extends: "<ref>#sha256:<hex>"` pins a base document.
- Hash-linked receipt log (`spec/hushspec-log.md`, `schemas/hushspec-log-entry.v0.schema.json`):
  `ChainedFileSink`, `PolicyEvent` records, `verify_logs`, and `h2h log verify`.
- Receipt signing (`sign_receipt` / `verify_receipt`) and `h2h receipts verify`.
- Policy bundle attestation (`spec/hushspec-bundle.md`, `schemas/hushspec-bundle.v0.schema.json`):
  `h2h bundle create` resolves a policy and wraps it in a DSSE envelope over an in-toto Statement
  v1 whose subject is the canonical form of the resolved document and whose predicate carries that
  document, every `extends` hop with its hash and signature status, and the resolver. `h2h bundle
  verify` runs the four ordered checks of bundle spec 5.2 (`malformed_bundle`, `unknown_key_id`,
  `dsse_signature_mismatch`, `subject_digest_mismatch`, `policy_mismatch`), optionally re-resolving
  the policy to cross-check it, and `h2h bundle inspect` prints the predicate. Bundles are signed
  with the same Ed25519 keys and `key_id` convention as policies, and are readable by generic DSSE
  and in-toto tooling. Eight vectors under `fixtures/bundle/`; every release now attaches a bundle
  for each `library/` and `rulesets/` policy, covered by `actions/attest-build-provenance`.
- The Python SDK ports the evidence chain: receipt format 0.2 (`evaluate_audited` takes a
  `Resolution` and an `AuditContext`; `receipt_hash`, `deterministic_uuid_v7`,
  `unverified_policy_receipt`; `compute_policy_hash` now returns the canonical `sha256:`
  hash), the hash-linked log (`hushspec.log`: `ChainedFileSink`, `PolicyEvent`,
  `verify_log` / `verify_logs` / `verify_log_files`), receipt signing
  (`sign_receipt` / `verify_receipt` / `SignedReceipt`), and `HushGuard(actor=...)` with
  `policy_loaded` / `policy_swapped` records. `SignatureStatus.signed_at` is renamed
  `verified_at`, an in-memory leaf resolves as `memory`, and a matching digest pin now
  satisfies `require_signature` for that hop.

### Added

- Governance hardening (core spec 2.5): `metadata.owner`, `reviewers[]`, `next_review_date`,
  `changelog[]` and `supersedes`; the four `metadata` date fields plus each changelog entry's
  `date` must now be an ISO 8601 calendar date (`YYYY-MM-DD`), checked in all four SDKs
  (`E011` from `h2h validate`). New governance checks with stable codes -- separation of
  duties (`GOV_SOD_VIOLATION`), `GOV_UNAPPROVED_STATE`, `GOV_REVIEW_OVERDUE`,
  `GOV_CHANGELOG_ORDER`, and the error-severity `GOV_SELF_SUPERSEDES`. `h2h audit` lists every
  finding with its code, severity and path; `--strict` makes warnings fatal. `h2h sign` refuses
  a policy that is not `approved` or `deployed` unless `--allow-unapproved` is passed.
- `spec/hushspec-canonical.md`: the canonical form of a resolved policy (schema defaults
  materialized, RFC 8785 serialization) and the `sha256:`-prefixed content hash, with a
  standard-library reference canonicalizer (`scripts/canonical_json.py`), the
  `hushspec-hash-vector` schema, and 14 normative vectors under `fixtures/core/hash/`.
- `spec/hushspec-receipt.md`: decision receipt format 0.2 (`receipt_version`, UUID v7 ids,
  millisecond timestamps with `time_source`, `actor`, `policy.extends_chain` and
  `policy.signature`, recorded rule and detection traces, required `enforcement`, a receipt
  hash for chaining). Schema staged at `schemas/staged/0.2.0/`; 12 valid and 14 invalid
  vectors under `fixtures/receipts/`. SDKs still emit format 0.1 until RFC 09 P2-04.
- `spec/hushspec-signing.md`: policy signature envelope 0.2 over the canonical content hash
  (not file bytes), PKCS#8/SPKI PEM keys, `key_id` from the SPKI digest, keyring format,
  expiry, rollback protection, and 16 verification vectors under `fixtures/signing/` signed
  with a published test-only key.
- Signing format 0.2 in the Rust SDK and `h2h` (RFC 09 P2-07): `hushspec::signing` now signs
  the content hash of the *resolved* policy over an RFC 8785 envelope, so reformatting a
  signed policy keeps its signature valid and a changed base policy invalidates it. Keys are
  PEM PKCS#8 / SPKI with `key_id` recomputed from the SPKI digest, trust is a `Keyring` with
  retirement and revocation, and `verify_policy` reports the closed reason-code set of signing
  spec 6.4 (`malformed_envelope`, `unsupported_format_version`, `unsupported_algorithm`,
  `unknown_key_id`, `key_revoked`, `key_retired`, `signed_at_in_future`, `expired`,
  `signature_mismatch`, `content_hash_mismatch`, `policy_version_rollback`). All 16 vectors
  under `fixtures/signing/` pass. `h2h keygen` writes `<name>.key.pem` / `<name>.pub.pem` and
  prints the key id (`--convert` upgrades a 0.1 key file); `h2h sign` gains `--expires-in`,
  `--policy-version` and `--out`; `h2h verify` gains `--keyring`, `--now`, `--max-skew`,
  `--last-seen-version` and `--format json`, and names a 0.1 signature rather than rejecting
  it as corrupt. The signature and keyring schemas are promoted out of
  `schemas/staged/0.2.0/`; TypeScript, Python and Go follow in the same work package.

### Changed

- **Breaking (signing).** Signature format 0.1 is superseded and cannot be verified by 0.2:
  it signed raw file bytes with bespoke 32-byte key files. Convert a key with
  `h2h keygen --convert <old.key>` and re-sign with `h2h sign`. `h2h keygen` now writes
  `h2h.key.pem` / `h2h.pub.pem` rather than `h2h.key` / `h2h.pub`, and `h2h sign` drops
  `--key-id` (the id is the SPKI digest and is never chosen by the signer). The Rust
  `hushspec::signing` API is rewritten around `Envelope`, `Keyring` and `ReasonCode`.
- Repositioned the project around "agentic compliance as code": updated the tagline and
  introductory copy across `README.md`, `docs/src/introduction.md`, package manifests, and
  package READMEs.
- Corrected `docs/plans/ROADMAP.md` and the SDK conformance docs to match a 2026-09-14
  code review: unchecked or re-labeled claims that were not actually implemented (e.g.
  byte-compatible receipt hashes, cloud-storage loaders, signed `extends` verification,
  separation-of-duties enforcement, "all SDKs" scoping on HushGuard/signing/hot reload/OTLP).
- Fixed the README "SDK Conformance" table and `docs/src/reference/sdk-conformance.md` to
  agree with each other and with the CI fixture matrix (all four SDKs at Level 3).

### Added

- `CHANGELOG.md`, `SECURITY.md`, `GOVERNANCE.md`, `CONTRIBUTING.md` at the repository root.
- Machine-readable control mappings (RFC 09 P2-09): `metadata.controls[]`
  (`framework`, `control_id`, `rule_paths`, `notes`) in the core schema, spec 2.5, and all
  four SDKs; a framework registry at `spec/registries/frameworks.yaml` with its own schema;
  lint `L011` (unmapped rule block), `L012` (rule path resolves to nothing) and `L013`
  (unregistered framework or non-conforming control id); `h2h audit --controls` (text and
  JSON) with a rule-block coverage line and a `--strict` exit code; and all eight
  `library/` policies migrated from comment-only mappings to structured ones.

### Planned

- RFC 09 (`docs/plans/09-compliance-as-code-plan.md`) tracks the work needed to make the
  corrected roadmap claims true: fail-closed correctness fixes (M1), canonical cross-SDK
  receipt hashing and policy/receipt signing everywhere (M2), a published conformance
  program (M3), and the spec 1.0 freeze (M4).

## [0.1.1] - 2026-09-14

An early pre-release of this version was tagged `v0.1.1-alpha` on 2026-03-16; development
continued under the same `0.1.1` version afterward. Highlights across the full range:

### Added

- Evaluation engines in TypeScript, Python, and Go, bringing all four SDKs to Level 3
  (parse, validate, merge, resolve, evaluate) conformance against a shared fixture corpus.
- `h2h` CLI (renamed from `hushspec`) with `validate`, `test`, `lint`, `diff`, `fmt`, `init`,
  `eval`, `explain`, `sign`, `verify`, `keygen`, and `panic` subcommands.
- Decision receipts and audit trail (`evaluate_audited()`) with rule traces and receipt
  sinks (file, console, filtered, multi, callback, null) in all four SDKs.
- Detection pipeline (prompt injection, jailbreak, exfiltration) with regex-based reference
  detectors, ported to all four SDKs.
- Ed25519 policy signing, verification, and key generation in the Rust SDK (feature-gated)
  and the `h2h` CLI.
- Emergency override ("panic mode") kill switch with file-based sentinel activation.
- `HushGuard` middleware and framework adapters for Claude/Anthropic, OpenAI, and MCP in
  TypeScript, plus a Python port of `HushGuard`.
- `PolicyWatcher` and `PolicyPoller` hot-reload support in TypeScript.
- `EvaluationObserver` / `ObservableEvaluator` structured observability hooks in
  TypeScript and Python.
- Vertical policy library (`library/`): 8 compliance-mapped starting-point policies
  (HIPAA, SOC2, PCI-DSS, FedRAMP, FERPA, CI/CD hardened, air-gapped, recommended).
- Cross-SDK conformance testkit, differential fuzzing (`hushspec-difftest`), and
  Criterion benchmarks with a receipt-overhead CI gate.
- CI/CD publish workflow for npm, PyPI, and crates.io.

### Fixed

- Numerous cross-SDK parity fixes closing divergences between Rust, TypeScript, Python,
  and Go in validation, regex/time-window handling, posture/origin evaluation, formatter
  idempotence, and builtin ruleset loading.
- SSRF and IPv6 hardening in the HTTPS policy loader; signature-verification tightening.

## [0.1.0] - 2026-03-15

Initial public release of the HushSpec specification and Rust reference implementation.

### Added

- Core HushSpec specification and JSON Schema definitions in `spec/` and `schemas/`.
- 10 core rule blocks: `forbidden_paths`, `path_allowlist`, `egress`, `secret_patterns`,
  `patch_integrity`, `shell_commands`, `tool_access`, `computer_use`,
  `remote_desktop_channels`, `input_injection`.
- 3 extension modules: `posture`, `origins`, `detection`.
- Rust reference implementation (`crates/hushspec`) with parsing, validation, and merging.

[Unreleased]: https://github.com/backbay-labs/hush/compare/v0.1.1-alpha...HEAD
[0.1.1]: https://github.com/backbay-labs/hush/compare/98727b8...v0.1.1-alpha
[0.1.0]: https://github.com/backbay-labs/hush/commit/98727b8
