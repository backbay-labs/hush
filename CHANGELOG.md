# Changelog

All notable changes to HushSpec are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
HushSpec follows the versioning policy in [`spec/versioning.md`](./spec/versioning.md);
until 1.0.0 the specification and SDKs are an unstable `0.x` series.

## [Unreleased]

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
  `hushspec-hash-vector` schema, and 13 normative vectors under `fixtures/core/hash/`.
- `spec/hushspec-receipt.md`: decision receipt format 0.2 (`receipt_version`, UUID v7 ids,
  millisecond timestamps with `time_source`, `actor`, `policy.extends_chain` and
  `policy.signature`, recorded rule and detection traces, required `enforcement`, a receipt
  hash for chaining). Schema staged at `schemas/staged/0.2.0/`; 12 valid and 14 invalid
  vectors under `fixtures/receipts/`. SDKs still emit format 0.1 until RFC 09 P2-04.
- `spec/hushspec-signing.md`: policy signature envelope 0.2 over the canonical content hash
  (not file bytes), PKCS#8/SPKI PEM keys, `key_id` from the SPKI digest, keyring format,
  expiry, rollback protection, and 16 verification vectors under `fixtures/signing/` signed
  with a published test-only key. Schemas staged at `schemas/staged/0.2.0/`; the Rust
  implementation is brought to it in RFC 09 P2-07.

### Changed

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
