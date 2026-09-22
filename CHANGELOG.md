# Changelog

All notable changes to HushSpec are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
HushSpec follows the versioning policy in [`spec/versioning.md`](./spec/versioning.md).

## [Unreleased]

### Fixed

- `h2h test` exits `2` when an argument names neither a file nor a directory. Such a path was
  dropped silently, so a run with a mistyped suite reported a green summary for the suites that
  did resolve.
- `h2h lint --dry-run` reports the document on disk. It re-linted the mutated in-memory model, so
  its JSON and SARIF reports listed applied fix codes and the post-fix findings for a file that was
  never written, and `--dry-run --fail-on-warnings` could exit `0` on a file that still held the
  warnings.
- `h2h test` credits rule coverage only from cases that passed. A failing case still credited its
  `matched_rule` and rule-trace paths, so a JUnit or JSON artifact could report full coverage from
  cases that did not pass.
- `h2h lint` exits `2` for a file that is missing or unreadable, matching `validate` and `fmt` and
  the documented exit-code table; it exited `1`, the code for a document that failed the check. A
  JSON or SARIF report that cannot be serialized now also exits `2` with the error on stderr instead
  of printing nothing and exiting `0`.
- `h2h lint` reports an unresolvable `extends` chain as `E010`, the code
  `spec/registries/error-codes.yaml` reserves for an extends failure. It emitted `E002`, which the
  same registry reserves for an unsupported `hushspec` version.
- `h2h receipts verify` replays a receipt under the posture state the receipt records, and fails the
  `decision` check when a recorded `action.origin` or `action.context` will not deserialize. The
  replay dropped both and always ran from the policy's initial posture state, then printed the check
  as if the recorded action had been re-derived.
- `h2h report --format oscal` carries the chain's status in `metadata`, the `result` and every
  `finding` as a `chain-verified` prop, and reports no control `satisfied` when the hash chain did
  not verify. An export made with `--unverified` over a broken chain read as clean evidence.

## [1.0.0] - 2026-09-15

HushSpec 1.0.0 is the first stable release. Every specification in the family carries version
1.0.0 with status Stable, and the document format, evaluation semantics, canonical form, wire
formats, error and reason codes, closed registries, and grammars are frozen for the 1.x series
(`spec/versioning.md` section 5). A `1.0.z` document is evaluated exactly as a `0.2.z` document,
and the reference SDKs accept `0.1`, `0.2`, and `1.0`. Everything below was developed in the
0.x series and ships for the first time in this release.

### Added

**Spec**

- **HushSpec 1.0.0 is declared** (core spec 10.2; versioning spec 10). A `1.0.Z` document is
  treated exactly as a `0.2.Z` document; the reference implementation accepts `0.1`, `0.2`, and
  `1.0` and rejects any other minor with E002. The one validation change from 0.2 is that `name`,
  when present, MUST be non-empty (core spec 2), rejected with E004; a `0.Y.Z` document keeps the
  frozen format's behaviour and is not held to it. Vectors:
  `fixtures/core/valid/version-1-0.yaml`, `fixtures/core/evaluation/version-1-0.test.yaml`,
  `fixtures/core/invalid/version-unsupported-minor.yaml`, `fixtures/core/invalid/empty-name.yaml`,
  `fixtures/core/valid/empty-name-0-2.yaml`.
- **Conformance levels 4 and 5** are normative in `spec/hushspec-core.md` section 8, closing the
  forward references the receipt and signing specifications already made. **Level 4 (Auditor)**:
  receipt format 0.2, a canonical `policy.content_hash` over the resolved document, a `rule_trace`
  recorded rather than reconstructed, the committed receipt for every evaluation case reproduced
  after RFC 8785 canonicalization, and the canonical-form and resolution vectors. **Level 5
  (Attested)**: a conforming signature verifier, verification on load recorded in
  `receipt.policy.signature`, a hash-linked log rejected at the line its file name names, receipt
  signing, and bundle verification. Section 8 also states that a claim is made against a corpus
  pinned by digest, and that `not_attempted` is never a pass.
- `spec/hushspec-canonical.md`: the canonical form of a resolved policy (schema defaults
  materialized, RFC 8785 serialization) and the `sha256:`-prefixed content hash, with a
  standard-library reference canonicalizer (`scripts/canonical_json.py`), the
  `hushspec-hash-vector` schema, and 16 normative vectors under `fixtures/core/hash/`.
- `spec/hushspec-receipt.md`: decision receipt format 0.2 (`receipt_version`, UUID v7 ids,
  millisecond timestamps with `time_source`, `actor`, `policy.extends_chain` and
  `policy.signature`, recorded rule and detection traces, required `enforcement`, a receipt
  hash for chaining), with 12 valid and 14 invalid vectors under `fixtures/receipts/`.
  `schemas/hushspec-receipt.v1.schema.json` is the 0.2 schema.
- `spec/hushspec-signing.md`: policy signature envelope 0.2 over the canonical content hash
  (not file bytes), PKCS#8/SPKI PEM keys, `key_id` from the SPKI digest, keyring format,
  expiry, rollback protection, and 18 verification vectors under `fixtures/signing/` signed
  with a published test-only key.
- `spec/hushspec-log.md` and `spec/hushspec-bundle.md`: the hash-linked receipt log and the
  policy bundle attestation format, with their schemas and vectors.
- **`when.capability` and `when.rate`** (core spec 3.13): a rule block can be gated on the
  effective posture state granting a capability, or on an engine-supplied counter in the new
  runtime-context `counters` map crossing a threshold; both are unevaluable-means-active.
- **`heuristic_injection@1`** (detection spec 3.5): a normative, integer-scored prompt-injection
  detector with a fixed signal table that every engine must reproduce exactly, configured by
  `prompt_injection.heuristics`, and registered beside `regex_injection@1`.
- **Transition priority** (posture spec 5.3): for the same trigger, a transition whose `from`
  names the current state outranks one whose `from` is `"*"`; among equals, document order wins.
  Every SDK implements it, against the shared vector
  `fixtures/posture/evaluation/transition-priority.test.yaml`.
- Governance hardening (core spec 2.5): `metadata.owner`, `reviewers[]`, `next_review_date`,
  `changelog[]` and `supersedes`; the four `metadata` date fields plus each changelog entry's
  `date` must now be an ISO 8601 calendar date (`YYYY-MM-DD`), checked in all four SDKs
  (`E011` from `h2h validate`). New governance checks with stable codes -- separation of
  duties (`GOV_SOD_VIOLATION`), `GOV_UNAPPROVED_STATE`, `GOV_REVIEW_OVERDUE`,
  `GOV_CHANGELOG_ORDER`, and the error-severity `GOV_SELF_SUPERSEDES`. `h2h audit` lists every
  finding with its code, severity and path; `--strict` makes warnings fatal. `h2h sign` refuses
  a policy that is not `approved` or `deployed` unless `--allow-unapproved` is passed.
- Machine-readable control mappings: `metadata.controls[]` (`framework`, `control_id`,
  `rule_paths`, `notes`) in the core schema, spec 2.5, and all four SDKs; a framework registry
  at `spec/registries/frameworks.yaml` with its own schema; lint `L011` (unmapped rule block),
  `L012` (rule path resolves to nothing) and `L013` (unregistered framework or non-conforming
  control id); `h2h audit --controls` (text and JSON) with a rule-block coverage line and a
  `--strict` exit code; and all eight `library/` policies migrated from comment-only mappings
  to structured ones.

**Schemas**

- **The `.v1.` schema lineage.** The sixteen document-format schemas are published as
  `hushspec-<name>.v1.schema.json` under `https://hushspec.dev/schemas/`, and every SDK, the CLI,
  the testkit, the fixture modelines, and the docs reference them. `hushspec-core.v1.schema.json`
  differs from its `.v0.` predecessor in exactly two keywords: `hushspec` matches
  `^(0|1)\.\d+\.\d+$` and `name` carries `minLength: 1`. The receipt, log-entry, and report
  schemas widen their `spec_version` patterns the same way, so a receipt for a `1.0.z` policy
  validates; every other `.v1.` file is its `.v0.` predecessor under a new `$id`. The `.v0.` files are frozen for documents that declare a 0.x
  version: each carries a `$comment` saying so, `schemas/frozen-v0.json` records their digests,
  and a test fails when one changes. The seven registry schemas keep the `.v0.` name.
  `h2h schema core` prints the v1 file; `h2h schema core.v0` prints the frozen one.
- **Expected error codes on every `invalid/` vector.** `spec/registries/error-codes.yaml`
  registers the codes the validator emits (`E000`-`E005`, `E010`, `E011`), validated by
  `schemas/hushspec-error-codes.v1.schema.json`, whose `$defs/ExpectedError` is the shape of the
  new `fixtures/<module>/invalid/<name>.expect.yaml` sidecars. All four SDK fixture runners
  assert the registered code and any `message_contains` substring.
- **`schemas/hushspec-merge-vector.v1.schema.json`** writes down the merge vector directory
  convention (`base.yaml`, `child-*.yaml`, `expected-*.yaml`, the digest-pin path through the
  resolver, and the two refusal markings all four runners honour), validated against every merge
  directory in the corpus by a testkit test.
- **`schemas/hushspec-conformance-report.v1.schema.json`**: the shape of a conformance report.
- Evaluator-test fixtures format **0.2.0** (`schemas/hushspec-evaluator-test.v1.schema.json`):
  a case may declare `controls: [{framework, control_id}]` -- the controls it
  is evidence for -- and free-form `tags`, and its `expect` may assert `rule_trace` (the
  recorded trace of receipt spec 4.3, compared in order and in full, with `rule_path` compared
  only where it is spelled) and `receipt` (a partial format 0.2 receipt whose members must equal
  the receipt produced under the fixed inputs of `fixtures/receipts/expected/README.md`;
  `actor`, `timestamp` and `receipt_id` are ignored, nested objects are compared member-wise).
  `hushspec_test` now accepts `0.1.0` and `0.2.0`, so every existing fixture stays valid.

**Rust**

- `version::HUSHSPEC_VERSION` is `1.0.0` and `HUSHSPEC_SUPPORTED_MINORS` lists `0.1`, `0.2`,
  and `1.0`.
- `HttpLoaderConfig::cache_max_entries` (default `DEFAULT_CACHE_MAX_ENTRIES`, 64) bounds the
  on-disk ETag cache; a write that would exceed it removes the oldest entries first.
- `hushspec::guard` -- `HushGuard`, the Rust enforcement point, at parity with the
  TypeScript SDK's. Built from a `Policy`, a `Resolution` or a `CompiledPolicy`; carries the
  enforcement mode (with per-rule-path overrides, longest prefix wins), an `on_warn`
  confirmation channel (absent, a `warn` denies -- core spec 6), a `ReceiptSink`, observers,
  the acting `Actor`, and the `TimeSource`. `check()` returns a `GuardDecision` (result,
  receipt, `enforced`, `enforcement`, `duration_us`); `evaluate()` records without enforcing;
  `swap_policy()` hot-swaps atomically and keeps the last good policy when the new one will
  not validate or compile. A policy that fails verification under `require_signature` puts the
  guard in the refused state -- every action denied with `__hushspec_policy_unverified__` and an
  unverified-policy receipt -- rather than failing to build. Panic mode and a refusal always
  enforce; monitor mode is refused without a sink or an observer. `Send + Sync`, `&self`
  everywhere, policy behind an `RwLock<Arc<..>>`.
- `hushspec::observer` -- `EvaluationObserver` (`on_policy_loaded` / `on_evaluation` /
  `on_error`, all defaulted), `ObservableEvaluator`, `JsonLineObserver`, `StderrObserver`,
  `MetricsCollector` (counters by decision, action type and rule block, a latency histogram,
  `snapshot()`, and `render_prometheus()` emitting the documented `hushspec_evaluate_total`,
  `hushspec_evaluate_duration_us`, `hushspec_rule_match_total` and `hushspec_policy_load_total`
  series), plus `WebhookObserver` behind `http`. Action `content` is stripped before any
  observer sees it.
- `hushspec::provider` -- `PolicyProvider` (`load()` -> `Resolution`, `source()`),
  `FileProvider`, `HttpProvider` (behind `http`, ETag-aware through the existing HTTPS loader),
  and two reload drivers: `PolicyWatcher` (stats one file per tick) and `PolicyPoller`
  (interval reload through any provider, delivering only on a `content_hash` change). Both swap
  into a `HushGuard`, keep the last good policy on any failure, report through `on_error`, and
  can check a panic sentinel on the same tick. `PolicyHandle` exposes `current()`,
  `generation()`, `errors()` and `last_error()`; dropping it stops the thread.
- `hushspec::otlp` (new `otlp` feature, implies `http`) -- `OtlpSink` exports receipts and
  policy events as OTLP/HTTP JSON logs to `<endpoint>/v1/logs`: one `logRecord` per entry,
  `timeUnixNano` from the entry's own timestamp, `INFO`/`WARN`/`ERROR` by decision,
  `body.stringValue` the canonical JSON of the receipt, and `hushspec.*` attributes for entry
  type, receipt version, decision, action type, matched rule, policy content hash, receipt hash
  and enforcement mode/outcome, under `service.name` / `hushspec.sdk` (`hushspec-rust`) /
  `hushspec.sdk.version` / `hushspec.spec_version` resource attributes. The mapping is written
  out in the module docs so every SDK agrees. Background thread and bounded queue, so
  export never blocks an evaluation; overflow drops with a counter and a `sink.error` observer
  event; `5xx` retried with backoff, `4xx` not; drop flushes.
- `cargo run --example guarded_agent --features otlp` -- a complete tool boundary: policy ->
  guard -> `check` -> `ChainedFileSink` + `OtlpSink`, with metrics, a monitored rule block and
  hot reload. New guide `docs/src/guides/runtime-integration.md`.
- `Policy::panic_state()` reads the kill switch a policy will compile with.
- Receipt format 0.2: `evaluate_audited` now takes a `Resolution` and an `AuditContext`,
  records actor, canonical `policy.content_hash`, `extends_chain`, signature status, recorded
  rule and detection traces, and the enforcement disposition; UUID v7 ids and millisecond
  timestamps.
- Verify-on-load and digest pinning: `resolve_with_options` / `resolve_path_with_options`
  return a `Resolution` with per-hop chain links and verification outcomes;
  `extends: "<ref>#sha256:<hex>"` pins a base document.
- Hash-linked receipt log (`spec/hushspec-log.md`, `schemas/hushspec-log-entry.v1.schema.json`):
  `ChainedFileSink`, `PolicyEvent` records, `verify_logs`, and `h2h log verify`.
- Receipt signing (`sign_receipt` / `verify_receipt`) and `h2h receipts verify`.
- Policy bundle attestation (`spec/hushspec-bundle.md`, `schemas/hushspec-bundle.v1.schema.json`):
  `h2h bundle create` resolves a policy and wraps it in a DSSE envelope over an in-toto Statement
  v1 whose subject is the canonical form of the resolved document and whose predicate carries that
  document, every `extends` hop with its hash and signature status, and the resolver. `h2h bundle
  verify` runs the four ordered checks of bundle spec 5.2 (`malformed_bundle`, `unknown_key_id`,
  `dsse_signature_mismatch`, `subject_digest_mismatch`, `policy_mismatch`), optionally re-resolving
  the policy to cross-check it, and `h2h bundle inspect` prints the predicate. Bundles are signed
  with the same Ed25519 keys and `key_id` convention as policies, and are readable by generic DSSE
  and in-toto tooling. Ten vectors under `fixtures/bundle/`; every release now attaches a bundle
  for each `library/` and `rulesets/` policy, covered by `actions/attest-build-provenance`.
- Signing format 0.2: `hushspec::signing` now signs the content hash of the *resolved* policy
  over an RFC 8785 envelope, so reformatting a signed policy keeps its signature valid and a
  changed base policy invalidates it. Keys are PEM PKCS#8 / SPKI with `key_id` recomputed from
  the SPKI digest, trust is a `Keyring` with retirement and revocation, and `verify_policy`
  reports the closed reason-code set of signing spec 6.4 (`malformed_envelope`,
  `unsupported_format_version`, `unsupported_algorithm`, `unknown_key_id`, `key_revoked`,
  `key_retired`, `signed_at_in_future`, `expired`, `signature_mismatch`,
  `content_hash_mismatch`, `policy_version_rollback`). All 18 vectors under `fixtures/signing/`
  pass.
- `when.capability` and `when.rate` support: `RateCondition`, `RateComparison`,
  `evaluate_condition_with_capabilities` and `is_capability_identifier` are exported.

**TypeScript**

- Receipt format 0.2 in `@hushspec/core`: `evaluateAudited(resolution, action, config, context)`
  (plus `evaluateAuditedSpec`) records `receipt_version`, a UUID v7 `receipt_id`, a
  millisecond `timestamp` with `time_source`, the optional `actor`, the canonical
  `policy.content_hash` with `extends_chain` and signature status, the evaluator's recorded
  rule trace under the schema's closed `rule_block` ids, `detection_trace` whenever the
  detection pipeline ran, `action.content_hash` / `content_size` in place of content, and the
  required `enforcement` disposition. New `receiptHash`, `parseReceipt`, `policySummary`,
  `unverifiedPolicyReceipt`, `deterministicUuidV7` and `formatTimestamp`; `computePolicyHash`
  now returns the canonical `sha256:` hash instead of the 0.1 per-SDK digest.
- Hash-linked receipt log: `ChainedFileSink` (fsync per entry, exclusive lock file, rotation
  through a `log_started` entry), `policyLoadedEvent` / `policySwappedEvent`, and
  `verifyLog` / `verifyLogs` / `verifyLogFiles` returning a `LogVerifyReport` that names the
  first break by file and line. `ReceiptSink` gains an optional `recordPolicyEvent`.
- Receipt signing: `signReceipt` / `verifyReceipt` over the receipt hash, plus the
  `signContentHash` / `verifyContentHash` primitives they and the log share.
- `HushGuard` emits 0.2 receipts through its sink using the guard's own resolution, records
  `policy_loaded` on construction and `policy_swapped` on hot reload, emits the reserved
  `__hushspec_policy_unverified__` receipt for actions refused under `requireSignature`, and
  accepts `actor` and `timeSource` options.
- Vector runners for `fixtures/core/resolve/`, `fixtures/receipts/{expected,valid,invalid}`,
  `fixtures/log/{valid,invalid}` and `fixtures/receipts/signed/`.
- `CompiledPolicy`: `compilePolicy(spec)` / `compileResolution(resolution)` build every
  policy regex, path glob, host pattern, tool set, parsed `when` condition, severity table and
  detector configuration once, and `evaluate` / `evaluateTraced` / `evaluateWithContext` /
  `evaluateWithDetection` / `evaluateAudited` run against that form; `contentHash` is computed on
  first use and cached, and the source document is kept verbatim for receipts. `compilePolicy`
  raises `CompileError` for a pattern outside the regex profile instead of deferring it to an
  evaluation-time deny (`{ strict: false }` keeps the deny). `HushGuard` compiles once at
  construction and on `swapPolicy()`, and exposes `guard.compiled`.
- `OtlpReceiptSink`: exports decision receipts and
  `policy_loaded` / `policy_swapped` events to an OpenTelemetry collector as OTLP/HTTP JSON
  logs (`POST <endpoint>/v1/logs`), over `node:http` / `node:https` with no new dependency.
  One `logRecord` per entry: `timeUnixNano` from the entry's own timestamp, `severityText`
  `INFO`/`WARN`/`ERROR` for allow/warn/deny (`INFO` for a policy event), `body.stringValue`
  the entry's RFC 8785 canonical JSON, and the `hushspec.*` attributes (`entry_type`,
  `receipt_version`, `decision`, `action_type`, `matched_rule`, `policy.content_hash`,
  `receipt_hash`, `enforcement.mode`, `enforcement.outcome`) plus the `service.name` /
  `hushspec.sdk` / `hushspec.sdk.version` / `hushspec.spec_version` resource attributes --
  the same wire mapping in every SDK. `send()` never blocks or throws: a bounded queue,
  batching by size or timer, retries with exponential backoff on 5xx/429/network errors,
  `flush()` and `close()`, and overflow that drops, counts (`sink.dropped`) and reports
  through `onError` rather than silently losing evidence.
- Vercel AI SDK adapter: `mapVercelToolCall()` (AI SDK 4 `args` and 5 `input` shapes) and
  `createVercelGuard(guard).wrapTools(tools)`, which gates each tool's `execute` -- deny
  throws `HushSpecDenied` before the tool body runs, warn goes to the guard's `onWarn`.
- LangChain.js adapter: `wrapLangChainTool()` (a proxy, so the tool keeps its prototype,
  fields and `instanceof`, with `invoke`, `call` and a `DynamicTool`'s `func` gated) and
  `createLangChainCallbackHandler()`, which gates every tool an executor starts.
  Both adapters are structurally typed: neither imports the framework it adapts.

**Python**

- `hushspec.provider`: a `PolicyProvider` protocol (`load() -> Resolution`, `source`)
  with `FileProvider` (carrying its `ResolveOptions`, so `require_signature` applies to every
  reload), `CallbackProvider`, and hot reload through `PolicyWatcher` (mtime + content hash) and
  `PolicyPoller` (any provider) -- daemon threads, context managers, an explicit `check_once()`
  tick, and optional panic-sentinel checking per tick. `HushGuard.from_provider(...)` builds a
  guard from a provider and can attach either loop; `HushGuard.swap_resolution()` swaps in an
  already-resolved policy without re-resolving it. A reload that cannot be read, parsed,
  resolved, verified or compiled leaves the policy in force untouched and is reported through
  `on_error`, then retried.
- `hushspec.otlp.OtlpReceiptSink`: exports receipts and policy events to an OTLP/HTTP
  collector as log records (`POST <endpoint>/v1/logs`) over `urllib` alone -- canonical JSON
  body, `INFO`/`WARN`/`ERROR` severity by decision, and the `hushspec.*` attributes and resource
  attributes shared with the Rust, TypeScript and Go sinks. Background thread, bounded queue
  (drop + counter + `on_error` on overflow), batching, retry with backoff on `429`/`5xx`/network
  errors, `flush()` and `close()`; `send()` never blocks on I/O.
- `hushspec.adapters.anthropic`: `map_claude_tool_to_action()` maps a Claude `tool_use`
  block onto the action a policy evaluates (`bash` -> `shell_command`, text editor -> `file_read`
  / `file_write` with content, `computer` -> `computer_use`, `web_fetch` -> `egress` on the host,
  `mcp__server__tool` -> the inner tool name, date-suffixed tool versions included), and
  `create_secure_tool_handler()` enforces before the tool runs. No `anthropic` import: blocks are
  read structurally.
- `hushspec.log.policy_event_to_dict()`: the one spelling of a policy event, shared by log
  entries and the OTLP sink.
- The evidence chain: receipt format 0.2 (`evaluate_audited` takes a
  `Resolution` and an `AuditContext`; `receipt_hash`, `deterministic_uuid_v7`,
  `unverified_policy_receipt`; `compute_policy_hash` now returns the canonical `sha256:`
  hash), the hash-linked log (`hushspec.log`: `ChainedFileSink`, `PolicyEvent`,
  `verify_log` / `verify_logs` / `verify_log_files`), receipt signing
  (`sign_receipt` / `verify_receipt` / `SignedReceipt`), and `HushGuard(actor=...)` with
  `policy_loaded` / `policy_swapped` records. `SignatureStatus.signed_at` is renamed
  `verified_at`, an in-memory leaf resolves as `memory`, and a matching digest pin now
  satisfies `require_signature` for that hop.

**Go**

- Parity for the runtime-integration surface. `Guard` (`hushspec.NewGuard`,
  `NewGuardFromFile`, `NewGuardFromProvider`) is the enforcement point: compiled policy,
  enforce/monitor mode with longest-prefix `RuleOverrides`, warn confirmation through `OnWarn`
  (nil denies), receipts and `policy_loaded` / `policy_swapped` records through a sink,
  `SwapPolicy` that keeps the last good policy on failure, and a refused state that denies every
  action with `__hushspec_policy_unverified__` and an unverified-policy receipt when
  `RequireSignature` cannot be satisfied. Observers (`EvaluationObserver`, `ObservableEvaluator`,
  `JSONLineObserver`, `StderrObserver`, `MetricsCollector` with Prometheus exposition,
  `WebhookObserver`) see every decision and can change none. `PolicyProvider` / `FileProvider`
  with `PolicyWatcher` (mtime + content hash) and `PolicyPoller` hot-swap a policy into a guard,
  checking the panic sentinel every tick. Adapters map Anthropic, OpenAI and MCP tool calls onto
  actions, with `GuardedToolHandler` wrappers that check before the tool runs. `OTLPReceiptSink`
  exports receipts and policy events as OTLP/HTTP JSON logs, batched and retried on a background
  goroutine, with the same wire mapping as the other SDKs.
- The evidence chain, byte for byte identical to the other SDKs. Receipt format
  0.2: `EvaluateAudited(resolution, action, config, ctx)` (and `EvaluateAuditedSpec`) records
  the actor, the canonical `policy.content_hash`, `extends_chain`, the signature outcome, the
  evaluator's recorded rule trace under the schema's closed `rule_block` ids, the detection
  trace, and the required enforcement disposition, with UUID v7 ids and millisecond
  timestamps; `ParseReceipt` accepts exactly what the 0.2 schema accepts, and
  `ComputePolicyHash` now returns the canonical `sha256:` hash. Hash-linked log:
  `ChainedFileSink` (fsync and an exclusive `flock` per append, rotation carrying `prev_hash`
  through a `log_started` entry, optional per-entry signatures), `PolicyEvent` records through
  the new `PolicyEventSink` interface, and `VerifyLog` / `VerifyLogs` / `VerifyLogFiles`
  reporting the first break by file and line. Receipt signing: `SignReceipt`, `VerifyReceipt`,
  `SignedReceipt`. `SignatureStatus.SignedAt` is renamed `VerifiedAt` (`verified_at`) to match
  the schema, and an in-memory leaf is recorded in the chain as `memory`.

**CLI**

- Lint **L022** `empty-list-entry` (warning): an empty string in `rules.tool_access.allow`,
  `block`, or `require_confirmation`, or in an origins profile overlay list, can never match and
  is reported at its index.
- `h2h report <log.jsonl|receipts.jsonl>...`: compliance evidence over a window of receipts.
  Reads a hash-linked log or a plain receipt JSONL (classified line by line, signed receipts
  included), verifies the chain before counting anything and refuses to report on a broken one
  without `--unverified`, and refuses a line that does not parse without `--lenient`. Aggregates
  totals by decision, enforcement mode and disposition; per rule block (evaluated, skipped, fired,
  deny/warn, top `rule_path`s); per action type; per policy `content_hash` with the
  `policy_loaded` / `policy_swapped` timeline; per actor; policy-signature outcomes by reason; and
  detections by detector and level. With `--policy`, joins `metadata.controls` into a per-control
  evidence table (evaluated / fired / denied / last seen, plus the rule blocks that fired with no
  control behind them). `--format json` is validated by the new
  `schemas/hushspec-report.v1.schema.json` (`h2h schema report`), `--format csv` writes one table
  per file into `--out` (or the `--by` table to stdout), and `--format oscal` behind
  `--experimental-oscal` emits a minimal OSCAL 1.1.2 assessment-results skeleton. The aggregation
  itself is the new `hushspec::report` module. Vectors: `fixtures/report/` -- a synthetic 24-hour
  log and the exact report it must produce, both drift-checked.
- **Lint source spans.** Every finding is now located at the key or list entry it is about
  rather than at the file. Positions come from a second pass over the same bytes with a
  real YAML event parser (`saphyr-parser`), which keeps quoted keys, block scalars, flow
  sequences and comments between entries aligned where a line scanner does not. Text
  output prints `file:line:column` with the document path beneath it; JSON findings gain
  `path` and a `span` object (`file`, `line`, `column`, `end_line`, `end_column`). Lint
  reports the resolved document, so a finding about an inherited block names the base that
  declares it -- `builtin:permissive:9:9`, not the leaf.
- **SARIF 2.1.0 output**: `h2h lint --format sarif`, with `--out <PATH>` to write the
  report to a file. One run, a `tool.driver` for `h2h` carrying the full rule catalog
  (`shortDescription`, `fullDescription`, `defaultConfiguration.level`, `helpUri`), and one
  `result` per finding with `ruleId`, `level`, `message`, a `physicalLocation` region, a
  `logicalLocations` entry naming the document path, and a `fixes` deletion for fixable
  findings. The SARIF 2.1.0 JSON Schema is vendored at
  `crates/hushspec-cli/schemas/sarif-2.1.0.schema.json` and every emitted document is
  validated against it offline in `tests/lint_span_tests.rs`. The `Policy Lint` CI job
  uploads the file with `github/codeql-action/upload-sarif`, guarded so a repository fork --
  which cannot hold `security-events: write` -- still passes.
- **Eight new lint rules**, each documented with its rationale in
  `docs/src/reference/cli.md`:
  - `L014` (warning/info) credential locations a filesystem denylist misses (`.env`,
    `.ssh`, `.aws`, `.gnupg`, `.kube`, `id_rsa`), naming the ones it does not reach;
    silent when the policy runs a `path_allowlist`, informational when it declares neither.
  - `L015` (warning) a secret pattern that detects a well-known credential class (AWS
    `AKIA`/`ASIA`, GitHub `gh[opsur]_`, a PEM private key header, OpenAI `sk-`) but is
    graded below `critical`.
  - `L016` (warning/info) a forbidden shell or patch pattern that matches every input
    (`.*`, `.+`, a bare single character, or anything matching the empty string): a warning
    beside other patterns, which it renders dead; information as the only entry in its
    list, which is the one way the block can express a deny-all.
  - `L017` (warning) a permissive default -- `egress.default: allow`, or
    `tool_access.default: allow` with empty `block` and `require_confirmation`.
  - `L018` (warning/info) a capability block enabled with an empty allowlist: information
    for a coherent total deny (the spec's only spelling of one, since `enabled: false`
    permits), a warning where the document contradicts itself or the block does nothing.
  - `L019` (error) extension configuration nothing can reach: an unreachable posture state,
    a transition naming an undefined state, an origin profile with no `match` or one that
    repeats an earlier profile's, and an overlay `allow` entry the base never allows.
  - `L020` (info) a `when` clause that narrows nothing -- `start == end`, all seven days,
    or an empty `all_of`/`any_of`.
  - `L021` (warning) a `when.capability` naming a capability no posture state grants.
- `h2h test --format junit` writes a JUnit XML report -- one `<testsuite>` per fixture file,
  one `<testcase>` per case, each case's `controls` and `tags` as `<property>` entries, and each
  failure as a `<failure>` carrying the expected and the actual value -- and `--report-file`
  writes the report to a path while stdout keeps the readable summary.
- Rule coverage in `h2h test`: every run compares the rule paths a policy declares (every rule
  block of the resolved document, plus every named secret pattern) with the paths its cases hit
  through `matched_rule` and through each `rule_trace` entry, prints the table, and reports the
  numbers in the JSON report's new `coverage` member and in a `rule coverage` JUnit suite.
  `--fail-on-uncovered` exits non-zero when a declared path was never hit.
- `h2h keygen` writes `<name>.key.pem` / `<name>.pub.pem` and prints the key id (`--convert`
  upgrades a 0.1 key file); `h2h sign` gains `--expires-in`, `--policy-version` and `--out`;
  `h2h verify` gains `--keyring`, `--now`, `--max-skew`, `--last-seen-version` and
  `--format json`, and names a 0.1 signature rather than rejecting it as corrupt.

**Testkit**

- **`fixtures/MANIFEST.json`**, generated and checked by
  `scripts/generate_fixture_manifest.py --check` in CI: every file under `fixtures/`
  with its SHA-256, category, module, and the level at which it becomes required. A
  conformance claim cites the corpus by this file's digest.
- `hushspec-testkit --fixtures fixtures --report report.json`, which runs the evidence-chain
  vectors as well as the document corpus, computes the highest fully passing level, validates
  the report against `schemas/hushspec-conformance-report.v1.schema.json`, and writes it.
- **`hushspec-testkit bundle`** packages `spec/`, `schemas/` and `fixtures/` with
  a README on running them. Reproducible byte for byte; `release.yml` builds it, checks
  reproducibility with a second build, and adds it to the release assets and the attestation
  `subject-path`.
- **Vectors for eleven previously unvectored requirements**: `enabled: false` on all twelve rule
  blocks, `tool_access.max_args_size` at and over the limit, deny-over-warn precedence with both
  outcomes real at once, all three secret severities, the inert `threat_intel` detector, an extends
  cycle, a three-hop chain (merge and evaluation), the missing merge strategy in every module
  (`merge` for core, `replace` for the three extensions), and `metadata` merge behaviour. The
  coverage table in `docs/src/reference/conformance.md` now has no empty cells.
- **`hushspec-testkit` is publishable**: crates.io metadata, a rewritten README, a publish step in
  `publish.yml` after `hushspec`, and `scripts/generate_testkit_schemas.py` embedding the schemas
  the runner validates against, without which `cargo package` cannot reach them.

**Library**

- The eight `library/` policies are embedded as built-ins in all four SDKs under
  `builtin:library/<vertical>/<name>`, so `extends: "builtin:library/finance/pci-dss"`
  resolves with no file system and no checkout. The four builtin generators now walk
  `library/` alongside `rulesets/`; the existing `rulesets/` names are unchanged, and the
  Go SDK gains an exported `BuiltinNames`. A library policy keeps its own document `name`
  (`pci-dss`): the prefix is a location, not a rename.
- A control-tagged evaluation suite for each of the eight library policies under
  `fixtures/library/<vertical>/<name>.test.yaml` (198 cases): every case declares the control
  it proves, and between them the cases hit every rule block and every named secret pattern of
  the resolved policy. CI runs them with `--fail-on-uncovered` and uploads the JUnit report.
  The conformance testkit discovers them too.

**CI**

- GitHub composite Action (`action.yml`, `backbay-labs/hush@<ref>`): installs `h2h` --
  downloading, `SHA256SUMS`- and provenance-attestation-verifying, and caching the prebuilt
  release tarball for the runner's platform, or building `crates/hushspec-cli` from source via
  `version: source` before any release with binaries exists -- and runs `validate`, `lint`,
  `test`, `audit` or `bundle-verify` over glob-matched paths with `text`/`json`/`sarif`/`junit`
  output, exposing `exit-code` and `report-path`. `.pre-commit-hooks.yaml` adds
  `hushspec-validate`, `hushspec-lint`, `hushspec-lint-strict` and `hushspec-fmt-check`. A
  multi-stage `Dockerfile` builds an `h2h` image, published to `ghcr.io/backbay-labs/h2h` on
  every tagged release. New guide: `docs/src/guides/ci.md`.
- A **Library Suites** job: it runs the library suites with `--fail-on-uncovered`, writes the
  run's results and rule-coverage table to the GitHub step summary, and uploads the JUnit
  report as an artifact for any JUnit consumer.

**Docs**

- `docs/src/reference/sdk-api.md`: the cross-SDK API contract. Nineteen capability
  areas -- parse/validate, merge/resolve with verify-on-load and digest pins, compiled
  policies, the four evaluation entry points, conditions (`capability` and `rate`),
  detection (`heuristic_injection@1`), canonical form and content hash, receipts 0.2 and
  the receipt hash, the log chain, signing and keyrings, bundle verification, the guard
  with its enforcement modes and refused state, observers and metrics, providers and hot
  reload, sinks including OTLP, adapters, panic mode, version constants and error codes --
  each a table giving the exact entry point every SDK publishes today, the shared semantic
  contract, and the deliberate language-idiom differences (Rust `Result`, TypeScript
  `{ok, value}` unions, Python `(ok, value)` tuples with `_or_raise` variants, Go
  `(T, error)`). Plus the cross-SDK invariants and the check that enforces each: identical
  decisions, identical canonical bytes and `content_hash`, byte-identical receipts after
  JCS under the fixed inputs, identical reason and error codes, and identical public names.
  Every name in the page is verified against the source.
- `docs/src/reference/conformance-statement.md`: the template a third party fills in to publish
  a conformance claim, with the procedure for producing the evidence and the rules for an honest
  statement.
- `CHANGELOG.md`, `SECURITY.md`, `GOVERNANCE.md`, `CONTRIBUTING.md` at the repository root.

### Changed

**Spec**

- **One HTTPS `extends` loader rule set.** Core spec 2.6.4 is rewritten as ten MUSTs that say
  exactly what every SDK enforces: `https:` only with `http://` refused outright, an optional
  exact and case-insensitive host allowlist checked before DNS, a tabulated blocked-network list
  (`0.0.0.0/8`, `10/8`, `100.64/10`, `127/8`, `169.254/16`, `172.16/12`, `192.0.0/24`,
  `192.168/16`, `198.18/15`, `224/4`, `240/4`, `::/128`, `::1/128`, `fc00::/7`, `fe80::/10`,
  `ff00::/8`) that *every* resolved address must clear, IPv4-mapped and IPv4-compatible IPv6
  forms unwrapped and judged on the address inside, an unparseable address treated as blocked,
  the checked address pinned for the connection while the host name still carries SNI,
  certificate validation and the `Host` header, no redirects, separate connect and read budgets,
  a capped body, `ETag` revalidation that serves a cached body only on a `304`, and `<url>.sig`
  fetched under the identical rules. The previous text named a looser list, said nothing about
  allowlists, pinning or the sidecar, and left the size and time bounds as one budget.
  `spec/hushspec-security.md` section 4 is aligned with it and its residual-risk paragraph now
  describes what the list and the pin actually leave open.

**SDKs**

- Package versions are 1.0.0: `hushspec`, `hushspec-cli`, and `hushspec-testkit` on crates.io,
  `@hushspec/core` on npm, and `hushspec` on PyPI.
- **All four SDKs are Level 5 (Attested)**, not Rust alone: TypeScript, Python and Go now run
  the bundle vectors, which were the last Level 5 gap, and all four fixture runners assert the
  `.expect.yaml` sidecar's registered error code and `message_contains` substring, closing the
  Level 1 error-code gap.
- A skipped rule block records why it was not consulted instead of reporting itself inactive.
  `secret_patterns` evaluated without content records
  `content not supplied; secret_patterns not consulted`, and `remote_desktop_channels` with a
  target that is not a channel records
  `target is not a remote desktop channel; remote_desktop_channels not consulted`. Both strings
  are byte-identical in all four evaluators, since a receipt records them; the expected receipts
  under `fixtures/receipts/expected/` and the log and report vectors are regenerated.
- **`args_size` is measured in UTF-8 bytes of the canonical JSON** (core spec 3.7) by every
  adapter and guard mapping in TypeScript, Python and Go. The previous measurements were the
  ones the spec names as wrong: `JSON.stringify(args).length` counts UTF-16 code units, so
  TypeScript undercounted every non-ASCII payload -- a 12-byte argument of emoji measured as 10
  slipped under a `max_args_size` of 11; `len(json.dumps(args))` counts the spaces Python's
  encoder writes; and measuring a string payload as received counts whatever whitespace and
  `\uXXXX` escaping the transport chose. One limit now bounds the same payload behind every
  adapter and in every SDK. Rust has no adapters and was already correct. Affects any
  `max_args_size` decision on a non-ASCII or non-compact payload, and the `action.args_size` a
  receipt records for it.

**Rust**

- The HTTPS `extends` loader (`hushspec::resolve::http`, the `http` feature) enforces the full
  rule set of core spec 2.6.4. The blocked-network list grows from the loopback, RFC 1918,
  link-local and unique-local ranges to every network the spec tabulates, IPv4-mapped and
  IPv4-compatible IPv6 forms are unwrapped and judged on the address inside, and an address that
  cannot be parsed is blocked. The connection is then **pinned** to the address that was checked
  -- `reqwest`'s `ClientBuilder::resolve` maps the host to the vetted socket address, so the
  socket goes there while TLS still validates the hostname the document wrote -- which closes the
  DNS-rebinding window between the check and the connect. A 3xx is refused with a message naming
  the refusal rather than reported as a generic non-2xx, `HttpLoaderConfig` gains
  `allowed_hosts` (exact, case-insensitive, checked before DNS) and splits `timeout_ms` into
  `connect_timeout_ms` and `read_timeout_ms`, and `fetch_signature` / `signature_locator` fetch
  `<url>.sig` under the identical rules. `is_blocked_address`, `validate_url` and `HttpTarget`
  are public, as they are in the Python and Go SDKs.

**TypeScript**

- The HTTPS `extends` loader (`http-loader.ts`) enforces the same rule set, over `node:https`
  rather than `fetch`, because a pinned connection is not something `fetch` can express. A
  `lookup` that returns only the checked address pins the socket while `servername` keeps SNI,
  certificate validation and the `Host` header on the hostname the document wrote; a 3xx is
  refused explicitly. The blocked-network list is the spec's, addresses are parsed rather than
  string-matched (so `100.64/10`, `192.0.0/24`, `198.18/15`, `224/4`, `240/4` and `ff00::/8` are
  covered and an unparseable address is blocked), and `HttpLoaderConfig` gains `allowedHosts`,
  `connectTimeoutMs` and `readTimeoutMs`. `isPrivateIp` is renamed `isBlockedAddress`, and it,
  `resolveTarget`, `CLOUD_METADATA_ADDRESSES` and the default bounds are exported.
  `HttpProvider`'s options are now the loader's, so a provider cannot quietly relax a rule.
- Evaluation no longer compiles patterns per call: the free `evaluate()` functions compile the
  document on first use and cache the compilation against the document object (a `WeakMap`), so
  decisions, receipts, hashes and traces are unchanged while a mixed action set against
  `rulesets/default.yaml` drops from 17.9 us to 4.4 us per evaluation (4.0x) and
  `HushGuard.check()` from 18.0 us to 4.9 us (3.7x); compiling the policy on every action would
  cost 73 us. `packages/hushspec/bench/evaluate.mjs` (`npm run bench`) is the benchmark.
- **Breaking.** `evaluateAudited` takes a `Resolution` rather than a `HushSpec`; use
  `evaluateAuditedSpec` for a bare document. `AuditConfig` is `{ enabled, includeRuleTrace,
  recordDuration }` -- `redact_content` is gone, because a 0.2 receipt never carries content.
- **Breaking.** `SignatureStatus.signed_at` is now `verified_at` and holds the verifier's
  clock rather than the envelope's signing time.
- **Breaking.** The chain identity of an in-memory document is `memory`, as in every other SDK
  and in `fixtures/core/resolve/`.
- Resolution failures throw a `ResolveError` carrying a machine-readable `reason`
  (`invalid_pin`, `not_found`, `cycle`, `max_depth`, ...) instead of a bare `Error`.

**Python**

- Compiled policies: `compile_policy(spec)` returns a `CompiledPolicy` that
  prepares everything independent of the action -- every regex through the profile, every path
  glob and host pattern, the tool-name sets, the decoded `when` conditions, the per-action-type
  rule-block plan, the origin overlays folded into `tool_access` / `egress` per profile, and the
  detectors a `detection:` block enables -- and keeps the source document with its content hash
  cached for receipts. It is fail-closed in both directions: strict by default (`CompileError`
  names the offending rule path), and `strict=False` keeps the evaluator's deferred deny. The
  free `evaluate` / `evaluate_traced` / `evaluate_with_context` / `evaluate_with_detection` /
  `evaluate_audited` functions are unchanged wrappers over a small compiled-policy cache, and
  `HushGuard` compiles once at construction and at every `swap_policy()` (`guard.compiled`).
  Pattern compilation is memoized, so policies that share a base compile once between them.
  No change to decisions, receipts, traces, hashes or wire formats. Evaluating the mixed action
  set of `packages/python/bench/evaluate.py` against `rulesets/default.yaml` goes from 127 us to
  9.0 us per action.

**CLI**

- **Breaking (signing).** Signature format 0.1 is superseded and cannot be verified by 0.2:
  it signed raw file bytes with bespoke 32-byte key files. Convert a key with
  `h2h keygen --convert <old.key>` and re-sign with `h2h sign`. `h2h keygen` now writes
  `h2h.key.pem` / `h2h.pub.pem` rather than `h2h.key` / `h2h.pub`, and `h2h sign` drops
  `--key-id` (the id is the SPKI digest and is never chosen by the signer). The Rust
  `hushspec::signing` API is rewritten around `Envelope`, `Keyring` and `ReasonCode`.
- `h2h test --format json` now prints an object (`passed`, `failed`, `fixtures[]`, `coverage`)
  rather than a bare array of per-file results; the per-file objects are unchanged and now also
  carry each case's `controls` and `tags`.
- `L007`'s twelve-block list and `L020`'s `when` walk are both checked against the published
  core schema, so a thirteenth rule block cannot be added without both noticing.
- Exit `2` now also covers `--out` combined with `--format text`.

**Docs**

- **The README capability matrix and the conformance pages are rewritten from the code**, and
  the claims that were no longer true are corrected: `HushGuard`, observers, hot reload, policy
  signing, receipt signing and the OTLP sink are in all four SDKs, not two; `content_hash` *is*
  byte-identical across the SDKs (`hushspec-difftest` compares it, and the receipt hash, on 500
  generated policy groups per commit); there are twelve rule blocks, not ten; the CLI has 22
  subcommands, not ten. Newly documented limits: Python and Go load `https:` `extends` references only through
  their opt-in loaders and refuse them otherwise, bundle *creation* is Rust and `h2h` only, Rust ships no
  framework adapters, Rust signing needs the `signing` feature and Python's needs the `signing`
  extra, and Go spells the guard `Guard`. `docs/src/reference/sdk-conformance.md` is written from
  the vectors each SDK's tests actually walk, citing the test file for every vector family, and
  Levels 0, 1 and 3 in `docs/src/reference/conformance.md` are aligned word for word with core
  spec section 8, with no known-gap note left.
- The roadmap records which of the section 8 criteria are now met -- `when` conditions specified
  and schema-defined, all four SDKs past Level 3, `HushGuard` in every SDK, Ed25519 signing in
  every SDK, panic mode in every SDK, separation of duties enforceable (`GOV_SOD_VIOLATION`,
  `h2h sign --allow-unapproved`), compliance mappings on every library policy, and evaluation
  suites for all eight -- and which are not: package-registry publication and prebuilt binaries (no
  `v1.0.0` tag cut yet), a cloud-storage policy loader, and published
  Prometheus recording rules and alert examples.
- Repositioned the project around "agentic compliance as code": updated the tagline and
  introductory copy across `README.md`, `docs/src/introduction.md`, package manifests, and
  package READMEs.

### Deprecated

**TypeScript**

- `INLINE_POLICY_SOURCE` is a deprecated alias of `MEMORY_SOURCE`.

### Removed

**CLI**

- **Lint rule `L005` is retired.** It reported a permissive default as information and only when
  the allow list was non-empty; `L017` reports every occurrence as a warning. The identifier
  will not be reused. `rulesets/permissive.yaml` stays gated on lint *errors* only and now
  reports `L004` and `L017` by design.

### Fixed

**Spec and SDKs**

- `when` conditions evaluate to true, false, or unevaluable (core spec 3.13). `not` over an
  unevaluable predicate (a `rate` counter the engine did not supply, a `capability` on a policy
  with no posture extension, a time window whose clock cannot be read) is itself unevaluable and
  leaves the block active; `all_of` and `any_of` propagate unevaluable the same way. Previously
  `not` negated the held result into false and switched the block off. Vectors:
  `fixtures/core/evaluation/conditions-unevaluable-not.test.yaml`,
  `fixtures/core/evaluation/conditions-unevaluable-combinators.test.yaml`.
- The posture guard looks the current state up before consulting the capability table (posture
  spec 3.3), so an action whose `posture.current` names an undeclared state is denied whatever
  its action type, including the types the table does not gate. Vector:
  `fixtures/posture/evaluation/unknown-state-fail-closed.test.yaml`.
- Host normalization ends the URL authority at a backslash as well as at `/`, `?` and `#` (core
  spec 3.14.2), the way browsers parse special-scheme URLs, so
  `http://blocked.example\@allowed.example` names `blocked.example`. Vector:
  `fixtures/core/evaluation/host-normalization-backslash.test.yaml`.
- `ChainedFileSink` in every SDK derives `seq` and `prev_hash` from the file's last entry while
  holding the write lock (log spec 4), so two sinks or processes appending to one log extend a
  single chain instead of forking it.
- Log verification validates every receipt payload as a 0.2 receipt (log spec 8, step 8). The
  TypeScript, Python and Go verifiers previously checked only `receipt_version`; their receipt
  parsers now enforce the required members, types, closed enums and timestamp spelling the Rust
  model enforces, and every SDK rejects a timestamp naming an impossible calendar date. Vector:
  `fixtures/log/invalid/malformed-receipt-line-2.jsonl`.
- The v1 schemas bound the month, day, hour, minute and second of every timestamp to its
  calendar range and carry `format: date-time`.
- Signing spec 6.2 step 1 defers the `format_version` and `algorithm` value constraints to
  steps 2 and 3, so `unsupported_format_version` and `unsupported_algorithm` stay reachable. The
  vector `impossible-signed-at-date` expects `malformed_envelope` for a February 30 `signed_at`.
- TypeScript: the regex profile's `.`, negated classes and negated shorthands consume an astral
  character as one code point and no longer backtrack into half a surrogate pair
  (`fixtures/core/evaluation/regex-dialect.test.yaml`); canonicalization refuses an integer
  outside the safe range (canonical spec 4.3) instead of hashing the rounded double;
  `HttpProvider` fetches a policy's `.sig` sidecar under the same TLS, loopback and
  authorization configuration as the policy; bundle creation treats only a `..` path segment as
  leaving `baseDir`.
- Auditing with the rule trace switched off records no trace at all; `AuditConfig`'s
  low-overhead mode no longer allocates a trace it discards.
- Go: every optional free-text string of the document model is a `*string`, so a property
  written as `""` is present in the canonical form and the content hash exactly as it is in the
  other SDKs, instead of being dropped as if absent. Merging, the receipt policy summary, the
  bundle subject and the observer events carry presence the same way. Vector:
  `fixtures/core/hash/empty-strings.yaml`. The Python bundle subject and the Rust signer's
  policy-name claim follow the same presence rule.

- The regex profile reads every pattern the same way in all four SDKs: one group grammar
  (named groups in either spelling are permitted; `(?#`, lookaround, backreferences and POSIX
  bracket classes are refused), `{,n}` is refused, `(?i)` folds ASCII letters only by expansion
  so no engine folds U+017F or U+212A, an astral character inside a class is one scalar value in
  TypeScript, a pattern is at most 2048 bytes, every rejection carries the same per-feature
  message and E005, and a fixed-offset `timezone` is `[+-]HH` or `[+-]HH:MM` with two-digit
  fields. Vectors under `fixtures/core/invalid/regex-*.yaml`, `when-timezone-*.yaml` and
  `fixtures/core/evaluation/regex-dialect.test.yaml`.
- Canonical form: a number written with integer syntax is bounded by 2^53-1 and one written
  with float syntax is emitted at any magnitude, in every SDK (TypeScript narrows integers at
  parse time; Go refuses an integer literal past 2^64 that its YAML parser would have rounded);
  a written `null` for a declared property, an unknown key, a non-object `extensions` and an
  unknown extension name are refused everywhere, and the reference canonicalizer refuses an
  unresolved `extends` and a duplicate YAML key. Vector `fixtures/core/hash/numbers-large.yaml`.
- Evidence chain: bundle verifiers reject a revoked or retired key (`key_revoked`,
  `key_retired`; vectors `revoked-key`, `retired-key`); every receipt parser validates the 0.2
  structure and refuses an explicit `null`; a leap second is refused (vector
  `leap-second-signed-at`); log writers share one lock protocol (the `<path>.lock` sentinel,
  with `flock` held underneath in Python and Go, and a bounded wait in every SDK), always record
  `previous_entry_hash`, rotate under one lock and refuse a corrupt tail; the Python refusal
  receipt carries the refused document's real content hash; TypeScript and Python record
  `missing_signature` when verification was attempted; a claimed `key_id` is recorded only when
  well formed; `compile()` refuses a document that still declares `extends` in every SDK;
  `Policy::resolve` merges options instead of replacing them; Go's `EvaluateAudited` returns an
  error rather than a receipt with an empty content hash.
- Conditions and adapters: `when.context` matching (scalar membership in both directions,
  array intersection, exact numbers) is written into core spec 3.13 and pinned by
  `conditions-context-match.test.yaml`; Python drops a counter that is not a whole number; Go
  refuses an empty `capability` or `timezone`; `min_score` is bounded to 100 at parse time; the
  TypeScript Claude adapter scans a `create` command's `file_text`, strips dated tool suffixes
  and maps `web_fetch` to egress; MCP tools map through the shared well-known table; the Vercel
  wrapper keeps a tool's prototype; the Go adapter entry points carry the same names as the
  other SDKs; the TypeScript guard re-checks an adopted resolution under `requireSignature`; the
  poller survives a throwing callback; the Python provider fingerprints a file before loading it.
- Observers and sinks: a failing receipt sink never changes a decision and is reported as a
  `sink.error` event in every SDK (Go's `Check` no longer returns it); `MultiSink` surfaces a
  child's failure; Rust observers absorb a panicking hook; Python and Go OTLP records carry
  `observedTimeUnixNano` and `severityNumber`; Go's metrics count only load failures as failed
  loads.

**CLI and tooling**

- `h2h report` runs the receipt schema pass `h2h log verify` runs and takes `--keyring`,
  `--key`, `--require-signatures` and `--max-skew`; an unresolvable `--policy` for
  `h2h bundle verify` is a `policy_mismatch`; `h2h audit` and `h2h schema` report a
  serialization failure instead of exiting 0 silently.
- Workflows declare `permissions: contents: read`; the PyPI publish action is pinned to a
  commit; the release job fails without both signing keys unless `allow-unsigned` is passed and
  verifies the bundles it ships; the action caches the binary under the resolved release tag;
  `cargo deny` refuses yanked and unmaintained crates; every generator requires `rustfmt` and
  formats for edition 2024.
- `h2h report` treats a file holding any log entry as a log and verifies its chain, so a plain
  receipt prepended to a log cannot carry it past verification; mixed record types are reported.
- Control coverage (lint L011, `h2h audit --controls`, `h2h report`) counts a mapping only when
  its rule path resolves in the document.
- The GitHub Action reads its inputs from the environment instead of interpolating them into
  the shell script.
- The `h2h` build script watches the branch ref and `packed-refs` as well as `.git/HEAD`,
  including from a linked worktree, so `h2h version` reports the current commit.

**Library**

- `library/devops/cicd-hardened.yaml` listed `github_actions_token` (`ghs_...`) after the
  general `github_token` (`gh[opsur]_...`) that subsumes it, so an Actions token was always
  reported as a personal access token and the specific rule could never fire. The specific
  pattern now comes first; the set of matched content is unchanged.

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

Initial public release of the HushSpec specification and its Rust implementation.

### Added

- Core HushSpec specification and JSON Schema definitions in `spec/` and `schemas/`.
- 10 core rule blocks: `forbidden_paths`, `path_allowlist`, `egress`, `secret_patterns`,
  `patch_integrity`, `shell_commands`, `tool_access`, `computer_use`,
  `remote_desktop_channels`, `input_injection`.
- 3 extension modules: `posture`, `origins`, `detection`.
- Rust implementation (`crates/hushspec`) with parsing, validation, and merging.

[Unreleased]: https://github.com/backbay-labs/hush/compare/v0.1.1-alpha...HEAD
[0.1.1]: https://github.com/backbay-labs/hush/compare/98727b8...v0.1.1-alpha
[0.1.0]: https://github.com/backbay-labs/hush/commit/98727b8
