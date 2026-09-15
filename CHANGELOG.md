# Changelog

All notable changes to HushSpec are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
HushSpec follows the versioning policy in [`spec/versioning.md`](./spec/versioning.md);
until 1.0.0 the specification and SDKs are an unstable `0.x` series.

## [Unreleased]

### Added (RFC 09 P6-02, TypeScript SDK parity)

- `OtlpReceiptSink` (`@hushspec/core`): exports decision receipts and
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
### Added (RFC 09 Wave 5, Python SDK parity)

- Python `hushspec.provider`: a `PolicyProvider` protocol (`load() -> Resolution`, `source`)
  with `FileProvider` (carrying its `ResolveOptions`, so `require_signature` applies to every
  reload), `CallbackProvider`, and hot reload through `PolicyWatcher` (mtime + content hash) and
  `PolicyPoller` (any provider) -- daemon threads, context managers, an explicit `check_once()`
  tick, and optional panic-sentinel checking per tick. `HushGuard.from_provider(...)` builds a
  guard from a provider and can attach either loop; `HushGuard.swap_resolution()` swaps in an
  already-resolved policy without re-resolving it. A reload that cannot be read, parsed,
  resolved, verified or compiled leaves the policy in force untouched and is reported through
  `on_error`, then retried.
- Python `hushspec.otlp.OtlpReceiptSink`: exports receipts and policy events to an OTLP/HTTP
  collector as log records (`POST <endpoint>/v1/logs`) over `urllib` alone -- canonical JSON
  body, `INFO`/`WARN`/`ERROR` severity by decision, and the `hushspec.*` attributes and resource
  attributes shared with the Rust, TypeScript and Go sinks. Background thread, bounded queue
  (drop + counter + `on_error` on overflow), batching, retry with backoff on `429`/`5xx`/network
  errors, `flush()` and `close()`; `send()` never blocks on I/O.
- Python `hushspec.adapters.anthropic`: `map_claude_tool_to_action()` maps a Claude `tool_use`
  block onto the action a policy evaluates (`bash` -> `shell_command`, text editor -> `file_read`
  / `file_write` with content, `computer` -> `computer_use`, `web_fetch` -> `egress` on the host,
  `mcp__server__tool` -> the inner tool name, date-suffixed tool versions included), and
  `create_secure_tool_handler()` enforces before the tool runs. No `anthropic` import: blocks are
  read structurally.
- `hushspec.log.policy_event_to_dict()`: the one spelling of a policy event, shared by log
  entries and the OTLP sink.
### Added (RFC 09 P6-02, Go SDK runtime integration)

- Go SDK parity for the runtime-integration surface. `Guard` (`hushspec.NewGuard`,
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
### Added (RFC 09 P6-02, Rust runtime integration)

- `hushspec::guard` -- `HushGuard`, the Rust enforcement point, at parity with the
  TypeScript SDK's. Built from a `Policy`, a `Resolution` or a `CompiledPolicy`; carries the
  enforcement mode (with per-rule-path overrides, longest prefix wins), an `on_warn`
  confirmation channel (absent, a `warn` denies -- core spec D16), a `ReceiptSink`, observers,
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
  out in the module docs so the four SDK ports agree. Background thread and bounded queue, so
  export never blocks an evaluation; overflow drops with a counter and a `sink.error` observer
  event; `5xx` retried with backoff, `4xx` not; drop flushes.
- `cargo run --example guarded_agent --features otlp` -- a complete tool boundary: policy ->
  guard -> `check` -> `ChainedFileSink` + `OtlpSink`, with metrics, a monitored rule block and
  hot reload. New guide `docs/src/guides/runtime-integration.md`.
- `Policy::panic_state()` reads the kill switch a policy will compile with.
### Added (RFC 09 Wave 5, spec-first)

- **D18 ratified** (posture spec 5.3): a transition whose `from` names the current state outranks a `"*"` transition for the same trigger; the reference evaluator now implements it and the last staged vector is promoted (`fixtures/staged/` is gone).
- **`when.capability` and `when.rate`** (core spec 3.13, D19): a rule block can be gated on the effective posture state granting a capability, or on an engine-supplied counter in the new runtime-context `counters` map crossing a threshold; both are unevaluable-means-active. Rust implements them; `RateCondition`, `RateComparison`, `evaluate_condition_with_capabilities`, and `is_capability_identifier` are exported.
- **`heuristic_injection@1`** (detection spec 3.5, D20): a normative, integer-scored prompt-injection detector with a fixed signal table that every engine must reproduce exactly, configured by `prompt_injection.heuristics`; the reference registry runs it beside `regex_injection@1`.
- Lint L021 (warning): a `when.capability` naming a capability no posture state grants.

### Added (RFC 09 Wave 5, Integrations)

- GitHub composite Action (`action.yml`, `backbay-labs/hush@<ref>`): installs `h2h` --
  downloading, `SHA256SUMS`- and provenance-attestation-verifying, and caching the prebuilt
  release tarball for the runner's platform, or building `crates/hushspec-cli` from source via
  `version: source` before any release with binaries exists -- and runs `validate`, `lint`,
  `test`, `audit` or `bundle-verify` over glob-matched paths with `text`/`json`/`sarif`/`junit`
  output, exposing `exit-code` and `report-path`. `.pre-commit-hooks.yaml` adds
  `hushspec-validate`, `hushspec-lint`, `hushspec-lint-strict` and `hushspec-fmt-check`. A
  multi-stage `Dockerfile` builds an `h2h` image, published to `ghcr.io/backbay-labs/h2h` on
  every tagged release. New guide: `docs/src/guides/ci.md`.
### Added (RFC 09 Wave 5)

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
  `schemas/hushspec-report.v0.schema.json` (`h2h schema report`), `--format csv` writes one table
  per file into `--out` (or the `--by` table to stdout), and `--format oscal` behind
  `--experimental-oscal` emits a minimal OSCAL 1.1.2 assessment-results skeleton. The aggregation
  itself is the new `hushspec::report` module. Vectors: `fixtures/report/` -- a synthetic 24-hour
  log and the exact report it must produce, both drift-checked.
### Added (RFC 09 P3-04, `h2h lint`)

- **Source spans.** Every finding is now located at the key or list entry it is about
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
  uploads the file with `github/codeql-action/upload-sarif`, guarded so a fork -- which
  cannot hold `security-events: write` -- still passes.
- **Seven new lint rules**, each documented with its rationale in
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

### Changed (RFC 09 P3-04, `h2h lint`)

- **`L005` is retired.** It reported a permissive default as information and only when the
  allow list was non-empty; `L017` reports every occurrence as a warning. The identifier
  will not be reused. `rulesets/permissive.yaml` stays gated on lint *errors* only and now
  reports `L004` and `L017` by design.
- L007's twelve-block list and L020's `when` walk are both checked against the published
  core schema, so a thirteenth rule block cannot be added without both noticing.
- Exit `2` now also covers `--out` combined with `--format text`.
### Added (RFC 09 Wave 5, conformance program: P4-01, P4-02, P4-03)

- **Conformance levels 4 and 5** are normative in `spec/hushspec-core.md` section 8, closing the
  forward references the receipt and signing specifications already made. **Level 4 (Auditor)**:
  receipt format 0.2, a canonical `policy.content_hash` over the resolved document, a `rule_trace`
  recorded rather than reconstructed, the committed receipt for every evaluation case reproduced
  after RFC 8785 canonicalization, and the canonical-form and resolution vectors. **Level 5
  (Attested)**: a conforming signature verifier, verification on load recorded in
  `receipt.policy.signature`, a hash-linked log rejected at the line its file name names, receipt
  signing, and bundle verification. Section 8 also states that a claim is made against a corpus
  pinned by digest, and that `not_attempted` is never a pass.
- **`fixtures/MANIFEST.json`**, generated and checked by
  `scripts/generate_fixture_manifest.py --check` in CI: every file under `fixtures/` except
  `staged/`, with its SHA-256, category, module, and the level at which it becomes required. A
  conformance claim cites the corpus by this file's digest.
- **Expected error codes on every `invalid/` vector.** `spec/registries/error-codes.yaml` registers
  the codes the reference validator emits (`E000`-`E005`, `E010`, `E011`), validated by
  `schemas/hushspec-error-codes.v0.schema.json`, whose `$defs/ExpectedError` is the shape of the new
  `fixtures/<module>/invalid/<name>.expect.yaml` sidecars. The Rust testkit asserts the code and any
  `message_contains` substring. The TypeScript, Python and Go runners still require only rejection;
  that gap is documented in `docs/src/reference/conformance.md` and closes with P6-03.
- **`schemas/hushspec-merge-vector.v0.schema.json`** writes down the merge vector directory
  convention (`base.yaml`, `child-*.yaml`, `expected-*.yaml`, the digest-pin path through the
  resolver, and the two refusal markings all four runners honour), validated against every merge
  directory in the corpus by a testkit test.
- **`schemas/hushspec-conformance-report.v0.schema.json`** and
  `hushspec-testkit --fixtures fixtures --report report.json`, which runs the evidence-chain vectors
  as well as the document corpus, computes the highest fully passing level, validates the report
  against its own schema, and writes it.
- **`hushspec-testkit bundle`** packages `spec/`, `schemas/` and `fixtures/` (minus `staged/`) with
  a README on running them. Reproducible byte for byte; `release.yml` builds it, checks
  reproducibility with a second build, and adds it to the release assets and the attestation
  `subject-path`.
- **`docs/src/reference/conformance-statement.md`**: the template a third party fills in to publish
  a conformance claim, with the procedure for producing the evidence and the rules for an honest
  statement.
- **Vectors for eleven previously unvectored requirements**: `enabled: false` on all twelve rule
  blocks, `tool_access.max_args_size` at and over the limit, deny-over-warn precedence with both
  outcomes real at once, all three secret severities, the inert `threat_intel` detector, an extends
  cycle, a three-hop chain (merge and evaluation), the missing merge strategy in every module
  (`merge` for core, `replace` for the three extensions), and `metadata` merge behaviour. The
  coverage table in `docs/src/reference/conformance.md` now has no empty cells.
- **`hushspec-testkit` is publishable**: crates.io metadata, a rewritten README, a publish step in
  `publish.yml` after `hushspec`, and `scripts/generate_testkit_schemas.py` embedding the schemas
  the runner validates against, without which `cargo package` cannot reach them.
### Added (RFC 09 P3-02, test-as-evidence)

- Evaluator-test fixtures format **0.2.0** (`schemas/hushspec-evaluator-test.v0.schema.json`,
  same file name): a case may declare `controls: [{framework, control_id}]` -- the controls it
  is evidence for -- and free-form `tags`, and its `expect` may assert `rule_trace` (the
  recorded trace of receipt spec 4.3, compared in order and in full, with `rule_path` compared
  only where it is spelled) and `receipt` (a partial format 0.2 receipt whose members must equal
  the receipt produced under the fixed inputs of `fixtures/receipts/expected/README.md`;
  `actor`, `timestamp` and `receipt_id` are ignored, nested objects are compared member-wise).
  `hushspec_test` now accepts `0.1.0` and `0.2.0`, so every existing fixture stays valid.
- `h2h test --format junit` writes a JUnit XML report -- one `<testsuite>` per fixture file,
  one `<testcase>` per case, each case's `controls` and `tags` as `<property>` entries, and each
  failure as a `<failure>` carrying the expected and the actual value -- and `--report-file`
  writes the report to a path while stdout keeps the readable summary.
- Rule coverage in `h2h test`: every run compares the rule paths a policy declares (every rule
  block of the resolved document, plus every named secret pattern) with the paths its cases hit
  through `matched_rule` and through each `rule_trace` entry, prints the table, and reports the
  numbers in the JSON report's new `coverage` member and in a `rule coverage` JUnit suite.
  `--fail-on-uncovered` exits non-zero when a declared path was never hit.

### Added (RFC 09 P3-03, vertical library)

- The eight `library/` policies are embedded as built-ins in all four SDKs under
  `builtin:library/<vertical>/<name>`, so `extends: "builtin:library/finance/pci-dss"`
  resolves with no file system and no checkout. The four builtin generators now walk
  `library/` alongside `rulesets/`; the existing `rulesets/` names are unchanged, and the
  Go SDK gains an exported `BuiltinNames`. A library policy keeps its own document `name`
  (`pci-dss`): the prefix is a location, not a rename.

### Added (RFC 09 P3-03, library suites)

- A control-tagged evaluation suite for each of the eight library policies under
  `fixtures/library/<vertical>/<name>.test.yaml` (198 cases): every case declares the control
  it proves, and between them the cases hit every rule block and every named secret pattern of
  the resolved policy. CI runs them with `--fail-on-uncovered` and uploads the JUnit report.
  The conformance testkit discovers them too.
- CI gains a **Library Suites** job: it runs the suites with `--fail-on-uncovered`, writes the
  run's results and rule-coverage table to the GitHub step summary, and uploads the JUnit
  report as an artifact for any JUnit consumer.

### Fixed (RFC 09 P3-03)

- `library/devops/cicd-hardened.yaml` listed `github_actions_token` (`ghs_...`) after the
  general `github_token` (`gh[opsur]_...`) that subsumes it, so an Actions token was always
  reported as a personal access token and the specific rule could never fire. The specific
  pattern now comes first; the set of matched content is unchanged.

### Changed (RFC 09 P3-02)

- `h2h test --format json` now prints an object (`passed`, `failed`, `fixtures[]`, `coverage`)
  rather than a bare array of per-file results; the per-file objects are unchanged and now also
  carry each case's `controls` and `tags`.

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

### Added (RFC 09 Wave 4, Go)

- The evidence chain in the Go SDK, matching the Rust reference byte for byte. Receipt format
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

### Added (RFC 09 Wave 4, TypeScript)

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
- `CompiledPolicy` (P6-01): `compilePolicy(spec)` / `compileResolution(resolution)` build every
  policy regex, path glob, host pattern, tool set, parsed `when` condition, severity table and
  detector configuration once, and `evaluate` / `evaluateTraced` / `evaluateWithContext` /
  `evaluateWithDetection` / `evaluateAudited` run against that form; `contentHash` is computed on
  first use and cached, and the source document is kept verbatim for receipts. `compilePolicy`
  raises `CompileError` for a pattern outside the regex profile instead of deferring it to an
  evaluation-time deny (`{ strict: false }` keeps the deny). `HushGuard` compiles once at
  construction and on `swapPolicy()`, and exposes `guard.compiled`.

### Changed (RFC 09 Wave 4, TypeScript)

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
- **Breaking.** The chain identity of an in-memory document is `memory`, matching the Rust
  reference and `fixtures/core/resolve/`. `INLINE_POLICY_SOURCE` is kept as a deprecated alias
  of the new `MEMORY_SOURCE`.
- Resolution failures throw a `ResolveError` carrying a machine-readable `reason`
  (`invalid_pin`, `not_found`, `cycle`, `max_depth`, ...) instead of a bare `Error`.
### Changed (RFC 09 P6-01, Python)

- Compiled policies in the Python SDK: `compile_policy(spec)` returns a `CompiledPolicy` that
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
