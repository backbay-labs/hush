# Trustworthy Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended by the general workflow) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repair Project A's evidence and attribution gaps without claiming that the independent-engine runner or MCP dispatch boundary has been delivered.

**Architecture:** Keep ordinary reporting and stable wire formats intact. Add an offline strict-verification module that produces authenticated, stream-scoped records and a separately versioned verification sidecar. Reuse existing aggregation and signing primitives; contextual OSCAL consumes verified evidence, never unverified input.

**Tech Stack:** Rust 2024/MSRV 1.88, serde/serde_json, existing jsonschema 0.18 and signing primitives; TypeScript/Vitest 4.1.11, Python/pytest and Go 1.22 for callback regressions. Promote already-locked `tempfile = "3"` to a CLI runtime dependency and add the already-locked `sha2 = "0.10"` for exact byte digests. No dependency upgrades.

**Spec:** [Approved trustworthy-evidence design](../specs/2026-09-22-trustworthy-evidence-design.md). Read it with this plan. The [milestone roadmap](../../plans/2026-09-22-foundation-assurance-roadmap.md) retains Projects B/C/D.

**Status:** User-approved; Tasks 1-9 are implemented on `wave-6`. Task 10 qualification is recorded in [Project A qualification](../../reviews/2026-09-22-project-a-qualification.md), with local and hosted evidence kept separate. The checklists below preserve the execution requirements, not an assertion that pending hosted checks passed. Planning baseline: clean `wave-6` at `3cca247`. Execution uses the existing checkout as requested, native implementation and one fresh independent whole-branch review.

## Global Constraints

- "Do not add fields to the closed receipt, log, conformance-report or report v1 schemas."
- "Keep ordinary `h2h report` as an exploratory aggregation command."
- "Preserve the existing log-only scope of `--require-signatures`, but make it explicit in help and examples."
- "The first implementation is offline: no implicit URL fetching from profile values."
- "Hash, parse and aggregate the same bytes."
- "Existing outputs must not be silently overwritten."
- "Continue targeting the exporter's pinned OSCAL 1.1.2 format; upgrading OSCAL itself is outside this repair."
- "Merging the stack, tagging and publishing remain distinct authorized actions."
- Ordinary callback failure stays a failure; no new receipt outcome, weakened assertions or exception swallowing that authorizes execution.
- Use conventional commits, `apply_patch` for authored edits, and preserve unrelated changes. Do not amend/rebase the user's stack.

## Review Focus

1. Duplicate JSON keys, explicit nulls and deeply nested input must not be accepted differently by signature verification and schema validation. Task 4 owns the tests.
2. A replaced pathname, duplicate file alias or record outside the selected time window must not bypass authentication. Tasks 5/7 own the tests.
3. Signed but misordered policy events and the same receipt copied between streams must not create false policy attribution or doubled counts. Task 6 owns the tests.
4. A callback throwing a nonstandard value, or a sink failing during that exception, must preserve the original failure and never authorize the action. Tasks 2/3 own the tests.
5. Output-path collisions, partial publication and AP references relative to a different directory must fail without creating a mismatched assurance packet. Tasks 7/8/9 own the tests.

## File and interface map

| Boundary | Files | Responsibility |
|---|---|---|
| Reference identity | `crates/hushspec-testkit/src/main.rs`, new `tests/identity_tests.rs` | Reference-only attribution, no arbitrary engine labels |
| Callback repair | Four existing middleware/guard files and tests | Record recoverable blocked attempts before propagating failure |
| Wire contracts | New `crates/hushspec-cli/src/report_evidence/model.rs` | Closed experimental profile, inventory and verification types |
| JSON/snapshot boundary | New `report_evidence/json.rs`, `snapshot.rs` | Reject ambiguity; bounded, exact-byte local input snapshots |
| Authentication | New `report_evidence/verify.rs` | Signed receipts, signed rotations, source authorization |
| Policy attribution | New `report_evidence/policy.rs`, `src/report_controls.rs` | Policy intervals, origin checks, interval-specific control mappings |
| CLI and output | New `report_evidence/{mod,output}.rs`; existing `src/{main,cmd_report}.rs` | Strict path, aggregate/report binding, publish completion sidecar last |
| OSCAL | New `src/{oscal_context,oscal_report}.rs`, `schemas/oscal/v1.1.2/` | Pinned offline schemas, bounded context, observations only |
| Tests | New `crates/hushspec-cli/tests/{evidence_report_tests,oscal_tests}.rs`; module unit tests | Negative cases plus CLI acceptance |
| Experimental schemas | New `schemas/hushspec-evidence-{profile,inventory,verification}-experimental.v1.schema.json` and `hushspec-assessment-context-experimental.v1.schema.json` | New schema identities, artifact version `0.1.0`, explicitly experimental |

All paths in the module rows are relative to `crates/hushspec-cli/src/` unless fully qualified. The new schema lineage does not change Core 1.0 or claim these artifacts are stable. Add only new schema IDs; never modify the existing report schema to fit the sidecar.

## Pinned contracts

### CLI, limits and exits

Strict JSON requires `--evidence-profile`, exactly one of `--key`/`--keyring`, `--format json`, `--out`, and `--verification-out`. The positional source files must equal the profile's files in flattened stream/file order after canonical path resolution. Reject `--lenient`, `--unverified`, `--by`, stdout output, and output aliases of any input. `--since`/`--until`, if supplied, must equal the profile window; otherwise use its bounds. `--now` remains the verifier clock, not the asserted event clock. Reject negative `--max-skew` in strict mode.

Strict OSCAL additionally requires `--format oscal --experimental-oscal --assessment-context <file> --native-report-out <file>`; `--out` names the OSCAL file. `--policy` may select a single already-declared, digest-checked local policy artifact, never trigger remote resolution. Without it, strict mode uses the profile's optional resolved policy artifacts. Do not discover policies from receipt `extends_chain` paths in strict mode.

New operator flags, all positive and strict-mode-only:

| Flag | Default | Maximum accepted |
|---|---:|---:|
| `--max-evidence-file-bytes` | 16777216 | 1073741824 |
| `--max-evidence-total-bytes` | 67108864 | 1073741824 |
| `--max-evidence-line-bytes` | 1048576 | 16777216 |

Require line <= file <= total. Fixed bounds: 64 streams, 1024 distinct artifacts, 1000000 evidence records, JSON depth 64. Metadata/context JSON uses the file/total bounds; JSONL lines also use the line bound. Fail rather than truncate. Bounds include policy/context/inventory artifacts; key inputs retain existing parser rules and get the file-size cap before loading. No profile can raise operator limits.

Exit 0 only after successful publication. Exit 1 for input digest mismatch, duplicate receipts, failed signature, signer authorization, chain, policy binding or required boundary checks. Exit 2 for usage, malformed documents, unsupported contracts, size limits, I/O, context/reference validation or output conflicts. Diagnostics identify a code, artifact and optional line without dumping raw records. These are CLI-local codes, not additions to the frozen signing reason registry.

### Profile and inventory

JSON member names below are exact. Every object rejects unknown members and explicit nulls. Optional means omitted. Digests are exact byte SHA-256 in `sha256:<64 lowercase hex>` form; policy `content_hash` instead uses existing canonical policy semantics. Lists have unique IDs/paths/hashes where applicable.

```text
ArtifactRef = { path: string, sha256: string }
Window = { since: RFC3339-UTC-ms, until: RFC3339-UTC-ms }
PolicySpec = {
  content_hash: string,
  artifact?: ArtifactRef,
  signature?: ArtifactRef,
  allowed_signer_key_ids: string[]
}
StreamSpec = {
  id: string,
  kind: "signed-receipts" | "signed-log",
  files: ArtifactRef[],
  allowed_signer_key_ids: string[],
  allowed_policy_hashes: string[]
}
EvidenceProfile = {
  profile_version: "0.1.0", run_id: string, window: Window,
  policies: PolicySpec[], streams: StreamSpec[],
  requirements: { boundary_inventory: boolean, policy_signatures: boolean },
  inventory?: ArtifactRef
}
LogBoundary = {
  start_prev_hash: string,
  initial_policy_hash?: string,
  end_file_sha256: string, end_seq: positive integer, end_entry_hash: string
}
InventoryStream = { id: string, file_sha256s: string[], log?: LogBoundary }
BoundaryInventory = {
  inventory_version: "0.1.0", run_id: string, window: Window,
  acquired_from: string, streams: InventoryStream[]
}
```

Profile-relative paths must be local regular files below the profile directory; reject absolute paths, `..`, URL schemes, fragments, NULs and symlink escape. Resolve aliases once and reject duplicate physical inputs. Policy artifacts are already-resolved JSON/YAML with no `extends`; validate and compare canonical hashes. Policy signatures are detached existing envelopes over those resolved policies, with explicit authorized signer IDs. Empty signer IDs are allowed only for a policy with no origin-signature requirement; evidence streams always require nonempty signer lists. Stream policy hashes must be a nonempty subset of declared policies.

Inventory has exactly the declared stream set and ordered file digests. Log streams require a `log` boundary; receipt collections forbid it. A supplied inventory is always checked even when not required. Missing required inventory fails. A log starting mid-stream may take initial policy state only from matching trusted inventory; otherwise require a signed `policy_loaded` before its first receipt. Inventory acquisition is an operator trust assertion, recorded verbatim as a bounded identifier, not something cryptography independently establishes.

### Verification result and internal seams

`VerificationResult` has required members `verification_version: "0.1.0"`, `run_id`, `window`, `verified_at`, `verifier`, `profile_sha256`, `keyring_sha256`, `report_sha256`, `sources`, `streams`, `limitations`; optional `inventory_sha256`. `verifier` is `{name:"h2h", version:string}`. `sources` contains `{stream_id,path,sha256,records,signer_key_ids}`. Do not serialize host absolute paths or key material.

Each stream result contains `id`, `kind`, `authenticity`, `continuity`, `completeness`, `policy_binding`, `policy_origin`, `signatures_verified`, optional `first`/`last`, and `intervals`. Property results are `{status: "verified" | "not-established" | "not-applicable", scope: string, basis: string[]}`. Positions are `{file_sha256,line,seq?}`. Intervals contain `{policy_content_hash,first,last,receipts,controls?}`; `controls` uses existing `ControlsEvidence`. Positions cover the verified input; interval receipt/control counts cover only the selected window. Source record counts and signature verification totals cover every supplied record, including outside that window. Actual input failures never become a success result with a `failed` property. Empty streams are rejected; a no-receipts-in-window report may still describe authenticated input outside the window.

Auth is mandatory. Continuity is bounded to supplied log endpoints; it is not applicable to standalone receipts. Completeness defaults to not-established, or verifies only the declared inventory/endpoints when trusted inventory matches. It never claims action-attempt completeness. Policy binding covers receipts and signed policy-event order for logs; standalone receipt binding covers hash identity only. Policy origin is not-established without independently checked policy artifacts/signatures.

Use these exact internal entrypoints with `pub(crate)` visibility for cross-module types, members and functions, except the validated-context encapsulation specified in Task 8. Errors use `EvidenceError { code: EvidenceCode, source: Option<String>, line: Option<usize>, message: String }` with `Display`, `Error` and `exit_code()`. `EvidenceCode` variants: `Configuration`, `Malformed`, `LimitExceeded`, `InputDigestMismatch`, `SignatureInvalid`, `UnauthorizedKey`, `DuplicateReceipt`, `ChainInvalid`, `PolicyMismatch`, `BoundaryMismatch`, `OutputConflict`, `ContextInvalid`, `Io`.

```rust
// model.rs: the four closed wire models above, PropertyResult, Position,
// StreamResult, PolicyInterval, VerificationResult, Limits and EvidenceError.
// json.rs
fn parse_json(bytes: &[u8], max_depth: usize) -> Result<serde_json::Value, EvidenceError>;
// snapshot.rs
struct Snapshot { path: std::path::PathBuf, label: String, sha256: String, bytes: Vec<u8> }
struct SnapshotSet { artifacts: std::collections::BTreeMap<String, Snapshot> }
struct InputBudget { bytes: u64, artifacts: usize }
fn snapshot_profile_inputs(profile_path: &std::path::Path, profile: &EvidenceProfile,
    limits: &Limits, budget: &mut InputBudget) -> Result<SnapshotSet, EvidenceError>;
// verify.rs
struct VerifiedStream { spec: StreamSpec, entries: Vec<hushspec::log::LogEntry>,
    receipts: Vec<hushspec::DecisionReceipt>, positions: Vec<Position>,
    signatures_verified: u64 }
fn verify_stream(stream: &StreamSpec, inputs: &SnapshotSet,
    keys: &hushspec::signing::Keyring, clock: &hushspec::signing::VerifyOptions,
    limits: &Limits) -> Result<VerifiedStream, EvidenceError>;
// policy.rs
fn qualify_stream(stream: &VerifiedStream, profile: &EvidenceProfile,
    inventory: Option<&BoundaryInventory>, inputs: &SnapshotSet,
    keys: &hushspec::signing::Keyring, clock: &hushspec::signing::VerifyOptions)
    -> Result<StreamResult, EvidenceError>;
// mod.rs: owns global duplicate-receipt detection across verified streams.
struct VerifiedEvidence { streams: Vec<VerifiedStream>, results: Vec<StreamResult> }
fn verify_evidence(profile: &EvidenceProfile, inputs: &SnapshotSet,
    keys: &hushspec::signing::Keyring, clock: &hushspec::signing::VerifyOptions,
    limits: &Limits) -> Result<VerifiedEvidence, EvidenceError>;
// report_controls.rs: extraction of existing aggregation, not new evaluation.
fn build_control_evidence(source: &str, spec: &hushspec::HushSpec, hash: &str,
    receipts: &[&hushspec::DecisionReceipt], report: &hushspec::report::Report)
    -> hushspec::report::ControlsEvidence;
// output.rs: sidecar is always the last artifact published.
struct OutputArtifact { path: std::path::PathBuf, bytes: Vec<u8> }
fn publish_outputs(data: &[OutputArtifact], completion: &OutputArtifact)
    -> Result<(), EvidenceError>;
```

`positions` is aligned with receipts. For logs, keep entries in verified stream order and derive receipt positions from their exact source lines. `SnapshotSet` keys use manifest-relative labels, with canonical paths retained only for alias checks. Raw-byte SHA-256 is a small `sha256_bytes(&[u8]) -> String` helper in snapshot.rs, not policy canonicalization. No serialized artifact contains a Rust-only enum discriminant or `null` for an absent optional value.

`Limits::default()` implements the numeric table above. `InputBudget::default()` starts at zero; one mutable budget covers profile, trust inputs, evidence, policies, inventory and context for the entire run. Global receipt/record limits are checked again by `verify_evidence`, not multiplied per stream. Derive `Debug` for returned models so error-path tests can use `unwrap_err`. Unit test modules can exercise these pure interfaces before Task 7 exposes the strict CLI. Register new modules as they gain implementations; do not commit stubbed `todo!()`/`unimplemented!()` branches or advertise a partially working strict flag.

### Output transaction

All strict outputs must be distinct new files in the same existing, operator-controlled directory, and cannot alias input/profile/key/context files. Stage complete bytes with private `tempfile::NamedTempFile`s in that directory; validate and `sync_all` staged files before publishing. Publish native JSON and optional OSCAL with `persist_noclobber`, sync the containing directory where supported, then publish the verification sidecar last with no subsequent fallible operation. Its existence plus matching `report_sha256` is the completion marker. On a recoverable earlier failure, remove only files created by this attempt; never delete pre-existing targets. Crash leftovers without the sidecar are unqualified partial outputs, not a valid packet. Document filesystem durability limits rather than claiming portable multi-file atomicity.

Build native report bytes first, then sidecar bytes/digest, then OSCAL linking both. Do not put the OSCAL digest into that sidecar and create a digest cycle. An offline consumer must reverify sources or trust an authenticated packet producer; an unsigned sidecar alone proves nothing.

## Task 1: Honest reference conformance identity and integration claims

**Files:** Modify `crates/hushspec-testkit/src/main.rs`; create `crates/hushspec-testkit/tests/identity_tests.rs`; modify `crates/hushspec-testkit/README.md`, `docs/src/reference/{conformance,conformance-statement}.md`, `docs/src/guides/clawdstrike.md`, `GOVERNANCE.md`, `packages/hushspec/src/adapters/tool-mapping.ts`; add a test to `packages/hushspec/tests/middleware.test.ts`.

**Interfaces:** Consumes existing `report::reference_implementation() -> Implementation`; preserves `report::build` and report v1. Removes the three metadata-only identity override flags. Tool mapper behavior is unchanged and explicitly insufficient as a complete invocation gate.

- [ ] Add this rejection test, including all three flags:

```rust
#[test]
fn reference_runner_rejects_identity_overrides() {
    for flag in ["--implementation", "--implementation-version", "--implementation-language"] {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("report.json");
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_hushspec-testkit"))
            .args(["--report", report.to_str().unwrap(), flag, "not-the-reference"])
            .output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{flag}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("unexpected argument"));
        assert!(!report.exists());
    }
}
```

- [ ] Run `cargo test -p hushspec-testkit --test identity_tests`. Require the expected assertion failure before the repair; do not accept an unrelated fixture-path error as the red result.
- [ ] Delete `Cli.implementation`, `.implementation_version`, `.implementation_language`. Replace the metadata substitution block with `let implementation = report::reference_implementation();`. Run the test again and existing testkit report tests. Keep the corpus/manifest identity distinct from engine identity in help/docs.
- [ ] Add the adapter boundary regression, importing `mapWellKnownTool` from `../src/adapters/tool-mapping.js`:

```typescript
it('effect mapping does not establish tool authorization', () => {
  const guard = HushGuard.fromYaml(`hushspec: "1.0.0"
rules:
  tool_access:
    block: [fetch]
    default: block
  egress:
    allow: [api.example.com]
    default: block
`);
  expect(guard.gate(mapWellKnownTool('fetch', {url: 'https://api.example.com'})).proceed).toBe(true);
  expect(guard.gate({type: 'tool_call', target: 'fetch'}).proceed).toBe(false);
});
```

This is a characterization test that should already pass, not a claimed security fix. Remove "unambiguous names" from the mapper's comment; explain that names are host conventions and mapping does not authenticate a server or enforce tool-plus-effect composition. Withdraw Clawdstrike L3/all-rules coverage until an engine-bound report exists, distinguish portable signing from engine integration, and describe current audit failure/strict behavior accurately.
- [ ] Run `npm --prefix packages/hushspec test -- tests/middleware.test.ts`, `cargo test -p hushspec-testkit`, and `python3 scripts/check_comment_hygiene.py --check`. Commit only this task as `fix(testkit): bind reference reports to the executed implementation`.

## Task 2: TypeScript and Python callback-error receipts

**Files:** `packages/hushspec/src/middleware.ts`, `packages/hushspec/tests/middleware.test.ts`, `packages/python/hushspec/middleware.py`, `packages/python/tests/test_middleware.py`.

**Interfaces:** Existing TS `record(action, result, durationUs, enforcement, receipt)` and Python `_record(action, result, duration_us, enforcement, receipt)`. No API or receipt schema changes.

- [ ] Add tests using the existing `DENY_SHELL_POLICY` and capture sinks:

```typescript
it('records a blocked warn before propagating callback failure', () => {
  const marker = {kind: 'confirmation unavailable'};
  const receipts: DecisionReceipt[] = [];
  const guard = HushGuard.fromYaml(DENY_SHELL_POLICY, {
    onWarn: () => { throw marker; },
    sink: {send: receipt => { receipts.push(receipt); }},
  });
  let caught: unknown;
  try { guard.gate({type: 'tool_call', target: 'risky_tool'}); }
  catch (error) { caught = error; }
  expect(caught).toBe(marker);
  expect(receipts).toHaveLength(1);
  expect(receipts[0].decision).toBe('warn');
  expect(receipts[0].enforcement).toEqual({mode: 'enforce', outcome: 'blocked'});
});
```

```python
def test_callback_failure_records_blocked_warn():
    marker = RuntimeError("confirmation unavailable")
    sink = _CaptureSink()
    def fail(_result, _action):
        raise marker
    guard = HushGuard.from_yaml(DENY_SHELL_POLICY, on_warn=fail, sink=sink)
    with pytest.raises(RuntimeError) as caught:
        guard.gate(EvaluationAction(type="tool_call", target="risky_tool"))
    assert caught.value is marker
    assert len(sink.receipts) == 1
    assert sink.receipts[0].decision == Decision.WARN
    assert sink.receipts[0].enforcement.outcome == "blocked"
```

- [ ] Run `npm --prefix packages/hushspec test -- tests/middleware.test.ts` and `pytest packages/python/tests/test_middleware.py -q`. Confirm the new tests fail because no receipt was sent.
- [ ] Catch only confirmation invocation, not the whole gate. On error, attempt one blocked recording inside a second protected block, then rethrow the original value. Python catches `Exception` and uses a bare `raise` from the original handler. TS rethrows the original value, including non-Error values. The insertion pattern is:

```typescript
let confirmed: boolean;
try { confirmed = this.onWarn(result, action); }
catch (original) {
  try { this.record(action, result, durationUs, {mode, outcome: 'blocked'}, receipt); }
  catch { /* Preserve the original confirmation failure. */ }
  throw original;
}
```

Use `confirmed` in the existing normal branch. Python uses `self._record(action, result, duration_us, EnforcementSummary(mode=mode, outcome="blocked"), receipt)` with the existing argument order. Leave ordinary sink semantics and monitor behavior unchanged. Do not include exception text or arguments in new diagnostics; existing observer reporting of the blocked attempt is sufficient.
- [ ] Parameterize sink success/failure and original error identity in both test suites. Assert the original reason and rule trace equal a normal declined confirmation's values, and that monitor mode never invokes the callback. For Python explicitly test that `KeyboardInterrupt` is not converted into an ordinary callback receipt guarantee. Re-run both suites plus `npm run lint`.
- [ ] Commit as `fix(runtime): record recoverable confirmation failures in scripting SDKs`.

## Task 3: Rust and Go callback panic receipts

**Files:** `crates/hushspec/src/guard.rs` including its test module; `packages/go/hushspec/guard.go`, `packages/go/hushspec/guard_test.go`.

**Interfaces:** Existing Rust `HushGuard::check`, `record`; existing Go `Guard.decide`, `record`. Change Go's private `gateOutcome` to consume an already-computed `confirmed bool`, not call user code itself. Only confirmation callback panics are intercepted.

- [ ] Add Rust's regression using existing test helpers:

```rust
#[test]
fn confirmation_panic_records_before_resuming() {
    let sink = Arc::new(RecordingSink::default());
    let guard = HushGuard::builder().sink(Box::new(SharedSink(sink.clone())))
        .on_warn(|_, _| panic!("confirmation-marker"))
        .build_from_policy(policy(WARN_POLICY)).unwrap();
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
        guard.check(&action("tool_call", "deploy")))).unwrap_err();
    assert_eq!(failure.downcast_ref::<&str>(), Some(&"confirmation-marker"));
    let receipts = sink.receipts.lock().unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].decision, Decision::Warn);
    assert_eq!(receipts[0].enforcement.outcome, EnforcementOutcome::Blocked);
}
```

- [ ] Add Go's regression using the existing `newTestGuard` policy:

```go
func TestGuardWarnPanicRecordsBeforeResuming(t *testing.T) {
    marker := errors.New("confirmation-marker")
    sink := &recordingSink{}
    guard := newTestGuard(t, GuardOptions{Sink: sink, OnWarn: func(EvaluationResult, *EvaluationAction) bool { panic(marker) }})
    var recovered any
    func() {
        defer func() { recovered = recover() }()
        content := "token WARNME here"
        _, _ = guard.Check(context.Background(), &EvaluationAction{Type: "file_write", Target: "a.txt", Content: &content})
    }()
    receipts, _ := sink.snapshot()
    if recovered != marker || len(receipts) != 1 { t.Fatalf("panic=%v receipts=%d", recovered, len(receipts)) }
    if receipts[0].Decision != DecisionWarn || receipts[0].Enforcement.Outcome != EnforcementOutcomeBlocked { t.Fatal("missing blocked warn") }
}
```

- [ ] Run `cargo test -p hushspec --lib guard::tests::confirmation_panic_records_before_resuming` and, from `packages/go`, `go test ./hushspec -run TestGuardWarnPanicRecordsBeforeResuming -count=1`. Confirm missing-receipt failures.
- [ ] In Rust make `evaluated` mutable, catch only `handler(&evaluated.result, action)` with narrowly scoped `AssertUnwindSafe`; on panic, protect the one `self.record(action, &evaluated.result, evaluated.duration_us, evaluated.receipt.take(), Some(blocked))` attempt with a separate `catch_unwind`, then `resume_unwind(payload)`. Do not broadly mark the guard unwind-safe or catch evaluation failures.
- [ ] In Go use a small closure around only the callback with a `completed` flag and a deferred recover. If it did not complete normally, stamp the existing receipt blocked, construct a blocked `GuardDecision`, protect `g.record` with a separate recover, then `panic(original)`. The completion flag must detect `panic(nil)` even under `GODEBUG=panicnil=1`. Normal callback results flow into `gateOutcome` without a second callback invocation.
- [ ] Add cases for sink panic, unchanged policy reason/trace, monitor callback suppression and a second invocation after a recoverable panic. Rust sink-panic tests use a sink that panics only in `send`, not bootstrap policy-event recording. Go nil-panic tests assert abnormal completion and one blocked receipt, not equality to a nonnil panic value. Run:

```sh
cargo test -p hushspec --lib guard::tests::
```

From `packages/go`:

```sh
go test ./hushspec -run 'TestGuard.*(Warn|Sink)' -count=1
GODEBUG=panicnil=1 go test ./hushspec -run TestGuardWarnNilPanic -count=1
go test -race ./hushspec -run 'TestGuard.*(Warn|Sink)' -count=1
```

- [ ] Document that abort-mode Rust panic, fatal process errors and missing storage cannot promise a receipt. Commit as `fix(runtime): retain blocked evidence across confirmation panics`.

## Task 4: Closed experimental contracts and unambiguous JSON

**Files:** Create `report_evidence/{mod,model,json}.rs` under the CLI's `src`; register `mod report_evidence` in `main.rs`. Create the four experimental schema files from the interface map and `fixtures/assurance/{README.md,profile-shape.json}`. Modify `scripts/generate_fixture_manifest.py`; regenerate existing CLI/testkit schema modules and `fixtures/MANIFEST.json` using their scripts, never by hand.

**Interfaces:** Produces all wire models, `Limits`, `EvidenceError` and `parse_json` from the contracts. New modules are internal; no strict CLI flags are exposed until Task 7. Schema fixtures under `fixtures/assurance/` are supplemental integration material, category `integration`, level 0, not a new core conformance requirement.

- [ ] Create the shape fixture from this exact JSON. Zero byte digests are deliberate schema-only examples, not claimed authentic source files:

```json
{
  "profile_version": "0.1.0",
  "run_id": "shape-only",
  "window": {"since":"2026-09-15T00:00:00.000Z","until":"2026-09-16T00:00:00.000Z"},
  "policies": [{"content_hash":"sha256:1a61b3186d0d19d8f684b4ff98924785c39e0e8396d2f2588b4c111e9e82f2d5","allowed_signer_key_ids":[]}],
  "streams": [{
    "id":"agent-1", "kind":"signed-receipts",
    "files":[{"path":"evidence.jsonl","sha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}],
    "allowed_signer_key_ids":["sha256:1187bb3ca0fd60b25cb90390812fb3a90823466b499e9c29effcc9f3c4ce6142"],
    "allowed_policy_hashes":["sha256:1a61b3186d0d19d8f684b4ff98924785c39e0e8396d2f2588b4c111e9e82f2d5"]
  }],
  "requirements":{"boundary_inventory":false,"policy_signatures":false}
}
```

- [ ] Add JSON unit tests before the implementation:

```rust
#[test]
fn rejects_duplicate_members_and_excessive_depth() {
    for raw in [br#"{"key":1,"key":2}"#.as_slice(), br#"{"outer":{"x":1,"x":2}}"#] {
        assert!(parse_json(raw, 64).is_err());
    }
    let too_deep = format!("{}0{}", "[".repeat(65), "]".repeat(65));
    assert!(parse_json(too_deep.as_bytes(), 64).is_err());
    assert!(parse_json(br#"{"ok":[1,true,"x"]}"#, 64).is_ok());
}
```

Run `cargo test -p hushspec-cli --bin h2h report_evidence::`. Red may initially be missing-module/function compilation; after adding types it must demonstrate the parser refusal checks themselves.
- [ ] Implement a `serde::de::DeserializeSeed` carrying depth, with map visitors tracking member names in a `BTreeSet` before consuming each value. Reject repeats instead of deserializing into a `Value` that has already discarded them. Keep serde_json's own recursion guard enabled; reject trailing input with `Deserializer::end()`. Invalid UTF-8 and nonfinite numbers are errors. Profiles/context/schemas enforce null/shape constraints separately; the parser itself can represent valid JSON null for schema rejection.
- [ ] Define serde models from the pinned field tables with `deny_unknown_fields` and omitted `Option` serialization. Validate raw JSON against the corresponding embedded schema before typed deserialization, so explicit null cannot become absent. Give all schemas closed objects, exact artifact-version constants, bounded arrays and identifiers, digest patterns, timestamp formats and `$id` matching the filename. Use only internal `#` schema references. Semantic validators reject duplicate IDs/paths, nonlocal paths, inconsistent windows, stream policy hashes absent from `policies`, and invalid signer requirements.
- [ ] Table-test profile version `0.2.0`, explicit null inventory, extra field, duplicate stream ID, empty source list, empty stream signers, negative/over-limit bounds and reversed windows. Generate schema variants from the shape fixture in the test, changing exactly one property and asserting the expected structural or semantic rejection, not merely any nonzero process exit.
- [ ] Add the `^fixtures/assurance/` supplemental manifest rule before general categories, then run:

```sh
python3 scripts/generate_cli_schemas.py
python3 scripts/generate_testkit_schemas.py
python3 scripts/generate_fixture_manifest.py
cargo test -p hushspec-cli --bin h2h report_evidence::
cargo test -p hushspec-cli --test schema_guard_tests
```

- [ ] Commit as `feat(evidence): define experimental strict verification contracts`.

## Task 5: Bounded snapshots and standalone receipt authentication

**Files:** Create `report_evidence/{snapshot,verify}.rs`; update `model.rs` and module exports. Add `sha2 = "0.10"` to CLI dependencies and update `Cargo.lock` only for that dependency edge. Tests live beside these modules and share a new `report_evidence/test_support.rs` under `#[cfg(test)]`.

**Interfaces:** Produces `Snapshot`, `SnapshotSet`, `sha256_bytes`, `snapshot_profile_inputs`, and standalone-receipt support in `verify_stream`. A declared signed-log stream must return a clear unsupported-kind error until Task 6 adds its implementation; it must not fall back to receipt parsing. No CLI exposes this intermediate state.

- [ ] Add a test helper `signed_fixture() -> (tempfile::TempDir, EvidenceProfile, SnapshotSet, Keyring, VerifyOptions)` that reads `fixtures/receipts/signed/valid/allow-egress.signed.json`, serializes it as one compact JSONL line in `evidence.jsonl`, loads the shape profile, replaces its source digest with the exact bytes' digest and snapshots the inputs. Set the clock to `2026-09-15T12:00:00Z`; load `fixtures/signing/keys/keyring.json`. Build the profile file inside the returned temporary directory and never reference a private key outside the committed test fixtures.
- [ ] Add the signature regression using an internally consistent profile digest, so it reaches cryptographic verification:

```rust
#[test]
fn tampered_envelope_cannot_be_counted() {
    let (_dir, mut profile, mut inputs, keys, clock) = signed_fixture();
    let source = inputs.artifacts.get_mut("evidence.jsonl").unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&source.bytes).unwrap();
    value["receipt"]["action"]["target"] = "evil.example".into();
    source.bytes = format!("{}\n", value).into_bytes();
    source.sha256 = sha256_bytes(&source.bytes);
    profile.streams[0].files[0].sha256 = source.sha256.clone();
    let error = verify_stream(&profile.streams[0], &inputs, &keys, &clock, &Limits::default()).unwrap_err();
    assert_eq!(error.code, EvidenceCode::SignatureInvalid);
}
```

- [ ] Run `cargo test -p hushspec-cli --bin h2h report_evidence::`. Confirm red, then implement bounded reads using `Read::take(limit + 1)` and checked arithmetic for cumulative limits. Reject nonregular files; canonicalize for containment/alias checks, then read once into owned bytes. Hash those bytes, compare declared digest, and never reopen for parsing/aggregation. Concurrent changes during a read are accepted only if the resulting exact bytes match the operator's digest and pass verification.
- [ ] For every nonblank line, enforce byte/record/depth bounds, parse unambiguously, validate the original receipt JSON against the existing receipt schema, then deserialize `SignedReceipt`. Check the envelope key ID is in this stream's allowlist and call `hushspec::signing::verify_receipt`. Verify all lines, including outside the report window, before returning receipts. Do not use `cmd_report::classify`, which drops envelopes.
- [ ] Add table cases using the valid fixture: no envelope, altered signature, valid but unauthorized signer, revoked/retired keyrings, a bad second line outside the window, a log entry mixed into the receipt file, whitespace-only file, byte digest mismatch and a repeated receipt ID. A valid record verifies exactly one signature and preserves the original receipt. For revoked/retired keys use the existing fixture keyrings and controlled verifier clock, not the real wall clock.
- [ ] Add snapshot tests for a symlink escape, two declarations resolving to the same path, file limit + 1 byte, total limit + 1 byte, invalid UTF-8, and pathname replacement after snapshot creation. The last case replaces the source path with tampered data and proves verification still uses the captured bytes. Run the focused module suite and `cargo test -p hushspec-cli --test report_tests` to preserve legacy reporting. Commit as `feat(evidence): authenticate immutable bounded receipt inputs`.

## Task 6: Signed stream continuity, policy intervals and scoped completeness

**Files:** Extend `report_evidence/verify.rs`; create `report_evidence/policy.rs`; extend module tests/test support; extract the existing control-counting body into new `src/report_controls.rs` and call it from legacy `cmd_report.rs` without changing ordinary report output.

**Interfaces:** Completes `verify_stream` for logs and implements `qualify_stream`/`verify_evidence`. `VerifiedStream.entries` retains signed-event order, and global duplicate receipt IDs are rejected before aggregate reporting. `StreamResult.intervals[].controls` is the only multipolicy control summary; the native report's single `controls` member is omitted for multipolicy input.

- [ ] Generate signed test logs with existing `ChainedFileSink::with_signer`, `record_policy_event`, `send` and `rotate`; use `fixtures/signing/keys/test-signing.key.pem`, the fixed fixture clock and deterministic receipt IDs. Add `signed_log_fixture(rotated: bool)`, returning the same five values as `signed_fixture`, and `sign_entry_document(&mut Value)` in test support: remove `entry_hash`/`signature`, hash JCS of the remaining document, sign that hash with existing `sign_content_hash`, then restore both fields. Use this helper only to make malicious semantic cases cryptographically valid.
- [ ] Add tests that independently valid unrelated logs fail as one continuation, valid rotations pass in order, reversed/missing/duplicate rotations fail, and two independent declared streams produce distinct heads. Invoke `verify_logs` on the ordered snapshot texts, with `require_signatures: true`, supplied keyring and clock. Validate original embedded receipt JSON against the schema before accepting it. Empty streams and unauthorized entry signer IDs fail.
- [ ] Implement policy tracking with this state machine, independently from cryptographic checks:

```text
state := inventory.initial_policy_hash, if a matching trusted boundary supplies it
log_started: preserve state; it is not a policy load
policy_loaded: require no existing state; require declared hash; set state
policy_swapped: require state exists and previous_content_hash == state;
                require declared new hash; close interval and set state
receipt: require state exists and receipt.policy.content_hash == state;
         require that hash authorized for this stream; append to that interval
```

Reject repeated `policy_loaded` as an undeclared reset in this strict profile; operators represent a restart as a new stream. Receipt collection streams check each hash against their allowlist but do not infer transition order. Approved same-hash reload events may open a new interval without changing policy identity. Ordering is by verified position, not timestamp sorting.
- [ ] Add semantic tests using re-signed entries: receipt before load, wrong receipt hash, swapped event with wrong predecessor, unapproved new hash, and a copied receipt ID across two valid independent streams. Assert `PolicyMismatch` or `DuplicateReceipt`, not a signature error. Supply two resolved local policies with different control mappings and verify no interval credits the other policy's receipts.
- [ ] Load resolved policy artifacts from snapshots, reject `extends`, validate, compare canonical identity, and call `verify_policy` with allowed policy signer IDs whenever a signature is supplied. An optional-but-invalid signature still fails; it is not silently ignored. `policy_signatures: true` requires an artifact and detached verified signature for every declared policy. Absent signatures leave origin not-established; never reuse receipt `policy.signature.verified` as proof. Extract `build_control_evidence` with its pinned signature and keep original `report_tests` totals unchanged.
- [ ] Compare inventory run/window, exact stream set, file order/digests, starting predecessor and ending file/hash/seq. Inventory does not become trusted because the log producer signed it; retain `acquired_from` as an operator assumption in the sidecar. Add tests where an internally consistent truncated file/profile passes bounded continuity without inventory but fails against the independently retained original endpoint. Do the equivalent prefix and missing-whole-stream tests.
- [ ] Run `cargo test -p hushspec-cli --bin h2h report_evidence::` and `cargo test -p hushspec-cli --test report_tests`. Require verified auth/continuity with `completeness.status == "not-established"` when no boundary inventory was supplied. Commit as `feat(evidence): qualify policy intervals and declared stream boundaries`.

## Task 7: Strict CLI, report binding and safe publication

**Files:** `crates/hushspec-cli/src/cmd_report.rs`, new `report_evidence/output.rs`, `report_evidence/mod.rs`, `crates/hushspec-cli/Cargo.toml`, `Cargo.lock`; new `crates/hushspec-cli/tests/evidence_report_tests.rs` and `tests/support/evidence.rs`.

**Interfaces:** New strict flags and private `cmd_report::run_strict(args: &ReportArgs) -> i32`; `publish_outputs` from the pinned contract. Move `tempfile = "3"` to regular CLI dependencies. Legacy `run` selects the strict path only when explicitly requested, except OSCAL always requires that path after Task 9.

- [ ] Create this integration helper in `tests/support/evidence.rs`; expose its fields to the sibling integration test modules. It uses real committed signed input, not unsigned synthetic reporting fixtures:

```rust
pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub root: std::path::PathBuf,
    pub profile: serde_json::Value,
}
impl Fixture {
    pub fn new() -> Self {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let dir = tempfile::tempdir().unwrap();
        let signed: serde_json::Value = serde_json::from_slice(&std::fs::read(
            root.join("fixtures/receipts/signed/valid/allow-egress.signed.json")).unwrap()).unwrap();
        let bytes = format!("{}\n", signed).into_bytes();
        std::fs::write(dir.path().join("evidence.jsonl"), &bytes).unwrap();
        let mut profile: serde_json::Value = serde_json::from_slice(&std::fs::read(
            root.join("fixtures/assurance/profile-shape.json")).unwrap()).unwrap();
        use sha2::Digest;
        profile["streams"][0]["files"][0]["sha256"] =
            format!("sha256:{:x}", sha2::Sha256::digest(&bytes)).into();
        let fixture = Self { dir, root, profile };
        fixture.save_profile();
        fixture
    }
    pub fn save_profile(&self) {
        std::fs::write(self.dir.path().join("profile.json"), self.profile.to_string()).unwrap();
    }
    pub fn command(&self) -> assert_cmd::Command {
        let mut command = assert_cmd::Command::cargo_bin("h2h").unwrap();
        command.current_dir(self.dir.path()).args([
            "report", "evidence.jsonl", "--format", "json", "--out", "report.json",
            "--evidence-profile", "profile.json", "--verification-out", "verification.json",
            "--now", "2026-09-15T12:00:00Z", "--keyring",
        ]).arg(self.root.join("fixtures/signing/keys/keyring.json"));
        command
    }
    pub fn json(&self, name: &str) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.dir.path().join(name)).unwrap()).unwrap()
    }
}
```

- [ ] Add the positive CLI contract test and run it before wiring the flags:

```rust
#[path = "support/evidence.rs"] mod evidence;
#[test]
fn strict_report_binds_authenticated_inputs_without_claiming_completeness() {
    let fixture = evidence::Fixture::new();
    fixture.command().assert().success();
    let verification = fixture.json("verification.json");
    assert_eq!(verification["streams"][0]["authenticity"]["status"], "verified");
    assert_eq!(verification["streams"][0]["completeness"]["status"], "not-established");
    let bytes = std::fs::read(fixture.dir.path().join("report.json")).unwrap();
    use sha2::Digest;
    assert_eq!(verification["report_sha256"], format!("sha256:{:x}", sha2::Sha256::digest(bytes)));
    assert_eq!(fixture.json("report.json")["totals"]["receipts"], 1);
}
```

Run `cargo test -p hushspec-cli --test evidence_report_tests`; initially require unknown-flag failure. Add flag parsing/conflicts and the strict orchestration. Validate profile, keys and all evidence before computing the windowed aggregate. Snapshot keyring/PEM bytes once under the shared budget; use `Keyring::parse` or `Keyring::from_public_key_pem` on those bytes and bind that exact input digest as `keyring_sha256` (also when a single PEM was supplied). Do not hash one key file read and authenticate using a second read through `VerifyOnLoadArgs::to_options`. Construct the same existing `VerifyOptions` clock/skew contract directly from parsed CLI options. Build native report with existing `build_report`; never call ordinary `read_file` on the same paths after verification. Preserve source semantics of native `signatures` (policy-signature statuses recorded by the runtime); put verifier-authenticated evidence counts in the sidecar instead of relabeling that old field.
- [ ] Build interval control summaries from their exact policy artifact and matching receipts. For one policy, populate native `controls` from the same verified data; for multiple policies, leave native `controls` absent and publish separate interval controls in the sidecar. Keep native chain fields within their documented per-file meaning, and per-stream continuity in the sidecar. Validate serialized native/sidecar documents against their embedded schemas before publication.
- [ ] Implement `publish_outputs` using the pinned transaction. Add unit tests with a pre-existing second target and with an injected pre-completion publication failure. Assert existing bytes unchanged and no new completion sidecar. Add CLI tests for output==input, report==sidecar, symlink alias, missing output parent, and two output directories. Do not change filesystem permissions on user directories.
- [ ] Add parameterized CLI cases for missing key/profile/output, lenient/unverified/by conflicts, mismatching CLI window, wrong key role, out-of-window tampering, required-but-absent inventory and zero matching-window receipts. Every refusal checks the intended diagnostic code plus absence of newly published report/sidecar. A zero-window report may succeed with zero totals and explicit limitations; it must not imply satisfaction or complete coverage.
- [ ] Run `cargo test -p hushspec-cli --test evidence_report_tests`, `cargo test -p hushspec-cli --test report_tests`, and `cargo clippy -p hushspec-cli --all-features -- -D warnings`. Commit as `feat(cli): publish strictly verified evidence reports`.

## Task 8: Pinned offline OSCAL assessment context

**Files:** New `crates/hushspec-cli/src/oscal_context.rs`; register in `main.rs`; create `crates/hushspec-cli/schemas/oscal/v1.1.2/` with four schemas, full `LICENSE.md` and `SHA256SUMS`; create `fixtures/assurance/oscal/{context,ap,ssp,catalog}.json`; regenerate the fixture manifest. Add context unit tests in `oscal_context.rs`.

**Interfaces:**

```text
AssessmentContext = {
  hushspec_assessment_context: "0.1.0",
  assessment_plan: ArtifactRef,
  system_security_plan: ArtifactRef,
  resolved_catalog: ArtifactRef
}
ValidatedAssessmentContext = {
  manifest_sha256: String, ap_sha256: String, ssp_sha256: String,
  catalog_sha256: String, ap_path: PathBuf,
  reviewed_controls: serde_json::Value, subjects: Vec<serde_json::Value>,
  control_ids: BTreeSet<String>
}
load_context(path: &Path, limits: &Limits, budget: &mut InputBudget)
    -> Result<ValidatedAssessmentContext, EvidenceError>
```

Only `load_context` constructs `ValidatedAssessmentContext`; keep fields private with read-only accessors for the renderer. Use the strict JSON/snapshot helpers and the shared total artifact budget, rather than a second unbounded loader.

- [ ] Vendor the exact official release assets with full attribution/license intact. These hashes were fetched and checked during planning; all four schemas have internal references only and use Draft 7. Treat a different digest as a failed pin, not permission to update it silently.

| File | SHA-256 of exact upstream bytes |
|---|---|
| `oscal_assessment-results_schema.json` | `d033da70154cf6625ae46a746199e88e58f2928b1387dfac051d381b92f41b0d` |
| `oscal_assessment-plan_schema.json` | `43464ad048b711c735934b66015bcf8239782c6263d377a742c6b205ea796ecb` |
| `oscal_ssp_schema.json` | `08d3faeb12f0fab7705dec15fb648c72400c7ab6ac0056222d49d21507e02a69` |
| `oscal_catalog_schema.json` | `5b069afa4f4ecc38d59914dab56098566d4247d3578a2123c030c80d36fc5104` |
| `LICENSE.md` | `63407ac41abc46911bc9759fc0c19fd0ba7f66c59bb6746e51d85e2f2f3244b1` |

Schema URLs are `https://github.com/usnistgov/OSCAL/releases/download/v1.1.2/<filename>`; the license is [the v1.1.2 license](https://raw.githubusercontent.com/usnistgov/OSCAL/v1.1.2/LICENSE.md). The SSP filename is `oscal_ssp_schema.json`, not `oscal_system-security-plan_schema.json`. Preserve upstream bytes without formatting. Embed from within the CLI crate so `cargo package` includes them. Add a test comparing embedded bytes to this manifest; schema compilation must use explicit Draft 7 and format validation. Pin a Unicode token-pattern case: NIST patterns use Unicode character classes that Python's standard `re` cannot compile. Do not remove those constraints to make validation pass. The plan's three context blueprints were checked using Python Draft 7 validation with ECMAScript Unicode pattern evaluation; production Rust schema compatibility remains a Task 8 test, not an already-qualified result.
- [ ] Create the three synthetic JSON documents from this concrete fixture blueprint, then schema-check each before calculating context digests. The metadata and SSP are test-system declarations, not real customer inventory or assessment conclusions:

```rust
fn context_documents() -> [(&'static str, serde_json::Value); 3] {
    use serde_json::json;
    let meta = json!({"title":"Synthetic evidence test", "last-modified":"2026-09-15T12:00:00Z", "version":"1", "oscal-version":"1.1.2"});
    let component = "00000000-0000-4000-8000-000000000001";
    [
        ("catalog.json", json!({"catalog":{
            "uuid":"00000000-0000-4000-8000-000000000002", "metadata":meta.clone(),
            "controls":[{"id":"tool-access","title":"Declared tool restriction"}]
        }})),
        ("ssp.json", json!({"system-security-plan":{
            "uuid":"00000000-0000-4000-8000-000000000003", "metadata":meta.clone(),
            "import-profile":{"href":"catalog.json"},
            "system-characteristics":{
                "system-ids":[{"id":"synthetic-pilot"}], "system-name":"Synthetic pilot",
                "description":"Non-production test system",
                "system-information":{"information-types":[{"title":"Synthetic source","description":"Public test data"}]},
                "status":{"state":"under-development"},
                "authorization-boundary":{"description":"Only the controlled test tool"}
            },
            "system-implementation":{
                "users":[{"uuid":"00000000-0000-4000-8000-000000000004"}],
                "components":[{"uuid":component,"type":"software","title":"Test tool","description":"Controlled fixture","status":{"state":"under-development"}}]
            },
            "control-implementation":{"description":"Test declarations only","implemented-requirements":[{"uuid":"00000000-0000-4000-8000-000000000005","control-id":"tool-access"}]}
        }})),
        ("ap.json", json!({"assessment-plan":{
            "uuid":"00000000-0000-4000-8000-000000000006", "metadata":meta,
            "import-ssp":{"href":"ssp.json"},
            "reviewed-controls":{"control-selections":[{"include-controls":[{"control-id":"tool-access"}]}]},
            "assessment-subjects":[{"type":"component","include-subjects":[{"subject-uuid":component,"type":"component"}]}]
        }}))
    ]
}
```

Write `context.json` with `hushspec_assessment_context: "0.1.0"` and the three `ArtifactRef`s computed from the actual serialized files. Put the blueprint in the context module's test support; Task 9 integration tests copy the committed JSON fixtures instead of depending on private module helpers.
- [ ] Add table-driven context tests. Construct each mutation from the valid package, update its declared digest so the test reaches semantic validation, then call `load_context` and assert `ContextInvalid`:

```text
AP import-ssp.href = https://example.invalid/ssp.json -> reject, no request
AP import-ssp.href = # -> reject
AP import-ssp.href names a different existing SSP -> reject identity mismatch
SSP import-profile.href names a profile document -> reject unsupported resolution
AP selects missing or duplicate control ID -> reject
AP selects unknown component UUID -> reject
AP uses include-all, exclude-controls, objective selections or a non-component subject -> reject
context artifact is outside the context directory via path or symlink -> reject
```

Add independent wrong-byte-digest and schema-invalid tests. Run `cargo test -p hushspec-cli --bin h2h oscal_context::`; verify red before `load_context` is implemented.
- [ ] Implement the supported subset: AP -> exact declared SSP -> exact declared resolved catalog. Input hrefs are relative local paths without query/fragment/percent escapes, never fetched. AP has one explicit nonempty control selection and explicit component subjects; no include-all/exclusions/objective selections. Catalog control IDs, including nested groups/controls, are unique. Selected component UUIDs are unique and belong to SSP components. Copy the validated selections, not guessed policy mappings. Schema validation and referential validation are separate required passes.
- [ ] Run context tests, embedded-digest tests and `cargo package -p hushspec-cli --locked` when the workspace package prerequisites are available; otherwise use the final workspace package gate rather than changing dependency resolution. Commit as `feat(oscal): validate pinned local assessment context`.

## Task 9: Observation-only OSCAL over strictly verified evidence

**Files:** New `crates/hushspec-cli/src/oscal_report.rs`, `tests/oscal_tests.rs`; modify `src/{main,cmd_report}.rs`, `tests/report_tests.rs`, `tests/support/evidence.rs`; add a signed monitor-mode test fixture builder to the integration test support.

**Interfaces:**

```rust
fn render_oscal(report: &hushspec::report::Report,
    verification: &VerificationResult, context: &ValidatedAssessmentContext,
    native: &OutputArtifact, sidecar: &OutputArtifact, output_path: &std::path::Path)
    -> Result<serde_json::Value, EvidenceError>;
```

CLI invokes the same strict pipeline as Task 7. `--native-report-out` carries native JSON, `--out` carries OSCAL, and `--verification-out` remains the completion marker. Context failures occur before any publication. Observation-control association uses validated AP scope and interval-specific verified control evidence, not `report.controls` alone.

- [ ] Replace the existing `oscal_is_gated_and_emits_one_result_with_findings` and `oscal_over_a_broken_chain_satisfies_nothing` expectations. Preserve the experimental flag gate, but require missing-context rejection and reject `--unverified` entirely for OSCAL. The unsigned `fixtures/report/24h.jsonl` is not a valid positive strict fixture.
- [ ] Extend integration `Fixture` with `command_oscal() -> assert_cmd::Command` that supplies the exact new flags rather than appending a second `--format`. Build a synthetic policy mapping `rules.tool_access` under a custom `pilot` framework to the context's `tool-access` ID, create one warn/monitor `would_block` receipt using existing `evaluate_audited`, and sign with the committed test key at the fixed clock. Add the resolved policy artifact/digest to the profile. Implement a `write_oscal_context(&Fixture)` helper that copies the Task 8 package into `context/` below the temp directory and writes matching byte digests.
- [ ] Add this positive assertion pattern using that genuinely signed monitor fixture:

```rust
fixture.command_oscal().assert().success();
let document = fixture.json("assessment-results.json");
let result = &document["assessment-results"]["results"][0];
assert!(result.get("findings").is_none());
assert!(result.get("risks").is_none());
for observation in result["observations"].as_array().unwrap() {
    assert_eq!(observation["methods"], serde_json::json!(["EXAMINE"]));
}
assert_ne!(document["assessment-results"]["import-ap"]["href"], "#");
assert_eq!(fixture.json("report.json")["totals"]["by_outcome"]["would_block"], 1);
```

Run `cargo test -p hushspec-cli --test oscal_tests`. Require the old behavior to fail these assertions before replacing the renderer.
- [ ] Extract rendering from the large `cmd_report.rs` into `oscal_report.rs`. Emit one Assessment Results result with genuine AP reference, copied reviewed-control selection and receipt-derived observations using `EXAMINE`. Each observation includes exact policy/interval identity, actual allow/warn/deny and enforcement counts, source/report/verification digest references and limitations. Do not emit findings, risks, objective status or a control-as-objective substitution. Omit empty optional observation arrays.
- [ ] Use OSCAL back-matter resources for native report and sidecar with `rlinks[].hashes = [{algorithm:"SHA-256",value:<bare hex>}]`; relevant evidence references actual resource UUIDs. Generate AP href relative to the OSCAL output directory, not relative to context.json. Restrict output resource basenames to URI-unreserved ASCII plus dot; reject unsupported path encodings clearly. Verify every generated local/fragment reference and that policy-mapped control IDs are selected by the AP and present in its catalog. Unknown/custom framework labels do not manufacture objective IDs.
- [ ] Schema-check generated AR against the pinned schema before calling `publish_outputs([native, oscal], sidecar)`. Test a context in a child directory, mismatched scope, empty selected-window evidence, unsigned/tampered evidence, unrelated streams, and pre-existing OSCAL target. Verify referenced digests equal actual published bytes and all three targets remain absent on input/context failure. Run `cargo test -p hushspec-cli --test oscal_tests` and `cargo test -p hushspec-cli --test report_tests`.
- [ ] Commit as `fix(oscal): export scoped observations without automatic findings`.

## Task 10: Operator documentation, adversarial review and exact-head qualification

**Files:** `docs/src/reference/cli.md`, `docs/src/guides/runtime-integration.md`, new `docs/src/guides/evidence-verification.md`, `docs/src/SUMMARY.md`, `docs/plans/STATUS.md`, new `docs/reviews/2026-09-22-project-a-qualification.md`; `.github/workflows/ci.yml` only if a new acceptance suite is not already covered by workspace testing. Preserve historical review records.

**Interfaces:** No new product API. The operator guide explains strict profiles/keys, policy origin, independent inventory acquisition, ordinary-vs-strict reporting, experimental OSCAL's supported context subset and why neither signatures nor local log chains establish all attempted actions.

- [ ] Add a guide with a runnable signed-fixture example, exact new flags, verification-sidecar/report digest check, a tampered-input failure example, and a monitor-only observation example. Link it from `SUMMARY.md`. Update CLI help/reference for the legacy log-only flag and for removed testkit identity overrides. State the reference helper's remaining tool-plus-effect gap and callback storage/crash limits. Never call the profile a certification.
- [ ] Add the exact fixture example as an automated CLI test and run it. Run `mdbook build docs`, `python3 scripts/smoke_snippets.py`, and `python3 scripts/check_comment_hygiene.py --check`. Update the delivery ledger with Project A's actual local state and explicitly open B/C/D gates; do not mark future hosted checks, merge or publication complete.
- [ ] Run full local qualification with original assertions and limits. Use existing installed environments or the repository's documented dev setup; retain stdout/stderr and exit codes outside the tracked tree. Do not install or upgrade tools merely because a gate is slow. Root commands:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo check -p hushspec --no-default-features --locked
cargo +1.88.0 build --workspace --all-features --locked
cargo package --workspace --locked
npm run build
npm run lint
npm test
npm audit --audit-level=high
pytest packages/python/tests -q
python3 scripts/check_cross_sdk_roundtrip.py
python3 scripts/smoke_snippets.py
python3 scripts/generate_cli_schemas.py --check
python3 scripts/generate_testkit_schemas.py --check
python3 scripts/generate_fixture_manifest.py --check
python3 scripts/generate_sdk_contracts.py --check
python3 scripts/generate_sdk_models.py --check
python3 scripts/generate_log_schema_vectors.py --check
cargo run --locked -p hushspec-testkit --bin hushspec-testkit -- --fixtures fixtures --report target/project-a-conformance.json
cargo run --locked --release -p hushspec-testkit --bin hushspec-difftest -- --seed 42 --groups 500 --actions-per-group 4 --report target/project-a-difftest.json
```

From `packages/go`, run `go test ./...`, `go vet ./...`, and the Task 3 race/nil-panic cases. Verify the TypeScript suite on the existing qualified Node 20 and Node 24 environments; record exact runtime versions. CI remains responsible for all existing generated-source, coverage, dependency, packaging, benchmark and container jobs; no passing local subset replaces those gates. If a tool/environment is unavailable, record the missing gate rather than claiming a pass.
- [ ] Give a fresh whole-branch reviewer the approved spec, this plan, baseline `3cca247`, final candidate diff, failures/retries and evidence artifacts. Ask specifically about duplicate JSON keys, key/source snapshot substitution, signer-role binding, policy-event ordering, inventory trust, callback double recording, output transaction failure and OSCAL reference/claim validity. Resolve actionable findings with new regression tests and repeat affected/full gates as appropriate. Do not equate a clean automated review with a human approval.
- [ ] Commit final documentation/review fixes before hosted qualification. Record the candidate and source state, then use the user's commit/push/CI authorization:

```sh
git diff --check
git status --short
git rev-parse HEAD
git push origin HEAD:wave-6
gh workflow run ci.yml --ref wave-6
```

Require an empty worktree and matching local/remote/PR #10 head before relying on results. Read-only checks:

```sh
candidate_sha=$(git rev-parse HEAD)
git ls-remote origin refs/heads/wave-6
gh pr view 10 --json headRefOid,baseRefName,state,mergeStateStatus,reviewDecision,url
gh run list --workflow ci.yml --commit "$candidate_sha" --json databaseId,headSha,status,conclusion,event,url
```

Inspect each matching run's jobs and REST `run_attempt`; include both the PR and direct-source run when applicable. Poll in short intervals with progress updates, not a single unbounded blocking watch. Preserve failed/cancelled attempts and their cause before retrying. Terminal required checks must all pass on this exact source, with no skipped gate substituted for a result. Do not merge PRs, resolve unrelated review threads, create tags or publish packages.
- [ ] Hand off exact SHA, commits, local gate results, hosted run URLs/attempts, review findings and remaining B/C/D work. Any further source/doc commit invalidates that exact-head qualification and needs a new run. If external CI is unavailable, report the unqualified gate explicitly.

## Spec coverage and execution order

| Approved design requirement | Owning tasks |
|---|---|
| Reference attribution and unsupported claims | 1, 10 |
| Callback receipts and original failure preservation in all four SDKs | 2, 3 |
| Stable formats, new experimental artifacts, strict flag compatibility | 4, 7 |
| Exact bytes, resource bounds, signatures and signer roles | 4, 5, 7 |
| Rotation continuity, policy ordering, policy origin and scoped completeness | 6 |
| Atomic failure semantics, no overwrite, sidecar/report binding | 7 |
| Genuine assessment context and observation-only OSCAL | 8, 9 |
| Negative tests, unchanged existing semantics, fresh review and exact-head CI | Every task; 10 consolidates |
| Independent engine, trusted MCP dispatch, external assessor/adopter | Excluded here; retained in roadmap B/C/D |

Execute 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8 -> 9 -> 10 for native execution. If subagent-driven execution is selected, 1/2/3 are independently implementable; 4-9 still follow their interface dependencies and share no simultaneous writes to `cmd_report.rs`. Read-only review may run alongside useful nonconflicting work. Do not delegate the plan's self-review; the coordinating agent checks the contracts and coverage itself.

Each task's commit includes only its owned changes and generated artifacts. Keep the red result, green result and commands in the qualification record. Do not advance to release claims because these checkboxes are checked: Project A is evidence repair, not the full foundational-standard milestone.
