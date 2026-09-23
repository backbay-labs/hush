# Implementation-bound Conformance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute and grade a digest-bound external engine against the real L0-L3 corpus without a reference fallback, with a working Go bring-up adapter and replayable evidence.

**Architecture:** A separate testkit external module snapshots inputs, constructs requests/expectations, runs bounded Linux processes, scores observations and publishes unchanged v1 reports plus an experimental execution record. Go is the first-party protocol implementation; independent-engine qualification stays open.

**Tech Stack:** Rust 2024/MSRV 1.88, serde/jsonschema/sha2/tempfile, already-locked Unix libc, Go 1.22. No version upgrades.

**Spec:** [Project B design](../specs/2026-09-23-implementation-bound-conformance-design.md).

**Execution:** User requested plan creation/review, complete native execution and final review in one pass. Work in existing `wave-6`, baseline `2835c86`; no intermediate approval pause. Preserve original failures, use conventional commits, then push and qualify exact-head CI; no merge/tag/publication.

## Global Constraints

- Keep Core semantics and conformance-report v1 unchanged.
- Use Rust 2024 / MSRV 1.88 and Go 1.22; no dependency version upgrades.
- Engine executables are operator-approved code, not sandboxed adversaries.
- Configuration and corpus are immutable bounded snapshots. Never calculate a digest from different bytes than those parsed, supplied or retained.
- Missing, duplicate, foreign, stale, malformed or oversized responses cannot produce a qualified result. Unsupported means not attempted, never pass.
- Publish only into a new output directory; completion record is written last.
- Preserve original failed attempts and retries; do not weaken assertions, deadline tests or existing CI gates to obtain a pass.

## Review Focus

1. A changed executable or fixture pathname cannot substitute different bytes after capture. Task 1 pins snapshot behavior; Task 5 runs the captured executable.
2. A rejected invalid policy must not pass because the engine crashed, timed out or returned an unrelated error. Tasks 2/3 distinguish transport failure from an observation.
3. A skipped subcase or unsupported operation cannot disappear behind a passing file-level result. Tasks 3/5 enumerate every result slot before execution.
4. A child holding inherited stdout/stderr cannot outlive the deadline or leave a blocked reader. Task 2 owns real descendant/output tests.
5. A report copied from a prior run or an unrelated executable cannot acquire new provenance from relabelling. Tasks 1/5 bind run/case/operation/input plus executable/report digests and preserve honest identity limits.

## File and interface map

| Unit | Files | Responsibility |
|---|---|---|
| Contracts/snapshots | `crates/hushspec-testkit/src/external/{mod,model,json,snapshot}.rs` | Closed protocol/profile/record contracts; bounded immutable inputs |
| Process runner | `external/process.rs` | Linux nonblocking capture, deadlines, group cleanup |
| Corpus/scoring | `external/{corpus,score}.rs`, `src/report.rs` | Snapshot-only case enumeration, normative expectations, v1 reporting |
| Go adapter | `packages/go/cmd/hushspec-conformance/{main,main_test}.go` | Real Go operation observations, no scoring |
| CLI/publication | `external/{run,output}.rs`, `src/main.rs` | Controller orchestration, retained packet, exit semantics |
| Schemas | `schemas/hushspec-engine-{profile,request,response}-experimental.v1.schema.json`, `schemas/hushspec-conformance-execution-experimental.v1.schema.json` | Versioned experimental wire contracts |
| Acceptance/CI/docs | `tests/external_tests.rs`, `scripts/run_external_conformance.py`, `.github/workflows/ci.yml`, docs/README references | Faulty engines, full Go corpus, runnable packet verification and exact-head qualification |

## Task 1: Closed wire contracts and bounded immutable snapshots

**Files:** Create external module/model/json/snapshot and four schemas; modify testkit lib/Cargo.toml, schema generators and JSON-schema reference. Use existing locked libc only when Task 2 needs it.

**Interfaces:** `EngineProfile`, `Request`, `Response`, `Operation`, `Observation`, `ExecutionRecord` in model; `parse_json(&[u8]) -> Result<Value,String>`; `Snapshot {label:String, bytes:Vec<u8>, sha256:String}`; `CorpusSnapshot {manifest:Manifest, manifest_snapshot:Snapshot, files:BTreeMap<String,Snapshot>}`; `snapshot_corpus(&Path) -> Result<CorpusSnapshot,String>`; `snapshot_file(&Path, label:&str, limit:usize) -> Result<Snapshot,String>`. Define limits in model with checked defaults from spec. Consumers hash input JSON bytes using existing manifest::digest_bytes.

- [ ] Write contract/snapshot tests first. Test unknown/duplicate keys, null where required, 65-level nesting, malformed digests, unsupported protocol, path traversal, symlinks/hardlink aliases, file/total caps, duplicate manifest entries and missing/unlisted/mutated files. The pathname replacement test reads once, replaces the original, and grades from the captured bytes.

```rust
#[test]
fn rejects_ambiguous_response() {
    assert!(external::json::parse_json(br#"{"case_id":"a","case_id":"b"}"#).is_err());
}
#[test]
fn captured_bytes_survive_path_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input");
    std::fs::write(&path, b"original").unwrap();
    let snapshot = external::snapshot::snapshot_file(&path, "input", 16).unwrap();
    std::fs::write(&path, b"replacement").unwrap();
    assert_eq!(snapshot.bytes, b"original");
    assert_eq!(snapshot.sha256, hushspec_testkit::manifest::digest_bytes(b"original"));
}
```

- [ ] Run `cargo test -p hushspec-testkit external::` and observe missing module/API failure; add strict decoder/contracts/snapshot implementation. Build JSON schemas before typed decoding so null does not become an absent optional member. Root all corpus lookups in the captured map. Validate manifests and pinned content before case construction.
- [ ] Run the new negative tests, `cargo test -p hushspec-testkit`, and all schema generators with `--check`. Existing schemas remain byte-identical. Expected: green suites; new experimental schemas embedded and indexed.
- [ ] Commit `feat(testkit): define external engine protocol and snapshots`.

## Task 2: Bounded executable process lifecycle

**Files:** `external/process.rs`, Cargo.toml target-specific locked libc edge; process test helpers under `tests/support/` if needed.

**Interfaces:** `ProcessLimits` from model; `ProcessCapture {stdout:Vec<u8>, stderr:Vec<u8>, exit_code:Option<i32>, signal:Option<i32>, failure:Option<String>, elapsed_ms:u64, truncated:bool}`; `run_process(executable:&Path,args:&[String],request:&[u8],cwd:&Path,limits:&ProcessLimits) -> Result<ProcessCapture,String>`. Linux-only implementation, clear refusal elsewhere.

- [ ] Add real executable tests before implementation: clean response; explicit nonzero exit; signal; no stdin consumption; stdout and stderr floods; a never-ending process; a parent exiting while a child holds pipes; scrubbed environment. Use controlled shell/Python test executables only as fixtures, never as the product command dispatcher.

```rust
#[cfg(target_os = "linux")]
#[test]
fn a_hung_engine_is_not_an_observation() {
    let dir = tempfile::tempdir().unwrap();
    let limits = ProcessLimits { timeout_ms: 100, ..Default::default() };
    let before = std::time::Instant::now();
    let capture = run_process(std::path::Path::new("/bin/sh"),
        &["-c".into(), "sleep 30".into()], b"{}", dir.path(), &limits).unwrap();
    assert!(capture.failure.is_some());
    assert!(before.elapsed() < std::time::Duration::from_secs(3));
}
```

- [ ] Observe red, implement request-file stdin, scrubbed environment, process group, nonblocking bounded pipe reads and deadline checks. Kill group/reap direct child on every completion/error path. Do not create blocking reader threads or use unbounded `Command::output()`.
- [ ] Run all process tests and the full testkit suite. Expected: successful clean subprocess, fail-closed failures, bounded output, no delayed descendant marker; unchanged test deadlines.
- [ ] Commit `feat(testkit): bound external engine process execution`.

## Task 3: Corpus-derived requests and controller-owned scoring

**Files:** `external/corpus.rs`, `external/score.rs`, `report.rs`; handwritten L2 cases in `fixtures/core/merge/` as needed, then regenerate fixture manifest.

**Interfaces:** `Case {id:String, operation:Operation, input:Value, expectations:Vec<Expectation>}`; `Plan {cases:Vec<Case>, unattempted:Vec<VectorResult>}`; `plan_cases(&CorpusSnapshot, target_level:u8) -> Result<Plan,String>`; `score(&Case,&Response,ErrorCodes) -> Result<Vec<VectorResult>,String>`; `build_from_snapshot(Implementation,&Manifest,String,Vec<VectorResult>,String) -> Result<ConformanceReport,String>`. Original report::build delegates without changing its result; explicit L0 results disable legacy inference only for the external path.

- [ ] Write literal/handwritten tests for unknown action deny, allowlist precedence, scalar source spelling, partial expected fields, default normalization, merge strategies, cycle rejection, missing subcases, conditional error-code checking, and unsupported operations. Confirm no expectation appears in any serialized request.

```rust
#[test]
fn a_fabricated_allow_does_not_pass_an_unknown_action() {
    let case = handwritten_unknown_action_case();
    let response = matching_response(&case, json!({"decision":"allow"}));
    let results = score(&case, &response).unwrap();
    assert!(results.iter().any(|result| result.status == Status::Fail));
}
```

Test helpers construct a literal policy `hushspec: '1.0.0'`, action type
`unrecognized`, expected decision `deny`; matching_response copies binding fields
only, never calculates an expected verdict. Tests for altered/missing result
slots assert highest_level cannot rise to 3.

- [ ] Observe red; build cases entirely from captured corpus bytes. Decode fixture containers as data without executing Rust policy operations. Send raw documents as text, evaluator embedded objects as JSON text. Supply dependency maps for resolver cases and builtin-dependent library suites; pin builtin source inputs separately if outside fixtures. Treat trace/receipt assertions as explicit L4 unattempted slots, not silently passed L3 assertions.
- [ ] Preserve full manifest coverage and case cardinality. Validate malformed fixture containers and unknown scored categories before execution. Refactor report aggregation to accept captured manifest/digest and explicit L0 results while preserving all old reference-runner tests.
- [ ] Run new unit tests, full testkit suite and fixture/schema generator checks. Expected: mutated decisions/rejections fail; unsupported/missing results remain unattempted; legacy report tests pass.
- [ ] Commit `feat(testkit): grade external observations against pinned cases`.

## Task 4: Real Go SDK protocol adapter

**Files:** `packages/go/cmd/hushspec-conformance/main.go`, `main_test.go`.

**Interfaces:** Native executable reads one Request JSON from stdin and writes one Response JSON to stdout. Uses public Go Parse/Validate/Merge/ResolveWithOptions/Evaluate/CanonicalJSON/ContentHash APIs. No conformance grading or Rust subprocess. Input document maps resolve only declared names, including builtin source text supplied by the controller.

- [ ] Add tests exercising main's protocol dispatcher with literal raw YAML, invalid syntax, scalar spellings, merge, multi-hop resolve/cycle refusal, evaluate, canonical form, malformed requests and unsupported operations.

```go
func TestEvaluateUnknownAction(t *testing.T) {
    input := []byte(`{"policy":"hushspec: '1.0.0'","action":{"type":"unknown"},"source":"policy.yaml","documents":{}}`)
    result := observe("evaluate", input)
    if result.Status != "ok" || result.Value["decision"] != "deny" {
        t.Fatalf("unexpected observation: %#v", result)
    }
}
```

`observe(operation string,input json.RawMessage) observation` is the adapter's
operation dispatcher; observation has Status, Value and refusal/error fields.

- [ ] Observe missing dispatcher failure, implement closed request decoding, binding echoes and operation-specific observations. Preserve absent optional expected fields; never include expected results or calculate a passed flag. Parse observations serialize the parsed SDK document, preserving unresolved extends and merge_strategy; test the valid extends-basic fixture. Canonicalization is a distinct operation, never a prerequisite for parse success.
- [ ] Run `go test ./...`, `go vet ./...`, `go test -race ./...` from packages/go. Build `CGO_ENABLED=0 go build -trimpath -o ../../target/hushspec-conformance-go ./cmd/hushspec-conformance`. Expected: real Go executable, all Go tests green.
- [ ] Commit `feat(go): add external conformance observation adapter`.

## Task 5: End-to-end controller and atomic completion packet

**Files:** `external/run.rs`, `external/output.rs`, `main.rs`, `tests/external_tests.rs`, execution schema.

**Interfaces:** `run_external(ExternalOptions) -> Result<RunOutcome,String>`; ExternalOptions contains profile/fixtures/output paths, target level, limits, optional source/CI context. RunOutcome contains qualified bool and report path. Create fresh run ID, serialize/hash inputs, dispatch each planned case via captured image, validate response bindings, score, retain every capture, build schema-valid report/record and publish completion last.

- [ ] Add CLI red tests for unknown `external` subcommand, report/record digests, existing-output refusal, executable substitution, wrong/stale/duplicate/missing case binding, malformed JSON, unsupported and lying engines, out-of-order/multiple responses, engine timeout/crash/output cap, and remaining cases after an abort.

```rust
#[test]
fn stale_response_cannot_qualify_a_new_run() {
    let fixture = ExternalFixture::stale_engine();
    let outcome = fixture.run();
    assert_eq!(outcome.code(), Some(1));
    assert_eq!(fixture.execution()["outcome"], "not_qualified");
    assert_ne!(fixture.report()["highest_level"], 3);
}
```

`ExternalFixture` is a test utility, not production configuration. It writes a
small digest-pinned corpus/profile and a controlled executable that echoes or
mutates protocol bindings. Assertions target controller outcomes and artifacts,
not the helper's own behavior.

- [ ] Observe red, wire CLI, profile/corpus snapshots, staged executable identity, case planning, budgets, observations and output. Keep process failures distinct from valid policy refusals. Include controller executable hash, declared build materials, environment and optional source/CI context, all retained request/output hashes, plus trust/independence limitations.
- [ ] Validate report and execution schemas before publication. Refuse existing directory atomically, never replace user files, write completion record last and clean only owned created paths on recoverable failure. Test injected publication failure, input/output collision and pre-existing directory content preservation.
- [ ] Run the real Go engine against the complete committed corpus at L3. Diagnose any mismatch; keep original failure logs. No unsupported fallback or corpus filtering to make the level pass. Validate every retained digest and exactly one terminal record per dispatched request.
- [ ] Run testkit and Go suites, clippy with unchanged `-D warnings`, and schema/fixture checks. Commit `feat(testkit): publish implementation-bound conformance runs`.

## Task 6: CI, operator guidance, qualification and final review

**Files:** `scripts/run_external_conformance.py`, `.github/workflows/ci.yml`, testkit README, docs conformance/CLI/schema references, `docs/plans/STATUS.md`, new `docs/reviews/2026-09-23-project-b-qualification.md`.

- [ ] Add a real acceptance driver that builds the Go native binary with CGO disabled, hashes binary/go.mod/go.sum into a profile, invokes `external` with explicit source SHA/run/attempt, checks requested L3 and packet digests, and leaves all artifacts. Add tests for the driver's packet-verification failure using tampered report/output bytes; observe red before implementing its checker.
- [ ] Add an isolated CI job with Rust stable and Go 1.22, read-only permissions, no secrets passed to the engine; run the driver and always upload the packet. Preserve every existing CI job.
- [ ] Document profile/request/response examples, exit semantics, supported Linux/self-contained-executable scope, resource defaults, report verification, unsafe-executable boundary, operator-declared identity/build context, and the distinction between Go bring-up and independent qualification. Update delivery/qualification records without rewriting historical evidence.
- [ ] Run full verification, retaining logs and exit codes:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo check -p hushspec --no-default-features --locked
cargo +1.88 build --workspace --all-features --locked
python3 scripts/run_external_conformance.py --out target/project-b-go-run
python3 scripts/generate_testkit_schemas.py --check
python3 scripts/generate_cli_schemas.py --check
python3 scripts/generate_fixture_manifest.py --check
python3 scripts/check_comment_hygiene.py --check
python3 scripts/check_cross_sdk_roundtrip.py
python3 scripts/smoke_snippets.py
mdbook build docs
```

Also run full Go tests/vet/race, TypeScript build/lint/test, Python tests and
existing conformance/differential gates. Package the Rust workspace with a
fresh synthetic-registry CARGO_HOME and separate target as learned in Project A;
do not run packaging over a shared test binary or accept stale registry source.

- [ ] Give a fresh whole-branch reviewer baseline `2835c86`, this spec/plan,
  final diff and logs. Re-grade findings by user impact, fix actionable
  Critical/Important findings in one RED→GREEN pass and repeat affected/full
  gates. Record Minor deferrals and every declined-to-judge ruling.
- [ ] Commit final repairs and local qualification before push. Push `HEAD:wave-6`,
  dispatch ci.yml and wait for terminal success on matching local/remote/PR10
  head, inspecting both PR/direct runs, run attempts and all jobs. Preserve
  original failures before retries. No merge/tag/publish/thread resolution.
- [ ] Archive the plan's execution ledger/logs, retaining the existing checkout.
  Hand off exact SHA, local and hosted evidence, review findings/rulings,
  first-party Go level, and the explicitly open independent-engine/C/D gates.

## Preflight coverage

Contracts/snapshots feed process/corpus/controller; corpus plans feed scoring;
Go consumes the same operation/observation schema; controller produces the
packet consumed by CI and docs. Tasks execute 1→2→3→4→5→6, with no concurrent
source writes. Plan self-review and an independent pre-implementation review
must resolve interface or scope conflicts before Task 1.

## Reviewed contract refinements

The independent pre-implementation review identified five Important interface
gaps and two Minor refinements; all are incorporated before implementation:

- Tasks 1/5 reject non-static ELF engine images and bind the running controller
  through `/proc/self/exe`, not a replaceable launch pathname. Test both checks.
- Tasks 3/4 preserve unresolved parse fields, schema-validate observed documents,
  reject resolution fields on merge/resolve output before normalization, and
  normalize only schema defaults and canonical presence rules. Tests retain
  metadata, absent/default equivalence and presence-significant empty arrays.
- Task 3 receives ErrorCodes explicitly; identical no-code refusals differ by
  policy, and emitted codes/required diagnostics are always checked.
- Task 3 assigns mandatory L0 rejection only to explicit syntax/profile/missing
  version vectors. Other invalid vectors permit early rejection or deferred
  validation at L0, while L1 independently requires rejection.
- Tasks 1/5 cap aggregate retained request bytes at 64 MiB (maximum 256 MiB),
  and each dispatch uses the smaller of per-case and remaining total deadline.
- Tasks 3/4 canonicalize dependency aliases to a single logical source name;
  add an alias-cycle regression and refuse undeclared document lookup.
- Tasks 5/6 retain every planned result slot, including undispatched requests;
  packet verification checks slot uniqueness/completeness and terminal-record
  cardinality as well as every retained artifact digest.
