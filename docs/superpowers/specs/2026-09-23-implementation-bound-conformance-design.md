# Implementation-bound conformance (Project B)

Date: 2026-09-23. Baseline: `wave-6`, `2835c86cce67f4bea930343a7685497460010615`.
The user approved harness-first bring-up, then requested creation/review of the
plan, full execution and final review in one pass. Intermediate approval stops
are replaced by that explicit instruction. Existing-checkout, commit/push and
exact-head CI preferences continue; merging, tagging, publishing and changing
Chio are not authorized by this project.

## Intent and boundaries

Project A made evidence claims narrower and verifiable. B must demonstrate
which executable actually answered every conformance case, without silently
using the reference evaluator for unsupported operations. The controller owns
the corpus, expectations and scoring. The engine returns observations, never
its own conformance verdict. This is executable qualification, not a proof that
the executable is honest or independently authored.

Deliver a working external controller, an experimental protocol and execution
record, a real Go SDK adapter, adversarial process/protocol tests, documentation
and exact-head CI. Target L0-L3. L4/L5 remain explicitly unattempted except for
individual optional canonical observations; no level is granted without every
required lower level. Independently authored engine qualification, external
adoption and Project C's MCP dispatch coordinator remain separate open gates.

The Go adapter imports this repository's Go parser/evaluator and no Rust
evaluator. It is first-party bring-up, not independent adoption. No changes to
Go policy semantics are planned; discrepancies discovered by the new controller
are failures to diagnose, not reasons to weaken expectations.

## Approaches and selection

1. **Separate external controller (selected):** reuse report wire models and
   published fixture formats, with new snapshot/case/process boundaries. This
   preserves the reference runner and prevents its in-process evaluator from
   becoming an invisible fallback.
2. Extend the differential runner: less initial plumbing, but its normalized
   bundle and Rust-oracle comparison do not establish raw-parser conformance.
3. Chio-first: useful future integration, but couples protocol delivery to an
   unqualified cross-repository migration and independence audit.

## Constraints

- Keep Core semantics and conformance-report v1 unchanged.
- Use Rust 2024 / MSRV 1.88 and Go 1.22; no dependency version upgrades.
- Use only already-locked dependencies; a direct Unix `libc` edge is permitted
  for nonblocking pipes and process-group cleanup.
- The experimental external process backend supports Linux initially. Other
  platforms refuse clearly before engine execution; existing commands remain
  portable and unchanged.
- Engine executables are operator-approved code, not sandboxed adversaries.
  CI must not expose secrets to them. Process-group cleanup is not containment
  against a program deliberately escaping its group or attacking the host.
- Configuration and corpus are immutable bounded snapshots. Never calculate a
  digest from different bytes than those parsed, supplied or retained.
- No shell interpolation; execute a captured local executable and explicit
  argument vector with a scrubbed environment.
- Missing, duplicate, foreign, stale, malformed or oversized responses cannot
  produce a qualified result. Unsupported means not attempted, never pass.
- Publish only into a new output directory; completion record is written last.
- Preserve original failed attempts and retries; do not weaken assertions,
  deadline tests or existing CI gates to obtain a pass.

## Architecture

Add `hushspec-testkit external --engine PROFILE --fixtures fixtures --out DIR
--level 3`. Existing root flags and `bundle` behavior remain unchanged.
`DIR` must not exist and its parent must be operator-controlled and exist.
Exit 0 means the requested level and every prerequisite passed; exit 1 means a
completed nonqualifying run (semantic failure, unsupported operation, process or
protocol failure); exit 2 means configuration/corpus/publication failure.

The profile is experimental `0.1.0`, a closed JSON object containing:

- `implementation`: required nonempty name, version and language, explicitly
  operator-declared identity bound to the executable digest, not self-proving.
- `executable`: local path and lowercase hex SHA-256. Paths resolve relative to
  the profile; no network acquisition. A captured executable is privately staged
  and that copy, not the mutable original path, is executed.
- `args`: explicit array, no shell; maximum 32 strings of 4096 bytes each.
- `error_codes`: `registry` or `none`; registry mode enforces fixture rejection
  codes and message fragments. A response emitting a code must be checked even
  when the profile declares no codes.
- `materials`: optional local dependency/build identity files with exact
  digests, retained as operator-declared build materials, not a claim that the
  controller attested the build. Go bring-up includes go.mod and go.sum.

The same staged binary contains the Go adapter and engine. This deliberately
avoids claiming a separately listed but never executed engine artifact. Other
engines may implement this monolithic executable protocol; interpreted/plugin
engines need a separately reviewed dependency/execution binding before making
equivalent provenance claims.

### Snapshot and corpus inventory

Capture profile (1 MiB), executable (128 MiB), controller executable (128 MiB),
materials (16 files / 16 MiB), manifest (8 MiB), and corpus files (16 MiB each,
64 MiB aggregate / 4096 entries). Reject duplicate manifest paths, malformed
digests, paths escaping `fixtures/`, duplicate physical input aliases, symlink
inputs, nonregular files, unlisted files, missing files and digest mismatches.
Every required fixture is loaded once; fixture discovery and expectations use
the captured map, not filesystem rereads. Reject unsupported corpus categories
or malformed scored fixture containers rather than skip them. Retain the
manifest and the exact input files used in the evidence packet.

Builtin policies used by library suites are additional captured data resources:
copy the controller's embedded `hushspec::load_builtin` source strings, hash and
retain them, and pass them through the request document map. Loading those raw
strings is not reference evaluation/resolution. Their identity is additionally
bound by the controller image digest. An engine must resolve the supplied map,
not substitute its own ambient builtin implementation.

Strict JSON rejects duplicate decoded keys, nesting beyond 64, trailing values,
invalid UTF-8 and nonfinite numbers before typed/schema decoding. Experimental
wire schemas are closed. Native report v1 schema is unchanged.

### Requests and observations

One process per request provides simple lifetime and response cardinality.
The request is a single JSON value on stdin:

```json
{"protocol":"0.1.0","run_id":"unique-run-id","case_id":"fixture#case",
 "operation":"evaluate","input_sha256":"64 lowercase hex digits",
 "input":{"policy":"raw YAML or JSON text","action":{"type":"tool_call","target":"read_file"}}}
```

`input_sha256` binds the controller's serialized input value, which is retained
alongside the whole request. `run_id`, case ID, operation and input digest must
be echoed exactly. Operations are `parse`, `validate`, `merge`, `resolve`,
`evaluate`, and `canonicalize`. The corresponding inputs contain raw policy
text, base/child raw texts, or root/source/document-map raw texts; evaluator
fixtures embed policy objects, so their JSON serialization is supplied as JSON
text without calling the Rust policy parser. Raw document and raw-YAML fixtures
retain their exact source spelling.

Responses have the same five binding fields and a closed tagged `result`:
`ok` with an operation-specific observation; `rejected` with phase, diagnostic
and optional code; `unsupported`; or `error` with a diagnostic. Controller
checks observation shape for the selected operation. Duplicate/trailing JSON,
unknown fields, wrong IDs/digests/operations and multiple responses fail the
case. Responses carry no `passed`, `expected` or reference answer fields.

Observation contracts:

| Operation | Observation |
|---|---|
| parse | Parsed document as JSON, retaining values for scalar assertions. |
| validate | Validated document as JSON, or a phase/code-qualified refusal. |
| merge | Merged document as JSON; no controller-side merge computation. |
| resolve | Resolved document as JSON, or resolution refusal; root and dependency texts are supplied explicitly. |
| evaluate | Decision and optional matched_rule, reason, origin_profile, posture. All fields asserted by the vector are checked. |
| canonicalize | Canonical JSON text and content hash, checked against committed expectations when attempted. |

Expectations are never sent in requests. The corpus is public and the process
is not sandboxed: withholding expectations from the protocol is a separation
of responsibilities, not a claim that an engine cannot cheat.

### Case construction and grading

Enumerate each case before dispatch. Each case owns explicit result slots and
literal expectations derived from committed vectors, not reference evaluation.

- Valid/invalid documents: separate parse and validation observations; enforce
  `.expect.yaml` codes/diagnostics where applicable. Raw scalar cases receive
  exact `yaml` strings; check acceptance and declared value paths. Parser and
  validator failures remain separate, with explicit L0 result slots.
- Merge directory conventions: base, child, expected sibling and refusal
  metadata come from captured files. Pinned/chain children use the engine's
  resolver. Expected documents may be decoded as data for comparison, but no
  reference merge/resolution runs. Compare normalized semantic document forms,
  explicitly accounting for omitted default fields, without hiding mismatches.
- Resolution: cover simple inheritance, all merge strategies, multi-hop chains,
  cycle rejection and unknown dependencies at L2. Add handwritten L2 cases
  where existing hash-oriented L4 fixtures cannot establish these independently.
- Evaluator and library suites: one result per action. If the embedded policy
  extends, the engine's evaluate operation resolves it first using captured
  builtin documents within that same request; never call the reference resolver.
  Dedicated resolve cases separately inspect resolved documents. Runtime context is supplied
  exactly with existing action-over-case precedence. Compare only stated L3
  fields. Receipt/trace expectations remain separate L4 not-attempted slots.
- Raw-YAML decision cases use their prescribed fixed action. Canonical/hash
  vectors may execute the canonicalize operation, but unrelated L4/L5
  requirements remain unattempted and cannot be inferred from those passes.
- Controller tracks every planned case, including aborted/unattempted cases.
  Existing report models are reused through a snapshot-based report builder;
  explicit L0 observations must not be overwritten by legacy inferred counts.

Unsupported required operations make the requested level unqualified. A wrong
answer is a semantic failure; timeout/crash/protocol violations are harness
failures and never count as a correct rejection of an invalid policy. Abort
remaining dispatch after a protocol/process failure or total resource limit;
record all remaining cases as not attempted. Ordinary semantic mismatches do
not prevent subsequent bounded cases from being scored.

### Resource and process lifecycle

CLI limits: per-case deadline default 2000 ms (1..30000), total run deadline
300000 ms (1..3600000), stdout 1 MiB and stderr 256 KiB per case (1..16 MiB),
64 MiB aggregate captured output (1..256 MiB), 10000 cases. Requests are capped
at 16 MiB each. Deadline includes response collection, not just leader exit.
The request is prepared in a private regular file used as stdin; no potentially
blocking stdin writer thread. Capture stdout/stderr through nonblocking pipes
with bounded buffers, poll status/deadline/output budget, kill the process group
on failure and on completion, and reap the direct child. Descendants inheriting
pipes must not hold the controller open. No sleeping reader threads remain.
The environment is exactly `LANG=C`, `LC_ALL=C`, `TZ=UTC`; no host secrets or
ambient PATH are forwarded. A native static Go binary needs no ambient runtime.

### Execution record and packet

Publish `report.json` unchanged v1 plus experimental `execution.json` version
0.1.0, written last. The record contains the exact report digest; profile,
manifest, controller and engine image digests; declared materials; argument
vector; scrubbed environment; OS/architecture; requested level; outcome;
limits; source SHA / CI run / attempt when supplied by the operator/CI; all
case bindings; process status, exit/signal, duration, bounded-output truncation;
request/stdout/stderr relative paths and digests; and explicit limitations.
Keep the actual request/response/diagnostic bytes and staged executable image.
The runner identifies controller code by its executable digest, not just a
version string. Source/CI metadata are declared context, not cryptographic
attestation of the executable's build. This record is unsigned; digest binding
alone is not trusted provenance.

All artifacts are staged privately and synced before publication. The final
directory is created exclusively only after the run and schemas validate.
Publish files without overwriting and write execution.json last; failures must
not leave a completion marker. Recoverable cleanup removes only files/directories
owned by this invocation. A process crash can leave an incomplete directory;
operators must require the completion marker and verify recorded digests.

## Verification and delivery

Acceptance covers the full committed L0-L3 corpus on the Go engine plus
handwritten counterexamples. Faulty engine processes exercise lying results,
unsupported operations, missing/wrong/duplicate/stale bindings, malformed JSON,
exit status/signal, hang, oversized stdout/stderr, and children holding pipes.
Input mutation, aliasing, digest mismatch, case omission and existing output
directory must fail without a qualified packet. No reference fallback is
permitted, including when the Go toolchain is absent in local tests.

Add a CI job that builds Go with CGO_ENABLED=0, hashes the resulting executable
and dependency files, runs the external controller at L3, verifies report and
execution bindings, and uploads the complete packet even on qualification
failure. Its source SHA/run/attempt are explicit. Keep all existing gates.

Finish with full Rust/Go suites, formatting/clippy/vet/race, generated/schema
checks, existing cross-SDK regressions, isolated workspace packaging, docs,
fresh final review, commit/push and terminal exact-head PR/direct CI. Archive
original failures and retries. No merge/tag/publish. State separately: harness
delivered; Go first-party L3 outcome; independent-engine gate open; C/D open.
