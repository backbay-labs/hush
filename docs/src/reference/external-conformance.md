# External engine conformance

`hushspec-testkit external` executes a digest-pinned engine and grades its
observations against captured corpus expectations. It never substitutes the
built-in evaluator. The experimental protocol and execution record are
version `0.1.0`; the resulting conformance report retains the stable v1 format.

The current backend targets L0-L3 on Linux with a static, native ELF executable.
Scripts, dynamic ELF images, and interpreted/plugin dependency graphs are not
supported. The Go SDK adapter is first-party bring-up, not evidence of
independent authorship, external adoption, or a trusted MCP dispatch boundary.

## Run and verify

From a checkout with Rust, Go and Python's `jsonschema` installed:

```sh
python3 scripts/run_external_conformance.py --out target/go-conformance
python3 scripts/run_external_conformance.py --verify target/go-conformance/packet
```

The driver builds Go with `CGO_ENABLED=0` and the controller in release mode,
records the source revision (marks a dirty implementation version), hashes the
binary and Go dependency files, requests L3, verifies the packet, and retains
all output. `--out` must be new. Use another directory for a retry. CI records
its run ID and attempt and uploads the entire directory, including failed runs.

Offline `--verify` executes no images. It verifies all artifact bytes, corpus
inventory, request/response bindings, terminal-record and result-slot
cardinality, level counts and outcome consistency. A valid *nonqualifying*
packet can pass integrity verification; inspect its outcome before citing a
level. Verification does not independently re-grade observations or authenticate
the unsigned producer. Keep the controller and corpus identities with the report.

For an approved engine implementing the protocol:

```sh
hushspec-testkit external --engine engine-profile.json --fixtures fixtures \
  --out run-packet --level 3
```

The output parent must exist, be operator-controlled, and be outside the
corpus. Existing output directories, including empty ones, are never replaced.
`execution.json` is the completion marker: the complete synced packet is
published atomically with Linux `RENAME_NOREPLACE`. A publication error does not
establish a durable complete packet.

| Exit | Meaning |
|---|---|
| 0 | Requested level and all prerequisites passed. |
| 1 | Completed nonqualifying packet: wrong answers, unsupported operations, process/protocol failure or dispatch budget exhaustion. |
| 2 | Configuration, corpus, supported-format or publication error; no qualification claim. |

## Profile and protocol

A profile uses these fields (replace the example digest with the actual SHA-256):

```json
{
  "protocol": "0.1.0",
  "implementation": {"name": "example-engine", "version": "1", "language": "Go"},
  "executable": {"path": "./engine", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  "args": [],
  "error_codes": "registry",
  "materials": []
}
```

Paths resolve relative to the profile. Identity and build materials are operator
declarations, not build attestations. `error_codes: "none"` allows code-free
validator refusals under Core section 8; emitted codes and explicit resolver
reason assertions are still checked. Unknown fields, duplicate JSON keys and
explicit null in non-nullable fields are refused.

Each fresh process reads one request from stdin and writes one response to
stdout. Send diagnostics to stderr. The controller supplies:

```json
{
  "protocol": "0.1.0", "run_id": "run-1", "case_id": "example#0",
  "operation": "evaluate",
  "input_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "input": {"policy": "hushspec: '1.0.0'", "source": "policy.yaml", "documents": {}, "action": {"type": "unknown"}}
}
```

The digest above is illustrative. Echo the actual five binding fields exactly;
`input_sha256` hashes the exact UTF-8 input-value bytes in the request, not a
fresh serialization. The controller retains those bytes separately. A response
replaces `input` with `result`, for example:

```json
{
  "protocol": "0.1.0", "run_id": "run-1", "case_id": "example#0",
  "operation": "evaluate",
  "input_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "result": {"status": "ok", "value": {"decision": "deny", "reason": "unknown action"}}
}
```

Other results are `rejected` with `phase`, `diagnostic` and optional `code`;
`unsupported`; or `error` with `diagnostic`. Unsupported is never a pass. A
crash or transport error is never a correct policy refusal. Protocol/process
failure aborts remaining dispatch; every remaining result slot is explicitly
unattempted. Semantic mismatches allow subsequent cases to run.

| Operation | Input | Successful value |
|---|---|---|
| parse / validate | `policy` raw text | Parsed / validated SDK document; preserve unresolved fields. |
| merge | `base`, `child` raw texts | Resolved merged document. |
| resolve | `policy`, `source`, `documents` text map | Resolved document. |
| evaluate | `policy`, `source`, `documents`, `action` | Decision plus the vector's asserted decision fields. |
| canonicalize | `policy` raw text | `canonical` text and `content_hash`. |

Use only supplied dependency documents, including builtin policy sources. There
is no ambient resolver fallback. Merge/resolve observations retaining `extends`
or `merge_strategy` are rejected. The controller compares corpus expectations,
schema defaults and presence rules, selecting the declared document's 0.x or
1.x schema lineage. It does not compute policy decisions or resolution results.
L4/L5 remain unqualified even when individual canonical observations pass.

## Limits and trust

Default limits are 2 seconds per process, 300 seconds for the engine-dispatch
window, 1 MiB stdout, 256 KiB stderr, 64 MiB aggregate captured output, and
64 MiB aggregate retained request-plus-input bytes. CLI options can raise these
within fixed ceilings: 30 seconds per process, 3600 seconds total dispatch,
16 MiB per output stream, and 256 MiB per aggregate. A request is at most
16 MiB, and at most 10,000 cases are planned, including cases above the requested
level. Serialized expectations and all unattempted result metadata share a
separate, fixed 64 MiB budget across the corpus. Snapshot/publication I/O has byte
caps but is outside the dispatch deadline.

Inputs are bounded snapshots: profile 1 MiB; engine 128 MiB; controller 256 MiB;
materials 16 files/16 MiB total; manifest 8 MiB; corpus 4096 files, 16 MiB per
file and 64 MiB total. Each decoded YAML fixture container has a separate 64 MiB
accounting budget, charging string/key bytes and 64 bytes per value/key before
retention, including expanded aliases. This is not a process RSS limit. Case
count, expectation/metadata and request/input budgets are checked incrementally
during planning. The encoded-data budgets are not process RSS limits.
Symlinks, physical aliases, missing/unlisted corpus files
and digest mismatches are refused. The controller captures its running image
through `/proc/self/exe`; it executes the private captured engine image, not
the original mutable path. JSON nesting is limited to 64.

Only run approved executables on a suitable host. This is **not a sandbox**:
static ELF validation does not prevent a program loading more code, reading
host files, networking, or escaping its process group. Process cleanup and
the scrubbed `LANG=C`, `LC_ALL=C`, `TZ=UTC` environment reduce accidental
interference; they do not contain hostile code. Never offer secrets to an
untrusted engine. Public expectations can be cheated; a passing packet binds
observations to captured executable bytes, not honesty or independent authorship.
