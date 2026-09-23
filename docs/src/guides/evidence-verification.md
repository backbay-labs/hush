# Verify evidence before reporting it

Ordinary `h2h report` is exploratory aggregation. Its legacy
`--require-signatures` flag applies to log entries only, not standalone signed
receipt envelopes. Use the experimental strict profile when a report must bind
authenticated inputs, policy identity and named stream boundaries.

Strict verification does not certify compliance. It authenticates supplied
records under operator-selected trust inputs. It cannot prove that a runtime
intercepted every attempted action, that a signer reported truthfully, or that
a control objective was satisfied.

## A runnable signed example

From the repository root, build the CLI and use the committed synthetic monitor
fixture. Its key is public test material, never a production trust root. The
fixed verifier clock is part of this reproducible example, not a way to bypass
expiry in production.

```bash
cargo build -p hushspec-cli --locked
packet_dir=$(mktemp -d)
target/debug/h2h report fixtures/assurance/monitor/evidence.jsonl \
  --format json --evidence-profile fixtures/assurance/monitor/profile.json \
  --keyring fixtures/signing/keys/keyring.json --now 2026-09-15T12:00:00Z \
  --out "$packet_dir/report.json" --verification-out "$packet_dir/verification.json"
python3 - "$packet_dir" <<'PY'
import hashlib, json, pathlib, sys
packet = pathlib.Path(sys.argv[1])
report_bytes = (packet / "report.json").read_bytes()
verification = json.loads((packet / "verification.json").read_bytes())
assert verification["report_sha256"] == "sha256:" + hashlib.sha256(report_bytes).hexdigest()
assert verification["streams"][0]["authenticity"]["status"] == "verified"
assert verification["streams"][0]["completeness"]["status"] == "not-established"
report = json.loads(report_bytes)
assert report["totals"]["by_decision"]["warn"] == 1
assert report["totals"]["by_outcome"]["would_block"] == 1
print("Matching report bytes; authenticated input; completeness not established.")
PY
```

The `documented_monitor_example_is_current_and_runnable` CLI regression checks
these committed inputs against a real audited evaluation and signature before
executing the report command. Fixture maintenance is explicit:
`HUSHSPEC_UPDATE_MONITOR_EXAMPLE=1 cargo test -p hushspec-cli --test oscal_tests documented_monitor_example_is_current_and_runnable`, followed by fixture-manifest
regeneration and a normal run without that environment variable.

Checking this unsigned sidecar's digest is necessary but insufficient: an
attacker could replace both files. Recipients must reverify the source evidence
using their own trusted profile/key inputs, or trust an independently
authenticated packet producer.

## Profile, trust and scope

The separately versioned `0.1.0` experimental profile declares:

- Run identifier and inclusive UTC-millisecond window.
- Expected canonical policy hashes and optional already-resolved local policy
  artifacts, byte digests and detached signatures.
- Named streams, each with one record class (`signed-receipts` or `signed-log`),
  ordered files and exact byte digests, authorized signer IDs and policy hashes.
- Whether independent policy-origin signatures and a boundary inventory are
  required; an optional inventory is still checked when supplied.

Paths are relative to the profile directory and must remain beneath it. No
URL fetching or `extends` resolution occurs. Positional files must match the
profile's flattened stream/file order. A valid signature from another key in a
large keyring does not grant permission to sign this stream.

All records are authenticated before window filtering. Duplicate JSON members,
receipt IDs and physical input aliases fail. A bad record outside the window
still fails. Strict mode refuses `--lenient`, `--unverified`, `--by`, negative
clock skew, stdout output and conflicting explicit window bounds. `--policy`
can only select an already-declared local policy artifact.

For signed logs, continuity includes ordered rotations and signed policy-event
transitions. Independent streams retain separate heads. Standalone receipts
establish signed policy-hash association, not transition history. A mid-stream
start needs matching inventory-provided initial policy state before receipts;
the verifier does not guess which policy was in force.

Policy origin is separate from receipt authentication. Without a verified
detached policy signature, origin remains `not-established`. The native report's
`signatures` member retains runtime-reported policy-signature status; the
sidecar's `signatures_verified` counts signatures actually checked now. Multiple
policies have separate interval control summaries, not one blended native
`controls` object.

## Completeness requires an independent expectation

No inventory means `completeness.status: "not-established"`, even for a valid
signed chain. Retain stream identities, ordered file digests and expected log
endpoints through an independently trusted collection/checkpoint process. Put
those expectations in the inventory and set `boundary_inventory: true` when they
are mandatory. The verifier compares the exact run, window, streams, files,
starting predecessor and ending sequence/hash. The inventory's `acquired_from`
is an operator trust assertion, recorded as such; producer signatures do not
make collection independent.

Matching inventory verifies only that declared scope. It does not establish
all attempted actions, reliable interception, signer honesty or durable dispatch
authorization. Zero window receipts means no observations in that window, never
automatic satisfaction.

## Tampering fails before publication

Continue with the temporary directory above. This changes bytes without
changing the trusted profile, so expect exit 1 with `InputDigestMismatch` and
neither requested output file:

```bash
mkdir "$packet_dir/tampered"
cp fixtures/assurance/monitor/* "$packet_dir/tampered/"
printf '\n' >> "$packet_dir/tampered/evidence.jsonl"
target/debug/h2h report "$packet_dir/tampered/evidence.jsonl" \
  --format json --evidence-profile "$packet_dir/tampered/profile.json" \
  --keyring fixtures/signing/keys/keyring.json --now 2026-09-15T12:00:00Z \
  --out "$packet_dir/rejected-report.json" \
  --verification-out "$packet_dir/rejected-verification.json"
```

Updating that digest to match altered receipt content does not repair a broken
signature. The signature-verification regression separately tests that case.

## Experimental OSCAL: observations, not findings

The exporter pins unmodified [NIST OSCAL 1.1.2 release schemas](https://github.com/usnistgov/OSCAL/releases/tag/v1.1.2),
with full license and byte hashes in the CLI crate. It validates both schema
shape and local references. An assessment-context manifest binds an AP, its
exact SSP and an already-resolved catalog. Supported scope is one explicit
nonempty control selection and explicit component subjects present in the SSP.
SSP implemented control IDs must exist in the catalog and cannot repeat;
AP-selected controls need not already be implemented. Structured `links` anywhere
in copied reviewed controls or subjects are unsupported: AP-local resources are
not copied into results. Remote import references, fragments, encoded import
references, profile resolution, include-all, exclusions, objective selections
and unknown IDs are refused.

This example uses the clearly labelled synthetic context, not a real customer
assessment plan:

```bash
cp -R fixtures/assurance/oscal "$packet_dir/context"
target/debug/h2h report fixtures/assurance/monitor/evidence.jsonl \
  --format oscal --experimental-oscal \
  --evidence-profile fixtures/assurance/monitor/profile.json \
  --keyring fixtures/signing/keys/keyring.json --now 2026-09-15T12:00:00Z \
  --assessment-context "$packet_dir/context/context.json" \
  --native-report-out "$packet_dir/oscal-report.json" \
  --out "$packet_dir/assessment-results.json" \
  --verification-out "$packet_dir/oscal-verification.json"
```

The observation says `warn=1` and `would_block=1`, with method `EXAMINE`: a
monitoring decision was recorded, not blocked execution. It includes verified
interval identity, source digests and qualifications. It emits no findings,
risks or objective status. AP scope and subjects are copied from validated
context, never inferred from a framework label. Native report and sidecar are
back-matter resources with exact byte digests; AP references resolve relative
to the output directory. Resource basenames must use URI-unreserved ASCII.

This intentionally replaces the earlier experimental skeleton exporter. Old
commands without assessment context fail; `--unverified` is not an OSCAL
fallback.

## Limits, outputs and failures

Default limits are 16 MiB per file, 64 MiB total and 1 MiB per JSONL line.
`--max-evidence-file-bytes`, `--max-evidence-total-bytes` and
`--max-evidence-line-bytes` are positive strict-only overrides. Require
line <= file <= total; file/total cannot exceed 1 GiB and line cannot exceed
16 MiB. One shared budget includes profile, keys, evidence, policies, inventory
and assessment context. Fixed caps are 64 streams, 1,024 artifacts, 1,000,000
records and JSON depth 64. Limits fail rather than truncate.

Every output must be a distinct new file in the same existing,
operator-controlled directory. Nothing is overwritten, and inputs cannot be
output targets. Complete validated bytes are privately staged and synced;
native JSON and optional OSCAL are published before the completion sidecar.
A recoverable failure cleans up this attempt's newly created data files.
Crashes can leave partial files without a sidecar. Filesystems differ in
durability; this is not a portable multi-file atomic transaction. Do not run it
in an attacker-controlled output directory.

Exit 0 means publication completed. Exit 1 covers digest, signature, signer
authorization, duplicate receipt, chain, policy and required-boundary failures.
Exit 2 covers configuration, malformed input, limits, I/O, context validation
and output conflicts. Diagnostics identify the code, artifact and, where
applicable, line without printing raw evidence.
