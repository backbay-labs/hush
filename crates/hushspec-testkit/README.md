# hushspec-testkit

Conformance and differential-testing toolkit for [HushSpec](https://github.com/backbay-labs/hush),
the portable specification for declaring, enforcing and proving the security
controls an AI agent operates under.

Its conformance runner replays the published corpus against the reference implementation in Rust, scores
the run against the six conformance levels of `spec/hushspec-core.md` section
8, and packages the corpus as a reproducible bundle a third party can download
and run on their own engine.

## Binaries

| Binary | Purpose |
|---|---|
| `hushspec-testkit` | Replay the shared fixture corpus (`--fixtures fixtures`), write a conformance report, and package the conformance bundle |
| `hushspec-gen` | Generate a portable differential case bundle (JSON) |
| `hushspec-difftest` | Differential fuzz: run bundles through all four SDK evaluators and fail on divergence |

## Conformance runs

```bash
# Replay the document corpus (levels 0-3)
hushspec-testkit --fixtures fixtures

# Add the evidence-chain vectors (levels 4 and 5) and write a report
hushspec-testkit --fixtures fixtures --report report.json

```

The report validates against
`schemas/hushspec-conformance-report.v1.schema.json` before it is written: it
names the implementation, pins the corpus by the SHA-256 of
`fixtures/MANIFEST.json`, gives an outcome for each of levels 0-5, and lists
every vector it ran. `highest_level` is the largest N for which levels 0..=N
all pass; a level with any unattempted vector is never a pass.

This runner executes only the reference implementation in Rust. It rejects the
former `--implementation`, `--implementation-version` and
`--implementation-language` metadata overrides: relabeling a reference run
does not test another engine. External engines need a harness that actually
invokes them; an implementation-bound external runner is not yet supplied.
The implementation version, testkit version and corpus manifest digest are
separate identities, even when their version strings happen to match.

Reports also run the JSON case corpora that SDK unit tests consume:
`core/raw-yaml/scalars.json` records parse acceptance at Level 0, decoded
values at Level 1, optional decisions at Level 3, and optional canonical/hash
assertions at Level 4;
`log/schema-vectors.json` records one Level 5 verifier result per entry. A
missing or malformed corpus is a failure, not an empty successful category.

## The conformance bundle

```bash
hushspec-testkit bundle --root . --out hushspec-conformance-1.0.0.tar.gz
```

The archive holds `spec/`, `schemas/`, and `fixtures/` plus a README on
running it against an implementation.
It is reproducible -- sorted entries, fixed modes, zeroed mtimes, no gzip
timestamp -- so the same tree always produces the same bytes and the digest in
a release attestation means something. `release.yml` attaches it to every
release.

`hushspec-gen` and `hushspec-difftest` share one bundle generator, the
`hushspec_testkit::gen` module (written `r#gen` in source, since `gen` is a
reserved keyword). `hushspec-gen` writes a bundle to disk for later replay;
`hushspec-difftest` calls the same generator in-memory per chunk unless
`--bundle` tells it to replay an existing file instead.

## Differential fuzzing

```bash
# Deterministic PR-style run (2,000 cases, all SDKs; build TS first: npm run build)
cargo run --release -p hushspec-testkit --bin hushspec-difftest -- \
  --seed 42 --groups 500 --actions-per-group 4

# Replay a saved bundle (e.g. a CI artifact)
cargo run --release -p hushspec-testkit --bin hushspec-difftest -- \
  --bundle target/difftest/bundle-42.json

# Minimize divergences and emit fixture candidates for review
cargo run --release -p hushspec-testkit --bin hushspec-difftest -- \
  --seed 42 --minimize --emit-fixtures target/difftest/fixture-candidates
```

`crates/hushspec-testkit/Cargo.toml` pins `proptest = "=1.11.0"` exactly
(not `"1.11.0"`). Proptest's RNG-to-value mapping for a given seed is an
implementation detail, not a semver-covered contract, so a routine proptest
upgrade could silently change which policies a `--seed` produces. The exact
pin is what makes `--seed`/`--seed-from-string` reproducible across machines
and over time — reproducing a divergence by seed alone depends on it.

Exit codes: `0` no divergence, `1` divergence found, `2` infrastructure error
(a missing harness is an error, never a skipped SDK).

## Case-bundle format (`hushspec_diff: "0.1.0"`)

```json
{
  "hushspec_diff": "0.1.0",
  "seed": 42,
  "generated_by": "hushspec-gen 1.0.0",
  "groups": [
    {
      "id": "g0001",
      "policy": { "hushspec": "0.1.0", "rules": { } },
      "actions": [ { "id": "a0001", "action": { "type": "tool_call", "target": "x" } } ]
    }
  ]
}
```

Case keys are `"{group_id}/{action_id}"`. Every policy in a generated bundle
passes `hushspec::validate` in the reference implementation, so any SDK
rejecting one is an acceptance divergence. Consumers must reject unknown
bundle fields and unknown `hushspec_diff` versions (fail-closed).

SDK harnesses: `scripts/diffeval_ts.mjs`, `scripts/diffeval_python.py`,
`packages/go/cmd/hushspec-diffeval`. Each prints
`{"sdk": "<name>", "results": {"<case key>": <verdict>}}` where a verdict is
`{"status":"ok","result":{...}}`, `{"status":"rejected","phase":"parse|validate","message":"..."}`,
or `{"status":"error","message":"..."}`.

Divergences found by the nightly workflow are minimized automatically and
uploaded as fixture candidates; after human review they are committed to
`fixtures/core/evaluation/regression-*.test.yaml`, where all four SDK suites
replay them forever.
