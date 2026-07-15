# hushspec-testkit

Conformance and differential-testing toolkit for HushSpec implementations.

## Binaries

| Binary | Purpose |
|---|---|
| `hushspec-testkit` | Replay the shared fixture corpus (`--fixtures fixtures`) |
| `hushspec-normalize` | Parse a policy and print normalized JSON (cross-SDK roundtrip check) |
| `hushspec-gen` | Generate a portable differential case bundle (JSON) |
| `hushspec-difftest` | Differential fuzz: run bundles through all four SDK evaluators and fail on divergence |

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
  "generated_by": "hushspec-gen 0.1.1",
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
passes `hushspec::validate` in the Rust reference implementation, so any SDK
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
