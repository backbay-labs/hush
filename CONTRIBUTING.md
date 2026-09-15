# Contributing to HushSpec

Thanks for your interest in contributing. HushSpec is a portable, open specification for
declaring security rules at the tool boundary of AI agent runtimes, with reference
implementations in Rust, TypeScript, Python, and Go plus the `h2h` CLI. See
[`GOVERNANCE.md`](./GOVERNANCE.md) for how spec changes are proposed and ratified, and
[`docs/plans/`](./docs/plans/) for the RFCs that describe planned and in-progress work.

## The One Rule: No SDK Behavior Change Without a Fixture

This is the most important convention in the repository. If you change how any SDK
parses, validates, merges, resolves, or evaluates a policy, you must add or update a
test fixture under `fixtures/` (evaluator behavior belongs under
`fixtures/core/evaluation/`) that demonstrates the expected input and output. Fixtures
are shared across all four SDKs and are what `hushspec-testkit` and the differential
fuzzer (`hushspec-difftest`) run against. A behavior change without a fixture cannot be
verified as consistent across languages and will not be merged. See
[`GOVERNANCE.md`](./GOVERNANCE.md) for the full spec-first / fixture-first process.

## Build and Test Commands

### Rust

```bash
cargo build --workspace          # build all crates
cargo test --workspace           # run all tests
cargo test -p hushspec           # single crate
cargo fmt --all                  # format
cargo fmt --all -- --check       # format check (CI)
cargo clippy --workspace -- -D warnings   # lint (warnings are errors)
```

### TypeScript

```bash
npm install     # install dependencies
npm run build   # build all packages
npm test        # run tests
npm run lint    # lint
```

### Python

```bash
pip install -e "packages/python[dev]"   # install with dev dependencies
pytest packages/python/tests            # run tests
```

### Go

```bash
cd packages/go && go test ./...   # run tests
cd packages/go && go vet ./...    # vet
```

### `h2h` CLI

```bash
h2h validate rulesets/default.yaml
h2h lint rulesets/default.yaml
h2h test --fixtures fixtures/core/evaluation
h2h eval rulesets/default.yaml --type egress --target api.example.com
h2h explain rulesets/default.yaml --type egress --target api.example.com
h2h init --preset default
h2h diff old.yaml new.yaml
h2h fmt policy.yaml
h2h keygen
h2h sign policy.yaml --key h2h.key
h2h verify policy.yaml --key h2h.pub
```

### Conformance, Fuzzing, and Benchmarks

```bash
# Conformance tests against fixtures
cargo run -p hushspec-testkit -- --fixtures fixtures

# Generate a portable differential case bundle
cargo run -p hushspec-testkit --bin hushspec-gen -- --seed 42 --groups 50 --out bundle.json

# Differential fuzz across all four SDKs (requires npm run build + pip install first)
cargo run --release -p hushspec-testkit --bin hushspec-difftest -- --seed 42 --groups 250

# Criterion benchmarks
cargo bench -p hushspec --bench evaluation

# Receipt-overhead CI gate (release mode only)
cargo test -p hushspec --release --test bench_thresholds -- --ignored --nocapture
```

Before opening a pull request that touches more than one language, run `npm run build`
and `pip install -e "packages/python[dev]"` first so the shared-fixture and roundtrip
tests can exercise the built packages, matching what `.github/workflows/ci.yml` does.

## Conventions

- **`deny_unknown_fields`** on every serde struct (and the equivalent strict-parsing
  behavior in TypeScript/Python/Go): unknown YAML/JSON keys must be a parse error, not a
  silently ignored field.
- **Fail-closed.** Malformed input, unknown guard/action/condition types, parse
  failures, and unresolvable references must all evaluate to `deny`, never `allow`. If
  you are unsure whether a new code path should allow or deny on error, it should deny.
- **Apache-2.0.** The repository is licensed under Apache-2.0 (see
  [`LICENSE`](./LICENSE)); contributions are accepted under the same license.
- **Conventional Commits.** Use `feat(scope):`, `fix(scope):`, `docs:`, `test:`,
  `refactor:`, `chore:` for commit messages (see the existing `git log` for examples).
- **Clippy.** `cargo clippy --workspace -- -D warnings` must pass; warnings are treated
  as errors.
- **Property testing.** Use `proptest` for serialization round-trip and schema
  validation code in Rust.
- **Edition 2024** for all Rust crates.
- **Cross-language parity.** Rust is the oracle: when porting a behavior to
  TypeScript, Python, or Go, match the Rust reference implementation's semantics exactly,
  including its known quirks, unless an RFC has ratified a change to the normative spec
  (in which case update the fixture and all four SDKs together -- see "The One Rule"
  above).

## Adding a Library Policy

The vertical policy library in [`library/`](./library/) holds curated,
compliance-mapped starting-point policies (see [`library/README.md`](./library/README.md)
for the full list and directory layout). To add a new one:

1. **Valid HushSpec.** The policy MUST parse and validate:
   `cargo run -p hushspec-cli -- validate <your-file>` (or `h2h validate <your-file>`).
2. **Comment headers.** Include a comment block at the top of the file naming the
   compliance framework and specific control mappings it targets, plus a disclaimer that
   it is a starting point, not a certification.
3. **Inline comments.** Map each rule block to specific compliance controls using YAML
   comments.
4. **Extends a base.** Use `extends: "builtin:default"` or `extends: "builtin:strict"`
   unless the policy needs to stand alone.
5. **Realistic patterns.** Use practical, tested regexes; avoid placeholders or
   overly broad patterns that would cause excessive false positives (and remember the
   regex profile is RE2-class -- no lookaround/backreferences).
6. **Focused scope.** One policy should address one compliance framework or deployment
   scenario, not try to cover everything.
7. **Test.** Run the validator before submitting. Note that library policies do not yet
   have per-policy evaluation test suites in `fixtures/library/` -- adding those is
   tracked as RFC 09 package P3-03; contributions toward that are welcome.

## Reporting Bugs and Security Issues

Open a GitHub issue for ordinary bugs. For anything that could cause a policy to
**fail open** (an action allowed when it should be denied or warned) or any other
security-relevant issue, follow [`SECURITY.md`](./SECURITY.md) instead of opening a
public issue.

## Pull Requests

- Keep pull requests focused; a spec/prose change, its fixture, and its SDK ports can be
  one PR, but unrelated changes should be separate PRs.
- Make sure CI is green: `.github/workflows/ci.yml` runs generated-sources checks,
  per-language builds/tests, shared fixtures across all four SDKs, smoke snippets, the
  cross-SDK roundtrip check, differential fuzzing, bench thresholds, and the docs build.
- Do not check a roadmap item off in `docs/plans/ROADMAP.md` (or claim something works in
  "all SDKs") unless the same PR ships the code and its fixture/test for every SDK named.
