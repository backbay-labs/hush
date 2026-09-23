# CI Integration

HushSpec ships three ways to wire `h2h` into a development workflow without
hand-rolling the plumbing: a GitHub Action, pre-commit hooks, and a
container image. All three are thin wrappers around the same `h2h` binary
described in the [CLI reference](../reference/cli.md) -- nothing here
changes what a command does, only how it gets invoked.

## GitHub Action

The action at the repository root (`action.yml`, named `HushSpec`) installs
`h2h` and runs one subcommand over a set of files.

```yaml
- uses: backbay-labs/hush@v1.0.0
  with:
    command: validate
    paths: policies/*.yaml
    version: v1.0.0
```

| Input | Default | Meaning |
|---|---|---|
| `command` | `validate` | `validate`, `lint`, `test`, `audit`, or `bundle-verify`. |
| `paths` | *(required)* | Glob pattern(s), one per line or space-separated. A run that matches no files fails closed (exit `2`), it does not silently pass. |
| `version` | `latest` | A release tag (`v1.0.0`), `latest`, or `source` to build `crates/hushspec-cli` from the action's own checkout -- no released binaries required. |
| `fail-on-warnings` | `false` | Adds `--fail-on-warnings` to `h2h lint`. |
| `format` | `text` | Forwarded as `h2h --format`: `text`/`json` everywhere, `sarif` for `lint`, `junit` for `test`. An unsupported combination is rejected by `h2h` itself, not silently downgraded. |
| `report-file` | `hushspec-<command>-report.<ext>` | Where the command's output is written. |
| `keyring` | *(none)* | Forwarded as `--keyring` to `h2h bundle verify`. |

Outputs: `exit-code` (the h2h exit code -- `0`/`1`/`2`/`4`, see the
[exit codes table](../reference/cli.md#exit-codes)) and `report-path` (the
file `report-file` resolved to).

The action downloads the prebuilt `h2h-<tag>-<target>.tar.gz` for the
runner's platform from GitHub Releases, checks it against the release's
`SHA256SUMS`, verifies the build provenance attestation when the runner's
`gh` CLI supports `gh attestation verify`, and caches the extracted binary
by `version` + target so repeat runs skip the download entirely.

Pin `version: v1.0.0` for repeatable release validation. Pin the action itself
to a reviewed commit SHA when your supply-chain policy requires immutable
workflow dependencies. `version: source` builds the action checkout with an
installed Rust toolchain and is useful when testing a source candidate; it is
not the same as qualifying a published binary.

### Validate on every PR

```yaml
name: policy
on: pull_request
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: backbay-labs/hush@v1.0.0
        with:
          command: validate
          paths: policies/**/*.yaml
          version: v1.0.0
```

### Lint with a SARIF upload

`format: sarif` makes `h2h lint`'s findings consumable by GitHub code
scanning:

```yaml
      - uses: backbay-labs/hush@v1.0.0
        id: lint
        with:
          command: lint
          paths: policies/**/*.yaml
          version: v1.0.0
          format: sarif
          fail-on-warnings: "true"
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.lint.outputs.report-path }}
      - if: steps.lint.outputs.exit-code != '0'
        run: exit 1
```

`continue-on-error: true` on the lint step lets the SARIF upload run even
when `h2h lint` finds something; the final step re-fails the job afterward
using the captured `exit-code` output, so findings still reach code
scanning's UI instead of being lost when the job stops at the first
failing step.

### Run policy test suites with JUnit

```yaml
      - uses: backbay-labs/hush@v1.0.0
        with:
          command: test
          paths: fixtures/policy-suite
          version: v1.0.0
          format: junit
          report-file: junit.xml
      - uses: test-summary/action@v2
        if: always()
        with:
          paths: junit.xml
```

## pre-commit hooks

`.pre-commit-hooks.yaml` at the repository root declares four hooks, all
`language: system` -- pre-commit does not install `h2h` for you, so it must
already be on `PATH` (see
[Installation](https://github.com/backbay-labs/hush#installation)).

| Hook id | Command | Fails the commit on |
|---|---|---|
| `hushspec-validate` | `h2h validate` | An invalid document. |
| `hushspec-lint` | `h2h lint` | Lint errors (warnings are reported, not blocking). |
| `hushspec-lint-strict` | `h2h lint --fail-on-warnings` | Lint errors *or* warnings. |
| `hushspec-fmt-check` | `h2h fmt --check` | A document that isn't canonically formatted. |

Each hook's default `files` pattern is
`\.hush(spec)?\.ya?ml$|policy.*\.ya?ml$` with `types: [yaml]` -- it matches
`*.hushspec.yaml`, `.hushspec.yaml`, and any `*policy*.yaml`/`*policy*.yml`
path, and skips everything else. Override `files` per-repo if policies live
under a different naming convention.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/backbay-labs/hush
    rev: v1.0.0
    hooks:
      - id: hushspec-validate
      - id: hushspec-fmt-check
      # or, to also block on lint warnings instead of hushspec-lint:
      # - id: hushspec-lint-strict
```

## Container image

The root `Dockerfile` builds a minimal image whose entrypoint is `h2h`:

```bash
docker build -t h2h .
docker run --rm h2h version
docker run --rm -v "$PWD:/workspace" h2h validate policy.yaml
```

Released images are published to `ghcr.io/backbay-labs/h2h` on every tag,
as `:<tag>` and `:latest`, with build provenance attached
(`docker/build-push-action`'s `provenance: true`):

```bash
docker run --rm --network none -v "$PWD:/workspace:ro" ghcr.io/backbay-labs/h2h:v1.0.0 lint policy.yaml
```

The image runs as a non-root user (`hushspec`, uid `10001`) with
`/workspace` as its working directory, so mount policy files there.
