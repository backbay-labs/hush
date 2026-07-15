# hushspec-cli (h2h)

*hush to hush* -- because your agent's permissions shouldn't be shouted about.

`h2h` is the command-line tool for working with [HushSpec](https://github.com/backbay-labs/hush) policy documents. It covers the full policy lifecycle: validate, lint, test, diff, format, scaffold, sign, and emergency override.

## Installation

| Method | Command |
|---|---|
| Homebrew (macOS/Linux) | `brew install backbay-labs/tap/h2h` |
| npm | `npm install -g @hushspec/cli` (or `npx @hushspec/cli validate policy.yaml`) |
| Cargo (from source) | `cargo install hushspec-cli` |
| Prebuilt binaries | [GitHub Releases](https://github.com/backbay-labs/hush/releases) — `h2h-<tag>-<target>.tar.gz` + `SHA256SUMS`, provenance-attested |

> Homebrew, npm, and prebuilt binaries become available starting with the first `v0.x` tag built by the release pipeline, once the release pipeline publishes artifacts, the tap formula, and the npm packages. Until then, install via Cargo.

All methods install the `h2h` binary.

## Commands

```bash
# Validate a policy against the HushSpec schema
h2h validate policy.yaml

# Static analysis and linting
h2h lint policy.yaml
h2h lint --fail-on-warnings policy.yaml

# Lint and auto-fix decision-neutral issues
h2h lint policy.yaml --fix
h2h lint policy.yaml --dry-run   # preview fixes without writing

# Run evaluation test suites
h2h test policy.test.yaml
h2h test --fixtures ./tests/

# Evaluate one action and trace the decision
h2h eval policy.yaml --type egress --target api.example.com
h2h eval policy.yaml --type tool_call --target deploy --explain
h2h explain policy.yaml --type file_write --target /app/.env
h2h eval builtin:ai-agent --action-json '{"type": "shell_command", "target": "rm -rf /"}'

# Compare two policies and show decision changes
h2h diff old.yaml new.yaml

# Format policy files canonically
h2h fmt policy.yaml
h2h fmt --check policy.yaml    # CI mode (exit 1 if unformatted)
h2h fmt --diff policy.yaml     # Show what would change

# Scaffold a new policy project
h2h init --preset default      # also: strict, permissive
h2h init --preset strict --dir ./my-project

# Policy signing (Ed25519)
h2h keygen                     # creates h2h.key + h2h.pub
h2h sign policy.yaml --key h2h.key
h2h verify policy.yaml --key h2h.pub

# Display governance metadata and run advisory checks
h2h audit policy.yaml

# Emergency deny-all kill switch
h2h panic activate --sentinel /tmp/hushspec.panic
h2h panic deactivate --sentinel /tmp/hushspec.panic
h2h panic status --sentinel /tmp/hushspec.panic
```

## Output Formats

Most commands support `--format text` (default), `--format json`, and where applicable `--format tap` for CI integration.

```bash
h2h validate --format json policy.yaml
h2h lint --format json policy.yaml
h2h test --format tap tests/
h2h diff --format json old.yaml new.yaml
```

`h2h eval` and `h2h explain` map the decision to the exit code — `0` allow,
`1` deny, `4` warn, `2` input/usage error — and additionally support
`--format receipt`, which emits a full `hushspec-receipt.v0` document.
`--format json` emits a deterministic report (no receipt id, timestamp, or
duration) whose fields are stable-additive across releases.

## Getting Started

```bash
# Scaffold a project, validate, and run tests in one go
h2h init --preset default --dir my-agent
h2h validate my-agent/.hushspec/policy.yaml
h2h test --fixtures my-agent/.hushspec/tests
```

## Library

The `h2h` CLI is built on the [`hushspec`](https://crates.io/crates/hushspec) Rust library. If you need programmatic access to parsing, validation, or evaluation, use that crate directly.

## License

Apache-2.0
