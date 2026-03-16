# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HushSpec is a portable, open specification for declaring security rules at the tool boundary of AI agent runtimes. It defines **what** security rules an agent operates under, without prescribing **how** those rules are enforced. The spec is runtime-agnostic and can be consumed by any enforcement engine.

**Design Philosophy:** Fail-closed. Invalid documents must be rejected at parse time; ambiguous rules deny access.

## Repo Structure

```
hush/
├── spec/              # Specification prose (versioned markdown)
├── schemas/           # JSON Schema definitions for HushSpec documents
├── crates/            # Rust reference implementation
│   ├── hushspec/      # Core library: parsing, validation, types
│   ├── hushspec-testkit/  # Test utilities and fixture runners
│   └── hushspec-cli/      # h2h CLI binary
├── packages/          # Language SDKs
│   ├── hushspec/      # TypeScript (@hushspec/core)
│   ├── python/        # Python (hushspec)
│   └── go/            # Go (hushspec)
├── rulesets/          # Example and built-in ruleset YAML files
├── fixtures/          # Test fixtures (valid/invalid documents, edge cases)
└── docs/              # Documentation source (mdBook)
```

## Common Commands

### Rust

```bash
# Build all crates
cargo build --workspace

# Run all tests
cargo test --workspace

# Single crate
cargo test -p hushspec

# Lint and format
cargo fmt --all
cargo clippy --workspace -- -D warnings

# Format check (CI)
cargo fmt --all -- --check
```

### TypeScript

```bash
# Install dependencies
npm install

# Build all packages
npm run build

# Run tests
npm test

# Lint
npm run lint
```

### Python

```bash
# Install with dev dependencies
pip install -e "packages/python[dev]"

# Run tests
pytest packages/python/tests
```

### Go

```bash
# Run tests
cd packages/go && go test ./...

# Vet
cd packages/go && go vet ./...
```

### h2h CLI

```bash
# Validate policy files
h2h validate rulesets/default.yaml

# Lint for best practices
h2h lint rulesets/default.yaml

# Run evaluation test suites
h2h test --fixtures fixtures/core/evaluation

# Scaffold a new policy project
h2h init --preset default

# Compare two policies
h2h diff old.yaml new.yaml

# Format policy files canonically
h2h fmt policy.yaml

# Sign / verify / keygen
h2h keygen
h2h sign policy.yaml --key h2h.key
h2h verify policy.yaml --key h2h.pub
```

### Conformance Testkit

```bash
# Run conformance tests against fixtures
cargo run -p hushspec-testkit -- --fixtures fixtures
```

## Conventions

- **`deny_unknown_fields`** on all serde struct types -- unknown YAML/JSON keys are parse errors
- **Fail-closed** -- malformed input, unknown guard types, and parse failures all result in deny
- **Apache-2.0** license for all source files
- **Conventional Commits** -- `feat(scope):`, `fix(scope):`, `docs:`, `test:`, `refactor:`, `chore:`
- **Clippy** must pass with `-D warnings` (warnings treated as errors)
- **Property testing** with `proptest` for serialization round-trip and schema validation code
- **Edition 2024** for all Rust crates

## Key Files

- `spec/` -- The specification documents (normative)
- `schemas/` -- JSON Schema files for validating HushSpec YAML/JSON documents
- `crates/hushspec/src/lib.rs` -- Rust library entry point
- `crates/hushspec-testkit/src/lib.rs` -- Test kit entry point
- `crates/hushspec-cli/src/main.rs` -- h2h CLI entry point
- `packages/hushspec/src/index.ts` -- TypeScript library entry point
- `packages/python/hushspec/__init__.py` -- Python library entry point
- `packages/go/hushspec/` -- Go library entry point
- `rulesets/` -- Built-in and example ruleset YAML files
- `fixtures/` -- Test fixture files (used by both Rust and TS test suites)
- `Cargo.toml` -- Rust workspace root
- `package.json` -- Node.js workspace root
