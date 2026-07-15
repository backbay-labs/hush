# Getting Started

## Installation

### CLI

| Method | Command |
|---|---|
| Homebrew (macOS/Linux) | `brew install backbay-labs/tap/h2h` |
| npm | `npm install -g @hushspec/cli` (or `npx @hushspec/cli validate policy.yaml`) |
| Cargo (from source) | `cargo install hushspec-cli` |
| Prebuilt binaries | [GitHub Releases](https://github.com/backbay-labs/hush/releases) — `h2h-<tag>-<target>.tar.gz` + `SHA256SUMS`, provenance-attested |

> Homebrew, npm, and prebuilt binaries become available starting with the first `v0.x` tag built by the release pipeline, once the release pipeline publishes artifacts, the tap formula, and the npm packages. Until then, install via Cargo.

This installs the `h2h` command.

The Rust crate and TypeScript package are not published yet. For now, consume
the reference implementations directly from a local checkout of this repo.

### Rust

Add a path dependency, or point Cargo at the Git repository:

```toml
[dependencies]
hushspec = { path = "../hush/crates/hushspec" }
```

### TypeScript / Node.js

Install the package from a local checkout:

```bash
npm install ../hush/packages/hushspec
```

## Parsing a Document

### Rust

<!-- smoke: guide-rust-parse -->
```rust
use hushspec::HushSpec;

let yaml = std::fs::read_to_string("policy.yaml")?;
let spec = HushSpec::parse(&yaml)?;

println!("Policy: {}", spec.name.as_deref().unwrap_or_default());
println!("Version: {}", spec.hushspec);
```

### TypeScript

<!-- smoke: guide-typescript-parse -->
```typescript
import { readFile } from 'node:fs/promises';
import { parseOrThrow } from '@hushspec/core';

const yaml = await readFile('policy.yaml', 'utf-8');
const spec = parseOrThrow(yaml);

console.log(`Policy: ${spec.name ?? ''}`);
console.log(`Version: ${spec.hushspec}`);
```

## Validating a Document

`parse` / `parseOrThrow` rejects malformed YAML, unknown fields, wrong types,
and other fail-closed schema violations. `validate` adds version checks,
cross-field validation, and warnings.

### Rust

<!-- smoke: guide-rust-validate -->
```rust
use hushspec::HushSpec;

let yaml = std::fs::read_to_string("policy.yaml")?;
let spec = HushSpec::parse(&yaml)?;
let result = hushspec::validate(&spec);

if result.is_valid() {
    println!("Valid");
} else {
    for error in result.errors {
        eprintln!("Rejected: {error}");
    }
}
```

### TypeScript

<!-- smoke: guide-typescript-validate -->
```typescript
import { readFile } from 'node:fs/promises';
import { parseOrThrow, validate } from '@hushspec/core';

const yaml = await readFile('policy.yaml', 'utf-8');
const spec = parseOrThrow(yaml);
const result = validate(spec);

if (result.valid) {
  console.log('Valid');
} else {
  for (const error of result.errors) {
    console.error(`Rejected: ${error.message}`);
  }
}
```

## What Next

- [Write your first policy](first-policy.md)
- [Use HushSpec with Clawdstrike](clawdstrike.md)
- Read the [Rules Reference](../rules-reference.md)
