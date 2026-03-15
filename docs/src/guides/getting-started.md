# Getting Started

## Installation

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

```rust
use hushspec::HushSpec;

let yaml = std::fs::read_to_string("policy.yaml")?;
let spec = HushSpec::parse(&yaml)?;

println!("Policy: {}", spec.name.as_deref().unwrap_or_default());
println!("Version: {}", spec.hushspec);
```

### TypeScript

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

```rust
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

```typescript
import { parseOrThrow, validate } from '@hushspec/core';

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
