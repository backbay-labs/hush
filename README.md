# HushSpec

A portable, open specification for AI agent security rules.

## What is HushSpec?

HushSpec defines a declarative format for expressing security rules at the tool boundary of AI agent runtimes. It specifies **what** constraints an agent operates under -- forbidden paths, allowed egress domains, shell command restrictions, secret leak detection, and more -- without prescribing **how** those rules are enforced. Any compliant engine can consume a HushSpec document and enforce it, making security policies portable across runtimes, frameworks, and languages.

## Quick Example

A minimal HushSpec document:

```yaml
hushspec: "0.1.0"
name: production-agent
description: Security rules for a production coding agent

rules:
  forbidden_paths:
    patterns:
      - "/etc/shadow"
      - "/etc/passwd"
      - "~/.ssh/*"

  egress:
    allow:
      - "api.github.com"
      - "registry.npmjs.org"
    default: block

  shell_commands:
    forbidden_patterns:
      - 'rm\\s+-rf\\s+/'
      - 'curl\\s+\\|\\s+sh'
```

## Repo Structure

```
spec/           Specification prose (versioned)
schemas/        JSON Schema definitions
crates/         Rust reference implementation
packages/       TypeScript reference implementation
rulesets/       Example and built-in rulesets
fixtures/       Test fixtures for conformance testing
docs/           Documentation
```

## Getting Started

The Rust crate and TypeScript package are not published yet. Today, the
reference implementations are consumed directly from this repository.

### Rust

```toml
[dependencies]
hushspec = { git = "https://github.com/backbay-labs/hush" }
```

```rust
use hushspec::HushSpec;

let spec = HushSpec::parse(&yaml_str)?;
let result = hushspec::validate(&spec);
assert!(result.is_valid());
```

### TypeScript / JavaScript

```bash
npm install /path/to/hush/packages/hushspec
```

```typescript
import { parseOrThrow, validate } from '@hushspec/core';

const spec = parseOrThrow(yamlString);
const result = validate(spec);
console.log(result.valid); // true
```

## Specification

The full specification lives in the [`spec/`](./spec) directory. JSON Schema definitions for validating HushSpec documents are in [`schemas/`](./schemas).

## License

Apache-2.0. See [LICENSE](./LICENSE) for details.
