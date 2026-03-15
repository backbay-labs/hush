<p align="center">
  <img src="assets/hero.png" alt="HushSpec" width="720" />
</p>

<p align="center">
  <strong>Portable, open specification for AI agent security rules</strong>
</p>

<p align="center">
  <a href="https://github.com/backbay-labs/hush/actions"><img src="https://github.com/backbay-labs/hush/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/backbay-labs/hush/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/spec-v0.1.0-orange.svg" alt="Spec Version">
</p>

<p align="center">
  <a href="./spec/hushspec-core.md">Spec</a> &middot;
  <a href="./docs/src/introduction.md">Docs</a> &middot;
  <a href="./rulesets/">Rulesets</a> &middot;
  <a href="./schemas/">JSON Schema</a>
</p>

---

HushSpec defines a declarative format for expressing security rules at the tool boundary of AI agent runtimes. It specifies **what** constraints an agent operates under — forbidden paths, egress domains, tool access, secret detection, and more — without prescribing **how** those rules are enforced. Any compliant engine can consume a HushSpec document and enforce it, making security policies portable across runtimes, frameworks, and languages.

**Status:** v0.1.0 (draft). The spec is under active development; breaking changes may occur before v1.0.

## Quick Example

```yaml
hushspec: "0.1.0"
name: production-agent

rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "/etc/shadow"

  egress:
    allow:
      - "api.openai.com"
      - "*.anthropic.com"
      - "api.github.com"
    default: block

  tool_access:
    block: [shell_exec, run_command]
    require_confirmation: [file_write, git_push]
    default: allow

  secret_patterns:
    patterns:
      - name: aws_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
    skip_paths: ["**/test/**"]

  shell_commands:
    forbidden_patterns:
      - "rm\\s+-rf\\s+/"
      - "curl.*\\|.*bash"
```

## 10 Core Rules

| Rule | Purpose |
|------|---------|
| `forbidden_paths` | Block access to sensitive filesystem paths |
| `path_allowlist` | Allowlist-based read/write/patch access |
| `egress` | Network egress control by domain |
| `secret_patterns` | Detect secrets in file content |
| `patch_integrity` | Validate diff safety (size limits, forbidden patterns) |
| `shell_commands` | Block dangerous shell commands |
| `tool_access` | Control tool/MCP invocations |
| `computer_use` | Control CUA actions |
| `remote_desktop_channels` | Control remote desktop side channels |
| `input_injection` | Control input injection capabilities |

## Extensions

HushSpec supports optional extension modules for advanced features:

| Extension | Purpose |
|-----------|---------|
| **Posture** | Declarative state machine for capabilities and budgets |
| **Origins** | Origin-aware policy projection (Slack, GitHub, email, etc.) |
| **Detection** | Threshold config for prompt injection, jailbreak, threat intel |

```yaml
extensions:
  posture:
    initial: standard
    states:
      standard: { capabilities: [file_access, egress] }
      restricted: { capabilities: [file_access] }
    transitions:
      - { from: "*", to: restricted, on: critical_violation }
  detection:
    prompt_injection:
      block_at_or_above: high
```

## Built-in Rulesets

Ready-to-use policies in [`rulesets/`](./rulesets/):

| Ruleset | Description |
|---------|-------------|
| `default` | Balanced security for AI agent execution |
| `strict` | Maximum security, minimal permissions |
| `permissive` | Development-friendly, relaxed limits |
| `ai-agent` | Optimized for AI coding assistants |
| `cicd` | CI/CD pipeline security |
| `remote-desktop` | Computer use agent sessions |

## Getting Started

### Rust

```toml
[dependencies]
hushspec = { git = "https://github.com/backbay-labs/hush" }
```

```rust
use hushspec::HushSpec;

let spec = HushSpec::parse(yaml_str)?;
let result = hushspec::validate(&spec);
assert!(result.is_valid());
```

### TypeScript

```typescript
import { parseOrThrow, validate } from '@hushspec/core';

const spec = parseOrThrow(yamlString);
const result = validate(spec);
console.log(result.valid); // true
```

### Python

```bash
pip install hushspec  # or from source: pip install ./packages/python
```

```python
from hushspec import parse_or_raise, validate

spec = parse_or_raise(yaml_string)
result = validate(spec)
assert result.is_valid()
```

### Go

```go
import "github.com/backbay-labs/hush/packages/go/hushspec"

spec, err := hushspec.Parse(yamlString)
result := hushspec.Validate(spec)
fmt.Println(result.IsValid())
```

### Using with Clawdstrike

HushSpec documents load natively in [Clawdstrike](https://github.com/backbay-labs/clawdstrike):

```rust
// Auto-detects HushSpec vs Clawdstrike-native format
let policy = clawdstrike::Policy::from_yaml_auto(yaml)?;
```

```bash
# Convert between formats
hush policy migrate policy.yaml --to hushspec
```

## Repo Structure

```
spec/           Normative specification (core + 3 extensions)
schemas/        JSON Schema definitions (draft 2020-12)
crates/         Rust reference crate (hushspec) + testkit CLI
packages/       Language SDKs (TypeScript, Python, Go)
rulesets/       6 built-in security rulesets
fixtures/       31 conformance test fixtures
docs/           mdBook documentation site
```

## Design Principles

- **Fail-closed** — Unknown fields are rejected; invalid documents produce errors, not silent misconfiguration
- **Stateless** — Core rules are pure declarations with no runtime state
- **Engine-neutral** — No detection algorithms, receipt formats, or plugin systems in the spec
- **Extensible** — Optional modules for posture, origins, and detection without bloating the core

## Specification

The normative spec lives in [`spec/`](./spec/). JSON Schema definitions for programmatic validation are in [`schemas/`](./schemas/). Full documentation is in [`docs/`](./docs/src/introduction.md).

## License

Apache-2.0. See [LICENSE](./LICENSE).
