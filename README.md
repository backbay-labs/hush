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

HushSpec is an open policy format for AI agent security rules. It defines **what** an agent may do at runtime, including filesystem access, network egress, tool usage, secret detection, and more, without prescribing **how** those controls must be enforced. That separation makes policies portable across runtimes, frameworks, and languages.

**Status:** v0.1.0 (draft). The spec is still evolving, and breaking changes may occur before v1.0.

The Rust crate, TypeScript package, Python package, and Go module are not published to package registries yet. Use them from this repository for now.

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

## SDK Conformance

All four SDKs implement the full HushSpec pipeline, from parse and validate through resolution and evaluation.

| Capability | Rust | TypeScript | Python | Go |
|---|:---:|:---:|:---:|:---:|
| Parse + Validate (Level 1) | Yes | Yes | Yes | Yes |
| Merge (Level 2) | Yes | Yes | Yes | Yes |
| Resolve (Level 2+) | Yes | Yes | Yes | Yes |
| Evaluate (Level 3) | Yes | Yes | Yes | Yes |
| Audit Trail (Level 4) | Yes | Yes | Yes | Yes |
| Detection | Yes | Yes | Yes | Yes |
| Observability | Yes | Yes | Yes | Yes |
| Receipt Sinks | Yes | Yes | Yes | Yes |

## Getting Started

The examples below use the current repo-local install path for each SDK.

### Rust

```toml
[dependencies]
hushspec = { git = "https://github.com/backbay-labs/hush" }
```

<!-- smoke: readme-rust -->
```rust
use hushspec::HushSpec;

let yaml_str = "hushspec: \"0.1.0\"\nname: example\n";
let spec = HushSpec::parse(yaml_str)?;
let result = hushspec::validate(&spec);
assert!(result.is_valid());
```

### TypeScript

```bash
npm install ../hush/packages/hushspec
```

<!-- smoke: readme-typescript -->
```typescript
import { parseOrThrow, validate } from '@hushspec/core';

const yamlString = 'hushspec: "0.1.0"\nname: example\n';
const spec = parseOrThrow(yamlString);
const result = validate(spec);
console.log(result.valid); // true
```

### Python

```bash
pip install ./packages/python
```

<!-- smoke: readme-python -->
```python
from hushspec import parse_or_raise, validate

yaml_string = 'hushspec: "0.1.0"\nname: example\n'
spec = parse_or_raise(yaml_string)
result = validate(spec)
assert result.is_valid
```

### Go

```bash
go get github.com/backbay-labs/hush/packages/go@main
```

<!-- smoke: readme-go -->
```go
import (
    "fmt"

    "github.com/backbay-labs/hush/packages/go/hushspec"
)

yamlString := "hushspec: \"0.1.0\"\nname: example\n"
spec, err := hushspec.Parse(yamlString)
if err != nil {
    panic(err)
}
result := hushspec.Validate(spec)
fmt.Println(result.IsValid())
```

## Evaluation

Each SDK exposes an `evaluate()` function that takes a parsed spec and an action, then returns a decision (`allow`, `warn`, or `deny`) plus matched rule details.

```typescript
import { parseOrThrow, evaluate } from '@hushspec/core';

const spec = parseOrThrow(policyYaml);
const result = evaluate(spec, { type: 'egress', target: 'api.openai.com' });
// result.decision === 'allow' | 'warn' | 'deny'
// result.matched_rule === 'egress'
```

```python
from hushspec import parse_or_raise, evaluate

spec = parse_or_raise(policy_yaml)
result = evaluate(spec, {"type": "egress", "target": "api.openai.com"})
assert result.decision in ("allow", "warn", "deny")
```

## HushGuard Middleware

`HushGuard` wraps policy loading and evaluation behind a simple `evaluate`, `check`, and `enforce` interface for application code.

```typescript
import { HushGuard } from '@hushspec/core';

const guard = HushGuard.fromFile('./policy.yaml');
guard.enforce({ type: 'tool_call', target: 'bash' }); // throws HushSpecDenied if denied
```

```python
from hushspec import HushGuard

guard = HushGuard.from_file("./policy.yaml")
guard.enforce({"type": "tool_call", "target": "bash"})  # raises HushSpecDenied if denied
```

## CLI Tool

The `h2h` CLI covers the common policy workflow: validate, test, lint, diff, format, initialize, sign, verify, and trigger panic mode.

```bash
# Validate a policy against the HushSpec schema
h2h validate policy.yaml

# Run evaluation test suites
h2h test --fixtures ./tests/

# Static analysis and linting
h2h lint policy.yaml

# Compare two policies and show effective decision changes
h2h diff old.yaml new.yaml

# Format policy files canonically
h2h fmt policy.yaml

# Scaffold a new policy project
h2h init --preset default

# Sign a policy with Ed25519
h2h sign policy.yaml --key h2h.key

# Verify a policy signature
h2h verify policy.yaml --key h2h.pub

# Generate a new Ed25519 keypair
h2h keygen

# Emergency override (deny-all kill switch)
h2h panic activate --sentinel /tmp/hushspec.panic
h2h panic deactivate --sentinel /tmp/hushspec.panic
```

Build from source:

```bash
cargo install --path crates/hushspec-cli
```

<details>
<summary>Decision Receipts (Audit Trail)</summary>

`evaluate_audited()` generates structured decision receipts with rule traces, policy summaries, and optional content redaction. Receipts conform to `hushspec-receipt.v0.schema.json` and are designed to support audit-heavy environments such as SOC 2, HIPAA, PCI-DSS, and FedRAMP.

```typescript
import { parseOrThrow, evaluateAudited } from '@hushspec/core';

const spec = parseOrThrow(policyYaml);
const receipt = evaluateAudited(spec, action, {
  enabled: true,
  include_rule_trace: true,
  redact_content: false,
});
// receipt.decision, receipt.rule_evaluations, receipt.policy_summary
```

Receipt sinks (`FileReceiptSink`, `ConsoleReceiptSink`, `FilteredSink`, `MultiSink`, `CallbackSink`) are available in all four SDKs for routing receipts to storage, logging, or OTLP endpoints.

</details>

<details>
<summary>Detection Pipeline</summary>

The detection pipeline plugs prompt injection, jailbreak, and exfiltration checks into the evaluation flow. Regex-based reference detectors ship with all SDKs, and custom detectors can be registered through `DetectorRegistry`.

```typescript
import { parseOrThrow, evaluateWithDetection, DetectorRegistry } from '@hushspec/core';

const registry = DetectorRegistry.withDefaults();
const result = evaluateWithDetection(spec, action, registry, {
  enabled: true,
  prompt_injection_threshold: 0.5,
});
// result.detection_results contains matched patterns and confidence scores
```

</details>

<details>
<summary>Framework Adapters</summary>

Prebuilt adapters translate framework-specific tool calls into HushSpec evaluation actions.

| Framework | Adapter | SDK |
|---|---|---|
| Claude / Anthropic | `mapClaudeToolToAction`, `createSecureToolHandler` | TypeScript |
| OpenAI | `mapOpenAIToolCall`, `createOpenAIGuard` | TypeScript |
| MCP (Model Context Protocol) | `mapMCPToolCall`, `createMCPGuard` | TypeScript |

```typescript
import { HushGuard, mapClaudeToolToAction } from '@hushspec/core';

const guard = HushGuard.fromFile('./policy.yaml');
const action = mapClaudeToolToAction(toolUseBlock);
guard.enforce(action);
```

</details>

<details>
<summary>Observability</summary>

The `EvaluationObserver` interface and `ObservableEvaluator` wrapper emit structured events for every evaluation, policy load, and policy reload. Built-in observers include `JsonLineObserver`, `ConsoleObserver`, and `MetricsCollector`.

```typescript
import { ObservableEvaluator, JsonLineObserver, MetricsCollector } from '@hushspec/core';

const evaluator = new ObservableEvaluator();
evaluator.addObserver(new JsonLineObserver(process.stderr));
evaluator.addObserver(new MetricsCollector());
const result = evaluator.evaluate(spec, action);
```

</details>

<details>
<summary>Policy Signing</summary>

Policies can be signed with Ed25519 keys and verified at load time. The CLI provides `sign`, `verify`, and `keygen` commands. The signature format conforms to `hushspec-signature.v0.schema.json`.

```bash
# Generate a keypair
h2h keygen --output-dir mykeys

# Sign a policy (creates policy.yaml.sig)
h2h sign policy.yaml --key mykeys/h2h.key

# Verify the signature
h2h verify policy.yaml --key mykeys/h2h.pub
```

</details>

<details>
<summary>Emergency Override (Panic Mode)</summary>

Panic mode is a deny-all kill switch that can be activated immediately without redeploying policies. You can trigger it with a sentinel file, the CLI, or an API call. While panic mode is active, every evaluation returns `deny`.

```bash
# Activate panic mode
h2h panic activate --sentinel /tmp/hushspec.panic

# Deactivate
h2h panic deactivate --sentinel /tmp/hushspec.panic
```

```typescript
import { activatePanic, deactivatePanic, isPanicActive } from '@hushspec/core';

activatePanic();
// All evaluate() calls now return deny
deactivatePanic();
```

</details>

<details>
<summary>Policy Loading and Hot Reload</summary>

Policies can be loaded from local files, HTTPS URLs (with ETag caching and SSRF protection), or built-in rulesets. `PolicyWatcher` and `PolicyPoller` support hot reload without restarting the process.

```typescript
import { PolicyWatcher, HushGuard } from '@hushspec/core';

const guard = HushGuard.fromFile('./policy.yaml');
const watcher = new PolicyWatcher('./policy.yaml', {
  onChange: (newSpec) => guard.swapPolicy(newSpec),
});
watcher.start();
```

</details>

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

HushSpec supports optional extension modules for more advanced policy behavior:

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

Ready-to-use policies live in [`rulesets/`](./rulesets/):

| Ruleset | Description |
|---------|-------------|
| `default` | Balanced security for AI agent execution |
| `strict` | Maximum security, minimal permissions |
| `permissive` | Development-friendly, relaxed limits |
| `ai-agent` | Optimized for AI coding assistants |
| `cicd` | CI/CD pipeline security |
| `remote-desktop` | Computer use agent sessions |
| `panic` | Deny-all emergency override |

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

```text
spec/              Normative specification, including core and extension docs
schemas/           JSON Schema definitions
crates/            Rust crates
  hushspec/          Core library: parse, validate, merge, resolve, evaluate, detect, sign
  hushspec-cli/      CLI tool
  hushspec-testkit/  Conformance test runner
packages/          Language SDKs for TypeScript, Python, and Go
rulesets/          Built-in security rulesets
fixtures/          Conformance and evaluation fixtures
docs/              mdBook documentation site
generated/         Generated shared SDK contract artifacts
scripts/           Code generation and CI tooling
```

## Design Principles

- **Fail-closed**: Unknown fields are rejected, and invalid documents fail with explicit errors.
- **Stateless**: Core rules are pure declarations with no runtime state.
- **Engine-neutral**: The spec does not require a specific enforcement engine, detector, or plugin model.
- **Extensible**: Posture, origins, and detection stay optional instead of bloating the core format.

## Specification

The normative spec lives in [`spec/`](./spec/). JSON Schema definitions for programmatic validation are in [`schemas/`](./schemas/). Full documentation is in [`docs/`](./docs/src/introduction.md).

## License

Apache-2.0. See [LICENSE](./LICENSE).
