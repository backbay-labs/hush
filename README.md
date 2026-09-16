<p align="center">
  <img src="assets/hero.png" alt="HushSpec" width="720" />
</p>

<p align="center">
  <strong>Agentic compliance as code: a portable, open specification for declaring, enforcing, and proving the security controls an AI agent operates under.</strong>
</p>

<p align="center">
  <a href="https://github.com/backbay-labs/hush/actions"><img src="https://github.com/backbay-labs/hush/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/backbay-labs/hush/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/spec-v1.0.0-brightgreen.svg" alt="Spec Version">
  <a href="https://crates.io/crates/hushspec"><img src="https://img.shields.io/crates/v/hushspec.svg" alt="crates.io"></a>
  <a href="https://www.npmjs.com/package/@hushspec/core"><img src="https://img.shields.io/npm/v/@hushspec/core.svg" alt="npm"></a>
  <a href="https://pypi.org/project/hushspec/"><img src="https://img.shields.io/pypi/v/hushspec.svg" alt="PyPI"></a>
</p>

<p align="center">
  <a href="./spec/hushspec-core.md">Spec</a> &middot;
  <a href="./docs/src/introduction.md">Docs</a> &middot;
  <a href="./rulesets/">Rulesets</a> &middot;
  <a href="./schemas/">JSON Schema</a>
</p>

---

HushSpec is agentic compliance as code: a portable, open specification for declaring, enforcing, and proving the security controls an AI agent operates under — filesystem access, network egress, tool usage, secret detection, and more. It defines **what** an agent may do at runtime without prescribing **how** those controls must be enforced, and it pairs each policy with structured decision receipts so enforcement can become evidence. That separation, plus fail-closed defaults, makes policies portable across runtimes, frameworks, and languages — and auditable wherever they run.

**Spec 1.0.0 (stable).** The core spec, all four SDKs (Rust, TypeScript, Python, Go), and the `h2h` CLI are published at 1.0.0. Parse, validate, merge, resolve, evaluate, detect, sign, audit and attest your way through 12 rule blocks and 3 extension modules, across 22 CLI subcommands. All four SDKs reach [Level 5 (Attested)](./docs/src/reference/sdk-conformance.md) against the published vector corpus. The document format, evaluation semantics, canonical form, and wire formats are frozen for the 1.x series ([versioning policy](./spec/versioning.md)).

## Quick Example

```yaml
hushspec: "1.0.0"
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

## SDK Parity

The six conformance levels are normative in
[`spec/hushspec-core.md`](./spec/hushspec-core.md) section 8. Which level each
SDK reaches, and the test file that runs each vector family, is in the
[SDK Conformance Matrix](./docs/src/reference/sdk-conformance.md). The exact
entry-point name each SDK publishes for each capability below is in the
[SDK API Contract](./docs/src/reference/sdk-api.md).

| Capability | Rust | TypeScript | Python | Go |
|---|:---:|:---:|:---:|:---:|
| **Conformance level** | **5** | **5** | **5** | **5** |
| Parse + validate, registry error codes (L1) | Yes | Yes | Yes | Yes |
| Merge + resolve `extends` (L2) | Yes | Yes | Yes | Yes |
| Evaluate: 12 rule blocks, 3 extensions (L3) | Yes | Yes | Yes | Yes |
| Compiled policies (`CompiledPolicy`) | Yes | Yes | Yes | Yes |
| `when` conditions, incl. `capability` and `rate` | Yes | Yes | Yes | Yes |
| Detection, incl. `heuristic_injection@1` | Yes | Yes | Yes | Yes |
| Canonical form + `content_hash` (RFC 8785) | Yes | Yes | Yes | Yes |
| Decision receipts 0.2 + receipt hash (L4) | Yes | Yes | Yes | Yes |
| Verify-on-load + `#sha256:` digest pins | Yes | Yes | Yes | Yes |
| Hash-linked log: chained sink + verify (L5) | Yes | Yes | Yes | Yes |
| Policy signing, keyrings, receipt signing | Partial<br>`signing` feature | Yes | Partial<br>`signing` extra | Yes |
| Bundle **verification** (L5) | Partial<br>`signing` feature | Yes | Partial<br>`signing` extra | Yes |
| Bundle **creation** | Yes | No | No | No |
| Enforcement point (`HushGuard`) | Yes | Yes | Yes | Partial<br>spelled `Guard` |
| Enforcement modes, refused state, policy events | Yes | Yes | Yes | Yes |
| Observers + Prometheus metrics | Yes | Yes | Yes | Yes |
| Receipt sinks (file, stderr, filtered, multi, callback, null) | Yes | Yes | Yes | Yes |
| OTLP receipt sink | Partial<br>`otlp` feature | Yes | Yes | Yes |
| Providers + hot reload (watch/poll) | Yes | Yes | Yes | Yes |
| HTTPS policy loading (ETag, SSRF-hardened) | Partial<br>`http` feature | Yes | No | No |
| Framework adapters | No | Yes<br>5 frameworks | Yes<br>5 frameworks | Yes<br>3 frameworks |
| Panic mode (kill switch) | Yes | Yes | Yes | Yes |

Every "No" is deliberate, and here is why:

- **Bundle creation** lives in Rust and `h2h bundle create`. Producing an
  attestation is a build-time act; verifying one is what a relying party depends
  on, and all four SDKs verify against all 8 bundle vectors.
- **Rust ships no framework adapters**, because that is not where agent
  frameworks live. The worked example
  `cargo run --example guarded_agent --features otlp` wires a policy through a
  guard, a chained sink and an OTLP sink instead.
- **Python and Go ship no HTTP client**, so they reject an `https:` `extends`
  reference outright rather than resolving it unverified. Pass your own loader,
  or resolve ahead of time and hand them the `Resolution`.

For the same resolved policy, all four produce the same decision, the same
canonical bytes, the same `content_hash`, and — under the fixed inputs of
`fixtures/receipts/expected/README.md` — byte-identical receipts after RFC 8785.
That is checked per commit by `hushspec-difftest` over 500 generated policy
groups, comparing every port against the Rust oracle on decision, rule trace,
`content_hash` and receipt hash.

## Installation

### CLI

| Method | Command |
|---|---|
| Homebrew (macOS/Linux) | `brew install backbay-labs/tap/h2h` |
| npm | `npm install -g @hushspec/cli` (or `npx @hushspec/cli validate policy.yaml`) |
| Cargo (from source) | `cargo install hushspec-cli` |
| Prebuilt binaries | [GitHub Releases](https://github.com/backbay-labs/hush/releases) — `h2h-<tag>-<target>.tar.gz` + `SHA256SUMS`, provenance-attested |

> Homebrew, npm, and prebuilt binaries become available once the release pipeline has run for the `v1.0.0` tag and published the artifacts, the tap formula, and the npm packages. Until then, install via Cargo.

All methods install the `h2h` command. See [CLI Tool](#cli-tool) below.

### GitHub Action

```yaml
- uses: backbay-labs/hush@v1.0.0
  with:
    command: validate       # validate | lint | test | audit | bundle-verify
    paths: policies/**/*.yaml
```

The composite action at [`action.yml`](./action.yml) downloads the matching
`h2h-<tag>-<target>.tar.gz` release, verifies it against `SHA256SUMS` and the
build provenance attestation, caches it, and runs the command -- no separate
install step. Before the first tagged release ships binaries, pass
`version: source` to build `crates/hushspec-cli` instead. See
[CI Integration](docs/src/guides/ci.md) for validate-on-PR, SARIF-uploading
lint, and JUnit test runs, plus the accompanying `.pre-commit-hooks.yaml` and
the `Dockerfile`/`ghcr.io/backbay-labs/h2h` container image.

### Rust

```toml
[dependencies]
hushspec = "1.0"
```

### TypeScript

```bash
npm install @hushspec/core
```

### Python

```bash
pip install hushspec
```

### Go

```bash
go get github.com/backbay-labs/hush/packages/go@v1.0.0
```

The SDK is a nested module, so Go resolves that version from the
`packages/go/v1.0.0` tag rather than from a plain `v1.0.0` at the repository
root ([packaging notes](./packages/go/README.md#versioning-and-tags)).

## Getting Started

### Rust

<!-- smoke: readme-rust -->
```rust
use hushspec::HushSpec;

let yaml_str = "hushspec: \"1.0.0\"\nname: example\n";
let spec = HushSpec::parse(yaml_str)?;
let result = hushspec::validate(&spec);
assert!(result.is_valid());
```

### TypeScript

<!-- smoke: readme-typescript -->
```typescript
import { parseOrThrow, validate } from '@hushspec/core';

const yamlString = 'hushspec: "1.0.0"\nname: example\n';
const spec = parseOrThrow(yamlString);
const result = validate(spec);
console.log(result.valid); // true
```

### Python

<!-- smoke: readme-python -->
```python
from hushspec import parse_or_raise, validate

yaml_string = 'hushspec: "1.0.0"\nname: example\n'
spec = parse_or_raise(yaml_string)
result = validate(spec)
assert result.is_valid
```

### Go

<!-- smoke: readme-go -->
```go
import (
    "fmt"

    "github.com/backbay-labs/hush/packages/go/hushspec"
)

yamlString := "hushspec: \"1.0.0\"\nname: example\n"
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

`HushGuard` wraps policy loading and evaluation behind a simple `evaluate`, `check`, and
`enforce` interface for application code, and carries the enforcement mode, the warn
confirmation channel, the receipt sink, the observers and the acting actor. Available in all
four SDKs — Go spells the type `Guard`, since `hushspec.HushGuard` would stutter.

A policy that fails verification under `require_signature` does not fail construction: it
builds a guard that denies **every** action with `__hushspec_policy_unverified__` and emits an
unverified-policy receipt, so there is no path where a caller falls back to no policy at all.

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

```rust
use hushspec::HushGuard;

let guard = HushGuard::from_path("./policy.yaml")?;
guard.enforce(&action)?; // Err(Denied) if denied
```

```go
guard, err := hushspec.NewGuardFromFile("./policy.yaml", hushspec.GuardOptions{})
decision, err := guard.Check(ctx, &hushspec.EvaluationAction{Type: "tool_call", Target: "bash"})
if !decision.Allowed() { /* blocked, and the receipt says why */ }
```

## CLI Tool

The `h2h` CLI has 22 subcommands covering the whole policy lifecycle: `validate`, `resolve`,
`hash`, `lint`, `fmt`, `diff`, `eval`, `explain`, `test`, `audit`, `init`, `schema`, `sign`,
`verify`, `keygen`, `bundle`, `log`, `receipts`, `report`, `panic`, `completions` and
`version`.

```bash
# Validate a policy against the HushSpec schema
h2h validate policy.yaml

# Run evaluation test suites
h2h test --fixtures ./tests/

# Evaluate one action and explain the decision
h2h eval policy.yaml --type egress --target api.example.com
h2h explain policy.yaml --type egress --target api.example.com

# Static analysis and linting
h2h lint policy.yaml

# Lint and auto-fix decision-neutral issues
h2h lint policy.yaml --fix

# Compare two policies and show effective decision changes
h2h diff old.yaml new.yaml

# Fail CI when a change can turn a deny into an allow or warn
h2h diff main.yaml pr.yaml --fail-on relaxed

# Print a policy with its extends chain resolved and merged
h2h resolve policy.yaml

# Format policy files canonically
h2h fmt policy.yaml

# validate, lint and fmt also read stdin
cat policy.yaml | h2h validate -

# Print a published JSON Schema (embedded in the binary)
h2h schema core
h2h schema --list

# Scaffold a new policy project
h2h init --preset default

# Generate a new Ed25519 keypair (writes h2h.key.pem / h2h.pub.pem)
h2h keygen

# Sign a policy with Ed25519 (signs the resolved policy's content hash)
h2h sign policy.yaml --key h2h.key.pem --expires-in 90d

# Verify a policy signature, against a key or a trusted keyring
h2h verify policy.yaml --key h2h.pub.pem
h2h verify policy.yaml --keyring keyring.json --last-seen-version 4

# Print the canonical content hash -- the portable identity of a policy
h2h hash policy.yaml

# Governance audit (separation of duties, review dates, control coverage)
h2h audit policy.yaml --controls --strict

# Create and verify a policy bundle (DSSE over an in-toto statement)
h2h bundle create policy.yaml --key h2h.key.pem
h2h bundle verify policy.bundle.json --keyring keyring.json

# Verify a hash-linked receipt log and a set of signed receipts
h2h log verify receipts-*.jsonl
h2h receipts verify signed-receipts.jsonl --keyring keyring.json

# Compliance evidence over a window of receipts
h2h report receipts.jsonl --policy policy.yaml --format json

# Emergency override (deny-all kill switch)
h2h panic activate --sentinel /tmp/hushspec.panic
h2h panic deactivate --sentinel /tmp/hushspec.panic

# Shell completions and build/spec provenance
h2h completions zsh > "${fpath[1]}/_h2h"
h2h version --format json
```

Every subcommand supports `--format json`, and exit codes are uniform: `0`
success, `1` policy failure, `2` input or usage failure (`4` for a `warn`
decision from `eval`/`explain`). Full flag and exit-code tables live in the
[CLI reference](docs/src/reference/cli.md).

See [Installation](#installation) above for install options — Homebrew, npm, Cargo, or prebuilt binaries.

<details>
<summary>Decision Receipts (Audit Trail)</summary>

`evaluate_audited()` takes a **`Resolution`** and generates format 0.2 decision receipts: the
resolved policy's canonical content hash, its `extends` chain with each hop's signature
outcome, the actor, the **recorded** rule and detection traces, and the enforcement
disposition. Content is never carried -- only its `sha256:` hash and byte size -- so a receipt
log is safe to hand to an auditor. Receipts conform to `hushspec-receipt.v1.schema.json` and
are designed to support audit-heavy environments such as SOC 2, HIPAA, PCI-DSS, and FedRAMP.

Receipts chain: `ChainedFileSink` writes a hash-linked JSONL log that `h2h log verify` checks,
naming the exact line where the chain first breaks. `sign_receipt` / `verify_receipt` sign the
receipt hash. All four SDKs write and verify both.

```typescript
import { parseOrThrow, resolveWithOptions, evaluateAudited } from '@hushspec/core';

const resolution = resolveWithOptions(parseOrThrow(policyYaml));
const receipt = evaluateAudited(resolution, action, {
  enabled: true,
  includeRuleTrace: true,
  recordDuration: true,
});
// receipt.decision, receipt.rule_trace, receipt.policy.content_hash
```

Receipt sinks (`FileReceiptSink`, `StderrReceiptSink`, `FilteredSink`, `MultiSink`,
`CallbackSink`, `NullSink`, `ChainedFileSink`) are available in all four SDKs for routing
receipts to storage, logging, or custom callback endpoints. An OTLP/HTTP sink ships in all
four too (`OtlpSink` in Rust behind the `otlp` feature, `OtlpReceiptSink` in TypeScript and
Python, `OTLPReceiptSink` in Go), exporting receipts and policy events to an OpenTelemetry
collector with the same wire mapping everywhere. Export never blocks an evaluation, and a full
queue drops with a counter and an error callback rather than silently losing evidence.

</details>

<details>
<summary>Detection Pipeline</summary>

The detection pipeline plugs prompt injection, jailbreak, and exfiltration checks into the
evaluation flow. Thresholds come from the policy's `detection:` extension, not from the call
site. Four reference detectors ship in all four SDKs and all four register them in the same
order: `regex_injection@1`, **`heuristic_injection@1`**, `regex_jailbreak@1` and
`regex_exfiltration@1`. `heuristic_injection@1` is normative (detection spec 3.5): its signal
table and weights are fixed and published, so every conformant engine produces the same
integer score for the same input. Custom detectors register through `DetectorRegistry`.

```typescript
import { parseOrThrow, evaluateWithDetection } from '@hushspec/core';

const spec = parseOrThrow(policyYaml);
const result = evaluateWithDetection(spec, action);
// result.evaluation   -- the decision, after detection folded in
// result.detections   -- matched patterns and scores per detector
```

</details>

<details>
<summary>Framework Adapters</summary>

Prebuilt adapters translate framework-specific tool calls into HushSpec evaluation actions.

| Framework | TypeScript | Python | Go |
|---|:---:|:---:|:---:|
| Claude / Anthropic | Yes | Yes | Yes |
| OpenAI | Yes | Yes | Yes |
| MCP (Model Context Protocol) | Yes | Yes | Yes |
| Vercel AI SDK | Yes | No | No |
| LangChain | Yes | Yes | No |
| CrewAI | No | Yes | No |

No adapter imports the framework it adapts: tool calls are read structurally, so
there is no version coupling and no new dependency. Rust ships no adapters; see
the `guarded_agent` example instead. Per-SDK entry-point names are in the
[SDK API Contract](./docs/src/reference/sdk-api.md#framework-adapters).

```typescript
import { HushGuard, mapClaudeToolToAction } from '@hushspec/core';

const guard = HushGuard.fromFile('./policy.yaml');
const action = mapClaudeToolToAction(toolUseBlock);
guard.enforce(action);
```

</details>

<details>
<summary>Observability</summary>

The `EvaluationObserver` interface and `ObservableEvaluator` wrapper emit structured events for
every evaluation, policy load, and policy reload, in **all four SDKs**. Built-in observers are
`JsonLineObserver`, a console/stderr observer (`ConsoleObserver` in TypeScript and Python,
`StderrObserver` in Rust and Go), `MetricsCollector` with Prometheus exposition, and a
`WebhookObserver` in Rust and Go. An observer sees every decision and can change none, and the
action's `content` is stripped before any observer sees it.

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

Policies can be signed and verified with Ed25519 keys in **all four SDKs** and through the
`h2h` CLI's `sign`, `verify`, and `keygen` commands. The signature covers the **content hash of
the resolved policy**, not the file's bytes, so reformatting a signed policy keeps it valid and
a change to a base policy reached through `extends` invalidates it. Keys are standard PEM
(PKCS#8 and SubjectPublicKeyInfo), named by the SHA-256 of their SPKI, and trust is a keyring
with retirement and revocation.

Verification runs **on load**: every hop of an `extends` chain is checked against the keyring
or its digest pin, the load fails closed when a signature is required and absent or invalid,
and the outcome is recorded in every receipt's `policy.signature`. All four SDKs return the
exact reason code for each of the 18 vectors in `fixtures/signing/vectors.yaml`. Rust needs the
`signing` Cargo feature; Python needs the `signing` extra
(`pip install "hushspec[signing]"`), without which the signature entry points raise
`SigningUnavailable` rather than reporting an unverified signature as good. The format is
specified in [`spec/hushspec-signing.md`](./spec/hushspec-signing.md) and
`hushspec-signature.v1.schema.json`.

```bash
# Generate a keypair (writes h2h.key.pem and h2h.pub.pem, prints the key id)
h2h keygen --output-dir mykeys

# Sign a policy (creates policy.yaml.sig)
h2h sign policy.yaml --key mykeys/h2h.key.pem --expires-in 90d

# Verify the signature
h2h verify policy.yaml --key mykeys/h2h.pub.pem
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

Policies load from local files or built-in rulesets in all four SDKs, and from HTTPS URLs (with
ETag caching and SSRF protection) in Rust (behind the `http` feature) and TypeScript. Python
and Go ship no HTTP client and reject an `https:` reference outright rather than resolving it
unverified.

`PolicyProvider`, `PolicyWatcher` and `PolicyPoller` support hot reload without restarting the
process, in **all four SDKs**. A reload that cannot be read, parsed, resolved, verified or
compiled leaves the policy in force untouched, reports through `on_error`, and retries — there
is never a window with no policy. The panic sentinel is checked on the same tick.

```typescript
import { PolicyWatcher, HushGuard } from '@hushspec/core';

const guard = HushGuard.fromFile('./policy.yaml');
const watcher = new PolicyWatcher('./policy.yaml', {
  onChange: (newSpec) => guard.swapPolicy(newSpec),
});
watcher.start();
```

</details>

## 12 Core Rule Blocks

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
| `browser_automation` | Control headless-browser navigation and interaction |
| `code_execution` | Control interpreter and sandbox execution |

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

The compliance-mapped [vertical library](./library/) is embedded the same way,
under `builtin:library/<vertical>/<name>`:

```yaml
extends: "builtin:library/healthcare/hipaa-base"
```

| Builtin | Frameworks |
|---------|------------|
| `library/healthcare/hipaa-base` | `hipaa-2013` |
| `library/finance/soc2-base` | `soc2-tsc-2017` |
| `library/finance/pci-dss` | `pci-dss-4.0` |
| `library/government/fedramp-base` | `nist-800-53-r5` |
| `library/education/ferpa-student` | `ferpa` |
| `library/devops/cicd-hardened` | `owasp-llm-top10-2025`, `iso-27001-2022` |
| `library/general/air-gapped` | `iso-27001-2022`, `owasp-llm-top10-2025` |
| `library/general/recommended` | `owasp-llm-top10-2025`, `nist-ai-rmf-1.0` |

Each carries a control-tagged test suite under
[`fixtures/library/`](./fixtures/library/) that CI runs with 100% rule
coverage required.

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

| Document | Covers |
|---|---|
| [`hushspec-core.md`](./spec/hushspec-core.md) | Document format, the twelve rule blocks, evaluation, conformance levels |
| [`hushspec-posture.md`](./spec/hushspec-posture.md), [`hushspec-origins.md`](./spec/hushspec-origins.md), [`hushspec-detection.md`](./spec/hushspec-detection.md) | Extension modules |
| [`hushspec-canonical.md`](./spec/hushspec-canonical.md) | Canonical form and `content_hash` of a resolved policy (RFC 8785) |
| [`hushspec-receipt.md`](./spec/hushspec-receipt.md) | Decision receipt format 0.2 |
| [`hushspec-signing.md`](./spec/hushspec-signing.md) | Policy signature envelopes, keys, keyrings, verification |
| [`hushspec-bundle.md`](./spec/hushspec-bundle.md) | Policy bundle attestation: DSSE envelope over an in-toto statement |
| [`hushspec-log.md`](./spec/hushspec-log.md) | Hash-linked receipt log |
| [`versioning.md`](./spec/versioning.md) | Versioning and stability policy |

## Project

- [`CHANGELOG.md`](./CHANGELOG.md) — release history, Keep a Changelog format.
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — build/test commands, conventions, and the fixture-first rule for SDK changes.
- [`GOVERNANCE.md`](./GOVERNANCE.md) — how spec changes are proposed, ratified, and released.
- [`SECURITY.md`](./SECURITY.md) — supported versions and how to report a vulnerability.
- [SDK API Contract](./docs/src/reference/sdk-api.md) — the entry point each SDK publishes for
  each capability, the contract they share, and the cross-SDK invariants CI enforces.

## License

Apache-2.0. See [LICENSE](./LICENSE).
