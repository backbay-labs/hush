# Using HushSpec with Clawdstrike

[Clawdstrike](https://github.com/backbay-labs/clawdstrike) is an integration target
for HushSpec. The examples below describe its integration surface, not a
qualified conformance claim. Pin and test the actual engine version before
relying on support: no implementation-bound report is supplied here for Core
1.0's 12 rule blocks or all three extensions. The Rust HushSpec crate is the
reference implementation tested by `hushspec-testkit`.

## Dual-Format Support

Clawdstrike supports both its native policy format (schema v1.5.0) and HushSpec documents. The engine auto-detects the format based on the presence of the `hushspec` field.

### Rust

```rust
use clawdstrike::Policy;

// Auto-detect format: works with both native and HushSpec YAML
let policy = Policy::from_yaml_auto(&yaml_string)?;
```

`from_yaml_auto` checks for the `hushspec` top-level field. If present, the document is parsed as HushSpec and translated to Clawdstrike's internal policy representation. If absent, it is parsed as a native Clawdstrike policy.

### CLI

```bash
# Evaluate a HushSpec policy directly
clawdstrike check --policy policy.hushspec.yaml --action-type file_read ~/.ssh/id_rsa

# Migrate a native Clawdstrike policy to HushSpec format
clawdstrike migrate --to hushspec policy.yaml > policy.hushspec.yaml

# Migrate a HushSpec policy to native Clawdstrike format
clawdstrike migrate --to native policy.hushspec.yaml > policy.yaml
```

## Mapping: HushSpec to Clawdstrike

The historical integration maps these ten rule blocks to Clawdstrike guards;
this table is not complete Core 1.0 coverage:

| HushSpec Rule | Clawdstrike Guard |
|---------------|-------------------|
| `forbidden_paths` | `ForbiddenPathGuard` |
| `path_allowlist` | `PathAllowlistGuard` |
| `egress` | `EgressAllowlistGuard` |
| `secret_patterns` | `SecretLeakGuard` |
| `patch_integrity` | `PatchIntegrityGuard` |
| `shell_commands` | `ShellCommandGuard` |
| `tool_access` | `McpToolGuard` |
| `computer_use` | `ComputerUseGuard` |
| `remote_desktop_channels` | `RemoteDesktopSideChannelGuard` |
| `input_injection` | `InputInjectionCapabilityGuard` |

## Engine-Specific Features

Portable policy and receipt signing are part of HushSpec's signing specification.
An engine's receipt format and signing integration still need compatibility
verification; Ed25519 alone does not establish it. Engine-specific features include:

- **Detection guards** -- `PromptInjectionGuard`, `JailbreakGuard`, `SpiderSenseGuard` (HushSpec detection extension configures thresholds, but the algorithms are engine-specific)
- **Async guard pipeline** -- `AsyncGuard` trait for guards that call external services
- **Broker subsystem** -- Brokered egress with capability tokens and secret injection
- **Additional/remove pattern helpers** -- `additional_patterns`, `remove_patterns` in native format

## Extending Built-in Rulesets

Clawdstrike resolves HushSpec `extends` references against its built-in rulesets:

```yaml
hushspec: "1.0.0"
name: "production"
extends: "strict"

rules:
  egress:
    allow:
      - "api.openai.com"
    default: "block"
```

Available built-in rulesets: `permissive`, `default`, `strict`, `ai-agent`, `cicd`, `remote-desktop`.
