# Using HushSpec with Clawdstrike

[Clawdstrike](https://github.com/backbay-labs/clawdstrike) is the reference engine for HushSpec. It implements all 10 core rules, all three extensions, plus engine-specific features like Ed25519 receipt signing, async guard pipelines, and detection algorithms.

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

HushSpec rules map directly to Clawdstrike's built-in guards:

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

These Clawdstrike features are not part of HushSpec and have no HushSpec equivalent:

- **Receipt signing** -- Ed25519-signed attestations of every decision
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
