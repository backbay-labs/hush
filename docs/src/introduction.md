# HushSpec

HushSpec is agentic compliance as code: a portable, open specification for declaring, enforcing, and proving the security controls an AI agent operates under. It defines **what** security rules an agent operates under, without prescribing **how** those rules are enforced.

## Why HushSpec?

AI agents interact with tools — file systems, network APIs, shell commands, MCP servers. HushSpec provides a standard way to declare which interactions are allowed, blocked, or require confirmation.

- **Portable**: Works with any engine that implements the spec
- **Declarative**: Rules are stateless YAML — no runtime state, no detection algorithms
- **Fail-closed**: Unknown fields are rejected; invalid documents produce errors, not silent misconfiguration
- **Extensible**: Optional modules for posture state machines, origin-aware profiles, and detection thresholds

## A Minimal Example

```yaml
hushspec: "0.1.0"
name: my-policy

rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"

  egress:
    allow:
      - "api.openai.com"
      - "*.anthropic.com"
    default: block

  tool_access:
    block:
      - shell_exec
      - run_command
    default: allow
```

## Spec vs Engine

HushSpec defines the **portable rule language**. Engines like [Clawdstrike](https://github.com/backbay-labs/clawdstrike) implement the spec and add engine-specific features (detection algorithms, receipt signing, async guard infrastructure).

## Current Status

HushSpec 1.0.0 is stable. The document format, evaluation semantics, canonical form, wire formats, error and reason codes, closed registries, and grammars are frozen for the 1.x series; a minor version only adds ([versioning](reference/versioning.md)).
