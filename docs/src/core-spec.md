# HushSpec Core Specification

The full normative specification is at [`spec/hushspec-core.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-core.md). This page summarizes HushSpec 1.0.0.

## Document Structure

A HushSpec document is a YAML file with these top-level fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hushspec` | string | Yes | Spec version (e.g., `"0.2.0"`). Engines accept every patch version of a supported minor version. |
| `name` | string | No | Human-readable policy name |
| `description` | string | No | Policy description |
| `extends` | string | No | Base policy reference. Never present in a resolved document. |
| `merge_strategy` | string | No | `replace`, `merge`, or `deep_merge` (default). Never present in a resolved document. |
| `rules` | object | No | Security rule declarations |
| `extensions` | object | No | Optional extension modules |
| `metadata` | object | No | Governance metadata (author, approver, lifecycle state, version, dates). Has no effect on evaluation. |

## YAML Profile

Documents use YAML 1.2 Core: only `true`/`false` are booleans (`yes`/`no`/`on`/`off` are rejected where a boolean is required), one document per file, duplicate keys rejected, anchors/aliases/merge keys rejected, and engines enforce size, depth, and node-count limits.

## Validation Rules

- The `hushspec` field **MUST** be present and be a string
- Unknown fields **MUST** be rejected at every nesting level (fail-closed)
- Path fields (`forbidden_paths`, `path_allowlist`, `skip_paths`) use the path-glob class; egress and browser domain fields use the host-pattern class; tool names are exact strings
- All patterns in `secret_patterns`, `patch_integrity`, `shell_commands`, and `extra_credential_patterns` must conform to the HushSpec regex profile (RE2 subset, ASCII `\d \w \s \b` and ASCII-only `(?i)`, named groups but no backreferences or lookaround, no POSIX classes, at most 2048 bytes)
- Secret pattern `name` fields **MUST** be unique within the array
- Every `when` condition is validated at parse time

## 12 Core Rules

1. **forbidden_paths** — Block access to sensitive filesystem paths
2. **path_allowlist** — Allowlist-based path access control
3. **egress** — Network egress control by host
4. **secret_patterns** — Detect secrets in content
5. **patch_integrity** — Validate patch/diff safety
6. **shell_commands** — Block dangerous shell commands
7. **tool_access** — Control tool/MCP invocations
8. **computer_use** — Control computer use agent actions
9. **remote_desktop_channels** — Control remote desktop side channels
10. **input_injection** — Control input injection capabilities
11. **browser_automation** — Control browser automation verbs, hosts, and typed credentials
12. **code_execution** — Control sandboxed interpreter language, modules, network, and time

Every rule block accepts `enabled` and an optional `when` condition that gates the block on a time window or runtime context.

See the [Rules Reference](rules-reference.md) for detailed field documentation.

## Resolution, Enforcement, and Panic Mode

- **Resolution** (Section 2.6): `extends` accepts `builtin:` names, filesystem paths, and `https:` URLs, each optionally pinned by digest. A chain is limited to 32 hops, cycles are rejected, and any loader failure refuses the resolution rather than evaluating the leaf alone.
- **Enforcement** (Section 6.2): an enforcement point runs in `enforce` or `monitor` mode with per-rule-path overrides. Monitor mode is refused without a receipt sink or observer, and a panic denial or a refused-policy denial is always enforced.
- **Panic mode** (Section 6.3): a latch, set programmatically or by a sentinel file, that denies every action with `__hushspec_panic__`. Checking the sentinel fails closed, and absence of the file never disarms the latch.
