# HushSpec Core Specification

**Version:** 0.1.0
**Status:** Draft
**Date:** 2026-03-15

---

## 1. Introduction

HushSpec is a portable, engine-neutral specification for declaring security rules at the tool boundary of AI agent runtimes. A HushSpec document declares security intent -- what actions are allowed, blocked, or require confirmation -- without prescribing how those rules are enforced.

The specification defines a YAML-based document format that any conformant engine can parse, validate, merge, and evaluate. HushSpec documents are designed to be authored by security teams, shared across organizations, and enforced by heterogeneous runtimes including CLI tools, SDKs, proxies, and embedded WebAssembly modules.

### 1.1 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### 1.2 Design Principles

1. **Fail-closed.** Ambiguity or error in a HushSpec document MUST result in denial, not allowance.
2. **Engine-neutral.** The specification declares intent. Enforcement mechanics are engine-specific.
3. **Portable.** A valid HushSpec document MUST produce identical semantic decisions across conformant engines.
4. **Composable.** Documents support single inheritance via `extends` with well-defined merge semantics.

---

## 2. Document Structure

A HushSpec document is a YAML file (YAML 1.2) with the following top-level fields:

| Field            | Type   | Required | Default       | Description                                      |
|------------------|--------|----------|---------------|--------------------------------------------------|
| `hushspec`       | string | REQUIRED | --            | Spec version. MUST match `^0\.` for v0.x.        |
| `name`           | string | OPTIONAL | --            | Human-readable policy name.                      |
| `description`    | string | OPTIONAL | --            | Policy description.                              |
| `extends`        | string | OPTIONAL | --            | Reference to a base policy.                      |
| `merge_strategy` | string | OPTIONAL | `"deep_merge"` | One of `replace`, `merge`, `deep_merge`.         |
| `rules`          | object | OPTIONAL | --            | Security rule declarations.                      |
| `extensions`     | object | OPTIONAL | --            | Extension modules.                               |

### 2.1 Strictness

Conformant parsers MUST reject documents containing unknown top-level fields. This requirement extends recursively: unknown fields within `rules`, within individual rule objects, and within `extensions` MUST also cause rejection. This ensures forward compatibility is explicit and prevents silent misconfiguration.

### 2.2 Version Field

The `hushspec` field is the only REQUIRED field. Its value MUST be a string matching the pattern `^0\.\d+\.\d+$` for the v0.x series. Parsers MUST reject documents where this field is absent, is not a string, or does not match the expected pattern for the parser's supported version range.

### 2.3 Extends Field

The `extends` field is a single string reference to a base policy document. Resolution of this reference (filesystem path, URL, registry identifier, built-in name) is engine-specific and outside the scope of this specification. Engines MUST document their resolution strategy. Circular inheritance MUST be detected and rejected.

---

## 3. Rules

The `rules` object contains up to ten named rule blocks. Each rule block controls a specific security domain. All rule blocks share a common `enabled` field; when `enabled` is `false`, the rule block is inert and MUST NOT influence decisions.

If `rules` is absent or empty, no rules are active. Engines MUST NOT inject implicit rules beyond what the document (and its resolved `extends` chain) declares.

### 3.1 `rules.forbidden_paths`

Block access to sensitive filesystem paths.

| Field        | Type            | Required | Default | Description                                     |
|--------------|-----------------|----------|---------|-------------------------------------------------|
| `enabled`    | boolean         | OPTIONAL | `true`  | Whether this rule is active.                    |
| `patterns`   | array of string | OPTIONAL | `[]`    | Glob patterns matching forbidden paths.         |
| `exceptions` | array of string | OPTIONAL | `[]`    | Glob patterns that override pattern matches.    |

**Semantics:** A path is forbidden if and only if:
1. It matches at least one entry in `patterns`, AND
2. It does NOT match any entry in `exceptions`.

Glob matching MUST support `*` (any sequence within a path segment), `**` (any sequence of segments including separators), and `?` (any single character). Matching is case-sensitive on case-sensitive filesystems. Engines on case-insensitive filesystems SHOULD document their behavior.

When `patterns` is empty, no paths are forbidden regardless of the `enabled` state.

### 3.2 `rules.path_allowlist`

Allowlist-based path access control. When enabled, only paths matching the allowlist are permitted for the specified operation type.

| Field   | Type            | Required | Default | Description                                          |
|---------|-----------------|----------|---------|------------------------------------------------------|
| `enabled` | boolean       | OPTIONAL | `false` | Whether this rule is active.                         |
| `read`  | array of string | OPTIONAL | `[]`    | Glob patterns allowed for read access.               |
| `write` | array of string | OPTIONAL | `[]`    | Glob patterns allowed for write access.              |
| `patch` | array of string | OPTIONAL | `[]`    | Glob patterns allowed for patch operations.          |

**Semantics:** When enabled, a file operation is allowed only if the target path matches at least one pattern in the corresponding array (`read`, `write`, or `patch`). If `patch` is empty, patch operations fall back to the `write` array. If the relevant array is empty (and no fallback applies), all operations of that type are denied.

Glob syntax follows the same rules as Section 3.1.

### 3.3 `rules.egress`

Network egress control by domain.

| Field     | Type            | Required | Default   | Description                                       |
|-----------|-----------------|----------|-----------|---------------------------------------------------|
| `enabled` | boolean         | OPTIONAL | `true`    | Whether this rule is active.                      |
| `allow`   | array of string | OPTIONAL | `[]`      | Domain glob patterns to allow.                    |
| `block`   | array of string | OPTIONAL | `[]`      | Domain glob patterns to block.                    |
| `default` | string          | OPTIONAL | `"block"` | Default decision: `"allow"` or `"block"`.         |

**Semantics:** For a given target domain:
1. If the domain matches any entry in `block`, the decision is **deny**. Block takes precedence over allow.
2. If the domain matches any entry in `allow`, the decision is **allow**.
3. Otherwise, the `default` value applies.

Domain patterns use glob syntax where `*` matches any sequence of characters within a single domain label and `**` matches across labels (e.g., `**.example.com` matches `foo.bar.example.com`). Port numbers, if present in the target, are stripped before matching.

### 3.4 `rules.secret_patterns`

Detect secrets in content before it is written or transmitted.

| Field        | Type                    | Required | Default | Description                                  |
|--------------|-------------------------|----------|---------|----------------------------------------------|
| `enabled`    | boolean                 | OPTIONAL | `true`  | Whether this rule is active.                 |
| `patterns`   | array of SecretPattern  | OPTIONAL | `[]`    | Named regex patterns for secret detection.   |
| `skip_paths` | array of string         | OPTIONAL | `[]`    | Glob patterns of paths to skip scanning.     |

**SecretPattern object:**

| Field         | Type   | Required | Description                                          |
|---------------|--------|----------|------------------------------------------------------|
| `name`        | string | REQUIRED | Unique identifier for this pattern.                  |
| `pattern`     | string | REQUIRED | Regular expression to match against content.         |
| `severity`    | string | REQUIRED | One of `"critical"`, `"error"`, `"warn"`.            |
| `description` | string | OPTIONAL | Human-readable description of what this detects.     |

**Constraints:**
- The `name` field MUST be unique within the `patterns` array. Parsers MUST reject documents with duplicate names.
- The `pattern` field MUST be a valid regular expression. Engines SHOULD support PCRE2-compatible syntax at minimum. Invalid regexes MUST cause document rejection (fail-closed).
- The `severity` field MUST be one of the three enumerated values.

**Semantics:** Content is scanned against each pattern. A match produces a finding at the specified severity. The engine determines how severities map to decisions (e.g., `"critical"` and `"error"` -> deny, `"warn"` -> warn). If the target path matches any `skip_paths` entry, scanning is bypassed.

### 3.5 `rules.patch_integrity`

Validate the safety and reasonableness of patch/diff content.

| Field                  | Type            | Required | Default | Description                                       |
|------------------------|-----------------|----------|---------|---------------------------------------------------|
| `enabled`              | boolean         | OPTIONAL | `true`  | Whether this rule is active.                      |
| `max_additions`        | integer         | OPTIONAL | `1000`  | Maximum number of added lines permitted.          |
| `max_deletions`        | integer         | OPTIONAL | `500`   | Maximum number of deleted lines permitted.        |
| `forbidden_patterns`   | array of string | OPTIONAL | `[]`    | Regex patterns forbidden in patch content.        |
| `require_balance`      | boolean         | OPTIONAL | `false` | Whether additions/deletions must be balanced.     |
| `max_imbalance_ratio`  | number          | OPTIONAL | `10.0`  | Maximum ratio of additions to deletions (or vice versa). |

**Constraints:**
- `max_additions` and `max_deletions` MUST be non-negative integers.
- `max_imbalance_ratio` MUST be a positive number (> 0).

**Semantics:** A patch is denied if:
1. The number of added lines exceeds `max_additions`, OR
2. The number of deleted lines exceeds `max_deletions`, OR
3. Any line in the patch matches a `forbidden_patterns` entry, OR
4. `require_balance` is `true` AND the ratio of additions to deletions (or deletions to additions, whichever is larger) exceeds `max_imbalance_ratio`. When either additions or deletions is zero and the other is nonzero and `require_balance` is `true`, the patch is denied.

### 3.6 `rules.shell_commands`

Block dangerous shell commands before execution.

| Field                | Type            | Required | Default | Description                                   |
|----------------------|-----------------|----------|---------|-----------------------------------------------|
| `enabled`            | boolean         | OPTIONAL | `true`  | Whether this rule is active.                  |
| `forbidden_patterns` | array of string | OPTIONAL | `[]`    | Regex patterns forbidden in shell commands.   |

**Semantics:** A shell command is denied if any portion of the command string matches any `forbidden_patterns` entry. Matching is performed against the complete command string as provided to the engine, including arguments and pipes. Empty `forbidden_patterns` means no commands are blocked by this rule.

### 3.7 `rules.tool_access`

Control tool and MCP (Model Context Protocol) invocations.

| Field                  | Type            | Required | Default   | Description                                      |
|------------------------|-----------------|----------|-----------|--------------------------------------------------|
| `enabled`              | boolean         | OPTIONAL | `true`    | Whether this rule is active.                     |
| `allow`                | array of string | OPTIONAL | `[]`      | Tool name allowlist.                             |
| `block`                | array of string | OPTIONAL | `[]`      | Tool name blocklist.                             |
| `require_confirmation` | array of string | OPTIONAL | `[]`      | Tools requiring user/operator approval.          |
| `default`              | string          | OPTIONAL | `"allow"` | Default decision: `"allow"` or `"block"`.        |
| `max_args_size`        | integer         | OPTIONAL | --        | Maximum argument payload size in bytes.          |

**Semantics:** For a given tool invocation:
1. If the tool name matches any entry in `block`, the decision is **deny**. Block takes precedence.
2. If `require_confirmation` is non-empty and the tool name matches an entry, the decision is **warn** (requiring confirmation). Confirmation semantics are engine-specific.
3. If `allow` is non-empty and the tool name matches an entry, the decision is **allow**.
4. If `allow` is non-empty and the tool name does NOT match, the decision is **deny** (allowlist mode).
5. Otherwise, the `default` value applies.

Tool names are matched as exact strings. Glob or regex matching is NOT supported for tool names.

If `max_args_size` is specified and the serialized argument payload exceeds this size in bytes, the invocation is denied regardless of other rules.

### 3.8 `rules.computer_use`

Control computer use agent (CUA) actions in remote desktop and browser automation contexts.

| Field             | Type            | Required | Default       | Description                                     |
|-------------------|-----------------|----------|---------------|-------------------------------------------------|
| `enabled`         | boolean         | OPTIONAL | `false`       | Whether this rule is active.                    |
| `mode`            | string          | OPTIONAL | `"guardrail"` | One of `"observe"`, `"guardrail"`, `"fail_closed"`. |
| `allowed_actions` | array of string | OPTIONAL | `[]`          | Action identifiers permitted.                   |

**Mode semantics:**
- `"observe"`: Log all actions but do not block. Decisions are **allow** with audit.
- `"guardrail"`: Block actions not in `allowed_actions`. Actions in the list are allowed; others are denied.
- `"fail_closed"`: Deny all actions unless explicitly listed in `allowed_actions`.

The distinction between `guardrail` and `fail_closed` is behavioral: in `guardrail` mode, engines MAY apply heuristics or additional context to borderline cases. In `fail_closed` mode, engines MUST deny anything not explicitly listed.

Action identifiers are engine-defined strings (e.g., `"remote.session.connect"`, `"input.inject"`, `"clipboard.read"`). This specification does not mandate a fixed set of action identifiers.

### 3.9 `rules.remote_desktop_channels`

Control side-channel capabilities in remote desktop sessions.

| Field           | Type    | Required | Default | Description                              |
|-----------------|---------|----------|---------|------------------------------------------|
| `enabled`       | boolean | OPTIONAL | `false` | Whether this rule is active.             |
| `clipboard`     | boolean | OPTIONAL | `false` | Allow clipboard sharing.                 |
| `file_transfer` | boolean | OPTIONAL | `false` | Allow file transfer.                     |
| `audio`         | boolean | OPTIONAL | `true`  | Allow audio redirection.                 |
| `drive_mapping` | boolean | OPTIONAL | `false` | Allow drive/filesystem mapping.          |

**Semantics:** When enabled, each boolean field controls whether the corresponding side channel is permitted. A value of `false` means the channel MUST be blocked. A value of `true` means the channel is permitted. Engines that do not support a particular channel SHOULD ignore the corresponding field and document this behavior.

### 3.10 `rules.input_injection`

Control input injection capabilities in computer use agent environments.

| Field                        | Type            | Required | Default | Description                                          |
|------------------------------|-----------------|----------|---------|------------------------------------------------------|
| `enabled`                    | boolean         | OPTIONAL | `false` | Whether this rule is active.                         |
| `allowed_types`              | array of string | OPTIONAL | `[]`    | Input type identifiers permitted.                    |
| `require_postcondition_probe`| boolean         | OPTIONAL | `false` | Whether postcondition verification is required.      |

**Semantics:** When enabled, only input injection types listed in `allowed_types` are permitted. If `allowed_types` is empty, all input injection is denied (fail-closed). Standard type identifiers include `"keyboard"`, `"mouse"`, and `"touch"`, but engines MAY define additional types.

If `require_postcondition_probe` is `true`, the engine MUST verify that the injected input produced the expected effect before proceeding. The mechanism for postcondition verification is engine-specific.

---

## 4. Merge Semantics

When `extends` is present, the base document is resolved first, then the child document is overlaid according to `merge_strategy`.

### 4.1 Strategies

**`deep_merge` (default):**
Recursively merge objects. For each field in the child document:
- If the field is an object and the corresponding base field is also an object, merge recursively.
- If the field is an array, the child array entirely replaces the base array. Arrays are NOT appended.
- If the field is a scalar, the child value replaces the base value.
- Fields present in the base but absent in the child are preserved.

**`merge`:**
Shallow merge at the `rules` level. If the child defines a rule block (e.g., `rules.egress`), the entire child rule block replaces the base rule block. Fields within the rule block are not individually merged. Top-level fields (`name`, `description`, etc.) follow scalar replacement.

**`replace`:**
The child document entirely replaces the base document. The base document is loaded only to validate that the reference is resolvable; its content is discarded.

### 4.2 Merge Order

Merge is performed pairwise from the root of the inheritance chain to the leaf:
1. Resolve the `extends` chain to produce an ordered list: `[root, ..., parent, child]`.
2. Start with the root document.
3. Apply each subsequent document using the `merge_strategy` declared in that document.

### 4.3 Engine-Specific Helpers

Convenience features such as `additional_patterns`, `remove_patterns`, or other additive/subtractive merge helpers are engine-specific extensions. They are NOT part of this specification. Engines that support such features MUST document them and MUST ensure that the result of applying helpers is expressible as a valid HushSpec document.

---

## 5. Action Types

HushSpec defines a standard taxonomy of action types. Engines use action types to route evaluation to the appropriate rule blocks.

| Action Type     | Description                                      | Primary Rule Block(s)                        |
|-----------------|--------------------------------------------------|----------------------------------------------|
| `file_read`     | Reading a file from the filesystem               | `forbidden_paths`, `path_allowlist`          |
| `file_write`    | Writing or creating a file                       | `forbidden_paths`, `path_allowlist`, `secret_patterns` |
| `egress`        | Outbound network request                         | `egress`                                     |
| `shell_command` | Executing a shell command                        | `shell_commands`                             |
| `tool_call`     | Invoking a tool or MCP endpoint                  | `tool_access`                                |
| `patch_apply`   | Applying a patch or diff to a file               | `patch_integrity`, `forbidden_paths`, `path_allowlist` |
| `computer_use`  | Computer use agent action                        | `computer_use`                               |
| `input_inject`  | Injecting keyboard/mouse/touch input             | `input_injection`                            |
| `custom`        | Engine-defined action type                       | Engine-specific                              |

An action MAY be evaluated against multiple rule blocks. For example, a `file_write` action is checked against `forbidden_paths`, `path_allowlist`, AND `secret_patterns`. If any applicable rule block produces a **deny**, the overall decision is **deny**.

---

## 6. Decision Types

HushSpec defines three standard decision outcomes:

| Decision | Semantics                                                                   |
|----------|-----------------------------------------------------------------------------|
| `allow`  | The action is permitted. Execution may proceed.                             |
| `warn`   | The action is permitted pending confirmation. Engines determine how confirmation is obtained (interactive prompt, approval queue, auto-approve in CI, etc.). If confirmation is not possible, engines SHOULD treat `warn` as `deny`. |
| `deny`   | The action is blocked. Execution MUST NOT proceed.                          |

### 6.1 Decision Precedence

When multiple rule blocks apply to a single action, decisions are aggregated by precedence:

1. **deny** takes absolute precedence. If any rule block denies, the action is denied.
2. **warn** is next. If no rule block denies but at least one warns, the action requires confirmation.
3. **allow** applies only when all applicable rule blocks allow.

---

## 7. Validation Requirements

Conformant parsers and validators MUST enforce the following:

1. **Unknown field rejection.** Documents containing fields not defined in this specification at any nesting level MUST be rejected. This is the fail-closed principle applied to schema validation.

2. **Version field presence.** The `hushspec` field MUST be present and MUST be a string matching `^0\.\d+\.\d+$` for v0.x documents.

3. **Type correctness.** All fields MUST conform to their declared types. A string where a boolean is expected MUST cause rejection.

4. **Enum constraints.** Fields with enumerated values (`severity`, `mode`, `default` in egress/tool_access, `merge_strategy`) MUST contain one of the specified values.

5. **Uniqueness constraints.** The `name` field within each element of `secret_patterns.patterns` MUST be unique across the array. Duplicate names MUST cause rejection.

6. **Regex validity.** All fields designated as regex patterns MUST be syntactically valid regular expressions. Invalid regexes MUST cause document rejection.

7. **Numeric constraints.** `max_additions` and `max_deletions` MUST be non-negative integers. `max_imbalance_ratio` MUST be a positive number (strictly greater than zero). `max_args_size` MUST be a positive integer if present.

8. **Boolean fields.** Boolean fields MUST be YAML booleans (`true`/`false`), not strings or integers.

---

## 8. Conformance Levels

Implementations of HushSpec declare conformance at one of four levels. Each level subsumes all requirements of the levels below it.

### Level 0: Parser

A Level 0 implementation can:
- Parse valid HushSpec YAML documents into a structured representation.
- Reject syntactically invalid YAML.
- Reject documents missing the required `hushspec` field.

### Level 1: Validator

A Level 1 implementation additionally:
- Validates all field types and constraints as specified in Section 7.
- Rejects documents with unknown fields at any nesting level.
- Validates enum values, uniqueness constraints, and numeric constraints.

### Level 2: Merger

A Level 2 implementation additionally:
- Resolves `extends` references (via at least one resolution strategy).
- Correctly implements all three merge strategies (`deep_merge`, `merge`, `replace`).
- Detects and rejects circular inheritance.

### Level 3: Evaluator

A Level 3 implementation additionally:
- Accepts an action (type + context) and a resolved HushSpec document.
- Produces a correct `allow`, `warn`, or `deny` decision per the semantics defined in Section 3.
- Implements decision precedence as defined in Section 6.1.
- Passes the HushSpec conformance test vectors (published separately).

---

## 9. Extensions

Extension modules are declared under the `extensions` top-level field. Extensions provide optional capabilities beyond the core rule set.

### 9.1 `extensions.posture`

Stateful capability and budget management. Posture extensions define budgets (e.g., maximum number of tool calls per session), capability state machines, and degradation policies.

The posture extension schema is defined in a separate specification document. Core HushSpec parsers MUST accept the `posture` key without rejecting the document but MAY ignore its contents.

### 9.2 `extensions.origins`

Origin-aware policy profiles. Origins extensions allow policies to vary based on the source context of a request (e.g., Slack channel, GitHub repository, API client identity).

The origins extension schema is defined in a separate specification document. Core HushSpec parsers MUST accept the `origins` key without rejecting the document but MAY ignore its contents.

### 9.3 `extensions.detection`

Detection engine thresholds and configuration. Detection extensions configure prompt injection detection, jailbreak detection, threat intelligence screening, and other content analysis capabilities.

The detection extension schema is defined in a separate specification document. Core HushSpec parsers MUST accept the `detection` key without rejecting the document but MAY ignore its contents.

### 9.4 Extension Versioning

In HushSpec v0.1.0, extension modules do **not** declare independent version
fields inside documents. The posture, origins, and detection companion specs are
versioned alongside the core HushSpec release. A future major version MAY add
in-document extension versioning if interoperability needs require it.

### 9.5 Unknown Extensions

Conformant parsers MUST reject unknown keys under `extensions`. Only the keys defined in this specification and its companion extension specifications are permitted.

---

## 10. Versioning

HushSpec uses semantic versioning (SemVer 2.0.0).

### 10.1 v0.x Series

The v0.x series is the initial development series. Breaking changes (field removals, semantic changes, structural reorganization) MAY occur between minor versions (e.g., 0.1.0 to 0.2.0). Patch versions (e.g., 0.1.0 to 0.1.1) are reserved for clarifications and errata that do not change document validity.

Implementations SHOULD clearly document which v0.x minor version(s) they support.

### 10.2 v1.0+ Series

Upon reaching v1.0.0, HushSpec guarantees backward compatibility within each major version:
- Minor versions (1.1.0, 1.2.0, ...) MAY add new optional fields and new rule blocks. Existing documents remain valid.
- Patch versions (1.0.1, 1.0.2, ...) contain only clarifications and errata.
- Major versions (2.0.0) MAY introduce breaking changes.

### 10.3 Independence

HushSpec versioning is independent of any engine, SDK, or implementation. An engine at version 3.5.0 may implement HushSpec 0.1.0. There is no coupling between specification versions and implementation versions.

---

## Appendix A. ABNF for Version Field

```abnf
hushspec-version = "0." 1*DIGIT "." 1*DIGIT
```

## Appendix B. Minimal Valid Document

```yaml
hushspec: "0.1.0"
```

## Appendix C. Example Document

```yaml
hushspec: "0.1.0"
name: "production-agent-policy"
description: "Security policy for production AI agent deployments"
extends: "default"
merge_strategy: "deep_merge"

rules:
  forbidden_paths:
    enabled: true
    patterns:
      - "**/.env"
      - "**/.ssh/**"
      - "**/credentials*"
    exceptions:
      - "**/.env.example"

  egress:
    enabled: true
    allow:
      - "api.openai.com"
      - "**.googleapis.com"
    default: "block"

  secret_patterns:
    enabled: true
    patterns:
      - name: "aws_access_key"
        pattern: "AKIA[0-9A-Z]{16}"
        severity: "critical"
        description: "AWS access key ID"
      - name: "generic_api_key"
        pattern: "(?i)(api[_-]?key|apikey)\\s*[=:]\\s*['\"]?[a-z0-9]{32,}"
        severity: "error"

  shell_commands:
    enabled: true
    forbidden_patterns:
      - "rm\\s+-rf\\s+/"
      - "curl.*\\|.*sh"
      - "wget.*\\|.*bash"

  tool_access:
    enabled: true
    block:
      - "dangerous_tool"
    require_confirmation:
      - "deploy"
      - "database_write"
    default: "allow"
```
