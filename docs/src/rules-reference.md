# Rules Reference

This page documents all 12 core HushSpec rules. For full normative semantics, see the [core specification](core-spec.md).

All rules share two common fields: `enabled` (boolean, default varies by rule) and `when` (optional condition object, see [Conditional blocks](#conditional-blocks-when)). When `enabled` is `false` or the `when` condition is not met, the rule is inert.

Every applicable rule for an action is evaluated; an allow from one rule never skips another. The most restrictive decision wins.

---

## 1. `forbidden_paths`

Block access to sensitive filesystem paths using path globs.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Whether this rule is active |
| `patterns` | array of string | `[]` | Glob patterns matching forbidden paths |
| `exceptions` | array of string | `[]` | Glob patterns that override matches |

A path is forbidden if it matches a `patterns` entry and does not match any `exceptions` entry. Targets are normalized before matching (NFC, `\` to `/`, `.` and `..` collapsed, trailing slash stripped); `*` and `?` never cross `/`; `[` and `{` are literal.

```yaml
rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
      - "**/.env"
    exceptions:
      - "**/.env.example"
```

---

## 2. `path_allowlist`

Allowlist-based path access control. When enabled, only matching paths are permitted.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Whether this rule is active |
| `read` | array of string | `[]` | Glob patterns allowed for reads |
| `write` | array of string | `[]` | Glob patterns allowed for writes |
| `patch` | array of string | `[]` | Glob patterns allowed for patches (falls back to `write`) |

A match allows the path for this rule only; `secret_patterns` and `patch_integrity` still run on the content.

```yaml
rules:
  path_allowlist:
    enabled: true
    read:
      - "/home/user/project/**"
    write:
      - "/home/user/project/src/**"
```

---

## 3. `egress`

Network egress control by host.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Whether this rule is active |
| `allow` | array of string | `[]` | Host patterns to allow |
| `block` | array of string | `[]` | Host patterns to block |
| `default` | string | `"block"` | Default decision: `"allow"` or `"block"` |

Block takes precedence over allow. The target is reduced to a host first: scheme, userinfo, port, path, and query are stripped, the host is lowercased, a trailing dot is removed, and non-ASCII labels are converted to punycode. `*` matches exactly one label; `**` matches one or more labels; the apex host is never implied. IP literals match only exact entries.

```yaml
rules:
  egress:
    allow:
      - "api.openai.com"
      - "**.googleapis.com"
    default: "block"
```

---

## 4. `secret_patterns`

Detect secrets in content before it is written or transmitted.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Whether this rule is active |
| `patterns` | array of SecretPattern | `[]` | Named regex patterns for detection |
| `skip_paths` | array of string | `[]` | Glob patterns of paths to skip |

**SecretPattern fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique identifier |
| `pattern` | string | Yes | Regular expression (HushSpec regex profile) |
| `severity` | string | Yes | `"critical"`, `"error"`, or `"warn"` |
| `description` | string | No | Human-readable description |

Content is scanned on `file_write` and `patch_apply`, and on `egress` and `tool_call` when the action carries content. All patterns are tested and the highest matched severity decides: `critical` and `error` deny, `warn` warns.

```yaml
rules:
  secret_patterns:
    patterns:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: generic_api_key
        pattern: "(?i)api[_-]?key[ \\t]*[=:][ \\t]*[a-z0-9]{32,}"
        severity: error
```

---

## 5. `patch_integrity`

Validate the safety and size of patch/diff content.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Whether this rule is active |
| `max_additions` | integer | `1000` | Max added lines |
| `max_deletions` | integer | `500` | Max deleted lines |
| `forbidden_patterns` | array of string | `[]` | Regex patterns forbidden in patch content |
| `require_balance` | boolean | `false` | Whether additions/deletions must be balanced |
| `max_imbalance_ratio` | number | `10.0` | Max ratio of additions to deletions (or vice versa) |

With `require_balance: true`, a patch where one count is zero and the other is not is always denied.

```yaml
rules:
  patch_integrity:
    max_additions: 500
    max_deletions: 200
    forbidden_patterns:
      - "eval\\("
      - "exec\\("
```

---

## 6. `shell_commands`

Block dangerous shell commands before execution.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Whether this rule is active |
| `forbidden_patterns` | array of string | `[]` | Regex patterns forbidden in commands |

Patterns match against the complete command string including arguments and pipes.

```yaml
rules:
  shell_commands:
    forbidden_patterns:
      - "rm[ \\t]+-rf[ \\t]+/"
      - "curl.*\\|.*sh"
      - "chmod[ \\t]+777"
```

---

## 7. `tool_access`

Control tool and MCP invocations.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Whether this rule is active |
| `allow` | array of string | `[]` | Tool name allowlist |
| `block` | array of string | `[]` | Tool name blocklist |
| `require_confirmation` | array of string | `[]` | Tools requiring approval |
| `default` | string | `"allow"` | Default decision: `"allow"` or `"block"` |
| `max_args_size` | integer | -- | Max argument payload size in bytes |

Evaluation order: `max_args_size` (deny) > block (deny) > require_confirmation (warn) > allow (allow). When `allow` is non-empty, any unlisted tool is denied and `default` is ignored; `default` applies only when `allow` is empty. Tool names are exact, case-sensitive strings; `*` has no special meaning.

```yaml
rules:
  tool_access:
    block:
      - dangerous_tool
    require_confirmation:
      - deploy
      - database_write
    default: allow
```

---

## 8. `computer_use`

Control computer use agent (CUA) actions.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Whether this rule is active |
| `mode` | string | `"guardrail"` | `"observe"`, `"guardrail"`, or `"fail_closed"` |
| `allowed_actions` | array of string | `[]` | Permitted action identifiers |

In `observe` mode, all actions are logged but allowed. In `guardrail` and `fail_closed` mode, unlisted actions are denied; the two modes have identical semantics.

```yaml
rules:
  computer_use:
    enabled: true
    mode: guardrail
    allowed_actions:
      - "remote.session.connect"
      - "clipboard.read"
```

---

## 9. `remote_desktop_channels`

Control side-channel capabilities in remote desktop sessions.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Whether this rule is active |
| `clipboard` | boolean | `false` | Allow clipboard sharing |
| `file_transfer` | boolean | `false` | Allow file transfer |
| `audio` | boolean | `true` | Allow audio redirection |
| `drive_mapping` | boolean | `false` | Allow drive/filesystem mapping |

Channels are addressed by the `computer_use` targets `remote.clipboard`, `remote.file_transfer`, `remote.audio`, and `remote.drive_mapping`.

```yaml
rules:
  remote_desktop_channels:
    enabled: true
    clipboard: false
    file_transfer: false
    audio: true
    drive_mapping: false
```

---

## 10. `input_injection`

Control input injection capabilities in CUA environments.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Whether this rule is active |
| `allowed_types` | array of string | `[]` | Permitted input types (e.g., `"keyboard"`, `"mouse"`, `"touch"`) |
| `require_postcondition_probe` | boolean | `false` | Whether postcondition verification is required |

When enabled, only listed input types are allowed. Empty `allowed_types` denies all injection (fail-closed).

```yaml
rules:
  input_injection:
    enabled: true
    allowed_types:
      - keyboard
      - mouse
    require_postcondition_probe: true
```

---

## 11. `browser_automation`

Control browser automation steps (`browser_action` actions).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Whether this rule is active |
| `allowed_domains` | array of string | `[]` | Host patterns the agent may navigate to |
| `blocked_domains` | array of string | `[]` | Host patterns always denied (checked first) |
| `allowed_verbs` | array of string | `[]` | Permitted verbs; empty means any verb |
| `credential_detection` | boolean | `true` | Scan typed input for credential-shaped secrets |
| `extra_credential_patterns` | array of string | `[]` | Additional credential regexes |

The action's `target` is the verb; navigation verbs carry `url` and input verbs carry `content`.

```yaml
rules:
  browser_automation:
    enabled: true
    allowed_domains:
      - "*.example.com"
    blocked_domains:
      - "evil.com"
    allowed_verbs:
      - navigate
      - screenshot
```

---

## 12. `code_execution`

Control sandboxed interpreter invocations (`code_exec` actions).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Whether this rule is active |
| `language_allowlist` | array of string | `[]` | Allowed languages; empty means any |
| `module_denylist` | array of string | `[]` | Modules whose use in the code body is denied (whole-word match) |
| `network_access` | boolean | `false` | Permit calls that request network access |
| `max_execution_time_ms` | integer | -- | Maximum requested execution time |
| `max_scan_bytes` | integer | -- | Maximum bytes of code scanned for modules |

The action's `target` is the language and `content` is the code body.

```yaml
rules:
  code_execution:
    enabled: true
    language_allowlist:
      - python
    module_denylist:
      - subprocess
      - socket
    network_access: false
    max_execution_time_ms: 5000
```

---

## Conditional blocks (`when`)

Any rule block may carry a `when` condition. When it evaluates to false the block is inert. Fields on one condition combine with AND; `all_of`, `any_of`, and `not` compose sub-conditions up to 8 levels deep.

| Field | Description |
|-------|-------------|
| `time_window` | `{start: "HH:MM", end: "HH:MM", timezone: "IANA or +HH:MM", days: [mon, ...]}`; half-open, wraps midnight when `start > end` |
| `context` | Map of dot-delimited runtime-context paths to required values (`user.role: admin`, `environment: production`) |
| `all_of` / `any_of` / `not` | Boolean composition of conditions |

Invalid times, time zones, day names, unknown keys, or excessive nesting are parse errors. A time zone the engine cannot resolve at evaluation time leaves the block active.

```yaml
rules:
  shell_commands:
    when:
      context:
        environment: production
      time_window:
        start: "22:00"
        end: "06:00"
        timezone: "America/New_York"
    forbidden_patterns:
      - "rm[ \\t]+-rf[ \\t]+/"
```
