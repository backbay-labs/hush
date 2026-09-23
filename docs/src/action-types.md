# Action Types

HushSpec defines a standard taxonomy of action types that rules evaluate against. For each action type, every listed rule that is enabled (and whose `when` condition holds) is evaluated; an allow from one rule never skips the others.

| Action Type | Description | Rules evaluated, in order |
|-------------|-------------|---------------------------|
| `file_read` | Reading a file | `forbidden_paths`, `path_allowlist` |
| `file_write` | Writing a file | `forbidden_paths`, `path_allowlist`, `secret_patterns` |
| `patch_apply` | Applying a patch/diff | `forbidden_paths`, `path_allowlist`, `patch_integrity`, `secret_patterns` |
| `shell_command` | Shell command execution | `shell_commands` |
| `egress` | Network egress request | `egress`, `secret_patterns` (when `content` is supplied) |
| `tool_call` | Tool/MCP invocation | `tool_access`, `secret_patterns` (when `content` is supplied) |
| `computer_use` | CUA action | `computer_use`, `remote_desktop_channels` |
| `input_inject` | Input injection | `input_injection` |
| `browser_action` | Browser automation step | `browser_automation` |
| `code_exec` | Sandboxed interpreter call | `code_execution` |
| `custom` | Engine-defined action | none: denied unless the posture state grants the `custom` capability |

Any action type not in this table is unknown and is **denied** with `matched_rule` `__unknown_action_type__`. Nothing is allowed merely because no rule mentions it.

Before rules run, the panic protocol, the origins `default_behavior`, and the posture capability guard are checked; a deny from any of them is final.

## Decision Types

Rules produce one of three decisions:

| Decision | Meaning |
|----------|---------|
| `allow` | Action is permitted |
| `warn` | Action is permitted pending confirmation (e.g., `require_confirmation`). An engine with no confirmation channel treats it as `deny`. |
| `deny` | Action is blocked |

When multiple rules evaluate the same action, the **most restrictive** decision wins: `deny` > `warn` > `allow`. The reported `matched_rule` comes from the first rule, in evaluation order, whose decision equals the final decision.
