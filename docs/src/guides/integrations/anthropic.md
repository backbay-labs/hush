# Anthropic tool use

Use the adapter at the host dispatch point for a tool-use block. HushSpec reads
the tool name and input structurally; it does not require a live model API to
verify your enforcement integration.

## What v1 maps

| Tool family | Action |
| --- | --- |
| `bash`, `terminal` | `shell_command` with the command |
| Text editor, `command: view` | `file_read` with the path |
| Text editor create/edit | `file_write` with path and supplied content |
| `computer` | `computer_use` with the action |
| `web_fetch`, `fetch` | `egress` with normalized host |
| Other names | `tool_call` with argument size |

The v1 mapper strips a recognized date suffix before matching built-in tool
families. An `mcp__server__tool` name is reduced to the inner tool name; that
does **not** authenticate `server`. Review the
[pinned mapper](https://github.com/backbay-labs/hush/blob/v1.0.0/packages/hushspec/src/adapters/anthropic.ts)
and test the precise tool shapes your runtime accepts.

## Block before calling the tool

TypeScript's `mapClaudeToolToAction`, Python's `map_claude_tool_to_action`,
and Go's `MapClaudeToolToAction` expose the mapping.
TypeScript/Python `createSecureToolHandler` / `create_secure_tool_handler`
evaluate; their names do not mean they execute or contain a tool.
Go's `CreateSecureToolHandler` is a guarded handler wrapper.

The [executable adapter test](../../../examples/sdks/typescript/adapters.mjs)
calls `guard.enforce` before an owned handler. It rejects a text-editor read
of a protected path and asserts that the handler never ran.
Run it using the [OpenAI guide's local setup](openai.md#executable-boundary-test).

## Effects that need another boundary

A shell command can launch subprocesses and access files or the network.
Matching a command string is not operating-system containment. A browser or
computer action can also cause effects not described by the immediate tool
input. Use a runtime that owns those effects, and document the remaining scope.
For tool identity plus mapped effects, use the [MCP integration pattern](mcp.md).
