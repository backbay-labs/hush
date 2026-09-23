# OpenAI tool calls

Apply HushSpec in the host code that receives a function name and arguments,
before that host invokes the function. No network model call is needed to test
this boundary.

## Mapping and enforcement are separate

`mapOpenAIToolCall(functionName, functionArgs)` returns a `tool_call` action
against the function's exact name. Arguments contribute canonical payload size
when valid JSON; malformed strings are measured as received. Mapping is not
argument-schema validation and does not infer file or network effects.

TypeScript's `createOpenAIGuard` and Python's `create_openai_guard` return
evaluation results, not dispatch authorization. Use the guard's `enforce` or
`gate` result before calling a handler. In Go, `GuardedOpenAIToolHandler`
wraps an owned handler; inspect its returned error.

## Executable boundary test

Download [adapters.mjs](../../../examples/sdks/typescript/adapters.mjs), the
[package manifest](../../../examples/sdks/typescript/package.json), and the
[quickstart policy](../../../examples/quickstart/policy.yaml), then run:

```sh
npm install
node adapters.mjs policy.yaml
```

The program attempts a blocked deploy and an allowed search. It asserts the
handler count, so a printed denial that still dispatches cannot pass.
The same file exercises Anthropic and LangChain structural adapters.

## Own the full function contract

Validate JSON and the function's argument schema before dispatch. Use a
host-owned registration map; do not dynamically evaluate a model-supplied
function name. For a function with several effects, gate each owned effect
and account for its real target and content. A name such as `safe_search`
does not make arbitrary subprocesses or network calls safe.

Obtain confirmation through an authenticated channel, bind it to the pending
call, and never interpret `warn` as permission by itself. Keep model-facing
errors concise while retaining structured refusal evidence for operators.
See [runtime integration](../runtime-integration.md) and [MCP boundaries](mcp.md).
