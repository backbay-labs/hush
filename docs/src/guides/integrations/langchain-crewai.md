# LangChain and CrewAI

Wrap the function that actually performs the effect. Telemetry callbacks that
only record a denied decision do not prevent the function from running.

## Availability

| Framework | TypeScript | Python | Go / Rust |
| --- | --- | --- | --- |
| LangChain | `wrapLangChainTool`, `createLangChainCallbackHandler` | `hush_tool` | Use the ordinary guard at your handler |
| CrewAI | No dedicated adapter | `secure_tool` | Use the ordinary guard at your handler |

These adapters use structural interfaces without importing LangChain or CrewAI.
Check the framework's dispatch lifecycle in your application.

## TypeScript wrapping

`wrapLangChainTool(tool, guard)` gates `invoke`, `call`, and `func` and
preserves the tool's prototype and fields. The returned proxy enforces before
calling the original method. The callback handler asks the framework to raise
errors and await handlers; verify that your selected executor respects both.

Run [adapters.mjs](https://hushspec.org/docs-examples/sdks/typescript/adapters.mjs) as described
in the [structural adapter test](openai.md#executable-boundary-test). A blocked
tool's asynchronous handler is never called.

## Python argument mapping

For the default `tool_call` action, decorators measure the actual bound
positional/keyword arguments and use the configured tool name.
For another action type, pass `action_mapper(args, kwargs)` returning an
`EvaluationAction` with the correct type and a nonempty target.
Do not infer filesystem authority from a Python function's name.

Download [adapters.py](https://hushspec.org/docs-examples/sdks/python/adapters.py) and use the
[Python SDK setup](../sdks/python.md). Run `python adapters.py policy.yaml`.
The test covers both decorators, a protected-path mapper, and refusal when a
non-tool action lacks a mapper. The dispatch list remains empty on every refusal.

## Lifecycle and error handling

Let `HushSpecDenied` stop the call. Do not catch it and then execute the same
handler as a fallback. Preserve a useful model-facing refusal and retain the
operator's evidence. Close a watching Python guard when the application stops;
stop TypeScript providers separately.

Warnings need affirmative confirmation, and custom callbacks must obey the
[same-guard non-reentrancy contract](../hot-reload.md). A framework wrapper does
not mediate effects performed elsewhere in the process.
