# TypeScript SDK

Use the TypeScript SDK at a runtime boundary you own. This guide needs Node 18 or newer
and the [quickstart policy](https://hushspec.org/docs-examples/quickstart/policy.yaml).

The SDK has TypeScript types and runs in JavaScript too. `parseOrThrow` throws on invalid input; `validate` returns `{ valid, errors, warnings }`. `check` returns a boolean; `gate` returns `{ proceed, result, enforcement }`. `enforce` throws `HushSpecDenied` when blocked.

## Install and run the complete example

Create an empty directory. Download these files, preserving the listed relative
paths, and place `policy.yaml` at the top of that directory:

- [package.json](https://hushspec.org/docs-examples/sdks/typescript/package.json)
- [main.mjs](https://hushspec.org/docs-examples/sdks/typescript/main.mjs)
- [trust.mjs](https://hushspec.org/docs-examples/sdks/typescript/trust.mjs)

`@hushspec/core@1.0.0` includes signing. The downloadable `.mjs` program is directly executable without a TypeScript transpiler; TypeScript applications can import the same APIs with typed actions.

```sh
npm install
node main.mjs policy.yaml
```

Expected output: `PASS: deny=0 dispatches; unconfirmed warn=0; confirmed warn=1; invalid policy refused`.
All effects are in a fresh temporary directory. No model API or credentials are
required, and the program cleans up its own synthetic output.

## Enforce before the effect

The example parses and validates the policy, resolves it, and compiles it once.
It then attaches a consistent actor and callback receipt sink to the guard.
The synthetic handler creates one file only after enforcement permits dispatch.

<!-- docs-file: sdk-typescript-dispatch docs/examples/sdks/typescript/main.mjs -->
```javascript
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseOrThrow, validate, resolveFromFileWithOptions, compilePolicy,
  HushGuard, CallbackSink } from '@hushspec/core';
import { checkTrust } from './trust.mjs';

const policyPath = process.argv[2] ?? 'policy.yaml';
const document = parseOrThrow(readFileSync(policyPath, 'utf8'));
assert.equal(validate(document).valid, true);
const resolution = resolveFromFileWithOptions(policyPath);
const compiled = compilePolicy(resolution.spec);
await checkTrust(policyPath, resolution.spec);
assert.equal(compiled.evaluate({type:'tool_call', target:'search'}).decision, 'allow');

const receipts = [];
const options = {
  actor:{agent_id:'docs-agent', session_id:'docs-session', principal:'docs-user', runtime:'docs/1.0.0'},
  sink:new CallbackSink(receipt => receipts.push(receipt)),
};
const guard = HushGuard.fromFile(policyPath, options);
const directory = mkdtempSync(join(tmpdir(), 'hush-doc-effect-'));
const output = join(directory, 'effect.txt');
let dispatches = 0;
function dispatch(enforcement, tool) {
  const outcome = enforcement.gate({type:'tool_call', target:tool});
  if (!outcome.proceed) return false;
  // This synthetic host owns the only effect and reaches it only after the gate.
  writeFileSync(output, 'confirmed once\n', {flag:'wx'});
  dispatches += 1;
  return true;
}
try {
  assert.equal(dispatch(guard, 'deploy'), false);
  assert.equal(dispatch(guard, 'write_file'), false);
  assert.equal(dispatches, 0);
  assert.equal(existsSync(output), false);
  const confirmed = HushGuard.fromFile(policyPath, {...options, onWarn:()=>true});
  assert.equal(dispatch(confirmed, 'write_file'), true);
  assert.equal(dispatches, 1);
  assert.equal(readFileSync(output, 'utf8'), 'confirmed once\n');
  assert.equal(receipts.at(-1).enforcement.outcome, 'confirmed');
  assert.equal(receipts.at(-1).actor.agent_id, 'docs-agent');
  assert.throws(()=>HushGuard.fromYaml('hushspec: "1.0.0"\nunknown_rule: true\n'));
  console.log('PASS: deny=0 dispatches; unconfirmed warn=0; confirmed warn=1; invalid policy refused');
} finally {
  rmSync(directory, {recursive:true,force:true});
}
```

The `on_warn` / `onWarn` callback in this demonstration approves one synthetic
test action. A real integration must obtain approval from an authenticated
channel and bind it to the pending action. Do not replace approval with
unconditional `true` in a production agent.

## Signing and keyrings

The companion `trust.mjs` program is called by the main example. It
creates an ephemeral test key, signs the resolved document, verifies with an
explicit keyring, and rejects a different keyring. It prints no private key and
does not persist one. Production signing identities belong to the operator.

Signing and verification must refer to the same resolved policy used for
evaluation. See [signing](../../signing-spec.md), [bundles](../../bundle-spec.md),
and the [exact signing APIs](../../reference/sdk-api.md#signing-keyrings-receipt-signing).
A successful signature proves authenticity relative to your trust roots, not
that a tool obeyed the policy.

## Providers and reload

`await HushGuard.fromProvider(provider)` loads and begins watching. Stop the provider with `provider.stop()` in a `finally` block. The guard has no `dispose()` method. Confirmation and custom-sink callbacks must not synchronously re-enter this guard; the SDK rejects that re-entry. Defer work until the current operation returns.

Initial policy-load errors cannot fall back to a nonexistent policy. Ordinary
guard reload preserves the last good policy on a rejected update and reports
the error. It is not nonblocking: reload can wait for confirmation and receipt
delivery. See [hot reload](../hot-reload.md) for ordering and the distinct
experimental coordinator refusal contract.

## Receipts and failure handling

The callback sink makes receipt contents visible to the test. It is not durable
storage. Configure a chained file sink or another reviewed delivery path for
operational evidence, and handle `sink.error` through an observer.
A failed ordinary sink does not change the decision; if dispatch must require a
durable permit, use the separately bounded [experimental invocation workflow](../../reference/trusted-invocation.md).

Receipts record actor fields, policy hash, decision, trace and enforcement outcome.
They do not carry raw action content. The `confirmed` outcome distinguishes an
approved warning from a plain allow.

## API map and next steps

The [SDK API contract](../../reference/sdk-api.md) covers parse/validate,
resolve/merge, compile/evaluate, actors, receipts, sinks, signing, keyrings,
providers, panic mode and error conventions. For mapping effects, read
[MCP](../integrations/mcp.md) and [runtime integration](../runtime-integration.md).
Use [conformance](../../reference/conformance.md) to understand what a test
corpus establishes; this example is an integration regression, not an
independent conformance certificate.
