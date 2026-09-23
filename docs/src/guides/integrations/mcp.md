# MCP tools

A tool name is not a security boundary. An MCP integration needs a trusted host
that owns registration, argument validation and dispatch, then checks both the
tool permission and the effects the tool can cause.

## What the adapters do

| Language | Mapper | Convenience entry point |
| --- | --- | --- |
| TypeScript | `mapMCPToolCall` | `createMCPGuard` evaluates; the caller still enforces |
| Python | `map_mcp_tool_call` | `create_mcp_guard` evaluates; the caller still enforces |
| Go | `MapMCPToolCall` | `GuardedMCPToolHandler` wraps an owned handler |
| Rust | Construct `EvaluationAction` | Use `HushGuard` at the owned boundary |

Known file, shell and fetch aliases map to effects; unknown names remain
`tool_call`. Mapping file access can therefore bypass a *tool-name* rule if
you never evaluate that tool gate separately. This is why the example checks
both. See the [shared adapter contract](https://github.com/backbay-labs/hush/blob/v1.0.0/fixtures/adapters/mcp-contract.json).

## Run an owned dispatch example

Use the [TypeScript example's package.json](https://hushspec.org/docs-examples/sdks/typescript/package.json),
[quickstart policy](https://hushspec.org/docs-examples/quickstart/policy.yaml), and
[mcp.mjs](https://hushspec.org/docs-examples/sdks/typescript/mcp.mjs) in one empty directory:

```sh
npm install
node mcp.mjs policy.yaml
```

The program accepts the `tools/call` JSON-RPC shape, validates a local tool
registry and a deliberately narrow argument schema, then performs an actual
owned file write. It asserts that protected reads, deploys and unconfirmed
writes never reach a handler. One confirmed write creates one file.

<!-- docs-file: mcp-dispatch docs/examples/sdks/typescript/mcp.mjs -->
```javascript
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HushGuard, mapMCPToolCall } from '@hushspec/core';

// A local host owns this registry and every effect. No remote server identity
// or general MCP containment is established by this demonstration.
const root = mkdtempSync(join(tmpdir(), 'hush-mcp-doc-'));
let approved = false;
let dispatches = 0;
const guard = HushGuard.fromFile(process.argv[2] ?? 'policy.yaml', {onWarn:()=>approved});
function call(request) {
  assert.equal(request.jsonrpc, '2.0');
  assert.equal(request.method, 'tools/call');
  const {name, arguments: args} = request.params;
  // Validate host-owned tool schemas. This example accepts a single basename,
  // never a caller-controlled directory, symlink, process or remote endpoint.
  if (!['read_file','write_file','deploy'].includes(name)) throw new Error('Unknown local tool');
  if (typeof args.path !== 'string' || !/^(?:[a-z0-9-]+\.txt|\.env)$/.test(args.path)) throw new Error('Invalid owned path');
  if (name === 'write_file' && typeof args.content !== 'string') throw new Error('Missing content');
  const trustedArgs = {...args, path:join(root,args.path)};
  // Tool permission and effect permission are distinct checks.
  const tool = guard.gate({type:'tool_call',target:name});
  if (!tool.proceed) return {blocked:true, at:'tool'};
  const effect = guard.gate(mapMCPToolCall(name, trustedArgs));
  if (!effect.proceed) return {blocked:true, at:'effect'};
  if (name === 'read_file') {
    dispatches += 1;
    return {content:readFileSync(trustedArgs.path,'utf8')};
  }
  if (name === 'write_file') {
    // Exclusive creation prevents following a preexisting target symlink.
    writeFileSync(trustedArgs.path,trustedArgs.content,{flag:'wx',mode:0o600});
    dispatches += 1;
    return {written:true};
  }
  throw new Error('Deploy has no registered effect');
}
const request=(name,path,content)=>({jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:{path,...(content===undefined?{}:{content})}}});
try {
  writeFileSync(join(root,'.env'),'synthetic only');
  assert.deepEqual(call(request('read_file','.env')), {blocked:true,at:'effect'});
  assert.deepEqual(call(request('deploy','output.txt')), {blocked:true,at:'tool'});
  assert.deepEqual(call(request('write_file','output.txt','ok')), {blocked:true,at:'tool'});
  assert.equal(dispatches,0);
  assert.equal(existsSync(join(root,'output.txt')),false);
  approved=true;
  assert.deepEqual(call(request('write_file','output.txt','ok')), {written:true});
  assert.equal(dispatches,1);
  assert.equal(readFileSync(join(root,'output.txt'),'utf8'),'ok');
  assert.throws(()=>call(request('read_file','../escape.txt')), /owned path/);
  console.log('PASS: MCP tool gate + effect gate; blocked handler never ran; confirmed write ran once');
} finally {
  rmSync(root,{recursive:true,force:true});
}
```

This is a synchronous single-owner demonstration. Its two checks are not a
durable transaction or a general filesystem sandbox. It accepts only basenames
inside a fresh private temporary directory and creates files exclusively.
Do not widen it to arbitrary paths, concurrent remote tools, symlinks or shell
execution without adding the corresponding runtime containment.

## Identity and argument binding

Authenticate the server connection, bind registration to the tool definition
you reviewed, validate arguments, and snapshot the exact request you will
dispatch. A model-controlled label such as `trusted-server` proves nothing.
The legacy mapper does not bind a server identity or issue a one-use permit.

An allowed egress host also does not authorize every effect of a tool that
contacts it. Check content, tool authority and destination at their actual
execution boundaries, and test attempts to bypass your dispatcher.

## Stronger evidence, explicitly experimental

The [trusted invocation pilot](../../reference/trusted-invocation.md) owns a
bounded coding-agent workflow with permits, journal checkpoints and crash
outcomes. It has Linux/Docker/tool-ownership limits. It is not universal MCP
containment and is not evidence of independent engine adoption.

For ordinary guards, a receipt-sink failure is reported but does not change the
decision. Use the pilot only when its stronger durability contract matches the
boundary you actually operate.
