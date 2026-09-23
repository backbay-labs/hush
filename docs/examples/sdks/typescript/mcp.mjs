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
