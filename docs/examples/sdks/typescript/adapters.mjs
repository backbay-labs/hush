import assert from 'node:assert/strict';
import { HushGuard, mapOpenAIToolCall, mapClaudeToolToAction, wrapLangChainTool } from '@hushspec/core';

const guard=HushGuard.fromFile(process.argv[2] ?? 'policy.yaml');
let dispatches=0;
function ownedHandler(action) {
  guard.enforce(action);
  dispatches += 1;
}
assert.throws(()=>ownedHandler(mapOpenAIToolCall('deploy','{}')));
assert.throws(()=>ownedHandler(mapClaudeToolToAction('text_editor_20250429',{command:'view',path:'/workspace/.env'})));
const tool={name:'deploy',invoke:async()=>{dispatches+=1;}};
await assert.rejects(()=>wrapLangChainTool(tool,guard).invoke());
assert.equal(dispatches,0);
ownedHandler(mapOpenAIToolCall('search','{"query":"synthetic"}'));
assert.equal(dispatches,1);
console.log('PASS: structural OpenAI, Anthropic and LangChain dispatch boundaries');
