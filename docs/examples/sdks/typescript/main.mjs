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
