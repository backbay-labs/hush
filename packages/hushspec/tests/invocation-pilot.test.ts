import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec = promisify(execFile);
const temporary: string[] = [];
afterEach(() => { for (const root of temporary.splice(0)) fs.rmSync(root, { recursive: true }); });

describe('pilot independent reconciliation', () => {
  const entries = [
    { event: { type: 'attempt', call_id: 'call', target: 'mcp:repo/fetch', arguments_hash: 'args', arguments: { url: 'http://127.0.0.1:1234/ok' } } },
    { event: { type: 'permit', call_id: 'call' } },
    { event: { type: 'terminal', call_id: 'call', outcome: 'completed' } },
  ];
  const observations = [
    { stage: 'received', call_id: 'call', tool: 'fetch', arguments_hash: 'args', connection: 'repo' },
    { stage: 'completed', call_id: 'call', tool: 'fetch', arguments_hash: 'args', connection: 'repo' },
  ];
  it('reconciles one actual server call and one endpoint request', async () => {
    const { reconcileObservations } = await import('../../../scripts/mcp-pilot/packet.mjs');
    expect(reconcileObservations(entries, observations, ['/ok'])).toMatchObject({ dispatched: 1, networkRequests: 1 });
  });
  it.each(['flipped-counter', 'missing-server-terminal', 'foreign-call', 'foreign-arguments', 'denied-dispatch'])
  ('rejects %s independently of signed journal validity', async mutation => {
    const { reconcileObservations } = await import('../../../scripts/mcp-pilot/packet.mjs');
    const changed = structuredClone(observations); const journal = structuredClone(entries);
    if (mutation === 'missing-server-terminal') changed.pop();
    if (mutation === 'foreign-call') changed[0].call_id = 'foreign';
    if (mutation === 'foreign-arguments') changed[0].arguments_hash = 'different';
    if (mutation === 'denied-dispatch') journal.splice(1, 1);
    expect(() => reconcileObservations(journal, changed, mutation === 'flipped-counter' ? [] : ['/ok'])).toThrow();
  });
  it('rejects substituted source bytes against the declared artifact digest', async () => {
    const { verifyArtifacts } = await import('../../../scripts/mcp-pilot/packet.mjs');
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hush-pilot-source-')); temporary.push(root);
    fs.writeFileSync(path.join(root, 'source.js'), 'abc');
    const inventory = [{ path: 'source.js', bytes: 3,
      sha256: 'sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' }];
    expect(() => verifyArtifacts(root, inventory)).not.toThrow();
    fs.writeFileSync(path.join(root, 'source.js'), 'abd');
    expect(() => verifyArtifacts(root, inventory)).toThrow(/digest/);
  });
  it('binds engine identity to evaluator and parser bytes, excluding unrelated evidence', async () => {
    const { engineMaterialDigest } = await import('../../../scripts/mcp-pilot/packet.mjs');
    const records = ['materials/packages/hushspec/dist/index.js', 'materials/packages/hushspec/dist/compiled.js',
      'materials/node_modules/yaml/package.json'].map(name => ({ path: name, bytes: 1, sha256: `sha256:${'0'.repeat(64)}` }));
    const original = engineMaterialDigest(records);
    expect(original).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(engineMaterialDigest([...records, { path: 'result.json', bytes: 1, sha256: `sha256:${'1'.repeat(64)}` }])).toBe(original);
    records[1].sha256 = `sha256:${'2'.repeat(64)}`;
    expect(engineMaterialDigest(records)).not.toBe(original);
    expect(() => engineMaterialDigest([])).toThrow();
  });
});

describe.skipIf(process.env.HUSH_MCP_PILOT_INTEGRATION !== '1')('Docker-contained coding pilot', () => {
  it('edits through MCP, refuses bypasses and preserves crash/negative evidence', async () => {
    const target = new URL('../../../target/', import.meta.url).pathname;
    fs.mkdirSync(target, { recursive: true });
    // Preserve completed and deliberately incomplete packets for qualification review.
    const root = fs.mkdtempSync(path.join(target, 'hush-pilot-test-'));
    const output = path.join(root, 'packet');
    const script = new URL('../../../scripts/run_mcp_pilot.mjs', import.meta.url);
    await exec(process.execPath, [script.pathname, '--output', output], { timeout: 120_000, maxBuffer: 1_048_576 });
    const packet = JSON.parse(fs.readFileSync(path.join(output, 'result.json'), 'utf8'));
    expect(packet.assertions.actual_file_edit).toBe(true);
    expect(packet.assertions.direct_actor_routes_denied).toBe(true);
    expect(packet.assertions.permits_match_server_calls).toBe(true);
    expect(packet.crashes.every((c: any) => c.complete_verification_refused)).toBe(true);
    expect(packet.negative_checks.every((c: any) => c.refused)).toBe(true);
  }, 125_000);
});
