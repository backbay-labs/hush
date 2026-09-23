#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { generateKeypair, hashJson, signContentHash, uuidV7, verifyInvocationJournal } from '../packages/hushspec/dist/index.js';
import { actorImage, digest, readJson, readLines, writeDurable } from './mcp-pilot/io.mjs';
import { engineMaterialDigest, reconcileObservations, verifyArtifacts, verifyIsolation, verifyPilotPacket } from './mcp-pilot/packet.mjs';

const exec = promisify(execFile);
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const initial = 'export const answer = 41;\n';
const secret = 'synthetic protected content\n';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function command(executable, args, timeout = 30_000) {
  return (await exec(executable, args, { cwd: repo, timeout, maxBuffer: 8_388_608 })).stdout;
}
function artifact(directory, relative) {
  const bytes = fs.readFileSync(path.join(directory, relative));
  return { path: relative, bytes: bytes.length, sha256: digest(bytes) };
}
function regularFiles(directory) {
  const result = [];
  for (const name of fs.readdirSync(directory).sort()) {
    const child = path.join(directory, name); const stat = fs.lstatSync(child);
    if (stat.isSymbolicLink()) throw new Error('unexpected source symlink');
    if (stat.isDirectory()) result.push(...regularFiles(child));
    else if (stat.isFile()) result.push(child);
  }
  return result;
}
async function runScenario(output, scenario, keys, image, engineHash) {
  const directory = path.join(output, scenario); fs.mkdirSync(directory, { mode: 0o700 });
  const files = path.join(directory, 'files'); fs.mkdirSync(files, { mode: 0o700 });
  writeDurable(path.join(files, 'note.txt'), initial); writeDurable(path.join(files, 'secret.txt'), secret);
  fs.symlinkSync(path.join(files, 'secret.txt'), path.join(files, 'symlink'));
  fs.linkSync(path.join(files, 'secret.txt'), path.join(files, 'hardlink'));
  const endpointFile = path.join(directory, 'endpoint.jsonl');
  const endpointFd = fs.openSync(endpointFile, 'wx', 0o600); fs.fsyncSync(endpointFd);
  let endpointCount = 0;
  const endpoint = http.createServer((request, response) => {
    const bytes = Buffer.from(JSON.stringify({ sequence: ++endpointCount, path: request.url }) + '\n');
    fs.writeSync(endpointFd, bytes); fs.fsyncSync(endpointFd);
    if (request.url === '/redirect') { response.writeHead(302, { location: '/must-not-follow' }); response.end(); }
    else if (request.url === '/ok') response.end('owned endpoint response');
    else { response.writeHead(403); response.end('unexpected path'); }
  });
  await new Promise(resolve => endpoint.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${endpoint.address().port}`;
  const streamId = uuidV7(); const containerName = `hush-project-c-${streamId}`;
  const config = { directory, origin, streamId, containerName, scenario, engineHash,
    runtimePrivateKeyPem: keys.runtime.privateKeyPem, policyPrivateKeyPem: keys.policy.privateKeyPem,
    policyPublicKeyPem: keys.policy.publicKeyPem };
  const child = spawn(process.execPath, ['scripts/mcp-pilot/host.mjs'], { cwd: repo,
    stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: process.env.PATH } });
  let stdout = ''; let stderr = ''; let exited;
  const closed = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => { exited = { code, signal }; resolve(exited); });
  });
  child.stdin.on('error', () => {});
  child.stdin.end(JSON.stringify(config));
  child.stdout.on('data', chunk => { stdout += chunk; if (stdout.length > 1_048_576) child.kill('SIGKILL'); });
  child.stderr.on('data', chunk => { stderr += chunk; if (stderr.length > 1_048_576) child.kill('SIGKILL'); });
  const lifetime = setTimeout(() => child.kill('SIGKILL'), 45_000);
  try {
    if (scenario !== 'completed') {
      const until = Date.now() + 40_000;
      while (!fs.existsSync(path.join(directory, 'crash-marker.json')) && !exited && Date.now() < until) await sleep(25);
      if (!fs.existsSync(path.join(directory, 'crash-marker.json'))) throw new Error(`crash marker missing: ${scenario}`);
      child.kill('SIGKILL');
    }
    const exit = await closed;
    writeDurable(path.join(directory, 'host-process.json'), { ...exit, stdout, stderr });
    if (scenario === 'completed' ? exit.code !== 0 : exit.signal !== 'SIGKILL') throw new Error(`host scenario failed: ${scenario}`);
    // SIGKILL closes the server pipes. Allow bounded owned children to finish their EOF/error path.
    await sleep(100);
    const inspection = JSON.parse(await command('docker', ['inspect', containerName]))[0];
    verifyIsolation(inspection, image.Id);
    writeDurable(path.join(directory, 'container.json'), inspection);
    const observations = { note_before: digest(Buffer.from(initial)), note_after: digest(fs.readFileSync(path.join(files, 'note.txt'))),
      secret_before: digest(Buffer.from(secret)), secret_after: digest(fs.readFileSync(path.join(files, 'secret.txt'))),
      host_signal: exit.signal, marker: scenario === 'completed' ? null : readJson(path.join(directory, 'crash-marker.json')) };
    writeDurable(path.join(directory, 'observations.json'), observations);
    const entries = readLines(path.join(directory, 'journal/entries.jsonl'));
    const server = ['repo', 'other'].flatMap(connection => readLines(path.join(directory, `${connection}-server.jsonl`)).map(event => ({ ...event, connection })));
    const endpointPaths = readLines(endpointFile).map(event => event.path);
    const counts = reconcileObservations(entries, server, endpointPaths, { incomplete: scenario !== 'completed' });
    const headHash = entries.at(-1)?.entry_hash;
    return { scenario, streamId, headHash, counts, entries, server, endpointPaths, observations };
  } finally {
    clearTimeout(lifetime);
    if (!exited) { child.kill('SIGKILL'); await closed; }
    await new Promise(resolve => endpoint.close(resolve)); fs.closeSync(endpointFd);
    // Only this controller's UUID-named container is eligible for cleanup; evidence is retained.
    try { await command('docker', ['rm', '-f', containerName]); }
    catch (error) { if (!String(error.stderr).includes('No such container')) throw error; }
  }
}

export async function runPilot(output, { fault } = {}) {
  if (process.platform !== 'linux') throw new Error('contained pilot requires Linux and Docker');
  output = path.resolve(output);
  fs.mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 });
  fs.mkdirSync(output, { mode: 0o700 });
  const trustFile = `${output}.trust.json`;
  try {
    let image;
    try { image = JSON.parse(await command('docker', ['image', 'inspect', actorImage]))[0]; }
    catch { await command('docker', ['pull', actorImage], 120_000); image = JSON.parse(await command('docker', ['image', 'inspect', actorImage]))[0]; }
    const keys = { runtime: generateKeypair(), policy: generateKeypair() };
    const sourcePaths = [
      ...regularFiles(path.join(repo, 'packages/hushspec/src')), ...regularFiles(path.join(repo, 'packages/hushspec/dist')),
      ...regularFiles(path.join(repo, 'node_modules/yaml')), ...regularFiles(path.join(repo, 'scripts/mcp-pilot')),
      path.join(repo, 'scripts/run_mcp_pilot.mjs'), path.join(repo, 'package-lock.json'), path.join(repo, 'packages/hushspec/package.json'),
    ];
    const materials = [];
    for (const source of sourcePaths) {
      const relative = path.relative(repo, source).split(path.sep).join('/');
      const target = `materials/${relative}`; fs.mkdirSync(path.dirname(path.join(output, target)), { recursive: true, mode: 0o700 });
      const bytes = fs.readFileSync(source); writeDurable(path.join(output, target), bytes.toString('utf8'));
      materials.push({ ...artifact(output, target), source: relative });
    }
    const engineHash = engineMaterialDigest(materials);
    const scenarios = [];
    for (const scenario of ['completed', 'crash-before', 'crash-after']) {
      const run = await runScenario(output, scenario, keys, image, engineHash); scenarios.push(run);
      if (fault === 'counter' && scenario === 'completed') reconcileObservations(run.entries, run.server, []);
    }
    for (const material of materials) {
      if (digest(fs.readFileSync(path.join(repo, material.source))) !== material.sha256) throw new Error('executed source changed during pilot');
    }
    const complete = scenarios[0];
    const negativeChecks = [];
    const negative = (name, fn) => {
      let refused = false; let reason = '';
      try { fn(); } catch (error) { refused = true; reason = error.message; }
      if (!refused) throw new Error(`faulty observation accepted: ${name}`);
      negativeChecks.push({ name, refused, reason });
    };
    negative('flipped_counter', () => reconcileObservations(complete.entries, complete.server, []));
    negative('missing_server_terminal', () => reconcileObservations(complete.entries, complete.server.filter((_, i) => i !== 1), complete.endpointPaths));
    negative('foreign_call', () => { const changed = structuredClone(complete.server); changed[0].call_id = uuidV7(); reconcileObservations(complete.entries, changed, complete.endpointPaths); });
    negative('foreign_arguments', () => { const changed = structuredClone(complete.server); changed[0].arguments_hash = hashJson({ changed: true }); reconcileObservations(complete.entries, changed, complete.endpointPaths); });
    const substitute = { ...materials[0], sha256: `sha256:${'0'.repeat(64)}` };
    negative('substituted_source_digest', () => verifyArtifacts(output, [substitute]));
    const crashes = scenarios.slice(1).map(run => {
      let refused = false;
      try {
        verifyInvocationJournal(fs.readFileSync(path.join(output, run.scenario, 'journal/entries.jsonl'), 'utf8'), '{}',
          { runtimePublicKeyPem: keys.runtime.publicKeyPem, policyPublicKeyPem: keys.policy.publicKeyPem, expectedStreamId: run.streamId });
      } catch { refused = true; }
      if (!refused) throw new Error('crash packet accepted as complete');
      return { scenario: run.scenario, complete_verification_refused: refused, observed_dispatches: run.counts.dispatched };
    });
    const host = readJson(path.join(output, 'completed/host-result.json'));
    const result = { assertions: {
      actual_file_edit: complete.observations.note_after === digest(Buffer.from('export const answer = 42;\n// review-me\n')),
      direct_actor_routes_denied: Object.values(host.actor.probes).every(value => value === true),
      permits_match_server_calls: complete.counts.dispatched === 6, single_confirmation: host.prompts === 1,
    }, crashes, negative_checks: negativeChecks };
    if (!Object.values(result.assertions).every(Boolean)) throw new Error('pilot acceptance assertions failed');
    writeDurable(path.join(output, 'result.json'), result);
    const evidencePaths = ['result.json', ...scenarios.flatMap(run => {
      const names = ['repo-server.jsonl', 'other-server.jsonl', 'endpoint.jsonl', 'observations.json', 'container.json',
        'host-process.json', 'discovery.json', 'actor-command.json', 'journal/entries.jsonl'];
      if (run.scenario === 'completed') names.push('host-result.json', 'actor-transcript.json', 'actor-stderr.txt', 'journal/checkpoint.json');
      else names.push('crash-marker.json');
      return names.map(name => `${run.scenario}/${name}`);
    })];
    const body = { kind: 'hush.mcp-pilot.packet', format_version: '0.1.0', timestamp: new Date().toISOString(),
      source_sha: (await command('git', ['rev-parse', 'HEAD'])).trim(), dirty_source: (await command('git', ['status', '--porcelain'])).trim() !== '',
      ci: { run: process.env.GITHUB_RUN_ID ?? 'local', attempt: process.env.GITHUB_RUN_ATTEMPT ?? 'local', source: process.env.GITHUB_SHA ?? 'local' },
      environment: { node: process.version, platform: process.platform, architecture: process.arch },
      image: { reference: actorImage, id: image.Id, architecture: image.Architecture }, engine_sha256: engineHash, scenarios: scenarios.map(run => run.scenario),
      artifacts: [...materials.map(({ source: _source, ...record }) => record), ...evidencePaths.map(relative => artifact(output, relative))],
      limitations: ['Trusted host and signer assertions, not build attestation', 'Scripted first-party actor, not independent adoption',
        'No unrestricted host shell or third-party tools', 'No kernel escape or hardware power-loss claim', 'No independently authored engine qualified'],
    };
    writeDurable(path.join(output, 'manifest.json'), { ...body, signature: signContentHash(hashJson(body), keys.runtime.privateKeyPem, { signedAt: body.timestamp }) });
    writeDurable(trustFile, { runtimePublicKeyPem: keys.runtime.publicKeyPem, policyPublicKeyPem: keys.policy.publicKeyPem,
      manifestHash: hashJson(body), scenarios: Object.fromEntries(scenarios.map(run => [run.scenario,
        { expectedStreamId: run.streamId, expectedHeadHash: run.headHash }])) });
    return { output, trustFile, ...verifyPilotPacket(output, trustFile) };
  } catch (error) {
    writeDurable(path.join(output, 'failure.json'), { qualified: false, error: error.message, fault: fault ?? null });
    throw error;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  try {
    if (args.length === 4 && args[0] === '--verify' && args[2] === '--trust') console.log(JSON.stringify(verifyPilotPacket(path.resolve(args[1]), path.resolve(args[3])), null, 2));
    else if ((args.length === 2 || (args.length === 4 && args[2] === '--fault' && args[3] === 'counter')) && args[0] === '--output') {
      console.log(JSON.stringify(await runPilot(args[1], { fault: args[3] }), null, 2));
    } else throw new Error('usage: run_mcp_pilot.mjs --output FRESH_DIRECTORY [--fault counter] | --verify PACKET --trust TRUST_FILE');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
