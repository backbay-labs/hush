import fs from 'node:fs';
import path from 'node:path';
import { hashJson, verifyContentHash, verifyInvocationJournal, inspectInvocationJournal } from '../../packages/hushspec/dist/index.js';
import { actorImage, digest, readJson, readLines } from './io.mjs';

const requireThat = (condition, reason) => { if (!condition) throw new Error(reason); };
export function engineMaterialDigest(artifacts) {
  const selected = artifacts.filter(artifact => artifact.path.startsWith('materials/packages/hushspec/dist/') ||
    artifact.path.startsWith('materials/node_modules/yaml/')).map(({ path, bytes, sha256 }) => ({ path, bytes, sha256 }))
    .sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  for (const required of ['materials/packages/hushspec/dist/index.js', 'materials/packages/hushspec/dist/compiled.js',
    'materials/node_modules/yaml/package.json']) requireThat(selected.some(artifact => artifact.path === required), 'missing engine/parser material');
  return hashJson({ kind: 'hush.mcp-pilot.engine', artifacts: selected });
}
export function reconcileObservations(entries, observations, endpointPaths, { incomplete = false } = {}) {
  const attempts = new Map(); const permits = new Set(); const terminals = new Map();
  for (const { event } of entries) {
    if (event.type === 'attempt') attempts.set(event.call_id, event);
    if (event.type === 'permit') permits.add(event.call_id);
    if (event.type === 'terminal') terminals.set(event.call_id, event.outcome);
  }
  const received = new Map(); const finished = new Map(); const expectedPaths = [];
  for (const observation of observations) {
    const attempt = attempts.get(observation.call_id);
    requireThat(attempt && permits.has(observation.call_id), 'unpermitted or foreign server call');
    const target = `mcp:${observation.connection}/${encodeURIComponent(observation.tool)}`;
    requireThat(target === attempt.target && observation.arguments_hash === attempt.arguments_hash, 'server binding mismatch');
    if (observation.stage === 'received') {
      requireThat(!received.has(observation.call_id) && !finished.has(observation.call_id), 'duplicate server call');
      received.set(observation.call_id, observation);
      if (observation.tool === 'fetch') expectedPaths.push(new URL(attempt.arguments.url).pathname);
    } else {
      requireThat(['completed', 'error'].includes(observation.stage) && received.has(observation.call_id) &&
        !finished.has(observation.call_id), 'invalid server terminal');
      finished.set(observation.call_id, observation.stage);
    }
  }
  for (const callId of permits) {
    const terminal = terminals.get(callId);
    if (terminal === 'aborted_before_dispatch') requireThat(!received.has(callId), 'aborted call reached server');
    else if (!incomplete || terminal !== undefined) {
      requireThat(received.has(callId) && finished.has(callId), 'missing independent server outcome');
      requireThat(terminal === 'completed' ? finished.get(callId) === 'completed' : terminal === 'error', 'server/host outcome mismatch');
    }
  }
  requireThat(JSON.stringify(endpointPaths) === JSON.stringify(expectedPaths), 'endpoint request counter mismatch');
  return { dispatched: received.size, networkRequests: endpointPaths.length };
}

export function verifyArtifacts(directory, artifacts) {
  requireThat(Array.isArray(artifacts) && artifacts.length > 0 && artifacts.length <= 10_000, 'invalid artifact inventory');
  const seen = new Set(); let total = 0;
  for (const artifact of artifacts) {
    requireThat(artifact && typeof artifact.path === 'string' &&
      /^[A-Za-z0-9_-][A-Za-z0-9_.-]*(\/[A-Za-z0-9_-][A-Za-z0-9_.-]*)*$/.test(artifact.path) &&
      !artifact.path.split('/').some(part => part === '.' || part === '..') && !seen.has(artifact.path), 'unsafe/duplicate artifact path');
    seen.add(artifact.path);
    let current = directory;
    for (const part of artifact.path.split('/')) {
      current = path.join(current, part); requireThat(!fs.lstatSync(current).isSymbolicLink(), 'symlink packet member');
    }
    const stat = fs.statSync(current);
    requireThat(stat.isFile() && stat.size <= 67_108_864 && stat.size === artifact.bytes, 'artifact size/type mismatch');
    total += stat.size; requireThat(total <= 268_435_456, 'packet byte limit');
    requireThat(digest(fs.readFileSync(current)) === artifact.sha256, `artifact digest mismatch: ${artifact.path}`);
  }
}

export function verifyIsolation(inspect, imageId) {
  const host = inspect.HostConfig;
  requireThat(inspect.Image === imageId && inspect.Config.Image === actorImage, 'actor image differs from pinned artifact');
  requireThat(host.NetworkMode === 'none' && host.ReadonlyRootfs === true && host.Privileged === false &&
    inspect.Config.User === '65534:65534' && host.CapDrop?.includes('ALL') && (!host.CapAdd || host.CapAdd.length === 0) &&
    host.SecurityOpt?.includes('no-new-privileges') && host.PidsLimit === 64 && host.Memory === 134_217_728 &&
    (!host.PidMode || host.PidMode === 'private') && (!host.Devices || host.Devices.length === 0), 'actor isolation configuration mismatch');
  requireThat(inspect.Mounts.length === 1 && inspect.Mounts[0].Destination === '/agent.py' &&
    inspect.Mounts[0].Type === 'bind' && inspect.Mounts[0].RW === false &&
    Object.keys(host.Tmpfs ?? {}).length === 1 && typeof host.Tmpfs['/tmp'] === 'string' &&
    ['noexec', 'nosuid', 'size=16m'].every(part => host.Tmpfs['/tmp'].includes(part)), 'unexpected actor mounts');
}

/** Caller supplies an independently retained trust file, never a key selected from the packet. */
export function verifyPilotPacket(directory, trustFile) {
  const trust = readJson(trustFile, 65_536);
  const manifest = readJson(path.join(directory, 'manifest.json'));
  const { signature, ...body } = manifest;
  requireThat(body.kind === 'hush.mcp-pilot.packet' && body.format_version === '0.1.0' &&
    hashJson(body) === trust.manifestHash, 'packet identity mismatch');
  requireThat(verifyContentHash(signature, hashJson(body), { publicKeyPem: trust.runtimePublicKeyPem,
    now: body.timestamp }).ok, 'packet signature refused');
  verifyArtifacts(directory, body.artifacts);
  requireThat(body.engine_sha256 === engineMaterialDigest(body.artifacts), 'engine material identity mismatch');
  const declared = new Set(body.artifacts.map(artifact => artifact.path));
  const member = relative => { requireThat(declared.has(relative), 'unbound packet member'); return path.join(directory, relative); };
  const result = readJson(member('result.json'));
  requireThat(body.image.reference === actorImage && body.scenarios.join(',') === 'completed,crash-before,crash-after', 'unexpected pilot scenarios/image');
  const summaries = [];
  for (const scenario of body.scenarios) {
    const scenarioTrust = { ...trust.scenarios[scenario], runtimePublicKeyPem: trust.runtimePublicKeyPem,
      policyPublicKeyPem: trust.policyPublicKeyPem, lastSeenVersion: 1 };
    const entriesFile = member(`${scenario}/journal/entries.jsonl`);
    const entriesText = fs.readFileSync(entriesFile, 'utf8');
    const entries = readLines(entriesFile);
    requireThat(entries.filter(entry => entry.event.type === 'policy' && entry.event.status === 'accepted').every(entry =>
      entry.event.engine.artifact_sha256 === body.engine_sha256), 'policy snapshot engine identity mismatch');
    const observations = ['repo', 'other'].flatMap(connection => readLines(member(`${scenario}/${connection}-server.jsonl`))
      .map(event => ({ ...event, connection })));
    const endpoint = readLines(member(`${scenario}/endpoint.jsonl`)).map(event => event.path);
    const independent = readJson(member(`${scenario}/observations.json`));
    verifyIsolation(readJson(member(`${scenario}/container.json`)), body.image.id);
    const checked = scenario === 'completed' ? verifyInvocationJournal(entriesText,
      fs.readFileSync(member(`${scenario}/journal/checkpoint.json`), 'utf8'), scenarioTrust) : inspectInvocationJournal(entriesText, scenarioTrust);
    const reconciled = reconcileObservations(entries, observations, endpoint, { incomplete: scenario !== 'completed' });
    requireThat(independent.secret_before === independent.secret_after, 'protected file changed');
    if (scenario === 'completed') {
      requireThat(independent.note_after === digest(Buffer.from('export const answer = 42;\n// review-me\n')) &&
        independent.note_before === digest(Buffer.from('export const answer = 41;\n')), 'coding edit mismatch');
      const host = readJson(member(`${scenario}/host-result.json`));
      requireThat(host.exit.code === 0 && host.prompts === 1 && host.actor.workflow_completed === true &&
        ['direct_read_denied', 'direct_write_denied', 'direct_network_denied', 'shell_host_write_denied']
          .every(probe => host.actor.probes[probe] === true), 'actor workflow/bypass probe mismatch');
      const discovery = readJson(member(`${scenario}/discovery.json`));
      requireThat(discovery.discoveries.length === 2 && discovery.discoveries.every(d =>
        d._meta['io.modelcontextprotocol/serverInfo'].name === 'same-untrusted-display-name'), 'same-name server challenge missing');
      requireThat(reconciled.dispatched === 6 && reconciled.networkRequests === 2 && observations.every(o => o.connection === 'repo'), 'unexpected pilot side effects');
    } else {
      requireThat(checked.complete === false && checked.calls.filter(call => call.outcome === 'unknown').length === 1 &&
        !fs.existsSync(path.join(directory, scenario, 'journal/checkpoint.json')), 'crash outcome was filled or marked complete');
      requireThat(independent.host_signal === 'SIGKILL' && independent.marker.scenario === scenario, 'missing actual host crash');
      const changed = independent.note_before !== independent.note_after;
      requireThat(scenario === 'crash-before' ? !changed && reconciled.dispatched === 1 : changed && reconciled.dispatched === 2,
        'crash effect reconciliation mismatch');
    }
    summaries.push({ scenario, ...reconciled, complete: checked.complete });
  }
  requireThat(Object.values(result.assertions).every(value => value === true) &&
    result.crashes.length === 2 && result.crashes.every(crash => crash.complete_verification_refused) &&
    result.negative_checks.length >= 5 && result.negative_checks.every(check => check.refused), 'pilot acceptance result failed');
  return { qualified: true, sourceSha: body.source_sha, dirtySource: body.dirty_source, scenarios: summaries };
}
