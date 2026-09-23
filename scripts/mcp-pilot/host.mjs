import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { FileInvocationJournal, InvocationCoordinator, InvocationRegistry, OwnedMcpConnection,
  signPolicy, snapshotJson, typescriptInvocationEngine } from '../../packages/hushspec/dist/index.js';
import { extractRead, extractPatch, extractFetch } from './effects.mjs';
import { receiveLines, validateRequest, response, errorResponse, protocolVersion } from './protocol.mjs';
import { actorImage, writeDurable } from './io.mjs';

const config = snapshotJson(fs.readFileSync(0, 'utf8'), { maxBytes: 65_536 });
const directory = config.directory;
const serverPath = fileURLToPath(new URL('./server.mjs', import.meta.url));
const connections = [];
let actor;
let journal;
function crashMarker(callId) {
  writeDurable(path.join(directory, 'crash-marker.json'), { scenario: config.scenario, callId });
  // The controller observes the durable marker and SIGKILLs this actual host process.
  process.kill(process.pid, 'SIGSTOP');
}
try {
  for (const name of ['repo', 'other']) connections.push(new OwnedMcpConnection(process.execPath,
    [serverPath, '--root', path.join(directory, 'files'), '--audit', path.join(directory, `${name}-server.jsonl`), '--origin', config.origin], { timeoutMs: 4000 }));
  const discoveries = await Promise.all(connections.map(connection => connection.discover()));
  const catalogs = await Promise.all(connections.map(connection => connection.listTools()));
  writeDurable(path.join(directory, 'discovery.json'), { discoveries, catalogs });
  const bind = (connectionId, toolName, extract, connection) => ({ connectionId, toolName, extract,
    dispatch: async (args, context) => {
      const result = await connection.callTool(toolName, args, context);
      if (config.scenario === 'crash-after' && toolName === 'patch_file') crashMarker(context.callId);
      return result;
    } });
  const registry = new InvocationRegistry([
    bind('repo', 'read_file', extractRead, connections[0]),
    bind('repo', 'patch_file', extractPatch, connections[0]),
    bind('repo', 'fetch', args => extractFetch(args, config.origin), connections[0]),
    bind('other', 'read_file', extractRead, connections[1]),
  ]);
  journal = new FileInvocationJournal(path.join(directory, 'journal'), config.runtimePrivateKeyPem, { streamId: config.streamId });
  const sink = { append: event => {
    const ack = journal.append(event);
    if (config.scenario === 'crash-before' && event.type === 'permit' && event.target === 'mcp:repo/patch_file') crashMarker(event.call_id);
    return ack;
  }, close: () => journal.close() };
  const prompts = [];
  const coordinator = new InvocationCoordinator({ registry, journal: sink, policyPublicKeyPem: config.policyPublicKeyPem,
    engine: { prepare: resolution => {
      const prepared = typescriptInvocationEngine.prepare(resolution);
      return { ...prepared, identity: { ...prepared.identity, artifact_sha256: config.engineHash } };
    } },
    timeoutMs: 10_000, confirm: prompt => { prompts.push(prompt); return true; } });
  const policy = { hushspec: '1.0.0', name: 'owned-coding-pilot', metadata: { policy_version: 1 }, rules: {
    tool_access: { allow: ['mcp:repo/read_file', 'mcp:repo/fetch'], require_confirmation: ['mcp:repo/patch_file'], default: 'block' },
    forbidden_paths: { patterns: ['/workspace/secret.txt'] },
    path_allowlist: { enabled: true, read: ['/workspace/**'], write: ['/workspace/**'], patch: ['/workspace/**'] },
    secret_patterns: { patterns: [{ name: 'review', pattern: 'review-me', severity: 'warn' }] },
    patch_integrity: { max_additions: 20, max_deletions: 20 }, egress: { allow: ['127.0.0.1'], default: 'block' },
  } };
  coordinator.installPolicy(JSON.stringify(policy), signPolicy(policy, config.policyPrivateKeyPem));
  const aliases = { 'repo.read_file': ['repo', 'read_file'], 'repo.patch_file': ['repo', 'patch_file'],
    'network.fetch': ['repo', 'fetch'], 'other.read_file': ['other', 'read_file'] };
  const agentFile = fileURLToPath(new URL('./agent.py', import.meta.url));
  const dockerArgs = ['run', '--name', config.containerName, '-i', '--network=none', '--read-only', '--user=65534:65534',
    '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=64', '--memory=128m', '--cpus=1',
    '--tmpfs=/tmp:rw,noexec,nosuid,size=16m', '--mount', `type=bind,src=${agentFile},dst=/agent.py,readonly`,
    '--entrypoint=python', actorImage, '-I', '-B', '/agent.py', '--origin', config.origin,
    '--protected-path', path.join(directory, 'files', 'secret.txt')];
  writeDurable(path.join(directory, 'actor-command.json'), { executable: 'docker', args: dockerArgs });
  actor = spawn('docker', dockerArgs, { stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: process.env.PATH } });
  const transcript = []; const ids = new Set(); let busy = false; let stderr = ''; let failure;
  actor.stdin.on('error', error => { failure = error; });
  actor.stderr.on('data', chunk => { stderr += chunk.toString('utf8'); if (Buffer.byteLength(stderr) > 16_384) { failure = new Error('actor stderr limit'); actor.kill('SIGKILL'); } });
  receiveLines(actor.stdout, async request => {
    if (failure) return;
    const invalid = validateRequest(request);
    if (invalid !== undefined || ids.has(request.id) || ids.size >= 64 || busy) {
      errorResponse(request?.id, invalid ?? -32600, 'invalid actor request', actor.stdin); return;
    }
    ids.add(request.id); busy = true;
    try {
      if (request.method === 'tools/list') {
        response(request.id, { resultType: 'complete', tools: Object.keys(aliases).map(name => ({ name,
          inputSchema: { type: 'object' }, description: 'Host-owned pilot tool' })) }, actor.stdin); return;
      }
      if (request.method === 'server/discover') {
        response(request.id, { resultType: 'complete', supportedVersions: [protocolVersion], capabilities: { tools: {} } }, actor.stdin); return;
      }
      if (request.method !== 'tools/call') { errorResponse(request.id, -32601, 'method unavailable', actor.stdin); return; }
      const selected = Object.hasOwn(aliases, request.params.name) ? aliases[request.params.name] : ['unregistered', request.params.name];
      const result = await coordinator.invoke(selected[0], selected[1], JSON.stringify(request.params.arguments),
        { agent: { id: 'contained-scripted-coder' }, environment: { name: 'synthetic-pilot' } });
      transcript.push({ request, result });
      response(request.id, { resultType: 'complete', content: [], structuredContent: result, isError: result.status !== 'completed' }, actor.stdin);
    } finally { busy = false; }
  }, error => { failure = error; actor.kill('SIGKILL'); });
  const timer = setTimeout(() => { failure = new Error('actor lifetime deadline'); actor.kill('SIGKILL'); }, 30_000);
  const exit = await new Promise((resolve, reject) => { actor.once('error', reject); actor.once('close', (code, signal) => resolve({ code, signal })); });
  clearTimeout(timer);
  writeDurable(path.join(directory, 'actor-transcript.json'), transcript);
  writeDurable(path.join(directory, 'actor-stderr.txt'), stderr);
  if (failure || exit.code !== 0 || busy) throw failure ?? new Error(`actor failed: ${JSON.stringify(exit)}`);
  await Promise.all(connections.map(connection => connection.close()));
  coordinator.close();
  writeDurable(path.join(directory, 'host-result.json'), { prompts: prompts.length, exit, actor: JSON.parse(stderr) });
} catch (error) {
  writeDurable(path.join(directory, 'host-error.json'), { error: error instanceof Error ? error.message : 'host failed' });
  process.exitCode = 1;
} finally {
  if (actor && actor.exitCode === null) actor.kill('SIGKILL');
  await Promise.all(connections.map(connection => connection.close()));
  if (journal) journal.dispose();
}
