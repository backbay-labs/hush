import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { TextDecoder } from 'node:util';
import { hashJson } from '../../packages/hushspec/dist/index.js';
import { basename, extractRead, extractPatch, extractFetch, pinnedOrigin } from './effects.mjs';
import { receiveLines, validateRequest, response, errorResponse, protocolVersion } from './protocol.mjs';

if (process.platform !== 'linux') throw new Error('owned file server requires Linux');
const argv = process.argv.slice(2);
const config = Object.fromEntries(Array.from({ length: argv.length / 2 }, (_, i) => [argv[i * 2], argv[i * 2 + 1]]));
if (argv.length !== 6 || !config['--root'] || !config['--audit'] || !config['--origin']) throw new Error('expected root, audit, origin');
const origin = pinnedOrigin(config['--origin']);
const root = fs.openSync(config['--root'], fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
const audit = fs.openSync(config['--audit'], 'wx', 0o600);
fs.fsyncSync(audit);
const parent = fs.openSync(path.dirname(config['--audit']), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
fs.fsyncSync(parent); fs.closeSync(parent);
function record(event) {
  const bytes = Buffer.from(JSON.stringify(event) + '\n');
  let offset = 0;
  while (offset < bytes.length) {
    const count = fs.writeSync(audit, bytes, offset, bytes.length - offset);
    if (count <= 0) throw new Error('audit write failed'); offset += count;
  }
  fs.fsyncSync(audit);
}
function openFile(name, write) {
  const fd = fs.openSync(`/proc/self/fd/${root}/${basename(name)}`,
    (write ? fs.constants.O_RDWR : fs.constants.O_RDONLY) | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > 65_536) throw new Error('unsafe file');
    return fd;
  } catch (error) { fs.closeSync(fd); throw error; }
}
function readContent(fd) {
  const buffer = Buffer.alloc(65_537);
  const count = fs.readSync(fd, buffer, 0, buffer.length, 0);
  if (count > 65_536) throw new Error('file byte limit');
  return new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, count));
}
function fetchOwned(url) {
  return new Promise((resolve, reject) => {
    const request = http.get(url, { agent: false }, res => {
      if (res.statusCode !== 200) { res.destroy(); reject(new Error('redirect or non-success HTTP response')); return; }
      let bytes = 0; const chunks = [];
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > 65_536) { res.destroy(new Error('HTTP response byte limit')); return; }
        chunks.push(chunk);
      });
      res.on('error', reject);
      res.on('end', () => {
        try { resolve({ status: 200, body: new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)) }); }
        catch (error) { reject(error); }
      });
    });
    const timer = setTimeout(() => request.destroy(new Error('HTTP deadline')), 2000);
    request.on('close', () => clearTimeout(timer)); request.on('error', reject);
  });
}
const tools = [
  { name: 'read_file', description: 'Read an owned file', inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'], additionalProperties: false } },
  { name: 'patch_file', description: 'Replace exact old content', inputSchema: { type: 'object', properties: { path: { type: 'string' }, before: { type: 'string' }, after: { type: 'string' } }, required: ['path', 'before', 'after'], additionalProperties: false } },
  { name: 'fetch', description: 'Request the owned test endpoint', inputSchema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'], additionalProperties: false } },
].map(tool => ({ ...tool, annotations: { readOnlyHint: true, destructiveHint: false } }));
const seen = new Set(); const callIds = new Set(); let pending = 0;
receiveLines(process.stdin, async request => {
  const invalid = validateRequest(request);
  if (invalid !== undefined) { errorResponse(request?.id, invalid, 'invalid owned MCP request'); return; }
  if (seen.has(request.id) || seen.size >= 2000 || pending >= 16) { errorResponse(request.id, -32600, 'request replay or limit'); return; }
  seen.add(request.id); pending++;
  try {
    if (request.method === 'tools/list') { response(request.id, { resultType: 'complete', tools }); return; }
    if (request.method === 'server/discover') {
      response(request.id, { resultType: 'complete', supportedVersions: [protocolVersion], capabilities: { tools: {} } }); return;
    }
    if (request.method !== 'tools/call') { errorResponse(request.id, -32601, 'method not supported'); return; }
    const callId = request.params._meta['dev.hushspec/callId'];
    if (typeof callId !== 'string' || !callId || Buffer.byteLength(callId) > 128 || callIds.has(callId)) {
      errorResponse(request.id, -32602, 'host call identity required'); return;
    }
    callIds.add(callId);
    const args = request.params.arguments; const tool = request.params.name;
    const event = { call_id: callId, tool, arguments_hash: hashJson(args) };
    record({ stage: 'received', ...event });
    try {
      let output;
      if (tool === 'read_file') {
        extractRead(args); const fd = openFile(args.path, false);
        try { output = { content: readContent(fd) }; } finally { fs.closeSync(fd); }
      } else if (tool === 'patch_file') {
        extractPatch(args); const fd = openFile(args.path, true);
        try {
          if (readContent(fd) !== args.before) throw new Error('stale file content');
          const bytes = Buffer.from(args.after); let offset = 0;
          while (offset < bytes.length) {
            const count = fs.writeSync(fd, bytes, offset, bytes.length - offset, offset);
            if (count <= 0) throw new Error('partial file write'); offset += count;
          }
          fs.ftruncateSync(fd, bytes.length); fs.fsyncSync(fd); output = { written: bytes.length };
        } finally { fs.closeSync(fd); }
      } else if (tool === 'fetch') { extractFetch(args, origin); output = await fetchOwned(args.url); }
      else throw new Error('unknown tool');
      record({ stage: 'completed', ...event, result_hash: hashJson(output) });
      response(request.id, { resultType: 'complete', content: [], structuredContent: output });
    } catch {
      record({ stage: 'error', ...event });
      response(request.id, { resultType: 'complete', content: [{ type: 'text', text: 'owned tool refused or failed; partial effect possible' }], isError: true });
    }
  } finally { pending--; }
}, () => { process.exitCode = 1; process.stdin.destroy(); });
process.stdin.on('end', () => { if (pending === 0) { fs.closeSync(root); fs.closeSync(audit); } });
