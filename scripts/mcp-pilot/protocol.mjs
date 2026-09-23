import { TextDecoder } from 'node:util';
import { snapshotJson } from '../../packages/hushspec/dist/index.js';

export const protocolVersion = '2026-07-28';
export function receiveLines(stream, onValue, onError) {
  let buffer = Buffer.alloc(0); let bytes = 0; let failed = false;
  const fail = error => { if (!failed) { failed = true; onError(error); } };
  stream.on('data', chunk => {
    if (failed) return;
    try {
      bytes += chunk.length;
      if (bytes > 4_194_304 || buffer.length + chunk.length > 262_144) throw new Error('input limit');
      buffer = Buffer.concat([buffer, chunk]);
      for (;;) {
        const end = buffer.indexOf(10);
        if (end < 0) { if (buffer.length > 131_072) throw new Error('frame limit'); break; }
        if (end > 131_072) throw new Error('frame limit');
        const text = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, end));
        buffer = buffer.subarray(end + 1);
        const value = snapshotJson(text, { maxBytes: 131_072, maxDepth: 24, maxNodes: 20_000 });
        Promise.resolve(onValue(value)).catch(fail);
      }
    } catch (error) { fail(error); }
  });
  stream.on('error', fail);
  stream.on('end', () => { if (buffer.length) fail(new Error('truncated frame')); });
}
export function validateRequest(request) {
  if (!request || typeof request !== 'object' || request.jsonrpc !== '2.0' ||
      !validId(request.id) || typeof request.method !== 'string' ||
      !request.params || typeof request.params !== 'object' || Array.isArray(request.params) ||
      Object.keys(request).some(key => !['jsonrpc', 'id', 'method', 'params'].includes(key))) return -32600;
  const meta = request.params._meta;
  if (!meta || typeof meta !== 'object' || !Object.hasOwn(meta, 'io.modelcontextprotocol/protocolVersion') ||
      !Object.hasOwn(meta, 'io.modelcontextprotocol/clientCapabilities') ||
      !meta['io.modelcontextprotocol/clientCapabilities'] || typeof meta['io.modelcontextprotocol/clientCapabilities'] !== 'object' ||
      Array.isArray(meta['io.modelcontextprotocol/clientCapabilities'])) return -32602;
  if (meta['io.modelcontextprotocol/protocolVersion'] !== protocolVersion) return -32022;
  return undefined;
}
export function response(id, result) {
  const frame = JSON.stringify({ jsonrpc: '2.0', id, result: { ...result, _meta: {
    'io.modelcontextprotocol/serverInfo': { name: 'same-untrusted-display-name', version: '1' },
  } } }) + '\n';
  if (Buffer.byteLength(frame) > 524_288) throw new Error('response frame limit');
  process.stdout.write(frame);
}
export function errorResponse(id, code, message) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: validId(id) ? id : null, error: { code, message } }) + '\n');
}
function validId(id) { return Number.isSafeInteger(id) || (typeof id === 'string' && Buffer.byteLength(id) <= 128); }
