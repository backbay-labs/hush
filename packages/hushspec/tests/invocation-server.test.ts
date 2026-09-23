import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import * as api from '../src/index.js';

const cleanups: (() => Promise<void> | void)[] = [];
afterEach(async () => { for (const fn of cleanups.splice(0).reverse()) await fn(); });
const serverFile = fileURLToPath(new URL('../../../scripts/mcp-pilot/server.mjs', import.meta.url));
async function setup() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hush-mcp-server-'));
  cleanups.push(() => fs.rmSync(root, { recursive: true }));
  const files = path.join(root, 'files'); fs.mkdirSync(files);
  fs.writeFileSync(path.join(files, 'note.txt'), 'hello\n');
  fs.writeFileSync(path.join(root, 'secret'), 'protected');
  fs.symlinkSync(path.join(root, 'secret'), path.join(files, 'symlink'));
  fs.linkSync(path.join(root, 'secret'), path.join(files, 'hardlink'));
  const requests: string[] = [];
  const endpoint = http.createServer((req, res) => {
    requests.push(req.url!);
    if (req.url === '/redirect') { res.writeHead(302, { location: '/elsewhere' }); res.end(); }
    else res.end('controlled response');
  });
  await new Promise<void>(resolve => endpoint.listen(0, '127.0.0.1', resolve));
  cleanups.push(() => new Promise<void>(resolve => endpoint.close(() => resolve())));
  const origin = `http://127.0.0.1:${(endpoint.address() as any).port}`;
  const audit = path.join(root, 'server.jsonl');
  const c = new api.OwnedMcpConnection(process.execPath, [serverFile, '--root', files, '--audit', audit, '--origin', origin], { timeoutMs: 2000 });
  cleanups.push(() => c.close());
  return { root, files, audit, origin, requests, c };
}
describe.skipIf(process.platform !== 'linux')('owned Linux effect server', () => {
  it('reads and patches a real file and independently records host call IDs', async () => {
    const h = await setup();
    expect((await h.c.listTools()).tools.map((tool: any) => tool.name)).toContain('patch_file');
    const read = await h.c.callTool('read_file', { path: 'note.txt' }, { callId: 'read-id' });
    expect(read.structuredContent).toEqual({ content: 'hello\n' });
    await h.c.callTool('patch_file', { path: 'note.txt', before: 'hello\n', after: 'hello world\n' }, { callId: 'patch-id' });
    expect(fs.readFileSync(path.join(h.files, 'note.txt'), 'utf8')).toBe('hello world\n');
    const audit = fs.readFileSync(h.audit, 'utf8').trim().split('\n').map(line => JSON.parse(line));
    expect(audit.map(e => [e.stage, e.call_id])).toEqual([
      ['received', 'read-id'], ['completed', 'read-id'], ['received', 'patch-id'], ['completed', 'patch-id']]);
  });
  it.each(['../secret', '/etc/passwd', 'symlink', 'hardlink'])('refuses unsafe file %s', async name => {
    const h = await setup();
    await expect(h.c.callTool('read_file', { path: name }, { callId: 'denied' })).rejects.toThrow();
    expect(fs.readFileSync(path.join(h.root, 'secret'), 'utf8')).toBe('protected');
  });
  it('refuses stale content without modifying the current file', async () => {
    const h = await setup();
    await expect(h.c.callTool('patch_file', { path: 'note.txt', before: 'wrong', after: 'changed' }, { callId: 'stale' })).rejects.toThrow();
    expect(fs.readFileSync(path.join(h.files, 'note.txt'), 'utf8')).toBe('hello\n');
  });
  it('uses only the pinned HTTP origin and never follows redirects', async () => {
    const h = await setup();
    expect((await h.c.callTool('fetch', { url: `${h.origin}/ok` }, { callId: 'ok' })).structuredContent.body).toBe('controlled response');
    await expect(h.c.callTool('fetch', { url: `${h.origin}/redirect` }, { callId: 'redirect' })).rejects.toThrow();
    for (const url of [`${h.origin}/ok?x=1`, `${h.origin}/ok#x`, `${h.origin.replace('127.0.0.1', 'localhost')}/ok`, 'https://example.com/']) {
      await expect(h.c.callTool('fetch', { url }, { callId: 'outside' })).rejects.toThrow();
    }
    expect(h.requests).toEqual(['/ok', '/redirect']);
  });
  it('derives read, write and full replacement patch effects from identical arguments', async () => {
    const effects = await import('../../../scripts/mcp-pilot/effects.mjs');
    const plan = effects.extractPatch({ path: 'note.txt', before: 'hello\n', after: 'hello world\n' });
    expect(plan).toEqual([
      { type: 'file_read', target: '/workspace/note.txt' },
      { type: 'file_write', target: '/workspace/note.txt', content: 'hello world\n' },
      { type: 'patch_apply', target: '/workspace/note.txt', content: '--- a/note.txt\n+++ b/note.txt\n@@ -1,1 +1,1 @@\n-hello\n+hello world\n' },
    ]);
  });
  it('discovers the pinned protocol with display-only metadata', async () => {
    const h = await setup();
    const discovered = await h.c.discover();
    expect(discovered.supportedVersions).toEqual(['2026-07-28']);
    expect(discovered._meta['io.modelcontextprotocol/serverInfo'].name).toBe('same-untrusted-display-name');
  });
  it('distinguishes missing metadata from unsupported versions and accepts opaque string request IDs', async () => {
    const { validateRequest } = await import('../../../scripts/mcp-pilot/protocol.mjs');
    const request = { jsonrpc: '2.0', id: 'opaque-client-id', method: 'tools/list', params: { _meta: {
      'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {},
    } } };
    expect(validateRequest(request)).toBeUndefined();
    expect(validateRequest({ ...request, params: { _meta: { 'io.modelcontextprotocol/clientCapabilities': {} } } })).toBe(-32602);
    request.params._meta['io.modelcontextprotocol/protocolVersion'] = '2025-11-25';
    expect(validateRequest(request)).toBe(-32022);
  });
});
