import { afterEach, describe, expect, it } from 'vitest';
import * as api from '../src/index.js';

const connections: any[] = [];
afterEach(async () => { await Promise.all(connections.splice(0).map(c => c.close())); });
function connection(body: string, options = {}) {
  const c = new api.OwnedMcpConnection(process.execPath, ['-e',
    `const readline=require('node:readline'); const r=readline.createInterface({input:process.stdin});
     r.on('line', line => { const request=JSON.parse(line); ${body} });`], { timeoutMs: 200, ...options });
  connections.push(c); return c;
}
describe('owned MCP stdio connection', () => {
  it('exports the bounded transport', () => { expect(api.OwnedMcpConnection).toBeTypeOf('function'); });
  it('binds each request to current protocol metadata and host call identity', async () => {
    const c = connection(String.raw`process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:request.id,result:{resultType:'complete',content:[],structuredContent:request.params}})+'\n');`);
    const response = await c.callTool('read_file', { path: 'note.txt' }, { callId: 'host-owned-id' });
    expect(response.structuredContent).toMatchObject({ name: 'read_file', arguments: { path: 'note.txt' }, _meta: {
      'io.modelcontextprotocol/protocolVersion': '2026-07-28',
      'io.modelcontextprotocol/clientCapabilities': {}, 'dev.hushspec/callId': 'host-owned-id',
    } });
  });
  it.each(['foreign-id', 'duplicate-id', 'oversize', 'invalid-json', 'invalid-utf8', 'early-exit', 'timeout', 'stderr-limit'])
  ('fails closed and stops reuse after %s', async failure => {
    const bodies: Record<string, string> = {
      'foreign-id': String.raw`process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:999,result:{}})+'\n');`,
      'duplicate-id': String.raw`const out=JSON.stringify({jsonrpc:'2.0',id:request.id,result:{resultType:'complete',content:[]}})+'\n'; process.stdout.write(out+out);`,
      'oversize': `process.stdout.write('x'.repeat(600000));`,
      'invalid-json': String.raw`process.stdout.write('{bad}\n');`,
      'invalid-utf8': `process.stdout.write(Buffer.from([255,10]));`,
      'early-exit': `process.exit(3);`,
      'timeout': ``,
      'stderr-limit': `process.stderr.write('x'.repeat(20000));`,
    };
    const c = connection(bodies[failure]);
    if (failure === 'duplicate-id') {
      // The first response may already have settled; the duplicate poisons subsequent admission.
      await c.callTool('x', {}, { callId: 'host' }).catch(() => {});
    } else {
      const reasons: Record<string, RegExp> = { 'foreign-id': /foreign/, oversize: /limit/,
        'invalid-json': /JSON/, 'invalid-utf8': /encoded|encoding|UTF/i,
        'early-exit': /exited/, timeout: /deadline/, 'stderr-limit': /stderr/ };
      await expect(c.callTool('x', {}, { callId: 'host' })).rejects.toThrow(reasons[failure]);
    }
    await expect(c.callTool('x', {}, { callId: 'next' })).rejects.toThrow();
  });
  it('treats tool isError as failure rather than successful invocation output', async () => {
    const c = connection(String.raw`process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:request.id,result:{resultType:'complete',content:[],isError:true}})+'\n');`);
    await expect(c.callTool('x', {}, { callId: 'host' })).rejects.toThrow(/tool/);
  });
  it('closes children that ignore stdin EOF and bounds in-flight requests', async () => {
    const c = connection(`setInterval(()=>{},1000);`, { timeoutMs: 1000 });
    const pending = Array.from({ length: 16 }, () => c.callTool('x', {}, { callId: 'host' }).catch(() => {}));
    await expect(c.callTool('x', {}, { callId: 'excess' })).rejects.toThrow(/pending/);
    await c.close(); await Promise.all(pending);
    await expect(c.listTools()).rejects.toThrow(/closed|unavailable/);
  });
});
