import { canonicalizeValue } from '../../packages/hushspec/dist/index.js';

export function exactArguments(args, fields) {
  if (!args || typeof args !== 'object' || Array.isArray(args) ||
      Object.keys(args).length !== fields.length || fields.some(key => !Object.hasOwn(args, key)) ||
      Buffer.byteLength(canonicalizeValue(args)) > 65_536) throw new Error('invalid tool arguments');
}
export function basename(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value)) throw new Error('unsafe file name');
  return value;
}
export function extractRead(args) {
  exactArguments(args, ['path']);
  return [{ type: 'file_read', target: `/workspace/${basename(args.path)}` }];
}
function lines(content, prefix) {
  if (content === '') return [];
  const values = content.split('\n');
  if (content.endsWith('\n')) values.pop();
  return values.map(line => prefix + line);
}
export function extractPatch(args) {
  exactArguments(args, ['path', 'before', 'after']);
  const name = basename(args.path);
  if (typeof args.before !== 'string' || typeof args.after !== 'string' ||
      Buffer.byteLength(args.before) > 65_536 || Buffer.byteLength(args.after) > 65_536) throw new Error('invalid patch content');
  const before = lines(args.before, '-'); const after = lines(args.after, '+');
  const diff = [`--- a/${name}`, `+++ b/${name}`, `@@ -1,${before.length} +1,${after.length} @@`, ...before,
    ...(args.before && !args.before.endsWith('\n') ? ['\\ No newline at end of file'] : []), ...after,
    ...(args.after && !args.after.endsWith('\n') ? ['\\ No newline at end of file'] : [])].join('\n') + '\n';
  return [{ type: 'file_read', target: `/workspace/${name}` },
    { type: 'file_write', target: `/workspace/${name}`, content: args.after },
    { type: 'patch_apply', target: `/workspace/${name}`, content: diff }];
}
export function pinnedOrigin(origin) {
  const parsed = new URL(origin);
  if (parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1' || !parsed.port ||
      parsed.origin !== origin) throw new Error('pilot requires a canonical pinned loopback origin');
  return origin;
}
export function extractFetch(args, origin) {
  exactArguments(args, ['url']); pinnedOrigin(origin);
  if (args.url !== `${origin}/ok` && args.url !== `${origin}/redirect`) throw new Error('URL outside owned endpoint');
  return [{ type: 'egress', target: '127.0.0.1', url: args.url }];
}
