import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { snapshotJson } from '../../packages/hushspec/dist/index.js';

export const actorImage = 'python@sha256:da047cb8f9d1d98e5c070f5300ba9f7274e33b8fc0e5be5ed88740aed1b95ba9';
export function digest(bytes) { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }
export function writeDurable(file, value) {
  const fd = fs.openSync(file, 'wx', 0o600);
  try {
    const bytes = Buffer.from(typeof value === 'string' ? value : JSON.stringify(value, null, 2) + '\n');
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.writeSync(fd, bytes, offset, bytes.length - offset);
      if (count <= 0) throw new Error('artifact write made no progress'); offset += count;
    }
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  const directory = fs.openSync(path.dirname(file), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
}
export function readJson(file, limit = 8_388_608) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.size > limit) throw new Error('unsafe or oversized packet member');
  return snapshotJson(fs.readFileSync(file, 'utf8'), { maxBytes: limit, maxDepth: 56, maxNodes: 180_000 });
}
export function readLines(file) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.size > 67_108_864) throw new Error('unsafe or oversized observation');
  const text = fs.readFileSync(file, 'utf8');
  if (text && !text.endsWith('\n')) throw new Error('incomplete observation line');
  return text ? text.slice(0, -1).split('\n').map(line => snapshotJson(line,
    { maxBytes: 2_097_152, maxDepth: 56, maxNodes: 180_000 })) : [];
}
