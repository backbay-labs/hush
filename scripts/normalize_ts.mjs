#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const distEntry = path.join(root, 'packages', 'hushspec', 'dist', 'index.js');
const { canonicalJson, parseOrThrow } = await import(distEntry);

if (process.argv.length !== 3) {
  console.error('usage: normalize_ts.mjs <path>');
  process.exit(2);
}

const filePath = process.argv[2];
const spec = parseOrThrow(readFileSync(filePath, 'utf8'));
// The document's own canonical form: `extends` and `merge_strategy` are
// resolution instructions, not policy (canonical spec 3).
const own = { ...spec, extends: undefined, merge_strategy: undefined };
process.stdout.write(`${canonicalJson(own)}\n`);
