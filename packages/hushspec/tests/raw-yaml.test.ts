import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parse, canonicalJson, contentHash, evaluate } from '../src/index.js';

const vectors = JSON.parse(readFileSync(new URL('../../../fixtures/core/raw-yaml/scalars.json', import.meta.url), 'utf8')) as Array<{
  id: string; yaml: string; accept: boolean; value_path?: string[];
  value?: unknown; canonical?: string; decision?: string;
}>;

describe('raw YAML Core scalar conformance', () => {
  for (const vector of vectors) it(vector.id, () => {
    // The JSON container preserves YAML spelling; never parse or re-emit it here.
    const result = parse(vector.yaml);
    expect(result.ok, JSON.stringify(result)).toBe(vector.accept);
    if (!result.ok) return;
    const canonical = canonicalJson(result.value);
    let value = JSON.parse(canonical);
    for (const key of vector.value_path!) value = value[key];
    expect(value).toEqual(vector.value);
    if (vector.canonical !== undefined) {
      expect(canonical).toBe(vector.canonical);
      expect(contentHash(result.value)).toBe(`sha256:${createHash('sha256').update(vector.canonical).digest('hex')}`);
    }
    if (vector.decision !== undefined) {
      expect(evaluate(result.value, { type: 'egress', target: 'example.com', context: { counters: { requests: 9 } } }).decision).toBe(vector.decision);
    }
  });
});
