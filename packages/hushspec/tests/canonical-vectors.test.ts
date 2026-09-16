import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import { describe, expect, it } from 'vitest';
import {
  CANONICAL_SCHEMA_TABLE,
  CanonicalError,
  canonicalJson,
  canonicalizeValue,
  contentHash,
  type PropertySchema,
  type SchemaNode,
} from '../src/canonical.js';
import { createBuiltinLoader, resolve } from '../src/resolve.js';
import { validate } from '../src/validate.js';
import type { HushSpec } from '../src/schema.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const vectorsDir = path.join(repoRoot, 'fixtures', 'core', 'hash');
const schemasDir = path.join(repoRoot, 'schemas');

/** `schemas/hushspec-hash-vector.v1.schema.json`. */
interface HashVector {
  hushspec_hash_vector: string;
  description: string;
  source?: Record<string, unknown>;
  policy: HushSpec;
  canonical: string;
  content_hash: string;
}

const VECTOR_VERSION = '0.1.0';

function loadVector(file: string): HashVector {
  const text = readFileSync(path.join(vectorsDir, file), 'utf8');
  // The HushSpec YAML profile (core spec 2.4): YAML 1.2 Core, so `on` is a
  // string key and `yes`/`no` are strings.
  return YAML.parse(text, { version: '1.2' }) as HashVector;
}

const vectorFiles = readdirSync(vectorsDir)
  .filter((name) => name.endsWith('.yaml'))
  .sort();

/**
 * Vectors carry an already-resolved `policy` (the schema says so, and `source`
 * holds the unresolved original for the `extends` vector). Resolving anyway
 * keeps the runner honest if a future vector ships an `extends` chain the
 * builtin loader can serve.
 */
function resolvedPolicy(vector: HashVector): HushSpec {
  if (vector.policy.extends == null) {
    return vector.policy;
  }
  const result = resolve(vector.policy, { load: createBuiltinLoader() });
  if (!result.ok) {
    throw new Error(`could not resolve vector policy: ${result.error}`);
  }
  return result.value;
}

/** A readable pointer at the first byte where two canonical strings part. */
function describeDifference(actual: string, expected: string): string {
  let index = 0;
  while (index < actual.length && index < expected.length && actual[index] === expected[index]) {
    index += 1;
  }
  const start = Math.max(0, index - 70);
  const window = (text: string): string =>
    `${start > 0 ? '...' : ''}${text.slice(start, index + 70)}${index + 70 < text.length ? '...' : ''}`;
  return [
    `canonical JSON differs at index ${index} (expected ${expected.length} chars, got ${actual.length})`,
    `  expected: ${window(expected)}`,
    `  actual:   ${window(actual)}`,
  ].join('\n');
}

describe('canonical form vectors (spec/hushspec-canonical.md section 7)', () => {
  it('finds the full vector set', () => {
    expect(vectorFiles.length).toBe(14);
  });

  for (const file of vectorFiles) {
    it(`${file} produces the vector's canonical form and content hash`, () => {
      const vector = loadVector(file);
      expect(vector.hushspec_hash_vector).toBe(VECTOR_VERSION);

      const policy = resolvedPolicy(vector);
      // Only valid documents have a canonical form (spec section 2.3): a
      // vector no conformant engine accepts would pin an unreachable hash.
      const validation = validate(policy);
      expect(validation.errors, `${file}: vector policy is not valid`).toEqual([]);

      const canonical = canonicalJson(policy);
      if (canonical !== vector.canonical) {
        throw new Error(`${file}: ${describeDifference(canonical, vector.canonical)}`);
      }
      expect(contentHash(policy)).toBe(vector.content_hash);
      expect(vector.content_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    });
  }
});

describe('canonicalJson', () => {
  it('refuses an unresolved document (section 2.1)', () => {
    expect(() => canonicalJson({ hushspec: '0.1.0', extends: 'builtin:default' })).toThrow(
      CanonicalError,
    );
    expect(() => contentHash({ hushspec: '0.1.0', extends: 'builtin:default' })).toThrow(
      /unresolved/,
    );
  });

  it('never emits merge_strategy, even when written (section 3.1)', () => {
    expect(canonicalJson({ hushspec: '0.1.0', merge_strategy: 'replace' })).toBe(
      '{"hushspec":"0.1.0"}',
    );
    expect(canonicalJson({ hushspec: '0.1.0' })).toBe('{"hushspec":"0.1.0"}');
  });

  it('strips an inline metadata signature (section 3.1)', () => {
    const signed = {
      hushspec: '0.1.0',
      metadata: { author: 'a@example.com', signature: 'base64url...' },
    } as unknown as HushSpec;
    expect(canonicalJson(signed)).toBe(
      '{"hushspec":"0.1.0","metadata":{"author":"a@example.com"}}',
    );
  });

  it('treats undefined properties as absent', () => {
    expect(canonicalJson({ hushspec: '0.1.0', name: undefined, rules: undefined })).toBe(
      '{"hushspec":"0.1.0"}',
    );
  });

  it('hashes the canonical bytes with the sha256: wire prefix (section 5)', () => {
    expect(contentHash({ hushspec: '0.1.0' })).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  // Section 4.3: an integer outside the IEEE 754 safe range must be refused,
  // never silently rounded. The same literal is refused by the Rust, Python
  // and Go suites; it arrives here already rounded to 2^53, which is itself
  // outside the safe range, so the refusal still lands.
  it('refuses an integer beyond the safe range (section 4.3)', () => {
    const document = {
      hushspec: '0.1.0',
      extensions: {
        posture: {
          initial: 'normal',
          states: { normal: { budgets: { tool_calls: 9007199254740993 } } },
          transitions: [],
        },
      },
    } as unknown as HushSpec;
    expect(() => canonicalJson(document)).toThrow(CanonicalError);
    expect(() => canonicalJson(document)).toThrow(/exceeds the safe range/);

    expect(() => canonicalizeValue({ budget: 9007199254740993 })).toThrow(
      /integer 9007199254740992 exceeds the safe range \(2\^53-1\)/,
    );
    expect(() => canonicalizeValue({ budget: -9007199254740993 })).toThrow(
      /exceeds the safe range/,
    );
  });

  it('keeps every integer inside the safe range', () => {
    expect(canonicalizeValue({ budget: 9007199254740991 })).toBe('{"budget":9007199254740991}');
    expect(canonicalizeValue({ budget: -9007199254740991 })).toBe('{"budget":-9007199254740991}');
    expect(canonicalizeValue({ ratio: 0.35 })).toBe('{"ratio":0.35}');
  });
});

// ---------------------------------------------------------------------------
// Drift guard: the projection table in src/canonical.ts against schemas/
// ---------------------------------------------------------------------------

type JsonSchema = Record<string, unknown>;

function loadSchema(name: string): JsonSchema {
  return JSON.parse(readFileSync(path.join(schemasDir, name), 'utf8')) as JsonSchema;
}

function deref(root: JsonSchema, node: JsonSchema): { schema: JsonSchema; name: string | null } {
  const ref = node['$ref'];
  if (typeof ref !== 'string') {
    return { schema: node, name: null };
  }
  if (!ref.startsWith('#/$defs/')) {
    throw new Error(`unsupported $ref ${ref}`);
  }
  const defName = ref.slice('#/$defs/'.length);
  const defs = root['$defs'] as Record<string, JsonSchema> | undefined;
  const target = defs?.[defName];
  if (target == null) {
    throw new Error(`missing $defs/${defName}`);
  }
  const inner = deref(root, target);
  return { schema: inner.schema, name: inner.name ?? defName };
}

function unwrapLazy(node: SchemaNode): SchemaNode {
  let current = node;
  while (current.kind === 'lazy') {
    current = current.get();
  }
  return current;
}

/**
 * Walk the hand-written table alongside the published schema.
 *
 * Tolerant in exactly one direction: a schema property the table does not know
 * about is fine *if it has no `default`*, because the projection passes
 * unknown keys through verbatim and a default-less property is emitted exactly
 * as written either way. A property that gains a `default`, changes one, or
 * changes `required` must be transcribed into the table, and fails here until
 * it is.
 */
function checkNode(
  table: SchemaNode,
  schemaRoot: JsonSchema,
  schemaNode: JsonSchema,
  label: string,
  seen: Map<SchemaNode, Set<string>>,
  errors: string[],
): void {
  const node = unwrapLazy(table);
  const { schema, name } = deref(schemaRoot, schemaNode);

  const key = name ?? label;
  const visited = seen.get(node);
  if (visited?.has(key)) return;
  if (visited) {
    visited.add(key);
  } else {
    seen.set(node, new Set([key]));
  }

  const properties = schema['properties'] as Record<string, JsonSchema> | undefined;
  const additional = schema['additionalProperties'];

  if (node.kind === 'object') {
    if (properties == null) {
      errors.push(`${label}: table says object, schema has no properties`);
      return;
    }
    const tableRequired = [...(node.required ?? [])].sort();
    const schemaRequired = [...((schema['required'] as string[] | undefined) ?? [])].sort();
    if (tableRequired.join(',') !== schemaRequired.join(',')) {
      errors.push(
        `${label}: required mismatch; table [${tableRequired}] vs schema [${schemaRequired}]`,
      );
    }
    for (const [propName, propSchema] of Object.entries(properties)) {
      const entry: PropertySchema | undefined = node.properties[propName];
      const schemaDefault = Object.prototype.hasOwnProperty.call(propSchema, 'default')
        ? propSchema['default']
        : undefined;
      if (entry == null) {
        if (schemaDefault !== undefined) {
          errors.push(`${label}.${propName}: schema declares a default, table is missing it`);
        }
        continue;
      }
      if (JSON.stringify(entry.default ?? null) !== JSON.stringify(schemaDefault ?? null)) {
        errors.push(
          `${label}.${propName}: default mismatch; table ${JSON.stringify(entry.default)} vs schema ${JSON.stringify(schemaDefault)}`,
        );
      }
      checkNode(entry.schema, schemaRoot, propSchema, `${label}.${propName}`, seen, errors);
    }
    for (const propName of Object.keys(node.properties)) {
      if (!Object.prototype.hasOwnProperty.call(properties, propName)) {
        errors.push(`${label}.${propName}: in the table but not in the schema`);
      }
    }
    return;
  }

  if (node.kind === 'array') {
    if (schema['type'] !== 'array') {
      errors.push(`${label}: table says array, schema type is ${String(schema['type'])}`);
      return;
    }
    const items = schema['items'];
    if (items != null && typeof items === 'object') {
      checkNode(node.items, schemaRoot, items as JsonSchema, `${label}[]`, seen, errors);
    }
    return;
  }

  if (node.kind === 'map') {
    if (additional == null || typeof additional !== 'object') {
      errors.push(`${label}: table says map, schema has no object additionalProperties`);
      return;
    }
    checkNode(node.values, schemaRoot, additional as JsonSchema, `${label}.*`, seen, errors);
    return;
  }

  // Leaf: the schema must not describe structure the projection would have to
  // walk (nested properties, or a map of sub-schemas).
  if (properties != null) {
    errors.push(`${label}: table says leaf, schema declares properties`);
  }
  if (additional != null && typeof additional === 'object') {
    errors.push(`${label}: table says leaf, schema declares a sub-schema map`);
  }
}

describe('projection table matches schemas/', () => {
  const cases: Array<[keyof typeof CANONICAL_SCHEMA_TABLE, string]> = [
    ['core', 'hushspec-core.v1.schema.json'],
    ['posture', 'hushspec-posture.v1.schema.json'],
    ['origins', 'hushspec-origins.v1.schema.json'],
    ['detection', 'hushspec-detection.v1.schema.json'],
  ];

  for (const [tableKey, schemaFile] of cases) {
    it(`${schemaFile} defaults and required lists are transcribed`, () => {
      const schema = loadSchema(schemaFile);
      const errors: string[] = [];
      const table = CANONICAL_SCHEMA_TABLE[tableKey] as SchemaNode;
      if (tableKey === 'core') {
        // `extends`, `merge_strategy` and `extensions` are handled outside the
        // core table (spec sections 3.1 and 3.4).
        const properties = { ...(schema['properties'] as Record<string, JsonSchema>) };
        delete properties['extends'];
        delete properties['merge_strategy'];
        delete properties['extensions'];
        checkNode(table, schema, { ...schema, properties }, '$', new Map(), errors);
      } else {
        checkNode(table, schema, schema, '$', new Map(), errors);
      }
      expect(errors).toEqual([]);
    });
  }
});
