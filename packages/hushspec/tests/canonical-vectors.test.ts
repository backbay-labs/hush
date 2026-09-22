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
import { parse } from '../src/parse.js';
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
    expect(vectorFiles.length).toBe(16);
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

  it('keeps every integer inside the safe range', () => {
    expect(canonicalizeValue({ budget: 9007199254740991 })).toBe('{"budget":9007199254740991}');
    expect(canonicalizeValue({ budget: -9007199254740991 })).toBe('{"budget":-9007199254740991}');
    expect(canonicalizeValue({ ratio: 0.35 })).toBe('{"ratio":0.35}');
  });

  it('refuses a null written for a declared property (section 2.2)', () => {
    expect(() => canonicalJson({ hushspec: '0.1.0', rules: { egress: null } } as HushSpec)).toThrow(
      /\$\.rules\.egress is null/,
    );
    expect(() => canonicalJson({ hushspec: '0.1.0', name: null } as unknown as HushSpec)).toThrow(
      CanonicalError,
    );
  });

  it('refuses a null written for a resolution field (section 3.1)', () => {
    // Stripping it would hash the document as though the property had never
    // been written, and no valid document carries it.
    expect(() =>
      canonicalJson({ hushspec: '0.1.0', extends: null } as unknown as HushSpec),
    ).toThrow(/\$\.extends is null/);
    expect(() =>
      canonicalJson({ hushspec: '0.1.0', merge_strategy: null } as unknown as HushSpec),
    ).toThrow(/\$\.merge_strategy is null/);
  });

  it('keeps a null inside a free-form value (section 2.2)', () => {
    const document = {
      hushspec: '0.1.0',
      rules: { egress: { when: { context: { a: null } } } },
    } as unknown as HushSpec;
    expect(canonicalJson(document)).toContain('"context":{"a":null}');
  });

  it('refuses a key the schema does not declare (section 2.3)', () => {
    expect(() => canonicalJson({ hushspec: '0.1.0', nope: 1 } as unknown as HushSpec)).toThrow(
      /unknown field \$\.nope/,
    );
    expect(() =>
      canonicalJson({ hushspec: '0.1.0', rules: { egress: { nope: 1 } } } as unknown as HushSpec),
    ).toThrow(/unknown field \$\.rules\.egress\.nope/);
  });

  it('refuses an extensions block the schemas do not describe (section 3.4)', () => {
    expect(() =>
      canonicalJson({ hushspec: '0.1.0', extensions: 'nope' } as unknown as HushSpec),
    ).toThrow(/\$\.extensions must be an object/);
    expect(() =>
      canonicalJson({ hushspec: '0.1.0', extensions: { nope: {} } } as unknown as HushSpec),
    ).toThrow(/unknown extension `nope`/);
  });
});

// Section 4.3: the safe-integer bound belongs to integer syntax, which only
// the parser sees. A literal past the range is refused there; float syntax
// keeps its ECMAScript form at any magnitude.
describe('the safe-integer bound (section 4.3)', () => {
  const policy = (literal: string): string =>
    [
      'hushspec: "0.1.0"',
      'rules:',
      '  egress:',
      '    when:',
      '      context:',
      `        budget: ${literal}`,
      '',
    ].join('\n');

  for (const literal of ['9007199254740993', '18446744073709551617']) {
    it(`refuses the integer literal ${literal}`, () => {
      const result = parse(policy(literal));
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.error).toContain(`integer ${literal} exceeds the safe range (2^53-1)`);
    });
  }

  it('keeps an integer literal inside the range', () => {
    const result = parse(policy('9007199254740991'));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(canonicalJson(result.value)).toContain('"budget":9007199254740991');
  });

  it('leaves float syntax unbounded', () => {
    const result = parse(
      [
        'hushspec: "0.1.0"',
        'rules:',
        '  egress:',
        '    when:',
        '      context:',
        '        a: 1.0e+16',
        '        b: 1.0e+21',
        '        c: 1.5e+300',
        '        d: -0.0',
        '',
      ].join('\n'),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(canonicalJson(result.value)).toContain(
      '"context":{"a":10000000000000000,"b":1e+21,"c":1.5e+300,"d":0}',
    );
  });

  // A `number` built in memory carries no syntax, and 2**53 is the same double
  // as the float-syntax literals above. Section 4.3 leaves the bound to the
  // parser here, so the serializer emits it; no valid document can hold such a
  // value, which is why that costs no cross-SDK agreement.
  it('emits a whole double past the range that no integer literal could write', () => {
    expect(canonicalizeValue({ budget: 2 ** 53 })).toBe('{"budget":9007199254740992}');
    expect(canonicalizeValue({ budget: -(2 ** 53) })).toBe('{"budget":-9007199254740992}');
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
 * Strict in both directions: the projection refuses a key the table does not
 * declare (spec section 2.3), so a schema property missing from the table
 * would make a valid document uncanonicalizable, and a table property missing
 * from the schema would let an invalid one through. Defaults and `required`
 * lists must match too.
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
        errors.push(`${label}.${propName}: in the schema but not in the table`);
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
