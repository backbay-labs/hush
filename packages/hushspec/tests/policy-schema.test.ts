/**
 * The published JSON Schemas, checked against the shared policy vectors.
 *
 * The schemas are the machine-readable half of the specification: an editor, a
 * CI job, or a SchemaStore consumer validates a policy with them and never
 * sees the SDKs at all. So they have to agree with the vectors on which
 * documents are HushSpec documents -- including inside `extensions`, where the
 * core schema composes each companion schema by `$ref` so that an unknown key
 * is a rejection rather than an annotation (core spec 2.1 and 9.5).
 */

import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import { describe, expect, it } from 'vitest';
import { schemaErrors, schemaValid, type SchemaDocument } from './helpers/json-schema.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const schemasRoot = path.join(repoRoot, 'schemas');
const fixturesRoot = path.join(repoRoot, 'fixtures');

const FAMILIES = ['core', 'posture', 'origins', 'detection'] as const;

/** `[extensions key, embedded $defs name, published file name]`. */
const EMBEDDED_EXTENSIONS = [
  ['posture', 'PostureExtension', 'hushspec-posture.v0.schema.json'],
  ['origins', 'OriginsExtension', 'hushspec-origins.v0.schema.json'],
  ['detection', 'DetectionExtension', 'hushspec-detection.v0.schema.json'],
] as const;

/**
 * Vectors the YAML profile refuses before there is a document to validate.
 * Anchors and aliases, merge keys, duplicate keys and multi-document streams
 * are properties of the YAML *text* (core spec 2.4); a JSON Schema only ever
 * sees the loaded document, so this file makes no claim about them.
 */
const PROFILE_ONLY_VECTORS = new Set([
  'yaml-alias.yaml',
  'yaml-duplicate-key.yaml',
  'yaml-merge-key.yaml',
  'yaml-multi-doc.yaml',
]);

/**
 * Vectors whose refusal no JSON Schema can express: referential integrity
 * between two members of a document, uniqueness by a field of a list entry, a
 * lookup in the IANA time zone database, the HushSpec regex profile, and a
 * recursion depth bound. The SDKs check them after parsing. They are asserted
 * to *pass* below, so a schema change that does become able to express one
 * fails this file until the name is removed.
 */
const BEYOND_SCHEMA_VECTORS = new Set([
  'bad-initial.yaml',
  'duplicate-ids.yaml',
  'duplicate-pattern-names.yaml',
  'regex-mid-pattern-flag.yaml',
  'when-bad-timezone.yaml',
  'when-too-deep.yaml',
]);

function loadSchema(fileName: string): SchemaDocument {
  return JSON.parse(readFileSync(path.join(schemasRoot, fileName), 'utf8')) as SchemaDocument;
}

const coreSchema = loadSchema('hushspec-core.v0.schema.json');

function policyVectors(kind: 'valid' | 'invalid'): { name: string; file: string }[] {
  return FAMILIES.flatMap((family) => {
    const directory = path.join(fixturesRoot, family, kind);
    return readdirSync(directory)
      .filter((name) => name.endsWith('.yaml') && !name.endsWith('.expect.yaml'))
      .sort()
      .map((name) => ({ name, file: path.join(directory, name) }));
  });
}

function loadDocument(file: string): unknown {
  return YAML.parse(readFileSync(file, 'utf8'));
}

describe('composed core schema', () => {
  it('embeds the companion schemas verbatim', () => {
    const extensions = coreSchema['$defs'] as Record<string, SchemaDocument>;
    const properties = (extensions['Extensions']['properties'] ?? {}) as Record<
      string,
      SchemaDocument
    >;

    for (const [key, defName, fileName] of EMBEDDED_EXTENSIONS) {
      const published = loadSchema(fileName);
      const expectedId = `https://hushspec.dev/schemas/${fileName}`;

      expect(properties[key]['$ref']).toBe(expectedId);
      expect(properties[key]['unevaluatedProperties']).toBe(false);
      expect(published['$id']).toBe(expectedId);
      // A copy that drifts from the published file would validate policies
      // against a schema nobody publishes.
      expect(extensions[defName]).toEqual(published);
    }

    expect(Object.keys(properties).sort()).toEqual(
      EMBEDDED_EXTENSIONS.map(([key]) => key).sort(),
    );
  });

  it.each(policyVectors('valid'))('accepts $name', ({ file }) => {
    expect(schemaErrors(coreSchema, loadDocument(file))).toEqual([]);
  });

  it.each(policyVectors('invalid'))('refuses $name', ({ name, file }) => {
    if (PROFILE_ONLY_VECTORS.has(name)) return;
    const valid = schemaValid(coreSchema, loadDocument(file));
    expect(valid).toBe(BEYOND_SCHEMA_VECTORS.has(name));
  });

  it('names only vectors that are still published', () => {
    const names = new Set(policyVectors('invalid').map(({ name }) => name));
    for (const name of [...PROFILE_ONLY_VECTORS, ...BEYOND_SCHEMA_VECTORS]) {
      expect(names.has(name)).toBe(true);
    }
  });

  it.each(EMBEDDED_EXTENSIONS.map(([key]) => key))(
    'refuses an unknown key inside extensions.%s',
    (key) => {
      const document = { hushspec: '0.1.0', extensions: { [key]: { bogus: 1 } } };
      expect(schemaValid(coreSchema, document)).toBe(false);
    },
  );
});
