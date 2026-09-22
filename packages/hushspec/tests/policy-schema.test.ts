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
import { majorVersion } from '../src/version.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const schemasRoot = path.join(repoRoot, 'schemas');
const fixturesRoot = path.join(repoRoot, 'fixtures');

const FAMILIES = ['core', 'posture', 'origins', 'detection'] as const;

/** `[extensions key, embedded $defs name, published file name]`. */
const EMBEDDED_EXTENSIONS = [
  ['posture', 'PostureExtension', 'hushspec-posture.v1.schema.json'],
  ['origins', 'OriginsExtension', 'hushspec-origins.v1.schema.json'],
  ['detection', 'DetectionExtension', 'hushspec-detection.v1.schema.json'],
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
 * lookup in the IANA time zone database, the HushSpec regex profile, a
 * recursion depth bound, the IEEE 754 safe-integer bound (canonical spec 4.3
 * applies it to every integer a document writes, free-form values included),
 * and the set of minor versions an engine supports (the schema admits every
 * `1.y.z`; core spec 2.2 makes acceptance the engine's decision). The SDKs
 * check them after parsing. They are asserted to *pass* below, so a schema
 * change that does become able to express one fails this file until the name
 * is removed.
 */
const BEYOND_SCHEMA_VECTORS = new Set([
  'bad-initial.yaml',
  'duplicate-ids.yaml',
  'duplicate-pattern-names.yaml',
  'integer-out-of-safe-range.yaml',
  'regex-comment-group.yaml',
  'regex-lookahead.yaml',
  'regex-mid-pattern-flag.yaml',
  'regex-negated-class-shorthand.yaml',
  'regex-open-lower-bound.yaml',
  'regex-posix-bracket.yaml',
  'version-unsupported-minor.yaml',
  'when-bad-timezone.yaml',
  'when-timezone-double-sign.yaml',
  'when-timezone-no-colon.yaml',
  'when-timezone-short-hour.yaml',
  'when-timezone-short-minute.yaml',
  'when-too-deep.yaml',
]);

function loadSchema(fileName: string): SchemaDocument {
  return JSON.parse(readFileSync(path.join(schemasRoot, fileName), 'utf8')) as SchemaDocument;
}

const coreSchema = loadSchema('hushspec-core.v1.schema.json');
const coreSchemaV0 = loadSchema('hushspec-core.v0.schema.json');

/**
 * The published core schema of the lineage the document declares.
 *
 * The two lineages are one schema apart: 0.x documents are validated against
 * the frozen `core.v0` file, 1.x (and anything unreadable, which the v1 file
 * refuses) against the current one. They differ only in the version pattern
 * and in `name`, which 1.0 requires to be non-empty (versioning spec 10).
 */
function schemaFor(document: unknown): SchemaDocument {
  const declared = (document as Record<string, unknown> | null)?.['hushspec'];
  return typeof declared === 'string' && majorVersion(declared) === 0 ? coreSchemaV0 : coreSchema;
}

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

  it('reads every published vector family', () => {
    // `policyVectors` is directory-derived, so an emptied or renamed fixture
    // family would take its coverage with it and every case below would still
    // report green -- there would simply be no cases. Floors, well under the
    // current counts, so that adding a vector never fails this.
    expect(policyVectors('valid').length).toBeGreaterThanOrEqual(15);
    expect(policyVectors('invalid').length).toBeGreaterThanOrEqual(25);
    for (const family of FAMILIES) {
      expect(readdirSync(path.join(fixturesRoot, family, 'valid')).length).toBeGreaterThan(0);
    }
  });

  it.each(policyVectors('valid'))('accepts $name', ({ file }) => {
    const document = loadDocument(file);
    expect(schemaErrors(schemaFor(document), document)).toEqual([]);
  });

  // The YAML-profile vectors are filtered out of the table rather than
  // returned from inside the case: a case that returns early still reports as
  // a pass, so the suite would claim four assertions it never made.
  it.each(policyVectors('invalid').filter(({ name }) => !PROFILE_ONLY_VECTORS.has(name)))(
    'refuses $name',
    ({ name, file }) => {
      const document = loadDocument(file);
      const valid = schemaValid(schemaFor(document), document);
      expect(valid).toBe(BEYOND_SCHEMA_VECTORS.has(name));
    },
  );

  it('names only vectors that are still published', () => {
    const names = new Set(policyVectors('invalid').map(({ name }) => name));
    for (const name of [...PROFILE_ONLY_VECTORS, ...BEYOND_SCHEMA_VECTORS]) {
      expect(names.has(name)).toBe(true);
    }
  });

  // A minimally valid body for each extension, so that adding one stray key
  // is the only thing wrong with the document. `{ bogus: 1 }` on its own also
  // fails `required` for posture, and would keep passing this test with
  // unknown-key handling entirely removed.
  const MINIMAL_EXTENSIONS: Record<string, Record<string, unknown>> = {
    posture: { initial: 'idle', states: { idle: {} }, transitions: [] },
    origins: { profiles: [] },
    detection: {},
  };

  it.each(EMBEDDED_EXTENSIONS.map(([key]) => key))(
    'refuses an unknown key inside extensions.%s',
    (key) => {
      const body = MINIMAL_EXTENSIONS[key];
      expect(schemaErrors(coreSchema, { hushspec: '0.1.0', extensions: { [key]: body } })).toEqual(
        [],
      );

      const errors = schemaErrors(coreSchema, {
        hushspec: '0.1.0',
        extensions: { [key]: { ...body, bogus: 1 } },
      });
      expect(errors).toEqual([`$.extensions.${key}: unknown property bogus`]);
    },
  );

  it.each(EMBEDDED_EXTENSIONS.map(([key]) => key))(
    'validates the body of extensions.%s, not just its keys',
    (key) => {
      // A key the companion schema declares, carrying the wrong type. Nothing
      // about the key is unknown, so only a schema that actually walks the
      // block can refuse this.
      const wrongType: Record<string, unknown> = {
        posture: { ...MINIMAL_EXTENSIONS['posture'], initial: 5 },
        origins: { default_behavior: 'allow' },
        detection: { prompt_injection: 'yes' },
      }[key] as Record<string, unknown>;

      expect(
        schemaValid(coreSchema, { hushspec: '0.1.0', extensions: { [key]: wrongType } }),
      ).toBe(false);
    },
  );
});
