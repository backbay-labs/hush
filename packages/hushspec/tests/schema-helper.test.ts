/**
 * The test suite's own JSON Schema validator, checked against the parts of
 * draft 2020-12 it claims to implement.
 *
 * Every schema assertion in this package runs through `schemaErrors`, so a
 * keyword it quietly ignores is a property that quietly stops being tested --
 * the vectors keep passing and nothing says otherwise. The helper's contract
 * is that it either enforces a keyword or throws, and these are the cases
 * where getting that wrong is invisible from the fixtures alone.
 */

import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { assertSupported, schemaErrors, type SchemaDocument } from './helpers/json-schema.js';

const errors = (schema: SchemaDocument, value: unknown): string[] => schemaErrors(schema, value);

describe('the test JSON Schema validator', () => {
  describe('refuses to ignore a keyword', () => {
    it('rejects an unsupported keyword in a branch no instance reaches', () => {
      // The guard used to run only on subschemas an instance walked into, so
      // a keyword added to an unexercised branch was enforced by nobody.
      const schema: SchemaDocument = {
        type: 'object',
        properties: { a: { type: 'string' }, b: { allOf: [{ type: 'number' }] } },
      };
      expect(() => errors(schema, { a: 'x' })).toThrow(/unsupported schema keyword allOf/);
    });

    it('rejects an unevaluatedProperties that is not false', () => {
      // Only `false` is implemented; a subschema form would silently
      // constrain nothing.
      expect(() =>
        errors({ type: 'object', unevaluatedProperties: { type: 'string' } }, { x: 1 }),
      ).toThrow(/only `false` is implemented/);
    });

    it.each(['required', 'enum'])('rejects a non-array %s', (keyword) => {
      expect(() => errors({ type: 'object', [keyword]: 'a' }, {})).toThrow(/must be an array/);
    });

    it('accepts every published schema', () => {
      // The other half of the contract. The walk is only useful if it passes
      // the documents this package validates against, so every schema the
      // repository publishes is walked here -- including the branches no
      // fixture reaches, which is the whole point.
      const schemasRoot = path.resolve(
        path.dirname(fileURLToPath(import.meta.url)),
        '../../../schemas',
      );
      const names = readdirSync(schemasRoot).filter((name) => name.endsWith('.json'));
      expect(names.length).toBeGreaterThanOrEqual(15);

      for (const name of names) {
        const document = JSON.parse(
          readFileSync(path.join(schemasRoot, name), 'utf8'),
        ) as SchemaDocument;
        expect(() => assertSupported(document), name).not.toThrow();
      }
    });
  });

  describe('boolean subschemas', () => {
    it('treats true as accepting anything', () => {
      expect(errors({ type: 'object', properties: { a: true } }, { a: 1 })).toEqual([]);
      expect(errors({ not: true }, 'x')).toEqual(['$: "x" is excluded by "not"']);
    });

    it('treats false as accepting nothing', () => {
      // Previously a raw TypeError out of the `'const' in schema` test.
      expect(errors({ type: 'object', properties: { a: false } }, { a: 1 })).toEqual([
        '$.a: the false schema accepts nothing',
      ]);
      expect(errors({ type: 'array', items: false }, [1])).toEqual([
        '$[0]: the false schema accepts nothing',
      ]);
      expect(errors({ type: 'object', additionalProperties: false }, { a: 1 })).toEqual([
        '$: unknown property a',
      ]);
    });
  });

  describe('if/then/else', () => {
    it('applies to a string instance', () => {
      // The block sat below the array and non-object returns, so it was
      // skipped for every instance that was not an object.
      const schema: SchemaDocument = { type: 'string', if: { const: 'a' }, then: { const: 'b' } };
      expect(errors(schema, 'a')).toEqual(['$: expected const "b"']);
      expect(errors(schema, 'z')).toEqual([]);
    });

    it('applies to an array instance', () => {
      const schema: SchemaDocument = { type: 'array', if: { minItems: 1 }, then: { maxItems: 0 } };
      expect(errors(schema, [1])).toEqual(['$: more than maxItems 0']);
      expect(errors(schema, [])).toEqual([]);
    });

    it('takes the else branch when the condition fails', () => {
      const schema: SchemaDocument = {
        type: 'string',
        if: { const: 'a' },
        then: { const: 'a' },
        else: { const: 'b' },
      };
      expect(errors(schema, 'z')).toEqual(['$: expected const "b"']);
    });

    it('feeds the matched condition into unevaluatedProperties', () => {
      const schema: SchemaDocument = {
        type: 'object',
        properties: { kind: { const: 'timed' } },
        if: { properties: { kind: { const: 'timed' } }, required: ['kind'] },
        then: { properties: { after: { type: 'string' } }, required: ['after'] },
        unevaluatedProperties: false,
      };
      expect(errors(schema, { kind: 'timed', after: '5m' })).toEqual([]);
      expect(errors(schema, { kind: 'timed' })).toEqual(['$: missing required property after']);
      expect(errors(schema, { kind: 'timed', after: '5m', other: 1 })).toEqual([
        '$: unevaluated property other',
      ]);
    });
  });

  describe('equality and length are defined over the JSON value', () => {
    it('compares const and enum structurally, not by identity', () => {
      // Key order is not part of a JSON value, so both of these must match.
      expect(errors({ const: { a: 1, b: 2 } }, { b: 2, a: 1 })).toEqual([]);
      expect(errors({ enum: [{ a: 1 }] }, { a: 1 })).toEqual([]);
      expect(errors({ const: { a: 1 } }, { a: 2 })).toEqual(['$: expected const {"a":1}']);
    });

    it('counts uniqueItems structurally', () => {
      expect(errors({ type: 'array', uniqueItems: true }, [{ a: 1, b: 2 }, { b: 2, a: 1 }])).toEqual(
        ['$: items are not unique'],
      );
    });

    it('measures minLength and maxLength in code points', () => {
      // A single astral character is two UTF-16 code units but one code
      // point, so `String.length` would have called this two characters.
      expect(errors({ type: 'string', minLength: 2 }, '\u{1F510}')).toEqual([
        '$: shorter than minLength 2',
      ]);
      expect(errors({ type: 'string', maxLength: 1 }, '\u{1F510}')).toEqual([]);
    });
  });

  describe('$ref scoping', () => {
    it('resolves a pointer inside an embedded resource against that resource', () => {
      // The outer document also declares `$defs/Thing`. A `#/$defs/Thing`
      // written inside the embedded resource must find the embedded one.
      const schema: SchemaDocument = {
        $id: 'https://example.test/outer',
        type: 'object',
        properties: { inner: { $ref: 'https://example.test/inner' } },
        $defs: {
          Thing: { type: 'string' },
          Inner: {
            $id: 'https://example.test/inner',
            type: 'object',
            properties: { thing: { $ref: '#/$defs/Thing' } },
            $defs: { Thing: { type: 'number' } },
          },
        },
      };
      expect(errors(schema, { inner: { thing: 1 } })).toEqual([]);
      expect(errors(schema, { inner: { thing: 'x' } })).toEqual(['$.inner.thing: expected number']);
    });

    it('throws on a reference it cannot resolve', () => {
      expect(() => errors({ $ref: 'https://example.test/missing' }, {})).toThrow(
        /unresolvable \$ref/,
      );
    });
  });
});
