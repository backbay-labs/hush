/**
 * A JSON Schema 2020-12 validator covering exactly the keywords the HushSpec
 * schemas use -- for tests only.
 *
 * The SDK has no runtime JSON Schema dependency and must not grow one: a
 * policy engine that needs a schema library at the tool boundary is a policy
 * engine that fails open when the library is missing. The receipt and
 * log-entry vectors still have to be checked against the published schemas,
 * so this walks them directly.
 *
 * Supported: `$ref` (local `#/$defs/...` only), `type` (including `integer`),
 * `const`, `enum`, `pattern`, `required`, `properties`,
 * `additionalProperties: false`, `items`, `minimum`, `maximum`, `minLength`.
 * Anything else in a schema is ignored, so a schema that grows a keyword this
 * does not know silently loosens -- `schema-keywords.test.ts`-style coverage
 * is provided by asserting the invalid vectors are all rejected.
 */

export interface SchemaDocument {
  [key: string]: unknown;
}

/** Every validation error found, as `path: message`. */
export function schemaErrors(document: SchemaDocument, value: unknown): string[] {
  const errors: string[] = [];
  check(document, document, value, '$', errors);
  return errors;
}

/** True when `value` satisfies `document`. */
export function schemaValid(document: SchemaDocument, value: unknown): boolean {
  return schemaErrors(document, value).length === 0;
}

function resolveRef(root: SchemaDocument, ref: string): SchemaDocument {
  if (!ref.startsWith('#/')) {
    throw new Error(`unsupported $ref ${ref}: only local pointers are resolved`);
  }
  let node: unknown = root;
  for (const rawSegment of ref.slice(2).split('/')) {
    const segment = rawSegment.replace(/~1/g, '/').replace(/~0/g, '~');
    if (typeof node !== 'object' || node === null) {
      throw new Error(`unresolvable $ref ${ref}`);
    }
    node = (node as Record<string, unknown>)[segment];
  }
  if (typeof node !== 'object' || node === null) {
    throw new Error(`unresolvable $ref ${ref}`);
  }
  return node as SchemaDocument;
}

function typeMatches(type: string, value: unknown): boolean {
  switch (type) {
    case 'object':
      return typeof value === 'object' && value !== null && !Array.isArray(value);
    case 'array':
      return Array.isArray(value);
    case 'string':
      return typeof value === 'string';
    case 'number':
      return typeof value === 'number' && Number.isFinite(value);
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value);
    case 'boolean':
      return typeof value === 'boolean';
    case 'null':
      return value === null;
    default:
      throw new Error(`unsupported schema type ${type}`);
  }
}

function check(
  root: SchemaDocument,
  schema: SchemaDocument,
  value: unknown,
  path: string,
  errors: string[],
): void {
  const ref = schema['$ref'];
  if (typeof ref === 'string') {
    // A $ref sits alongside its siblings in 2020-12; the HushSpec schemas only
    // add `description` next to one, which is not a constraint.
    check(root, resolveRef(root, ref), value, path, errors);
    return;
  }

  const type = schema['type'];
  if (typeof type === 'string' && !typeMatches(type, value)) {
    errors.push(`${path}: expected ${type}`);
    return;
  }
  if (Array.isArray(type) && !type.some((one) => typeMatches(String(one), value))) {
    errors.push(`${path}: expected one of ${type.join(', ')}`);
    return;
  }

  if ('const' in schema && value !== schema['const']) {
    errors.push(`${path}: expected const ${JSON.stringify(schema['const'])}`);
  }
  const enumValues = schema['enum'];
  if (Array.isArray(enumValues) && !enumValues.includes(value as never)) {
    errors.push(`${path}: ${JSON.stringify(value)} is not one of the enum values`);
  }

  if (typeof value === 'string') {
    const pattern = schema['pattern'];
    if (typeof pattern === 'string' && !new RegExp(pattern, 'u').test(value)) {
      errors.push(`${path}: ${JSON.stringify(value)} does not match ${pattern}`);
    }
    const minLength = schema['minLength'];
    if (typeof minLength === 'number' && value.length < minLength) {
      errors.push(`${path}: shorter than minLength ${minLength}`);
    }
  }

  if (typeof value === 'number') {
    const minimum = schema['minimum'];
    if (typeof minimum === 'number' && value < minimum) {
      errors.push(`${path}: ${value} is below minimum ${minimum}`);
    }
    const maximum = schema['maximum'];
    if (typeof maximum === 'number' && value > maximum) {
      errors.push(`${path}: ${value} is above maximum ${maximum}`);
    }
  }

  if (Array.isArray(value)) {
    const items = schema['items'];
    if (typeof items === 'object' && items !== null) {
      value.forEach((item, index) => {
        check(root, items as SchemaDocument, item, `${path}[${index}]`, errors);
      });
    }
    return;
  }

  if (typeof value !== 'object' || value === null) return;

  const members = value as Record<string, unknown>;
  const required = schema['required'];
  if (Array.isArray(required)) {
    for (const key of required) {
      if (!(String(key) in members)) {
        errors.push(`${path}: missing required property ${String(key)}`);
      }
    }
  }

  const properties = (schema['properties'] ?? {}) as Record<string, SchemaDocument>;
  for (const [key, member] of Object.entries(members)) {
    const property = properties[key];
    if (property !== undefined) {
      check(root, property, member, `${path}.${key}`, errors);
    } else if (schema['additionalProperties'] === false) {
      errors.push(`${path}: unknown property ${key}`);
    }
  }
}
