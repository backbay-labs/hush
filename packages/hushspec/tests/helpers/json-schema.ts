/**
 * A JSON Schema 2020-12 validator covering exactly the keywords the HushSpec
 * schemas use -- for tests only.
 *
 * The SDK has no runtime JSON Schema dependency and must not grow one: a
 * policy engine that needs a schema library at the tool boundary is a policy
 * engine that fails open when the library is missing. The receipt, log-entry
 * and policy vectors still have to be checked against the published schemas,
 * so this walks them directly.
 *
 * Supported: `$ref` (a local `#/...` pointer, or the absolute `$id` of a
 * schema resource embedded in the same document), `$defs`, `type` (including
 * `integer`), `const`, `enum`, `pattern`, `format` (`date`, `date-time`,
 * `uri`), `required`, `properties`, `additionalProperties` (`false` or a
 * subschema), `unevaluatedProperties: false`, `if`/`then`/`else`, `not`,
 * `items`, `minimum`, `exclusiveMinimum`, `maximum`, `minLength`,
 * `maxLength`, `minItems`, `maxItems`, `uniqueItems` and `minProperties`.
 *
 * A keyword outside that list throws rather than being ignored. An ignored
 * constraint loosens the schema silently, which is the one failure mode a
 * fail-closed project cannot accept from its own test tooling: the vectors
 * would keep passing while the property under test had stopped being checked.
 */

export interface SchemaDocument {
  [key: string]: unknown;
}

/** Keywords that constrain an instance, each implemented by `check`. */
const ASSERTIONS = new Set([
  '$ref',
  'type',
  'const',
  'enum',
  'pattern',
  'format',
  'required',
  'properties',
  'additionalProperties',
  'unevaluatedProperties',
  'if',
  'then',
  'else',
  'not',
  'items',
  'minimum',
  'exclusiveMinimum',
  'maximum',
  'minLength',
  'maxLength',
  'minItems',
  'maxItems',
  'uniqueItems',
  'minProperties',
]);

/** Keywords that describe rather than constrain, and are deliberately inert. */
const ANNOTATIONS = new Set([
  '$schema',
  '$id',
  '$comment',
  '$defs',
  'title',
  'description',
  'default',
  'examples',
  'deprecated',
]);

/** Formats this validator asserts; any other format name throws. */
const FORMATS: Record<string, RegExp> = {
  // RFC 3339 full-date, with the day-of-month range checked separately.
  date: /^\d{4}-\d{2}-\d{2}$/,
  'date-time':
    /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/,
  uri: /^[A-Za-z][A-Za-z0-9+.-]*:/,
};

/**
 * One document's schema resources, keyed by `$id`. A 2020-12 document may
 * embed whole schema resources (the core schema carries each extension schema
 * verbatim so its `$ref`s resolve with no network access); a `#/...` pointer
 * inside one of those resolves against that resource, not against the
 * enclosing document.
 */
interface Registry {
  byId: Map<string, SchemaDocument>;
}

/** Where a `#/...` pointer resolves: the innermost enclosing resource. */
interface Scope {
  registry: Registry;
  resource: SchemaDocument;
}

/** Every validation error found, as `path: message`. */
export function schemaErrors(document: SchemaDocument, value: unknown): string[] {
  const errors: string[] = [];
  const scope: Scope = { registry: buildRegistry(document), resource: document };
  check(scope, document, value, '$', errors);
  return errors;
}

/** True when `value` satisfies `document`. */
export function schemaValid(document: SchemaDocument, value: unknown): boolean {
  return schemaErrors(document, value).length === 0;
}

function buildRegistry(document: SchemaDocument): Registry {
  const byId = new Map<string, SchemaDocument>();
  const visit = (node: unknown): void => {
    if (Array.isArray(node)) {
      node.forEach(visit);
      return;
    }
    if (typeof node !== 'object' || node === null) return;
    const record = node as Record<string, unknown>;
    const id = record['$id'];
    if (typeof id === 'string') byId.set(id, record as SchemaDocument);
    for (const member of Object.values(record)) visit(member);
  };
  visit(document);
  return { byId };
}

/**
 * Resolve a `$ref`, returning the target schema and the scope its own
 * references resolve in -- which changes when the reference crosses into an
 * embedded resource.
 */
function resolveRef(scope: Scope, ref: string): { schema: SchemaDocument; scope: Scope } {
  if (!ref.startsWith('#')) {
    const [base, pointer] = ref.split('#');
    const resource = scope.registry.byId.get(base);
    if (resource === undefined) {
      throw new Error(`unresolvable $ref ${ref}: no embedded resource declares that $id`);
    }
    const inner: Scope = { registry: scope.registry, resource };
    if (pointer === undefined || pointer === '') return { schema: resource, scope: inner };
    return { schema: pointerInto(inner.resource, `#${pointer}`, ref), scope: inner };
  }
  return { schema: pointerInto(scope.resource, ref, ref), scope };
}

function pointerInto(resource: SchemaDocument, pointer: string, ref: string): SchemaDocument {
  if (pointer === '#') return resource;
  if (!pointer.startsWith('#/')) {
    throw new Error(`unsupported $ref ${ref}: plain-name anchors are not resolved`);
  }
  let node: unknown = resource;
  for (const rawSegment of pointer.slice(2).split('/')) {
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

function formatMatches(format: string, value: string): boolean {
  const pattern = FORMATS[format];
  if (pattern === undefined) {
    throw new Error(`unsupported format ${format}`);
  }
  if (!pattern.test(value)) return false;
  if (format !== 'date') return true;
  // A shape-only check would accept 2026-13-45, so read the calendar date back.
  const [year, month, day] = value.split('-').map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
}

/**
 * Validate `value` against `schema`, appending any errors, and return the
 * property names of `value` this schema evaluated -- what
 * `unevaluatedProperties` is defined against. The set is empty for anything
 * that is not an object.
 */
function check(
  scope: Scope,
  schema: SchemaDocument,
  value: unknown,
  path: string,
  errors: string[],
): Set<string> {
  for (const keyword of Object.keys(schema)) {
    if (!ASSERTIONS.has(keyword) && !ANNOTATIONS.has(keyword)) {
      throw new Error(`unsupported schema keyword ${keyword} at ${path}`);
    }
  }

  const evaluated = new Set<string>();

  const ref = schema['$ref'];
  if (typeof ref === 'string') {
    // A `$ref` sits alongside its siblings in 2020-12: both apply, and the
    // annotations the reference produces are what a sibling
    // `unevaluatedProperties` is measured against.
    const target = resolveRef(scope, ref);
    for (const key of check(target.scope, target.schema, value, path, errors)) {
      evaluated.add(key);
    }
  }

  const type = schema['type'];
  if (typeof type === 'string' && !typeMatches(type, value)) {
    errors.push(`${path}: expected ${type}`);
    return evaluated;
  }
  if (Array.isArray(type) && !type.some((one) => typeMatches(String(one), value))) {
    errors.push(`${path}: expected one of ${type.join(', ')}`);
    return evaluated;
  }

  if ('const' in schema && value !== schema['const']) {
    errors.push(`${path}: expected const ${JSON.stringify(schema['const'])}`);
  }
  const enumValues = schema['enum'];
  if (Array.isArray(enumValues) && !enumValues.includes(value as never)) {
    errors.push(`${path}: ${JSON.stringify(value)} is not one of the enum values`);
  }

  const negated = schema['not'];
  if (typeof negated === 'object' && negated !== null) {
    const negatedErrors: string[] = [];
    check(scope, negated as SchemaDocument, value, path, negatedErrors);
    if (negatedErrors.length === 0) {
      errors.push(`${path}: ${JSON.stringify(value)} is excluded by "not"`);
    }
  }

  if (typeof value === 'string') {
    const pattern = schema['pattern'];
    if (typeof pattern === 'string' && !new RegExp(pattern, 'u').test(value)) {
      errors.push(`${path}: ${JSON.stringify(value)} does not match ${pattern}`);
    }
    const format = schema['format'];
    if (typeof format === 'string' && !formatMatches(format, value)) {
      errors.push(`${path}: ${JSON.stringify(value)} is not a valid ${format}`);
    }
    const minLength = schema['minLength'];
    if (typeof minLength === 'number' && value.length < minLength) {
      errors.push(`${path}: shorter than minLength ${minLength}`);
    }
    const maxLength = schema['maxLength'];
    if (typeof maxLength === 'number' && value.length > maxLength) {
      errors.push(`${path}: longer than maxLength ${maxLength}`);
    }
  }

  if (typeof value === 'number') {
    const minimum = schema['minimum'];
    if (typeof minimum === 'number' && value < minimum) {
      errors.push(`${path}: ${value} is below minimum ${minimum}`);
    }
    const exclusiveMinimum = schema['exclusiveMinimum'];
    if (typeof exclusiveMinimum === 'number' && value <= exclusiveMinimum) {
      errors.push(`${path}: ${value} is not above exclusiveMinimum ${exclusiveMinimum}`);
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
        check(scope, items as SchemaDocument, item, `${path}[${index}]`, errors);
      });
    }
    const minItems = schema['minItems'];
    if (typeof minItems === 'number' && value.length < minItems) {
      errors.push(`${path}: fewer than minItems ${minItems}`);
    }
    const maxItems = schema['maxItems'];
    if (typeof maxItems === 'number' && value.length > maxItems) {
      errors.push(`${path}: more than maxItems ${maxItems}`);
    }
    if (schema['uniqueItems'] === true) {
      const seen = new Set(value.map((item) => JSON.stringify(item)));
      if (seen.size !== value.length) {
        errors.push(`${path}: items are not unique`);
      }
    }
    return evaluated;
  }

  if (typeof value !== 'object' || value === null) return evaluated;

  const members = value as Record<string, unknown>;
  const required = schema['required'];
  if (Array.isArray(required)) {
    for (const key of required) {
      if (!(String(key) in members)) {
        errors.push(`${path}: missing required property ${String(key)}`);
      }
    }
  }
  const minProperties = schema['minProperties'];
  if (typeof minProperties === 'number' && Object.keys(members).length < minProperties) {
    errors.push(`${path}: fewer than minProperties ${minProperties}`);
  }

  const properties = (schema['properties'] ?? {}) as Record<string, SchemaDocument>;
  const additional = schema['additionalProperties'];
  for (const [key, member] of Object.entries(members)) {
    const property = properties[key];
    if (property !== undefined) {
      check(scope, property, member, `${path}.${key}`, errors);
      evaluated.add(key);
    } else if (additional === false) {
      errors.push(`${path}: unknown property ${key}`);
      evaluated.add(key);
    } else if (typeof additional === 'object' && additional !== null) {
      check(scope, additional as SchemaDocument, member, `${path}.${key}`, errors);
      evaluated.add(key);
    } else if (additional === true) {
      evaluated.add(key);
    }
  }

  const condition = schema['if'];
  if (typeof condition === 'object' && condition !== null) {
    const conditionErrors: string[] = [];
    const conditionEvaluated = check(
      scope,
      condition as SchemaDocument,
      value,
      path,
      conditionErrors,
    );
    const branch = conditionErrors.length === 0 ? schema['then'] : schema['else'];
    if (conditionErrors.length === 0) {
      for (const key of conditionEvaluated) evaluated.add(key);
    }
    if (typeof branch === 'object' && branch !== null) {
      for (const key of check(scope, branch as SchemaDocument, value, path, errors)) {
        evaluated.add(key);
      }
    }
  }

  if (schema['unevaluatedProperties'] === false) {
    for (const key of Object.keys(members)) {
      if (!evaluated.has(key)) {
        errors.push(`${path}: unevaluated property ${key}`);
      }
    }
  }

  return evaluated;
}
