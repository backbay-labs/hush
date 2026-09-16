import { createHash } from 'node:crypto';
import type { HushSpec } from './schema.js';

/**
 * Canonical form and content hash for HushSpec documents
 * (spec/hushspec-canonical.md 0.2.0).
 *
 * Two steps, exactly as the specification defines them:
 *
 *  1. **Projection** (spec section 3): walk the *resolved* document alongside
 *     the published JSON Schemas, materialize every schema default that sits
 *     inside an object the document actually wrote, drop the resolution-only
 *     fields, and normalize empty no-default containers away.
 *  2. **Serialization** (spec section 4): RFC 8785 (JCS) over the projection --
 *     keys sorted by UTF-16 code unit, no whitespace, JCS string escapes, ES6
 *     number formatting.
 *
 * The content hash (spec section 5) is `sha256:` + lowercase hex of SHA-256
 * over the UTF-8 canonical bytes.
 *
 * The normative vectors live in `fixtures/core/hash/`; `tests/canonical-vectors.test.ts`
 * runs all of them and additionally checks this file's schema table against
 * `schemas/*.json` so the two cannot silently drift apart.
 */

// --------------------------------------------------------------------------
// JSON data model
// --------------------------------------------------------------------------

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

/** The document cannot be canonicalized (spec sections 2.1, 2.2, 2.3, 3.4, 4.3). */
export class CanonicalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CanonicalError';
  }
}

// --------------------------------------------------------------------------
// Schema table (spec section 3)
// --------------------------------------------------------------------------
//
// A transcription of the parts of `schemas/*.json` the projection needs:
// which properties exist, which carry a `default`, which are `required`, and
// which are presence-significant (spec section 3.3). Nothing else from the
// schemas matters here -- types, patterns and enums are validation's job, and
// `validate()` has already run by the time a document reaches this file.
//
// The property lists are exhaustive, because a key the table does not declare
// is refused (spec section 2.3). `tests/canonical-vectors.test.ts` diffs the
// table against the real schema files in both directions, so a property added,
// removed or given a default in `schemas/` fails CI here.

/** @internal Exported for the schema drift test in `tests/canonical-vectors.test.ts`. */
export type SchemaNode =
  /** Scalar, or a free-form object the schema does not describe (`when.context`). */
  | { readonly kind: 'leaf' }
  | {
      readonly kind: 'object';
      readonly properties: Readonly<Record<string, PropertySchema>>;
      readonly required?: readonly string[];
    }
  | { readonly kind: 'array'; readonly items: SchemaNode }
  /** `type: object` with an object-valued `additionalProperties` (posture `states`). */
  | { readonly kind: 'map'; readonly values: SchemaNode }
  /** Indirection for the recursive `Condition` schema. */
  | { readonly kind: 'lazy'; readonly get: () => SchemaNode };

/** @internal Exported for the schema drift test in `tests/canonical-vectors.test.ts`. */
export interface PropertySchema {
  readonly schema: SchemaNode;
  /** The schema `default`, materialized when the property is absent. */
  readonly default?: JsonValue;
  /**
   * Spec section 3.3: an empty value here changes meaning and MUST survive
   * projection. `OriginProfile.match` is the only such property; the origins
   * overlay lists are not, because an absent overlay list and an empty one
   * evaluate identically (origins spec section 4).
   */
  readonly presenceSignificant?: true;
}

const LEAF: SchemaNode = { kind: 'leaf' };
const STRING_ARRAY: SchemaNode = { kind: 'array', items: LEAF };
/** posture `budgets`: a map of integers. Keys are kept as written. */
const INTEGER_MAP: SchemaNode = { kind: 'map', values: LEAF };

type ObjectNode = Extract<SchemaNode, { kind: 'object' }>;

function object(
  properties: Record<string, PropertySchema>,
  required?: readonly string[],
): ObjectNode {
  return { kind: 'object', properties, required };
}

function array(items: SchemaNode): SchemaNode {
  return { kind: 'array', items };
}

const TIME_WINDOW = object(
  {
    start: { schema: LEAF },
    end: { schema: LEAF },
    timezone: { schema: LEAF, default: 'UTC' },
    days: { schema: STRING_ARRAY },
  },
  ['start', 'end'],
);

// `Condition` refers to itself through `all_of` / `any_of` / `not`.
const CONDITION_REF: SchemaNode = { kind: 'lazy', get: () => CONDITION };

const RATE_CONDITION = object(
  {
    counter: { schema: LEAF },
    threshold: { schema: LEAF },
    comparison: { schema: LEAF },
  },
  ['counter', 'threshold', 'comparison'],
);

const CONDITION = object({
  time_window: { schema: TIME_WINDOW },
  // `additionalProperties: true` -- arbitrary values, kept exactly as written.
  context: { schema: LEAF },
  all_of: { schema: array(CONDITION_REF) },
  any_of: { schema: array(CONDITION_REF) },
  not: { schema: CONDITION_REF },
  capability: { schema: LEAF },
  rate: { schema: RATE_CONDITION },
});

const WHEN: PropertySchema = { schema: CONDITION };

const SECRET_PATTERN = object(
  {
    name: { schema: LEAF },
    pattern: { schema: LEAF },
    severity: { schema: LEAF },
    description: { schema: LEAF },
  },
  ['name', 'pattern', 'severity'],
);

const RULES = object({
  forbidden_paths: {
    schema: object({
      when: WHEN,
      enabled: { schema: LEAF, default: true },
      patterns: { schema: STRING_ARRAY, default: [] },
      exceptions: { schema: STRING_ARRAY, default: [] },
    }),
  },
  path_allowlist: {
    schema: object({
      when: WHEN,
      enabled: { schema: LEAF, default: false },
      read: { schema: STRING_ARRAY, default: [] },
      write: { schema: STRING_ARRAY, default: [] },
      patch: { schema: STRING_ARRAY, default: [] },
    }),
  },
  egress: {
    schema: object({
      when: WHEN,
      enabled: { schema: LEAF, default: true },
      allow: { schema: STRING_ARRAY, default: [] },
      block: { schema: STRING_ARRAY, default: [] },
      default: { schema: LEAF, default: 'block' },
    }),
  },
  secret_patterns: {
    schema: object({
      when: WHEN,
      enabled: { schema: LEAF, default: true },
      patterns: { schema: array(SECRET_PATTERN), default: [] },
      skip_paths: { schema: STRING_ARRAY, default: [] },
    }),
  },
  patch_integrity: {
    schema: object({
      when: WHEN,
      enabled: { schema: LEAF, default: true },
      max_additions: { schema: LEAF, default: 1000 },
      max_deletions: { schema: LEAF, default: 500 },
      forbidden_patterns: { schema: STRING_ARRAY, default: [] },
      require_balance: { schema: LEAF, default: false },
      // Written `10.0` in the schema; JSON and ES6 both render it `10`
      // (spec section 4.3).
      max_imbalance_ratio: { schema: LEAF, default: 10.0 },
    }),
  },
  shell_commands: {
    schema: object({
      when: WHEN,
      enabled: { schema: LEAF, default: true },
      forbidden_patterns: { schema: STRING_ARRAY, default: [] },
    }),
  },
  tool_access: {
    schema: object({
      when: WHEN,
      enabled: { schema: LEAF, default: true },
      allow: { schema: STRING_ARRAY, default: [] },
      block: { schema: STRING_ARRAY, default: [] },
      require_confirmation: { schema: STRING_ARRAY, default: [] },
      default: { schema: LEAF, default: 'allow' },
      max_args_size: { schema: LEAF },
    }),
  },
  computer_use: {
    schema: object({
      when: WHEN,
      enabled: { schema: LEAF, default: false },
      mode: { schema: LEAF, default: 'guardrail' },
      allowed_actions: { schema: STRING_ARRAY, default: [] },
    }),
  },
  remote_desktop_channels: {
    schema: object({
      when: WHEN,
      enabled: { schema: LEAF, default: false },
      clipboard: { schema: LEAF, default: false },
      file_transfer: { schema: LEAF, default: false },
      audio: { schema: LEAF, default: true },
      drive_mapping: { schema: LEAF, default: false },
    }),
  },
  input_injection: {
    schema: object({
      when: WHEN,
      enabled: { schema: LEAF, default: false },
      allowed_types: { schema: STRING_ARRAY, default: [] },
      require_postcondition_probe: { schema: LEAF, default: false },
    }),
  },
  browser_automation: {
    schema: object({
      when: WHEN,
      enabled: { schema: LEAF, default: false },
      allowed_domains: { schema: STRING_ARRAY, default: [] },
      blocked_domains: { schema: STRING_ARRAY, default: [] },
      allowed_verbs: { schema: STRING_ARRAY, default: [] },
      credential_detection: { schema: LEAF, default: true },
      extra_credential_patterns: { schema: STRING_ARRAY, default: [] },
    }),
  },
  code_execution: {
    schema: object({
      when: WHEN,
      enabled: { schema: LEAF, default: false },
      language_allowlist: { schema: STRING_ARRAY, default: [] },
      module_denylist: { schema: STRING_ARRAY, default: [] },
      network_access: { schema: LEAF, default: false },
      max_execution_time_ms: { schema: LEAF },
      max_scan_bytes: { schema: LEAF },
    }),
  },
});

const CONTROL_MAPPING = object(
  {
    framework: { schema: LEAF },
    control_id: { schema: LEAF },
    rule_paths: { schema: STRING_ARRAY },
    notes: { schema: LEAF },
  },
  ['framework', 'control_id', 'rule_paths'],
);

const CHANGELOG_ENTRY = object(
  {
    version: { schema: LEAF },
    date: { schema: LEAF },
    summary: { schema: LEAF },
    author: { schema: LEAF },
  },
  ['version', 'date', 'summary'],
);

const GOVERNANCE_METADATA = object({
  author: { schema: LEAF },
  approved_by: { schema: LEAF },
  approval_date: { schema: LEAF },
  classification: { schema: LEAF },
  change_ticket: { schema: LEAF },
  lifecycle_state: { schema: LEAF },
  policy_version: { schema: LEAF },
  effective_date: { schema: LEAF },
  expiry_date: { schema: LEAF },
  owner: { schema: LEAF },
  reviewers: { schema: STRING_ARRAY },
  next_review_date: { schema: LEAF },
  changelog: { schema: array(CHANGELOG_ENTRY) },
  supersedes: { schema: LEAF },
  controls: { schema: array(CONTROL_MAPPING) },
});

const CORE = object(
  {
    hushspec: { schema: LEAF },
    name: { schema: LEAF },
    description: { schema: LEAF },
    rules: { schema: RULES },
    metadata: { schema: GOVERNANCE_METADATA },
    // `extends` and `merge_strategy` are stripped before projection and
    // `extensions` is projected against the extension schemas, so none of the
    // three appear here (spec sections 3.1 and 3.4).
  },
  ['hushspec'],
);

const POSTURE = object(
  {
    initial: { schema: LEAF },
    states: {
      schema: {
        kind: 'map',
        values: object({
          description: { schema: LEAF },
          capabilities: { schema: STRING_ARRAY },
          budgets: { schema: INTEGER_MAP },
        }),
      },
    },
    transitions: {
      schema: array(
        object(
          {
            from: { schema: LEAF },
            to: { schema: LEAF },
            on: { schema: LEAF },
            after: { schema: LEAF },
          },
          ['from', 'to', 'on'],
        ),
      ),
    },
  },
  ['initial', 'states', 'transitions'],
);

const ORIGINS = object({
  default_behavior: { schema: LEAF, default: 'deny' },
  profiles: {
    schema: array(
      object(
        {
          id: { schema: LEAF },
          // `match: {}` is the explicit catch-all profile; an absent `match`
          // never matches (spec section 3.3, origins spec 3).
          match: {
            presenceSignificant: true,
            schema: object({
              provider: { schema: LEAF },
              tenant_id: { schema: LEAF },
              space_id: { schema: LEAF },
              space_type: { schema: LEAF },
              visibility: { schema: LEAF },
              external_participants: { schema: LEAF },
              tags: { schema: STRING_ARRAY },
              sensitivity: { schema: LEAF },
              actor_role: { schema: LEAF },
            }),
          },
          posture: { schema: LEAF },
          tool_access: {
            schema: object({
              // Overlay lists: an absent one inherits the base block, an empty
              // one contributes nothing, and the two evaluate alike (origins
              // spec section 4), so an empty one is omitted like any other
              // no-default empty container (spec section 3.3).
              allow: { schema: STRING_ARRAY },
              block: { schema: STRING_ARRAY },
              require_confirmation: { schema: STRING_ARRAY },
              default: { schema: LEAF },
              max_args_size: { schema: LEAF },
            }),
          },
          egress: {
            schema: object({
              allow: { schema: STRING_ARRAY },
              block: { schema: STRING_ARRAY },
              default: { schema: LEAF },
            }),
          },
          data: {
            schema: object({
              allow_external_sharing: { schema: LEAF, default: false },
              redact_before_send: { schema: LEAF, default: false },
              block_sensitive_outputs: { schema: LEAF, default: false },
            }),
          },
          budgets: {
            schema: object({
              tool_calls: { schema: LEAF },
              egress_calls: { schema: LEAF },
              shell_commands: { schema: LEAF },
            }),
          },
          bridge: {
            schema: object({
              allow_cross_origin: { schema: LEAF, default: false },
              allowed_targets: {
                schema: array(
                  object({
                    provider: { schema: LEAF },
                    space_type: { schema: LEAF },
                    tags: { schema: STRING_ARRAY },
                    visibility: { schema: LEAF },
                  }),
                ),
              },
              require_approval: { schema: LEAF, default: false },
            }),
          },
          explanation: { schema: LEAF },
        },
        ['id'],
      ),
    ),
  },
});

const DETECTION = object({
  prompt_injection: {
    schema: object({
      enabled: { schema: LEAF, default: true },
      warn_at_or_above: { schema: LEAF, default: 'suspicious' },
      block_at_or_above: { schema: LEAF, default: 'high' },
      max_scan_bytes: { schema: LEAF, default: 200000 },
      heuristics: {
        schema: object({
          enabled: { schema: LEAF, default: true },
          min_score: { schema: LEAF, default: 0 },
        }),
      },
    }),
  },
  jailbreak: {
    schema: object({
      enabled: { schema: LEAF, default: true },
      block_threshold: { schema: LEAF, default: 80 },
      warn_threshold: { schema: LEAF, default: 50 },
      max_input_bytes: { schema: LEAF, default: 200000 },
    }),
  },
  threat_intel: {
    schema: object({
      enabled: { schema: LEAF, default: false },
      pattern_db: { schema: LEAF },
      similarity_threshold: { schema: LEAF, default: 0.7 },
      top_k: { schema: LEAF, default: 5 },
    }),
  },
});

/** Extension block name -> root schema (spec section 3.4). */
const EXTENSION_SCHEMAS: Readonly<Record<string, SchemaNode>> = {
  posture: POSTURE,
  origins: ORIGINS,
  detection: DETECTION,
};

/** Exposed for the schema drift test; not part of the public API. */
export const CANONICAL_SCHEMA_TABLE = {
  core: CORE,
  posture: POSTURE,
  origins: ORIGINS,
  detection: DETECTION,
} as const;

/** Resolution fields (core spec 2.3): never part of a resolved document. */
const RESOLUTION_FIELDS = ['extends', 'merge_strategy'] as const;
/** Reserved for an inline signature; never covered by the hash it signs. */
const INLINE_SIGNATURE_FIELD = 'signature';

// --------------------------------------------------------------------------
// Projection (spec section 3)
// --------------------------------------------------------------------------

function unwrap(node: SchemaNode): SchemaNode {
  let current = node;
  while (current.kind === 'lazy') {
    current = current.get();
  }
  return current;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isEmptyContainer(value: JsonValue): boolean {
  if (Array.isArray(value)) return value.length === 0;
  if (isPlainObject(value)) return Object.keys(value).length === 0;
  return false;
}

/**
 * Project one property value and decide whether it survives (spec section 3.3).
 * Returns `undefined` when the property is omitted.
 */
function projectProperty(
  value: unknown,
  property: PropertySchema,
  required: boolean,
  path: string,
): JsonValue | undefined {
  const projected = projectNode(value, property.schema, path);
  if (required || property.presenceSignificant === true) {
    return projected;
  }
  if (property.default !== undefined) {
    return projected;
  }
  // No schema default, not required, not presence-significant: an empty
  // container means the same as absence, so omit it.
  return isEmptyContainer(projected) ? undefined : projected;
}

function projectObject(
  value: Record<string, unknown>,
  node: ObjectNode,
  path: string,
): JsonValue {
  const required = new Set(node.required ?? []);
  const out: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;

  for (const key of Object.keys(value)) {
    const raw = value[key];
    // `undefined` is JavaScript's spelling of "absent"; a typed HushSpec
    // object built in code carries it where YAML would simply omit the key.
    if (raw === undefined) continue;
    const property = node.properties[key];
    if (property === undefined) {
      throw new CanonicalError(`unknown field ${path}.${key}`);
    }
    // Spec section 2.2: no HushSpec property is nullable, so a `null` written
    // for one is a validation error with no canonical form. A `null` inside a
    // free-form value is an ordinary leaf and never reaches here.
    if (raw === null) {
      throw new CanonicalError(`${path}.${key} is null; no property is nullable`);
    }
    const projected = projectProperty(raw, property, required.has(key), `${path}.${key}`);
    if (projected !== undefined) {
      out[key] = projected;
    }
  }

  for (const [key, property] of Object.entries(node.properties)) {
    if (property.default === undefined) continue;
    if (Object.prototype.hasOwnProperty.call(value, key) && value[key] !== undefined) continue;
    out[key] = clone(property.default);
  }

  return out;
}

function projectNode(value: unknown, schema: SchemaNode, path: string): JsonValue {
  const node = unwrap(schema);
  if (node.kind === 'object' && isPlainObject(value)) {
    return projectObject(value, node, path);
  }
  if (node.kind === 'array' && Array.isArray(value)) {
    return value.map((item, index) => projectNode(item, node.items, `${path}[${index}]`));
  }
  if (node.kind === 'map' && isPlainObject(value)) {
    // Schema map: every key is kept as written, every value projected.
    const out: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
    for (const key of Object.keys(value)) {
      const raw = value[key];
      if (raw === undefined) continue;
      out[key] = projectNode(raw, node.values, `${path}.${key}`);
    }
    return out;
  }
  // Leaves, free-form objects, and anything whose runtime shape does not match
  // the schema (validation's problem, not the projection's) pass through.
  return clone(value, path);
}

/** Structural copy that also rejects values with no JSON representation. */
function clone(value: unknown, path = '$'): JsonValue {
  if (value === null) return null;
  const kind = typeof value;
  if (kind === 'boolean' || kind === 'string') return value as boolean | string;
  if (kind === 'number') {
    const numeric = value as number;
    if (!Number.isFinite(numeric)) {
      throw new CanonicalError(`${path}: NaN and Infinity have no JSON representation`);
    }
    return numeric;
  }
  if (Array.isArray(value)) {
    return value.map((item, index) => clone(item, `${path}[${index}]`));
  }
  if (isPlainObject(value)) {
    const out: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
    for (const key of Object.keys(value)) {
      const raw = value[key];
      if (raw === undefined) continue;
      out[key] = clone(raw, `${path}.${key}`);
    }
    return out;
  }
  throw new CanonicalError(`${path}: value of type ${kind} cannot be canonicalized`);
}

/** The canonical projection of a resolved document (spec section 3). */
function project(spec: HushSpec): JsonValue {
  if (!isPlainObject(spec)) {
    throw new CanonicalError('document must be a mapping');
  }
  // Spec section 2.1: the canonical form identifies the policy that is
  // enforced, so an unresolved document has none.
  if (spec.extends != null) {
    throw new CanonicalError(
      `cannot canonicalize an unresolved document (extends: ${String(spec.extends)}); ` +
        'resolve the extends chain first',
    );
  }

  const document: Record<string, unknown> = { ...(spec as Record<string, unknown>) };
  for (const field of RESOLUTION_FIELDS) {
    delete document[field];
  }
  const metadata = document['metadata'];
  if (
    isPlainObject(metadata) &&
    Object.prototype.hasOwnProperty.call(metadata, INLINE_SIGNATURE_FIELD)
  ) {
    const stripped = { ...metadata };
    delete stripped[INLINE_SIGNATURE_FIELD];
    document['metadata'] = stripped;
  }

  const declaresExtensions = Object.prototype.hasOwnProperty.call(document, 'extensions');
  const extensions = document['extensions'];
  delete document['extensions'];

  const out = projectObject(document, CORE, '$');
  if (!declaresExtensions || extensions === undefined) {
    return out;
  }
  // Spec section 3.4: `extensions` is an object of published extension names.
  // Passing anything else through unprojected would hash a block no schema
  // describes.
  if (!isPlainObject(extensions)) {
    throw new CanonicalError('$.extensions must be an object');
  }

  const projectedExtensions: Record<string, JsonValue> = Object.create(null) as Record<
    string,
    JsonValue
  >;
  for (const name of Object.keys(extensions)) {
    const block = extensions[name];
    if (block === undefined) continue;
    const schema = EXTENSION_SCHEMAS[name];
    if (schema === undefined) {
      throw new CanonicalError(`unknown extension \`${name}\``);
    }
    const projected = projectNode(block, schema, `$.extensions.${name}`);
    if (isEmptyContainer(projected)) continue;
    projectedExtensions[name] = projected;
  }
  if (Object.keys(projectedExtensions).length > 0) {
    (out as Record<string, JsonValue>)['extensions'] = projectedExtensions;
  }
  return out;
}

// --------------------------------------------------------------------------
// RFC 8785 serialization (spec section 4)
// --------------------------------------------------------------------------

/**
 * Ascending order of UTF-16 code units (RFC 8785 3.2.3).
 *
 * JavaScript's `<` on strings already compares UTF-16 code units, so `"€"`
 * (U+20AC) sorts before `"😀"` (U+1F600) -- which is the order RFC
 * 8785 wants and *not* code-point order. `fixtures/core/hash/key-order-utf16.yaml`
 * pins it.
 */
function compareKeys(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

/**
 * ES6 `Number::toString` (RFC 8785 3.2.2.3): the shortest decimal that
 * round-trips through an IEEE 754 double.
 *
 * `String(n)` *is* that algorithm, so there is nothing to reimplement: whole
 * values lose their fraction (`10.0` -> `10`), `1e16` spells itself out as
 * `10000000000000000`, `1e21` becomes `1e+21`, and negative zero prints as
 * `0`.
 *
 * Spec section 4.3 bounds integer *syntax* by the IEEE 754 safe range and
 * leaves float syntax unbounded. A `number` no longer carries that
 * distinction, so the bound is applied by `parse()`, which reads the literal;
 * every finite double that reaches here is emitted.
 */
function formatNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw new CanonicalError('NaN and Infinity have no JSON representation');
  }
  return Object.is(value, -0) ? '0' : String(value);
}

/**
 * JCS string escaping (RFC 8785 3.2.2.2).
 *
 * `JSON.stringify` on a string produces exactly the JCS escape set: only
 * quote, reverse solidus and the C0 controls are escaped, with the short forms
 * for BS/TAB/LF/FF/CR and lowercase `\u00xx` for the rest. U+007F, U+00A0,
 * U+2028/U+2029 and astral characters are emitted literally, which is what JCS
 * requires and what `fixtures/core/hash/strings-escapes.yaml` pins.
 */
function formatString(value: string): string {
  return JSON.stringify(value);
}

function serialize(value: JsonValue, out: string[]): void {
  if (value === null) {
    out.push('null');
    return;
  }
  switch (typeof value) {
    case 'boolean':
      out.push(value ? 'true' : 'false');
      return;
    case 'number':
      out.push(formatNumber(value));
      return;
    case 'string':
      out.push(formatString(value));
      return;
    default:
      break;
  }
  if (Array.isArray(value)) {
    out.push('[');
    for (let index = 0; index < value.length; index += 1) {
      if (index > 0) out.push(',');
      serialize(value[index] as JsonValue, out);
    }
    out.push(']');
    return;
  }
  const keys = Object.keys(value).sort(compareKeys);
  out.push('{');
  for (let index = 0; index < keys.length; index += 1) {
    if (index > 0) out.push(',');
    const key = keys[index] as string;
    out.push(formatString(key), ':');
    serialize((value as Record<string, JsonValue>)[key] as JsonValue, out);
  }
  out.push('}');
}

// --------------------------------------------------------------------------
// Public API
// --------------------------------------------------------------------------

/**
 * The canonical JSON text of a **resolved** HushSpec document
 * (spec/hushspec-canonical.md sections 3 and 4).
 *
 * The document must already be valid (`validate()`) and resolved
 * (`resolve()`): a document that still carries `extends` identifies a fragment
 * rather than the policy that is enforced, so it is rejected instead of
 * hashed. `merge_strategy` and `metadata.signature` are never emitted.
 *
 * @throws {CanonicalError} if `extends` is set, if a key is not one the
 * schema declares, if a declared property is `null`, if `extensions` is not an
 * object of published extension names, or if the document holds a value with
 * no JSON representation (spec sections 2.1, 2.2, 2.3, 3.4 and 4.3).
 */
export function canonicalJson(spec: HushSpec): string {
  const out: string[] = [];
  serialize(project(spec), out);
  return out.join('');
}

/**
 * RFC 8785 (JCS) serialization of an arbitrary JSON value (spec section 4,
 * the serialization step on its own).
 *
 * The projection of section 3 is schema-driven and applies to HushSpec
 * documents only; other objects that have to be hashed or signed byte-exactly
 * -- a signature envelope (spec/hushspec-signing.md section 4.1), a receipt
 * -- carry no schema defaults and need the serializer alone. Sharing it is the
 * point: the envelope a signer signs and the envelope a verifier checks are
 * canonicalized by the same code as the policy hash inside them.
 *
 * @throws {CanonicalError} if the value holds something with no JSON
 * representation: NaN, Infinity, a function, a symbol.
 */
export function canonicalizeValue(value: JsonValue): string {
  const out: string[] = [];
  serialize(clone(value), out);
  return out.join('');
}

/**
 * The content hash of a **resolved** HushSpec document (spec section 5):
 * `sha256:` followed by 64 lowercase hex digits of SHA-256 over the UTF-8
 * bytes of {@link canonicalJson}.
 *
 * The `sha256:` prefix is part of the wire value everywhere a content hash
 * appears -- receipts, signature envelopes, log entries -- so a verifier can
 * reject an unknown algorithm instead of guessing.
 *
 * @throws {CanonicalError} under the same conditions as {@link canonicalJson}.
 */
export function contentHash(spec: HushSpec): string {
  return `sha256:${createHash('sha256').update(canonicalJson(spec), 'utf8').digest('hex')}`;
}
