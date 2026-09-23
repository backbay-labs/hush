import YAML, { isScalar } from 'yaml';
import type { HushSpec } from './schema.js';
import { validateForParse, type ErrorCode } from './validate.js';
import { utf8ByteLength } from './utf8.js';

export type ParseResult =
  | { ok: true; value: HushSpec }
  | {
    ok: false;
    error: string;
    /**
     * The registered code for this refusal
     * (`spec/registries/error-codes.yaml`). Every shape, type, profile and
     * syntax failure is `E001`; a document whose `hushspec` names a version
     * this engine does not accept is `E002`.
     */
    code: ErrorCode;
  };

/** Maximum accepted document size in bytes (core spec 2.4, RECOMMENDED default). */
export const MAX_DOCUMENT_BYTES = 1024 * 1024;
/** Maximum accepted nesting depth (core spec 2.4, RECOMMENDED default). */
export const MAX_DOCUMENT_DEPTH = 32;
/** Maximum accepted node count (core spec 2.4, RECOMMENDED default). */
export const MAX_NODE_COUNT = 100_000;

/** Largest integer an IEEE 754 double holds exactly (canonical spec 4.3). */
const MAX_SAFE_INTEGER = BigInt(Number.MAX_SAFE_INTEGER);

/**
 * Parse a HushSpec document under the YAML profile of core spec 2.4.
 *
 * The `yaml` package is configured for the YAML 1.2 Core schema (so `yes`/`no`
 * are strings, not booleans), rejects duplicate mapping keys, rejects tab
 * indentation, and rejects multi-document streams. The profile additionally
 * forbids anchors, aliases and merge keys, and bounds the input size, nesting
 * depth and node count; those checks live here.
 *
 * `intAsBigInt` keeps integer syntax apart from float syntax through the
 * decode, which is what canonical spec 4.3's safe-integer bound is written
 * against. `narrowIntegers` applies the bound and hands every integer on as a
 * `number`, so no BigInt leaves this module.
 */
export function parse(yaml: string): ParseResult {
  if (utf8ByteLength(yaml) > MAX_DOCUMENT_BYTES) {
    return parseError(`document exceeds the maximum size of ${MAX_DOCUMENT_BYTES} bytes`);
  }

  const violation = yamlProfileViolation(yaml);
  if (violation != null) {
    return parseError(violation);
  }

  let doc: unknown;
  // A duplicate mapping key is reported by the `yaml` package without naming
  // the key; this records it so the diagnostic can say which one.
  let duplicateKey: string | undefined;
  try {
    const parsed = YAML.parseDocument(yaml, {
      version: '1.2',
      schema: 'core',
      intAsBigInt: true,
      resolveKnownTags: false,
      customTags: [{
        tag: 'tag:yaml.org,2002:float',
        default: false,
        resolve(text: string, onError: (message: string) => void) {
          if (!/^[-+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]+)?$/.test(text)) {
            onError('invalid YAML 1.2 Core float');
          }
          return Number(text);
        },
      }],
      uniqueKeys: (a, b) => {
        const equal = a === b || (isScalar(a) && isScalar(b) && a.value === b.value);
        if (equal && duplicateKey === undefined) {
          duplicateKey = isScalar(a) ? String(a.value) : String(a);
        }
        return equal;
      },
      // Anchors and aliases are rejected by the pre-scan above; refuse to
      // expand any that slip past it rather than silently duplicating nodes.
      merge: false,
    });
    if (parsed.errors.length > 0) throw parsed.errors[0];
    const tagError = parsed.warnings.find((warning) => warning.code === 'TAG_RESOLVE_FAILED');
    if (tagError !== undefined) throw tagError;
    doc = parsed.toJS({ maxAliasCount: 0 });
  } catch (error) {
    return parseError(describeYamlError(error, duplicateKey));
  }

  try {
    doc = narrowIntegers(doc, '$');
  } catch (error) {
    if (error instanceof UnsafeIntegerError) {
      return parseError(error.message);
    }
    throw error;
  }

  const measured = measure(doc, 1);
  if (measured.depth > MAX_DOCUMENT_DEPTH) {
    return parseError(`document nesting exceeds the maximum depth of ${MAX_DOCUMENT_DEPTH}`);
  }
  if (measured.nodes > MAX_NODE_COUNT) {
    return parseError(`document exceeds the maximum node count of ${MAX_NODE_COUNT}`);
  }

  if (typeof doc === 'object' && doc !== null && 'hushspec' in doc && typeof doc.hushspec !== 'string') {
    return parseError('hushspec: invalid type, expected a version string');
  }
  const result = validateForParse(doc);
  if (!result.valid) {
    const first = result.errors[0];
    return {
      ok: false,
      error: first?.message ?? 'invalid HushSpec document',
      code: first?.code ?? 'E001',
    };
  }

  const integerViolation = policyIntegerViolation(doc);
  if (integerViolation !== undefined) return parseError(integerViolation);

  return { ok: true, value: doc as HushSpec };
}

/** Integer properties have the portable range even when written with float
 * syntax. The ratio/similarity number fields and arbitrary condition context
 * retain finite doubles beyond this range (canonical 4.3).
 */
function policyIntegerViolation(value: unknown, path: string[] = []): string | undefined {
  const tail = path.slice(-2).join('.');
  if (path.at(-1) === 'context' && typeof value === 'object' && value !== null && !Array.isArray(value)) return undefined;
  if (typeof value === 'number') {
    if (tail !== 'patch_integrity.max_imbalance_ratio' && tail !== 'threat_intel.similarity_threshold'
        && !Number.isSafeInteger(value)) {
      return `${path.join('.')}: integer field exceeds the safe range (2^53-1)`;
    }
  } else if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index++) {
      const issue = policyIntegerViolation(value[index], [...path, String(index)]);
      if (issue !== undefined) return issue;
    }
  } else if (typeof value === 'object' && value !== null) {
    for (const [key, child] of Object.entries(value)) {
      const issue = policyIntegerViolation(child, [...path, key]);
      if (issue !== undefined) return issue;
    }
  }
  return undefined;
}

/** Throwing variant of `parse()`. */
export function parseOrThrow(yaml: string): HushSpec {
  const result = parse(yaml);
  if (!result.ok) {
    throw new Error(result.error);
  }
  return result.value;
}

/** A refusal at the YAML layer: always E001 (error-code registry). */
function parseError(detail: string): ParseResult {
  return { ok: false, error: `YAML parse error: ${detail}`, code: 'E001' };
}

/**
 * The `yaml` package's diagnostic, with a duplicate-key failure respelled to
 * name the key -- `Map keys must be unique` says which line but not which key,
 * and the key is what an author needs.
 */
function describeYamlError(error: unknown, duplicateKey: string | undefined): string {
  const message = error instanceof Error ? error.message : String(error);
  if (duplicateKey === undefined) return message;
  const position = /at line (\d+), column (\d+)/.exec(message);
  const where = position == null ? '' : ` at line ${position[1]} column ${position[2]}`;
  return `duplicate entry with key ${JSON.stringify(duplicateKey)}${where}`;
}

/** An integer literal the IEEE 754 safe range cannot hold (canonical spec 4.3). */
class UnsafeIntegerError extends Error {}

/**
 * Replace every BigInt the decode produced with a `number`, refusing one
 * outside the IEEE 754 safe range (canonical spec 4.3).
 *
 * The bound belongs to integer syntax: `10000000000000000` names an exact
 * integer that a double cannot hold, while `1.0e+16` names the double itself
 * and is emitted whatever its magnitude. JavaScript has one numeric type, so
 * the parser is the only place that distinction survives -- `intAsBigInt`
 * hands integer-syntax scalars over as BigInt and float-syntax scalars as
 * `number`. Applying the bound here means a rounded integer can never reach a
 * content hash, and the rest of the SDK works with plain numbers.
 */
function narrowIntegers(value: unknown, path: string): unknown {
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new UnsafeIntegerError(`${path}: non-finite numbers are not allowed`);
  }
  if (typeof value === 'bigint') {
    if (value > MAX_SAFE_INTEGER || value < -MAX_SAFE_INTEGER) {
      throw new UnsafeIntegerError(
        `${path}: integer ${value} exceeds the safe range (2^53-1)`,
      );
    }
    return Number(value);
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      value[index] = narrowIntegers(value[index], `${path}[${index}]`);
    }
    return value;
  }
  if (typeof value === 'object' && value !== null) {
    const record = value as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      record[key] = narrowIntegers(record[key], `${path}.${key}`);
    }
    return value;
  }
  return value;
}

interface Measured {
  depth: number;
  nodes: number;
}

function measure(value: unknown, depth: number): Measured {
  if (Array.isArray(value)) {
    let maxDepth = depth;
    let nodes = 1;
    for (const item of value) {
      const child = measure(item, depth + 1);
      if (child.depth > maxDepth) maxDepth = child.depth;
      nodes += child.nodes;
    }
    return { depth: maxDepth, nodes };
  }
  if (typeof value === 'object' && value !== null) {
    let maxDepth = depth;
    let nodes = 1;
    for (const [, item] of Object.entries(value as Record<string, unknown>)) {
      // A mapping key is itself a scalar node one level down, so it counts
      // toward both the depth and the node budget (core spec 2.4).
      if (depth + 1 > maxDepth) maxDepth = depth + 1;
      nodes += 1;
      const child = measure(item, depth + 1);
      if (child.depth > maxDepth) maxDepth = child.depth;
      nodes += child.nodes;
    }
    return { depth: maxDepth, nodes };
  }
  return { depth, nodes: 1 };
}

/**
 * Scan the raw text for constructs the YAML profile forbids: a second
 * document, anchors (`&name`), aliases (`*name`), and merge keys (`<<:`).
 *
 * The scanner tracks comments, quoted scalars, and block scalars so that a `*`
 * or `&` inside them is not mistaken for an indicator. In YAML a plain scalar
 * cannot begin with `&` or `*`, so an indicator at a node-start position is
 * always an anchor or alias.
 */
export function yamlProfileViolation(yaml: string): string | undefined {
  let blockScalarIndent: number | undefined;
  let sawContent = false;
  let lineNumber = 0;

  for (const line of yaml.split('\n')) {
    lineNumber += 1;
    let indent = 0;
    while (indent < line.length && line[indent] === ' ') indent += 1;
    const trimmed = line.trim();

    if (blockScalarIndent != null) {
      if (trimmed.length === 0 || indent >= blockScalarIndent) {
        continue;
      }
      blockScalarIndent = undefined;
    }

    if (trimmed.length === 0 || trimmed.startsWith('#')) {
      continue;
    }
    if (trimmed === '---' || trimmed.startsWith('--- ')) {
      if (sawContent) {
        return `line ${lineNumber}: multi-document streams are not allowed (YAML profile)`;
      }
      continue;
    }
    if (trimmed === '...') {
      sawContent = true;
      continue;
    }
    sawContent = true;

    const message = scanLine(line, lineNumber);
    if (message != null) {
      return message;
    }
    if (lineStartsBlockScalar(line)) {
      blockScalarIndent = indent + 1;
    }
  }
  return undefined;
}

/**
 * Whether the line's value (outside quotes and comments) ends with a block
 * scalar indicator (`|`, `>`, with optional chomping/indentation modifiers).
 */
function lineStartsBlockScalar(line: string): boolean {
  const code = stripCommentAndQuotes(line).replace(/\s+$/, '');
  const lastSpace = code.lastIndexOf(' ');
  if (lastSpace < 0) return false;
  const token = code.slice(lastSpace + 1);
  if (token.length === 0) return false;
  if (token[0] !== '|' && token[0] !== '>') return false;
  for (const ch of token.slice(1)) {
    if (ch !== '+' && ch !== '-' && !/[0-9]/.test(ch)) return false;
  }
  const head = code.slice(0, lastSpace).replace(/\s+$/, '');
  return head.endsWith(':') || head.endsWith('-');
}

/**
 * Replace quoted scalars with spaces and drop trailing comments so indicator
 * scanning only sees structural text.
 */
function stripCommentAndQuotes(line: string): string {
  let out = '';
  let inSingle = false;
  let inDouble = false;
  let prevSpace = true;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inDouble) {
      if (c === '\\') {
        i += 1;
        out += '  ';
        continue;
      }
      if (c === '"') {
        inDouble = false;
      }
      out += ' ';
      continue;
    }
    if (inSingle) {
      if (c === "'") {
        if (line[i + 1] === "'") {
          i += 1;
          out += '  ';
          continue;
        }
        inSingle = false;
      }
      out += ' ';
      continue;
    }
    if (c === '"') {
      inDouble = true;
      out += ' ';
    } else if (c === "'") {
      inSingle = true;
      out += ' ';
    } else if (c === '#' && prevSpace) {
      break;
    } else {
      out += c;
    }
    prevSpace = c === ' ';
  }
  return out;
}

const NODE_START_PREDECESSORS = new Set([' ', '[', '{', ',', '\t']);
const NODE_START_ANCESTORS = new Set([':', '-', '?', '[', '{', ',']);

function scanLine(line: string, lineNumber: number): string | undefined {
  const code = stripCommentAndQuotes(line);
  for (let index = 0; index < code.length; index++) {
    const ch = code[index];
    if (ch !== '&' && ch !== '*' && ch !== '<') continue;

    const next = code[index + 1];
    const nextIsWord = next != null && !/\s/.test(next) && next !== ',' && next !== ']' && next !== '}';

    let atNodeStart: boolean;
    if (index === 0) {
      atNodeStart = true;
    } else if (!NODE_START_PREDECESSORS.has(code[index - 1])) {
      atNodeStart = false;
    } else if (index < 2) {
      atNodeStart = true;
    } else {
      let lastNonSpace: string | undefined;
      for (let back = index - 1; back >= 0; back--) {
        if (code[back] !== ' ') {
          lastNonSpace = code[back];
          break;
        }
      }
      atNodeStart = lastNonSpace == null || NODE_START_ANCESTORS.has(lastNonSpace);
    }
    if (!atNodeStart) continue;

    if (ch === '&' && nextIsWord) {
      return `line ${lineNumber}: anchors are not allowed (YAML profile)`;
    }
    if (ch === '*' && nextIsWord) {
      return `line ${lineNumber}: aliases are not allowed (YAML profile)`;
    }
    if (ch === '<' && code.startsWith('<<', index)) {
      const rest = code.slice(index + 2).replace(/^\s+/, '');
      if (rest.startsWith(':')) {
        return `line ${lineNumber}: merge keys are not allowed (YAML profile)`;
      }
    }
  }
  return undefined;
}
