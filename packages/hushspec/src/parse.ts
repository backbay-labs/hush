import YAML from 'yaml';
import type { HushSpec } from './schema.js';
import { validateForParse } from './validate.js';

export type ParseResult =
  | { ok: true; value: HushSpec }
  | { ok: false; error: string };

/** Maximum accepted document size in bytes (core spec 2.4, RECOMMENDED default). */
export const MAX_DOCUMENT_BYTES = 1024 * 1024;
/** Maximum accepted nesting depth (core spec 2.4, RECOMMENDED default). */
export const MAX_DOCUMENT_DEPTH = 32;
/** Maximum accepted node count (core spec 2.4, RECOMMENDED default). */
export const MAX_NODE_COUNT = 100_000;

/**
 * Parse a HushSpec document under the YAML profile of core spec 2.4 (D17).
 *
 * The `yaml` package is configured for the YAML 1.2 Core schema (so `yes`/`no`
 * are strings, not booleans), rejects duplicate mapping keys, rejects tab
 * indentation, and rejects multi-document streams. The profile additionally
 * forbids anchors, aliases and merge keys, and bounds the input size, nesting
 * depth and node count; those checks live here.
 */
export function parse(yaml: string): ParseResult {
  if (byteLength(yaml) > MAX_DOCUMENT_BYTES) {
    return {
      ok: false,
      error: `YAML parse error: document exceeds the maximum size of ${MAX_DOCUMENT_BYTES} bytes`,
    };
  }

  const violation = yamlProfileViolation(yaml);
  if (violation != null) {
    return { ok: false, error: `YAML parse error: ${violation}` };
  }

  let doc: unknown;
  try {
    doc = YAML.parse(yaml, {
      version: '1.2',
      schema: 'core',
      uniqueKeys: true,
      // Anchors and aliases are rejected by the pre-scan above; refuse to
      // expand any that slip past it rather than silently duplicating nodes.
      maxAliasCount: 0,
      merge: false,
    });
  } catch (error) {
    return {
      ok: false,
      error: `YAML parse error: ${error instanceof Error ? error.message : String(error)}`,
    };
  }

  const measured = measure(doc, 1);
  if (measured.depth > MAX_DOCUMENT_DEPTH) {
    return {
      ok: false,
      error: `YAML parse error: document nesting exceeds the maximum depth of ${MAX_DOCUMENT_DEPTH}`,
    };
  }
  if (measured.nodes > MAX_NODE_COUNT) {
    return {
      ok: false,
      error: `YAML parse error: document exceeds the maximum node count of ${MAX_NODE_COUNT}`,
    };
  }

  const result = validateForParse(doc);
  if (!result.valid) {
    return {
      ok: false,
      error: result.errors[0]?.message ?? 'invalid HushSpec document',
    };
  }

  return { ok: true, value: doc as HushSpec };
}

/** Throwing variant of `parse()`. */
export function parseOrThrow(yaml: string): HushSpec {
  const result = parse(yaml);
  if (!result.ok) {
    throw new Error(result.error);
  }
  return result.value;
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).length;
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
      // The key is a scalar node one level down, matching the reference
      // engine's traversal of YAML mappings.
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
 * always an anchor or alias. Port of `yaml_profile_violation` in
 * `crates/hushspec/src/schema.rs`.
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
