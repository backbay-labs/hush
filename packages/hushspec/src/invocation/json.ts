import { createHash } from 'node:crypto';
import { canonicalizeValue, type JsonValue } from '../canonical.js';

export interface SnapshotLimits {
  maxBytes?: number;
  maxDepth?: number;
  maxNodes?: number;
}

/** Reject unpaired UTF-16 code units before UTF-8 encoding could replace them. */
export function assertUnicode(value: string): void {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error('invalid Unicode');
    } else if (unit >= 0xdc00 && unit <= 0xdfff) throw new Error('invalid Unicode');
  }
}

/** Strict JSON at the invocation boundary, including escape-equivalent duplicate keys. */
export function snapshotJson(text: string, limits: SnapshotLimits = {}): JsonValue {
  const { maxBytes = 65_536, maxDepth = 16, maxNodes = 4096 } = limits;
  if (![maxBytes, maxDepth, maxNodes].every(n => Number.isSafeInteger(n) && n > 0)) {
    throw new Error('invalid snapshot limits');
  }
  if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > maxBytes) {
    throw new Error('JSON byte limit exceeded');
  }
  let position = 0;
  let nodes = 0;
  const fail = (): never => { throw new Error(`invalid JSON at offset ${position}`); };
  const space = () => { while (/[\x20\t\r\n]/.test(text[position] ?? '\0')) position++; };
  const count = () => { if (++nodes > maxNodes) throw new Error('JSON node limit exceeded'); };
  const string = (): string => {
    if (text[position] !== '"') return fail();
    const start = position++;
    while (position < text.length) {
      const char = text[position++];
      if (char === '\\') position++;
      else if (char === '"') {
        const result: string = JSON.parse(text.slice(start, position));
        assertUnicode(result);
        return result;
      }
    }
    return fail();
  };
  const value = (depth: number): JsonValue => {
    if (depth > maxDepth) throw new Error('JSON depth limit exceeded');
    count();
    space();
    const char = text[position];
    if (char === '"') return string();
    if (char === '{' || char === '[') {
      position++;
      const object: Record<string, JsonValue> = Object.create(null);
      const array: JsonValue[] = [];
      const close = char === '{' ? '}' : ']';
      space();
      if (text[position] !== close) {
        for (;;) {
          space();
          if (char === '{') {
            count();
            const key = string();
            if (Object.hasOwn(object, key)) throw new Error('duplicate JSON key');
            space();
            if (text[position++] !== ':') return fail();
            object[key] = value(depth + 1);
          } else array.push(value(depth + 1));
          space();
          if (text[position] === close) break;
          if (text[position++] !== ',') return fail();
        }
      }
      position++;
      return Object.freeze(char === '{' ? object : array) as JsonValue;
    }
    for (const [token, literal] of [['true', true], ['false', false], ['null', null]] as const) {
      if (text.startsWith(token, position)) { position += token.length; return literal; }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(position));
    if (number === null) return fail();
    position += number[0].length;
    const result = Number(number[0]);
    if (!Number.isFinite(result)) throw new Error('nonfinite JSON number');
    return result;
  };
  const result = value(0);
  space();
  if (position !== text.length) return fail();
  return result;
}

/** Copy trusted JSON-shaped host data without retaining mutable references. */
export function copyJson<T>(value: T, limits?: SnapshotLimits): T {
  return snapshotJson(canonicalizeValue(value as JsonValue), limits) as T;
}

export function hashJson(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalizeValue(value as JsonValue), 'utf8').digest('hex')}`;
}

export function jsonObject(value: unknown): Record<string, JsonValue> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('expected JSON object');
  }
  return value as Record<string, JsonValue>;
}
