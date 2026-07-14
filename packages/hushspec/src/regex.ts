/**
 * Pattern that detects regex features outside the RE2 subset.
 *
 * HushSpec requires all regex patterns to be RE2-compatible to prevent ReDoS
 * attacks. JavaScript's RegExp uses a backtracking engine that is vulnerable
 * to catastrophic backtracking with certain pattern constructs. By restricting
 * patterns to the RE2 subset, we ensure safe O(mn) evaluation across all SDKs.
 *
 * Disallowed features:
 * - Backreferences: \1, \2, ..., \k<name>
 * - Lookahead: (?=...), (?!...)
 * - Lookbehind: (?<=...), (?<!...)
 * - Atomic groups: (?>...)
 * - Possessive quantifiers: *+, ++, ?+
 * - Conditional patterns: (?(...)...|...)
 * - Recursive patterns: (?R), (?1), (?2), ...
 * - Named backreferences: (?P=name)
 * - Subroutine calls: \g<name>
 */
const RE2_DISALLOWED = /\\[1-9]|\\k<|\(\?[=!]|\(\?<[=!]|\(\?>|\*\+|\+\+|\?\+|\(\?\(|\(\?R\)|\(\?\d+\)|\(\?P=|\\g</;
const LEADING_INLINE_FLAGS = /^\(\?([ims]+)\)/;
const PYTHON_NAMED_GROUP = /\(\?P<([A-Za-z_][A-Za-z0-9_]*)>/g;

export interface CompiledPolicyRegex {
  source: string;
  flags: string;
  regex: RegExp;
}

export function isSafeRegex(pattern: string): boolean {
  // RE2-feature check first: reject non-RE2 features (backreferences, lookaround,
  // atomic/possessive constructs, ...). This alone guarantees safety on the
  // RE2-based SDKs (Rust, Go).
  if (RE2_DISALLOWED.test(pattern)) {
    return false;
  }
  // Nested-quantifier check second: RE2 tolerates shapes like `(a+)+` that
  // catastrophically backtrack on the backtracking engines (JavaScript `RegExp`,
  // Python `re`), so reject them here to keep the contract identical across SDKs.
  return !hasNestedQuantifier(pattern);
}

type QuantKind = 'none' | 'bounded' | 'unbounded';

/**
 * Fail-closed over-approximation that flags nested unbounded quantifiers such as
 * `(a+)+`, `([0-9]+)*`, or `((ab)+)+`. Scans `(`...`)` group nesting -- ignoring
 * escaped parens and character-class contents -- and rejects when a group whose
 * body contains an unbounded quantifier (`*`, `+`, `{n,}`) is itself immediately
 * followed by an unbounded quantifier. Bounded quantifiers (`(a{1,3}){1,3}`,
 * `(abc)+`) are accepted. Must stay identical to the Rust, Python, and Go
 * implementations.
 */
function hasNestedQuantifier(pattern: string): boolean {
  const chars = Array.from(pattern);
  const n = chars.length;
  // Per open group: whether its body has seen an unbounded quantifier.
  const stack: boolean[] = [];
  let inClass = false;
  let i = 0;
  while (i < n) {
    const c = chars[i];
    if (c === '\\') {
      // Escaped char (e.g. `\(`, `\)`, `\[`, `\+`) -- skip both.
      i += 2;
      continue;
    }
    if (inClass) {
      if (c === ']') {
        inClass = false;
      }
      i += 1;
      continue;
    }
    if (c === '[') {
      inClass = true;
      i += 1;
      continue;
    }
    if (c === '(') {
      stack.push(false);
      i += 1;
      continue;
    }
    if (c === ')') {
      const closedUnbounded = stack.pop() ?? false;
      const [kind, qlen] = classifyQuantifier(chars, i + 1);
      if (kind === 'unbounded') {
        if (closedUnbounded) {
          return true;
        }
        // The just-closed group is unbounded-quantified, so it is an unbounded
        // quantifier within the parent group's body.
        if (stack.length > 0) {
          stack[stack.length - 1] = true;
        }
        i += 1 + qlen;
      } else {
        i += 1;
      }
      continue;
    }
    const [kind, qlen] = classifyQuantifier(chars, i);
    if (kind === 'unbounded') {
      if (stack.length > 0) {
        stack[stack.length - 1] = true;
      }
      i += qlen;
    } else if (kind === 'bounded') {
      i += qlen;
    } else {
      i += 1;
    }
  }
  return false;
}

/**
 * Classify the quantifier token starting at `pos`, returning its kind and the
 * number of chars it spans (including any trailing lazy/possessive marker).
 */
function classifyQuantifier(chars: string[], pos: number): [QuantKind, number] {
  if (pos >= chars.length) {
    return ['none', 0];
  }
  const c = chars[pos];
  if (c === '*' || c === '+') {
    return ['unbounded', markerFollows(chars, pos + 1) ? 2 : 1];
  }
  if (c === '?') {
    return ['bounded', markerFollows(chars, pos + 1) ? 2 : 1];
  }
  if (c === '{') {
    let j = pos + 1;
    while (j < chars.length && chars[j] !== '}') {
      j += 1;
    }
    if (j >= chars.length) {
      return ['none', 0]; // unterminated `{` -> literal
    }
    const inner = chars.slice(pos + 1, j).join('');
    const kind = braceKind(inner);
    if (kind === 'none') {
      return ['none', 0];
    }
    const length = j - pos + 1 + (markerFollows(chars, j + 1) ? 1 : 0);
    return [kind, length];
  }
  return ['none', 0];
}

function markerFollows(chars: string[], pos: number): boolean {
  return pos < chars.length && (chars[pos] === '?' || chars[pos] === '+');
}

/**
 * Classify the content between `{` and `}`: `{n,}` is unbounded, `{n}` and
 * `{n,m}` are bounded, anything else is a literal brace (not a quantifier).
 */
function braceKind(inner: string): QuantKind {
  if (inner.length === 0) {
    return 'none';
  }
  const isDigits = (s: string): boolean => s.length > 0 && /^[0-9]+$/.test(s);
  const commas = (inner.match(/,/g) ?? []).length;
  if (commas === 0) {
    return isDigits(inner) ? 'bounded' : 'none';
  }
  if (commas === 1) {
    const [lo, hi] = inner.split(',');
    const loOk = lo === '' || isDigits(lo);
    const hiOk = hi === '' || isDigits(hi);
    if (!loOk || !hiOk || (lo === '' && hi === '')) {
      return 'none';
    }
    return hi === '' ? 'unbounded' : 'bounded';
  }
  return 'none';
}

export function compilePolicyRegex(pattern: string): CompiledPolicyRegex {
  const normalized = normalizePolicyRegex(pattern);
  return {
    ...normalized,
    regex: new RegExp(normalized.source, normalized.flags),
  };
}

export function compileSafePolicyRegex(pattern: string): CompiledPolicyRegex {
  if (!isSafeRegex(pattern)) {
    throw new Error('pattern uses features not in the RE2 subset');
  }
  return compilePolicyRegex(pattern);
}

function normalizePolicyRegex(pattern: string): { source: string; flags: string } {
  let source = pattern;
  let flags = '';

  while (true) {
    const match = source.match(LEADING_INLINE_FLAGS);
    if (match == null) {
      break;
    }

    for (const flag of match[1]) {
      if (!flags.includes(flag)) {
        flags += flag;
      }
    }

    source = source.slice(match[0].length);
  }

  source = source.replace(PYTHON_NAMED_GROUP, '(?<$1>');
  return { source, flags };
}
