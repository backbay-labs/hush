/**
 * Pattern that detects regex features outside the RE2 subset.
 *
 * HushSpec requires every policy regex to stay inside the RE2 subset (core
 * spec 3.14.3). JavaScript's `RegExp` is a backtracking engine, and certain
 * constructs make it backtrack catastrophically; the subset keeps evaluation
 * O(mn) whichever engine a conformant SDK is built on.
 *
 * Disallowed features:
 * - Backreferences: \1, \2, ..., \k<name>
 * - Lookahead: (?=...), (?!...)
 * - Lookbehind: (?<=...), (?<!...)
 * - Atomic groups: (?>...)
 * - Possessive quantifiers: *+, ++, ?+, and possessive braces {n}+, {n,}+,
 *   {n,m}+ (checked separately by hasPossessiveQuantifier below, since
 *   distinguishing a genuine possessive quantifier from possessive-looking
 *   characters that are actually literal class members (`[*+]`, `[?+]`) or
 *   an unrelated literal brace (`a{b}+`) needs escape/class-aware scanning,
 *   not a fixed substring)
 * - Conditional patterns: (?(...)...|...)
 * - Recursive patterns: (?R), (?1), (?2), ...
 * - Named backreferences: (?P=name)
 * - Subroutine calls: \g<name>
 * - \Z / \z end-of-string anchors (engines disagree on their meaning, and
 *   JavaScript reads them as literal letters). Use $ instead. (checked
 *   separately by hasEndAnchorEscape below, since a fixed substring can't
 *   distinguish the anchor `\Z` from an escaped backslash followed by a
 *   literal Z, i.e. the pattern text `\\Z`)
 * - Empty character classes: [], [^] (checked separately by
 *   hasEmptyCharacterClass below; JavaScript accepts them where most engines
 *   reject them)
 */
const RE2_DISALLOWED = /\\[1-9]|\\k<|\(\?[=!]|\(\?<[=!]|\(\?>|\(\?\(|\(\?R\)|\(\?\d+\)|\(\?P=|\\g</;

export interface CompiledPolicyRegex {
  source: string;
  flags: string;
  regex: RegExp;
}

export function isSafeRegex(pattern: string): boolean {
  // RE2-feature check first: reject the constructs outside the subset
  // (backreferences, lookaround, atomic groups, ...). On an RE2-backed engine
  // this alone is enough for the linear-time guarantee.
  if (RE2_DISALLOWED.test(pattern)) {
    return false;
  }
  // Possessive quantifiers (bare `*+`/`++`/`?+` and braced `{n}+`, `{n,}+`,
  // `{n,m}+`), `\Z`/`\z` end-anchors, and empty character classes (`[]`,
  // `[^]`) all need escape/class-aware scanning to detect precisely -- a
  // fixed substring would also misfire inside an unrelated character class
  // (`[*+]`, `[a{2}+]`) or on an escaped backslash followed by a literal Z/z
  // (`\\Z`), so each gets a dedicated walk rather than a RE2_DISALLOWED
  // alternative.
  if (hasPossessiveQuantifier(pattern) || hasEndAnchorEscape(pattern) || hasEmptyCharacterClass(pattern)) {
    return false;
  }
  // Nested-quantifier check last: RE2 tolerates shapes like `(a+)+` that
  // catastrophically backtrack on a backtracking engine, so they are rejected
  // here too and the accepted set is the same whatever the engine.
  return !hasNestedQuantifier(pattern);
}

type QuantKind = 'none' | 'bounded' | 'unbounded';

/**
 * Fail-closed over-approximation that flags nested unbounded quantifiers such as
 * `(a+)+`, `([0-9]+)*`, or `((ab)+)+`. Scans `(`...`)` group nesting -- ignoring
 * escaped parens and character-class contents -- and rejects when a group whose
 * body contains an unbounded quantifier (`*`, `+`, `{n,}`) is itself immediately
 * followed by an unbounded quantifier. Bounded quantifiers (`(a{1,3}){1,3}`,
 * `(abc)+`) are accepted.
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

/**
 * Fail-closed, escape/class-aware scan for possessive quantifiers: the bare
 * forms `*+`, `++`, `?+` and the brace forms `{n}+`, `{n,}+`, `{n,m}+`.
 *
 * A fixed substring would over-reject: `*`, `+`, `?` and `}+` are ordinary
 * literal members inside a character class (`[*+]`, `[?+]`, `[a{2}+]`), and a
 * `{...}` that is not digit-shaped is a literal brace whose trailing `+`
 * genuinely quantifies the `}` (`a{b}+`). So the scan tracks class state and
 * reuses `braceKind` to confirm a real quantifier. A `?` after the closing
 * brace is the allowed lazy marker (`{n,m}?`), not a possessive one.
 */
function hasPossessiveQuantifier(pattern: string): boolean {
  const chars = Array.from(pattern);
  const n = chars.length;
  let inClass = false;
  let i = 0;
  while (i < n) {
    const c = chars[i];
    if (c === '\\') {
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
    if ((c === '*' || c === '+' || c === '?') && chars[i + 1] === '+') {
      return true;
    }
    if (c === '{') {
      let j = i + 1;
      while (j < n && chars[j] !== '}') {
        j += 1;
      }
      if (j < n && braceKind(chars.slice(i + 1, j).join('')) !== 'none' && chars[j + 1] === '+') {
        return true;
      }
    }
    i += 1;
  }
  return false;
}

/**
 * Fail-closed, escape/class-aware scan for the `\Z` / `\z` end-of-string
 * anchors, which the profile forbids in favour of `$`: engines that treat
 * them as anchors disagree with each other about whether a trailing newline
 * is inside the match, and JavaScript `RegExp` reads them as a literal
 * letter instead.
 *
 * The escaped pair is consumed (`i += 2`) only *after* checking whether the
 * next character is `Z`/`z`, which is what distinguishes the anchor `\Z`
 * (one backslash then Z) from the pattern text `\\Z` -- an escaped backslash
 * followed by a literal Z, matching `\` then `Z` and not an anchor at all.
 * In the latter the first backslash's escape pair swallows the second before
 * `Z` is ever examined, so `\\Z` stays accepted.
 *
 * Deliberately not class-aware for the anchor: `[\Z]`, `[\z]` and `[x\Z]` are
 * flagged too. Engines that reject `\Z` at compile time also reject it inside
 * a class, but `new RegExp('[\\Z]')` succeeds, so a pattern accepted here
 * would be a compile error elsewhere unless this scan refuses it.
 */
function hasEndAnchorEscape(pattern: string): boolean {
  const chars = Array.from(pattern);
  const n = chars.length;
  let inClass = false;
  let i = 0;
  while (i < n) {
    const c = chars[i];
    if (c === '\\') {
      if (chars[i + 1] === 'Z' || chars[i + 1] === 'z') {
        return true;
      }
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
    i += 1;
  }
  return false;
}

/**
 * Fail-closed scan for empty character classes: `[]`, `[^]`. Most regex
 * engines reject an empty class as a compile error, but JavaScript's `RegExp`
 * accepts `[]` (matches nothing) and `[^]` (matches any character, including
 * newline) as valid syntax, so neither `new RegExp(...)` nor
 * `hasNestedQuantifier`'s class handling catches them.
 *
 * A class is empty when the first content character right after `[`
 * (or after the `[^` negation marker) is an unescaped `]`, which in
 * JavaScript/PCRE-family semantics closes the class immediately rather than
 * being read as a literal `]` member (unlike POSIX bracket expressions).
 * Escaping it (`[\]abc]`) makes it a literal first member instead, and is
 * correctly not flagged.
 */
function hasEmptyCharacterClass(pattern: string): boolean {
  const chars = Array.from(pattern);
  const n = chars.length;
  let inClass = false;
  let i = 0;
  while (i < n) {
    const c = chars[i];
    if (c === '\\') {
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
      let j = i + 1;
      if (chars[j] === '^') {
        j += 1;
      }
      if (chars[j] === ']') {
        return true;
      }
      inClass = true;
      i += 1;
      continue;
    }
    i += 1;
  }
  return false;
}

/* ---------------------------------------------------------------------------
 * The HushSpec regex profile
 * ------------------------------------------------------------------------ */

/**
 * The HushSpec regex profile (core spec 3.14.3): the one regex dialect every
 * HushSpec engine implements, so a user-authored pattern in `secret_patterns`,
 * `patch_integrity.forbidden_patterns`, or `shell_commands.forbidden_patterns`
 * produces the *same* decision wherever the policy is enforced.
 *
 * Host regex engines agree on syntax but disagree on semantics, so the profile
 * is reached by *translating* the author's pattern into an equivalent pattern
 * in the host dialect before compiling it. The same translation runs in
 * `validate` and in `evaluate`, so the two can never disagree.
 *
 * Profile (summary of the normative definition):
 *
 * 1. Syntax is RE2-class -- lookaround, backreferences, possessive
 *    quantifiers, atomic/conditional/recursive groups and nested unbounded
 *    quantifiers are rejected (`isSafeRegex`).
 * 2. Inline flags only as a leading group: `(?i)`, `(?s)`, `(?m)`, `(?is)` at
 *    the very start (one or more consecutive groups). A flag group anywhere
 *    else -- including the scoped form `(?i:...)` and negations like `(?-i)` --
 *    is an error.
 * 3. `\d \w \s \b` and their negations are ASCII-only: `\d` = `[0-9]`,
 *    `\w` = `[0-9A-Za-z_]`, `\s` = `[\t\n\v\f\r ]` (includes the vertical tab,
 *    excludes NBSP and the Unicode space separators -- JavaScript's own `\s`
 *    includes both), and `\b`/`\B` are boundaries under that ASCII `\w`
 *    (JavaScript's already are). They are translated, not rejected, including
 *    inside character classes (`[\d_]` -> `[0-9_]`). The negated shorthands
 *    `\D \W \S` and the boundaries `\b \B` are rejected *inside* a class,
 *    where they cannot be expressed as members.
 * 4. `.` matches any character except `\n` -- one *code point*, and with a
 *    leading `(?s)` any code point at all. JavaScript's `.` also excludes `\r`,
 *    U+2028 and U+2029, and consumes a single UTF-16 code unit, so it is
 *    rewritten to an explicit alternation that takes a surrogate pair as one
 *    character (see `DOT_SOURCE`/`DOT_ALL_SOURCE`). The `u` flag would give the
 *    same code-point semantics but would also reject patterns the profile
 *    accepts (identity escapes like `\-`, a literal `{`), so it is not used.
 * 5. `$` matches only at end of text, and `^` only at start, unless a leading
 *    `(?m)` makes them line anchors around `\n`. JavaScript's `m` flag also
 *    treats `\r`, U+2028 and U+2029 as line terminators, so `(?m)` is compiled
 *    by rewriting `^`/`$` to `\n`-only lookarounds rather than by setting `m`.
 * 6. Unanchored search semantics.
 * 7. Compile failure at evaluation time denies, carrying the offending rule
 *    path (see `evaluate.ts`).
 *
 * Escapes are restricted to the intersection the four engines agree on:
 * `\n \r \t \f \v`, `\xHH`, `\d \D \w \W \s \S \b \B`, and any escaped ASCII
 * punctuation. `\A`, `\Z`, `\z`, `\Q`, `\E`, `\p{...}`, `\P{...}`, `\uXXXX`,
 * `\0`, `\a`, `\cX` and every other alphanumeric escape are rejected: each is
 * unsupported by at least one engine, or -- worse -- silently reinterpreted by
 * JavaScript as the bare letter.
 *
 * Known residual divergence: under a leading `(?i)`, an engine that applies
 * the full Unicode simple case-folding table matches U+017F (long s) and
 * U+212A (Kelvin sign) against `(?i)s` / `(?i)k`. JavaScript without the `u`
 * flag folds only ASCII, so they do not match here.
 */

/** Character-class body for ASCII `\d`. */
const DIGIT_BODY = '0-9';
/** Character-class body for ASCII `\w`. */
const WORD_BODY = '0-9A-Za-z_';
/** Character-class body for ASCII `\s` -- includes `\v`, excludes NBSP. */
const SPACE_BODY = '\\t\\n\\v\\f\\r ';

/**
 * One code point that is not `\n` -- the profile's `.`.
 *
 * The surrogate-pair alternation comes first so an astral code point is
 * consumed whole, as one character; a bare `[^\n]` would consume half of it.
 * `[^\n]` (unlike JavaScript's own `.`) deliberately keeps `\r`, U+2028 and
 * U+2029 as ordinary characters.
 */
const DOT_SOURCE = '(?:[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]|[^\\n])';

/** One code point, `\n` included -- the profile's `.` under a leading `(?s)`. */
const DOT_ALL_SOURCE = '(?:[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]|[\\s\\S])';

/**
 * `^` and `$` under a leading `(?m)`. The profile breaks lines only at `\n`,
 * while JavaScript's `m` flag would also break at `\r`, U+2028 and U+2029, so
 * the anchors are spelled out as `\n`-only lookarounds instead.
 */
const MULTILINE_START_SOURCE = '(?:^|(?<=\\n))';
const MULTILINE_END_SOURCE = '(?:$|(?=\\n))';

/** Shared rejection message for nested unbounded quantifiers. */
const NESTED_QUANTIFIER_MESSAGE =
  'pattern contains a nested unbounded quantifier (e.g. (a+)+) that can cause catastrophic backtracking (ReDoS)';

interface ProfileFlags {
  caseInsensitive: boolean;
  dotAll: boolean;
  multiLine: boolean;
}

/** Characters that may appear in an inline flag group; used only to detect one. */
function isInlineFlagChar(c: string): boolean {
  return (
    c === 'i' ||
    c === 'm' ||
    c === 's' ||
    c === 'x' ||
    c === 'u' ||
    c === 'U' ||
    c === 'a' ||
    c === 'L' ||
    c === 'n' ||
    c === '-'
  );
}

/**
 * Consume the leading run of `(?flags)` groups, returning the accumulated flags
 * and the index at which the pattern body starts. Only `i`, `s` and `m` are
 * recognized; anything else leaves the group in place, where the body walk
 * rejects it as a non-leading inline flag group.
 */
function splitLeadingFlags(chars: string[]): [ProfileFlags, number] {
  const flags: ProfileFlags = { caseInsensitive: false, dotAll: false, multiLine: false };
  let index = 0;
  while (index + 2 < chars.length && chars[index] === '(' && chars[index + 1] === '?') {
    let cursor = index + 2;
    const start = cursor;
    while (
      cursor < chars.length &&
      (chars[cursor] === 'i' || chars[cursor] === 's' || chars[cursor] === 'm')
    ) {
      cursor += 1;
    }
    if (cursor === start || cursor >= chars.length || chars[cursor] !== ')') {
      break;
    }
    for (let k = start; k < cursor; k++) {
      if (chars[k] === 'i') flags.caseInsensitive = true;
      if (chars[k] === 's') flags.dotAll = true;
      if (chars[k] === 'm') flags.multiLine = true;
    }
    index = cursor + 1;
  }
  return [flags, index];
}

/** Reject `(?flags)` / `(?flags:...)` groups outside the leading position. */
function inlineFlagGroupError(chars: string[], index: number): string | undefined {
  if (chars[index + 1] !== '?') {
    return undefined;
  }
  let cursor = index + 2;
  const start = cursor;
  while (cursor < chars.length && isInlineFlagChar(chars[cursor])) {
    cursor += 1;
  }
  if (cursor === start) {
    return undefined;
  }
  if (chars[cursor] === ')' || chars[cursor] === ':') {
    return (
      'inline flags are only allowed as a leading group such as (?i), (?s), (?m) or (?is); ' +
      'a flag group elsewhere in the pattern is not portable across the HushSpec SDK regex engines'
    );
  }
  return undefined;
}

/** Number of chars consumed by the escape sequence starting at `index`. */
function escapeLength(chars: string[], index: number): number {
  return chars[index + 1] === 'x' ? 4 : 2;
}

function isAsciiHexDigit(c: string | undefined): boolean {
  return c != null && /^[0-9A-Fa-f]$/.test(c);
}

function isAsciiAlphanumeric(c: string): boolean {
  return /^[0-9A-Za-z]$/.test(c);
}

/** Translate one escape sequence into JavaScript `RegExp` source. */
function translateEscape(
  escaped: string,
  inClass: boolean,
  chars: string[],
  index: number,
): string {
  if (escaped === 'd' || escaped === 'w' || escaped === 's') {
    const body = escaped === 'd' ? DIGIT_BODY : escaped === 'w' ? WORD_BODY : SPACE_BODY;
    return inClass ? body : `[${body}]`;
  }
  if (escaped === 'D' || escaped === 'W' || escaped === 'S') {
    if (inClass) {
      throw new Error(
        `\\${escaped} is not portable inside a character class; a negated shorthand cannot be expressed as a class member`,
      );
    }
    const body = escaped === 'D' ? DIGIT_BODY : escaped === 'W' ? WORD_BODY : SPACE_BODY;
    return `[^${body}]`;
  }
  if (escaped === 'b' || escaped === 'B') {
    if (inClass) {
      throw new Error(
        `\\${escaped} is not portable inside a character class (JavaScript and Python read it as a backspace; Rust and Go reject it)`,
      );
    }
    // JavaScript word boundaries are ASCII without the `u` flag, which is
    // exactly the profile definition, so the escape passes through unchanged.
    return `\\${escaped}`;
  }
  if (escaped === 'A' || escaped === 'Z' || escaped === 'z') {
    throw new Error(
      `\\${escaped} is not portable across the HushSpec SDK regex engines (JavaScript reads it as a literal letter); anchor with ^ and $`,
    );
  }
  if (escaped === 'Q' || escaped === 'E') {
    throw new Error(
      '\\Q ... \\E literal spans are not portable across the HushSpec SDK regex engines; escape the literal characters individually',
    );
  }
  if (escaped === 'p' || escaped === 'P') {
    throw new Error(
      `Unicode property escapes (\\${escaped}) are not portable across the HushSpec SDK regex engines; spell the character class out`,
    );
  }
  if (escaped === 'x') {
    const hi = chars[index + 2];
    const lo = chars[index + 3];
    if (!isAsciiHexDigit(hi) || !isAsciiHexDigit(lo)) {
      throw new Error(
        '\\x must be followed by exactly two hex digits (\\x41); the braced form \\x{...} is not portable across the HushSpec SDK regex engines',
      );
    }
    return `\\x${hi}${lo}`;
  }
  if (
    escaped === 'n' ||
    escaped === 'r' ||
    escaped === 't' ||
    escaped === 'f' ||
    escaped === 'v'
  ) {
    return `\\${escaped}`;
  }
  if (isAsciiAlphanumeric(escaped) || escaped === '_') {
    throw new Error(`\\${escaped} is not a HushSpec regex profile escape`);
  }
  if ((escaped.codePointAt(0) ?? 0) <= 0x7f) {
    return `\\${escaped}`;
  }
  throw new Error(
    `escaping the non-ASCII character '${escaped}' is not portable across the HushSpec SDK regex engines`,
  );
}

/**
 * Walk the pattern body, translating profile constructs into JavaScript
 * `RegExp` source and rejecting anything outside the profile. `dotAll` and
 * `multiLine` carry a leading `(?s)` / `(?m)`: both are
 * compiled by rewriting the affected constructs rather than by setting the `s`
 * and `m` flags, whose JavaScript definitions of "any character" and "line
 * terminator" both differ from the profile's.
 */
function translateProfileBody(chars: string[], dotAll: boolean, multiLine: boolean): string {
  const n = chars.length;
  let out = '';
  let inClass = false;
  let index = 0;

  while (index < n) {
    const c = chars[index];

    if (c === '\\') {
      if (index + 1 >= n) {
        throw new Error('pattern ends with a trailing backslash');
      }
      out += translateEscape(chars[index + 1], inClass, chars, index);
      index += escapeLength(chars, index);
      continue;
    }

    if (inClass) {
      if (c === ']') {
        inClass = false;
      }
      out += c;
      index += 1;
      continue;
    }

    if (c === '[') {
      // `[]` / `[^]` are a compile error in most engines but read as "match
      // nothing" / "match anything" in JavaScript.
      let cursor = index + 1;
      if (chars[cursor] === '^') {
        cursor += 1;
      }
      if (cursor >= n || chars[cursor] === ']') {
        throw new Error(
          'empty character classes [] and [^] are not portable across the HushSpec SDK regex engines',
        );
      }
      inClass = true;
      out += '[';
      index += 1;
      continue;
    }

    if (c === '(') {
      const error = inlineFlagGroupError(chars, index);
      if (error != null) {
        throw new Error(error);
      }
      // The `(?P<name>...)` named-group spelling is a syntax error in
      // JavaScript; `(?<name>...)` means the same thing and is accepted by
      // every engine the profile targets.
      if (chars[index + 1] === '?' && chars[index + 2] === 'P' && chars[index + 3] === '<') {
        out += '(?<';
        index += 4;
        continue;
      }
      out += '(';
      index += 1;
      continue;
    }

    if (c === '.') {
      out += dotAll ? DOT_ALL_SOURCE : DOT_SOURCE;
      index += 1;
      continue;
    }

    if (multiLine && (c === '^' || c === '$')) {
      out += c === '^' ? MULTILINE_START_SOURCE : MULTILINE_END_SOURCE;
      index += 1;
      continue;
    }

    out += c;
    index += 1;
  }

  return out;
}

/**
 * Compile a policy-authored pattern under the HushSpec regex profile.
 *
 * This is the only way policy regexes are compiled in this SDK: both
 * `validate` and `evaluate` route through it, so validation and evaluation can
 * never disagree about what a pattern means. Throws on any pattern outside the
 * profile -- the evaluator turns that throw into a deny.
 */
export function compileProfileRegex(pattern: string): CompiledPolicyRegex {
  // Portability pre-check and the ReDoS heuristic run here, not only in
  // `validate`, so the evaluator denies on exactly the patterns the validator
  // rejects even for a hand-built, never-validated policy object.
  if (
    RE2_DISALLOWED.test(pattern) ||
    hasPossessiveQuantifier(pattern) ||
    hasEndAnchorEscape(pattern) ||
    hasEmptyCharacterClass(pattern)
  ) {
    throw new Error('pattern uses features not in the RE2 subset');
  }
  if (hasNestedQuantifier(pattern)) {
    throw new Error(NESTED_QUANTIFIER_MESSAGE);
  }

  const chars = Array.from(pattern);
  const [profileFlags, bodyStart] = splitLeadingFlags(chars);
  const source = translateProfileBody(
    chars.slice(bodyStart),
    profileFlags.dotAll,
    profileFlags.multiLine,
  );
  // Only `i` reaches the RegExp: `(?s)` and `(?m)` are compiled into the source
  // above, because JavaScript's `s` and `m` flags do not mean what the profile
  // means (see DOT_ALL_SOURCE / MULTILINE_END_SOURCE).
  const flags = profileFlags.caseInsensitive ? 'i' : '';

  return { source, flags, regex: new RegExp(source, flags) };
}
