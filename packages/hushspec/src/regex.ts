export interface CompiledPolicyRegex {
  source: string;
  regex: RegExp;
}

/**
 * Whether `pattern` is accepted by the HushSpec regex profile (core spec
 * 3.14.3): the pattern a policy may carry, which every HushSpec engine
 * compiles to the same language and matches with the same semantics.
 *
 * It answers by compiling under the profile, so it accepts exactly what
 * `validate` accepts and what the evaluator can run -- the portability
 * pre-check, the nested-quantifier refusal, the RE2 subset, the ASCII class
 * escapes, leading-only flag groups and the 2048-byte bound included.
 */
export function isSafeRegex(pattern: string): boolean {
  try {
    compileProfileRegex(pattern);
    return true;
  } catch {
    return false;
  }
}

/** Shared rejection message for possessive quantifiers. */
const POSSESSIVE_MESSAGE =
  'possessive quantifiers (*+, ++, ?+, {n}+, {n,}+, {n,m}+) are not portable across the HushSpec SDK regex engines';

/** Shared rejection message for the open-lower-bound quantifier `{,n}`. */
const OPEN_LOWER_BOUND_MESSAGE =
  'the {,n} quantifier is not portable across the HushSpec SDK regex engines (Python reads it as {0,n}, the others as literal text); write {0,n}';

/** Shared rejection message for the `\Z` / `\z` end-of-string anchors. */
const END_ANCHOR_MESSAGE =
  '\\Z and \\z end-anchors are not portable across the HushSpec SDK regex engines; anchor with $';

/** Shared rejection message for an empty character class. */
const EMPTY_CLASS_MESSAGE =
  'empty character classes [] and [^] are not portable across the HushSpec SDK regex engines';

/**
 * Portability pre-check: reject regex constructs that are unsupported by, or
 * behave differently across, the four SDK engines so a pattern validates
 * identically everywhere. Scanning outside character classes and honoring
 * `\`-escapes, it rejects:
 * - possessive quantifiers `*+`, `++`, `?+` and possessive braces `{n}+`,
 *   `{n,}+`, `{n,m}+` (Rust's `regex` silently downgrades possessive to
 *   greedy; JavaScript `RegExp` and Go RE2 reject them at compile time),
 * - `\Z` and `\z` end-anchors (Rust/Python/Go accept them with differing
 *   semantics; JavaScript reads `\Z`/`\z` as a literal letter -- users anchor
 *   with `$`),
 * - empty character classes `[]` and `[^]` (JavaScript accepts them; the
 *   others reject them),
 * - the `{,n}` quantifier (Python reads it as `{0,n}`; the others read the
 *   whole brace as literal text).
 *
 * Must stay byte-identical to the Rust, Python, and Go implementations.
 */
function disallowedRegexFeature(pattern: string): string | undefined {
  const chars = Array.from(pattern);
  const n = chars.length;
  let inClass = false;
  let i = 0;
  while (i < n) {
    const c = chars[i];
    if (c === '\\') {
      // `\Z` / `\z` are end-anchors only outside a character class; inside one
      // they are an escaped literal letter, so ignore them there.
      if (!inClass && i + 1 < n && (chars[i + 1] === 'Z' || chars[i + 1] === 'z')) {
        return END_ANCHOR_MESSAGE;
      }
      i += 2; // skip the escaped char
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
      // Empty class `[]` or negated-empty `[^]` (JavaScript matches none/any;
      // the other engines reject the bare form).
      let j = i + 1;
      if (j < n && chars[j] === '^') {
        j += 1;
      }
      if (j < n && chars[j] === ']') {
        return EMPTY_CLASS_MESSAGE;
      }
      inClass = true;
      i += 1;
      continue;
    }
    if (c === '*' || c === '+' || c === '?') {
      // A quantifier immediately followed by `+` is possessive.
      if (i + 1 < n && chars[i + 1] === '+') {
        return POSSESSIVE_MESSAGE;
      }
      i += 1;
      continue;
    }
    if (c === '{') {
      // Treat `{...}` as a quantifier only when it parses as one; a literal `{`
      // is scanned through. A quantifier brace followed by `+` is possessive
      // (`{n}+`, `{n,}+`, `{n,m}+`).
      let j = i + 1;
      while (j < n && chars[j] !== '}') {
        j += 1;
      }
      if (j < n) {
        const inner = chars.slice(i + 1, j).join('');
        if (braceKind(inner) !== 'none') {
          if (inner.startsWith(',')) {
            return OPEN_LOWER_BOUND_MESSAGE;
          }
          if (j + 1 < n && chars[j + 1] === '+') {
            return POSSESSIVE_MESSAGE;
          }
          i = j + 1;
          continue;
        }
      }
      i += 1;
      continue;
    }
    i += 1;
  }
  return undefined;
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
 *    quantifiers are rejected. The group forms are `(...)`, `(?:...)` and the
 *    named pair `(?<name>...)` / `(?P<name>...)`, whose names are ASCII
 *    letters, digits and underscores not starting with a digit; any other
 *    `(?...)` opener is rejected.
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
 * 4. `.` matches any scalar value except `\n`, and with a leading `(?s)` any
 *    scalar value at all. JavaScript's `.` also excludes `\r`, U+2028 and
 *    U+2029, and consumes a single UTF-16 code unit, so it is rewritten to an
 *    explicit alternation that takes a surrogate pair as one character (see
 *    `DOT_SOURCE`/`DOT_ALL_SOURCE`). The `u` flag would give the same
 *    code-point semantics but would also reject patterns the profile accepts
 *    (identity escapes like `\-`, a literal `{`), so it is not used.
 * 5. `$` matches only at end of text, and `^` only at start, unless a leading
 *    `(?m)` makes them line anchors around `\n`. JavaScript's `m` flag also
 *    treats `\r`, U+2028 and U+2029 as line terminators, so `(?m)` is compiled
 *    by rewriting `^`/`$` to `\n`-only lookarounds rather than by setting `m`.
 * 6. `(?i)` folds ASCII letters only. Each ASCII letter is expanded into a
 *    two-member class (`s` -> `[sS]`) and no flag reaches the `RegExp`, so the
 *    profile answers the same way as an engine whose own `(?i)` would apply the
 *    full Unicode case-folding table.
 * 7. Unanchored search semantics.
 * 8. Compile failure at evaluation time denies, carrying the offending rule
 *    path (see `evaluate.ts`).
 *
 * A character class is a set of scalar values: an unescaped `[` inside one is
 * rejected (so POSIX bracket expressions are not mistaken for a class of their
 * own), a range endpoint outside the Basic Multilingual Plane is rejected
 * because the SDKs cannot express such a range alike, and an astral member is
 * lifted out of the class into an alternation of its surrogate pair, which is
 * what makes the class match the scalar value rather than either half of it.
 * A pattern is limited to 2048 UTF-8 bytes (core spec 3.14.3).
 *
 * Escapes are restricted to the intersection the four engines agree on:
 * `\n \r \t \f \v`, `\xHH`, `\d \D \w \W \s \S \b \B`, and any escaped ASCII
 * punctuation. `\A`, `\Z`, `\z`, `\Q`, `\E`, `\p{...}`, `\P{...}`, `\uXXXX`,
 * `\0`, `\a`, `\cX` and every other alphanumeric escape are rejected: each is
 * unsupported by at least one engine, or -- worse -- silently reinterpreted by
 * JavaScript as the bare letter.
 */

/** Character-class body for ASCII `\d`. */
const DIGIT_BODY = '0-9';
/** Character-class body for ASCII `\w`. */
const WORD_BODY = '0-9A-Za-z_';
/** Character-class body for ASCII `\s` -- includes `\v`, excludes NBSP. */
const SPACE_BODY = '\\t\\n\\v\\f\\r ';

/** A UTF-16 surrogate pair: the two code units of one astral code point. */
const SURROGATE_PAIR_SOURCE = '[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]';

/** Character-class body covering every surrogate code unit. */
const SURROGATE_BODY = '\\uD800-\\uDFFF';

/**
 * A surrogate code unit with no partner.
 *
 * Valid UTF-8 input cannot contain one, but a JavaScript string can, and
 * leaving it unmatchable would make a negated construct silently skip a
 * character the other engines would have matched.
 */
const LONE_SURROGATE_SOURCE =
  '[\\uD800-\\uDBFF](?![\\uDC00-\\uDFFF])|(?<![\\uD800-\\uDBFF])[\\uDC00-\\uDFFF]';

/**
 * One code point that is not a member of the character-class body `body`.
 *
 * The four alternatives are mutually exclusive and between them cover every
 * code point, so exactly one matches at any position: a surrogate pair is
 * always consumed whole, and the fallback excludes surrogate code units rather
 * than letting the engine backtrack into half of a pair. That is what makes
 * `^..$` refuse a single astral character here as it does in the other SDKs.
 *
 * The surrogate range leads the negated class so that a body ending in a
 * trailing `-` (`[^a-]`) cannot form a range with what follows it.
 */
function codePointOutside(body: string): string {
  return `(?:${SURROGATE_PAIR_SOURCE}|[^${SURROGATE_BODY}${body}]|${LONE_SURROGATE_SOURCE})`;
}

/**
 * One code point that is not `\n` -- the profile's `.`.
 *
 * Unlike JavaScript's own `.` this deliberately keeps `\r`, U+2028 and U+2029
 * as ordinary characters.
 */
const DOT_SOURCE = codePointOutside('\\n');

/** One code point, `\n` included -- the profile's `.` under a leading `(?s)`. */
const DOT_ALL_SOURCE = codePointOutside('');

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

/** Size limit of a policy-authored pattern, in UTF-8 bytes (core spec 3.14.3). */
const MAX_PATTERN_BYTES = 2048;

/** Shared rejection message for an over-long pattern. */
const PATTERN_TOO_LONG_MESSAGE =
  'pattern exceeds the HushSpec regex profile limit of 2048 bytes';

/** Shared rejection message for group openers outside the profile. */
const GROUP_FORM_MESSAGE =
  'this group form is not portable across the HushSpec SDK regex engines; the profile allows (?:...), the named forms (?<name>...) and (?P<name>...), and a leading inline flag group such as (?i)';

/** Shared rejection message for a malformed or non-portable group name. */
const GROUP_NAME_MESSAGE =
  "a named group's name must be ASCII letters, digits and underscores, must not start with a digit, and must be closed by >";

/** Shared rejection message for an unescaped `[` inside a character class. */
const NESTED_CLASS_MESSAGE =
  'an unescaped [ inside a character class is not portable across the HushSpec SDK regex engines (Rust and Go read [[:alpha:]] as a POSIX class, JavaScript and Python as a literal [); escape it as \\[';

/** Shared rejection message for a class range reaching outside the BMP. */
const ASTRAL_RANGE_MESSAGE =
  'a character-class range with an endpoint outside the Basic Multilingual Plane is not portable across the HushSpec SDK regex engines';

const PATTERN_ENCODER = new TextEncoder();

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

/** The other ASCII case of `c`, or `undefined` when `c` is not an ASCII letter. */
function asciiCaseCounterpart(c: string): string | undefined {
  if (c >= 'a' && c <= 'z') return c.toUpperCase();
  if (c >= 'A' && c <= 'Z') return c.toLowerCase();
  return undefined;
}

/**
 * The class-body ranges that fold `low`-`high` to its other ASCII case.
 *
 * A range is emitted for the part of `low`-`high` inside `a-z` and for the part
 * inside `A-Z`, so `[a-f]` under `(?i)` becomes `[a-fA-F]` and a range over
 * digits is left alone.
 */
function foldedClassRange(low: string, high: string): string {
  const lowerA = 0x61;
  const lowerZ = 0x7a;
  const upperA = 0x41;
  const upperZ = 0x5a;
  const lo = low.codePointAt(0) ?? 0;
  const hi = high.codePointAt(0) ?? 0;
  let out = '';
  const lowerStart = Math.max(lo, lowerA);
  const lowerEnd = Math.min(hi, lowerZ);
  if (lowerStart <= lowerEnd) {
    out += `${String.fromCodePoint(lowerStart - lowerA + upperA)}-${String.fromCodePoint(lowerEnd - lowerA + upperA)}`;
  }
  const upperStart = Math.max(lo, upperA);
  const upperEnd = Math.min(hi, upperZ);
  if (upperStart <= upperEnd) {
    out += `${String.fromCodePoint(upperStart - upperA + lowerA)}-${String.fromCodePoint(upperEnd - upperA + lowerA)}`;
  }
  return out;
}

/**
 * Translate one escape sequence into JavaScript `RegExp` source. `fold` asks
 * for the profile's ASCII case folding, which applies only outside a character
 * class -- `translateCharacterClass` folds its own members.
 */
function translateEscape(
  escaped: string,
  inClass: boolean,
  fold: boolean,
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
    return codePointOutside(body);
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
    if (fold) {
      const other = asciiCaseCounterpart(String.fromCharCode(parseInt(`${hi}${lo}`, 16)));
      if (other !== undefined) {
        return `[\\x${hi}${lo}${other}]`;
      }
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
 * The scalar value an escape sequence stands for, or `undefined` when it stands
 * for a set of them. Only reached for escapes `translateEscape` accepted.
 */
function escapeLiteralValue(chars: string[], index: number): string | undefined {
  const escaped = chars[index + 1];
  switch (escaped) {
    case 'd':
    case 'w':
    case 's':
      return undefined;
    case 'n':
      return '\n';
    case 'r':
      return '\r';
    case 't':
      return '\t';
    case 'f':
      return '\f';
    case 'v':
      return '\v';
    case 'x':
      return String.fromCharCode(parseInt(`${chars[index + 2]}${chars[index + 3]}`, 16));
    default:
      return escaped;
  }
}

/**
 * One member of a character class: its translated source, the scalar value it
 * stands for (absent for a multi-member shorthand such as `\d`), and the number
 * of chars it spans.
 */
interface ClassAtom {
  source: string;
  value?: string;
  length: number;
}

/** Read the class member starting at `chars[index]`. */
function readClassAtom(chars: string[], index: number): ClassAtom {
  const c = chars[index];
  if (c === '\\') {
    if (index + 1 >= chars.length) {
      throw new Error('pattern ends with a trailing backslash');
    }
    return {
      source: translateEscape(chars[index + 1], true, false, chars, index),
      value: escapeLiteralValue(chars, index),
      length: escapeLength(chars, index),
    };
  }
  if (c === '[') {
    throw new Error(NESTED_CLASS_MESSAGE);
  }
  return { source: c, value: c, length: 1 };
}

/**
 * Translate the character class starting at `chars[start]`, returning its
 * JavaScript source and the index just past its closing `]`.
 *
 * Members are read one at a time so that an unescaped `[` can be refused, a
 * range can be checked for a non-BMP endpoint, an astral member can be lifted
 * into an alternation of its surrogate pair -- a class over UTF-16 code units
 * would match either half on its own -- and, under `(?i)`, both the members and
 * the ranges can be folded to their other ASCII case.
 *
 * A negated class means "one code point outside this set" to every other
 * HushSpec engine, so it is rewritten the same way `.` is.
 */
function translateCharacterClass(
  chars: string[],
  start: number,
  caseInsensitive: boolean,
): [string, number] {
  const n = chars.length;
  let index = start + 1;
  const negated = chars[index] === '^';
  if (negated) {
    index += 1;
  }
  // `[]` / `[^]` are a compile error in most engines but read as "match
  // nothing" / "match anything" in JavaScript.
  if (index >= n || chars[index] === ']') {
    throw new Error(EMPTY_CLASS_MESSAGE);
  }

  let body = '';
  const astral: string[] = [];
  while (index < n && chars[index] !== ']') {
    const atom = readClassAtom(chars, index);
    const after = index + atom.length;
    // A `-` is a range only between two single members and never just before
    // the closing `]`, where it is a literal hyphen.
    if (
      atom.value !== undefined &&
      chars[after] === '-' &&
      after + 1 < n &&
      chars[after + 1] !== ']'
    ) {
      const high = readClassAtom(chars, after + 1);
      if (high.value !== undefined) {
        if (isAstral(atom.value) || isAstral(high.value)) {
          throw new Error(ASTRAL_RANGE_MESSAGE);
        }
        body += `${atom.source}-${high.source}`;
        if (caseInsensitive) {
          body += foldedClassRange(atom.value, high.value);
        }
        index = after + 1 + high.length;
        continue;
      }
    }
    if (atom.value !== undefined && isAstral(atom.value)) {
      astral.push(atom.source);
    } else {
      body += atom.source;
      if (caseInsensitive && atom.value !== undefined) {
        const other = asciiCaseCounterpart(atom.value);
        if (other !== undefined) {
          body += other;
        }
      }
    }
    index = after;
  }

  if (index >= n) {
    // Unterminated: hand it to `RegExp`, whose own diagnostic names the class.
    return [`[${negated ? '^' : ''}${body}${astral.join('')}`, index];
  }
  if (negated) {
    const rest = codePointOutside(body);
    return [
      astral.length === 0 ? rest : `(?:(?!${astral.join('|')})${rest})`,
      index + 1,
    ];
  }
  if (astral.length === 0) {
    return [`[${body}]`, index + 1];
  }
  const branches = body === '' ? astral : [...astral, `[${body}]`];
  return [`(?:${branches.join('|')})`, index + 1];
}

function isAstral(value: string): boolean {
  return (value.codePointAt(0) ?? 0) > 0xffff;
}

/**
 * Translate the group opener starting at `chars[start]`, returning its source
 * and the index just past it.
 *
 * `(`, `(?:` and the two named spellings are the profile's only group forms;
 * `(?=`, `(?!`, `(?>`, `(?#`, `(?(`, `(?R)` and `(?P=name)` are rejected here
 * rather than left to a host engine that may accept them.
 */
function translateGroup(chars: string[], start: number): [string, number] {
  if (chars[start + 1] !== '?') {
    return ['(', start + 1];
  }
  const error = inlineFlagGroupError(chars, start);
  if (error != null) {
    throw new Error(error);
  }
  const marker = chars[start + 2];
  if (marker === ':') {
    return ['(?:', start + 3];
  }
  // The `(?P<name>...)` named-group spelling is a syntax error in JavaScript;
  // `(?<name>...)` means the same thing and is accepted by every engine the
  // profile targets.
  if (marker === '<' && chars[start + 3] !== '=' && chars[start + 3] !== '!') {
    return translateGroupName(chars, start + 3);
  }
  if (marker === 'P' && chars[start + 3] === '<') {
    return translateGroupName(chars, start + 4);
  }
  throw new Error(GROUP_FORM_MESSAGE);
}

/**
 * Copy the group name that starts at `start` and ends at `>`, returning the
 * index just past the `>`. The name is never case-folded: it is an identifier,
 * not subject text.
 */
function translateGroupName(chars: string[], start: number): [string, number] {
  let cursor = start;
  while (cursor < chars.length && chars[cursor] !== '>') {
    cursor += 1;
  }
  if (cursor >= chars.length) {
    throw new Error(GROUP_NAME_MESSAGE);
  }
  const name = chars.slice(start, cursor).join('');
  if (!/^[A-Za-z_][0-9A-Za-z_]*$/.test(name)) {
    throw new Error(GROUP_NAME_MESSAGE);
  }
  return [`(?<${name}>`, cursor + 1];
}

/**
 * Walk the pattern body, translating profile constructs into JavaScript
 * `RegExp` source and rejecting anything outside the profile. `dotAll`,
 * `multiLine` and `caseInsensitive` carry a leading `(?s)` / `(?m)` / `(?i)`:
 * all three are compiled by rewriting the affected constructs rather than by
 * setting the `s`, `m` and `i` flags, whose JavaScript definitions of "any
 * character", "line terminator" and "same letter" each differ from the
 * profile's.
 */
function translateProfileBody(
  chars: string[],
  dotAll: boolean,
  multiLine: boolean,
  caseInsensitive: boolean,
): string {
  const n = chars.length;
  let out = '';
  let index = 0;

  while (index < n) {
    const c = chars[index];

    if (c === '\\') {
      if (index + 1 >= n) {
        throw new Error('pattern ends with a trailing backslash');
      }
      out += translateEscape(chars[index + 1], false, caseInsensitive, chars, index);
      index += escapeLength(chars, index);
      continue;
    }

    if (c === '[') {
      const [source, next] = translateCharacterClass(chars, index, caseInsensitive);
      out += source;
      index = next;
      continue;
    }

    if (c === '(') {
      const [source, next] = translateGroup(chars, index);
      out += source;
      index = next;
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

    const other = caseInsensitive ? asciiCaseCounterpart(c) : undefined;
    if (other !== undefined) {
      out += `[${c}${other}]`;
    } else {
      // `Array.from` splits by code point, so an astral literal is one element
      // of two UTF-16 code units. Grouping it keeps a following quantifier on
      // the whole character instead of on its trailing code unit.
      out += c.length > 1 ? `(?:${c})` : c;
    }
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
  if (PATTERN_ENCODER.encode(pattern).length > MAX_PATTERN_BYTES) {
    throw new Error(PATTERN_TOO_LONG_MESSAGE);
  }
  // Portability pre-check and the ReDoS heuristic run here, not only in
  // `validate`, so the evaluator denies on exactly the patterns the validator
  // rejects even for a hand-built, never-validated policy object. The rest of
  // the RE2 subset -- lookaround, backreferences, atomic and recursive groups
  // -- is refused by the translation below, which names the construct.
  const feature = disallowedRegexFeature(pattern);
  if (feature !== undefined) {
    throw new Error(feature);
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
    profileFlags.caseInsensitive,
  );
  // No flag reaches the `RegExp`: `(?i)`, `(?s)` and `(?m)` are each compiled
  // into the source above, because JavaScript's `i`, `s` and `m` flags do not
  // mean what the profile means (see DOT_ALL_SOURCE / MULTILINE_END_SOURCE and
  // the ASCII-only folding in `translateProfileBody`).
  return { source, regex: new RegExp(source) };
}
