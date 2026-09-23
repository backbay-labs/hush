import { describe, it, expect } from 'vitest';
import { compileProfileRegex } from '../src/regex.js';

// ---------------------------------------------------------------------------
// HushSpec regex profile (compileProfileRegex) unit tests.
//
// Mirrors crates/hushspec/src/regex_profile.rs,
// packages/python/tests/test_regex_profile.py, and
// packages/go/hushspec/regex_profile_test.go: the same cases must produce the
// same answers in all four SDKs.
// ---------------------------------------------------------------------------

function profileMatches(pattern: string, haystack: string): boolean {
  return compileProfileRegex(pattern).regex.test(haystack);
}

function profileRejects(pattern: string): string {
  try {
    compileProfileRegex(pattern);
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error(`${pattern} should be rejected`);
}

describe('compileProfileRegex', () => {
  it('treats \\d as ASCII-only', () => {
    expect(profileMatches('key\\d{3}', 'key123')).toBe(true);
    // Arabic-Indic digits are digits to a Unicode-aware \d, but not to the profile.
    expect(profileMatches('key\\d{3}', 'key١٢٣')).toBe(false);
  });

  it('treats \\w as ASCII-only', () => {
    expect(profileMatches('\\w+', 'abc_123')).toBe(true);
    expect(profileMatches('^\\w$', 'é')).toBe(false);
  });

  it('anchors $ at end of text only', () => {
    expect(profileMatches('token$', 'token')).toBe(true);
    expect(profileMatches('token$', 'token\n')).toBe(false);
    expect(profileMatches('(?m)token$', 'token\nmore')).toBe(true);
    // JavaScript's own `m` flag would also break the line at `\r`;
    // Rust, Python and Go break only at `\n`.
    expect(profileMatches('(?m)token$', 'token\rmore')).toBe(false);
    expect(profileMatches('(?m)^more', 'token\nmore')).toBe(true);
    expect(profileMatches('(?m)^more', 'token\rmore')).toBe(false);
  });

  it('treats \\b as an ASCII word boundary', () => {
    expect(profileMatches('\\bfoo', 'éfoo')).toBe(true);
    expect(profileMatches('\\bfoo\\b', 'éfoo')).toBe(true);
    expect(profileMatches('\\bfoo\\b', 'foobar')).toBe(false);
    expect(profileMatches('\\Bfoo', 'barfoo')).toBe(true);
  });

  it('makes . exclude only \\n', () => {
    expect(profileMatches('a.b', 'a\rb')).toBe(true);
    expect(profileMatches('a.b', 'a\nb')).toBe(false);
    expect(profileMatches('(?s)a.b', 'a\nb')).toBe(true);
    expect(compileProfileRegex('a.b').source).toBe(
      'a(?:[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]|[^\\uD800-\\uDFFF\\n]' +
        '|[\\uD800-\\uDBFF](?![\\uDC00-\\uDFFF])|(?<![\\uD800-\\uDBFF])[\\uDC00-\\uDFFF])b',
    );
  });

  // Rust, Python and Go all match over code points, so a `.` takes an astral
  // character whole and never half of one. JavaScript strings are UTF-16, so
  // the translation has to say so explicitly; a fallback that admitted
  // surrogate code units would let `^..$` backtrack through the two halves of
  // one emoji and match where the other three SDKs do not.
  it('counts an astral character as one code point', () => {
    expect(profileMatches('^a.b$', 'a\u{1F600}b')).toBe(true);
    expect(profileMatches('^.$', '\u{1F600}')).toBe(true);
    expect(profileMatches('^..$', '\u{1F600}')).toBe(false);
    expect(profileMatches('^..$', '\u{1F600}\u{1F600}')).toBe(true);
    expect(profileMatches('^..$', 'ab')).toBe(true);
    expect(profileMatches('(?s)^..$', '\u{1F600}')).toBe(false);
    expect(profileMatches('(?s)^.$', '\u{1F600}')).toBe(true);
    // A negated class and a negated shorthand are "one code point outside this
    // set", so they take an astral character whole as well.
    expect(profileMatches('^[^a]$', '\u{1F600}')).toBe(true);
    expect(profileMatches('^[^a]{2}$', '\u{1F600}')).toBe(false);
    expect(profileMatches('^\\D$', '\u{1F600}')).toBe(true);
    expect(profileMatches('^\\W$', '\u{1F600}')).toBe(true);
    expect(profileMatches('^\\S$', '\u{1F600}')).toBe(true);
    // A quantifier after an astral literal applies to the whole character.
    expect(profileMatches('^\u{1F600}+$', '\u{1F600}\u{1F600}')).toBe(true);
    expect(profileMatches('^\u{1F600}+$', '\u{1F600}\u{1F600}b')).toBe(false);
    // A trailing `-` in a negated class must stay a literal member.
    expect(profileMatches('^[^a-]$', '-')).toBe(false);
    expect(profileMatches('^[^a-]$', 'b')).toBe(true);
  });

  it('makes \\s ASCII whitespace including the vertical tab', () => {
    expect(profileMatches('a\\sb', 'ab')).toBe(true);
    expect(profileMatches('a\\sb', 'a b')).toBe(true);
    expect(profileMatches('a\\sb', 'a	b')).toBe(true);
    // NBSP is whitespace to JavaScript's own \s, but not to the profile.
    expect(profileMatches('a\\sb', 'a b')).toBe(false);
    expect(profileMatches('a\\Sb', 'a b')).toBe(false);
    expect(profileMatches('a\\Sb', 'axb')).toBe(true);
  });

  it('accepts leading inline flags and rejects them anywhere else', () => {
    expect(() => compileProfileRegex('(?i)foobar')).not.toThrow();
    expect(() => compileProfileRegex('(?is)foobar')).not.toThrow();
    expect(() => compileProfileRegex('(?i)(?m)foobar')).not.toThrow();
    expect(profileRejects('foo(?i)bar')).toContain('leading group');
    expect(profileRejects('(?i:foo)')).toContain('leading group');
    expect(profileRejects('foo(?-i)bar')).toContain('leading group');
    expect(profileRejects('(?i)foo(?s)bar')).toContain('leading group');
  });

  it('never reads an escaped backslash as a shorthand', () => {
    expect(compileProfileRegex('\\\\d').source).toBe('\\\\d');
    expect(profileMatches('\\\\d', '\\d')).toBe(true);
    expect(profileMatches('\\\\d', '5')).toBe(false);
  });

  it('expands shorthands inside character classes', () => {
    expect(compileProfileRegex('[\\d_]').source).toBe('[0-9_]');
    expect(compileProfileRegex('[\\w-]').source).toBe('[0-9A-Za-z_-]');
    expect(compileProfileRegex('[\\s]').source).toBe('[\\t\\n\\v\\f\\r ]');
    expect(profileMatches('[\\d_]+', '_1')).toBe(true);
    expect(profileMatches('^[\\d_]+$', '١')).toBe(false);
  });

  it('keeps an escaped bracket literal', () => {
    expect(profileMatches('[\\]]', ']')).toBe(true);
    expect(profileMatches('a\\[b', 'a[b')).toBe(true);
    expect(compileProfileRegex('[\\]]').source).toBe('[\\]]');
  });

  it('rejects negated shorthands and boundaries inside character classes', () => {
    expect(profileRejects('[\\D]')).toContain('character class');
    expect(profileRejects('[\\W]')).toContain('character class');
    expect(profileRejects('[a\\S]')).toContain('character class');
    expect(profileRejects('[\\b]')).toContain('character class');
    expect(profileRejects('[\\B]')).toContain('character class');
  });

  it('rejects non-portable escapes', () => {
    expect(profileRejects('\\Qa.b\\E')).toContain('\\Q');
    expect(profileRejects('\\Afoo')).toContain('anchor with');
    // \Z / \z are caught by the shared portability pre-check.
    expect(profileRejects('foo\\Z')).toContain('end-anchors');
    expect(profileRejects('foo\\z')).toContain('end-anchors');
    expect(profileRejects('\\p{L}')).toContain('Unicode property');
    expect(profileRejects('\\P{L}')).toContain('Unicode property');
    expect(profileRejects('\\u00a0')).toContain('profile escape');
    expect(profileRejects('\\a')).toContain('profile escape');
    expect(profileRejects('\\0')).toContain('profile escape');
    expect(profileRejects('a\\x{41}')).toContain('two hex digits');
    expect(profileRejects('foo\\')).toContain('trailing backslash');
    expect(profileRejects('\\é')).toContain('non-ASCII');
  });

  it('keeps the escapes the profile does support', () => {
    expect(profileMatches('a\\x41b', 'aAb')).toBe(true);
    expect(profileMatches('a\\tb', 'a	b')).toBe(true);
    expect(profileMatches('a\\vb', 'ab')).toBe(true);
    expect(profileMatches('a\\.b', 'a.b')).toBe(true);
    expect(profileMatches('a\\.b', 'axb')).toBe(false);
    expect(profileMatches('a\\-b', 'a-b')).toBe(true);
  });

  it('rejects empty character classes', () => {
    // Caught by the shared portability pre-check.
    expect(profileRejects('[]')).toContain('empty character class');
    expect(profileRejects('[^]')).toContain('empty character class');
  });

  it('rewrites the Python named-group spelling for JavaScript', () => {
    expect(compileProfileRegex('(?P<year>[0-9]{4})').source).toBe('(?<year>[0-9]{4})');
    expect(profileMatches('(?P<year>[0-9]{4})', 'in 2026')).toBe(true);
  });

  it('still compiles and matches the shipped library patterns', () => {
    expect(profileMatches('\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b', 'ssn 123-45-6789.')).toBe(true);
    expect(profileMatches('(AKIA|ASIA)[0-9A-Z]{16}', 'AKIA1234567890ABCDEF')).toBe(true);
    expect(
      profileMatches(
        '(?i)\\b(mrn|medical[ \\t\\n\\r\\f_-]?record)[ \\t\\n\\r\\f]*:?[ \\t\\n\\r\\f]*[A-Z0-9]{6,15}\\b',
        'MRN: AB12345',
      ),
    ).toBe(true);
  });

  it('rejects the RE2-unsafe patterns the validator rejects', () => {
    expect(profileRejects('(a+)+')).toContain('nested unbounded quantifier');
    expect(profileRejects('(?=foo)bar')).toContain('group form');
    expect(profileRejects('(foo)\\1')).toContain('profile escape');
    expect(profileRejects('a*+')).toContain('possessive');
  });

  it('accepts only the profile group names', () => {
    expect(profileRejects('(?<1st>x)')).toContain("named group's name");
    expect(profileRejects('(?<année>x)')).toContain("named group's name");
    expect(profileRejects('(?<year x)')).toContain("named group's name");
  });

  it('rejects every group opener outside the profile', () => {
    for (const pattern of [
      'a(?#comment)b',
      'a(?=b)',
      'a(?!b)',
      '(?<=a)b',
      '(?<!a)b',
      '(?>a)',
      '(?(1)a|b)',
      '(?R)',
      '(?1)',
      '(?P<a>x)(?P=a)',
    ]) {
      expect(profileRejects(pattern)).toContain('group form');
    }
    expect(() => compileProfileRegex('(?:ab)+')).not.toThrow();
  });

  it('rejects POSIX bracket expressions', () => {
    expect(profileRejects('[[:alpha:]]')).toContain('unescaped [');
    expect(profileRejects('[a[b]')).toContain('unescaped [');
    expect(profileMatches('[a\\[]', '[')).toBe(true);
  });

  it('rejects the {,n} quantifier', () => {
    expect(profileRejects('a{,3}')).toContain('{,n} quantifier');
    expect(() => compileProfileRegex('a{0,3}')).not.toThrow();
  });

  it('rejects a pattern over the profile size limit', () => {
    expect(profileRejects('a'.repeat(2049))).toContain('2048 bytes');
    expect(() => compileProfileRegex('a'.repeat(2048))).not.toThrow();
  });

  it('takes an astral class member as one scalar value', () => {
    expect(profileRejects('[\u{1F600}-\u{1F64F}]')).toContain('Basic Multilingual Plane');
    expect(profileMatches('^[\u{1F600}a]$', '\u{1F600}')).toBe(true);
    expect(profileMatches('^[\u{1F600}a]$', 'a')).toBe(true);
    expect(profileMatches('^[\u{1F600}a]$', '\uD83D')).toBe(false);
    expect(profileMatches('^[^\u{1F600}]$', '\u{1F600}')).toBe(false);
    expect(profileMatches('^[^\u{1F600}]$', 'a')).toBe(true);
    expect(profileMatches('^[^\u{1F600}]$', '\u{1F64F}')).toBe(true);
  });

  it('folds ASCII letters only under (?i)', () => {
    expect(profileMatches('(?i)stra', 'STRA')).toBe(true);
    expect(profileMatches('(?i)stra', 'Stra')).toBe(true);
    // U+017F (long s) and U+212A (Kelvin sign) simple-case-fold to ASCII under
    // the full Unicode table; the profile folds ASCII only.
    expect(profileMatches('(?i)s', 'ſ')).toBe(false);
    expect(profileMatches('(?i)k', 'K')).toBe(false);
  });

  it('folds class members and ranges under (?i)', () => {
    expect(profileMatches('(?i)^[a-f]$', 'C')).toBe(true);
    expect(profileMatches('(?i)^[a-f]$', 'G')).toBe(false);
    expect(profileMatches('(?i)^[sq]$', 'S')).toBe(true);
    expect(profileMatches('(?i)^[sq]$', 'ſ')).toBe(false);
    expect(profileMatches('(?i)^[^s]$', 'S')).toBe(false);
    expect(profileMatches('(?i)^[^s]$', 'ſ')).toBe(true);
    expect(profileMatches('(?i)\\x41', 'a')).toBe(true);
    expect(profileMatches('(?i)\\x61', 'A')).toBe(true);
    expect(compileProfileRegex('(?i)[0-9]').source).toBe('[0-9]');
    expect(compileProfileRegex('(?i)(?P<ab>c)').source).toBe('(?<ab>[cC])');
  });
});
