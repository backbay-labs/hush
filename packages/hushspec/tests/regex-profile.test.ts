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
      'a(?:[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]|[^\\n])b',
    );
    // One astral code point, like Rust/Python/Go `.` (a bare `[^\n]` would
    // match only half the surrogate pair).
    expect(profileMatches('^a.b$', 'a\u{1F600}b')).toBe(true);
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
    // \Z / \z are caught by the shared RE2 portability pre-check.
    expect(profileRejects('foo\\Z')).toContain('RE2 subset');
    expect(profileRejects('foo\\z')).toContain('RE2 subset');
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
    // Caught by the shared RE2 portability pre-check.
    expect(profileRejects('[]')).toContain('RE2 subset');
    expect(profileRejects('[^]')).toContain('RE2 subset');
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
    expect(profileRejects('(?=foo)bar')).toContain('RE2 subset');
    expect(profileRejects('(foo)\\1')).toContain('RE2 subset');
    expect(profileRejects('a*+')).toContain('RE2 subset');
  });
});
