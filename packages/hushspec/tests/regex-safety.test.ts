import { describe, it, expect } from 'vitest';
import { parse } from '../src/parse.js';
import { validate, isSafeRegex } from '../src/validate.js';
import { parseOrThrow } from '../src/parse.js';

// ---------------------------------------------------------------------------
// isSafeRegex unit tests
// ---------------------------------------------------------------------------

describe('isSafeRegex', () => {
  it('accepts simple character class patterns', () => {
    expect(isSafeRegex('AKIA[0-9A-Z]{16}')).toBe(true);
  });

  it('accepts case-insensitive flag', () => {
    // (?i) is RE2-compatible but not valid JS RegExp; isSafeRegex only checks for non-RE2 features
    expect(isSafeRegex('(?i)disable[\\s_\\-]?(security|auth)')).toBe(true);
  });

  it('accepts dot-star with literal separator', () => {
    expect(isSafeRegex('curl.*\\|.*bash')).toBe(true);
  });

  it('accepts non-capturing groups', () => {
    expect(isSafeRegex('(?:key|token)\\s*[:=]\\s*[A-Za-z0-9]{32,}')).toBe(true);
  });

  it('accepts named groups (Python-style)', () => {
    expect(isSafeRegex('(?P<name>[a-z]+)')).toBe(true);
  });

  it('accepts anchors and word boundaries', () => {
    expect(isSafeRegex('^\\bfoo\\b$')).toBe(true);
  });

  it('accepts \\0 (null character, not a backreference)', () => {
    expect(isSafeRegex('\\0')).toBe(true);
  });

  it('rejects backreferences (\\1)', () => {
    expect(isSafeRegex('(a)\\1')).toBe(false);
  });

  it('rejects backreferences (\\2)', () => {
    expect(isSafeRegex('(a)(b)\\2')).toBe(false);
  });

  it('rejects named backreferences (\\k<name>)', () => {
    expect(isSafeRegex('(?<word>\\w+)\\k<word>')).toBe(false);
  });

  it('rejects positive lookahead (?=...)', () => {
    expect(isSafeRegex('foo(?=bar)')).toBe(false);
  });

  it('rejects negative lookahead (?!...)', () => {
    expect(isSafeRegex('foo(?!bar)')).toBe(false);
  });

  it('rejects positive lookbehind (?<=...)', () => {
    expect(isSafeRegex('(?<=password:)\\s*\\S+')).toBe(false);
  });

  it('rejects negative lookbehind (?<!...)', () => {
    expect(isSafeRegex('(?<!\\d)\\d{3}')).toBe(false);
  });

  it('rejects atomic groups (?>...)', () => {
    expect(isSafeRegex('(?>abc)')).toBe(false);
  });

  it('rejects possessive quantifier *+', () => {
    expect(isSafeRegex('a*+')).toBe(false);
  });

  it('rejects possessive quantifier ++', () => {
    expect(isSafeRegex('a++')).toBe(false);
  });

  it('rejects possessive quantifier ?+', () => {
    expect(isSafeRegex('a?+')).toBe(false);
  });

  // Cross-SDK parity fix (spec item S3): the bare possessive check used to be
  // a raw substring over the whole pattern (`\*\+|\+\+|\?\+`), which matched
  // these possessive-*looking* character sequences even though they sit
  // inside a character class as ordinary literal members, not a quantifier.
  // hasPossessiveQuantifier is class-aware, so it never evaluates them as a
  // quantifier candidate in the first place.
  it('does not misread possessive-looking characters inside a class as possessive ([*+])', () => {
    expect(isSafeRegex('[*+]')).toBe(true);
  });

  it('does not misread possessive-looking characters inside a class as possessive ([?+])', () => {
    expect(isSafeRegex('[?+]')).toBe(true);
  });

  it('does not misread possessive-looking characters inside a class in either order ([+*])', () => {
    expect(isSafeRegex('[+*]')).toBe(true);
  });

  // Cross-SDK parity fix (spec item S2): possessive *brace* quantifiers were
  // the one shape the existing possessive check missed (`*+`/`++`/`?+` were
  // already rejected above, but `{n}+`/`{n,}+`/`{n,m}+` slipped through).
  it('rejects possessive brace quantifier {n}+', () => {
    expect(isSafeRegex('a{2}+')).toBe(false);
  });

  it('rejects possessive brace quantifier {n,}+', () => {
    expect(isSafeRegex('a{2,}+')).toBe(false);
  });

  it('rejects possessive brace quantifier {n,m}+', () => {
    expect(isSafeRegex('a{2,3}+')).toBe(false);
  });

  it('accepts a lazy brace quantifier {n,m}? (not possessive)', () => {
    expect(isSafeRegex('a{2,3}?')).toBe(true);
  });

  it('accepts a literal brace followed by an unrelated + quantifier (a{b}+)', () => {
    // `{b}` isn't digit-shaped, so it's literal text, not a quantifier; the
    // `+` genuinely quantifies the literal `}` (one-or-more), which is not
    // possessive syntax at all.
    expect(isSafeRegex('a{b}+')).toBe(true);
  });

  it('does not misread a brace-and-plus inside a character class as possessive ([a{2}+])', () => {
    expect(isSafeRegex('[a{2}+]')).toBe(true);
  });

  // Cross-SDK parity fix (spec item S2): \Z and \z end-of-string anchors
  // have differing semantics across Rust/Python/Go and are treated as
  // literal letters by JavaScript RegExp; reject both so policies anchor
  // with $ instead.
  it('rejects \\Z end-of-string anchor', () => {
    expect(isSafeRegex('foo\\Z')).toBe(false);
  });

  it('rejects \\z end-of-string anchor', () => {
    expect(isSafeRegex('foo\\z')).toBe(false);
  });

  // Cross-SDK parity fix (spec item S3): the anchor check used to be a raw
  // substring (`\\Z|\\z`) over the whole pattern, which could not distinguish
  // the `\Z` anchor (one backslash then Z) from an escaped backslash followed
  // by a literal Z -- the pattern text `\\Z` (two backslash characters then
  // Z), which matches a literal `\` then a literal `Z` and is not an anchor
  // at all. hasEndAnchorEscape consumes the escaped pair before ever
  // reconsidering the following character, so it tells the two apart.
  it('accepts an escaped backslash followed by a literal Z (not an anchor)', () => {
    expect(isSafeRegex('\\\\Z')).toBe(true);
  });

  it('accepts an escaped backslash followed by a literal z (not an anchor)', () => {
    expect(isSafeRegex('\\\\z')).toBe(true);
  });

  // Cross-SDK parity regression fix (v3, item 2): `\Z`/`\z` INSIDE a character
  // class. JavaScript `RegExp` is the only SDK engine that accepts `[\Z]`/`[\z]`
  // (reading the escape as a literal letter); Rust `regex`, Python `re`, and Go
  // RE2 all reject them at compile time. Those three lean on that compile-time
  // rejection (their scanners skip in-class `\Z`), but TS `isSafeRegex` has no
  // compile backstop -- `new RegExp('[\\Z]')` succeeds -- so hasEndAnchorEscape
  // must flag in-class `\Z`/`\z` itself to keep the net accept/reject identical.
  // A prior wave over-corrected here and accepted `[\Z]`; this re-rejects it.
  it('rejects \\Z inside a character class ([\\Z])', () => {
    expect(isSafeRegex('[\\Z]')).toBe(false);
  });

  it('rejects \\z inside a character class ([\\z])', () => {
    expect(isSafeRegex('[\\z]')).toBe(false);
  });

  it('rejects \\Z inside a non-empty character class ([x\\Z])', () => {
    expect(isSafeRegex('[x\\Z]')).toBe(false);
  });

  // The escaped-literal `\\Z` (backslash-backslash then Z) is still NOT an
  // anchor and stays accepted, including inside a class (`[\\Z]` = literal `\`
  // and `Z`) -- the escape pair consumes the second backslash before Z is seen.
  it('still accepts the escaped-literal \\\\Z inside a class ([\\\\Z])', () => {
    expect(isSafeRegex('[\\\\Z]')).toBe(true);
  });

  // Cross-SDK parity fix (spec item S2): empty character classes compile
  // successfully in JavaScript ([] matches nothing, [^] matches any
  // character including newline) but are a compile error in Rust/Python/Go;
  // reject both so validation agrees everywhere.
  it('rejects empty character class []', () => {
    expect(isSafeRegex('a[]b')).toBe(false);
  });

  it('rejects negated empty character class [^]', () => {
    expect(isSafeRegex('a[^]b')).toBe(false);
  });

  it('accepts a non-empty character class starting with an escaped ] ([\\]abc])', () => {
    expect(isSafeRegex('[\\]abc]')).toBe(true);
  });

  it('rejects conditional patterns', () => {
    expect(isSafeRegex('(?(1)yes|no)')).toBe(false);
  });

  it('rejects named backreference (?P=name)', () => {
    expect(isSafeRegex('(?P<word>\\w+)(?P=word)')).toBe(false);
  });

  it('rejects subroutine calls \\g<name>', () => {
    expect(isSafeRegex('\\g<name>')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// S3 parity fix: shared REJECT/ACCEPT list (cross-SDK parity spec, section
// S3)
//
// Rust `disallowed_regex_feature` / Go `disallowedRegexFeature` are
// escape/class-aware char scanners. TS's RE2_DISALLOWED used to check the
// possessive-star (`*+`/`++`/`?+`) and `\Z`/`\z` forms as raw substrings over
// the whole pattern, which over-rejected patterns the other three SDKs
// accept (e.g. `[*+]`, where the possessive-looking characters are ordinary
// class members, not a quantifier). hasPossessiveQuantifier and
// hasEndAnchorEscape now scan the same escape/class-aware way Rust/Go do.
// This block reproduces the exact shared REJECT/ACCEPT list from the parity
// spec verbatim, so all four SDKs are verified against the identical set.
// ---------------------------------------------------------------------------

describe('S3 shared REJECT/ACCEPT list (cross-SDK parity)', () => {
  const REJECT = [
    'a++',
    'a*+',
    'a?+',
    'a{2}+',
    'a{2,}+',
    '(ab)++',
    '\\Z',
    '\\z',
    '[]',
    '[^]',
  ];
  const ACCEPT = [
    '[*+]',
    '[?+]',
    '\\\\Z',
    '\\\\z',
    '[a{2}+]',
    'a\\{2}+',
    '\\[]',
    'a{2,5}?',
    '(?:abc)+',
    '[+*]',
  ];

  for (const pattern of REJECT) {
    it(`rejects: ${pattern}`, () => {
      expect(isSafeRegex(pattern)).toBe(false);
    });
  }

  for (const pattern of ACCEPT) {
    it(`accepts: ${pattern}`, () => {
      expect(isSafeRegex(pattern)).toBe(true);
    });
  }
});

// ---------------------------------------------------------------------------
// Nested-quantifier (catastrophic backtracking / ReDoS) heuristic
// ---------------------------------------------------------------------------

describe('isSafeRegex nested-quantifier heuristic', () => {
  const REJECT = ['(a+)+', '(a*)*', '(a+)*', '([0-9]+)*', '(\\d+)+', '(a+)+$'];
  const ACCEPT = [
    '(abc)+',
    'a+',
    '\\d{3}-\\d{2}-\\d{4}',
    '(?:foo|bar)+',
    '(a{1,3}){1,3}',
    'sk-(proj-)?[A-Za-z0-9_-]{20,}',
    '(AKIA|ASIA)[0-9A-Z]{16}',
    'github_pat_[0-9a-zA-Z_]{50,}',
  ];

  for (const pattern of REJECT) {
    it(`rejects nested unbounded quantifier: ${pattern}`, () => {
      expect(isSafeRegex(pattern)).toBe(false);
    });
  }

  for (const pattern of ACCEPT) {
    it(`accepts safe quantifier shape: ${pattern}`, () => {
      expect(isSafeRegex(pattern)).toBe(true);
    });
  }
});

// ---------------------------------------------------------------------------
// Regex validation in parse/validate pipeline
// ---------------------------------------------------------------------------

describe('regex safety in validation', () => {
  it('accepts valid RE2-compatible secret pattern', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: aws_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
`);
    expect(result.ok).toBe(true);
  });

  it('accepts RE2 inline case-insensitive modifiers during parse', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  shell_commands:
    forbidden_patterns:
      - "(?i)rm\\\\s+-rf\\\\s+/"
`);
    expect(result.ok).toBe(true);
  });

  it('accepts Python-style named groups during parse', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: named_group
        pattern: "(?P<token>sk-[A-Za-z0-9]{48})"
        severity: critical
`);
    expect(result.ok).toBe(true);
  });

  it('rejects syntactically invalid regex', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: bad
        pattern: "["
        severity: critical
`);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('valid regular expression');
    }
  });

  it('rejects regex with backreference in secret_patterns', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: backref
        pattern: "(a)\\\\1"
        severity: critical
`);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('RE2');
    }
  });

  it('rejects regex with lookahead in shell_commands.forbidden_patterns', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  shell_commands:
    forbidden_patterns:
      - "(?=foo)bar"
`);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('RE2');
    }
  });

  it('rejects regex with lookbehind in patch_integrity.forbidden_patterns', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  patch_integrity:
    max_imbalance_ratio: 10.0
    forbidden_patterns:
      - "(?<=password:)\\\\s*\\\\S+"
`);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('RE2');
    }
  });

  it('accepts valid JS-compatible patterns across all regex fields', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: aws_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: github_token
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: critical
  shell_commands:
    forbidden_patterns:
      - "[Rr][Mm]\\\\s+-[Rr][Ff]\\\\s+/"
  patch_integrity:
    max_imbalance_ratio: 10.0
    forbidden_patterns:
      - "[Cc][Hh][Mm][Oo][Dd]\\\\s+777"
`);
    expect(result.ok).toBe(true);
  });

  it('rejects non-RE2 patterns even if they are valid JS', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: lookahead
        pattern: "(?=secret)\\\\w+"
        severity: critical
`);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('RE2');
    }
  });
});

// ---------------------------------------------------------------------------
// Built-in rulesets: verify regex patterns are RE2-safe
// ---------------------------------------------------------------------------

describe('built-in ruleset patterns are RE2-safe', () => {
  const rulesetPatterns: Array<{ name: string; patterns: string[] }> = [
    {
      name: 'default.yaml',
      patterns: [
        'AKIA[0-9A-Z]{16}',
        'gh[ps]_[A-Za-z0-9]{36}',
        'sk-[A-Za-z0-9]{48}',
        '-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----',
        '(?i)disable[\\s_\\-]?(security|auth|ssl|tls)',
        '(?i)skip[\\s_\\-]?(verify|validation|check)',
        '(?i)rm\\s+-rf\\s+/',
        '(?i)chmod\\s+777',
      ],
    },
    {
      name: 'strict.yaml',
      patterns: [
        'AKIA[0-9A-Z]{16}',
        'gh[ps]_[A-Za-z0-9]{36}',
        'sk-[A-Za-z0-9]{48}',
        'sk-ant-[A-Za-z0-9\\-]{95}',
        '-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----',
        'npm_[A-Za-z0-9]{36}',
        'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
        '(?i)(api[_\\-]?key|apikey)\\s*[:=]\\s*[A-Za-z0-9]{32,}',
        '(?i)disable[\\s_\\-]?(security|auth|ssl|tls)',
        '(?i)skip[\\s_\\-]?(verify|validation|check)',
        '(?i)rm\\s+-rf\\s+/',
        '(?i)chmod\\s+777',
        '(?i)eval\\s*\\(',
        '(?i)exec\\s*\\(',
        '(?i)reverse[_\\-]?shell',
        '(?i)bind[_\\-]?shell',
      ],
    },
    {
      name: 'ai-agent.yaml',
      patterns: [
        'AKIA[0-9A-Z]{16}',
        'gh[ps]_[A-Za-z0-9]{36}',
        'sk-[A-Za-z0-9]{48}',
        'sk-ant-[A-Za-z0-9\\-]{95}',
        '-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----',
        '(?i)rm\\s+-rf\\s+/',
        '(?i)chmod\\s+777',
        'curl.*\\|.*bash',
        'wget.*\\|.*bash',
      ],
    },
    {
      name: 'cicd.yaml',
      patterns: [
        'AKIA[0-9A-Z]{16}',
        'gh[ps]_[A-Za-z0-9]{36}',
        '-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----',
      ],
    },
  ];

  for (const { name, patterns } of rulesetPatterns) {
    it(`${name}: all patterns are RE2-safe`, () => {
      for (const pattern of patterns) {
        expect(isSafeRegex(pattern)).toBe(true);
      }
    });
  }

  // permissive.yaml and remote-desktop.yaml have no regex patterns to validate.
});

// ---------------------------------------------------------------------------
// Detection engine: exfiltration boundary patterns are RE2-safe
//
// The ssn/credit_card patterns in RegexExfiltrationDetector (src/detection.ts)
// replaced `\b` digit-run boundaries with explicit ASCII non-digit boundaries
// for cross-SDK parity (see detection-wiring spec §3). The ssn pattern's body
// also uses `[0-9]` instead of `\d` (spec item S3), and email_address
// replaced its `\b` word boundaries with explicit ASCII boundaries the same
// way. These are built-in patterns (not parsed from policy YAML), but must
// still stay within the RE2 subset like every other pattern in the repo.
// ---------------------------------------------------------------------------

describe('detection engine boundary patterns are RE2-safe', () => {
  it('exfiltration ssn pattern is RE2-safe', () => {
    expect(isSafeRegex('(?:^|[^0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}(?:[^0-9]|$)')).toBe(true);
  });

  it('exfiltration credit_card pattern is RE2-safe', () => {
    expect(
      isSafeRegex(
        '(?:^|[^0-9])(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})(?:[^0-9]|$)',
      ),
    ).toBe(true);
  });

  it('exfiltration email_address pattern is RE2-safe', () => {
    expect(
      isSafeRegex(
        '(?:^|[^A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}(?:[^A-Za-z0-9.-]|$)',
      ),
    ).toBe(true);
  });
});
