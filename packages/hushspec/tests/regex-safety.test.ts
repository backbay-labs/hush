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
// for cross-SDK parity (see detection-wiring spec §3). These are built-in
// patterns (not parsed from policy YAML), but must still stay within the
// RE2 subset like every other pattern in the repo.
// ---------------------------------------------------------------------------

describe('detection engine boundary patterns are RE2-safe', () => {
  it('exfiltration ssn pattern is RE2-safe', () => {
    expect(isSafeRegex('(?:^|[^0-9])\\d{3}-\\d{2}-\\d{4}(?:[^0-9]|$)')).toBe(true);
  });

  it('exfiltration credit_card pattern is RE2-safe', () => {
    expect(
      isSafeRegex(
        '(?:^|[^0-9])(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})(?:[^0-9]|$)',
      ),
    ).toBe(true);
  });
});
