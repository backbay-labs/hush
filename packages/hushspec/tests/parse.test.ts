import { describe, it, expect } from 'vitest';
import { parse, parseOrThrow } from '../src/parse.js';
import { validate } from '../src/validate.js';

describe('parse', () => {
  it('parses minimal valid document', () => {
    const result = parse('hushspec: "0.1.0"\nname: test\n');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.hushspec).toBe('0.1.0');
      expect(result.value.name).toBe('test');
    }
  });

  it('rejects unknown top-level fields', () => {
    const result = parse('hushspec: "0.1.0"\nunknown_field: true\n');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('unknown field `unknown_field`');
    }
  });

  it('rejects unknown rules', () => {
    const result = parse('hushspec: "0.1.0"\nrules:\n  nonexistent_rule:\n    enabled: true\n');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('rules: unknown field `nonexistent_rule`');
    }
  });

  it('rejects unknown nested rule fields', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  egress:
    default: block
    extra_field: true
`);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('rules.egress: unknown field `extra_field`');
    }
  });

  it('rejects invalid enum values', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  egress:
    default: maybe
`);
    expect(result.ok).toBe(false);
  });

  it('rejects invalid field types', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: "yes"
`);
    expect(result.ok).toBe(false);
  });

  // browser_automation and code_execution deny unknown members and check
  // field types like every other `rules.*` block (core spec 2.4).
  it('rejects unknown field in rules.browser_automation', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  browser_automation:
    enabled: true
    extra_field: true
`);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('rules.browser_automation: unknown field `extra_field`');
    }
  });

  it('rejects invalid field type in rules.browser_automation', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  browser_automation:
    allowed_domains: "*.example.com"
`);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('rules.browser_automation.allowed_domains');
    }
  });

  it('rejects an invalid regex in rules.browser_automation.extra_credential_patterns', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  browser_automation:
    extra_credential_patterns:
      - "("
`);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('rules.browser_automation.extra_credential_patterns[0]');
    }
  });

  it('rejects unknown field in rules.code_execution', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  code_execution:
    enabled: true
    extra_field: true
`);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('rules.code_execution: unknown field `extra_field`');
    }
  });

  it('rejects invalid field type in rules.code_execution', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  code_execution:
    network_access: "no"
`);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('rules.code_execution.network_access');
    }
  });

  it('rejects rules.code_execution.max_scan_bytes below the minimum of 1', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  code_execution:
    max_scan_bytes: 0
`);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('rules.code_execution.max_scan_bytes');
    }
  });

  it('accepts valid browser_automation and code_execution rules', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  browser_automation:
    enabled: true
    allowed_domains:
      - "*.example.com"
    allowed_verbs:
      - navigate
    extra_credential_patterns:
      - "sk-[A-Za-z0-9]{20,}"
  code_execution:
    enabled: true
    language_allowlist:
      - python
    module_denylist:
      - subprocess
    max_execution_time_ms: 5000
    max_scan_bytes: 65536
`);
    expect(result.ok).toBe(true);
  });

  it('rejects invalid regex patterns', () => {
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
  });

  it('rejects invalid numeric ranges', () => {
    const result = parse(`
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      top_k: 0
`);
    expect(result.ok).toBe(false);
  });

  it('rejects missing hushspec field', () => {
    const result = parse('name: test\n');
    expect(result.ok).toBe(false);
  });

  it('parses full rules', () => {
    const yaml = `
hushspec: "0.1.0"
name: full-test
rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
    exceptions:
      - "**/.ssh/config"
  egress:
    allow:
      - "api.openai.com"
    default: block
  tool_access:
    block:
      - shell_exec
    default: allow
  secret_patterns:
    patterns:
      - name: aws_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
`;
    const result = parse(yaml);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.rules?.forbidden_paths?.patterns).toHaveLength(2);
      expect(result.value.rules?.egress?.default).toBe('block');
      expect(result.value.rules?.tool_access?.block).toEqual(['shell_exec']);
      expect(result.value.rules?.secret_patterns?.patterns).toHaveLength(1);
    }
  });
});

describe('validate', () => {
  it('validates supported version', () => {
    const spec = parseOrThrow('hushspec: "0.1.0"\n');
    const result = validate(spec);
    expect(result.valid).toBe(true);
  });

  it('rejects unsupported version', () => {
    const spec = parseOrThrow('hushspec: "99.0.0"\n');
    const result = validate(spec);
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('E002');
  });

  // Core spec 2: `name` is optional, but a present one must not be empty --
  // a bundle's subject and a receipt's policy summary both carry it, and an
  // empty name names nothing. The v1 core schema says the same with
  // `minLength: 1`; the shared vector is `fixtures/core/invalid/empty-name.yaml`.
  describe('name', () => {
    it('rejects an empty name with E004', () => {
      const result = validate({ hushspec: '1.0.0', name: '' });
      expect(result.valid).toBe(false);
      expect(result.errors[0].code).toBe('E004');
      expect(result.errors[0].message).toBe('name: must not be empty when present');
    });

    it('refuses the document at parse time, before it can be evaluated', () => {
      const result = parse('hushspec: "1.0.0"\nname: ""\n');
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.code).toBe('E004');
      expect(result.error).toContain('name: must not be empty');
    });

    it('rejects an empty name under every supported minor', () => {
      // 1.0 froze the 0.2 semantics, and this is the one validation rule the
      // declaration added (core spec 10.2) -- it is not gated on the version
      // the document declares.
      for (const version of ['0.1.0', '0.2.0', '1.0.0']) {
        expect(validate({ hushspec: version, name: '' }).valid, version).toBe(false);
      }
    });

    it('accepts an absent name and a non-empty one', () => {
      expect(validate(parseOrThrow('hushspec: "1.0.0"\n')).valid).toBe(true);
      expect(validate(parseOrThrow('hushspec: "1.0.0"\nname: a\n')).valid).toBe(true);
      // Whitespace is a name; only the empty string is refused, exactly as
      // the schema's `minLength: 1` reads.
      expect(validate(parseOrThrow('hushspec: "1.0.0"\nname: " "\n')).valid).toBe(true);
    });
  });

  it('rejects duplicate secret pattern names', () => {
    const result = parse(`
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: dup
        pattern: "a"
        severity: critical
      - name: dup
        pattern: "b"
        severity: critical
`);
    expect(result.ok).toBe(false);
  });

  it('warns when no rules present', () => {
    const spec = parseOrThrow('hushspec: "0.1.0"\n');
    const result = validate(spec);
    expect(result.warnings).toContain('no rules section present');
  });

  // Every comparison against NaN is false, so `max_imbalance_ratio: .nan`
  // would slip past the `minExclusive: 0` range check and then make
  // `require_balance` fail OPEN at evaluation time (`ratio > NaN` is false
  // too). Non-finite floats are refused before a value can reach evaluation.
  describe('rejects non-finite floats', () => {
    it('rejects max_imbalance_ratio: .nan', () => {
      const result = parse(`
hushspec: "0.1.0"
rules:
  patch_integrity:
    require_balance: true
    max_imbalance_ratio: .nan
`);
      expect(result.ok).toBe(false);
    });

    it('rejects max_imbalance_ratio: .inf', () => {
      const result = parse(`
hushspec: "0.1.0"
rules:
  patch_integrity:
    require_balance: true
    max_imbalance_ratio: .inf
`);
      expect(result.ok).toBe(false);
    });

    it('rejects max_imbalance_ratio: -.inf', () => {
      const result = parse(`
hushspec: "0.1.0"
rules:
  patch_integrity:
    require_balance: true
    max_imbalance_ratio: -.inf
`);
      expect(result.ok).toBe(false);
    });

    it('rejects extensions.detection.threat_intel.similarity_threshold: .nan', () => {
      const result = parse(`
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      enabled: true
      similarity_threshold: .nan
`);
      expect(result.ok).toBe(false);
    });
  });
});
