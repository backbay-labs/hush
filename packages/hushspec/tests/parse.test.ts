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
      expect(result.error).toContain('unknown top-level field');
    }
  });

  it('rejects unknown rules', () => {
    const result = parse('hushspec: "0.1.0"\nrules:\n  nonexistent_rule:\n    enabled: true\n');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('unknown rule');
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
      expect(result.error).toContain('unknown field at rules.egress');
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
    expect(result.errors[0].code).toBe('unsupported_version');
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
});
