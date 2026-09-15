import { describe, it, expect } from 'vitest';
import { parse, yamlProfileViolation, MAX_DOCUMENT_BYTES } from '../src/parse.js';

// D17 (core spec 2.4): the HushSpec YAML profile.

const VALID = `hushspec: "0.2.0"
name: profile
rules:
  egress:
    default: block
`;

describe('YAML profile (D17)', () => {
  it('accepts a plain single-document policy', () => {
    const result = parse(VALID);
    expect(result.ok).toBe(true);
  });

  it('rejects anchors and aliases', () => {
    const withAlias = `hushspec: "0.2.0"
rules:
  forbidden_paths:
    patterns: &secrets
      - "**/.env"
    exceptions: *secrets
`;
    const result = parse(withAlias);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('anchors are not allowed');
  });

  it('rejects a bare alias without a preceding anchor', () => {
    expect(yamlProfileViolation('a: *ref\n')).toContain('aliases are not allowed');
  });

  it('rejects merge keys', () => {
    expect(yamlProfileViolation('b:\n  <<: *base\n')).toContain('merge keys are not allowed');
  });

  it('rejects a multi-document stream', () => {
    const result = parse(`hushspec: "0.2.0"
name: first
---
hushspec: "0.2.0"
name: second
`);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('multi-document streams are not allowed');
  });

  it('accepts a leading document marker', () => {
    expect(parse(`---\n${VALID}`).ok).toBe(true);
  });

  it('rejects `yes` where a boolean is required (YAML 1.2 Core has no such boolean)', () => {
    const result = parse(`hushspec: "0.2.0"
rules:
  egress:
    enabled: yes
    default: block
`);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('expected a boolean');
  });

  it('rejects duplicate mapping keys', () => {
    const result = parse(`hushspec: "0.2.0"
name: first
name: second
`);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('duplicate entry with key "name"');
  });

  it('rejects tabs used as indentation', () => {
    const result = parse('hushspec: "0.2.0"\nrules:\n\tegress:\n\t  default: block\n');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('Tabs are not allowed');
  });

  it('rejects a document over the size cap', () => {
    const padding = 'x'.repeat(MAX_DOCUMENT_BYTES);
    const result = parse(`hushspec: "0.2.0"\nname: "${padding}"\n`);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('maximum size');
  });

  it('rejects a document nested past the depth cap', () => {
    let body = 'deep';
    for (let i = 0; i < 40; i++) {
      body = `[${body}]`;
    }
    const result = parse(`hushspec: "0.2.0"\nname: ${body}\n`);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('maximum depth');
  });

  it('does not mistake `*` or `&` inside quoted scalars for indicators', () => {
    expect(yamlProfileViolation('a: "*not-an-alias"\n')).toBeUndefined();
    expect(yamlProfileViolation("a: '&not-an-anchor'\n")).toBeUndefined();
    expect(yamlProfileViolation('rules:\n  egress:\n    block:\n      - "*.evil.com"\n'))
      .toBeUndefined();
  });

  it('does not scan inside block scalars', () => {
    expect(yamlProfileViolation('description: |\n  &anchor *alias\n  <<: merge\nname: x\n'))
      .toBeUndefined();
  });

  it('ignores indicators inside comments', () => {
    expect(yamlProfileViolation('a: 1 # &anchor *alias\n')).toBeUndefined();
  });
});
