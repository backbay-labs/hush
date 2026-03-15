import { describe, it, expect } from 'vitest';
import { parseOrThrow } from '../src/parse.js';
import YAML from 'yaml';

describe('roundtrip', () => {
  it('parse -> serialize -> parse preserves structure', () => {
    const yaml = `
hushspec: "0.1.0"
name: roundtrip-test
rules:
  egress:
    allow:
      - "api.openai.com"
    default: block
  tool_access:
    block:
      - shell_exec
    default: allow
`;
    const spec1 = parseOrThrow(yaml);
    const serialized = YAML.stringify(spec1);
    const spec2 = parseOrThrow(serialized);

    expect(spec2.name).toBe(spec1.name);
    expect(spec2.rules?.egress?.allow).toEqual(spec1.rules?.egress?.allow);
    expect(spec2.rules?.egress?.default).toBe(spec1.rules?.egress?.default);
    expect(spec2.rules?.tool_access?.block).toEqual(spec1.rules?.tool_access?.block);
  });

  it('roundtrip with extensions', () => {
    const yaml = `
hushspec: "0.1.0"
name: ext-roundtrip
extensions:
  posture:
    initial: standard
    states:
      standard:
        capabilities:
          - file_access
          - egress
    transitions: []
  detection:
    prompt_injection:
      enabled: true
      block_at_or_above: high
`;
    const spec1 = parseOrThrow(yaml);
    const serialized = YAML.stringify(spec1);
    const spec2 = parseOrThrow(serialized);

    expect(spec2.extensions?.posture?.initial).toBe('standard');
    expect(spec2.extensions?.detection?.prompt_injection?.block_at_or_above).toBe('high');
  });
});
