import { describe, it, expect } from 'vitest';
import { parse, parseOrThrow } from '../src/parse.js';
import { validate } from '../src/validate.js';
import { merge } from '../src/merge.js';

describe('posture extension', () => {
  it('parses valid posture', () => {
    const spec = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  posture:
    initial: standard
    states:
      restricted:
        capabilities: [file_access]
      standard:
        capabilities: [file_access, egress]
        budgets:
          file_writes: 50
      elevated:
        capabilities: [file_access, egress, shell]
    transitions:
      - from: restricted
        to: standard
        on: user_approval
      - from: "*"
        to: restricted
        on: critical_violation
      - from: elevated
        to: standard
        on: timeout
        after: "1h"
`);
    expect(spec.extensions?.posture?.initial).toBe('standard');
    expect(Object.keys(spec.extensions?.posture?.states ?? {})).toHaveLength(3);
    expect(spec.extensions?.posture?.transitions).toHaveLength(3);
    const result = validate(spec);
    expect(result.valid).toBe(true);
  });

  it('rejects invalid initial state', () => {
    const result = parse(`
hushspec: "0.1.0"
extensions:
  posture:
    initial: nonexistent
    states:
      valid:
        capabilities: []
    transitions: []
`);
    expect(result.ok).toBe(false);
  });

  it('rejects timeout without after', () => {
    const result = parse(`
hushspec: "0.1.0"
extensions:
  posture:
    initial: a
    states:
      a:
        capabilities: []
      b:
        capabilities: []
    transitions:
      - from: a
        to: b
        on: timeout
`);
    expect(result.ok).toBe(false);
  });
});

describe('origins extension', () => {
  it('parses valid origins', () => {
    const spec = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  posture:
    initial: elevated
    states:
      elevated:
        capabilities: [tool_call]
    transitions: []
  origins:
    default_behavior: deny
    profiles:
      - id: incident-room
        match:
          provider: slack
          tags: [incident]
        posture: elevated
        budgets:
          tool_calls: 200
        explanation: Incident response
      - id: external
        match:
          visibility: external_shared
        data:
          redact_before_send: true
`);
    expect(spec.extensions?.origins?.profiles).toHaveLength(2);
    const result = validate(spec);
    expect(result.valid).toBe(true);
  });

  it('rejects duplicate profile ids', () => {
    const result = parse(`
hushspec: "0.1.0"
extensions:
  origins:
    profiles:
      - id: dup
        match:
          provider: slack
      - id: dup
        match:
          provider: teams
`);
    expect(result.ok).toBe(false);
  });

  it('rejects posture references without posture states', () => {
    const result = parse(`
hushspec: "0.1.0"
extensions:
  origins:
    profiles:
      - id: incident-room
        posture: elevated
`);
    expect(result.ok).toBe(false);
  });
});

describe('detection extension', () => {
  it('parses valid detection', () => {
    const spec = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      enabled: true
      warn_at_or_above: suspicious
      block_at_or_above: high
    jailbreak:
      block_threshold: 40
      warn_threshold: 15
    threat_intel:
      pattern_db: "builtin:s2bench-v1"
      similarity_threshold: 0.85
`);
    expect(spec.extensions?.detection?.prompt_injection?.enabled).toBe(true);
    const result = validate(spec);
    expect(result.valid).toBe(true);
  });

  it('warns on inverted thresholds', () => {
    const spec = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  detection:
    jailbreak:
      block_threshold: 10
      warn_threshold: 50
`);
    const result = validate(spec);
    expect(result.valid).toBe(true);
    expect(result.warnings.length).toBeGreaterThan(0);
  });

  it('rejects out-of-range similarity', () => {
    const result = parse(`
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      similarity_threshold: 1.5
`);
    expect(result.ok).toBe(false);
  });

  it('rejects zero top_k', () => {
    const result = parse(`
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      top_k: 0
`);
    expect(result.ok).toBe(false);
  });
});

describe('unknown extensions', () => {
  it('rejects unknown extension keys', () => {
    const result = parse(`
hushspec: "0.1.0"
extensions:
  unknown_ext:
    enabled: true
`);
    expect(result.ok).toBe(false);
  });
});

describe('extension merge', () => {
  it('deep_merge preserves base posture states by name', () => {
    const base = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  posture:
    initial: a
    states:
      a:
        capabilities: [file_access]
    transitions: []
`);
    const child = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  posture:
    initial: b
    states:
      b:
        capabilities: [egress]
    transitions: []
`);
    const merged = merge(base, child);
    expect(merged.extensions?.posture?.initial).toBe('b');
    expect(merged.extensions?.posture?.states.a?.capabilities).toEqual(['file_access']);
    expect(merged.extensions?.posture?.states.b?.capabilities).toEqual(['egress']);
  });

  it('deep_merge merges origin profiles by id and preserves default_behavior', () => {
    const base = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  origins:
    default_behavior: deny
    profiles:
      - id: existing
        explanation: base
`);
    const child = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  origins:
    profiles:
      - id: existing
        explanation: overridden
      - id: new-one
        explanation: appended
`);
    const merged = merge(base, child);
    expect(merged.extensions?.origins?.profiles).toHaveLength(2);
    expect(merged.extensions?.origins?.default_behavior).toBe('deny');
    const existing = merged.extensions?.origins?.profiles?.find(p => p.id === 'existing');
    expect(existing?.explanation).toBe('overridden');
  });

  it('merge strategy replaces the child extension block', () => {
    const base = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  origins:
    default_behavior: minimal_profile
    profiles:
      - id: base
        explanation: base
`);
    const child = parseOrThrow(`
hushspec: "0.1.0"
merge_strategy: merge
extensions:
  origins:
    profiles:
      - id: child
        explanation: child
`);
    const merged = merge(base, child);
    expect(merged.extensions?.origins?.default_behavior).toBeUndefined();
    expect(merged.extensions?.origins?.profiles).toEqual([{ id: 'child', explanation: 'child' }]);
  });

  it('deep_merge merges detection subsections and preserves base fields', () => {
    const base = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      enabled: true
    jailbreak:
      warn_threshold: 20
`);
    const child = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  detection:
    jailbreak:
      block_threshold: 90
`);
    const merged = merge(base, child);
    expect(merged.extensions?.detection?.prompt_injection?.enabled).toBe(true);
    expect(merged.extensions?.detection?.jailbreak?.block_threshold).toBe(90);
    expect(merged.extensions?.detection?.jailbreak?.warn_threshold).toBe(20);
  });

  it('base extensions preserved when child has none', () => {
    const base = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  detection:
    jailbreak:
      block_threshold: 40
`);
    const child = parseOrThrow('hushspec: "0.1.0"\n');
    const merged = merge(base, child);
    expect(merged.extensions?.detection?.jailbreak?.block_threshold).toBe(40);
  });
});

describe('full document with rules + extensions', () => {
  it('parses and validates', () => {
    const spec = parseOrThrow(`
hushspec: "0.1.0"
name: complete
rules:
  egress:
    allow: ["api.openai.com"]
    default: block
extensions:
  posture:
    initial: std
    states:
      std:
        capabilities: [egress]
    transitions: []
  detection:
    prompt_injection:
      block_at_or_above: high
`);
    const result = validate(spec);
    expect(result.valid).toBe(true);
    expect(spec.rules?.egress).toBeDefined();
    expect(spec.extensions?.posture).toBeDefined();
    expect(spec.extensions?.detection).toBeDefined();
  });
});
