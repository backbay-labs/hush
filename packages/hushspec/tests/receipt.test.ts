import { describe, expect, it } from 'vitest';
import type { HushSpec } from '../src/schema.js';
import type { EvaluationAction } from '../src/evaluate.js';
import { evaluate } from '../src/evaluate.js';
import { HUSHSPEC_VERSION } from '../src/version.js';
import {
  evaluateAudited,
  computePolicyHash,
  DEFAULT_AUDIT_CONFIG,
} from '../src/receipt.js';
import type { AuditConfig, DecisionReceipt } from '../src/receipt.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;
const SHA256_RE = /^[0-9a-f]{64}$/;

function minimalSpec(): HushSpec {
  return {
    hushspec: '0.1.0',
    name: 'test-policy',
  };
}

function specWithToolAccess(): HushSpec {
  return {
    hushspec: '0.1.0',
    name: 'tool-policy',
    rules: {
      tool_access: {
        allow: ['read_file', 'write_file'],
        block: ['dangerous_tool'],
        default: 'block',
      },
    },
  };
}

function enabledConfig(): AuditConfig {
  return { ...DEFAULT_AUDIT_CONFIG };
}

function disabledConfig(): AuditConfig {
  return { enabled: false, include_rule_trace: false, redact_content: true };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('evaluateAudited', () => {
  it('returns correct decision matching evaluate()', () => {
    const spec = specWithToolAccess();
    const action: EvaluationAction = { type: 'tool_call', target: 'read_file' };
    const receipt = evaluateAudited(spec, action, enabledConfig());
    const result = evaluate(spec, action);

    expect(receipt.decision).toBe(result.decision);
    expect(receipt.decision).toBe('allow');
  });

  it('returns deny for blocked tool matching evaluate()', () => {
    const spec = specWithToolAccess();
    const action: EvaluationAction = { type: 'tool_call', target: 'dangerous_tool' };
    const receipt = evaluateAudited(spec, action, enabledConfig());
    const result = evaluate(spec, action);

    expect(receipt.decision).toBe(result.decision);
    expect(receipt.decision).toBe('deny');
    expect(receipt.matched_rule).toBe(result.matched_rule);
  });

  it('has valid UUID receipt_id', () => {
    const spec = minimalSpec();
    const action: EvaluationAction = { type: 'tool_call', target: 'test' };
    const receipt = evaluateAudited(spec, action, enabledConfig());

    expect(receipt.receipt_id).toMatch(UUID_RE);
  });

  it('has valid ISO timestamp', () => {
    const spec = minimalSpec();
    const action: EvaluationAction = { type: 'tool_call', target: 'test' };
    const receipt = evaluateAudited(spec, action, enabledConfig());

    expect(receipt.timestamp).toMatch(ISO_RE);
  });

  it('sets hushspec_version to current version', () => {
    const spec = minimalSpec();
    const action: EvaluationAction = { type: 'tool_call', target: 'test' };
    const receipt = evaluateAudited(spec, action, enabledConfig());

    expect(receipt.hushspec_version).toBe(HUSHSPEC_VERSION);
  });

  it('populates rule trace when enabled', () => {
    const spec = specWithToolAccess();
    const action: EvaluationAction = { type: 'tool_call', target: 'read_file' };
    const receipt = evaluateAudited(spec, action, enabledConfig());

    expect(receipt.rule_trace.length).toBeGreaterThan(0);
    expect(receipt.rule_trace[0].rule_block).toBe('tool_access');
    expect(receipt.rule_trace[0].evaluated).toBe(true);
  });

  it('returns empty trace when config disabled', () => {
    const spec = specWithToolAccess();
    const action: EvaluationAction = { type: 'tool_call', target: 'read_file' };
    const receipt = evaluateAudited(spec, action, disabledConfig());

    expect(receipt.rule_trace).toEqual([]);
    expect(receipt.evaluation_duration_us).toBe(0);
  });

  it('omits policy content_hash when config disabled', () => {
    const spec = specWithToolAccess();
    const action: EvaluationAction = { type: 'tool_call', target: 'read_file' };
    const receipt = evaluateAudited(spec, action, disabledConfig());

    // Absent, not an empty string -- an empty string would violate the
    // receipt schema's `^[0-9a-f]{64}$` pattern on content_hash.
    expect(receipt.policy.content_hash).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(receipt.policy, 'content_hash')).toBe(false);
    expect(JSON.stringify(receipt.policy)).not.toContain('content_hash');
  });

  it('sets content_redacted when content present and redact enabled', () => {
    const spec: HushSpec = {
      hushspec: '0.1.0',
      rules: {
        shell_commands: {
          enabled: true,
          forbidden_patterns: [],
        },
      },
    };
    const action: EvaluationAction = {
      type: 'shell_command',
      target: 'echo hello',
      content: 'some content here',
    };
    const receipt = evaluateAudited(spec, action, enabledConfig());

    expect(receipt.action.content_redacted).toBe(true);
  });

  it('does not set content_redacted when no content', () => {
    const spec = minimalSpec();
    const action: EvaluationAction = { type: 'tool_call', target: 'test' };
    const receipt = evaluateAudited(spec, action, enabledConfig());

    // Omitted, not `false` -- matches Rust/Go, which skip-serialize false.
    expect(receipt.action.content_redacted).toBeUndefined();
    expect(JSON.stringify(receipt.action)).not.toContain('content_redacted');
  });

  it('has non-negative evaluation_duration_us when enabled', () => {
    const spec = specWithToolAccess();
    const action: EvaluationAction = { type: 'tool_call', target: 'read_file' };
    const receipt = evaluateAudited(spec, action, enabledConfig());

    expect(receipt.evaluation_duration_us).toBeGreaterThanOrEqual(0);
  });

  it('generates unique receipt IDs', () => {
    const spec = minimalSpec();
    const action: EvaluationAction = { type: 'tool_call', target: 'test' };

    const receipt1 = evaluateAudited(spec, action, enabledConfig());
    const receipt2 = evaluateAudited(spec, action, enabledConfig());

    expect(receipt1.receipt_id).not.toBe(receipt2.receipt_id);
  });

  it('includes action type and target in summary', () => {
    const spec = minimalSpec();
    const action: EvaluationAction = { type: 'egress', target: 'api.example.com' };
    const receipt = evaluateAudited(spec, action, enabledConfig());

    expect(receipt.action.type).toBe('egress');
    expect(receipt.action.target).toBe('api.example.com');
  });

  it('populates policy name from spec', () => {
    const spec = minimalSpec();
    const action: EvaluationAction = { type: 'tool_call', target: 'test' };
    const receipt = evaluateAudited(spec, action, enabledConfig());

    expect(receipt.policy.name).toBe('test-policy');
    expect(receipt.policy.version).toBe('0.1.0');
  });
});

describe('computePolicyHash', () => {
  it('produces a valid SHA-256 hex string', () => {
    const spec = minimalSpec();
    const hash = computePolicyHash(spec);

    expect(hash).toMatch(SHA256_RE);
  });

  it('is deterministic', () => {
    const spec = minimalSpec();
    const hash1 = computePolicyHash(spec);
    const hash2 = computePolicyHash(spec);

    expect(hash1).toBe(hash2);
  });

  it('differs for different specs', () => {
    const spec1 = minimalSpec();
    const spec2: HushSpec = {
      hushspec: '0.1.0',
      name: 'different-policy',
    };

    expect(computePolicyHash(spec1)).not.toBe(computePolicyHash(spec2));
  });
});

describe('rule trace for different action types', () => {
  it('traces egress rule', () => {
    const spec: HushSpec = {
      hushspec: '0.1.0',
      rules: {
        egress: {
          allow: ['api.example.com'],
          default: 'block',
        },
      },
    };
    const action: EvaluationAction = { type: 'egress', target: 'api.example.com' };
    const receipt = evaluateAudited(spec, action, enabledConfig());

    expect(receipt.decision).toBe('allow');
    const egressTrace = receipt.rule_trace.find(t => t.rule_block === 'egress');
    expect(egressTrace).toBeDefined();
    expect(egressTrace!.evaluated).toBe(true);
    expect(egressTrace!.outcome).toBe('allow');
  });

  it('traces shell_commands rule', () => {
    const spec: HushSpec = {
      hushspec: '0.1.0',
      rules: {
        shell_commands: {
          enabled: true,
          forbidden_patterns: ['rm\\s+-rf'],
        },
      },
    };
    const action: EvaluationAction = { type: 'shell_command', target: 'ls -la' };
    const receipt = evaluateAudited(spec, action, enabledConfig());

    expect(receipt.decision).toBe('allow');
    const shellTrace = receipt.rule_trace.find(t => t.rule_block === 'shell_commands');
    expect(shellTrace).toBeDefined();
    expect(shellTrace!.evaluated).toBe(true);
    expect(shellTrace!.outcome).toBe('allow');
  });

  it('traces skip for unconfigured tool_access', () => {
    const spec: HushSpec = { hushspec: '0.1.0' };
    const action: EvaluationAction = { type: 'tool_call', target: 'test' };
    const receipt = evaluateAudited(spec, action, enabledConfig());

    const toolTrace = receipt.rule_trace.find(t => t.rule_block === 'tool_access');
    expect(toolTrace).toBeDefined();
    expect(toolTrace!.evaluated).toBe(false);
    expect(toolTrace!.outcome).toBe('skip');
  });

  it('handles unknown action type with default trace', () => {
    const spec: HushSpec = { hushspec: '0.1.0' };
    const action: EvaluationAction = { type: 'unknown_action', target: 'test' };
    const receipt = evaluateAudited(spec, action, enabledConfig());

    expect(receipt.decision).toBe('allow');
    const defaultTrace = receipt.rule_trace.find(t => t.rule_block === 'default');
    expect(defaultTrace).toBeDefined();
    expect(defaultTrace!.evaluated).toBe(true);
  });
});
