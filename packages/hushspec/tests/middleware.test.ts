import { describe, it, expect } from 'vitest';
import { HushGuard, HushSpecDenied } from '../src/middleware.js';
import { parseOrThrow } from '../src/parse.js';
import { mapClaudeToolToAction, createSecureToolHandler } from '../src/adapters/anthropic.js';
import type { PolicyProvider } from '../src/policy-provider.js';


// ---------------------------------------------------------------------------
// Shared policies
// ---------------------------------------------------------------------------

const ALLOW_ALL_POLICY = `
hushspec: "0.1.0"
name: allow-all
rules:
  tool_access:
    allow: ["*"]
    default: allow
  egress:
    allow: ["*"]
    default: allow
`;

const DENY_SHELL_POLICY = `
hushspec: "0.1.0"
name: deny-shell
rules:
  shell_commands:
    forbidden_patterns:
      - "rm -rf"
  tool_access:
    block: ["dangerous_tool"]
    require_confirmation: ["risky_tool"]
    allow: ["safe_tool"]
    default: block
  egress:
    allow: ["api.example.com"]
    default: block
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
`;

// ---------------------------------------------------------------------------
// HushGuard core
// ---------------------------------------------------------------------------

describe('HushGuard', () => {
  describe('fromYaml', () => {
    it('creates guard from valid YAML', () => {
      const guard = HushGuard.fromYaml(ALLOW_ALL_POLICY);
      expect(guard).toBeInstanceOf(HushGuard);
    });

    it('throws on invalid YAML', () => {
      expect(() => HushGuard.fromYaml('not: valid: yaml: {')).toThrow('Failed to parse policy');
    });
  });

  describe('check', () => {
    it('returns true for allowed actions', () => {
      const guard = HushGuard.fromYaml(ALLOW_ALL_POLICY);
      expect(guard.check({ type: 'tool_call', target: 'any_tool' })).toBe(true);
    });

    it('returns false for denied actions', () => {
      const guard = HushGuard.fromYaml(DENY_SHELL_POLICY);
      expect(guard.check({ type: 'tool_call', target: 'dangerous_tool' })).toBe(false);
    });

    it('returns false for denied file reads', () => {
      const guard = HushGuard.fromYaml(DENY_SHELL_POLICY);
      expect(guard.check({ type: 'file_read', target: '/home/user/.ssh/id_rsa' })).toBe(false);
    });

    it('returns false for denied egress', () => {
      const guard = HushGuard.fromYaml(DENY_SHELL_POLICY);
      expect(guard.check({ type: 'egress', target: 'evil.com' })).toBe(false);
    });

    it('returns true for allowed egress', () => {
      const guard = HushGuard.fromYaml(DENY_SHELL_POLICY);
      expect(guard.check({ type: 'egress', target: 'api.example.com' })).toBe(true);
    });
  });

  describe('enforce', () => {
    it('does not throw for allowed actions', () => {
      const guard = HushGuard.fromYaml(ALLOW_ALL_POLICY);
      expect(() => guard.enforce({ type: 'tool_call', target: 'any_tool' })).not.toThrow();
    });

    it('throws HushSpecDenied for denied actions', () => {
      const guard = HushGuard.fromYaml(DENY_SHELL_POLICY);
      try {
        guard.enforce({ type: 'tool_call', target: 'dangerous_tool' });
        expect.unreachable('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(HushSpecDenied);
        const denied = error as HushSpecDenied;
        expect(denied.result.decision).toBe('deny');
        expect(denied.name).toBe('HushSpecDenied');
      }
    });

    it('throws HushSpecDenied for denied shell commands', () => {
      const guard = HushGuard.fromYaml(DENY_SHELL_POLICY);
      expect(() =>
        guard.enforce({ type: 'shell_command', target: 'rm -rf /' }),
      ).toThrow(HushSpecDenied);
    });
  });

  describe('warn handler', () => {
    it('calls onWarn for warn decisions and allows when handler returns true', () => {
      let warnCalled = false;
      const guard = HushGuard.fromYaml(DENY_SHELL_POLICY, {
        onWarn: () => {
          warnCalled = true;
          return true;
        },
      });
      const result = guard.check({ type: 'tool_call', target: 'risky_tool' });
      expect(warnCalled).toBe(true);
      expect(result).toBe(true);
    });

    it('calls onWarn for warn decisions and denies when handler returns false', () => {
      const guard = HushGuard.fromYaml(DENY_SHELL_POLICY, {
        onWarn: () => false,
      });
      expect(guard.check({ type: 'tool_call', target: 'risky_tool' })).toBe(false);
    });

    it('default onWarn denies (fail-closed)', () => {
      const guard = HushGuard.fromYaml(DENY_SHELL_POLICY);
      expect(guard.check({ type: 'tool_call', target: 'risky_tool' })).toBe(false);
    });

    it('enforce throws when onWarn returns false', () => {
      const guard = HushGuard.fromYaml(DENY_SHELL_POLICY, {
        onWarn: () => false,
      });
      expect(() =>
        guard.enforce({ type: 'tool_call', target: 'risky_tool' }),
      ).toThrow(HushSpecDenied);
    });

    it('enforce passes when onWarn returns true', () => {
      const guard = HushGuard.fromYaml(DENY_SHELL_POLICY, {
        onWarn: () => true,
      });
      expect(() =>
        guard.enforce({ type: 'tool_call', target: 'risky_tool' }),
      ).not.toThrow();
    });
  });

  describe('swapPolicy', () => {
    it('changes active policy', () => {
      const guard = HushGuard.fromYaml(DENY_SHELL_POLICY);
      expect(guard.check({ type: 'tool_call', target: 'dangerous_tool' })).toBe(false);

      const newPolicy = parseOrThrow(ALLOW_ALL_POLICY);
      guard.swapPolicy(newPolicy);
      expect(guard.check({ type: 'tool_call', target: 'dangerous_tool' })).toBe(true);
    });
  });

  describe('fromProvider', () => {
    it('fails closed when the provider reports the policy as unavailable', async () => {
      const provider: PolicyProvider = {
        async load() {
          return parseOrThrow(ALLOW_ALL_POLICY);
        },
        watch() {},
        stop() {},
        current() {
          throw new Error('Policy is stale: last successful load exceeded maxStaleMs');
        },
      };

      const guard = await HushGuard.fromProvider(provider);
      const result = guard.evaluate({ type: 'tool_call', target: 'any_tool' });

      expect(result.decision).toBe('deny');
      expect(result.matched_rule).toBe('__hushspec_policy_provider__');
      expect(result.reason).toContain('Policy is stale');
    });
  });

  describe('static action mappers', () => {
    it('mapToolCall creates correct action', () => {
      const action = HushGuard.mapToolCall('my_tool', { key: 'value' });
      expect(action.type).toBe('tool_call');
      expect(action.target).toBe('my_tool');
      expect(action.args_size).toBeGreaterThan(0);
    });

    it('mapToolCall without args has undefined args_size', () => {
      const action = HushGuard.mapToolCall('my_tool');
      expect(action.args_size).toBeUndefined();
    });

    it('mapFileRead creates correct action', () => {
      const action = HushGuard.mapFileRead('/etc/passwd');
      expect(action.type).toBe('file_read');
      expect(action.target).toBe('/etc/passwd');
    });

    it('mapFileWrite creates correct action', () => {
      const action = HushGuard.mapFileWrite('/tmp/test.txt', 'content');
      expect(action.type).toBe('file_write');
      expect(action.target).toBe('/tmp/test.txt');
      expect(action.content).toBe('content');
    });

    it('mapEgress creates correct action', () => {
      const action = HushGuard.mapEgress('api.example.com');
      expect(action.type).toBe('egress');
      expect(action.target).toBe('api.example.com');
    });

    it('mapShellCommand creates correct action', () => {
      const action = HushGuard.mapShellCommand('ls -la');
      expect(action.type).toBe('shell_command');
      expect(action.target).toBe('ls -la');
    });
  });
});

// ---------------------------------------------------------------------------
// Anthropic adapter
// ---------------------------------------------------------------------------

describe('mapClaudeToolToAction', () => {
  it('maps bash tool to shell_command', () => {
    const action = mapClaudeToolToAction('bash', { command: 'echo hello' });
    expect(action.type).toBe('shell_command');
    expect(action.target).toBe('echo hello');
  });

  it('maps terminal tool to shell_command', () => {
    const action = mapClaudeToolToAction('terminal', { command: 'ls' });
    expect(action.type).toBe('shell_command');
    expect(action.target).toBe('ls');
  });

  it('maps str_replace_editor view to file_read', () => {
    const action = mapClaudeToolToAction('str_replace_editor', {
      command: 'view',
      path: '/src/main.ts',
    });
    expect(action.type).toBe('file_read');
    expect(action.target).toBe('/src/main.ts');
  });

  it('maps str_replace_editor write to file_write', () => {
    const action = mapClaudeToolToAction('str_replace_editor', {
      command: 'str_replace',
      path: '/src/main.ts',
      new_str: 'new content',
    });
    expect(action.type).toBe('file_write');
    expect(action.target).toBe('/src/main.ts');
    expect(action.content).toBe('new content');
  });

  it('maps text_editor_20250124 to file operations', () => {
    const action = mapClaudeToolToAction('text_editor_20250124', {
      command: 'view',
      path: '/tmp/file.txt',
    });
    expect(action.type).toBe('file_read');
  });

  it('maps text_editor_20250429 to file operations', () => {
    const action = mapClaudeToolToAction('text_editor_20250429', {
      command: 'create',
      path: '/tmp/file.txt',
      new_str: 'data',
    });
    expect(action.type).toBe('file_write');
  });

  it('maps computer tool to computer_use', () => {
    const action = mapClaudeToolToAction('computer', { action: 'screenshot' });
    expect(action.type).toBe('computer_use');
    expect(action.target).toBe('screenshot');
  });

  it('maps MCP-proxied tools (mcp__server__tool)', () => {
    const action = mapClaudeToolToAction('mcp__github__create_issue', { repo: 'test' });
    expect(action.type).toBe('tool_call');
    expect(action.target).toBe('create_issue');
    expect(action.args_size).toBeGreaterThan(0);
  });

  it('maps MCP-proxied tools with nested underscores', () => {
    const action = mapClaudeToolToAction('mcp__server__nested__tool', {});
    expect(action.type).toBe('tool_call');
    expect(action.target).toBe('nested__tool');
  });

  it('maps unknown tools to tool_call', () => {
    const action = mapClaudeToolToAction('custom_tool', { data: 123 });
    expect(action.type).toBe('tool_call');
    expect(action.target).toBe('custom_tool');
    expect(action.args_size).toBeGreaterThan(0);
  });
});

describe('createSecureToolHandler', () => {
  it('returns evaluation result for tool calls', () => {
    const guard = HushGuard.fromYaml(DENY_SHELL_POLICY);
    const handler = createSecureToolHandler(guard);

    const result = handler('bash', { command: 'rm -rf /' });
    expect(result.decision).toBe('deny');
  });

  it('allows permitted tools', () => {
    const guard = HushGuard.fromYaml(DENY_SHELL_POLICY);
    const handler = createSecureToolHandler(guard);

    const result = handler('safe_tool', {});
    expect(result.decision).toBe('allow');
  });
});
