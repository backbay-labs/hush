import { describe, it, expect, afterEach } from 'vitest';
import { HushGuard, HushSpecDenied, matchesRulePathPrefix } from '../src/middleware.js';
import { parseOrThrow } from '../src/parse.js';
import { mapClaudeToolToAction, createSecureToolHandler } from '../src/adapters/anthropic.js';
import type { PolicyProvider } from '../src/policy-provider.js';
import type { EnforcementMode } from '../src/receipt.js';
import { activatePanic, deactivatePanic } from '../src/evaluate.js';
import type { DecisionReceipt } from '../src/receipt.js';
import type { ObserverEvent, EvaluationCompletedEvent } from '../src/observer.js';
import type { EvaluationResult } from '../src/evaluate.js';


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

const SECRET_POLICY = `
hushspec: "0.1.0"
name: secrets
rules:
  secret_patterns:
    patterns:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: github_token
        pattern: "gh[ps]_[A-Za-z0-9]{36}"
        severity: critical
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

// ---------------------------------------------------------------------------
// Enforcement mode: config validation and prefix matching
// ---------------------------------------------------------------------------

describe('matchesRulePathPrefix', () => {
  it('matches exact keys and segment boundaries only', () => {
    expect(matchesRulePathPrefix('rules.tool_access', 'rules.tool_access')).toBe(true);
    expect(matchesRulePathPrefix('rules.tool_access.block', 'rules.tool_access')).toBe(true);
    expect(
      matchesRulePathPrefix(
        'rules.shell_commands.forbidden_patterns[0]',
        'rules.shell_commands.forbidden_patterns',
      ),
    ).toBe(true);
    expect(matchesRulePathPrefix('rules.tool_access_x', 'rules.tool_access')).toBe(false);
    expect(matchesRulePathPrefix('rules.egress.block', 'rules.egres')).toBe(false);
  });
});

describe('enforcement config validation', () => {
  const noopObserver = { onEvent: () => {} };

  it('rejects monitor mode without an observer or sink', () => {
    expect(() =>
      HushGuard.fromYaml(ALLOW_ALL_POLICY, { enforcement: { mode: 'monitor' } }),
    ).toThrow('monitor mode requires an observer or a receipt sink');
  });

  it('rejects unknown rule names in override keys', () => {
    expect(() =>
      HushGuard.fromYaml(ALLOW_ALL_POLICY, {
        observer: noopObserver,
        enforcement: { mode: 'monitor', overrides: { 'rules.egres': 'enforce' } },
      }),
    ).toThrow("unknown rule in enforcement override 'rules.egres'");
  });

  it('rejects override keys outside rules. and extensions.', () => {
    expect(() =>
      HushGuard.fromYaml(ALLOW_ALL_POLICY, {
        observer: noopObserver,
        enforcement: { overrides: { tool_access: 'monitor' } },
      }),
    ).toThrow("enforcement override keys must start with 'rules.' or 'extensions.'");
  });

  it('rejects invalid mode values', () => {
    expect(() =>
      HushGuard.fromYaml(ALLOW_ALL_POLICY, {
        enforcement: { mode: 'audit' as EnforcementMode },
      }),
    ).toThrow('invalid enforcement mode: audit');
  });

  it('accepts a valid monitor config with an observer', () => {
    const guard = HushGuard.fromYaml(ALLOW_ALL_POLICY, {
      observer: noopObserver,
      enforcement: {
        mode: 'monitor',
        overrides: { 'rules.egress': 'enforce', 'extensions.posture': 'monitor' },
      },
    });
    expect(guard).toBeInstanceOf(HushGuard);
  });

  it('rejects a typo in the extension segment of an override key', () => {
    expect(() =>
      HushGuard.fromYaml(ALLOW_ALL_POLICY, {
        observer: noopObserver,
        enforcement: { mode: 'monitor', overrides: { 'extensions.postur': 'enforce' } },
      }),
    ).toThrow("unknown extension in enforcement override 'extensions.postur'");
  });

  it('accepts a deep extension override segment', () => {
    const guard = HushGuard.fromYaml(ALLOW_ALL_POLICY, {
      observer: noopObserver,
      enforcement: { overrides: { 'extensions.posture.states': 'monitor' } },
    });
    expect(guard).toBeInstanceOf(HushGuard);
  });

  it('accepts extensions.detection as an override key', () => {
    const guard = HushGuard.fromYaml(ALLOW_ALL_POLICY, {
      observer: noopObserver,
      enforcement: { overrides: { 'extensions.detection': 'monitor' } },
    });
    expect(guard).toBeInstanceOf(HushGuard);
  });
});

// ---------------------------------------------------------------------------
// Monitor mode gate
// ---------------------------------------------------------------------------

describe('monitor mode gate', () => {
  const noopObserver = { onEvent: () => {} };

  it('deny proceeds under monitor with would_block outcome', () => {
    const guard = HushGuard.fromYaml(DENY_SHELL_POLICY, {
      observer: noopObserver,
      enforcement: { mode: 'monitor' },
    });
    const action = { type: 'tool_call', target: 'dangerous_tool' };
    const outcome = guard.gate(action);
    expect(outcome.proceed).toBe(true);
    expect(outcome.result.decision).toBe('deny');
    expect(outcome.enforcement).toEqual({ mode: 'monitor', outcome: 'would_block' });
    expect(guard.check(action)).toBe(true);
    expect(() => guard.enforce(action)).not.toThrow();
  });

  it('warn proceeds under monitor without invoking onWarn', () => {
    let warnCalled = false;
    const guard = HushGuard.fromYaml(DENY_SHELL_POLICY, {
      observer: noopObserver,
      onWarn: () => {
        warnCalled = true;
        return false;
      },
      enforcement: { mode: 'monitor' },
    });
    const outcome = guard.gate({ type: 'tool_call', target: 'risky_tool' });
    expect(outcome.proceed).toBe(true);
    expect(outcome.result.decision).toBe('warn');
    expect(outcome.enforcement.outcome).toBe('would_block');
    expect(warnCalled).toBe(false);
  });

  it('allow is allowed under monitor', () => {
    const guard = HushGuard.fromYaml(DENY_SHELL_POLICY, {
      observer: noopObserver,
      enforcement: { mode: 'monitor' },
    });
    const outcome = guard.gate({ type: 'tool_call', target: 'safe_tool' });
    expect(outcome.proceed).toBe(true);
    expect(outcome.enforcement).toEqual({ mode: 'monitor', outcome: 'allowed' });
  });

  it('gate under enforce blocks deny and confirms warn', () => {
    const guard = HushGuard.fromYaml(DENY_SHELL_POLICY, { onWarn: () => true });
    expect(guard.gate({ type: 'tool_call', target: 'dangerous_tool' })).toMatchObject({
      proceed: false,
      enforcement: { mode: 'enforce', outcome: 'blocked' },
    });
    expect(guard.gate({ type: 'tool_call', target: 'risky_tool' })).toMatchObject({
      proceed: true,
      enforcement: { mode: 'enforce', outcome: 'confirmed' },
    });
  });

  it('escalates specific rules to enforce while the guard monitors', () => {
    const guard = HushGuard.fromYaml(DENY_SHELL_POLICY, {
      observer: noopObserver,
      enforcement: { mode: 'monitor', overrides: { 'rules.tool_access': 'enforce' } },
    });
    expect(() => guard.enforce({ type: 'tool_call', target: 'dangerous_tool' })).toThrow(
      HushSpecDenied,
    );
    expect(guard.check({ type: 'egress', target: 'evil.com' })).toBe(true);
  });

  it('de-escalates specific rules to monitor while the guard enforces', () => {
    const guard = HushGuard.fromYaml(DENY_SHELL_POLICY, {
      observer: noopObserver,
      enforcement: { overrides: { 'rules.shell_commands': 'monitor' } },
    });
    expect(guard.check({ type: 'shell_command', target: 'rm -rf /' })).toBe(true);
    expect(() => guard.enforce({ type: 'tool_call', target: 'dangerous_tool' })).toThrow(
      HushSpecDenied,
    );
  });

  it('longest override prefix wins', () => {
    const guard = HushGuard.fromYaml(SECRET_POLICY, {
      observer: noopObserver,
      enforcement: {
        overrides: {
          'rules.secret_patterns': 'monitor',
          'rules.secret_patterns.patterns.aws_access_key': 'enforce',
        },
      },
    });
    expect(
      guard.check({
        type: 'file_write',
        target: '/tmp/app.txt',
        content: 'token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
      }),
    ).toBe(true);
    expect(() =>
      guard.enforce({
        type: 'file_write',
        target: '/tmp/app.txt',
        content: 'key=AKIAABCDEFGHIJKLMNOP',
      }),
    ).toThrow(HushSpecDenied);
  });
});

describe('panic supremacy over monitor', () => {
  afterEach(() => {
    deactivatePanic();
  });

  it('monitor guard blocks while panic is active', () => {
    const guard = HushGuard.fromYaml(ALLOW_ALL_POLICY, {
      observer: { onEvent: () => {} },
      enforcement: { mode: 'monitor' },
    });
    activatePanic();
    const outcome = guard.gate({ type: 'tool_call', target: 'any_tool' });
    expect(outcome.proceed).toBe(false);
    expect(outcome.enforcement).toEqual({ mode: 'enforce', outcome: 'blocked' });
    expect(() => guard.enforce({ type: 'tool_call', target: 'any_tool' })).toThrow(
      HushSpecDenied,
    );
  });

  it('stale provider under monitor proceeds, but blocks when panic is active', async () => {
    const provider: PolicyProvider = {
      async load() {
        return parseOrThrow(ALLOW_ALL_POLICY);
      },
      watch() {},
      stop() {},
      current() {
        throw new Error('Policy is stale');
      },
    };
    const guard = await HushGuard.fromProvider(provider, {
      observer: { onEvent: () => {} },
      enforcement: { mode: 'monitor' },
    });

    const outcome = guard.gate({ type: 'tool_call', target: 'any_tool' });
    expect(outcome.proceed).toBe(true);
    expect(outcome.enforcement).toEqual({ mode: 'monitor', outcome: 'would_block' });
    expect(outcome.result.matched_rule).toBe('__hushspec_policy_provider__');

    activatePanic();
    expect(guard.gate({ type: 'tool_call', target: 'any_tool' }).proceed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Controller directive: detection.ts matched_rule normalization
//
// packages/hushspec/src/detection.ts emits the bare literal matched_rule:
// 'detection' (not a hierarchical rule path). effectiveMode() must normalize
// it to 'extensions.detection' before prefix matching, or an override keyed
// 'extensions.detection' would silently never match. gate() only accepts an
// EvaluationAction (evaluateWithDetection() is not wired into the enforcement
// path in this task), so there is no organic way to produce a result with
// matched_rule 'detection' through the public API; this test reaches into
// the private effectiveMode() resolver directly to exercise the
// normalization in isolation, exactly as the brief specifies its signature:
// `private effectiveMode(result: EvaluationResult): EnforcementMode`.
// ---------------------------------------------------------------------------

describe('detection matched_rule normalization', () => {
  const noopObserver = { onEvent: () => {} };

  it('resolves a bare "detection" matched_rule against an extensions.detection override', () => {
    const guard = HushGuard.fromYaml(ALLOW_ALL_POLICY, {
      observer: noopObserver,
      enforcement: {
        overrides: { 'extensions.detection': 'monitor' },
      },
    });
    const detectionResult: EvaluationResult = {
      decision: 'deny',
      matched_rule: 'detection',
      reason: 'content exceeded detection threshold',
    };
    type GuardInternals = { effectiveMode(result: EvaluationResult): EnforcementMode };
    const mode = (guard as unknown as GuardInternals).effectiveMode(detectionResult);
    expect(mode).toBe('monitor');
  });
});

// ---------------------------------------------------------------------------
// Receipt sink integration
// ---------------------------------------------------------------------------

describe('receipt sink integration', () => {
  it('gate() sends a tagged receipt to the sink', () => {
    const receipts: DecisionReceipt[] = [];
    const guard = HushGuard.fromYaml(DENY_SHELL_POLICY, {
      enforcement: { mode: 'monitor' },
      sink: { send: (r) => receipts.push(r) },
    });
    const outcome = guard.gate({ type: 'tool_call', target: 'dangerous_tool' });
    expect(outcome.proceed).toBe(true);
    expect(receipts).toHaveLength(1);
    expect(receipts[0].decision).toBe('deny');
    expect(receipts[0].enforcement).toEqual({ mode: 'monitor', outcome: 'would_block' });
    expect(receipts[0].policy.content_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('evaluate() sends an untagged receipt', () => {
    const receipts: DecisionReceipt[] = [];
    const guard = HushGuard.fromYaml(DENY_SHELL_POLICY, {
      sink: { send: (r) => receipts.push(r) },
    });
    const result = guard.evaluate({ type: 'tool_call', target: 'dangerous_tool' });
    expect(result.decision).toBe('deny');
    expect(receipts).toHaveLength(1);
    expect(receipts[0].enforcement).toBeUndefined();
  });

  it('a throwing sink never breaks enforcement', () => {
    const guard = HushGuard.fromYaml(ALLOW_ALL_POLICY, {
      enforcement: { mode: 'monitor' },
      sink: {
        send: () => {
          throw new Error('sink down');
        },
      },
    });
    expect(guard.check({ type: 'tool_call', target: 'any_tool' })).toBe(true);
  });

  it('gated actions emit one tagged observer event', () => {
    const events: ObserverEvent[] = [];
    const guard = HushGuard.fromYaml(DENY_SHELL_POLICY, {
      enforcement: { mode: 'monitor' },
      observer: { onEvent: (e) => events.push(e) },
    });
    guard.check({ type: 'tool_call', target: 'dangerous_tool' });
    const completed = events.filter(
      (e) => e.type === 'evaluation.completed',
    ) as EvaluationCompletedEvent[];
    expect(completed).toHaveLength(1);
    expect(completed[0].enforcement).toEqual({ mode: 'monitor', outcome: 'would_block' });
  });

  it('exports the enforcement API from the package root', async () => {
    const pkg = await import('../src/index.js');
    expect(typeof pkg.matchesRulePathPrefix).toBe('function');
  });
});
