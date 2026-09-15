import { describe, it, expect } from 'vitest';
import { HushGuard } from '../src/middleware.js';
import { mapOpenAIToolCall, createOpenAIGuard } from '../src/adapters/openai.js';
import { mapMCPToolCall, extractDomain, createMCPGuard } from '../src/adapters/mcp.js';

// ---------------------------------------------------------------------------
// Shared policies
// ---------------------------------------------------------------------------

const DENY_POLICY = `
hushspec: "0.1.0"
name: deny-policy
rules:
  tool_access:
    block: ["dangerous_tool"]
    allow: ["safe_tool"]
    default: block
  shell_commands:
    forbidden_patterns:
      - "rm -rf"
  egress:
    allow: ["api.example.com"]
    default: block
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
`;

const ALLOW_ALL_POLICY = `
hushspec: "0.1.0"
name: allow-all
rules:
  tool_access:
    default: allow
  egress:
    allow: ["**"]
    default: allow
`;

// ---------------------------------------------------------------------------
// OpenAI adapter
// ---------------------------------------------------------------------------

describe('mapOpenAIToolCall', () => {
  it('maps function name and string args correctly', () => {
    const action = mapOpenAIToolCall('get_weather', '{"location":"NYC"}');
    expect(action.type).toBe('tool_call');
    expect(action.target).toBe('get_weather');
    expect(action.args_size).toBe('{"location":"NYC"}'.length);
  });

  it('maps function name and object args correctly', () => {
    const args = { location: 'NYC', units: 'celsius' };
    const action = mapOpenAIToolCall('get_weather', args);
    expect(action.type).toBe('tool_call');
    expect(action.target).toBe('get_weather');
    expect(action.args_size).toBe(JSON.stringify(args).length);
  });

  it('preserves exact string length for string args', () => {
    const rawArgs = '{"key":   "value"}'; // note extra spaces
    const action = mapOpenAIToolCall('fn', rawArgs);
    expect(action.args_size).toBe(rawArgs.length);
  });

  it('handles empty object args', () => {
    const action = mapOpenAIToolCall('noop', {});
    expect(action.type).toBe('tool_call');
    expect(action.target).toBe('noop');
    expect(action.args_size).toBe(2); // '{}'
  });

  it('handles empty string args', () => {
    const action = mapOpenAIToolCall('noop', '{}');
    expect(action.type).toBe('tool_call');
    expect(action.args_size).toBe(2);
  });

  // A model can emit truncated or malformed JSON arguments. Throwing here
  // would gate the call on whatever the caller does with the exception rather
  // than on the policy, so the mapping never parses the arguments.
  it('maps malformed JSON arguments without throwing', () => {
    const truncated = '{"location":"NY';
    const action = mapOpenAIToolCall('get_weather', truncated);
    expect(action.type).toBe('tool_call');
    expect(action.target).toBe('get_weather');
    expect(action.args_size).toBe(truncated.length);
  });

  it('still evaluates a call whose arguments are not JSON', () => {
    const guard = HushGuard.fromYaml(DENY_POLICY);
    expect(createOpenAIGuard(guard)('dangerous_tool', 'not json').decision).toBe('deny');
  });
});

describe('createOpenAIGuard', () => {
  it('evaluates allowed tool calls', () => {
    const guard = HushGuard.fromYaml(DENY_POLICY);
    const handler = createOpenAIGuard(guard);
    const result = handler('safe_tool', '{}');
    expect(result.decision).toBe('allow');
  });

  it('evaluates denied tool calls', () => {
    const guard = HushGuard.fromYaml(DENY_POLICY);
    const handler = createOpenAIGuard(guard);
    const result = handler('dangerous_tool', '{}');
    expect(result.decision).toBe('deny');
  });
});

// ---------------------------------------------------------------------------
// MCP adapter
// ---------------------------------------------------------------------------

describe('mapMCPToolCall', () => {
  it('maps read_file to file_read', () => {
    const action = mapMCPToolCall('read_file', { path: '/etc/hosts' });
    expect(action.type).toBe('file_read');
    expect(action.target).toBe('/etc/hosts');
  });

  it('maps write_file to file_write', () => {
    const action = mapMCPToolCall('write_file', {
      path: '/tmp/out.txt',
      content: 'hello',
    });
    expect(action.type).toBe('file_write');
    expect(action.target).toBe('/tmp/out.txt');
    expect(action.content).toBe('hello');
  });

  it('maps list_directory to file_read', () => {
    const action = mapMCPToolCall('list_directory', { path: '/src' });
    expect(action.type).toBe('file_read');
    expect(action.target).toBe('/src');
  });

  it('maps run_command to shell_command', () => {
    const action = mapMCPToolCall('run_command', { command: 'ls -la' });
    expect(action.type).toBe('shell_command');
    expect(action.target).toBe('ls -la');
  });

  it('maps execute to shell_command', () => {
    const action = mapMCPToolCall('execute', { command: 'echo hi' });
    expect(action.type).toBe('shell_command');
    expect(action.target).toBe('echo hi');
  });

  it('maps fetch to egress with extracted domain', () => {
    const action = mapMCPToolCall('fetch', {
      url: 'https://api.example.com/data',
    });
    expect(action.type).toBe('egress');
    expect(action.target).toBe('api.example.com');
  });

  it('maps http_request to egress with extracted domain', () => {
    const action = mapMCPToolCall('http_request', {
      url: 'https://evil.com/steal',
    });
    expect(action.type).toBe('egress');
    expect(action.target).toBe('evil.com');
  });

  it('maps unknown tools to tool_call', () => {
    const action = mapMCPToolCall('custom_search', { query: 'test' });
    expect(action.type).toBe('tool_call');
    expect(action.target).toBe('custom_search');
    expect(action.args_size).toBeGreaterThan(0);
  });

  it('maps unknown tools without args to tool_call with undefined args_size', () => {
    const action = mapMCPToolCall('ping');
    expect(action.type).toBe('tool_call');
    expect(action.target).toBe('ping');
    expect(action.args_size).toBeUndefined();
  });

  it('handles missing path in read_file gracefully', () => {
    const action = mapMCPToolCall('read_file', {});
    expect(action.type).toBe('file_read');
    expect(action.target).toBe('');
  });

  it('handles missing command in run_command gracefully', () => {
    const action = mapMCPToolCall('run_command', {});
    expect(action.type).toBe('shell_command');
    expect(action.target).toBe('');
  });
});

describe('extractDomain', () => {
  it('extracts hostname from valid URLs', () => {
    expect(extractDomain('https://api.example.com/path')).toBe(
      'api.example.com',
    );
    expect(extractDomain('http://localhost:3000')).toBe('localhost');
    expect(extractDomain('https://sub.domain.org:8443/api')).toBe(
      'sub.domain.org',
    );
  });

  it('returns bare string for invalid URLs', () => {
    expect(extractDomain('not-a-url')).toBe('not-a-url');
    expect(extractDomain('')).toBe('');
  });
});

describe('createMCPGuard', () => {
  it('evaluates file_read through guard', () => {
    const guard = HushGuard.fromYaml(DENY_POLICY);
    const mcpGuard = createMCPGuard(guard);

    const result = mcpGuard('read_file', { path: '/home/user/.ssh/id_rsa' });
    expect(result.decision).toBe('deny');
  });

  it('allows permitted egress', () => {
    const guard = HushGuard.fromYaml(DENY_POLICY);
    const mcpGuard = createMCPGuard(guard);

    const result = mcpGuard('fetch', { url: 'https://api.example.com/data' });
    expect(result.decision).toBe('allow');
  });

  it('denies forbidden egress', () => {
    const guard = HushGuard.fromYaml(DENY_POLICY);
    const mcpGuard = createMCPGuard(guard);

    const result = mcpGuard('http_request', { url: 'https://evil.com/steal' });
    expect(result.decision).toBe('deny');
  });

  it('denies forbidden shell commands', () => {
    const guard = HushGuard.fromYaml(DENY_POLICY);
    const mcpGuard = createMCPGuard(guard);

    const result = mcpGuard('run_command', { command: 'rm -rf /' });
    expect(result.decision).toBe('deny');
  });

  it('evaluates unknown tools against tool_access rules', () => {
    const guard = HushGuard.fromYaml(DENY_POLICY);
    const mcpGuard = createMCPGuard(guard);

    const result = mcpGuard('safe_tool', { data: 'test' });
    expect(result.decision).toBe('allow');
  });

  it('allows all actions with permissive policy', () => {
    const guard = HushGuard.fromYaml(ALLOW_ALL_POLICY);
    const mcpGuard = createMCPGuard(guard);

    expect(mcpGuard('read_file', { path: '/any/path' }).decision).toBe(
      'allow',
    );
    expect(
      mcpGuard('fetch', { url: 'https://any.domain.com' }).decision,
    ).toBe('allow');
    expect(mcpGuard('run_command', { command: 'anything' }).decision).toBe(
      'allow',
    );
  });
});
