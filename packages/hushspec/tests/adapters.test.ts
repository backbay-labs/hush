import { describe, it, expect } from 'vitest';
import { canonicalizeValue } from '../src/canonical.js';
import { HushGuard } from '../src/middleware.js';
import { mapClaudeToolToAction } from '../src/adapters/anthropic.js';
import { mapOpenAIToolCall, createOpenAIGuard } from '../src/adapters/openai.js';
import { mapMCPToolCall, extractDomain, createMCPGuard } from '../src/adapters/mcp.js';
import { argsSize, mapWellKnownTool } from '../src/adapters/tool-mapping.js';
import { utf8ByteLength } from '../src/utf8.js';
import { readFileSync } from 'node:fs';

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
    expect(action.args_size).toBe(utf8ByteLength('{"location":"NYC"}'));
  });

  it('maps function name and object args correctly', () => {
    const args = { location: 'NYC', units: 'celsius' };
    const action = mapOpenAIToolCall('get_weather', args);
    expect(action.type).toBe('tool_call');
    expect(action.target).toBe('get_weather');
    expect(action.args_size).toBe(utf8ByteLength(canonicalizeValue(args)));
  });

  it('measures string args canonically, so padding does not change the count', () => {
    // Core spec 3.7 permits measuring the bytes received only when they are
    // compact JSON, and forbids measuring a pretty-printed form: the spaces
    // the model padded these arguments with are not part of the payload a
    // `max_args_size` limit bounds.
    const rawArgs = '{"key":   "value"}';
    const action = mapOpenAIToolCall('fn', rawArgs);
    expect(action.args_size).toBe(utf8ByteLength('{"key":"value"}'));
    expect(action.args_size).toBeLessThan(utf8ByteLength(rawArgs));
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
  // than on the policy, so a payload with no canonical form is measured as
  // received instead.
  it('maps malformed JSON arguments without throwing', () => {
    const truncated = '{"location":"NY';
    const action = mapOpenAIToolCall('get_weather', truncated);
    expect(action.type).toBe('tool_call');
    expect(action.target).toBe('get_weather');
    expect(action.args_size).toBe(utf8ByteLength(truncated));
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
  it('matches the shared MCP mapping contract', () => {
    const corpus = JSON.parse(
      readFileSync(new URL('../../../fixtures/adapters/mcp-contract.json', import.meta.url), 'utf8'),
    ) as Array<{
      name: string;
      tool: string;
      arguments: Record<string, unknown>;
      expect: { type: string; target: string; content?: string; args_size?: number };
    }>;
    for (const testCase of corpus) {
      const action = mapMCPToolCall(testCase.tool, testCase.arguments);
      expect(action, testCase.name).toMatchObject(testCase.expect);
      expect(action.args_size, testCase.name).toBe(testCase.expect.args_size);
    }
  });
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

  it('measures an empty arguments object as the two bytes it is', () => {
    // A call carrying `"arguments": {}` did carry arguments; only a call with
    // no `arguments` member goes unmeasured. The Python and Go adapters agree,
    // so one `max_args_size` bounds the same payload in all three.
    const action = mapMCPToolCall('custom_search', {});
    expect(action.type).toBe('tool_call');
    expect(action.args_size).toBe(2);
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

  it('recognizes the shared table\'s spellings, so readFile is a file read here too', () => {
    const action = mapMCPToolCall('readFile', { path: '/etc/hosts' });
    expect(action.type).toBe('file_read');
    expect(action.target).toBe('/etc/hosts');
  });

  it('measures the arguments of a recognized tool', () => {
    const args = { path: '/etc/hosts' };
    const action = mapMCPToolCall('read_file', args);
    expect(action.args_size).toBe(utf8ByteLength(canonicalizeValue(args)));
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

  it('reduces the authority as a browser would', () => {
    expect(extractDomain('http://blocked.example\\@allowed.example/x')).toBe('blocked.example');
    expect(extractDomain('https://user:pw@Host.Example:8443/')).toBe('host.example');
    expect(extractDomain('http://[::1]:8080/health')).toBe('[::1]');
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

// ---------------------------------------------------------------------------
// args_size (core spec 3.7)
// ---------------------------------------------------------------------------

/**
 * `args_size` is "the length in bytes of the UTF-8 encoding of the arguments
 * serialized as JSON in the canonical form" (core spec 3.7, canonical spec 4),
 * and the spec says in as many words that it must not be "a count of UTF-16
 * code units or of escaped characters".
 *
 * JavaScript makes that the easy mistake to make: `JSON.stringify(x).length`
 * counts UTF-16 code units, so it undercounts every argument outside ASCII --
 * a 12-byte payload of emoji measured as 10 slips under a `max_args_size` of
 * 11 that the enforcement point believes it is applying. Every mapper in this
 * package is checked against the same measurement so none of them can drift
 * back to the string length.
 */
describe('args_size (core spec 3.7)', () => {
  /** The measurement the spec defines, spelled out rather than reused. */
  function specSize(args: unknown): number {
    return Buffer.byteLength(canonicalizeValue(args as never), 'utf8');
  }

  const NON_ASCII = { q: 'h\u00e9llo' };
  const EMOJI = { q: '\u{1F642}' };
  const ESCAPED = { q: 'a\nb\t"c"\\d' };
  const CONTROL = { q: '\u0001\u001f' };

  it('counts UTF-8 bytes, not UTF-16 code units', () => {
    // 'é' is one code unit and two bytes; '🙂' is two code units and four.
    expect(specSize(NON_ASCII)).toBe(14);
    expect(JSON.stringify(NON_ASCII).length).toBe(13);
    expect(specSize(EMOJI)).toBe(12);
    expect(JSON.stringify(EMOJI).length).toBe(10);
  });

  it('counts the escape sequences the canonical form writes', () => {
    // RFC 8785 escapes `\n`, `\t`, `"` and `\` two characters at a time and
    // other control characters as `\u00xx`; the bytes on the wire are what
    // is counted, never the characters they stand for.
    expect(specSize(ESCAPED)).toBe(utf8ByteLength(canonicalizeValue(ESCAPED as never)));
    expect(specSize(ESCAPED)).toBeGreaterThan(utf8ByteLength(ESCAPED.q));
    // `{"q":"` + two six-character `\u00xx` escapes + `"}`.
    expect(specSize(CONTROL)).toBe(20);
  });

  it.each([
    ['non-ASCII', NON_ASCII],
    ['emoji', EMOJI],
    ['escapes', ESCAPED],
    ['control characters', CONTROL],
    ['empty', {}],
  ])('argsSize measures %s as the spec does', (_label, args) => {
    expect(argsSize(args)).toBe(specSize(args));
  });

  it('serializes canonically, so key order never changes the count', () => {
    expect(argsSize({ b: 1, a: 2 })).toBe(argsSize({ a: 2, b: 1 }));
    expect(argsSize({ b: 1, a: 2 })).toBe(specSize({ a: 2, b: 1 }));
  });

  it('measures arguments that arrive already serialized in the same canonical form', () => {
    // Compact JSON is already its own canonical form, so the received bytes
    // are the answer -- counted as bytes, never as code units.
    const raw = '{"q":"h\u00e9llo"}';
    expect(argsSize(raw)).toBe(utf8ByteLength(raw));
    expect(argsSize(raw)).toBe(raw.length + 1);
    // The same payload padded, escaped, or with its keys out of order is the
    // same payload: one `max_args_size` must bound all four.
    expect(argsSize('{ "q": "h\u00e9llo" }')).toBe(argsSize(raw));
    expect(argsSize('{"q":"h\\u00e9llo"}')).toBe(argsSize(raw));
    expect(argsSize('{"b":1,"a":2}')).toBe(argsSize('{"a":2,"b":1}'));
  });

  it('measures a string with no canonical form as received', () => {
    // Not JSON at all: LangChain's single-input tools hand the argument over
    // bare, and a model can emit a truncated payload. Either way an
    // unmeasured call is one `max_args_size` cannot bound.
    expect(argsSize('/etc/h\u00f6sts')).toBe(utf8ByteLength('/etc/h\u00f6sts'));
    expect(argsSize('{"q":"tru')).toBe(utf8ByteLength('{"q":"tru'));
  });

  it('yields no size signal for a payload with no JSON representation', () => {
    // Fail quietly rather than throwing at the tool boundary: an exception
    // here would gate the call on the caller's error handling instead of on
    // the policy.
    expect(argsSize({ nope: () => 0 })).toBeUndefined();
    expect(argsSize(undefined)).toBeUndefined();
  });

  it.each([
    ['mapOpenAIToolCall', (args: Record<string, unknown>) => mapOpenAIToolCall('search', args)],
    ['mapMCPToolCall', (args: Record<string, unknown>) => mapMCPToolCall('custom_search', args)],
    ['mapClaudeToolToAction', (args: Record<string, unknown>) => mapClaudeToolToAction('search', args)],
    ['mapClaudeToolToAction (mcp__)', (args: Record<string, unknown>) => mapClaudeToolToAction('mcp__server__search', args)],
    ['mapWellKnownTool', (args: Record<string, unknown>) => mapWellKnownTool('search', args)],
    ['HushGuard.mapToolCall', (args: Record<string, unknown>) => HushGuard.mapToolCall('search', args)],
  ])('%s reports the spec measurement', (_name, map) => {
    expect(map(NON_ASCII).args_size).toBe(specSize(NON_ASCII));
    expect(map(EMOJI).args_size).toBe(specSize(EMOJI));
    expect(map(ESCAPED).args_size).toBe(specSize(ESCAPED));
  });

  it('gates a call on the byte count the policy names', () => {
    // End to end: a limit between the UTF-16 and UTF-8 measurements of the
    // same arguments. Under the old count this call was allowed.
    const guard = HushGuard.fromYaml(`
hushspec: "1.0.0"
name: args-budget
rules:
  tool_access:
    default: allow
    max_args_size: 11
`);
    expect(specSize(EMOJI)).toBe(12);
    expect(JSON.stringify(EMOJI).length).toBe(10);

    const result = guard.evaluate(mapMCPToolCall('custom_search', EMOJI));
    expect(result.decision).toBe('deny');
    expect(result.matched_rule).toBe('rules.tool_access.max_args_size');
  });
});
